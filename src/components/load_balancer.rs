use crate::{
    component::Component,
    config::{LoadBalancerComponentConfig, LoadBalancerDetourRule},
    packet::Packet,
    router::Router,
};
use anyhow::Result;
use async_trait::async_trait;
use evalexpr::{build_operator_tree, ContextWithMutableVariables, HashMapContext, Node, Value};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::Mutex,
    time::{self, MissedTickBehavior},
};

#[derive(Clone, Copy, Default)]
struct TrafficSample {
    bytes: u64,
    packets: u64,
}

struct TrafficStats {
    samples: Vec<TrafficSample>,
    idx: usize,
    current_bytes: u64,
    current_packets: u64,
    total_bytes: u64,
    total_packets: u64,
}

struct CompiledRule {
    exec: RuleExec,
    targets: Vec<String>,
    available_tags: Vec<String>,
    delay_tags: Vec<String>,
}

enum RuleExec {
    Fast(FastRule),
    Expr(Node),
}

enum FastRule {
    SeqModEq {
        modulo: u64,
        equals: u64,
        available_tag: Option<String>,
    },
    DelayLt {
        tag: String,
        threshold: f64,
    },
    Available {
        tag: String,
    },
}

pub struct LoadBalancerComponent {
    tag: String,
    rules: Vec<CompiledRule>,
    miss: Vec<String>,
    packet_seq: AtomicU64,
    running: AtomicBool,
    stats: Arc<Mutex<TrafficStats>>,
    sample_interval: Duration,
}

impl LoadBalancerComponent {
    pub fn new(cfg: LoadBalancerComponentConfig) -> Result<Arc<Self>> {
        let mut rules = Vec::with_capacity(cfg.detour.len());
        for rule in cfg.detour {
            rules.push(Self::compile_rule(rule)?);
        }

        let window_size = cfg.window_size.max(1) as usize;

        Ok(Arc::new(Self {
            tag: cfg.tag,
            rules,
            miss: cfg.miss,
            packet_seq: AtomicU64::new(0),
            running: AtomicBool::new(false),
            stats: Arc::new(Mutex::new(TrafficStats {
                samples: vec![TrafficSample::default(); window_size],
                idx: 0,
                current_bytes: 0,
                current_packets: 0,
                total_bytes: 0,
                total_packets: 0,
            })),
            sample_interval: Duration::from_secs(1),
        }))
    }

    fn compile_rule(rule: LoadBalancerDetourRule) -> Result<CompiledRule> {
        let available_tags = extract_tag_vars(&rule.rule, "available_");
        let delay_tags = extract_tag_vars(&rule.rule, "delay_");
        let exec = if let Some(fast) = parse_fast_rule(&rule.rule) {
            RuleExec::Fast(fast)
        } else {
            RuleExec::Expr(build_operator_tree(&rule.rule)?)
        };
        Ok(CompiledRule {
            exec,
            targets: rule.targets,
            available_tags,
            delay_tags,
        })
    }

    async fn sampler(self: Arc<Self>) {
        let mut ticker = time::interval(self.sample_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        while self.running.load(Ordering::Relaxed) {
            ticker.tick().await;
            let mut stats = self.stats.lock().await;
            let idx = stats.idx % stats.samples.len();

            stats.total_bytes = stats
                .total_bytes
                .saturating_sub(stats.samples[idx].bytes)
                .saturating_add(stats.current_bytes);
            stats.total_packets = stats
                .total_packets
                .saturating_sub(stats.samples[idx].packets)
                .saturating_add(stats.current_packets);

            stats.samples[idx] = TrafficSample {
                bytes: stats.current_bytes,
                packets: stats.current_packets,
            };

            stats.current_bytes = 0;
            stats.current_packets = 0;
            stats.idx = (stats.idx + 1) % stats.samples.len();
        }
    }

    async fn current_bps_pps(&self) -> (u64, u64) {
        let stats = self.stats.lock().await;
        let sample_count = stats.samples.len() as u64 + 1;
        let bytes = stats.total_bytes + stats.current_bytes;
        let packets = stats.total_packets + stats.current_packets;
        ((bytes * 8) / sample_count.max(1), packets / sample_count.max(1))
    }

    async fn evaluate_targets(&self, router: &Router, seq: u64, size: u64, bps: u64, pps: u64) -> Vec<String> {
        let mut selected = Vec::new();
        for rule in &self.rules {
            if let RuleExec::Fast(fast) = &rule.exec {
                if fast_rule_matches(fast, router, seq).await {
                    selected.extend(rule.targets.iter().cloned());
                }
                continue;
            }

            let mut ctx = HashMapContext::new();
            let _ = ctx.set_value("seq".into(), Value::Int(seq as i64));
            let _ = ctx.set_value("size".into(), Value::Int(size as i64));
            let _ = ctx.set_value("bps".into(), Value::Int(bps as i64));
            let _ = ctx.set_value("pps".into(), Value::Int(pps as i64));

            for tag in &rule.available_tags {
                let available = router.get_component(tag).is_some();
                let _ = ctx.set_value(format!("available_{tag}").into(), Value::Boolean(available));
            }

            for tag in &rule.delay_tags {
                let delay = if let Some(comp) = router.get_component(tag) {
                    comp.average_delay_ms().await
                } else {
                    f64::MAX
                };
                let _ = ctx.set_value(format!("delay_{tag}").into(), Value::Float(delay));
            }

            let RuleExec::Expr(expr) = &rule.exec else {
                unreachable!();
            };
            if let Ok(value) = expr.eval_with_context(&ctx) {
                let matched = match value {
                    Value::Boolean(v) => v,
                    Value::Int(v) => v != 0,
                    Value::Float(v) => v != 0.0,
                    _ => false,
                };
                if matched {
                    selected.extend(rule.targets.iter().cloned());
                }
            }
        }

        selected
    }
}

#[async_trait]
impl Component for LoadBalancerComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, _router: Arc<Router>) -> Result<()> {
        self.running.store(true, Ordering::Relaxed);
        tokio::spawn(Arc::clone(&self).sampler());
        Ok(())
    }

    async fn handle_packet(&self, router: &Router, packet: Packet) -> Result<()> {
        {
            let mut stats = self.stats.lock().await;
            stats.current_packets = stats.current_packets.saturating_add(1);
            stats.current_bytes = stats.current_bytes.saturating_add(packet.data.len() as u64);
        }

        let (bps, pps) = self.current_bps_pps().await;
        let seq = self.packet_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let size = packet.data.len() as u64;

        let mut targets = self.evaluate_targets(router, seq, size, bps, pps).await;
        if targets.is_empty() {
            targets = self.miss.clone();
        }

        if !targets.is_empty() {
            router.route(packet, &targets)?;
        }

        Ok(())
    }
}

fn extract_tag_vars(expr: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in expr.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if let Some(tag) = token.strip_prefix(prefix) {
            if !tag.is_empty() && !out.iter().any(|v| v == tag) {
                out.push(tag.to_string());
            }
        }
    }
    out
}

fn parse_fast_rule(expr: &str) -> Option<FastRule> {
    let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();

    if let Some((left, right)) = compact.split_once("&&") {
        if let Some(tag) = left.strip_prefix("available_") {
            if let Some((modulo, equals)) = parse_seq_mod_eq(right) {
                return Some(FastRule::SeqModEq {
                    modulo,
                    equals,
                    available_tag: Some(tag.to_string()),
                });
            }
        }
        if let Some(tag) = right.strip_prefix("available_") {
            if let Some((modulo, equals)) = parse_seq_mod_eq(left) {
                return Some(FastRule::SeqModEq {
                    modulo,
                    equals,
                    available_tag: Some(tag.to_string()),
                });
            }
        }
    }

    if let Some((modulo, equals)) = parse_seq_mod_eq(&compact) {
        return Some(FastRule::SeqModEq {
            modulo,
            equals,
            available_tag: None,
        });
    }

    if let Some(tag) = compact.strip_prefix("available_") {
        return Some(FastRule::Available {
            tag: tag.to_string(),
        });
    }

    if let Some(body) = compact.strip_prefix("delay_") {
        if let Some((tag, threshold)) = body.split_once('<') {
            if let Ok(th) = threshold.parse::<f64>() {
                return Some(FastRule::DelayLt {
                    tag: tag.to_string(),
                    threshold: th,
                });
            }
        }
    }

    None
}

fn parse_seq_mod_eq(expr: &str) -> Option<(u64, u64)> {
    let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.starts_with("seq%") {
        return None;
    }
    let rest = &compact[4..];
    let (mod_s, eq_s) = rest.split_once("==")?;
    let modulo = mod_s.parse::<u64>().ok()?;
    let equals = eq_s.parse::<u64>().ok()?;
    if modulo == 0 {
        return None;
    }
    Some((modulo, equals))
}

async fn fast_rule_matches(rule: &FastRule, router: &Router, seq: u64) -> bool {
    match rule {
        FastRule::SeqModEq {
            modulo,
            equals,
            available_tag,
        } => {
            if seq % *modulo != *equals {
                return false;
            }
            if let Some(tag) = available_tag {
                return router.get_component(tag).is_some();
            }
            true
        }
        FastRule::DelayLt { tag, threshold } => {
            let Some(comp) = router.get_component(tag) else {
                return false;
            };
            comp.average_delay_ms().await < *threshold
        }
        FastRule::Available { tag } => router.get_component(tag).is_some(),
    }
}
