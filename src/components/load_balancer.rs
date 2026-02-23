use crate::{
    component::Component,
    config::{LoadBalancerComponentConfig, LoadBalancerDetourRule},
    packet::Packet,
    router::Router,
};
use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use evalexpr::{build_operator_tree, ContextWithMutableVariables, HashMapContext, Node, Value};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
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
    total_bytes: u64,
    total_packets: u64,
}

struct CompiledRule {
    exec: RuleExec,
    targets: Arc<[String]>,
    available_tags: Vec<String>,
    delay_tags: Vec<String>,
    uses_traffic_stats: bool,
}

enum RuleExec {
    Fast(FastRule),
    Expr(Node),
}

enum FastRule {
    SeqMaskEq {
        mask: u64,
        equals: u64,
        available_tag: Option<String>,
    },
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

#[derive(Clone, Copy)]
struct DelaySample {
    value_ms: f64,
    updated_at: Instant,
}

pub struct LoadBalancerComponent {
    tag: String,
    rules: Vec<CompiledRule>,
    miss: Arc<[String]>,
    packet_seq: AtomicU64,
    enable_traffic_stats: bool,
    current_bytes: AtomicU64,
    current_packets: AtomicU64,
    avg_bps: AtomicU64,
    avg_pps: AtomicU64,
    running: AtomicBool,
    stats: Arc<Mutex<TrafficStats>>,
    delay_cache: DashMap<String, DelaySample>,
    delay_cache_ttl: Duration,
    sample_interval: Duration,
}

impl LoadBalancerComponent {
    pub fn new(cfg: LoadBalancerComponentConfig) -> Result<Arc<Self>> {
        let mut rules = Vec::with_capacity(cfg.detour.len());
        for rule in cfg.detour {
            rules.push(Self::compile_rule(rule)?);
        }
        let enable_traffic_stats = rules.iter().any(|r| r.uses_traffic_stats);

        let window_size = cfg.window_size.max(1) as usize;

        Ok(Arc::new(Self {
            tag: cfg.tag,
            rules,
            miss: Arc::<[String]>::from(cfg.miss),
            packet_seq: AtomicU64::new(0),
            enable_traffic_stats,
            current_bytes: AtomicU64::new(0),
            current_packets: AtomicU64::new(0),
            avg_bps: AtomicU64::new(0),
            avg_pps: AtomicU64::new(0),
            running: AtomicBool::new(false),
            stats: Arc::new(Mutex::new(TrafficStats {
                samples: vec![TrafficSample::default(); window_size],
                idx: 0,
                total_bytes: 0,
                total_packets: 0,
            })),
            delay_cache: DashMap::new(),
            delay_cache_ttl: Duration::from_millis(200),
            sample_interval: Duration::from_secs(1),
        }))
    }

    fn compile_rule(rule: LoadBalancerDetourRule) -> Result<CompiledRule> {
        let available_tags = extract_tag_vars(&rule.rule, "available_");
        let delay_tags = extract_tag_vars(&rule.rule, "delay_");
        let uses_traffic_stats = has_identifier(&rule.rule, "bps") || has_identifier(&rule.rule, "pps");
        let exec = if let Some(fast) = parse_fast_rule(&rule.rule) {
            RuleExec::Fast(fast)
        } else {
            RuleExec::Expr(build_operator_tree(&rule.rule)?)
        };
        Ok(CompiledRule {
            exec,
            targets: Arc::<[String]>::from(rule.targets),
            available_tags,
            delay_tags,
            uses_traffic_stats,
        })
    }

    async fn sampler(self: Arc<Self>) {
        let mut ticker = time::interval(self.sample_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        while self.running.load(Ordering::Relaxed) {
            ticker.tick().await;
            let current_bytes = self.current_bytes.swap(0, Ordering::Relaxed);
            let current_packets = self.current_packets.swap(0, Ordering::Relaxed);
            let mut stats = self.stats.lock().await;
            let idx = stats.idx % stats.samples.len();

            stats.total_bytes = stats
                .total_bytes
                .saturating_sub(stats.samples[idx].bytes)
                .saturating_add(current_bytes);
            stats.total_packets = stats
                .total_packets
                .saturating_sub(stats.samples[idx].packets)
                .saturating_add(current_packets);

            stats.samples[idx] = TrafficSample {
                bytes: current_bytes,
                packets: current_packets,
            };

            stats.idx = (stats.idx + 1) % stats.samples.len();

            let sample_count = stats.samples.len() as u64 + 1;
            let bytes = stats.total_bytes + current_bytes;
            let packets = stats.total_packets + current_packets;
            self.avg_bps
                .store((bytes * 8) / sample_count.max(1), Ordering::Relaxed);
            self.avg_pps
                .store(packets / sample_count.max(1), Ordering::Relaxed);
        }
    }

    fn current_bps_pps(&self) -> (u64, u64) {
        (
            self.avg_bps.load(Ordering::Relaxed),
            self.avg_pps.load(Ordering::Relaxed),
        )
    }

    async fn delay_ms_for(&self, router: &Router, tag: &str) -> f64 {
        let now = Instant::now();
        if let Some(v) = self.delay_cache.get(tag) {
            if now.duration_since(v.updated_at) <= self.delay_cache_ttl {
                return v.value_ms;
            }
        }

        let delay = if let Some(comp) = router.get_component(tag) {
            comp.average_delay_ms().await
        } else {
            f64::MAX
        };
        self.delay_cache.insert(
            tag.to_string(),
            DelaySample {
                value_ms: delay,
                updated_at: now,
            },
        );
        delay
    }

    async fn evaluate_targets(
        &self,
        router: &Router,
        seq: u64,
        size: u64,
        bps: u64,
        pps: u64,
    ) -> Vec<Arc<[String]>> {
        let mut selected = Vec::new();
        for rule in &self.rules {
            if let RuleExec::Fast(fast) = &rule.exec {
                let matched = match fast {
                    FastRule::SeqMaskEq {
                        mask,
                        equals,
                        available_tag,
                    } => {
                        if (seq & *mask) != *equals {
                            false
                        } else if let Some(tag) = available_tag {
                            router.has_component(tag)
                        } else {
                            true
                        }
                    }
                    FastRule::SeqModEq {
                        modulo,
                        equals,
                        available_tag,
                    } => {
                        if seq % *modulo != *equals {
                            false
                        } else if let Some(tag) = available_tag {
                            router.has_component(tag)
                        } else {
                            true
                        }
                    }
                    FastRule::DelayLt { tag, threshold } => {
                        self.delay_ms_for(router, tag).await < *threshold
                    }
                    FastRule::Available { tag } => router.has_component(tag),
                };
                if matched {
                    selected.push(Arc::clone(&rule.targets));
                }
                continue;
            }

            let mut ctx = HashMapContext::new();
            let _ = ctx.set_value("seq".into(), Value::Int(seq as i64));
            let _ = ctx.set_value("size".into(), Value::Int(size as i64));
            let _ = ctx.set_value("bps".into(), Value::Int(bps as i64));
            let _ = ctx.set_value("pps".into(), Value::Int(pps as i64));

            for tag in &rule.available_tags {
                let available = router.has_component(tag);
                let _ = ctx.set_value(format!("available_{tag}").into(), Value::Boolean(available));
            }

            for tag in &rule.delay_tags {
                let delay = self.delay_ms_for(router, tag).await;
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
                    selected.push(Arc::clone(&rule.targets));
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
        if self.enable_traffic_stats {
            tokio::spawn(Arc::clone(&self).sampler());
        }
        Ok(())
    }

    async fn handle_packet(&self, router: &Router, packet: Packet) -> Result<()> {
        if self.enable_traffic_stats {
            self.current_packets.fetch_add(1, Ordering::Relaxed);
            self.current_bytes
                .fetch_add(packet.data.len() as u64, Ordering::Relaxed);
        }

        let (bps, pps) = if self.enable_traffic_stats {
            self.current_bps_pps()
        } else {
            (0, 0)
        };
        let seq = self.packet_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let size = packet.data.len() as u64;

        let targets = self.evaluate_targets(router, seq, size, bps, pps).await;
        if targets.is_empty() {
            if !self.miss.is_empty() {
                router
                    .route_shared(packet, Arc::clone(&self.miss))
                    .await?;
            }
            return Ok(());
        }

        if targets.len() == 1 {
            router.route_shared(packet, Arc::clone(&targets[0])).await?;
            return Ok(());
        }

        let total = targets.len();
        let mut packet = Some(packet);
        for (idx, detour) in targets.into_iter().enumerate() {
            let routed = if idx + 1 == total {
                packet.take().expect("packet must exist")
            } else {
                packet.as_ref().expect("packet must exist").clone()
            };
            router.route_shared(routed, detour).await?;
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

fn has_identifier(expr: &str, identifier: &str) -> bool {
    expr.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|token| token == identifier)
}

fn parse_fast_rule(expr: &str) -> Option<FastRule> {
    let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();

    if let Some((left, right)) = compact.split_once("&&") {
        if let Some(tag) = left.strip_prefix("available_") {
            if let Some((modulo, equals)) = parse_seq_mod_eq(right) {
                return Some(seq_rule_for(modulo, equals, Some(tag.to_string())));
            }
        }
        if let Some(tag) = right.strip_prefix("available_") {
            if let Some((modulo, equals)) = parse_seq_mod_eq(left) {
                return Some(seq_rule_for(modulo, equals, Some(tag.to_string())));
            }
        }
    }

    if let Some((modulo, equals)) = parse_seq_mod_eq(&compact) {
        return Some(seq_rule_for(modulo, equals, None));
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

fn seq_rule_for(modulo: u64, equals: u64, available_tag: Option<String>) -> FastRule {
    if modulo.is_power_of_two() {
        FastRule::SeqMaskEq {
            mask: modulo - 1,
            equals,
            available_tag,
        }
    } else {
        FastRule::SeqModEq {
            modulo,
            equals,
            available_tag,
        }
    }
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

