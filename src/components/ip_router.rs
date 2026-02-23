use crate::{component::Component, config::IPRouteComponentConfig, packet::Packet, router::Router};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use maxminddb::{geoip2, Reader};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};
use tokio::{fs, time};
use tracing::warn;

enum RuleMatch {
    Ip(IpAddr),
    Cidr(IpNet),
    Geo(String),
}

struct IpRule {
    matcher: RuleMatch,
    targets: Arc<[String]>,
}

pub struct IPRouterComponent {
    tag: String,
    rules: Vec<IpRule>,
    detour_miss: Arc<[String]>,
    geoip_url: String,
    geoip_path: RwLock<String>,
    update_interval: Duration,
    geo_db: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    updater_running: AtomicBool,
}

impl IPRouterComponent {
    pub fn new(cfg: IPRouteComponentConfig) -> Result<Arc<Self>> {
        let mut geoip_mmdb = cfg.geoip_mmdb.trim().to_string();
        let mut geoip_url = cfg.geoip_url.trim().to_string();
        if geoip_url.is_empty() && is_http_url(&geoip_mmdb) {
            geoip_url = geoip_mmdb;
            geoip_mmdb = String::new();
        }

        let mut rules = Vec::with_capacity(cfg.rules.len());
        for rule in cfg.rules {
            let r = rule.rule.trim();
            let matcher = if r.to_ascii_lowercase().starts_with("geo:") {
                RuleMatch::Geo(r[4..].trim().to_ascii_uppercase())
            } else if r.contains('/') {
                let cidr: IpNet = r.parse().map_err(|_| anyhow!("invalid cidr rule {r}"))?;
                RuleMatch::Cidr(cidr)
            } else {
                let ip: IpAddr = r.parse().map_err(|_| anyhow!("invalid ip rule {r}"))?;
                RuleMatch::Ip(ip)
            };
            rules.push(IpRule {
                matcher,
                targets: Arc::<[String]>::from(rule.targets),
            });
        }

        let update_interval = parse_update_interval(&cfg.geoip_update_interval);

        let component = Arc::new(Self {
            tag: cfg.tag,
            rules,
            detour_miss: Arc::<[String]>::from(cfg.detour_miss),
            geoip_url,
            geoip_path: RwLock::new(geoip_mmdb.clone()),
            update_interval,
            geo_db: RwLock::new(None),
            updater_running: AtomicBool::new(false),
        });

        if !geoip_mmdb.is_empty() {
            component
                .load_geoip_from_path(PathBuf::from(&geoip_mmdb))
                .with_context(|| format!("failed to load geoip mmdb from {geoip_mmdb}"))?;
        }

        Ok(component)
    }

    pub fn api_info(&self) -> Value {
        let rules = self
            .rules
            .iter()
            .map(|rule| {
                json!({
                    "match": match &rule.matcher {
                        RuleMatch::Ip(ip) => ip.to_string(),
                        RuleMatch::Cidr(cidr) => cidr.to_string(),
                        RuleMatch::Geo(code) => format!("geo:{code}"),
                    },
                    "targets": rule.targets.to_vec(),
                })
            })
            .collect::<Vec<_>>();

        let geoip_path = self
            .geoip_path
            .read()
            .ok()
            .map(|v| v.clone())
            .unwrap_or_default();
        let db_loaded = self.geo_db.read().ok().is_some_and(|db| db.is_some());

        json!({
            "tag": self.tag,
            "type": "ip_router",
            "rules": rules,
            "detour_miss": self.detour_miss.to_vec(),
            "geoip": {
                "db_loaded": db_loaded,
                "geoip_url": self.geoip_url,
                "geoip_path": geoip_path,
                "update_interval_sec": self.update_interval.as_secs(),
            },
        })
    }

    pub async fn geoip_update(&self) -> Result<()> {
        self.download_and_swap().await
    }

    fn geo_country_code(&self, ip: IpAddr) -> Option<String> {
        let db = self.geo_db.read().ok()?.as_ref()?.clone();
        let country: geoip2::Country = db.lookup(ip).ok()?;
        country
            .country
            .and_then(|v| v.iso_code.map(|s| s.to_string()))
    }

    fn load_geoip_from_path(&self, path: PathBuf) -> Result<()> {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("failed to read geoip file {}", path.display()))?;
        let reader = Reader::from_source(bytes)
            .with_context(|| format!("failed to parse geoip file {}", path.display()))?;
        let mut db_lock = self
            .geo_db
            .write()
            .map_err(|_| anyhow!("geo db lock poisoned"))?;
        *db_lock = Some(Arc::new(reader));
        let mut path_lock = self
            .geoip_path
            .write()
            .map_err(|_| anyhow!("geo path lock poisoned"))?;
        *path_lock = path.to_string_lossy().to_string();
        Ok(())
    }

    async fn download_and_swap(&self) -> Result<()> {
        if self.geoip_url.is_empty() {
            return Err(anyhow!("geoip_url is empty"));
        }

        let response = reqwest::get(&self.geoip_url)
            .await
            .with_context(|| format!("failed to download geoip from {}", self.geoip_url))?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(anyhow!(
                "geoip download failed from {} with status {}",
                self.geoip_url,
                status
            ));
        }

        let body = response
            .bytes()
            .await
            .with_context(|| format!("failed to read geoip body from {}", self.geoip_url))?;
        let reader = Reader::from_source(body.to_vec())
            .with_context(|| format!("invalid geoip mmdb from {}", self.geoip_url))?;

        let mut final_path = std::env::temp_dir();
        let file_name = if self.tag.is_empty() {
            "prismux_geoip.mmdb".to_string()
        } else {
            format!("prismux_geoip_{}.mmdb", self.tag)
        };
        final_path.push(file_name);

        fs::write(&final_path, &body)
            .await
            .with_context(|| format!("failed to write geoip file {}", final_path.display()))?;

        {
            let mut db_lock = self
                .geo_db
                .write()
                .map_err(|_| anyhow!("geo db lock poisoned"))?;
            *db_lock = Some(Arc::new(reader));
        }
        {
            let mut path_lock = self
                .geoip_path
                .write()
                .map_err(|_| anyhow!("geo path lock poisoned"))?;
            *path_lock = final_path.to_string_lossy().to_string();
        }

        Ok(())
    }

    fn start_updater_if_needed(self: &Arc<Self>) {
        if self.geoip_url.is_empty() || self.update_interval.is_zero() {
            return;
        }
        if self.updater_running.swap(true, Ordering::Relaxed) {
            return;
        }

        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = time::interval(this.update_interval);
            loop {
                ticker.tick().await;
                if let Err(err) = this.download_and_swap().await {
                    warn!("{} geoip periodic update failed: {err}", this.tag);
                }
            }
        });
    }
}

#[async_trait]
impl Component for IPRouterComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(self: Arc<Self>, _router: Arc<Router>) -> Result<()> {
        if !self.geoip_url.is_empty() {
            if let Err(err) = self.download_and_swap().await {
                warn!("{} initial geoip update failed: {err}", self.tag);
            }
        }
        self.start_updater_if_needed();
        Ok(())
    }

    async fn handle_packet(&self, router: &Router, packet: Packet) -> Result<()> {
        let src_ip = packet.src_addr.map(|a| a.ip());
        if src_ip.is_none() {
            if !self.detour_miss.is_empty() {
                router
                    .route_shared(packet, Arc::clone(&self.detour_miss))
                    .await?;
            }
            return Ok(());
        }
        let src_ip = src_ip.unwrap();

        for rule in &self.rules {
            match &rule.matcher {
                RuleMatch::Ip(ip) if *ip == src_ip => {
                    router
                        .route_shared(packet, Arc::clone(&rule.targets))
                        .await?;
                    return Ok(());
                }
                RuleMatch::Cidr(cidr) if cidr.contains(&src_ip) => {
                    router
                        .route_shared(packet, Arc::clone(&rule.targets))
                        .await?;
                    return Ok(());
                }
                RuleMatch::Geo(_) => {
                    if let RuleMatch::Geo(code) = &rule.matcher {
                        let country = self.geo_country_code(src_ip);
                        if country.as_deref() == Some(code.as_str()) {
                            router
                                .route_shared(packet, Arc::clone(&rule.targets))
                                .await?;
                            return Ok(());
                        }
                    }
                }
                _ => {}
            }
        }

        if !self.detour_miss.is_empty() {
            router
                .route_shared(packet, Arc::clone(&self.detour_miss))
                .await?;
        }

        Ok(())
    }
}

fn is_http_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn parse_update_interval(raw: &str) -> Duration {
    let input = raw.trim();
    if input.is_empty() {
        return Duration::ZERO;
    }

    if let Ok(sec) = input.parse::<u64>() {
        return Duration::from_secs(sec);
    }

    let (num, unit) = split_num_unit(input);
    let Ok(value) = num.parse::<u64>() else {
        return Duration::ZERO;
    };
    match unit {
        "s" | "" => Duration::from_secs(value),
        "m" => Duration::from_secs(value.saturating_mul(60)),
        "h" => Duration::from_secs(value.saturating_mul(3600)),
        "d" => Duration::from_secs(value.saturating_mul(86400)),
        _ => Duration::ZERO,
    }
}

fn split_num_unit(input: &str) -> (&str, &str) {
    let idx = input
        .char_indices()
        .find_map(|(idx, ch)| (!ch.is_ascii_digit()).then_some(idx))
        .unwrap_or(input.len());
    (&input[..idx], &input[idx..])
}
