use crate::{
    component::Component,
    config::IPRouteComponentConfig,
    packet::Packet,
    router::Router,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::{net::IpAddr, sync::Arc};

enum RuleMatch {
    Ip(IpAddr),
    Cidr(IpNet),
    Geo(String),
}

struct IpRule {
    matcher: RuleMatch,
    targets: Vec<String>,
}

pub struct IPRouterComponent {
    tag: String,
    rules: Vec<IpRule>,
    detour_miss: Vec<String>,
}

impl IPRouterComponent {
    pub fn new(cfg: IPRouteComponentConfig) -> Result<Arc<Self>> {
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
                targets: rule.targets,
            });
        }

        Ok(Arc::new(Self {
            tag: cfg.tag,
            rules,
            detour_miss: cfg.detour_miss,
        }))
    }
}

#[async_trait]
impl Component for IPRouterComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, _router: Arc<Router>) -> Result<()> {
        Ok(())
    }

    async fn handle_packet(&self, router: &Router, packet: Packet) -> Result<()> {
        let src_ip = packet.src_addr.map(|a| a.ip());
        if src_ip.is_none() {
            if !self.detour_miss.is_empty() {
                router.route(packet, &self.detour_miss)?;
            }
            return Ok(());
        }
        let src_ip = src_ip.unwrap();

        for rule in &self.rules {
            match &rule.matcher {
                RuleMatch::Ip(ip) if *ip == src_ip => {
                    router.route(packet, &rule.targets)?;
                    return Ok(());
                }
                RuleMatch::Cidr(cidr) if cidr.contains(&src_ip) => {
                    router.route(packet, &rule.targets)?;
                    return Ok(());
                }
                RuleMatch::Geo(_) => {
                    // GeoIP matching is optional and requires an MMDB; if unavailable, treat as miss.
                }
                _ => {}
            }
        }

        if !self.detour_miss.is_empty() {
            router.route(packet, &self.detour_miss)?;
        }

        Ok(())
    }
}
