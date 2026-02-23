mod auth;
mod component;
mod components;
mod config;
mod packet;
mod protocol_detector;
mod router;
mod tcp_frame;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use component::Component;
use config::{
    ComponentConfig, Config, FilterComponentConfig, IPRouteComponentConfig, LoadBalancerComponentConfig,
};
use protocol_detector::ProtocolDetector;
use router::Router;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "prismux")]
#[command(about = "High performance UDP multiplexing/forwarding tool in Rust")]
struct Cli {
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    config: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    init_logger(&config);
    info!("Prismux booting with config {}", cli.config.display());

    let router = Router::new(config.clone());
    let detector = Arc::new(ProtocolDetector::new(config.protocol_detectors.clone()));

    for service in &config.services {
        let component = build_component(service, Arc::clone(&detector))
            .with_context(|| format!("invalid service definition: {service:?}"))?;
        router.register(component)?;
    }

    router.start().await?;

    if config.api.enabled {
        warn!("API server requested but not enabled in this Rust refactor build");
    }

    info!("UDPlex started and ready");

    tokio::signal::ctrl_c().await?;
    router.shutdown();
    Ok(())
}

fn init_logger(config: &Config) {
    let level = if config.logging.level.is_empty() {
        "info".to_string()
    } else {
        config.logging.level.to_ascii_lowercase()
    };

    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    if config.logging.format.eq_ignore_ascii_case("json") {
        fmt().with_env_filter(filter).json().init();
    } else {
        fmt().with_env_filter(filter).init();
    }
}

fn load_config(path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;

    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "yaml" | "yml" => Ok(serde_yaml::from_str(&raw)?),
        _ => Ok(serde_json::from_str(&raw)?),
    }
}

fn build_component(
    value: &serde_yaml::Value,
    detector: Arc<ProtocolDetector>,
) -> Result<Arc<dyn Component>> {
    let component_type = value
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("service missing type"))?;

    let serialized = serde_yaml::to_string(value)?;

    match component_type {
        "listen" => {
            let cfg: ComponentConfig = serde_yaml::from_str(&serialized)?;
            Ok(components::listen::ListenComponent::new(cfg)?)
        }
        "forward" => {
            let cfg: ComponentConfig = serde_yaml::from_str(&serialized)?;
            Ok(components::forward::ForwardComponent::new(cfg)?)
        }
        "filter" => {
            let cfg: FilterComponentConfig = serde_yaml::from_str(&serialized)?;
            Ok(components::filter::FilterComponent::new(cfg, detector))
        }
        "load_balancer" => {
            let cfg: LoadBalancerComponentConfig = serde_yaml::from_str(&serialized)?;
            Ok(components::load_balancer::LoadBalancerComponent::new(cfg)?)
        }
        "tcp_tunnel_listen" => {
            let cfg: ComponentConfig = serde_yaml::from_str(&serialized)?;
            Ok(components::tcp_tunnel_listen::TcpTunnelListenComponent::new(cfg)?)
        }
        "tcp_tunnel_forward" => {
            let cfg: ComponentConfig = serde_yaml::from_str(&serialized)?;
            Ok(components::tcp_tunnel_forward::TcpTunnelForwardComponent::new(cfg)?)
        }
        "ip_router" => {
            let cfg: IPRouteComponentConfig = serde_yaml::from_str(&serialized)?;
            Ok(components::ip_router::IPRouterComponent::new(cfg)?)
        }
        _ => Err(anyhow!("unknown component type: {component_type}")),
    }
}
