mod api_server;
mod auth;
mod component;
mod components;
mod config;
mod packet;
mod protocol_detector;
mod router;
mod tcp_frame;
mod timefmt;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use component::Component;
use config::{
    ComponentConfig, Config, FilterComponentConfig, IPRouteComponentConfig,
    LoadBalancerComponentConfig,
};
use protocol_detector::ProtocolDetector;
use router::Router;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{error, info};
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
    install_panic_hook();
    info!("Prismux booting with config {}", cli.config.display());

    let router = Router::new(config.clone());
    let detector = Arc::new(ProtocolDetector::new(config.protocol_detectors.clone()));

    for service in &config.services {
        let component = build_component(service, Arc::clone(&detector))
            .with_context(|| format!("invalid service definition: {service:?}"))?;
        router.register(component)?;
    }

    router.start().await?;

    let api_server = if config.api.enabled {
        Some(api_server::ApiServer::start(config.api.clone(), Arc::clone(&router)).await?)
    } else {
        None
    };

    info!("UDPlex started and ready");

    let signal = wait_for_shutdown_signal().await?;
    info!("Shutdown signal received: {signal}");

    if let Some(server) = api_server {
        info!("Stopping API server");
        server.stop().await;
        info!("API server stopped");
    }
    router.shutdown();
    info!("Router shutdown notified, Prismux exiting");
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

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let message = if let Some(msg) = panic_info.payload().downcast_ref::<&str>() {
            *msg
        } else if let Some(msg) = panic_info.payload().downcast_ref::<String>() {
            msg.as_str()
        } else {
            "non-string panic payload"
        };

        if let Some(location) = panic_info.location() {
            error!(
                file = location.file(),
                line = location.line(),
                column = location.column(),
                "panic occurred: {message}"
            );
        } else {
            error!("panic occurred: {message}");
        }

        default_hook(panic_info);
    }));
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;

    tokio::select! {
        _ = sigint.recv() => Ok("SIGINT"),
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    tokio::signal::ctrl_c()
        .await
        .context("failed waiting for Ctrl+C signal")?;
    Ok("CTRL_C")
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
