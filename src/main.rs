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
    time::{Duration, Instant},
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
    if let Err(err) = run().await {
        error!("Prismux fatal error: {err:#}");
        return Err(err);
    }
    Ok(())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;
    let mut exit_guard = ExitGuard::new();

    init_logger(&config);
    install_panic_hook();
    let pid = std::process::id();
    info!(
        "Prismux process started pid={} version={} marker={}",
        pid,
        env!("CARGO_PKG_VERSION"),
        "diag-v2-2026-02-24"
    );
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

    let diag_task = maybe_start_diag_heartbeat();

    let signal = wait_for_shutdown_signal().await?;
    info!("Shutdown signal received: {signal}");

    if let Some(server) = api_server {
        info!("Stopping API server");
        server.stop().await;
        info!("API server stopped");
    }
    router.shutdown();
    if let Some(task) = diag_task {
        task.abort();
    }
    info!("Router shutdown notified, Prismux exiting");
    exit_guard.disarm("graceful-signal-shutdown");
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

struct ExitGuard {
    reason: Option<&'static str>,
}

impl ExitGuard {
    fn new() -> Self {
        Self { reason: None }
    }

    fn disarm(&mut self, reason: &'static str) {
        self.reason = Some(reason);
    }
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        if let Some(reason) = self.reason {
            info!("Prismux run loop exit reason={reason}");
        } else {
            error!("Prismux run loop exited without graceful shutdown marker");
        }
    }
}

fn maybe_start_diag_heartbeat() -> Option<tokio::task::JoinHandle<()>> {
    let raw = std::env::var("PRISMUX_DIAG_INTERVAL_SEC").ok()?;
    let sec = raw.parse::<u64>().ok()?;
    if sec == 0 {
        return None;
    }

    let interval = Duration::from_secs(sec);
    info!(
        "Diagnostics heartbeat enabled interval={}s (env PRISMUX_DIAG_INTERVAL_SEC)",
        sec
    );
    Some(tokio::spawn(async move {
        diag_heartbeat_loop(interval).await;
    }))
}

async fn diag_heartbeat_loop(interval: Duration) {
    use tokio::time::{self, MissedTickBehavior};

    let started = Instant::now();
    let pid = std::process::id();
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let uptime_s = started.elapsed().as_secs();
        #[cfg(target_os = "linux")]
        {
            if let Some((rss_kb, threads)) = read_linux_proc_status() {
                info!(
                    "diag heartbeat pid={} uptime_s={} rss_kb={} threads={}",
                    pid, uptime_s, rss_kb, threads
                );
                continue;
            }
        }
        info!("diag heartbeat pid={} uptime_s={}", pid, uptime_s);
    }
}

#[cfg(target_os = "linux")]
fn read_linux_proc_status() -> Option<(u64, u64)> {
    let content = fs::read_to_string("/proc/self/status").ok()?;
    let mut rss_kb = None;
    let mut threads = None;

    for line in content.lines() {
        if line.starts_with("VmRSS:") {
            rss_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok());
        } else if line.starts_with("Threads:") {
            threads = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok());
        }
    }

    Some((rss_kb.unwrap_or(0), threads.unwrap_or(0)))
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("failed to install SIGHUP handler")?;
    let mut sigquit = signal(SignalKind::quit()).context("failed to install SIGQUIT handler")?;

    tokio::select! {
        _ = sigint.recv() => Ok("SIGINT"),
        _ = sigterm.recv() => Ok("SIGTERM"),
        _ = sighup.recv() => Ok("SIGHUP"),
        _ = sigquit.recv() => Ok("SIGQUIT"),
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
