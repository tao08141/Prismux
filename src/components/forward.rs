use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_RESPONSE, MSG_TYPE_DATA, MSG_TYPE_HEARTBEAT,
        MSG_TYPE_HEARTBEAT_ACK,
    },
    component::Component,
    config::ComponentConfig,
    packet::Packet,
    router::Router,
    timefmt::format_system_time,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use rand::Rng;
use serde_json::{json, Value};
use socket2::SockRef;
use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::RwLock,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

struct ForwardPeer {
    remote: String,
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    authenticated: AtomicBool,
    has_traffic: AtomicBool,
    auth_retry_count: AtomicU32,
    heartbeat_miss_count: AtomicU32,
    send_refusal_count: AtomicU32,
    last_reconnect_at: SystemTime,
    last_heartbeat_at: RwLock<Option<SystemTime>>,
    last_heartbeat_sent: RwLock<Option<Instant>>,
}

const AUTH_RETRY_RECONNECT_THRESHOLD: u32 = 5;
const HEARTBEAT_MISS_REAUTH_THRESHOLD: u32 = 2;
const HEARTBEAT_MISS_RECONNECT_THRESHOLD: u32 = 5;
const SEND_REFUSAL_RECONNECT_THRESHOLD: u32 = 1;

pub struct ForwardComponent {
    tag: String,
    tag_arc: Arc<str>,
    detour: Arc<[String]>,
    forwarders: Vec<String>,
    reconnect_interval: Duration,
    check_interval: Duration,
    send_keepalive: bool,
    recv_buffer_size: usize,
    send_buffer_size: usize,
    auth: Option<AuthManager>,
    peers: DashMap<String, Arc<ForwardPeer>>,
    running: AtomicBool,
    forward_id: [u8; 8],
}

impl ForwardComponent {
    pub fn new(cfg: ComponentConfig) -> Result<Arc<Self>> {
        let auth = AuthManager::from_config(cfg.auth.as_ref())?;
        let reconnect_interval = Duration::from_secs(cfg.reconnect_interval.max(1));
        let check_interval = Duration::from_secs(cfg.connection_check_time.max(1));
        let recv_buffer_size = cfg.recv_buffer_size.max(2 * 1024 * 1024);
        let send_buffer_size = cfg.send_buffer_size.max(2 * 1024 * 1024);
        let send_keepalive = cfg.send_keepalive.unwrap_or(true);
        let tag = cfg.tag;
        let tag_arc = Arc::<str>::from(tag.as_str());

        let mut forward_id = [0u8; 8];
        rand::thread_rng().fill(&mut forward_id);

        Ok(Arc::new(Self {
            tag,
            tag_arc,
            detour: Arc::<[String]>::from(cfg.detour),
            forwarders: cfg.forwarders,
            reconnect_interval,
            check_interval,
            send_keepalive,
            recv_buffer_size,
            send_buffer_size,
            auth,
            peers: DashMap::new(),
            running: AtomicBool::new(false),
            forward_id,
        }))
    }

    async fn create_peer(&self, remote: &str, addr: SocketAddr) -> Result<Arc<ForwardPeer>> {
        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let std_socket = StdUdpSocket::bind(bind_addr)?;
        std_socket.set_nonblocking(true)?;
        let sock_ref = SockRef::from(&std_socket);
        let _ = sock_ref.set_recv_buffer_size(self.recv_buffer_size);
        let _ = sock_ref.set_send_buffer_size(self.send_buffer_size);
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        socket.connect(addr).await?;

        Ok(Arc::new(ForwardPeer {
            remote: remote.to_string(),
            addr,
            socket,
            authenticated: AtomicBool::new(false),
            has_traffic: AtomicBool::new(false),
            auth_retry_count: AtomicU32::new(0),
            heartbeat_miss_count: AtomicU32::new(0),
            send_refusal_count: AtomicU32::new(0),
            last_reconnect_at: SystemTime::now(),
            last_heartbeat_at: RwLock::new(None),
            last_heartbeat_sent: RwLock::new(None),
        }))
    }

    async fn read_loop(self: Arc<Self>, router: Arc<Router>, peer: Arc<ForwardPeer>) {
        let mut buffer =
            vec![0u8; router.config.buffer_size.max(2048) + router.config.buffer_offset];

        while self.running.load(Ordering::Relaxed) {
            let n = match peer.socket.recv(&mut buffer).await {
                Ok(n) => n,
                Err(err) => {
                    if self.running.load(Ordering::Relaxed) {
                        warn!("{} peer {} recv failed: {err}", self.tag, peer.addr);
                    }
                    break;
                }
            };
            if n == 0 {
                continue;
            }

            if let Some(auth) = &self.auth {
                match auth.unwrap_frame(&buffer[..n]) {
                    Ok(UnwrappedFrame::Data { conn_id, payload }) => {
                        if !peer.authenticated.load(Ordering::Relaxed) {
                            continue;
                        }
                        peer.heartbeat_miss_count.store(0, Ordering::Relaxed);
                        peer.send_refusal_count.store(0, Ordering::Relaxed);
                        let mut ts = peer.last_heartbeat_at.write().await;
                        *ts = Some(SystemTime::now());
                        let packet = Packet {
                            data: payload,
                            src_tag: Arc::clone(&self.tag_arc),
                            src_addr: Some(peer.addr),
                            conn_id,
                            proto: None,
                        };
                        if let Err(err) =
                            router.route_shared(packet, Arc::clone(&self.detour)).await
                        {
                            debug!("{} route dropped: {err}", self.tag);
                        }
                    }
                    Ok(UnwrappedFrame::Control { header, payload }) => match header.msg_type {
                        MSG_TYPE_AUTH_RESPONSE => {
                            if auth.process_auth_challenge(&payload).await.is_ok() {
                                peer.authenticated.store(true, Ordering::Relaxed);
                                peer.auth_retry_count.store(0, Ordering::Relaxed);
                                peer.heartbeat_miss_count.store(0, Ordering::Relaxed);
                                peer.send_refusal_count.store(0, Ordering::Relaxed);
                                *peer.last_heartbeat_at.write().await = Some(SystemTime::now());
                                info!("{} authenticated {}", self.tag, peer.addr);
                            }
                        }
                        MSG_TYPE_HEARTBEAT => {
                            let hb = auth.create_heartbeat(true);
                            let _ = peer.socket.send(&hb).await;
                            let mut ts = peer.last_heartbeat_at.write().await;
                            *ts = Some(SystemTime::now());
                            peer.heartbeat_miss_count.store(0, Ordering::Relaxed);
                            peer.send_refusal_count.store(0, Ordering::Relaxed);
                        }
                        MSG_TYPE_HEARTBEAT_ACK => {
                            let mut lock = peer.last_heartbeat_sent.write().await;
                            if let Some(sent) = lock.take() {
                                auth.record_delay(sent.elapsed()).await;
                            }
                            let mut ts = peer.last_heartbeat_at.write().await;
                            *ts = Some(SystemTime::now());
                            peer.heartbeat_miss_count.store(0, Ordering::Relaxed);
                            peer.send_refusal_count.store(0, Ordering::Relaxed);
                        }
                        MSG_TYPE_DATA => {}
                        _ => {}
                    },
                    Err(err) => debug!("{} unwrap error from {}: {err}", self.tag, peer.addr),
                }
            } else {
                let packet = Packet {
                    data: Bytes::copy_from_slice(&buffer[..n]),
                    src_tag: Arc::clone(&self.tag_arc),
                    src_addr: Some(peer.addr),
                    conn_id: 0,
                    proto: None,
                };
                if let Err(err) = router.route_shared(packet, Arc::clone(&self.detour)).await {
                    debug!("{} route dropped: {err}", self.tag);
                }
            }
        }

        peer.authenticated.store(false, Ordering::Relaxed);
        if self.running.load(Ordering::Relaxed) && self.detach_peer_if_current(&peer.remote, &peer)
        {
            warn!(
                "{} peer {} closed, waiting for reconnect",
                self.tag, peer.addr
            );
        }
    }

    fn detach_peer_if_current(&self, remote: &str, peer: &Arc<ForwardPeer>) -> bool {
        if let Some(current) = self.peers.get(remote) {
            if Arc::ptr_eq(current.value(), peer) {
                drop(current);
                self.peers.remove(remote);
                return true;
            }
        }
        false
    }

    fn mark_peer_for_reconnect(&self, remote: &str, peer: &Arc<ForwardPeer>, reason: &str) {
        peer.authenticated.store(false, Ordering::Relaxed);
        if self.detach_peer_if_current(remote, peer) {
            warn!(
                "{} peer {} marked for reconnect: {}",
                self.tag, peer.addr, reason
            );
        }
    }

    async fn reconcile_peers(self: &Arc<Self>, router: &Arc<Router>) {
        for addr in &self.forwarders {
            let resolved = match self.resolve_forwarder(addr).await {
                Ok(resolved) => resolved,
                Err(err) => {
                    debug!("{} resolve {} failed: {err}", self.tag, addr);
                    continue;
                }
            };

            let existing = self.peers.get(addr).map(|p| Arc::clone(p.value()));
            let mut reconnect_reason = None::<String>;

            match existing.as_ref() {
                Some(peer) if peer.addr != resolved => {
                    reconnect_reason =
                        Some(format!("target changed {} -> {}", peer.addr, resolved));
                }
                Some(peer) => {
                    if let Some(auth) = &self.auth {
                        if !peer.authenticated.load(Ordering::Relaxed) {
                            let retries = peer.auth_retry_count.load(Ordering::Relaxed);
                            if retries >= AUTH_RETRY_RECONNECT_THRESHOLD {
                                reconnect_reason =
                                    Some(format!("auth retries exhausted ({retries})"));
                            }
                        } else {
                            let last_heartbeat = *peer.last_heartbeat_at.read().await;
                            if let Some(ts) = last_heartbeat {
                                if let Ok(elapsed) = ts.elapsed() {
                                    let stale_for = auth.heartbeat_interval.saturating_mul(3);
                                    if elapsed >= stale_for {
                                        reconnect_reason =
                                            Some(format!("heartbeat stale for {elapsed:?}"));
                                    }
                                }
                            }
                        }
                    }
                }
                None => {
                    reconnect_reason = Some("missing peer".to_string());
                }
            }

            if let Some(reason) = reconnect_reason {
                if let Some(peer) = existing {
                    if self.detach_peer_if_current(addr, &peer) {
                        info!(
                            "{} peer {} removed before reconnect: {}",
                            self.tag, peer.addr, reason
                        );
                    }
                }
                info!("{} reconnect {}: {}", self.tag, addr, reason);
                match self.connect_one(router, addr, resolved).await {
                    Ok(()) => info!("{} reconnect {} succeeded", self.tag, addr),
                    Err(err) => warn!("{} reconnect {} failed: {err}", self.tag, addr),
                }
            }
        }
    }

    async fn auth_maintenance(&self, auth: &AuthManager) {
        for addr in &self.forwarders {
            let Some(peer) = self.peers.get(addr).map(|p| Arc::clone(p.value())) else {
                continue;
            };
            if peer.authenticated.load(Ordering::Relaxed) {
                let hb = auth.create_heartbeat(false);
                if let Err(err) = peer.socket.send(&hb).await {
                    self.mark_peer_for_reconnect(
                        addr,
                        &peer,
                        &format!("heartbeat send failed: {err}"),
                    );
                    continue;
                }

                let mut last = peer.last_heartbeat_sent.write().await;
                let misses = if last.is_some() {
                    peer.heartbeat_miss_count.fetch_add(1, Ordering::Relaxed) + 1
                } else {
                    peer.heartbeat_miss_count.load(Ordering::Relaxed)
                };
                *last = Some(Instant::now());

                if misses >= HEARTBEAT_MISS_REAUTH_THRESHOLD
                    && peer.authenticated.swap(false, Ordering::Relaxed)
                {
                    *last = None;
                    warn!(
                        "{} heartbeat miss {} on {}, switching to re-auth",
                        self.tag, misses, peer.addr
                    );
                }

                if misses >= HEARTBEAT_MISS_RECONNECT_THRESHOLD {
                    self.mark_peer_for_reconnect(
                        addr,
                        &peer,
                        &format!("heartbeat timeout ({misses} misses)"),
                    );
                }
            } else {
                let retries = peer.auth_retry_count.load(Ordering::Relaxed);
                if retries >= AUTH_RETRY_RECONNECT_THRESHOLD {
                    self.mark_peer_for_reconnect(
                        addr,
                        &peer,
                        &format!("auth retries exhausted ({retries})"),
                    );
                    continue;
                }

                let mut pool_id = [0u8; 8];
                rand::thread_rng().fill(&mut pool_id);
                if let Ok(challenge) = auth
                    .create_auth_challenge(
                        crate::auth::MSG_TYPE_AUTH_CHALLENGE,
                        self.forward_id,
                        pool_id,
                    )
                    .await
                {
                    let attempt = peer.auth_retry_count.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Err(err) = peer.socket.send(&challenge).await {
                        self.mark_peer_for_reconnect(
                            addr,
                            &peer,
                            &format!("auth challenge send failed: {err}"),
                        );
                    } else {
                        debug!(
                            "{} auth challenge {} attempt {}",
                            self.tag, peer.addr, attempt
                        );
                    }
                }
            }
        }
    }

    async fn keepalive_maintenance(&self) {
        for addr in &self.forwarders {
            let Some(peer) = self.peers.get(addr).map(|p| Arc::clone(p.value())) else {
                continue;
            };
            if !peer.has_traffic.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(err) = peer.socket.send(&[]).await {
                self.mark_peer_for_reconnect(addr, &peer, &format!("keepalive send failed: {err}"));
            }
        }
    }

    async fn connection_maintenance(self: Arc<Self>, router: Arc<Router>) {
        let mut reconnect_ticker = time::interval(self.reconnect_interval);
        reconnect_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Consume the immediate first tick to avoid sending maintenance traffic right after startup.
        reconnect_ticker.tick().await;

        if let Some(auth) = self.auth.clone() {
            let mut hb_ticker = time::interval(auth.heartbeat_interval);
            hb_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            hb_ticker.tick().await;

            while self.running.load(Ordering::Relaxed) {
                tokio::select! {
                    _ = reconnect_ticker.tick() => {
                        self.reconcile_peers(&router).await;
                    }
                    _ = hb_ticker.tick() => {
                        self.auth_maintenance(&auth).await;
                    }
                }
            }
            return;
        }

        if self.send_keepalive {
            let mut keepalive_ticker = time::interval(self.check_interval);
            keepalive_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            keepalive_ticker.tick().await;

            while self.running.load(Ordering::Relaxed) {
                tokio::select! {
                    _ = reconnect_ticker.tick() => {
                        self.reconcile_peers(&router).await;
                    }
                    _ = keepalive_ticker.tick() => {
                        self.keepalive_maintenance().await;
                    }
                }
            }
            return;
        }

        while self.running.load(Ordering::Relaxed) {
            reconnect_ticker.tick().await;
            self.reconcile_peers(&router).await;
        }
    }

    async fn resolve_forwarder(&self, addr_str: &str) -> Result<SocketAddr> {
        let mut addrs = lookup_host(addr_str)
            .await
            .map_err(|_| anyhow!("invalid forwarder addr {addr_str}"))?;
        addrs
            .next()
            .ok_or_else(|| anyhow!("invalid forwarder addr {addr_str}"))
    }

    async fn connect_one(
        self: &Arc<Self>,
        router: &Arc<Router>,
        addr_str: &str,
        addr: SocketAddr,
    ) -> Result<()> {
        let peer = self.create_peer(addr_str, addr).await?;

        if let Some(auth) = &self.auth {
            let mut pool_id = [0u8; 8];
            rand::thread_rng().fill(&mut pool_id);
            let challenge = auth
                .create_auth_challenge(
                    crate::auth::MSG_TYPE_AUTH_CHALLENGE,
                    self.forward_id,
                    pool_id,
                )
                .await?;
            peer.auth_retry_count.fetch_add(1, Ordering::Relaxed);
            let _ = peer.socket.send(&challenge).await?;
            info!(
                "{} peer {} connected (resolved {}, auth pending)",
                self.tag, addr_str, addr
            );
        } else {
            peer.authenticated.store(true, Ordering::Relaxed);
            info!(
                "{} peer {} connected (resolved {})",
                self.tag, addr_str, addr
            );
        }

        if let Some(old_peer) = self.peers.insert(addr_str.to_string(), Arc::clone(&peer)) {
            old_peer.authenticated.store(false, Ordering::Relaxed);
            info!(
                "{} peer {} replaced old connection {} -> {}",
                self.tag, addr_str, old_peer.addr, peer.addr
            );
        }
        tokio::spawn(Arc::clone(self).read_loop(Arc::clone(router), peer));
        Ok(())
    }

    pub fn api_info(&self) -> Value {
        json!({
            "tag": self.tag,
            "type": "forward",
            "forwarders": self.forwarders,
            "reconnect_interval": self.reconnect_interval.as_secs(),
            "connection_check_time": self.check_interval.as_secs(),
            "send_keepalive": self.send_keepalive,
            "detour": self.detour.to_vec(),
        })
    }

    pub async fn api_connections(&self) -> Value {
        let has_auth = self.auth.is_some();
        let mut connections = Vec::with_capacity(self.forwarders.len());
        for remote in &self.forwarders {
            if let Some(peer) = self.peers.get(remote) {
                let last_heartbeat = peer
                    .last_heartbeat_at
                    .read()
                    .await
                    .as_ref()
                    .map(|v| format_system_time(*v));
                let mut entry = json!({
                    "remote_addr": remote,
                    "resolved_addr": peer.addr.to_string(),
                    "resolved_ip": peer.addr.ip().to_string(),
                    "is_connected": true,
                    "last_reconnect": format_system_time(peer.last_reconnect_at),
                    "auth_retry_count": peer.auth_retry_count.load(Ordering::Relaxed),
                    "heartbeat_miss": peer.heartbeat_miss_count.load(Ordering::Relaxed),
                    "last_heartbeat": last_heartbeat,
                });
                if has_auth {
                    entry["is_authenticated"] = json!(peer.authenticated.load(Ordering::Relaxed));
                }
                connections.push(entry);
            } else {
                connections.push(json!({
                    "remote_addr": remote,
                    "resolved_addr": Value::Null,
                    "resolved_ip": Value::Null,
                    "is_connected": false,
                    "last_reconnect": Value::Null,
                    "auth_retry_count": 0,
                    "heartbeat_miss": 0,
                    "last_heartbeat": Value::Null,
                }));
            }
        }

        let mut out = json!({
            "tag": self.tag,
            "connections": connections,
            "count": connections.len(),
        });
        if let Some(auth) = &self.auth {
            out["average_delay_ms"] = json!(auth.average_delay_ms().await);
        }
        out
    }
}

#[async_trait]
impl Component for ForwardComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(self: Arc<Self>, router: Arc<Router>) -> Result<()> {
        self.running.store(true, Ordering::Relaxed);

        for addr in &self.forwarders {
            let resolved = match self.resolve_forwarder(addr).await {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!("{} connect {} failed: {err}", self.tag, addr);
                    continue;
                }
            };
            match self.connect_one(&router, addr, resolved).await {
                Ok(()) => info!("{} connected {}", self.tag, addr),
                Err(err) => warn!("{} connect {} failed: {err}", self.tag, addr),
            }
        }

        tokio::spawn(Arc::clone(&self).connection_maintenance(Arc::clone(&router)));

        info!("{} forwarding to {:?}", self.tag, self.forwarders);
        Ok(())
    }

    async fn handle_packet(&self, _router: &Router, packet: Packet) -> Result<()> {
        let payload = if let Some(auth) = &self.auth {
            auth.wrap_data(packet.conn_id, &packet.data)?
        } else {
            packet.data
        };

        for addr in &self.forwarders {
            let Some(peer) = self.peers.get(addr).map(|p| Arc::clone(p.value())) else {
                continue;
            };
            if self.auth.is_some() && !peer.authenticated.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(err) = peer.socket.send(&payload).await {
                let kind = err.kind();
                // Linux/WSL can transiently return ConnectionRefused for UDP when the
                // remote port has just restarted or is not ready yet. Dropping the peer
                // immediately causes avoidable outages during integration tests.
                if kind == std::io::ErrorKind::ConnectionRefused {
                    let refusals = peer.send_refusal_count.fetch_add(1, Ordering::Relaxed) + 1;
                    warn!(
                        "{} transient send refusal to {} (count {}): {err}",
                        self.tag, peer.addr, refusals
                    );
                    if refusals >= SEND_REFUSAL_RECONNECT_THRESHOLD {
                        self.mark_peer_for_reconnect(
                            addr,
                            &peer,
                            &format!("consecutive send refusal ({refusals})"),
                        );
                    }
                    continue;
                }
                self.mark_peer_for_reconnect(addr, &peer, &format!("send failed: {err}"));
            } else {
                peer.has_traffic.store(true, Ordering::Relaxed);
                peer.send_refusal_count.store(0, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.forwarders.iter().any(|addr| {
            self.peers
                .get(addr)
                .map(|p| p.authenticated.load(Ordering::Relaxed))
                .unwrap_or(false)
        })
    }

    async fn average_delay_ms(&self) -> f64 {
        if let Some(auth) = &self.auth {
            return auth.average_delay_ms().await;
        }
        f64::INFINITY
    }
}
