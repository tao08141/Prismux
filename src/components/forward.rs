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
    auth_retry_count: AtomicU32,
    heartbeat_miss_count: AtomicU32,
    last_reconnect_at: SystemTime,
    last_heartbeat_at: RwLock<Option<SystemTime>>,
    last_heartbeat_sent: RwLock<Option<Instant>>,
}

pub struct ForwardComponent {
    tag: String,
    tag_arc: Arc<str>,
    detour: Arc<[String]>,
    forwarders: Vec<String>,
    reconnect_interval: Duration,
    check_interval: Duration,
    send_keepalive: bool,
    send_timeout: Duration,
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
        let send_timeout = Duration::from_millis(cfg.send_timeout.max(1));
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
            send_timeout,
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
            auth_retry_count: AtomicU32::new(0),
            heartbeat_miss_count: AtomicU32::new(0),
            last_reconnect_at: SystemTime::now(),
            last_heartbeat_at: RwLock::new(None),
            last_heartbeat_sent: RwLock::new(None),
        }))
    }

    async fn read_loop(self: Arc<Self>, router: Arc<Router>, peer: Arc<ForwardPeer>) {
        let mut buffer =
            vec![0u8; router.config.buffer_size.max(2048) + router.config.buffer_offset];

        while self.running.load(Ordering::Relaxed) {
            let recv = peer.socket.recv(&mut buffer).await;
            let Ok(n) = recv else {
                break;
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
                            }
                        }
                        MSG_TYPE_HEARTBEAT => {
                            let hb = auth.create_heartbeat(true);
                            let _ = peer.socket.send(&hb).await;
                            let mut ts = peer.last_heartbeat_at.write().await;
                            *ts = Some(SystemTime::now());
                        }
                        MSG_TYPE_HEARTBEAT_ACK => {
                            let mut lock = peer.last_heartbeat_sent.write().await;
                            if let Some(sent) = lock.take() {
                                auth.record_delay(sent.elapsed()).await;
                            }
                            let mut ts = peer.last_heartbeat_at.write().await;
                            *ts = Some(SystemTime::now());
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
        if let Some(current) = self.peers.get(&peer.remote) {
            if Arc::ptr_eq(current.value(), &peer) {
                drop(current);
                self.peers.remove(&peer.remote);
            }
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

            let needs_connect = match self.peers.get(addr) {
                Some(peer) if peer.addr == resolved => false,
                Some(peer) => {
                    debug!(
                        "{} forwarder {} changed {} -> {}, reconnecting",
                        self.tag, addr, peer.addr, resolved
                    );
                    true
                }
                None => true,
            };

            if needs_connect {
                if let Some((_, old_peer)) = self.peers.remove(addr) {
                    old_peer.authenticated.store(false, Ordering::Relaxed);
                }
                if let Err(err) = self.connect_one(router, addr, resolved).await {
                    debug!("{} reconnect {} failed: {err}", self.tag, addr);
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
                let _ = peer.socket.send(&hb).await;
                let mut last = peer.last_heartbeat_sent.write().await;
                if last.is_some() {
                    peer.heartbeat_miss_count.fetch_add(1, Ordering::Relaxed);
                }
                *last = Some(Instant::now());
                let mut ts = peer.last_heartbeat_at.write().await;
                *ts = Some(SystemTime::now());
            } else {
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
                    peer.auth_retry_count.fetch_add(1, Ordering::Relaxed);
                    let _ = peer.socket.send(&challenge).await;
                }
            }
        }
    }

    async fn keepalive_maintenance(&self) {
        for addr in &self.forwarders {
            let Some(peer) = self.peers.get(addr).map(|p| Arc::clone(p.value())) else {
                continue;
            };
            let _ = peer.socket.send(&[]).await;
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
        } else {
            peer.authenticated.store(true, Ordering::Relaxed);
        }

        if let Some(old_peer) = self.peers.insert(addr_str.to_string(), Arc::clone(&peer)) {
            old_peer.authenticated.store(false, Ordering::Relaxed);
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
            if let Err(err) = self.connect_one(&router, addr, resolved).await {
                warn!("{} connect {} failed: {err}", self.tag, addr);
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
                peer.authenticated.store(false, Ordering::Relaxed);
                if let Some(current) = self.peers.get(addr) {
                    if Arc::ptr_eq(current.value(), &peer) {
                        drop(current);
                        self.peers.remove(addr);
                    }
                }
                warn!("{} send to {} failed: {err}", self.tag, peer.addr);
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
