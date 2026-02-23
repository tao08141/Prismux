use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_RESPONSE, MSG_TYPE_DATA, MSG_TYPE_HEARTBEAT,
        MSG_TYPE_HEARTBEAT_ACK,
    },
    component::Component,
    config::ComponentConfig,
    packet::Packet,
    router::Router,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use rand::Rng;
use std::{
    net::SocketAddr,
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::RwLock,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

struct ForwardPeer {
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    authenticated: AtomicBool,
    last_heartbeat_sent: RwLock<Option<Instant>>,
}

pub struct ForwardComponent {
    tag: String,
    detour: Vec<String>,
    forwarders: Vec<String>,
    reconnect_interval: Duration,
    check_interval: Duration,
    send_keepalive: bool,
    send_timeout: Duration,
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
        let send_keepalive = cfg.send_keepalive.unwrap_or(true);

        let mut forward_id = [0u8; 8];
        rand::thread_rng().fill(&mut forward_id);

        Ok(Arc::new(Self {
            tag: cfg.tag,
            detour: cfg.detour,
            forwarders: cfg.forwarders,
            reconnect_interval,
            check_interval,
            send_keepalive,
            send_timeout,
            auth,
            peers: DashMap::new(),
            running: AtomicBool::new(false),
            forward_id,
        }))
    }

    async fn create_peer(addr: SocketAddr) -> Result<Arc<ForwardPeer>> {
        let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        socket.connect(addr).await?;

        Ok(Arc::new(ForwardPeer {
            addr,
            socket,
            authenticated: AtomicBool::new(false),
            last_heartbeat_sent: RwLock::new(None),
        }))
    }

    async fn read_loop(self: Arc<Self>, router: Arc<Router>, peer: Arc<ForwardPeer>) {
        let mut buffer = vec![0u8; router.config.buffer_size.max(2048) + router.config.buffer_offset];

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
                            src_tag: Arc::from(self.tag.as_str()),
                            src_addr: Some(peer.addr),
                            conn_id,
                            proto: None,
                        };
                        if let Err(err) = router.route(packet, &self.detour) {
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
                        }
                        MSG_TYPE_HEARTBEAT_ACK => {
                            let mut lock = peer.last_heartbeat_sent.write().await;
                            if let Some(sent) = lock.take() {
                                auth.record_delay(sent.elapsed()).await;
                            }
                        }
                        MSG_TYPE_DATA => {}
                        _ => {}
                    },
                    Err(err) => debug!("{} unwrap error from {}: {err}", self.tag, peer.addr),
                }
            } else {
                let packet = Packet {
                    data: Bytes::copy_from_slice(&buffer[..n]),
                    src_tag: Arc::from(self.tag.as_str()),
                    src_addr: Some(peer.addr),
                    conn_id: 0,
                    proto: None,
                };
                if let Err(err) = router.route(packet, &self.detour) {
                    debug!("{} route dropped: {err}", self.tag);
                }
            }
        }

        peer.authenticated.store(false, Ordering::Relaxed);
    }

    async fn connection_maintenance(self: Arc<Self>) {
        let mut ticker = time::interval(self.check_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        while self.running.load(Ordering::Relaxed) {
            ticker.tick().await;

            for addr in &self.forwarders {
                if !self.peers.contains_key(addr) {
                    if let Err(err) = self.connect_one(addr).await {
                        debug!("{} reconnect {} failed: {err}", self.tag, addr);
                    }
                }
            }

            if let Some(auth) = &self.auth {
                for peer in self.peers.iter() {
                    if peer.authenticated.load(Ordering::Relaxed) {
                        let hb = auth.create_heartbeat(false);
                        let _ = peer.socket.send(&hb).await;
                        let mut last = peer.last_heartbeat_sent.write().await;
                        *last = Some(Instant::now());
                    } else {
                        let mut pool_id = [0u8; 8];
                        rand::thread_rng().fill(&mut pool_id);
                        if let Ok(challenge) = auth
                            .create_auth_challenge(crate::auth::MSG_TYPE_AUTH_CHALLENGE, self.forward_id, pool_id)
                            .await
                        {
                            let _ = peer.socket.send(&challenge).await;
                        }
                    }
                }
            } else if self.send_keepalive {
                for peer in self.peers.iter() {
                    let _ = peer.socket.send(&[]).await;
                }
            }
        }
    }

    async fn connect_one(self: &Arc<Self>, addr_str: &str) -> Result<()> {
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|_| anyhow!("invalid forwarder addr {addr_str}"))?;

        let peer = Self::create_peer(addr).await?;

        if let Some(auth) = &self.auth {
            let mut pool_id = [0u8; 8];
            rand::thread_rng().fill(&mut pool_id);
            let challenge = auth
                .create_auth_challenge(crate::auth::MSG_TYPE_AUTH_CHALLENGE, self.forward_id, pool_id)
                .await?;
            let _ = peer.socket.send(&challenge).await?;
        } else {
            peer.authenticated.store(true, Ordering::Relaxed);
        }

        self.peers.insert(addr_str.to_string(), Arc::clone(&peer));
        Ok(())
    }
}

#[async_trait]
impl Component for ForwardComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, router: Arc<Router>) -> Result<()> {
        self.running.store(true, Ordering::Relaxed);

        for addr in &self.forwarders {
            if let Err(err) = self.connect_one(addr).await {
                warn!("{} connect {} failed: {err}", self.tag, addr);
            }
        }

        for peer in self.peers.iter() {
            tokio::spawn(Arc::clone(&self).read_loop(Arc::clone(&router), Arc::clone(peer.value())));
        }

        tokio::spawn(Arc::clone(&self).connection_maintenance());

        info!("{} forwarding to {:?}", self.tag, self.forwarders);
        Ok(())
    }

    async fn handle_packet(&self, _router: &Router, packet: Packet) -> Result<()> {
        let payload = if let Some(auth) = &self.auth {
            auth.wrap_data(packet.conn_id, &packet.data)?
        } else {
            packet.data
        };

        for peer in self.peers.iter() {
            if self.auth.is_some() && !peer.authenticated.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(err) = peer.socket.send(&payload).await {
                peer.authenticated.store(false, Ordering::Relaxed);
                warn!("{} send to {} failed: {err}", self.tag, peer.addr);
            }
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.peers
            .iter()
            .any(|p| p.authenticated.load(Ordering::Relaxed))
    }

    async fn average_delay_ms(&self) -> f64 {
        if let Some(auth) = &self.auth {
            return auth.average_delay_ms().await;
        }
        f64::INFINITY
    }
}
