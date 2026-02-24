use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_CHALLENGE, MSG_TYPE_AUTH_RESPONSE,
        MSG_TYPE_DATA, MSG_TYPE_DISCONNECT, MSG_TYPE_HEARTBEAT, MSG_TYPE_HEARTBEAT_ACK,
    },
    component::Component,
    config::ComponentConfig,
    packet::Packet,
    router::Router,
    timefmt::format_from_elapsed,
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
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::RwLock as TokioRwLock,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

struct ListenConn {
    conn_id: u64,
    last_active: Instant,
    authenticated: bool,
    last_heartbeat_sent: Option<Instant>,
}

pub struct ListenComponent {
    tag: String,
    tag_arc: Arc<str>,
    listen_addr: String,
    timeout: Duration,
    replace_old_mapping: bool,
    detour: Arc<[String]>,
    broadcast_mode: bool,
    recv_buffer_size: usize,
    send_buffer_size: usize,
    auth: Option<AuthManager>,
    socket: TokioRwLock<Option<Arc<UdpSocket>>>,
    mappings: DashMap<SocketAddr, ListenConn>,
    broadcast_targets: RwLock<Arc<[SocketAddr]>>,
    running: AtomicBool,
}

impl ListenComponent {
    pub fn new(cfg: ComponentConfig) -> Result<Arc<Self>> {
        let timeout = Duration::from_secs(cfg.timeout.max(1));
        let recv_buffer_size = cfg.recv_buffer_size.max(2 * 1024 * 1024);
        let send_buffer_size = cfg.send_buffer_size.max(2 * 1024 * 1024);
        let auth = AuthManager::from_config(cfg.auth.as_ref())?;
        let tag = cfg.tag;
        let tag_arc = Arc::<str>::from(tag.as_str());

        Ok(Arc::new(Self {
            tag,
            tag_arc,
            listen_addr: cfg.listen_addr,
            timeout,
            replace_old_mapping: cfg.replace_old_mapping,
            detour: Arc::<[String]>::from(cfg.detour),
            broadcast_mode: cfg.broadcast_mode.unwrap_or(true),
            recv_buffer_size,
            send_buffer_size,
            auth,
            socket: TokioRwLock::new(None),
            mappings: DashMap::new(),
            broadcast_targets: RwLock::new(Arc::from(Vec::<SocketAddr>::new().into_boxed_slice())),
            running: AtomicBool::new(false),
        }))
    }

    async fn reader_loop(self: Arc<Self>, router: Arc<Router>, socket: Arc<UdpSocket>) {
        let mut buffer =
            vec![0u8; router.config.buffer_size.max(2048) + router.config.buffer_offset];

        while self.running.load(Ordering::Relaxed) {
            let recv = socket.recv_from(&mut buffer).await;
            let Ok((n, addr)) = recv else {
                continue;
            };
            if n == 0 {
                continue;
            }

            if let Err(err) = self
                .handle_inbound(&router, &socket, addr, &buffer[..n])
                .await
            {
                debug!("{} inbound dropped: {err}", self.tag);
            }
        }
    }

    async fn cleanup_loop(self: Arc<Self>) {
        let mut ticker = time::interval(self.timeout / 2);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        while self.running.load(Ordering::Relaxed) {
            ticker.tick().await;
            let timeout = self.timeout;
            let expired: Vec<(SocketAddr, u64)> = self
                .mappings
                .iter()
                .filter_map(|entry| {
                    (entry.value().last_active.elapsed() > timeout)
                        .then_some((*entry.key(), entry.value().conn_id))
                })
                .collect();
            if !expired.is_empty() {
                for (addr, conn_id) in expired {
                    if self.mappings.remove(&addr).is_some() {
                        info!(
                            "{} disconnected {} conn_id={} reason=idle-timeout",
                            self.tag, addr, conn_id
                        );
                    }
                }
                self.refresh_broadcast_targets();
            }
        }
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        let Some(auth) = self.auth.clone() else {
            return;
        };
        let mut ticker = time::interval(auth.heartbeat_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;

        while self.running.load(Ordering::Relaxed) {
            ticker.tick().await;

            let socket = match self.socket().await {
                Ok(socket) => socket,
                Err(_) => continue,
            };

            let targets: Vec<SocketAddr> = self
                .mappings
                .iter()
                .filter_map(|entry| entry.authenticated.then_some(*entry.key()))
                .collect();

            for addr in targets {
                let hb = auth.create_heartbeat(false);
                if socket.send_to(&hb, addr).await.is_ok() {
                    if let Some(mut mapping) = self.mappings.get_mut(&addr) {
                        mapping.last_heartbeat_sent = Some(Instant::now());
                    }
                }
            }
        }
    }

    async fn handle_inbound(
        &self,
        router: &Router,
        socket: &UdpSocket,
        addr: SocketAddr,
        datagram: &[u8],
    ) -> Result<()> {
        let (payload, conn_id) = if let Some(auth) = &self.auth {
            match auth.unwrap_frame(datagram) {
                Ok(UnwrappedFrame::Data { conn_id, payload }) => {
                    let Some(mut mapping) = self.mappings.get_mut(&addr) else {
                        return Err(anyhow!("unauthenticated data"));
                    };
                    if !mapping.authenticated {
                        return Err(anyhow!("unauthenticated data"));
                    }
                    mapping.last_active = Instant::now();
                    (payload, conn_id)
                }
                Ok(UnwrappedFrame::Control { header, payload }) => match header.msg_type {
                    MSG_TYPE_AUTH_CHALLENGE => {
                        let (_forward_id, _pool_id) = auth.process_auth_challenge(&payload).await?;
                        let mut forward_id = [0u8; 8];
                        let mut pool_id = [0u8; 8];
                        rand::thread_rng().fill(&mut forward_id);
                        rand::thread_rng().fill(&mut pool_id);
                        let resp = auth
                            .create_auth_challenge(MSG_TYPE_AUTH_RESPONSE, forward_id, pool_id)
                            .await?;
                        socket.send_to(&resp, addr).await?;

                        let (_, changed) = self.upsert_mapping(addr, true, 0);
                        if changed {
                            self.refresh_broadcast_targets();
                        }
                        return Ok(());
                    }
                    MSG_TYPE_HEARTBEAT => {
                        if let Some(mut mapping) = self.mappings.get_mut(&addr) {
                            if !mapping.authenticated {
                                return Ok(());
                            }
                            let hb = auth.create_heartbeat(true);
                            socket.send_to(&hb, addr).await?;
                            mapping.last_active = Instant::now();
                        }
                        return Ok(());
                    }
                    MSG_TYPE_HEARTBEAT_ACK => {
                        if let Some(mut mapping) = self.mappings.get_mut(&addr) {
                            mapping.last_active = Instant::now();
                            if let Some(sent_at) = mapping.last_heartbeat_sent.take() {
                                auth.record_delay(sent_at.elapsed()).await;
                            }
                        }
                        return Ok(());
                    }
                    MSG_TYPE_DISCONNECT => {
                        if let Some((_, conn)) = self.mappings.remove(&addr) {
                            info!(
                                "{} disconnected {} conn_id={} reason=peer-disconnect",
                                self.tag, addr, conn.conn_id
                            );
                            self.refresh_broadcast_targets();
                        }
                        return Ok(());
                    }
                    MSG_TYPE_DATA => unreachable!(),
                    _ => return Ok(()),
                },
                Err(err) => return Err(err),
            }
        } else {
            let (conn_id, changed) = self.upsert_mapping(addr, false, 0);
            if changed {
                self.refresh_broadcast_targets();
            }
            (Bytes::copy_from_slice(datagram), conn_id)
        };

        let packet = Packet {
            data: payload,
            src_tag: Arc::clone(&self.tag_arc),
            src_addr: Some(addr),
            conn_id,
            proto: None,
        };

        router.route_shared(packet, Arc::clone(&self.detour)).await
    }

    fn upsert_mapping(
        &self,
        addr: SocketAddr,
        authenticated: bool,
        conn_override: u64,
    ) -> (u64, bool) {
        if let Some(mut existing) = self.mappings.get_mut(&addr) {
            let mut changed = false;
            existing.last_active = Instant::now();
            if authenticated && !existing.authenticated {
                existing.authenticated = true;
                changed = true;
                info!(
                    "{} connection {} conn_id={} authenticated",
                    self.tag, addr, existing.conn_id
                );
            }
            if conn_override != 0 && existing.conn_id != conn_override {
                existing.conn_id = conn_override;
                changed = true;
            }
            return (existing.conn_id, changed);
        }

        if self.replace_old_mapping {
            let same_ip: Vec<SocketAddr> = self
                .mappings
                .iter()
                .filter_map(|entry| {
                    if entry.key().ip() == addr.ip() {
                        Some(*entry.key())
                    } else {
                        None
                    }
                })
                .collect();
            for old in same_ip {
                if let Some((_, old_conn)) = self.mappings.remove(&old) {
                    info!(
                        "{} disconnected {} conn_id={} reason=replaced-by-new-connection {}",
                        self.tag, old, old_conn.conn_id, addr
                    );
                }
            }
        }

        let conn_id = if conn_override == 0 {
            rand::thread_rng().gen::<u64>()
        } else {
            conn_override
        };

        self.mappings.insert(
            addr,
            ListenConn {
                conn_id,
                last_active: Instant::now(),
                authenticated,
                last_heartbeat_sent: None,
            },
        );
        info!(
            "{} connected {} conn_id={} authenticated={}",
            self.tag, addr, conn_id, authenticated
        );
        (conn_id, true)
    }

    fn refresh_broadcast_targets(&self) {
        let mut targets = Vec::with_capacity(self.mappings.len());
        for conn in self.mappings.iter() {
            if self.auth.is_some() && !conn.authenticated {
                continue;
            }
            targets.push(*conn.key());
        }
        if let Ok(mut lock) = self.broadcast_targets.write() {
            *lock = Arc::from(targets.into_boxed_slice());
        }
    }

    async fn socket(&self) -> Result<Arc<UdpSocket>> {
        let lock = self.socket.read().await;
        lock.as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("listener socket not initialized"))
    }

    pub fn api_info(&self) -> Value {
        json!({
            "tag": self.tag,
            "type": "listen",
            "listen_addr": self.listen_addr,
            "timeout": self.timeout.as_secs(),
            "replace_old_mapping": self.replace_old_mapping,
            "detour": self.detour.to_vec(),
        })
    }

    pub async fn api_connections(&self) -> Value {
        let has_auth = self.auth.is_some();
        let mut connections = Vec::with_capacity(self.mappings.len());

        for entry in self.mappings.iter() {
            let conn = entry.value();
            let addr = *entry.key();
            let mut item = json!({
                "address": addr.to_string(),
                "ip": addr.ip().to_string(),
                "port": addr.port(),
                "connection_id": format!("{:016x}", conn.conn_id),
                "last_active": format_from_elapsed(conn.last_active.elapsed()),
            });
            if has_auth {
                item["is_authenticated"] = json!(conn.authenticated);
            }
            connections.push(item);
        }

        let mut out = json!({
            "tag": self.tag,
            "listen_addr": self.listen_addr,
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
impl Component for ListenComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(self: Arc<Self>, router: Arc<Router>) -> Result<()> {
        let std_socket = StdUdpSocket::bind(&self.listen_addr)?;
        std_socket.set_nonblocking(true)?;
        let sock_ref = SockRef::from(&std_socket);
        let _ = sock_ref.set_recv_buffer_size(self.recv_buffer_size);
        let _ = sock_ref.set_send_buffer_size(self.send_buffer_size);

        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        socket.set_broadcast(true)?;
        {
            let mut lock = self.socket.write().await;
            *lock = Some(Arc::clone(&socket));
        }

        self.running.store(true, Ordering::Relaxed);
        info!("{} listening on {}", self.tag, self.listen_addr);

        tokio::spawn(Arc::clone(&self).reader_loop(Arc::clone(&router), Arc::clone(&socket)));
        tokio::spawn(Arc::clone(&self).cleanup_loop());
        if self.auth.is_some() {
            tokio::spawn(Arc::clone(&self).heartbeat_loop());
        }

        Ok(())
    }

    async fn handle_packet(&self, _router: &Router, packet: Packet) -> Result<()> {
        let socket = self.socket().await?;

        let payload = if let Some(auth) = &self.auth {
            auth.wrap_data(packet.conn_id, &packet.data)?
        } else {
            packet.data
        };

        if self.broadcast_mode {
            let mut sent = 0usize;
            let targets = self
                .broadcast_targets
                .read()
                .ok()
                .map(|g| Arc::clone(&*g))
                .unwrap_or_else(|| Arc::from(Vec::<SocketAddr>::new().into_boxed_slice()));
            for addr in targets.iter() {
                match socket.send_to(&payload, *addr).await {
                    Ok(_) => sent += 1,
                    Err(err) => warn!("{} send error: {err}", self.tag),
                }
            }
            if sent == 0 {
                debug!("{} dropped packet: no active clients", self.tag);
            }
        } else {
            let target = self
                .mappings
                .iter()
                .find_map(|entry| (entry.conn_id == packet.conn_id).then_some(*entry.key()));

            if let Some(addr) = target {
                if let Err(err) = socket.send_to(&payload, addr).await {
                    warn!("{} send error to {}: {err}", self.tag, addr);
                }
            }
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.running.load(Ordering::Relaxed) && !self.mappings.is_empty()
    }

    async fn average_delay_ms(&self) -> f64 {
        if let Some(auth) = &self.auth {
            return auth.average_delay_ms().await;
        }
        f64::INFINITY
    }
}
