use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_CHALLENGE, MSG_TYPE_DATA, MSG_TYPE_DISCONNECT,
        MSG_TYPE_HEARTBEAT, MSG_TYPE_HEARTBEAT_ACK, MSG_TYPE_AUTH_RESPONSE,
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

struct ListenConn {
    conn_id: u64,
    last_active: Instant,
    authenticated: bool,
    last_heartbeat_sent: Option<Instant>,
}

pub struct ListenComponent {
    tag: String,
    listen_addr: String,
    timeout: Duration,
    replace_old_mapping: bool,
    detour: Vec<String>,
    broadcast_mode: bool,
    send_timeout: Duration,
    auth: Option<AuthManager>,
    socket: RwLock<Option<Arc<UdpSocket>>>,
    mappings: DashMap<SocketAddr, ListenConn>,
    running: AtomicBool,
}

impl ListenComponent {
    pub fn new(cfg: ComponentConfig) -> Result<Arc<Self>> {
        let timeout = Duration::from_secs(cfg.timeout.max(1));
        let send_timeout = Duration::from_millis(cfg.send_timeout.max(1));
        let auth = AuthManager::from_config(cfg.auth.as_ref())?;

        Ok(Arc::new(Self {
            tag: cfg.tag,
            listen_addr: cfg.listen_addr,
            timeout,
            replace_old_mapping: cfg.replace_old_mapping,
            detour: cfg.detour,
            broadcast_mode: cfg.broadcast_mode.unwrap_or(true),
            send_timeout,
            auth,
            socket: RwLock::new(None),
            mappings: DashMap::new(),
            running: AtomicBool::new(false),
        }))
    }

    async fn reader_loop(self: Arc<Self>, router: Arc<Router>, socket: Arc<UdpSocket>) {
        let mut buffer = vec![0u8; router.config.buffer_size.max(2048) + router.config.buffer_offset];

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
            self.mappings.retain(|_, conn| conn.last_active.elapsed() <= timeout);
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
                Ok(UnwrappedFrame::Control { header, payload }) => {
                    match header.msg_type {
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

                            self.upsert_mapping(addr, true, 0);
                            return Ok(());
                        }
                        MSG_TYPE_HEARTBEAT => {
                            let hb = auth.create_heartbeat(true);
                            socket.send_to(&hb, addr).await?;
                            if let Some(mut mapping) = self.mappings.get_mut(&addr) {
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
                            self.mappings.remove(&addr);
                            return Ok(());
                        }
                        MSG_TYPE_DATA => unreachable!(),
                        _ => return Ok(()),
                    }
                }
                Err(err) => return Err(err),
            }
        } else {
            let conn_id = self.upsert_mapping(addr, false, 0);
            (Bytes::copy_from_slice(datagram), conn_id)
        };

        let packet = Packet {
            data: payload,
            src_tag: Arc::from(self.tag.as_str()),
            src_addr: Some(addr),
            conn_id,
            proto: None,
        };

        router.route(packet, &self.detour)
    }

    fn upsert_mapping(&self, addr: SocketAddr, authenticated: bool, conn_override: u64) -> u64 {
        if let Some(mut existing) = self.mappings.get_mut(&addr) {
            existing.last_active = Instant::now();
            if authenticated {
                existing.authenticated = true;
            }
            if conn_override != 0 {
                existing.conn_id = conn_override;
            }
            return existing.conn_id;
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
                self.mappings.remove(&old);
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
        conn_id
    }

    async fn socket(&self) -> Result<Arc<UdpSocket>> {
        let lock = self.socket.read().await;
        lock.as_ref().cloned().ok_or_else(|| anyhow!("listener socket not initialized"))
    }
}

#[async_trait]
impl Component for ListenComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, router: Arc<Router>) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(&self.listen_addr).await?);
        socket.set_broadcast(true)?;
        {
            let mut lock = self.socket.write().await;
            *lock = Some(Arc::clone(&socket));
        }

        self.running.store(true, Ordering::Relaxed);
        info!("{} listening on {}", self.tag, self.listen_addr);

        tokio::spawn(Arc::clone(&self).reader_loop(Arc::clone(&router), Arc::clone(&socket)));
        tokio::spawn(Arc::clone(&self).cleanup_loop());

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
            for conn in self.mappings.iter() {
                if self.auth.is_some() && !conn.authenticated {
                    continue;
                }
                match socket.send_to(&payload, *conn.key()).await {
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
                let _ = socket.send_to(&payload, addr).await;
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
