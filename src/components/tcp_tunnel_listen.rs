use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_CHALLENGE, MSG_TYPE_HEARTBEAT,
        MSG_TYPE_HEARTBEAT_ACK,
    },
    component::Component,
    config::ComponentConfig,
    packet::Packet,
    router::Router,
    tcp_frame::{read_frame_into, write_frame},
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rand::Rng;
use socket2::SockRef;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock},
    time,
};
use tracing::{debug, info};

struct TunnelListenConn {
    tx: mpsc::Sender<Bytes>,
    authenticated: AtomicBool,
    conn_id_hint: AtomicU64,
    forward_id: AtomicU64,
    pool_id: AtomicU64,
    last_active: RwLock<Instant>,
    last_heartbeat_sent: RwLock<Option<Instant>>,
}

pub struct TcpTunnelListenComponent {
    tag: String,
    tag_arc: Arc<str>,
    listen_addr: String,
    detour: Arc<[String]>,
    auth: AuthManager,
    send_timeout: Duration,
    no_delay: bool,
    recv_buffer_size: usize,
    send_buffer_size: usize,
    broadcast_mode: bool,
    running: AtomicBool,
    conns: DashMap<u64, Arc<TunnelListenConn>>,
    next_id: AtomicU64,
}

impl TcpTunnelListenComponent {
    pub fn new(cfg: ComponentConfig) -> Result<Arc<Self>> {
        let auth = AuthManager::from_config(cfg.auth.as_ref())?
            .ok_or_else(|| anyhow!("tcp_tunnel_listen requires auth.enabled=true"))?;
        let tag = cfg.tag;
        let tag_arc = Arc::<str>::from(tag.as_str());
        let no_delay = cfg.no_delay.unwrap_or(true);
        let recv_buffer_size = cfg.recv_buffer_size.max(2 * 1024 * 1024);
        let send_buffer_size = cfg.send_buffer_size.max(2 * 1024 * 1024);

        Ok(Arc::new(Self {
            tag,
            tag_arc,
            listen_addr: cfg.listen_addr,
            detour: Arc::<[String]>::from(cfg.detour),
            auth,
            send_timeout: Duration::from_millis(if cfg.send_timeout == 0 {
                500
            } else {
                cfg.send_timeout
            }),
            no_delay,
            recv_buffer_size,
            send_buffer_size,
            broadcast_mode: cfg.broadcast_mode.unwrap_or(true),
            running: AtomicBool::new(false),
            conns: DashMap::new(),
            next_id: AtomicU64::new(1),
        }))
    }

    async fn accept_loop(self: Arc<Self>, router: Arc<Router>, listener: TcpListener) {
        while self.running.load(Ordering::Relaxed) {
            let accept = listener.accept().await;
            let Ok((stream, remote)) = accept else {
                continue;
            };
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            info!("{} accepted TCP tunnel from {}", self.tag, remote);
            tokio::spawn(Arc::clone(&self).handle_stream(Arc::clone(&router), id, stream));
        }
    }

    async fn handle_stream(self: Arc<Self>, router: Arc<Router>, id: u64, stream: TcpStream) {
        let std_stream = match stream.into_std() {
            Ok(s) => s,
            Err(err) => {
                debug!("{} failed to convert tcp stream: {err}", self.tag);
                return;
            }
        };
        let _ = std_stream.set_nonblocking(true);
        let _ = std_stream.set_nodelay(self.no_delay);
        let sock_ref = SockRef::from(&std_stream);
        let _ = sock_ref.set_recv_buffer_size(self.recv_buffer_size);
        let _ = sock_ref.set_send_buffer_size(self.send_buffer_size);
        let stream = match TcpStream::from_std(std_stream) {
            Ok(s) => s,
            Err(err) => {
                debug!("{} failed to restore tokio tcp stream: {err}", self.tag);
                return;
            }
        };
        let (mut reader, mut writer) = stream.into_split();
        let queue_cap = router.config.queue_size.max(16384).min(131072);
        let (tx, mut rx) = mpsc::channel::<Bytes>(queue_cap);
        let mut frame_buf = BytesMut::with_capacity(2048);

        let conn = Arc::new(TunnelListenConn {
            tx,
            authenticated: AtomicBool::new(false),
            conn_id_hint: AtomicU64::new(0),
            forward_id: AtomicU64::new(0),
            pool_id: AtomicU64::new(0),
            last_active: RwLock::new(Instant::now()),
            last_heartbeat_sent: RwLock::new(None),
        });

        self.conns.insert(id, Arc::clone(&conn));

        let write_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if write_frame(&mut writer, &frame).await.is_err() {
                    break;
                }
            }
        });

        loop {
            if read_frame_into(&mut reader, &mut frame_buf).await.is_err() {
                break;
            }

            match self.auth.unwrap_frame(&frame_buf) {
                Ok(UnwrappedFrame::Data { conn_id, payload }) => {
                    if !conn.authenticated.load(Ordering::Relaxed) {
                        continue;
                    }
                    conn.conn_id_hint.store(conn_id, Ordering::Relaxed);
                    *conn.last_active.write().await = Instant::now();
                    let packet = Packet {
                        data: payload,
                        src_tag: Arc::clone(&self.tag_arc),
                        src_addr: None,
                        conn_id,
                        proto: None,
                    };
                    let _ = router.route_shared(packet, Arc::clone(&self.detour)).await;
                }
                Ok(UnwrappedFrame::Control { header, payload }) => match header.msg_type {
                    MSG_TYPE_AUTH_CHALLENGE => {
                        if let Ok((forward_id, pool_id)) =
                            self.auth.process_auth_challenge(&payload).await
                        {
                            conn.authenticated.store(true, Ordering::Relaxed);
                            conn.forward_id
                                .store(u64::from_be_bytes(forward_id), Ordering::Relaxed);
                            conn.pool_id
                                .store(u64::from_be_bytes(pool_id), Ordering::Relaxed);
                            let mut forward_id = [0u8; 8];
                            let mut pool_id = [0u8; 8];
                            rand::thread_rng().fill(&mut forward_id);
                            rand::thread_rng().fill(&mut pool_id);
                            if let Ok(resp) = self
                                .auth
                                .create_auth_challenge(
                                    crate::auth::MSG_TYPE_AUTH_RESPONSE,
                                    forward_id,
                                    pool_id,
                                )
                                .await
                            {
                                Self::send_frame(&conn.tx, resp, self.send_timeout).await;
                            }
                        }
                    }
                    MSG_TYPE_HEARTBEAT => {
                        let hb = self.auth.create_heartbeat(true);
                        Self::send_frame(&conn.tx, hb, self.send_timeout).await;
                        *conn.last_active.write().await = Instant::now();
                    }
                    MSG_TYPE_HEARTBEAT_ACK => {
                        let mut lock = conn.last_heartbeat_sent.write().await;
                        if let Some(ts) = lock.take() {
                            self.auth.record_delay(ts.elapsed()).await;
                        }
                    }
                    _ => {}
                },
                Err(err) => {
                    debug!("{} tcp unwrap error: {err}", self.tag);
                }
            }
        }

        self.conns.remove(&id);
        write_task.abort();
    }

    async fn send_frame(tx: &mpsc::Sender<Bytes>, frame: Bytes, send_timeout: Duration) {
        match tx.try_send(frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(frame)) => {
                let _ = time::timeout(send_timeout, tx.send(frame)).await;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

#[async_trait]
impl Component for TcpTunnelListenComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, router: Arc<Router>) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        self.running.store(true, Ordering::Relaxed);
        info!("{} listening on tcp {}", self.tag, self.listen_addr);
        tokio::spawn(Arc::clone(&self).accept_loop(router, listener));
        Ok(())
    }

    async fn handle_packet(&self, _router: &Router, packet: Packet) -> Result<()> {
        let frame = self.auth.wrap_data(packet.conn_id, &packet.data)?;

        if self.broadcast_mode {
            let mut best_by_pool: HashMap<(u64, u64), (usize, Arc<TunnelListenConn>)> =
                HashMap::new();
            for conn in self.conns.iter() {
                if !conn.authenticated.load(Ordering::Relaxed) {
                    continue;
                }

                let key = (
                    conn.forward_id.load(Ordering::Relaxed),
                    conn.pool_id.load(Ordering::Relaxed),
                );

                if key == (0, 0) {
                    Self::send_frame(&conn.tx, frame.clone(), self.send_timeout).await;
                    continue;
                }

                let cap = conn.tx.capacity();
                match best_by_pool.get(&key) {
                    Some((best_cap, _)) if *best_cap >= cap => {}
                    _ => {
                        best_by_pool.insert(key, (cap, Arc::clone(conn.value())));
                    }
                }
            }

            for (_, (_, conn)) in best_by_pool {
                Self::send_frame(&conn.tx, frame.clone(), self.send_timeout).await;
            }
        } else {
            let target = self
                .conns
                .iter()
                .find(|entry| entry.conn_id_hint.load(Ordering::Relaxed) == packet.conn_id)
                .map(|e| e.key().to_owned());
            if let Some(id) = target {
                if let Some(conn) = self.conns.get(&id) {
                    Self::send_frame(&conn.tx, frame, self.send_timeout).await;
                }
            }
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.conns
            .iter()
            .any(|c| c.authenticated.load(Ordering::Relaxed))
    }

    async fn average_delay_ms(&self) -> f64 {
        self.auth.average_delay_ms().await
    }
}
