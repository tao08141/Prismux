use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_CHALLENGE, MSG_TYPE_HEARTBEAT,
        MSG_TYPE_HEARTBEAT_ACK,
    },
    component::Component,
    config::ComponentConfig,
    packet::Packet,
    router::Router,
    tcp_frame::{read_frame, write_frame},
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use rand::Rng;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock},
};
use tracing::{debug, info};

struct TunnelListenConn {
    tx: mpsc::Sender<Bytes>,
    authenticated: AtomicBool,
    conn_id_hint: AtomicU64,
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

        Ok(Arc::new(Self {
            tag,
            tag_arc,
            listen_addr: cfg.listen_addr,
            detour: Arc::<[String]>::from(cfg.detour),
            auth,
            send_timeout: Duration::from_millis(cfg.send_timeout.max(1)),
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
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Bytes>(16384);

        let conn = Arc::new(TunnelListenConn {
            tx,
            authenticated: AtomicBool::new(false),
            conn_id_hint: AtomicU64::new(0),
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
            let frame = match read_frame(&mut reader).await {
                Ok(v) => v,
                Err(_) => break,
            };

            match self.auth.unwrap_frame(&frame) {
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
                    let _ = router
                        .route_shared(packet, Arc::clone(&self.detour))
                        .await;
                }
                Ok(UnwrappedFrame::Control { header, payload }) => {
                    match header.msg_type {
                        MSG_TYPE_AUTH_CHALLENGE => {
                            if self.auth.process_auth_challenge(&payload).await.is_ok() {
                                conn.authenticated.store(true, Ordering::Relaxed);
                                let mut forward_id = [0u8; 8];
                                let mut pool_id = [0u8; 8];
                                rand::thread_rng().fill(&mut forward_id);
                                rand::thread_rng().fill(&mut pool_id);
                                if let Ok(resp) = self
                                    .auth
                                    .create_auth_challenge(crate::auth::MSG_TYPE_AUTH_RESPONSE, forward_id, pool_id)
                                    .await
                                {
                                    let _ = conn.tx.send(resp).await;
                                }
                            }
                        }
                        MSG_TYPE_HEARTBEAT => {
                            let hb = self.auth.create_heartbeat(true);
                            let _ = conn.tx.send(hb).await;
                            *conn.last_active.write().await = Instant::now();
                        }
                        MSG_TYPE_HEARTBEAT_ACK => {
                            let mut lock = conn.last_heartbeat_sent.write().await;
                            if let Some(ts) = lock.take() {
                                self.auth.record_delay(ts.elapsed()).await;
                            }
                        }
                        _ => {}
                    }
                }
                Err(err) => {
                    debug!("{} tcp unwrap error: {err}", self.tag);
                }
            }
        }

        self.conns.remove(&id);
        write_task.abort();
    }

    async fn send_frame(tx: &mpsc::Sender<Bytes>, frame: Bytes) {
        match tx.try_send(frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(frame)) => {
                let _ = tx.send(frame).await;
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
            for conn in self.conns.iter() {
                if !conn.authenticated.load(Ordering::Relaxed) {
                    continue;
                }
                Self::send_frame(&conn.tx, frame.clone()).await;
            }
        } else {
            let target = self
                .conns
                .iter()
                .find(|entry| entry.conn_id_hint.load(Ordering::Relaxed) == packet.conn_id)
                .map(|e| e.key().to_owned());
            if let Some(id) = target {
                if let Some(conn) = self.conns.get(&id) {
                    Self::send_frame(&conn.tx, frame).await;
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
