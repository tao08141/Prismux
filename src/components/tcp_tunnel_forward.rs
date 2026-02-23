use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_RESPONSE, MSG_TYPE_HEARTBEAT,
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
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
    time,
};
use tracing::{debug, info};

struct TunnelForwardConn {
    tx: mpsc::Sender<Bytes>,
    authenticated: AtomicBool,
    pool_id: [u8; 8],
    last_heartbeat_sent: RwLock<Option<Instant>>,
}

struct TunnelTarget {
    addr: String,
    desired: usize,
    pool_id: [u8; 8],
    conns: DashMap<u64, Arc<TunnelForwardConn>>,
    rr: AtomicU64,
}

pub struct TcpTunnelForwardComponent {
    tag: String,
    tag_arc: Arc<str>,
    detour: Arc<[String]>,
    auth: AuthManager,
    targets: Vec<Arc<TunnelTarget>>,
    forward_id: [u8; 8],
    check_interval: Duration,
    send_timeout: Duration,
    running: AtomicBool,
    next_conn_id: AtomicU64,
}

impl TcpTunnelForwardComponent {
    pub fn new(cfg: ComponentConfig) -> Result<Arc<Self>> {
        let auth = AuthManager::from_config(cfg.auth.as_ref())?
            .ok_or_else(|| anyhow!("tcp_tunnel_forward requires auth.enabled=true"))?;

        let mut forward_id = [0u8; 8];
        rand::thread_rng().fill(&mut forward_id);

        let mut targets = Vec::new();
        for forwarder in cfg.forwarders {
            let (addr, count) = parse_forwarder(&forwarder)?;
            let mut pool_id = [0u8; 8];
            rand::thread_rng().fill(&mut pool_id);
            targets.push(Arc::new(TunnelTarget {
                addr,
                desired: count,
                pool_id,
                conns: DashMap::new(),
                rr: AtomicU64::new(0),
            }));
        }

        if targets.is_empty() {
            return Err(anyhow!(
                "tcp_tunnel_forward requires at least one forwarder"
            ));
        }
        let tag = cfg.tag;
        let tag_arc = Arc::<str>::from(tag.as_str());

        Ok(Arc::new(Self {
            tag,
            tag_arc,
            detour: Arc::<[String]>::from(cfg.detour),
            auth,
            targets,
            forward_id,
            check_interval: Duration::from_secs(cfg.connection_check_time.max(1)),
            send_timeout: Duration::from_millis(cfg.send_timeout.max(1)),
            running: AtomicBool::new(false),
            next_conn_id: AtomicU64::new(1),
        }))
    }

    async fn maintain(self: Arc<Self>, router: Arc<Router>) {
        while self.running.load(Ordering::Relaxed) {
            for target in &self.targets {
                while target.conns.len() < target.desired {
                    if let Err(err) = self
                        .connect_one(Arc::clone(target), Arc::clone(&router))
                        .await
                    {
                        debug!("{} connect {} failed: {err}", self.tag, target.addr);
                        break;
                    }
                }
            }

            for target in &self.targets {
                for conn in target.conns.iter() {
                    if conn.authenticated.load(Ordering::Relaxed) {
                        let hb = self.auth.create_heartbeat(false);
                        Self::send_frame(&conn.tx, hb, self.send_timeout).await;
                        *conn.last_heartbeat_sent.write().await = Some(Instant::now());
                    }
                }
            }

            time::sleep(self.check_interval).await;
        }
    }

    async fn connect_one(
        self: &Arc<Self>,
        target: Arc<TunnelTarget>,
        router: Arc<Router>,
    ) -> Result<()> {
        let stream = TcpStream::connect(&target.addr).await?;
        stream.set_nodelay(true)?;
        let (mut reader, mut writer) = stream.into_split();

        let (tx, mut rx) = mpsc::channel::<Bytes>(16384);

        let conn = Arc::new(TunnelForwardConn {
            tx,
            authenticated: AtomicBool::new(false),
            pool_id: target.pool_id,
            last_heartbeat_sent: RwLock::new(None),
        });

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        target.conns.insert(conn_id, Arc::clone(&conn));

        let target_for_writer = Arc::clone(&target);
        let writer_conn_id = conn_id;
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if write_frame(&mut writer, &frame).await.is_err() {
                    break;
                }
            }
            target_for_writer.conns.remove(&writer_conn_id);
        });

        let auth_challenge = self
            .auth
            .create_auth_challenge(
                crate::auth::MSG_TYPE_AUTH_CHALLENGE,
                self.forward_id,
                conn.pool_id,
            )
            .await?;
        Self::send_frame(&conn.tx, auth_challenge, self.send_timeout).await;

        let this = Arc::clone(self);
        let target_for_reader = Arc::clone(&target);
        tokio::spawn(async move {
            loop {
                let frame = match read_frame(&mut reader).await {
                    Ok(f) => f,
                    Err(_) => break,
                };

                match this.auth.unwrap_frame(&frame) {
                    Ok(UnwrappedFrame::Data { conn_id, payload }) => {
                        if !conn.authenticated.load(Ordering::Relaxed) {
                            continue;
                        }
                        let packet = Packet {
                            data: payload,
                            src_tag: Arc::clone(&this.tag_arc),
                            src_addr: None,
                            conn_id,
                            proto: None,
                        };
                        let _ = router.route_shared(packet, Arc::clone(&this.detour)).await;
                    }
                    Ok(UnwrappedFrame::Control { header, payload }) => match header.msg_type {
                        MSG_TYPE_AUTH_RESPONSE => {
                            if this.auth.process_auth_challenge(&payload).await.is_ok() {
                                conn.authenticated.store(true, Ordering::Relaxed);
                            }
                        }
                        MSG_TYPE_HEARTBEAT => {
                            let hb = this.auth.create_heartbeat(true);
                            Self::send_frame(&conn.tx, hb, this.send_timeout).await;
                        }
                        MSG_TYPE_HEARTBEAT_ACK => {
                            let mut lock = conn.last_heartbeat_sent.write().await;
                            if let Some(ts) = lock.take() {
                                this.auth.record_delay(ts.elapsed()).await;
                            }
                        }
                        _ => {}
                    },
                    Err(err) => debug!("{} tunnel unwrap error: {err}", this.tag),
                }
            }

            target_for_reader.conns.remove(&conn_id);
        });

        Ok(())
    }

    fn pick_conn(&self, target: &TunnelTarget) -> Option<Arc<TunnelForwardConn>> {
        let len = target.conns.len();
        if len == 0 {
            return None;
        }
        let start = (target.rr.fetch_add(1, Ordering::Relaxed) as usize) % len;

        let mut idx = 0usize;
        for entry in target.conns.iter() {
            if idx >= start && entry.authenticated.load(Ordering::Relaxed) {
                return Some(Arc::clone(entry.value()));
            }
            idx = idx.saturating_add(1);
        }

        idx = 0;
        for entry in target.conns.iter() {
            if idx >= start {
                break;
            }
            if entry.authenticated.load(Ordering::Relaxed) {
                return Some(Arc::clone(entry.value()));
            }
            idx = idx.saturating_add(1);
        }
        None
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
impl Component for TcpTunnelForwardComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, router: Arc<Router>) -> Result<()> {
        self.running.store(true, Ordering::Relaxed);
        tokio::spawn(Arc::clone(&self).maintain(router));
        info!("{} started tcp tunnel forward", self.tag);
        Ok(())
    }

    async fn handle_packet(&self, _router: &Router, packet: Packet) -> Result<()> {
        let frame = self.auth.wrap_data(packet.conn_id, &packet.data)?;

        for target in &self.targets {
            if let Some(conn) = self.pick_conn(target) {
                Self::send_frame(&conn.tx, frame.clone(), self.send_timeout).await;
            }
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.targets.iter().any(|target| {
            target
                .conns
                .iter()
                .any(|conn| conn.authenticated.load(Ordering::Relaxed))
        })
    }

    async fn average_delay_ms(&self) -> f64 {
        self.auth.average_delay_ms().await
    }
}

fn parse_forwarder(raw: &str) -> Result<(String, usize)> {
    let mut count = 4usize;
    let mut addr_part = raw.trim().to_string();

    if let Some(idx) = addr_part.rfind(':') {
        let tail = &addr_part[idx + 1..];
        if let Ok(v) = tail.parse::<usize>() {
            count = v.max(1);
            addr_part = addr_part[..idx].to_string();
        }
    }

    let addr: SocketAddr = addr_part
        .parse()
        .map_err(|_| anyhow!("invalid tcp forwarder: {raw}"))?;

    Ok((addr.to_string(), count))
}
