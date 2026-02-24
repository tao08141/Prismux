use crate::{
    auth::{
        AuthManager, UnwrappedFrame, MSG_TYPE_AUTH_RESPONSE, MSG_TYPE_HEARTBEAT,
        MSG_TYPE_HEARTBEAT_ACK,
    },
    component::Component,
    config::ComponentConfig,
    packet::Packet,
    router::Router,
    tcp_frame::{read_frame_into, write_frame},
    timefmt::{format_from_elapsed, format_system_time},
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rand::Rng;
use serde_json::{json, Value};
use socket2::SockRef;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

struct TunnelForwardConn {
    tx: mpsc::Sender<Bytes>,
    authenticated: AtomicBool,
    pool_id: [u8; 8],
    remote_addr: String,
    heartbeat_miss_count: AtomicU32,
    last_active: RwLock<Instant>,
    last_heartbeat_at: RwLock<Option<SystemTime>>,
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
    no_delay: bool,
    recv_buffer_size: usize,
    send_buffer_size: usize,
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
        let no_delay = cfg.no_delay.unwrap_or(true);
        let recv_buffer_size = cfg.recv_buffer_size.max(2 * 1024 * 1024);
        let send_buffer_size = cfg.send_buffer_size.max(2 * 1024 * 1024);

        Ok(Arc::new(Self {
            tag,
            tag_arc,
            detour: Arc::<[String]>::from(cfg.detour),
            auth,
            targets,
            forward_id,
            check_interval: Duration::from_secs(cfg.connection_check_time.max(1)),
            send_timeout: Duration::from_millis(if cfg.send_timeout == 0 {
                500
            } else {
                cfg.send_timeout
            }),
            no_delay,
            recv_buffer_size,
            send_buffer_size,
            running: AtomicBool::new(false),
            next_conn_id: AtomicU64::new(1),
        }))
    }

    async fn maintain(self: Arc<Self>, router: Arc<Router>) {
        let mut check_ticker = time::interval(self.check_interval);
        check_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut hb_ticker = time::interval(self.auth.heartbeat_interval);
        hb_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        while self.running.load(Ordering::Relaxed) {
            tokio::select! {
                _ = check_ticker.tick() => {
                    for target in &self.targets {
                        while target.conns.len() < target.desired {
                            let next_index = target.conns.len() + 1;
                            info!(
                                "{} reconnect {} attempt {}/{}",
                                self.tag, target.addr, next_index, target.desired
                            );
                            if let Err(err) = self
                                .connect_one(Arc::clone(target), Arc::clone(&router))
                                .await
                            {
                                warn!("{} reconnect {} failed: {err}", self.tag, target.addr);
                                break;
                            } else {
                                info!(
                                    "{} reconnect {} succeeded ({}/{})",
                                    self.tag,
                                    target.addr,
                                    target.conns.len(),
                                    target.desired
                                );
                            }
                        }
                    }
                }
                _ = hb_ticker.tick() => {
                    for target in &self.targets {
                        for conn in target.conns.iter() {
                            if conn.authenticated.load(Ordering::Relaxed) {
                                let hb = self.auth.create_heartbeat(false);
                                Self::send_frame(&conn.tx, hb, self.send_timeout).await;
                                let mut sent = conn.last_heartbeat_sent.write().await;
                                if sent.is_some() {
                                    conn.heartbeat_miss_count.fetch_add(1, Ordering::Relaxed);
                                }
                                *sent = Some(Instant::now());
                                *conn.last_heartbeat_at.write().await = Some(SystemTime::now());
                            } else if let Ok(challenge) = self
                                .auth
                                .create_auth_challenge(
                                    crate::auth::MSG_TYPE_AUTH_CHALLENGE,
                                    self.forward_id,
                                    conn.pool_id,
                                )
                                .await
                            {
                                Self::send_frame(&conn.tx, challenge, self.send_timeout).await;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn connect_one(
        self: &Arc<Self>,
        target: Arc<TunnelTarget>,
        router: Arc<Router>,
    ) -> Result<()> {
        debug!("{} dialing tcp tunnel {}", self.tag, target.addr);
        let stream = TcpStream::connect(&target.addr).await?;
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(true)?;
        std_stream.set_nodelay(self.no_delay)?;
        let sock_ref = SockRef::from(&std_stream);
        let _ = sock_ref.set_recv_buffer_size(self.recv_buffer_size);
        let _ = sock_ref.set_send_buffer_size(self.send_buffer_size);
        let stream = TcpStream::from_std(std_stream)?;
        let local_addr = stream
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let peer_addr = stream
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| target.addr.clone());
        let (mut reader, mut writer) = stream.into_split();

        let queue_cap = router.config.queue_size.max(16384).min(131072);
        let (tx, mut rx) = mpsc::channel::<Bytes>(queue_cap);

        let conn = Arc::new(TunnelForwardConn {
            tx,
            authenticated: AtomicBool::new(false),
            pool_id: target.pool_id,
            remote_addr: target.addr.clone(),
            heartbeat_miss_count: AtomicU32::new(0),
            last_active: RwLock::new(Instant::now()),
            last_heartbeat_at: RwLock::new(None),
            last_heartbeat_sent: RwLock::new(None),
        });

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        target.conns.insert(conn_id, Arc::clone(&conn));

        let target_for_writer = Arc::clone(&target);
        let writer_conn_id = conn_id;
        let writer_tag = self.tag.clone();
        let writer_remote = target.addr.clone();
        tokio::spawn(async move {
            let mut close_reason = "writer-queue-closed".to_string();
            while let Some(frame) = rx.recv().await {
                if let Err(err) = write_frame(&mut writer, &frame).await {
                    warn!(
                        "{} tcp_tunnel writer {} #{} closed: {err}",
                        writer_tag, writer_remote, writer_conn_id
                    );
                    close_reason = format!("writer-io-error: {err}");
                    break;
                }
            }
            if target_for_writer.conns.remove(&writer_conn_id).is_some() {
                info!(
                    "{} tcp_tunnel {} #{} disconnected ({}), waiting reconnect",
                    writer_tag, writer_remote, writer_conn_id, close_reason
                );
            }
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
            let mut frame_buf = BytesMut::with_capacity(2048);
            loop {
                if let Err(err) = read_frame_into(&mut reader, &mut frame_buf).await {
                    warn!(
                        "{} tcp_tunnel reader {} #{} closed: {err}",
                        this.tag, conn.remote_addr, conn_id
                    );
                    break;
                }

                match this.auth.unwrap_frame(&frame_buf) {
                    Ok(UnwrappedFrame::Data { conn_id, payload }) => {
                        if !conn.authenticated.load(Ordering::Relaxed) {
                            continue;
                        }
                        *conn.last_active.write().await = Instant::now();
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
                                conn.heartbeat_miss_count.store(0, Ordering::Relaxed);
                                info!(
                                    "{} tcp_tunnel {} #{} authenticated",
                                    this.tag, conn.remote_addr, conn_id
                                );
                            }
                        }
                        MSG_TYPE_HEARTBEAT => {
                            // This heartbeat is the listen-side response to our probe.
                            // Record RTT before sending final ACK.
                            let mut lock = conn.last_heartbeat_sent.write().await;
                            if let Some(ts) = lock.take() {
                                this.auth.record_delay(ts.elapsed()).await;
                            }
                            let hb = this.auth.create_heartbeat(true);
                            Self::send_frame(&conn.tx, hb, this.send_timeout).await;
                            *conn.last_heartbeat_at.write().await = Some(SystemTime::now());
                            conn.heartbeat_miss_count.store(0, Ordering::Relaxed);
                            *conn.last_active.write().await = Instant::now();
                        }
                        MSG_TYPE_HEARTBEAT_ACK => {
                            let mut lock = conn.last_heartbeat_sent.write().await;
                            if let Some(ts) = lock.take() {
                                this.auth.record_delay(ts.elapsed()).await;
                            }
                            *conn.last_heartbeat_at.write().await = Some(SystemTime::now());
                            conn.heartbeat_miss_count.store(0, Ordering::Relaxed);
                            *conn.last_active.write().await = Instant::now();
                        }
                        _ => {}
                    },
                    Err(err) => debug!("{} tunnel unwrap error: {err}", this.tag),
                }
            }

            if target_for_reader.conns.remove(&conn_id).is_some() {
                info!(
                    "{} tcp_tunnel {} #{} removed, waiting reconnect",
                    this.tag, conn.remote_addr, conn_id
                );
            }
        });

        info!(
            "{} tcp_tunnel {} #{} established local={} peer={}",
            self.tag, target.addr, conn_id, local_addr, peer_addr
        );
        Ok(())
    }

    fn pick_conn(&self, target: &TunnelTarget) -> Option<Arc<TunnelForwardConn>> {
        let _ = target.rr.fetch_add(1, Ordering::Relaxed);
        let mut best: Option<(usize, Arc<TunnelForwardConn>)> = None;
        for entry in target.conns.iter() {
            if !entry.authenticated.load(Ordering::Relaxed) {
                continue;
            }
            let cap = entry.tx.capacity();
            match &best {
                Some((best_cap, _)) if *best_cap >= cap => {}
                _ => best = Some((cap, Arc::clone(entry.value()))),
            }
        }
        best.map(|(_, conn)| conn)
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

    pub fn api_info(&self) -> Value {
        let forwarders = self
            .targets
            .iter()
            .map(|target| format!("{}:{}", target.addr, target.desired))
            .collect::<Vec<_>>();

        json!({
            "tag": self.tag,
            "type": "tcp_tunnel_forward",
            "forwarders": forwarders,
            "connection_check_time": self.check_interval.as_secs(),
            "detour": self.detour.to_vec(),
        })
    }

    pub async fn api_connections(&self) -> Value {
        let mut pools = Vec::with_capacity(self.targets.len());
        let mut total_connections = 0usize;

        for target in &self.targets {
            let mut connections = Vec::new();
            for conn in target.conns.iter() {
                let last_heartbeat = conn
                    .last_heartbeat_at
                    .read()
                    .await
                    .as_ref()
                    .map(|v| format_system_time(*v));
                connections.push(json!({
                    "connection_id": conn.key(),
                    "remote_addr": conn.remote_addr,
                    "is_authenticated": conn.authenticated.load(Ordering::Relaxed),
                    "last_active": format_from_elapsed(conn.last_active.read().await.elapsed()),
                    "heartbeat_miss": conn.heartbeat_miss_count.load(Ordering::Relaxed),
                    "last_heartbeat": last_heartbeat,
                }));
            }

            total_connections += connections.len();
            pools.push(json!({
                "pool_id": format!("{:016x}", u64::from_be_bytes(target.pool_id)),
                "remote_addr": target.addr,
                "connections": connections,
                "conn_count": connections.len(),
                "target_count": target.desired,
            }));
        }

        json!({
            "tag": self.tag,
            "forward_id": format!("{:016x}", u64::from_be_bytes(self.forward_id)),
            "pools": pools,
            "total_connections": total_connections,
            "average_delay_ms": self.auth.average_delay_ms().await,
        })
    }
}

#[async_trait]
impl Component for TcpTunnelForwardComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
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
    let candidate = raw.trim();
    if candidate.is_empty() {
        return Err(anyhow!("invalid tcp forwarder: {raw}"));
    }

    if parse_endpoint(candidate).is_ok() {
        return Ok((candidate.to_string(), 4));
    }

    if let Some((addr_part, count_part)) = candidate.rsplit_once(':') {
        if let Ok(count) = count_part.parse::<usize>() {
            parse_endpoint(addr_part).map_err(|_| anyhow!("invalid tcp forwarder: {raw}"))?;
            return Ok((addr_part.to_string(), count.max(1)));
        }
    }

    Err(anyhow!("invalid tcp forwarder: {raw}"))
}

fn parse_endpoint(addr: &str) -> Result<()> {
    if let Some(rest) = addr.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow!("invalid tcp endpoint: {addr}"))?;
        if end == 0 {
            return Err(anyhow!("invalid tcp endpoint: {addr}"));
        }
        let remain = &rest[end + 1..];
        let port = remain
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("invalid tcp endpoint: {addr}"))?;
        port.parse::<u16>()
            .map_err(|_| anyhow!("invalid tcp endpoint: {addr}"))?;
        return Ok(());
    }

    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid tcp endpoint: {addr}"))?;
    if host.is_empty() || host.contains(':') {
        return Err(anyhow!("invalid tcp endpoint: {addr}"));
    }
    port.parse::<u16>()
        .map_err(|_| anyhow!("invalid tcp endpoint: {addr}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_forwarder;

    #[test]
    fn parse_forwarder_supports_host_port_without_count() {
        let (addr, count) = parse_forwarder("edge.example.com:5203").expect("parse host");
        assert_eq!(addr, "edge.example.com:5203");
        assert_eq!(count, 4);
    }

    #[test]
    fn parse_forwarder_supports_host_port_with_count() {
        let (addr, count) = parse_forwarder("edge.example.com:5203:8").expect("parse host");
        assert_eq!(addr, "edge.example.com:5203");
        assert_eq!(count, 8);
    }

    #[test]
    fn parse_forwarder_supports_ipv6_with_count() {
        let (addr, count) = parse_forwarder("[2001:db8::1]:5203:2").expect("parse ipv6");
        assert_eq!(addr, "[2001:db8::1]:5203");
        assert_eq!(count, 2);
    }

    #[test]
    fn parse_forwarder_rejects_missing_port() {
        assert!(parse_forwarder("edge.example.com").is_err());
    }
}
