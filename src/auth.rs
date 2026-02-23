use crate::config::AuthConfig;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit, OsRng, rand_core::RngCore},
    Aes128Gcm, Nonce, Tag,
};
use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub const PROTOCOL_VERSION: u8 = 2;

pub const MSG_TYPE_AUTH_CHALLENGE: u8 = 1;
pub const MSG_TYPE_AUTH_RESPONSE: u8 = 2;
pub const MSG_TYPE_HEARTBEAT: u8 = 4;
pub const MSG_TYPE_DATA: u8 = 5;
pub const MSG_TYPE_DISCONNECT: u8 = 6;
pub const MSG_TYPE_HEARTBEAT_ACK: u8 = 7;

pub const HEADER_SIZE: usize = 8;
const CHALLENGE_SIZE: usize = 32;
const TIMESTAMP_SIZE: usize = 8;
const MAC_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const FORWARD_ID_SIZE: usize = 8;
const POOL_ID_SIZE: usize = 8;
const CONN_ID_SIZE: usize = 8;
pub const HANDSHAKE_SIZE: usize = CHALLENGE_SIZE + FORWARD_ID_SIZE + POOL_ID_SIZE + TIMESTAMP_SIZE + MAC_SIZE;

#[derive(Clone, Debug)]
pub struct ProtocolHeader {
    pub version: u8,
    pub msg_type: u8,
    pub length: u32,
}

#[derive(Clone)]
pub struct AuthManager {
    secret: Arc<[u8; 32]>,
    enable_encryption: bool,
    cipher: Option<Arc<Aes128Gcm>>,
    pub heartbeat_interval: Duration,
    pub auth_timeout: Duration,
    pub data_timeout: Duration,
    nonce_prefix: [u8; 4],
    nonce_counter: Arc<AtomicU64>,
    challenge_cache: Arc<Mutex<HashMap<[u8; CHALLENGE_SIZE], Instant>>>,
    delay_window: Arc<Mutex<Vec<Duration>>>,
    delay_index: Arc<AtomicUsize>,
}

impl AuthManager {
    pub fn from_config(cfg: Option<&AuthConfig>) -> Result<Option<Self>> {
        let Some(cfg) = cfg else {
            return Ok(None);
        };
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.secret.is_empty() {
            return Err(anyhow!("auth.secret cannot be empty"));
        }

        let mut hasher = Sha256::new();
        hasher.update(cfg.secret.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();

        let cipher = if cfg.enable_encryption {
            let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&digest[..16]);
            Some(Arc::new(Aes128Gcm::new(key)))
        } else {
            None
        };

        let delay_window_size = cfg.delay_window_size.max(1);
        let mut nonce_prefix = [0u8; 4];
        OsRng.fill_bytes(&mut nonce_prefix);

        Ok(Some(Self {
            secret: Arc::new(digest),
            enable_encryption: cfg.enable_encryption,
            cipher,
            heartbeat_interval: Duration::from_secs(cfg.heartbeat_interval.max(1)),
            auth_timeout: Duration::from_secs(cfg.auth_timeout.max(1)),
            data_timeout: Duration::from_secs(65),
            nonce_prefix,
            nonce_counter: Arc::new(AtomicU64::new(0)),
            challenge_cache: Arc::new(Mutex::new(HashMap::new())),
            delay_window: Arc::new(Mutex::new(vec![Duration::ZERO; delay_window_size])),
            delay_index: Arc::new(AtomicUsize::new(0)),
        }))
    }

    pub fn create_heartbeat(&self, ack: bool) -> Bytes {
        let mut out = BytesMut::with_capacity(HEADER_SIZE);
        let msg = if ack { MSG_TYPE_HEARTBEAT_ACK } else { MSG_TYPE_HEARTBEAT };
        write_header(&mut out, msg, 0);
        out.freeze()
    }

    pub async fn create_auth_challenge(&self, msg_type: u8, forward_id: [u8; 8], pool_id: [u8; 8]) -> Result<Bytes> {
        let mut challenge = [0u8; CHALLENGE_SIZE];
        OsRng.fill_bytes(&mut challenge);

        {
            let mut cache = self.challenge_cache.lock().await;
            cache.insert(challenge, Instant::now());
            cleanup_challenge_cache(&mut cache, self.auth_timeout);
        }

        let mut out = BytesMut::with_capacity(HEADER_SIZE + HANDSHAKE_SIZE);
        write_header(&mut out, msg_type, HANDSHAKE_SIZE as u32);
        let payload_start = out.len();

        out.extend_from_slice(&challenge);
        out.extend_from_slice(&forward_id);
        out.extend_from_slice(&pool_id);
        out.extend_from_slice(&now_millis().to_be_bytes());

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.secret.as_slice())
            .context("failed to create hmac")?;
        mac.update(&out[payload_start..]);
        let mac_bytes = mac.finalize().into_bytes();
        out.extend_from_slice(&mac_bytes);
        Ok(out.freeze())
    }

    pub async fn process_auth_challenge(&self, payload: &[u8]) -> Result<([u8; 8], [u8; 8])> {
        if payload.len() < HANDSHAKE_SIZE {
            return Err(anyhow!("invalid handshake payload length"));
        }

        let challenge: [u8; CHALLENGE_SIZE] = payload[..CHALLENGE_SIZE].try_into().unwrap();
        {
            let cache = self.challenge_cache.lock().await;
            if let Some(ts) = cache.get(&challenge) {
                if ts.elapsed() < self.auth_timeout {
                    return Err(anyhow!("duplicate challenge"));
                }
            }
        }

        let mut offset = CHALLENGE_SIZE;
        let forward_id: [u8; 8] = payload[offset..offset + FORWARD_ID_SIZE].try_into().unwrap();
        offset += FORWARD_ID_SIZE;
        let pool_id: [u8; 8] = payload[offset..offset + POOL_ID_SIZE].try_into().unwrap();
        offset += POOL_ID_SIZE;

        let ts = i64::from_be_bytes(payload[offset..offset + TIMESTAMP_SIZE].try_into().unwrap());
        offset += TIMESTAMP_SIZE;

        let recv_mac = &payload[offset..offset + MAC_SIZE];

        let now = now_millis();
        if now - ts > self.auth_timeout.as_millis() as i64 {
            return Err(anyhow!("challenge timestamp expired"));
        }

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.secret.as_slice())
            .context("failed to create hmac")?;
        mac.update(&payload[..CHALLENGE_SIZE + FORWARD_ID_SIZE + POOL_ID_SIZE + TIMESTAMP_SIZE]);
        mac.verify_slice(recv_mac)
            .map_err(|_| anyhow!("invalid challenge mac"))?;

        {
            let mut cache = self.challenge_cache.lock().await;
            cache.insert(challenge, Instant::now());
            cleanup_challenge_cache(&mut cache, self.auth_timeout);
        }

        Ok((forward_id, pool_id))
    }

    pub fn wrap_data(&self, conn_id: u64, payload: &[u8]) -> Result<Bytes> {
        if self.enable_encryption {
            let Some(cipher) = &self.cipher else {
                return Err(anyhow!("cipher unavailable"));
            };

            let mut nonce_bytes = [0u8; NONCE_SIZE];
            nonce_bytes[..4].copy_from_slice(&self.nonce_prefix);
            let ctr = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
            nonce_bytes[4..].copy_from_slice(&ctr.to_be_bytes());

            let plaintext_len = TIMESTAMP_SIZE + CONN_ID_SIZE + payload.len();
            let frame_body_len = NONCE_SIZE + plaintext_len + 16;
            let mut out = BytesMut::with_capacity(HEADER_SIZE + frame_body_len);
            write_header(&mut out, MSG_TYPE_DATA, frame_body_len as u32);
            out.extend_from_slice(&nonce_bytes);

            let encrypted_start = out.len();
            out.extend_from_slice(&now_millis().to_be_bytes());
            out.extend_from_slice(&conn_id.to_be_bytes());
            out.extend_from_slice(payload);

            let tag = cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&nonce_bytes),
                    b"",
                    &mut out[encrypted_start..],
                )
                .map_err(|_| anyhow!("encrypt failed"))?;
            out.extend_from_slice(tag.as_slice());
            Ok(out.freeze())
        } else {
            let mut out = BytesMut::with_capacity(HEADER_SIZE + CONN_ID_SIZE + payload.len());
            write_header(&mut out, MSG_TYPE_DATA, (CONN_ID_SIZE + payload.len()) as u32);
            out.extend_from_slice(&conn_id.to_be_bytes());
            out.extend_from_slice(payload);
            Ok(out.freeze())
        }
    }

    pub fn unwrap_frame(&self, frame: &[u8]) -> Result<UnwrappedFrame> {
        let header = parse_header(frame)?;
        if header.version != PROTOCOL_VERSION {
            return Err(anyhow!("unsupported protocol version {}", header.version));
        }

        if frame.len() < HEADER_SIZE + header.length as usize {
            return Err(anyhow!("frame length mismatch"));
        }

        let body = &frame[HEADER_SIZE..HEADER_SIZE + header.length as usize];

        if header.msg_type != MSG_TYPE_DATA {
            return Ok(UnwrappedFrame::Control { header, payload: Bytes::copy_from_slice(body) });
        }

        if self.enable_encryption {
            let Some(cipher) = &self.cipher else {
                return Err(anyhow!("cipher unavailable"));
            };
            if body.len() < NONCE_SIZE + 16 {
                return Err(anyhow!("encrypted frame too short"));
            }

            let nonce = Nonce::from_slice(&body[..NONCE_SIZE]);
            let encrypted = &body[NONCE_SIZE..];
            let split = encrypted
                .len()
                .checked_sub(16)
                .ok_or_else(|| anyhow!("encrypted frame too short"))?;
            let mut plaintext = encrypted[..split].to_vec();
            let tag = Tag::from_slice(&encrypted[split..]);
            cipher
                .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
                .map_err(|_| anyhow!("decrypt failed"))?;

            if plaintext.len() < TIMESTAMP_SIZE + CONN_ID_SIZE {
                return Err(anyhow!("decrypted payload too short"));
            }

            let ts = i64::from_be_bytes(plaintext[..TIMESTAMP_SIZE].try_into().unwrap());
            let now = now_millis();
            if now - ts > self.data_timeout.as_millis() as i64 {
                return Err(anyhow!("data timestamp expired"));
            }

            let conn_id = u64::from_be_bytes(plaintext[TIMESTAMP_SIZE..TIMESTAMP_SIZE + CONN_ID_SIZE].try_into().unwrap());
            let plaintext = Bytes::from(plaintext);
            let payload = plaintext.slice(TIMESTAMP_SIZE + CONN_ID_SIZE..);
            Ok(UnwrappedFrame::Data { conn_id, payload })
        } else {
            if body.len() < CONN_ID_SIZE {
                return Err(anyhow!("unencrypted payload too short"));
            }
            let conn_id = u64::from_be_bytes(body[..CONN_ID_SIZE].try_into().unwrap());
            Ok(UnwrappedFrame::Data {
                conn_id,
                payload: Bytes::copy_from_slice(&body[CONN_ID_SIZE..]),
            })
        }
    }

    pub async fn record_delay(&self, delay: Duration) {
        let mut win = self.delay_window.lock().await;
        let idx = self.delay_index.fetch_add(1, Ordering::Relaxed) % win.len();
        win[idx] = delay;
    }

    pub async fn average_delay_ms(&self) -> f64 {
        let win = self.delay_window.lock().await;
        let mut total = Duration::ZERO;
        let mut count = 0usize;
        for d in win.iter() {
            if !d.is_zero() {
                total += *d;
                count += 1;
            }
        }
        if count == 0 {
            0.0
        } else {
            total.as_secs_f64() * 1000.0 / count as f64
        }
    }
}

fn cleanup_challenge_cache(cache: &mut HashMap<[u8; CHALLENGE_SIZE], Instant>, timeout: Duration) {
    cache.retain(|_, ts| ts.elapsed() <= timeout);
}

pub fn parse_header(frame: &[u8]) -> Result<ProtocolHeader> {
    if frame.len() < HEADER_SIZE {
        return Err(anyhow!("frame too short for header"));
    }
    Ok(ProtocolHeader {
        version: frame[0],
        msg_type: frame[1],
        length: u32::from_be_bytes(frame[4..8].try_into().unwrap()),
    })
}

pub fn write_header(out: &mut BytesMut, msg_type: u8, len: u32) {
    out.put_u8(PROTOCOL_VERSION);
    out.put_u8(msg_type);
    out.put_u16(0);
    out.put_u32(len);
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub enum UnwrappedFrame {
    Data { conn_id: u64, payload: Bytes },
    Control { header: ProtocolHeader, payload: Bytes },
}
