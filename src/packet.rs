use bytes::Bytes;
use std::{net::SocketAddr, sync::Arc};

#[derive(Clone, Debug)]
pub struct Packet {
    pub data: Bytes,
    pub src_tag: Arc<str>,
    pub src_addr: Option<SocketAddr>,
    pub conn_id: u64,
    pub proto: Option<Arc<str>>,
}
