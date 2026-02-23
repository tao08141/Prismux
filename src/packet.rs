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

impl Packet {
    pub fn new(data: Bytes, src_tag: impl Into<Arc<str>>) -> Self {
        Self {
            data,
            src_tag: src_tag.into(),
            src_addr: None,
            conn_id: 0,
            proto: None,
        }
    }
}
