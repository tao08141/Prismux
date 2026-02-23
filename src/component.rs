use crate::{packet::Packet, router::Router};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait Component: Send + Sync {
    fn tag(&self) -> &str;
    async fn start(self: Arc<Self>, router: Arc<Router>) -> Result<()>;
    async fn handle_packet(&self, router: &Router, packet: Packet) -> Result<()>;

    fn is_available(&self) -> bool {
        true
    }

    async fn average_delay_ms(&self) -> f64 {
        f64::INFINITY
    }
}
