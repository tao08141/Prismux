use crate::{
    component::Component,
    config::FilterComponentConfig,
    packet::Packet,
    protocol_detector::ProtocolDetector,
    router::Router,
};
use anyhow::Result;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

pub struct FilterComponent {
    tag: String,
    detour: HashMap<String, Arc<[String]>>,
    detour_miss: Arc<[String]>,
    use_detectors: Vec<String>,
    detector: Arc<ProtocolDetector>,
}

impl FilterComponent {
    pub fn new(cfg: FilterComponentConfig, detector: Arc<ProtocolDetector>) -> Arc<Self> {
        let mut detour = HashMap::with_capacity(cfg.detour.len());
        for (proto, targets) in cfg.detour {
            detour.insert(proto, Arc::<[String]>::from(targets));
        }
        Arc::new(Self {
            tag: cfg.tag,
            detour,
            detour_miss: Arc::<[String]>::from(cfg.detour_miss),
            use_detectors: cfg.use_proto_detectors,
            detector,
        })
    }
}

#[async_trait]
impl Component for FilterComponent {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, _router: Arc<Router>) -> Result<()> {
        Ok(())
    }

    async fn handle_packet(&self, router: &Router, mut packet: Packet) -> Result<()> {
        if let Some(proto) = self.detector.detect(&packet.data, &self.use_detectors) {
            packet.proto = Some(Arc::from(proto.as_str()));
            if let Some(targets) = self.detour.get(&proto) {
                router.route_shared(packet, Arc::clone(targets)).await?;
            }
        } else {
            router
                .route_shared(packet, Arc::clone(&self.detour_miss))
                .await?;
        }

        Ok(())
    }
}
