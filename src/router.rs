use crate::{component::Component, config::Config, packet::Packet};
use anyhow::{anyhow, Result};
use dashmap::DashMap;
use flume::{Receiver, Sender};
use std::sync::Arc;
use tokio::{sync::Notify, task::JoinHandle};
use tracing::{debug, warn};

#[derive(Clone)]
struct RouteTask {
    packet: Packet,
    destinations: Arc<Vec<String>>,
}

pub struct Router {
    pub config: Arc<Config>,
    components: DashMap<String, Arc<dyn Component>>,
    tx: Sender<RouteTask>,
    rx: Receiver<RouteTask>,
    workers: DashMap<usize, JoinHandle<()>>,
    shutdown: Arc<Notify>,
}

impl Router {
    pub fn new(config: Config) -> Arc<Self> {
        let cap = config.queue_size.max(1024);
        let (tx, rx) = flume::bounded(cap);

        Arc::new(Self {
            config: Arc::new(config),
            components: DashMap::new(),
            tx,
            rx,
            workers: DashMap::new(),
            shutdown: Arc::new(Notify::new()),
        })
    }

    pub fn register(&self, component: Arc<dyn Component>) -> Result<()> {
        let tag = component.tag().to_string();
        if tag.is_empty() {
            return Err(anyhow!("component tag cannot be empty"));
        }
        if self.components.contains_key(&tag) {
            return Err(anyhow!("duplicate component tag: {tag}"));
        }
        self.components.insert(tag, component);
        Ok(())
    }

    pub fn get_component(&self, tag: &str) -> Option<Arc<dyn Component>> {
        self.components.get(tag).map(|v| Arc::clone(v.value()))
    }

    pub fn all_component_tags(&self) -> Vec<String> {
        self.components.iter().map(|v| v.key().clone()).collect()
    }

    pub fn route(&self, packet: Packet, dest_tags: &[String]) -> Result<()> {
        if dest_tags.is_empty() {
            return Ok(());
        }

        let task = RouteTask {
            packet,
            destinations: Arc::new(dest_tags.to_vec()),
        };

        self.tx
            .send(task)
            .map_err(|_| anyhow!("routing queue closed"))
    }

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        for component in self.components.iter() {
            let comp = Arc::clone(component.value());
            let router = Arc::clone(self);
            comp.start(router).await?;
        }

        self.start_workers();
        Ok(())
    }

    fn start_workers(self: &Arc<Self>) {
        let cpu_scaled = num_cpus::get().saturating_mul(4);
        let workers = self
            .config
            .worker_count
            .max(cpu_scaled)
            .max(16);
        for idx in 0..workers {
            let rx = self.rx.clone();
            let router = Arc::clone(self);
            let shutdown = Arc::clone(&self.shutdown);
            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.notified() => {
                            return;
                        }
                        recv = rx.recv_async() => {
                            let Ok(task) = recv else {
                                return;
                            };
                            if let Err(err) = router.process_route_task(task).await {
                                debug!("route task dropped: {err}");
                            }
                        }
                    }
                }
            });
            self.workers.insert(idx, handle);
        }
    }

    async fn process_route_task(&self, task: RouteTask) -> Result<()> {
        let mut any_target = false;
        for tag in task.destinations.iter() {
            if tag == task.packet.src_tag.as_ref() {
                continue;
            }

            let Some(component) = self.get_component(tag) else {
                warn!("route target missing: {tag}");
                continue;
            };

            any_target = true;
            component
                .handle_packet(self, task.packet.clone())
                .await?;
        }

        if !any_target {
            debug!("packet had no valid target");
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}
