use crate::{component::Component, config::Config, packet::Packet};
use anyhow::{anyhow, Result};
use dashmap::DashMap;
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};
use tracing::{debug, warn};

#[derive(Clone)]
struct RouteTask {
    packet: Packet,
    destinations: Arc<[String]>,
}

pub struct Router {
    pub config: Arc<Config>,
    components: DashMap<String, Arc<dyn Component>>,
    route_cache: DashMap<usize, Arc<[Arc<dyn Component>]>>,
    worker_txs: OnceCell<Arc<[mpsc::Sender<RouteTask>]>>,
    next_worker: AtomicUsize,
    workers: DashMap<usize, JoinHandle<()>>,
    shutdown: Arc<Notify>,
}

impl Router {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            config: Arc::new(config),
            components: DashMap::new(),
            route_cache: DashMap::new(),
            worker_txs: OnceCell::new(),
            next_worker: AtomicUsize::new(0),
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
        self.route_cache.clear();
        Ok(())
    }

    pub fn get_component(&self, tag: &str) -> Option<Arc<dyn Component>> {
        self.components.get(tag).map(|v| Arc::clone(v.value()))
    }

    pub fn has_component(&self, tag: &str) -> bool {
        self.components.contains_key(tag)
    }

    pub fn all_component_tags(&self) -> Vec<String> {
        self.components.iter().map(|v| v.key().clone()).collect()
    }

    pub async fn route_shared(&self, packet: Packet, destinations: Arc<[String]>) -> Result<()> {
        if destinations.is_empty() {
            return Ok(());
        }

        let worker_txs = self
            .worker_txs
            .get()
            .ok_or_else(|| anyhow!("router workers not started"))?;
        if worker_txs.is_empty() {
            return Err(anyhow!("router workers not available"));
        }

        let task = RouteTask {
            packet,
            destinations,
        };

        let idx = self.next_worker.fetch_add(1, Ordering::Relaxed) % worker_txs.len();
        let tx = &worker_txs[idx];
        match tx.try_send(task) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(anyhow!("routing queue closed")),
            Err(mpsc::error::TrySendError::Full(task)) => tx
                .send(task)
                .await
                .map_err(|_| anyhow!("routing queue closed")),
        }
    }

    pub async fn route(&self, packet: Packet, dest_tags: &[String]) -> Result<()> {
        if dest_tags.is_empty() {
            return Ok(());
        }
        self.route_shared(packet, Arc::<[String]>::from(dest_tags.to_vec()))
            .await
    }

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        self.start_workers();

        for component in self.components.iter() {
            let comp = Arc::clone(component.value());
            let router = Arc::clone(self);
            comp.start(router).await?;
        }
        Ok(())
    }

    fn start_workers(self: &Arc<Self>) {
        let workers = self.config.worker_count.max(num_cpus::get()).max(1);
        let per_worker_cap = (self.config.queue_size.max(1024) / workers).max(512);
        let mut txs = Vec::with_capacity(workers);

        for idx in 0..workers {
            let (tx, mut rx) = mpsc::channel::<RouteTask>(per_worker_cap);
            txs.push(tx);

            let router = Arc::clone(self);
            let shutdown = Arc::clone(&self.shutdown);
            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.notified() => {
                            return;
                        }
                        recv = rx.recv() => {
                            let Some(task) = recv else {
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

        let _ = self.worker_txs.set(Arc::from(txs.into_boxed_slice()));
    }

    async fn process_route_task(&self, task: RouteTask) -> Result<()> {
        let cache_key = Arc::as_ptr(&task.destinations) as *const () as usize;
        let targets = if let Some(cached) = self.route_cache.get(&cache_key) {
            Arc::clone(cached.value())
        } else {
            let mut resolved = Vec::with_capacity(task.destinations.len());
            for tag in task.destinations.iter() {
                let Some(component) = self.get_component(tag) else {
                    warn!("route target missing: {tag}");
                    continue;
                };
                resolved.push(component);
            }
            let resolved: Arc<[Arc<dyn Component>]> = resolved.into();
            self.route_cache.insert(cache_key, Arc::clone(&resolved));
            resolved
        };

        let src_tag = Arc::clone(&task.packet.src_tag);
        let mut route_count = 0usize;
        for component in targets.iter() {
            if component.tag() != src_tag.as_ref() {
                route_count += 1;
            }
        }

        if route_count == 0 {
            debug!("packet had no valid target");
            return Ok(());
        }

        let mut packet = Some(task.packet);
        for component in targets.iter() {
            if component.tag() == src_tag.as_ref() {
                continue;
            }
            route_count -= 1;
            let current = if route_count == 0 {
                packet.take().expect("packet must exist")
            } else {
                packet.as_ref().expect("packet must exist").clone()
            };
            component.handle_packet(self, current).await?;
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}
