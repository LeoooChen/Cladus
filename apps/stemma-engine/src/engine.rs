//! Connects a platform backend to the decision core.

use std::collections::HashMap;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use stemma_core::config::Config;
use stemma_core::decision::DecisionCore;
use stemma_core::model::{FlowQuery, GroupId, Verdict};
use stemma_core::platform::{
    Counter, DecisionOracle, ProcessEvent, ProcessInspector, ProcessSource, RedirectedTcp,
    TcpHandoff, TrafficInterceptor,
};
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, info, warn};

use crate::relay::{self, ProxyEndpoint, RelayCounters};

/// The OS-specific parts the engine runs on.
pub struct Platform {
    pub processes: Arc<dyn ProcessSource>,
    pub inspector: Arc<dyn ProcessInspector>,
    pub interceptor: Box<dyn TrafficInterceptor>,
}

/// The decision core behind a lock that lets connection decisions go first.
///
/// A connection's first packet is held until it is decided, so a decision
/// must never wait behind a burst of process events.
struct Core {
    state: Mutex<DecisionCore>,
    /// Threads waiting to make a connection decision.
    urgent: AtomicUsize,
    inspector: Arc<dyn ProcessInspector>,
    resync_needed: AtomicBool,
}

impl Core {
    fn lock_urgent(&self) -> MutexGuard<'_, DecisionCore> {
        self.urgent.fetch_add(1, SeqCst);
        let guard = self.state.lock().expect("decision core poisoned");
        self.urgent.fetch_sub(1, SeqCst);
        guard
    }

    fn lock_background(&self) -> MutexGuard<'_, DecisionCore> {
        while self.urgent.load(SeqCst) != 0 {
            thread::yield_now();
        }
        self.state.lock().expect("decision core poisoned")
    }

    fn on_process_event(&self, event: ProcessEvent) {
        if let ProcessEvent::Lost { count } = event {
            warn!(count, "process events were lost; requesting a resync");
            self.resync_needed.store(true, Relaxed);
            return;
        }
        self.lock_background()
            .apply_event(event, self.inspector.as_ref(), Instant::now());
    }
}

impl DecisionOracle for Core {
    fn decide(&self, query: &FlowQuery) -> Verdict {
        self.lock_urgent()
            .decide(query, self.inspector.as_ref(), Instant::now())
    }
}

pub struct Engine {
    core: Arc<Core>,
    processes: Arc<dyn ProcessSource>,
    interceptor: Box<dyn TrafficInterceptor>,
    relays: Arc<RelayCounters>,
    housekeeping: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
    runtime: Option<Runtime>,
}

impl Engine {
    pub fn start(config: &Config, platform: Platform) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("stemma-relay")
            .enable_all()
            .build()?;
        let core = Arc::new(Core {
            state: Mutex::new(DecisionCore::new(config, std::process::id())),
            urgent: AtomicUsize::new(0),
            inspector: platform.inspector,
            resync_needed: AtomicBool::new(false),
        });
        let groups: HashMap<GroupId, Arc<ProxyEndpoint>> = config
            .proxy_groups
            .iter()
            .map(|group| (group.id, Arc::new(ProxyEndpoint::from(group))))
            .collect();
        let relays = Arc::new(RelayCounters::default());
        let handoff: TcpHandoff = {
            let (runtime, relays) = (runtime.handle().clone(), Arc::clone(&relays));
            Arc::new(move |redirected| spawn_relay(&runtime, &groups, &relays, redirected))
        };
        let housekeeping = spawn_housekeeping(Arc::clone(&core), Arc::clone(&platform.processes));
        let mut engine = Self {
            core,
            processes: platform.processes,
            interceptor: platform.interceptor,
            relays,
            housekeeping: Some(housekeeping),
            runtime: Some(runtime),
        };
        // On error, dropping `engine` undoes whatever was started.
        let sink_core = Arc::clone(&engine.core);
        engine
            .processes
            .start(Box::new(move |event| sink_core.on_process_event(event)))?;
        // Announce the processes that are already running.
        engine.processes.request_resync();
        let oracle: Arc<dyn DecisionOracle> = engine.core.clone();
        engine.interceptor.start(oracle, handoff)?;
        info!("engine started");
        Ok(engine)
    }

    pub fn counters(&self) -> Vec<Counter> {
        let stats = self.core.lock_background().stats();
        let mut counters = vec![
            count("processes.tracked", stats.processes as u64),
            count("processes.alive", stats.alive as u64),
            count("processes.sync_resolves", stats.sync_resolves),
            count("processes.recycled_pids", stats.recycled_pids),
            count("processes.unknown", stats.unknown_processes),
        ];
        counters.extend(self.interceptor.counters());
        counters.extend(self.relays.snapshot());
        counters
    }

    /// Stops the engine and returns its final counters.
    pub fn stop(mut self) -> Vec<Counter> {
        self.shutdown();
        self.counters()
    }

    fn shutdown(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        // Stop redirecting first: traffic flows directly from here on.
        self.interceptor.stop();
        self.processes.stop();
        if let Some((stop, thread)) = self.housekeeping.take() {
            drop(stop);
            let _ = thread.join();
        }
        runtime.shutdown_timeout(Duration::from_secs(2));
        info!("engine stopped");
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn count(name: &'static str, value: u64) -> Counter {
    Counter { name, value }
}

fn spawn_housekeeping(
    core: Arc<Core>,
    processes: Arc<dyn ProcessSource>,
) -> (mpsc::Sender<()>, JoinHandle<()>) {
    let (stop, stopped) = mpsc::channel::<()>();
    let thread = thread::Builder::new()
        .name("stemma-housekeeping".to_owned())
        .spawn(move || {
            let mut last_resync = Instant::now();
            while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(Duration::from_secs(1)) {
                core.lock_background().tick(Instant::now());
                if core.resync_needed.load(Relaxed) && last_resync.elapsed() >= Duration::from_secs(1) {
                    core.resync_needed.store(false, Relaxed);
                    last_resync = Instant::now();
                    processes.request_resync();
                }
            }
        })
        .expect("failed to spawn the housekeeping thread");
    (stop, thread)
}

fn spawn_relay(
    runtime: &Handle,
    groups: &HashMap<GroupId, Arc<ProxyEndpoint>>,
    counters: &Arc<RelayCounters>,
    redirected: RedirectedTcp,
) {
    let Some(proxy) = groups.get(&redirected.group).cloned() else {
        warn!(group = %redirected.group, "no such proxy group; closing the connection");
        return;
    };
    let counters = Arc::clone(counters);
    counters.started.fetch_add(1, Relaxed);
    counters.active.fetch_add(1, Relaxed);
    runtime.spawn(async move {
        let RedirectedTcp {
            stream,
            original_dst,
            lease,
            ..
        } = redirected;
        let result = async {
            stream.set_nonblocking(true)?;
            let client = tokio::net::TcpStream::from_std(stream)?;
            Ok::<_, anyhow::Error>(relay::relay(client, &proxy, original_dst).await?)
        }
        .await;
        match result {
            Ok((up, down)) => {
                counters.bytes_up.fetch_add(up, Relaxed);
                counters.bytes_down.fetch_add(down, Relaxed);
                debug!(target = %original_dst, up, down, "relay finished");
            }
            Err(err) => {
                counters.failed.fetch_add(1, Relaxed);
                warn!(target = %original_dst, proxy = %format!("{}:{}", proxy.host, proxy.port), "relay failed: {err:#}");
            }
        }
        counters.active.fetch_sub(1, Relaxed);
        drop(lease);
    });
}
