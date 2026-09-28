//! Connects a platform backend to the decision core.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, RwLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cladus_core::config::Config;
use cladus_core::decision::DecisionCore;
use cladus_core::model::{DirectReason, FlowQuery, GroupId, ProcessKey, ProcessView, Verdict};
use cladus_core::platform::{
    Counter, DecisionOracle, Handoff, ProcessEvent, ProcessInspector, ProcessSource, RedirectedTcp,
    SystemDns, TrafficInterceptor,
};
use cladus_core::policy::{PolicyId, PolicyTable};
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, info, warn};

use crate::dns::{DnsCounters, DnsForwarder, DnsSettings};
use crate::relay::{self, ProxyEndpoint, RelayCounters};
use crate::system_dns::{DnsRedirect, LISTEN_V4, LISTEN_V6};
use crate::udp::{UdpCounters, UdpRelay};

/// The OS-specific parts the engine runs on.
pub struct Platform {
    pub processes: Arc<dyn ProcessSource>,
    pub inspector: Arc<dyn ProcessInspector>,
    pub interceptor: Box<dyn TrafficInterceptor>,
    /// System DNS control; `None` where redirecting DNS is unsupported.
    pub dns: Option<DnsBackend>,
}

pub struct DnsBackend {
    pub system: Arc<dyn SystemDns>,
    /// Original settings are recorded here while DNS is redirected.
    pub journal: std::path::PathBuf,
}

/// Redirected system DNS and the forwarder serving it.
struct DnsState {
    forwarder: Arc<DnsForwarder>,
    redirect: Arc<DnsRedirect>,
    watcher: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
}

impl DnsState {
    fn restore(&mut self) -> anyhow::Result<()> {
        if let Some((stop, thread)) = self.watcher.take() {
            drop(stop);
            let _ = thread.join();
        }
        // Point the system back at its own servers before the forwarder goes.
        self.redirect.restore()
    }
}

impl Drop for DnsState {
    fn drop(&mut self) {
        if let Err(err) = self.restore() {
            warn!("{err:#}");
        }
    }
}

type Groups = HashMap<GroupId, Arc<ProxyEndpoint>>;

fn groups_of(config: &Config) -> Arc<Groups> {
    Arc::new(
        config
            .proxy_groups
            .iter()
            .map(|group| (group.id, Arc::new(ProxyEndpoint::from(group))))
            .collect(),
    )
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
    /// Read for every proxied datagram, so kept outside the core's lock.
    policies: RwLock<Arc<PolicyTable>>,
    resync_needed: AtomicBool,
    processes: Arc<dyn ProcessSource>,
    changed: Condvar,
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
        self.changed.notify_all();
    }
}

impl DecisionOracle for Core {
    fn decide(&self, query: &FlowQuery) -> Verdict {
        let mut core = self.lock_urgent();
        let verdict = core.decide(query, self.inspector.as_ref(), Instant::now());
        if query.pid <= 4
            || verdict != Verdict::Direct(DirectReason::NotAssigned)
            || !core.take_ancestry_retry(query.pid)
        {
            return verdict;
        }
        // Do not hold the core while ETW delivers a short-lived parent's
        // buffered start event. The SYN watchdog remains the fail-open bound.
        drop(core);
        let deadline = Instant::now() + Duration::from_millis(10);
        let started = Instant::now();
        self.processes.flush();
        debug!(pid = query.pid, elapsed = ?started.elapsed(), "flushed process events for unresolved ancestry");
        core = self.lock_urgent();
        loop {
            let now = Instant::now();
            let verdict = core.decide(query, self.inspector.as_ref(), now);
            if verdict != Verdict::Direct(DirectReason::NotAssigned)
                || !core.has_unresolved_ancestry(query.pid)
                || now >= deadline
            {
                return verdict;
            }
            core = self
                .changed
                .wait_timeout(core, deadline - now)
                .expect("decision core poisoned")
                .0;
        }
    }

    fn allows_destination(&self, policy: PolicyId, dst: SocketAddr) -> bool {
        self.policies.read().unwrap().check(policy, dst).is_ok()
    }
}

pub struct Engine {
    core: Arc<Core>,
    groups: Arc<RwLock<Arc<Groups>>>,
    processes: Arc<dyn ProcessSource>,
    interceptor: Box<dyn TrafficInterceptor>,
    relays: Arc<RelayCounters>,
    udp: Arc<UdpCounters>,
    dns_backend: Option<DnsBackend>,
    dns: Option<DnsState>,
    dns_counters: Arc<DnsCounters>,
    housekeeping: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
    runtime: Option<Runtime>,
}

impl Engine {
    pub fn start(config: &Config, platform: Platform) -> anyhow::Result<Self> {
        config.validate()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("cladus-relay")
            .enable_all()
            .build()?;
        let core_state = DecisionCore::new(config, std::process::id());
        let core = Arc::new(Core {
            policies: RwLock::new(core_state.policies()),
            state: Mutex::new(core_state),
            urgent: AtomicUsize::new(0),
            inspector: platform.inspector,
            resync_needed: AtomicBool::new(false),
            processes: Arc::clone(&platform.processes),
            changed: Condvar::new(),
        });
        let groups = Arc::new(RwLock::new(groups_of(config)));
        let relays = Arc::new(RelayCounters::default());
        let udp = Arc::new(UdpCounters::default());
        // The UDP relay needs the injector that starting interception returns;
        // datagrams arriving before that are dropped.
        let udp_relay: Arc<OnceLock<Arc<UdpRelay>>> = Arc::default();
        let handoff = Handoff {
            tcp: {
                let (runtime, groups, relays) = (
                    runtime.handle().clone(),
                    Arc::clone(&groups),
                    Arc::clone(&relays),
                );
                Arc::new(move |redirected: RedirectedTcp| {
                    let proxy = groups.read().unwrap().get(&redirected.group).cloned();
                    spawn_relay(&runtime, proxy, &relays, redirected);
                })
            },
            udp: {
                let (udp_relay, groups) = (Arc::clone(&udp_relay), Arc::clone(&groups));
                Arc::new(move |datagram| {
                    if let Some(relay) = udp_relay.get() {
                        let proxy = groups.read().unwrap().get(&datagram.group).cloned();
                        relay.send(datagram, proxy);
                    }
                })
            },
        };
        let housekeeping = spawn_housekeeping(Arc::clone(&core), Arc::clone(&platform.processes));
        let mut engine = Self {
            core,
            groups,
            processes: platform.processes,
            interceptor: platform.interceptor,
            relays,
            udp,
            dns_backend: platform.dns,
            dns: None,
            dns_counters: Arc::default(),
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
        let injector = engine.interceptor.start(oracle, handoff)?;
        let runtime = engine
            .runtime
            .as_ref()
            .expect("runtime is running")
            .handle()
            .clone();
        let _ = udp_relay.set(UdpRelay::new(runtime, injector, Arc::clone(&engine.udp)));
        engine.apply_dns(config)?;
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
        counters.extend(self.udp.snapshot());
        counters.extend(self.dns_counters.snapshot());
        counters
    }

    pub fn processes(&self) -> Vec<ProcessView> {
        self.core.lock_background().snapshot()
    }

    /// `None` once `process` has exited.
    pub fn process_detail(&self, process: ProcessKey) -> Option<(Option<String>, Option<String>)> {
        let inspector = self.core.inspector.as_ref();
        if inspector.live_key(process.pid) != Some(process) {
            return None;
        }
        Some((inspector.image_path(process), inspector.cmdline(process)))
    }

    /// Call only with a validated configuration.
    pub fn reconfigure(&mut self, config: &Config) -> anyhow::Result<()> {
        config.validate()?;
        self.apply_dns(config)?;
        let mut core = self.core.lock_urgent();
        core.reconfigure(config, self.core.inspector.as_ref());
        *self.core.policies.write().unwrap() = core.policies();
        *self.groups.write().unwrap() = groups_of(config);
        drop(core);
        self.interceptor.refresh_assignments();
        Ok(())
    }

    fn apply_dns(&mut self, config: &Config) -> anyhow::Result<()> {
        if !config.dns.enabled {
            if let Some(state) = &mut self.dns {
                state.restore()?;
            }
            self.dns = None;
            return Ok(());
        }
        let proxy = config
            .group(config.dns.proxy_group_id)
            .map(|group| Arc::new(ProxyEndpoint::from(group)));
        let mut settings = DnsSettings {
            upstream: config.dns.upstream,
            proxy,
            strict: config.dns.strict,
            fallback: Vec::new(),
        };
        if let Some(state) = &self.dns {
            settings.fallback = state.forwarder.fallback();
            state.forwarder.update(settings);
            return Ok(());
        }
        let backend = self
            .dns_backend
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("redirecting system DNS is not supported here"))?;
        let runtime = self.runtime.as_ref().expect("runtime is running").handle();
        let listen = [
            SocketAddr::from((LISTEN_V4, 53)),
            SocketAddr::from((LISTEN_V6, 53)),
        ];
        let forwarder = Arc::new(
            DnsForwarder::start(runtime, &listen, settings, Arc::clone(&self.dns_counters))
                .map_err(|err| {
                    anyhow::anyhow!(
                        "cannot start the DNS forwarder on port 53: {err}. Another program                          may own port 53 (outside the Cladus service, a port held by a                          system service cannot be shared)"
                    )
                })?,
        );
        let redirect = Arc::new(DnsRedirect::new(
            Arc::clone(&backend.system),
            backend.journal.clone(),
        )?);
        let mut state = DnsState {
            forwarder,
            redirect,
            watcher: None,
        };
        state.forwarder.set_fallback(state.redirect.apply()?);
        let (forwarder, redirect) = (Arc::clone(&state.forwarder), Arc::clone(&state.redirect));
        let (stop, stopped) = mpsc::channel::<()>();
        // Interfaces that come up later are redirected too.
        let thread = thread::Builder::new()
            .name("cladus-dns-watch".to_owned())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    stopped.recv_timeout(Duration::from_secs(5))
                {
                    match redirect.apply() {
                        Ok(servers) => forwarder.set_fallback(servers),
                        Err(err) => warn!("cannot check interface DNS settings: {err:#}"),
                    }
                }
            })?;
        state.watcher = Some((stop, thread));
        self.dns = Some(state);
        info!("system DNS goes through the proxy");
        Ok(())
    }

    pub fn set_manual(&mut self, process: ProcessKey, group: Option<GroupId>) -> bool {
        if self.core.inspector.live_key(process.pid) != Some(process) {
            return false;
        }
        let changed = self.core.lock_urgent().set_manual(
            process.pid,
            group,
            self.core.inspector.as_ref(),
            Instant::now(),
        );
        self.interceptor.refresh_assignments();
        changed
    }

    pub fn set_excluded(&mut self, process: ProcessKey, rule_id: &str, excluded: bool) -> bool {
        if self.core.inspector.live_key(process.pid) != Some(process) {
            return false;
        }
        let changed = self.core.lock_urgent().set_excluded(
            process.pid,
            rule_id,
            excluded,
            self.core.inspector.as_ref(),
            Instant::now(),
        );
        self.interceptor.refresh_assignments();
        changed
    }

    /// Stops the engine and returns its final counters.
    /// Restore DNS first when an interactive stop must report recovery failures.
    pub fn prepare_stop(&mut self) -> anyhow::Result<()> {
        if let Some(state) = &mut self.dns {
            state.restore()?;
        }
        self.dns = None;
        Ok(())
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
        self.dns = None;
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
        .name("cladus-housekeeping".to_owned())
        .spawn(move || {
            let mut last_resync = Instant::now();
            while let Err(mpsc::RecvTimeoutError::Timeout) =
                stopped.recv_timeout(Duration::from_secs(1))
            {
                core.lock_background().tick(Instant::now());
                if core.resync_needed.load(Relaxed)
                    && last_resync.elapsed() >= Duration::from_secs(1)
                {
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
    proxy: Option<Arc<ProxyEndpoint>>,
    counters: &Arc<RelayCounters>,
    redirected: RedirectedTcp,
) {
    let Some(proxy) = proxy else {
        warn!(group = %redirected.group, "no such proxy group; closing the connection");
        return;
    };
    let counters = Arc::clone(counters);
    counters.started.fetch_add(1, Relaxed);
    counters.active.fetch_add(1, Relaxed);
    let active = ActiveRelay(Arc::clone(&counters));
    runtime.spawn(async move {
        let _active = active;
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
        drop(lease);
    });
}

struct ActiveRelay(Arc<RelayCounters>);

impl Drop for ActiveRelay {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Relaxed);
    }
}
