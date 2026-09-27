use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use stemma_core::config::SynParking;
use stemma_core::model::{FlowQuery, GroupId, Protocol, Verdict};
use stemma_core::platform::{
    Counter, DecisionOracle, FlowLease, PlatformError, RedirectedTcp, TcpHandoff,
    TrafficInterceptor,
};
use tracing::{debug, error, info, warn};
use windows_sys::Win32::Foundation::ERROR_NO_DATA;

use super::ffi::{self, Address, Handle, SocketData, WinDivert};
use super::packet::Ipv4Tcp;
use super::parker::Parker;
use super::tracker::{Decision, PortTracker, Publish, SlotState};
use crate::util::qpc_frequency;

const NETWORK_FILTER: &str = "outbound and !loopback and ip and tcp";
// No `ip` here: the socket layer reports IPv4 endpoints IPv4-mapped, so they
// never match it. IPv6 connections are skipped in code instead.
const SOCKET_FILTER: &str = "outbound and !loopback and tcp and (event == CONNECT or event == CLOSE)";
const NETWORK_WORKERS: usize = 2;
/// Above the default of 0, so Stemma sees packets before other WinDivert
/// users (such as Clew) and sends them on to those afterwards.
const NETWORK_PRIORITY: i16 = 1000;

pub struct TcpInterceptor {
    api: Arc<WinDivert>,
    parking: SynParking,
    counters: Arc<Counters>,
    running: Option<Running>,
    /// Counters as they were when interception stopped.
    final_counters: Option<Vec<Counter>>,
}

#[derive(Default)]
struct Counters {
    connects: AtomicU64,
    proxied: AtomicU64,
    direct: AtomicU64,
    echoes: AtomicU64,
    late_rejected: AtomicU64,
    parked: AtomicU64,
    park_failed: AtomicU64,
    accepted: AtomicU64,
    rejected_peers: AtomicU64,
}

/// State shared by the packet threads.
struct Shared {
    tracker: Arc<PortTracker>,
    network: Handle,
    parker: Option<Parker>,
    acceptor_port: u16,
    counters: Arc<Counters>,
}

struct Running {
    shared: Arc<Shared>,
    socket: Arc<Handle>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    socket_thread: JoinHandle<()>,
    injector: Option<JoinHandle<()>>,
    acceptor: JoinHandle<()>,
}

impl TcpInterceptor {
    pub fn new(api: Arc<WinDivert>, parking: SynParking) -> Self {
        Self {
            api,
            parking,
            counters: Arc::default(),
            running: None,
            final_counters: None,
        }
    }
}

impl Drop for TcpInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

impl TrafficInterceptor for TcpInterceptor {
    fn start(
        &mut self,
        oracle: Arc<dyn DecisionOracle>,
        handoff: TcpHandoff,
    ) -> Result<(), PlatformError> {
        if self.running.is_some() {
            return Ok(());
        }
        let frequency = qpc_frequency();
        // A decision older than this does not belong to the SYN at hand.
        let tracker = Arc::new(PortTracker::new(frequency / 100));
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| {
            PlatformError::Other(format!("cannot listen for redirected connections: {e}"))
        })?;
        let acceptor_port = listener
            .local_addr()
            .map_err(|e| PlatformError::Other(e.to_string()))?
            .port();

        let network = Handle::open(&self.api, NETWORK_FILTER, ffi::LAYER_NETWORK, NETWORK_PRIORITY, 0)?;
        network.set_param(ffi::PARAM_QUEUE_LENGTH, 16_384);
        network.set_param(ffi::PARAM_QUEUE_TIME, 2_000);
        network.set_param(ffi::PARAM_QUEUE_SIZE, 16 << 20);
        let socket = Arc::new(Handle::open(
            &self.api,
            SOCKET_FILTER,
            ffi::LAYER_SOCKET,
            0,
            ffi::FLAG_SNIFF | ffi::FLAG_RECV_ONLY,
        )?);
        info!(
            driver = %format!(
                "{}.{}",
                network.param(ffi::PARAM_VERSION_MAJOR),
                network.param(ffi::PARAM_VERSION_MINOR)
            ),
            acceptor_port,
            syn_parking = self.parking.enabled,
            "TCP interception started"
        );

        let parker = self.parking.enabled.then(|| {
            let watchdog = frequency * i64::from(self.parking.watchdog_ms) / 1000;
            Parker::new(self.parking.pool_size as usize, watchdog)
        });
        let shared = Arc::new(Shared {
            tracker: Arc::clone(&tracker),
            network,
            parker,
            acceptor_port,
            counters: Arc::clone(&self.counters),
        });
        let stop = Arc::new(AtomicBool::new(false));

        let socket_thread = spawn("stemma-tcp-socket", {
            let (shared, socket) = (Arc::clone(&shared), Arc::clone(&socket));
            move || socket_loop(&shared, &socket, oracle.as_ref())
        });
        let injector = shared.parker.is_some().then(|| {
            let shared = Arc::clone(&shared);
            spawn("stemma-tcp-parking", move || {
                let parker = shared.parker.as_ref().expect("parking enabled");
                parker.run(&shared.tracker, &|packet, addr, decision| {
                    send_decided(&shared, packet, addr, decision);
                });
            })
        });
        let workers = (0..NETWORK_WORKERS)
            .map(|i| {
                let shared = Arc::clone(&shared);
                spawn(&format!("stemma-tcp-net-{i}"), move || network_loop(&shared))
            })
            .collect();
        let acceptor = spawn("stemma-tcp-accept", {
            let (stop, counters) = (Arc::clone(&stop), Arc::clone(&self.counters));
            move || accept_loop(&listener, &tracker, &handoff, &stop, &counters)
        });
        self.running = Some(Running {
            shared,
            socket,
            stop,
            workers,
            socket_thread,
            injector,
            acceptor,
        });
        Ok(())
    }

    fn stop(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        running.stop.store(true, Relaxed);
        // From here on packets are no longer captured; the workers still send
        // on what is already queued.
        running.shared.network.shutdown_recv();
        for worker in running.workers {
            let _ = worker.join();
        }
        running.socket.shutdown_recv();
        let _ = running.socket_thread.join();
        if let Some(parker) = &running.shared.parker {
            parker.stop();
        }
        if let Some(injector) = running.injector {
            let _ = injector.join();
        }
        let wake = SocketAddr::from((Ipv4Addr::LOCALHOST, running.shared.acceptor_port));
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        let _ = running.acceptor.join();
        self.final_counters = Some(self.collect(running.shared.parker.as_ref()));
        info!("TCP interception stopped");
    }

    fn counters(&self) -> Vec<Counter> {
        match &self.running {
            Some(running) => self.collect(running.shared.parker.as_ref()),
            None => self
                .final_counters
                .clone()
                .unwrap_or_else(|| self.collect(None)),
        }
    }
}

impl TcpInterceptor {
    fn collect(&self, parker: Option<&Parker>) -> Vec<Counter> {
        let c = &self.counters;
        let mut counters = vec![
            counter("tcp.connects", &c.connects),
            counter("tcp.proxied", &c.proxied),
            counter("tcp.direct", &c.direct),
            counter("tcp.echoes_ignored", &c.echoes),
            counter("tcp.late_rejected", &c.late_rejected),
            counter("tcp.accepted", &c.accepted),
            counter("tcp.rejected_peers", &c.rejected_peers),
            counter("syn.parked", &c.parked),
            counter("syn.park_failed", &c.park_failed),
        ];
        if let Some(parker) = parker {
            counters.extend([
                counter("syn.released_by_decision", &parker.released_by_decision),
                counter("syn.released_by_watchdog", &parker.released_by_watchdog),
                Counter {
                    name: "syn.pool_in_use",
                    value: u64::from(parker.in_use()),
                },
                Counter {
                    name: "syn.pool_peak",
                    value: u64::from(parker.peak()),
                },
            ]);
        }
        counters
    }
}

fn counter(name: &'static str, value: &AtomicU64) -> Counter {
    Counter {
        name,
        value: value.load(Relaxed),
    }
}

fn spawn(name: &str, body: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .expect("failed to spawn a thread")
}

fn socket_loop(shared: &Shared, socket: &Handle, oracle: &dyn DecisionOracle) {
    let mut addr = Address::zeroed();
    loop {
        if let Err(code) = socket.recv(&mut [], &mut addr) {
            if code != ERROR_NO_DATA {
                error!(code, "socket-layer receive failed; new connections are no longer proxied");
            }
            return;
        }
        let data = addr.socket();
        match addr.event() {
            ffi::EVENT_SOCKET_CONNECT => on_connect(shared, oracle, &addr, &data),
            ffi::EVENT_SOCKET_CLOSE => {
                if let Some(pending) = shared.tracker.on_close(data.local_port, addr.timestamp) {
                    // The socket closed while its SYN was parked; drop the SYN.
                    if let Some(parker) = &shared.parker {
                        parker.free(pending.index());
                    }
                }
            }
            _ => {}
        }
    }
}

fn on_connect(shared: &Shared, oracle: &dyn DecisionOracle, addr: &Address, data: &SocketData) {
    // IPv6 connections are not intercepted; the network filter lets their
    // packets pass untouched.
    let Some(remote_ip) = data.remote_ipv4() else {
        return;
    };
    let counters = &shared.counters;
    counters.connects.fetch_add(1, Relaxed);
    let port = data.local_port;
    let remote = SocketAddr::from((remote_ip, data.remote_port));
    if shared
        .tracker
        .is_echo(port, addr.timestamp, remote_ip, data.remote_port)
    {
        counters.echoes.fetch_add(1, Relaxed);
        return;
    }
    let verdict = oracle.decide(&FlowQuery {
        pid: data.process_id,
        protocol: Protocol::Tcp,
        remote,
    });
    let decision = match verdict {
        Verdict::Proxy { group } => {
            counters.proxied.fetch_add(1, Relaxed);
            debug!(pid = data.process_id, port, %remote, %group, "proxying TCP connection");
            Decision::Proxied { group: group.0 }
        }
        Verdict::Direct(reason) => {
            counters.direct.fetch_add(1, Relaxed);
            debug!(pid = data.process_id, port, %remote, reason = reason.as_str(), "direct TCP connection");
            Decision::Direct
        }
    };
    match shared
        .tracker
        .publish(port, decision, remote_ip, data.remote_port, addr.timestamp)
    {
        Publish::Stored => {}
        Publish::Released(pending) => {
            if let Some(parker) = &shared.parker {
                parker.release(pending, decision);
            }
        }
        Publish::LateRejected => {
            counters.late_rejected.fetch_add(1, Relaxed);
            if matches!(decision, Decision::Proxied { .. }) {
                warn!(
                    pid = data.process_id,
                    port,
                    %remote,
                    "decision came after the connection had left directly; it is not proxied"
                );
            }
        }
    }
}

fn network_loop(shared: &Shared) {
    let mut buffer = vec![0u8; ffi::MTU_MAX];
    let mut addr = Address::zeroed();
    loop {
        let len = match shared.network.recv(&mut buffer, &mut addr) {
            Ok(len) => len,
            Err(code) => {
                if code != ERROR_NO_DATA {
                    error!(code, "network-layer receive failed");
                }
                return;
            }
        };
        handle_packet(shared, &mut buffer[..len], &mut addr);
    }
}

fn handle_packet(shared: &Shared, packet: &mut [u8], addr: &mut Address) {
    let Some(tcp) = Ipv4Tcp::parse(packet) else {
        return send_unchanged(shared, packet, addr);
    };
    let (src_port, dst_port) = (tcp.src_port(), tcp.dst_port());
    if src_port == shared.acceptor_port {
        // The acceptor answering a redirected connection.
        return match shared.tracker.proxied_remote_port(dst_port) {
            Some(original_port) => from_acceptor(shared, packet, addr, original_port),
            None => send_unchanged(shared, packet, addr),
        };
    }
    if tcp.is_initial_syn() {
        let seq = tcp.seq();
        return handle_syn(shared, packet, addr, src_port, seq);
    }
    if shared.tracker.state(src_port) == SlotState::Proxied {
        to_acceptor(shared, packet, addr);
    } else {
        send_unchanged(shared, packet, addr);
    }
}

/// The first packet of a connection. It must not leave before its flow has
/// been decided, or a proxied flow would escape.
fn handle_syn(shared: &Shared, packet: &mut [u8], addr: &mut Address, port: u16, seq: u32) {
    let tracker = &shared.tracker;
    let view = tracker.load(port);
    match view.word.state() {
        state @ (SlotState::Proxied | SlotState::Direct | SlotState::Abandoned) => {
            let decided_at = if state == SlotState::Abandoned {
                view.syn_ts
            } else {
                view.connect_ts
            };
            // Fresh decisions belong to this SYN. A retransmitted SYN (same
            // ISN) keeps the decision of its first transmission.
            if addr.timestamp - decided_at <= tracker.ttl() || tracker.is_retransmit(port, seq) {
                tracker.note_syn(port, seq);
                return send_by_state(shared, packet, addr, state);
            }
            // Otherwise the slot is left over from an earlier flow.
        }
        // The parked first transmission covers this flow.
        SlotState::Pending => return,
        SlotState::Empty => {}
    }
    tracker.note_syn(port, seq);
    let Some(parker) = &shared.parker else {
        // Parking disabled: let the SYN go direct and pin the port so that a
        // decision arriving later cannot redirect the connection mid-flow.
        tracker.pin_abandoned(port, view.word, addr.timestamp);
        return send_unchanged(shared, packet, addr);
    };
    let Some((generation, index)) = parker.park(packet, addr, port) else {
        shared.counters.park_failed.fetch_add(1, Relaxed);
        tracker.pin_abandoned(port, view.word, addr.timestamp);
        return send_unchanged(shared, packet, addr);
    };
    if tracker.try_park(port, view.word, generation, index, addr.timestamp) {
        shared.counters.parked.fetch_add(1, Relaxed);
        return;
    }
    // A decision landed between our read and the park: act on it now.
    parker.free(index);
    send_by_state(shared, packet, addr, tracker.state(port));
}

fn send_by_state(shared: &Shared, packet: &mut [u8], addr: &mut Address, state: SlotState) {
    if state == SlotState::Proxied {
        to_acceptor(shared, packet, addr);
    } else {
        send_unchanged(shared, packet, addr);
    }
}

fn send_decided(shared: &Shared, packet: &mut [u8], addr: &mut Address, decision: Decision) {
    match decision {
        Decision::Proxied { .. } => to_acceptor(shared, packet, addr),
        Decision::Direct => send_unchanged(shared, packet, addr),
    }
}

/// An outbound packet of a proxied flow becomes an inbound packet to the
/// acceptor, coming from the original destination.
fn to_acceptor(shared: &Shared, packet: &mut [u8], addr: &mut Address) {
    let mut tcp = Ipv4Tcp::parse(packet).expect("packet was parsed before");
    tcp.swap_addresses();
    tcp.set_dst_port(shared.acceptor_port);
    inject_inbound(shared, packet, addr);
}

/// The acceptor's reply becomes an inbound packet to the application, coming
/// from the original destination.
fn from_acceptor(shared: &Shared, packet: &mut [u8], addr: &mut Address, original_port: u16) {
    let mut tcp = Ipv4Tcp::parse(packet).expect("packet was parsed before");
    tcp.swap_addresses();
    tcp.set_src_port(original_port);
    inject_inbound(shared, packet, addr);
}

fn inject_inbound(shared: &Shared, packet: &mut [u8], addr: &mut Address) {
    addr.set_outbound(false);
    shared.network.api().calc_checksums(packet, addr);
    send_unchanged(shared, packet, addr);
}

fn send_unchanged(shared: &Shared, packet: &[u8], addr: &Address) {
    if let Err(code) = shared.network.send(packet, addr) {
        debug!(code, "WinDivertSend failed");
    }
}

fn accept_loop(
    listener: &TcpListener,
    tracker: &Arc<PortTracker>,
    handoff: &TcpHandoff,
    stop: &AtomicBool,
    counters: &Counters,
) {
    for stream in listener.incoming() {
        if stop.load(Relaxed) {
            return;
        }
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                debug!(%err, "accept failed");
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        // A redirected connection arrives from (original destination, the
        // application's local port). Anything else is not ours.
        let Ok(SocketAddr::V4(peer)) = stream.peer_addr() else {
            continue;
        };
        let port = peer.port();
        let Some(taken) = tracker.take(port).filter(|t| t.remote_ip == *peer.ip()) else {
            counters.rejected_peers.fetch_add(1, Relaxed);
            debug!(%peer, "closed an unexpected connection to the redirect listener");
            continue;
        };
        counters.accepted.fetch_add(1, Relaxed);
        let lease_tracker = Arc::clone(tracker);
        handoff(RedirectedTcp {
            stream,
            original_dst: SocketAddr::from((taken.remote_ip, taken.remote_port)),
            group: GroupId(taken.group),
            lease: FlowLease::new(move || {
                lease_tracker.clear_if(port, taken.word);
            }),
        });
    }
}
