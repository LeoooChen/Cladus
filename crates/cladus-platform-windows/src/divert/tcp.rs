//! TCP interception: CONNECT decisions from the socket layer, SYN parking,
//! and reflection of proxied flows into the local acceptor.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::JoinHandle;
use std::time::Duration;

use cladus_core::config::SynParking;
use cladus_core::model::{FlowQuery, GroupId, Protocol, Verdict};
use cladus_core::platform::{Counter, DecisionOracle, FlowLease, PlatformError, RedirectedTcp};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};
use windows_sys::Win32::Foundation::ERROR_NO_DATA;

use super::ffi::{self, Address, Handle, SocketData, WinDivert};
use super::packet::{self, Packet};
use super::parker::Parker;
use super::tracker::{Decision, PortTracker, Publish, SlotState};
use super::{Counters, NETWORK_PRIORITY, spawn};
use crate::util::qpc_frequency;

const NETWORK_FILTER: &str = "outbound and !loopback and tcp";
const SOCKET_FILTER: &str =
    "outbound and !loopback and tcp and (event == CONNECT or event == CLOSE)";
const NETWORK_WORKERS: usize = 2;

/// One port table per address family: index 0 for IPv4, 1 for IPv6.
type Trackers = [PortTracker; 2];

fn family(ip: IpAddr) -> usize {
    usize::from(ip.is_ipv6())
}

/// State shared by the TCP threads.
struct Shared {
    trackers: Arc<Trackers>,
    network: Handle,
    parker: Option<Parker>,
    acceptor_port: u16,
    counters: Arc<Counters>,
}

pub(super) struct Tcp {
    shared: Arc<Shared>,
    socket: Arc<Handle>,
    stop: oneshot::Sender<()>,
    workers: Vec<JoinHandle<()>>,
    socket_thread: JoinHandle<()>,
    injector: Option<JoinHandle<()>>,
    acceptor: JoinHandle<()>,
}

impl Tcp {
    pub(super) fn start(
        api: &Arc<WinDivert>,
        parking: &SynParking,
        oracle: Arc<dyn DecisionOracle>,
        handoff: Arc<dyn Fn(RedirectedTcp) + Send + Sync>,
        counters: Arc<Counters>,
    ) -> Result<Self, PlatformError> {
        let frequency = qpc_frequency();
        // A decision older than 10 ms does not belong to the SYN at hand.
        let ttl = frequency / 100;
        let trackers = Arc::new([PortTracker::new(ttl), PortTracker::new(ttl)]);
        let listener = dual_stack_listener().map_err(|e| {
            PlatformError::Other(format!("cannot listen for redirected connections: {e}"))
        })?;
        let acceptor_port = listener
            .local_addr()
            .map_err(|e| PlatformError::Other(e.to_string()))?
            .port();
        // The accept loop has its own event-driven runtime. Shutdown must not
        // depend on a loopback connection succeeding (firewall/service isolation).
        let accept_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| PlatformError::Other(format!("cannot start TCP accept runtime: {e}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| PlatformError::Other(e.to_string()))?;
        let listener = {
            let _guard = accept_runtime.enter();
            tokio::net::TcpListener::from_std(listener)
                .map_err(|e| PlatformError::Other(e.to_string()))?
        };
        let network = Handle::open(api, NETWORK_FILTER, ffi::LAYER_NETWORK, NETWORK_PRIORITY, 0)?;
        network.set_param(ffi::PARAM_QUEUE_LENGTH, 16_384);
        network.set_param(ffi::PARAM_QUEUE_TIME, 2_000);
        network.set_param(ffi::PARAM_QUEUE_SIZE, 16 << 20);
        let socket = Arc::new(Handle::open(
            api,
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
            syn_parking = parking.enabled,
            "TCP interception started"
        );

        let parker = parking.enabled.then(|| {
            let watchdog = frequency * i64::from(parking.watchdog_ms) / 1000;
            Parker::new(parking.pool_size as usize, watchdog)
        });
        let shared = Arc::new(Shared {
            trackers: Arc::clone(&trackers),
            network,
            parker,
            acceptor_port,
            counters: Arc::clone(&counters),
        });
        let (stop, stopped) = oneshot::channel();

        let socket_thread = spawn("cladus-tcp-socket", {
            let (shared, socket) = (Arc::clone(&shared), Arc::clone(&socket));
            move || socket_loop(&shared, &socket, oracle.as_ref())
        });
        let injector = shared.parker.is_some().then(|| {
            let shared = Arc::clone(&shared);
            spawn("cladus-tcp-parking", move || {
                let parker = shared.parker.as_ref().expect("parking enabled");
                parker.run(&shared.trackers, &|packet, addr, decision| {
                    send_decided(&shared, packet, addr, decision);
                });
            })
        });
        let workers = (0..NETWORK_WORKERS)
            .map(|i| {
                let shared = Arc::clone(&shared);
                spawn(&format!("cladus-tcp-net-{i}"), move || {
                    network_loop(&shared)
                })
            })
            .collect();
        let acceptor = spawn("cladus-tcp-accept", {
            move || {
                accept_runtime.block_on(accept_loop(
                    &listener,
                    &trackers,
                    handoff.as_ref(),
                    stopped,
                    &counters,
                ))
            }
        });
        Ok(Self {
            shared,
            socket,
            stop,
            workers,
            socket_thread,
            injector,
            acceptor,
        })
    }

    pub(super) fn stop(self) {
        let _ = self.stop.send(());
        // From here on packets are no longer captured; the workers still send
        // on what is already queued.
        self.shared.network.shutdown_recv();
        for worker in self.workers {
            let _ = worker.join();
        }
        self.socket.shutdown_recv();
        let _ = self.socket_thread.join();
        if let Some(parker) = &self.shared.parker {
            parker.stop();
        }
        if let Some(injector) = self.injector {
            let _ = injector.join();
        }
        let _ = self.acceptor.join();
        info!("TCP interception stopped");
    }

    pub(super) fn parking_counters(&self) -> Vec<Counter> {
        let Some(parker) = &self.shared.parker else {
            return Vec::new();
        };
        vec![
            Counter {
                name: "syn.released_by_decision",
                value: parker.released_by_decision.load(Relaxed),
            },
            Counter {
                name: "syn.released_by_watchdog",
                value: parker.released_by_watchdog.load(Relaxed),
            },
            Counter {
                name: "syn.pool_in_use",
                value: u64::from(parker.in_use()),
            },
            Counter {
                name: "syn.pool_peak",
                value: u64::from(parker.peak()),
            },
        ]
    }
}

/// Accepts IPv4 (as IPv4-mapped) and IPv6 connections on one port.
fn dual_stack_listener() -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(SocketProtocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

fn socket_loop(shared: &Shared, socket: &Handle, oracle: &dyn DecisionOracle) {
    let mut addr = Address::zeroed();
    loop {
        if let Err(code) = socket.recv(&mut [], &mut addr) {
            if code != ERROR_NO_DATA {
                error!(
                    code,
                    "socket-layer receive failed; new connections are no longer proxied"
                );
            }
            return;
        }
        let data = addr.socket();
        match addr.event() {
            ffi::EVENT_SOCKET_CONNECT => on_connect(shared, oracle, &addr, &data),
            ffi::EVENT_SOCKET_CLOSE => {
                // A CLOSE does not tell the address family; each table checks
                // whether the CLOSE belongs to its flow on this port.
                for tracker in shared.trackers.iter() {
                    if let Some(pending) = tracker.on_close(data.local_port, addr.timestamp) {
                        // The socket closed while its SYN was parked; drop it.
                        if let Some(parker) = &shared.parker {
                            parker.free(pending.index());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn on_connect(shared: &Shared, oracle: &dyn DecisionOracle, addr: &Address, data: &SocketData) {
    let counters = &shared.counters;
    counters.tcp_connects.fetch_add(1, Relaxed);
    let port = data.local_port;
    let remote_ip = data.remote_ip();
    let remote = SocketAddr::new(remote_ip, data.remote_port);
    let tracker = &shared.trackers[family(remote_ip)];
    if data.process_id == 4 && tracker.is_echo(port, addr.timestamp, remote_ip, data.remote_port) {
        counters.tcp_echoes.fetch_add(1, Relaxed);
        return;
    }
    let verdict = oracle.decide(&FlowQuery {
        pid: data.process_id,
        protocol: Protocol::Tcp,
        remote: Some(remote),
    });
    let decision = match verdict {
        Verdict::Proxy { group, .. } => {
            counters.tcp_proxied.fetch_add(1, Relaxed);
            debug!(pid = data.process_id, port, %remote, %group, "proxying TCP connection");
            Decision::Proxied { group: group.0 }
        }
        Verdict::Direct(reason) => {
            counters.tcp_direct.fetch_add(1, Relaxed);
            debug!(pid = data.process_id, port, %remote, reason = reason.as_str(), "direct TCP connection");
            Decision::Direct
        }
    };
    match tracker.publish(port, decision, remote_ip, data.remote_port, addr.timestamp) {
        Publish::Stored => {}
        Publish::Released(pending) => {
            if let Some(parker) = &shared.parker {
                parker.release(pending, decision);
            }
        }
        Publish::LateRejected => {
            counters.tcp_late_rejected.fetch_add(1, Relaxed);
            if matches!(decision, Decision::Proxied { .. }) {
                counters.tcp_proxy_late_rejected.fetch_add(1, Relaxed);
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

fn handle_packet(shared: &Shared, buffer: &mut [u8], addr: &mut Address) {
    let Some(packet) = Packet::parse(buffer).filter(|p| p.protocol() == packet::TCP) else {
        return send_unchanged(shared, buffer, addr);
    };
    let family = usize::from(packet.is_ipv6());
    let (src_port, dst_port) = (packet.src_port(), packet.dst_port());
    let tracker = &shared.trackers[family];
    if src_port == shared.acceptor_port {
        // The acceptor answering a redirected connection.
        return match tracker.proxied_remote_port(dst_port) {
            Some(original_port) => from_acceptor(shared, buffer, addr, original_port),
            None => send_unchanged(shared, buffer, addr),
        };
    }
    if packet.is_initial_syn() {
        let seq = packet.seq();
        return handle_syn(shared, family, buffer, addr, src_port, seq);
    }
    if tracker.state(src_port) == SlotState::Proxied {
        to_acceptor(shared, buffer, addr);
    } else {
        send_unchanged(shared, buffer, addr);
    }
}

/// The first packet of a connection. It must not leave before its flow has
/// been decided, or a proxied flow would escape.
fn handle_syn(
    shared: &Shared,
    family: usize,
    packet: &mut [u8],
    addr: &mut Address,
    port: u16,
    seq: u32,
) {
    let tracker = &shared.trackers[family];
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
    let Some((generation, index)) = parker.park(packet, addr, family, port) else {
        shared.counters.syn_park_failed.fetch_add(1, Relaxed);
        tracker.pin_abandoned(port, view.word, addr.timestamp);
        return send_unchanged(shared, packet, addr);
    };
    if tracker.try_park(port, view.word, generation, index, addr.timestamp) {
        shared.counters.syn_parked.fetch_add(1, Relaxed);
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
fn to_acceptor(shared: &Shared, buffer: &mut [u8], addr: &mut Address) {
    let mut packet = Packet::parse(buffer).expect("packet was parsed before");
    packet.swap_addresses();
    packet.set_dst_port(shared.acceptor_port);
    inject_inbound(shared, buffer, addr);
}

/// The acceptor's reply becomes an inbound packet to the application, coming
/// from the original destination.
fn from_acceptor(shared: &Shared, buffer: &mut [u8], addr: &mut Address, original_port: u16) {
    let mut packet = Packet::parse(buffer).expect("packet was parsed before");
    packet.swap_addresses();
    packet.set_src_port(original_port);
    inject_inbound(shared, buffer, addr);
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

async fn accept_loop(
    listener: &tokio::net::TcpListener,
    trackers: &Arc<Trackers>,
    handoff: &(dyn Fn(RedirectedTcp) + Send + Sync),
    mut stop: oneshot::Receiver<()>,
    counters: &Counters,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = &mut stop => return,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(err) => {
                debug!(%err, "accept failed");
                tokio::select! {
                    _ = &mut stop => return,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
                continue;
            }
        };
        // A redirected connection arrives from (original destination, the
        // application's local port). Anything else is not ours.
        let Ok(peer) = stream.peer_addr() else {
            continue;
        };
        let (peer_ip, port) = (peer.ip().to_canonical(), peer.port());
        let family = family(peer_ip);
        let Some(taken) = trackers[family]
            .take(port)
            .filter(|t| t.remote_ip == peer_ip)
        else {
            counters.tcp_rejected_peers.fetch_add(1, Relaxed);
            debug!(%peer, "closed an unexpected connection to the redirect listener");
            continue;
        };
        counters.tcp_accepted.fetch_add(1, Relaxed);
        let lease_trackers = Arc::clone(trackers);
        let Ok(stream) = stream.into_std() else {
            continue;
        };
        handoff(RedirectedTcp {
            stream,
            original_dst: SocketAddr::new(taken.remote_ip, taken.remote_port),
            group: GroupId(taken.group),
            lease: FlowLease::new(move || {
                lease_trackers[family].clear_if(port, taken.word);
            }),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acceptor_cancels_without_any_wakeup_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let trackers = Arc::new([PortTracker::new(1), PortTracker::new(1)]);
        let counters = Counters::default();
        let (stop, stopped) = oneshot::channel();
        let handoff = |_: RedirectedTcp| panic!("no connection should arrive");
        let accepting = accept_loop(&listener, &trackers, &handoff, stopped, &counters);
        let cancel = async {
            tokio::task::yield_now().await;
            stop.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(accepting, cancel);
        })
        .await
        .expect("idle accept must be cancellable without network activity");
        drop(listener);
        assert!(TcpListener::bind(address).is_ok());
    }
}
