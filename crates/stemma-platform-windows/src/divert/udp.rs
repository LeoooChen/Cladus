//! UDP interception.
//!
//! Datagrams from sockets of proxied processes are taken off the network and
//! handed to the engine, which forwards them through a SOCKS5 UDP relay;
//! replies are injected back as inbound datagrams. Which process owns a local
//! port is looked up when the port's first datagram is seen, so sockets that
//! existed before interception started are covered as well. BIND and CLOSE
//! events from the socket layer forget a port's decision when it is reused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};
use std::sync::atomic::{AtomicU16, AtomicU64};
use std::thread::JoinHandle;

use arc_swap::ArcSwapOption;
use stemma_core::model::{DirectReason, FlowQuery, Protocol, Verdict};
use stemma_core::platform::{DecisionOracle, PlatformError, RedirectedUdp, UdpInjector};
use tracing::{debug, error};
use windows_sys::Win32::Foundation::ERROR_NO_DATA;

use super::ffi::{self, Address, Handle, WinDivert};
use super::packet::{self, Packet};
use super::{Counters, NETWORK_PRIORITY, spawn};
use crate::sockets::udp_owner;

const NETWORK_FILTER: &str = "outbound and !loopback and udp";
const SOCKET_FILTER: &str = "udp and (event == BIND or event == CLOSE)";
const NETWORK_WORKERS: usize = 2;

/// What is known about one local UDP port.
#[derive(Default)]
struct Slot {
    generation: AtomicU64,
    decision: ArcSwapOption<SocketDecision>,
}

struct SocketDecision {
    generation: u64,
    app: SocketAddr,
    verdict: Verdict,
    interface: (u32, u32),
    observed_at: i64,
}

impl Slot {
    fn forget(&self, event_at: i64) {
        if self
            .decision
            .load()
            .as_ref()
            .is_some_and(|entry| entry.observed_at > event_at)
        {
            return;
        }
        self.generation.fetch_add(1, AcqRel);
        self.decision.store(None);
    }

    fn current(&self, app: SocketAddr) -> Option<Arc<SocketDecision>> {
        self.decision
            .load_full()
            .filter(|entry| entry.app == app && entry.generation == self.generation.load(Acquire))
    }
}

struct Shared {
    /// Per address family (IPv4, IPv6), per local port.
    slots: [Box<[Slot]>; 2],
    network: Handle,
    oracle: Arc<dyn DecisionOracle>,
    handoff: Arc<dyn Fn(RedirectedUdp) + Send + Sync>,
    counters: Arc<Counters>,
    next_ip_id: AtomicU16,
}

impl Shared {
    fn slot(&self, ipv6: bool, port: u16) -> &Slot {
        &self.slots[usize::from(ipv6)][usize::from(port)]
    }

    fn forget(&self, port: u16, event_at: i64) {
        for slots in &self.slots {
            slots[usize::from(port)].forget(event_at);
        }
    }
}

pub(super) struct Udp {
    shared: Arc<Shared>,
    socket: Arc<Handle>,
    workers: Vec<JoinHandle<()>>,
    socket_thread: JoinHandle<()>,
}

impl Udp {
    pub(super) fn start(
        api: &Arc<WinDivert>,
        oracle: Arc<dyn DecisionOracle>,
        handoff: Arc<dyn Fn(RedirectedUdp) + Send + Sync>,
        counters: Arc<Counters>,
    ) -> Result<(Self, Arc<dyn UdpInjector>), PlatformError> {
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
        let table = || {
            (0..1 << 16)
                .map(|_| Slot::default())
                .collect::<Box<[Slot]>>()
        };
        let shared = Arc::new(Shared {
            slots: [table(), table()],
            network,
            oracle,
            handoff,
            counters,
            next_ip_id: AtomicU16::new(1),
        });
        let workers = (0..NETWORK_WORKERS)
            .map(|i| {
                let shared = Arc::clone(&shared);
                spawn(&format!("stemma-udp-net-{i}"), move || {
                    network_loop(&shared)
                })
            })
            .collect();
        let socket_thread = spawn("stemma-udp-socket", {
            let (shared, socket) = (Arc::clone(&shared), Arc::clone(&socket));
            move || socket_loop(&shared, &socket)
        });
        let injector: Arc<dyn UdpInjector> = Arc::new(Injector(Arc::clone(&shared)));
        Ok((
            Self {
                shared,
                socket,
                workers,
                socket_thread,
            },
            injector,
        ))
    }

    pub(super) fn stop(self) {
        self.shared.network.shutdown_recv();
        for worker in self.workers {
            let _ = worker.join();
        }
        self.socket.shutdown_recv();
        let _ = self.socket_thread.join();
    }

    pub(super) fn refresh_assignments(&self) {
        for family in &self.shared.slots {
            for slot in family {
                slot.forget(i64::MAX);
            }
        }
    }
}

/// Forgets a port's decision whenever a socket binds or closes it.
fn socket_loop(shared: &Shared, socket: &Handle) {
    let mut addr = Address::zeroed();
    loop {
        if let Err(code) = socket.recv(&mut [], &mut addr) {
            if code != ERROR_NO_DATA {
                error!(code, "UDP socket-layer receive failed");
            }
            return;
        }
        if matches!(
            addr.event(),
            ffi::EVENT_SOCKET_BIND | ffi::EVENT_SOCKET_CLOSE
        ) {
            shared.forget(addr.socket().local_port, addr.timestamp);
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
                    error!(code, "UDP network-layer receive failed");
                }
                return;
            }
        };
        if !divert(shared, &mut buffer[..len], &addr)
            && let Err(code) = shared.network.send(&buffer[..len], &addr)
        {
            debug!(code, "WinDivertSend failed");
        }
    }
}

/// Hands the datagram to the engine if its socket is proxied. Returns false
/// if it must be sent on unchanged.
fn divert(shared: &Shared, buffer: &mut [u8], addr: &Address) -> bool {
    let Some(packet) = Packet::parse(buffer).filter(|p| p.protocol() == packet::UDP) else {
        return false;
    };
    let (app, dst) = (packet.src(), packet.dst());
    let slot = shared.slot(packet.is_ipv6(), app.port());
    let entry = match slot.current(app) {
        Some(entry) => entry,
        None => match decide(shared, slot, app, addr) {
            Some(entry) => entry,
            // Ownership changed while it was read. Do not leak this datagram
            // under a decision belonging to a different socket.
            None => return true,
        },
    };
    let Verdict::Proxy { group, policy } = entry.verdict else {
        return false;
    };
    if !shared.oracle.allows_destination(policy, dst) {
        return false;
    }
    shared.counters.udp_datagrams_out.fetch_add(1, Relaxed);
    (shared.handoff)(RedirectedUdp {
        app,
        generation: entry.generation,
        dst,
        group,
        payload: packet.payload().to_vec(),
    });
    true
}

/// Decides a port on its first datagram and records the result.
fn decide(
    shared: &Shared,
    slot: &Slot,
    app: SocketAddr,
    addr: &Address,
) -> Option<Arc<SocketDecision>> {
    let generation = slot.generation.load(Acquire);
    let verdict = match udp_owner(app) {
        Some(pid) => shared.oracle.decide(&FlowQuery {
            pid,
            protocol: Protocol::Udp,
            remote: None,
        }),
        None => {
            shared.counters.udp_owner_unknown.fetch_add(1, Relaxed);
            Verdict::Direct(DirectReason::UnknownProcess)
        }
    };
    if slot.generation.load(Acquire) != generation {
        return None;
    }
    if let Verdict::Proxy { group, .. } = verdict {
        shared.counters.udp_sockets_proxied.fetch_add(1, Relaxed);
        debug!(%app, %group, "proxying UDP socket");
    }
    let entry = Arc::new(SocketDecision {
        generation,
        app,
        verdict,
        interface: addr.interface(),
        observed_at: addr.timestamp,
    });
    if verdict != Verdict::Direct(DirectReason::UnknownProcess) {
        slot.decision.store(Some(Arc::clone(&entry)));
    }
    Some(entry)
}

struct Injector(Arc<Shared>);

impl UdpInjector for Injector {
    fn inject(&self, app: SocketAddr, generation: u64, from: SocketAddr, payload: &[u8]) -> bool {
        let shared = &self.0;
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        let ipv6 = app.is_ipv6();
        let Some(entry) = shared.slot(ipv6, app.port()).current(app).filter(|entry| {
            entry.generation == generation && matches!(entry.verdict, Verdict::Proxy { .. })
        }) else {
            return false;
        };
        let id = shared.next_ip_id.fetch_add(1, Relaxed);
        let Some(mut packet) = packet::build_udp(from, app, payload, id) else {
            shared.counters.udp_inject_failed.fetch_add(1, Relaxed);
            return false;
        };
        let mut addr = Address::inbound(entry.interface, ipv6);
        shared.network.api().calc_checksums(&mut packet, &mut addr);
        match shared.network.send(&packet, &addr) {
            Ok(()) => {
                shared.counters.udp_datagrams_in.fetch_add(1, Relaxed);
                true
            }
            Err(code) => {
                shared.counters.udp_inject_failed.fetch_add(1, Relaxed);
                debug!(code, %app, "UDP reply injection failed");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(generation: u64) -> Arc<SocketDecision> {
        Arc::new(SocketDecision {
            generation,
            app: "192.168.1.2:50000".parse().unwrap(),
            verdict: Verdict::Direct(DirectReason::NotAssigned),
            interface: (1, 0),
            observed_at: 20,
        })
    }

    #[test]
    fn socket_reuse_invalidates_a_cached_decision() {
        let slot = Slot::default();
        let old = entry(0);
        slot.decision.store(Some(Arc::clone(&old)));
        assert!(slot.current(old.app).is_some());
        slot.forget(30);
        assert!(slot.current(old.app).is_none());
        // A racing publisher must not resurrect an old generation.
        slot.decision.store(Some(Arc::clone(&old)));
        assert!(slot.current(old.app).is_none());
        slot.decision.store(Some(entry(1)));
        assert!(slot.current(old.app).is_some());
    }

    #[test]
    fn delayed_bind_does_not_invalidate_the_first_datagram() {
        let slot = Slot::default();
        let current = entry(0);
        slot.decision.store(Some(Arc::clone(&current)));
        slot.forget(10);
        assert!(slot.current(current.app).is_some());
        assert!(slot.current("192.168.1.3:50000".parse().unwrap()).is_none());
    }
}
