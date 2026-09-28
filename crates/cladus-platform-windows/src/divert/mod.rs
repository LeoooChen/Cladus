//! Traffic interception with WinDivert.
//!
//! TCP: a socket-layer handle reports every `connect()` with its process ID,
//! and a decision is published per local port. A network-layer handle sees
//! every outbound TCP packet: packets of proxied flows are reflected into the
//! local acceptor by swapping source and destination and re-injecting them
//! inbound (WinDivert's streamdump technique), and the acceptor's replies are
//! swapped back. The network layer has no process IDs and the socket layer
//! cannot touch packets; the local port is the key they share.
//!
//! UDP: datagrams of proxied sockets are taken off the network and handed to
//! the engine; replies are injected back (see [`udp`]).

mod ffi;
mod packet;
mod parker;
mod tcp;
mod tracker;
mod udp;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::{self, JoinHandle};

use cladus_core::config::SynParking;
use cladus_core::platform::{
    Counter, DecisionOracle, Handoff, PlatformError, TrafficInterceptor, UdpInjector,
};
pub use ffi::WinDivert;

/// Above the default of 0, so Cladus sees packets before other WinDivert
/// users (such as Clew) and sends them on to those afterwards.
const NETWORK_PRIORITY: i16 = 1000;

#[derive(Default)]
struct Counters {
    tcp_connects: AtomicU64,
    tcp_proxied: AtomicU64,
    tcp_direct: AtomicU64,
    tcp_echoes: AtomicU64,
    tcp_late_rejected: AtomicU64,
    tcp_proxy_late_rejected: AtomicU64,
    tcp_accepted: AtomicU64,
    tcp_rejected_peers: AtomicU64,
    syn_parked: AtomicU64,
    syn_park_failed: AtomicU64,
    udp_sockets_proxied: AtomicU64,
    udp_owner_unknown: AtomicU64,
    udp_datagrams_out: AtomicU64,
    udp_datagrams_in: AtomicU64,
    udp_inject_failed: AtomicU64,
}

/// Intercepts TCP and UDP traffic of proxied processes.
pub struct Interceptor {
    api: Arc<WinDivert>,
    parking: SynParking,
    counters: Arc<Counters>,
    running: Option<(tcp::Tcp, udp::Udp)>,
    /// Parking counters as they were when interception stopped.
    final_parking: Vec<Counter>,
}

impl Interceptor {
    pub fn new(api: Arc<WinDivert>, parking: SynParking) -> Self {
        Self {
            api,
            parking,
            counters: Arc::default(),
            running: None,
            final_parking: Vec::new(),
        }
    }
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

impl TrafficInterceptor for Interceptor {
    fn start(
        &mut self,
        oracle: Arc<dyn DecisionOracle>,
        handoff: Handoff,
    ) -> Result<Arc<dyn UdpInjector>, PlatformError> {
        if self.running.is_some() {
            return Err(PlatformError::Other(
                "interception is already running".to_owned(),
            ));
        }
        let tcp = tcp::Tcp::start(
            &self.api,
            &self.parking,
            Arc::clone(&oracle),
            handoff.tcp,
            Arc::clone(&self.counters),
        )?;
        let (udp, injector) =
            match udp::Udp::start(&self.api, oracle, handoff.udp, Arc::clone(&self.counters)) {
                Ok(started) => started,
                Err(err) => {
                    tcp.stop();
                    return Err(err);
                }
            };
        self.running = Some((tcp, udp));
        Ok(injector)
    }

    fn stop(&mut self) {
        if let Some((tcp, udp)) = self.running.take() {
            udp.stop();
            self.final_parking = tcp.parking_counters();
            tcp.stop();
        }
    }

    fn counters(&self) -> Vec<Counter> {
        let c = &self.counters;
        let counter = |name, value: &AtomicU64| Counter {
            name,
            value: value.load(Relaxed),
        };
        let mut counters = vec![
            counter("tcp.connects", &c.tcp_connects),
            counter("tcp.proxied", &c.tcp_proxied),
            counter("tcp.direct", &c.tcp_direct),
            counter("tcp.echoes_ignored", &c.tcp_echoes),
            counter("tcp.late_rejected", &c.tcp_late_rejected),
            counter("tcp.proxy_late_rejected", &c.tcp_proxy_late_rejected),
            counter("tcp.accepted", &c.tcp_accepted),
            counter("tcp.rejected_peers", &c.tcp_rejected_peers),
            counter("syn.parked", &c.syn_parked),
            counter("syn.park_failed", &c.syn_park_failed),
            counter("udp.sockets_proxied", &c.udp_sockets_proxied),
            counter("udp.owner_unknown", &c.udp_owner_unknown),
            counter("udp.datagrams_out", &c.udp_datagrams_out),
            counter("udp.datagrams_in", &c.udp_datagrams_in),
            counter("udp.inject_failed", &c.udp_inject_failed),
        ];
        match &self.running {
            Some((tcp, _)) => counters.extend(tcp.parking_counters()),
            None => counters.extend(self.final_parking.iter().cloned()),
        }
        counters
    }

    fn refresh_assignments(&self) {
        if let Some((_, udp)) = &self.running {
            udp.refresh_assignments();
        }
    }
}

fn spawn(name: &str, body: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .expect("failed to spawn a thread")
}
