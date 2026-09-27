//! Interfaces between the core and operating-system backends.
//!
//! A backend provides process events ([`ProcessSource`]), on-demand process
//! queries ([`ProcessInspector`]) and traffic interception
//! ([`TrafficInterceptor`]). The interceptor asks a [`DecisionOracle`] about
//! every new connection and socket, hands redirected TCP connections and UDP
//! datagrams to the engine, and injects UDP replies back.

use std::fmt;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use crate::model::{FlowQuery, GroupId, ProcessInfo, ProcessKey, Verdict};
use crate::policy::PolicyId;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("{operation} failed: {message}")]
    Os {
        operation: String,
        code: i32,
        message: String,
    },
    #[error("{0}")]
    Other(String),
}

/// Process lifecycle notifications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessEvent {
    /// A process started, or was announced by a resync.
    Started(ProcessInfo),
    Exited(ProcessKey),
    /// The source dropped `count` events; its view may be incomplete until
    /// the next resync.
    Lost {
        count: u64,
    },
}

pub type ProcessEventSink = Box<dyn Fn(ProcessEvent) + Send + Sync>;

pub trait ProcessSource: Send + Sync {
    /// Starts delivering events to `sink` from a backend thread.
    fn start(&self, sink: ProcessEventSink) -> Result<(), PlatformError>;
    /// Asks the source to announce every running process again.
    fn request_resync(&self);
    /// Makes already recorded events available promptly. Used when a first
    /// connection races the events of a short-lived ancestor.
    fn flush(&self) {}
    fn stop(&self);
}

/// One level of a process's ancestry, read from the live process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessDescription {
    pub key: ProcessKey,
    pub parent_pid: u32,
    pub name: String,
    pub create_time: u64,
}

/// Synchronous queries about running processes. Every call may hit the OS,
/// so callers cache the results.
pub trait ProcessInspector: Send + Sync {
    /// Identity of the process that currently owns `pid`.
    fn live_key(&self, pid: u32) -> Option<ProcessKey>;
    fn describe(&self, pid: u32) -> Option<ProcessDescription>;
    /// Full image path. `None` if `key` is no longer running.
    fn image_path(&self, key: ProcessKey) -> Option<String>;
    /// Command line. `None` if `key` is no longer running.
    fn cmdline(&self, key: ProcessKey) -> Option<String>;
}

pub trait DecisionOracle: Send + Sync {
    fn decide(&self, query: &FlowQuery) -> Verdict;
    /// Whether a datagram of a proxied socket may go to `dst` under the
    /// socket's policy. Called per datagram, so it must be cheap.
    fn allows_destination(&self, policy: PolicyId, dst: SocketAddr) -> bool;
}

/// Releases the backend state of one redirected connection when dropped.
pub struct FlowLease(Option<Box<dyn FnOnce() + Send>>);

impl FlowLease {
    pub fn new(release: impl FnOnce() + Send + 'static) -> Self {
        Self(Some(Box::new(release)))
    }
}

impl Drop for FlowLease {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            release();
        }
    }
}

impl fmt::Debug for FlowLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FlowLease")
    }
}

/// A TCP connection that the interceptor diverted to Stemma.
#[derive(Debug)]
pub struct RedirectedTcp {
    pub stream: TcpStream,
    /// Where the application was connecting to.
    pub original_dst: SocketAddr,
    pub group: GroupId,
    /// Keep alive for as long as the connection is relayed.
    pub lease: FlowLease,
}

/// A datagram an application sent from a proxied UDP socket. It was taken
/// off the network; the engine forwards it through the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectedUdp {
    /// The application's socket address.
    pub app: SocketAddr,
    /// Backend socket generation; replies to a closed/reused socket are discarded.
    pub generation: u64,
    pub dst: SocketAddr,
    pub group: GroupId,
    pub payload: Vec<u8>,
}

/// Delivers datagrams to applications as if they came from the network.
pub trait UdpInjector: Send + Sync {
    /// Delivers `payload` to the application socket `app`, from `from`.
    fn inject(&self, app: SocketAddr, generation: u64, from: SocketAddr, payload: &[u8]) -> bool;
}

/// Where the interceptor delivers redirected traffic. Both callbacks run on
/// backend threads and must return quickly.
#[derive(Clone)]
pub struct Handoff {
    pub tcp: Arc<dyn Fn(RedirectedTcp) + Send + Sync>,
    pub udp: Arc<dyn Fn(RedirectedUdp) + Send + Sync>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counter {
    pub name: &'static str,
    pub value: u64,
}

pub trait TrafficInterceptor: Send {
    /// Starts intercepting. Returns the injector for UDP replies.
    fn start(
        &mut self,
        oracle: Arc<dyn DecisionOracle>,
        handoff: Handoff,
    ) -> Result<Arc<dyn UdpInjector>, PlatformError>;
    /// Stops interception. Traffic must keep flowing directly afterwards.
    fn stop(&mut self);
    fn counters(&self) -> Vec<Counter>;
    /// Invalidates cached socket assignments after rules or manual choices change.
    fn refresh_assignments(&self) {}
}
