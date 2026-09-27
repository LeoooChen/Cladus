//! Plain data types shared by the core and the platform backends.

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::config::RuleProtocol;

/// Identity of a process that stays unique when the OS reuses its PID.
///
/// `instance` tells apart processes that held the same PID at different
/// times: the ProcessSequenceNumber on Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub instance: u64,
}

impl fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.pid, self.instance)
    }
}

/// How a process refers to its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentRef {
    pub pid: u32,
    /// `None` when the parent had already exited and its identity could not
    /// be read. The tree then links by PID only when creation times prove the
    /// candidate is older than the child.
    pub instance: Option<u64>,
}

/// A process as announced by a [`ProcessSource`](crate::platform::ProcessSource)
/// or resolved through a [`ProcessInspector`](crate::platform::ProcessInspector).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub key: ProcessKey,
    pub parent: Option<ParentRef>,
    /// Image file name without directory, e.g. `chrome.exe`.
    pub name: String,
    /// Creation time in platform ticks, 0 when unknown. Only ever compared
    /// with other creation times from the same platform.
    pub create_time: u64,
}

/// Identifier of a proxy group in the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub u32);

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Which rule covers a process, and whether it matched the process itself or
/// one of its ancestors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Index of the rule in the active rule set.
    pub rule: usize,
    pub inherited: bool,
    pub group: GroupId,
    pub protocol: RuleProtocol,
}

/// A connection attempt the platform asks the core about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowQuery {
    pub pid: u32,
    pub protocol: Protocol,
    pub remote: SocketAddr,
}

/// What to do with a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Direct(DirectReason),
    Proxy { group: GroupId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectReason {
    /// Stemma's own connections are never intercepted.
    SelfProcess,
    /// The process could not be identified (already exited or inaccessible).
    UnknownProcess,
    /// No rule covers the process.
    NotAssigned,
    /// The covering rule does not include this protocol.
    ProtocolNotSelected,
    /// The destination is loopback or matches a global exclusion.
    ExcludedDestination,
}

impl DirectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfProcess => "self",
            Self::UnknownProcess => "unknown-process",
            Self::NotAssigned => "not-assigned",
            Self::ProtocolNotSelected => "protocol-not-selected",
            Self::ExcludedDestination => "excluded-destination",
        }
    }
}
