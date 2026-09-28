//! Plain data types shared by the core and the platform backends.

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::config::RuleProtocol;
use crate::policy::PolicyId;

/// Identity of a process that stays unique when the OS reuses its PID.
///
/// `instance` tells apart processes that held the same PID at different
/// times: the ProcessSequenceNumber on Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Chosen by the user for this process or an ancestor.
    Manual,
    /// Index of the rule in the active rule set.
    Rule(usize),
}

/// Why a process is proxied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub source: Source,
    /// The assignment was inherited from the parent process.
    pub inherited: bool,
    pub group: GroupId,
    pub protocol: RuleProtocol,
    pub policy: PolicyId,
}

/// A connection or socket the platform asks the core about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowQuery {
    pub pid: u32,
    pub protocol: Protocol,
    /// The destination, if already known. Without it only the process is
    /// judged; the caller must check each destination against the returned
    /// policy.
    pub remote: Option<SocketAddr>,
}

/// What to do with a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Direct(DirectReason),
    Proxy { group: GroupId, policy: PolicyId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectReason {
    /// Cladus's own connections are never intercepted.
    SelfProcess,
    /// The process could not be identified (already exited or inaccessible).
    UnknownProcess,
    /// No rule covers the process.
    NotAssigned,
    /// The covering rule does not include this protocol.
    ProtocolNotSelected,
    /// The destination is local or matches a global exclusion.
    ExcludedDestination,
    /// The covering rule's destination filter does not include it.
    FilteredByRule,
}

impl DirectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfProcess => "self",
            Self::UnknownProcess => "unknown-process",
            Self::NotAssigned => "not-assigned",
            Self::ProtocolNotSelected => "protocol-not-selected",
            Self::ExcludedDestination => "excluded-destination",
            Self::FilteredByRule => "filtered-by-rule",
        }
    }
}

/// A process as shown to the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessView {
    pub pid: u32,
    pub instance: u64,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub alive: bool,
    pub proxy: Option<ProxyView>,
    /// Rules the user excluded this process (and its descendants) from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_rules: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyView {
    /// `None` for a manual assignment.
    pub rule_id: Option<String>,
    pub inherited: bool,
    pub group: GroupId,
    pub protocol: RuleProtocol,
}
