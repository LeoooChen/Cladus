//! Destination policies: which destinations a proxied connection may be sent
//! to the proxy for.
//!
//! Every rule gets a policy id that stays the same for as long as the engine
//! runs, even if rules are reordered or reloaded, so backends can cache the id
//! per socket and evaluate each datagram against the latest table.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::config::{Cidr, DestinationFilter};
use crate::model::DirectReason;

/// Policy of manual assignments: global exclusions only.
pub const GLOBAL_POLICY: PolicyId = PolicyId(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyId(pub u32);

#[derive(Clone, Debug, Default)]
pub struct PolicyTable {
    global_excludes: Vec<Cidr>,
    rules: HashMap<PolicyId, DestinationFilter>,
}

impl PolicyTable {
    pub fn new(global_excludes: Vec<Cidr>, rules: HashMap<PolicyId, DestinationFilter>) -> Self {
        Self {
            global_excludes,
            rules,
        }
    }

    /// Whether traffic to `dst` may be proxied under `policy`. An unknown
    /// policy (its rule was removed) falls back to the global exclusions.
    pub fn check(&self, policy: PolicyId, dst: SocketAddr) -> Result<(), DirectReason> {
        let ip = canonical_ip(dst.ip());
        if is_local_only(ip) || self.global_excludes.iter().any(|c| c.contains(ip)) {
            return Err(DirectReason::ExcludedDestination);
        }
        match self.rules.get(&policy) {
            Some(filter) if !filter.allows(ip, dst.port()) => Err(DirectReason::FilteredByRule),
            _ => Ok(()),
        }
    }
}

/// Destinations that can never be reached through a proxy.
fn is_local_only(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

/// IPv4-mapped IPv6 addresses are treated as the IPv4 address they carry.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PolicyTable {
        let filter = DestinationFilter {
            exclude_cidrs: vec!["203.0.113.0/28".parse().unwrap()],
            include_ports: vec!["443".parse().unwrap(), "8000-8100".parse().unwrap()],
            ..DestinationFilter::default()
        };
        PolicyTable::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            HashMap::from([(PolicyId(1), filter)]),
        )
    }

    fn check(policy: u32, dst: &str) -> Result<(), DirectReason> {
        table().check(PolicyId(policy), dst.parse().unwrap())
    }

    #[test]
    fn global_and_local_destinations_are_excluded() {
        let excluded = Err(DirectReason::ExcludedDestination);
        assert_eq!(check(0, "10.1.2.3:443"), excluded);
        assert_eq!(check(0, "[::ffff:10.1.2.3]:443"), excluded);
        assert_eq!(check(0, "127.0.0.1:443"), excluded);
        assert_eq!(check(0, "[::1]:443"), excluded);
        assert_eq!(check(0, "224.0.0.251:5353"), excluded);
        assert_eq!(check(0, "255.255.255.255:67"), excluded);
        assert_eq!(check(0, "[fe80::1]:443"), excluded);
        assert_eq!(check(0, "[ff02::fb]:5353"), excluded);
        assert_eq!(check(0, "8.8.8.8:53"), Ok(()));
        assert_eq!(check(0, "[2001:db8::1]:443"), Ok(()));
    }

    #[test]
    fn rule_filter_applies_to_its_policy_only() {
        let filtered = Err(DirectReason::FilteredByRule);
        assert_eq!(check(1, "203.0.113.5:443"), filtered);
        assert_eq!(check(1, "203.0.113.200:443"), Ok(()));
        assert_eq!(check(1, "203.0.113.200:80"), filtered);
        assert_eq!(check(1, "203.0.113.200:8050"), Ok(()));
        assert_eq!(check(0, "203.0.113.5:80"), Ok(()));
        // A policy whose rule is gone keeps only the global exclusions.
        assert_eq!(check(9, "203.0.113.5:80"), Ok(()));
    }
}
