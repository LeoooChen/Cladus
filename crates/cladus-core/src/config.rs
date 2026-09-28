//! The engine configuration file.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::model::{GroupId, Protocol};

/// Current configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub proxy_groups: Vec<ProxyGroup>,
    /// Evaluated in order; the first rule that covers a process wins.
    pub rules: Vec<Rule>,
    /// Destinations that are never proxied, whatever the rules say.
    pub global_exclude_cidrs: Vec<Cidr>,
    pub tcp_syn_parking: SynParking,
    pub dns: DnsConfig,
    pub log_level: LogLevel,
}

impl Default for Config {
    fn default() -> Self {
        let excludes = [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ];
        Self {
            version: CONFIG_VERSION,
            proxy_groups: vec![ProxyGroup::default()],
            rules: Vec::new(),
            global_exclude_cidrs: excludes
                .iter()
                .map(|s| s.parse().expect("built-in CIDR is valid"))
                .collect(),
            tcp_syn_parking: SynParking::default(),
            dns: DnsConfig::default(),
            log_level: LogLevel::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyGroup {
    pub id: GroupId,
    pub name: String,
    /// SOCKS5 server host name or address.
    pub host: String,
    pub port: u16,
    /// Credentials for SOCKS5 username/password authentication (RFC 1929).
    /// Empty means no authentication.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// Reached through the proxy to measure its latency.
    pub test_url: String,
}

impl Default for ProxyGroup {
    fn default() -> Self {
        Self {
            id: GroupId(0),
            name: "default".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 7890,
            username: String::new(),
            password: String::new(),
            test_url: "https://www.google.com".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Wildcard on the image file name, e.g. `curl*` or `python.exe`.
    /// A rule with an empty process name never matches.
    pub process_name: String,
    /// Optional: keywords that must all appear in the command line, or a
    /// wildcard pattern when it contains `*` or `?`.
    pub cmdline_pattern: String,
    /// Optional: image path prefix, or a wildcard pattern.
    pub image_path_pattern: String,
    pub protocol: RuleProtocol,
    pub proxy_group_id: GroupId,
    /// Which destinations of covered processes are proxied.
    pub dst_filter: DestinationFilter,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            process_name: String::new(),
            cmdline_pattern: String::new(),
            image_path_pattern: String::new(),
            protocol: RuleProtocol::default(),
            proxy_group_id: GroupId(0),
            dst_filter: DestinationFilter::default(),
        }
    }
}

/// Destinations a rule applies to. Exclusions win; a non-empty include list
/// admits only what it lists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DestinationFilter {
    pub include_cidrs: Vec<Cidr>,
    pub exclude_cidrs: Vec<Cidr>,
    pub include_ports: Vec<PortRange>,
    pub exclude_ports: Vec<PortRange>,
}

impl DestinationFilter {
    pub fn allows(&self, ip: IpAddr, port: u16) -> bool {
        !self.exclude_cidrs.iter().any(|c| c.contains(ip))
            && !self.exclude_ports.iter().any(|p| p.contains(port))
            && (self.include_cidrs.is_empty() || self.include_cidrs.iter().any(|c| c.contains(ip)))
            && (self.include_ports.is_empty()
                || self.include_ports.iter().any(|p| p.contains(port)))
    }
}

/// A port or an inclusive range such as `8000-8100`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

impl FromStr for PortRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse = |p: &str| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid port range `{s}`"))
        };
        let (first, last) = match s.split_once('-') {
            Some((a, b)) => (parse(a)?, parse(b)?),
            None => (parse(s)?, parse(s)?),
        };
        if first > last {
            return Err(format!("invalid port range `{s}`"));
        }
        Ok(Self { first, last })
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleProtocol {
    #[default]
    Tcp,
    Udp,
    Both,
}

impl RuleProtocol {
    pub fn includes(self, protocol: Protocol) -> bool {
        matches!(
            (self, protocol),
            (Self::Both, _) | (Self::Tcp, Protocol::Tcp) | (Self::Udp, Protocol::Udp)
        )
    }
}

/// Holding a new connection's first SYN until its proxy decision is made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SynParking {
    /// Kill switch. When off, a SYN that arrives before its decision is
    /// released immediately and its connection stays direct.
    pub enabled: bool,
    /// How long a SYN may wait for its decision before it is released direct.
    pub watchdog_ms: u32,
    /// Maximum number of SYNs held at once.
    pub pool_size: u32,
}

impl Default for SynParking {
    fn default() -> Self {
        Self {
            enabled: true,
            watchdog_ms: 150,
            pool_size: 256,
        }
    }
}

/// System-wide DNS through the proxy. When enabled, the system's DNS servers
/// point at a local forwarder that sends every query to `upstream` through
/// the proxy group, over TCP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub enabled: bool,
    /// Upstream resolver, reached through the proxy.
    pub upstream: SocketAddr,
    pub proxy_group_id: GroupId,
    /// When the proxy path fails, queries normally go to the system's
    /// original DNS servers directly. Strict mode fails them instead.
    pub strict: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream: SocketAddr::from(([8, 8, 8, 8], 53)),
            proxy_group_id: GroupId(0),
            strict: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    #[serde(alias = "warning")]
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// An IP network. Accepts `10.0.0.0/8` as well as a bare address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr(IpNet);

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip)
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let net = match s.parse::<IpNet>() {
            Ok(net) => net,
            Err(_) => s
                .parse::<IpAddr>()
                .map(IpNet::from)
                .map_err(|_| format!("invalid CIDR `{s}`"))?,
        };
        Ok(Self(net.trunc()))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid configuration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "unsupported configuration version {found} (this build reads version {CONFIG_VERSION})"
    )]
    Version { found: u32 },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("configuration always serializes")
    }

    pub fn group(&self, id: GroupId) -> Option<&ProxyGroup> {
        self.proxy_groups.iter().find(|g| g.id == id)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError::Version {
                found: self.version,
            });
        }
        let mut problems = Vec::new();
        if self.proxy_groups.is_empty() {
            problems.push("at least one proxy group is required".to_owned());
        }
        let mut group_ids = HashSet::new();
        for group in &self.proxy_groups {
            if !group_ids.insert(group.id) {
                problems.push(format!("duplicate proxy group id {}", group.id));
            }
            if group.host.trim().is_empty() {
                problems.push(format!("proxy group {} has no host", group.id));
            }
            if group.port == 0 {
                problems.push(format!("proxy group {} has no port", group.id));
            }
            if group.username.len() > 255 || group.password.len() > 255 {
                problems.push(format!(
                    "proxy group {}: SOCKS5 username and password are limited to 255 bytes",
                    group.id
                ));
            }
            if group.username.is_empty() != group.password.is_empty() {
                problems.push(format!(
                    "proxy group {}: SOCKS5 authentication needs both username and password",
                    group.id
                ));
            }
        }
        let mut rule_ids = HashSet::new();
        for rule in &self.rules {
            if rule.id.is_empty() {
                problems.push(format!("rule `{}` has no id", rule.name));
            } else if !rule_ids.insert(rule.id.as_str()) {
                problems.push(format!("duplicate rule id `{}`", rule.id));
            }
            if !group_ids.contains(&rule.proxy_group_id) {
                problems.push(format!(
                    "rule `{}` refers to missing proxy group {}",
                    rule.id, rule.proxy_group_id
                ));
            }
        }
        if !group_ids.contains(&self.dns.proxy_group_id) {
            problems.push(format!(
                "dns refers to missing proxy group {}",
                self.dns.proxy_group_id
            ));
        }
        if self.dns.upstream.ip().is_unspecified() || self.dns.upstream.port() == 0 {
            problems.push("dns.upstream must be a resolver address and port".to_owned());
        }
        let parking = &self.tcp_syn_parking;
        if !(5..=500).contains(&parking.watchdog_ms) {
            problems.push("tcp_syn_parking.watchdog_ms must be between 5 and 500".to_owned());
        }
        if !(32..=4096).contains(&parking.pool_size) {
            problems.push("tcp_syn_parking.pool_size must be between 32 and 4096".to_owned());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(problems.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_and_round_trips() {
        let config = Config::default();
        config.validate().unwrap();
        assert_eq!(Config::from_json(&config.to_json()).unwrap(), config);
    }

    #[test]
    fn missing_fields_take_defaults() {
        let config = Config::from_json(
            r#"{"rules": [{"id": "r1", "process_name": "curl.exe", "protocol": "both"}]}"#,
        )
        .unwrap();
        let rule = &config.rules[0];
        assert!(rule.enabled);
        assert_eq!(rule.protocol, RuleProtocol::Both);
        assert_eq!(rule.proxy_group_id, GroupId(0));
        assert_eq!(config.proxy_groups, vec![ProxyGroup::default()]);
    }

    #[test]
    fn cidr_accepts_bare_addresses_and_normalizes() {
        let cidr: Cidr = "10.1.2.3/8".parse().unwrap();
        assert_eq!(cidr.to_string(), "10.0.0.0/8");
        let host: Cidr = "1.2.3.4".parse().unwrap();
        assert_eq!(host.to_string(), "1.2.3.4/32");
        assert!(host.contains("1.2.3.4".parse().unwrap()));
        assert!(!host.contains("1.2.3.5".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
    }

    #[test]
    fn destination_filter() {
        let filter: DestinationFilter = serde_json::from_str(
            r#"{"exclude_cidrs": ["1.1.1.0/24"], "include_ports": ["443", "8000-8100"]}"#,
        )
        .unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(filter.allows(ip("8.8.8.8"), 443));
        assert!(filter.allows(ip("8.8.8.8"), 8100));
        assert!(!filter.allows(ip("8.8.8.8"), 80));
        assert!(!filter.allows(ip("1.1.1.1"), 443));
        assert!(DestinationFilter::default().allows(ip("::1"), 1));
        assert!("9-1".parse::<PortRange>().is_err());
        assert!("x".parse::<PortRange>().is_err());
        assert_eq!(
            serde_json::to_string(&filter.include_ports).unwrap(),
            r#"["443","8000-8100"]"#
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = Config::from_json(r#"{"proxy_group": []}"#).unwrap_err();
        assert!(matches!(err, ConfigError::Json(_)), "{err}");
    }

    #[test]
    fn validation_reports_every_problem() {
        let json = r#"{
            "proxy_groups": [{"id": 1, "host": ""}, {"id": 1, "host": "h", "port": 1}],
            "rules": [{"id": "a", "proxy_group_id": 7}, {"id": "a", "proxy_group_id": 1}],
            "tcp_syn_parking": {"watchdog_ms": 501}
        }"#;
        let ConfigError::Invalid(message) = Config::from_json(json).unwrap_err() else {
            panic!("expected a validation error");
        };
        for expected in [
            "duplicate proxy group id 1",
            "proxy group 1 has no host",
            "duplicate rule id `a`",
            "missing proxy group 7",
            "watchdog_ms",
        ] {
            assert!(
                message.contains(expected),
                "missing `{expected}` in: {message}"
            );
        }
    }

    #[test]
    fn other_versions_are_rejected() {
        let err = Config::from_json(r#"{"version": 2}"#).unwrap_err();
        assert!(matches!(err, ConfigError::Version { found: 2 }));
    }

    #[test]
    fn log_level_accepts_warning_alias() {
        let config = Config::from_json(r#"{"log_level": "warning"}"#).unwrap();
        assert_eq!(config.log_level, LogLevel::Warn);
    }

    #[test]
    fn rule_protocol_selection() {
        assert!(RuleProtocol::Tcp.includes(Protocol::Tcp));
        assert!(!RuleProtocol::Tcp.includes(Protocol::Udp));
        assert!(!RuleProtocol::Udp.includes(Protocol::Tcp));
        assert!(RuleProtocol::Both.includes(Protocol::Udp));
    }
}
