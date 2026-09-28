//! Importing a Clew (C++) `clew.json` version 2 configuration.
//!
//! Only engine settings are carried over; Clew's window and language
//! preferences belong to the desktop app. Unreadable entries are skipped
//! and reported rather than failing the whole import.

use std::net::{IpAddr, SocketAddr};

use serde_json::Value;

use crate::config::{
    Config, DestinationFilter, DnsConfig, LogLevel, ProxyGroup, Rule, RuleProtocol,
};
use crate::model::GroupId;

#[derive(Debug)]
pub struct Imported {
    pub config: Config,
    /// Human-readable notes about what could not be carried over exactly.
    pub warnings: Vec<String>,
}

pub fn import_clew(json: &str) -> Result<Imported, String> {
    let root: Value = serde_json::from_str(json).map_err(|err| format!("not valid JSON: {err}"))?;
    if !root.is_object() {
        return Err("not a Clew configuration".to_owned());
    }
    if let Some(version) = root.get("version") {
        if version.as_u64() != Some(2) {
            return Err("only Clew configuration version 2 is supported".to_owned());
        }
    } else if !["default_proxy", "proxy_groups", "auto_rules"]
        .iter()
        .any(|key| root.get(key).is_some())
    {
        return Err("not a Clew configuration".to_owned());
    }
    for key in ["proxy_groups", "auto_rules", "default_exclude_cidrs"] {
        if root.get(key).is_some_and(|value| !value.is_array()) {
            return Err(format!("Clew `{key}` must be an array"));
        }
    }
    let mut warnings = Vec::new();
    let mut config = Config::default();
    let text = |v: &Value, key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };

    let mut groups = Vec::new();
    for group in root
        .get("proxy_groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = u32::try_from(group.get("id").and_then(Value::as_u64).unwrap_or(0))
            .map_err(|_| "proxy group id is out of range")?;
        let port = group.get("port").and_then(Value::as_u64).unwrap_or(0);
        let kind = text(group, "type");
        if !kind.is_empty() && kind != "socks5" {
            warnings.push(format!(
                "proxy group {id}: type `{kind}` is not supported; group skipped"
            ));
            continue;
        }
        if port == 0
            || port > u16::MAX as u64
            || text(group, "host").is_empty()
            || groups.iter().any(|g: &ProxyGroup| g.id.0 == id)
        {
            warnings.push(format!(
                "proxy group {id} was skipped: invalid or duplicate"
            ));
            continue;
        }
        let mut imported = ProxyGroup {
            id: GroupId(id),
            name: text(group, "name"),
            host: text(group, "host"),
            port: port as u16,
            ..ProxyGroup::default()
        };
        if !text(group, "test_url").is_empty() {
            imported.test_url = text(group, "test_url");
        }
        groups.push(imported);
    }
    if groups.is_empty() {
        // Clew v2 files written before proxy groups existed have only this.
        let default = root.get("default_proxy").cloned().unwrap_or(Value::Null);
        let mut group = ProxyGroup::default();
        if let Some(host) = default
            .get("host")
            .and_then(Value::as_str)
            .filter(|h| !h.is_empty())
        {
            group.host = host.to_owned();
        }
        if let Some(port) = default
            .get("port")
            .and_then(Value::as_u64)
            .filter(|p| (1..=65535).contains(p))
        {
            group.port = port as u16;
        }
        group.username = text(&default, "user");
        group.password = text(&default, "password");
        groups.push(group);
    }
    config.proxy_groups = groups;
    let fallback_group = config.proxy_groups[0].id;

    for (index, rule) in root
        .get("auto_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let mut id = text(rule, "id");
        if id.is_empty() || config.rules.iter().any(|r| r.id == id) {
            id = format!("clew-{index}");
            let mut suffix = 1;
            while config.rules.iter().any(|r| r.id == id) {
                id = format!("clew-{index}-{suffix}");
                suffix += 1;
            }
        }
        let mut enabled = rule.get("enabled").and_then(Value::as_bool).unwrap_or(true);
        let protocol = match text(rule, "protocol").as_str() {
            "udp" => RuleProtocol::Udp,
            "both" => RuleProtocol::Both,
            _ => RuleProtocol::Tcp,
        };
        let dst_filter = match rule.get("dst_filter") {
            Some(filter) => serde_json::from_value::<DestinationFilter>(filter.clone())
                .unwrap_or_else(|err| {
                    warnings.push(format!(
                        "rule `{id}` disabled: invalid destination filter ({err})"
                    ));
                    enabled = false;
                    DestinationFilter::default()
                }),
            None => DestinationFilter::default(),
        };
        let mut group = GroupId(
            u32::try_from(
                rule.get("proxy_group_id")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .map_err(|_| format!("rule `{id}` has an out-of-range proxy group id"))?,
        );
        if config.group(group).is_none() {
            warnings.push(format!(
                "rule `{id}` disabled: proxy group {group} is missing; review fallback group {fallback_group}"
            ));
            group = fallback_group;
            enabled = false;
        }
        if rule.get("hack_tree").and_then(Value::as_bool) == Some(false) {
            warnings.push(format!(
                "rule `{id}`: Stemma rules always include child processes"
            ));
        }
        config.rules.push(Rule {
            id,
            name: text(rule, "name"),
            enabled,
            process_name: text(rule, "process_name"),
            cmdline_pattern: text(rule, "cmdline_pattern"),
            image_path_pattern: text(rule, "image_path_pattern"),
            protocol,
            proxy_group_id: group,
            dst_filter,
        });
    }

    if let Some(cidrs) = root.get("default_exclude_cidrs").and_then(Value::as_array) {
        config.global_exclude_cidrs = cidrs
            .iter()
            .filter_map(|c| {
                let parsed = c.as_str().and_then(|s| s.parse().ok());
                if parsed.is_none() {
                    warnings.push(format!("excluded network {c} was dropped"));
                }
                parsed
            })
            .collect();
    }

    if let Some(dns) = root.get("dns") {
        let host = text(dns, "upstream_host");
        let port = dns
            .get("upstream_port")
            .and_then(Value::as_u64)
            .filter(|p| (1..=65535).contains(p))
            .unwrap_or(53) as u16;
        let upstream = host.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, port));
        if upstream.is_err() && !host.is_empty() {
            warnings.push(format!(
                "DNS upstream `{host}` is not an IP address; using {}",
                DnsConfig::default().upstream
            ));
        }
        config.dns = DnsConfig {
            enabled: dns.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            upstream: upstream.unwrap_or(DnsConfig::default().upstream),
            proxy_group_id: fallback_group,
            strict: false,
        };
    }

    config.log_level = match text(&root, "log_level").as_str() {
        "trace" => LogLevel::Trace,
        "debug" => LogLevel::Debug,
        "warn" | "warning" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => LogLevel::Info,
    };

    if let Some(parking) = root.get("tcp_syn_parking") {
        let current = config.tcp_syn_parking.clone();
        config.tcp_syn_parking.enabled = parking
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(current.enabled);
        if let Some(ms) = parking
            .get("watchdog_ms")
            .and_then(Value::as_u64)
            .filter(|v| (5..=50).contains(v))
        {
            config.tcp_syn_parking.watchdog_ms = ms as u32;
        }
        if let Some(size) = parking
            .get("pool_size")
            .and_then(Value::as_u64)
            .filter(|v| (32..=4096).contains(v))
        {
            config.tcp_syn_parking.pool_size = size as u32;
        }
    }

    config.validate().map_err(|err| err.to_string())?;
    Ok(Imported { config, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "version": 2,
        "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": 7890},
        "proxy_groups": [
            {"id": 0, "name": "default", "host": "127.0.0.1", "port": 7897, "type": "socks5", "test_url": "http://www.gstatic.com/generate_204"},
            {"id": 3, "name": "work", "host": "10.0.0.5", "port": 1080, "type": "socks5", "test_url": ""}
        ],
        "next_group_id": 4,
        "default_exclude_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "bogus"],
        "auto_rules": [
            {"id": "a1", "name": "Antigravity", "enabled": true, "process_name": "Antigravity.exe",
             "cmdline_pattern": "", "image_path_pattern": "", "hack_tree": true,
             "dst_filter": {"include_cidrs": [], "exclude_cidrs": ["192.168.0.0/16"], "include_ports": ["443", "8000-8100"], "exclude_ports": []},
             "proxy_group_id": 3, "protocol": "both", "proxy": {"type": "socks5", "host": "", "port": 0}},
            {"id": "a1", "name": "dup", "process_name": "curl.exe", "proxy_group_id": 9, "hack_tree": false}
        ],
        "ui": {"language": "zh-CN", "close_to_tray": true},
        "io_threads": 0,
        "log_level": "warning",
        "dns": {"enabled": true, "mode": "forwarder", "upstream_host": "1.1.1.1", "upstream_port": 53, "listen_host": "127.0.0.2", "listen_port": 53},
        "tcp_syn_parking": {"enabled": false, "watchdog_ms": 30, "pool_size": 512}
    }"#;

    #[test]
    fn a_full_clew_file_imports() {
        let Imported { config, warnings } = import_clew(SAMPLE).unwrap();
        assert_eq!(config.proxy_groups.len(), 2);
        assert_eq!(config.proxy_groups[0].port, 7897);
        assert_eq!(
            config.proxy_groups[1].test_url,
            ProxyGroup::default().test_url
        );
        let rule = &config.rules[0];
        assert_eq!(
            (rule.proxy_group_id, rule.protocol),
            (GroupId(3), RuleProtocol::Both)
        );
        assert_eq!(rule.dst_filter.include_ports.len(), 2);
        let dup = &config.rules[1];
        assert_eq!(
            (dup.id.as_str(), dup.proxy_group_id),
            ("clew-1", GroupId(0))
        );
        assert_eq!(config.global_exclude_cidrs.len(), 2);
        assert!(config.dns.enabled);
        assert_eq!(config.dns.upstream, "1.1.1.1:53".parse().unwrap());
        assert_eq!(config.log_level, LogLevel::Warn);
        assert!(!config.tcp_syn_parking.enabled);
        assert_eq!(
            (
                config.tcp_syn_parking.watchdog_ms,
                config.tcp_syn_parking.pool_size
            ),
            (30, 512)
        );
        assert_eq!(warnings.len(), 3, "{warnings:?}");
    }

    #[test]
    fn legacy_default_proxy_becomes_the_group() {
        let Imported { config, .. } =
            import_clew(r#"{"default_proxy": {"host": "192.168.1.2", "port": 1081}, "auto_rules": [{"process_name": "a.exe"}]}"#).unwrap();
        assert_eq!(
            (
                config.proxy_groups[0].host.as_str(),
                config.proxy_groups[0].port
            ),
            ("192.168.1.2", 1081)
        );
        assert_eq!(config.rules[0].id, "clew-0");
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(import_clew("[]").is_err());
        assert!(import_clew("{").is_err());
        assert!(import_clew("{}").is_err());
        assert!(import_clew(r#"{"version":3}"#).is_err());
        assert!(import_clew(r#"{"version":2,"auto_rules":{}}"#).is_err());
    }

    #[test]
    fn invalid_filters_cannot_turn_into_enabled_unrestricted_rules() {
        let imported = import_clew(r#"{"version":2,"auto_rules":[{"id":"a","process_name":"app.exe","dst_filter":{"include_ports":["bad"]}}]}"#).unwrap();
        assert!(!imported.config.rules[0].enabled);
        assert_eq!(imported.warnings.len(), 1);
    }

    #[test]
    fn generated_rule_ids_never_collide_with_imported_ids() {
        let imported = import_clew(r#"{"version":2,"auto_rules":[{"id":"clew-1"},{}]}"#).unwrap();
        assert_ne!(imported.config.rules[0].id, imported.config.rules[1].id);
    }
}
