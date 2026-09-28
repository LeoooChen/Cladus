//! The data shapes the web UI works with, built from engine state.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use cladus_core::config::{Config, DestinationFilter, Rule, RuleProtocol};
use cladus_core::model::{GroupId, ProcessView, Protocol};
use cladus_core::policy::{GLOBAL_POLICY, PolicyId, PolicyTable};
use cladus_platform_windows::sockets::SocketEntry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub hijacked: bool,
    /// `manual`, `auto` or empty.
    pub hijack_source: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<ProcessNode>,
}

/// Running processes as a forest; a process whose parent is gone is a root.
pub fn tree(processes: &[ProcessView]) -> Vec<ProcessNode> {
    let alive: Vec<&ProcessView> = processes.iter().filter(|p| p.alive).collect();
    let pids: HashSet<u32> = alive.iter().map(|p| p.pid).collect();
    let mut children: HashMap<u32, Vec<&ProcessView>> = HashMap::new();
    let mut roots = Vec::new();
    for process in &alive {
        match process
            .parent_pid
            .filter(|parent| pids.contains(parent) && *parent != process.pid)
        {
            Some(parent) => children.entry(parent).or_default().push(process),
            None => roots.push(*process),
        }
    }
    fn build(
        process: &ProcessView,
        children: &HashMap<u32, Vec<&ProcessView>>,
        seen: &mut HashSet<u32>,
    ) -> ProcessNode {
        seen.insert(process.pid);
        let mut kids = Vec::new();
        for child in children.get(&process.pid).into_iter().flatten() {
            if !seen.contains(&child.pid) {
                kids.push(build(child, children, seen));
            }
        }
        kids.sort_by_key(|k| k.pid);
        let source = match &process.proxy {
            Some(proxy) if proxy.rule_id.is_none() => "manual",
            Some(_) => "auto",
            None => "",
        };
        ProcessNode {
            pid: process.pid,
            parent_pid: process.parent_pid.unwrap_or(0),
            name: process.name.clone(),
            hijacked: process.proxy.is_some(),
            hijack_source: source,
            children: kids,
        }
    }
    let mut seen = HashSet::new();
    roots.sort_by_key(|p| p.pid);
    let mut forest: Vec<ProcessNode> = roots
        .iter()
        .map(|root| build(root, &children, &mut seen))
        .collect();
    // Parent cycles (possible with PID reuse) have no root; show them flat.
    for process in alive {
        if !seen.contains(&process.pid) {
            forest.push(build(process, &children, &mut seen));
        }
    }
    forest
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyTarget {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct MatchedPid {
    pub pid: u32,
    pub name: String,
    pub excluded: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AutoRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub process_name: String,
    pub cmdline_pattern: String,
    pub image_path_pattern: String,
    pub hack_tree: bool,
    pub protocol: RuleProtocol,
    pub dst_filter: DestinationFilter,
    pub proxy_group_id: GroupId,
    pub proxy: ProxyTarget,
    pub matched_count: usize,
    pub excluded_count: usize,
    pub matched_pids: Vec<MatchedPid>,
}

/// What the rule editor sends. Display-only fields are ignored.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct RuleInput {
    pub name: String,
    pub enabled: bool,
    pub process_name: String,
    pub cmdline_pattern: String,
    pub image_path_pattern: String,
    pub protocol: RuleProtocol,
    pub dst_filter: DestinationFilter,
    pub proxy_group_id: GroupId,
}

impl Default for RuleInput {
    fn default() -> Self {
        let rule = Rule::default();
        Self {
            name: rule.name,
            enabled: rule.enabled,
            process_name: rule.process_name,
            cmdline_pattern: rule.cmdline_pattern,
            image_path_pattern: rule.image_path_pattern,
            protocol: rule.protocol,
            dst_filter: rule.dst_filter,
            proxy_group_id: rule.proxy_group_id,
        }
    }
}

impl RuleInput {
    pub fn apply(self, rule: &mut Rule) {
        rule.name = self.name.trim().to_owned();
        rule.enabled = self.enabled;
        rule.process_name = self.process_name.trim().to_owned();
        rule.cmdline_pattern = self.cmdline_pattern.trim().to_owned();
        rule.image_path_pattern = self.image_path_pattern.trim().to_owned();
        rule.protocol = self.protocol;
        rule.dst_filter = self.dst_filter;
        rule.proxy_group_id = self.proxy_group_id;
    }
}

pub fn rules(config: &Config, processes: &[ProcessView]) -> Vec<AutoRule> {
    config
        .rules
        .iter()
        .map(|rule| {
            let matched_pids: Vec<MatchedPid> = processes
                .iter()
                .filter(|p| p.alive)
                .filter_map(|p| {
                    let excluded = p.excluded_rules.contains(&rule.id);
                    let matched = p
                        .proxy
                        .as_ref()
                        .is_some_and(|v| v.rule_id.as_deref() == Some(&rule.id));
                    (matched || excluded).then(|| MatchedPid {
                        pid: p.pid,
                        name: p.name.clone(),
                        excluded,
                    })
                })
                .collect();
            let group = config.group(rule.proxy_group_id);
            AutoRule {
                id: rule.id.clone(),
                name: rule.name.clone(),
                enabled: rule.enabled,
                process_name: rule.process_name.clone(),
                cmdline_pattern: rule.cmdline_pattern.clone(),
                image_path_pattern: rule.image_path_pattern.clone(),
                hack_tree: true,
                protocol: rule.protocol,
                dst_filter: rule.dst_filter.clone(),
                proxy_group_id: rule.proxy_group_id,
                proxy: ProxyTarget {
                    kind: "socks5",
                    host: group.map(|g| g.host.clone()).unwrap_or_default(),
                    port: group.map_or(0, |g| g.port),
                },
                matched_count: matched_pids.iter().filter(|m| !m.excluded).count(),
                excluded_count: matched_pids.iter().filter(|m| m.excluded).count(),
                matched_pids,
            }
        })
        .collect()
}

/// A new rule id that is not in use.
pub fn new_rule_id(config: &Config) -> String {
    let used: HashSet<&str> = config.rules.iter().map(|r| r.id.as_str()).collect();
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    (0..)
        .map(|n| format!("rule-{:x}", seed + n))
        .find(|id| !used.contains(id.as_str()))
        .expect("an unused id exists")
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyGroupView {
    pub id: GroupId,
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub test_url: String,
}

pub fn groups(config: &Config) -> Vec<ProxyGroupView> {
    config
        .proxy_groups
        .iter()
        .map(|g| ProxyGroupView {
            id: g.id,
            name: g.name.clone(),
            host: g.host.clone(),
            port: g.port,
            kind: "socks5",
            test_url: g.test_url.clone(),
        })
        .collect()
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GroupInput {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub test_url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Connection {
    pub protocol: &'static str,
    pub pid: u32,
    pub process_name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub dest: String,
    pub state: &'static str,
    pub hijacked: bool,
    pub pid_alive: bool,
    /// `PROXIED`, `IGNORED` (proxied process, excluded destination), `DIRECT` or `-`.
    pub proxy_status: &'static str,
}

/// Socket table rows, labeled with what the engine does with them.
pub fn connections(
    entries: &[SocketEntry],
    processes: &[ProcessView],
    config: &Config,
    pid: Option<u32>,
) -> Vec<Connection> {
    let by_pid: HashMap<u32, &ProcessView> = processes
        .iter()
        .filter(|p| p.alive)
        .map(|p| (p.pid, p))
        .collect();
    let rule_index: HashMap<&str, PolicyId> = config
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), PolicyId(i as u32 + 1)))
        .collect();
    let policies = PolicyTable::new(
        config.global_exclude_cidrs.clone(),
        config
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (PolicyId(i as u32 + 1), r.dst_filter.clone()))
            .collect(),
    );
    entries
        .iter()
        .filter(|e| pid.is_none_or(|pid| e.pid == pid))
        .map(|entry| {
            let process = by_pid.get(&entry.pid);
            let proxy = process.and_then(|p| p.proxy.as_ref());
            let protocol = if entry.tcp {
                Protocol::Tcp
            } else {
                Protocol::Udp
            };
            let status = match (proxy, entry.remote) {
                (None, _) => "DIRECT",
                (Some(proxy), _) if !proxy.protocol.includes(protocol) => "DIRECT",
                (Some(_), None) => "-",
                (Some(proxy), Some(remote)) => {
                    let policy = proxy
                        .rule_id
                        .as_deref()
                        .and_then(|id| rule_index.get(id).copied())
                        .unwrap_or(GLOBAL_POLICY);
                    if policies.check(policy, remote).is_ok() {
                        "PROXIED"
                    } else {
                        "IGNORED"
                    }
                }
            };
            let (remote_ip, remote_port) =
                entry.remote.map_or((String::new(), 0), |r: SocketAddr| {
                    (r.ip().to_string(), r.port())
                });
            Connection {
                protocol: if entry.tcp { "TCP" } else { "UDP" },
                pid: entry.pid,
                process_name: process.map(|p| p.name.clone()).unwrap_or_default(),
                local_ip: entry.local.ip().to_string(),
                local_port: entry.local.port(),
                dest: entry.remote.map(|r| r.to_string()).unwrap_or_default(),
                remote_ip,
                remote_port,
                state: entry.state,
                hijacked: proxy.is_some(),
                pid_alive: process.is_some(),
                proxy_status: status,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use cladus_core::model::ProxyView;

    use super::*;

    fn process(pid: u32, parent: Option<u32>, proxy: Option<Option<&str>>) -> ProcessView {
        ProcessView {
            pid,
            instance: 1,
            parent_pid: parent,
            name: format!("p{pid}.exe"),
            alive: true,
            proxy: proxy.map(|rule| ProxyView {
                rule_id: rule.map(str::to_owned),
                inherited: false,
                group: GroupId(0),
                protocol: RuleProtocol::Tcp,
            }),
            excluded_rules: Vec::new(),
        }
    }

    #[test]
    fn processes_form_a_forest() {
        let list = [
            process(1, None, None),
            process(2, Some(1), Some(None)),
            process(3, Some(2), Some(Some("r"))),
            process(9, Some(77), None),
        ];
        let forest = tree(&list);
        assert_eq!(forest.iter().map(|n| n.pid).collect::<Vec<_>>(), [1, 9]);
        let child = &forest[0].children[0];
        assert_eq!((child.pid, child.hijack_source), (2, "manual"));
        assert_eq!(child.children[0].hijack_source, "auto");
    }

    #[test]
    fn parent_cycles_are_still_shown() {
        let forest = tree(&[process(1, Some(2), None), process(2, Some(1), None)]);
        assert_eq!((forest[0].pid, forest[0].children[0].pid), (1, 2));
        assert!(forest[0].children[0].children.is_empty());
    }

    #[test]
    fn connection_status_follows_policy() {
        let mut config = Config::default();
        config.rules.push(Rule {
            id: "r".into(),
            process_name: "p3.exe".into(),
            dst_filter: DestinationFilter {
                exclude_ports: vec!["80".parse().unwrap()],
                ..Default::default()
            },
            ..Rule::default()
        });
        let list = [process(3, None, Some(Some("r"))), process(4, None, None)];
        let entry = |pid, remote: &str, tcp| SocketEntry {
            tcp,
            pid,
            local: "10.0.0.2:5000".parse().unwrap(),
            remote: Some(remote.parse().unwrap()),
            state: "ESTABLISHED",
        };
        let rows = connections(
            &[
                entry(3, "1.1.1.1:443", true),
                entry(3, "1.1.1.1:80", true),
                entry(3, "10.1.1.1:443", true),
                entry(3, "1.1.1.1:443", false),
                entry(4, "1.1.1.1:443", true),
            ],
            &list,
            &config,
            None,
        );
        let status: Vec<_> = rows.iter().map(|r| r.proxy_status).collect();
        assert_eq!(
            status,
            ["PROXIED", "IGNORED", "IGNORED", "DIRECT", "DIRECT"]
        );
    }
}
