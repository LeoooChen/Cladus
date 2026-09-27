//! The decision core: owns the process tree and answers connection queries.

use std::net::IpAddr;
use std::time::Instant;

use tracing::debug;

use crate::config::{Cidr, Config};
use crate::matching::{fold, fold_path};
use crate::model::{Assignment, DirectReason, FlowQuery, ParentRef, ProcessInfo, Verdict};
use crate::platform::{ProcessEvent, ProcessInspector};
use crate::rules::RuleSet;
use crate::tree::{Lazy, NodeId, ProcessTree};

/// How many processes one synchronous lineage lookup may insert.
const MAX_LINEAGE: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreStats {
    /// Processes in the tree, including retained exited ones.
    pub processes: usize,
    pub alive: usize,
    /// Connections whose process was looked up before its start event arrived.
    pub sync_resolves: u64,
    /// Connections that revealed a reused PID before the old owner's exit event.
    pub recycled_pids: u64,
    /// Connections from processes that could not be identified.
    pub unknown_processes: u64,
}

pub struct DecisionCore {
    tree: ProcessTree,
    rules: RuleSet,
    global_excludes: Vec<Cidr>,
    self_pid: u32,
    stats: CoreStats,
}

impl DecisionCore {
    pub fn new(config: &Config, self_pid: u32) -> Self {
        Self {
            tree: ProcessTree::new(),
            rules: RuleSet::compile(config),
            global_excludes: config.global_exclude_cidrs.clone(),
            self_pid,
            stats: CoreStats::default(),
        }
    }

    pub fn tree(&self) -> &ProcessTree {
        &self.tree
    }

    pub fn stats(&self) -> CoreStats {
        CoreStats {
            processes: self.tree.len(),
            alive: self.tree.alive_count(),
            ..self.stats
        }
    }

    pub fn apply_event(
        &mut self,
        event: ProcessEvent,
        inspector: &dyn ProcessInspector,
        now: Instant,
    ) {
        match event {
            ProcessEvent::Started(info) => self.insert(info, inspector, now),
            ProcessEvent::Exited(key) => {
                self.tree.mark_exited(key, now);
            }
            ProcessEvent::Lost { .. } => {}
        }
    }

    /// Housekeeping; call about once a second.
    pub fn tick(&mut self, now: Instant) {
        self.tree.prune(now);
    }

    pub fn decide(
        &mut self,
        query: &FlowQuery,
        inspector: &dyn ProcessInspector,
        now: Instant,
    ) -> Verdict {
        if query.pid == self.self_pid {
            return Verdict::Direct(DirectReason::SelfProcess);
        }
        let Some(id) = self.resolve_alive(query.pid, inspector, now) else {
            self.stats.unknown_processes += 1;
            return Verdict::Direct(DirectReason::UnknownProcess);
        };
        let Some(assignment) = self.tree.node(id).assignment else {
            return Verdict::Direct(DirectReason::NotAssigned);
        };
        if !assignment.protocol.includes(query.protocol) {
            return Verdict::Direct(DirectReason::ProtocolNotSelected);
        }
        let ip = canonical_ip(query.remote.ip());
        if ip.is_loopback() || self.global_excludes.iter().any(|c| c.contains(ip)) {
            return Verdict::Direct(DirectReason::ExcludedDestination);
        }
        Verdict::Proxy {
            group: assignment.group,
        }
    }

    /// The tree node of the process that owns `pid` right now.
    ///
    /// Process start events arrive a second or two late, and so do exit
    /// events, so a connecting process may be missing from the tree or its
    /// PID may still point at a previous owner. Both are resolved here.
    fn resolve_alive(
        &mut self,
        pid: u32,
        inspector: &dyn ProcessInspector,
        now: Instant,
    ) -> Option<NodeId> {
        if let Some(id) = self.tree.find_alive(pid) {
            match inspector.live_key(pid) {
                // Cannot verify (e.g. access denied): trust the tree.
                None => return Some(id),
                Some(key) if key == self.tree.node(id).info.key => return Some(id),
                Some(_) => self.stats.recycled_pids += 1,
            }
        }
        self.resolve_lineage(pid, inspector, now)
    }

    /// Reads a process and its ancestors that the tree does not know yet from
    /// the OS, and inserts them oldest first so that inheritance applies.
    fn resolve_lineage(
        &mut self,
        pid: u32,
        inspector: &dyn ProcessInspector,
        now: Instant,
    ) -> Option<NodeId> {
        let mut current = inspector.describe(pid)?;
        let target = current.key;
        let mut chain = Vec::new();
        loop {
            let mut parent = None;
            let mut next = None;
            let parent_pid = current.parent_pid;
            if parent_pid != 0 && parent_pid != current.key.pid {
                parent = Some(ParentRef {
                    pid: parent_pid,
                    instance: None,
                });
                if let Some(candidate) = inspector.describe(parent_pid) {
                    // A parent must be older than its child; otherwise the
                    // parent has exited and its PID now belongs to someone else.
                    let older = candidate.create_time == 0
                        || current.create_time == 0
                        || candidate.create_time <= current.create_time;
                    if older {
                        parent = Some(ParentRef {
                            pid: parent_pid,
                            instance: Some(candidate.key.instance),
                        });
                        if self.tree.find(candidate.key).is_none() && chain.len() + 1 < MAX_LINEAGE
                        {
                            next = Some(candidate);
                        }
                    }
                }
            }
            chain.push(ProcessInfo {
                key: current.key,
                parent,
                name: current.name,
                create_time: current.create_time,
            });
            match next {
                Some(candidate) => current = candidate,
                None => break,
            }
        }
        self.stats.sync_resolves += 1;
        for info in chain.into_iter().rev() {
            self.insert(info, inspector, now);
        }
        self.tree
            .find(target)
            .filter(|&id| self.tree.node(id).alive)
    }

    fn insert(&mut self, info: ProcessInfo, inspector: &dyn ProcessInspector, now: Instant) {
        let Some(inserted) = self.tree.insert(info, now) else {
            return;
        };
        self.assign(inserted.id, inspector);
        for child in inserted.adopted {
            for id in self.tree.subtree(child) {
                self.assign(id, inspector);
            }
        }
    }

    /// Computes which rule covers `id`. Its parent must be up to date.
    ///
    /// Rules are tried in order; a rule covers the process if it matches the
    /// process itself or covers its parent. The first such rule wins.
    fn assign(&mut self, id: NodeId, inspector: &dyn ProcessInspector) {
        let inherited = self
            .tree
            .node(id)
            .parent
            .and_then(|parent| self.tree.node(parent).assignment)
            .map(|a| a.rule);
        let mut found = None;
        for index in 0..self.rules.len() {
            if inherited == Some(index) {
                found = Some((index, true));
                break;
            }
            if self.matches(index, id, inspector) {
                found = Some((index, false));
                break;
            }
        }
        let assignment = found.map(|(rule, inherited)| {
            let compiled = self.rules.get(rule);
            Assignment {
                rule,
                inherited,
                group: compiled.group,
                protocol: compiled.protocol,
            }
        });
        let node = self.tree.node_mut(id);
        if let Some(a) = assignment {
            debug!(
                pid = node.info.key.pid,
                name = %node.info.name,
                rule = %self.rules.get(a.rule).id,
                inherited = a.inherited,
                group = %a.group,
                "process covered by rule"
            );
        }
        node.assignment = assignment;
    }

    fn matches(&mut self, index: usize, id: NodeId, inspector: &dyn ProcessInspector) -> bool {
        let rule = self.rules.get(index);
        let node = self.tree.node_mut(id);
        if !rule.matches_name(&node.name_folded) {
            return false;
        }
        let (key, alive) = (node.info.key, node.alive);
        if let Some(pattern) = &rule.image_path {
            let path = read_lazy(&mut node.image_path, alive, || {
                inspector.image_path(key).map(|p| fold_path(&p))
            });
            if !path.is_some_and(|p| pattern.matches(p)) {
                return false;
            }
        }
        if let Some(pattern) = &rule.cmdline {
            let cmdline = read_lazy(&mut node.cmdline, alive, || {
                inspector.cmdline(key).map(|c| fold(&c))
            });
            if !cmdline.is_some_and(|c| pattern.matches(c)) {
                return false;
            }
        }
        true
    }
}

/// Returns the cached attribute, reading it once if needed. Exited processes
/// can no longer be read.
fn read_lazy(
    slot: &mut Lazy,
    alive: bool,
    read: impl FnOnce() -> Option<String>,
) -> Option<&str> {
    if *slot == Lazy::Unread {
        *slot = match alive.then(read).flatten() {
            Some(value) => Lazy::Value(value),
            None => Lazy::Unavailable,
        };
    }
    match slot {
        Lazy::Value(value) => Some(value),
        _ => None,
    }
}

/// IPv4-mapped IPv6 addresses are treated as the IPv4 address they carry.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::config::{ProxyGroup, Rule, RuleProtocol};
    use crate::model::{GroupId, ProcessKey, Protocol};
    use crate::platform::ProcessDescription;
    use crate::tree::tests::{key, process};

    const SELF_PID: u32 = 4242;

    /// The processes a fake OS reports as running.
    #[derive(Default)]
    struct FakeOs {
        processes: HashMap<u32, FakeProcess>,
        cmdline_reads: AtomicUsize,
    }

    struct FakeProcess {
        description: ProcessDescription,
        path: String,
        cmdline: String,
    }

    impl FakeOs {
        fn run(&mut self, pid: u32, instance: u64, parent_pid: u32, name: &str, cmdline: &str) {
            self.processes.insert(
                pid,
                FakeProcess {
                    description: ProcessDescription {
                        key: key(pid, instance),
                        parent_pid,
                        name: name.to_owned(),
                        create_time: instance,
                    },
                    path: format!(r"C:\Apps\{name}"),
                    cmdline: cmdline.to_owned(),
                },
            );
        }

        fn running(&self, key: ProcessKey) -> Option<&FakeProcess> {
            self.processes
                .get(&key.pid)
                .filter(|p| p.description.key == key)
        }
    }

    impl ProcessInspector for FakeOs {
        fn live_key(&self, pid: u32) -> Option<ProcessKey> {
            self.processes.get(&pid).map(|p| p.description.key)
        }

        fn describe(&self, pid: u32) -> Option<ProcessDescription> {
            self.processes.get(&pid).map(|p| p.description.clone())
        }

        fn image_path(&self, key: ProcessKey) -> Option<String> {
            self.running(key).map(|p| p.path.clone())
        }

        fn cmdline(&self, key: ProcessKey) -> Option<String> {
            self.cmdline_reads.fetch_add(1, Ordering::Relaxed);
            self.running(key).map(|p| p.cmdline.clone())
        }
    }

    fn rule(id: &str, process_name: &str, group: u32) -> Rule {
        Rule {
            id: id.to_owned(),
            process_name: process_name.to_owned(),
            proxy_group_id: GroupId(group),
            ..Rule::default()
        }
    }

    fn core_with(rules: Vec<Rule>) -> DecisionCore {
        let config = Config {
            proxy_groups: vec![
                ProxyGroup::default(),
                ProxyGroup {
                    id: GroupId(1),
                    ..ProxyGroup::default()
                },
            ],
            rules,
            ..Config::default()
        };
        config.validate().unwrap();
        DecisionCore::new(&config, SELF_PID)
    }

    fn tcp(pid: u32) -> FlowQuery {
        tcp_to(pid, "203.0.113.10:443")
    }

    fn tcp_to(pid: u32, remote: &str) -> FlowQuery {
        FlowQuery {
            pid,
            protocol: Protocol::Tcp,
            remote: remote.parse::<SocketAddr>().unwrap(),
        }
    }

    fn started(core: &mut DecisionCore, os: &FakeOs, info: ProcessInfo) {
        core.apply_event(ProcessEvent::Started(info), os, Instant::now());
    }

    fn decide(core: &mut DecisionCore, os: &FakeOs, query: FlowQuery) -> Verdict {
        core.decide(&query, os, Instant::now())
    }

    fn proxy(group: u32) -> Verdict {
        Verdict::Proxy {
            group: GroupId(group),
        }
    }

    #[test]
    fn matched_process_and_its_descendants_are_proxied() {
        let mut os = FakeOs::default();
        os.run(1, 1, 0, "bash.exe", "");
        os.run(2, 2, 1, "curl.exe", "");
        os.run(3, 3, 2, "helper.exe", "");
        os.run(4, 4, 3, "grandchild.exe", "");
        let mut core = core_with(vec![rule("r", "curl*", 0)]);
        started(&mut core, &os, process(1, 1, None, "bash.exe"));
        started(&mut core, &os, process(2, 2, Some((1, 1)), "curl.exe"));
        started(&mut core, &os, process(3, 3, Some((2, 2)), "helper.exe"));
        started(&mut core, &os, process(4, 4, Some((3, 3)), "grandchild.exe"));

        assert_eq!(decide(&mut core, &os, tcp(1)), Verdict::Direct(DirectReason::NotAssigned));
        assert_eq!(decide(&mut core, &os, tcp(2)), proxy(0));
        assert_eq!(decide(&mut core, &os, tcp(4)), proxy(0));
        let child = core.tree().find(key(3, 3)).unwrap();
        assert!(core.tree().node(child).assignment.unwrap().inherited);
    }

    #[test]
    fn first_covering_rule_wins() {
        let mut os = FakeOs::default();
        os.run(2, 2, 0, "curl.exe", "");
        os.run(3, 3, 2, "helper.exe", "");
        let tree = [
            process(2, 2, None, "curl.exe"),
            process(3, 3, Some((2, 2)), "helper.exe"),
        ];

        // The helper's own rule comes first.
        let mut core = core_with(vec![rule("helper", "helper.exe", 1), rule("curl", "curl.exe", 0)]);
        tree.iter().for_each(|p| started(&mut core, &os, p.clone()));
        assert_eq!(decide(&mut core, &os, tcp(3)), proxy(1));

        // The inherited rule comes first.
        let mut core = core_with(vec![rule("curl", "curl.exe", 0), rule("helper", "helper.exe", 1)]);
        tree.iter().for_each(|p| started(&mut core, &os, p.clone()));
        assert_eq!(decide(&mut core, &os, tcp(3)), proxy(0));
    }

    #[test]
    fn protocol_of_the_rule_is_respected() {
        let mut os = FakeOs::default();
        os.run(2, 2, 0, "game.exe", "");
        let mut core = core_with(vec![Rule {
            protocol: RuleProtocol::Udp,
            ..rule("r", "game.exe", 0)
        }]);
        started(&mut core, &os, process(2, 2, None, "game.exe"));
        assert_eq!(
            decide(&mut core, &os, tcp(2)),
            Verdict::Direct(DirectReason::ProtocolNotSelected)
        );
    }

    #[test]
    fn excluded_and_loopback_destinations_go_direct() {
        let mut os = FakeOs::default();
        os.run(2, 2, 0, "curl.exe", "");
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        started(&mut core, &os, process(2, 2, None, "curl.exe"));
        let excluded = Verdict::Direct(DirectReason::ExcludedDestination);
        assert_eq!(decide(&mut core, &os, tcp_to(2, "192.168.1.1:80")), excluded);
        assert_eq!(decide(&mut core, &os, tcp_to(2, "[::ffff:10.1.2.3]:80")), excluded);
        assert_eq!(decide(&mut core, &os, tcp_to(2, "[::1]:80")), excluded);
        assert_eq!(decide(&mut core, &os, tcp_to(2, "8.8.8.8:53")), proxy(0));
    }

    #[test]
    fn own_connections_are_never_proxied() {
        let mut os = FakeOs::default();
        os.run(SELF_PID, 9, 0, "stemma-engine.exe", "");
        let mut core = core_with(vec![rule("r", "*", 0)]);
        assert_eq!(
            decide(&mut core, &os, tcp(SELF_PID)),
            Verdict::Direct(DirectReason::SelfProcess)
        );
    }

    #[test]
    fn unknown_process_is_resolved_with_its_ancestors() {
        let mut os = FakeOs::default();
        os.run(1, 1, 0, "explorer.exe", "");
        os.run(10, 10, 1, "git.exe", "");
        os.run(11, 11, 10, "git-remote-https.exe", "");
        let mut core = core_with(vec![rule("r", "git.exe", 0)]);
        started(&mut core, &os, process(1, 1, None, "explorer.exe"));

        assert_eq!(decide(&mut core, &os, tcp(11)), proxy(0));
        assert_eq!(core.stats().sync_resolves, 1);
        assert_eq!(core.stats().processes, 3);

        // The start events that arrive later change nothing.
        started(&mut core, &os, process(10, 10, Some((1, 1)), "git.exe"));
        started(&mut core, &os, process(11, 11, Some((10, 10)), "git-remote-https.exe"));
        assert_eq!(core.stats().processes, 3);
        assert_eq!(decide(&mut core, &os, tcp(11)), proxy(0));
    }

    #[test]
    fn reused_pid_is_resolved_again() {
        let mut os = FakeOs::default();
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        started(&mut core, &os, process(20, 1, None, "curl.exe"));
        // curl exited and notepad got its PID; the exit event is still in flight.
        os.run(20, 2, 0, "notepad.exe", "");
        assert_eq!(decide(&mut core, &os, tcp(20)), Verdict::Direct(DirectReason::NotAssigned));
        assert_eq!(core.stats().recycled_pids, 1);
    }

    #[test]
    fn newer_process_on_parent_pid_is_not_the_parent() {
        let mut os = FakeOs::default();
        os.run(30, 100, 31, "child.exe", "");
        // PID 31 was reused by a process started after the child.
        os.run(31, 200, 0, "curl.exe", "");
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        assert_eq!(decide(&mut core, &os, tcp(30)), Verdict::Direct(DirectReason::NotAssigned));
    }

    #[test]
    fn unknown_process_goes_direct() {
        let os = FakeOs::default();
        let mut core = core_with(vec![rule("r", "*", 0)]);
        assert_eq!(decide(&mut core, &os, tcp(99)), Verdict::Direct(DirectReason::UnknownProcess));
        assert_eq!(core.stats().unknown_processes, 1);
    }

    #[test]
    fn command_line_is_read_once_and_only_when_needed() {
        let mut os = FakeOs::default();
        os.run(5, 5, 0, "python.exe", r"python.exe C:\jobs\crawler.py --fast");
        os.run(6, 6, 0, "python.exe", "python.exe other.py");
        os.run(7, 7, 0, "node.exe", "node crawler.js");
        let mut core = core_with(vec![Rule {
            cmdline_pattern: "CRAWLER".to_owned(),
            ..rule("r", "python.exe", 0)
        }]);
        for (pid, name) in [(5, "python.exe"), (6, "python.exe"), (7, "node.exe")] {
            started(&mut core, &os, process(pid, u64::from(pid), None, name));
        }
        assert_eq!(decide(&mut core, &os, tcp(5)), proxy(0));
        assert_eq!(decide(&mut core, &os, tcp(5)), proxy(0));
        assert_eq!(decide(&mut core, &os, tcp(6)), Verdict::Direct(DirectReason::NotAssigned));
        assert_eq!(decide(&mut core, &os, tcp(7)), Verdict::Direct(DirectReason::NotAssigned));
        assert_eq!(os.cmdline_reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn image_path_condition() {
        let mut os = FakeOs::default();
        os.run(5, 5, 0, "tool.exe", "");
        let mut core = core_with(vec![
            Rule {
                image_path_pattern: r"C:\Other\".to_owned(),
                ..rule("other", "tool.exe", 1)
            },
            Rule {
                image_path_pattern: "c:/apps/".to_owned(),
                ..rule("apps", "tool.exe", 0)
            },
        ]);
        started(&mut core, &os, process(5, 5, None, "tool.exe"));
        assert_eq!(decide(&mut core, &os, tcp(5)), proxy(0));
    }

    #[test]
    fn child_announced_before_parent_inherits_once_linked() {
        let mut os = FakeOs::default();
        os.run(2, 2, 0, "curl.exe", "");
        os.run(3, 3, 2, "helper.exe", "");
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        started(&mut core, &os, process(3, 3, Some((2, 2)), "helper.exe"));
        started(&mut core, &os, process(2, 2, None, "curl.exe"));
        assert_eq!(decide(&mut core, &os, tcp(3)), proxy(0));
    }

    #[test]
    fn child_of_exited_parent_still_inherits() {
        let mut os = FakeOs::default();
        os.run(3, 3, 2, "helper.exe", "");
        let mut core = core_with(vec![rule("r", "sh.exe", 0)]);
        let now = Instant::now();
        core.apply_event(ProcessEvent::Started(process(2, 2, None, "sh.exe")), &os, now);
        core.apply_event(ProcessEvent::Exited(key(2, 2)), &os, now);
        started(&mut core, &os, process(3, 3, Some((2, 2)), "helper.exe"));
        assert_eq!(decide(&mut core, &os, tcp(3)), proxy(0));
    }
}
