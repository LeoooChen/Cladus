//! The decision core: owns the process tree and answers connection queries.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tracing::debug;

use crate::config::{Config, RuleProtocol};
use crate::matching::{fold, fold_path};
use crate::model::{
    Assignment, DirectReason, FlowQuery, GroupId, ParentRef, ProcessInfo, ProcessKey, ProcessView,
    ProxyView, Source, Verdict,
};
use crate::platform::{ProcessEvent, ProcessInspector};
use crate::policy::{GLOBAL_POLICY, PolicyTable};
use crate::rules::{PolicyIds, RuleSet};
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
    policy_ids: PolicyIds,
    policies: Arc<PolicyTable>,
    self_pid: u32,
    stats: CoreStats,
    ancestry_retries: HashSet<ProcessKey>,
}

impl DecisionCore {
    pub fn new(config: &Config, self_pid: u32) -> Self {
        let mut policy_ids = PolicyIds::default();
        let rules = RuleSet::compile(config, &mut policy_ids);
        let policies = Arc::new(rules.policies(config));
        Self {
            tree: ProcessTree::new(),
            rules,
            policy_ids,
            policies,
            self_pid,
            stats: CoreStats::default(),
            ancestry_retries: HashSet::new(),
        }
    }

    /// Applies new rules and exclusions to every known process.
    pub fn reconfigure(&mut self, config: &Config, inspector: &dyn ProcessInspector) {
        self.rules = RuleSet::compile(config, &mut self.policy_ids);
        self.policies = Arc::new(self.rules.policies(config));
        for id in self.tree.all() {
            self.assign(id, inspector);
        }
    }

    /// Destination policies of the current rules.
    pub fn policies(&self) -> Arc<PolicyTable> {
        Arc::clone(&self.policies)
    }

    pub fn tree(&self) -> &ProcessTree {
        &self.tree
    }

    /// A missing ancestor may still be in the platform's event buffer.
    pub fn has_unresolved_ancestry(&self, pid: u32) -> bool {
        self.unresolved_ancestor(pid).is_some()
    }

    pub fn take_ancestry_retry(&mut self, pid: u32) -> bool {
        self.unresolved_ancestor(pid)
            .is_some_and(|key| self.ancestry_retries.insert(key))
    }

    fn unresolved_ancestor(&self, pid: u32) -> Option<ProcessKey> {
        let mut id = self.tree.find_alive(pid)?;
        while let Some(parent) = self.tree.node(id).parent {
            id = parent;
        }
        let node = self.tree.node(id);
        node.info
            .parent
            .is_some_and(|p| p.pid != node.info.key.pid)
            .then_some(node.info.key)
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
        self.ancestry_retries
            .retain(|key| self.tree.find(*key).is_some());
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
        if let Some(remote) = query.remote
            && let Err(reason) = self.policies.check(assignment.policy, remote)
        {
            return Verdict::Direct(reason);
        }
        Verdict::Proxy {
            group: assignment.group,
            policy: assignment.policy,
        }
    }

    /// Proxies a running process and all of its descendants, present and
    /// future, through `group` (or removes that choice with `None`). Returns
    /// false if the process is not running.
    pub fn set_manual(
        &mut self,
        pid: u32,
        group: Option<GroupId>,
        inspector: &dyn ProcessInspector,
        now: Instant,
    ) -> bool {
        let Some(id) = self.resolve_alive(pid, inspector, now) else {
            return false;
        };
        if group.is_some() {
            self.tree.node_mut(id).manual = group;
        } else {
            // Clearing applies to the whole subtree, so a descendant chosen
            // separately does not stay proxied behind the user's back.
            for node in self.tree.subtree(id) {
                self.tree.node_mut(node).manual = None;
            }
        }
        self.reassign_subtree(id, inspector);
        true
    }

    /// Excludes a running process and its descendants from a rule, or
    /// includes them again. Returns false if the process is not running.
    pub fn set_excluded(
        &mut self,
        pid: u32,
        rule_id: &str,
        excluded: bool,
        inspector: &dyn ProcessInspector,
        now: Instant,
    ) -> bool {
        let Some(id) = self.resolve_alive(pid, inspector, now) else {
            return false;
        };
        let rules = &mut self.tree.node_mut(id).excluded_rules;
        rules.retain(|r| r != rule_id);
        if excluded {
            rules.push(rule_id.to_owned());
        }
        self.reassign_subtree(id, inspector);
        true
    }

    /// Every known process, parents before children.
    pub fn snapshot(&self) -> Vec<ProcessView> {
        self.tree
            .all()
            .into_iter()
            .map(|id| {
                let node = self.tree.node(id);
                ProcessView {
                    pid: node.info.key.pid,
                    instance: node.info.key.instance,
                    parent_pid: node.parent.map(|p| self.tree.node(p).info.key.pid),
                    name: node.info.name.clone(),
                    alive: node.alive,
                    proxy: node.assignment.map(|a| ProxyView {
                        rule_id: match a.source {
                            Source::Manual => None,
                            Source::Rule(index) => Some(self.rules.get(index).id.clone()),
                        },
                        inherited: a.inherited,
                        group: a.group,
                        protocol: a.protocol,
                    }),
                    excluded_rules: node.excluded_rules.clone(),
                }
            })
            .collect()
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
            self.reassign_subtree(child, inspector);
        }
    }

    fn reassign_subtree(&mut self, id: NodeId, inspector: &dyn ProcessInspector) {
        for node in self.tree.subtree(id) {
            self.assign(node, inspector);
        }
    }

    /// Computes how `id` is proxied. Its parent must be up to date.
    ///
    /// A manual choice on the process or an ancestor wins. Otherwise rules
    /// are tried in order; a rule covers the process if it matches the
    /// process itself or covers its parent, unless the process or an
    /// ancestor was excluded from it. The first such rule wins.
    fn assign(&mut self, id: NodeId, inspector: &dyn ProcessInspector) {
        let node = self.tree.node(id);
        let parent = node.parent.and_then(|p| self.tree.node(p).assignment);
        let assignment = if let Some(group) = node.manual {
            Some(manual(group))
        } else if let Some(
            inherited @ Assignment {
                source: Source::Manual,
                ..
            },
        ) = parent
        {
            Some(Assignment {
                inherited: true,
                ..inherited
            })
        } else {
            let inherited_rule = parent.map(|a| a.source);
            let mut found = None;
            for index in 0..self.rules.len() {
                if self.is_excluded(id, &self.rules.get(index).id) {
                    continue;
                }
                if inherited_rule == Some(Source::Rule(index)) {
                    found = Some((index, true));
                    break;
                }
                if self.matches(index, id, inspector) {
                    found = Some((index, false));
                    break;
                }
            }
            found.map(|(index, inherited)| {
                let rule = self.rules.get(index);
                Assignment {
                    source: Source::Rule(index),
                    inherited,
                    group: rule.group,
                    protocol: rule.protocol,
                    policy: rule.policy,
                }
            })
        };
        let node = self.tree.node_mut(id);
        if assignment != node.assignment
            && let Some(a) = assignment
        {
            debug!(
                pid = node.info.key.pid,
                name = %node.info.name,
                source = ?a.source,
                inherited = a.inherited,
                group = %a.group,
                "process proxied"
            );
        }
        node.assignment = assignment;
    }

    /// Whether `id` or one of its ancestors was excluded from `rule_id`.
    fn is_excluded(&self, mut id: NodeId, rule_id: &str) -> bool {
        loop {
            let node = self.tree.node(id);
            if node.excluded_rules.iter().any(|r| r == rule_id) {
                return true;
            }
            match node.parent {
                Some(parent) => id = parent,
                None => return false,
            }
        }
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

fn manual(group: GroupId) -> Assignment {
    Assignment {
        source: Source::Manual,
        inherited: false,
        group,
        protocol: RuleProtocol::Both,
        policy: GLOBAL_POLICY,
    }
}

/// Returns the cached attribute, reading it once if needed. Exited processes
/// can no longer be read.
fn read_lazy(slot: &mut Lazy, alive: bool, read: impl FnOnce() -> Option<String>) -> Option<&str> {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::config::{DestinationFilter, ProxyGroup, Rule};
    use crate::model::{ProcessKey, Protocol};
    use crate::platform::ProcessDescription;
    use crate::policy::PolicyId;
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

    fn config_with(rules: Vec<Rule>) -> Config {
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
        config
    }

    fn core_with(rules: Vec<Rule>) -> DecisionCore {
        DecisionCore::new(&config_with(rules), SELF_PID)
    }

    fn tcp(pid: u32) -> FlowQuery {
        tcp_to(pid, "203.0.113.10:443")
    }

    fn tcp_to(pid: u32, remote: &str) -> FlowQuery {
        FlowQuery {
            pid,
            protocol: Protocol::Tcp,
            remote: Some(remote.parse::<SocketAddr>().unwrap()),
        }
    }

    fn started(core: &mut DecisionCore, os: &FakeOs, info: ProcessInfo) {
        core.apply_event(ProcessEvent::Started(info), os, Instant::now());
    }

    fn decide(core: &mut DecisionCore, os: &FakeOs, query: FlowQuery) -> Verdict {
        core.decide(&query, os, Instant::now())
    }

    /// The group a query is proxied through, if any.
    fn group_of(core: &mut DecisionCore, os: &FakeOs, query: FlowQuery) -> Option<u32> {
        match decide(core, os, query) {
            Verdict::Proxy { group, .. } => Some(group.0),
            Verdict::Direct(_) => None,
        }
    }

    fn direct(reason: DirectReason) -> Verdict {
        Verdict::Direct(reason)
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
        started(
            &mut core,
            &os,
            process(4, 4, Some((3, 3)), "grandchild.exe"),
        );

        assert_eq!(
            decide(&mut core, &os, tcp(1)),
            direct(DirectReason::NotAssigned)
        );
        assert_eq!(group_of(&mut core, &os, tcp(2)), Some(0));
        assert_eq!(group_of(&mut core, &os, tcp(4)), Some(0));
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
        let mut core = core_with(vec![
            rule("helper", "helper.exe", 1),
            rule("curl", "curl.exe", 0),
        ]);
        tree.iter().for_each(|p| started(&mut core, &os, p.clone()));
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(1));

        // The inherited rule comes first.
        let mut core = core_with(vec![
            rule("curl", "curl.exe", 0),
            rule("helper", "helper.exe", 1),
        ]);
        tree.iter().for_each(|p| started(&mut core, &os, p.clone()));
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(0));
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
            direct(DirectReason::ProtocolNotSelected)
        );
        let udp = FlowQuery {
            pid: 2,
            protocol: Protocol::Udp,
            remote: None,
        };
        assert_eq!(group_of(&mut core, &os, udp), Some(0));
    }

    #[test]
    fn excluded_and_local_destinations_go_direct() {
        let mut os = FakeOs::default();
        os.run(2, 2, 0, "curl.exe", "");
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        started(&mut core, &os, process(2, 2, None, "curl.exe"));
        let excluded = direct(DirectReason::ExcludedDestination);
        assert_eq!(
            decide(&mut core, &os, tcp_to(2, "192.168.1.1:80")),
            excluded
        );
        assert_eq!(
            decide(&mut core, &os, tcp_to(2, "[::ffff:10.1.2.3]:80")),
            excluded
        );
        assert_eq!(decide(&mut core, &os, tcp_to(2, "[::1]:80")), excluded);
        assert_eq!(group_of(&mut core, &os, tcp_to(2, "8.8.8.8:53")), Some(0));
    }

    #[test]
    fn rule_destination_filter_is_applied() {
        let mut os = FakeOs::default();
        os.run(2, 2, 0, "curl.exe", "");
        let mut core = core_with(vec![Rule {
            dst_filter: DestinationFilter {
                include_ports: vec!["443".parse().unwrap()],
                ..DestinationFilter::default()
            },
            ..rule("r", "curl.exe", 0)
        }]);
        started(&mut core, &os, process(2, 2, None, "curl.exe"));
        assert_eq!(group_of(&mut core, &os, tcp_to(2, "8.8.8.8:443")), Some(0));
        assert_eq!(
            decide(&mut core, &os, tcp_to(2, "8.8.8.8:80")),
            direct(DirectReason::FilteredByRule)
        );
        let Verdict::Proxy { policy, .. } = decide(&mut core, &os, tcp(2)) else {
            panic!("expected proxy");
        };
        assert!(
            core.policies()
                .check(policy, "8.8.8.8:80".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn own_connections_are_never_proxied() {
        let mut os = FakeOs::default();
        os.run(SELF_PID, 9, 0, "stemma-engine.exe", "");
        let mut core = core_with(vec![rule("r", "*", 0)]);
        assert_eq!(
            decide(&mut core, &os, tcp(SELF_PID)),
            direct(DirectReason::SelfProcess)
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

        assert_eq!(group_of(&mut core, &os, tcp(11)), Some(0));
        assert_eq!(core.stats().sync_resolves, 1);
        assert_eq!(core.stats().processes, 3);

        // The start events that arrive later change nothing.
        started(&mut core, &os, process(10, 10, Some((1, 1)), "git.exe"));
        started(
            &mut core,
            &os,
            process(11, 11, Some((10, 10)), "git-remote-https.exe"),
        );
        assert_eq!(core.stats().processes, 3);
        assert_eq!(group_of(&mut core, &os, tcp(11)), Some(0));
    }

    #[test]
    fn reused_pid_is_resolved_again() {
        let mut os = FakeOs::default();
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        started(&mut core, &os, process(20, 1, None, "curl.exe"));
        // curl exited and notepad got its PID; the exit event is still in flight.
        os.run(20, 2, 0, "notepad.exe", "");
        assert_eq!(
            decide(&mut core, &os, tcp(20)),
            direct(DirectReason::NotAssigned)
        );
        assert_eq!(core.stats().recycled_pids, 1);
    }

    #[test]
    fn newer_process_on_parent_pid_is_not_the_parent() {
        let mut os = FakeOs::default();
        os.run(30, 100, 31, "child.exe", "");
        // PID 31 was reused by a process started after the child.
        os.run(31, 200, 0, "curl.exe", "");
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        assert_eq!(
            decide(&mut core, &os, tcp(30)),
            direct(DirectReason::NotAssigned)
        );
    }

    #[test]
    fn unknown_process_goes_direct() {
        let os = FakeOs::default();
        let mut core = core_with(vec![rule("r", "*", 0)]);
        assert_eq!(
            decide(&mut core, &os, tcp(99)),
            direct(DirectReason::UnknownProcess)
        );
        assert_eq!(core.stats().unknown_processes, 1);
    }

    #[test]
    fn command_line_is_read_once_and_only_when_needed() {
        let mut os = FakeOs::default();
        os.run(
            5,
            5,
            0,
            "python.exe",
            r"python.exe C:\jobs\crawler.py --fast",
        );
        os.run(6, 6, 0, "python.exe", "python.exe other.py");
        os.run(7, 7, 0, "node.exe", "node crawler.js");
        let mut core = core_with(vec![Rule {
            cmdline_pattern: "CRAWLER".to_owned(),
            ..rule("r", "python.exe", 0)
        }]);
        for (pid, name) in [(5, "python.exe"), (6, "python.exe"), (7, "node.exe")] {
            started(&mut core, &os, process(pid, u64::from(pid), None, name));
        }
        assert_eq!(group_of(&mut core, &os, tcp(5)), Some(0));
        assert_eq!(group_of(&mut core, &os, tcp(5)), Some(0));
        assert_eq!(
            decide(&mut core, &os, tcp(6)),
            direct(DirectReason::NotAssigned)
        );
        assert_eq!(
            decide(&mut core, &os, tcp(7)),
            direct(DirectReason::NotAssigned)
        );
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
        assert_eq!(group_of(&mut core, &os, tcp(5)), Some(0));
    }

    #[test]
    fn child_announced_before_parent_inherits_once_linked() {
        let mut os = FakeOs::default();
        os.run(2, 2, 0, "curl.exe", "");
        os.run(3, 3, 2, "helper.exe", "");
        let mut core = core_with(vec![rule("r", "curl.exe", 0)]);
        started(&mut core, &os, process(3, 3, Some((2, 2)), "helper.exe"));
        started(&mut core, &os, process(2, 2, None, "curl.exe"));
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(0));
    }

    #[test]
    fn child_of_exited_parent_still_inherits() {
        let mut os = FakeOs::default();
        os.run(3, 3, 2, "helper.exe", "");
        let mut core = core_with(vec![rule("r", "sh.exe", 0)]);
        let now = Instant::now();
        core.apply_event(
            ProcessEvent::Started(process(2, 2, None, "sh.exe")),
            &os,
            now,
        );
        core.apply_event(ProcessEvent::Exited(key(2, 2)), &os, now);
        started(&mut core, &os, process(3, 3, Some((2, 2)), "helper.exe"));
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(0));
    }

    #[test]
    fn late_parent_event_repairs_a_synchronously_resolved_subtree() {
        let mut os = FakeOs::default();
        os.run(3, 3, 2, "helper.exe", "");
        os.run(4, 4, 3, "worker.exe", "");
        let mut core = core_with(vec![rule("r", "sh.exe", 0)]);
        assert_eq!(group_of(&mut core, &os, tcp(4)), None);
        assert!(core.has_unresolved_ancestry(4));
        started(&mut core, &os, process(2, 2, None, "sh.exe"));
        core.apply_event(ProcessEvent::Exited(key(2, 2)), &os, Instant::now());
        assert_eq!(group_of(&mut core, &os, tcp(4)), Some(0));
        assert!(!core.has_unresolved_ancestry(4));
    }

    /// bash (1) -> app (2) -> worker (3)
    fn chain_os() -> (FakeOs, Vec<ProcessInfo>) {
        let mut os = FakeOs::default();
        os.run(1, 1, 0, "bash.exe", "");
        os.run(2, 2, 1, "app.exe", "");
        os.run(3, 3, 2, "worker.exe", "");
        let tree = vec![
            process(1, 1, None, "bash.exe"),
            process(2, 2, Some((1, 1)), "app.exe"),
            process(3, 3, Some((2, 2)), "worker.exe"),
        ];
        (os, tree)
    }

    #[test]
    fn manual_choice_covers_descendants_and_overrides_rules() {
        let (os, tree) = chain_os();
        let mut core = core_with(vec![rule("r", "worker.exe", 0)]);
        tree.into_iter().for_each(|p| started(&mut core, &os, p));
        let now = Instant::now();

        assert!(core.set_manual(2, Some(GroupId(1)), &os, now));
        assert_eq!(group_of(&mut core, &os, tcp(2)), Some(1));
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(1));
        assert_eq!(
            decide(&mut core, &os, tcp(1)),
            direct(DirectReason::NotAssigned)
        );
        // A manual choice proxies both protocols, with global exclusions only.
        let udp = FlowQuery {
            pid: 3,
            protocol: Protocol::Udp,
            remote: None,
        };
        assert_eq!(
            decide(&mut core, &os, udp),
            Verdict::Proxy {
                group: GroupId(1),
                policy: GLOBAL_POLICY
            }
        );

        // Future children inherit it too.
        let mut os = os;
        os.run(4, 4, 3, "late.exe", "");
        started(&mut core, &os, process(4, 4, Some((3, 3)), "late.exe"));
        assert_eq!(group_of(&mut core, &os, tcp(4)), Some(1));

        // Clearing it restores the rules.
        assert!(core.set_manual(2, None, &os, now));
        assert_eq!(
            decide(&mut core, &os, tcp(2)),
            direct(DirectReason::NotAssigned)
        );
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(0));
        assert!(!core.set_manual(99, Some(GroupId(0)), &os, now));
    }

    #[test]
    fn excluded_subtree_falls_through_to_other_rules() {
        let (os, tree) = chain_os();
        let mut core = core_with(vec![
            rule("app", "app.exe", 0),
            rule("worker", "worker.exe", 1),
        ]);
        tree.into_iter().for_each(|p| started(&mut core, &os, p));
        let now = Instant::now();
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(0));

        assert!(core.set_excluded(2, "app", true, &os, now));
        assert_eq!(
            decide(&mut core, &os, tcp(2)),
            direct(DirectReason::NotAssigned)
        );
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(1));

        assert!(core.set_excluded(2, "app", false, &os, now));
        assert_eq!(group_of(&mut core, &os, tcp(2)), Some(0));
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(0));
    }

    #[test]
    fn reconfigure_applies_new_rules_to_running_processes() {
        let (os, tree) = chain_os();
        let mut core = core_with(vec![rule("r", "app.exe", 0)]);
        tree.into_iter().for_each(|p| started(&mut core, &os, p));
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(0));
        let Verdict::Proxy { policy: before, .. } = decide(&mut core, &os, tcp(3)) else {
            panic!("expected proxy");
        };

        core.reconfigure(
            &config_with(vec![rule("w", "worker.exe", 1), rule("r", "app.exe", 0)]),
            &os,
        );
        assert_eq!(group_of(&mut core, &os, tcp(3)), Some(1));
        assert_eq!(group_of(&mut core, &os, tcp(2)), Some(0));
        let Verdict::Proxy { policy: after, .. } = decide(&mut core, &os, tcp(2)) else {
            panic!("expected proxy");
        };
        assert_eq!(before, after, "a rule keeps its policy id across reloads");
        assert_ne!(after, PolicyId(0));

        core.reconfigure(&config_with(vec![]), &os);
        assert_eq!(
            decide(&mut core, &os, tcp(3)),
            direct(DirectReason::NotAssigned)
        );
    }

    #[test]
    fn snapshot_shows_the_tree_and_why_processes_are_proxied() {
        let (os, tree) = chain_os();
        let mut core = core_with(vec![rule("r", "app.exe", 0)]);
        tree.into_iter().for_each(|p| started(&mut core, &os, p));
        core.set_excluded(3, "other", true, &os, Instant::now());
        let views = core.snapshot();
        assert_eq!(views.iter().map(|v| v.pid).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(views[0].proxy, None);
        let app = views[1].proxy.as_ref().unwrap();
        assert_eq!((app.rule_id.as_deref(), app.inherited), (Some("r"), false));
        assert_eq!(views[2].parent_pid, Some(2));
        assert!(views[2].proxy.as_ref().unwrap().inherited);
        assert_eq!(views[2].excluded_rules, ["other"]);
    }
}
