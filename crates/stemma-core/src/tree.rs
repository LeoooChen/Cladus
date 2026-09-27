//! The process tree.
//!
//! Nodes are keyed by [`ProcessKey`], so a reused PID never aliases an older
//! process. Exited processes stay in the tree while they have descendants and
//! for a grace period afterwards: process events can arrive out of order (a
//! short-lived parent's exit may be reported before its child's start), and
//! the child must still find its parent to inherit the parent's rule.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::matching::fold;
use crate::model::{Assignment, ParentRef, ProcessInfo, ProcessKey};

/// How long an exited process without children stays in the tree.
pub const EXITED_RETENTION: Duration = Duration::from_secs(10);
/// How long a process waits to be linked to a parent that has not been seen.
pub const PARENT_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(usize);

/// A process attribute that is read from the OS only when a rule needs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Lazy {
    #[default]
    Unread,
    Unavailable,
    /// Folded for matching.
    Value(String),
}

#[derive(Debug)]
pub struct Node {
    pub info: ProcessInfo,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub alive: bool,
    pub assignment: Option<Assignment>,
    pub(crate) name_folded: String,
    pub(crate) cmdline: Lazy,
    pub(crate) image_path: Lazy,
    exited_at: Option<Instant>,
}

/// Result of inserting a process.
#[derive(Debug, PartialEq, Eq)]
pub struct Inserted {
    pub id: NodeId,
    /// Processes seen earlier that were waiting for this one as their parent.
    pub adopted: Vec<NodeId>,
}

#[derive(Debug, Default)]
pub struct ProcessTree {
    nodes: Vec<Option<Node>>,
    free: Vec<usize>,
    by_key: HashMap<ProcessKey, NodeId>,
    /// Most recent process for each PID, alive or exited.
    by_pid: HashMap<u32, NodeId>,
    /// Parent key -> children that arrived before it, with their arrival time.
    waiting: HashMap<ProcessKey, Vec<(ProcessKey, Instant)>>,
    alive: usize,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of processes in the tree, including retained exited ones.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn alive_count(&self) -> usize {
        self.alive
    }

    pub fn node(&self, id: NodeId) -> &Node {
        self.nodes[id.0].as_ref().expect("node id refers to a live slot")
    }

    pub(crate) fn node_mut(&mut self, id: NodeId) -> &mut Node {
        self.nodes[id.0].as_mut().expect("node id refers to a live slot")
    }

    pub fn find(&self, key: ProcessKey) -> Option<NodeId> {
        self.by_key.get(&key).copied()
    }

    /// The running process that owns `pid`, as far as the tree knows.
    pub fn find_alive(&self, pid: u32) -> Option<NodeId> {
        self.by_pid
            .get(&pid)
            .copied()
            .filter(|&id| self.node(id).alive)
    }

    /// Adds a process. Returns `None` if it is already known.
    pub fn insert(&mut self, info: ProcessInfo, now: Instant) -> Option<Inserted> {
        if self.by_key.contains_key(&info.key) {
            return None;
        }
        let key = info.key;
        // A new owner of the PID proves the previous one has exited, even if
        // its exit has not been reported yet.
        if let Some(previous) = self.find_alive(key.pid) {
            self.mark_exited_node(previous, now);
        }
        let parent = self.resolve_parent(&info);
        let waiting_for = match (parent, info.parent) {
            (
                None,
                Some(ParentRef {
                    pid,
                    instance: Some(instance),
                }),
            ) if pid != key.pid => Some(ProcessKey { pid, instance }),
            _ => None,
        };
        let id = self.alloc(Node {
            name_folded: fold(&info.name),
            info,
            parent,
            children: Vec::new(),
            alive: true,
            assignment: None,
            cmdline: Lazy::Unread,
            image_path: Lazy::Unread,
            exited_at: None,
        });
        if let Some(parent) = parent {
            self.node_mut(parent).children.push(id);
        }
        if let Some(parent_key) = waiting_for {
            self.waiting.entry(parent_key).or_default().push((key, now));
        }
        self.by_key.insert(key, id);
        self.by_pid.insert(key.pid, id);
        self.alive += 1;
        let adopted = self.adopt_waiting(key, id);
        Some(Inserted { id, adopted })
    }

    fn resolve_parent(&self, info: &ProcessInfo) -> Option<NodeId> {
        let parent = info.parent?;
        if parent.pid == info.key.pid {
            return None;
        }
        match parent.instance {
            Some(instance) => self.find(ProcessKey {
                pid: parent.pid,
                instance,
            }),
            None => {
                // The parent's identity is unknown: link to the latest owner of
                // the PID only if it provably started before the child.
                let id = *self.by_pid.get(&parent.pid)?;
                let candidate = self.node(id).info.create_time;
                (candidate != 0 && info.create_time != 0 && candidate <= info.create_time)
                    .then_some(id)
            }
        }
    }

    fn adopt_waiting(&mut self, key: ProcessKey, id: NodeId) -> Vec<NodeId> {
        let Some(children) = self.waiting.remove(&key) else {
            return Vec::new();
        };
        let mut adopted = Vec::new();
        for (child_key, _) in children {
            let Some(child) = self.find(child_key) else {
                continue;
            };
            if self.node(child).parent.is_some() || self.is_ancestor(child, id) {
                continue;
            }
            self.node_mut(child).parent = Some(id);
            self.node_mut(id).children.push(child);
            adopted.push(child);
        }
        adopted
    }

    /// True if `ancestor` is `id` itself or lies on the path from `id` to its root.
    fn is_ancestor(&self, ancestor: NodeId, mut id: NodeId) -> bool {
        loop {
            if id == ancestor {
                return true;
            }
            match self.node(id).parent {
                Some(parent) => id = parent,
                None => return false,
            }
        }
    }

    /// Records that a process exited. Returns its node if it was alive.
    pub fn mark_exited(&mut self, key: ProcessKey, now: Instant) -> Option<NodeId> {
        let id = self.find(key)?;
        if !self.node(id).alive {
            return None;
        }
        self.mark_exited_node(id, now);
        Some(id)
    }

    fn mark_exited_node(&mut self, id: NodeId, now: Instant) {
        let node = self.node_mut(id);
        node.alive = false;
        node.exited_at = Some(now);
        self.alive -= 1;
    }

    /// Removes exited processes that have no children left and have been
    /// retained long enough, and forgets children that waited too long for a
    /// parent. Returns the number of removed processes.
    pub fn prune(&mut self, now: Instant) -> usize {
        self.waiting.retain(|_, children| {
            children.retain(|(_, since)| now.duration_since(*since) < PARENT_WAIT);
            !children.is_empty()
        });
        let mut candidates: Vec<NodeId> = self
            .by_key
            .values()
            .copied()
            .filter(|&id| self.removable(id, now))
            .collect();
        let mut removed = 0;
        while let Some(id) = candidates.pop() {
            if !self.removable(id, now) {
                continue;
            }
            removed += 1;
            if let Some(parent) = self.remove(id)
                && self.removable(parent, now)
            {
                candidates.push(parent);
            }
        }
        removed
    }

    fn removable(&self, id: NodeId, now: Instant) -> bool {
        self.nodes[id.0].as_ref().is_some_and(|node| {
            node.children.is_empty()
                && node
                    .exited_at
                    .is_some_and(|t| now.duration_since(t) >= EXITED_RETENTION)
        })
    }

    /// Removes a childless node and returns its parent.
    fn remove(&mut self, id: NodeId) -> Option<NodeId> {
        let node = self.nodes[id.0].take().expect("node exists");
        self.free.push(id.0);
        self.by_key.remove(&node.info.key);
        if self.by_pid.get(&node.info.key.pid) == Some(&id) {
            self.by_pid.remove(&node.info.key.pid);
        }
        if let Some(parent) = node.parent {
            self.node_mut(parent).children.retain(|&c| c != id);
        }
        node.parent
    }

    /// `id` and all of its descendants, parents before children.
    pub fn subtree(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(next) = stack.pop() {
            out.push(next);
            stack.extend(self.node(next).children.iter().rev());
        }
        out
    }

    fn alloc(&mut self, node: Node) -> NodeId {
        match self.free.pop() {
            Some(index) => {
                self.nodes[index] = Some(node);
                NodeId(index)
            }
            None => {
                self.nodes.push(Some(node));
                NodeId(self.nodes.len() - 1)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn key(pid: u32, instance: u64) -> ProcessKey {
        ProcessKey { pid, instance }
    }

    pub(crate) fn process(pid: u32, instance: u64, parent: Option<(u32, u64)>, name: &str) -> ProcessInfo {
        ProcessInfo {
            key: key(pid, instance),
            parent: parent.map(|(pid, instance)| ParentRef {
                pid,
                instance: Some(instance),
            }),
            name: name.to_owned(),
            create_time: instance,
        }
    }

    fn parent_key(tree: &ProcessTree, id: NodeId) -> Option<ProcessKey> {
        tree.node(id).parent.map(|p| tree.node(p).info.key)
    }

    #[test]
    fn links_child_to_known_parent() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        let parent = tree.insert(process(1, 1, None, "a.exe"), now).unwrap().id;
        let child = tree.insert(process(2, 2, Some((1, 1)), "b.exe"), now).unwrap().id;
        assert_eq!(tree.node(child).parent, Some(parent));
        assert_eq!(tree.node(parent).children, vec![child]);
        assert_eq!(tree.subtree(parent), vec![parent, child]);
    }

    #[test]
    fn insert_is_idempotent() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        assert!(tree.insert(process(1, 1, None, "a.exe"), now).is_some());
        assert!(tree.insert(process(1, 1, None, "a.exe"), now).is_none());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn child_seen_before_parent_is_adopted() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        let child = tree.insert(process(2, 2, Some((1, 1)), "b.exe"), now).unwrap().id;
        assert_eq!(tree.node(child).parent, None);
        let inserted = tree.insert(process(1, 1, None, "a.exe"), now).unwrap();
        assert_eq!(inserted.adopted, vec![child]);
        assert_eq!(tree.node(child).parent, Some(inserted.id));
    }

    #[test]
    fn adoption_never_creates_a_cycle() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        // `c` waits for 9#9, which then claims `c` as its own parent.
        let c = tree.insert(process(2, 2, Some((9, 9)), "c.exe"), now).unwrap().id;
        let inserted = tree.insert(process(9, 9, Some((2, 2)), "p.exe"), now).unwrap();
        assert!(inserted.adopted.is_empty());
        assert_eq!(tree.node(c).parent, None);
    }

    #[test]
    fn reused_pid_supersedes_previous_owner() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        let old = tree.insert(process(10, 1, None, "old.exe"), now).unwrap().id;
        let new = tree.insert(process(10, 2, None, "new.exe"), now).unwrap().id;
        assert!(!tree.node(old).alive);
        assert_eq!(tree.find_alive(10), Some(new));
        assert_eq!(tree.alive_count(), 1);
        // The late exit event for the old owner changes nothing.
        assert_eq!(tree.mark_exited(key(10, 1), now), None);
        assert_eq!(tree.find_alive(10), Some(new));
    }

    #[test]
    fn parent_without_identity_links_only_to_an_older_process() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        let parent = tree.insert(process(5, 100, None, "p.exe"), now).unwrap().id;
        let mut child = process(6, 200, None, "c.exe");
        child.parent = Some(ParentRef { pid: 5, instance: None });
        let linked = tree.insert(child, now).unwrap().id;
        assert_eq!(tree.node(linked).parent, Some(parent));

        let mut older_child = process(7, 50, None, "c.exe");
        older_child.parent = Some(ParentRef { pid: 5, instance: None });
        let unlinked = tree.insert(older_child, now).unwrap().id;
        assert_eq!(tree.node(unlinked).parent, None);
    }

    #[test]
    fn exited_processes_are_retained_then_pruned_bottom_up() {
        let start = Instant::now();
        let mut tree = ProcessTree::new();
        tree.insert(process(1, 1, None, "a.exe"), start);
        let child = tree.insert(process(2, 2, Some((1, 1)), "b.exe"), start).unwrap().id;
        tree.mark_exited(key(1, 1), start);

        // An exited parent with a running child stays.
        assert_eq!(tree.prune(start + EXITED_RETENTION * 2), 0);
        assert_eq!(parent_key(&tree, child), Some(key(1, 1)));

        let exit = start + EXITED_RETENTION * 2;
        tree.mark_exited(key(2, 2), exit);
        assert_eq!(tree.prune(exit + EXITED_RETENTION / 2), 0);
        assert_eq!(tree.prune(exit + EXITED_RETENTION), 2);
        assert!(tree.is_empty());
    }

    #[test]
    fn late_child_finds_recently_exited_parent() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        tree.insert(process(1, 1, None, "sh.exe"), now);
        tree.mark_exited(key(1, 1), now);
        let child = tree.insert(process(2, 2, Some((1, 1)), "curl.exe"), now).unwrap().id;
        assert_eq!(parent_key(&tree, child), Some(key(1, 1)));
    }

    #[test]
    fn children_stop_waiting_after_a_while() {
        let now = Instant::now();
        let mut tree = ProcessTree::new();
        let child = tree.insert(process(2, 2, Some((1, 1)), "b.exe"), now).unwrap().id;
        tree.prune(now + PARENT_WAIT);
        let inserted = tree.insert(process(1, 1, None, "a.exe"), now + PARENT_WAIT).unwrap();
        assert!(inserted.adopted.is_empty());
        assert_eq!(tree.node(child).parent, None);
    }
}
