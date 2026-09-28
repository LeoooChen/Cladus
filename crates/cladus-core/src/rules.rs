//! Rules compiled from the configuration.

use std::collections::HashMap;

use crate::config::{Config, DestinationFilter, RuleProtocol};
use crate::matching::{CmdlinePattern, PathPattern, fold, wildcard_match};
use crate::model::GroupId;
use crate::policy::{GLOBAL_POLICY, PolicyId, PolicyTable};

/// A configuration rule prepared for matching.
#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub group: GroupId,
    pub protocol: RuleProtocol,
    pub policy: PolicyId,
    pub filter: DestinationFilter,
    /// Folded wildcard on the image file name.
    process_name: String,
    pub cmdline: Option<CmdlinePattern>,
    pub image_path: Option<PathPattern>,
}

impl CompiledRule {
    /// `name` must be folded.
    pub fn matches_name(&self, name: &str) -> bool {
        wildcard_match(&self.process_name, name)
    }
}

/// Hands out a policy id per rule id that never changes or gets reused while
/// the engine runs.
#[derive(Debug)]
pub struct PolicyIds {
    ids: HashMap<String, PolicyId>,
    next: u32,
}

impl Default for PolicyIds {
    fn default() -> Self {
        Self {
            ids: HashMap::new(),
            next: GLOBAL_POLICY.0 + 1,
        }
    }
}

impl PolicyIds {
    fn get(&mut self, rule_id: &str) -> PolicyId {
        if let Some(&id) = self.ids.get(rule_id) {
            return id;
        }
        let id = PolicyId(self.next);
        self.next += 1;
        self.ids.insert(rule_id.to_owned(), id);
        id
    }
}

/// The enabled rules, in configuration order.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub fn compile(config: &Config, ids: &mut PolicyIds) -> Self {
        let rules = config
            .rules
            .iter()
            .filter(|r| r.enabled && !r.process_name.trim().is_empty())
            .map(|r| CompiledRule {
                id: r.id.clone(),
                name: r.name.clone(),
                group: r.proxy_group_id,
                protocol: r.protocol,
                policy: ids.get(&r.id),
                filter: r.dst_filter.clone(),
                process_name: fold(r.process_name.trim()),
                cmdline: CmdlinePattern::new(&r.cmdline_pattern),
                image_path: PathPattern::new(&r.image_path_pattern),
            })
            .collect();
        Self { rules }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn get(&self, index: usize) -> &CompiledRule {
        &self.rules[index]
    }

    pub fn policies(&self, config: &Config) -> PolicyTable {
        PolicyTable::new(
            config.global_exclude_cidrs.clone(),
            self.rules
                .iter()
                .map(|r| (r.policy, r.filter.clone()))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Rule;

    fn rule(id: &str, name: &str, enabled: bool) -> Rule {
        Rule {
            id: id.to_owned(),
            process_name: name.to_owned(),
            enabled,
            ..Rule::default()
        }
    }

    #[test]
    fn compile_keeps_enabled_named_rules_in_order() {
        let config = Config {
            rules: vec![
                rule("a", "Curl*", true),
                rule("b", "git.exe", false),
                rule("c", "  ", true),
                rule("d", "node.exe", true),
            ],
            ..Config::default()
        };
        let set = RuleSet::compile(&config, &mut PolicyIds::default());
        assert_eq!(set.len(), 2);
        assert_eq!(set.get(0).id, "a");
        assert!(set.get(0).matches_name("curl.exe"));
        assert_eq!(set.get(1).id, "d");
    }

    #[test]
    fn policy_ids_survive_reordering_and_are_never_reused() {
        let mut ids = PolicyIds::default();
        let first = Config {
            rules: vec![rule("a", "a.exe", true), rule("b", "b.exe", true)],
            ..Config::default()
        };
        let set = RuleSet::compile(&first, &mut ids);
        let (a, b) = (set.get(0).policy, set.get(1).policy);
        assert_ne!(a, GLOBAL_POLICY);
        assert_ne!(a, b);

        let second = Config {
            rules: vec![rule("c", "c.exe", true), rule("a", "a.exe", true)],
            ..Config::default()
        };
        let set = RuleSet::compile(&second, &mut ids);
        assert_eq!(set.get(1).policy, a);
        assert!(![a, b].contains(&set.get(0).policy));
    }
}
