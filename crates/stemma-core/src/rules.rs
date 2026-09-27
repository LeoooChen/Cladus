//! Rules compiled from the configuration.

use crate::config::{Config, RuleProtocol};
use crate::matching::{CmdlinePattern, PathPattern, fold, wildcard_match};
use crate::model::GroupId;

/// A configuration rule prepared for matching.
#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub group: GroupId,
    pub protocol: RuleProtocol,
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

/// The enabled rules, in configuration order.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub fn compile(config: &Config) -> Self {
        let rules = config
            .rules
            .iter()
            .filter(|r| r.enabled && !r.process_name.trim().is_empty())
            .map(|r| CompiledRule {
                id: r.id.clone(),
                name: r.name.clone(),
                group: r.proxy_group_id,
                protocol: r.protocol,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Rule;

    #[test]
    fn compile_keeps_enabled_named_rules_in_order() {
        let rule = |id: &str, name: &str, enabled| Rule {
            id: id.to_owned(),
            process_name: name.to_owned(),
            enabled,
            ..Rule::default()
        };
        let config = Config {
            rules: vec![
                rule("a", "Curl*", true),
                rule("b", "git.exe", false),
                rule("c", "  ", true),
                rule("d", "node.exe", true),
            ],
            ..Config::default()
        };
        let set = RuleSet::compile(&config);
        assert_eq!(set.len(), 2);
        assert_eq!(set.get(0).id, "a");
        assert!(set.get(0).matches_name("curl.exe"));
        assert_eq!(set.get(1).id, "d");
    }
}
