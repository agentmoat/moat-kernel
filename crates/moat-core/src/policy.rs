//! Policy file model, loading and linting (DESIGN.md §6).

use std::collections::{BTreeMap, BTreeSet};

/// Fallback verdicts when no rule matches: one verdict for everything, or a map
/// from action kind (`shell`, `fs.read`, `fs.write`, `net`, `env.read`,
/// `env.set`, `mcp`, or `"*"`) to a verdict. This is how "outbound network is
/// deny-by-default" is expressed, because deny rules are absolute and cannot
/// be punched through by allow rules (DESIGN.md §6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Defaults {
    All(Verdict),
    PerKind(BTreeMap<String, Verdict>),
}

impl Defaults {
    /// Verdict and synthetic rule id (`default` or `default.<kind>`) for a kind.
    #[must_use]
    pub fn for_kind(&self, kind: &str) -> (Verdict, String) {
        match self {
            Self::All(v) => (*v, "default".to_owned()),
            Self::PerKind(map) => map.get(kind).map_or_else(
                || {
                    (
                        map.get("*").copied().unwrap_or(Verdict::Ask),
                        "default".to_owned(),
                    )
                },
                |v| (*v, format!("default.{kind}")),
            ),
        }
    }
}

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pattern::{GlobPattern, ShellPattern};
use crate::verdict::Verdict;

pub const SUPPORTED_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(#[from] serde_yaml_ng::Error),
    #[error("unsupported policy version {found}; this build supports {supported}")]
    Version { found: u32, supported: u32 },
    #[error("duplicate rule id `{0}`")]
    DuplicateId(String),
    #[error("rule `{0}` has no patterns")]
    EmptyRule(String),
    #[error("empty pattern")]
    EmptyPattern,
    #[error("bad glob `{pattern}`: {source}")]
    BadGlob {
        pattern: String,
        source: globset::Error,
    },
    #[error("bad shell pattern `{pattern}` (unbalanced quotes?)")]
    BadShellPattern { pattern: String },
    #[error("rule `{rule}`: {problem}")]
    Rule { rule: String, problem: String },
}

/// One named group of patterns. A group matches when **any** of its patterns
/// matches the atomic action of the corresponding kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleGroup {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shell: Vec<String>,
    #[serde(default, rename = "fs.read", skip_serializing_if = "Vec::is_empty")]
    pub fs_read: Vec<String>,
    #[serde(default, rename = "fs.write", skip_serializing_if = "Vec::is_empty")]
    pub fs_write: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net: Vec<String>,
    #[serde(default, rename = "env.read", skip_serializing_if = "Vec::is_empty")]
    pub env_read: Vec<String>,
    #[serde(default, rename = "env.set", skip_serializing_if = "Vec::is_empty")]
    pub env_set: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp: Vec<String>,
}

impl RuleGroup {
    fn is_empty(&self) -> bool {
        self.shell.is_empty()
            && self.fs_read.is_empty()
            && self.fs_write.is_empty()
            && self.net.is_empty()
            && self.env_read.is_empty()
            && self.env_set.is_empty()
            && self.mcp.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default = "default_roots")]
    pub project_roots: Vec<String>,
}

fn default_roots() -> Vec<String> {
    vec![".".to_owned()]
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            project_roots: default_roots(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalChannel {
    Terminal,
    Telegram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RememberScope {
    Once,
    Session,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    #[serde(default = "default_channel")]
    pub channel: ApprovalChannel,
    #[serde(default = "default_remember")]
    pub remember: RememberScope,
    #[serde(default = "default_timeout")]
    pub timeout_s: u32,
}

fn default_channel() -> ApprovalChannel {
    ApprovalChannel::Terminal
}
fn default_remember() -> RememberScope {
    RememberScope::Session
}
fn default_timeout() -> u32 {
    300
}

impl Default for Approval {
    fn default() -> Self {
        Self {
            channel: default_channel(),
            remember: default_remember(),
            timeout_s: default_timeout(),
        }
    }
}

/// The policy document (`policy.yaml`), as written by users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default = "default_verdict")]
    pub defaults: Defaults,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub deny: Vec<RuleGroup>,
    #[serde(default)]
    pub allow: Vec<RuleGroup>,
    #[serde(default)]
    pub ask: Vec<RuleGroup>,
    #[serde(default)]
    pub approval: Approval,
    /// Basename → allowed absolute paths (defeats PATH poisoning).
    #[serde(default)]
    pub executables: BTreeMap<String, Vec<String>>,
}

fn default_verdict() -> Defaults {
    Defaults::All(Verdict::Ask)
}

impl Policy {
    /// Parse and lint a policy document. Pure: takes the YAML text.
    pub fn parse(yaml: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml_ng::from_str(yaml)?;
        policy.lint()?;
        Ok(policy)
    }

    /// Structural validation independent of any environment.
    pub fn lint(&self) -> Result<(), PolicyError> {
        if self.version != SUPPORTED_VERSION {
            return Err(PolicyError::Version {
                found: self.version,
                supported: SUPPORTED_VERSION,
            });
        }
        let mut ids = BTreeSet::new();
        for group in self.deny.iter().chain(&self.allow).chain(&self.ask) {
            if group.id.trim().is_empty() {
                return Err(PolicyError::Rule {
                    rule: "<unnamed>".into(),
                    problem: "missing id".into(),
                });
            }
            if !ids.insert(group.id.clone()) {
                return Err(PolicyError::DuplicateId(group.id.clone()));
            }
            if group.is_empty() {
                return Err(PolicyError::EmptyRule(group.id.clone()));
            }
            for p in &group.shell {
                ShellPattern::compile(p).map_err(|e| rule_err(&group.id, &e))?;
            }
            for p in group
                .fs_read
                .iter()
                .chain(&group.fs_write)
                .chain(&group.net)
                .chain(&group.env_read)
                .chain(&group.env_set)
                .chain(&group.mcp)
            {
                GlobPattern::compile(p, false).map_err(|e| rule_err(&group.id, &e))?;
            }
        }
        for (name, paths) in &self.executables {
            if paths.is_empty() {
                return Err(PolicyError::Rule {
                    rule: format!("executables.{name}"),
                    problem: "no paths listed".into(),
                });
            }
            if let Some(bad) = paths.iter().find(|p| !p.starts_with('/')) {
                return Err(PolicyError::Rule {
                    rule: format!("executables.{name}"),
                    problem: format!("`{bad}` is not an absolute path"),
                });
            }
        }
        Ok(())
    }

    /// Total number of rule groups.
    #[must_use]
    pub fn rule_count(&self) -> (usize, usize, usize) {
        (self.deny.len(), self.allow.len(), self.ask.len())
    }
}

fn rule_err(rule: &str, e: &PolicyError) -> PolicyError {
    PolicyError::Rule {
        rule: rule.to_owned(),
        problem: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal() {
        let p = Policy::parse("version: 1\ndeny:\n  - id: a\n    shell: ['sudo *']\n").unwrap();
        assert_eq!(p.defaults, Defaults::All(Verdict::Ask));
        assert_eq!(p.rule_count(), (1, 0, 0));
    }

    #[test]
    fn rejects_duplicate_and_empty() {
        let dup =
            "version: 1\ndeny:\n  - id: a\n    shell: ['x']\nallow:\n  - id: a\n    net: ['h']\n";
        assert!(matches!(
            Policy::parse(dup),
            Err(PolicyError::DuplicateId(_))
        ));
        let empty = "version: 1\ndeny:\n  - id: a\n";
        assert!(matches!(
            Policy::parse(empty),
            Err(PolicyError::EmptyRule(_))
        ));
        let ver = "version: 2\n";
        assert!(matches!(
            Policy::parse(ver),
            Err(PolicyError::Version { .. })
        ));
    }

    #[test]
    fn per_kind_defaults() {
        let p = Policy::parse("version: 1\ndefaults: { net: deny, '*': ask }\n").unwrap();
        assert_eq!(
            p.defaults.for_kind("net"),
            (Verdict::Deny, "default.net".to_owned())
        );
        assert_eq!(
            p.defaults.for_kind("shell"),
            (Verdict::Ask, "default".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Policy::parse("version: 1\nbogus: 1\n").is_err());
    }
}
