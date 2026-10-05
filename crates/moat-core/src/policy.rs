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
    /// The same verdict for every kind.
    All(Verdict),
    /// A verdict per kind name (`net`, `fs.read`, …), with `*` as the fallback.
    PerKind(BTreeMap<String, Verdict>),
}

impl Defaults {
    /// Verdict and synthetic rule id (`default` or `default.<kind>`) for a kind.
    #[must_use]
    pub fn for_kind(&self, kind: Kind) -> (Verdict, String) {
        match self {
            Self::All(v) => (*v, "default".to_owned()),
            Self::PerKind(map) => map.get(kind.as_str()).map_or_else(
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

use crate::kind::Kind;
use crate::pattern::{GlobPattern, ShellPattern};
use crate::verdict::Verdict;

pub const SUPPORTED_VERSION: u32 = 1;

#[derive(Debug, Error)]
/// Why a policy file cannot be used. Any of these keeps `guard` from deciding.
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    /// The file is not valid YAML or does not fit the schema.
    Parse(#[from] serde_yaml_ng::Error),
    #[error("unsupported policy version {found}; this build supports {supported}")]
    /// The `version` key names a schema this build does not know.
    Version {
        /// The version in the file.
        found: u32,
        /// The version this build supports.
        supported: u32,
    },
    #[error("duplicate rule id `{0}`")]
    /// Two rule groups share an id.
    DuplicateId(String),
    #[error("rule `{0}` has no patterns")]
    /// A rule group lists no patterns.
    EmptyRule(String),
    #[error("empty pattern")]
    /// A pattern is empty (or only `!`/`$`).
    EmptyPattern,
    #[error("bad glob `{pattern}`: {source}")]
    /// A glob does not compile.
    BadGlob {
        /// The pattern as written.
        pattern: String,
        /// The glob compiler's explanation.
        source: globset::Error,
    },
    #[error("bad shell pattern `{pattern}` (unbalanced quotes?)")]
    /// A shell pattern does not tokenise (unbalanced quotes, a here-document).
    BadShellPattern {
        /// The pattern as written.
        pattern: String,
    },
    #[error("rule `{rule}`: {problem}")]
    /// A rule group or `executables` entry is invalid; `problem` says why.
    Rule {
        /// Rule id, or `executables.<name>`.
        rule: String,
        /// What is wrong.
        problem: String,
    },
}

/// One named group of patterns. A group matches when **any** of its patterns
/// matches the atomic action of the corresponding kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleGroup {
    /// Stable identifier shown in decisions and the audit log.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Text prepended to the reason when this group decides.
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Shell patterns (token prefixes, `*`, `!`, trailing `$`).
    pub shell: Vec<String>,
    #[serde(default, rename = "fs.read", skip_serializing_if = "Vec::is_empty")]
    /// Path globs for file reads.
    pub fs_read: Vec<String>,
    #[serde(default, rename = "fs.write", skip_serializing_if = "Vec::is_empty")]
    /// Path globs for file writes.
    pub fs_write: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Host globs.
    pub net: Vec<String>,
    #[serde(default, rename = "env.read", skip_serializing_if = "Vec::is_empty")]
    /// Variable-name globs for reads.
    pub env_read: Vec<String>,
    #[serde(default, rename = "env.set", skip_serializing_if = "Vec::is_empty")]
    /// Variable-name globs for sets.
    pub env_set: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// MCP tool-name globs.
    pub mcp: Vec<String>,
}

impl RuleGroup {
    /// The patterns this group lists for `kind`.
    #[must_use]
    pub fn patterns(&self, kind: Kind) -> &[String] {
        match kind {
            Kind::Shell => &self.shell,
            Kind::FsRead => &self.fs_read,
            Kind::FsWrite => &self.fs_write,
            Kind::Net => &self.net,
            Kind::EnvRead => &self.env_read,
            Kind::EnvSet => &self.env_set,
            Kind::Mcp => &self.mcp,
        }
    }

    fn is_empty(&self) -> bool {
        Kind::ALL.iter().all(|k| self.patterns(*k).is_empty())
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
    /// Schema version; only 1 is supported.
    pub version: u32,
    #[serde(default = "default_verdict")]
    /// Verdict when no rule matches.
    pub defaults: Defaults,
    /// Reserved for multi-root projects; parsed so existing files stay valid,
    /// not yet consulted (`policy lint` warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    #[serde(default)]
    /// Evaluated first; a match is final.
    pub deny: Vec<RuleGroup>,
    #[serde(default)]
    /// Evaluated after `deny`.
    pub allow: Vec<RuleGroup>,
    #[serde(default)]
    /// Evaluated after `allow`.
    pub ask: Vec<RuleGroup>,
    /// Reserved for the kernel's own approval prompt; parsed so existing files
    /// stay valid, not yet consulted (`policy lint` warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<Approval>,
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
            for kind in Kind::ALL {
                for p in group.patterns(kind) {
                    let compiled = if kind == Kind::Shell {
                        ShellPattern::compile(p).map(drop)
                    } else {
                        GlobPattern::compile(p, false).map(drop)
                    };
                    compiled.map_err(|e| rule_err(&group.id, &e))?;
                }
            }
        }
        for (name, paths) in &self.executables {
            if paths.is_empty() {
                return Err(PolicyError::Rule {
                    rule: format!("executables.{name}"),
                    problem: "no paths listed".into(),
                });
            }
            if let Some(bad) = paths.iter().find(|p| !crate::paths::is_absolute(p)) {
                return Err(PolicyError::Rule {
                    rule: format!("executables.{name}"),
                    problem: format!("`{bad}` is not an absolute path"),
                });
            }
        }
        Ok(())
    }

    /// Number of rule groups in `deny`, `allow` and `ask`.
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
            p.defaults.for_kind(Kind::Net),
            (Verdict::Deny, "default.net".to_owned())
        );
        assert_eq!(
            p.defaults.for_kind(Kind::Shell),
            (Verdict::Ask, "default".to_owned())
        );
    }

    #[test]
    fn executables_must_be_absolute_on_every_platform() {
        let ok = "version: 1\nexecutables:\n  git: ['/usr/bin/git', 'C:/Program Files/Git/bin/git.exe']\n";
        assert!(Policy::parse(ok).is_ok());
        let rel = "version: 1\nexecutables:\n  git: ['bin/git']\n";
        assert!(matches!(Policy::parse(rel), Err(PolicyError::Rule { .. })));
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Policy::parse("version: 1\nbogus: 1\n").is_err());
    }
}
