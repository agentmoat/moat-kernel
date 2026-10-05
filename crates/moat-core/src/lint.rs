//! Policy warnings: valid policies that probably do not mean what they say.
//!
//! Errors (`Policy::lint`) make a policy unusable; warnings do not. Evaluation
//! is `deny → allow → ask` per atomic action, so a pattern in a later list that
//! an earlier list already matches can never decide anything. The checks are
//! conservative: a warning means the shadowing was shown from the patterns
//! alone; silence does not prove a rule is reachable.

use std::fmt;

use crate::kind::Kind;
use crate::paths;
use crate::pattern::{GlobPattern, ShellPattern};
use crate::policy::{Defaults, Policy, RuleGroup};

/// Placeholders so `~` and `${project}` compare equal on both sides without
/// `{…}` being read as glob alternation.
const HOME: &str = "/__home__";
const PROJECT: &str = "/__project__";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Rule id the warning is about (`defaults` for the defaults table).
    pub rule: String,
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule `{}`: {}", self.rule, self.message)
    }
}

/// Every warning for `policy`, in policy order. `policy` must already lint.
#[must_use]
pub fn warnings(policy: &Policy) -> Vec<Warning> {
    let mut out = unknown_default_kinds(&policy.defaults);
    for (key, present) in [
        ("approval", policy.approval.is_some()),
        ("scope", policy.scope.is_some()),
    ] {
        if present {
            out.push(Warning {
                rule: key.to_owned(),
                message: format!(
                    "`{key}` is reserved and has no effect yet; approvals are made with `moat allow` \
                     and the project root is the git root of the call's working directory"
                ),
            });
        }
    }
    shadowed(&policy.ask, &policy.allow, "ask", "allow", &mut out);
    shadowed(&policy.allow, &policy.deny, "allow", "deny", &mut out);
    out
}

fn unknown_default_kinds(defaults: &Defaults) -> Vec<Warning> {
    let Defaults::PerKind(map) = defaults else {
        return Vec::new();
    };
    let known: Vec<&str> = std::iter::once("*")
        .chain(Kind::ALL.iter().map(|k| k.as_str()))
        .collect();
    map.keys()
        .filter(|k| !known.contains(&k.as_str()))
        .map(|k| Warning {
            rule: "defaults".to_owned(),
            message: format!(
                "unknown kind `{k}` is ignored; known kinds: {}",
                known.join(", ")
            ),
        })
        .collect()
}

/// Warn for every pattern in `later` that a pattern of the same kind in
/// `earlier` (evaluated first) fully covers. Lists with `!` exclusions are
/// never assumed to cover anything.
fn shadowed(
    later: &[RuleGroup],
    earlier: &[RuleGroup],
    later_name: &str,
    earlier_name: &str,
    out: &mut Vec<Warning>,
) {
    for group in later {
        for kind in Kind::ALL {
            for pattern in group.patterns(kind) {
                let hit = earlier.iter().find_map(|e| {
                    let list = e.patterns(kind);
                    if list.iter().any(|p| p.starts_with('!')) {
                        return None;
                    }
                    list.iter()
                        .find(|by| covers(kind, by, pattern))
                        .map(|by| (&e.id, by))
                });
                if let Some((by_rule, by_pattern)) = hit {
                    out.push(Warning {
                        rule: group.id.clone(),
                        message: format!(
                            "{later_name} {kind} pattern `{pattern}` is unreachable: \
                             {earlier_name} rule `{by_rule}` pattern `{by_pattern}` matches \
                             everything it matches and {earlier_name} is evaluated first"
                        ),
                    });
                }
            }
        }
    }
}

/// Does pattern `by` match everything pattern `target` matches?
fn covers(kind: Kind, by: &str, target: &str) -> bool {
    if kind == Kind::Shell {
        match (ShellPattern::compile(by), ShellPattern::compile(target)) {
            (Ok(by), Ok(target)) => by.covers(&target),
            _ => false,
        }
    } else {
        matches!((glob(by), glob(target)), (Some(by), Some(target)) if by.covers(&target))
    }
}

fn glob(raw: &str) -> Option<GlobPattern> {
    GlobPattern::compile(&paths::expand_pattern(raw, HOME, PROJECT), false).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warn(yaml: &str) -> Vec<String> {
        warnings(&Policy::parse(yaml).unwrap())
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn ask_shadowed_by_allow_shell_prefix() {
        let w = warn(
            "version: 1\nallow:\n  - id: dev\n    shell: ['cargo *']\n\
             ask:\n  - id: push\n    shell: ['cargo publish*', 'git push*']\n",
        );
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("rule `push`") && w[0].contains("`cargo publish*`"));
        assert!(w[0].contains("rule `dev`") && w[0].contains("`cargo *`"));
    }

    #[test]
    fn allow_shadowed_by_deny_glob() {
        let w = warn(
            "version: 1\ndeny:\n  - id: secrets\n    fs.read: ['~/.ssh/**']\n\
             allow:\n  - id: keys\n    fs.read: ['~/.ssh/config', '${project}/**']\n",
        );
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("allow fs.read pattern `~/.ssh/config`"));
    }

    #[test]
    fn negated_lists_are_not_assumed_to_cover() {
        let w = warn(
            "version: 1\nallow:\n  - id: proj\n    fs.write: ['${project}/**', '!${project}/.git/**']\n\
             ask:\n  - id: git\n    fs.write: ['${project}/.git/**']\n",
        );
        assert!(w.is_empty(), "{w:?}");
    }

    #[test]
    fn reserved_blocks_are_reported() {
        let w =
            warn("version: 1\napproval:\n  channel: telegram\nscope:\n  project_roots: ['.']\n");
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("`approval` is reserved") && w[1].contains("`scope` is reserved"));
        assert!(warn("version: 1\n").is_empty());
    }

    #[test]
    fn unknown_default_kinds() {
        let w = warn("version: 1\ndefaults: { network: deny, net: deny, '*': ask }\n");
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("`network`"));
        assert!(warn("version: 1\ndefaults: allow\n").is_empty());
    }
}
