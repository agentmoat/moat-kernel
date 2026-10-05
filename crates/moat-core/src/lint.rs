//! Policy warnings: valid policies that probably do not mean what they say.
//!
//! Errors (`Policy::lint`) make a policy unusable; warnings do not. Evaluation
//! is `deny → allow → ask` per atomic action, so a pattern in a later list that
//! an earlier list already matches can never decide anything. The checks are
//! conservative: a warning means the shadowing was shown from the patterns
//! alone; silence does not prove a rule is reachable.

use std::fmt;

use crate::paths;
use crate::pattern::{GlobPattern, ShellPattern};
use crate::policy::{Defaults, Policy, RuleGroup};

/// Kinds a `defaults` map may name.
const KINDS: &[&str] = &[
    "*", "shell", "fs.read", "fs.write", "net", "env.read", "env.set", "mcp",
];

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
    shadowed(&policy.ask, &policy.allow, "ask", "allow", &mut out);
    shadowed(&policy.allow, &policy.deny, "allow", "deny", &mut out);
    out
}

fn unknown_default_kinds(defaults: &Defaults) -> Vec<Warning> {
    let Defaults::PerKind(map) = defaults else {
        return Vec::new();
    };
    map.keys()
        .filter(|k| !KINDS.contains(&k.as_str()))
        .map(|k| Warning {
            rule: "defaults".to_owned(),
            message: format!(
                "unknown kind `{k}` is ignored; known kinds: {}",
                KINDS.join(", ")
            ),
        })
        .collect()
}

/// Warn for every pattern in `later` that a pattern of the same kind in
/// `earlier` (evaluated first) fully covers.
fn shadowed(
    later: &[RuleGroup],
    earlier: &[RuleGroup],
    later_name: &str,
    earlier_name: &str,
    out: &mut Vec<Warning>,
) {
    for group in later {
        for (kind, patterns) in globs(group) {
            for pattern in patterns {
                let Some(target) = glob(pattern) else {
                    continue;
                };
                let hit = earlier.iter().find_map(|e| {
                    let list = globs(e).into_iter().find(|(k, _)| *k == kind)?.1;
                    if list.iter().any(|p| p.starts_with('!')) {
                        return None;
                    }
                    list.iter()
                        .find(|p| glob(p).is_some_and(|g| g.covers(&target)))
                        .map(|p| (&e.id, p))
                });
                if let Some((id, by)) = hit {
                    out.push(cover_warning(
                        group,
                        kind,
                        pattern,
                        later_name,
                        earlier_name,
                        id,
                        by,
                    ));
                }
            }
        }
        for pattern in &group.shell {
            let Ok(target) = ShellPattern::compile(pattern) else {
                continue;
            };
            let hit = earlier.iter().find_map(|e| {
                if e.shell.iter().any(|p| p.starts_with('!')) {
                    return None;
                }
                e.shell
                    .iter()
                    .find(|p| ShellPattern::compile(p).is_ok_and(|s| s.covers(&target)))
                    .map(|p| (&e.id, p))
            });
            if let Some((id, by)) = hit {
                out.push(cover_warning(
                    group,
                    "shell",
                    pattern,
                    later_name,
                    earlier_name,
                    id,
                    by,
                ));
            }
        }
    }
}

fn cover_warning(
    group: &RuleGroup,
    kind: &str,
    pattern: &str,
    later: &str,
    earlier: &str,
    by_rule: &str,
    by_pattern: &str,
) -> Warning {
    Warning {
        rule: group.id.clone(),
        message: format!(
            "{later} {kind} pattern `{pattern}` is unreachable: {earlier} rule `{by_rule}` \
             pattern `{by_pattern}` matches everything it matches and {earlier} is evaluated first"
        ),
    }
}

fn globs(group: &RuleGroup) -> [(&'static str, &[String]); 6] {
    [
        ("fs.read", &group.fs_read),
        ("fs.write", &group.fs_write),
        ("net", &group.net),
        ("env.read", &group.env_read),
        ("env.set", &group.env_set),
        ("mcp", &group.mcp),
    ]
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
    fn unknown_default_kinds() {
        let w = warn("version: 1\ndefaults: { network: deny, net: deny, '*': ask }\n");
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("`network`"));
        assert!(warn("version: 1\ndefaults: allow\n").is_empty());
    }
}
