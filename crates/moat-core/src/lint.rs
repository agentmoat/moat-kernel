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
use crate::pattern::{self, GlobPattern, ShellPattern};
use crate::policy::{Defaults, Policy, RuleGroup};
use crate::secret::Source as SecretSource;

/// Placeholders so `~` and `${project}` compare equal on both sides without
/// `{…}` being read as glob alternation.
const HOME: &str = "/__home__";
const PROJECT: &str = "/__project__";

/// A policy construct that is valid but probably not what its author meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Rule id the warning is about (`defaults` for the defaults table).
    pub rule: String,
    /// What is wrong and what happens instead.
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
    secrets(policy, &mut out);
    out
}

/// A secret whose host the proxy refuses is never injected, and one whose
/// source the agent may read is not kept from the agent.
fn secrets(policy: &Policy, out: &mut Vec<Warning>) {
    for secret in &policy.secrets {
        let mut warn = |message: String| {
            out.push(Warning {
                rule: format!("secrets.{}", secret.id),
                message,
            });
        };
        if !listed(&policy.allow, &[Kind::Net, Kind::Fetch], &secret.host) {
            warn(format!(
                "no net or fetch allow rule names {}, so `moat proxy` refuses it and the \
                 secret is never injected",
                secret.host
            ));
        }
        let exposed = match &secret.source {
            SecretSource::File(path) => paths::expand_pattern(path, HOME, Some(PROJECT))
                .filter(|p| !listed(&policy.deny, &[Kind::FsRead], p))
                .map(|_| format!("no deny fs.read rule covers `{path}`, so the agent can read it")),
            SecretSource::Env(name) => (!listed(&policy.deny, &[Kind::EnvRead], name)).then(|| {
                format!("no deny env.read rule covers `{name}`, so the agent can read it")
            }),
            SecretSource::Keychain { .. } => None,
        };
        if let Some(message) = exposed {
            warn(message);
        }
        if secret.plain_http && !secret.is_loopback() {
            warn(format!(
                "`plain_http: true` sends the value to {} in clear text, readable by anyone \
                 on the network path",
                secret.host
            ));
        }
    }
}

/// Does a group in `groups` match `candidate` in one of `kinds`, `!` exclusions
/// applied?
fn listed(groups: &[RuleGroup], kinds: &[Kind], candidate: &str) -> bool {
    groups.iter().any(|g| {
        kinds.iter().any(|k| {
            let list: Vec<GlobPattern> = g.patterns(*k).iter().filter_map(|p| glob(p)).collect();
            pattern::any_match(&list, candidate)
        })
    })
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

/// Warn for every pattern in `later` that a pattern in `earlier` (evaluated
/// first) fully covers: one of the same kind, or a `net` pattern for a `fetch`
/// one (`net` lists match fetches too; a `fetch` pattern never covers a `net`
/// one). Lists with `!` exclusions are never assumed to cover anything.
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
                    kind.rule_kinds().iter().find_map(|by_kind| {
                        let list = e.patterns(*by_kind);
                        if list.iter().any(|p| p.starts_with('!')) {
                            return None;
                        }
                        list.iter()
                            .find(|by| covers(kind, by, pattern))
                            .map(|by| (&e.id, *by_kind, by))
                    })
                });
                if let Some((by_rule, by_kind, by_pattern)) = hit {
                    out.push(Warning {
                        rule: group.id.clone(),
                        message: format!(
                            "{later_name} {kind} pattern `{pattern}` is unreachable: \
                             {earlier_name} rule `{by_rule}` {by_kind} pattern `{by_pattern}` \
                             matches everything it matches and {earlier_name} is evaluated first"
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
    GlobPattern::compile(&paths::expand_pattern(raw, HOME, Some(PROJECT))?, false).ok()
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
    fn net_patterns_shadow_fetch_patterns_but_not_the_reverse() {
        let w = warn(
            "version: 1\nallow:\n  - id: reg\n    net: ['*.crates.io']\n    fetch: ['docs.rs']\n\
             ask:\n  - id: web\n    fetch: ['static.crates.io']\n    net: ['docs.rs']\n",
        );
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("ask fetch pattern `static.crates.io`"),
            "{w:?}"
        );
        assert!(
            w[0].contains("rule `reg` net pattern `*.crates.io`"),
            "{w:?}"
        );
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

    #[test]
    fn secrets_the_proxy_refuses_or_the_agent_can_read() {
        let secrets = "secrets:\n  - id: gh\n    host: api.github.com\n    header: Authorization\n    \
                       source: { file: ~/.config/moat/gh }\n  - id: npm\n    host: registry.npmjs.org\n    \
                       header: Authorization\n    source: { env: NPM_TOKEN }\n";
        let w = warn(&format!("version: 1\n{secrets}"));
        assert_eq!(w.len(), 4, "{w:?}");
        assert!(
            w[0].contains("secrets.gh") && w[0].contains("refuses it"),
            "{w:?}"
        );
        assert!(
            w[1].contains("`~/.config/moat/gh`, so the agent can read it"),
            "{w:?}"
        );
        assert!(
            w[3].contains("`NPM_TOKEN`, so the agent can read it"),
            "{w:?}"
        );
        let covered = warn(&format!(
            "version: 1\ndeny:\n  - id: s\n    fs.read: ['~/.config/moat/**']\n    env.read: ['*_TOKEN']\n\
             allow:\n  - id: n\n    net: ['api.github.com', '*.npmjs.org']\n{secrets}"
        ));
        assert!(covered.is_empty(), "{covered:?}");
        let excluded = warn(&format!(
            "version: 1\ndeny:\n  - id: s\n    fs.read: ['~/.config/**', '!~/.config/moat/**']\n    \
             env.read: ['*']\nallow:\n  - id: n\n    net: ['*', '!api.github.com']\n{secrets}"
        ));
        assert_eq!(excluded.len(), 2, "{excluded:?}");
    }

    #[test]
    fn plain_http_injection_off_this_machine_is_reported() {
        let policy = |host: &str| {
            format!(
                "version: 1\ndeny:\n  - id: s\n    env.read: ['*']\nallow:\n  - id: n\n    net: ['*']\n\
                 secrets:\n  - id: s\n    host: {host}\n    header: X-K\n    source: {{ env: K }}\n    \
                 plain_http: true\n"
            )
        };
        let w = warn(&policy("api.example.com"));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("in clear text"), "{w:?}");
        assert!(warn(&policy("localhost")).is_empty());
        assert!(warn(&policy("127.0.0.1")).is_empty());
    }
}
