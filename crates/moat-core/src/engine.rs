//! The decision engine (DESIGN.md §6.3, §7.1).
//!
//! Per atomic action: `deny → allow → ask → defaults`. Across the atomic
//! actions of one tool call: strictest verdict wins. Deny rules are absolute;
//! an allow rule can never override a deny, so "deny by default with holes"
//! is expressed through per-kind `defaults`, never through a deny rule.

use crate::action::{Action, AtomicAction};
use crate::paths;
use crate::pattern::{GlobPattern, ShellPattern, any_match};
use crate::policy::{Policy, PolicyError, RuleGroup};
use crate::shell::{ParseOutcome, ShellContext, classify};
use crate::verdict::{Decision, Verdict};

/// Everything the engine needs from the environment. Supplied by the caller.
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub home: String,
    pub project: String,
    pub cwd: String,
}

/// A policy with all patterns compiled for one evaluation context.
///
/// Compile once per process (or per policy reload) and reuse for every tool
/// call; compilation dominates the cost of a single decision.
#[derive(Debug)]
pub struct CompiledPolicy<'p> {
    policy: &'p Policy,
    ctx: EvalContext,
    deny: Vec<CompiledGroup<'p>>,
    allow: Vec<CompiledGroup<'p>>,
    ask: Vec<CompiledGroup<'p>>,
}

#[derive(Debug)]
struct CompiledGroup<'p> {
    group: &'p RuleGroup,
    shell: Vec<ShellPattern>,
    fs_read: Vec<GlobPattern>,
    fs_write: Vec<GlobPattern>,
    net: Vec<GlobPattern>,
    env_read: Vec<GlobPattern>,
    env_set: Vec<GlobPattern>,
    mcp: Vec<GlobPattern>,
}

const PATH_CASE_INSENSITIVE: bool = cfg!(any(target_os = "macos", windows));

impl<'p> CompiledPolicy<'p> {
    pub fn compile(policy: &'p Policy, ctx: &EvalContext) -> Result<Self, PolicyError> {
        let compile_group = |g: &'p RuleGroup| -> Result<CompiledGroup<'p>, PolicyError> {
            let globs = |pats: &[String], case_insensitive: bool| {
                pats.iter()
                    .map(|p| {
                        GlobPattern::compile(
                            &paths::expand_pattern(p, &ctx.home, &ctx.project),
                            case_insensitive,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            };
            Ok(CompiledGroup {
                group: g,
                shell: g
                    .shell
                    .iter()
                    .map(|p| ShellPattern::compile(p))
                    .collect::<Result<_, _>>()?,
                fs_read: globs(&g.fs_read, PATH_CASE_INSENSITIVE)?,
                fs_write: globs(&g.fs_write, PATH_CASE_INSENSITIVE)?,
                net: globs(&g.net, true)?,
                env_read: globs(&g.env_read, false)?,
                env_set: globs(&g.env_set, false)?,
                mcp: globs(&g.mcp, false)?,
            })
        };
        Ok(Self {
            policy,
            ctx: ctx.clone(),
            deny: policy
                .deny
                .iter()
                .map(compile_group)
                .collect::<Result<_, _>>()?,
            allow: policy
                .allow
                .iter()
                .map(compile_group)
                .collect::<Result<_, _>>()?,
            ask: policy
                .ask
                .iter()
                .map(compile_group)
                .collect::<Result<_, _>>()?,
        })
    }

    /// Evaluate one atomic action: deny → allow → ask → default.
    ///
    /// Returns `None` for a whole-pipeline atom that no rule mentions: pipelines
    /// are only there so rules like `curl * | sh` can see across `|`; the
    /// per-sub-command atoms carry the default verdict.
    #[must_use]
    pub fn evaluate_atomic(&self, action: &AtomicAction) -> Option<Decision> {
        for (groups, verdict) in [
            (&self.deny, Verdict::Deny),
            (&self.allow, Verdict::Allow),
            (&self.ask, Verdict::Ask),
        ] {
            let mut hit = Decision::new(verdict);
            for g in groups {
                if g.matches(action) {
                    let why = g.group.reason.as_ref().map_or_else(
                        || action.describe(),
                        |r| format!("{r}: {}", action.describe()),
                    );
                    hit.push(&g.group.id, why);
                }
            }
            if !hit.rules.is_empty() {
                return Some(hit);
            }
        }
        if matches!(action, AtomicAction::Pipeline { .. }) {
            return None;
        }
        let (verdict, rule_id) = self.policy.defaults.for_kind(action.kind());
        let mut d = Decision::new(verdict);
        d.push(&rule_id, format!("no rule matched {}", action.describe()));
        Some(d)
    }
}

impl CompiledGroup<'_> {
    fn matches(&self, action: &AtomicAction) -> bool {
        match action {
            AtomicAction::Shell { argv } | AtomicAction::Pipeline { argv } => {
                self.shell.iter().any(|p| p.is_match(argv))
            }
            AtomicAction::FsRead { path } => any_match(&self.fs_read, path),
            AtomicAction::FsWrite { path } => any_match(&self.fs_write, path),
            AtomicAction::Net { host } => any_match(&self.net, host),
            AtomicAction::EnvRead { name } => any_match(&self.env_read, name),
            AtomicAction::EnvSet { name } => any_match(&self.env_set, name),
            AtomicAction::McpTool { name } => any_match(&self.mcp, name),
        }
    }
}

/// Classify an [`Action`] into atomic actions for the given context.
#[must_use]
pub fn classify_action(action: &Action, ctx: &EvalContext) -> ParseOutcome {
    match action {
        Action::Shell { command } => classify(
            command,
            &ShellContext {
                home: &ctx.home,
                project: &ctx.project,
                cwd: &ctx.cwd,
            },
        ),
        Action::FsRead { path } => ParseOutcome::Parsed(vec![AtomicAction::FsRead {
            path: paths::normalise(path, &ctx.home, &ctx.project, &ctx.cwd),
        }]),
        Action::FsWrite { path } => ParseOutcome::Parsed(vec![AtomicAction::FsWrite {
            path: paths::normalise(path, &ctx.home, &ctx.project, &ctx.cwd),
        }]),
        Action::Net { url } => match host_of_url(url) {
            Some(host) => ParseOutcome::Parsed(vec![AtomicAction::Net { host }]),
            None => ParseOutcome::Unparseable {
                reason: format!("no host in url `{url}`"),
            },
        },
        Action::McpTool { name } => {
            ParseOutcome::Parsed(vec![AtomicAction::McpTool { name: name.clone() }])
        }
    }
}

fn host_of_url(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .split(':')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

impl CompiledPolicy<'_> {
    /// Decide one host action.
    ///
    /// Unparseable input yields `ask` with the parser's reason, never `allow`.
    #[must_use]
    pub fn decide(&self, action: &Action) -> Decision {
        let atoms = match classify_action(action, &self.ctx) {
            ParseOutcome::Parsed(atoms) => atoms,
            ParseOutcome::Unparseable { reason } => {
                return unparseable(format!("could not parse action safely: {reason}"));
            }
        };
        atoms
            .iter()
            .filter_map(|atom| self.evaluate_atomic(atom))
            .reduce(|mut acc, next| {
                acc.merge(next);
                acc
            })
            .unwrap_or_else(|| unparseable("action has no evaluable parts".to_owned()))
    }
}

fn unparseable(reason: String) -> Decision {
    let mut decision = Decision::new(Verdict::Ask);
    decision.push("unparseable", reason);
    decision
}

/// Compile `policy` for `ctx` and decide a single action.
///
/// Convenience for one-shot callers; long-lived callers should keep a
/// [`CompiledPolicy`] instead.
pub fn evaluate(
    policy: &Policy,
    ctx: &EvalContext,
    action: &Action,
) -> Result<Decision, PolicyError> {
    Ok(CompiledPolicy::compile(policy, ctx)?.decide(action))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EvalContext {
        EvalContext {
            home: "/h".into(),
            project: "/p".into(),
            cwd: "/p".into(),
        }
    }

    fn policy(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("test policy must lint")
    }

    fn shell(command: &str) -> Action {
        Action::Shell {
            command: command.to_owned(),
        }
    }

    #[test]
    fn deny_is_absolute_over_allow() {
        let p = policy(
            "version: 1\ndeny:\n  - id: d\n    shell: ['git push --force*']\n\
             allow:\n  - id: a\n    shell: ['git *']\n",
        );
        let d = evaluate(&p, &ctx(), &shell("git push --force")).unwrap();
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, ["d"]);
    }

    #[test]
    fn strictest_atom_wins_and_weaker_matches_become_context() {
        let p = policy(
            "version: 1\ndeny:\n  - id: secret\n    fs.read: ['~/.ssh/**']\n\
             allow:\n  - id: cat\n    shell: ['cat *']\n",
        );
        let d = evaluate(&p, &ctx(), &shell("cat ~/.ssh/id_rsa")).unwrap();
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, ["secret"]);
        assert!(d.context.iter().any(|c| c.contains("cat")));
    }

    #[test]
    fn per_kind_defaults_apply_with_synthetic_ids() {
        let p = policy("version: 1\ndefaults: { '*': allow, net: deny }\n");
        let d = evaluate(&p, &ctx(), &shell("curl https://example.org")).unwrap();
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, ["default.net"]);
        let d = evaluate(&p, &ctx(), &shell("ls")).unwrap();
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.rules, ["default"]);
    }

    #[test]
    fn negated_allow_patterns_fall_through_to_default() {
        let p = policy(
            "version: 1\ndefaults: ask\nallow:\n  - id: proj\n    \
             fs.write: ['${project}/**', '!${project}/.git/**']\n",
        );
        let write = |path: &str| Action::FsWrite {
            path: path.to_owned(),
        };
        assert_eq!(
            evaluate(&p, &ctx(), &write("/p/src/a.rs")).unwrap().verdict,
            Verdict::Allow
        );
        assert_eq!(
            evaluate(&p, &ctx(), &write("/p/.git/HEAD"))
                .unwrap()
                .verdict,
            Verdict::Ask
        );
    }

    #[test]
    fn unparseable_is_never_allowed() {
        let p = policy("version: 1\ndefaults: allow\n");
        let d = evaluate(&p, &ctx(), &shell("echo 'unterminated")).unwrap();
        assert_eq!(d.verdict, Verdict::Ask);
        assert_eq!(d.rules, ["unparseable"]);
        let d = evaluate(
            &p,
            &ctx(),
            &Action::Net {
                url: "https://".into(),
            },
        )
        .unwrap();
        assert_eq!(d.verdict, Verdict::Ask);
    }

    #[test]
    fn compiled_policy_is_reusable() {
        let p = policy("version: 1\ndefaults: ask\nallow:\n  - id: ls\n    shell: ['ls*']\n");
        let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
        for _ in 0..3 {
            assert_eq!(compiled.decide(&shell("ls -la")).verdict, Verdict::Allow);
        }
    }
}
