//! The decision engine (DESIGN.md §6.3, §7.1).
//!
//! Per atomic action: `deny → allow → ask → defaults`. Across the atomic
//! actions of one tool call: strictest verdict wins. Deny rules are absolute;
//! an allow rule can never override a deny, so "deny by default with holes"
//! is expressed through per-kind `defaults`, never through a deny rule.

use crate::action::{Action, AtomicAction};
use crate::pattern::{GlobPattern, ShellPattern, any_match, any_shell_match};
use crate::policy::{Policy, PolicyError, RuleGroup};
use crate::programs::{self, NoResolver, ProgramResolver};
use crate::realpath::PathResolver;
use crate::shell::{ParseOutcome, ShellContext, classify};
use crate::verdict::{Decision, Verdict};
use crate::{host, paths};

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
                any_shell_match(&self.shell, argv)
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
        Action::Patch { writes } if writes.is_empty() => ParseOutcome::Unparseable {
            reason: "patch names no files".to_owned(),
        },
        Action::Patch { writes } => ParseOutcome::Parsed(
            writes
                .iter()
                .map(|p| AtomicAction::FsWrite {
                    path: paths::normalise(p, &ctx.home, &ctx.project, &ctx.cwd),
                })
                .collect(),
        ),
        Action::Net { url } => match host::of_url(url) {
            Some(host) => ParseOutcome::Parsed(vec![AtomicAction::Net { host }]),
            None => ParseOutcome::Unparseable {
                reason: format!("no host in url `{url}`"),
            },
        },
        Action::McpTool {
            name,
            reads,
            writes,
            hosts,
        } => {
            let norm = |p: &String| paths::normalise(p, &ctx.home, &ctx.project, &ctx.cwd);
            let mut atoms = vec![AtomicAction::McpTool { name: name.clone() }];
            atoms.extend(reads.iter().map(|p| AtomicAction::FsRead { path: norm(p) }));
            atoms.extend(
                writes
                    .iter()
                    .map(|p| AtomicAction::FsWrite { path: norm(p) }),
            );
            for host in hosts {
                match host::of_url(host) {
                    Some(host) => atoms.push(AtomicAction::Net { host }),
                    None => {
                        return ParseOutcome::Unparseable {
                            reason: format!("no host in mcp argument `{host}`"),
                        };
                    }
                }
            }
            ParseOutcome::Parsed(atoms)
        }
    }
}

impl CompiledPolicy<'_> {
    /// Decide one host action without executable resolution.
    ///
    /// Unparseable input yields `ask` with the parser's reason, never `allow`.
    #[must_use]
    pub fn decide(&self, action: &Action) -> Decision {
        self.decide_with(action, &NoResolver, &NoResolver)
    }

    /// Decide one host action, resolving shell programs through `resolver` so
    /// that `executables` pins and installation pins are enforced, and paths
    /// through `paths` so a symlink cannot move a read or write past a rule.
    #[must_use]
    pub fn decide_with(
        &self,
        action: &Action,
        resolver: &dyn ProgramResolver,
        paths: &dyn PathResolver,
    ) -> Decision {
        let atoms = match classify_action(action, &self.ctx) {
            ParseOutcome::Parsed(atoms) => with_resolved_paths(atoms, paths),
            ParseOutcome::Unparseable { reason } => {
                return unparseable(format!("could not parse action safely: {reason}"));
            }
        };
        let pins = atoms.iter().filter_map(|atom| match atom {
            AtomicAction::Shell { argv } => {
                programs::check(&argv[0], &self.policy.executables, resolver)
            }
            _ => None,
        });
        atoms
            .iter()
            .filter_map(|atom| self.evaluate_atomic(atom))
            .chain(pins)
            .reduce(|mut acc, next| {
                acc.merge(next);
                acc
            })
            .unwrap_or_else(|| unparseable("action has no evaluable parts".to_owned()))
    }
}

/// Add an atom for the resolved path of every read and write that goes
/// through a symlink. The literal atom stays: a rule may name either location.
fn with_resolved_paths(atoms: Vec<AtomicAction>, paths: &dyn PathResolver) -> Vec<AtomicAction> {
    let resolved: Vec<AtomicAction> = atoms
        .iter()
        .filter_map(|atom| match atom {
            AtomicAction::FsRead { path } => paths
                .resolve(path)
                .filter(|real| real != path)
                .map(|path| AtomicAction::FsRead { path }),
            AtomicAction::FsWrite { path } => paths
                .resolve(path)
                .filter(|real| real != path)
                .map(|path| AtomicAction::FsWrite { path }),
            _ => None,
        })
        .collect();
    atoms.into_iter().chain(resolved).collect()
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
mod tests;
