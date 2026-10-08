//! Session taint (ADR-020): what earlier calls of a session brought into it,
//! and how that tightens later decisions.
//!
//! The caller keeps the session's history (the CLI reads it from the audit
//! log) and folds [`CompiledPolicy::exposure`] over the calls that ran. The
//! resulting [`Taint`] then goes into [`CompiledPolicy::with_taint`], which can
//! only turn an outcome stricter.

use super::{CompiledPolicy, EvalContext, classify_action, with_resolved_paths};
use crate::action::{Action, AtomicAction};
use crate::pattern::{GlobPattern, any_match};
use crate::policy::{Policy, PolicyError};
use crate::realpath::PathResolver;
use crate::verdict::{Decision, Verdict};

/// The rule group whose `fs.read` patterns name secret material, wherever the
/// policy puts it. In the default policy it denies, so only a policy that asks
/// for these reads lets one run and taint the session.
const SECRET_RULE: &str = "secrets-paths";

/// The rule id a tightened decision carries.
const TAINT_RULE: &str = "session-taint";

/// Where secret material in a session came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// What brought it in, for reasons (`read /Users/me/.ssh/id_rsa`).
    pub source: String,
    /// The one host the secret belongs to and may still go to. `None` for a
    /// file read: it belongs to no host, so every host asks. This is the
    /// extension point for the secrets broker (#172): a brokered secret that
    /// was used is a `Secret` with its own host.
    pub host: Option<String>,
}

/// What earlier calls of one session exposed it to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Taint {
    /// Secret material the session read, de-duplicated by source.
    pub secrets: Vec<Secret>,
    /// The first untrusted content the session read (`fetch docs.rs`), if any.
    pub untrusted: Option<String>,
}

impl Taint {
    /// Add what another call exposed the session to.
    pub fn absorb(&mut self, other: Taint) {
        for secret in other.secrets {
            if !self.secrets.contains(&secret) {
                self.secrets.push(secret);
            }
        }
        if self.untrusted.is_none() {
            self.untrusted = other.untrusted;
        }
    }
}

/// The built-in protected paths and the ones `policy` adds, compiled for `ctx`.
pub(super) fn compile_protected(
    policy: &Policy,
    ctx: &EvalContext,
) -> Result<Vec<GlobPattern>, PolicyError> {
    crate::taint::protected_writes(policy.taint.as_ref())
        .flat_map(|p| ctx.spellings(p))
        .map(|p| GlobPattern::compile(&p, ctx.case_insensitive_paths))
        .collect()
}

impl CompiledPolicy<'_> {
    /// What running `action` in `cwd` exposed its session to: secret material
    /// from a read the `secrets-paths` group names, untrusted content from a
    /// fetch or an MCP result. The caller passes only calls that ran; the parts
    /// of an action that cannot be classified expose nothing they can name.
    #[must_use]
    pub fn exposure(&self, action: &Action, cwd: &str, paths: &dyn PathResolver) -> Taint {
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (atoms, _) = classify_action(action, &ctx).into_parts();
        let mut taint = Taint::default();
        for atom in with_resolved_paths(atoms, paths) {
            match atom {
                AtomicAction::FsRead { .. } if self.names_secret(&atom) => {
                    taint.absorb(Taint {
                        secrets: vec![Secret {
                            source: atom.describe(),
                            host: None,
                        }],
                        untrusted: None,
                    });
                }
                AtomicAction::Fetch { .. } | AtomicAction::McpTool { .. } => {
                    taint.untrusted.get_or_insert_with(|| atom.describe());
                }
                _ => {}
            }
        }
        taint
    }

    /// `decision` for `action`, tightened by `taint`: after secret material,
    /// network to any host but the secret's own, and every MCP call (its
    /// server's hosts are unknown), asks; after untrusted content, a write to
    /// a protected path asks. Merging keeps the strictest verdict, so this
    /// never loosens a decision.
    #[must_use]
    pub fn with_taint(
        &self,
        decision: Decision,
        action: &Action,
        paths: &dyn PathResolver,
        taint: &Taint,
    ) -> Decision {
        self.atoms(action, paths)
            .0
            .iter()
            .filter_map(|atom| self.tainted(atom, taint))
            .fold(decision, |mut acc, next| {
                acc.merge(next);
                acc
            })
    }

    fn tainted(&self, atom: &AtomicAction, taint: &Taint) -> Option<Decision> {
        let reason = match atom {
            AtomicAction::Net { host } | AtomicAction::Fetch { host } => {
                let secret = taint.secrets.iter().find(|s| {
                    !s.host
                        .as_deref()
                        .is_some_and(|own| own.eq_ignore_ascii_case(host))
                })?;
                secret_reason(secret, atom)
            }
            AtomicAction::McpTool { .. } => secret_reason(taint.secrets.first()?, atom),
            AtomicAction::FsWrite { path } if any_match(&self.protected, path.as_str()) => {
                format!(
                    "the session read untrusted content ({}); {} changes what runs or what the agent is told later",
                    taint.untrusted.as_ref()?,
                    atom.describe()
                )
            }
            _ => return None,
        };
        Some(Decision::single(Verdict::Ask, TAINT_RULE, reason))
    }

    fn names_secret(&self, atom: &AtomicAction) -> bool {
        [&self.deny, &self.allow, &self.ask]
            .into_iter()
            .flatten()
            .any(|g| g.group.id == SECRET_RULE && g.matches(atom))
    }
}

fn secret_reason(secret: &Secret, atom: &AtomicAction) -> String {
    format!(
        "the session read secret material ({}); {} could carry it out",
        secret.source,
        atom.describe()
    )
}
