//! Evaluating the IR on atomic actions: the reference semantics every OS
//! backend must reproduce, and what the consistency tests compare with the engine.

use super::{Access, Effect, Enforcement};
use crate::action::AtomicAction;
use crate::kind::Kind;
use crate::pattern::{GlobPattern, any_match};
use crate::policy::PolicyError;

/// An [`Enforcement`] with its globs compiled.
#[derive(Debug)]
pub struct Checker {
    read: CompiledAccess,
    write: CompiledAccess,
    net: CompiledAccess,
    fetch: CompiledAccess,
}

#[derive(Debug)]
struct CompiledAccess {
    default: Effect,
    deny: Vec<Vec<GlobPattern>>,
    allow: Vec<Vec<GlobPattern>>,
}

impl Enforcement {
    /// Compile the IR's globs for [`Checker::check`].
    pub fn checker(&self) -> Result<Checker, PolicyError> {
        let paths = self.fs.case_insensitive;
        Ok(Checker {
            read: CompiledAccess::compile(&self.fs.read, paths)?,
            write: CompiledAccess::compile(&self.fs.write, paths)?,
            net: CompiledAccess::compile(&self.egress.net, true)?,
            fetch: CompiledAccess::compile(&self.egress.fetch, true)?,
        })
    }
}

impl Checker {
    /// What an OS layer does with `atom`: `None` for a decide-only kind.
    #[must_use]
    pub fn check(&self, atom: &AtomicAction) -> Option<Effect> {
        let access = match atom.kind() {
            Kind::FsRead => &self.read,
            Kind::FsWrite => &self.write,
            Kind::Net => &self.net,
            Kind::Fetch => &self.fetch,
            Kind::Shell | Kind::EnvRead | Kind::EnvSet | Kind::Mcp => return None,
        };
        Some(access.effect(atom.subject()?))
    }
}

impl CompiledAccess {
    fn compile(access: &Access, case_insensitive: bool) -> Result<Self, PolicyError> {
        let compile = |rules: &[super::Rule]| {
            rules
                .iter()
                .map(|rule| {
                    rule.patterns
                        .iter()
                        .map(|p| GlobPattern::compile(p, case_insensitive))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            default: access.default,
            deny: compile(&access.deny)?,
            allow: compile(&access.allow)?,
        })
    }

    fn effect(&self, subject: &str) -> Effect {
        let hit = |rules: &[Vec<GlobPattern>]| rules.iter().any(|r| any_match(r, subject));
        if hit(&self.deny) {
            Effect::Deny
        } else if hit(&self.allow) {
            Effect::Allow
        } else {
            self.default
        }
    }
}
