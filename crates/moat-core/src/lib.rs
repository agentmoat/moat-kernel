//! `moat-core`: the trusted decision core of agentmoat.
//!
//! This crate is **pure**: it performs no I/O and makes no OS calls. Callers
//! (the CLI, host adapters) read files, resolve the environment and pass
//! everything in. That keeps the security-relevant logic small, testable and
//! portable (it also builds for `wasm32`).
//!
//! Pipeline: an [`Action`] is classified into [`AtomicAction`]s, each atomic
//! action is evaluated `deny → allow → ask → defaults` by a [`CompiledPolicy`],
//! and the strictest verdict across them becomes the [`Decision`]. Facts that
//! need the filesystem reach the engine through [`ProgramResolver`] and
//! [`PathResolver`].

#![warn(missing_docs)]

mod action;
mod engine;
mod host;
mod kind;
mod lexer;
pub mod lint;
mod paths;
mod pattern;
mod policy;
mod programs;
mod realpath;
mod shell;
mod verdict;

pub use action::{Action, AtomicAction};
pub use engine::{CompiledPolicy, EvalContext, evaluate};
pub use kind::{Kind, UnknownKind};
pub use pattern::literal_shell_pattern;
pub use policy::{Defaults, Policy, PolicyError, RuleGroup};
pub use programs::{MapResolver, NoResolver, ProgramResolver};
pub use realpath::{MapPathResolver, PathResolver};
pub use verdict::{Decision, UnknownVerdict, Verdict};

/// The shipped default policy, as YAML: what `moat init` installs and what the
/// conformance suite pins. Parse it with [`Policy::parse`].
pub const DEFAULT_POLICY: &str = include_str!("../policies/default-v1.yaml");
