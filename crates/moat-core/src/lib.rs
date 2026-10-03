//! `moat-core`: the trusted decision core of agentmoat.
//!
//! This crate is **pure**: it performs no I/O and makes no OS calls. Callers
//! (the CLI, host adapters) read files, resolve the environment and pass
//! everything in. That keeps the security-relevant logic small, testable and
//! portable (it also builds for `wasm32`).
//!
//! Pipeline (DESIGN.md §7.1): `Action` → [`shell::classify`] → atomic actions →
//! [`engine::evaluate`] → [`verdict::Decision`].

pub mod action;
pub mod engine;
pub mod lexer;
pub mod paths;
pub mod pattern;
pub mod policy;
pub mod shell;
pub mod verdict;

pub use action::{Action, AtomicAction};
pub use engine::{CompiledPolicy, EvalContext, evaluate};
pub use policy::{Defaults, Policy, PolicyError, RuleGroup};
pub use verdict::{Decision, Verdict};
