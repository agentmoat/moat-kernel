//! End-to-end tests of the `moat` binary, one test target for all of them.
//!
//! Every test runs the real binary in an isolated home (`HOME`, `USERPROFILE`
//! and the process environment cleared), never the developer's own `~`, and
//! never the network.

mod common;

mod allow;
mod approvals;
mod cli;
mod config_change;
mod cursor;
mod guard;
#[cfg(unix)]
mod install_path;
mod lock;
mod paths;
mod replay_report;
