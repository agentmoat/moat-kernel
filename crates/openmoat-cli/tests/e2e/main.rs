//! End-to-end tests of the `moat` binary, one test target for all of them.
//!
//! Every test runs the real binary in an isolated home (`HOME`, `USERPROFILE`
//! and the process environment cleared), never the developer's own `~`, and
//! never the network.

mod common;

mod allow;
mod approvals;
mod audit;
mod cli;
mod closed_pipe;
mod codex;
mod config_change;
mod continue_cli;
mod cursor;
mod differential;
mod export;
mod guard;
#[cfg(unix)]
mod install_path;
mod lock;
mod moatbench;
mod paths;
mod proxy;
mod replay_report;
mod repo_policy;
mod run;
mod sandbox;
#[cfg(unix)]
mod sandbox_exec;
mod sandbox_sync;
mod taint;
mod team;
mod trust;
