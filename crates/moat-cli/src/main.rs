//! `moat`: command-line entry point for agentmoat.
//!
//! The binary owns all I/O (files, environment, terminal); decisions are made
//! by `moat-core`. Exit codes are a stable contract used by host hooks:
//! see [`exit::Code`].

mod approvals;
mod cli;
mod commands;
mod context;
mod environment;
mod exit;
mod home;
mod install;
mod integrity;
mod project;
mod realpath;
mod render;
mod terminal;
mod time;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    // A host runs `moat guard` and blocks the tool call only on exit 2; any other
    // failure lets the call through. So a `guard` that cannot even parse its
    // arguments denies (ADR-015), and every other command reports usage errors
    // with the dedicated code, never 2.
    let failed = if invoked_as_hook() {
        exit::Code::Deny
    } else {
        exit::Code::Usage
    };
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = !error.use_stderr();
            let _ = error.print();
            return if informational {
                exit::Code::Ok
            } else {
                failed
            }
            .into();
        }
    };
    match commands::run(cli) {
        Ok(code) => code.into(),
        Err(error) => {
            eprintln!("moat: {error:#}");
            failed.into()
        }
    }
}

/// True when the first argument is `guard`, the subcommand host hooks run.
fn invoked_as_hook() -> bool {
    std::env::args_os().nth(1).is_some_and(|arg| arg == "guard")
}
