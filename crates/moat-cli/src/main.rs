//! `moat`: command-line entry point for agentmoat.
//!
//! The binary owns all I/O (files, environment, terminal); decisions are made
//! by `moat-core`. Exit codes are a stable contract used by host hooks:
//! see [`exit::Code`].

mod cli;
mod commands;
mod context;
mod environment;
mod exit;
mod home;
mod install;
mod integrity;
mod project;
mod render;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    // clap exits with 2 on usage errors, which hosts would read as `deny`.
    // Parse explicitly so usage errors use the dedicated code instead.
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = !error.use_stderr();
            let _ = error.print();
            return if informational {
                exit::Code::Ok
            } else {
                exit::Code::Usage
            }
            .into();
        }
    };
    match commands::run(cli) {
        Ok(code) => code.into(),
        Err(error) => {
            eprintln!("moat: {error:#}");
            exit::Code::Usage.into()
        }
    }
}
