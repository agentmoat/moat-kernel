//! Command dispatch.

mod allow;
mod doctor;
mod guard;
mod init;
mod policy;
mod replay;
mod report;
mod sandbox;
mod show;
mod status;

use anyhow::Result;

use crate::cli::{Cli, Command, PolicyCommand, SandboxCommand};
use crate::exit::Code;

pub fn run(cli: Cli) -> Result<Code> {
    match cli.command {
        Command::Init(args) => init::run(&args),
        Command::Guard(args) => Ok(guard::run(&args)),
        Command::Show(args) => show::run(&args),
        Command::Status => status::run(),
        Command::Doctor(args) => doctor::run(&args),
        Command::Allow(args) => allow::run(&args),
        Command::Replay(args) => replay::run(&args),
        Command::Report(args) => report::run(&args),
        Command::Policy { command } => match command {
            PolicyCommand::Lint(args) => policy::lint(&args),
            PolicyCommand::Check(args) => policy::check(&args),
            PolicyCommand::Compile(args) => policy::compile(&args),
        },
        Command::Sandbox { command } => match command {
            SandboxCommand::Show(args) => sandbox::show(&args),
        },
    }
}
