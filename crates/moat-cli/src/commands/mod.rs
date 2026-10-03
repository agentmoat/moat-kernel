//! Command dispatch.

mod guard;
mod init;
mod policy;
mod show;
mod status;

use anyhow::Result;

use crate::cli::{Cli, Command, PolicyCommand};
use crate::exit::Code;

pub fn run(cli: Cli) -> Result<Code> {
    match cli.command {
        Command::Init(args) => init::run(&args),
        Command::Guard(args) => Ok(guard::run(&args)),
        Command::Show(args) => show::run(&args),
        Command::Status => status::run(),
        Command::Policy { command } => match command {
            PolicyCommand::Lint(args) => policy::lint(&args),
            PolicyCommand::Check(args) => policy::check(&args),
        },
    }
}
