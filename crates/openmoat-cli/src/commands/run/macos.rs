//! `moat run` on macOS: the agent under `sandbox-exec` with the Seatbelt
//! profile generated for the session (`crate::sandbox::seatbelt`).

use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Result, bail};
use openmoat_core::{EvalContext, Policy};

use crate::cli::IsolatedArgs;
use crate::exit::Code;
use crate::sandbox::{Grants, Report, seatbelt_profile};

/// Part of the base system; never one found on `PATH`. Apple has deprecated
/// it, but Codex, Claude Code and Chromium still start their sandboxes with it.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The agent, ready to start in its sandbox.
pub struct Confined {
    command: Command,
    report: Report,
}

pub fn confine(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
    program: &Path,
) -> Result<Confined> {
    let generated = seatbelt_profile(policy, ctx, grants)?;
    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-p").arg(&generated.profile).arg(program);
    Ok(Confined {
        command,
        report: generated.report,
    })
}

/// The Isolated tier needs a Linux guest here: a virtual machine (#175).
pub fn isolate(_: &Policy, _: &EvalContext, _: Grants, _: &Path) -> Result<Confined> {
    bail!(
        "`moat run --isolate` runs on Linux only for now; on macOS the Isolated tier needs a \
         virtual machine (#175). `moat run` without --isolate is the Lightweight tier"
    )
}

pub fn inside(_: &IsolatedArgs) -> Result<Code> {
    bail!("only `moat run --isolate` on Linux starts this")
}

impl Confined {
    pub fn command(&mut self) -> &mut Command {
        &mut self.command
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    pub fn status(mut self) -> Result<ExitStatus> {
        Ok(self.command.status()?)
    }
}
