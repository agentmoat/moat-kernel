//! `moat run` on macOS: the agent under `sandbox-exec` with the Seatbelt
//! profile generated for the session (`crate::sandbox::seatbelt`).

use std::process::Command;

use anyhow::Result;
use moat_core::{EvalContext, Policy};

use crate::sandbox::{Grants, Report, seatbelt_profile};

/// Part of the base system; never one found on `PATH`. Apple has deprecated
/// it, but Codex, Claude Code and Chromium still start their sandboxes with it.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// `sandbox-exec` with the profile, ready for the agent's command line, and
/// the profile's report.
pub fn confine(policy: &Policy, ctx: &EvalContext, grants: Grants) -> Result<(Command, Report)> {
    let generated = seatbelt_profile(policy, ctx, grants)?;
    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-p").arg(&generated.profile);
    Ok((command, generated.report))
}
