//! `moat run` on Linux: Landlock rules generated for the session
//! (`crate::sandbox::landlock`), applied to a thread of its own that starts the
//! agent. Landlock restricts the calling thread and what it starts, so moat's
//! proxy thread stays unrestricted and keeps its audit log and its network.

use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Context as _, Result};
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, Scope, path_beneath_rules,
};
use moat_core::{EvalContext, Policy};

use crate::sandbox::{Grants, Report, landlock_rules};

/// The first ABI that restricts TCP connections (Linux 6.7). An older kernel
/// is refused rather than run with the network open.
const ABI_REQUIRED: ABI = ABI::V4;

/// The agent, ready to start in its sandbox.
pub struct Confined {
    command: Command,
    report: Report,
    ruleset: RulesetCreated,
}

pub fn confine(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
    program: &Path,
) -> Result<Confined> {
    let generated = landlock_rules(policy, ctx, grants)?;
    let rules = &generated.rules;
    let ports = rules
        .connect_port
        .map(|port| Ok(NetPort::new(port, AccessNet::ConnectTcp)));
    let build = || -> Result<RulesetCreated, RulesetError> {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI_REQUIRED))?
            .handle_access(AccessNet::from_all(ABI_REQUIRED))?
            // Abstract Unix sockets and signals outside the sandbox (Linux
            // 6.12), where the kernel has them.
            .set_compatibility(CompatLevel::BestEffort)
            .scope(Scope::from_all(ABI::V6))?
            .create()?
            .add_rules(path_beneath_rules(
                &rules.read,
                AccessFs::from_read(ABI_REQUIRED),
            ))?
            .add_rules(path_beneath_rules(
                &rules.write,
                AccessFs::from_all(ABI_REQUIRED),
            ))?
            .add_rules(ports)
    };
    let ruleset = build().context("`moat run` needs Landlock ABI 4 (Linux 6.7 or later)")?;
    Ok(Confined {
        command: Command::new(program),
        report: generated.report,
        ruleset,
    })
}

impl Confined {
    pub fn command(&mut self) -> &mut Command {
        &mut self.command
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    pub fn status(self) -> Result<ExitStatus> {
        let Self {
            mut command,
            ruleset,
            ..
        } = self;
        std::thread::spawn(move || {
            ruleset
                .restrict_self()
                .context("applying the Landlock rules")?;
            command.status().context("starting the agent")
        })
        .join()
        .ok()
        .context("the thread that starts the agent panicked")?
    }
}
