//! `moat sandbox show`: the host sandbox settings the policy compiles to.

use std::io::{self, Write as _};

use anyhow::Result;
use moat_hosts::Host;
use serde_json::{Value, json};

use crate::cli::{Format, SandboxShowArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::install::HostConfig;
use crate::render;
use crate::sandbox::{Plan, Report, claude};

pub fn show(args: &SandboxShowArgs) -> Result<Code> {
    let plan = Plan::new(&Home::locate()?.load_policy()?)?;
    let hosts = [(
        Host::ClaudeCode,
        HostConfig::for_host(Host::ClaudeCode)?.settings_path,
        claude_settings(&plan.claude),
        &plan.claude.report,
    )];
    if args.format == Format::Json {
        let doc: serde_json::Map<String, Value> = hosts
            .iter()
            .map(|(host, path, settings, report)| {
                let entry = json!({ "path": path, "settings": settings, "report": report });
                (host.id().to_owned(), entry)
            })
            .collect();
        render::json(&json!({ "default_read_roots": plan.default_read_roots, "hosts": doc }))?;
        return Ok(Code::Ok);
    }
    let mut out = io::stdout().lock();
    if plan.default_read_roots {
        writeln!(
            out,
            "note: the policy has no `sandbox.read_roots`; the default policy's list applies"
        )?;
    }
    for (host, path, settings, report) in hosts {
        writeln!(out, "{}  {}", host.display_name(), path.display())?;
        writeln!(out, "{}", serde_json::to_string_pretty(&settings)?)?;
        write_report(&mut out, report)?;
    }
    writeln!(out, "dry run: nothing was written")?;
    Ok(Code::Ok)
}

/// The part of Claude Code's settings moat owns, as it would appear in the file.
fn claude_settings(generated: &claude::Generated) -> Value {
    let mut settings = json!({ "sandbox": generated.sandbox });
    if generated.block_reads {
        settings["permissions"] = json!({ claude::BLOCK_READS: true });
    }
    settings
}

/// Losses and allowances, as `sandbox show`, `sandbox sync` and `doctor` print them.
pub fn write_report(out: &mut impl io::Write, report: &Report) -> io::Result<()> {
    for loss in &report.losses {
        writeln!(out, "  stricter: {loss}")?;
    }
    for allowance in &report.allowances {
        writeln!(out, "  wider:    {allowance}")?;
    }
    Ok(())
}
