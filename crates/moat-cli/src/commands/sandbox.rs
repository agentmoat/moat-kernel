//! `moat sandbox show`: the host sandbox settings the policy compiles to.

use std::io::{self, Write as _};
use std::path::PathBuf;

use anyhow::Result;
use moat_hosts::Host;
use serde_json::{Value, json};
use toml_edit::DocumentMut;

use crate::cli::{Format, SandboxShowArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::install::HostConfig;
use crate::render;
use crate::sandbox::{Plan, Report, claude, codex, codex_config_path};

/// One host's generated settings, ready to print.
struct Shown<'a> {
    host: Host,
    path: PathBuf,
    /// What moat owns in the file, in the file's own format.
    text: String,
    report: &'a Report,
}

pub fn show(args: &SandboxShowArgs) -> Result<Code> {
    let plan = Plan::new(&Home::locate()?.load_policy()?)?;
    let mut codex_doc = DocumentMut::new();
    codex::apply(&mut codex_doc, &plan.codex)?;
    let hosts = [
        Shown {
            host: Host::ClaudeCode,
            path: HostConfig::for_host(Host::ClaudeCode)?.settings_path,
            text: serde_json::to_string_pretty(&claude_settings(&plan.claude))?,
            report: &plan.claude.report,
        },
        Shown {
            host: Host::Codex,
            path: codex_config_path()?,
            text: codex_doc.to_string(),
            report: &plan.codex.report,
        },
    ];
    if args.format == Format::Json {
        let doc: serde_json::Map<String, Value> = hosts
            .iter()
            .map(|s| {
                let entry = json!({ "path": s.path, "settings": s.text, "report": s.report });
                (s.host.id().to_owned(), entry)
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
    for shown in hosts {
        writeln!(
            out,
            "{}  {}",
            shown.host.display_name(),
            shown.path.display()
        )?;
        writeln!(out, "{}", shown.text.trim_end())?;
        write_report(&mut out, shown.report)?;
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
