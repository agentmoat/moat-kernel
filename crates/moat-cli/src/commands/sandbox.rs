//! `moat sandbox show` and `moat sandbox sync`: the host sandbox settings the policy compiles to.

use std::io::{self, Write as _};
use std::path::PathBuf;

use anyhow::{Result, bail};
use moat_hosts::Host;
use serde_json::{Value, json};
use toml_edit::DocumentMut;

use crate::cli::{Format, SandboxShowArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::install::HostConfig;
use crate::integrity::{self, HookPins};
use crate::render::{self, Deferred};
use crate::sandbox::{
    Grants, Plan, Report, claude, codex, codex_config_path, install, landlock_rules,
    seatbelt_profile,
};

/// One host's generated settings, ready to print.
struct Shown<'a> {
    host: Host,
    path: PathBuf,
    /// What moat owns in the file, in the file's own format.
    text: String,
    report: &'a Report,
}

pub fn show(args: &SandboxShowArgs) -> Result<Code> {
    let policy = Home::locate()?.load_policy()?;
    let plan = Plan::new(&policy)?;
    let ctx = crate::context::eval_context(None, None)?;
    let seatbelt = seatbelt_profile(&policy, &ctx, Grants::default())?;
    let landlock = landlock_rules(&policy, &ctx, Grants::default())?;
    // `moat run` in this directory, before it adds the agent, `--write` paths
    // and its proxy's port.
    let landlock_text = serde_json::to_string_pretty(&landlock.rules)?;
    let lightweight = [
        ("Seatbelt (macOS)", &seatbelt.profile, &seatbelt.report),
        ("Landlock (Linux)", &landlock_text, &landlock.report),
    ];
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
        render::json(&json!({
            "default_read_roots": plan.default_read_roots,
            "hosts": doc,
            "lightweight": {
                "seatbelt": { "profile": &seatbelt.profile, "report": &seatbelt.report },
                "landlock": { "rules": &landlock.rules, "report": &landlock.report },
            },
        }))?;
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
    for (title, text, report) in lightweight {
        writeln!(
            out,
            "{title}  `moat run` in this directory (Lightweight tier)"
        )?;
        writeln!(out, "{}", text.trim_end())?;
        write_report(&mut out, report)?;
    }
    writeln!(out, "dry run: nothing was written")?;
    Ok(Code::Ok)
}

/// `moat sandbox sync`: write every present host's sandbox settings from the
/// current policy and re-pin them. A re-pin accepts what it pins, so like
/// `moat allow` it refuses over a drifted lock (#163) and without a person.
pub fn sync() -> Result<Code> {
    if !crate::terminal::interactive() {
        bail!(
            "`moat sandbox sync` must be run by a person in a terminal, not from a hook or script"
        );
    }
    let home = Home::locate()?;
    if let Some(deny) = integrity::violation(&home)? {
        bail!(
            "refusing to sync while the policy lock shows drift ({}):\n  {}",
            integrity::INTEGRITY_RULE,
            deny.reasons.join("\n  ")
        );
    }
    let plan = Plan::new(&home.load_policy()?)?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();
    let (mut files, mut codex_configs) = (Vec::new(), Vec::new());
    for host in install::HOSTS {
        let path = install::settings_path(host)?;
        if !path.parent().is_some_and(std::path::Path::is_dir) {
            writeln!(out, "· {:<16} host not found", host.display_name())?;
            continue;
        }
        let verb = if install::write(host, &plan, false)? {
            "updated"
        } else {
            "unchanged"
        };
        writeln!(
            out,
            "✔ {:<16} {} (sandbox {verb})",
            host.display_name(),
            path.display()
        )?;
        write_report(&mut out, install::report(host, &plan))?;
        match host {
            Host::Codex => codex_configs.push(path),
            _ => files.push(path),
        }
    }
    let lock = integrity::repin_with(&home, &binary, HookPins::Keep, &files, &codex_configs)?;
    writeln!(
        out,
        "✔ lock             {} files and {} Codex profile(s) pinned",
        lock.entries.len(),
        lock.codex_profiles.len()
    )?;
    out.finish()?;
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
pub(super) fn write_report(out: &mut impl io::Write, report: &Report) -> io::Result<()> {
    for loss in &report.losses {
        writeln!(out, "  stricter: {loss}")?;
    }
    for allowance in &report.allowances {
        writeln!(out, "  wider:    {allowance}")?;
    }
    Ok(())
}
