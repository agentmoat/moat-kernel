//! `moat init`: create the state directory, default policy, audit log and host hooks.

use std::io::Write as _;

use anyhow::Result;
use openmoat_audit::Store;
use openmoat_core::{DEFAULT_POLICY, Policy};
use openmoat_hosts::Host;

use crate::cli::InitArgs;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HostConfig, Outcome};
use crate::integrity;
use crate::render::Deferred;
use crate::sandbox::{self, Plan};

pub fn run(args: &InitArgs) -> Result<Code> {
    let dry_run = args.dry_run;
    let prefix = if dry_run { "would" } else { "✔" };
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    let mut out = Deferred::default();

    if !dry_run {
        home.ensure()?;
    }
    writeln!(out, "{prefix} state directory  {}", home.root().display())?;

    let policy_path = home.policy_path();
    let wrote_policy = if dry_run {
        !policy_path.exists()
    } else {
        home.ensure_policy()?
    };
    if wrote_policy {
        writeln!(
            out,
            "{prefix} policy           {} (defaults v1)",
            policy_path.display()
        )?;
    } else {
        writeln!(out, "✔ policy           {} (kept)", policy_path.display())?;
    }

    if !dry_run {
        Store::open(&home.audit_path())?;
    }
    writeln!(
        out,
        "{prefix} audit log        {}",
        home.audit_path().display()
    )?;

    let hosts = match &args.hosts {
        Some(explicit) => explicit.clone(),
        None => Host::ALL
            .into_iter()
            .filter(|h| HostConfig::for_host(*h).is_ok_and(|c| c.host_present()))
            .collect(),
    };
    if hosts.is_empty() {
        writeln!(
            out,
            "· hooks            no supported host found; pass --hosts to force"
        )?;
    }
    if dry_run {
        writeln!(
            out,
            "would environment      {}",
            home.environment_path().display()
        )?;
    } else {
        let snapshot = Snapshot::capture();
        snapshot.save(&home.environment_path())?;
        writeln!(
            out,
            "✔ environment      {} ({} dirs, {} programs pinned)",
            home.environment_path().display(),
            snapshot.path.len(),
            snapshot.programs.len()
        )?;
    }

    if !dry_run {
        home.ensure_approval_files()?;
    }
    for host in hosts.iter().copied() {
        let config = HostConfig::for_host(host)?;
        let outcome = config.install(&binary, dry_run)?;
        let verb = match outcome {
            Outcome::Installed => "installed",
            Outcome::Updated => "updated",
            Outcome::Unchanged => "unchanged",
        };
        let events: Vec<&str> = config.hooks.iter().map(|spec| spec.event).collect();
        writeln!(
            out,
            "{prefix} {:<16} {} ({verb}: {} → {} guard --host {})",
            host.display_name(),
            config.settings_path.display(),
            events.join(", "),
            binary.display(),
            host.id()
        )?;
    }

    sandboxes(&home, &hosts, dry_run, &mut out)?;

    if dry_run {
        writeln!(out, "would lock             {}", home.lock_path().display())?;
    } else {
        let lock = integrity::repin(&home, &binary, integrity::HookPins::Adopt)?;
        writeln!(
            out,
            "✔ lock             {} ({} files pinned)",
            home.lock_path().display(),
            lock.entries.len()
        )?;
    }

    if dry_run {
        writeln!(out, "dry run: nothing was written")?;
    } else {
        writeln!(out, "done. run `moat status` any time to verify.")?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Standard tier (ADR-018): each selected host's own sandbox, configured from
/// the policy. A policy that does not lint is reported, not fatal, so `init`
/// can still repair hooks; `moat sandbox sync` writes the sandboxes later.
fn sandboxes(home: &Home, hosts: &[Host], dry_run: bool, out: &mut Deferred) -> Result<()> {
    let prefix = if dry_run { "would" } else { "✔" };
    let selected: Vec<Host> = sandbox::install::HOSTS
        .into_iter()
        .filter(|h| hosts.contains(h))
        .collect();
    if selected.is_empty() {
        return Ok(());
    }
    let policy = if home.policy_path().exists() {
        home.load_policy()
    } else {
        Ok(Policy::parse(DEFAULT_POLICY)?)
    };
    let plan = match policy.and_then(|p| Plan::new(&p)) {
        Ok(plan) => plan,
        Err(e) => {
            writeln!(out, "✗ sandbox          not written: {e:#}")?;
            return Ok(());
        }
    };
    for host in selected {
        let verb = if sandbox::install::write(host, &plan, dry_run)? {
            "updated"
        } else {
            "unchanged"
        };
        let report = sandbox::install::report(host, &plan);
        writeln!(
            out,
            "{prefix} {:<16} {} (sandbox {verb}; {} stricter, {} wider than the policy: `moat sandbox show`)",
            host.display_name(),
            sandbox::install::settings_path(host)?.display(),
            report.losses.len(),
            report.allowances.len()
        )?;
    }
    Ok(())
}
