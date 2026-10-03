//! `moat init`: create the state directory, default policy, audit log and host hooks.

use anyhow::{Context as _, Result};
use moat_audit::Store;
use moat_hosts::Host;

use crate::cli::InitArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HostConfig, Outcome};

pub fn run(args: &InitArgs) -> Result<Code> {
    let dry_run = args.dry_run;
    let prefix = if dry_run { "would" } else { "✔" };
    let home = Home::locate()?;
    let binary = std::env::current_exe().context("locating the moat binary")?;

    if !dry_run {
        home.ensure()?;
    }
    println!("{prefix} state directory  {}", home.root().display());

    let policy_path = home.policy_path();
    let wrote_policy = if dry_run {
        !policy_path.exists()
    } else {
        home.ensure_policy()?
    };
    if wrote_policy {
        println!(
            "{prefix} policy           {} (defaults v1)",
            policy_path.display()
        );
    } else {
        println!("✔ policy           {} (kept)", policy_path.display());
    }

    if !dry_run {
        Store::open(&home.audit_path())?;
    }
    println!("{prefix} audit log        {}", home.audit_path().display());

    let hosts = match &args.hosts {
        Some(explicit) => explicit.clone(),
        None => Host::ALL
            .into_iter()
            .filter(|h| HostConfig::for_host(*h).is_ok_and(|c| c.host_present()))
            .collect(),
    };
    if hosts.is_empty() {
        println!("· hooks            no supported host found; pass --hosts to force");
    }
    for host in hosts {
        let config = HostConfig::for_host(host)?;
        let outcome = config.install(&binary, dry_run)?;
        let verb = match outcome {
            Outcome::Installed => "installed",
            Outcome::Updated => "updated",
            Outcome::Unchanged => "unchanged",
        };
        println!(
            "{prefix} {:<16} {} ({verb}: PreToolUse → {} guard --host {})",
            host.display_name(),
            config.settings_path.display(),
            binary.display(),
            host.id()
        );
    }

    if dry_run {
        println!("dry run: nothing was written");
    } else {
        println!("done. run `moat status` any time to verify.");
    }
    Ok(Code::Ok)
}
