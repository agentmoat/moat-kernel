//! `moat init`: create the state directory, default policy, audit log and host hooks.

use std::io::Write as _;
use std::path::{Path, PathBuf};

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
    // Asked before anything is written, so declining everything changes nothing
    // but OpenMoat's own state directory.
    let hosts = choose_hosts(args, &mut out)?;

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
        if !hosts.is_empty() {
            let mut backups = Vec::new();
            for host in &hosts {
                for file in host_files(*host)? {
                    backups.extend(crate::install::backups(&file));
                }
            }
            let backups: Vec<String> = backups.iter().map(|p| p.display().to_string()).collect();
            if backups.is_empty() {
                writeln!(
                    out,
                    "· backups          none: the agents had no files to back up"
                )?;
            } else {
                writeln!(out, "✔ backups          {}", backups.join(", "))?;
            }
            writeln!(out, "Undo anytime: moat uninstall")?;
        }
        writeln!(out, "done. run `moat status` any time to verify.")?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// The hosts to set up: `--hosts` as given; else every host found, each confirmed
/// at the terminal (all of them with `--yes` or `--dry-run`, none without a
/// terminal, so a script never changes an agent's files unasked).
fn choose_hosts(args: &InitArgs, out: &mut Deferred) -> Result<Vec<Host>> {
    if let Some(explicit) = &args.hosts {
        return Ok(explicit.clone());
    }
    let found: Vec<HostConfig> = Host::ALL
        .into_iter()
        .filter_map(|h| HostConfig::for_host(h).ok())
        .filter(HostConfig::host_present)
        .collect();
    let names: Vec<&str> = found.iter().map(|c| c.host.display_name()).collect();
    if found.is_empty() {
        writeln!(
            out,
            "· agents           none found; pass --hosts to set one up"
        )?;
        return Ok(Vec::new());
    }
    if args.yes || args.dry_run {
        return Ok(found.iter().map(|c| c.host).collect());
    }
    if !crate::terminal::interactive() {
        writeln!(
            out,
            "· agents           found {}; none changed without a terminal: run `moat init` \
             in a terminal to choose, or `moat init --yes` to set up all of them",
            names.join(", ")
        )?;
        return Ok(Vec::new());
    }
    writeln!(out, "Found these agents:")?;
    for config in &found {
        let files: Vec<String> = host_files(config.host)?
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        writeln!(
            out,
            "  {:<12} {} (changes {})",
            config.host.display_name(),
            config_dir(config).display(),
            files.join(", ")
        )?;
    }
    writeln!(
        out,
        "OpenMoat adds its hook and sandbox settings to each agent you accept, backing \
         up every file first; `moat uninstall` undoes it."
    )?;
    let mut chosen = Vec::new();
    for config in &found {
        write!(
            out,
            "Protect {} ({})? [Y/n] ",
            config.host.display_name(),
            config_dir(config).display()
        )?;
        out.flush()?;
        let mut answer = String::new();
        // End of input is a no: nothing is changed that a person did not accept.
        if std::io::stdin().read_line(&mut answer)? == 0 {
            writeln!(out)?;
            continue;
        }
        if matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "" | "y" | "yes"
        ) {
            chosen.push(config.host);
        }
    }
    if chosen.is_empty() {
        writeln!(
            out,
            "· agents           none accepted; no agent's files were changed"
        )?;
    }
    Ok(chosen)
}

fn config_dir(config: &HostConfig) -> &Path {
    config
        .settings_path
        .parent()
        .unwrap_or(&config.settings_path)
}

/// Every file `init` may change for `host`: its hook file, and its sandbox
/// settings when they live elsewhere (Codex `config.toml`).
fn host_files(host: Host) -> Result<Vec<PathBuf>> {
    let mut files = vec![HostConfig::for_host(host)?.settings_path];
    if sandbox::install::HOSTS.contains(&host) {
        let settings = sandbox::install::settings_path(host)?;
        if !files.contains(&settings) {
            files.push(settings);
        }
    }
    Ok(files)
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
