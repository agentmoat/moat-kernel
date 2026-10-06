//! `moat status`: is the kernel installed, current and active?

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use anyhow::Result;
use openmoat_audit::Store;
use openmoat_hosts::Host;

use crate::approvals::{GRANT_TTL_MS, Grants};
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::integrity::{self, HookPinGap, Lock};
use crate::sandbox::{Plan, install as host_sandbox};
use crate::{render, time};

pub fn run() -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    let mut healthy = true;
    let mut out = io::stdout().lock();

    writeln!(out, "state directory  {}", home.root().display())?;

    let policy_path = home.policy_path();
    match home.load_policy() {
        Ok(policy) => {
            let bytes = fs::read(&policy_path)?;
            let digest = crate::integrity::sha256_hex(&bytes);
            let (deny, allow, ask) = policy.rule_count();
            writeln!(
                out,
                "policy           {}  sha256:{digest}  ({deny} deny, {allow} allow, {ask} ask)",
                policy_path.display()
            )?;
        }
        Err(error) => {
            healthy = false;
            writeln!(out, "policy           ✗ {error:#}")?;
        }
    }
    match crate::repo::summary(&home) {
        Ok(Some(line)) => writeln!(out, "repo policy      {line}")?,
        Ok(None) => {}
        Err(error) => {
            healthy = false;
            writeln!(
                out,
                "repo policy      ✗ {error:#}; every call in this project is denied"
            )?;
        }
    }

    let lock_path = home.lock_path();
    match Lock::load(&lock_path) {
        Ok(lock) => {
            let drift = lock.verify();
            if drift.is_empty() {
                writeln!(
                    out,
                    "lock             ✔ {} files pinned, intact",
                    lock.entries.len()
                )?;
            } else {
                healthy = false;
                for d in drift {
                    writeln!(out, "lock             ✗ {d} (run `moat doctor`)")?;
                }
            }
            let installed = integrity::installed_hook_files(&binary)?;
            let gap = HookPinGap::new(&lock, &home, &installed);
            for path in gap.unpinned {
                healthy = false;
                writeln!(
                    out,
                    "lock             ✗ {} is not pinned (run `moat init` to pin it)",
                    path.display()
                )?;
            }
            for path in gap.elsewhere {
                writeln!(
                    out,
                    "lock             · {} is pinned but not this shell's hook file (CLAUDE_CONFIG_DIR, CODEX_HOME or CURSOR_CONFIG_DIR differ)",
                    path.display()
                )?;
            }
        }
        Err(_) if !lock_path.exists() => {
            healthy = false;
            writeln!(out, "lock             ✗ missing (run `moat init`)")?;
        }
        Err(error) => {
            healthy = false;
            writeln!(out, "lock             ✗ {error:#}")?;
        }
    }

    match Grants::load(&home.grants_path()) {
        Ok(grants) => {
            let now = time::now_ms();
            let ages: Vec<i64> = grants.active(now).map(|g| now - g.granted_at_ms).collect();
            match ages.iter().max() {
                Some(oldest) => writeln!(
                    out,
                    "approvals        {} active session grant(s), oldest {} old (each expires after {})",
                    ages.len(),
                    time::duration(*oldest),
                    time::duration(GRANT_TTL_MS)
                )?,
                None => writeln!(out, "approvals        no active session grants")?,
            }
        }
        Err(error) => {
            healthy = false;
            writeln!(out, "approvals        ✗ {error:#}")?;
        }
    }

    for host in Host::ALL {
        let config = HostConfig::for_host(host)?;
        let line = match config.state(&binary) {
            HookState::Installed => "✔ installed".to_owned(),
            HookState::Missing if !config.host_present() => "· host not found".to_owned(),
            HookState::Missing => {
                healthy = false;
                "✗ hook missing (run `moat init`)".to_owned()
            }
            HookState::Stale { command } => {
                healthy = false;
                format!("✗ {}", crate::install::stale_hint(&command))
            }
            HookState::Unreadable(error) => {
                healthy = false;
                format!("✗ {error}")
            }
        };
        writeln!(
            out,
            "{:<16} {line}  {}",
            host.display_name(),
            config.settings_path.display()
        )?;
    }
    if let Some(found) = crate::install::continue_cli()? {
        writeln!(
            out,
            "{:<16} · {}  {}",
            Host::Continue.display_name(),
            crate::install::CONTINUE_CLI_WARNING,
            found.display()
        )?;
    }

    if let Ok(policy) = home.load_policy() {
        healthy &= sandboxes(&mut out, &Plan::new(&policy)?, &lock_path)?;
    }

    let audit_path = home.audit_path();
    if audit_path.is_file() {
        let store = Store::open_read_only(&audit_path)?;
        writeln!(
            out,
            "audit log        {}  ({} events)",
            audit_path.display(),
            store.count()?
        )?;
        let recent = store.recent(5)?;
        if !recent.is_empty() {
            writeln!(out)?;
            render::event_table(&recent)?;
        }
    } else {
        healthy = false;
        writeln!(out, "audit log        ✗ missing (run `moat init`)")?;
    }

    Ok(if healthy { Code::Ok } else { Code::Usage })
}

/// One line per present host's sandbox (Standard tier); `false` on any problem.
fn sandboxes(out: &mut impl io::Write, plan: &Plan, lock_path: &Path) -> Result<bool> {
    let lock = Lock::load(lock_path).ok();
    let mut healthy = true;
    let mut present = false;
    for host in host_sandbox::HOSTS {
        let name = host.display_name();
        let problems = host_sandbox::problems(host, plan, lock.as_ref());
        present |= !matches!(problems, Ok(None));
        match problems {
            Ok(None) => {}
            Ok(Some(problems)) if problems.is_empty() => {
                let report = host_sandbox::report(host, plan);
                writeln!(
                    out,
                    "{name:<16} ✔ sandbox matches the policy ({} stricter, {} wider: `moat sandbox show`)",
                    report.losses.len(),
                    report.allowances.len()
                )?;
            }
            Ok(Some(problems)) => {
                healthy = false;
                for problem in problems {
                    writeln!(out, "{name:<16} ✗ sandbox: {problem}")?;
                }
            }
            Err(error) => {
                healthy = false;
                writeln!(out, "{name:<16} ✗ sandbox: {error:#}")?;
            }
        }
    }
    if present {
        // A warning that leaves `healthy` alone: a stopped proxy fails closed.
        let (ok, text) = super::proxy::listening_line(plan.proxy_port);
        writeln!(
            out,
            "moat proxy       {} {text}",
            if ok { "✔" } else { "!" }
        )?;
    }
    Ok(healthy)
}
