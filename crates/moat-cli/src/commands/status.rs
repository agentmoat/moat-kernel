//! `moat status`: is the kernel installed, current and active?

use std::fs;
use std::io::{self, Write as _};

use anyhow::Result;
use moat_audit::Store;
use moat_hosts::Host;

use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::integrity::Lock;
use crate::render;

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
