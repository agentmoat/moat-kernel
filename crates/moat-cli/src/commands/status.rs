//! `moat status`: is the kernel installed, current and active?

use std::fmt::Write as _;
use std::fs;

use anyhow::{Context as _, Result};
use moat_audit::Store;
use moat_hosts::Host;
use sha2::{Digest as _, Sha256};

use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::integrity::Lock;
use crate::render;

pub fn run() -> Result<Code> {
    let home = Home::locate()?;
    let binary = std::env::current_exe().context("locating the moat binary")?;
    let mut healthy = true;

    println!("state directory  {}", home.root().display());

    let policy_path = home.policy_path();
    match home.load_policy() {
        Ok(policy) => {
            let bytes = fs::read(&policy_path)?;
            let digest = Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                });
            let (deny, allow, ask) = policy.rule_count();
            println!(
                "policy           {}  sha256:{digest}  ({deny} deny, {allow} allow, {ask} ask)",
                policy_path.display()
            );
        }
        Err(error) => {
            healthy = false;
            println!("policy           ✗ {error:#}");
        }
    }

    match Lock::load(&home.lock_path()) {
        Ok(lock) => {
            let drift = lock.verify();
            if drift.is_empty() {
                println!(
                    "lock             ✔ {} files pinned, intact",
                    lock.entries.len()
                );
            } else {
                healthy = false;
                for d in drift {
                    println!("lock             ✗ {d} (run `moat doctor`)");
                }
            }
        }
        Err(error) => {
            healthy = false;
            println!("lock             ✗ {error:#}");
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
                format!("✗ hook points at {command} (run `moat init`)")
            }
            HookState::Unreadable(error) => {
                healthy = false;
                format!("✗ {error}")
            }
        };
        println!(
            "{:<16} {line}  {}",
            host.display_name(),
            config.settings_path.display()
        );
    }

    let audit_path = home.audit_path();
    if audit_path.is_file() {
        let store = Store::open_read_only(&audit_path)?;
        println!(
            "audit log        {}  ({} events)",
            audit_path.display(),
            store.count()?
        );
        let recent = store.recent(5)?;
        if !recent.is_empty() {
            println!();
            render::event_table(&recent)?;
        }
    } else {
        healthy = false;
        println!("audit log        ✗ missing (run `moat init`)");
    }

    Ok(if healthy { Code::Ok } else { Code::Usage })
}
