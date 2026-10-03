//! `moat doctor`: verify the installation and, from a terminal, accept changes.

use std::io::IsTerminal as _;

use anyhow::{Context as _, Result, bail};
use moat_audit::Store;
use moat_hosts::Host;

use crate::cli::DoctorArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig};
use crate::integrity::Lock;

struct Report {
    problems: Vec<String>,
}

impl Report {
    fn line(&mut self, ok: bool, text: String) {
        println!("{} {text}", if ok { "✔" } else { "✗" });
        if !ok {
            self.problems.push(text);
        }
    }

    fn note(text: &str) {
        println!("· {text}");
    }
}

pub fn run(args: &DoctorArgs) -> Result<Code> {
    let home = Home::locate()?;
    let binary = std::env::current_exe().context("locating the moat binary")?;
    let mut report = Report {
        problems: Vec::new(),
    };

    report.line(
        home.exists(),
        format!("state directory  {}", home.root().display()),
    );

    match home.load_policy() {
        Ok(policy) => {
            let (deny, allow, ask) = policy.rule_count();
            report.line(
                true,
                format!("policy           lints ({deny} deny, {allow} allow, {ask} ask)"),
            );
        }
        Err(e) => {
            report.line(false, format!("policy           {e:#}"));
        }
    }

    let lock_path = home.lock_path();
    let lock = match Lock::load(&lock_path) {
        Ok(lock) => Some(lock),
        Err(_) if !lock_path.exists() => {
            report.line(
                false,
                "lock             missing; run `moat init`".to_owned(),
            );
            None
        }
        Err(e) => {
            report.line(false, format!("lock             {e:#}"));
            None
        }
    };
    let mut drift = Vec::new();
    if let Some(lock) = &lock {
        drift = lock.verify();
        if drift.is_empty() {
            report.line(
                true,
                format!(
                    "lock             {} files pinned, all intact",
                    lock.entries.len()
                ),
            );
        }
        for d in &drift {
            report.line(false, format!("lock             {d}"));
        }
        if lock.binary != binary.to_string_lossy() {
            report.line(
                false,
                format!(
                    "binary           lock expects {}, running {}",
                    lock.binary,
                    binary.display()
                ),
            );
        }
    }

    let mut hook_files = Vec::new();
    for host in Host::ALL {
        let config = HostConfig::for_host(host)?;
        let name = host.display_name();
        match config.state(&binary) {
            HookState::Installed => {
                hook_files.push(config.settings_path.clone());
                report.line(
                    true,
                    format!(
                        "{name:<16} hook installed  {}",
                        config.settings_path.display()
                    ),
                );
            }
            HookState::Missing if !config.host_present() => {
                Report::note(&format!("{name:<16} host not found"));
            }
            HookState::Missing => {
                report.line(false, format!("{name:<16} hook missing; run `moat init`"));
            }
            HookState::Stale { command } => {
                report.line(
                    false,
                    format!("{name:<16} hook points at {command}; run `moat init`"),
                );
            }
            HookState::Unreadable(e) => {
                report.line(false, format!("{name:<16} {e}"));
            }
        }
    }

    match Store::open_read_only(&home.audit_path()) {
        Ok(store) => {
            report.line(true, format!("audit log        {} events", store.count()?));
        }
        Err(e) => {
            report.line(false, format!("audit log        {e}"));
        }
    }

    if args.accept {
        if !std::io::stdin().is_terminal() {
            bail!(
                "`moat doctor --accept` must be run by a person in a terminal, not from a hook or script"
            );
        }
        if drift.is_empty() && lock.is_some() {
            println!("nothing to accept: lock is intact");
        } else {
            let mut paths = vec![home.policy_path()];
            paths.extend(hook_files);
            let lock = Lock::pin(&binary, &paths)?;
            lock.save(&lock_path)?;
            println!("✔ lock re-pinned for {} files", lock.entries.len());
            report
                .problems
                .retain(|p| !p.starts_with("lock") && !p.starts_with("binary"));
        }
    }

    if report.problems.is_empty() {
        println!("healthy");
        return Ok(Code::Ok);
    }
    println!(
        "{} problem(s). `moat init` re-installs and re-pins; `moat doctor --accept` accepts edits you made yourself.",
        report.problems.len()
    );
    Ok(Code::Usage)
}
