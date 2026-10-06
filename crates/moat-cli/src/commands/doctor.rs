//! `moat doctor`: verify the installation and, from a terminal, accept changes.

use anyhow::{Result, bail};
use moat_audit::Store;
use moat_hosts::Host;

use crate::cli::DoctorArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookState, HostConfig, stale_hint};
use crate::integrity::{self, Lock};

/// What a check is about, so accepting changes clears exactly the problems a
/// re-pin fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Area {
    State,
    Policy,
    Lock,
    Binary,
    Environment,
    Hook,
    Audit,
}

struct Report {
    problems: Vec<(Area, String)>,
}

impl Report {
    fn line(&mut self, area: Area, ok: bool, text: String) {
        println!("{} {text}", if ok { "✔" } else { "✗" });
        if !ok {
            self.problems.push((area, text));
        }
    }

    fn note(text: &str) {
        println!("· {text}");
    }
}

pub fn run(args: &DoctorArgs) -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    let mut report = Report {
        problems: Vec::new(),
    };

    report.line(
        Area::State,
        home.exists(),
        format!("state directory  {}", home.root().display()),
    );

    let policy_lints = match home.load_policy() {
        Ok(policy) => {
            let (deny, allow, ask) = policy.rule_count();
            report.line(
                Area::Policy,
                true,
                format!("policy           lints ({deny} deny, {allow} allow, {ask} ask)"),
            );
            true
        }
        Err(e) => {
            report.line(Area::Policy, false, format!("policy           {e:#}"));
            false
        }
    };

    let lock_path = home.lock_path();
    let lock = match Lock::load(&lock_path) {
        Ok(lock) => Some(lock),
        Err(_) if !lock_path.exists() => {
            report.line(
                Area::Lock,
                false,
                "lock             missing; run `moat init`".to_owned(),
            );
            None
        }
        Err(e) => {
            report.line(Area::Lock, false, format!("lock             {e:#}"));
            None
        }
    };
    let mut drift = Vec::new();
    if let Some(lock) = &lock {
        drift = lock.verify();
        if drift.is_empty() {
            report.line(
                Area::Lock,
                true,
                format!(
                    "lock             {} files pinned, all intact",
                    lock.entries.len()
                ),
            );
        }
        for d in &drift {
            report.line(Area::Lock, false, format!("lock             {d}"));
        }
        if lock.binary != binary.to_string_lossy() {
            report.line(
                Area::Binary,
                false,
                format!(
                    "binary           lock expects {}, running {}; run `moat init`",
                    lock.binary,
                    binary.display()
                ),
            );
        }
    }

    match crate::environment::Snapshot::load(&home.environment_path()) {
        Ok(snapshot) => report.line(
            Area::Environment,
            true,
            format!(
                "environment      {} dirs, {} programs pinned",
                snapshot.path.len(),
                snapshot.programs.len()
            ),
        ),
        Err(e) => report.line(
            Area::Environment,
            false,
            format!("environment      {e:#}; run `moat init`"),
        ),
    }

    let mut hook_files = Vec::new();
    for host in Host::ALL {
        let config = HostConfig::for_host(host)?;
        let name = host.display_name();
        match config.state(&binary) {
            HookState::Installed => {
                hook_files.push(config.settings_path.clone());
                report.line(
                    Area::Hook,
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
                report.line(
                    Area::Hook,
                    false,
                    format!("{name:<16} hook missing; run `moat init`"),
                );
            }
            HookState::Stale { command } => {
                report.line(
                    Area::Hook,
                    false,
                    format!("{name:<16} {}", stale_hint(&command)),
                );
            }
            HookState::Unreadable(e) => {
                report.line(Area::Hook, false, format!("{name:<16} {e}"));
            }
        }
    }

    match Store::open_read_only(&home.audit_path()) {
        Ok(store) => {
            report.line(
                Area::Audit,
                true,
                format!("audit log        {} events", store.count()?),
            );
        }
        Err(e) => {
            report.line(Area::Audit, false, format!("audit log        {e}"));
        }
    }

    if args.accept {
        if !crate::terminal::interactive() {
            bail!(
                "`moat doctor --accept` must be run by a person in a terminal, not from a hook or script"
            );
        }
        if !policy_lints {
            bail!(
                "refusing to pin a policy that does not lint; fix it, then run `moat doctor --accept` again"
            );
        }
        if drift.is_empty() && lock.is_some() {
            println!("nothing to accept: lock is intact");
        } else {
            let lock = integrity::repin(&home, &binary)?;
            println!("✔ lock re-pinned for {} files", lock.entries.len());
            report
                .problems
                .retain(|(area, _)| !matches!(area, Area::Lock | Area::Binary));
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
