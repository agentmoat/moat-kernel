//! `moat doctor`: verify the installation and, from a terminal, accept changes.

use std::io::Write as _;

use anyhow::{Result, bail};
use openmoat_audit::{ChainReport, Store};
use openmoat_core::Policy;
use openmoat_hosts::Host;

use crate::cli::DoctorArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{
    CONTINUE_CLI_WARNING, HookState, HostConfig, Recorded, dir_variable, env_config_dir, stale_hint,
};
use crate::integrity::{self, HookPinGap, HookPins, Lock};
use crate::render::Deferred;
use crate::sandbox::{Plan, install as host_sandbox};

use super::sandbox::write_report;

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
    Sandbox,
    Audit,
}

/// The Standard tier: each present host's sandbox settings against the policy,
/// then how many places the translation loses or widens (each one with `verbose`).
fn sandboxes(report: &mut Report, policy: &Policy, lock: Option<&Lock>, verbose: bool) {
    let plan = match Plan::new(policy) {
        Ok(plan) => plan,
        Err(e) => {
            report.line(Area::Sandbox, false, format!("sandbox          {e:#}"));
            return;
        }
    };
    let mut present = false;
    for host in host_sandbox::HOSTS {
        let name = host.display_name();
        let problems = host_sandbox::problems(host, &plan, lock);
        present |= !matches!(problems, Ok(None));
        let translation = host_sandbox::report(host, &plan);
        match problems {
            Ok(None) => continue,
            Ok(Some(problems)) if problems.is_empty() => {
                let details = if verbose {
                    ""
                } else {
                    "; --verbose for details"
                };
                report.line(
                    Area::Sandbox,
                    true,
                    format!(
                        "{name:<16} sandbox matches the policy ({} stricter, {} wider{details})",
                        translation.losses.len(),
                        translation.allowances.len()
                    ),
                );
            }
            Ok(Some(problems)) => {
                for problem in problems {
                    report.line(
                        Area::Sandbox,
                        false,
                        format!("{name:<16} sandbox: {problem}"),
                    );
                }
            }
            Err(e) => report.line(Area::Sandbox, false, format!("{name:<16} sandbox: {e:#}")),
        }
        if verbose {
            let _ = write_report(&mut report.out, translation);
        }
    }
    if let Some(port) = plan.proxy_port.filter(|_| present) {
        // A warning, not a problem: a stopped proxy fails closed.
        let (ok, text) = super::proxy::listening_line(port);
        let _ = writeln!(
            report.out,
            "{} moat proxy       {text}",
            if ok { "✔" } else { "!" }
        );
    }
}

struct Report {
    problems: Vec<(Area, String)>,
    out: Deferred,
}

impl Report {
    fn line(&mut self, area: Area, ok: bool, text: String) {
        // `Deferred` keeps a write error for `finish`; it never returns one here.
        let _ = writeln!(self.out, "{} {text}", if ok { "✔" } else { "✗" });
        if !ok {
            self.problems.push((area, text));
        }
    }

    fn note(&mut self, text: &str) {
        let _ = writeln!(self.out, "· {text}");
    }
}

pub fn run(args: &DoctorArgs) -> Result<Code> {
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    let mut report = Report {
        problems: Vec::new(),
        out: Deferred::default(),
    };

    report.line(
        Area::State,
        home.exists(),
        format!("state directory  {}", home.root().display()),
    );

    let policy = match home.load_policy() {
        Ok(policy) => {
            let (deny, allow, ask) = policy.rule_count();
            report.line(
                Area::Policy,
                true,
                format!("policy           lints ({deny} deny, {allow} allow, {ask} ask)"),
            );
            Some(policy)
        }
        Err(e) => {
            report.line(Area::Policy, false, format!("policy           {e:#}"));
            None
        }
    };
    let policy_lints = policy.is_some();
    match crate::repo::summary(&home) {
        Ok(Some(line)) => report.note(&format!("repo policy      {line}")),
        Ok(None) => {}
        Err(e) => report.line(
            Area::Policy,
            false,
            format!("repo policy      {e:#}; every call in this project is denied"),
        ),
    }

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

    let hook_files = hooks(&mut report, &home, &binary)?;

    if let Some(lock) = &lock {
        let gap = HookPinGap::new(lock, &home, &hook_files);
        for path in gap.unpinned {
            report.line(
                Area::Hook,
                false,
                format!(
                    "hook file        {} is not pinned by the lock; run `moat init` to pin it",
                    path.display()
                ),
            );
        }
        for path in gap.elsewhere {
            report.note(&format!(
                "hook file        {} is pinned but not this shell's (CLAUDE_CONFIG_DIR, CODEX_HOME or CURSOR_CONFIG_DIR differ); re-pinning keeps it",
                path.display()
            ));
        }
    }

    if let Some(policy) = &policy {
        sandboxes(&mut report, policy, lock.as_ref(), args.verbose);
    }

    match Store::open_read_only(&home.audit_path()).and_then(|store| store.verify_chain()) {
        Ok(chain) => audit_line(&mut report, &chain),
        Err(e) => report.line(Area::Audit, false, format!("audit log        {e}")),
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
            writeln!(report.out, "nothing to accept: lock is intact")?;
        } else {
            let lock = integrity::repin(&home, &binary, HookPins::Keep)?;
            writeln!(
                report.out,
                "✔ lock re-pinned for {} files",
                lock.entries.len()
            )?;
            report
                .problems
                .retain(|(area, _)| !matches!(area, Area::Lock | Area::Binary));
        }
    }

    if report.problems.is_empty() {
        writeln!(report.out, "healthy")?;
        report.out.finish()?;
        return Ok(Code::Ok);
    }
    writeln!(
        report.out,
        "{} problem(s). `moat init` re-installs and re-pins; `moat doctor --accept` accepts edits you made yourself.",
        report.problems.len()
    )?;
    report.out.finish()?;
    Ok(Code::Usage)
}

/// One line per host's hook, then the Continue CLI warning; returns the
/// installed hook files.
fn hooks(
    report: &mut Report,
    home: &Home,
    binary: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>> {
    let recorded = Recorded::load(home)?;
    let mut hook_files = Vec::new();
    for host in Host::ALL {
        let config = HostConfig::for_host(host)?;
        let name = host.display_name();
        // Every command follows the record; a variable naming another directory
        // is reported rather than silently ignored or followed.
        if let (Some(env), Some(dir)) = (env_config_dir(host)?, recorded.dir(host))
            && env != dir
        {
            let (var, _) = dir_variable(host)?;
            report.line(
                Area::Hook,
                false,
                format!(
                    "{name:<16} {var} is {}, but `moat init` set it up in {}, which moat uses; \
                     run `moat init` with {var} set to set up that directory instead",
                    env.display(),
                    dir.display()
                ),
            );
        }
        match config.state(binary) {
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
                report.note(&format!("{name:<16} host not found"));
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
    if let Some(found) = crate::install::continue_cli()? {
        let name = Host::Continue.display_name();
        report.note(&format!(
            "{name:<16} {CONTINUE_CLI_WARNING}  {}",
            found.display()
        ));
    }
    Ok(hook_files)
}

/// The audit log line: event count and whether the hash chain holds.
fn audit_line(report: &mut Report, chain: &ChainReport) {
    if let Some(broken) = &chain.broken {
        report.line(
            Area::Audit,
            false,
            format!(
                "audit log        hash chain broken at event {}: {}; keep the file as evidence",
                broken.id,
                broken.kind.describe()
            ),
        );
        return;
    }
    report.line(
        Area::Audit,
        true,
        format!(
            "audit log        {} events, hash chain intact",
            chain.events
        ),
    );
    if let Some(head) = &chain.head {
        report.note(&format!(
            "audit log        head {head}; record it elsewhere, then `moat audit verify --anchor` a later export"
        ));
    }
    if chain.unchained > 0 {
        report.note(&format!(
            "audit log        {} events written before the hash chain existed are not covered",
            chain.unchained
        ));
    }
}
