//! `moat guard --host <id>`: the hook entry point.
//!
//! Reads one hook payload from stdin, decides, records, and answers on stdout.
//! Every failure path produces a `deny` response and exit code 2: a kernel
//! that cannot evaluate must not let the action through.

use std::io::{self, Read as _, Write as _};
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use moat_audit::{NewEvent, Store};
use moat_core::{CompiledPolicy, Decision, EvalContext, Verdict};
use moat_hosts::{HookEvent, HookRequest, Host};

use crate::approvals::Grants;
use crate::cli::GuardArgs;
use crate::context;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::Lock;
use crate::project;

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const UNGOVERNED_RULE: &str = "ungoverned";
const KERNEL_ERROR_RULE: &str = "kernel-error";
const INTEGRITY_RULE: &str = "kernel-integrity";
const CONFIG_CHANGE_RULE: &str = "config-change";
const SESSION_GRANT_RULE: &str = "approved-session";

pub fn run(args: &GuardArgs) -> Code {
    let started = Instant::now();
    let host = args.host;

    let (request, decision) = match evaluate(host) {
        Ok(outcome) => outcome,
        Err(error) => (None, kernel_error(&error)),
    };

    if let Err(error) = record(host, request.as_ref(), &decision, started) {
        eprintln!("moat: audit unavailable: {error:#}");
    }

    let event = request
        .as_ref()
        .map(|r| r.event.clone())
        .unwrap_or_default();
    let response = host.render_response(&event, &decision);
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{response}");
    let _ = stdout.flush();

    match decision.verdict {
        Verdict::Allow | Verdict::Ask => Code::Ok,
        Verdict::Deny => {
            eprintln!("{}", moat_hosts::reason_line(&decision));
            Code::Deny
        }
    }
}

fn evaluate(host: Host) -> Result<(Option<HookRequest>, Decision)> {
    let payload = read_stdin()?;
    let request = host
        .parse_request(&payload)
        .context("parsing hook payload")?;

    let Some(action) = &request.action else {
        return Ok((Some(request), ungoverned()));
    };

    let home = Home::locate()?;
    if let HookEvent::ConfigChange { change_type, .. } = &request.event {
        let decision = config_change_decision(&home, action, change_type)?;
        return Ok((Some(request), decision));
    }
    if let Some(decision) = integrity_violation(&home)? {
        return Ok((Some(request), decision));
    }
    let policy = home.load_policy()?;
    let cwd = request
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_dir, Ok)
        .context("resolving working directory")?;
    let ctx = EvalContext {
        home: context::path_string(&crate::home::user_home()?),
        project: context::path_string(&project::root_of(&cwd)),
        cwd: context::path_string(&cwd),
    };
    let snapshot = Snapshot::load(&home.environment_path())?;
    let mut decision = CompiledPolicy::compile(&policy, &ctx)?.decide_with(action, &snapshot);
    if decision.verdict == Verdict::Ask
        && let moat_core::Action::Shell { command } = action
        && Grants::load(&home.grants_path())?.matches(host.id(), &request.session_id, command)
    {
        decision = Decision::new(Verdict::Allow);
        decision.rules.push(SESSION_GRANT_RULE.to_owned());
        decision
            .reasons
            .push("approved for this session with `moat allow`".to_owned());
    }
    Ok((Some(request), decision))
}

fn record(
    host: Host,
    request: Option<&HookRequest>,
    decision: &Decision,
    started: Instant,
) -> Result<()> {
    let home = Home::locate()?;
    if !home.exists() {
        bail!("{} does not exist; run `moat init`", home.root().display());
    }
    let store = Store::open(&home.audit_path())?;
    let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let event = NewEvent {
        host: host.id(),
        session_id: request.map_or("unknown", |r| r.session_id.as_str()),
        call_id: request.and_then(|r| r.call_id.as_deref()),
        cwd: request.and_then(|r| r.cwd.as_deref()),
        tool: request.map_or("unknown", |r| r.tool.as_str()),
        action: request.and_then(|r| r.action.as_ref()),
        decision,
        latency_us,
    };
    let id = store.record(&event)?;
    if decision.verdict != Verdict::Allow {
        eprintln!("moat: trace {id}  (moat show {id})");
    }
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut payload = String::new();
    io::stdin()
        .lock()
        .take(MAX_PAYLOAD_BYTES)
        .read_to_string(&mut payload)
        .context("reading hook payload from stdin (must be UTF-8)")?;
    if payload.trim().is_empty() {
        bail!("empty hook payload on stdin");
    }
    Ok(payload)
}

/// `Some(deny)` when the pinned policy or hook files changed since `moat init`.
fn integrity_violation(home: &Home) -> Result<Option<Decision>> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!("no policy lock at {}; run `moat init`", lock_path.display());
    }
    let drift = Lock::load(&lock_path)?.verify();
    if drift.is_empty() {
        return Ok(None);
    }
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(INTEGRITY_RULE.to_owned());
    for d in drift {
        decision.reasons.push(format!("{d}"));
    }
    decision.reasons.push(
        "run `moat doctor` to inspect; `moat doctor --accept` or `moat init` to re-pin".to_owned(),
    );
    Ok(Some(decision))
}

/// A settings file changed on disk. If `moat` pinned that file, it may only be
/// loaded when it still matches the lock; otherwise the session keeps the old
/// settings and the change is reported. Unpinned files are audited and allowed.
fn config_change_decision(
    home: &Home,
    action: &moat_core::Action,
    change_type: &str,
) -> Result<Decision> {
    let moat_core::Action::FsWrite { path } = action else {
        bail!("config change without a file path");
    };
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!("no policy lock at {}; run `moat init`", lock_path.display());
    }
    let lock = Lock::load(&lock_path)?;
    let path = std::path::Path::new(path);
    let mut decision = Decision::new(Verdict::Allow);
    if !lock.pins(path) {
        decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
        decision.reasons.push(format!(
            "{} {change_type}; not pinned by moat",
            path.display()
        ));
        return Ok(decision);
    }
    match lock.verify_one(path) {
        None => {
            decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
            decision.reasons.push(format!(
                "{} {change_type}; matches the policy lock",
                path.display()
            ));
        }
        Some(drift) => {
            decision = Decision::new(Verdict::Deny);
            decision.rules.push(INTEGRITY_RULE.to_owned());
            decision.reasons.push(format!(
                "{drift} outside moat; the change is not loaded into this session. Run `moat doctor` to inspect, `moat doctor --accept` to accept it"
            ));
        }
    }
    Ok(decision)
}

fn ungoverned() -> Decision {
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push(UNGOVERNED_RULE.to_owned());
    decision
        .reasons
        .push("tool is outside policy scope".to_owned());
    decision
}

fn kernel_error(error: &anyhow::Error) -> Decision {
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(KERNEL_ERROR_RULE.to_owned());
    decision
        .reasons
        .push(format!("kernel could not evaluate this action: {error:#}"));
    decision
}
