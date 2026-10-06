//! `moat guard --host <id>`: the hook entry point.
//!
//! Reads one hook payload from stdin, decides, records, and answers on stdout.
//! Every failure path produces a `deny` response and exit code 2: a kernel
//! that cannot evaluate must not let the action through.

use std::io::{self, Read as _, Write as _};
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use moat_audit::{NewEvent, Store};
use moat_core::{CompiledPolicy, Decision, Verdict};
use moat_hosts::{HookEvent, HookRequest, Host};

use crate::approvals::Grants;
use crate::cli::GuardArgs;
use crate::context;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::{self, INTEGRITY_RULE, Lock};
use crate::realpath::FsPathResolver;

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const UNGOVERNED_RULE: &str = "ungoverned";
const KERNEL_ERROR_RULE: &str = "kernel-error";
const CONFIG_CHANGE_RULE: &str = "config-change";
const SESSION_GRANT_RULE: &str = "approved-session";

pub fn run(args: &GuardArgs) -> Code {
    let host = args.host;
    // A panic would exit 101, which Claude Code treats as a non-blocking hook
    // failure, i.e. the call would proceed. Turn it into an explicit deny.
    if let Ok(code) = std::panic::catch_unwind(|| decide_and_respond(host)) {
        return code;
    }
    let decision = kernel_error(&anyhow::Error::msg("internal error while deciding"));
    let response = host.render_response(&HookEvent::default(), &decision);
    // `println!` would panic again on a closed pipe and exit 101; exit 2 is
    // the deny every host honours whether or not the response arrives.
    let _ = writeln!(io::stdout(), "{response}");
    eprintln!("{}", moat_hosts::reason_line(&decision));
    Code::Deny
}

fn decide_and_respond(host: Host) -> Code {
    let started = Instant::now();

    // The event is read separately so a payload that cannot be parsed is still
    // refused in the format its hook expects.
    let mut event = HookEvent::default();
    let (request, mut decision) = match read_stdin() {
        Ok(payload) => {
            event = host.event_of(&payload);
            evaluate(host, &payload).unwrap_or_else(|error| (None, kernel_error(&error)))
        }
        Err(error) => (None, kernel_error(&error)),
    };

    // The audit log is part of the decision: a call that cannot be recorded
    // is not allowed, so a missing or unwritable log cannot hide activity.
    if let Err(error) = record(host, request.as_ref(), &decision, started) {
        decision = kernel_error(&error.context("audit log unavailable"));
    }

    let event = request.as_ref().map_or(event, |r| r.event.clone());
    // What the host receives can be stricter than what was decided and recorded
    // (Codex cannot ask, so an `ask` reaches it as a `deny`).
    let decision = host.answer(&event, &decision);
    let response = host.render_response(&event, &decision);
    let mut stdout = io::stdout().lock();
    let written = writeln!(stdout, "{response}").and_then(|()| stdout.flush());
    if let Err(error) = written {
        // Without a response the host falls back to its own default, which
        // may be to proceed; exit 2 is the one signal every host honours.
        eprintln!("moat: could not write the hook response: {error}");
        return Code::Deny;
    }

    match decision.verdict {
        Verdict::Allow | Verdict::Ask => Code::Ok,
        Verdict::Deny => {
            eprintln!("{}", moat_hosts::reason_line(&decision));
            Code::Deny
        }
    }
}

fn evaluate(host: Host, payload: &str) -> Result<(Option<HookRequest>, Decision)> {
    let request = host
        .parse_request(payload)
        .context("parsing hook payload")?;

    if let HookEvent::ConfigChange {
        source,
        change_type,
    } = &request.event
    {
        let change = change_type.as_deref().unwrap_or("changed");
        let decision =
            config_change_decision(&Home::locate()?, request.action.as_ref(), source, change)?;
        return Ok((Some(request), decision));
    }
    let Some(action) = &request.action else {
        return Ok((Some(request), ungoverned()));
    };

    let home = Home::locate()?;
    if let Some(decision) = integrity::violation(&home)? {
        return Ok((Some(request), decision));
    }
    let policy = home.load_policy()?;
    let cwd = request
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_dir, Ok)
        .context("resolving working directory")?;
    let ctx = context::eval_context(Some(&cwd), None)?;
    let snapshot = Snapshot::load(&home.environment_path())?;
    let mut decision =
        CompiledPolicy::compile(&policy, &ctx)?.decide_with(action, &snapshot, &FsPathResolver);
    if decision.verdict == Verdict::Ask
        && let moat_core::Action::Shell { command } = action
        && Grants::load(&home.grants_path())?.matches(
            host.id(),
            &request.session_id,
            command,
            crate::time::now_ms(),
        )
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
    let store = Store::open_existing(&home.audit_path())?;
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

/// A settings file changed on disk. If `moat` pinned that file, it may only be
/// loaded when it still matches the lock; otherwise the session keeps the old
/// settings and the change is reported. Unpinned files are audited and allowed.
fn config_change_decision(
    home: &Home,
    action: Option<&moat_core::Action>,
    source: &str,
    change: &str,
) -> Result<Decision> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!("no policy lock at {}; run `moat init`", lock_path.display());
    }
    let lock = Lock::load(&lock_path)?;
    let path = match action {
        Some(moat_core::Action::FsWrite { path }) => std::path::Path::new(path),
        Some(_) => bail!("config change for something other than a file"),
        // Claude Code may report a change without naming the file. The veto
        // exists to keep a tampered pinned file out of the session, and the
        // change is already on disk, so check every pinned file: block when any
        // drifted (every tool call is denied then anyway), load otherwise.
        // Refusing every unnamed change would block the user's own edits while
        // protecting nothing the lock does not already cover.
        None => return Ok(unnamed_config_change(&lock, source, change)),
    };
    // A settings-review copy holds exactly what its target will become, so the
    // target's pin decides: block unless the copy leaves the pinned file as is.
    // Only a person re-pins, and the hook cannot tell an owner's accept in
    // `/settings-review` from an agent's, so any edit of a pinned file is refused.
    let mut decision = Decision::new(Verdict::Allow);
    if let Some(target) = path.to_str().and_then(moat_hosts::proposal_target)
        && lock.pins(std::path::Path::new(&target))
    {
        if let Some(drift) = lock.verify_proposal(path, std::path::Path::new(&target)) {
            decision = Decision::new(Verdict::Deny);
            decision.rules.push(INTEGRITY_RULE.to_owned());
            decision.reasons.push(format!(
                "{drift}; moat pinned {target}, so the proposal is not applied. Edit the file yourself and run `moat doctor --accept` to change it"
            ));
        } else {
            decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
            decision
                .reasons
                .push(format!("{} leaves {target} as pinned", path.display()));
        }
        return Ok(decision);
    }
    if !lock.pins(path) {
        decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
        decision
            .reasons
            .push(format!("{} {change}; not pinned by moat", path.display()));
        return Ok(decision);
    }
    match lock.verify_one(path) {
        None => {
            decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
            decision.reasons.push(format!(
                "{} {change}; matches the policy lock",
                path.display()
            ));
        }
        Some(drift) => decision = drift_blocks_change(&[drift]),
    }
    Ok(decision)
}

fn unnamed_config_change(lock: &Lock, source: &str, change: &str) -> Decision {
    let drift = lock.verify();
    if !drift.is_empty() {
        return drift_blocks_change(&drift);
    }
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push(CONFIG_CHANGE_RULE.to_owned());
    decision.reasons.push(format!(
        "{source} {change} (no file named); every file pinned by moat matches the policy lock"
    ));
    decision
}

fn drift_blocks_change(drift: &[crate::integrity::Drift]) -> Decision {
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(INTEGRITY_RULE.to_owned());
    for d in drift {
        decision.reasons.push(format!(
            "{d} outside moat; the change is not loaded into this session. Run `moat doctor` to inspect, `moat doctor --accept` to accept it"
        ));
    }
    decision
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
