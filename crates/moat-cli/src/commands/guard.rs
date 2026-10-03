//! `moat guard --host <id>`: the hook entry point.
//!
//! Reads one hook payload from stdin, decides, records, and answers on stdout.
//! Every failure path produces a `deny` response and exit code 2: a kernel
//! that cannot evaluate must not let the action through.

use std::io::{self, Read as _, Write as _};
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow};
use moat_audit::{NewEvent, Store};
use moat_core::{CompiledPolicy, Decision, EvalContext, Verdict};
use moat_hosts::{HookRequest, Host};

use crate::cli::GuardArgs;
use crate::context;
use crate::exit::Code;
use crate::home::Home;
use crate::project;

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const UNGOVERNED_RULE: &str = "ungoverned";
const KERNEL_ERROR_RULE: &str = "kernel-error";

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

    let response = host.render_response(&decision);
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
    let decision = CompiledPolicy::compile(&policy, &ctx)?.decide(action);
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
        return Err(anyhow!(
            "{} does not exist; run `moat init`",
            home.root().display()
        ));
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
        return Err(anyhow!("empty hook payload on stdin"));
    }
    Ok(payload)
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
