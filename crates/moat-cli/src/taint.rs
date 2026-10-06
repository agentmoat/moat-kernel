//! Session taint (ADR-020) read from the audit log: the calls of one host
//! session that ran, folded into the [`Taint`] the core tightens the next call
//! with. The log is moat's, not the agent's, so the agent cannot reset it.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{CompiledPolicy, Decision, Taint, Verdict};
use openmoat_hosts::{HookEvent, Host};

use crate::context;
use crate::home::Home;
use crate::realpath::FsPathResolver;

/// What the earlier calls of `session` on `host` exposed it to. A call
/// recorded without a working directory is taken to have run in `cwd`. A log
/// that cannot be read fails the call: without it the session's history is
/// unknown, and the guard denies.
pub fn of_session(
    home: &Home,
    host: Host,
    session: &str,
    policy: &CompiledPolicy<'_>,
    cwd: &str,
) -> Result<Taint> {
    let events = home
        .open_audit()?
        .session(session)
        .context("reading this session from the audit log")?;
    let mut taint = Taint::default();
    for event in events
        .iter()
        .filter(|e| e.host == host.id() && ran(host, e.verdict))
    {
        if event.action_unreadable {
            bail!("audit event {} of this session cannot be decoded", event.id);
        }
        let Some(action) = &event.action else {
            continue;
        };
        let cwd = event
            .cwd
            .as_deref()
            .map_or_else(|| cwd.to_owned(), |c| context::path_string(Path::new(c)));
        taint.absorb(policy.exposure(action, &cwd, &FsPathResolver));
    }
    Ok(taint)
}

/// Whether a call decided `verdict` may have run: it was allowed, or it asked
/// a host that can ask (Codex turns an ask into a deny). A person may have
/// declined an ask; that is not recorded, so it counts as run.
fn ran(host: Host, verdict: Verdict) -> bool {
    host.answer(&HookEvent::PreToolUse, &Decision::new(verdict))
        .verdict
        != Verdict::Deny
}
