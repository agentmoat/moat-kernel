//! `moat allow`: turn an `ask` into a session grant or a permanent rule.

use std::io::Write as _;

use anyhow::{Context as _, Result, bail};
use moat_core::{Action, Verdict};

use crate::approvals::{GRANT_TTL_MS, Grants, Overlay};
use crate::cli::AllowArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::{self, HookPins};
use crate::render::Deferred;

/// How many recent events `--last` searches for the newest shell `ask`.
const LAST_ASK_SEARCH: usize = 200;

pub fn run(args: &AllowArgs) -> Result<Code> {
    if !crate::terminal::interactive() {
        bail!("`moat allow` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    if !home.exists() {
        bail!("{} does not exist; run `moat init`", home.root().display());
    }
    // The re-pin below covers every pinned file, so approving one command over a
    // drifted lock would also accept a tampered policy or hook unseen. Without a
    // lock there is nothing to accept yet and the re-pin creates one.
    if home.lock_path().exists()
        && let Some(deny) = integrity::violation(&home)?
    {
        bail!(
            "refusing to approve while the policy lock shows drift ({}):\n  {}",
            integrity::INTEGRITY_RULE,
            deny.reasons.join("\n  ")
        );
    }

    let mut out = Deferred::default();
    let (host, session, command) = match (&args.command, args.last) {
        (Some(command), false) => (
            args.host.map(|h| h.id().to_owned()),
            args.session.clone(),
            command.clone(),
        ),
        (None, true) => last_ask(&home, &mut out)?,
        _ => bail!("give a command, or --last to take the most recent ask"),
    };

    if args.always {
        let path = home.overlay_path();
        let mut overlay = Overlay::load(&path)?;
        let rule = overlay.allow_command(&command)?.clone();
        overlay.save(&path)?;
        writeln!(
            out,
            "✔ permanent rule {} allows shell \"{command}\"",
            rule.id
        )?;
        warn_if_shadowed(&home, &rule.id, &mut out)?;
    } else {
        let session = session.context(
            "give --host and --session for a session grant, --always for a permanent rule, or --last",
        )?;
        let host = host.context("--session needs --host")?;
        let path = home.grants_path();
        let mut grants = Grants::load(&path)?;
        let now = crate::time::now_ms();
        grants.grant(&host, &session, &command, now);
        grants.save(&path, now)?;
        writeln!(
            out,
            "✔ session {session} on {host} may run \"{command}\" for {}",
            crate::time::duration(GRANT_TTL_MS)
        )?;
    }

    let binary = crate::install::hook_binary()?;
    let lock = integrity::repin(&home, &binary, HookPins::Keep)?;
    writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    out.finish()?;
    Ok(Code::Ok)
}

/// A rule a deny already covers can never decide anything; say so rather than
/// let the person believe the command is now allowed.
fn warn_if_shadowed(home: &Home, id: &str, out: &mut Deferred) -> Result<()> {
    let Ok(policy) = home.load_policy() else {
        return Ok(());
    };
    for warning in moat_core::lint::warnings(&policy) {
        if warning.rule == id {
            writeln!(out, "warning: {warning}")?;
        }
    }
    Ok(())
}

/// Host, session and command of the most recent `ask` for a shell command.
fn last_ask(home: &Home, out: &mut Deferred) -> Result<(Option<String>, Option<String>, String)> {
    let store = home.open_audit()?;
    let event = store
        .recent(LAST_ASK_SEARCH)?
        .into_iter()
        .find(|e| e.verdict == Verdict::Ask && matches!(e.action, Some(Action::Shell { .. })))
        .context("no recent `ask` for a shell command in the audit log")?;
    let Some(Action::Shell { command }) = event.action else {
        unreachable!("filtered to shell actions");
    };
    writeln!(
        out,
        "last ask: {} on {} (session {}) wanted to run \"{command}\"",
        event.id, event.host, event.session_id
    )?;
    Ok((Some(event.host), Some(event.session_id), command))
}
