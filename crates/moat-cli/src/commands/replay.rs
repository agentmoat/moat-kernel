//! `moat replay`: what each agent session did, as a timeline.

use anyhow::{Result, bail};
use moat_audit::SessionSummary;
use moat_hosts::Host;

use crate::cli::{Format, ReplayArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

pub fn run(args: &ReplayArgs) -> Result<Code> {
    let store = Home::locate()?.open_audit()?;
    let host = args.host.map(Host::id);

    let sessions: Vec<SessionSummary> = if let Some(id) = &args.session {
        let events = store.session(id)?;
        if events.is_empty() {
            bail!("no session `{id}`");
        }
        let first = &events[0];
        vec![SessionSummary {
            session_id: first.session_id.clone(),
            host: first.host.clone(),
            cwd: first.cwd.clone(),
            first_ms: first.ts_ms,
            last_ms: events.last().map_or(first.ts_ms, |e| e.ts_ms),
            events,
        }]
    } else {
        let since = time::parse_since(&args.since, time::now_ms())?;
        store.sessions_since(since, host)?
    };

    match args.format {
        Format::Json => render::json(&sessions)?,
        Format::Text => render::replay(&sessions)?,
    }
    Ok(Code::Ok)
}
