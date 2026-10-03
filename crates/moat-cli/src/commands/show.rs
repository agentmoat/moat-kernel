//! `moat show`: inspect audit events.

use anyhow::{Result, bail};
use moat_audit::{Event, EventId, Store};

use crate::cli::{Format, ShowArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;

pub fn run(args: &ShowArgs) -> Result<Code> {
    let home = Home::locate()?;
    let path = home.audit_path();
    if !path.is_file() {
        bail!("no audit log at {}; run `moat init`", path.display());
    }
    let store = Store::open_read_only(&path)?;

    let events: Vec<Event> = if let Some(id) = &args.id {
        let id: EventId = id.parse()?;
        match store.get(id)? {
            Some(event) => vec![event],
            None => bail!("no event {id}"),
        }
    } else if let Some(session) = &args.session {
        store.session(session)?
    } else {
        store.recent(args.recent)?
    };

    match args.format {
        Format::Json => render::events_json(&events)?,
        Format::Text if args.id.is_some() => render::event_detail(&events[0])?,
        Format::Text => render::event_table(&events)?,
    }
    Ok(Code::Ok)
}
