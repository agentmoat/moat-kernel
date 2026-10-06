//! `moat audit`: take the audit log off the machine in a form that can be checked.

use anyhow::Result;
use moat_audit::ExportFilter;
use moat_hosts::Host;

use crate::cli::ExportArgs;
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

pub fn export(args: &ExportArgs) -> Result<Code> {
    let since_ms = time::parse_since(&args.since, time::now_ms())?;
    let store = Home::locate()?.open_audit()?;
    let events = store.export(&ExportFilter {
        since_ms,
        host: args.host.map(Host::id),
        session_id: args.session.as_deref(),
    })?;
    render::json_lines(&events)?;
    Ok(Code::Ok)
}
