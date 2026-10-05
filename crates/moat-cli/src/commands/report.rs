//! `moat report`: how the policy behaved over a window.

use anyhow::Result;
use moat_hosts::Host;

use crate::cli::{Format, ReportArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

pub fn run(args: &ReportArgs) -> Result<Code> {
    let since = time::parse_since(&args.since, time::now_ms())?;
    let store = Home::locate()?.open_audit()?;
    let summary = store.summary(since, args.host.map(Host::id))?;
    match args.format {
        Format::Json => render::json(&summary)?,
        Format::Text => render::report(&summary, &args.since)?,
    }
    Ok(Code::Ok)
}
