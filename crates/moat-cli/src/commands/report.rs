//! `moat report`: how the policy behaved over a window.

use anyhow::{Result, bail};
use moat_audit::Store;
use moat_hosts::Host;

use crate::cli::{Format, ReportArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::render;
use crate::time;

pub fn run(args: &ReportArgs) -> Result<Code> {
    let home = Home::locate()?;
    let path = home.audit_path();
    if !path.is_file() {
        bail!("no audit log at {}; run `moat init`", path.display());
    }
    let since = time::parse_since(&args.since, time::now_ms())?;
    let store = Store::open_read_only(&path)?;
    let summary = store.summary(since, args.host.map(Host::id))?;
    match args.format {
        Format::Json => render::summary_json(&summary)?,
        Format::Text => render::report(&summary, &args.since)?,
    }
    Ok(Code::Ok)
}
