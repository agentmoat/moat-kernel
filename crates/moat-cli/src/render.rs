//! Human and machine output.

use std::io::{self, Write};

use anyhow::Result;
use moat_audit::Event;
use moat_core::{Action, Decision, Verdict};
use serde::Serialize;

#[derive(Serialize)]
struct DecisionReport<'a> {
    verdict: Verdict,
    rules: &'a [String],
    reasons: &'a [String],
    context: &'a [String],
}

pub fn decision_json(decision: &Decision) -> Result<()> {
    let report = DecisionReport {
        verdict: decision.verdict,
        rules: &decision.rules,
        reasons: &decision.reasons,
        context: &decision.context,
    };
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &report)?;
    writeln!(out)?;
    Ok(())
}

pub fn decision_text(decision: &Decision) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}", verdict_mark(decision.verdict))?;
    writeln!(out, "   rules : {}", decision.rules.join(" · "))?;
    for reason in &decision.reasons {
        writeln!(out, "   reason: {reason}")?;
    }
    for line in &decision.context {
        writeln!(out, "   also  : {line}")?;
    }
    Ok(())
}

pub fn events_json(events: &[Event]) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, events)?;
    writeln!(out)?;
    Ok(())
}

pub fn event_table(events: &[Event]) -> Result<()> {
    let mut out = io::stdout().lock();
    if events.is_empty() {
        writeln!(out, "no events")?;
        return Ok(());
    }
    writeln!(
        out,
        "id     time     host         verdict rules          action"
    )?;
    for event in events {
        writeln!(
            out,
            "{:<6} {:<8} {:<12} {:<7} {:<14} {}",
            event.id,
            clock(event.ts_ms),
            event.host,
            event.verdict.as_str(),
            truncate(&event.rules.join(","), 14),
            truncate(&describe(event.action.as_ref(), &event.tool), 70),
        )?;
    }
    Ok(())
}

pub fn event_detail(event: &Event) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}  event {}", verdict_mark(event.verdict), event.id)?;
    writeln!(out, "   when    : {}", timestamp(event.ts_ms))?;
    writeln!(
        out,
        "   host    : {}  session {}",
        event.host, event.session_id
    )?;
    if let Some(call) = &event.call_id {
        writeln!(out, "   call    : {call}")?;
    }
    if let Some(cwd) = &event.cwd {
        writeln!(out, "   cwd     : {cwd}")?;
    }
    writeln!(out, "   tool    : {}", event.tool)?;
    writeln!(
        out,
        "   action  : {}",
        describe(event.action.as_ref(), &event.tool)
    )?;
    writeln!(out, "   rules   : {}", event.rules.join(" · "))?;
    for reason in &event.reasons {
        writeln!(out, "   reason  : {reason}")?;
    }
    writeln!(out, "   latency : {} µs", event.latency_us)?;
    Ok(())
}

fn verdict_mark(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "✔ allow",
        Verdict::Ask => "❓ ask",
        Verdict::Deny => "⛔ deny",
    }
}

fn describe(action: Option<&Action>, tool: &str) -> String {
    match action {
        Some(Action::Shell { command }) => command.clone(),
        Some(Action::FsRead { path }) => format!("read {path}"),
        Some(Action::FsWrite { path }) => format!("write {path}"),
        Some(Action::Net { url }) => format!("fetch {url}"),
        Some(Action::McpTool { name }) => name.clone(),
        None => format!("{tool} (ungoverned)"),
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let cut: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

fn clock(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000).rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn timestamp(ts_ms: i64) -> String {
    let (date, _) = civil_from_unix(ts_ms.div_euclid(1000));
    format!("{date} {} UTC", clock(ts_ms))
}

fn civil_from_unix(secs: i64) -> (String, i64) {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (format!("{year:04}-{month:02}-{day:02}"), days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_utc_civil_dates() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(timestamp(1_790_985_600_000), "2026-10-03 00:00:00 UTC");
        assert_eq!(clock(90_061_000), "01:01:01");
    }

    #[test]
    fn truncation_keeps_width() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a very long command line", 10), "a very lo…");
    }
}
