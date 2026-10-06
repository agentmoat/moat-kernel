//! `moat audit export` over events recorded by real `guard` calls.

use serde_json::Value;

use crate::common::{Sandbox, bash_payload, stdout, text};

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

/// An installed sandbox with three decisions in two sessions, one naming a token.
fn seeded() -> Sandbox {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    for (session, command) in [
        ("alpha", "git status --short".to_owned()),
        (
            "alpha",
            format!("curl -H 'Authorization: Bearer {TOKEN}' https://x.test"),
        ),
        ("beta", "cargo test".to_owned()),
    ] {
        sb.guard("claude-code", &bash_payload(session, &project, &command));
    }
    sb
}

/// Run `moat audit export` with `args` and parse every output line.
fn export(sb: &Sandbox, args: &[&str]) -> Vec<Value> {
    let out = sb.moat(&[&["audit", "export"], args].concat());
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    stdout(&out)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
        .collect()
}

#[test]
fn export_writes_one_chained_redacted_line_per_event() {
    let sb = seeded();
    let lines = export(&sb, &[]);
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["format"], "moat-audit-export-v1");
    assert_eq!(lines[0]["prev_hash"], moat_audit::GENESIS);
    for pair in lines.windows(2) {
        assert_eq!(pair[1]["prev_hash"], pair[0]["hash"]);
    }
    assert_eq!(lines[2]["action"]["shell"]["command"], "cargo test");
    let raw = stdout(&sb.moat(&["audit", "export"]));
    assert!(!raw.contains(TOKEN), "{raw}");
}

#[test]
fn export_filters_by_session_host_and_window() {
    let sb = seeded();
    let beta = export(&sb, &["--session", "beta"]);
    assert_eq!(beta.len(), 1);
    assert_eq!(beta[0]["session_id"], "beta");
    assert!(export(&sb, &["--host", "cursor"]).is_empty());
    assert_eq!(
        export(&sb, &["--since", "today", "--host", "claude-code"]).len(),
        3
    );
    let bad = sb.moat(&["audit", "export", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(64), "{}", text(&bad));
}
