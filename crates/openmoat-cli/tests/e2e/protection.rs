//! Each agent's protection level in `moat status` (text and JSON), `moat doctor`
//! and the home screen (#334).

use std::fs;

use serde_json::Value;

use crate::common::{Sandbox, json, output, stdout, text};

/// The `agents` entry of `moat status --format json` for `host`.
fn agent(sb: &Sandbox, host: &str) -> Value {
    let out = sb.moat(&["status", "--format", "json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    json(&out)["agents"]
        .as_array()
        .and_then(|agents| agents.iter().find(|a| a["host"] == host).cloned())
        .unwrap_or_else(|| panic!("{host} missing: {}", text(&out)))
}

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
#[test]
fn each_agent_reports_its_level_and_gaps() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    let status = stdout(&sb.moat(&["status"]));
    for line in [
        "Claude Code      ✔ protection: hook + OS sandbox",
        "Claude Code      · known gaps: WebSearch is not hooked",
        "Codex            ✔ protection: hook + OS sandbox",
        "Codex            · known gaps: web search and hosted tools are not hooked; asks become denies",
        "Cursor           ! protection: hook only: no OS sandbox from OpenMoat",
        "Cursor           · known gaps: OS sandbox not configured by OpenMoat",
    ] {
        assert!(status.contains(line), "{line:?} in {status}");
    }
    let doctor = stdout(&sb.moat(&["doctor"]));
    assert!(
        doctor.contains("· Codex            protection: hook + OS sandbox"),
        "{doctor}"
    );
    assert!(
        doctor.contains("· Cursor           protection: hook only"),
        "{doctor}"
    );
    assert!(
        doctor.contains("healthy"),
        "hook only is no problem: {doctor}"
    );

    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "hook-and-os-sandbox", "{claude}");
    assert_eq!(claude["reason"], Value::Null, "{claude}");
    assert_eq!(claude["name"], "Claude Code");
    assert!(claude["gaps"].as_str().unwrap().contains("WebSearch"));
    let cursor = agent(&sb, "cursor");
    assert_eq!(cursor["level"], "hook-only", "{cursor}");

    let home = text(&output(&mut sb.command(), Some("")));
    assert!(
        home.contains(
            "Protecting Claude Code (hook + OS sandbox), Codex (hook + OS sandbox), Cursor (hook only)"
        ),
        "{home}"
    );
}

#[test]
fn a_drifted_sandbox_is_hook_only_and_says_which() {
    let sb = Sandbox::installed(&[".codex"]);
    let path = sb.home.join(".codex/config.toml");
    let weakened = fs::read_to_string(&path).unwrap().replace(
        "default_permissions = \"moat\"",
        "default_permissions = \":workspace\"",
    );
    fs::write(&path, weakened).unwrap();
    let codex = agent(&sb, "codex");
    assert_eq!(codex["level"], "hook-only", "{codex}");
    let reason = codex["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("sandbox: default_permissions is not \"moat\""),
        "{reason}"
    );
    let status = stdout(&sb.moat(&["status"]));
    assert!(
        status.contains("Codex            ! protection: hook only: sandbox: default_permissions"),
        "{status}"
    );
}

#[test]
fn a_missing_hook_is_not_protected_and_absent_agents_keep_their_line() {
    let sb = Sandbox::installed(&[".claude"]);
    fs::write(sb.home.join(".claude/settings.json"), "{}").unwrap();
    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "not-protected", "{claude}");
    assert_eq!(claude["reason"], "hook missing", "{claude}");
    assert_eq!(agent(&sb, "codex")["level"], "not-found");

    let status = stdout(&sb.moat(&["status"]));
    assert!(
        status.contains("Claude Code      ✗ protection: not protected: hook missing"),
        "{status}"
    );
    assert!(
        status.contains("Codex            · host not found"),
        "{status}"
    );
    assert!(!status.contains("Codex            ✗"), "{status}");
    assert!(
        !status.contains("Codex            · known gaps"),
        "{status}"
    );

    let home = text(&output(&mut sb.command(), Some("")));
    assert!(home.contains("No agent is protected"), "{home}");
}

/// #327: Claude Code's sandbox cannot run on native Windows, so its hook is all
/// OpenMoat gives it there.
#[cfg(windows)]
#[test]
fn claude_code_on_native_windows_is_hook_only() {
    let sb = Sandbox::installed(&[".claude"]);
    let claude = agent(&sb, "claude-code");
    assert_eq!(claude["level"], "hook-only", "{claude}");
    assert!(
        claude["reason"]
            .as_str()
            .unwrap()
            .starts_with("sandbox not available on native Windows"),
        "{claude}"
    );
    let status = stdout(&sb.moat(&["status"]));
    assert!(
        status.contains("Claude Code      ! protection: hook only: sandbox not available"),
        "{status}"
    );
    let home = text(&output(&mut sb.command(), Some("")));
    assert!(
        home.contains("Protecting Claude Code (hook only)"),
        "{home}"
    );
}
