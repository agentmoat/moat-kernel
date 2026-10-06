//! The Continue CLI (`cn`) runs the Claude Code hook and ignores an `ask`, so an
//! `ask` must still stop a `cn` call.

use std::process::Output;

use serde_json::Value;

use crate::common::{Sandbox, bash_payload, fixture, hook_output, output, stderr};

/// Run the Claude Code hook as `cn` does: with `CONTINUE_PROJECT_DIR` set.
fn guard_under_cn(sb: &Sandbox, payload: &str) -> Output {
    let mut cmd = sb.command();
    cmd.args(["guard", "--host", "claude-code"])
        .env("CONTINUE_PROJECT_DIR", &sb.home);
    output(&mut cmd, Some(payload))
}

fn recorded(sb: &Sandbox, session: &str) -> Value {
    let shown = sb.moat(&["show", "--session", session, "--format", "json"]);
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    serde_json::from_slice(&shown.stdout).unwrap()
}

fn assert_blocked_ask(out: &Output) {
    assert_eq!(out.status.code(), Some(2), "{}", stderr(out));
    let d = hook_output(out);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("[installs]"), "{reason}");
    assert!(reason.contains("Continue CLI"), "{reason}");
    assert!(reason.contains("moat allow --last"), "{reason}");
}

/// `cn` runs the call when its hook answers `ask`. An `ask` must reach it as a
/// blocking `deny` (exit 2) that says how to approve it; the audit log records
/// the host as `continue` and keeps the `ask`, so `moat allow --last` grants it.
#[test]
fn an_ask_blocks_cn_until_a_person_approves_it() {
    let sb = Sandbox::installed(&[".claude"]);
    let cn = fixture("continue/pretooluse-bash.json");
    let session = "3f2a9c1e-7b4d-4e8a-9f0b-2c6d8e1a5b7f";

    assert_blocked_ask(&guard_under_cn(&sb, &cn));
    let events = recorded(&sb, session);
    assert_eq!(events[0]["host"], "continue", "{events}");
    assert_eq!(events[0]["verdict"], "ask", "{events}");

    let allow = sb.moat_as_person(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(0), "{}", stderr(&allow));
    let out = guard_under_cn(&sb, &cn);
    assert_eq!(out.status.code(), Some(0), "approved for the session");
    assert_eq!(hook_output(&out)["permissionDecision"], "allow");

    // Claude Code can ask, so it still receives the `ask` itself.
    let claude = bash_payload("s-claude", &sb.home, "npm install left-pad");
    let out = sb.guard("claude-code", &claude);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(hook_output(&out)["permissionDecision"], "ask");
    assert_eq!(recorded(&sb, "s-claude")[0]["host"], "claude-code");
}

/// Either sign of `cn` is enough on its own: its empty `transcript_path`
/// without the variable, or the variable with a Claude Code-shaped payload.
#[test]
fn either_sign_of_cn_turns_an_ask_into_a_deny() {
    let sb = Sandbox::installed(&[".claude"]);
    assert_blocked_ask(&sb.guard("claude-code", &fixture("continue/pretooluse-bash.json")));

    let claude_shaped = bash_payload("s-env", &sb.home, "npm install left-pad");
    assert_blocked_ask(&guard_under_cn(&sb, &claude_shaped));
    assert_eq!(recorded(&sb, "s-env")[0]["host"], "continue");
}
