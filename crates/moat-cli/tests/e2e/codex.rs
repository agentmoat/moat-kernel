//! Codex: its `PreToolUse` cannot ask, so an `ask` must still stop the call.

use crate::common::{Sandbox, hook_output, stderr};

fn shell(session: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": session,
        "turn_id": "t-1",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "call-1",
        "tool_input": { "command": command },
    })
    .to_string()
}

/// Codex rejects `permissionDecision: "ask"` as unsupported and then runs the
/// call. An `ask` must therefore reach Codex as a blocking `deny` (exit 2) that
/// tells the person how to approve it, while the audit log keeps the `ask` so
/// `moat allow --last` can turn it into a session grant.
#[test]
fn an_ask_blocks_codex_until_a_person_approves_it() {
    let sb = Sandbox::bare(&[".claude"]);
    std::fs::create_dir_all(sb.home.join(".codex")).unwrap();
    assert_eq!(sb.moat(&["init"]).status.code(), Some(0));

    let command = "npm install left-pad";
    let out = sb.guard("codex", &shell("codex-s1", command));
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let d = hook_output(&out);
    assert_eq!(d["permissionDecision"], "deny", "{d}");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("[installs]"), "{reason}");
    assert!(reason.contains("moat allow --last"), "{reason}");

    let allow = sb.moat_as_person(&["allow", "--last"]);
    assert_eq!(allow.status.code(), Some(0), "{}", stderr(&allow));
    let out = sb.guard("codex", &shell("codex-s1", command));
    assert_eq!(out.status.code(), Some(0), "approved for the session");
    assert_eq!(hook_output(&out)["permissionDecision"], "allow");

    // Claude Code can ask, so it still receives the `ask` itself.
    let claude = serde_json::json!({
        "session_id": "s-claude", "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": { "command": command }, "tool_use_id": "t1"
    });
    let out = sb.guard("claude-code", &claude.to_string());
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(hook_output(&out)["permissionDecision"], "ask");
}
