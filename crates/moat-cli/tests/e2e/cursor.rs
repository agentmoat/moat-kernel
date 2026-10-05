//! Cursor integration end to end: `init` writes a fail-closed `hooks.json`,
//! `guard --host cursor` answers in Cursor's permission format.

use serde_json::Value;

use crate::common::{Sandbox, fixture as host_fixture, json, text};

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".cursor"])
}

fn guard(sb: &Sandbox, payload: &str) -> (Option<i32>, Value) {
    let out = sb.guard("cursor", payload);
    (out.status.code(), json(&out))
}

fn fixture(name: &str) -> String {
    host_fixture(&format!("cursor/{name}"))
}

#[test]
fn init_installs_fail_closed_hooks_for_every_cursor_event() {
    let sb = sandbox();
    let root: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".cursor/hooks.json")).unwrap())
            .unwrap();
    assert_eq!(root["version"], 1);
    for event in [
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "preToolUse",
    ] {
        let entries = root["hooks"][event]
            .as_array()
            .unwrap_or_else(|| panic!("{event} missing"));
        assert_eq!(entries.len(), 1, "{event}");
        assert_eq!(entries[0]["failClosed"], true, "{event}");
        assert!(
            entries[0]["command"]
                .as_str()
                .unwrap()
                .ends_with("guard --host cursor"),
            "{event}"
        );
    }
    let status = sb.moat(&["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", text(&status));
    assert!(text(&status).contains("Cursor"));
}

#[test]
fn shell_exfiltration_is_denied_in_cursor_format() {
    let sb = sandbox();
    let (code, doc) = guard(&sb, &fixture("beforeShellExecution.json"));
    assert_eq!(code, Some(2));
    assert_eq!(doc["permission"], "deny");
    let msg = doc["user_message"].as_str().unwrap();
    assert!(msg.contains("secrets-paths"), "{msg}");
    assert_eq!(doc["agent_message"], doc["user_message"]);
}

#[test]
fn secret_file_read_and_safe_mcp_tool() {
    let sb = sandbox();
    let read = serde_json::json!({
        "conversation_id": "conv-42", "generation_id": "gen-9",
        "hook_event_name": "beforeReadFile", "cursor_version": "2.3.1",
        "workspace_roots": [sb.home.to_string_lossy()],
        "file_path": sb.home.join(".aws").join("credentials").to_string_lossy(),
        "content": "[default]", "attachments": []
    })
    .to_string();
    let (code, doc) = guard(&sb, &read);
    assert_eq!(code, Some(2), "{doc}");
    assert_eq!(doc["permission"], "deny");
    assert!(
        doc["user_message"]
            .as_str()
            .unwrap()
            .contains("secrets-paths"),
        "{doc}"
    );

    let (code, doc) = guard(&sb, &fixture("beforeMCPExecution.json"));
    assert_eq!(code, Some(0));
    assert_eq!(doc["permission"], "allow", "{doc}");
}

#[test]
fn mcp_fetch_to_an_unlisted_host_is_denied() {
    let sb = sandbox();
    let (code, doc) = guard(&sb, &fixture("beforeMCPExecution-fetch.json"));
    assert_eq!(code, Some(2));
    assert_eq!(doc["permission"], "deny");
    let msg = doc["agent_message"].to_string();
    assert!(msg.contains("default.net"), "{msg}");
}

/// A safe-listed tool whose arguments cannot be read must not be judged by
/// its name alone: the path it would read is unknown.
#[test]
fn mcp_arguments_that_do_not_parse_fail_closed() {
    let sb = sandbox();
    let (code, doc) = guard(&sb, &fixture("beforeMCPExecution-malformed.json"));
    assert_eq!(code, Some(2));
    assert_eq!(doc["permission"], "deny");
    let msg = doc["agent_message"].to_string();
    assert!(msg.contains("arguments cannot be checked"), "{msg}");
}

#[test]
fn pre_tool_use_write_inside_the_workspace_is_allowed() {
    let sb = sandbox();
    let project = sb.home.join("proj");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let payload = serde_json::json!({
        "conversation_id": "c", "hook_event_name": "preToolUse",
        "workspace_roots": [project.to_string_lossy()], "cwd": project.to_string_lossy(),
        "tool_name": "Write",
        "tool_input": {"file_path": project.join("src/main.rs").to_string_lossy(), "content": ""},
        "tool_use_id": "tu-9"
    })
    .to_string();
    let (code, doc) = guard(&sb, &payload);
    assert_eq!(code, Some(0));
    assert_eq!(doc["permission"], "allow", "{doc}");

    let (code, doc) = guard(&sb, &fixture("preToolUse-shell.json"));
    assert_eq!(code, Some(0));
    assert_eq!(doc["permission"], "allow");
    assert!(doc["user_message"].as_str().unwrap().contains("ungoverned"));
}

#[test]
fn unknown_cursor_event_fails_closed() {
    let sb = sandbox();
    let (code, doc) = guard(
        &sb,
        r#"{"hook_event_name":"afterFileEdit","file_path":"/p/x"}"#,
    );
    assert_eq!(code, Some(2));
    assert_eq!(doc["permission"], "deny");
    assert!(
        doc["user_message"]
            .as_str()
            .unwrap()
            .contains("kernel-error")
    );
}
