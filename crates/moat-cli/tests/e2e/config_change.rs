//! Claude Code `ConfigChange` veto: a pinned hook file that no longer matches the
//! lock is refused for the session; untouched or unpinned files load normally.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::common::{Sandbox, json};

fn sandbox() -> Sandbox {
    Sandbox::installed(&[".claude"])
}

fn settings(sb: &Sandbox) -> PathBuf {
    sb.home.join(".claude/settings.json")
}

/// Send a `ConfigChange` for `path` and return the exit code and response.
fn config_change(sb: &Sandbox, path: &Path, change_type: &str) -> (Option<i32>, Value) {
    let payload = serde_json::json!({
        "session_id": "cfg", "cwd": sb.home.to_string_lossy(),
        "hook_event_name": "ConfigChange", "source": "user_settings",
        "change_type": change_type, "file_path": path.to_string_lossy(),
    });
    let out = sb.guard("claude-code", &payload.to_string());
    (out.status.code(), json(&out))
}

#[test]
fn init_registers_the_config_change_hook() {
    let sb = sandbox();
    let root: Value =
        serde_json::from_str(&std::fs::read_to_string(settings(&sb)).unwrap()).unwrap();
    let entries = root["hooks"]["ConfigChange"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["matcher"],
        "user_settings|project_settings|local_settings"
    );
    assert_eq!(
        entries[0]["hooks"][0]["args"],
        serde_json::json!(["guard", "--host", "claude-code"])
    );
}

#[test]
fn untouched_pinned_file_loads() {
    let sb = sandbox();
    let (code, doc) = config_change(&sb, &settings(&sb), "modified");
    assert_eq!(code, Some(0));
    assert_eq!(doc, serde_json::json!({}));
}

#[test]
fn tampered_pinned_file_is_blocked() {
    let sb = sandbox();
    let mut root: Value =
        serde_json::from_str(&std::fs::read_to_string(settings(&sb)).unwrap()).unwrap();
    root["hooks"].as_object_mut().unwrap().remove("PreToolUse");
    std::fs::write(settings(&sb), root.to_string()).unwrap();

    let (code, doc) = config_change(&sb, &settings(&sb), "modified");
    assert_eq!(code, Some(2));
    assert_eq!(doc["decision"], "block");
    let reason = doc["reason"].as_str().unwrap();
    assert!(reason.contains("kernel-integrity"), "{reason}");
    assert!(reason.contains("settings.json"), "{reason}");

    let shown = sb.moat(&["show", "--recent", "1", "--format", "json"]);
    let events: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(events[0]["tool"], "ConfigChange");
    assert_eq!(events[0]["verdict"], "deny");
}

#[test]
fn deleted_pinned_file_is_blocked() {
    let sb = sandbox();
    std::fs::remove_file(settings(&sb)).unwrap();
    let (code, doc) = config_change(&sb, &settings(&sb), "deleted");
    assert_eq!(code, Some(2));
    assert_eq!(doc["decision"], "block");
}

#[test]
fn unpinned_project_settings_load_and_are_audited() {
    let sb = sandbox();
    let project = sb.home.join("proj/.claude");
    std::fs::create_dir_all(&project).unwrap();
    let file = project.join("settings.json");
    std::fs::write(&file, "{}").unwrap();
    let (code, doc) = config_change(&sb, &file, "created");
    assert_eq!(code, Some(0));
    assert_eq!(doc, serde_json::json!({}));
    let shown = sb.moat(&["show", "--recent", "1"]);
    assert!(String::from_utf8_lossy(&shown.stdout).contains("allow"));
}
