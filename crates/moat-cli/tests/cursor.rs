//! Cursor integration end to end: `init` writes a fail-closed `hooks.json`,
//! `guard --host cursor` answers in Cursor's permission format.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

struct Sandbox {
    _dir: TempDir,
    home: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        let sb = Self { _dir: dir, home };
        let out = sb.moat(&["init"], "");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        sb
    }

    fn moat(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_moat"))
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn guard(&self, payload: &str) -> (Option<i32>, Value) {
        let out = self.moat(&["guard", "--host", "cursor"], payload);
        let doc = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .unwrap_or(Value::Null);
        (out.status.code(), doc)
    }
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hosts/cursor")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn init_installs_fail_closed_hooks_for_every_cursor_event() {
    let sb = Sandbox::new();
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
    let status = sb.moat(&["status"], "");
    assert_eq!(status.status.code(), Some(0), "{}", text(&status));
    assert!(text(&status).contains("Cursor"));
}

#[test]
fn shell_exfiltration_is_denied_in_cursor_format() {
    let sb = Sandbox::new();
    let (code, doc) = sb.guard(&fixture("beforeShellExecution.json"));
    assert_eq!(code, Some(2));
    assert_eq!(doc["permission"], "deny");
    let msg = doc["user_message"].as_str().unwrap();
    assert!(msg.contains("secrets-paths"), "{msg}");
    assert_eq!(doc["agent_message"], doc["user_message"]);
}

#[test]
fn secret_file_read_and_safe_mcp_tool() {
    let sb = Sandbox::new();
    let read = serde_json::json!({
        "conversation_id": "conv-42", "generation_id": "gen-9",
        "hook_event_name": "beforeReadFile", "cursor_version": "2.3.1",
        "workspace_roots": [sb.home.to_string_lossy()],
        "file_path": sb.home.join(".aws").join("credentials").to_string_lossy(),
        "content": "[default]", "attachments": []
    })
    .to_string();
    let (code, doc) = sb.guard(&read);
    assert_eq!(code, Some(2), "{doc}");
    assert_eq!(doc["permission"], "deny");
    assert!(
        doc["user_message"]
            .as_str()
            .unwrap()
            .contains("secrets-paths"),
        "{doc}"
    );

    let (code, doc) = sb.guard(&fixture("beforeMCPExecution.json"));
    assert_eq!(code, Some(0));
    assert_eq!(doc["permission"], "allow", "{doc}");
}

#[test]
fn pre_tool_use_write_inside_the_workspace_is_allowed() {
    let sb = Sandbox::new();
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
    let (code, doc) = sb.guard(&payload);
    assert_eq!(code, Some(0));
    assert_eq!(doc["permission"], "allow", "{doc}");

    let (code, doc) = sb.guard(&fixture("preToolUse-shell.json"));
    assert_eq!(code, Some(0));
    assert_eq!(doc["permission"], "allow");
    assert!(doc["user_message"].as_str().unwrap().contains("ungoverned"));
}

#[test]
fn unknown_cursor_event_fails_closed() {
    let sb = Sandbox::new();
    let (code, doc) = sb.guard(r#"{"hook_event_name":"afterFileEdit","file_path":"/p/x"}"#);
    assert_eq!(code, Some(2));
    assert_eq!(doc["permission"], "deny");
    assert!(
        doc["user_message"]
            .as_str()
            .unwrap()
            .contains("kernel-error")
    );
}
