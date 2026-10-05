//! End-to-end tests of `moat init`, `moat guard`, `moat show` and `moat status`
//! inside an isolated HOME.

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
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        Self { _dir: dir, home }
    }

    fn moat(&self, args: &[&str]) -> Output {
        self.moat_with_stdin(args, None)
    }

    fn moat_with_stdin(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_moat"));
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawning moat");
        if let Some(payload) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.as_bytes())
                .unwrap();
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().unwrap()
    }

    fn guard(&self, host: &str, payload: &str) -> Output {
        self.moat_with_stdin(&["guard", "--host", host], Some(payload))
    }

    fn settings(&self) -> Value {
        let text = std::fs::read_to_string(self.home.join(".claude/settings.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hosts")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn decision(out: &Output) -> Value {
    let doc: Value = serde_json::from_str(stdout(out).trim()).expect("hook response is JSON");
    doc["hookSpecificOutput"].clone()
}

#[test]
fn init_creates_state_and_installs_claude_code_hook() {
    let sb = Sandbox::new();
    let out = sb.moat(&["init"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(sb.home.join(".moat/policy.yaml").is_file());
    assert!(sb.home.join(".moat/audit.db").is_file());

    let hooks = &sb.settings()["hooks"]["PreToolUse"];
    assert_eq!(hooks.as_array().unwrap().len(), 1);
    assert_eq!(
        hooks[0]["hooks"][0]["args"],
        serde_json::json!(["guard", "--host", "claude-code"])
    );
    let command = hooks[0]["hooks"][0]["command"].as_str().unwrap();
    assert!(
        command.ends_with("moat") || command.ends_with("moat.exe"),
        "{command}"
    );

    let again = sb.moat(&["init"]);
    assert_eq!(again.status.code(), Some(0));
    assert!(stdout(&again).contains("unchanged"));
    assert!(stdout(&again).contains("(kept)"));
    assert_eq!(
        sb.settings()["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let status = sb.moat(&["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", stdout(&status));
    assert!(stdout(&status).contains("✔ installed"));
}

#[test]
fn init_dry_run_touches_nothing() {
    let sb = Sandbox::new();
    let out = sb.moat(&["init", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("would"));
    assert!(!sb.home.join(".moat").exists());
    assert!(!sb.home.join(".claude/settings.json").exists());
}

#[test]
fn guard_denies_secret_exfiltration_and_records_it() {
    let sb = Sandbox::new();
    sb.moat(&["init"]);

    let out = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    assert_eq!(out.status.code(), Some(2));
    let d = decision(&out);
    assert_eq!(d["hookEventName"], "PreToolUse");
    assert_eq!(d["permissionDecision"], "deny");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("secrets-paths")
    );
    assert!(stderr(&out).contains("moat show "));

    let shown = sb.moat(&["show", "--recent", "1"]);
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    let text = stdout(&shown);
    assert!(text.contains("deny"));
    assert!(text.contains("curl -d @~/.ssh/id_rsa"));

    let id = stderr(&out)
        .lines()
        .find_map(|l| l.strip_prefix("moat: trace "))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("trace id")
        .to_owned();
    let detail = sb.moat(&["show", &id]);
    assert_eq!(detail.status.code(), Some(0));
    assert!(stdout(&detail).contains("session 7c1e4b2a"));
    assert!(stdout(&detail).contains("secrets-paths"));

    let json = sb.moat(&["show", &id, "--format", "json"]);
    let events: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(events[0]["verdict"], "deny");
    assert_eq!(events[0]["tool"], "Bash");
}

#[test]
fn guard_allows_ordinary_work_and_asks_for_installs() {
    let sb = Sandbox::new();
    sb.moat(&["init"]);
    let project = sb.home.join("proj");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let cwd = project.to_string_lossy();

    let payload = |command: &str| {
        serde_json::json!({
            "session_id": "s-allow", "cwd": cwd, "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "t1"
        })
        .to_string()
    };

    let out = sb.guard("claude-code", &payload("git status --short"));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(decision(&out)["permissionDecision"], "allow");

    let out = sb.guard("claude-code", &payload("npm install left-pad-pro"));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(decision(&out)["permissionDecision"], "ask");

    let edit = serde_json::json!({
        "session_id": "s-allow", "cwd": cwd, "tool_name": "Write",
        "tool_input": {"file_path": project.join("src/main.rs").to_string_lossy(), "content": "fn main(){}"}
    });
    let out = sb.guard("claude-code", &edit.to_string());
    assert_eq!(
        decision(&out)["permissionDecision"],
        "allow",
        "{}",
        stderr(&out)
    );

    let since = sb.moat(&["show", "--since", "1h"]);
    assert_eq!(since.status.code(), Some(0), "{}", stderr(&since));
    assert_eq!(
        stdout(&since).lines().count(),
        4,
        "header + three events:\n{}",
        stdout(&since)
    );
    let bad = sb.moat(&["show", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(64));
    assert!(stderr(&bad).contains("time window"));

    let session = sb.moat(&["show", "--session", "s-allow"]);
    assert_eq!(
        stdout(&session).lines().count(),
        4,
        "header + three events:\n{}",
        stdout(&session)
    );
}

#[test]
fn guard_passes_ungoverned_tools_through() {
    let sb = Sandbox::new();
    sb.moat(&["init"]);
    let out = sb.guard("claude-code", &fixture("claude-code/ungoverned.json"));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(decision(&out)["permissionDecision"], "allow");
    assert!(
        decision(&out)["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("ungoverned")
    );
}

#[test]
fn guard_fails_closed() {
    let sb = Sandbox::new();

    let out = sb.guard("claude-code", &fixture("claude-code/read.json"));
    assert_eq!(out.status.code(), Some(2), "no policy installed must deny");
    assert_eq!(decision(&out)["permissionDecision"], "deny");
    assert!(
        decision(&out)["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("moat init")
    );

    sb.moat(&["init"]);
    for payload in ["", "not json", r#"{"tool_name":"Bash","tool_input":{}}"#] {
        let out = sb.guard("claude-code", payload);
        assert_eq!(out.status.code(), Some(2), "payload {payload:?} must deny");
        assert_eq!(decision(&out)["permissionDecision"], "deny");
        assert_eq!(
            decision(&out)["permissionDecisionReason"]
                .as_str()
                .map(|r| r.contains("kernel-error")),
            Some(true)
        );
    }

    let out = sb.moat_with_stdin(&["guard", "--host", "windsurf"], Some("{}"));
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn deleted_audit_log_denies_instead_of_recreating_it() {
    let sb = Sandbox::new();
    sb.moat(&["init"]);
    let audit = sb.home.join(".moat/audit.db");
    let before = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    assert!(
        !stderr(&before).contains("audit log unavailable"),
        "{}",
        stderr(&before)
    );

    std::fs::remove_file(&audit).unwrap();
    let out = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(decision(&out)["permissionDecision"], "deny");
    let reason = decision(&out)["permissionDecisionReason"].to_string();
    assert!(reason.contains("kernel-error"), "{reason}");
    assert!(reason.contains("audit log unavailable"), "{reason}");
    assert!(!audit.exists(), "guard must not quietly create a fresh log");
}

#[cfg(unix)]
#[test]
fn unwritable_audit_log_denies() {
    use std::os::unix::fs::PermissionsExt as _;
    let sb = Sandbox::new();
    sb.moat(&["init"]);
    let audit = sb.home.join(".moat/audit.db");
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = sb.guard("claude-code", &fixture("claude-code/bash.json"));
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(decision(&out)["permissionDecision"], "deny");
    assert!(
        stderr(&out).contains("audit log unavailable"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn mcp_arguments_are_checked_as_paths() {
    let sb = Sandbox::new();
    sb.moat(&["init"]);
    let out = sb.guard(
        "claude-code",
        &fixture("claude-code/mcp_filesystem_read_secret.json"),
    );
    assert_eq!(out.status.code(), Some(2));
    let d = decision(&out);
    assert_eq!(d["permissionDecision"], "deny");
    let reason = d["permissionDecisionReason"].to_string();
    assert!(reason.contains("secrets-paths"), "{reason}");
}

#[test]
fn codex_payloads_use_the_same_contract() {
    let sb = Sandbox::new();
    std::fs::create_dir_all(sb.home.join(".codex")).unwrap();
    let out = sb.moat(&["init"]);
    assert!(stdout(&out).contains("Codex"), "{}", stdout(&out));
    assert!(sb.home.join(".codex/hooks.json").is_file());

    let out = sb.guard("codex", &fixture("codex/pretooluse-shell.json"));
    assert_eq!(out.status.code(), Some(2));
    assert!(
        decision(&out)["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("env-poison")
    );
}

#[test]
fn status_reports_missing_installation() {
    let sb = Sandbox::new();
    let out = sb.moat(&["status"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(stdout(&out).contains("run `moat init`"));
}
