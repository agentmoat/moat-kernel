//! Session grants and the permanent allow overlay as seen by `guard`.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

struct Sandbox {
    _dir: TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let project = home.join("proj");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(project.join(".git")).unwrap();
        let sb = Self {
            _dir: dir,
            home,
            project,
        };
        assert_eq!(sb.moat(&["init"], "").status.code(), Some(0));
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

    fn decide(&self, session: &str, command: &str) -> Value {
        let payload = serde_json::json!({
            "session_id": session, "cwd": self.project.to_string_lossy(),
            "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "t"
        })
        .to_string();
        let out = self.moat(&["guard", "--host", "claude-code"], &payload);
        let doc: Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
        doc["hookSpecificOutput"].clone()
    }

    fn write_private(&self, rel: &str, contents: &str) {
        let path = self.home.join(".moat").join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn init_pins_grants_and_overlay() {
    let sb = Sandbox::new();
    let lock: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
            .unwrap();
    let keys: Vec<&str> = lock["entries"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        keys.iter().any(|k| k.ends_with("approvals.json")),
        "{keys:?}"
    );
    assert!(
        keys.iter().any(|k| k.ends_with("approved.yaml")),
        "{keys:?}"
    );
}

#[test]
fn session_grant_turns_ask_into_allow_for_that_session_only() {
    let sb = Sandbox::new();
    assert_eq!(
        sb.decide("s1", "npm install left-pad-pro")["permissionDecision"],
        "ask"
    );

    sb.write_private(
        "approvals.json",
        r#"{"version":1,"entries":[{"host":"claude-code","session_id":"s1","command":"npm install left-pad-pro","granted_at_ms":0}]}"#,
    );
    let tampered = sb.decide("s1", "npm install left-pad-pro");
    assert_eq!(
        tampered["permissionDecision"], "deny",
        "edited grants break the lock"
    );
    assert!(
        tampered["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("kernel-integrity")
    );

    assert_eq!(
        sb.moat(&["init"], "").status.code(),
        Some(0),
        "init re-pins"
    );
    let granted = sb.decide("s1", "npm install left-pad-pro");
    assert_eq!(granted["permissionDecision"], "allow", "{granted}");
    assert!(
        granted["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("approved-session")
    );
    assert_eq!(
        sb.decide("s2", "npm install left-pad-pro")["permissionDecision"],
        "ask"
    );
    assert_eq!(
        sb.decide("s1", "npm install left-pad-pro --save-dev")["permissionDecision"],
        "ask"
    );
    assert_eq!(
        sb.decide("s1", "cat ~/.ssh/id_rsa")["permissionDecision"],
        "deny",
        "grants never beat deny"
    );
}

#[test]
fn permanent_overlay_rules_merge_into_the_policy() {
    let sb = Sandbox::new();
    sb.write_private(
        "policy.d/approved.yaml",
        "version: 1\nallow:\n  - id: approved-1\n    reason: test\n    shell: ['pip install requests']\n",
    );
    assert_eq!(sb.moat(&["init"], "").status.code(), Some(0));
    let d = sb.decide("any", "pip install requests");
    assert_eq!(d["permissionDecision"], "allow", "{d}");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("approved-1")
    );

    sb.write_private(
        "policy.d/approved.yaml",
        "version: 1\nallow:\n  - id: evil\n    shell: ['*']\n",
    );
    assert_eq!(sb.moat(&["init"], "").status.code(), Some(0));
    let d = sb.decide("any", "terraform apply");
    assert_eq!(
        d["permissionDecision"], "deny",
        "a malformed overlay fails closed: {d}"
    );
}

#[test]
fn allow_requires_a_terminal() {
    let sb = Sandbox::new();
    let out = sb.moat(&["allow", "npm install x", "--always"], "");
    assert_eq!(out.status.code(), Some(64));
    assert!(text(&out).contains("must be run by a person in a terminal"));
    assert!(
        !sb.home.join(".moat/policy.d/approved.yaml").exists()
            || std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml"))
                .unwrap()
                .contains("allow: []")
    );
}
