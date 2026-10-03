//! `moat replay` and `moat report` over events produced by real `guard` calls.

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

    fn bash(&self, session: &str, command: &str) {
        let payload = serde_json::json!({
            "session_id": session, "cwd": self.project.to_string_lossy(),
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "tool_use_id": "t"
        })
        .to_string();
        self.moat(&["guard", "--host", "claude-code"], &payload);
    }

    fn seed(&self) {
        self.bash("alpha", "git status --short");
        self.bash("alpha", "npm install left-pad-pro");
        self.bash("alpha", "cat ~/.ssh/id_rsa");
        self.bash("beta", "cargo test");
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
fn replay_groups_sessions_into_a_timeline() {
    let sb = Sandbox::new();
    sb.seed();
    let out = sb.moat(&["replay"], "");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("alpha"), "{t}");
    assert!(t.contains("beta"), "{t}");
    assert!(t.contains("├─") && t.contains("└─"), "{t}");
    assert!(
        t.contains("✔") && t.contains("❓") && t.contains("⛔"),
        "{t}"
    );
    assert!(t.contains("secrets-paths"), "{t}");
    assert!(
        t.find("alpha").unwrap() < t.find("beta").unwrap(),
        "oldest session first"
    );
}

#[test]
fn replay_filters_by_session_host_and_window() {
    let sb = Sandbox::new();
    sb.seed();
    let one = text(&sb.moat(&["replay", "--session", "beta"], ""));
    assert!(
        one.contains("cargo test") && !one.contains("left-pad-pro"),
        "{one}"
    );

    let json: Value =
        serde_json::from_slice(&sb.moat(&["replay", "--format", "json"], "").stdout).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2);
    assert_eq!(json[0]["session_id"], "alpha");
    assert_eq!(json[0]["events"].as_array().unwrap().len(), 3);

    let none = text(&sb.moat(&["replay", "--host", "cursor"], ""));
    assert!(none.contains("no sessions"), "{none}");

    let missing = sb.moat(&["replay", "--session", "nope"], "");
    assert_eq!(missing.status.code(), Some(64));
    let bad = sb.moat(&["replay", "--since", "soon"], "");
    assert_eq!(bad.status.code(), Some(64));
    assert!(text(&bad).contains("time window"));
}

#[test]
fn report_summarises_the_window() {
    let sb = Sandbox::new();
    sb.seed();
    let out = sb.moat(&["report"], "");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("4 decisions"), "{t}");
    assert!(
        t.contains("2 allowed") && t.contains("1 asked") && t.contains("1 denied"),
        "{t}"
    );
    assert!(t.contains("secrets-paths") && t.contains("installs"), "{t}");
    assert!(t.contains("claude-code"), "{t}");

    let json: Value = serde_json::from_slice(
        &sb.moat(&["report", "--format", "json", "--since", "today"], "")
            .stdout,
    )
    .unwrap();
    assert_eq!(json["total"], 4);
    assert_eq!(json["sessions"], 2);
    assert_eq!(json["by_host"]["claude-code"], 4);

    let empty = text(&sb.moat(&["report", "--host", "codex"], ""));
    assert!(empty.contains("0 decisions"), "{empty}");
}
