//! Self-protection: the policy lock and fail-closed `guard` on tampering.

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
        let sb = Self { _dir: dir, home };
        assert_eq!(sb.moat(&["init"], None).status.code(), Some(0));
        sb
    }

    fn moat(&self, args: &[&str], stdin: Option<&str>) -> Output {
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
        match stdin {
            Some(payload) => child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.as_bytes())
                .unwrap(),
            None => drop(child.stdin.take()),
        }
        child.wait_with_output().unwrap()
    }

    fn guard_read_src(&self) -> Value {
        let payload = fixture("claude-code/read.json");
        let out = self.moat(&["guard", "--host", "claude-code"], Some(&payload));
        let doc: Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
        let mut d = doc["hookSpecificOutput"].clone();
        d["exit"] = Value::from(out.status.code().unwrap_or(-1));
        d
    }

    fn policy(&self) -> PathBuf {
        self.home.join(".moat/policy.yaml")
    }

    fn lock(&self) -> PathBuf {
        self.home.join(".moat/policy.lock")
    }

    fn settings(&self) -> PathBuf {
        self.home.join(".claude/settings.json")
    }
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hosts")
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
fn init_writes_a_lock_covering_policy_and_hooks() {
    let sb = Sandbox::new();
    let lock: Value = serde_json::from_str(&std::fs::read_to_string(sb.lock()).unwrap()).unwrap();
    let entries = lock["entries"].as_object().unwrap();
    assert_eq!(entries.len(), 3, "{entries:?}");
    assert!(entries.keys().any(|k| k.ends_with("policy.yaml")));
    assert!(entries.keys().any(|k| k.ends_with("environment.json")));
    assert!(entries.keys().any(|k| k.ends_with("settings.json")));
}

#[test]
fn edited_policy_makes_guard_fail_closed_until_repinned() {
    let sb = Sandbox::new();
    assert_eq!(sb.guard_read_src()["permissionDecision"], "allow");

    let mut policy = std::fs::read_to_string(sb.policy()).unwrap();
    policy.push_str("\n# tampered by an agent\n");
    std::fs::write(sb.policy(), policy).unwrap();

    let d = sb.guard_read_src();
    assert_eq!(d["permissionDecision"], "deny");
    assert_eq!(d["exit"], 2);
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("kernel-integrity"), "{reason}");
    assert!(reason.contains("policy.yaml"), "{reason}");

    assert_eq!(
        sb.moat(&["init"], None).status.code(),
        Some(0),
        "init re-pins"
    );
    assert_eq!(sb.guard_read_src()["permissionDecision"], "allow");
}

#[test]
fn removed_hook_file_is_detected() {
    let sb = Sandbox::new();
    std::fs::remove_file(sb.settings()).unwrap();
    let d = sb.guard_read_src();
    assert_eq!(d["permissionDecision"], "deny");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("settings.json is missing")
    );
}

#[test]
fn missing_lock_denies_and_points_to_init() {
    let sb = Sandbox::new();
    std::fs::remove_file(sb.lock()).unwrap();
    let d = sb.guard_read_src();
    assert_eq!(d["permissionDecision"], "deny");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("moat init")
    );
}

#[test]
fn status_reports_lock_state() {
    let sb = Sandbox::new();
    let out = sb.moat(&["status"], None);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("lock"));
    std::fs::write(sb.policy(), "version: 1\n").unwrap();
    let out = sb.moat(&["status"], None);
    assert_eq!(out.status.code(), Some(64));
    assert!(text(&out).contains("was modified"));
}

#[cfg(unix)]
#[test]
fn planted_binary_earlier_on_the_search_path_is_denied() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let early = dir.path().join("early-bin");
    let real = dir.path().join("real-bin");
    for d in [home.join(".claude"), early.clone(), real.clone()] {
        std::fs::create_dir_all(d).unwrap();
    }
    let script = |p: &Path| {
        std::fs::write(p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    script(&real.join("git"));
    let search_path = format!("{}:{}", early.display(), real.display());
    let run = |args: &[&str], stdin: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_moat"))
            .args(args)
            .env_clear()
            .env("PATH", &search_path)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
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
    };
    assert_eq!(run(&["init"], "").status.code(), Some(0));
    let payload = serde_json::json!({
        "session_id": "pin", "cwd": home.to_string_lossy(), "tool_name": "Bash",
        "tool_input": {"command": "git status --short"}, "tool_use_id": "t"
    })
    .to_string();
    let decision = |out: Output| -> Value {
        serde_json::from_str::<Value>(String::from_utf8_lossy(&out.stdout).trim()).unwrap()
            ["hookSpecificOutput"]
            .clone()
    };
    assert_eq!(
        decision(run(&["guard", "--host", "claude-code"], &payload))["permissionDecision"],
        "allow"
    );

    script(&early.join("git"));
    let d = decision(run(&["guard", "--host", "claude-code"], &payload));
    assert_eq!(d["permissionDecision"], "deny");
    let reason = d["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("executables"), "{reason}");
    assert!(reason.contains("early-bin"), "{reason}");
}
