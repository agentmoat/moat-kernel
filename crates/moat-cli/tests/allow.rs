//! `moat allow` and `moat doctor --accept` success paths, end to end.
//!
//! Both commands require a terminal. Debug builds honour `MOAT_ASSUME_TTY=1`
//! (see `terminal.rs`), which these tests set only for the commands a person
//! would type; `guard` runs without it, exactly as a hook does.

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
        assert_eq!(sb.run(&["init"], "", false).status.code(), Some(0));
        sb
    }

    fn run(&self, args: &[&str], stdin: &str, person: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_moat"));
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if person {
            cmd.env("MOAT_ASSUME_TTY", "1");
        }
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// A person at the terminal.
    fn person(&self, args: &[&str]) -> Output {
        self.run(args, "", true)
    }

    /// The hook: verdict and rule ids for one Bash call.
    fn guard(&self, session: &str, command: &str) -> (String, String) {
        let payload = serde_json::json!({
            "session_id": session, "cwd": self.project.to_string_lossy(),
            "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "t"
        })
        .to_string();
        let out = self.run(&["guard", "--host", "claude-code"], &payload, false);
        let doc: Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
        let d = &doc["hookSpecificOutput"];
        (
            d["permissionDecision"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            d["permissionDecisionReason"].to_string(),
        )
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const INSTALL: &str = "npm install left-pad";

#[test]
fn allow_last_grants_the_session_and_repins() {
    let sb = Sandbox::new();
    assert_eq!(sb.guard("s1", INSTALL).0, "ask");

    let out = sb.person(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        text(&out).contains("session s1 on claude-code may run"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));

    let (verdict, reason) = sb.guard("s1", INSTALL);
    assert_eq!(verdict, "allow", "{reason}");
    assert!(reason.contains("approved-session"), "{reason}");
    assert_eq!(sb.guard("s2", INSTALL).0, "ask", "grants are per session");
}

#[test]
fn allow_explicit_session_grant() {
    let sb = Sandbox::new();
    let out = sb.person(&["allow", INSTALL, "--host", "claude-code", "--session", "s9"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(sb.guard("s9", INSTALL).0, "allow");
    assert_eq!(sb.guard("s1", INSTALL).0, "ask");
}

#[test]
fn allow_always_writes_the_overlay_and_keeps_the_lock_intact() {
    let sb = Sandbox::new();
    assert_eq!(sb.guard("s1", INSTALL).0, "ask");
    let out = sb.person(&["allow", "--last", "--always"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    let overlay = std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml")).unwrap();
    assert!(
        overlay.contains("approved-1") && overlay.contains(INSTALL),
        "{overlay}"
    );

    let (verdict, reason) = sb.guard("another-session", INSTALL);
    assert_eq!(
        verdict, "allow",
        "the overlay is re-pinned, not drift: {reason}"
    );
    assert!(reason.contains("approved-1"), "{reason}");
}

#[test]
fn doctor_accept_repins_after_a_person_edits_the_policy() {
    let sb = Sandbox::new();
    let policy = sb.home.join(".moat/policy.yaml");
    let mut text_now = std::fs::read_to_string(&policy).unwrap();
    text_now.push_str("\n# edited by the owner\n");
    std::fs::write(&policy, text_now).unwrap();
    let (verdict, reason) = sb.guard("s1", "git status");
    assert_eq!(verdict, "deny");
    assert!(reason.contains("kernel-integrity"), "{reason}");

    let out = sb.person(&["doctor", "--accept"]);
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));
    assert_eq!(sb.guard("s1", "git status").0, "allow");
}

#[test]
fn hooks_without_a_terminal_are_still_refused() {
    let sb = Sandbox::new();
    let out = sb.run(&["allow", INSTALL, "--always"], "", false);
    assert_ne!(out.status.code(), Some(0));
    assert!(text(&out).contains("must be run by a person in a terminal"));
}
