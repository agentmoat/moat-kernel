//! Standard tier (ADR-018): `init` and `sandbox sync` write the host sandboxes,
//! the lock pins them, and `doctor` names every weakened setting.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use crate::common::{Sandbox, fixture, hook_output, stdout, text};

fn claude_settings(sb: &Sandbox) -> PathBuf {
    sb.home.join(".claude/settings.json")
}

fn codex_config(sb: &Sandbox) -> PathBuf {
    sb.home.join(".codex/config.toml")
}

/// Both hosts present, each with a setting of the user's own, then `init`.
fn installed() -> Sandbox {
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    fs::write(
        claude_settings(&sb),
        r#"{"theme":"dark","permissions":{"allow":["Bash(ls)"]}}"#,
    )
    .unwrap();
    fs::write(codex_config(&sb), "# my settings\nmodel = \"o3\"\n").unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    sb
}

fn settings(sb: &Sandbox) -> Value {
    serde_json::from_str(&fs::read_to_string(claude_settings(sb)).unwrap()).unwrap()
}

fn codex_shell(command: &str) -> String {
    serde_json::json!({
        "session_id": "s", "turn_id": "t", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_use_id": "c", "tool_input": { "command": command },
    })
    .to_string()
}

fn verdict(out: &std::process::Output) -> String {
    hook_output(out)["permissionDecision"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn init_writes_both_sandboxes_keeps_user_settings_and_pins_them() {
    let sb = installed();
    let claude = settings(&sb);
    assert_eq!(claude["sandbox"]["enabled"], Value::Bool(true));
    assert_eq!(claude["sandbox"]["failIfUnavailable"], Value::Bool(true));
    assert_eq!(
        claude["sandbox"]["allowUnsandboxedCommands"],
        Value::Bool(false)
    );
    assert_eq!(
        claude["permissions"]["blockReadsOutsideWorkingDirectories"],
        Value::Bool(true)
    );
    assert_eq!(claude["theme"], "dark");
    assert_eq!(claude["permissions"]["allow"][0], "Bash(ls)");
    assert!(
        claude["hooks"]["PreToolUse"].is_array(),
        "hooks still installed"
    );

    let codex = fs::read_to_string(codex_config(&sb)).unwrap();
    for expected in [
        "# my settings",
        "model = \"o3\"",
        "default_permissions = \"moat\"",
        "[permissions.moat.filesystem]",
    ] {
        assert!(codex.contains(expected), "{expected}: {codex}");
    }
    let lock: Value =
        serde_json::from_str(&fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap())
            .unwrap();
    assert_eq!(
        lock["codex_profiles"].as_object().map(serde_json::Map::len),
        Some(1),
        "{lock}"
    );

    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(0), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("Codex            sandbox matches the policy"),
        "{}",
        text(&doctor)
    );
    assert!(
        stdout(&doctor).contains("wider; --verbose for details)"),
        "{}",
        text(&doctor)
    );
    assert!(
        !stdout(&doctor).contains("stricter: "),
        "the list waits for --verbose"
    );
    let verbose = sb.moat(&["doctor", "--verbose"]);
    assert!(
        stdout(&verbose).contains("stricter: fs.write `codex.git`"),
        "losses are printed with --verbose"
    );
}

#[test]
fn sync_is_person_only_and_idempotent() {
    let sb = installed();
    let refused = sb.moat(&["sandbox", "sync"]);
    assert_eq!(refused.status.code(), Some(64), "{}", text(&refused));
    assert!(text(&refused).contains("must be run by a person"));

    let before = (
        fs::read(claude_settings(&sb)).unwrap(),
        fs::read(codex_config(&sb)).unwrap(),
    );
    let out = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("(sandbox unchanged)"),
        "{}",
        stdout(&out)
    );
    let after = (
        fs::read(claude_settings(&sb)).unwrap(),
        fs::read(codex_config(&sb)).unwrap(),
    );
    assert_eq!(before, after, "sync after init changes nothing");
    assert_eq!(sb.moat(&["status"]).status.code(), Some(0));
}

#[test]
fn a_tampered_sandbox_block_denies_every_call_and_sync_refuses_over_it() {
    let sb = installed();
    let mut claude = settings(&sb);
    claude["sandbox"]["excludedCommands"] = serde_json::json!(["curl"]);
    fs::write(claude_settings(&sb), claude.to_string()).unwrap();

    let out = sb.guard("claude-code", &fixture("claude-code/read.json"));
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("kernel-integrity"), "{}", text(&out));

    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(64));
    assert!(
        stdout(&doctor).contains("sandbox.excludedCommands is not empty"),
        "{}",
        stdout(&doctor)
    );

    let sync = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(sync.status.code(), Some(64), "{}", text(&sync));
    assert!(text(&sync).contains("drift"), "{}", text(&sync));
}

#[test]
fn codex_may_edit_its_own_keys_but_not_the_moat_profile() {
    let sb = installed();
    let path = codex_config(&sb);
    // What Codex writes itself when a project is trusted.
    let trusted =
        fs::read_to_string(&path).unwrap() + "\n[projects.\"/w\"]\ntrust_level = \"trusted\"\n";
    fs::write(&path, trusted).unwrap();
    let out = sb.guard("codex", &codex_shell("ls"));
    assert_eq!(verdict(&out), "allow", "{}", text(&out));

    let weakened = fs::read_to_string(&path).unwrap().replace(
        "default_permissions = \"moat\"",
        "default_permissions = \":workspace\"",
    );
    fs::write(&path, weakened).unwrap();
    let out = sb.guard("codex", &codex_shell("ls"));
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out).contains("kernel-integrity"), "{}", text(&out));

    let accepted = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(
        stdout(&accepted).contains("lock re-pinned"),
        "{}",
        text(&accepted)
    );
    assert!(
        stdout(&accepted).contains("default_permissions is not \"moat\""),
        "accepting the edit does not hide the weakness: {}",
        stdout(&accepted)
    );
    let out = sb.moat_as_person(&["sandbox", "sync"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("default_permissions = \"moat\"")
    );
    assert_eq!(sb.moat(&["doctor"]).status.code(), Some(0));
}
