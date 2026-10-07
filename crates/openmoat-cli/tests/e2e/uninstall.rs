//! `moat init` asks before changing an agent, and `moat uninstall` undoes it.

use std::fs;
use std::path::Path;

use crate::common::{Sandbox, output, stdout, text};

/// `moat init` as a person at a terminal answering `answers`.
fn init_answering(sb: &Sandbox, answers: &str) -> std::process::Output {
    output(
        sb.command().arg("init").env("MOAT_ASSUME_TTY", "1"),
        Some(answers),
    )
}

fn pinned(sb: &Sandbox) -> String {
    fs::read_to_string(sb.home.join(".moat/policy.lock")).unwrap()
}

fn backups_in(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.contains(".moat-"))
        .collect()
}

#[test]
fn init_without_a_terminal_changes_no_agent() {
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    let out = sb.moat(&["init"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stdout(&out).contains("moat init --yes"), "{}", text(&out));
    assert!(sb.home.join(".moat/policy.yaml").is_file());
    assert!(!sb.home.join(".claude/settings.json").exists());
    assert!(!sb.home.join(".codex/hooks.json").exists());
    assert!(!sb.home.join(".codex/config.toml").exists());
}

#[test]
fn init_asks_per_agent_and_changes_only_the_accepted_ones() {
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    let out = init_answering(&sb, "\nn\n");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let shown = stdout(&out);
    assert!(shown.contains("Protect Claude Code ("), "{shown}");
    assert!(shown.contains("Protect Codex ("), "{shown}");
    assert!(shown.contains("Undo anytime: moat uninstall"), "{shown}");
    assert!(sb.home.join(".claude/settings.json").is_file());
    assert!(!sb.home.join(".codex/hooks.json").exists());
    assert!(!sb.home.join(".codex/config.toml").exists());

    let declined = Sandbox::bare(&[".claude"]);
    let out = init_answering(&declined, "");
    assert!(stdout(&out).contains("none accepted"), "{}", text(&out));
    assert!(!declined.home.join(".claude/settings.json").exists());
}

#[test]
fn init_hosts_leaves_other_agents_untouched() {
    let sb = Sandbox::bare(&[".claude", ".codex"]);
    let out = sb.moat(&["init", "--hosts", "claude-code"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(sb.home.join(".claude/settings.json").is_file());
    assert!(
        fs::read_dir(sb.home.join(".codex"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn uninstall_restores_the_original_files_byte_for_byte() {
    let sb = Sandbox::bare(&[".claude", ".codex", ".cursor"]);
    let settings = sb.home.join(".claude/settings.json");
    let codex_config = sb.home.join(".codex/config.toml");
    let claude_original = "{ \"theme\" : \"dark\",\n  \"hooks\": {\"Stop\": []} }\n";
    let codex_original = "# mine\nmodel = \"o3\"\n";
    fs::write(&settings, claude_original).unwrap();
    fs::write(&codex_config, codex_original).unwrap();
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("settings.json.moat-backup"),
        "{}",
        text(&out)
    );
    assert!(pinned(&sb).contains("settings.json"));

    let refused = sb.moat(&["uninstall"]);
    assert_eq!(refused.status.code(), Some(64), "{}", text(&refused));
    assert_ne!(fs::read_to_string(&settings).unwrap(), claude_original);

    let out = sb.moat_as_person(&["uninstall"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stdout(&out).contains("restored from"), "{}", text(&out));
    assert_eq!(fs::read_to_string(&settings).unwrap(), claude_original);
    assert_eq!(fs::read_to_string(&codex_config).unwrap(), codex_original);
    assert!(
        !sb.home.join(".codex/hooks.json").exists(),
        "init created it"
    );
    assert!(
        !sb.home.join(".cursor/hooks.json").exists(),
        "init created it"
    );
    for dir in [".claude", ".codex", ".cursor"] {
        assert!(backups_in(&sb.home.join(dir)).is_empty(), "{dir}");
    }
    assert!(!pinned(&sb).contains("settings.json"), "{}", pinned(&sb));
    assert!(!pinned(&sb).contains("config.toml"), "{}", pinned(&sb));
    assert!(sb.home.join(".moat/policy.yaml").is_file(), "state is kept");

    let again = sb.moat_as_person(&["uninstall"]);
    assert!(stdout(&again).contains("not set up"), "{}", text(&again));
}

#[test]
fn uninstall_keeps_changes_made_since_init() {
    let sb = Sandbox::bare(&[".claude"]);
    let settings = sb.home.join(".claude/settings.json");
    fs::write(&settings, "{\"theme\": \"dark\"}").unwrap();
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(0));
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    doc["model"] = "opus".into();
    fs::write(&settings, doc.to_string()).unwrap();

    let out = sb.moat_as_person(&["uninstall", "--hosts", "claude-code"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stdout(&out).contains("backup kept"), "{}", text(&out));
    let left: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(left, serde_json::json!({"theme": "dark", "model": "opus"}));
}

#[test]
fn uninstall_purge_deletes_the_state_directory() {
    let sb = Sandbox::bare(&[".claude"]);
    assert_eq!(sb.moat(&["init", "--yes"]).status.code(), Some(0));
    let out = sb.moat_as_person(&["uninstall", "--purge"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!sb.home.join(".moat").exists());
    assert!(!sb.home.join(".claude/settings.json").exists());
}
