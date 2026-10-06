//! Standard tier (ADR-018): host sandbox settings generated from the policy.

use serde_json::Value;

use crate::common::{Sandbox, json, stdout, text};

#[test]
fn show_prints_the_settings_and_their_losses_without_writing() {
    let sb = Sandbox::installed(&[".claude"]);
    let settings = sb.home.join(".claude/settings.json");
    let before = std::fs::read(&settings).unwrap();
    let out = sb.moat(&["sandbox", "show"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let shown = stdout(&out);
    for expected in [
        "\"failIfUnavailable\": true",
        "\"allowUnsandboxedCommands\": false",
        "\"blockReadsOutsideWorkingDirectories\": true",
        "/**/.env",
        "stricter: fs.read `secrets-paths`",
        "wider:    fs.read `sandbox.read_roots`",
        "wider:    fs.write `claude-code.git-internals`",
        "\"/**/.git/hooks\"",
        "\"/**/.git/config\"",
        "dry run: nothing was written",
    ] {
        assert!(shown.contains(expected), "{expected}: {shown}");
    }
    assert!(!shown.contains("\"/**/.git\""), "git commit works: {shown}");
    let home = sb.home.to_string_lossy().replace('\\', "/");
    assert!(shown.contains(&format!("{home}/.ssh")), "{shown}");
    assert_eq!(
        std::fs::read(&settings).unwrap(),
        before,
        "show writes nothing"
    );

    let out = sb.moat(&["sandbox", "show", "--format", "json"]);
    let doc = json(&out);
    let claude = &doc["hosts"]["claude-code"];
    assert_eq!(
        settings_json(claude)["sandbox"]["enabled"],
        Value::Bool(true)
    );
    assert!(
        claude["report"]["losses"]
            .as_array()
            .is_some_and(|l| !l.is_empty())
    );
    let codex = doc["hosts"]["codex"]["settings"]
        .as_str()
        .unwrap_or_default();
    for expected in [
        "default_permissions = \"moat\"",
        "[permissions.moat.filesystem]",
        "network_proxy = true",
    ] {
        assert!(codex.contains(expected), "{expected}: {codex}");
    }
    assert_eq!(doc["default_read_roots"], Value::Bool(false));
}

/// The Claude Code settings `sandbox show --format json` prints, parsed.
fn settings_json(host: &Value) -> Value {
    serde_json::from_str(host["settings"].as_str().unwrap_or_default()).unwrap_or(Value::Null)
}

#[test]
fn a_policy_without_read_roots_uses_the_default_list() {
    let sb = Sandbox::installed(&[".claude"]);
    std::fs::write(sb.home.join(".moat/policy.yaml"), "version: 1\n").unwrap();
    let out = sb.moat(&["sandbox", "show", "--format", "json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let doc = json(&out);
    assert_eq!(doc["default_read_roots"], Value::Bool(true));
    let settings = settings_json(&doc["hosts"]["claude-code"]);
    let allow = &settings["sandbox"]["filesystem"]["allowRead"];
    assert!(
        allow
            .as_array()
            .is_some_and(|a| a.contains(&Value::from("/usr"))),
        "{allow}"
    );
}
