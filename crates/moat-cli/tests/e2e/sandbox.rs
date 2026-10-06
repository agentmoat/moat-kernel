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
        "dry run: nothing was written",
    ] {
        assert!(shown.contains(expected), "{expected}: {shown}");
    }
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
    assert_eq!(claude["settings"]["sandbox"]["enabled"], Value::Bool(true));
    assert!(
        claude["report"]["losses"]
            .as_array()
            .is_some_and(|l| !l.is_empty())
    );
    assert_eq!(doc["default_read_roots"], Value::Bool(false));
}

#[test]
fn a_policy_without_read_roots_uses_the_default_list() {
    let sb = Sandbox::installed(&[".claude"]);
    std::fs::write(sb.home.join(".moat/policy.yaml"), "version: 1\n").unwrap();
    let out = sb.moat(&["sandbox", "show", "--format", "json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let doc = json(&out);
    assert_eq!(doc["default_read_roots"], Value::Bool(true));
    let allow = &doc["hosts"]["claude-code"]["settings"]["sandbox"]["filesystem"]["allowRead"];
    assert!(
        allow
            .as_array()
            .is_some_and(|a| a.contains(&Value::from("/usr"))),
        "{allow}"
    );
}
