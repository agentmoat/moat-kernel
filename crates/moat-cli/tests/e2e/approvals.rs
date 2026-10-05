//! Session grants and the permanent allow overlay as seen by `guard`.

use serde_json::Value;

use crate::common::{Sandbox, bash_payload, hook_output, text};

/// The hook decision for one Bash call in the sandbox's project.
fn decide(sb: &Sandbox, session: &str, command: &str) -> Value {
    hook_output(&sb.guard(
        "claude-code",
        &bash_payload(session, &sb.project(), command),
    ))
}

/// Write a state file directly, as a person (or an attacker) editing it would.
fn write_state(sb: &Sandbox, relative: &str, contents: &str) {
    let path = sb.home.join(".moat").join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

#[test]
fn init_pins_grants_and_overlay() {
    let sb = Sandbox::installed(&[".claude"]);
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
    let sb = Sandbox::installed(&[".claude"]);
    assert_eq!(
        decide(&sb, "s1", "npm install left-pad-pro")["permissionDecision"],
        "ask"
    );

    write_state(
        &sb,
        "approvals.json",
        r#"{"version":1,"entries":[{"host":"claude-code","session_id":"s1","command":"npm install left-pad-pro","granted_at_ms":0}]}"#,
    );
    let tampered = decide(&sb, "s1", "npm install left-pad-pro");
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

    assert_eq!(sb.moat(&["init"]).status.code(), Some(0), "init re-pins");
    let granted = decide(&sb, "s1", "npm install left-pad-pro");
    assert_eq!(granted["permissionDecision"], "allow", "{granted}");
    assert!(
        granted["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("approved-session")
    );
    assert_eq!(
        decide(&sb, "s2", "npm install left-pad-pro")["permissionDecision"],
        "ask"
    );
    assert_eq!(
        decide(&sb, "s1", "npm install left-pad-pro --save-dev")["permissionDecision"],
        "ask"
    );
    assert_eq!(
        decide(&sb, "s1", "cat ~/.ssh/id_rsa")["permissionDecision"],
        "deny",
        "grants never beat deny"
    );
}

#[test]
fn permanent_overlay_rules_merge_into_the_policy() {
    let sb = Sandbox::installed(&[".claude"]);
    write_state(
        &sb,
        "policy.d/approved.yaml",
        "version: 1\nallow:\n  - id: approved-1\n    reason: test\n    shell: ['pip install requests']\n",
    );
    assert_eq!(sb.moat(&["init"]).status.code(), Some(0));
    let d = decide(&sb, "any", "pip install requests");
    assert_eq!(d["permissionDecision"], "allow", "{d}");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("approved-1")
    );

    write_state(
        &sb,
        "policy.d/approved.yaml",
        "version: 1\nallow:\n  - id: evil\n    shell: ['*']\n",
    );
    assert_eq!(sb.moat(&["init"]).status.code(), Some(0));
    let d = decide(&sb, "any", "terraform apply");
    assert_eq!(
        d["permissionDecision"], "deny",
        "a malformed overlay fails closed: {d}"
    );
}

#[test]
fn allow_requires_a_terminal() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["allow", "npm install x", "--always"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(text(&out).contains("must be run by a person in a terminal"));
    assert!(
        !sb.home.join(".moat/policy.d/approved.yaml").exists()
            || std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml"))
                .unwrap()
                .contains("allow: []")
    );
}
