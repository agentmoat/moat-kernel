//! `moat allow` and `moat doctor --accept` success paths, end to end.
//!
//! Both commands require a terminal. Debug builds honour `MOAT_ASSUME_TTY=1`
//! (see `terminal.rs`), which these tests set only for the commands a person
//! would type; `guard` runs without it, exactly as a hook does.

use crate::common::{Sandbox, bash_payload, hook_output, text};

/// The hook's verdict and reason for one Bash call in the sandbox's project.
fn guard(sb: &Sandbox, session: &str, command: &str) -> (String, String) {
    let d = hook_output(&sb.guard(
        "claude-code",
        &bash_payload(session, &sb.project(), command),
    ));
    (
        d["permissionDecision"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        d["permissionDecisionReason"].to_string(),
    )
}

const INSTALL: &str = "npm install left-pad";

#[test]
fn allow_last_grants_the_session_and_repins() {
    let sb = Sandbox::installed(&[".claude"]);
    assert_eq!(guard(&sb, "s1", INSTALL).0, "ask");

    let out = sb.moat_as_person(&["allow", "--last"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        text(&out).contains("session s1 on claude-code may run"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));

    let (verdict, reason) = guard(&sb, "s1", INSTALL);
    assert_eq!(verdict, "allow", "{reason}");
    assert!(reason.contains("approved-session"), "{reason}");
    assert_eq!(guard(&sb, "s2", INSTALL).0, "ask", "grants are per session");
}

#[test]
fn allow_explicit_session_grant() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat_as_person(&["allow", INSTALL, "--host", "claude-code", "--session", "s9"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(guard(&sb, "s9", INSTALL).0, "allow");
    assert_eq!(guard(&sb, "s1", INSTALL).0, "ask");
}

#[test]
fn allow_always_writes_the_overlay_and_keeps_the_lock_intact() {
    let sb = Sandbox::installed(&[".claude"]);
    assert_eq!(guard(&sb, "s1", INSTALL).0, "ask");
    let out = sb.moat_as_person(&["allow", "--last", "--always"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    let overlay = std::fs::read_to_string(sb.home.join(".moat/policy.d/approved.yaml")).unwrap();
    assert!(
        overlay.contains("approved-1") && overlay.contains(INSTALL),
        "{overlay}"
    );

    let (verdict, reason) = guard(&sb, "another-session", INSTALL);
    assert_eq!(
        verdict, "allow",
        "the overlay is re-pinned, not drift: {reason}"
    );
    assert!(reason.contains("approved-1"), "{reason}");
}

#[test]
fn allow_explains_missing_flags_and_shadowed_rules() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat_as_person(&["allow", "ls"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(
        text(&out).contains("--always for a permanent rule"),
        "{}",
        text(&out)
    );

    let out = sb.moat_as_person(&["allow", "rm -rf /", "--always"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        text(&out).contains("warning: rule `approved-1`") && text(&out).contains("unreachable"),
        "{}",
        text(&out)
    );
    assert_eq!(guard(&sb, "s1", "rm -rf /").0, "deny");

    guard(&sb, "s1", INSTALL);
    let out = sb.moat_as_person(&["allow", "--last"]);
    assert!(text(&out).contains("wanted to run"), "{}", text(&out));
}

#[test]
fn doctor_accept_repins_after_a_person_edits_the_policy() {
    let sb = Sandbox::installed(&[".claude"]);
    let policy = sb.home.join(".moat/policy.yaml");
    let mut text_now = std::fs::read_to_string(&policy).unwrap();
    text_now.push_str("\n# edited by the owner\n");
    std::fs::write(&policy, text_now).unwrap();
    let (verdict, reason) = guard(&sb, "s1", "git status");
    assert_eq!(verdict, "deny");
    assert!(reason.contains("kernel-integrity"), "{reason}");

    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("lock re-pinned"), "{}", text(&out));
    assert_eq!(guard(&sb, "s1", "git status").0, "allow");
}

#[test]
fn doctor_accept_refuses_to_pin_a_policy_that_does_not_lint() {
    let sb = Sandbox::installed(&[".claude"]);
    let policy = sb.home.join(".moat/policy.yaml");
    std::fs::write(&policy, "version: 1\ndeny:\n  - id: broken\n").unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out).contains("refusing to pin a policy that does not lint"),
        "{}",
        text(&out)
    );
    let (verdict, reason) = guard(&sb, "s1", "git status");
    assert_eq!(verdict, "deny", "the broken edit is still drift: {reason}");
}

#[test]
fn hooks_without_a_terminal_are_still_refused() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["allow", INSTALL, "--always"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(text(&out).contains("must be run by a person in a terminal"));
}
