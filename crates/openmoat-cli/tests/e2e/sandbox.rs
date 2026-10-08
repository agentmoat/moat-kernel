//! Standard tier (ADR-018): host sandbox settings generated from the policy.

use serde_json::Value;

use crate::common::{Sandbox, json, output, stdout, text};

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
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

/// #327: on native Windows `show` says why there is no Claude Code sandbox.
#[cfg(windows)]
#[test]
fn show_says_claude_code_has_no_sandbox_on_native_windows() {
    let sb = Sandbox::installed(&[".claude"]);
    let out = sb.moat(&["sandbox", "show"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let shown = stdout(&out);
    assert!(
        shown.contains("Claude Code  sandbox not available on native Windows"),
        "{shown}"
    );
    assert!(!shown.contains("failIfUnavailable"), "{shown}");
    let doc = json(&sb.moat(&["sandbox", "show", "--format", "json"]));
    let claude = &doc["hosts"]["claude-code"];
    assert!(
        claude["unavailable"]
            .as_str()
            .is_some_and(|n| n.contains("WSL2")),
        "{doc}"
    );
    assert_eq!(settings_json(claude), Value::Null, "{doc}");
}

#[cfg(not(windows))] // #327: no Claude Code sandbox on native Windows
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

#[test]
fn show_prints_the_landlock_rules_and_what_they_leave_open() {
    let sb = Sandbox::installed(&[]);
    let out = output(
        sb.command()
            .args(["sandbox", "show", "--format", "json"])
            .current_dir(sb.project()),
        None,
    );
    let landlock = &json(&out)["lightweight"]["landlock"];
    let read = landlock["rules"]["read"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        read.iter()
            .any(|p| p.as_str().is_some_and(|p| p.ends_with("/home/proj")))
    );
    let rules: Vec<&str> = landlock["report"]["allowances"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a["rule"].as_str())
        .collect();
    assert!(rules.contains(&"landlock.inside-grants"), "{landlock}");
    // The seccomp filter closes UDP and Unix sockets.
    assert!(!rules.contains(&"landlock.sockets"), "{landlock}");
}

#[test]
fn show_prints_the_seatbelt_profile_for_the_project_here() {
    let sb = Sandbox::installed(&[]);
    let project = sb.project();
    let out = output(
        sb.command()
            .args(["sandbox", "show", "--format", "json"])
            .current_dir(&project),
        None,
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let seatbelt = &json(&out)["lightweight"]["seatbelt"];
    let profile = seatbelt["profile"].as_str().unwrap_or_default();
    // The child's working directory comes back resolved (`/private/var/…`).
    for expected in ["(deny default)", "/home/proj\")", "; network: none"] {
        assert!(profile.contains(expected), "{expected}: {profile}");
    }
    assert!(
        seatbelt["report"]["allowances"]
            .as_array()
            .is_some_and(|a| a.iter().any(|a| a["rule"] == "seatbelt.platform")),
        "{seatbelt}"
    );
}
