//! End-to-end tests of where `moat guard` takes paths to be: the project root
//! it trusts, and the home directory and symlinks it resolves through.

use std::path::Path;

use crate::common::{Sandbox, bash_payload, hook_output, stderr};

/// The verdict and reason `guard` gives a Bash command run in `cwd`.
fn verdict(sb: &Sandbox, cwd: &Path, command: &str) -> (String, String) {
    let out = sb.guard("claude-code", &bash_payload("s-paths", cwd, command));
    let d = hook_output(&out);
    let verdict = d["permissionDecision"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(!verdict.is_empty(), "{command}: {}", stderr(&out));
    (verdict, d["permissionDecisionReason"].to_string())
}

fn assert_verdict(sb: &Sandbox, cwd: &Path, command: &str, expected: &str, rule: &str) {
    let (verdict, reason) = verdict(sb, cwd, command);
    assert_eq!(verdict, expected, "{command}: {reason}");
    assert!(reason.contains(rule), "{command}: {reason}");
}

/// A session started in the home directory, outside any repository, has no
/// project: `project-fs` must not turn into "the whole home directory".
#[test]
fn a_session_in_home_has_no_project() {
    let sb = Sandbox::installed(&[".claude"]);
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::create_dir_all(sb.home.join(".aws")).unwrap();
    let home = sb.home.clone();
    assert_verdict(&sb, &home, "grep -r . ~/.ssh", "deny", "secrets-paths");
    assert_verdict(&sb, &home, "rg -uu . ~/.aws", "deny", "secrets-paths");
    for command in [
        "echo x > Library/LaunchAgents/evil.plist",
        "echo x > ~/.gitconfig",
        "cat notes.txt",
    ] {
        assert_verdict(&sb, &home, command, "ask", "default");
    }
    let project = sb.project();
    assert_verdict(&sb, &project, "echo x > notes.txt", "allow", "project-fs");
}

/// A dotfiles repository in the home directory does not make it the project;
/// the session's own directory is the project instead.
#[test]
fn a_repository_in_home_is_not_the_project() {
    let sb = Sandbox::installed(&[".claude"]);
    std::fs::create_dir_all(sb.home.join(".git")).unwrap();
    let app = sb.home.join("code/app");
    std::fs::create_dir_all(&app).unwrap();
    assert_verdict(&sb, &sb.home, "echo x > ~/.gitconfig", "ask", "default");
    assert_verdict(&sb, &app, "echo x > notes.txt", "allow", "project-fs");
}

/// `moat policy check --project ~` is refused rather than silently ignored.
#[test]
fn an_explicit_home_project_is_a_usage_error() {
    let sb = Sandbox::installed(&[]);
    let home = sb.home.to_string_lossy().into_owned();
    let out = sb.moat(&["policy", "check", "ls", "--project", &home, "--cwd", &home]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot be a project root"),
        "{}",
        stderr(&out)
    );
}

/// `~name` is expanded the way the shell does it; the sandbox user is `home`,
/// the last component of its home directory.
#[test]
fn tilde_user_paths_are_home_directories() {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    assert_verdict(
        &sb,
        &project,
        "cat ~home/.ssh/id_rsa",
        "deny",
        "secrets-paths",
    );
    assert_verdict(&sb, &project, "cat ~alice/notes.txt", "ask", "default");
    assert_verdict(&sb, &project, "cat ~-/notes.txt", "ask", "unparseable");
}

/// After `ln -s ~/.ssh s` in the project, every spelling of a read through the
/// link meets the deny, not only `./s/…` (POLICY.md §4). Symlinks are only
/// created on Unix here; Windows needs a privilege for them.
#[cfg(unix)]
#[test]
fn relative_operands_are_resolved_through_symlinks() {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::write(sb.home.join(".ssh/id_rsa"), "key").unwrap();
    std::os::unix::fs::symlink(sb.home.join(".ssh"), project.join("s")).unwrap();
    std::os::unix::fs::symlink(sb.home.join(".ssh/id_rsa"), project.join("k")).unwrap();
    for command in [
        "cat s/id_rsa",
        "head s/id_rsa",
        "grep -r . s/",
        "cat k",
        "cd s && cat id_rsa",
        "cd ~ && cat .ssh/id_rsa",
        "cp k out.txt",
    ] {
        assert_verdict(&sb, &project, command, "deny", "secrets-paths");
    }
    std::fs::create_dir_all(project.join("src")).unwrap();
    for command in ["cat src/main.rs", "ls src", "git status", "echo s/id_rsa"] {
        assert_verdict(&sb, &project, command, "allow", "dev-shell");
    }
    assert_verdict(&sb, &project, "npm install left-pad", "ask", "installs");
}

/// `path` with its links resolved, in slash form: on macOS the sandbox sits
/// under `/var` → `/private/var`, on Windows under a `RUNNER~1` short name.
fn real(path: &Path) -> String {
    let real = std::fs::canonicalize(path).unwrap();
    let real = real.to_string_lossy();
    real.strip_prefix(r"\\?\")
        .unwrap_or(&real)
        .replace('\\', "/")
}

/// A file in the project is the project's however its path is spelled: as
/// the session wrote the root, or resolved (POLICY.md §3.2).
#[test]
fn the_resolved_project_path_is_the_project() {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    std::fs::write(project.join("a"), "x").unwrap();
    let file = format!("{}/a", real(&project));
    assert_verdict(&sb, &project, &format!("cat {file}"), "allow", "project-fs");
    assert_verdict(&sb, &project, "cat a", "allow", "project-fs");
}

/// A project reached through a symlinked directory (`~/code` →
/// `/Volumes/dev/code`) keeps `project-fs` under both spellings, exclusions
/// included, and a link inside it is still checked where it points.
#[cfg(unix)]
#[test]
fn a_project_under_a_symlinked_directory_is_the_project() {
    let sb = Sandbox::installed(&[".claude"]);
    let volume = sb.home.join("../volume/code");
    std::fs::create_dir_all(volume.join("app/.git")).unwrap();
    std::os::unix::fs::symlink(&volume, sb.home.join("code")).unwrap();
    let project = sb.home.join("code/app");
    let real = real(&project);
    std::fs::write(project.join("a"), "x").unwrap();
    for command in [
        "cat a".to_owned(),
        format!("cat {real}/a"),
        format!("echo x > {real}/b"),
    ] {
        assert_verdict(&sb, &project, &command, "allow", "project-fs");
    }
    let hook = format!("echo x > {real}/.git/hooks/pre-commit");
    assert_verdict(&sb, &project, &hook, "ask", "default");
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::write(sb.home.join(".ssh/id_rsa"), "key").unwrap();
    std::os::unix::fs::symlink(sb.home.join(".ssh"), project.join("s")).unwrap();
    std::os::unix::fs::symlink("/etc", project.join("e")).unwrap();
    assert_verdict(&sb, &project, "cat s/id_rsa", "deny", "secrets-paths");
    assert_verdict(&sb, &project, "cat e/hosts", "ask", "default");
}

/// A Claude Code `Glob` whose pattern is absolute searches the pattern's own
/// directory, whatever `path` says; that directory is what gets checked.
#[test]
fn an_absolute_glob_pattern_is_a_read_of_its_directory() {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    let home = sb.home.to_string_lossy().replace('\\', "/");
    let glob = |pattern: &str| {
        let payload = serde_json::json!({
            "session_id": "s-glob", "cwd": project.to_string_lossy(),
            "hook_event_name": "PreToolUse", "tool_name": "Glob",
            "tool_input": {"pattern": pattern, "path": project.to_string_lossy()}
        });
        let d = hook_output(&sb.guard("claude-code", &payload.to_string()));
        (
            d["permissionDecision"].clone(),
            d["permissionDecisionReason"].to_string(),
        )
    };
    for pattern in [format!("{home}/.ssh/id_*"), "~/.aws/**/cred*".to_owned()] {
        let (verdict, reason) = glob(&pattern);
        assert_eq!(verdict, "deny", "{pattern}: {reason}");
        assert!(reason.contains("secrets-paths"), "{pattern}: {reason}");
    }
    let (verdict, reason) = glob(&format!("{home}/proj/src/**/*.rs"));
    assert_eq!(verdict, "allow", "{reason}");
}
