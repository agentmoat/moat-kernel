//! The generated Codex profile, executed by Codex's own sandbox when a `codex`
//! binary is available (`MOAT_CODEX_BIN`, else `codex` on `PATH`). Without one
//! the test says so and passes; the differential suite (#170) runs every
//! fixture against every backend in CI.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::common::{Sandbox, text};

fn codex_binary() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("MOAT_CODEX_BIN").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(explicit));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("codex"))
        .find(|p| p.is_file())
}

/// Run `cat <file>` in `project` under the `moat` profile; `Some(contents)` when it was readable.
fn cat(codex: &Path, sb: &Sandbox, project: &Path, file: &str) -> Option<String> {
    let out = Command::new(codex)
        .args(["sandbox", "-P", "moat", "-C"])
        .arg(project)
        .args(["--", "/bin/cat", file])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &sb.home)
        .env("CODEX_HOME", sb.home.join(".codex"))
        .output()
        .expect("running codex sandbox");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn codex_enforces_the_generated_profile() {
    let Some(codex) = codex_binary() else {
        eprintln!("skipped: no codex binary (set MOAT_CODEX_BIN) to execute the generated profile");
        return;
    };
    let sb = Sandbox::bare(&[".codex"]);
    let out = sb.moat(&["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let project = sb.project();
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    fs::write(project.join(".env"), "TOKEN=fake").unwrap();
    fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    fs::write(sb.home.join(".ssh/id_rsa"), "FAKE-KEY").unwrap();

    assert_eq!(
        cat(&codex, &sb, &project, "main.rs").as_deref(),
        Some("fn main() {}")
    );
    assert_eq!(cat(&codex, &sb, &project, ".env"), None, "secrets-paths");
    let key = sb.home.join(".ssh/id_rsa");
    assert_eq!(
        cat(&codex, &sb, &project, &key.to_string_lossy()),
        None,
        "secrets-paths"
    );
    let system = cat(&codex, &sb, &project, "/etc/hosts");
    assert!(system.is_some(), "a read root stays readable");
}
