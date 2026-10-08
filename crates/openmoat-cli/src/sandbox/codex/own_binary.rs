//! Codex on Linux runs its own executable again inside bubblewrap to apply
//! seccomp (`build_inner_seccomp_command` in `linux-sandbox/src/linux_run_main.rs`
//! re-executes `current_exe()`) but grants itself no read access to it, so a
//! command starts only when the profile lets it read that file (#371). The
//! release executable is statically linked (musl): the file alone is enough.

use std::path::{Path, PathBuf};

use openmoat_core::Kind;
use toml_edit::{Item, value};

use super::Generated;
use crate::sandbox::patterns::is_below;

const RULE: &str = "codex.own-binary";

/// The executable `codex` on `PATH` runs, symlinks resolved.
pub fn own_binary() -> Option<PathBuf> {
    let path: Vec<PathBuf> = std::env::split_paths(&std::env::var_os("PATH")?).collect();
    native(&std::fs::canonicalize(crate::environment::find_in(&path, &[], "codex")?).ok()?)
}

/// `found` itself, or for npm's launcher (`<package>/bin/codex.js`) the
/// executable it starts: `vendor/<triple>/bin/codex` in the platform package
/// (`@openai/codex-linux-x64`) installed inside or beside the package, else in
/// the package itself (`findCodexExecutable` in `codex-cli/bin/codex.js`).
fn native(found: &Path) -> Option<PathBuf> {
    if found.extension().is_none_or(|e| e != "js") {
        return Some(found.to_path_buf());
    }
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => return None,
    };
    let package = found.parent()?.parent()?;
    let platform = format!("codex-linux-{arch}");
    let binary = Path::new("vendor")
        .join(format!("{}-unknown-linux-musl", std::env::consts::ARCH))
        .join("bin/codex");
    [
        package.join("node_modules/@openai").join(&platform),
        package.with_file_name(&platform),
        package.to_path_buf(),
    ]
    .iter()
    .map(|dir| dir.join(&binary))
    .find(|candidate| candidate.is_file())
    .and_then(|candidate| std::fs::canonicalize(candidate).ok())
}

/// Let commands read Codex's own executable `binary`. A path the profile
/// denies stays denied (Codex applies deny masks last), and that, like Codex
/// missing from `PATH`, is reported as stricter.
pub fn read_own_binary(generated: &mut Generated, binary: Option<&Path>) {
    let Some(binary) = binary else {
        generated.report.loss(
            Kind::FsRead,
            RULE,
            "`codex` was not on PATH: Codex on Linux runs its own executable inside the \
             sandbox, so it starts commands only when installed under a read root; run \
             `moat sandbox sync` after installing it"
                .into(),
        );
        return;
    };
    let key = crate::context::path_string(binary);
    let Some(filesystem) = generated
        .profile
        .get_mut("filesystem")
        .and_then(Item::as_table_mut)
    else {
        return;
    };
    let denied = filesystem
        .iter()
        .find(|(path, mode)| {
            mode.as_str() == Some("deny") && (*path == key || is_below(&key, path))
        })
        .map(|(path, _)| path.to_owned());
    if let Some(denied) = denied {
        generated.report.loss(
            Kind::FsRead,
            RULE,
            format!(
                "Codex's executable `{key}` is inside the denied `{denied}`, and Codex on Linux \
                 runs it inside the sandbox, so no command starts; install Codex outside it"
            ),
        );
        return;
    }
    if !filesystem.contains_key(&key) {
        filesystem.insert(&key, value("read"));
    }
    generated.report.allowance(
        Kind::FsRead,
        RULE,
        vec![key],
        "Codex on Linux runs its own executable again inside the sandbox, so commands may read \
         it; run `moat sandbox sync` after moving Codex",
    );
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::sandbox::codex::tests::generated;

    fn mode<'a>(out: &'a Generated, key: &str) -> Option<&'a str> {
        out.profile["filesystem"].get(key)?.as_str()
    }

    #[test]
    fn the_executable_is_readable_and_listed_as_wider() {
        let mut out = generated(openmoat_core::DEFAULT_POLICY);
        read_own_binary(&mut out, Some(Path::new("/opt/codex/bin/codex")));
        assert_eq!(mode(&out, "/opt/codex/bin/codex"), Some("read"));
        let allowance = out.report.allowances.iter().find(|a| a.rule == RULE);
        assert_eq!(
            allowance.map(|a| a.patterns.clone()),
            Some(vec!["/opt/codex/bin/codex".to_owned()])
        );
    }

    #[test]
    fn a_denied_or_missing_executable_is_stricter_and_never_granted() {
        let mut out = generated(openmoat_core::DEFAULT_POLICY);
        let inside = "/Users/me/.ssh/codex";
        read_own_binary(&mut out, Some(Path::new(inside)));
        assert_eq!(mode(&out, inside), None);
        read_own_binary(&mut out, None);
        let losses: Vec<&str> = out
            .report
            .losses
            .iter()
            .filter(|l| l.rule == RULE)
            .map(|l| l.message.as_str())
            .collect();
        assert_eq!(losses.len(), 2, "{losses:?}");
        assert!(losses[0].contains("inside the denied `/Users/me/.ssh`"));
        assert!(!out.report.allowances.iter().any(|a| a.rule == RULE));
    }

    #[test]
    fn npm_launcher_resolves_to_the_platform_executable() {
        let dir = tempfile::tempdir().unwrap();
        let modules = std::fs::canonicalize(dir.path()).unwrap();
        let launcher = modules.join("@openai/codex/bin/codex.js");
        std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        std::fs::write(&launcher, "").unwrap();
        assert_eq!(native(&launcher), None, "no executable installed");
        let arch = if std::env::consts::ARCH == "x86_64" {
            "x64"
        } else {
            "arm64"
        };
        let executable = modules
            .join(format!("@openai/codex-linux-{arch}/vendor"))
            .join(format!("{}-unknown-linux-musl", std::env::consts::ARCH))
            .join("bin/codex");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, "").unwrap();
        assert_eq!(native(&launcher), Some(executable.clone()));
        assert_eq!(native(&executable), Some(executable));
    }
}
