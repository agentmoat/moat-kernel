//! Installation-time snapshot of the search path and where key programs live.
//!
//! `moat init` records `PATH` and the absolute location of security-relevant
//! programs in `~/.moat/environment.json` (pinned by the policy lock). `moat guard`
//! resolves command names through this snapshot, never through the environment
//! the hook inherited, so a poisoned `PATH` or a planted `git` cannot change which
//! binary the kernel believes is about to run.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use moat_core::ProgramResolver;
use serde::{Deserialize, Serialize};

use crate::home::write_private;

const SNAPSHOT_VERSION: u32 = 1;

/// Programs whose location is recorded at install time.
pub const PINNED_PROGRAMS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "git",
    "gh",
    "ssh",
    "scp",
    "curl",
    "wget",
    "sudo",
    "node",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "bun",
    "python",
    "python3",
    "pip",
    "pip3",
    "uv",
    "cargo",
    "rustc",
    "go",
    "swift",
    "docker",
    "kubectl",
    "terraform",
    "aws",
    "gcloud",
    "az",
    "make",
    "brew",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub captured_at_ms: u64,
    /// Search path directories, in order, as seen by `moat init`.
    pub path: Vec<PathBuf>,
    /// Program name → absolute path found at install time.
    pub programs: BTreeMap<String, PathBuf>,
}

impl Snapshot {
    /// Capture the current process's search path and resolve the pinned programs.
    pub fn capture() -> Self {
        let path: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        let mut programs = BTreeMap::new();
        for name in PINNED_PROGRAMS {
            if let Some(found) = find_in(&path, name) {
                programs.insert((*name).to_owned(), found);
            }
        }
        Self {
            version: SNAPSHOT_VERSION,
            captured_at_ms: now_ms(),
            path,
            programs,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading environment snapshot {}", path.display()))?;
        let snapshot: Self = serde_json::from_str(&text)
            .with_context(|| format!("parsing environment snapshot {}", path.display()))?;
        if snapshot.version != SNAPSHOT_VERSION {
            bail!(
                "environment snapshot {} has version {}; this build supports {SNAPSHOT_VERSION}",
                path.display(),
                snapshot.version
            );
        }
        Ok(snapshot)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)? + "\n";
        write_private(path, text.as_bytes())
    }
}

impl ProgramResolver for Snapshot {
    fn resolve(&self, program: &str) -> Option<String> {
        find_in(&self.path, program).map(|p| p.to_string_lossy().replace('\\', "/"))
    }

    fn pinned(&self, program: &str) -> Option<String> {
        self.programs
            .get(program)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
    }
}

/// First executable named `program` in `dirs`, following the platform's rules.
fn find_in(dirs: &[PathBuf], program: &str) -> Option<PathBuf> {
    let candidates: &[String] = if cfg!(windows) {
        &[
            program.to_owned(),
            format!("{program}.exe"),
            format!("{program}.cmd"),
            format!("{program}.bat"),
        ]
    } else {
        &[program.to_owned()]
    };
    dirs.iter()
        .filter(|d| !d.as_os_str().is_empty())
        .flat_map(|d| candidates.iter().map(move |c| d.join(c)))
        .find(|p| is_executable(p))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn executable(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn resolves_in_search_path_order_and_skips_non_executables() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("git"), "not executable").unwrap();
        let real = executable(&second, "git");
        let snap = Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_ms: 0,
            path: vec![first.clone(), second.clone()],
            programs: BTreeMap::from([("git".to_owned(), real.clone())]),
        };
        assert_eq!(snap.resolve("git").as_deref(), Some(real.to_str().unwrap()));
        assert_eq!(snap.pinned("git").as_deref(), Some(real.to_str().unwrap()));
        assert_eq!(snap.resolve("nope"), None);

        let planted = executable(&first, "git");
        assert_eq!(
            snap.resolve("git").as_deref(),
            Some(planted.to_str().unwrap())
        );
    }

    #[test]
    fn round_trips_and_rejects_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("environment.json");
        let snap = Snapshot::capture();
        snap.save(&file).unwrap();
        assert_eq!(Snapshot::load(&file).unwrap(), snap);
        fs::write(
            &file,
            r#"{"version":7,"captured_at_ms":0,"path":[],"programs":{}}"#,
        )
        .unwrap();
        assert!(
            Snapshot::load(&file)
                .unwrap_err()
                .to_string()
                .contains("version 7")
        );
    }
}
