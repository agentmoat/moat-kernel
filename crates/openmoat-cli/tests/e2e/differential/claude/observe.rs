//! What a command under Claude Code's sandbox did, seen from the host: the
//! tool's report, the fake secrets it showed and every change to the home
//! outside the project. Inside the project the sandbox lets commands write
//! (`ln -s ~/.ssh link`), and what it keeps read-only there (`.git/hooks`, the
//! `.claude` settings) makes the command fail, which the report shows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Markers Claude Code's sandbox (or the tools under it) emit when it blocks a
/// command. Any one of them means the command did not complete.
const BLOCKED: &[&str] = &[
    "peration not permitted",
    "sandbox_violation",
    "Failed to connect",
    "Could not resolve host",
    // Claude Code's Bash tool prefixes any non-zero exit with this; a sandbox
    // that denies a file read, a write or a connection makes the command fail.
    "Exit code ",
];

/// The fixtures' fake secrets: shown only where a read went through.
const SECRETS: [&str; 3] = ["FAKE-PRIVATE-KEY", "key=FAKE", "TOKEN=secret"];

/// What a command under Claude Code's sandbox did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// The command failed: the sandbox refused it.
    Refused,
    /// It completed without changing the home or showing a secret, so what
    /// it wrote stayed inside the sandbox.
    Contained,
    /// It changed the home or showed a secret.
    Escaped(String),
}

impl Seen {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Refused => "deny",
            Self::Contained => "contained",
            Self::Escaped(_) => "allow",
        }
    }
}

/// One run: what the tool reported and the paths in the home it changed.
pub struct Run {
    pub reported: String,
    pub changed: Vec<String>,
}

impl Run {
    /// Snapshot `home` but `project`, run `f` (which returns the tool's
    /// report), and compare.
    pub fn observe(home: &Path, project: &Path, f: impl FnOnce() -> String) -> Self {
        let before = home_state(home, project);
        let reported = f();
        let after = home_state(home, project);
        let changed = before
            .keys()
            .chain(after.keys())
            .filter(|p| before.get(*p) != after.get(*p))
            .map(|p| p.display().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self { reported, changed }
    }

    /// What the run did, leaving out the paths in `artefacts`: those Claude
    /// Code itself writes outside its sandbox on every run (its state under
    /// `~/.claude` and `~/.config`).
    pub fn seen(&self, artefacts: &BTreeSet<String>) -> Seen {
        let changed: Vec<&String> = self
            .changed
            .iter()
            .filter(|p| !artefacts.contains(*p))
            .collect();
        let shown: Vec<&str> = SECRETS
            .into_iter()
            .filter(|secret| self.reported.contains(secret))
            .collect();
        if !changed.is_empty() || !shown.is_empty() {
            Seen::Escaped(format!(
                "changed {changed:?}, showed {shown:?}:\n{}",
                self.reported
            ))
        } else if BLOCKED.iter().any(|m| self.reported.contains(m)) {
            Seen::Refused
        } else {
            Seen::Contained
        }
    }
}

/// Every file, link and directory below `home` with its contents, except the
/// project, each run's own Claude Code config directory and the audit log
/// `moat proxy` appends to.
fn home_state(home: &Path, project: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(home: &Path, project: &Path, dir: &Path, state: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path == project {
                continue;
            }
            let rel = path.strip_prefix(home).unwrap().to_path_buf();
            let name = rel.to_string_lossy();
            if name.starts_with(".cfg-") || name.starts_with(".moat/audit.db") {
                continue;
            }
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                state.insert(rel, target.to_string_lossy().as_bytes().to_vec());
            } else if kind.is_dir() {
                state.insert(rel, b"<dir>".to_vec());
                walk(home, project, &path, state);
            } else {
                state.insert(rel, std::fs::read(&path).unwrap_or_default());
            }
        }
    }
    let mut state = BTreeMap::new();
    walk(home, project, home, &mut state);
    state
}
