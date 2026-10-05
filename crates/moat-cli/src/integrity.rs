//! The policy lock: a pinned set of file digests the kernel refuses to run without.
//!
//! `moat init` pins the policy and every host hook file it installed. `moat guard`
//! recomputes the digests on every call and denies everything when a pinned file
//! changed or disappeared, so an agent that edits `~/.moat/policy.yaml` or removes
//! a hook gets a `deny`, not a quieter kernel. Only a human can re-pin
//! (`moat init`, or `moat doctor --accept` from a terminal).

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::home::{Home, write_private};
use crate::install::{HookState, HostConfig};

const LOCK_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub version: u32,
    pub pinned_at_ms: u64,
    /// Absolute path of the `moat` binary the hooks point at.
    pub binary: String,
    /// Canonical path → lowercase hex SHA-256 of the file contents.
    pub entries: BTreeMap<String, String>,
}

/// Pin everything the kernel trusts: policy, environment snapshot, approval
/// files and every installed host hook file. Used by `init`, `doctor --accept`
/// and `allow`, which are the only human paths that may re-pin.
pub fn repin(home: &Home, binary: &Path) -> Result<Lock> {
    let mut paths = vec![
        home.policy_path(),
        home.environment_path(),
        home.grants_path(),
        home.overlay_path(),
    ];
    for host in moat_hosts::Host::ALL {
        let config = HostConfig::for_host(host)?;
        if config.state(binary) == HookState::Installed {
            paths.push(config.settings_path);
        }
    }
    let lock = Lock::pin(binary, &paths)?;
    lock.save(&home.lock_path())?;
    Ok(lock)
}

/// One way a pinned file differs from the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    Modified(PathBuf),
    Missing(PathBuf),
    Unreadable(PathBuf, String),
}

impl fmt::Display for Drift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Modified(p) => write!(f, "{} was modified", p.display()),
            Self::Missing(p) => write!(f, "{} is missing", p.display()),
            Self::Unreadable(p, why) => write!(f, "{} is unreadable: {why}", p.display()),
        }
    }
}

impl Lock {
    /// Pin the current contents of `paths`. Files that do not exist are skipped;
    /// callers pass only files they just wrote or verified.
    pub fn pin(binary: &Path, paths: &[PathBuf]) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for path in paths {
            if path.is_file() {
                entries.insert(key(path), digest(path)?);
            }
        }
        Ok(Self {
            version: LOCK_VERSION,
            pinned_at_ms: now_ms(),
            binary: binary.to_string_lossy().into_owned(),
            entries,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading lock {}", path.display()))?;
        let lock: Self = serde_json::from_str(&text)
            .with_context(|| format!("parsing lock {}", path.display()))?;
        if lock.version != LOCK_VERSION {
            bail!(
                "lock {} has version {}; this build supports {LOCK_VERSION}",
                path.display(),
                lock.version
            );
        }
        Ok(lock)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)? + "\n";
        write_private(path, text.as_bytes())
    }

    /// Compare pinned digests with the files on disk. Empty means intact.
    pub fn verify(&self) -> Vec<Drift> {
        self.entries
            .keys()
            .filter_map(|path| self.verify_one(Path::new(path)))
            .collect()
    }

    /// Drift for one pinned file, or `None` when it is intact or not pinned.
    pub fn verify_one(&self, path: &Path) -> Option<Drift> {
        let expected = self.entries.get(&key(path))?;
        let path = PathBuf::from(key(path));
        if fs::symlink_metadata(&path).is_err() {
            return Some(Drift::Missing(path));
        }
        match digest(&path) {
            Ok(actual) if &actual == expected => None,
            Ok(_) => Some(Drift::Modified(path)),
            Err(e) => Some(Drift::Unreadable(path, format!("{e:#}"))),
        }
    }

    pub fn pins(&self, path: &Path) -> bool {
        self.entries.contains_key(&key(path))
    }
}

/// Identity of a pinned file: its canonical directory plus its own name. The
/// leaf is deliberately not resolved, so a file that is later replaced by a
/// symlink keeps the same key and is compared, not forgotten. The parent is
/// canonicalised so `/var/...` and `/private/var/...` agree on macOS and a
/// deleted file still has a key.
fn key(path: &Path) -> String {
    let located = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            fs::canonicalize(parent).map_or_else(|_| path.to_path_buf(), |p| p.join(name))
        }
        _ => path.to_path_buf(),
    };
    let text = located.to_string_lossy();
    if cfg!(windows) {
        crate::context::strip_verbatim(&text)
    } else {
        text.into_owned()
    }
}

/// SHA-256 of the file. A symlink hashes its target path together with the
/// contents, so swapping a regular file for a link (or re-pointing a link)
/// changes the digest even when the bytes read through it are identical.
fn digest(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    if meta.file_type().is_symlink() {
        let target =
            fs::read_link(path).with_context(|| format!("reading link {}", path.display()))?;
        bytes.extend_from_slice(b"symlink:");
        bytes.extend_from_slice(target.to_string_lossy().as_bytes());
        bytes.push(b'\n');
    }
    bytes.extend(fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    Ok(Sha256::digest(&bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        }))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn pin_verify_and_detect_drift() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write(dir.path(), "policy.yaml", "version: 1\n");
        let hook = write(dir.path(), "settings.json", "{}");
        let absent = dir.path().join("never-written.json");

        let lock = Lock::pin(
            Path::new("/x/moat"),
            &[policy.clone(), hook.clone(), absent],
        )
        .unwrap();
        assert_eq!(lock.entries.len(), 2, "absent files are not pinned");
        assert!(lock.entries.keys().any(|k| k.ends_with("policy.yaml")));
        assert!(lock.verify().is_empty());

        fs::write(&policy, "version: 1\nallow: []\n").unwrap();
        fs::remove_file(&hook).unwrap();
        let drift = lock.verify();
        assert_eq!(drift.len(), 2);
        assert!(
            drift
                .iter()
                .any(|d| matches!(d, Drift::Modified(p) if p.ends_with("policy.yaml")))
        );
        assert!(
            drift
                .iter()
                .any(|d| matches!(d, Drift::Missing(p) if p.ends_with("settings.json")))
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_pinned_file_with_a_symlink_is_drift() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write(dir.path(), "policy.yaml", "version: 1\n");
        let other = write(dir.path(), "other.yaml", "version: 1\n");
        let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&policy)).unwrap();

        fs::remove_file(&policy).unwrap();
        std::os::unix::fs::symlink(&other, &policy).unwrap();
        assert!(lock.pins(&policy), "a symlinked leaf keeps its identity");
        assert!(
            matches!(lock.verify_one(&policy), Some(Drift::Modified(p)) if p.ends_with("policy.yaml")),
            "same bytes through a link must still count as modified"
        );

        fs::remove_file(&policy).unwrap();
        assert!(matches!(lock.verify_one(&policy), Some(Drift::Missing(_))));
    }

    #[test]
    fn round_trips_through_disk_and_rejects_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write(dir.path(), "policy.yaml", "version: 1\n");
        let lock_path = dir.path().join("policy.lock");
        let lock = Lock::pin(Path::new("/x/moat"), &[policy]).unwrap();
        lock.save(&lock_path).unwrap();
        assert_eq!(Lock::load(&lock_path).unwrap(), lock);

        fs::write(
            &lock_path,
            r#"{"version":9,"pinned_at_ms":0,"binary":"","entries":{}}"#,
        )
        .unwrap();
        assert!(
            Lock::load(&lock_path)
                .unwrap_err()
                .to_string()
                .contains("version 9")
        );
    }
}
