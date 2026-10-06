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

use anyhow::{Context as _, Result, bail};
use moat_core::{Decision, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::home::{Home, write_private};
use crate::install::{HookState, HostConfig};

const LOCK_VERSION: u32 = 1;
/// Rule id of every decision the lock forces.
pub const INTEGRITY_RULE: &str = "kernel-integrity";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub version: u32,
    pub pinned_at_ms: i64,
    /// Absolute path of the `moat` binary the hooks point at.
    pub binary: String,
    /// Canonical path → lowercase hex SHA-256 of the file contents.
    pub entries: BTreeMap<String, String>,
    /// Codex `config.toml` → SHA-256 of the part moat owns (its permissions
    /// profile, ADR-018). Codex edits the rest of that file itself.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub codex_profiles: BTreeMap<String, String>,
}

/// Which hook files a re-pin covers, besides moat's own state files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPins {
    /// `moat init`: the hook files already pinned plus every hook file installed
    /// under this shell's environment.
    Adopt,
    /// `moat allow`, `moat doctor --accept`: the hook files already pinned. The
    /// hook file an agent reads depends on the agent's environment
    /// (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CURSOR_CONFIG_DIR`), which need not be
    /// this shell's, so a re-pin must not decide again which files those are.
    Keep,
}

/// Pin everything the kernel trusts: policy, environment snapshot, approval
/// files and the host hook files `hooks` selects. Used by `init`,
/// `doctor --accept` and `allow`, which are the only human paths that may re-pin.
pub fn repin(home: &Home, binary: &Path, hooks: HookPins) -> Result<Lock> {
    repin_with(home, binary, hooks, &[], &[])
}

/// [`repin`], also pinning `files` whole and the Codex profiles in
/// `codex_configs`: the files `moat sandbox sync` just wrote.
pub fn repin_with(
    home: &Home,
    binary: &Path,
    hooks: HookPins,
    files: &[PathBuf],
    codex_configs: &[PathBuf],
) -> Result<Lock> {
    let mut paths = state_files(home);
    paths.extend_from_slice(files);
    let mut profiles = codex_configs.to_vec();
    let lock_path = home.lock_path();
    let had_lock = lock_path.exists();
    if had_lock {
        match (Lock::load(&lock_path), hooks) {
            (Ok(old), _) => {
                paths.extend(old.entries.into_keys().map(PathBuf::from));
                profiles.extend(old.codex_profiles.into_keys().map(PathBuf::from));
            }
            (Err(e), HookPins::Keep) => {
                return Err(e.context("cannot tell which hook files are pinned; run `moat init`"));
            }
            // `init` is how a person recovers from an unreadable lock.
            (Err(_), HookPins::Adopt) => {}
        }
    }
    // Without a lock there is nothing to keep, so this environment's hooks it is.
    if hooks == HookPins::Adopt || !had_lock {
        paths.extend(installed_hook_files(binary)?);
        profiles.extend(crate::sandbox::install::codex_profile_files()?);
    }
    let mut lock = Lock::pin(binary, &paths)?;
    for path in profiles.iter().filter(|p| p.is_file()) {
        let digest = crate::sandbox::install::codex_part_digest(path)?;
        lock.codex_profiles.insert(key(path), digest);
    }
    lock.save(&lock_path)?;
    Ok(lock)
}

/// moat's own files, pinned by every lock whatever the environment.
fn state_files(home: &Home) -> Vec<PathBuf> {
    vec![
        home.policy_path(),
        home.environment_path(),
        home.grants_path(),
        home.overlay_path(),
        home.trust_path(),
    ]
}

/// Hook files with a current `moat` hook under this shell's environment.
pub fn installed_hook_files(binary: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for host in moat_hosts::Host::ALL {
        let config = HostConfig::for_host(host)?;
        if config.state(binary) == HookState::Installed {
            paths.push(config.settings_path);
        }
    }
    Ok(paths)
}

/// How this shell's hook files differ from the ones the lock pins.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HookPinGap {
    /// Installed here but not pinned: changes to them go unseen until `moat init`.
    pub unpinned: Vec<PathBuf>,
    /// Pinned but not this shell's: another environment's hook files, still verified.
    pub elsewhere: Vec<PathBuf>,
}

impl HookPinGap {
    pub fn new(lock: &Lock, home: &Home, installed: &[PathBuf]) -> Self {
        let state: Vec<String> = state_files(home).iter().map(|p| key(p)).collect();
        let here: Vec<String> = installed.iter().map(|p| key(p)).collect();
        Self {
            unpinned: installed
                .iter()
                .filter(|p| !lock.pins(p))
                .cloned()
                .collect(),
            elsewhere: lock
                .entries
                .keys()
                .filter(|k| !state.contains(k) && !here.contains(k))
                .map(PathBuf::from)
                .collect(),
        }
    }
}

/// `Some(deny)` when the pinned policy or hook files changed since `moat init`.
pub fn violation(home: &Home) -> Result<Option<Decision>> {
    let lock_path = home.lock_path();
    if !lock_path.is_file() {
        bail!("no policy lock at {}; run `moat init`", lock_path.display());
    }
    let drift = Lock::load(&lock_path)?.verify();
    if drift.is_empty() {
        return Ok(None);
    }
    let mut decision = Decision::new(Verdict::Deny);
    decision.rules.push(INTEGRITY_RULE.to_owned());
    for d in drift {
        decision.reasons.push(format!("{d}"));
    }
    decision.reasons.push(
        "run `moat doctor` to inspect; `moat doctor --accept` or `moat init` to re-pin".to_owned(),
    );
    Ok(Some(decision))
}

/// Refuse a person's command that re-pins while pinned files drifted: the
/// re-pin would accept a tampered file unseen. `doing` completes "refusing to …".
pub fn refuse_drift(home: &Home, doing: &str) -> Result<()> {
    if let Some(deny) = violation(home)? {
        bail!(
            "refusing to {doing} while the policy lock shows drift ({INTEGRITY_RULE}):\n  {}",
            deny.reasons.join("\n  ")
        );
    }
    Ok(())
}

/// One way a pinned file differs from the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    Modified(PathBuf),
    Missing(PathBuf),
    Unreadable(PathBuf, String),
    /// A staged copy (`proposal`) that would change the pinned `target`.
    Proposed {
        proposal: PathBuf,
        target: PathBuf,
    },
}

impl fmt::Display for Drift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Modified(p) => write!(f, "{} was modified", p.display()),
            Self::Missing(p) => write!(f, "{} is missing", p.display()),
            Self::Unreadable(p, why) => write!(f, "{} is unreadable: {why}", p.display()),
            Self::Proposed { proposal, target } => write!(
                f,
                "{} would change {}",
                proposal.display(),
                target.display()
            ),
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
            pinned_at_ms: crate::time::now_ms(),
            binary: binary.to_string_lossy().into_owned(),
            entries,
            codex_profiles: BTreeMap::new(),
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
        let files = self.entries.keys().filter_map(|stored| {
            // A stored key is canonical as of pinning. If it no longer maps to
            // itself, a directory on the way was moved or replaced by a link:
            // the file the kernel will read is not the one that was pinned.
            if key(Path::new(stored)) != *stored {
                return Some(Drift::Modified(PathBuf::from(stored)));
            }
            self.verify_one(Path::new(stored))
        });
        let profiles = self.codex_profiles.iter().filter_map(|(stored, expected)| {
            let path = PathBuf::from(stored);
            if key(&path) != *stored {
                return Some(Drift::Modified(path));
            }
            if fs::symlink_metadata(&path).is_err() {
                return Some(Drift::Missing(path));
            }
            match crate::sandbox::install::codex_part_digest(&path) {
                Ok(actual) if &actual == expected => None,
                Ok(_) => Some(Drift::Modified(path)),
                Err(e) => Some(Drift::Unreadable(path, format!("{e:#}"))),
            }
        });
        files.chain(profiles).collect()
    }

    /// Whether the lock pins the moat profile in the Codex config at `path`.
    pub fn pins_codex_profile(&self, path: &Path) -> bool {
        self.codex_profiles.contains_key(&key(path))
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

    /// Drift that renaming `proposal` over the pinned `target` would leave: the
    /// target's own drift, else any difference between the proposal and the
    /// pinned contents. `None` when the target is not pinned.
    pub fn verify_proposal(&self, proposal: &Path, target: &Path) -> Option<Drift> {
        let expected = self.entries.get(&key(target))?;
        if let Some(drift) = self.verify_one(target) {
            return Some(drift);
        }
        match digest(proposal) {
            Ok(actual) if &actual == expected => None,
            Ok(_) => Some(Drift::Proposed {
                proposal: proposal.to_path_buf(),
                target: PathBuf::from(key(target)),
            }),
            Err(e) => Some(Drift::Unreadable(proposal.to_path_buf(), format!("{e:#}"))),
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
    Ok(sha256_hex(&bytes))
}

/// Lowercase hex SHA-256, as pinned in the lock and shown by `status`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        })
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
