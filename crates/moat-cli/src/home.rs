//! The kernel's own state directory (`~/.moat`, or `$MOAT_HOME`).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use moat_core::Policy;

use crate::context;

pub const DEFAULT_POLICY: &str = include_str!("../../../policies/default-v1.yaml");

#[derive(Debug, Clone)]
pub struct Home {
    root: PathBuf,
}

impl Home {
    /// Locate the state directory without creating it.
    pub fn locate() -> Result<Self> {
        let root = match std::env::var_os("MOAT_HOME").filter(|v| !v.is_empty()) {
            Some(custom) => PathBuf::from(custom),
            None => user_home()?.join(".moat"),
        };
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn policy_path(&self) -> PathBuf {
        self.root.join("policy.yaml")
    }

    pub fn audit_path(&self) -> PathBuf {
        self.root.join("audit.db")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.root.join("policy.lock")
    }

    pub fn environment_path(&self) -> PathBuf {
        self.root.join("environment.json")
    }

    pub fn grants_path(&self) -> PathBuf {
        self.root.join("approvals.json")
    }

    pub fn overlay_path(&self) -> PathBuf {
        self.root.join("policy.d").join("approved.yaml")
    }

    pub fn exists(&self) -> bool {
        self.root.is_dir()
    }

    /// Create the directory with owner-only permissions.
    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("creating {}", self.root.display()))?;
        restrict_dir(&self.root);
        Ok(())
    }

    /// Write the default policy unless one is already present. Returns `true` if written.
    pub fn ensure_policy(&self) -> Result<bool> {
        let path = self.policy_path();
        if path.exists() {
            return Ok(false);
        }
        write_private(&path, DEFAULT_POLICY.as_bytes())?;
        Ok(true)
    }

    /// Load and lint the installed user policy, with `moat allow --always` rules merged in.
    pub fn load_policy(&self) -> Result<Policy> {
        let path = self.policy_path();
        if !path.is_file() {
            bail!("no policy at {}; run `moat init`", path.display());
        }
        let mut policy = context::load_policy(&path)?;
        let overlay = crate::approvals::Overlay::load(&self.overlay_path())?;
        if !overlay.allow.is_empty() {
            policy.allow.extend(overlay.allow);
            policy
                .lint()
                .with_context(|| format!("merging {}", self.overlay_path().display()))?;
        }
        Ok(policy)
    }

    /// Create empty approval files so the lock covers them from the first run.
    pub fn ensure_approval_files(&self) -> Result<()> {
        if !self.grants_path().exists() {
            crate::approvals::Grants::default().save(&self.grants_path())?;
        }
        if !self.overlay_path().exists() {
            crate::approvals::Overlay::default().save(&self.overlay_path())?;
        }
        Ok(())
    }
}

/// Write a file atomically with owner-only permissions.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    restrict_file(&tmp);
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

pub fn user_home() -> Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(home) => Ok(PathBuf::from(home)),
        None => bail!("{var} is not set"),
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}
