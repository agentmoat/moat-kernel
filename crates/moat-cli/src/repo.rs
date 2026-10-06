//! The repository policy of a session's project (ADR-022): found and read here,
//! merged by `moat_core::RepoPolicy`.
//!
//! The file is attacker-controlled input. One that exists but cannot be read
//! or parsed is an error, so `guard` denies with `kernel-error` rather than
//! dropping the team's deny rules.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use moat_core::{EvalContext, Policy, RepoPolicy};

use crate::context;
use crate::home::Home;

/// The repository policy file of the project at `root`.
fn path(root: &Path) -> PathBuf {
    root.join(".moat").join("policy.yaml")
}

/// The project's repository policy, if it has one.
pub fn find(home: &Home, root: &Path) -> Result<Option<(PathBuf, RepoPolicy)>> {
    let path = path(root);
    let meta = match fs::metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        meta => meta.with_context(|| format!("reading repository policy {}", path.display()))?,
    };
    // `$MOAT_HOME` set to the project's `.moat`: that is moat's own state.
    let canonical = |p: &Path| fs::canonicalize(p).ok();
    if path.parent().and_then(canonical) == canonical(home.root()) {
        return Ok(None);
    }
    // A FIFO would block the hook until the host times it out, and a host may
    // proceed then; a directory or a device is no policy either.
    if !meta.is_file() {
        bail!("repository policy {} is not a regular file", path.display());
    }
    let policy = RepoPolicy::parse(&context::read_policy(&path)?)
        .with_context(|| format!("invalid repository policy {}", path.display()))?;
    Ok(Some((path, policy)))
}

/// The user policy with the project's repository policy merged in, as `guard`
/// decides with it: tightening only.
pub fn effective_policy(home: &Home, ctx: &EvalContext) -> Result<Policy> {
    let user = home.load_policy()?;
    let Some(root) = &ctx.project else {
        return Ok(user);
    };
    let Some((path, repo)) = find(home, Path::new(root))? else {
        return Ok(user);
    };
    repo.merge(&user, false)
        .with_context(|| format!("merging repository policy {}", path.display()))
}
