//! Environment and filesystem access: everything `moat-core` must not do itself.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use moat_core::{EvalContext, Policy};

use crate::home;
use crate::project;

/// Largest policy file accepted. Policies are human-written; anything bigger is
/// a mistake or an attack on the loader.
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

/// Read and lint a policy file.
pub fn load_policy(path: &Path) -> Result<Policy> {
    let file =
        fs::File::open(path).with_context(|| format!("opening policy {}", path.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("reading metadata of {}", path.display()))?
        .len();
    if size > MAX_POLICY_BYTES {
        bail!(
            "policy {} is {size} bytes; the limit is {MAX_POLICY_BYTES}",
            path.display()
        );
    }
    let mut text = String::with_capacity(usize::try_from(size).unwrap_or(0));
    file.take(MAX_POLICY_BYTES)
        .read_to_string(&mut text)
        .with_context(|| format!("reading policy {} (must be UTF-8)", path.display()))?;
    Policy::parse(&text).with_context(|| format!("invalid policy {}", path.display()))
}

/// Build the evaluation context from explicit flags and the process environment.
/// The project root defaults to the git root above `cwd`.
pub fn eval_context(cwd: Option<&Path>, project: Option<&Path>) -> Result<EvalContext> {
    let cwd = match cwd {
        Some(dir) => absolute(dir)?,
        None => std::env::current_dir().context("determining the current directory")?,
    };
    let project = match project {
        Some(dir) => absolute(dir)?,
        None => project::root_of(&cwd),
    };
    Ok(EvalContext {
        home: path_string(&home::user_home()?),
        project: path_string(&project),
        cwd: path_string(&cwd),
    })
}

/// Canonical path when it exists (resolving symlinks such as macOS `/tmp`),
/// otherwise a lexically absolute path.
fn absolute(path: &Path) -> Result<PathBuf> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }
    std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))
}

pub fn path_string(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.into_owned()
    }
}
