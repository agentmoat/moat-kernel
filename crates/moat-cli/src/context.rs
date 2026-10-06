//! Environment and filesystem access: everything `openmoat-core` must not do itself.

use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{EvalContext, Policy};

use crate::home;
use crate::project;

/// Largest policy file accepted. Policies are human-written; anything bigger is
/// a mistake or an attack on the loader.
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

/// Read and lint a policy file.
pub fn load_policy(path: &Path) -> Result<Policy> {
    Policy::parse(&read_policy(path)?).with_context(|| format!("invalid policy {}", path.display()))
}

/// The text of a policy file, at most [`MAX_POLICY_BYTES`] of UTF-8.
pub fn read_policy(path: &Path) -> Result<String> {
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
    Ok(text)
}

/// Build the evaluation context from explicit flags and the process environment.
/// The project root defaults to the git root above `cwd` (`project::root_of`);
/// an explicit `project` that could never be trusted is an error, not a
/// silent change of meaning.
pub fn eval_context(cwd: Option<&Path>, project: Option<&Path>) -> Result<EvalContext> {
    let cwd = match cwd {
        Some(dir) => absolute(dir)?,
        None => std::env::current_dir().context("determining the current directory")?,
    };
    let home = home::user_home()?;
    let project = match project {
        Some(dir) => {
            let dir = absolute(dir)?;
            if !project::trusted(&dir, &home) {
                bail!(
                    "{} cannot be a project root: it is the home directory, one of its \
                     ancestors or a filesystem root",
                    dir.display()
                );
            }
            Some(dir)
        }
        None => project::root_of(&cwd, &home),
    };
    let home = path_string(&home);
    let project = project.as_deref().map(path_string);
    Ok(EvalContext {
        real_home: real_root(&home),
        real_project: project.as_deref().and_then(real_root),
        home,
        project,
        cwd: path_string(&cwd),
        case_insensitive_paths: CASE_INSENSITIVE_PATHS,
    })
}

/// The home directory as written and with its symlinks resolved (when that
/// differs), the spellings host-wide sandbox settings must cover.
pub fn home_spellings() -> Result<(String, Option<String>)> {
    let home = path_string(&home::user_home()?);
    let real = real_root(&home);
    Ok((home, real))
}

/// `root` with its symlinks resolved, when that differs from `root`: the form
/// the path resolver reports paths under it in (`realpath.rs`).
fn real_root(root: &str) -> Option<String> {
    let real = path_string(&fs::canonicalize(root).ok()?);
    (real != root).then_some(real)
}

/// Absolute and lexically normalised (`.` and `..` removed) without touching
/// the filesystem, the way `guard` takes the host's `cwd`.
///
/// `--project` and `--cwd` must name directories the same way the checked
/// action does: canonicalising only the roots turned `/tmp/p` into
/// `/private/tmp/p` on macOS and `RUNNER~1` into the long name on Windows, so
/// a file inside the project no longer matched `${project}/**`.
pub fn absolute(path: &Path) -> Result<PathBuf> {
    let absolute =
        std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
    let mut normalised = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalised.pop();
            }
            other => normalised.push(other),
        }
    }
    Ok(normalised)
}

/// Default file systems on macOS (APFS) and Windows (NTFS) ignore case, so
/// `~/.SSH/id_rsa` names the same file as `~/.ssh/id_rsa` there.
pub const CASE_INSENSITIVE_PATHS: bool = cfg!(any(target_os = "macos", windows));

/// The slash-separated canonical form the core works in (`docs/POLICY.md` §3.2).
pub fn path_string(path: &Path) -> String {
    slash_form(&path.to_string_lossy(), cfg!(windows))
}

/// On Windows: drop the verbatim prefix `canonicalize` adds (`\\?\C:\x`,
/// `\\?\UNC\srv\share`), which the core would read as a UNC path named `?`,
/// then use `/` as the separator.
fn slash_form(text: &str, windows: bool) -> String {
    if windows {
        strip_verbatim(text).replace('\\', "/")
    } else {
        text.to_owned()
    }
}

pub fn strip_verbatim(text: &str) -> String {
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(text).to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_made_absolute_lexically() {
        let base = std::env::current_dir().unwrap();
        assert_eq!(
            absolute(Path::new("a/./b/../c")).unwrap(),
            base.join("a").join("c")
        );
        let root = base.ancestors().last().unwrap();
        assert_eq!(absolute(&root.join("..")).unwrap(), root);
    }

    #[test]
    fn windows_verbatim_paths_become_canonical_slash_form() {
        assert_eq!(slash_form(r"\\?\C:\p\src", true), "C:/p/src");
        assert_eq!(slash_form(r"\\?\UNC\srv\share\x", true), "//srv/share/x");
        assert_eq!(slash_form(r"C:\p", true), "C:/p");
        assert_eq!(slash_form("/Users/me/p", false), "/Users/me/p");
        assert_eq!(strip_verbatim(r"\\?\C:\p"), r"C:\p");
    }
}
