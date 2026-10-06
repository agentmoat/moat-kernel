//! Symlink resolution of action paths for the engine (`openmoat_core::PathResolver`).
//!
//! `moat guard` checks every path a tool call reads or writes where it really
//! points as well as where it was written, so `cat ./s/id_rsa` after
//! `ln -s ~/.ssh ./s` meets the `~/.ssh/**` deny. Resolution happens at
//! decision time; a link swapped afterwards is out of reach until OS
//! enforcement exists (ADR-009).

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::PathResolver;

use crate::context::path_string;

/// Dangling links followed before giving up; the OS limit is about 40, but a
/// chain this long in an agent's working tree is already suspicious and the
/// literal path is still checked.
const MAX_LINK_HOPS: u8 = 8;

/// Resolves through the real filesystem. The policy is compiled for the
/// resolved spellings of the project and home roots too (`context.rs`), so a
/// project under a symlinked directory (macOS `/tmp` → `/private/tmp`) still
/// matches `${project}/**` once its paths are resolved.
#[derive(Debug)]
pub struct FsPathResolver;

impl PathResolver for FsPathResolver {
    fn resolve(&self, path: &str) -> Option<String> {
        let real = path_string(&real_path(Path::new(path), MAX_LINK_HOPS)?);
        (real != path).then_some(real)
    }
}

/// Canonical form of `path`. A path that does not exist resolves through its
/// deepest existing ancestor; a dangling symlink through its target. A root is
/// kept as written: it cannot be a link, and on Windows `canonicalize("/")`
/// would turn a drive-less path into one on the current drive.
fn real_path(path: &Path, hops: u8) -> Option<PathBuf> {
    if path.parent().is_none() {
        return Some(path.to_path_buf());
    }
    if let Ok(real) = fs::canonicalize(path) {
        return Some(real);
    }
    let parent = path.parent()?;
    if let Ok(target) = fs::read_link(path) {
        return real_path(&parent.join(target), hops.checked_sub(1)?);
    }
    Some(real_path(parent, hops)?.join(path.file_name()?))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn missing_paths_keep_their_root() {
        assert_eq!(
            FsPathResolver.resolve("/moat-missing-root/src/lib.rs"),
            None
        );
    }

    /// A home with a project in it, under a temporary directory with its own
    /// links (macOS `/var` → `/private/var`) resolved: `(dir, home, project)`.
    #[cfg(unix)]
    fn setup() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(dir.path()).unwrap().join("home");
        let project = home.join("proj");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(home.join(".ssh/id_rsa"), "key").unwrap();
        (dir, path_string(&home), path_string(&project))
    }

    #[cfg(unix)]
    #[test]
    fn plain_paths_inside_the_project_resolve_to_themselves() {
        let (_dir, _, p) = setup();
        let r = FsPathResolver;
        assert_eq!(r.resolve(&format!("{p}/src")), None);
        assert_eq!(r.resolve(&format!("{p}/src/new/file.rs")), None);
    }

    #[cfg(unix)]
    #[test]
    fn linked_directories_and_files_resolve_to_their_target() {
        let (_dir, h, p) = setup();
        let r = FsPathResolver;
        symlink(format!("{h}/.ssh"), format!("{p}/s")).unwrap();
        assert_eq!(
            r.resolve(&format!("{p}/s/id_rsa")),
            Some(format!("{h}/.ssh/id_rsa"))
        );
        assert_eq!(
            r.resolve(&format!("{p}/s/authorized_keys")),
            Some(format!("{h}/.ssh/authorized_keys")),
            "a file that does not exist yet resolves through its directory"
        );
        symlink("../.ssh/known_hosts", format!("{p}/k")).unwrap();
        assert_eq!(
            r.resolve(&format!("{p}/k")),
            Some(format!("{h}/.ssh/known_hosts")),
            "a dangling relative link resolves through its target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn link_loops_give_up() {
        let (_dir, _, p) = setup();
        let r = FsPathResolver;
        symlink(format!("{p}/b"), format!("{p}/a")).unwrap();
        symlink(format!("{p}/a"), format!("{p}/b")).unwrap();
        assert_eq!(r.resolve(&format!("{p}/a")), None);
    }
}
