//! Symlink resolution of action paths for the engine (`moat_core::PathResolver`).
//!
//! `moat guard` checks every path a tool call reads or writes where it really
//! points as well as where it was written, so `cat ./s/id_rsa` after
//! `ln -s ~/.ssh ./s` meets the `~/.ssh/**` deny. Resolution happens at
//! decision time; a link swapped afterwards is out of reach until OS
//! enforcement exists (ADR-009).

use std::fs;
use std::path::{Path, PathBuf};

use moat_core::{EvalContext, PathResolver};

use crate::context::path_string;

/// Dangling links followed before giving up; the OS limit is about 40, but a
/// chain this long in an agent's working tree is already suspicious and the
/// literal path is still checked.
const MAX_LINK_HOPS: u8 = 8;

/// Resolves through the real filesystem, then rewrites the result back onto the
/// project and home prefixes the policy was compiled with. Without that, a
/// project under a symlinked directory (macOS `/tmp` → `/private/tmp`, or a
/// symlinked home) would resolve every in-project path to a location
/// `${project}/**` does not name.
#[derive(Debug)]
pub struct FsPathResolver {
    /// `(canonical, as the policy sees it)`, longest canonical prefix first.
    roots: Vec<(String, String)>,
}

impl FsPathResolver {
    pub fn new(ctx: &EvalContext) -> Self {
        let mut roots: Vec<(String, String)> = ctx
            .project
            .iter()
            .chain([&ctx.home])
            .filter_map(|logical| {
                let canonical = path_string(&fs::canonicalize(logical).ok()?);
                (&canonical != logical).then(|| (canonical, logical.clone()))
            })
            .collect();
        roots.sort_by_key(|(canonical, _)| std::cmp::Reverse(canonical.len()));
        Self { roots }
    }

    fn reroot(&self, real: String) -> String {
        for (canonical, logical) in &self.roots {
            if let Some(rest) = real.strip_prefix(canonical.as_str())
                && (rest.is_empty() || rest.starts_with('/'))
            {
                return format!("{logical}{rest}");
            }
        }
        real
    }
}

impl PathResolver for FsPathResolver {
    fn resolve(&self, path: &str) -> Option<String> {
        let real = self.reroot(path_string(&real_path(Path::new(path), MAX_LINK_HOPS)?));
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
        let r = FsPathResolver { roots: Vec::new() };
        assert_eq!(r.resolve("/moat-missing-root/src/lib.rs"), None);
    }

    #[cfg(unix)]
    fn setup() -> (tempfile::TempDir, EvalContext, FsPathResolver) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let project = home.join("proj");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(home.join(".ssh/id_rsa"), "key").unwrap();
        let ctx = EvalContext {
            home: path_string(&home),
            project: Some(path_string(&project)),
            cwd: path_string(&project),
            case_insensitive_paths: false,
        };
        let resolver = FsPathResolver::new(&ctx);
        (dir, ctx, resolver)
    }

    #[cfg(unix)]
    #[test]
    fn plain_paths_inside_the_project_resolve_to_themselves() {
        let (_dir, ctx, r) = setup();
        let p = ctx.project.as_deref().unwrap();
        assert_eq!(r.resolve(&format!("{p}/src")), None);
        assert_eq!(r.resolve(&format!("{p}/src/new/file.rs")), None);
    }

    #[cfg(unix)]
    #[test]
    fn linked_directories_and_files_resolve_to_their_target() {
        let (_dir, ctx, r) = setup();
        let (h, p) = (&ctx.home, ctx.project.as_deref().unwrap());
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
        let (_dir, ctx, r) = setup();
        let p = ctx.project.as_deref().unwrap();
        symlink(format!("{p}/b"), format!("{p}/a")).unwrap();
        symlink(format!("{p}/a"), format!("{p}/b")).unwrap();
        assert_eq!(r.resolve(&format!("{p}/a")), None);
    }
}
