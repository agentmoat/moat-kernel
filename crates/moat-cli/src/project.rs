//! Project root discovery: the nearest ancestor that is a git work tree.

use std::path::{Path, PathBuf};

/// Walk up from `start` to the first directory containing `.git`
/// (a directory, or the file git uses for worktrees). Falls back to `start`.
pub fn root_of(start: &Path) -> PathBuf {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map_or_else(|| start.to_path_buf(), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::root_of;

    #[test]
    fn finds_git_root_or_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let nested = repo.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(root_of(&nested), nested);
        std::fs::create_dir(repo.join(".git")).unwrap();
        assert_eq!(root_of(&nested), repo);
        std::fs::remove_dir(repo.join(".git")).unwrap();
        std::fs::write(repo.join(".git"), "gitdir: ../main/.git/worktrees/x").unwrap();
        assert_eq!(root_of(&nested), repo);
    }
}
