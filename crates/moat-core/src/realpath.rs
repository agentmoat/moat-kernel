//! Symlink resolution of action paths, supplied by the caller.
//!
//! Policy patterns name locations (`~/.ssh/**`, `${project}/**`), but a path an
//! agent writes can reach a location through a symlink: after
//! `ln -s ~/.ssh ./s`, `cat ./s/id_rsa` reads the private key while its literal
//! path is inside the project. The core cannot look at the filesystem, so the
//! caller resolves each normalised path and the engine checks the literal and
//! the resolved path; the strictest verdict wins (DESIGN.md §7.3).

use std::collections::BTreeMap;

use crate::programs::NoResolver;

/// Resolves symlinks in normalised, slash-separated absolute paths.
pub trait PathResolver {
    /// The path `path` really refers to, or `None` when it is the same path or
    /// cannot be resolved. Paths that do not exist yet resolve through their
    /// deepest existing ancestor, so a new file written into a symlinked
    /// directory still resolves to where it would land.
    fn resolve(&self, path: &str) -> Option<String>;
}

impl PathResolver for NoResolver {
    fn resolve(&self, _path: &str) -> Option<String> {
        None
    }
}

/// In-memory resolver for tests and conformance fixtures: symlink path →
/// target. The longest link that is the path itself or one of its ancestors
/// is replaced by its target.
#[derive(Debug, Default, Clone)]
pub struct MapPathResolver {
    /// Symlink path → target.
    pub links: BTreeMap<String, String>,
}

impl PathResolver for MapPathResolver {
    fn resolve(&self, path: &str) -> Option<String> {
        self.links
            .iter()
            .filter_map(|(link, target)| {
                let rest = path.strip_prefix(link.as_str())?;
                (rest.is_empty() || rest.starts_with('/')).then_some((link.len(), target, rest))
            })
            .max_by_key(|(len, _, _)| *len)
            .map(|(_, target, rest)| format!("{target}{rest}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_resolver_replaces_the_longest_linked_ancestor() {
        let r = MapPathResolver {
            links: BTreeMap::from([
                ("/p/s".to_owned(), "/h/.ssh".to_owned()),
                ("/p/s/k".to_owned(), "/h/.aws/credentials".to_owned()),
            ]),
        };
        assert_eq!(r.resolve("/p/s").as_deref(), Some("/h/.ssh"));
        assert_eq!(r.resolve("/p/s/id_rsa").as_deref(), Some("/h/.ssh/id_rsa"));
        assert_eq!(r.resolve("/p/s/k").as_deref(), Some("/h/.aws/credentials"));
        assert_eq!(r.resolve("/p/sx/id_rsa"), None);
        assert_eq!(r.resolve("/p/src/main.rs"), None);
        assert_eq!(NoResolver.resolve("/p/s"), None);
    }
}
