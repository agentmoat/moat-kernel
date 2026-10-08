//! Filename expansion of unquoted glob operands, as the shell does it.
//!
//! The shell replaces an unquoted word holding `*`, `?` or `[` with the names
//! it matches before the command runs, so `cat .en?` reads `.env` although
//! the word never spells it. The classifier marks such operands (the lexer
//! knows the quoting, `Word::glob`) and the engine evaluates the literal path
//! and every path the pattern names. Listing a directory needs I/O, so it goes
//! through [`PathResolver::read_dir`]; a resolver that lists nothing leaves
//! only the literal, as `bash` does with a pattern that matches nothing.
//!
//! What a pattern names, component by component:
//! - a component without `*`, `?` or `[` is taken as written, without asking
//!   whether it exists: `~/.ss?/id_rsa` names `~/.ssh/id_rsa` once `~/.ssh`
//!   matches, so a file created after the check is covered too;
//! - other components match the entries of their directory; `*`, `?` and
//!   classes do not match a leading `.` unless the component starts with one
//!   (no `dotglob`), and `[^…]` negates like `[!…]`;
//! - `**` matches any number of directories, as with `globstar` or in `zsh`,
//!   which only adds paths to check.

use globset::{GlobBuilder, GlobMatcher};

use crate::paths;
use crate::realpath::PathResolver;

/// Most paths the globs of one tool call may name; past it the call asks.
pub const MAX_MATCHES: usize = 256;
/// Most directories listed for one tool call.
pub const MAX_LISTINGS: usize = 1024;
/// Most directories one `**` descends.
pub const MAX_GLOBSTAR_DEPTH: usize = 8;

/// The expansion of every glob of one tool call, sharing one budget.
pub(crate) struct Expansion<'r> {
    paths: &'r dyn PathResolver,
    matches: usize,
    listings: usize,
    exhausted: bool,
    /// The first pattern that was not expanded in full.
    overflow: Option<String>,
}

impl<'r> Expansion<'r> {
    pub(crate) fn new(paths: &'r dyn PathResolver) -> Self {
        Self {
            paths,
            matches: 0,
            listings: 0,
            exhausted: false,
            overflow: None,
        }
    }

    /// The paths the canonical absolute `pattern` names (module docs).
    pub(crate) fn paths(&mut self, pattern: &str) -> Vec<String> {
        let (root, rest) = paths::split_root(pattern);
        let components: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
        let mut out = Vec::new();
        self.walk(root, &components, 0, &mut out);
        if self.exhausted && self.overflow.is_none() {
            self.overflow = Some(pattern.to_owned());
        }
        out
    }

    /// Why the expansion is incomplete, when a bound stopped it: what was not
    /// listed may be a secret, so the call asks.
    pub(crate) fn overflow(self) -> Option<String> {
        self.overflow.map(|pattern| {
            format!(
                "glob `{pattern}` names more than can be checked \
                 ({MAX_MATCHES} paths, {MAX_LISTINGS} directories, {MAX_GLOBSTAR_DEPTH} levels of `**`)"
            )
        })
    }

    fn walk(&mut self, dir: String, components: &[&str], depth: usize, out: &mut Vec<String>) {
        if self.exhausted {
            return;
        }
        let Some((first, rest)) = components.split_first() else {
            self.matches += 1;
            self.exhausted = self.matches > MAX_MATCHES;
            out.push(dir);
            return;
        };
        if *first == "**" {
            let mut children = self.list(&dir);
            // Below its first directory, `**` stands only for directories: an
            // entry that lists nothing is a file (or empty) and holds nothing.
            if depth == 0 || !children.is_empty() {
                self.walk(dir.clone(), rest, depth, out);
            }
            children.retain(|name| !name.starts_with('.'));
            if depth == MAX_GLOBSTAR_DEPTH && !children.is_empty() {
                self.exhausted = true;
                return;
            }
            for name in children {
                self.walk(join(&dir, &name), components, depth + 1, out);
            }
            return;
        }
        let Some(glob) = component_glob(first) else {
            return self.walk(join(&dir, first), rest, depth, out);
        };
        for name in self.list(&dir) {
            let visible = first.starts_with('.') || !name.starts_with('.');
            // The name itself also counts: a project root spelled with `[`
            // (`/w/a[1]`) is still the directory it names.
            if name == *first || (visible && glob.is_match(&name)) {
                self.walk(join(&dir, &name), rest, depth, out);
            }
        }
    }

    fn list(&mut self, dir: &str) -> Vec<String> {
        self.listings += 1;
        if self.listings > MAX_LISTINGS {
            self.exhausted = true;
            return Vec::new();
        }
        self.paths.read_dir(dir)
    }
}

/// The matcher for one path component, or `None` when the shell takes it
/// literally: no `*`, `?` or `[`, or a class that is never closed.
fn component_glob(component: &str) -> Option<GlobMatcher> {
    if !component.contains(['*', '?', '[']) {
        return None;
    }
    GlobBuilder::new(&component.replace("[^", "[!"))
        .literal_separator(true)
        .backslash_escape(false)
        .build()
        .ok()
        .map(|g| g.compile_matcher())
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::programs::NoResolver;
    use crate::realpath::MapPathResolver;

    fn files(paths: &[&str]) -> MapPathResolver {
        MapPathResolver {
            files: paths.iter().map(|p| (*p).to_owned()).collect(),
            ..MapPathResolver::default()
        }
    }

    fn expand(resolver: &MapPathResolver, pattern: &str) -> Vec<String> {
        let mut paths = Expansion::new(resolver).paths(pattern);
        paths.sort();
        paths
    }

    #[test]
    fn patterns_name_what_the_shell_would_pass() {
        let fs = files(&[
            "/p/.env",
            "/p/.envrc",
            "/p/README.md",
            "/p/src/main.rs",
            "/p/src/lib.rs",
            "/p/src/deep/mod.rs",
            "/p/.git/config",
            "/h/.ssh/id_rsa",
        ]);
        for (pattern, expected) in [
            ("/p/.en?", &["/p/.env"][..]),
            ("/p/.e*", &["/p/.env", "/p/.envrc"]),
            ("/p/.[e]nv", &["/p/.env"]),
            ("/p/.[!x]nv", &["/p/.env"]),
            ("/p/.[^x]nv", &["/p/.env"]),
            ("/p/*", &["/p/README.md", "/p/src"]),
            ("/p/src/*.rs", &["/p/src/lib.rs", "/p/src/main.rs"]),
            ("/p/?rc/m*", &["/p/src/main.rs"]),
            ("/h/.ss?/id_rsa", &["/h/.ssh/id_rsa"]),
            ("/h/.ss?/authorized_keys", &["/h/.ssh/authorized_keys"]),
            ("/p/.e[", &["/p/.e["]),
            ("/p/*.txt", &[]),
        ] {
            assert_eq!(expand(&fs, pattern), expected, "{pattern}");
        }
        assert_eq!(
            expand(&fs, "/p/**/*.rs"),
            ["/p/src/deep/mod.rs", "/p/src/lib.rs", "/p/src/main.rs"]
        );
        assert_eq!(
            expand(&fs, "/p/**/.env"),
            ["/p/.env", "/p/src/.env", "/p/src/deep/.env"]
        );
    }

    #[test]
    fn a_literal_name_under_a_glob_root_is_kept() {
        let fs = files(&["/w/a[1]/x.rs", "/w/a1/y.rs"]);
        assert_eq!(expand(&fs, "/w/a[1]/*.rs"), ["/w/a1/y.rs", "/w/a[1]/x.rs"]);
    }

    #[test]
    fn nothing_listed_names_nothing() {
        let mut e = Expansion::new(&NoResolver);
        assert!(e.paths("/p/.en?").is_empty());
        assert_eq!(e.overflow(), None);
    }

    #[test]
    fn bounds_stop_the_expansion_and_say_so() {
        let many: Vec<String> = (0..=MAX_MATCHES).map(|n| format!("/p/f{n}")).collect();
        let fs = MapPathResolver {
            files: many,
            ..MapPathResolver::default()
        };
        let mut e = Expansion::new(&fs);
        assert_eq!(e.paths("/p/*").len(), MAX_MATCHES + 1);
        assert!(e.overflow().is_some_and(|r| r.contains("`/p/*`")));

        let deep = format!("/p/{}x", "d/".repeat(MAX_GLOBSTAR_DEPTH + 1));
        let fs = files(&[&deep]);
        let mut e = Expansion::new(&fs);
        e.paths("/p/**/x");
        assert!(e.overflow().is_some());
    }
}
