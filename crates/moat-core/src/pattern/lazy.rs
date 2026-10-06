//! A glob parsed eagerly and compiled to a matcher on first use.

use std::sync::OnceLock;

use globset::{Glob, GlobMatcher};

/// Parsing a glob is what can fail, so it happens when the policy is compiled
/// and a bad pattern is still reported (and still fails `moat guard` closed)
/// before any decision. Building the regex behind the matcher cannot fail
/// (`Glob::compile_matcher` is infallible) but is the expensive part: a hook
/// call consults only the patterns for the kinds its action touches, so the
/// rest are never built.
#[derive(Debug, Clone)]
pub(super) struct LazyGlob {
    glob: Glob,
    matcher: OnceLock<GlobMatcher>,
}

impl LazyGlob {
    pub(super) fn new(glob: Glob) -> Self {
        Self {
            glob,
            matcher: OnceLock::new(),
        }
    }

    pub(super) fn is_match(&self, candidate: &str) -> bool {
        self.matcher
            .get_or_init(|| self.glob.compile_matcher())
            .is_match(candidate)
    }
}
