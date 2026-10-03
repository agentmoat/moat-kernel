//! Path normalisation without touching the filesystem (DESIGN.md §7.3).
//!
//! Symlink resolution needs I/O and is done by the caller, which may pass both
//! the literal and the resolved path through [`crate::engine::evaluate`].

/// Expand `~`, `$HOME`, `${project}` and make the path absolute against `cwd`,
/// then collapse `.` and `..` lexically.
#[must_use]
pub fn normalise(raw: &str, home: &str, project: &str, cwd: &str) -> String {
    let mut s = expand_home(raw, home);
    s = s
        .replace("${project}", project)
        .replace("${HOME}", home)
        .replace("$HOME", home);
    if !s.starts_with('/') {
        s = format!("{cwd}/{s}");
    }
    collapse(&s)
}

/// Lexically collapse `//`, `/./` and `/../` segments.
#[must_use]
pub fn collapse(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    format!("/{joined}")
}

/// Expand `~` and `${project}` inside a *pattern* (not a path), leaving globs intact.
#[must_use]
pub fn expand_pattern(raw: &str, home: &str, project: &str) -> String {
    let (neg, body) = match raw.strip_prefix('!') {
        Some(b) => ("!", b),
        None => ("", raw),
    };
    let s = expand_home(body, home).replace("${project}", project);
    format!("{neg}{s}")
}

fn expand_home(raw: &str, home: &str) -> String {
    if let Some(rest) = raw.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if raw == "~" {
        home.to_owned()
    } else {
        raw.to_owned()
    }
}

/// Heuristic: does this shell token look like a filesystem path?
#[must_use]
pub fn looks_like_path(token: &str) -> bool {
    token.starts_with('/')
        || token.starts_with("~/")
        || token == "~"
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with("$HOME/")
        || token.starts_with("${HOME}/")
        || token.starts_with("${project}/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises() {
        assert_eq!(
            normalise("~/.ssh/id_rsa", "/Users/me", "/p", "/p"),
            "/Users/me/.ssh/id_rsa"
        );
        assert_eq!(
            normalise("src/../.env", "/Users/me", "/p", "/p/app"),
            "/p/app/.env"
        );
        assert_eq!(normalise("${project}/x", "/h", "/p", "/c"), "/p/x");
        assert_eq!(collapse("/a//b/./c/../d"), "/a/b/d");
    }
}
