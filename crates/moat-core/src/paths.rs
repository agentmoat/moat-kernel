//! Path normalisation without touching the filesystem (DESIGN.md §7.3).
//!
//! All paths are handled in a slash-separated canonical form on every platform:
//! `/Users/me/x` on Unix, `C:/Users/me/x` or `//server/share/x` on Windows.
//! Callers convert OS paths to this form (`\` → `/`) before passing them in.
//! Symlink resolution needs I/O and is done by the caller through
//! [`crate::realpath::PathResolver`]; the engine checks both paths.

/// Expand `~`, `$HOME`, `${project}` and make the path absolute against `cwd`,
/// then collapse `.` and `..` lexically.
#[must_use]
pub fn normalise(raw: &str, home: &str, project: &str, cwd: &str) -> String {
    let unified = raw.replace('\\', "/");
    let mut s = expand_home(&unified, home)
        .replace("${project}", project)
        .replace("${HOME}", home)
        .replace("$HOME", home);
    if !is_absolute(&s) {
        s = format!("{cwd}/{s}");
    }
    collapse(&s)
}

/// Absolute in canonical form: `/…`, `X:/…`, or UNC `//…`.
#[must_use]
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/') || drive_prefix(path).is_some()
}

/// `C:` for `C:/x`, `C:x` or `c:\x`; `None` otherwise.
fn drive_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':').then(|| &path[..2])
}

/// Lexically collapse `//`, `/./` and `/../` segments while preserving the root
/// (`/`, `C:/` or `//server`).
#[must_use]
pub fn collapse(path: &str) -> String {
    let (root, rest) = split_root(path);
    let mut out: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("{root}{}", out.join("/"))
}

fn split_root(path: &str) -> (String, &str) {
    if let Some(drive) = drive_prefix(path) {
        let rest = &path[2..];
        let root = format!("{}:/", drive[..1].to_ascii_uppercase());
        return (root, rest.trim_start_matches('/'));
    }
    if let Some(unc) = path.strip_prefix("//") {
        let (server, rest) = unc.split_once('/').unwrap_or((unc, ""));
        return (format!("//{server}/"), rest);
    }
    ("/".to_owned(), path.trim_start_matches('/'))
}

/// Expand `~` and `${project}` inside a *pattern* (not a path), leaving globs intact.
#[must_use]
pub fn expand_pattern(raw: &str, home: &str, project: &str) -> String {
    let (negated, body) = crate::pattern::split_negation(raw);
    let expanded = expand_home(body, home).replace("${project}", project);
    if negated {
        format!("!{expanded}")
    } else {
        expanded
    }
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
///
/// Besides the obvious prefixes, a token counts as a path when it traverses
/// (`src/../x`, `a/..`) or names a hidden entry (`.env`, `config/.env.local`,
/// `.ssh/id_rsa`): those are the relative forms that reach secrets, and a
/// bare `cat .env` must produce a file-read atom. Plain `a/b` tokens do not
/// qualify, so branch names, MIME types and `owner/repo` stay unclassified.
#[must_use]
pub fn looks_like_path(token: &str) -> bool {
    if token.contains("://") {
        return false;
    }
    token.starts_with('/')
        || token.starts_with("~/")
        || token == "~"
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with(".\\")
        || token.starts_with("..\\")
        || token.starts_with("$HOME/")
        || token.starts_with("${HOME}/")
        || token.starts_with("${project}/")
        || drive_prefix(token)
            .is_some_and(|_| matches!(token.as_bytes().get(2), Some(b'/' | b'\\')))
        || token.starts_with("\\\\")
        || traverses(token)
        || names_hidden_entry(token)
}

fn traverses(token: &str) -> bool {
    token == ".."
        || token
            .split(['/', '\\'])
            .enumerate()
            .any(|(i, seg)| seg == ".." && (i > 0 || token.len() > 2))
}

/// A segment such as `.env` or `.ssh` (not `.`, `..`, or a number like `.5`).
fn names_hidden_entry(token: &str) -> bool {
    token.split(['/', '\\']).any(|seg| {
        seg.len() > 1
            && seg != ".."
            && seg.starts_with('.')
            && !seg[1..].chars().all(|c| c.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_unix_paths() {
        assert_eq!(
            normalise("~/.ssh/id_rsa", "/Users/me", "/p", "/p"),
            "/Users/me/.ssh/id_rsa"
        );
        assert_eq!(
            normalise("src/../.env", "/Users/me", "/p", "/p/app"),
            "/p/app/.env"
        );
        assert_eq!(normalise("${project}/x", "/h", "/p", "/c"), "/p/x");
        assert_eq!(
            normalise("$HOME/.aws/credentials", "/h", "/p", "/c"),
            "/h/.aws/credentials"
        );
        assert_eq!(collapse("/a//b/./c/../d"), "/a/b/d");
        assert_eq!(collapse("/../x"), "/x");
    }

    #[test]
    fn normalises_windows_paths() {
        let home = "C:/Users/me";
        assert_eq!(
            normalise("~/.ssh/id_rsa", home, "C:/p", "C:/p"),
            "C:/Users/me/.ssh/id_rsa"
        );
        assert_eq!(
            normalise(r"C:\p\src\main.rs", home, "C:/p", "C:/p"),
            "C:/p/src/main.rs"
        );
        assert_eq!(
            normalise(r"src\lib.rs", home, "C:/p", "C:/p"),
            "C:/p/src/lib.rs"
        );
        assert_eq!(normalise("c:/P/../q", home, "C:/p", "C:/p"), "C:/q");
        assert_eq!(
            normalise(r"\\server\share\f.txt", home, "C:/p", "C:/p"),
            "//server/share/f.txt"
        );
        assert!(is_absolute("D:/x") && is_absolute("//srv/s") && !is_absolute("x/y"));
    }

    #[test]
    fn path_heuristics() {
        for token in [
            "/etc/passwd",
            "~/.ssh",
            "./a",
            "../a",
            r"C:\x",
            "D:/y",
            r".\x",
            r"\\srv\s",
        ] {
            assert!(looks_like_path(token), "{token}");
        }
        for token in ["main.rs", "C:", "https://x", "-v", "ab/cd"] {
            assert!(!looks_like_path(token), "{token}");
        }
    }

    #[test]
    fn relative_forms_that_reach_secrets_are_paths() {
        for token in [
            ".env",
            ".env.production",
            "config/.env.local",
            ".ssh/id_rsa",
            "src/../../.ssh/id_rsa",
            "a/..",
            "..",
            r"src\..\.env",
        ] {
            assert!(looks_like_path(token), "{token}");
        }
        for token in [
            "origin/main",
            "application/json",
            "owner/repo",
            ".",
            ".5",
            "s/foo/bar/",
            "https://x/.env",
            "fix.bug",
        ] {
            assert!(!looks_like_path(token), "{token}");
        }
    }
}
