//! Files named by a Codex `apply_patch` envelope.
//!
//! ```text
//! *** Begin Patch
//! *** Add File: path        (create)
//! *** Update File: path     (edit; may be followed by `*** Move to: other`)
//! *** Delete File: path
//! *** End Patch
//! ```
//!
//! Every named path is written (a delete or a move removes its source). A
//! patch that names no file is passed on empty and decided as unparseable.

const HEADERS: &[&str] = &[
    "*** Add File:",
    "*** Update File:",
    "*** Delete File:",
    "*** Move to:",
];

pub(crate) fn writes(text: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let Some(path) = HEADERS
            .iter()
            .find_map(|h| line.strip_prefix(h))
            .map(str::trim)
            .filter(|p| !p.is_empty())
        else {
            continue;
        };
        if !paths.iter().any(|p| p == path) {
            paths.push(path.to_owned());
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_header_names_a_written_file() {
        let patch = "*** Begin Patch\n*** Add File: src/new.rs\n+fn x() {}\n\
                     *** Update File: src/lib.rs\n*** Move to: src/core.rs\n@@\n-a\n+b\n\
                     *** Delete File: old.txt\r\n*** Update File: src/lib.rs\n*** End Patch\n";
        assert_eq!(
            writes(patch),
            ["src/new.rs", "src/lib.rs", "src/core.rs", "old.txt"]
        );
    }

    #[test]
    fn added_lines_that_look_like_headers_are_content() {
        // An added line `+*** Add File: x` starts with `+`, so it is content.
        assert_eq!(writes("*** Add File: a\n+*** Add File: ~/.zshrc\n"), ["a"]);
    }

    #[test]
    fn no_headers_means_no_files() {
        assert!(writes("just text").is_empty());
        assert!(writes("*** Add File:   \n").is_empty());
    }
}
