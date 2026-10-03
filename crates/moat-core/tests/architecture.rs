//! Architecture invariants for the trusted core (`REPO_STRUCTURE.md` §3).
//!
//! `moat-core` must stay pure: no internal crates, no I/O or runtime crates.
//! The wasm32 build in CI proves the absence of OS calls; this test keeps the
//! dependency list from drifting in the first place.

use std::fs;
use std::path::Path;

const ALLOWED_DEPENDENCIES: &[&str] = &["serde", "serde_yaml_ng", "globset", "thiserror"];

#[test]
fn core_depends_only_on_pure_crates() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = fs::read_to_string(&manifest).unwrap();
    let deps = section(&text, "[dependencies]");
    for name in deps {
        assert!(
            ALLOWED_DEPENDENCIES.contains(&name.as_str()),
            "moat-core gained dependency `{name}`; the core must stay free of I/O and internal crates"
        );
    }
}

#[test]
fn core_forbids_unsafe() {
    let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let combined = fs::read_to_string(lib).unwrap() + &fs::read_to_string(root).unwrap();
    assert!(
        combined.contains("unsafe_code = \"forbid\"") || combined.contains("forbid(unsafe_code)"),
        "unsafe must be forbidden for moat-core"
    );
}

#[test]
fn no_source_file_exceeds_the_size_budget() {
    const MAX_LINES: usize = 500;
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    visit(&src, &mut |path| {
        let lines = fs::read_to_string(path).unwrap().lines().count();
        if lines > MAX_LINES {
            offenders.push(format!("{} ({lines} lines)", path.display()));
        }
    });
    assert!(
        offenders.is_empty(),
        "split these files:\n{}",
        offenders.join("\n")
    );
}

fn section(toml: &str, header: &str) -> Vec<String> {
    toml.lines()
        .skip_while(|l| l.trim() != header)
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .filter_map(|l| {
            let key = l.split(['=', '.']).next()?.trim();
            (!key.is_empty() && !key.starts_with('#')).then(|| key.to_owned())
        })
        .collect()
}

fn visit(dir: &Path, f: &mut dyn FnMut(&Path)) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            visit(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            f(&path);
        }
    }
}
