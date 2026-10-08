//! Virtual environments: what `python -m venv` creates and what sourcing an
//! activate script reads.

use super::*;

#[test]
fn venv_directories_are_writes() {
    let atoms = parsed("python3 -m venv .venv");
    assert!(has_write(&atoms, "/p/.venv"));
    // A plain name is a directory venv creates, not just a word.
    assert!(has_write(&parsed("python -m venv env"), "/p/env"));
    let atoms = parsed("cd /tmp && python3 -m venv --prompt x env");
    assert!(has_write(&atoms, "/tmp/env"));
    assert!(has_write(&atoms, "/tmp/x"));
    assert!(has_write(&parsed("python3 -m venv ~/env"), "/Users/me/env"));
}

#[test]
fn other_modules_write_nothing() {
    let atoms = parsed("python3 -m pytest tests");
    assert!(
        !atoms
            .iter()
            .any(|a| matches!(a, AtomicAction::FsWrite { .. }))
    );
}

#[test]
fn activate_script_is_read_where_it_resolves() {
    assert!(has_read(
        &parsed("source .venv/bin/activate"),
        "/p/.venv/bin/activate"
    ));
    assert!(has_read(
        &parsed(". .venv/bin/../../../Users/me/.zshrc"),
        "/Users/me/.zshrc"
    ));
}
