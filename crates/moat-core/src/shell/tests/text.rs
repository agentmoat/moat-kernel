//! Text tools: option values and program text are data (`shell/text.rs`).

use super::*;

#[test]
fn option_values_are_not_files() {
    let a = parsed("cut -d '/' -f 2 paths.txt");
    assert!(has_read(&a, "/p/paths.txt"));
    assert!(!has_read(&a, "/"));
    assert!(has_read(&parsed("sort -t / -k 2 x"), "/p/x"));
    assert!(!has_read(&parsed("sort -t / -k 2 x"), "/"));
}

#[test]
fn written_files() {
    assert!(has_write(&parsed("sort -o /tmp/out data.txt"), "/tmp/out"));
    assert!(has_write(&parsed("sort -no/tmp/out data.txt"), "/tmp/out"));
    assert!(has_write(
        &parsed("sort data.txt --output ~/.zshrc"),
        "/Users/me/.zshrc"
    ));
    assert!(has_write(&parsed("sort -T /tmp/t data.txt"), "/tmp/t"));
    let a = parsed("uniq -c -f 1 in.txt ~/.bashrc");
    assert!(has_read(&a, "/p/in.txt"));
    assert!(has_write(&a, "/Users/me/.bashrc"));
    assert!(!has_write(&parsed("uniq -c in.txt"), "/p/in.txt"));
}

#[test]
fn a_value_after_an_operand_may_be_a_file() {
    // BSD getopt stops at `data.txt`, so `-t` and `s` are files it reads.
    assert!(has_read(&parsed("sort data.txt -t s"), "/p/s"));
}

#[test]
fn unknown_options_are_reported() {
    for (cmd, marker) in [
        (
            "sort --compress-program=sh x",
            "sort @--compress-program=sh",
        ),
        ("sort --files0-from=list", "sort @--files0-from=list"),
        ("uniq --frobnicate x", "uniq @--frobnicate"),
        ("cut -Q x", "cut @-Q"),
    ] {
        assert!(has_shell(&parsed(cmd), marker), "{cmd}");
    }
    assert!(
        !parsed("sort -rn -k2 x | uniq -c")
            .iter()
            .any(|a| matches!(a, AtomicAction::Shell { argv } if argv[1].starts_with('@')))
    );
}
