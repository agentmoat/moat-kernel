use super::script::{Effects, effects};

#[test]
fn printing_scripts_touch_nothing() {
    for script in [
        "1,20p",
        "$p",
        "s/a/b/",
        "s|/usr|/opt|g",
        "s|[/]|x|;p",
        "/start/,/end/p",
        "\\,a/b,d",
        "0~4p; 1,+3d; 2,~5 !p",
        "/x/I,/y/M{s/(a|b)+/[&]/2;p;=}",
        "s/[[:space:]]*$//",
        ":a;N;$!ba;s/\\n/ /g",
        "y/abc/xyz/",
        "1i\\\nheader; e id\n$a footer",
        "q5",
        "#n\nl 40",
        "",
    ] {
        assert_eq!(effects(script), Some(Effects::default()), "{script:?}");
    }
}

#[test]
fn files_read_and_written() {
    let found = effects("1r /etc/hosts\n/x/w out.txt\ns/a/b/gw log; p\nR in").unwrap();
    assert_eq!(found.reads, ["/etc/hosts", "in"]);
    assert_eq!(found.writes, ["out.txt", "log; p"]);
}

#[test]
fn executing_and_unreadable_scripts_are_unknown() {
    for script in [
        "1e id",
        "e",
        "s/x/id/e",
        "s/x/id/ge",
        "p;e id",
        "/x/{e id\n}",
        "F",
        "v",
        "1",
        "s/a/b",
        "s/a\nb/c/",
        "y/a/",
        "p x",
        "b x a;e id",
        "b x#;e id",
        // GNU ends the regex at the `/` inside the brackets, BSD does not
        "s/[/]/x/e",
        "s/[]/]e/x/",
        "s:[[:alpha:]]:x:",
        "w",
        "-e",
    ] {
        assert_eq!(effects(script), None, "{script:?}");
    }
}
