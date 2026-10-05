//! Shell patterns that match one command literally.
//!
//! A person who approves a command (`moat allow --always`) approves exactly
//! that command. Written as a rule, glob characters would become wildcards
//! (`cat *` would allow every `cat`), a leading `!` an exclusion and a
//! trailing `$` an end anchor, so each word is escaped before it becomes a
//! pattern.

use crate::lexer::{self, Token};
use crate::policy::PolicyError;

/// A shell pattern that matches `command` token for token and nothing wider.
///
/// Glob characters and `$` are put in one-character classes (`*` → `[*]`).
/// Words the pattern lexer would split or reinterpret (whitespace, quotes,
/// operators, a leading `!`) are single-quoted. Operators (`|`, `&&`, …) stay
/// operators. Shell rules are prefixes, so arguments appended after the
/// approved command still match.
pub fn literal_shell_pattern(command: &str) -> Result<String, PolicyError> {
    let bad = || PolicyError::BadShellPattern {
        pattern: command.to_owned(),
    };
    let tokens = lexer::lex(command.trim()).map_err(|_| bad())?;
    if tokens.is_empty() {
        return Err(PolicyError::EmptyPattern);
    }
    tokens
        .iter()
        .map(|token| match token {
            Token::Word(w) => Ok(literal_word(&w.text)),
            Token::Operator(op) => Ok(op.symbol().to_owned()),
            Token::HereDoc { .. } => Err(bad()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join(" "))
}

fn literal_word(text: &str) -> String {
    let escaped: String = text
        .chars()
        .map(|c| match c {
            '*' | '?' | '[' | ']' | '{' | '}' | '$' => format!("[{c}]"),
            // A backslash escapes the next character in a shell pattern; as
            // a one-character class it is literal.
            '\\' => "[\\\\]".to_owned(),
            c => c.to_string(),
        })
        .collect();
    let needs_quotes = escaped.is_empty()
        || escaped.starts_with('!')
        || escaped
            .chars()
            .any(|c| c.is_whitespace() || "'\"\\|&;<>()`#".contains(c));
    if needs_quotes {
        format!("'{}'", escaped.replace('\'', "'\\''"))
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::ShellPattern;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|w| (*w).to_owned()).collect()
    }

    fn compiled(command: &str) -> ShellPattern {
        ShellPattern::compile(&literal_shell_pattern(command).unwrap()).unwrap()
    }

    #[test]
    fn glob_characters_and_anchors_stay_literal() {
        assert_eq!(
            literal_shell_pattern("npm install left-pad").unwrap(),
            "npm install left-pad"
        );
        assert_eq!(literal_shell_pattern("cat *").unwrap(), "cat [*]");
        let cat = compiled("cat *");
        assert!(cat.is_match(&argv(&["cat", "*"])));
        assert!(
            !cat.is_match(&argv(&["cat", "~/.ssh/id_rsa"])),
            "`*` is not a wildcard"
        );
        let q = compiled("ls file?.[ch] {a,b}");
        assert!(q.is_match(&argv(&["ls", "file?.[ch]", "{a,b}"])));
        assert!(!q.is_match(&argv(&["ls", "file1.c", "a"])));
        let bang = compiled("!echo hi $");
        assert!(!bang.negated, "a leading `!` stays literal");
        assert!(
            bang.is_match(&argv(&["!echo", "hi", "$", "more"])),
            "`$` is not an anchor"
        );
    }

    #[test]
    fn backslashes_stay_literal() {
        // `\` left a dangling
        // escape in the glob, so the approved rule broke the whole policy.
        for command in ["++\\\\", "printf 'a\\nb'", "echo C:\\\\temp"] {
            let pattern = literal_shell_pattern(command).unwrap();
            let compiled = ShellPattern::compile(&pattern)
                .unwrap_or_else(|e| panic!("{command:?} -> {pattern:?}: {e}"));
            let words: Vec<String> = crate::lexer::lex(command)
                .unwrap()
                .into_iter()
                .map(|t| t.to_string())
                .collect();
            assert!(compiled.is_match(&words), "{command:?} -> {pattern:?}");
        }
    }

    #[test]
    fn quotes_and_operators_round_trip() {
        assert!(compiled("echo \"it's\"").is_match(&argv(&["echo", "it's"])));
        let piped = compiled("npm test | tee out.log");
        assert!(piped.is_match(&argv(&["npm", "test", "|", "tee", "out.log"])));
    }

    #[test]
    fn unusable_commands_are_errors() {
        assert!(matches!(
            literal_shell_pattern("echo 'unterminated"),
            Err(PolicyError::BadShellPattern { .. })
        ));
        assert!(matches!(
            literal_shell_pattern("   "),
            Err(PolicyError::EmptyPattern)
        ));
        assert!(literal_shell_pattern("cat <<EOF\nx\nEOF\n").is_err());
    }
}
