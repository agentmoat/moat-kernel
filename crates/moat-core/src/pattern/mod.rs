//! Pattern matching helpers shared by all rule kinds (DESIGN.md §6.2).

use globset::{Glob, GlobBuilder, GlobMatcher};

mod literal;
pub use literal::literal_shell_pattern;

use crate::lexer;
use crate::policy::PolicyError;

/// A compiled glob for paths, hosts, env names and MCP tool names.
#[derive(Debug, Clone)]
pub struct GlobPattern {
    source: String,
    matcher: GlobMatcher,
    /// `!pattern` inside an allow list excludes matches (DESIGN.md §6.2).
    pub negated: bool,
}

impl GlobPattern {
    pub fn compile(raw: &str, case_insensitive: bool) -> Result<Self, PolicyError> {
        let (negated, body) = match raw.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        if body.is_empty() {
            return Err(PolicyError::EmptyPattern);
        }
        let glob: Glob = GlobBuilder::new(body)
            .literal_separator(true)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|e| PolicyError::BadGlob {
                pattern: raw.to_owned(),
                source: e,
            })?;
        Ok(Self {
            source: raw.to_owned(),
            matcher: glob.compile_matcher(),
            negated,
        })
    }

    #[must_use]
    pub fn is_match(&self, candidate: &str) -> bool {
        self.matcher.is_match(candidate)
    }

    /// True when every candidate `other` matches is also matched by `self`.
    /// Negated patterns never cover. Conservative: a glob `other` is covered
    /// only by the same glob or by `self` = `prefix/**` with `other` under `prefix/`.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        if self.negated || other.negated {
            return false;
        }
        let (mine, theirs) = (&self.source, &other.source);
        if !has_glob_syntax(theirs) {
            return self.is_match(theirs);
        }
        mine == theirs
            || mine.strip_suffix("**").is_some_and(|prefix| {
                prefix.ends_with('/') && !has_glob_syntax(prefix) && theirs.starts_with(prefix)
            })
    }
}

/// Evaluate a list of (possibly negated) globs: a candidate matches if at
/// least one positive pattern matches and no negated pattern matches.
#[must_use]
pub fn any_match(patterns: &[GlobPattern], candidate: &str) -> bool {
    let mut positive = false;
    for p in patterns {
        if p.is_match(candidate) {
            if p.negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

#[derive(Debug, Clone)]
enum Token {
    /// A bare `*`: matches zero or more argv tokens.
    Any,
    /// A glob matched against exactly one argv token, with its source text.
    One(GlobMatcher, String),
    /// A trailing `$`: argv must end here.
    End,
}

/// Shell rule: an ordered token sequence matched as a **prefix** of argv.
///
/// Semantics (DESIGN.md §6.2):
/// - a bare `*` token matches any number of argv tokens (including none);
/// - any other token is a glob matched against exactly one argv token
///   (`--force*` matches `--force-with-lease`);
/// - the pattern is a prefix: extra argv tokens after a full match are accepted,
///   unless the last token is a bare `$`, which matches only the end of argv
///   (`env $` is `env` with no arguments, not `env FOO=1 cmd`). A `$` anywhere
///   else is an ordinary token.
///   `git status` therefore also matches `git status --short`; pipelines and
///   `&&` lists are split and matched per sub-command and as whole pipelines
///   (see `shell/commands.rs`), so `git status | sh` is still caught by `* | sh` rules.
#[derive(Debug, Clone)]
pub struct ShellPattern {
    source: String,
    tokens: Vec<Token>,
    /// `!pattern` excludes matches from its list, as for globs (ADR-012).
    pub negated: bool,
}

/// Evaluate a list of (possibly negated) shell patterns like [`any_match`].
#[must_use]
pub fn any_shell_match(patterns: &[ShellPattern], argv: &[String]) -> bool {
    let mut positive = false;
    for p in patterns {
        if p.is_match(argv) {
            if p.negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

impl ShellPattern {
    pub fn compile(raw: &str) -> Result<Self, PolicyError> {
        // Patterns are tokenised with the same lexer as commands so that `a|b`
        // and `a | b` mean the same thing on both sides of the match.
        let (negated, body) = match raw.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        let lexed = lexer::lex(body).map_err(|_| PolicyError::BadShellPattern {
            pattern: raw.to_owned(),
        })?;
        let mut words = Vec::with_capacity(lexed.len());
        for token in lexed {
            match token {
                lexer::Token::Word(w) => words.push(w.text),
                lexer::Token::Operator(op) => words.push(op.symbol().to_owned()),
                lexer::Token::HereDoc { .. } => {
                    return Err(PolicyError::BadShellPattern {
                        pattern: raw.to_owned(),
                    });
                }
            }
        }
        let anchored = words.last().is_some_and(|w| w == "$");
        if anchored {
            words.pop();
        }
        if words.is_empty() {
            return Err(PolicyError::EmptyPattern);
        }
        let mut tokens = words
            .iter()
            .map(|w| {
                if w == "*" {
                    return Ok(Token::Any);
                }
                GlobBuilder::new(w)
                    .literal_separator(false)
                    .build()
                    .map(|g| Token::One(g.compile_matcher(), w.clone()))
                    .map_err(|e| PolicyError::BadGlob {
                        pattern: raw.to_owned(),
                        source: e,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if anchored {
            tokens.push(Token::End);
        }
        Ok(Self {
            source: raw.to_owned(),
            tokens,
            negated,
        })
    }

    #[must_use]
    pub fn is_match(&self, argv: &[String]) -> bool {
        matches_from(&self.tokens, argv)
    }

    /// True when every command `other` matches is also matched by `self`.
    /// Conservative: `false` when that cannot be shown from the patterns alone.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        if self.negated || other.negated {
            return false;
        }
        let anchored = |p: &Self| matches!(p.tokens.last(), Some(Token::End));
        let Ok(lexed) = lexer::lex(&other.source) else {
            return false;
        };
        let mut words: Vec<String> = lexed
            .into_iter()
            .filter_map(|t| match t {
                lexer::Token::Word(w) => Some(w.text),
                lexer::Token::Operator(op) => Some(op.symbol().to_owned()),
                lexer::Token::HereDoc { .. } => None,
            })
            .collect();
        if anchored(other) {
            words.pop();
        } else if anchored(self) {
            return false;
        }
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        covers_from(&self.tokens, &words)
    }
}

/// Classic wildcard matching over token sequences with prefix semantics:
/// once every pattern token is consumed the match succeeds regardless of
/// remaining argv.
fn matches_from(pattern: &[Token], argv: &[String]) -> bool {
    match pattern.split_first() {
        None => true,
        Some((Token::Any, rest)) => {
            // `*` as the last token matches everything that remains.
            if rest.is_empty() {
                return true;
            }
            (0..=argv.len()).any(|skip| matches_from(rest, &argv[skip..]))
        }
        Some((Token::One(glob, _), rest)) => match argv.split_first() {
            Some((head, tail)) if glob.is_match(head) => matches_from(rest, tail),
            _ => false,
        },
        Some((Token::End, _)) => argv.is_empty(),
    }
}

/// Does every argv `words` (a pattern's own tokens) can match also match
/// `pattern`? Like [`matches_from`], but a word that is itself a glob is only
/// covered by an equal glob, a broader `literal*` glob or a bare `*`, so the
/// answer errs towards "no".
fn covers_from(pattern: &[Token], words: &[&str]) -> bool {
    match pattern.split_first() {
        None => true,
        Some((Token::Any, rest)) => {
            rest.is_empty() || (0..=words.len()).any(|skip| covers_from(rest, &words[skip..]))
        }
        Some((Token::One(glob, source), rest)) => match words.split_first() {
            Some((word, tail)) if glob_covers(glob, source, word) => covers_from(rest, tail),
            _ => false,
        },
        Some((Token::End, _)) => words.is_empty(),
    }
}

fn has_glob_syntax(text: &str) -> bool {
    text.contains(['*', '?', '[', '{'])
}

/// A glob covers a word when the word is literal and matches, the word is the
/// same glob, or the glob is `prefix*` and the word starts with `prefix`.
fn glob_covers(glob: &GlobMatcher, source: &str, word: &str) -> bool {
    if !has_glob_syntax(word) {
        return glob.is_match(word);
    }
    source == word
        || source
            .strip_suffix('*')
            .is_some_and(|prefix| !has_glob_syntax(prefix) && word.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn shell_prefix_and_wildcards() {
        let p = ShellPattern::compile("git push --force*").unwrap();
        assert!(p.is_match(&argv("git push --force")));
        assert!(p.is_match(&argv("git push --force-with-lease origin main")));
        assert!(!p.is_match(&argv("git push origin main")));

        let p = ShellPattern::compile("sudo *").unwrap();
        assert!(p.is_match(&argv("sudo rm -rf /")));
        assert!(p.is_match(&argv("sudo")));
        assert!(!p.is_match(&argv("sudoedit x")));

        let p = ShellPattern::compile("npm test").unwrap();
        assert!(p.is_match(&argv("npm test -- --watch")));
        assert!(!p.is_match(&argv("npm install")));
    }

    #[test]
    fn wildcard_spans_many_tokens() {
        let p = ShellPattern::compile("curl * | sh").unwrap();
        assert!(p.is_match(&argv("curl -fsSL https://x | sh")));
        assert!(p.is_match(&argv("curl https://x | sh -s -- --yes")));
        assert!(!p.is_match(&argv("curl https://x | tee out")));

        let p = ShellPattern::compile("* | base64 -d | *sh*").unwrap();
        assert!(p.is_match(&argv("echo abc | base64 -d | sh")));
        assert!(p.is_match(&argv("cat f | base64 -d | bash -x")));
    }

    #[test]
    fn trailing_dollar_anchors_the_end_of_argv() {
        let p = ShellPattern::compile("env $").unwrap();
        assert!(p.is_match(&argv("env")));
        assert!(!p.is_match(&argv("env FOO=1 git status")));
        assert!(!p.is_match(&argv("envsubst")));

        let p = ShellPattern::compile("export -p $").unwrap();
        assert!(p.is_match(&argv("export -p")));
        assert!(!p.is_match(&argv("export -p FOO")));

        let p = ShellPattern::compile("* | sh $").unwrap();
        assert!(p.is_match(&argv("curl x | sh")));
        assert!(!p.is_match(&argv("curl x | sh -s -- --yes")));

        let p = ShellPattern::compile("echo $ x").unwrap();
        assert!(
            p.is_match(&argv("echo $ x")),
            "`$` before the end is literal"
        );
        assert!(matches!(
            ShellPattern::compile("$"),
            Err(PolicyError::EmptyPattern)
        ));
    }

    #[test]
    fn shell_coverage_is_conservative() {
        let c = |a: &str, b: &str| {
            ShellPattern::compile(a)
                .unwrap()
                .covers(&ShellPattern::compile(b).unwrap())
        };
        assert!(c("cargo *", "cargo publish*"));
        assert!(c("cargo pub*", "cargo publish*"));
        assert!(c("cargo", "cargo install"));
        assert!(c("env", "env $"));
        assert!(c("env $", "env $"));
        assert!(!c("env $", "env"));
        assert!(!c("cargo publish", "cargo pub*"));
        assert!(!c("cargo ?", "cargo *"));
        assert!(!c("cargo build*", "cargo *"));
        assert!(!c("git status*", "git push*"));
    }

    #[test]
    fn glob_coverage_is_conservative() {
        let g = |s: &str| GlobPattern::compile(s, false).unwrap();
        assert!(g("/p/**").covers(&g("/p/secrets/**")));
        assert!(g("/p/**").covers(&g("/p/a.rs")));
        assert!(g("*.github.com").covers(&g("api.github.com")));
        assert!(!g("/p/*").covers(&g("/p/**")));
        assert!(!g("/p/**").covers(&g("!/p/x")));
        assert!(!g("/p/a/**").covers(&g("/p/**")));
    }

    #[test]
    fn shell_negation_excludes_from_its_list() {
        let list = [
            ShellPattern::compile("find *").unwrap(),
            ShellPattern::compile("!find * -exec*").unwrap(),
        ];
        assert!(any_shell_match(&list, &argv("find . -name x")));
        assert!(!any_shell_match(
            &list,
            &argv("find . -name x -execdir rm {} ;")
        ));
        assert!(!any_shell_match(&list[1..], &argv("find . -exec x")));
        assert!(!list[0].covers(&list[1]) && !list[1].covers(&list[0]));
    }

    #[test]
    fn glob_negation() {
        let pats = vec![
            GlobPattern::compile("/p/**", false).unwrap(),
            GlobPattern::compile("!/p/.git/**", false).unwrap(),
        ];
        assert!(any_match(&pats, "/p/src/main.rs"));
        assert!(!any_match(&pats, "/p/.git/config"));
        assert!(!any_match(&pats, "/q/x"));
    }
}
