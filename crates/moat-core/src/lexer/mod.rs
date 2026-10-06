//! POSIX-shell lexer sufficient for policy classification.
//!
//! The lexer does **not** execute anything and does not expand variables; it
//! produces words and control operators so that the classifier (`shell/`) can decompose a
//! command line into simple commands, redirections and nested commands.
//!
//! Supported syntax:
//! - whitespace and newlines; `#` comments at word start;
//! - single quotes, double quotes (with `\"`, `\\`, `\$`, `` \` `` escapes), backslash
//!   escapes outside quotes;
//! - control operators `|`, `||`, `&`, `&&`, `;`, `(`, `)`, newline;
//! - redirections `<`, `>`, `>>`, `<>`, `&>`, `&>>`, `<&`, `>&`, with optional
//!   leading file-descriptor digits (`2>&1`, `3<file`);
//! - here-documents `<<` / `<<-`: the body (up to the delimiter line) is consumed
//!   as data and exposed on the token so callers can treat it as content, never as code;
//! - here-strings `<<<`: a redirect operator whose following word is stdin data; the
//!   word is lexed like any other, so its `$( … )` substitutions are still captured;
//! - command substitution `$( … )` (nesting aware) and backticks; the inner text is
//!   attached to the containing word so it can be classified as its own command.
//!
//! Anything the lexer cannot make sense of is an error; the engine maps lexer
//! errors to `ask`, never to `allow`.

#[cfg(test)]
mod tests;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Pipe,
    And,
    Or,
    Sequence,
    Background,
    OpenParen,
    CloseParen,
    RedirectIn,
    RedirectOut,
    RedirectAppend,
    RedirectReadWrite,
    /// `<&` / `>&`: duplicates a descriptor; the target is a descriptor or `-`.
    DuplicateDescriptor,
    /// `<<<`: the following word is the command's stdin, not a file.
    HereString,
}

impl Operator {
    #[must_use]
    pub fn is_separator(self) -> bool {
        matches!(
            self,
            Self::Pipe | Self::And | Self::Or | Self::Sequence | Self::Background
        )
    }

    #[must_use]
    pub fn is_grouping(self) -> bool {
        matches!(self, Self::OpenParen | Self::CloseParen)
    }

    #[must_use]
    pub fn is_redirect(self) -> bool {
        matches!(
            self,
            Self::RedirectIn
                | Self::RedirectOut
                | Self::RedirectAppend
                | Self::RedirectReadWrite
                | Self::DuplicateDescriptor
                | Self::HereString
        )
    }

    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Pipe => "|",
            Self::And => "&&",
            Self::Or => "||",
            Self::Sequence => ";",
            Self::Background => "&",
            Self::OpenParen => "(",
            Self::CloseParen => ")",
            Self::RedirectIn => "<",
            Self::RedirectOut => ">",
            Self::RedirectAppend => ">>",
            Self::RedirectReadWrite => "<>",
            Self::DuplicateDescriptor => ">&",
            Self::HereString => "<<<",
        }
    }
}

/// A shell word with quoting removed and nested commands extracted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Word {
    /// The word with quotes and escapes resolved. `$VAR` text is preserved.
    pub text: String,
    /// True if any part of the word was quoted (affects glob/host heuristics).
    pub quoted: bool,
    /// Inner text of every `$( … )` / `` ` … ` `` found inside the word.
    pub substitutions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(Word),
    Operator(Operator),
    /// The raw body lines of a here-document; classified as data, never as commands.
    HereDoc {
        body: String,
    },
}

/// Why a command line could not be tokenised. Any of these makes the action `ask`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LexError {
    #[error("unterminated single quote")]
    UnterminatedSingleQuote,
    #[error("unterminated double quote")]
    UnterminatedDoubleQuote,
    #[error("unterminated `$(` command substitution")]
    UnterminatedSubstitution,
    #[error("unterminated backtick substitution")]
    UnterminatedBacktick,
    #[error("here-document `{delimiter}` has no terminating line")]
    UnterminatedHereDoc { delimiter: String },
    #[error("command ends with a backslash")]
    TrailingBackslash,
    #[error("command exceeds {max} bytes")]
    TooLong { max: usize },
}

/// Upper bound on input size; larger commands are refused (and therefore `ask`).
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;

/// Tokenise a command line.
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    if input.len() > MAX_COMMAND_BYTES {
        return Err(LexError::TooLong {
            max: MAX_COMMAND_BYTES,
        });
    }
    Lexer::new(input).run()
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    tokens: Vec<Token>,
    pending_heredocs: Vec<(String, bool)>,
    current: Option<Word>,
}

impl Lexer {
    fn new(src: &str) -> Self {
        Self {
            chars: src.chars().collect(),
            pos: 0,
            tokens: Vec::new(),
            pending_heredocs: Vec::new(),
            current: None,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn word(&mut self) -> &mut Word {
        self.current.get_or_insert_with(Word::default)
    }

    fn flush_word(&mut self) {
        if let Some(w) = self.current.take() {
            if self
                .pending_heredocs
                .last()
                .is_some_and(|(d, _)| d.is_empty())
            {
                // The word following `<<` is the delimiter, not an argument.
                let strip_tabs = self.pending_heredocs.last().is_some_and(|(_, s)| *s);
                self.pending_heredocs.pop();
                self.pending_heredocs.push((w.text, strip_tabs));
                return;
            }
            self.tokens.push(Token::Word(w));
        }
    }

    fn push_operator(&mut self, op: Operator) {
        self.flush_word();
        self.tokens.push(Token::Operator(op));
    }

    fn run(mut self) -> Result<Vec<Token>, LexError> {
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' => {
                    self.bump();
                    self.flush_word();
                }
                '\n' => {
                    self.bump();
                    self.flush_word();
                    self.consume_heredoc_bodies()?;
                    self.tokens.push(Token::Operator(Operator::Sequence));
                }
                '#' if self.current.is_none() => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                '\'' => {
                    self.bump();
                    self.single_quoted()?;
                }
                '"' => {
                    self.bump();
                    self.double_quoted()?;
                }
                '\\' => {
                    self.bump();
                    match self.bump() {
                        Some('\n') => {}
                        Some(escaped) => self.word().text.push(escaped),
                        None => return Err(LexError::TrailingBackslash),
                    }
                }
                '`' => {
                    self.bump();
                    self.backtick()?;
                }
                '$' if self.peek_at(1) == Some('(') => {
                    self.pos += 2;
                    self.dollar_paren()?;
                }
                '|' | '&' | ';' | '(' | ')' | '<' | '>' => self.operator(),
                _ => {
                    self.bump();
                    self.word().text.push(c);
                }
            }
        }
        self.flush_word();
        if let Some((delimiter, _)) = self.pending_heredocs.first() {
            if delimiter.is_empty() {
                // `<<` at end of input with no delimiter: treat as plain input redirect.
                self.pending_heredocs.clear();
            } else {
                return Err(LexError::UnterminatedHereDoc {
                    delimiter: delimiter.clone(),
                });
            }
        }
        Ok(self.tokens)
    }

    fn operator(&mut self) {
        // Optional leading descriptor digits belong to a redirect: `2>&1`, `3<file`.
        if let Some(w) = &self.current {
            let is_fd = !w.text.is_empty() && w.text.chars().all(|c| c.is_ascii_digit());
            let next_is_redirect = matches!(self.peek(), Some('<' | '>'));
            if is_fd && next_is_redirect && !w.quoted {
                self.current = None;
            }
        }
        let c = self.bump().expect("operator char present");
        let next = self.peek();
        let op = match (c, next) {
            ('|', Some('|')) => {
                self.bump();
                Operator::Or
            }
            // `|&` pipes stderr too; for what reaches the next command it is a pipe.
            ('|', Some('&')) => {
                self.bump();
                Operator::Pipe
            }
            ('|', _) => Operator::Pipe,
            ('&', Some('&')) => {
                self.bump();
                Operator::And
            }
            ('&', Some('>')) => {
                self.bump();
                if self.peek() == Some('>') {
                    self.bump();
                    Operator::RedirectAppend
                } else {
                    Operator::RedirectOut
                }
            }
            ('&', _) => Operator::Background,
            (';', _) => {
                while self.peek() == Some(';') {
                    self.bump();
                }
                Operator::Sequence
            }
            ('(', _) => Operator::OpenParen,
            (')', _) => Operator::CloseParen,
            ('<', Some('<')) if self.peek_at(1) == Some('<') => {
                self.pos += 2;
                Operator::HereString
            }
            ('<', Some('<')) => {
                self.bump();
                let strip_tabs = if self.peek() == Some('-') {
                    self.bump();
                    true
                } else {
                    false
                };
                self.flush_word();
                self.pending_heredocs.push((String::new(), strip_tabs));
                return;
            }
            ('<' | '>', Some('&')) => {
                self.bump();
                Operator::DuplicateDescriptor
            }
            ('<', Some('>')) => {
                self.bump();
                Operator::RedirectReadWrite
            }
            ('<', _) => Operator::RedirectIn,
            ('>', Some('>')) => {
                self.bump();
                Operator::RedirectAppend
            }
            ('>', Some('|')) => {
                self.bump();
                Operator::RedirectOut
            }
            ('>', _) => Operator::RedirectOut,
            _ => unreachable!("operator dispatch covers all first characters"),
        };
        self.push_operator(op);
    }

    fn single_quoted(&mut self) -> Result<(), LexError> {
        self.word().quoted = true;
        loop {
            match self.bump() {
                Some('\'') => return Ok(()),
                Some(c) => self.word().text.push(c),
                None => return Err(LexError::UnterminatedSingleQuote),
            }
        }
    }

    fn double_quoted(&mut self) -> Result<(), LexError> {
        self.word().quoted = true;
        loop {
            match self.bump() {
                Some('"') => return Ok(()),
                Some('\\') => match self.bump() {
                    Some(c @ ('"' | '\\' | '$' | '`')) => self.word().text.push(c),
                    Some('\n') => {}
                    Some(c) => {
                        self.word().text.push('\\');
                        self.word().text.push(c);
                    }
                    None => return Err(LexError::UnterminatedDoubleQuote),
                },
                Some('`') => self.backtick()?,
                Some('$') if self.peek() == Some('(') => {
                    self.bump();
                    self.dollar_paren()?;
                }
                Some(c) => self.word().text.push(c),
                None => return Err(LexError::UnterminatedDoubleQuote),
            }
        }
    }

    /// `$( … )` with nesting; the inner text is recorded as a substitution.
    fn dollar_paren(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        let mut depth = 1usize;
        let mut in_single = false;
        let mut in_double = false;
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    self.bump();
                }
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                '(' if !in_single => depth += 1,
                ')' if !in_single => {
                    depth -= 1;
                    if depth == 0 {
                        let inner: String = self.chars[start..self.pos - 1].iter().collect();
                        let w = self.word();
                        w.quoted = true;
                        w.substitutions.push(inner.trim().to_owned());
                        w.text.push_str("$(…)");
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(LexError::UnterminatedSubstitution)
    }

    fn backtick(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    self.bump();
                }
                '`' => {
                    let inner: String = self.chars[start..self.pos - 1].iter().collect();
                    let w = self.word();
                    w.quoted = true;
                    w.substitutions.push(inner.trim().to_owned());
                    w.text.push_str("`…`");
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(LexError::UnterminatedBacktick)
    }

    /// After a newline, consume the bodies of every pending here-document.
    fn consume_heredoc_bodies(&mut self) -> Result<(), LexError> {
        let pending = std::mem::take(&mut self.pending_heredocs);
        for (delimiter, strip_tabs) in pending {
            if delimiter.is_empty() {
                continue;
            }
            let mut body = String::new();
            loop {
                if self.pos >= self.chars.len() {
                    return Err(LexError::UnterminatedHereDoc { delimiter });
                }
                let line_start = self.pos;
                while self.peek().is_some_and(|c| c != '\n') {
                    self.bump();
                }
                let line: String = self.chars[line_start..self.pos].iter().collect();
                self.bump(); // the newline, if any
                let candidate = if strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    &line
                };
                if candidate == delimiter {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            self.tokens.push(Token::HereDoc { body });
        }
        Ok(())
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Word(w) => f.write_str(&w.text),
            Self::Operator(op) => f.write_str(op.symbol()),
            Self::HereDoc { .. } => f.write_str("<<heredoc"),
        }
    }
}
