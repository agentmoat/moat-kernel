//! Here-documents: delimiter bookkeeping and body capture.

use super::{LexError, Lexer, Token, Word};

/// A `<<` whose body starts after the next newline.
pub(super) struct Pending {
    /// `None` until the delimiter word has been read.
    pub delimiter: Option<String>,
    strip_tabs: bool,
    /// Any part of the delimiter was quoted or escaped: the body is not expanded.
    pub literal: bool,
    /// Index of the placeholder token that receives the body.
    token: usize,
}

impl Lexer {
    /// Record a `<<` and leave a placeholder token where it appears, so the body
    /// belongs to the command that redirects it, not to the line it ends.
    pub(super) fn start_heredoc(&mut self, strip_tabs: bool) {
        self.pending_heredocs.push(Pending {
            delimiter: None,
            strip_tabs,
            literal: false,
            token: self.tokens.len(),
        });
        self.tokens.push(Token::HereDoc {
            body: Word::default(),
            literal: false,
        });
    }

    pub(super) fn awaiting_delimiter(&mut self) -> Option<&mut Pending> {
        self.pending_heredocs
            .last_mut()
            .filter(|h| h.delimiter.is_none())
    }

    /// After a newline, consume the bodies of every pending here-document.
    pub(super) fn consume_heredoc_bodies(&mut self) -> Result<(), LexError> {
        let pending = std::mem::take(&mut self.pending_heredocs);
        for heredoc in pending {
            let Some(delimiter) = heredoc.delimiter else {
                continue;
            };
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
                let candidate = if heredoc.strip_tabs {
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
            let body = if heredoc.literal {
                Word {
                    text: body,
                    ..Word::default()
                }
            } else {
                let mut expander = Lexer::new(&body);
                expander.expanding(None)?;
                expander.current.unwrap_or_default()
            };
            self.tokens[heredoc.token] = Token::HereDoc {
                body,
                literal: heredoc.literal,
            };
        }
        Ok(())
    }
}
