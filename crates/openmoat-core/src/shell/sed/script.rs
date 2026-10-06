//! A sed script, read far enough to know everything it touches.
//!
//! Only the commands and addresses GNU and BSD sed share are accepted; any
//! other command, and any text the reader cannot follow, makes the script
//! unknown. Where the two implementations would split a script differently (a
//! delimiter inside a bracket expression, a label followed by more text) the
//! script is unknown too, so a command one of them would run is never hidden.

/// Files a script reads (`r`, `R`) and writes (`w`, `W`, the `s///w` flag).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Effects<'a> {
    pub reads: Vec<&'a str>,
    pub writes: Vec<&'a str>,
}

/// What `script` touches, or `None` when it runs a command (`e`, the `s///e`
/// flag), uses a command outside the shared set, or cannot be read completely.
pub(super) fn effects(script: &str) -> Option<Effects<'_>> {
    let mut parser = Parser {
        rest: script,
        effects: Effects::default(),
    };
    loop {
        parser.skip(|c| c.is_whitespace() || c == ';');
        if parser.rest.is_empty() {
            return Some(parser.effects);
        }
        parser.address()?;
        parser.command()?;
    }
}

/// Commands that take no argument (`{` opens a block, `}` closes one).
const PLAIN: &str = "=dDgGhHnNpPxz}";
/// Commands with an optional exit code or line length.
const NUMERIC: &str = "lqQ";
/// Commands followed by a label.
const LABELLED: &str = "btT:";
/// Commands whose text runs to the end of the line.
const TEXT: &str = "aic";

struct Parser<'a> {
    rest: &'a str,
    effects: Effects<'a>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.rest.chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.rest = &self.rest[c.len_utf8()..];
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        let found = self.peek() == Some(c);
        if found {
            self.bump();
        }
        found
    }

    fn skip(&mut self, pattern: impl Fn(char) -> bool) {
        self.rest = self.rest.trim_start_matches(pattern);
    }

    fn blanks(&mut self) {
        self.skip(|c| c == ' ' || c == '\t');
    }

    /// True when at least one digit was skipped.
    fn digits(&mut self) -> bool {
        let before = self.rest.len();
        self.skip(|c| c.is_ascii_digit());
        self.rest.len() < before
    }

    /// The rest of the line, without its newline.
    fn line(&mut self) -> &'a str {
        let (line, rest) = self
            .rest
            .split_at(self.rest.find('\n').unwrap_or(self.rest.len()));
        self.rest = rest;
        line
    }

    /// `[ADDR[,ADDR]][!]`: a line number, `$`, `FIRST~STEP`, `/RE/`, `\cREc`,
    /// and after the comma also `+N` or `~N`.
    fn address(&mut self) -> Option<()> {
        if self.one_address()? {
            self.blanks();
            if self.eat(',') {
                self.blanks();
                let found = if self.eat('+') || self.eat('~') {
                    self.digits()
                } else {
                    self.one_address()?
                };
                if !found {
                    return None;
                }
            }
        }
        self.blanks();
        while self.eat('!') {
            self.blanks();
        }
        Some(())
    }

    fn one_address(&mut self) -> Option<bool> {
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                self.digits();
                if self.eat('~') {
                    self.digits();
                }
            }
            Some('$') => {
                self.bump();
            }
            Some('/' | '\\') => {
                let delimiter = match self.bump()? {
                    '/' => '/',
                    _ => self.delimiter()?,
                };
                self.delimited(delimiter, true)?;
                self.skip(|c| c == 'I' || c == 'M');
            }
            _ => return Some(false),
        }
        Some(true)
    }

    fn command(&mut self) -> Option<()> {
        match self.bump()? {
            '{' => Some(()),
            '#' => {
                self.line();
                Some(())
            }
            c if PLAIN.contains(c) => self.end(),
            c if NUMERIC.contains(c) => {
                self.blanks();
                self.digits();
                self.end()
            }
            c if LABELLED.contains(c) => {
                // GNU ends a label at `;`, BSD only at the newline; anything
                // else after the label could belong to it.
                self.blanks();
                self.skip(|c| c.is_ascii_alphanumeric() || c == '_');
                self.blanks();
                matches!(self.peek(), None | Some(';' | '\n' | '}')).then_some(())
            }
            c if TEXT.contains(c) => {
                self.text();
                Some(())
            }
            'r' | 'R' => {
                let file = self.filename()?;
                self.effects.reads.push(file);
                Some(())
            }
            'w' | 'W' => {
                let file = self.filename()?;
                self.effects.writes.push(file);
                Some(())
            }
            's' => self.substitute(),
            'y' => {
                let delimiter = self.delimiter()?;
                self.delimited(delimiter, true)?;
                self.delimited(delimiter, true)?;
                self.end()
            }
            _ => None,
        }
    }

    /// A command must end here: `;`, a newline, `}`, a comment or the end.
    fn end(&mut self) -> Option<()> {
        self.blanks();
        matches!(self.peek(), None | Some(';' | '\n' | '}' | '#')).then_some(())
    }

    /// `a`, `i`, `c`: the text runs to the first newline not escaped by `\`.
    fn text(&mut self) {
        let mut chars = self.rest.char_indices();
        let mut end = self.rest.len();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '\n' => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        self.rest = &self.rest[end..];
    }

    /// `r`, `w` and the `w` flag: the file name is the rest of the line.
    fn filename(&mut self) -> Option<&'a str> {
        self.blanks();
        Some(self.line()).filter(|file| !file.is_empty())
    }

    /// `s/RE/REPLACEMENT/FLAGS`; the `e` flag (run the pattern space) is refused.
    fn substitute(&mut self) -> Option<()> {
        let delimiter = self.delimiter()?;
        self.delimited(delimiter, true)?;
        self.delimited(delimiter, false)?;
        loop {
            match self.peek() {
                Some('g' | 'p' | 'i' | 'I' | 'm' | 'M' | '0'..='9') => {
                    self.bump();
                }
                Some('w') => {
                    self.bump();
                    let file = self.filename()?;
                    self.effects.writes.push(file);
                    return Some(());
                }
                _ => return self.end(),
            }
        }
    }

    fn delimiter(&mut self) -> Option<char> {
        self.bump().filter(|&c| c != '\n' && c != '\\')
    }

    /// Up to and past the next `delimiter` not escaped by `\`. With `brackets`
    /// (a regex), a bracket expression containing the delimiter is refused: GNU
    /// sed ends the regex there and BSD sed does not.
    fn delimited(&mut self, delimiter: char, brackets: bool) -> Option<()> {
        loop {
            match self.bump()? {
                c if c == delimiter => return Some(()),
                '\\' => {
                    self.bump()?;
                }
                '\n' => return None,
                '[' if brackets => self.bracket(delimiter)?,
                _ => {}
            }
        }
    }

    /// Past the `]` that closes a bracket expression whose `[` was just read.
    fn bracket(&mut self, delimiter: char) -> Option<()> {
        self.eat('^');
        self.eat(']');
        loop {
            match self.bump()? {
                c if c == delimiter || c == '\n' => return None,
                ']' => return Some(()),
                '[' if matches!(self.peek(), Some(':' | '.' | '=')) => {
                    let close = match self.bump()? {
                        ':' => ":]",
                        '.' => ".]",
                        _ => "=]",
                    };
                    let end = self.rest.find(close)?;
                    if close.starts_with(delimiter) || self.rest[..end].contains(delimiter) {
                        return None;
                    }
                    self.rest = &self.rest[end + close.len()..];
                }
                _ => {}
            }
        }
    }
}
