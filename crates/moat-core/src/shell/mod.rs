//! Shell command classification (DESIGN.md §7.2).
//!
//! A command line is lexed ([`crate::lexer`]), grouped into simple commands,
//! and each simple command is decomposed into [`AtomicAction`]s:
//!
//! | Source | Atomic action |
//! |---|---|
//! | the command itself | `Shell { argv }` |
//! | every pipeline / list suffix with ≥ 2 commands | `Pipeline { argv }` |
//! | leading `VAR=value`, `export`/`declare`/`set` assignments | `EnvSet` |
//! | `$VAR` / `${VAR}` references, `printenv NAME` | `EnvRead` |
//! | path-looking arguments, `<` targets, `source`/`.` files | `FsRead` |
//! | `>`/`>>`/`&>` targets, `tee`, destructive/destination args | `FsWrite` |
//! | URLs, `host:port`, dotted hosts, IP literals | `Net` |
//! | `$( … )`, backticks, `sh -c`, `eval`, `xargs`, `sudo`, `env`, … | nested classification |
//! | `python -c`, `node -e`, `perl -e`, … payloads | URL/path scan of the payload |
//!
//! Classification is conservative by design: when the input cannot be parsed
//! safely the result is [`ParseOutcome::Unparseable`], which the engine maps to
//! `ask`, never `allow`. Here-document bodies are treated as data.
//!
//! Module layout: `commands` groups tokens and classifies each simple command,
//! `tokens` recognises assignments, variable references and hosts inside single
//! words, `tables` holds the program and extension lists that drive both.

mod commands;
mod tables;
#[cfg(test)]
mod tests;
mod tokens;

use std::fmt;

use crate::action::AtomicAction;
use crate::lexer::LexError;

/// Result of classifying a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Parsed(Vec<AtomicAction>),
    Unparseable { reason: String },
}

/// Context needed to normalise paths inside a command. No I/O.
#[derive(Debug, Clone, Copy)]
pub struct ShellContext<'a> {
    pub home: &'a str,
    pub project: &'a str,
    pub cwd: &'a str,
}

/// Maximum nesting of `$( … )`, `sh -c`, `eval` and wrapper commands.
pub const MAX_DEPTH: u8 = 4;
/// Upper bound on atomic actions per command line, to bound work on hostile input.
pub const MAX_ATOMS: usize = 2048;

/// Classify a shell command string into atomic actions.
#[must_use]
pub fn classify(command: &str, ctx: &ShellContext<'_>) -> ParseOutcome {
    let mut out = Vec::new();
    match commands::classify_into(command, ctx, &mut out, 0) {
        Ok(()) if out.is_empty() => ParseOutcome::Unparseable {
            reason: "no command found".to_owned(),
        },
        Ok(()) => ParseOutcome::Parsed(out),
        Err(e) => ParseOutcome::Unparseable {
            reason: e.to_string(),
        },
    }
}

#[derive(Debug)]
pub(crate) enum ClassifyError {
    Lex(LexError),
    TooDeep,
    TooManyActions,
}

impl fmt::Display for ClassifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lex(e) => write!(f, "{e}"),
            Self::TooDeep => write!(f, "command nesting deeper than {MAX_DEPTH}"),
            Self::TooManyActions => write!(f, "command expands to more than {MAX_ATOMS} actions"),
        }
    }
}

impl From<LexError> for ClassifyError {
    fn from(e: LexError) -> Self {
        Self::Lex(e)
    }
}

/// Accumulates atomic actions with de-duplication and a hard size bound.
pub(crate) struct Sink<'o> {
    out: &'o mut Vec<AtomicAction>,
}

impl<'o> Sink<'o> {
    pub(crate) fn new(out: &'o mut Vec<AtomicAction>) -> Self {
        Self { out }
    }

    pub(crate) fn push(&mut self, atom: AtomicAction) -> Result<(), ClassifyError> {
        if self.out.contains(&atom) {
            return Ok(());
        }
        if self.out.len() >= MAX_ATOMS {
            return Err(ClassifyError::TooManyActions);
        }
        self.out.push(atom);
        Ok(())
    }
}
