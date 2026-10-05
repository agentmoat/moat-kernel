//! Shell command classification (DESIGN.md §7.2).
//!
//! A command line is lexed ([`crate::lexer`]), grouped into simple commands,
//! and each simple command is decomposed into [`AtomicAction`]s:
//!
//! | Source | Atomic action |
//! |---|---|
//! | the command itself | `Shell { argv }` |
//! | every pipeline / list suffix with ≥ 2 commands | `Pipeline { argv }` |
//! | a decoder stage piped into an interpreter reading stdin (`decoders.rs`) | canonical `Pipeline { <decoder> -d \| <interpreter> }` |
//! | leading `VAR=value`, `export`/`declare`/`set` assignments | `EnvSet` |
//! | `$VAR` / `${VAR}` references, `printenv NAME` | `EnvRead` |
//! | path-looking arguments, `<` targets, `source`/`.` files | `FsRead` |
//! | `>`/`>>`/`&>` targets, `tee`, destructive/destination args | `FsWrite` |
//! | URLs with any host, bare dotted names under a known TLD, IPv4 literals (`crate::host`) | `Net` |
//! | `$( … )`, backticks, `sh -c`, `eval`, `xargs`, `sudo`, `env`, … | nested classification |
//! | `python -c`, `node -e`, `perl -e`, … payloads | URL/path scan of the payload |
//! | `find -exec/-execdir/-ok/-okdir` commands, `--output=FILE` (`options.rs`) | nested classification, `FsWrite` |
//! | `make --eval`, `-e`, `SHELL=`, `X!=cmd`, `$(shell …)` (`make.rs`) | `make <arg>` `Shell` atom + nested classification |
//!
//! Classification is conservative by design: when the input cannot be parsed
//! safely the result is [`ParseOutcome::Unparseable`], which the engine maps to
//! `ask`, never `allow`. Here-document bodies are treated as data.
//!
//! Module layout: `commands` groups tokens and classifies each simple command;
//! `tokens` recognises assignments and variable references inside one word;
//! `decoders`, `make` and `options` handle constructs that hide a command or a
//! write (decoded pipelines, make arguments, `find -exec`, `--output=`);
//! `tables` holds the program lists that drive all of them.

mod commands;
mod decoders;
mod make;
mod options;
pub(crate) mod tables;
#[cfg(test)]
mod tests;
mod tokens;

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
    let mut sink = Sink::default();
    match commands::classify_into(command, ctx, &mut sink, 0) {
        Ok(()) if sink.atoms.is_empty() => ParseOutcome::Unparseable {
            reason: "no command found".to_owned(),
        },
        Ok(()) => ParseOutcome::Parsed(sink.atoms),
        Err(e) => ParseOutcome::Unparseable {
            reason: e.to_string(),
        },
    }
}

/// Why a command line could not be classified safely; the engine turns it into `ask`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClassifyError {
    #[error(transparent)]
    Lex(#[from] LexError),
    #[error("command nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("command expands to more than {MAX_ATOMS} actions")]
    TooManyActions,
}

/// Accumulates atomic actions with de-duplication and a hard size bound.
///
/// Every classifier function writes through a `&mut Sink`, never a bare
/// `Vec`, so no code path can exceed [`MAX_ATOMS`].
#[derive(Debug, Default)]
pub(crate) struct Sink {
    atoms: Vec<AtomicAction>,
}

impl Sink {
    pub(crate) fn push(&mut self, atom: AtomicAction) -> Result<(), ClassifyError> {
        if self.atoms.contains(&atom) {
            return Ok(());
        }
        if self.atoms.len() >= MAX_ATOMS {
            return Err(ClassifyError::TooManyActions);
        }
        self.atoms.push(atom);
        Ok(())
    }
}
