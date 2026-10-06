//! `sed`: the script is data, read by `script.rs`, never as shell.
//!
//! A script's words are not file operands (`sed -n '/a/,/b/p' f` reads only
//! `f`). Files it reads or writes (`r FILE`, `w FILE`) become `fs` atoms. A
//! script that runs a command or cannot be read, a script file (`-f`) and an
//! unknown option become a `sed @<text>` atom.
//!
//! GNU sed lets options follow operands; BSD sed stops at the first operand.
//! Every word either one could take for the script is read as one, and stays a
//! file operand unless both agree.

mod script;
#[cfg(test)]
mod tests;

use super::text::{Arg, Operands, Spec, parse, unproven};
use super::{ClassifyError, ShellContext, Sink};

const SED: Spec = Spec {
    flags: "nErsuz",
    valued: "ef",
    optional: "",
    long_flags: &[
        "quiet",
        "silent",
        "regexp-extended",
        "separate",
        "unbuffered",
        "null-data",
        "posix",
        "debug",
        "sandbox",
        "follow-symlinks",
    ],
    long_valued: &["expression", "file"],
    long_optional: &[],
    permute: true,
};

/// The command line as both sed implementations may read it.
#[derive(Default)]
struct Line<'a> {
    /// `-e` values: scripts to GNU sed; files to BSD sed after an operand.
    scripts: Vec<&'a str>,
    /// An `-e` comes before the first operand, so BSD sed has a script too.
    script_first: bool,
    operands: Vec<usize>,
}

pub(super) fn classify(
    argv: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<Operands, ClassifyError> {
    let mut ops = Operands::default();
    let mut line = Line::default();
    for arg in parse(argv, &SED) {
        match arg {
            Arg::Opt {
                name: "e" | "expression",
                value: Some(script),
                data,
            } => {
                line.script_first |= line.operands.is_empty();
                line.scripts.push(script);
                ops.data.extend(data);
            }
            Arg::Opt {
                name: "f" | "file", ..
            } => unproven(argv, "-f", sink)?,
            Arg::Unknown(word) => unproven(argv, word, sink)?,
            Arg::Opt { .. } => {}
            Arg::Operand(at) => line.operands.push(at),
        }
    }
    for (at, is_data) in operand_scripts(&line) {
        if is_data {
            ops.data.push(at);
        }
        check(argv, &argv[at], ctx, sink)?;
    }
    for script in &line.scripts {
        check(argv, script, ctx, sink)?;
    }
    Ok(ops)
}

/// Operands that one implementation reads as the script, with true when the
/// other agrees, so the word is no file.
fn operand_scripts(line: &Line<'_>) -> Vec<(usize, bool)> {
    let first = line.operands.first().copied();
    if !line.scripts.is_empty() {
        // BSD sed stops at the first operand: the script unless an `-e` came first.
        return first
            .filter(|_| !line.script_first)
            .map(|at| vec![(at, false)])
            .unwrap_or_default();
    }
    first.map(|at| vec![(at, true)]).unwrap_or_default()
}

/// Record the files `script` touches, or report it when it may do more.
fn check(
    argv: &[String],
    script: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let Some(effects) = script::effects(script) else {
        return unproven(argv, script, sink);
    };
    for file in &effects.reads {
        sink.read(ctx, &literal(file))?;
    }
    for file in &effects.writes {
        sink.write(ctx, &literal(file))?;
    }
    Ok(())
}

/// sed does not expand `~`: `w ~/x` writes `./~/x`.
fn literal(file: &str) -> String {
    if file.starts_with('~') {
        format!("./{file}")
    } else {
        file.to_owned()
    }
}
