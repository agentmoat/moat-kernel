//! Options of ordinary programs that run another command or write a file.
//!
//! `find . -exec cmd {} \;` runs `cmd`; `git diff --output=FILE` writes `FILE`.
//! Neither shows up as a separate command or a path-looking token, so they are
//! surfaced here: the `-exec` command is classified as a command of its own and
//! the `--output` value becomes an `fs.write`.

use super::commands::classify_wrapped;
use super::{ClassifyError, ShellContext, Sink};
use crate::action::AtomicAction;
use crate::paths;

/// `find` actions whose arguments, up to `;` or `+`, are a command to run.
const FIND_EXEC: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

pub(super) fn classify(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    out: &mut Vec<AtomicAction>,
    depth: u8,
) -> Result<(), ClassifyError> {
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if program == "find" && FIND_EXEC.contains(&arg.as_str()) {
            let rest = &argv[i..];
            let end = rest
                .iter()
                .position(|a| a == ";" || a == "+")
                .unwrap_or(rest.len());
            if end > 0 {
                classify_wrapped(&rest[..end], ctx, out, depth)?;
            }
            i += end + 1;
            continue;
        }
        let target = match arg.strip_prefix("--output=") {
            Some(value) => Some(value),
            None if arg == "--output" => argv.get(i).map(String::as_str),
            None => None,
        };
        if let Some(path) = target.filter(|p| !p.is_empty() && *p != "-") {
            Sink::new(out).push(AtomicAction::FsWrite {
                path: paths::normalise(path, ctx.home, ctx.project, ctx.cwd),
            })?;
        }
    }
    Ok(())
}
