//! Options of ordinary programs that run another command or write a file.
//!
//! `find . -exec cmd {} \;` runs `cmd`; `git diff --output=FILE` writes `FILE`.
//! Neither shows up as a separate command or a path-looking token, so they are
//! surfaced here: the `-exec` command is classified as a command of its own and
//! the `--output` value becomes an `fs.write`.

use super::commands::classify_wrapped;
use super::{ClassifyError, ShellContext, Sink};

/// `find` actions whose arguments, up to `;` or `+`, are a command to run.
const FIND_EXEC: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// Short output-file options whose meaning is specific to one program
/// (`grep -o` is a flag, `curl -o` takes a file).
const OUTPUT_SHORT: &[(&str, &str)] = &[("curl", "-o"), ("wget", "-O")];

pub(super) fn classify(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
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
                classify_wrapped(&rest[..end], ctx, sink, depth)?;
            }
            i += end + 1;
            continue;
        }
        let short = OUTPUT_SHORT
            .iter()
            .any(|(p, flag)| *p == program && arg == flag);
        let target = match arg
            .strip_prefix("--output=")
            .or_else(|| arg.strip_prefix("--output-document="))
        {
            Some(value) => Some(value),
            None if arg == "--output" || arg == "--output-document" || short => {
                argv.get(i).map(String::as_str)
            }
            None => None,
        };
        if let Some(path) = target.filter(|p| !p.is_empty() && *p != "-") {
            sink.write(ctx, path)?;
        }
    }
    Ok(())
}
