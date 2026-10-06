//! git's global options come before the subcommand: `git -C dir push --force` and
//! `git -c k=v reset --hard` are `git push --force` and `git reset --hard`, so the
//! `Shell` atom is reported without them and rules written as `git <subcommand> …`
//! match. Directories they name are reads.
//!
//! A config value can name a program git runs (`core.sshCommand`, `core.fsmonitor`,
//! `core.hooksPath`, `alias.*`, `credential.helper`, `include.path`, …); the list is
//! open-ended, so any key not known to be inert, an `--exec-path=` and any option
//! git does not document also keep the command line as written. That atom matches
//! no `git <subcommand>` allow, so the command cannot ride on `dev-shell`.

use super::{ClassifyError, ShellContext, Sink};
use crate::action::AtomicAction;

const FLAGS: &[&str] = &[
    "-p",
    "--paginate",
    "-P",
    "--no-pager",
    "--bare",
    "--no-replace-objects",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-advice",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
];
const DIRECTORIES: &[&str] = &["-C", "--git-dir", "--work-tree"];
const CONFIG: &[&str] = &["-c", "--config-env"];
const OTHER_VALUES: &[&str] = &["--namespace", "--super-prefix", "--attr-source"];

/// Config keys (lowercase; a trailing `.` is a whole section) that never name a program.
const INERT_CONFIG: &[&str] = &[
    "color.",
    "column.",
    "advice.",
    "log.",
    "user.name",
    "user.email",
    "core.quotepath",
    "core.autocrlf",
    "core.abbrev",
    "init.defaultbranch",
    "pull.rebase",
];

/// git's argv with its global options taken apart.
pub(crate) struct GitCommand<'a> {
    /// `git` as written, then the subcommand and its arguments.
    pub subcommand: Vec<String>,
    /// Values of `-C`, `--git-dir` and `--work-tree`.
    pub directories: Vec<&'a str>,
    /// True when an option can run a program or is not understood: the command
    /// line as written must be judged too.
    pub keep_original: bool,
}

/// Split `argv` (`argv[0]` is git) into its global options and the subcommand.
pub(crate) fn parse(argv: &[String]) -> GitCommand<'_> {
    let mut directories = Vec::new();
    let mut keep_original = false;
    let mut i = 1;
    while let Some(arg) = argv.get(i).filter(|a| a.starts_with('-')) {
        i += 1;
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (arg.as_str(), None),
        };
        if inline.is_none() && FLAGS.contains(&name) {
            continue;
        }
        if ![DIRECTORIES, CONFIG, OTHER_VALUES]
            .iter()
            .any(|options| options.contains(&name))
        {
            keep_original = true;
            continue;
        }
        let Some(value) = inline.or_else(|| argv.get(i).map(String::as_str)) else {
            keep_original = true;
            break;
        };
        i += usize::from(inline.is_none());
        if DIRECTORIES.contains(&name) {
            directories.push(value);
        } else if CONFIG.contains(&name) {
            let key = value
                .split_once('=')
                .map_or(value, |(k, _)| k)
                .to_ascii_lowercase();
            keep_original |= !INERT_CONFIG
                .iter()
                .any(|k| key == *k || (k.ends_with('.') && key.starts_with(k)));
        }
    }
    GitCommand {
        subcommand: argv[..1].iter().chain(&argv[i..]).cloned().collect(),
        directories,
        keep_original,
    }
}

pub(super) fn push_shell(
    argv: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let git = parse(argv);
    for dir in git.directories {
        sink.read(ctx, dir)?;
    }
    sink.push(AtomicAction::Shell {
        argv: git.subcommand,
    })?;
    if git.keep_original {
        sink.push(AtomicAction::Shell {
            argv: argv.to_vec(),
        })?;
    }
    Ok(())
}
