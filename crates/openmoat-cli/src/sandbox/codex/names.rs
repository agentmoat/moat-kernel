//! The Linux-only part of the profile: denies by name in the workspace roots,
//! where bubblewrap can mount over a path a deny glob would miss (see the
//! module documentation of [`super`]).

use openmoat_core::Kind;
use openmoat_core::ir::Enforcement;
use toml_edit::{Item, value};

use super::{Generated, Mode};
use crate::sandbox::patterns::{Spot, has_glob, literal_tree, push_unique, split, spot};

/// Directories Codex keeps read-only in every workspace root itself
/// (`codex-rs/protocol/src/permissions.rs`), so they need no mount of ours.
const CODEX_PROTECTED: &[&str] = &[".git", ".agents", ".codex", ".aws"];

/// The single names a write deny covers anywhere, as a node (`**/.claude`) or
/// a tree (`**/.moat/**`).
pub(super) fn denied_dirs(ir: &Enforcement) -> Vec<String> {
    let mut names = Vec::new();
    for rule in &ir.fs.write.deny {
        let (positive, _) = split(&rule.patterns);
        for pattern in positive {
            if let Spot::Anywhere(rest) = spot(pattern)
                && let Some(name) = literal_tree(rest).filter(|n| !n.contains('/'))
            {
                push_unique(&mut names, name.to_owned());
            }
        }
    }
    names
}

/// On Linux, also deny each `**/<name>` workspace deny's name directly in the
/// workspace roots, so a command cannot create it there. A deny below a
/// directory (`**/.claude/settings.local.json`) is not written by path: two such
/// paths below one missing directory would both mount over it, and bubblewrap
/// then fails to start any command. Instead, when the policy denies writing the
/// directory itself (`.claude`, `.cursor`), that directory is made read-only in
/// the workspace roots, which bubblewrap mounts over once when it is missing.
/// Any other directory is left out: a missing `bin` would be mounted over for
/// `bin/moat`, which breaks builds. What stays creatable is reported.
pub fn deny_names(generated: &mut Generated) {
    let Some(workspace) = generated
        .profile
        .get_mut("filesystem")
        .and_then(|fs| fs.get_mut(":workspace_roots"))
        .and_then(Item::as_table_mut)
    else {
        return;
    };
    let globs: Vec<String> = workspace
        .iter()
        .filter(|(key, mode)| key.starts_with("**/") && mode.as_str() == Some("deny"))
        .map(|(key, _)| key.to_owned())
        .collect();
    let mut read_only = Vec::new();
    for path in globs.iter().filter_map(|g| g.strip_prefix("**/")) {
        match path.split_once('/') {
            None if !has_glob(path) => {
                workspace.insert(path, value(Mode::Deny.as_str()));
            }
            Some((dir, _))
                if generated.denied_dirs.iter().any(|d| d == dir)
                    && !CODEX_PROTECTED.contains(&dir)
                    && !workspace.contains_key(dir) =>
            {
                workspace.insert(dir, value(Mode::Read.as_str()));
                read_only.push(dir.to_owned());
            }
            _ => {}
        }
    }
    if !read_only.is_empty() {
        generated.report.loss(
            Kind::FsWrite,
            "codex.linux-agent-dirs",
            format!(
                "on Linux sandboxed commands cannot write in a workspace root's {}, so they \
                 cannot plant another agent's settings there; while a command runs a missing \
                 one shows up as an empty file",
                read_only
                    .iter()
                    .map(|d| format!("`{d}`"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
        );
    }
    if !globs.is_empty() {
        generated.report.allowance(
            Kind::FsWrite,
            "codex.linux-write-globs",
            globs,
            "Codex on Linux hides only the files a deny glob matches when a command starts, \
             so sandboxed commands may create a missing match, except a name directly in a \
             workspace root (`.env`, `.envrc`) and anything in its `.claude` or `.cursor`, \
             which the profile also denies or makes read-only by path; the hook still denies \
             the agent's own writes",
        );
    }
}
