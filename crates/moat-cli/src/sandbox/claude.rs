//! Claude Code backend: the `sandbox` block of the user settings (ADR-018).
//!
//! Key names are those of Claude Code 2.1.290's settings schema. Its sandbox
//! covers `Bash`, `PowerShell` and `Monitor`; file and web tools run outside it
//! and stay with the hook. What the generator relies on, verified on macOS:
//! - a relative path in user settings resolves against `~/.claude`, so every
//!   pattern is made absolute (`**/.env` becomes `/**/.env`);
//! - a directory in `denyWrite` covers its whole subtree;
//! - `allowRead` re-opens what it names inside a `denyRead` region, but not a
//!   `denyRead` entry below it (`~/.cargo` leaves `~/.cargo/credentials.toml`
//!   denied), and a `**/` exception re-opens it everywhere;
//! - `permissions.blockReadsOutsideWorkingDirectories` denies sandboxed reads
//!   under the user directories (`/Users`, `/home`, `/Volumes`, …) outside the
//!   working directories, and makes file tools refuse them.

use anyhow::Result;
use moat_core::ir::{Access, Effect, Enforcement, Rule};
use moat_core::{AtomicAction, Kind};
use serde_json::{Map, Value, json};

use super::Report;
use super::patterns::{Spot, domain, has_glob, literal_tree, push_unique, split, spot};

/// The permissions key that closes reads outside the working directories.
pub const BLOCK_READS: &str = "blockReadsOutsideWorkingDirectories";

/// What moat writes into the user settings.
#[derive(Debug, Clone, PartialEq)]
pub struct Generated {
    /// The keys of the `sandbox` object moat owns; `filesystem` and `network`
    /// are owned key by key, so other keys in them survive.
    pub sandbox: Map<String, Value>,
    /// Whether `permissions.blockReadsOutsideWorkingDirectories` must be on.
    pub block_reads: bool,
    /// Losses and allowances of this backend.
    pub report: Report,
}

/// Generate the settings for `ir`, lowered by [`super::lower_for_hosts`].
pub fn generate(ir: &Enforcement) -> Result<Generated> {
    let mut report = Report::default();
    let filesystem = Filesystem::build(ir, &mut report)?;
    let network = network(&ir.egress.net, &mut report);
    let mut sandbox = Map::new();
    sandbox.insert("enabled".into(), json!(true));
    sandbox.insert("failIfUnavailable".into(), json!(true));
    sandbox.insert("allowUnsandboxedCommands".into(), json!(false));
    sandbox.insert("excludedCommands".into(), json!([]));
    sandbox.insert("filesystem".into(), filesystem.into_json());
    sandbox.insert("network".into(), network);
    let block_reads = ir.fs.read.default == Effect::Deny;
    if block_reads {
        report.loss(
            Kind::FsRead,
            "default",
            "Claude Code's file tools refuse reads outside the working directories \
             (permissions.blockReadsOutsideWorkingDirectories) where the hook would ask; \
             `/add-dir` adds a directory"
                .into(),
        );
    }
    report.allowance(
        Kind::FsRead,
        "claude-code.system-paths",
        Vec::new(),
        "Claude Code closes reads only under the user directories (/Users, /home, /Volumes, \
         /media, /root); other paths that are not read roots stay readable for sandboxed commands",
    );
    report.allowance(
        Kind::FsWrite,
        "claude-code.working-directories",
        Vec::new(),
        "sandboxed commands may write the session's working directories and temp directory; \
         moat's project is the git root and never the home directory, so a session started \
         above a project writes more than the hook allows",
    );
    Ok(Generated {
        sandbox,
        block_reads,
        report,
    })
}

#[derive(Default)]
struct Filesystem {
    deny_read: Vec<String>,
    allow_read: Vec<String>,
    deny_write: Vec<String>,
    allow_write: Vec<String>,
    /// `denyWrite` entries that name a directory node only (no `/**`).
    nodes: Vec<String>,
    /// `denyWrite` entries that name a whole tree.
    trees: Vec<String>,
}

impl Filesystem {
    fn build(ir: &Enforcement, report: &mut Report) -> Result<Self> {
        let checker = ir.checker()?;
        let mut fs = Self::default();
        for rule in &ir.fs.read.deny {
            fs.deny_rule(rule, Kind::FsRead, report);
        }
        for rule in &ir.fs.write.deny {
            fs.deny_rule(rule, Kind::FsWrite, report);
        }
        fs.allow_rules(&ir.fs.read, Kind::FsRead, report);
        fs.allow_rules(&ir.fs.write, Kind::FsWrite, report);
        for allowance in ir.allowances.iter().filter(|a| a.kind == Kind::FsRead) {
            for root in allowance.patterns.iter().filter(|p| !p.ends_with("/**")) {
                let read = AtomicAction::FsRead { path: root.clone() };
                if checker.check_os(&read) == Some(Effect::Allow) {
                    push_unique(&mut fs.allow_read, root.clone());
                } else {
                    report.loss(
                        Kind::FsRead,
                        &allowance.rule,
                        format!("`{root}` is inside a denied path, so it is not re-opened"),
                    );
                }
            }
            report.allowances.push(allowance.clone());
        }
        if ir.fs.write.default == Effect::Allow {
            report.loss(
                Kind::FsWrite,
                "default",
                "Claude Code allows writes only in the working directories and listed paths".into(),
            );
        }
        fs.drop_directory_nodes(report);
        Ok(fs)
    }

    fn deny_rule(&mut self, rule: &Rule, kind: Kind, report: &mut Report) {
        let (positive, excluded) = split(&rule.patterns);
        for pattern in positive {
            self.deny(kind, pattern);
        }
        if !excluded.is_empty() {
            report.loss(
                kind,
                &rule.id,
                format!(
                    "Claude Code would re-open the exceptions ({}) outside the working directories \
                     too, so they are left out: denied for sandboxed commands",
                    excluded.join(", ")
                ),
            );
        }
    }

    fn deny(&mut self, kind: Kind, pattern: &str) {
        let anchored = match spot(pattern) {
            Spot::Project("" | "**") => "/".to_owned(),
            Spot::Project(rest) | Spot::Anywhere(rest) => format!("/**/{rest}"),
            Spot::Absolute(path) => path.to_owned(),
        };
        let list = match kind {
            Kind::FsRead => &mut self.deny_read,
            _ => &mut self.deny_write,
        };
        if let Some(base) = anchored.strip_suffix("/**") {
            push_unique(list, base.to_owned());
            if has_glob(base) {
                push_unique(list, anchored.clone());
            }
            if kind == Kind::FsWrite {
                self.trees.push(base.to_owned());
            }
        } else {
            push_unique(list, anchored.clone());
            if kind == Kind::FsWrite {
                self.nodes.push(anchored);
            }
        }
    }

    /// Project patterns need nothing: the working directories are the host's
    /// own grant. An exclusion becomes a deny; what cannot be named is dropped.
    fn allow_rules(&mut self, access: &Access, kind: Kind, report: &mut Report) {
        for rule in &access.allow {
            let (positive, excluded) = split(&rule.patterns);
            for pattern in excluded {
                self.deny(kind, pattern);
                if let Spot::Project(rest) = spot(pattern) {
                    report.loss(
                        kind,
                        &rule.id,
                        format!(
                            "user settings cannot name the project, so `{rest}` is denied in every \
                             directory (for `.git`: sandboxed commands cannot commit)"
                        ),
                    );
                }
            }
            for pattern in positive {
                let literal = match spot(pattern) {
                    Spot::Project(_) => continue,
                    Spot::Absolute(path) => literal_tree(path),
                    Spot::Anywhere(_) => None,
                };
                let list = match kind {
                    Kind::FsRead => &mut self.allow_read,
                    _ => &mut self.allow_write,
                };
                match literal {
                    Some(dir) => push_unique(list, dir.to_owned()),
                    None => report.loss(
                        kind,
                        &rule.id,
                        format!("`{pattern}` cannot be granted as a path, so it stays denied"),
                    ),
                }
            }
        }
    }

    /// A directory node in `denyWrite` (no rename or delete of `.claude`) would
    /// make its whole subtree read-only, `.claude/worktrees/*` included, so a
    /// node with more specific entries below it is left out and listed.
    fn drop_directory_nodes(&mut self, report: &mut Report) {
        let dropped: Vec<String> = self
            .nodes
            .iter()
            .filter(|node| !self.trees.contains(node))
            .filter(|node| {
                let below = format!("{node}/");
                self.deny_write.iter().any(|e| e.starts_with(&below))
            })
            .cloned()
            .collect();
        if dropped.is_empty() {
            return;
        }
        self.deny_write.retain(|e| !dropped.contains(e));
        report.allowance(
            Kind::FsWrite,
            "claude-code.directory-nodes",
            dropped,
            "a directory in denyWrite covers its subtree, so these directory nodes are left out \
             and only the files below them are denied; renaming or deleting the directory \
             itself is left to the hook",
        );
    }

    fn into_json(self) -> Value {
        json!({
            "denyRead": self.deny_read,
            "allowRead": self.allow_read,
            "denyWrite": self.deny_write,
            "allowWrite": self.allow_write,
        })
    }
}

/// `network.*` for sandboxed commands: Claude Code gates only those, so the
/// `net` rules apply (a fetch-only allow would widen `curl`).
fn network(net: &Access, report: &mut Report) -> Value {
    let mut allowed = Vec::new();
    let mut denied = Vec::new();
    if net.default == Effect::Allow {
        report.loss(
            Kind::Net,
            "default.net",
            "Claude Code's allowlist cannot allow every host: sandboxed commands reach only listed hosts"
                .into(),
        );
    }
    // A host that is not a domain name (`169.254.*`) cannot be listed; it is
    // unlisted and no allowed domain can match an address, so it stays denied.
    for rule in &net.deny {
        let (positive, excluded) = split(&rule.patterns);
        for pattern in positive.into_iter().filter(|p| domain(p)) {
            push_unique(&mut denied, pattern.to_owned());
        }
        if !excluded.is_empty() {
            report.loss(
                Kind::Net,
                &rule.id,
                "exceptions to a deny rule are left out: denied".into(),
            );
        }
    }
    for rule in &net.allow {
        let (positive, excluded) = split(&rule.patterns);
        if !excluded.iter().all(|p| domain(p)) {
            report.loss(
                Kind::Net,
                &rule.id,
                "an exception is not a domain name, so the whole rule is left out: denied".into(),
            );
            continue;
        }
        for pattern in excluded {
            push_unique(&mut denied, pattern.to_owned());
        }
        for pattern in positive {
            if domain(pattern) {
                push_unique(&mut allowed, pattern.to_owned());
            } else {
                report.loss(
                    Kind::Net,
                    &rule.id,
                    format!("`{pattern}` is not a domain name, so it stays denied"),
                );
            }
        }
    }
    json!({ "allowedDomains": allowed, "deniedDomains": denied, "strictAllowlist": true })
}

#[cfg(test)]
mod tests;
