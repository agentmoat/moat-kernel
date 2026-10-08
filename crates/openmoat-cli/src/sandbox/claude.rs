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
//!   working directories, and makes file tools refuse them;
//! - with `network.httpProxyPort` and `network.socksProxyPort` set (only when
//!   the policy sets `sandbox.proxy_port`), sandboxed commands reach the
//!   network only through those loopback ports (2.1.292; the sandboxing docs,
//!   "Custom proxy configuration"), so with nothing listening they have none.
//!
//! On Linux bubblewrap mounts concrete paths, so the sandbox runtime expands a
//! `denyRead` glob from its literal leading directory when each command starts
//! and skips one that has none, such as `/**/.env` (`@anthropic-ai/sandbox-runtime`,
//! "Glob pattern has no literal directory to start from"). A `Read(…)` deny
//! rule is added to `denyRead` relative to the session's working directory
//! (the settings reference: Read deny rules are merged into the sandbox; a
//! relative path resolves against the current directory), so each `/**/…`
//! read deny is also written as `Read(./**/…)`.

mod settings;

use anyhow::Result;
use openmoat_core::ir::{Access, Effect, Enforcement, Rule};
use openmoat_core::{AtomicAction, Kind};
use serde_json::{Map, Value, json};

pub use settings::{apply, in_sync, protect, remove, weaknesses};

use super::Report;
use super::patterns::{Spot, domain, has_glob, is_below, literal_tree, push_unique, split, spot};

/// The permissions key that closes reads outside the working directories.
pub const BLOCK_READS: &str = "blockReadsOutsideWorkingDirectories";

/// Paths in `.git` that make git run code or read another repository's
/// (`core.hooksPath`, `core.fsmonitor`, filters and aliases live in config),
/// denied although the rest of `.git` is writable. A directory in `denyWrite`
/// covers its subtree, which is what `hooks` needs.
const GIT_EXEC_VECTORS: &[&str] = &[
    "/**/.git/hooks",
    "/**/.git/hooks/**",
    "/**/.git/config",
    "/**/.git/config.worktree",
    "/**/.git/info/attributes",
    "/**/.git/worktrees/*/config.worktree",
    "/**/.git/worktrees/*/commondir",
    "/**/.git/modules/**/hooks",
    "/**/.git/modules/**/hooks/**",
    "/**/.git/modules/**/config",
    "/**/.git/modules/**/config.worktree",
    "/**/.git/modules/**/info/attributes",
    "/**/.git/modules/**/commondir",
];

/// What OpenMoat writes into the user settings.
#[derive(Debug, Clone, PartialEq)]
pub struct Generated {
    /// The keys of the `sandbox` object OpenMoat owns; `filesystem` and `network`
    /// are owned key by key, so other keys in them survive.
    pub sandbox: Map<String, Value>,
    /// Whether `permissions.blockReadsOutsideWorkingDirectories` must be on.
    pub block_reads: bool,
    /// The `permissions.deny` rules OpenMoat owns (Linux only): every
    /// `Read(./**/…)` rule, the spelling no other writer is expected to use.
    pub read_rules: Vec<String>,
    /// Losses and allowances of this backend.
    pub report: Report,
}

/// Generate the settings for `ir`, lowered by [`super::lower_for_hosts`]. With
/// `proxy_port`, sandboxed commands' traffic goes to `moat proxy` there; with
/// `linux`, for bubblewrap.
pub fn generate(ir: &Enforcement, proxy_port: Option<u16>, linux: bool) -> Result<Generated> {
    let mut report = Report::default();
    let filesystem = Filesystem::build(ir, &mut report)?;
    let read_rules = if linux {
        filesystem.read_rules(&mut report)
    } else {
        Vec::new()
    };
    let network = match proxy_port {
        None => network(&ir.egress.net, &mut report),
        Some(port) => through_moat_proxy(&ir.egress.net, port, &mut report),
    };
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
         OpenMoat's project is the git root and never the home directory, so a session started \
         above a project writes more than the hook allows",
    );
    Ok(Generated {
        sandbox,
        block_reads,
        read_rules,
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
                let project = match spot(pattern) {
                    Spot::Project(rest) => Some(rest),
                    _ => None,
                };
                if kind == Kind::FsWrite && project == Some(".git/**") {
                    self.git_internals(report);
                    continue;
                }
                self.deny(kind, pattern);
                if let Some(rest) = project {
                    report.loss(
                        kind,
                        &rule.id,
                        format!(
                            "user settings cannot name the project, so `{rest}` is denied in every \
                             directory"
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

    /// The policy keeps the project's `.git` from writes, but user settings
    /// cannot name the project, and denying `.git` everywhere breaks `git commit`.
    /// Only what makes git run code or follow another repository is denied
    /// (ADR-021, amendment of 2026-10-06); the rest of `.git` is an allowance.
    fn git_internals(&mut self, report: &mut Report) {
        for vector in GIT_EXEC_VECTORS {
            push_unique(&mut self.deny_write, (*vector).to_owned());
        }
        report.allowance(
            Kind::FsWrite,
            "claude-code.git-internals",
            vec!["/**/.git/**".to_owned()],
            "user settings cannot name the project, so sandboxed commands may write `.git` \
             (objects, refs, index: `git commit` works) in every directory, except what makes git \
             run code or follow another repository (hooks, config, config.worktree, \
             info/attributes, a linked worktree's commondir, the same in submodules); a script \
             can still rewrite history, and the hook still asks for file-tool writes to `.git`",
        );
    }

    /// A directory node in `denyWrite` (no rename or delete of `.claude`) would
    /// make its whole subtree read-only, `.claude/worktrees/*` included, so a
    /// node with more specific entries below it is left out and listed.
    fn drop_directory_nodes(&mut self, report: &mut Report) {
        let dropped: Vec<String> = self
            .nodes
            .iter()
            .filter(|node| !self.trees.contains(node))
            .filter(|node| self.deny_write.iter().any(|e| is_below(e, node)))
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

    /// The `Read(./**/…)` rules that make Linux deny what each `/**/…` read
    /// deny names under the working directory, and what that leaves out.
    fn read_rules(&self, report: &mut Report) -> Vec<String> {
        let rules: Vec<String> = self
            .deny_read
            .iter()
            .filter_map(|entry| entry.strip_prefix("/**/"))
            .map(|rest| format!("Read(./**/{rest})"))
            .collect();
        if rules.is_empty() {
            return rules;
        }
        report.loss(
            Kind::FsRead,
            "claude-code.linux-read-rules",
            "on Linux these denies are also Claude Code `Read` deny rules, so its file tools \
             refuse them in the working directory too, an exception the hook allows (such as \
             `.env.example`) included"
                .into(),
        );
        report.allowance(
            Kind::FsRead,
            "claude-code.linux-read-globs",
            rules.clone(),
            "on Linux Claude Code denies only the files these match under the session's working \
             directory when each command starts: a file created after that, or one in another \
             readable directory (`/add-dir`, a read root, outside the user directories), stays \
             readable for sandboxed commands",
        );
        rules
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

/// `network.*` with both proxy ports naming `moat proxy`, which then decides
/// every connection by the policy; Claude Code's own lists and local-address
/// check stop applying to that traffic. The lists are still written: they
/// apply again if the ports are removed (`moat doctor` reports that), and
/// `strictAllowlist` in user settings keeps a repository from setting its own
/// ports or domains. Their losses are not reported, since they do not decide.
fn through_moat_proxy(net: &Access, port: u16, report: &mut Report) -> Value {
    let mut value = network(net, &mut Report::default());
    value["httpProxyPort"] = json!(port);
    value["socksProxyPort"] = json!(port);
    report.proxy_only(net);
    report.loss(
        Kind::Net,
        "claude-code.proxy",
        format!(
            "sandboxed commands have no network while nothing listens on 127.0.0.1:{port} \
             (`moat proxy`), and none over SOCKS5 (`ALL_PROXY`, ssh): `moat proxy` speaks HTTP only"
        ),
    );
    value
}

#[cfg(test)]
mod tests;
