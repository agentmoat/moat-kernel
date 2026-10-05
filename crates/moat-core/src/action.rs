use serde::{Deserialize, Serialize};

use crate::kind::Kind;

/// A tool call as seen from a host, before classification.
///
/// Host adapters (`moat-hosts`) translate each payload into exactly one of
/// these. Adapters never decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// A shell command string as the host would execute it.
    Shell { command: String },
    /// A direct file read through a host tool (e.g. Claude Code `Read`).
    FsRead { path: String },
    /// A direct file write/edit through a host tool.
    FsWrite { path: String },
    /// A direct network request through a host tool (e.g. `WebFetch`).
    Net { url: String },
    /// A patch that edits several files in one call (Codex `apply_patch`):
    /// every path it adds, updates, deletes or moves to is written.
    Patch { writes: Vec<String> },
    /// An MCP tool call, `mcp__<server>__<tool>`. Adapters that understand a
    /// server's arguments add the paths and hosts the call touches so the
    /// usual `fs.*` and `net` rules apply to it as well.
    McpTool {
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reads: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        writes: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        hosts: Vec<String>,
    },
}

impl Action {
    /// The kind of action as a user would describe it (`Patch` writes files).
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self {
            Self::Shell { .. } => Kind::Shell,
            Self::FsRead { .. } => Kind::FsRead,
            Self::FsWrite { .. } | Self::Patch { .. } => Kind::FsWrite,
            Self::Net { .. } => Kind::Net,
            Self::McpTool { .. } => Kind::Mcp,
        }
    }

    /// An MCP call whose arguments are not interpreted.
    #[must_use]
    pub fn mcp(name: impl Into<String>) -> Self {
        Self::McpTool {
            name: name.into(),
            reads: Vec::new(),
            writes: Vec::new(),
            hosts: Vec::new(),
        }
    }
}

/// The primitive operations an [`Action`] decomposes into.
///
/// One shell command typically yields several: the command itself, every
/// path it touches, every host it may contact, every env var it reads or sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicAction {
    /// Normalised argv of one (sub-)command.
    Shell {
        argv: Vec<String>,
    },
    /// A whole pipeline / list (`a | b && c`) with separators kept as tokens, so
    /// rules such as `curl * | sh` can match across sub-commands. Never carries
    /// a default verdict (see `engine/mod.rs`).
    Pipeline {
        argv: Vec<String>,
    },
    /// Absolute path in slash-separated canonical form (`~`, `${project}` and
    /// `cwd` already applied).
    FsRead {
        path: String,
    },
    FsWrite {
        path: String,
    },
    /// Host name only (no scheme, no port).
    Net {
        host: String,
    },
    EnvRead {
        name: String,
    },
    EnvSet {
        name: String,
    },
    McpTool {
        name: String,
    },
}

impl AtomicAction {
    /// The rule kind this atom is matched against.
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self {
            Self::Shell { .. } | Self::Pipeline { .. } => Kind::Shell,
            Self::FsRead { .. } => Kind::FsRead,
            Self::FsWrite { .. } => Kind::FsWrite,
            Self::Net { .. } => Kind::Net,
            Self::EnvRead { .. } => Kind::EnvRead,
            Self::EnvSet { .. } => Kind::EnvSet,
            Self::McpTool { .. } => Kind::Mcp,
        }
    }

    /// The text a glob rule is matched against; `None` for shell atoms, which
    /// are matched as argv.
    pub(crate) fn subject(&self) -> Option<&str> {
        match self {
            Self::Shell { .. } | Self::Pipeline { .. } => None,
            Self::FsRead { path } | Self::FsWrite { path } => Some(path),
            Self::Net { host } => Some(host),
            Self::EnvRead { name } | Self::EnvSet { name } | Self::McpTool { name } => Some(name),
        }
    }

    /// Short human description used in reasons and audit lines.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Shell { argv } => format!("shell \"{}\"", argv.join(" ")),
            Self::Pipeline { argv } => format!("pipeline \"{}\"", argv.join(" ")),
            Self::FsRead { path } => format!("read {path}"),
            Self::FsWrite { path } => format!("write {path}"),
            Self::Net { host } => format!("net {host}"),
            Self::EnvRead { name } => format!("env read {name}"),
            Self::EnvSet { name } => format!("env set {name}"),
            Self::McpTool { name } => format!("mcp {name}"),
        }
    }
}
