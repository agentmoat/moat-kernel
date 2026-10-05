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
    /// A shell command line, exactly as the host would run it.
    Shell {
        /// The command line.
        command: String,
    },
    /// A direct file read through a host tool (e.g. Claude Code `Read`).
    /// A file read by a host tool (`Read`, `Glob`, `Grep`, `beforeReadFile`).
    FsRead {
        /// Path as the tool gave it; normalised during classification.
        path: String,
    },
    /// A direct file write/edit through a host tool.
    /// A file write or edit by a host tool (`Edit`, `Write`, `NotebookEdit`).
    FsWrite {
        /// Path as the tool gave it; normalised during classification.
        path: String,
    },
    /// A direct network request through a host tool (e.g. `WebFetch`).
    /// A URL fetched by a host tool (`WebFetch`).
    Net {
        /// The URL as the tool gave it.
        url: String,
    },
    /// A patch that edits several files in one call (Codex `apply_patch`):
    /// every path it adds, updates, deletes or moves to is written.
    /// Files changed by one multi-file patch (Codex `apply_patch`).
    Patch {
        /// Every file the patch adds, updates, deletes or moves to.
        writes: Vec<String>,
    },
    /// An MCP tool call, `mcp__<server>__<tool>`. Adapters that understand a
    /// server's arguments add the paths and hosts the call touches so the
    /// usual `fs.*` and `net` rules apply to it as well.
    McpTool {
        /// `mcp__<server>__<tool>`.
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        /// Paths the call reads, derived from its arguments.
        reads: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        /// Paths the call writes, derived from its arguments.
        writes: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        /// URLs or hosts the call contacts, derived from its arguments.
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
        /// Program and arguments after quote removal.
        argv: Vec<String>,
    },
    /// A whole pipeline / list (`a | b && c`) with separators kept as tokens, so
    /// rules such as `curl * | sh` can match across sub-commands. Never carries
    /// a default verdict (see `engine/mod.rs`).
    Pipeline {
        /// Words and separator tokens of the whole pipeline or list.
        argv: Vec<String>,
    },
    /// Absolute path in slash-separated canonical form (`~`, `${project}` and
    /// `cwd` already applied).
    FsRead {
        /// Absolute path in canonical form.
        path: String,
    },
    /// A file write, create, delete or move.
    FsWrite {
        /// Absolute path in canonical form.
        path: String,
    },
    /// Host name only (no scheme, no port).
    Net {
        /// Lowercase host name.
        host: String,
    },
    /// An environment variable read (`$NAME`, `printenv NAME`).
    EnvRead {
        /// Variable name.
        name: String,
    },
    /// An environment variable set (`NAME=value`, `export NAME=…`).
    EnvSet {
        /// Variable name.
        name: String,
    },
    /// An MCP tool invocation.
    McpTool {
        /// `mcp__<server>__<tool>`.
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
