//! Host adapters: the only place that knows each agent's hook wire format.
//!
//! An adapter translates a host payload into a [`HookRequest`] and a
//! [`Decision`] back into the host's response document. Adapters never
//! decide; `moat-core` does.

mod pre_tool_use;

pub use pre_tool_use::reason_line;

use std::fmt;
use std::str::FromStr;

use moat_core::{Action, Decision};
use thiserror::Error;

/// Agents with a supported integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Host {
    ClaudeCode,
    Codex,
}

impl Host {
    pub const ALL: [Host; 2] = [Host::ClaudeCode, Host::Codex];

    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }

    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
        }
    }

    /// Parse a hook payload read from the host.
    pub fn parse_request(self, payload: &str) -> Result<HookRequest, HostError> {
        match self {
            Self::ClaudeCode | Self::Codex => pre_tool_use::parse(self, payload),
        }
    }

    /// Render the response document the host expects on stdout.
    #[must_use]
    pub fn render_response(self, decision: &Decision) -> String {
        match self {
            Self::ClaudeCode | Self::Codex => pre_tool_use::render(decision),
        }
    }
}

impl FromStr for Host {
    type Err = HostError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|h| h.id() == s)
            .ok_or_else(|| HostError::UnknownHost(s.to_owned()))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A host tool call, normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRequest {
    pub host: Host,
    pub session_id: String,
    pub call_id: Option<String>,
    pub cwd: Option<String>,
    pub tool: String,
    /// `None` when the tool is outside the kernel's scope (e.g. a todo list).
    pub action: Option<Action>,
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("unknown host `{0}`; supported: claude-code, codex")]
    UnknownHost(String),
    #[error("payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("payload is for event `{0}`, expected PreToolUse")]
    WrongEvent(String),
    #[error("tool `{tool}` payload is missing field `{field}`")]
    MissingField { tool: String, field: &'static str },
}
