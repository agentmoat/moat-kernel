//! Host adapters: the only place that knows each agent's hook wire format.
//!
//! An adapter translates a host payload into a [`HookRequest`] and a
//! [`Decision`] back into the host's response document. Adapters never
//! decide; `moat-core` does.

mod config_change;
mod cursor;
mod mcp;
mod patch;
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
    Cursor,
}

impl Host {
    pub const ALL: [Host; 3] = [Host::ClaudeCode, Host::Codex, Host::Cursor];

    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
        }
    }

    /// Parse a hook payload read from the host. The event name selects the format;
    /// a missing name means `PreToolUse`, the original contract.
    pub fn parse_request(self, payload: &str) -> Result<HookRequest, HostError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            #[serde(default)]
            hook_event_name: Option<String>,
        }
        let envelope: Envelope = serde_json::from_str(payload)?;
        match (self, envelope.hook_event_name.as_deref()) {
            (Self::Cursor, Some(event)) if cursor::EVENTS.contains(&event) => {
                cursor::parse(self, payload)
            }
            (Self::Cursor, _) => Err(HostError::WrongEvent(
                envelope.hook_event_name.unwrap_or_default(),
            )),
            (_, None | Some(pre_tool_use::EVENT)) => pre_tool_use::parse(self, payload),
            (Self::ClaudeCode, Some(config_change::EVENT)) => config_change::parse(self, payload),
            (_, Some(other)) => Err(HostError::WrongEvent(other.to_owned())),
        }
    }

    /// Render the response document the host expects on stdout for `event`.
    #[must_use]
    pub fn render_response(self, event: &HookEvent, decision: &Decision) -> String {
        match (self, event) {
            (Self::Cursor, _) => cursor::render(decision),
            (_, HookEvent::PreToolUse) => pre_tool_use::render(decision),
            (_, HookEvent::ConfigChange { .. }) => config_change::render(decision),
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

/// Which hook fired. Drives the response format and the guard's handling.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HookEvent {
    #[default]
    PreToolUse,
    /// A host settings file changed on disk (Claude Code only).
    ConfigChange { source: String, change_type: String },
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
    pub event: HookEvent,
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("unknown host `{0}`; supported: claude-code, codex, cursor")]
    UnknownHost(String),
    #[error("payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("payload is for event `{0}`, which this host adapter does not handle")]
    WrongEvent(String),
    #[error("tool `{tool}` payload is missing field `{field}`")]
    MissingField { tool: String, field: &'static str },
}
