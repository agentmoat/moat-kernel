//! The payload each host sends for one tool call, and the answer it must get
//! back. Shapes follow the golden payloads in `tests/fixtures/hosts/`.

use std::path::Path;
use std::process::Output;

use serde_json::{Value, json};

use super::{Call, Verdict};
use crate::common::{hook_output, json};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Host {
    ClaudeCode,
    Codex,
    Cursor,
}

impl Host {
    pub const ALL: [Self; 3] = [Self::ClaudeCode, Self::Codex, Self::Cursor];

    pub fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    /// The hook payload for `call`, or `None` when this host has no tool for it
    /// (Codex reads files through its shell; only Claude Code has `WebFetch`).
    pub fn payload(self, call: &Call, at: &Place<'_>) -> Option<String> {
        let (tool, input) = match (self, call) {
            (Self::Cursor, _) => return cursor(call, at).map(|v| v.to_string()),
            (_, Call::Shell(command)) => ("Bash".to_owned(), json!({ "command": command })),
            (Self::ClaudeCode, Call::Read(path)) => {
                ("Read".to_owned(), json!({ "file_path": at.file(path) }))
            }
            (Self::ClaudeCode, Call::Write(path)) => (
                "Write".to_owned(),
                json!({ "file_path": at.file(path), "content": CONTENT }),
            ),
            (Self::Codex, Call::Write(path)) => (
                "apply_patch".to_owned(),
                json!({ "command": format!(
                    "*** Begin Patch\n*** Add File: {}\n+{CONTENT}\n*** End Patch\n",
                    at.file(path)
                ) }),
            ),
            (Self::ClaudeCode, Call::Fetch(url)) => (
                "WebFetch".to_owned(),
                json!({ "url": url, "prompt": "summarise" }),
            ),
            (_, Call::Mcp { server, tool, args }) => {
                (format!("mcp__{server}__{tool}"), args.clone())
            }
            _ => return None,
        };
        Some(
            json!({
                "session_id": at.session, "turn_id": "t-1", "cwd": at.cwd(),
                "hook_event_name": "PreToolUse", "tool_name": tool,
                "tool_input": input, "tool_use_id": at.call_id,
            })
            .to_string(),
        )
    }

    /// The verdict the host is told for a kernel verdict: Codex cannot ask, so
    /// an `ask` reaches it as a blocking `deny`.
    pub fn answer(self, verdict: Verdict) -> Verdict {
        match (self, verdict) {
            (Self::Codex, Verdict::Ask) => Verdict::Deny,
            (_, other) => other,
        }
    }

    /// The decision word in the host's response document.
    pub fn decision(self, out: &Output) -> Value {
        match self {
            Self::Cursor => json(out)["permission"].clone(),
            _ => hook_output(out)["permissionDecision"].clone(),
        }
    }
}

const CONTENT: &str = "written by the agent";

/// Where a call happens: the isolated home, the project, and its ids.
pub struct Place<'a> {
    pub home: &'a Path,
    pub project: &'a Path,
    pub session: &'a str,
    pub call_id: &'a str,
}

impl Place<'_> {
    fn cwd(&self) -> String {
        self.project.to_string_lossy().into_owned()
    }

    /// File tools send absolute paths: `~/x` is in the home, anything relative
    /// is in the project.
    fn file(&self, path: &str) -> String {
        let full = match path.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None => self.project.join(path),
        };
        full.to_string_lossy().into_owned()
    }
}

fn cursor(call: &Call, at: &Place<'_>) -> Option<Value> {
    let common = json!({
        "conversation_id": at.session, "generation_id": at.call_id,
        "cursor_version": "2.3.1", "workspace_roots": [at.cwd()],
    });
    let event = match call {
        Call::Shell(command) => json!({
            "hook_event_name": "beforeShellExecution", "command": command,
            "cwd": at.cwd(), "sandbox": false,
        }),
        Call::Read(path) => json!({
            "hook_event_name": "beforeReadFile", "file_path": at.file(path),
            "content": "", "attachments": [],
        }),
        Call::Write(path) => json!({
            "hook_event_name": "preToolUse", "cwd": at.cwd(), "tool_name": "Write",
            "tool_input": { "file_path": at.file(path), "content": CONTENT },
            "tool_use_id": at.call_id,
        }),
        // Cursor sends MCP arguments as a JSON string.
        Call::Mcp { server, tool, args } => json!({
            "hook_event_name": "beforeMCPExecution", "tool_name": tool,
            "tool_input": args.to_string(), "mcp_server_name": server,
        }),
        Call::Fetch(_) => return None,
    };
    let mut merged = common;
    merged.as_object_mut()?.extend(event.as_object()?.clone());
    Some(merged)
}
