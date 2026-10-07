//! Host hook installation.

mod binary;
mod hook_file;

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_hosts::Host;

pub use binary::{hook_binary, stale_hint};
pub use hook_file::{HookState, Outcome, read_or_empty};

use crate::home::user_home;

/// Suffix of the copy of a host file taken before OpenMoat's hook edit changes it.
pub const HOOK_BACKUP: &str = "moat-backup";
/// Suffix of the copy taken before OpenMoat's sandbox edit changes it.
pub const SANDBOX_BACKUP: &str = "moat-sandbox-backup";

/// The copy of `path` named `<path>.<suffix>`.
pub fn backup_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// The backups of `path` that exist, hook backup first.
pub fn backups(path: &Path) -> Vec<PathBuf> {
    [HOOK_BACKUP, SANDBOX_BACKUP]
        .into_iter()
        .map(|suffix| backup_path(path, suffix))
        .filter(|p| p.is_file())
        .collect()
}

/// One hook entry we own in a host's configuration.
#[derive(Debug, Clone, Copy)]
pub struct HookSpec {
    /// Host event name, e.g. `PreToolUse`.
    pub event: &'static str,
    /// Host matcher expression for that event.
    pub matcher: &'static str,
    /// Seconds the host waits for `moat guard` before treating it as failed.
    pub timeout: u64,
}

/// Seconds a host waits for a tool-call hook. Long enough for a person to
/// answer an `ask` prompted by the host; Claude Code and Codex default to 600.
const TOOL_HOOK_TIMEOUT_S: u64 = 600;
/// Seconds for the settings-change veto, which never waits for a person.
const CONFIG_HOOK_TIMEOUT_S: u64 = 60;

/// Every Claude Code tool `openmoat-hosts` maps to an action; a tool missing here
/// never reaches `moat guard`.
const TOOL_MATCHER: &str = "Bash|Monitor|PowerShell|Edit|Write|MultiEdit|NotebookEdit|Read|Glob|Grep|LSP|SendFile|WebFetch|mcp__.*";

const CLAUDE_CODE_HOOKS: &[HookSpec] = &[
    HookSpec {
        event: "PreToolUse",
        matcher: TOOL_MATCHER,
        timeout: TOOL_HOOK_TIMEOUT_S,
    },
    HookSpec {
        event: "ConfigChange",
        matcher: "user_settings|project_settings|local_settings",
        timeout: CONFIG_HOOK_TIMEOUT_S,
    },
];

/// Codex runs `PreToolUse` for shell, `apply_patch` file edits and MCP tools;
/// web search and hosted tools have no hook.
const CODEX_HOOKS: &[HookSpec] = &[HookSpec {
    event: "PreToolUse",
    matcher: "Bash|apply_patch|mcp__.*",
    timeout: TOOL_HOOK_TIMEOUT_S,
}];

const CURSOR_HOOKS: &[HookSpec] = &[
    HookSpec {
        event: "beforeShellExecution",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
    },
    HookSpec {
        event: "beforeMCPExecution",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
    },
    HookSpec {
        event: "beforeReadFile",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
    },
    HookSpec {
        event: "preToolUse",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
    },
];

/// How a host's hook file is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFormat {
    /// `{"hooks": {"<Event>": [{"matcher", "hooks": [{type, command, args, timeout}]}]}}`
    /// (Claude Code `settings.json`, Codex `hooks.json`).
    Nested,
    /// `{"version": 1, "hooks": {"<event>": [{"command": "<shell string>", "timeout", "failClosed"}]}}`
    /// (Cursor `hooks.json`). Cursor is fail-open unless `failClosed` is set.
    Cursor,
}

/// Where a host keeps its hook configuration and which events we subscribe to.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub host: Host,
    pub settings_path: PathBuf,
    pub hooks: &'static [HookSpec],
    pub format: HookFormat,
}

impl HostConfig {
    pub fn for_host(host: Host) -> Result<Self> {
        let home = user_home()?;
        let config = match host {
            Host::ClaudeCode => Self {
                host,
                settings_path: env_dir("CLAUDE_CONFIG_DIR")
                    .unwrap_or_else(|| home.join(".claude"))
                    .join("settings.json"),
                hooks: CLAUDE_CODE_HOOKS,
                format: HookFormat::Nested,
            },
            Host::Codex => Self {
                host,
                settings_path: env_dir("CODEX_HOME")
                    .unwrap_or_else(|| home.join(".codex"))
                    .join("hooks.json"),
                hooks: CODEX_HOOKS,
                format: HookFormat::Nested,
            },
            Host::Cursor => Self {
                host,
                settings_path: env_dir("CURSOR_CONFIG_DIR")
                    .unwrap_or_else(|| home.join(".cursor"))
                    .join("hooks.json"),
                hooks: CURSOR_HOOKS,
                format: HookFormat::Cursor,
            },
            Host::Continue => {
                bail!("the Continue CLI runs the Claude Code hook; it has none of its own")
            }
        };
        Ok(config)
    }

    /// The host is considered present when its configuration directory exists.
    pub fn host_present(&self) -> bool {
        self.settings_path
            .parent()
            .is_some_and(std::path::Path::is_dir)
    }

    pub fn install(&self, binary: &std::path::Path, dry_run: bool) -> Result<Outcome> {
        hook_file::install(self, binary, dry_run)
    }

    pub fn state(&self, binary: &std::path::Path) -> HookState {
        hook_file::state(self, binary)
    }

    /// Remove OpenMoat's hook entries from the parsed hook file `root`.
    pub fn remove(&self, root: &mut serde_json::Value) -> bool {
        hook_file::remove(root, self)
    }
}

/// What `moat doctor` and `moat status` say when the Continue CLI is present.
pub const CONTINUE_CLI_WARNING: &str = "the released Continue CLI does not run hooks, so \
     OpenMoat cannot check its tool calls; run it under `moat run`";

/// Where the Continue CLI (`cn`) shows itself: its global directory
/// (`CONTINUE_GLOBAL_DIR`, else `~/.continue`, as `cn` resolves it), or `cn`
/// on the search path. `cn` loads Claude Code's hooks but fires none of them
/// yet (released 1.5.47), so its tool calls never reach `guard`.
pub fn continue_cli() -> Result<Option<PathBuf>> {
    let dir = match env_dir("CONTINUE_GLOBAL_DIR") {
        Some(dir) => dir,
        None => user_home()?.join(".continue"),
    };
    if dir.is_dir() {
        return Ok(Some(dir));
    }
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    Ok(crate::environment::find_in(&path, &[], "cn"))
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}
