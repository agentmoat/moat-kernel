//! Host hook installation.

mod hook_file;

use std::path::PathBuf;

use anyhow::Result;
use moat_hosts::Host;

pub use hook_file::{HookState, Outcome};

use crate::home::user_home;

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

const TOOL_MATCHER: &str = "Bash|Edit|Write|MultiEdit|NotebookEdit|Read|Glob|Grep|WebFetch|mcp__.*";

const CLAUDE_CODE_HOOKS: &[HookSpec] = &[HookSpec {
    event: "PreToolUse",
    matcher: TOOL_MATCHER,
    timeout: 600,
}];

const CODEX_HOOKS: &[HookSpec] = &[HookSpec {
    event: "PreToolUse",
    matcher: "Bash",
    timeout: 600,
}];

/// Where a host keeps its hook configuration and which events we subscribe to.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub host: Host,
    pub settings_path: PathBuf,
    pub hooks: &'static [HookSpec],
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
            },
            Host::Codex => Self {
                host,
                settings_path: env_dir("CODEX_HOME")
                    .unwrap_or_else(|| home.join(".codex"))
                    .join("hooks.json"),
                hooks: CODEX_HOOKS,
            },
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
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}
