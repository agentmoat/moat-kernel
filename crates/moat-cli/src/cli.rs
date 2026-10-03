//! Command-line grammar.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use moat_hosts::Host;

#[derive(Debug, Parser)]
#[command(
    name = "moat",
    version,
    about = "agentmoat: the kernel your AI agents run on",
    long_about = "Decides what AI agents may do on this machine, enforces it, and records it.\n\
                  Exit codes: 0 allow/ok, 2 deny, 3 ask (unresolved), 64 usage or configuration error."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Install the kernel: default policy, audit log and host hooks.
    Init(InitArgs),
    /// Decide one hook request from stdin (invoked by host hooks, not by people).
    Guard(GuardArgs),
    /// Show one audit event, a session, or the most recent events.
    Show(ShowArgs),
    /// Report installation health: policy, hooks, recent activity.
    Status,
    /// Verify policy lock, hooks and binary; `--accept` re-pins edits made by a person.
    Doctor(DoctorArgs),
    /// Inspect and test policy files.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Hosts to install hooks for. Defaults to every supported host that is present.
    #[arg(long, value_delimiter = ',', value_parser = parse_host)]
    pub hosts: Option<Vec<Host>>,

    /// Print what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Accept the current policy and hook files as trusted and re-pin the lock.
    /// Refused unless run from an interactive terminal.
    #[arg(long)]
    pub accept: bool,
}

#[derive(Debug, Args)]
pub struct GuardArgs {
    /// Host whose hook payload is on stdin.
    #[arg(long, value_parser = parse_host)]
    pub host: Host,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Event id as printed by `guard` (hex).
    #[arg(conflicts_with = "session")]
    pub id: Option<String>,

    /// All events of one host session, oldest first.
    #[arg(long)]
    pub session: Option<String>,

    /// Most recent events (default when nothing else is given).
    #[arg(long, default_value_t = 10)]
    pub recent: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Validate a policy file and print a summary.
    Lint(LintArgs),
    /// Decide one action against a policy and explain the result.
    Check(CheckArgs),
}

#[derive(Debug, Args)]
pub struct LintArgs {
    /// Policy file to validate. Defaults to the installed user policy.
    pub file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// The action: a shell command, a path, a URL or an MCP tool name, depending on --kind.
    pub action: String,

    /// Policy file to evaluate against. Defaults to the installed user policy.
    #[arg(long, short)]
    pub policy: Option<PathBuf>,

    /// Kind of action.
    #[arg(long, value_enum, default_value_t = ActionKind::Shell)]
    pub kind: ActionKind,

    /// Trusted project root that `${project}` expands to. Defaults to the git root of --cwd.
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Working directory the action runs in. Defaults to the current directory.
    #[arg(long)]
    pub cwd: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ActionKind {
    Shell,
    FsRead,
    FsWrite,
    Net,
    Mcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

fn parse_host(value: &str) -> Result<Host, String> {
    value
        .parse()
        .map_err(|e: moat_hosts::HostError| e.to_string())
}
