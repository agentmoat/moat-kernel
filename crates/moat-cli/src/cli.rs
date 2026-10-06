//! Command-line grammar.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use moat_hosts::Host;

#[derive(Debug, Parser)]
#[command(
    name = "moat",
    version,
    about = "agentmoat: the kernel your AI agents run on",
    long_about = "Decides what AI agents may do on this machine and records every decision.\n\
                  Alpha: decisions are not enforced by the operating system; an allowed\n\
                  command runs with your permissions.\n\
                  Exit codes: 0 allow/ok, 2 deny, 3 ask (unresolved), 64 usage or configuration error\n\
                  (`guard` exits 2 instead, so a broken hook blocks rather than fails open)."
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
    /// Approve a shell command for one session, or permanently.
    Allow(AllowArgs),
    /// Replay agent sessions as a timeline of decisions.
    Replay(ReplayArgs),
    /// Summarise decisions over a window: verdicts, hosts, top rules, asks per hour.
    Report(ReportArgs),
    /// Run the default-deny egress proxy: only hosts the policy allows, every connection recorded.
    Proxy(ProxyArgs),
    /// Export the audit log for review elsewhere.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Inspect and test policy files.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// The host sandboxes moat configures from the policy (Standard tier, ADR-018).
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum SandboxCommand {
    /// Print the sandbox settings the policy compiles to and the translation losses; writes nothing.
    Show(SandboxShowArgs),
    /// Write the sandbox settings from the current policy and re-pin them.
    /// Refused unless run from an interactive terminal, and over a drifted lock.
    Sync,
}

#[derive(Debug, Args)]
pub struct SandboxShowArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
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
pub struct ReplayArgs {
    /// Window start: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, default_value = "24h", conflicts_with = "session")]
    pub since: String,

    /// Only this host.
    #[arg(long, value_parser = parse_host, conflicts_with = "session")]
    pub host: Option<Host>,

    /// One session by id, regardless of window.
    #[arg(long)]
    pub session: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Window start: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, default_value = "7d")]
    pub since: String,

    /// Only this host.
    #[arg(long, value_parser = parse_host)]
    pub host: Option<Host>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct AllowArgs {
    /// The exact shell command to approve.
    #[arg(conflicts_with = "last")]
    pub command: Option<String>,

    /// Take host, session and command from the most recent `ask` in the audit log.
    #[arg(long)]
    pub last: bool,

    /// Host of the session to approve (with --session).
    #[arg(long, value_parser = parse_host, requires = "session")]
    pub host: Option<Host>,

    /// Approve for this session id only (exact command match).
    #[arg(long, conflicts_with = "always")]
    pub session: Option<String>,

    /// Add a permanent allow rule to ~/.moat/policy.d/approved.yaml instead.
    #[arg(long)]
    pub always: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Accept the current policy and hook files as trusted and re-pin the lock.
    /// Refused unless run from an interactive terminal.
    #[arg(long)]
    pub accept: bool,
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// Address to listen on. Must be a loopback address: the proxy serves this machine only.
    #[arg(long, default_value = "127.0.0.1:18080")]
    pub listen: std::net::SocketAddr,
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

    /// Events since a window start, oldest first: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, conflicts_with_all = ["id", "session"])]
    pub since: Option<String>,

    /// Most recent events (default when nothing else is given).
    #[arg(long, default_value_t = 10)]
    pub recent: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Write events to stdout as JSON Lines, oldest first, each with its chain hashes.
    Export(ExportArgs),
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Window start: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, default_value = "all")]
    pub since: String,

    /// Only this host.
    #[arg(long, value_parser = parse_host)]
    pub host: Option<Host>,

    /// Only this session id.
    #[arg(long)]
    pub session: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Validate a policy file and print a summary.
    Lint(LintArgs),
    /// Decide one action against a policy and explain the result.
    Check(CheckArgs),
    /// Print what OS layers enforce for a policy: the compiled IR and its losses.
    Compile(CompileArgs),
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

#[derive(Debug, Args)]
pub struct CompileArgs {
    /// Policy file to compile. Defaults to the installed user policy.
    #[arg(long, short)]
    pub policy: Option<PathBuf>,

    /// Trusted project root that `${project}` expands to. Defaults to the git root of --cwd.
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Working directory to compile for. Defaults to the current directory.
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
    /// A URL read by a host fetch tool (`WebFetch`).
    Fetch,
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
