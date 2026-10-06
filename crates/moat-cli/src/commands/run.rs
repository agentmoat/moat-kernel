//! `moat run [--write PATH]… -- <agent> [args]`: the Lightweight tier (ADR-018).
//!
//! The agent and every command it starts share one sandbox generated from the
//! policy for the project in the current directory. Their only network is a
//! `moat proxy` this process serves on a loopback port: the sandbox allows that
//! port alone, and the proxy refuses loopback destinations, so no other local
//! service is reachable through it either.

#[cfg_attr(target_os = "macos", path = "run/macos.rs")]
#[cfg_attr(not(target_os = "macos"), path = "run/unsupported.rs")]
mod platform;

use std::ffi::OsStr;
use std::io::Write as _;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context as _, Result, bail};

use super::proxy::{self, Exit};
use super::sandbox::write_report;
use crate::cli::RunArgs;
use crate::context::{self, path_string};
use crate::environment::find_in;
use crate::exit::Code;
use crate::sandbox::Report;
use crate::sandbox::seatbelt::Grants;

/// What a proxy-aware program reads to find its proxy.
const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

pub fn run(args: &RunArgs) -> Result<Code> {
    let home = proxy::installed()?;
    let ctx = context::eval_context(None, None)?;
    if ctx.project.is_none() {
        bail!(
            "`moat run` confines the agent to a project: start it in the project, not in \
             your home directory, one of its ancestors or a filesystem root"
        );
    }
    let (name, rest) = args.command.split_first().context("no agent to run")?;
    // The sandbox checks the file it starts, not a link to it.
    let program = resolve(name)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("listening on a loopback port for the proxy")?;
    let port = listener.local_addr()?.port();
    let grants = Grants {
        proxy_port: Some(port),
        tmpdir: None,
        program: Some(path_string(&program)),
        writes: args.writes.iter().map(|w| resolved(w)).collect(),
    };
    let policy = home.load_policy()?;
    let (mut agent, report) = platform::confine(&policy, &ctx, grants)?;
    agent.arg(&program).args(rest);
    let exit = Exit::open(&home, policy, ctx)?;
    notice(&program, port, exit.session(), &report)?;
    std::thread::spawn(move || {
        if let Err(error) = exit.serve(&listener) {
            eprintln!("moat run: the proxy stopped, so the agent has no network: {error:#}");
        }
    });
    let url = format!("http://127.0.0.1:{port}");
    for var in PROXY_VARS {
        agent.env(var, &url);
    }
    agent.env_remove("NO_PROXY").env_remove("no_proxy");
    // Ctrl-C at the terminal reaches the agent and moat alike. The agent decides
    // what it means; moat keeps running, or the proxy would die under the agent.
    signal_hook::flag::register(
        signal_hook::consts::SIGINT,
        Arc::new(AtomicBool::new(false)),
    )
    .context("keeping moat running on Ctrl-C")?;
    let status = agent
        .status()
        .with_context(|| format!("starting {}", program.display()))?;
    Ok(if status.success() {
        Code::Ok
    } else {
        Code::Failed
    })
}

/// The executable `name` starts, symlinks resolved.
fn resolve(name: &OsStr) -> Result<PathBuf> {
    let path = Path::new(name);
    let found = if path.components().count() > 1 {
        Some(path.to_path_buf())
    } else {
        let dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        find_in(&dirs, &[], &name.to_string_lossy())
    };
    let found = found.with_context(|| format!("{} is not on PATH", path.display()))?;
    std::fs::canonicalize(&found).with_context(|| format!("resolving {}", found.display()))
}

/// `path` with its symlinks resolved, or made absolute when it does not exist yet.
fn resolved(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).or_else(|_| context::absolute(path));
    path_string(resolved.as_deref().unwrap_or(path))
}

/// What the user must know before the agent starts, on standard error.
fn notice(program: &Path, port: u16, session: &str, report: &Report) -> Result<()> {
    let mut err = std::io::stderr().lock();
    writeln!(
        err,
        "moat run: {} in a sandbox generated from the policy (Lightweight tier, ADR-018)\n  \
         network: only through moat's proxy on 127.0.0.1:{port} (audit session {session})\n  \
         turn the agent's own sandbox off: sandboxes do not nest, so Claude Code's or Codex's \
         cannot start in here\n  \
         (Codex: --sandbox danger-full-access). This one confines the agent and every command \
         it starts as one, so it is weaker per command than the Standard tier.",
        program.display()
    )?;
    write_report(&mut err, report)?;
    Ok(())
}
