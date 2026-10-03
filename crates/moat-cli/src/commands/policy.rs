//! `moat policy lint` and `moat policy check`.

use std::path::PathBuf;

use anyhow::Result;
use moat_core::{Action, CompiledPolicy, Policy};

use crate::cli::{ActionKind, CheckArgs, Format, LintArgs};
use crate::context;
use crate::exit::Code;
use crate::home::Home;
use crate::render;

pub fn lint(args: &LintArgs) -> Result<Code> {
    let (policy, path) = load(args.file.clone())?;
    let (deny, allow, ask) = policy.rule_count();
    println!(
        "ok: {} ({deny} deny, {allow} allow, {ask} ask groups)",
        path.display()
    );
    Ok(Code::Ok)
}

pub fn check(args: &CheckArgs) -> Result<Code> {
    let (policy, _) = load(args.policy.clone())?;
    let ctx = context::eval_context(args.cwd.as_deref(), args.project.as_deref())?;
    let decision =
        CompiledPolicy::compile(&policy, &ctx)?.decide(&to_action(args.kind, &args.action));
    match args.format {
        Format::Text => render::decision_text(&decision)?,
        Format::Json => render::decision_json(&decision)?,
    }
    Ok(decision.verdict.into())
}

fn load(explicit: Option<PathBuf>) -> Result<(Policy, PathBuf)> {
    if let Some(path) = explicit {
        return Ok((context::load_policy(&path)?, path));
    }
    let home = Home::locate()?;
    Ok((home.load_policy()?, home.policy_path()))
}

fn to_action(kind: ActionKind, value: &str) -> Action {
    let value = value.to_owned();
    match kind {
        ActionKind::Shell => Action::Shell { command: value },
        ActionKind::FsRead => Action::FsRead { path: value },
        ActionKind::FsWrite => Action::FsWrite { path: value },
        ActionKind::Net => Action::Net { url: value },
        ActionKind::Mcp => Action::McpTool { name: value },
    }
}
