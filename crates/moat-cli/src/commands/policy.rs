//! `moat policy lint` and `moat policy check`.

use std::path::PathBuf;

use anyhow::Result;
use moat_core::{Action, CompiledPolicy, Decision, NoResolver, Policy, ProgramResolver};

use crate::cli::{ActionKind, CheckArgs, Format, LintArgs};
use crate::context;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity;
use crate::realpath::FsPathResolver;
use crate::render;

pub fn lint(args: &LintArgs) -> Result<Code> {
    let (policy, path) = load(args.file.clone())?;
    let warnings = moat_core::lint::warnings(&policy);
    for warning in &warnings {
        println!("warning: {warning}");
    }
    let (deny, allow, ask) = policy.rule_count();
    let suffix = match warnings.len() {
        0 => String::new(),
        1 => ", 1 warning".to_owned(),
        n => format!(", {n} warnings"),
    };
    println!(
        "ok: {} ({deny} deny, {allow} allow, {ask} ask groups{suffix})",
        path.display()
    );
    Ok(Code::Ok)
}

pub fn check(args: &CheckArgs) -> Result<Code> {
    // The installed policy decides nothing while the lock is broken: report the
    // `kernel-integrity` deny `guard` would answer instead of the policy's verdict.
    if args.policy.is_none()
        && let Some(decision) = integrity::violation(&Home::locate()?)?
    {
        return report(&decision, args.format);
    }
    let (policy, _) = load(args.policy.clone())?;
    let ctx = context::eval_context(args.cwd.as_deref(), args.project.as_deref())?;
    // Decide the way `guard` would: symlinks resolved on this machine, and
    // programs resolved through the installation snapshot when one exists.
    let paths = FsPathResolver::new(&ctx);
    let snapshot = Home::locate()
        .ok()
        .and_then(|home| Snapshot::load(&home.environment_path()).ok());
    let programs: &dyn ProgramResolver = match &snapshot {
        Some(snapshot) => snapshot,
        None => &NoResolver,
    };
    let decision = CompiledPolicy::compile(&policy, &ctx)?.decide_with(
        &to_action(args.kind, &args.action),
        programs,
        &paths,
    );
    report(&decision, args.format)
}

fn report(decision: &Decision, format: Format) -> Result<Code> {
    match format {
        Format::Text => render::decision_text(decision)?,
        Format::Json => render::decision_json(decision)?,
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
        ActionKind::Fetch => Action::Fetch { url: value },
        ActionKind::Mcp => Action::mcp(value),
    }
}
