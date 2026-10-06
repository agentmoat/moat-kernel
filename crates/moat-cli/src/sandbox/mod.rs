//! Standard tier (ADR-018): each host's own sandbox settings, generated from
//! the enforcement IR (ADR-019).
//!
//! The settings are host-wide (Claude Code user settings, Codex `config.toml`),
//! so the IR is lowered once for no particular session: [`PROJECT`] stands in
//! for the project, and each backend maps it to the host's own notion of the
//! workspace (Claude Code's working directories, Codex `:workspace_roots`).
//! Backends only narrow, reported as losses, except where a host cannot run
//! without a wider grant; those are listed as allowances, never silent.

mod patterns;

use moat_core::ir::{Allowance, Enforcement, Loss};
use moat_core::{EvalContext, Policy, PolicyError};
use serde::Serialize;

/// Stand-in for the session's project in a host-wide lowering. Never a real
/// directory: it only marks the patterns that name `${project}`.
pub const PROJECT: &str = "/__moat_project__";

/// Lower `policy` for host-wide settings of a user whose home is `home`
/// (`real_home`: the same with symlinks resolved, when that differs).
pub fn lower_for_hosts(
    policy: &Policy,
    home: &str,
    real_home: Option<String>,
    case_insensitive_paths: bool,
) -> Result<Enforcement, PolicyError> {
    moat_core::ir::lower(
        policy,
        &EvalContext {
            home: home.to_owned(),
            project: Some(PROJECT.to_owned()),
            real_home,
            real_project: None,
            cwd: PROJECT.to_owned(),
            case_insensitive_paths,
        },
    )
}

/// How one backend's output differs from the IR.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Where the host is stricter than the IR.
    pub losses: Vec<Loss>,
    /// Where the host is wider than the IR, the IR's own allowances included.
    pub allowances: Vec<Allowance>,
}

impl Report {
    fn loss(&mut self, kind: moat_core::Kind, rule: &str, message: String) {
        let loss = Loss {
            kind,
            rule: rule.to_owned(),
            message,
        };
        if !self.losses.contains(&loss) {
            self.losses.push(loss);
        }
    }

    fn allowance(
        &mut self,
        kind: moat_core::Kind,
        rule: &str,
        patterns: Vec<String>,
        message: &str,
    ) {
        self.allowances.push(Allowance {
            kind,
            rule: rule.to_owned(),
            patterns,
            message: message.to_owned(),
        });
    }
}

/// Compare `actual` with `tests/fixtures/sandbox/<name>`; `MOAT_UPDATE_GOLDEN=1`
/// rewrites the file instead.
#[cfg(test)]
pub fn assert_golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/sandbox")
        .join(name);
    if std::env::var_os("MOAT_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        actual,
        expected,
        "MOAT_UPDATE_GOLDEN=1 updates {}",
        path.display()
    );
}
