//! The policy's `taint:` section (ADR-020, docs/POLICY.md §4.1): what session
//! taint protects beyond the built-in list. The engine applies it in
//! `engine/taint.rs`.

use serde::{Deserialize, Serialize};

use crate::pattern::GlobPattern;
use crate::policy::PolicyError;

/// Files whose change runs code or steers the agent later, beyond the edit
/// itself: CI, git hooks, editor tasks, build scripts the allowed dev commands
/// run, and agent instructions and settings. Writing them is ordinary work,
/// until the session has read content an attacker may control.
const PROTECTED_WRITES: [&str; 16] = [
    "**/.github/workflows/**",
    "**/.gitlab-ci.yml",
    "**/.circleci/**",
    "**/.husky/**",
    "**/.githooks/**",
    "**/.vscode/**",
    "**/package.json",
    "**/Makefile",
    "**/build.rs",
    "**/CLAUDE.md",
    "**/AGENTS.md",
    "**/.claude/**",
    "**/.codex/**",
    "**/.cursor/**",
    "**/.cursorrules",
    "**/.mcp.json",
];

/// The `taint:` section. Absent in policies written before it existed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintSettings {
    /// Path globs a write to asks once the session read untrusted content, in
    /// addition to the built-in list, which a policy cannot shorten. No `!`
    /// exclusions, for the same reason.
    #[serde(default)]
    pub protected_writes: Vec<String>,
}

/// The built-in protected paths followed by the ones `settings` adds.
pub(crate) fn protected_writes(settings: Option<&TaintSettings>) -> impl Iterator<Item = &str> {
    PROTECTED_WRITES.into_iter().chain(
        settings
            .into_iter()
            .flat_map(|s| s.protected_writes.iter().map(String::as_str)),
    )
}

/// Each added path is a glob that compiles and is not an exclusion, which
/// would take a built-in path out of protection.
pub(crate) fn check(settings: Option<&TaintSettings>) -> Result<(), PolicyError> {
    let problem = |problem: String| PolicyError::Rule {
        rule: "taint.protected_writes".to_owned(),
        problem,
    };
    for p in settings.iter().flat_map(|s| &s.protected_writes) {
        if p.trim_start().starts_with('!') {
            return Err(problem(format!(
                "`{p}` is an exclusion; the list can only add paths"
            )));
        }
        GlobPattern::compile(p, false).map_err(|e| problem(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::policy::{Policy, PolicyError};

    #[test]
    fn protected_writes_must_be_plain_globs() {
        let ok = "version: 1\ntaint:\n  protected_writes: ['**/deploy/**', '${project}/run.sh']\n";
        assert_eq!(
            Policy::parse(ok)
                .unwrap()
                .taint
                .unwrap()
                .protected_writes
                .len(),
            2
        );
        assert!(Policy::parse("version: 1\ntaint: {}\n").is_ok());
        for bad in ["'**/[x'", "'!**/package.json'", "''"] {
            let yaml = format!("version: 1\ntaint:\n  protected_writes: [{bad}]\n");
            assert!(
                matches!(Policy::parse(&yaml), Err(PolicyError::Rule { rule, .. }) if rule == "taint.protected_writes"),
                "{bad} must be rejected"
            );
        }
        assert!(Policy::parse("version: 1\ntaint: { bogus: [] }\n").is_err());
    }
}
