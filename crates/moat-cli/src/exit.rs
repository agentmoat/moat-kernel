//! Process exit codes (DESIGN.md §10.3). Hosts depend on these values.

use std::process::ExitCode;

use moat_core::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Success, or verdict `allow`.
    Ok = 0,
    /// Verdict `deny`. Claude Code and Codex treat exit 2 as a blocking hook result.
    Deny = 2,
    /// Verdict `ask` that was not resolved; adapters treat it as deny.
    Ask = 3,
    /// Usage or configuration error. Adapters fail closed on any value ≥ 64.
    Usage = 64,
}

impl From<Verdict> for Code {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Ok,
            Verdict::Ask => Self::Ask,
            Verdict::Deny => Self::Deny,
        }
    }
}

impl From<Code> for ExitCode {
    fn from(code: Code) -> Self {
        Self::from(code as u8)
    }
}
