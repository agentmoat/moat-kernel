//! Whether a person is at the keyboard.
//!
//! `moat allow` and `moat doctor --accept` widen or re-pin the policy, so they
//! refuse to run unless stdin is a terminal: hooks and scripts never have one.

use std::io::IsTerminal as _;

/// Debug builds honour `MOAT_ASSUME_TTY=1` so end-to-end tests can drive the
/// terminal-only commands. Release builds (`cargo install`, distributed
/// binaries) do not contain this check at all.
#[cfg(debug_assertions)]
const ASSUME_TTY: &str = "MOAT_ASSUME_TTY";

pub fn interactive() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os(ASSUME_TTY).is_some_and(|v| v == "1") {
        eprintln!("moat: {ASSUME_TTY}=1 honoured (debug build only)");
        return true;
    }
    std::io::stdin().is_terminal()
}
