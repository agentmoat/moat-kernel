//! `moat run` where moat cannot generate a Lightweight sandbox yet: refused,
//! never run unconfined.

use std::process::Command;

use anyhow::{Result, bail};
use moat_core::{EvalContext, Policy};

use crate::sandbox::{Grants, Report};

pub fn confine(_: &Policy, _: &EvalContext, _: Grants) -> Result<(Command, Report)> {
    bail!(
        "`moat run` needs an operating-system sandbox moat can generate (Seatbelt on macOS); \
         there is none on {} yet. Use the Standard tier: `moat init` configures the agent's \
         own sandbox",
        std::env::consts::OS
    )
}
