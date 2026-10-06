//! `moat run` where moat cannot generate a Lightweight sandbox: refused, never
//! run unconfined.

use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Result, bail};
use openmoat_core::{EvalContext, Policy};

use crate::sandbox::{Grants, Report};

/// Never constructed.
pub enum Confined {}

pub fn confine(_: &Policy, _: &EvalContext, _: Grants, _: &Path) -> Result<Confined> {
    bail!(
        "`moat run` needs an operating-system sandbox moat can generate (Seatbelt on macOS, \
         Landlock on Linux); there is none on {}. Use the Standard tier: `moat init` \
         configures the agent's own sandbox",
        std::env::consts::OS
    )
}

impl Confined {
    pub fn command(&mut self) -> &mut Command {
        match *self {}
    }

    pub fn report(&self) -> &Report {
        match *self {}
    }

    pub fn status(self) -> Result<ExitStatus> {
        match self {}
    }
}
