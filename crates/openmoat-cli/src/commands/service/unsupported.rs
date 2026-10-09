//! Platforms without a `moat proxy` service story yet. Windows is here:
//! Standard-tier proxy routing is not planned for the first release (#272),
//! so `moat proxy install` on Windows refuses with a clear message and the
//! user still has `moat proxy` to run the proxy in a terminal themselves.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{Manager, State};
use crate::home::{Home, user_home};

pub const DISPLAY: &str = "user service";

pub fn manager(_home: &Home) -> Result<Box<dyn Manager>> {
    // Resolve the user's home so the Windows branch mirrors the macOS/Linux
    // ones: no home means no story, surfaced as the error there instead of
    // later from inside a `Manager` call.
    let _ = user_home()?;
    Ok(Box::new(Unsupported))
}

struct Unsupported;

impl Manager for Unsupported {
    fn file_path(&self) -> Result<PathBuf> {
        Ok(PathBuf::new())
    }

    fn install(&self, _binary: &Path, _moat_home: &Path) -> Result<PathBuf> {
        bail!(
            "`moat proxy install` is not supported on {} yet (#272 defers Standard-tier \
             proxy routing on Windows); run `moat proxy` in a terminal to keep the proxy up",
            std::env::consts::OS
        )
    }

    fn uninstall(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }

    fn state(&self) -> Result<State> {
        Ok(State::Unknown {
            details: format!(
                "no user-service story on {} yet (#272)",
                std::env::consts::OS
            ),
        })
    }

    fn restart(&self) -> Result<()> {
        Ok(())
    }
}
