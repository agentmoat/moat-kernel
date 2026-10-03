//! Human approvals that outlive one prompt.
//!
//! Two files under `~/.moat`, both pinned by the policy lock so an agent cannot
//! grant itself anything:
//! - `approvals.json`: session grants, exact command for one host session;
//! - `policy.d/approved.yaml`: permanent allow rules appended by `moat allow --always`,
//!   merged into the user policy at load time so `policy.yaml` is never rewritten.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use moat_core::RuleGroup;
use serde::{Deserialize, Serialize};

use crate::home::write_private;

const GRANTS_VERSION: u32 = 1;
const OVERLAY_VERSION: u32 = 1;
pub const OVERLAY_PREFIX: &str = "approved-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub host: String,
    pub session_id: String,
    pub command: String,
    pub granted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grants {
    pub version: u32,
    pub entries: Vec<Grant>,
}

impl Default for Grants {
    fn default() -> Self {
        Self {
            version: GRANTS_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Grants {
    /// Missing file means no grants; a malformed or newer file is an error.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let grants: Self =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if grants.version != GRANTS_VERSION {
            bail!(
                "{} has version {}; this build supports {GRANTS_VERSION}",
                path.display(),
                grants.version
            );
        }
        Ok(grants)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(
            path,
            (serde_json::to_string_pretty(self)? + "\n").as_bytes(),
        )
    }

    /// Exact command match for this host session; no prefix or glob semantics.
    #[must_use]
    pub fn matches(&self, host: &str, session_id: &str, command: &str) -> bool {
        let command = command.trim();
        self.entries
            .iter()
            .any(|g| g.host == host && g.session_id == session_id && g.command == command)
    }
}

/// Allow rules appended by `moat allow --always`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overlay {
    pub version: u32,
    #[serde(default)]
    pub allow: Vec<RuleGroup>,
}

impl Default for Overlay {
    fn default() -> Self {
        Self {
            version: OVERLAY_VERSION,
            allow: Vec::new(),
        }
    }
}

impl Overlay {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let overlay: Self = serde_yaml_ng::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
        if overlay.version != OVERLAY_VERSION {
            bail!(
                "{} has version {}; this build supports {OVERLAY_VERSION}",
                path.display(),
                overlay.version
            );
        }
        if let Some(bad) = overlay
            .allow
            .iter()
            .find(|g| !g.id.starts_with(OVERLAY_PREFIX))
        {
            bail!(
                "{}: rule `{}` must have an id starting with `{OVERLAY_PREFIX}`",
                path.display(),
                bad.id
            );
        }
        Ok(overlay)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = format!(
            "# Permanent allow rules added with `moat allow --always`. Edit or delete freely,\n\
             # then run `moat doctor --accept`.\n{}",
            serde_yaml_ng::to_string(self)?
        );
        write_private(path, text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(host: &str, session: &str, command: &str) -> Grant {
        Grant {
            host: host.to_owned(),
            session_id: session.to_owned(),
            command: command.to_owned(),
            granted_at_ms: 0,
        }
    }

    #[test]
    fn grants_match_exactly_per_host_session() {
        let g = Grants {
            entries: vec![grant("claude-code", "s1", "npm install left-pad")],
            ..Grants::default()
        };
        assert!(g.matches("claude-code", "s1", " npm install left-pad "));
        assert!(!g.matches("claude-code", "s2", "npm install left-pad"));
        assert!(!g.matches("cursor", "s1", "npm install left-pad"));
        assert!(!g.matches("claude-code", "s1", "npm install left-pad --save"));
    }

    #[test]
    fn grants_and_overlay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let grants_path = dir.path().join("approvals.json");
        let g = Grants {
            entries: vec![grant("codex", "k1", "cargo add serde")],
            ..Grants::default()
        };
        g.save(&grants_path).unwrap();
        assert_eq!(Grants::load(&grants_path).unwrap(), g);
        assert_eq!(
            Grants::load(&dir.path().join("missing.json")).unwrap(),
            Grants::default()
        );

        let overlay_path = dir.path().join("approved.yaml");
        let o = Overlay {
            allow: vec![RuleGroup {
                id: "approved-1".into(),
                reason: Some("test".into()),
                shell: vec!["pip install requests".into()],
                ..RuleGroup::default()
            }],
            ..Overlay::default()
        };
        o.save(&overlay_path).unwrap();
        assert_eq!(Overlay::load(&overlay_path).unwrap(), o);

        fs::write(
            &overlay_path,
            "version: 1\nallow:\n  - id: sneaky\n    shell: ['*']\n",
        )
        .unwrap();
        assert!(
            Overlay::load(&overlay_path)
                .unwrap_err()
                .to_string()
                .contains("approved-")
        );
    }
}
