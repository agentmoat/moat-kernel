//! Human approvals that outlive one prompt.
//!
//! Two files under `~/.moat`, both pinned by the policy lock so an agent cannot
//! grant itself anything:
//! - `approvals.json`: session grants, exact command for one host session;
//! - `policy.d/approved.yaml`: permanent allow rules appended by `moat allow --always`,
//!   merged into the user policy at load time so `policy.yaml` is never rewritten.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use moat_core::{RuleGroup, lexer};
use serde::{Deserialize, Serialize};

use crate::home::write_private;
use crate::time;

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

    pub fn grant(&mut self, host: &str, session_id: &str, command: &str) {
        let command = command.trim();
        if self.matches(host, session_id, command) {
            return;
        }
        self.entries.push(Grant {
            host: host.to_owned(),
            session_id: session_id.to_owned(),
            command: command.to_owned(),
            granted_at_ms: time::now_ms(),
        });
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

    /// Append an allow rule for one shell command, matched literally: glob
    /// characters in the command are not wildcards in the rule. Shell rules are
    /// prefixes, so extra arguments after the approved command are accepted.
    pub fn allow_command(&mut self, command: &str) -> Result<&RuleGroup> {
        let pattern = literal_pattern(command)?;
        // One past the highest existing number: ids stay unique after a person
        // deletes an earlier rule, and a duplicate id would fail the policy lint.
        let n = self
            .allow
            .iter()
            .filter_map(|g| g.id.strip_prefix(OVERLAY_PREFIX)?.parse::<u64>().ok())
            .max()
            .unwrap_or(0)
            + 1;
        self.allow.push(RuleGroup {
            id: format!("{OVERLAY_PREFIX}{n}"),
            reason: Some(format!(
                "approved with `moat allow --always` on {}",
                time::timestamp(time::now_ms())
            )),
            shell: vec![pattern],
            ..RuleGroup::default()
        });
        Ok(&self.allow[self.allow.len() - 1])
    }
}

/// A shell pattern that matches `command` token for token and nothing wider.
///
/// Glob characters and `$` are put in one-character classes (`*` → `[*]`), so
/// `cat *` approves `cat *`, not `cat anything`, and a trailing `$` is not an
/// end anchor. Words that the pattern lexer would split or reinterpret
/// (whitespace, quotes, operators, a leading `!` exclusion) are single-quoted.
/// Operators (`|`, `&&`, …) stay operators.
fn literal_pattern(command: &str) -> Result<String> {
    let tokens = lexer::lex(command.trim())
        .with_context(|| format!("cannot approve `{command}`: it does not parse"))?;
    ensure!(!tokens.is_empty(), "cannot approve an empty command");
    let mut parts = Vec::with_capacity(tokens.len());
    for token in tokens {
        match token {
            lexer::Token::Word(w) => parts.push(literal_word(&w.text)),
            lexer::Token::Operator(op) => parts.push(op.symbol().to_owned()),
            lexer::Token::HereDoc { .. } => bail!("cannot approve a command with a here-document"),
        }
    }
    Ok(parts.join(" "))
}

fn literal_word(text: &str) -> String {
    let escaped: String = text
        .chars()
        .map(|c| match c {
            '*' | '?' | '[' | ']' | '{' | '}' | '$' => format!("[{c}]"),
            c => c.to_string(),
        })
        .collect();
    let needs_quotes = escaped.is_empty()
        || escaped.starts_with('!')
        || escaped
            .chars()
            .any(|c| c.is_whitespace() || "'\"\\|&;<>()`#".contains(c));
    if needs_quotes {
        format!("'{}'", escaped.replace('\'', "'\\''"))
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use moat_core::pattern::ShellPattern;

    use super::*;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn approved_commands_match_literally() {
        let p = |c: &str| ShellPattern::compile(&literal_pattern(c).unwrap()).unwrap();
        let cat = p("cat *");
        assert!(cat.is_match(&argv(&["cat", "*"])));
        assert!(
            !cat.is_match(&argv(&["cat", "~/.ssh/id_rsa"])),
            "`*` is not a wildcard"
        );
        let q = p("ls file?.[ch] {a,b}");
        assert!(q.is_match(&argv(&["ls", "file?.[ch]", "{a,b}"])));
        assert!(!q.is_match(&argv(&["ls", "file1.c", "a"])));
        let bang = p("!echo hi $");
        assert!(!bang.negated, "a leading `!` stays literal");
        assert!(
            bang.is_match(&argv(&["!echo", "hi", "$", "more"])),
            "`$` is not an anchor"
        );
        let quoted = p("echo \"it's\"");
        assert!(quoted.is_match(&argv(&["echo", "it's"])));
        assert_eq!(literal_pattern("cat *").unwrap(), "cat [*]");
        let piped = p("npm test | tee out.log");
        assert!(piped.is_match(&argv(&["npm", "test", "|", "tee", "out.log"])));
        assert!(literal_pattern("echo 'unterminated").is_err());
        assert!(literal_pattern("   ").is_err());
    }

    #[test]
    fn overlay_ids_stay_unique_after_a_deletion() {
        let mut o = Overlay::default();
        for c in ["a", "b", "c"] {
            o.allow_command(c).unwrap();
        }
        o.allow.remove(0);
        assert_eq!(o.allow_command("d").unwrap().id, "approved-4");
        let ids: std::collections::BTreeSet<_> = o.allow.iter().map(|g| &g.id).collect();
        assert_eq!(ids.len(), o.allow.len());
    }

    #[test]
    fn grants_match_exactly_per_host_session() {
        let mut g = Grants::default();
        g.grant("claude-code", "s1", " npm install left-pad ");
        g.grant("claude-code", "s1", "npm install left-pad");
        assert_eq!(g.entries.len(), 1, "duplicates collapse");
        assert!(g.matches("claude-code", "s1", "npm install left-pad"));
        assert!(!g.matches("claude-code", "s2", "npm install left-pad"));
        assert!(!g.matches("cursor", "s1", "npm install left-pad"));
        assert!(!g.matches("claude-code", "s1", "npm install left-pad --save"));
    }

    #[test]
    fn grants_and_overlay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let grants_path = dir.path().join("approvals.json");
        let mut g = Grants::default();
        g.grant("codex", "k1", "cargo add serde");
        g.save(&grants_path).unwrap();
        assert_eq!(Grants::load(&grants_path).unwrap(), g);
        assert_eq!(
            Grants::load(&dir.path().join("missing.json")).unwrap(),
            Grants::default()
        );

        let overlay_path = dir.path().join("approved.yaml");
        let mut o = Overlay::default();
        assert_eq!(
            o.allow_command("npm install left-pad").unwrap().id,
            "approved-1"
        );
        assert_eq!(
            o.allow_command("pip install requests").unwrap().id,
            "approved-2"
        );
        o.save(&overlay_path).unwrap();
        let loaded = Overlay::load(&overlay_path).unwrap();
        assert_eq!(loaded.allow.len(), 2);
        assert_eq!(loaded.allow[1].shell, ["pip install requests"]);
        assert!(
            loaded.allow[0]
                .reason
                .as_deref()
                .unwrap()
                .contains("moat allow --always")
        );

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
