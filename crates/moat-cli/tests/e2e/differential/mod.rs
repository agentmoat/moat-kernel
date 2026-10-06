//! Differential fixtures (ADR-019, issue #170): one scenario suite run against
//! every enforcement point available on the machine. Each layer must give the
//! verdict recorded in `tests/differential/scenarios.yaml`; a disagreement
//! fails the suite.
//!
//! This module is the backbone and the always-on layer, the hook decision
//! (`moat guard` on a host payload). The executing host-sandbox layers are
//! stacked on top: `codex sandbox -P moat` (#170) and a fake-API `claude -p`.
//! Where a host binary is missing the layer prints a visible skip and the suite
//! still passes on the layers it can run.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::common::{Sandbox, bash_payload, hook_output, json};

/// A layer's verdict. Sandboxes express only `Allow` (ran) and `Deny` (blocked);
/// `Ask` is a hook outcome (the host prompts the person).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    fn symbol(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask ",
            Self::Deny => "deny",
        }
    }
}

/// Which fixture tree the command runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Project {
    /// A clean project whose scripts do ordinary work.
    #[default]
    Benign,
    /// A project whose `test`/`build.rs` scripts carry the attack payload.
    Evil,
}

/// One row of the matrix.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Unique across the file; also the audit session id.
    pub id: String,
    /// `T1…T12` for attacks; absent for benign scenarios.
    #[serde(default)]
    pub threat: Option<String>,
    /// A public advisory this scenario replays, by id.
    #[serde(default)]
    pub cite: Option<String>,
    /// Why the recorded verdicts are what they are.
    pub why: String,
    /// The command every layer runs; the hook classifies the same string.
    pub command: String,
    /// The fixture tree it runs in.
    #[serde(default)]
    pub project: Project,
    /// The expected hook decision.
    pub hook: Verdict,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    attacks: Vec<Scenario>,
    benign: Vec<Scenario>,
}

/// The scenario file, attacks first.
pub fn scenarios() -> Vec<Scenario> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/scenarios.yaml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let suite: Suite = serde_yaml_ng::from_str(&text).expect("scenarios.yaml");
    let mut all = suite.attacks;
    for mut benign in suite.benign {
        assert!(
            benign.threat.is_none(),
            "{}: benign carries a threat",
            benign.id
        );
        benign.threat = None;
        all.push(benign);
    }
    all
}

impl Scenario {
    /// Whether this is an attack (carries a threat) or a benign scenario.
    pub fn is_attack(&self) -> bool {
        self.threat.is_some()
    }
}

/// The two fixture trees (a git project and a malicious one) and the home
/// files the scenarios read, inside a freshly `moat init`-ed home.
pub struct Fixtures {
    pub sb: Sandbox,
    pub benign: PathBuf,
    pub evil: PathBuf,
}

impl Fixtures {
    /// Build an installed home with both fixture trees and the secret files the
    /// attacks target.
    pub fn build() -> Self {
        let sb = Sandbox::installed(&[".claude", ".codex"]);
        let w = |p: &Path, name: &str, body: &str| std::fs::write(p.join(name), body).unwrap();

        std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
        w(&sb.home.join(".ssh"), "id_rsa", "FAKE-PRIVATE-KEY");
        std::fs::create_dir_all(sb.home.join(".aws")).unwrap();
        w(&sb.home.join(".aws"), "credentials", "[default]\nkey=FAKE");
        std::fs::create_dir_all(sb.home.join(".cargo")).unwrap();
        w(&sb.home.join(".cargo"), "config.toml", "[build]\n");
        w(&sb.home, ".zshrc", "# rc\n");
        w(&sb.home, ".zshenv", "# env\n");

        let benign = Self::project(&sb, "proj", false);
        let evil = Self::project(&sb, "evil", true);
        Self { sb, benign, evil }
    }

    /// A git-initialised project. With `malicious`, its `npm test` and `build.rs`
    /// read `~/.ssh/id_rsa` and write above the project.
    fn project(sb: &Sandbox, name: &str, malicious: bool) -> PathBuf {
        let root = sb.home.join(name);
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let w = |name: &str, body: &str| std::fs::write(root.join(name), body).unwrap();
        w("src/main.rs", "fn main() {}\n");
        w(".env", "TOKEN=secret\n");
        w(".env.example", "TOKEN=\n");
        let test = if malicious {
            "cat ~/.ssh/id_rsa > ../stolen.txt"
        } else {
            "echo ok"
        };
        w(
            "package.json",
            &format!("{{\"scripts\":{{\"test\":\"{test}\"}}}}\n"),
        );
        let build = if malicious {
            "fn main() { let _ = std::fs::read(concat!(env!(\"HOME\"), \"/.ssh/id_rsa\")); }\n"
        } else {
            "fn main() {}\n"
        };
        w("build.rs", build);
        w(
            "Cargo.toml",
            "[package]\nname = \"p\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        );
        root
    }

    fn tree(&self, project: Project) -> &Path {
        match project {
            Project::Benign => &self.benign,
            Project::Evil => &self.evil,
        }
    }

    /// The hook decision for `scenario`: `moat guard` on a Claude Code Bash
    /// payload, mapped from `permissionDecision`.
    pub fn hook_verdict(&self, scenario: &Scenario) -> Verdict {
        let cwd = self.tree(scenario.project);
        let payload = bash_payload(&scenario.id, cwd, &scenario.command);
        let out = self.sb.guard("claude-code", &payload);
        let decision = hook_output(&out)["permissionDecision"].clone();
        match decision.as_str() {
            Some("allow") => Verdict::Allow,
            Some("ask") => Verdict::Ask,
            Some("deny") => Verdict::Deny,
            _ => panic!("{}: no permissionDecision in {}", scenario.id, json(&out)),
        }
    }
}

#[test]
fn scenario_file_is_well_formed() {
    let all = scenarios();
    let mut ids = std::collections::BTreeSet::new();
    for s in &all {
        assert!(ids.insert(s.id.clone()), "duplicate id {}", s.id);
        assert!(!s.why.trim().is_empty(), "{}: empty why", s.id);
        if let Some(threat) = &s.threat {
            let n: u8 = threat
                .strip_prefix('T')
                .and_then(|d| d.parse().ok())
                .unwrap_or(0);
            assert!(
                (1..=12).contains(&n),
                "{}: threat {threat} not T1..T12",
                s.id
            );
        }
    }
    assert!(all.iter().any(|s| s.cite.is_some()), "no CVE replays");
}

#[test]
fn hook_layer_agrees_with_every_scenario() {
    let fx = Fixtures::build();
    let all = scenarios();
    let mut matrix = String::from("\ndifferential matrix (scenario x layer):\n");
    let mut mismatches = Vec::new();
    for s in &all {
        let got = fx.hook_verdict(s);
        let kind = if s.is_attack() { "attack" } else { "benign" };
        let _ = writeln!(matrix, "  {kind} {:<28} hook={}", s.id, got.symbol());
        if got != s.hook {
            mismatches.push(format!(
                "{}: hook gave {} but scenarios.yaml expects {}",
                s.id,
                got.symbol().trim(),
                s.hook.symbol().trim()
            ));
        }
    }
    eprintln!("{matrix}");
    assert!(
        mismatches.is_empty(),
        "disagreements:\n{}",
        mismatches.join("\n")
    );
}
