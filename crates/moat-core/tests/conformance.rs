//! Conformance suite: every fixture in `tests/conformance/*.yaml` is evaluated
//! against `policies/default-v1.yaml`. A fixture passes when the verdict matches
//! and every expected rule id is present in the decision.
//!
//! The suite is the executable form of the security claims in DESIGN.md §3.3,
//! so it is strict about its own inputs: unknown keys, duplicate ids and
//! fixtures with zero or several actions are rejected.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use moat_core::{
    Action, CompiledPolicy, EvalContext, MapPathResolver, MapResolver, Policy, Verdict,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    action: FixtureAction,
    expect: Expect,
    /// Program name → path it resolves to on the kernel search path.
    #[serde(default)]
    resolve: BTreeMap<String, String>,
    /// Program name → path recorded at install time.
    #[serde(default)]
    pins: BTreeMap<String, String>,
    /// Symlink path → target, as the filesystem would resolve it.
    #[serde(default)]
    links: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureAction {
    shell: Option<String>,
    fs_read: Option<String>,
    fs_write: Option<String>,
    net: Option<String>,
    mcp_tool: Option<McpFixture>,
    /// Files a multi-file patch writes (Codex `apply_patch`).
    patch: Option<Vec<String>>,
}

/// `mcp_tool: "name"` or `mcp_tool: { name, reads, writes, hosts }`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum McpFixture {
    Name(String),
    Call {
        name: String,
        #[serde(default)]
        reads: Vec<String>,
        #[serde(default)]
        writes: Vec<String>,
        #[serde(default)]
        hosts: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    verdict: Verdict,
    #[serde(default)]
    rules: Vec<String>,
}

impl FixtureAction {
    fn into_action(self, id: &str) -> Action {
        let candidates = [
            self.shell.map(|command| Action::Shell { command }),
            self.fs_read.map(|path| Action::FsRead { path }),
            self.fs_write.map(|path| Action::FsWrite { path }),
            self.net.map(|url| Action::Net { url }),
            self.patch.map(|writes| Action::Patch { writes }),
            self.mcp_tool.map(|m| match m {
                McpFixture::Name(name) => Action::mcp(name),
                McpFixture::Call {
                    name,
                    reads,
                    writes,
                    hosts,
                } => Action::McpTool {
                    name,
                    reads,
                    writes,
                    hosts,
                },
            }),
        ];
        let mut present: Vec<Action> = candidates.into_iter().flatten().collect();
        assert_eq!(
            present.len(),
            1,
            "fixture `{id}` must declare exactly one action"
        );
        present.remove(0)
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_fixtures(dir: &Path) -> Vec<(String, Fixture)> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no fixture files in {}", dir.display());

    let mut seen = BTreeSet::new();
    let mut fixtures = Vec::new();
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&file).unwrap();
        let parsed: Vec<Fixture> =
            serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        for fixture in parsed {
            assert!(
                seen.insert(fixture.id.clone()),
                "duplicate fixture id `{}`",
                fixture.id
            );
            fixtures.push((name.clone(), fixture));
        }
    }
    fixtures
}

#[test]
fn default_policy_conformance() {
    let root = repo_root();
    let policy_text = fs::read_to_string(root.join("policies/default-v1.yaml")).unwrap();
    let policy = Policy::parse(&policy_text).expect("default policy must lint");
    let ctx = EvalContext {
        home: "/Users/me".into(),
        project: "/p".into(),
        cwd: "/p".into(),
    };

    let compiled = CompiledPolicy::compile(&policy, &ctx).expect("default policy must compile");

    let fixtures = load_fixtures(&root.join("tests/conformance"));
    let total = fixtures.len();
    let mut report = String::new();
    let mut failed = 0usize;

    for (file, fixture) in fixtures {
        let action = fixture.action.into_action(&fixture.id);
        let resolver = MapResolver {
            resolved: fixture.resolve.clone(),
            pins: fixture.pins.clone(),
        };
        let links = MapPathResolver {
            links: fixture.links.clone(),
        };
        let decision = compiled.decide_with(&action, &resolver, &links);
        let missing: Vec<&String> = fixture
            .expect
            .rules
            .iter()
            .filter(|rule| !decision.rules.contains(rule))
            .collect();
        if decision.verdict != fixture.expect.verdict || !missing.is_empty() {
            failed += 1;
            let _ = writeln!(
                report,
                "  {file}/{id}: expected {expected:?} {rules:?}, got {got:?} {got_rules:?}\n    reasons: {reasons}",
                id = fixture.id,
                expected = fixture.expect.verdict,
                rules = fixture.expect.rules,
                got = decision.verdict,
                got_rules = decision.rules,
                reasons = decision.reasons.join(" | "),
            );
        }
    }

    assert!(
        failed == 0,
        "{failed} of {total} conformance fixtures failed:\n{report}"
    );
}
