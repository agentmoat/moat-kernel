//! `MoatBench` mini: end-to-end attack and benign scenarios run through the real
//! `moat guard` of every host whose payload shape can express them
//! (`docs/MOATBENCH.md`). The kernel verdict of each step is read back from the
//! audit log, and the host's response must carry that verdict in the host's own
//! format. A scorecard is printed; any mismatch fails the test.
//!
//! `cargo test -p openmoat --test e2e moatbench -- --nocapture` shows the
//! scorecard of a passing run.

mod hosts;
mod score;

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::common::{Sandbox, json, stderr};
use hosts::{Host, Place};
use score::{Outcome, Run, Scorecard};

/// One scenario of `tests/moatbench/<category>.yaml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    id: String,
    /// `T1`…`T12` from `docs/THREAT_MODEL.md` §3; benign scenarios name the
    /// threat whose rules they must not trip.
    threat: String,
    /// What the agent was steered into doing, and why the verdict is right.
    why: String,
    /// A tracked bypass or false positive (`"#123"`): `expect` is the secure
    /// verdict, and a mismatch is reported as a known gap instead of failing.
    #[serde(default)]
    gap: Option<String>,
    steps: Vec<Step>,
}

/// One tool call: exactly one of `shell`, `read`, `write`, `edit`, `fetch`, `mcp`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    shell: Option<String>,
    read: Option<String>,
    write: Option<String>,
    edit: Option<String>,
    fetch: Option<String>,
    mcp: Option<Mcp>,
    expect: Verdict,
    /// A rule id that must be in the decision.
    #[serde(default)]
    rule: Option<String>,
    /// The scenario-level `gap` for one step, so the other steps still count.
    #[serde(default)]
    gap: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mcp {
    server: String,
    tool: String,
    #[serde(default)]
    args: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    fn word(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

/// A tool call, independent of the host that makes it.
pub enum Call {
    Shell(String),
    Read(String),
    Write(String),
    Edit(String),
    Fetch(String),
    Mcp {
        server: String,
        tool: String,
        args: Value,
    },
}

impl Step {
    fn call(&self) -> Call {
        let mut calls = [
            self.shell.clone().map(Call::Shell),
            self.read.clone().map(Call::Read),
            self.write.clone().map(Call::Write),
            self.edit.clone().map(Call::Edit),
            self.fetch.clone().map(Call::Fetch),
            self.mcp.as_ref().map(|m| Call::Mcp {
                server: m.server.clone(),
                tool: m.tool.clone(),
                args: m.args.clone(),
            }),
        ]
        .into_iter()
        .flatten();
        let call = calls.next().expect("a step names one tool call");
        assert!(calls.next().is_none(), "a step names one tool call");
        call
    }
}

fn scenarios() -> Vec<(String, Scenario)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/moatbench");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();
    let mut ids = BTreeSet::new();
    let mut all = Vec::new();
    for file in files {
        let category = file.file_stem().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&file).unwrap();
        let list: Vec<Scenario> =
            serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        for s in list {
            assert!(ids.insert(s.id.clone()), "duplicate scenario id {}", s.id);
            assert!(
                s.threat
                    .strip_prefix('T')
                    .and_then(|n| n.parse::<u8>().ok())
                    .is_some_and(|n| (1..=12).contains(&n)),
                "{}: threat must be T1…T12",
                s.id
            );
            assert!(
                !s.why.trim().is_empty() && !s.steps.is_empty(),
                "{}: why and steps",
                s.id
            );
            assert!(
                s.gap.is_none() || s.steps.iter().all(|step| step.gap.is_none()),
                "{}: a gap on the scenario or on its steps, not both",
                s.id
            );
            all.push((category.clone(), s));
        }
    }
    all
}

/// Run `scenario` on `host` and compare every step with its expectation.
fn run(sb: &Sandbox, project: &Path, scenario: &Scenario, host: Host) -> Option<Run> {
    let session = format!("{}@{}", scenario.id, host.id());
    let payloads = scenario
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let call_id = format!("{session}#{i}");
            let at = Place {
                home: &sb.home,
                project,
                session: &session,
                call_id: &call_id,
            };
            host.payload(&step.call(), &at)
        })
        .collect::<Option<Vec<_>>>()?;
    let answers: Vec<_> = payloads
        .iter()
        .map(|payload| {
            let out = sb.guard(host.id(), payload);
            (out.status.code(), host.decision(&out), stderr(&out))
        })
        .collect();
    let recorded = recorded(sb, &session);
    assert_eq!(
        recorded.len(),
        payloads.len(),
        "{session}: one audit event per step"
    );
    let mut problems = Vec::new();
    let mut known = Vec::new();
    for (i, ((step, (verdict, rules)), (code, decision, err))) in scenario
        .steps
        .iter()
        .zip(&recorded)
        .zip(&answers)
        .enumerate()
    {
        let answer = host.answer(&step.call(), *verdict);
        let expected_code = if answer == Verdict::Deny { 2 } else { 0 };
        assert!(
            *code == Some(expected_code) && *decision == answer.word(),
            "{session} step {i}: kernel said {verdict:?}, host got {decision} exit {code:?}: {err}"
        );
        match (&step.gap, *verdict == step.expect) {
            (Some(issue), false) => known.push(format!(
                "step {i} {issue}: expected {:?}, got {verdict:?} {rules:?}",
                step.expect
            )),
            (Some(issue), true) => problems.push(format!(
                "step {i}: marked as gap {issue} but passes; remove the marker"
            )),
            (None, false) => problems.push(format!(
                "step {i}: expected {:?}, got {verdict:?} {rules:?}",
                step.expect
            )),
            (None, true) => {
                if let Some(rule) = step.rule.as_ref().filter(|r| !rules.contains(r)) {
                    problems.push(format!(
                        "step {i}: {verdict:?} without rule {rule} ({rules:?})"
                    ));
                }
            }
        }
    }
    Some(Run {
        strictest: recorded
            .iter()
            .map(|(v, _)| *v)
            .max()
            .unwrap_or(Verdict::Allow),
        steps: scenario
            .steps
            .iter()
            .zip(&recorded)
            .map(|(step, (verdict, _))| (*verdict, step.expect, step.gap.is_some()))
            .collect(),
        outcome: match (&scenario.gap, problems.is_empty()) {
            (_, true) if known.is_empty() => Outcome::Pass,
            (_, true) => Outcome::Gap(known),
            (Some(issue), false) => Outcome::Gap(vec![format!("{issue}: {}", problems.join("; "))]),
            (None, false) => Outcome::Fail(problems),
        },
    })
}

/// The kernel verdict and rules of each event of `session`, oldest first.
fn recorded(sb: &Sandbox, session: &str) -> Vec<(Verdict, Vec<String>)> {
    let out = sb.moat(&["show", "--session", session, "--format", "json"]);
    let events = json(&out).as_array().cloned().unwrap_or_default();
    events
        .iter()
        .map(|e| {
            let verdict = serde_json::from_value(e["verdict"].clone()).expect("verdict");
            let rules = serde_json::from_value(e["rules"].clone()).unwrap_or_default();
            (verdict, rules)
        })
        .collect()
}

#[test]
fn moatbench_mini() {
    let sb = Sandbox::installed(&[".claude", ".codex", ".cursor"]);
    let project = sb.project();
    let mut card = Scorecard::default();
    for (category, scenario) in scenarios() {
        if let Some(issue) = &scenario.gap {
            card.note_gap(&scenario.id, issue);
        }
        let mut ran = 0;
        for host in Host::ALL {
            if let Some(result) = run(&sb, &project, &scenario, host) {
                card.add(&category, &scenario.id, host.id(), result);
                ran += 1;
            }
        }
        assert!(ran > 0, "{}: no host can run it", scenario.id);
    }
    card.check_gaps();
    println!("{card}");
    assert!(card.passed(), "MoatBench mismatches:\n{card}");
}
