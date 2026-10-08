//! The `MoatBench` scorecard: verdicts per category, asks per developer workflow,
//! false positives, known gaps and mismatches.

use std::collections::BTreeMap;
use std::fmt;

use super::Verdict;

/// The category whose scenarios must stay allowed; anything stricter there is
/// a false positive.
const BENIGN: &str = "benign";

/// Everyday development step by step: each step is allowed unless it expects the
/// ask the policy intends (installs, push), and asks are counted per workflow.
const WORKFLOWS: &str = "workflows";

/// One scenario on one host.
pub struct Run {
    /// The strictest kernel verdict across its steps.
    pub strictest: Verdict,
    /// Each step's kernel verdict, its `expect`, and whether it carries a gap.
    pub steps: Vec<(Verdict, Verdict, bool)>,
    pub outcome: Outcome,
}

pub enum Outcome {
    Pass,
    /// Mismatches tracked by gap markers; each line names its marker.
    Gap(Vec<String>),
    Fail(Vec<String>),
}

#[derive(Default)]
struct Row {
    runs: usize,
    by_verdict: [usize; 3],
}

/// Step counts of one workflow across the hosts that ran it.
#[derive(Default, Clone, Copy)]
struct Tally {
    steps: usize,
    asks: usize,
    expected: usize,
    /// Verdicts that differ from `expect` without a gap marker: these fail the run.
    unexpected: usize,
    /// Verdicts that differ from `expect` under a gap marker.
    known: usize,
}

impl Tally {
    fn add(&mut self, steps: &[(Verdict, Verdict, bool)]) {
        for &(got, expect, gap) in steps {
            self.steps += 1;
            self.asks += usize::from(got == Verdict::Ask);
            self.expected += usize::from(expect == Verdict::Ask);
            self.unexpected += usize::from(got != expect && !gap);
            self.known += usize::from(got != expect && gap);
        }
    }

    fn total<'a>(all: impl Iterator<Item = &'a Self>) -> Self {
        all.fold(Self::default(), |t, a| Self {
            steps: t.steps + a.steps,
            asks: t.asks + a.asks,
            expected: t.expected + a.expected,
            unexpected: t.unexpected + a.unexpected,
            known: t.known + a.known,
        })
    }
}

impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} steps, {} asks (expected {}), {} unexpected, {} expected failures",
            self.steps, self.asks, self.expected, self.unexpected, self.known
        )
    }
}

#[derive(Default)]
pub struct Scorecard {
    rows: BTreeMap<String, Row>,
    workflows: BTreeMap<String, Tally>,
    false_positives: Vec<String>,
    gaps: Vec<String>,
    failures: Vec<String>,
    /// Scenario id → (gap issue, whether any run still shows it).
    gap_seen: BTreeMap<String, (String, bool)>,
}

impl Scorecard {
    pub fn add(&mut self, category: &str, id: &str, host: &str, run: Run) {
        let row = self.rows.entry(category.to_owned()).or_default();
        row.runs += 1;
        row.by_verdict[run.strictest as usize] += 1;
        if category == WORKFLOWS {
            self.workflows
                .entry(id.to_owned())
                .or_default()
                .add(&run.steps);
        }
        let name = format!("{id} ({host})");
        if category == BENIGN && run.strictest != Verdict::Allow {
            self.false_positives
                .push(format!("{name}: {:?}", run.strictest));
        }
        match run.outcome {
            Outcome::Pass => {}
            Outcome::Gap(lines) => {
                // Only a scenario-level marker is tracked here; a step marker that
                // passes is already a failure of its run.
                if let Some((_, seen)) = self.gap_seen.get_mut(id) {
                    *seen = true;
                }
                self.gaps.push(format!("{name} {}", lines.join("; ")));
            }
            Outcome::Fail(problems) => self
                .failures
                .push(format!("{name}: {}", problems.join("; "))),
        }
    }

    /// A gap marker on a scenario that now passes everywhere must be removed,
    /// so the marker never outlives its fix.
    pub fn note_gap(&mut self, id: &str, issue: &str) {
        self.gap_seen
            .entry(id.to_owned())
            .or_insert_with(|| (issue.to_owned(), false));
    }

    pub fn check_gaps(&mut self) {
        for (id, (issue, seen)) in &self.gap_seen {
            if !*seen {
                self.failures.push(format!(
                    "{id}: marked as gap {issue} but passes; remove the marker"
                ));
            }
        }
    }

    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

impl fmt::Display for Scorecard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "MoatBench mini")?;
        writeln!(
            f,
            "{:<16} {:>5} {:>8} {:>6} {:>8}",
            "category", "runs", "blocked", "asked", "allowed"
        )?;
        let mut total = Row::default();
        for (category, row) in &self.rows {
            let [allow, ask, deny] = row.by_verdict;
            writeln!(
                f,
                "{category:<16} {:>5} {deny:>8} {ask:>6} {allow:>8}",
                row.runs
            )?;
            total.runs += row.runs;
            for (t, n) in total.by_verdict.iter_mut().zip(row.by_verdict) {
                *t += n;
            }
        }
        let [allow, ask, deny] = total.by_verdict;
        writeln!(
            f,
            "{:<16} {:>5} {deny:>8} {ask:>6} {allow:>8}",
            "total", total.runs
        )?;
        writeln!(f, "workflows: {}", Tally::total(self.workflows.values()))?;
        for (id, asks) in &self.workflows {
            writeln!(f, "  {id:<24} {asks}")?;
        }
        for (title, list) in [
            ("false positives", &self.false_positives),
            ("known gaps", &self.gaps),
            ("mismatches", &self.failures),
        ] {
            writeln!(f, "{title}: {}", list.len())?;
            for line in list {
                writeln!(f, "  {line}")?;
            }
        }
        Ok(())
    }
}
