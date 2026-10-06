//! The `MoatBench` scorecard: verdicts per category, false positives, known gaps
//! and mismatches.

use std::collections::BTreeMap;
use std::fmt;

use super::Verdict;

/// The category whose scenarios must stay allowed; anything stricter there is
/// a false positive.
const BENIGN: &str = "benign";

/// One scenario on one host.
pub struct Run {
    /// The strictest kernel verdict across its steps.
    pub strictest: Verdict,
    pub outcome: Outcome,
}

pub enum Outcome {
    Pass,
    /// A mismatch tracked by an issue.
    Gap(String, Vec<String>),
    Fail(Vec<String>),
}

#[derive(Default)]
struct Row {
    runs: usize,
    by_verdict: [usize; 3],
}

#[derive(Default)]
pub struct Scorecard {
    rows: BTreeMap<String, Row>,
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
        let name = format!("{id} ({host})");
        if category == BENIGN && run.strictest != Verdict::Allow {
            self.false_positives
                .push(format!("{name}: {:?}", run.strictest));
        }
        match run.outcome {
            Outcome::Pass => {}
            Outcome::Gap(issue, problems) => {
                self.gap_seen.insert(id.to_owned(), (issue.clone(), true));
                self.gaps
                    .push(format!("{name} {issue}: {}", problems.join("; ")));
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
