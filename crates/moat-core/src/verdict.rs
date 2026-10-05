use serde::{Deserialize, Serialize};

/// Outcome of evaluating one or more atomic actions.
///
/// Ordering is by strictness: `Allow < Ask < Deny`. When several atomic
/// actions are combined, the strictest wins (DESIGN.md §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

/// A verdict with the rule ids and human-readable reasons that produced it.
///
/// `rules`/`reasons` describe only the matches that carry the **final** verdict.
/// Matches with a weaker verdict (e.g. an `allow` on `git status` inside a command
/// that was denied for touching `~/.ssh`) are kept in `context` so the user still
/// sees the full picture without the headline being noisy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    /// Ids of the rule groups that produced `verdict`, in evaluation order, de-duplicated.
    pub rules: Vec<String>,
    /// One line per rule in `rules`.
    pub reasons: Vec<String>,
    /// Matches that did not determine the verdict (weaker outcomes), for display/audit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
}

impl Decision {
    #[must_use]
    pub fn new(verdict: Verdict) -> Self {
        Self {
            verdict,
            rules: Vec::new(),
            reasons: Vec::new(),
            context: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, rule: &str, reason: String) {
        if !self.rules.iter().any(|r| r == rule) {
            self.rules.push(rule.to_owned());
        }
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    /// Merge another decision in: strictest verdict wins; matches of the losing
    /// side are demoted to `context`.
    pub(crate) fn merge(&mut self, other: Decision) {
        if other.verdict > self.verdict {
            let demoted: Vec<String> = self.reasons.drain(..).collect();
            self.rules.clear();
            self.context.extend(demoted);
            self.verdict = other.verdict;
        } else if other.verdict < self.verdict {
            self.context.extend(other.reasons);
            self.context.extend(other.context);
            return;
        }
        for (r, why) in other.rules.into_iter().zip(other.reasons) {
            self.push(&r, why);
        }
        self.context.extend(other.context);
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, Verdict};

    fn decided(verdict: Verdict, rule: &str) -> Decision {
        let mut d = Decision::new(verdict);
        d.push(rule, format!("because {rule}"));
        d
    }

    #[test]
    fn stricter_verdict_replaces_and_demotes_the_weaker_match() {
        let mut d = decided(Verdict::Allow, "project-fs");
        d.merge(decided(Verdict::Deny, "secrets-paths"));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, ["secrets-paths"]);
        assert_eq!(d.reasons, ["because secrets-paths"]);
        assert_eq!(d.context, ["because project-fs"]);
    }

    #[test]
    fn weaker_verdict_only_adds_context() {
        let mut d = decided(Verdict::Deny, "secrets-paths");
        d.merge(decided(Verdict::Allow, "dev-shell"));
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rules, ["secrets-paths"]);
        assert_eq!(d.context, ["because dev-shell"]);
    }

    #[test]
    fn equal_verdicts_union_rules_without_duplicates() {
        let mut d = decided(Verdict::Ask, "installs");
        d.merge(decided(Verdict::Ask, "installs"));
        d.merge(decided(Verdict::Ask, "push"));
        assert_eq!(d.rules, ["installs", "push"]);
        assert_eq!(d.reasons.len(), 2);
        assert!(d.context.is_empty());
    }

    #[test]
    fn verdict_order_is_allow_ask_deny() {
        assert!(Verdict::Allow < Verdict::Ask && Verdict::Ask < Verdict::Deny);
    }
}
