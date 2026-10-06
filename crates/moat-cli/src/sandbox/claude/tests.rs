use openmoat_core::{DEFAULT_POLICY, Policy};
use serde_json::{Value, json};

use super::*;
use crate::sandbox::{assert_golden, lower_for_hosts};

pub(super) fn generated(yaml: &str) -> Generated {
    let policy = Policy::parse(yaml).expect("test policy lints");
    generate(&lower_for_hosts(&policy, "/Users/me", None, false).expect("lowers"))
        .expect("generates")
}

fn list(generated: &Generated, pointer: &str) -> Vec<String> {
    let value = Value::Object(generated.sandbox.clone());
    serde_json::from_value(value.pointer(pointer).cloned().unwrap_or(json!([]))).unwrap()
}

/// The settings and report for the default policy, as a reviewer reads them.
#[test]
fn default_policy_matches_the_golden_settings() {
    let out = generated(DEFAULT_POLICY);
    let actual = serde_json::to_string_pretty(&json!({
        "sandbox": out.sandbox,
        "permissions": { BLOCK_READS: out.block_reads },
        "losses": out.report.losses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "allowances": out.report.allowances.iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
    .unwrap();
    assert_golden("claude-default.json", &(actual + "\n"));
}

#[test]
fn every_pattern_is_absolute() {
    let out = generated(DEFAULT_POLICY);
    for pointer in [
        "/filesystem/denyRead",
        "/filesystem/allowRead",
        "/filesystem/denyWrite",
    ] {
        for p in list(&out, pointer) {
            assert!(
                p.starts_with('/'),
                "{pointer}: {p} would resolve against ~/.claude"
            );
        }
    }
    let deny = list(&out, "/filesystem/denyRead");
    for expected in [
        "/**/.env",
        "/**/.env.*",
        "/Users/me/.ssh",
        "/Users/me/.cargo/credentials.toml",
    ] {
        assert!(deny.contains(&expected.to_owned()), "{expected}: {deny:?}");
    }
    assert!(list(&out, "/filesystem/allowRead").contains(&"/Users/me/.cargo".to_owned()));
    assert!(
        !list(&out, "/filesystem/allowRead")
            .iter()
            .any(|p| p.contains(".env")),
        "a `**/` exception would re-open .env.example everywhere"
    );
    assert!(out.block_reads);
}

#[test]
fn directory_nodes_with_entries_below_are_left_out_and_listed() {
    let out = generated(DEFAULT_POLICY);
    let deny = list(&out, "/filesystem/denyWrite");
    assert!(
        !deny.contains(&"/**/.claude".to_owned()),
        "would make .claude/worktrees read-only"
    );
    assert!(deny.contains(&"/**/.claude/settings.json".to_owned()));
    assert!(
        deny.contains(&"/Users/me/.codex".to_owned()),
        "a tree rule keeps its directory"
    );
    let nodes = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "claude-code.directory-nodes");
    assert!(nodes.is_some_and(|a| a.patterns.contains(&"/**/.claude".to_owned())));
}

#[test]
fn network_lists_domains_and_keeps_addresses_denied() {
    let out = generated(DEFAULT_POLICY);
    let allowed = list(&out, "/network/allowedDomains");
    assert!(allowed.contains(&"registry.npmjs.org".to_owned()));
    assert!(
        !allowed.iter().any(|h| h == "localhost"),
        "an ask is a deny"
    );
    let denied = list(&out, "/network/deniedDomains");
    assert!(denied.contains(&"metadata.google.internal".to_owned()));
    assert!(!denied.iter().any(|h| h.contains("169.254")));
    assert_eq!(out.sandbox["network"]["strictAllowlist"], json!(true));
}

#[test]
fn a_read_root_inside_a_deny_is_not_reopened() {
    let out = generated(
        "version: 1\ndeny:\n  - id: s\n    fs.read: ['~/.ssh/**']\nsandbox:\n  read_roots: ['~/.ssh/pub', '/usr']\n",
    );
    assert_eq!(list(&out, "/filesystem/allowRead"), ["/usr"]);
    assert!(
        out.report
            .losses
            .iter()
            .any(|l| l.message.contains("/Users/me/.ssh/pub"))
    );
}

#[test]
fn git_is_writable_except_what_makes_it_run_code() {
    let out = generated(DEFAULT_POLICY);
    let deny = list(&out, "/filesystem/denyWrite");
    for whole in ["/**/.git", "/**/.git/**"] {
        assert!(
            !deny.contains(&whole.to_owned()),
            "git commit needs {whole}"
        );
    }
    for vector in [
        "/**/.git/hooks",
        "/**/.git/hooks/**",
        "/**/.git/config",
        "/**/.git/config.worktree",
        "/**/.git/info/attributes",
        "/**/.git/worktrees/*/config.worktree",
        "/**/.git/worktrees/*/commondir",
        "/**/.git/modules/**/hooks",
        "/**/.git/modules/**/config",
    ] {
        assert!(deny.contains(&vector.to_owned()), "{vector}: {deny:?}");
    }
    let allowance = out
        .report
        .allowances
        .iter()
        .find(|a| a.rule == "claude-code.git-internals");
    assert!(allowance.is_some_and(|a| a.patterns == ["/**/.git/**"]));
    assert!(
        !out.report.losses.iter().any(|l| l.message.contains(".git")),
        "{:?}",
        out.report.losses
    );
    assert!(
        deny.contains(&"/**/.moat".to_owned()),
        "other exceptions stay denied"
    );
}

#[test]
fn a_policy_that_denies_git_keeps_it_denied() {
    let out = generated(
        "version: 1\ndeny:\n  - id: g\n    fs.write: ['**/.git/**']\nallow:\n  - id: p\n    fs.write: ['${project}/**', '!${project}/.git/**']\n",
    );
    let deny = list(&out, "/filesystem/denyWrite");
    assert!(deny.contains(&"/**/.git".to_owned()), "{deny:?}");
}
