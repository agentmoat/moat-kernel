use moat_core::{Action, Decision, Verdict};

use super::chain::Fields;
use super::*;

fn fields() -> Fields<'static> {
    Fields {
        id: 1,
        ts_ms: 1_700_000_000_000,
        host: "claude-code",
        session_id: "s1",
        call_id: Some("c1"),
        cwd: None,
        tool: "Bash",
        action: r#"{"shell":{"command":"git status"}}"#,
        verdict: "allow",
        rules: r#"["dev-shell"]"#,
        reasons: r#"["ok"]"#,
        latency_us: 1200,
        prev_hash: GENESIS,
    }
}

#[test]
fn canonical_encoding_is_pinned() {
    // Changing this value breaks every chain already written: bump the domain tag
    // instead (chain.rs). The same value is computed independently from the
    // encoding as documented in `docs/ARCHITECTURE.md`.
    assert_eq!(
        fields().hash(),
        "a4c71c405a0719bae1d6cd1fa50a92b6bfdcdf41f6789c7eea604f63c549c774"
    );
    let encoded = fields().encode();
    assert!(encoded.starts_with(&[0, 0, 0, 0, 0, 0, 0, 19]));
    assert!(encoded.ends_with(GENESIS.as_bytes()));
}

#[test]
fn canonical_encoding_separates_fields() {
    let base = fields();
    let shifted = Fields {
        host: "claude-codes",
        session_id: "1",
        ..base
    };
    assert_ne!(base.hash(), shifted.hash());
    let absent = Fields {
        call_id: None,
        cwd: Some("c1"),
        ..base
    };
    assert_ne!(base.hash(), absent.hash());
    let empty = Fields {
        call_id: Some(""),
        ..base
    };
    assert_ne!(
        Fields {
            call_id: None,
            ..base
        }
        .hash(),
        empty.hash()
    );
}

fn record(store: &Store, command: &str) -> EventId {
    let mut decision = Decision::new(Verdict::Allow);
    decision.rules.push("dev-shell".to_owned());
    decision.reasons.push("ok".to_owned());
    let action = Action::Shell {
        command: command.to_owned(),
    };
    store
        .record(&NewEvent {
            host: "claude-code",
            session_id: "s1",
            call_id: None,
            cwd: Some("/p"),
            tool: "Bash",
            action: Some(&action),
            decision: &decision,
            latency_us: 900,
        })
        .unwrap()
}

fn chain_of(n: usize) -> Store {
    let store = Store::open_in_memory().unwrap();
    for i in 0..n {
        record(&store, &format!("echo {i}"));
    }
    store
}

#[test]
fn each_event_links_to_the_one_before() {
    let store = chain_of(4);
    let events = store.session("s1").unwrap();
    assert_eq!(events[0].prev_hash.as_deref(), Some(GENESIS));
    for pair in events.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
    }
}
