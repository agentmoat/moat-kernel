use moat_core::{Action, Decision, Verdict};

use super::*;

fn record(store: &Store, host: &str, session: &str, command: &str, ts_ms: i64) {
    let mut decision = Decision::new(Verdict::Ask);
    decision.rules.push("installs".to_owned());
    decision.reasons.push(format!("asked about {command}"));
    let action = Action::Shell {
        command: command.to_owned(),
    };
    store
        .record_at(
            &NewEvent {
                host,
                session_id: session,
                call_id: None,
                cwd: Some("/p"),
                tool: "Bash",
                action: Some(&action),
                decision: &decision,
                latency_us: 7,
            },
            ts_ms,
        )
        .unwrap();
}

fn seeded() -> Store {
    let store = Store::open_in_memory().unwrap();
    record(&store, "claude-code", "s1", "npm install a", 1_000);
    record(&store, "cursor", "c1", "npm install b", 2_000);
    record(&store, "claude-code", "s2", "npm install c", 3_000);
    store
}

fn ids(events: &[ExportedEvent]) -> Vec<i64> {
    events.iter().map(|e| e.id.0).collect()
}

#[test]
fn export_carries_stored_cells_and_chain_links() {
    let store = seeded();
    let exported = store.export(&ExportFilter::default()).unwrap();
    assert_eq!(ids(&exported), [1, 2, 3]);
    let stored: String = store
        .conn
        .query_row("SELECT action FROM events WHERE id = 2", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        exported[1].action.get(),
        stored,
        "the stored text, byte for byte"
    );
    assert_eq!(exported[0].prev_hash, GENESIS);
    for (event, line) in store.session("s1").unwrap().iter().zip(&exported) {
        assert_eq!(event.hash.as_deref(), Some(line.hash.as_str()));
    }
    let line = serde_json::to_string(&exported[1]).unwrap();
    assert!(
        line.starts_with(r#"{"format":"moat-audit-export-v1","id":"2","#),
        "{line}"
    );
    assert!(line.contains(r#""rules":["installs"]"#), "{line}");
    assert!(!line.contains('\n'));
}

#[test]
fn export_filters_by_time_host_and_session() {
    let store = seeded();
    let export = |filter: ExportFilter<'_>| ids(&store.export(&filter).unwrap());
    let since = |since_ms| ExportFilter {
        since_ms,
        ..ExportFilter::default()
    };
    assert_eq!(export(since(2_000)), [2, 3]);
    let claude = ExportFilter {
        host: Some("claude-code"),
        ..ExportFilter::default()
    };
    assert_eq!(export(claude), [1, 3]);
    let s2 = ExportFilter {
        session_id: Some("s2"),
        ..ExportFilter::default()
    };
    assert_eq!(export(s2), [3]);
    assert_eq!(
        export(ExportFilter {
            since_ms: 2_000,
            ..claude
        }),
        [3]
    );
}

#[test]
fn export_holds_only_redacted_text() {
    let store = Store::open_in_memory().unwrap();
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    record(
        &store,
        "codex",
        "k1",
        &format!("curl -H 'Authorization: Bearer {secret}' https://x"),
        1,
    );
    let exported = store.export(&ExportFilter::default()).unwrap();
    let line = serde_json::to_string(&exported).unwrap();
    assert!(!line.contains(secret), "{line}");
    assert!(line.contains("curl"), "{line}");
}

#[test]
fn export_leaves_out_events_from_before_the_chain() {
    let store = seeded();
    store
        .conn
        .execute(
            "UPDATE events SET hash = NULL, prev_hash = NULL WHERE id = 1",
            [],
        )
        .unwrap();
    assert_eq!(
        ids(&store.export(&ExportFilter::default()).unwrap()),
        [2, 3]
    );
}
