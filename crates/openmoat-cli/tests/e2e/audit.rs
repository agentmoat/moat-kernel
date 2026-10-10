//! The audit hash chain end to end: concurrent `guard` processes, `show` and
//! `doctor` after an edit.

use crate::common::{OK, Sandbox, USAGE, bash_payload, json, stdout, text};

/// Run `count` `guard` calls at once, as parallel tool calls do.
fn guard_concurrently(sb: &Sandbox, count: usize) {
    let project = sb.project();
    std::thread::scope(|scope| {
        let calls: Vec<_> = (0..count)
            .map(|i| {
                let payload = bash_payload("s1", &project, &format!("echo {i}"));
                scope.spawn(move || sb.guard("claude-code", &payload))
            })
            .collect();
        for call in calls {
            let out = call.join().unwrap();
            assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        }
    });
}

#[test]
fn concurrent_guards_build_one_chain_that_doctor_verifies() {
    let sb = Sandbox::installed(&[".claude"]);
    guard_concurrently(&sb, 12);
    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(OK), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("12 events, hash chain intact"),
        "{}",
        text(&doctor)
    );

    let shown = json(&sb.moat(&["show", "--session", "s1", "--format", "json"]));
    let events = shown.as_array().expect("an array of events");
    assert_eq!(events.len(), 12);
    assert_eq!(events[0]["prev_hash"], openmoat_audit::GENESIS);
    for pair in events.windows(2) {
        assert_eq!(pair[1]["prev_hash"], pair[0]["hash"]);
        assert_eq!(pair[1]["hash"].as_str().map(str::len), Some(64));
    }
}

#[test]
fn doctor_reports_an_edited_event_with_exit_64() {
    let sb = Sandbox::installed(&[".claude"]);
    guard_concurrently(&sb, 4);
    openmoat_audit::testing::tamper_with_event(
        &sb.home.join(".moat/audit.db"),
        3,
        "deny",
        r#"["secrets-paths"]"#,
    )
    .unwrap();

    let doctor = sb.moat(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(USAGE), "{}", text(&doctor));
    assert!(
        stdout(&doctor).contains("hash chain broken at event 3: its contents do not match"),
        "{}",
        text(&doctor)
    );
    // Recording continues after the edit; the break stays reported.
    guard_concurrently(&sb, 1);
    assert_eq!(sb.moat(&["doctor"]).status.code(), Some(USAGE));
}
