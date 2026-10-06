use moat_core::{Policy, Verdict};
use zeroize::Zeroizing;

use super::{Broker, BrokerError, Carried, RULE_SECRET, Watch};

/// A generated stand-in; no real secret is used anywhere in these tests.
const VALUE: &str = "fake-0123456789abcdef";

fn broker(value: &str) -> Result<Broker, BrokerError> {
    let policy = Policy::parse(
        "version: 1\nsecrets:\n  - id: gh\n    host: api.github.com\n    header: Authorization\n    \
         source: { env: FAKE_TOKEN }\n",
    )
    .unwrap();
    let secrets = policy
        .secrets
        .into_iter()
        .map(|s| (s, Zeroizing::new(value.to_owned())))
        .collect();
    Broker::new(secrets)
}

#[test]
fn values_that_could_break_a_header_are_refused() {
    assert!(matches!(broker(""), Err(BrokerError::Empty(id)) if id == "gh"));
    for bad in ["a\r\nX-Evil: 1", "a\nb", "a\0b"] {
        let err = broker(bad).unwrap_err();
        assert!(matches!(err, BrokerError::Control(_)), "{bad:?}");
        assert!(!err.to_string().contains(bad), "{err}");
    }
}

#[test]
fn the_owner_may_receive_both_forms_and_no_other_host_may() {
    let b = broker(VALUE).unwrap();
    let placeholder = b"Authorization: Bearer moat-secret:gh:placeholder";
    let value = format!("POST /x HTTP/1.1\r\n\r\ntoken={VALUE}");
    assert!(b.leak("api.github.com", placeholder).is_none());
    assert!(b.leak("api.github.com", value.as_bytes()).is_none());
    let leak = b.leak("evil.example", placeholder).unwrap();
    assert_eq!(
        (leak.id, leak.owner, leak.carried),
        ("gh", "api.github.com", Carried::Placeholder)
    );
    let leak = b.leak("github.com", value.as_bytes()).unwrap();
    assert_eq!(leak.carried, Carried::Value);
    let decision = leak.decision("github.com");
    assert_eq!(decision.verdict, Verdict::Deny);
    assert_eq!(decision.rules, [RULE_SECRET]);
    assert!(!decision.reasons.join(" ").contains(VALUE), "{decision:?}");
    assert!(b.leak("evil.example", b"GET / HTTP/1.1\r\n\r\n").is_none());
}

#[test]
fn a_secret_split_across_chunks_is_found() {
    let b = broker(VALUE).unwrap();
    let stream = format!("{}{VALUE}{}", "x".repeat(5000), "y".repeat(100));
    for cut in 1..VALUE.len() {
        let at = 5000 + cut;
        let mut watch = Watch::new(&b, "evil.example");
        assert!(watch.next(&stream.as_bytes()[..at]).is_none(), "{cut}");
        assert!(watch.next(&stream.as_bytes()[at..]).is_some(), "{cut}");
    }
    let mut owner = Watch::new(&b, "api.github.com");
    assert!(owner.next(stream.as_bytes()).is_none());
}

#[test]
fn nothing_brokered_finds_nothing() {
    let b = Broker::default();
    assert!(
        Watch::new(&b, "evil.example")
            .next(VALUE.as_bytes())
            .is_none()
    );
}

#[test]
fn debug_names_ids_and_hosts_never_values() {
    let shown = format!("{:?}", broker(VALUE).unwrap());
    assert!(
        shown.contains("gh") && shown.contains("api.github.com"),
        "{shown}"
    );
    assert!(!shown.contains(VALUE), "{shown}");
}
