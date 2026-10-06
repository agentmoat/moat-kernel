use moat_core::{EvalContext, Policy};

use super::*;

fn ctx() -> EvalContext {
    EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        cwd: "/home/u".to_owned(),
        case_insensitive_paths: false,
    }
}

fn verdicts(yaml: &str, cases: &[(&str, Verdict, &str)]) {
    let policy = Policy::parse(yaml).unwrap();
    let compiled = CompiledPolicy::compile(&policy, &ctx()).unwrap();
    for (h, verdict, rule) in cases {
        let d = host(&compiled, h);
        assert_eq!(
            (d.verdict, d.rules[0].as_str()),
            (*verdict, *rule),
            "{h}: {d:?}"
        );
    }
}

#[test]
fn the_default_policy_allows_only_listed_hosts() {
    verdicts(
        moat_core::DEFAULT_POLICY,
        &[
            ("api.github.com", Verdict::Allow, "registries"),
            ("crates.io", Verdict::Allow, "registries"),
            // unlisted: the fetch default (ask) is refused, never asked
            ("evil.example", Verdict::Deny, "default.fetch"),
            // local-net is an ask group: refused too
            ("localhost", Verdict::Deny, "local-net"),
            ("169.254.169.254", Verdict::Deny, "cloud-metadata"),
            ("metadata.google.internal", Verdict::Deny, RULE_ADDRESS),
        ],
    );
}

#[test]
fn net_and_fetch_lists_both_allow_and_deny_wins() {
    let yaml = r#"
version: 1
defaults: { "*": deny }
deny:
  - { id: no-evil, net: ["*.evil.example"] }
allow:
  - { id: docs, fetch: ["docs.rs"] }
  - { id: wide, net: ["*.example", "*.evil.example"] }
"#;
    verdicts(
        yaml,
        &[
            ("docs.rs", Verdict::Allow, "docs"),
            ("a.example", Verdict::Allow, "wide"),
            ("x.evil.example", Verdict::Deny, "no-evil"),
            ("other.org", Verdict::Deny, "default"),
        ],
    );
}

#[test]
fn metadata_names_are_refused_even_when_allowed() {
    let yaml = r#"
version: 1
allow:
  - { id: all, net: ["*"] }
"#;
    verdicts(
        yaml,
        &[
            ("metadata.google.internal", Verdict::Deny, RULE_ADDRESS),
            ("x.metadata.goog", Verdict::Deny, RULE_ADDRESS),
            ("notmetadata.goog", Verdict::Allow, "all"),
        ],
    );
}

#[test]
fn local_and_metadata_addresses_are_forbidden() {
    for (ip, why) in [
        ("127.0.0.1", Forbidden::Loopback),
        ("127.8.9.10", Forbidden::Loopback),
        ("::1", Forbidden::Loopback),
        ("::ffff:127.0.0.1", Forbidden::Loopback),
        ("169.254.169.254", Forbidden::LinkLocal),
        ("::ffff:169.254.169.254", Forbidden::LinkLocal),
        ("64:ff9b::a9fe:a9fe", Forbidden::LinkLocal),
        ("::a9fe:a9fe", Forbidden::LinkLocal),
        ("fe80::1", Forbidden::LinkLocal),
        ("febf::1", Forbidden::LinkLocal),
        ("fd00:ec2::254", Forbidden::Metadata),
        ("100.100.100.200", Forbidden::Metadata),
        ("0.0.0.0", Forbidden::NotUnicast),
        ("0.1.2.3", Forbidden::NotUnicast),
        ("::", Forbidden::NotUnicast),
        ("255.255.255.255", Forbidden::NotUnicast),
        ("224.0.0.1", Forbidden::NotUnicast),
        ("ff02::1", Forbidden::NotUnicast),
    ] {
        assert_eq!(forbidden(ip.parse().unwrap()), Some(why), "{ip}");
    }
}

#[test]
fn ordinary_addresses_are_not_forbidden() {
    for ip in [
        "93.184.215.14",
        "10.0.0.5",
        "192.168.1.1",
        "2606:4700::1111",
        "fec0::1",
    ] {
        assert_eq!(forbidden(ip.parse().unwrap()), None, "{ip}");
    }
}
