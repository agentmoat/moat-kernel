//! `moat proxy`: start-up checks, and one refused connection recorded in the
//! audit log. Allowed traffic is covered by `moat-proxy`'s own tests, which
//! can point a name at a local server; this binary uses the system resolver.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::Stdio;
use std::time::Duration;

use crate::common::{Sandbox, json, stderr};

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
