use super::*;

#[test]
fn oversized_and_malformed_heads_get_400() {
    let limits = Limits {
        max_head_bytes: 256,
        ..Limits::default()
    };
    let h = start(None, limits);
    let big = format!(
        "GET http://allowed.test/ HTTP/1.1\r\nX: {}\r\n\r\n",
        "a".repeat(400)
    );
    assert!(h.exchange(&big).starts_with("HTTP/1.1 400"));
    assert!(
        h.exchange("GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            .starts_with("HTTP/1.1 400")
    );
    assert!(
        h.exchange("\x16\x03\x01\x00\x05hello")
            .starts_with("HTTP/1.1 400")
    );
    let rows = h.rows();
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|r| r.rules == ["proxy-request"] && r.dest.is_none())
    );
}

#[test]
fn connections_over_the_limit_get_503() {
    let limits = Limits {
        max_connections: 1,
        handshake_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    let h = start(None, limits);
    let _held = h.connect(); // sends nothing, so it holds its slot
    thread::sleep(Duration::from_millis(200));
    let reply = h.exchange("GET http://allowed.test/ HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
}

#[test]
fn a_silent_client_is_dropped_after_the_handshake_timeout() {
    let limits = Limits {
        handshake_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let h = start(None, limits);
    let mut s = h.connect();
    s.write_all(b"GET http://allowed.test/ HT").unwrap();
    let reply = read_all(&mut s);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
}

#[test]
fn a_trickling_client_cannot_stretch_the_handshake_timeout() {
    let limits = Limits {
        handshake_timeout: Duration::from_millis(400),
        ..Limits::default()
    };
    let h = start(None, limits);
    let mut s = h.connect();
    let started = std::time::Instant::now();
    for byte in b"GET http://allowed.test/ HTTP/1.1\r\n" {
        if s.write_all(&[*byte]).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
        if started.elapsed() > Duration::from_secs(1) {
            break;
        }
    }
    let reply = read_all(&mut s);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(started.elapsed() < Duration::from_secs(2));
}
