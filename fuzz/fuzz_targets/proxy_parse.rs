//! `moat proxy` parses bytes from any local client: a request head, then for a
//! tunnel the TLS `ClientHello`. Neither parser may panic, and what they accept
//! must be what the proxy then relies on.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openmoat_proxy::{Hello, Target, parse_request, server_name};

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(request)) = parse_request(data) {
        assert!(request.head_len <= data.len());
        assert!(request.port() != 0);
        let host = request.host();
        assert!(
            !host.is_empty() && host == host.to_ascii_lowercase(),
            "{host:?}"
        );
        if let Target::Http { head, .. } = &request.target {
            // The rewritten head is one complete head that ends the request
            // with `Connection: close`, whatever the client sent.
            assert!(head.ends_with(b"Connection: close\r\n\r\n"));
            let end = head.windows(4).position(|w| w == b"\r\n\r\n");
            assert_eq!(end, Some(head.len() - 4));
        }
    }
    if let Ok(Hello::ServerName(Some(name))) = server_name(data) {
        assert!(!name.is_empty() && name.is_ascii(), "{name:?}");
        assert_eq!(name, name.to_ascii_lowercase());
    }
});
