//! Any hook payload a host (or something pretending to be one) writes to
//! `moat guard`: every adapter must parse or reject it without panicking, and
//! render a response for any decision.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moat_core::{Decision, Verdict};
use moat_hosts::Host;

fuzz_target!(|data: &[u8]| {
    let Ok(payload) = std::str::from_utf8(data) else {
        return;
    };
    for host in Host::ALL {
        if let Ok(request) = host.parse_request(payload) {
            let decision = Decision::single(Verdict::Deny, "fuzz", "fuzz");
            let _ = host.render_response(&request.event, &decision);
        }
    }
});
