//! `moat-proxy`: the default-deny egress proxy behind `moat proxy` (ADR-020).
//!
//! It serves HTTP `CONNECT` tunnels and absolute-form plain-HTTP requests on a
//! loopback port:
//!
//! - Hosts are decided by moat-core's [`CompiledPolicy`](moat_core::CompiledPolicy)
//!   as `moat guard` decides a fetch tool's URL: only an `allow` passes.
//! - Cloud metadata and link-local addresses are refused whatever the policy
//!   says, by name and on every address the proxy resolves.
//! - A tunnel's TLS `ClientHello` must name the CONNECT host (SNI); nothing is
//!   decrypted.
//! - Every decision is recorded through a `Recorder`; a failed record is a
//!   refused connection.
//!
//! Plain `std::net` and one thread per connection, capped by `Limits`; the
//! choice is explained in `docs/notes/proxy-evaluation.md`.

#![warn(missing_docs)]

mod audit;
mod decide;
mod request;
mod sni;
mod tunnel;
mod upstream;

pub use audit::{Connection, RecordError, Recorder};
pub use decide::{
    Forbidden, RULE_ADDRESS, RULE_AUDIT, RULE_REQUEST, RULE_SNI, RULE_UPSTREAM, forbidden,
    host as decide_host,
};
pub use request::{MAX_HEADERS, Request, RequestError, Target, parse as parse_request};
pub use sni::{Hello, HelloError, MAX_HELLO, server_name};
pub use upstream::{Refusal, Resolve, SystemResolver, connect};
