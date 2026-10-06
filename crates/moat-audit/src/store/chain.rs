//! The hash chain over audit events: canonical encoding, hashing and verification.
//!
//! Each event stores `prev_hash` (the `hash` of the event before it) and `hash`,
//! the lowercase hex SHA-256 of the event's canonical encoding (below). Editing,
//! deleting or reordering an event in the middle of the log breaks a link that
//! verification reports. The chain is unkeyed: someone who can write
//! the file can recompute every hash after an edit, and deleting the newest
//! events leaves a valid shorter chain. Detecting either needs the head hash
//! recorded outside the file (`docs/THREAT_MODEL.md`).
//!
//! # Canonical encoding, version 1
//!
//! The concatenation, in this order, of:
//!
//! 1. the domain tag `moat-audit-chain-v1` as a string;
//! 2. `id`, `ts_ms` as integers;
//! 3. `host`, `session_id` as strings;
//! 4. `call_id`, `cwd` as optional strings;
//! 5. `tool`, `action`, `verdict`, `rules`, `reasons` as strings: the cells exactly
//!    as stored, so `action`, `rules` and `reasons` are their redacted JSON text;
//! 6. `latency_us` as an integer;
//! 7. `prev_hash` as a string.
//!
//! An integer is 8 bytes, big-endian two's complement. A string is its UTF-8 length
//! as 8 bytes big-endian, then its bytes. An optional string is the byte `0x00`
//! when absent, or `0x01` followed by the string. Length prefixes make the encoding
//! unambiguous; hashing stored cells rather than re-serialised values keeps it
//! independent of how a later build serialises an `Action`.
//!
//! The first chained event's `prev_hash` is [`GENESIS`]. A change to this encoding
//! needs a new domain tag; events already written keep verifying under v1.

use rusqlite::{OptionalExtension, params};
use sha2::{Digest as _, Sha256};

use super::StoreError;

/// `prev_hash` of the first chained event: 64 zeros.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const DOMAIN: &str = "moat-audit-chain-v1";

/// The stored cells of one event, in the form the chain hashes them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fields<'a> {
    pub id: i64,
    pub ts_ms: i64,
    pub host: &'a str,
    pub session_id: &'a str,
    pub call_id: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub tool: &'a str,
    pub action: &'a str,
    pub verdict: &'a str,
    pub rules: &'a str,
    pub reasons: &'a str,
    pub latency_us: i64,
    pub prev_hash: &'a str,
}

impl Fields<'_> {
    /// The canonical encoding described in the module documentation.
    pub(crate) fn encode(&self) -> Vec<u8> {
        fn int(out: &mut Vec<u8>, value: i64) {
            out.extend_from_slice(&value.to_be_bytes());
        }
        fn text(out: &mut Vec<u8>, value: &str) {
            // usize → u64 is lossless on every supported target.
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        fn optional(out: &mut Vec<u8>, value: Option<&str>) {
            match value {
                None => out.push(0),
                Some(value) => {
                    out.push(1);
                    text(out, value);
                }
            }
        }
        let mut out = Vec::with_capacity(256);
        text(&mut out, DOMAIN);
        int(&mut out, self.id);
        int(&mut out, self.ts_ms);
        text(&mut out, self.host);
        text(&mut out, self.session_id);
        optional(&mut out, self.call_id);
        optional(&mut out, self.cwd);
        for cell in [
            self.tool,
            self.action,
            self.verdict,
            self.rules,
            self.reasons,
        ] {
            text(&mut out, cell);
        }
        int(&mut out, self.latency_us);
        text(&mut out, self.prev_hash);
        out
    }

    /// Lowercase hex SHA-256 of [`Fields::encode`].
    pub(crate) fn hash(&self) -> String {
        Sha256::digest(self.encode())
            .iter()
            .fold(String::with_capacity(64), |mut hex, b| {
                use std::fmt::Write as _;
                let _ = write!(hex, "{b:02x}");
                hex
            })
    }
}

/// The `id` and `prev_hash` the next event gets: one past the newest row, linked
/// to its hash (or [`GENESIS`] when there is none, or it predates the chain).
/// Called inside the write transaction, so concurrent writers serialise here.
pub(crate) fn next_link(conn: &rusqlite::Connection) -> Result<(i64, String), StoreError> {
    let last: Option<(i64, Option<String>)> = conn
        .query_row(
            "SELECT id, hash FROM events ORDER BY id DESC LIMIT 1",
            params![],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match last {
        Some((id, hash)) => (
            id.saturating_add(1),
            hash.unwrap_or_else(|| GENESIS.to_owned()),
        ),
        None => (1, GENESIS.to_owned()),
    })
}
