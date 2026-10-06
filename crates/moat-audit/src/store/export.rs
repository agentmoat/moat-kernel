//! The export format: one JSON object per event, carrying the cells exactly as
//! stored and the event's place in the hash chain, so a file can be checked
//! without the database.
//!
//! `action`, `rules` and `reasons` are embedded as the stored JSON text, byte for
//! byte, rather than re-serialised: the chain hashes that text, and re-encoding it
//! (key order, escapes) could change it. Every cell is already redacted, because
//! nothing unredacted is ever stored, and an export adds nothing the store does
//! not hold.

use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::chain::{ROWS, Row, read_row};
use super::{EventId, Store, StoreError};

/// Which events [`Store::export`] writes. Conditions combine with AND.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExportFilter<'a> {
    /// Only events recorded at or after this time (ms since the epoch).
    pub since_ms: i64,
    /// Only this host id.
    pub host: Option<&'a str>,
    /// Only this host session id.
    pub session_id: Option<&'a str>,
}

/// Version of the export line format, the `format` field of every line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// Chain encoding v1 (`moat-audit-chain-v1`) over the fields below.
    #[serde(rename = "moat-audit-export-v1")]
    V1,
}

/// One exported event. A field this struct does not name makes the line
/// invalid, so nothing outside the hash can ride along.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedEvent {
    /// Line format version.
    pub format: ExportFormat,
    /// Row id in the database the event was exported from.
    pub id: EventId,
    /// Time recorded (ms since the epoch).
    pub ts_ms: i64,
    /// Host id.
    pub host: String,
    /// Host session id.
    pub session_id: String,
    /// Host call id, when sent.
    pub call_id: Option<String>,
    /// Working directory, when sent.
    pub cwd: Option<String>,
    /// Tool name as the host spells it.
    pub tool: String,
    /// The redacted action as stored (`null` for an ungoverned tool).
    pub action: Box<RawValue>,
    /// The verdict as stored.
    pub verdict: String,
    /// Rule ids as stored.
    pub rules: Box<RawValue>,
    /// Redacted reasons as stored.
    pub reasons: Box<RawValue>,
    /// Time spent deciding, in microseconds.
    pub latency_us: i64,
    /// Hash of the event before this one in the database's chain.
    pub prev_hash: String,
    /// This event's chain hash.
    pub hash: String,
}

impl ExportedEvent {
    fn from_row(row: Row) -> Result<Self, StoreError> {
        let [host, session_id, tool, action, verdict, rules, reasons] = row.cells;
        Ok(Self {
            format: ExportFormat::V1,
            id: EventId(row.id),
            ts_ms: row.ts_ms,
            host,
            session_id,
            call_id: row.call_id,
            cwd: row.cwd,
            tool,
            action: RawValue::from_string(action)?,
            verdict,
            rules: RawValue::from_string(rules)?,
            reasons: RawValue::from_string(reasons)?,
            latency_us: row.latency_us,
            // The export query selects only rows with both; an empty hash
            // would fail verification rather than pass.
            prev_hash: row.prev_hash.unwrap_or_default(),
            hash: row.hash.unwrap_or_default(),
        })
    }
}

impl Store {
    /// Chained events matching `filter`, oldest first, in export form. Events
    /// written before the chain existed have no hash to verify and are left out.
    pub fn export(&self, filter: &ExportFilter<'_>) -> Result<Vec<ExportedEvent>, StoreError> {
        if !self.chained {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare(&format!(
            "{ROWS} WHERE hash IS NOT NULL AND prev_hash IS NOT NULL AND ts_ms >= ?1
             AND (?2 IS NULL OR host = ?2) AND (?3 IS NULL OR session_id = ?3) ORDER BY id"
        ))?;
        let rows = stmt.query_map(
            params![filter.since_ms, filter.host, filter.session_id],
            read_row,
        )?;
        rows.map(|row| ExportedEvent::from_row(row?)).collect()
    }
}
