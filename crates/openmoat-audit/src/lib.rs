//! Local audit log: every decision the kernel makes, append-only, redacted.
//!
//! One `SQLite` file in WAL mode. Several `moat guard` processes may write at
//! once (parallel tool calls, several agents), so each write is one short
//! `BEGIN IMMEDIATE` transaction with a busy timeout: it reads the newest event's
//! hash and appends the next event linked to it, so the hash chain never forks.

#![warn(missing_docs)]

mod query;
mod redact;
mod store;
#[cfg(feature = "test-support")]
pub mod testing;

pub use query::{SessionSummary, Summary};
pub use redact::{redact, redact_value};
pub use store::{
    BreakKind, ChainBreak, ChainReport, Event, EventId, ExportBreak, ExportFilter, ExportFormat,
    ExportReport, ExportedEvent, GENESIS, NewEvent, Store, StoreError, verify_export,
};
