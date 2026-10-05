//! Local audit log: every decision the kernel makes, append-only, redacted.
//!
//! One `SQLite` file in WAL mode. Several `moat guard` processes may write at
//! once (parallel tool calls, several agents), so writes are single statements
//! with a busy timeout and no long-lived transactions.

#![warn(missing_docs)]

mod query;
mod redact;
mod store;

pub use query::{SessionSummary, Summary};
pub use redact::{redact, redact_value};
pub use store::{Event, EventId, NewEvent, Store, StoreError};
