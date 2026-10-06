//! Schema versions and the migration ladder.

use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::StoreError;

/// Schema version this build writes, kept in `PRAGMA user_version`.
pub(super) const SCHEMA_VERSION: i64 = 1;

/// Version 1: the events table.
const V1: &str = "
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    call_id     TEXT,
    cwd         TEXT,
    tool        TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    verdict     TEXT    NOT NULL CHECK (verdict IN ('allow','ask','deny')),
    rules       TEXT    NOT NULL,
    reasons     TEXT    NOT NULL,
    latency_us  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, id);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts_ms);
";

/// The `user_version` of the open database.
pub(super) fn version(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.pragma_query_value(None, "user_version", |r| r.get(0))?)
}

/// Bring the database to [`SCHEMA_VERSION`]. Several `moat guard` processes may
/// open an old database at once, so the version is re-read under the write lock
/// and each step runs at most once.
pub(super) fn migrate(conn: &Connection) -> Result<(), StoreError> {
    let found = version(conn)?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found == SCHEMA_VERSION {
        return Ok(());
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let found = version(&tx)?;
    if found >= SCHEMA_VERSION {
        // Another process migrated first; recheck without the lock.
        drop(tx);
        return migrate(conn);
    }
    if found < 1 {
        tx.execute_batch(V1)?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}
