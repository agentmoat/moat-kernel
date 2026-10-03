use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use moat_core::{Action, Decision, Verdict};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::redact;

const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT_MS: u64 = 2000;

const SCHEMA: &str = "
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

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("audit database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(
        "audit database schema version {found} is newer than this build supports ({supported})"
    )]
    SchemaTooNew { found: i64, supported: i64 },
    #[error("invalid event id `{0}`; expected hex such as 1f")]
    InvalidId(String),
    #[error("encoding event: {0}")]
    Encode(#[from] serde_json::Error),
}

/// Row id, shown and parsed as lowercase hex (`moat show 1f`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub i64);

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl FromStr for EventId {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.trim().trim_start_matches('#');
        i64::from_str_radix(digits, 16)
            .ok()
            .filter(|id| *id > 0)
            .map(EventId)
            .ok_or_else(|| StoreError::InvalidId(s.to_owned()))
    }
}

/// What a caller records. Secrets are redacted before storage.
#[derive(Debug, Clone)]
pub struct NewEvent<'a> {
    pub host: &'a str,
    pub session_id: &'a str,
    pub call_id: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub tool: &'a str,
    pub action: Option<&'a Action>,
    pub decision: &'a Decision,
    pub latency_us: u64,
}

/// A stored decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub ts_ms: i64,
    pub host: String,
    pub session_id: String,
    pub call_id: Option<String>,
    pub cwd: Option<String>,
    pub tool: String,
    pub action: Option<Action>,
    pub verdict: Verdict,
    pub rules: Vec<String>,
    pub reasons: Vec<String>,
    pub latency_us: i64,
}

#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Connection,
}

impl Store {
    /// Open (creating if needed) the audit database at `path`.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        restrict_permissions(path);
        Self::initialise(conn)
    }

    /// Read-only handle; fails if the database does not exist.
    pub fn open_read_only(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::initialise(Connection::open_in_memory()?)
    }

    fn initialise(conn: Connection) -> Result<Self, StoreError> {
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        if version < SCHEMA_VERSION {
            conn.execute_batch(SCHEMA)?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        Ok(Self { conn })
    }

    /// Append one decision and return its id.
    pub fn record(&self, event: &NewEvent<'_>) -> Result<EventId, StoreError> {
        self.record_at(event, now_ms())
    }

    /// Append one decision with an explicit timestamp (milliseconds since the epoch).
    pub fn record_at(&self, event: &NewEvent<'_>, ts_ms: i64) -> Result<EventId, StoreError> {
        let action_json = match event.action {
            Some(action) => redact(&serde_json::to_string(action)?),
            None => "null".to_owned(),
        };
        let reasons: Vec<String> = event.decision.reasons.iter().map(|r| redact(r)).collect();
        self.conn.execute(
            "INSERT INTO events (ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                ts_ms,
                event.host,
                event.session_id,
                event.call_id,
                event.cwd,
                event.tool,
                action_json,
                event.decision.verdict.as_str(),
                serde_json::to_string(&event.decision.rules)?,
                serde_json::to_string(&reasons)?,
                i64::try_from(event.latency_us).unwrap_or(i64::MAX),
            ],
        )?;
        Ok(EventId(self.conn.last_insert_rowid()))
    }

    pub fn get(&self, id: EventId) -> Result<Option<Event>, StoreError> {
        self.conn
            .query_row(
                &format!("{SELECT} WHERE id = ?1"),
                params![id.0],
                row_to_event,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Most recent events, newest first.
    pub fn recent(&self, limit: usize) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(&format!("{SELECT} ORDER BY id DESC LIMIT ?1"))?;
        let rows = stmt.query_map(
            params![i64::try_from(limit).unwrap_or(i64::MAX)],
            row_to_event,
        )?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// All events of one session, oldest first.
    pub fn session(&self, session_id: &str) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(&format!("{SELECT} WHERE session_id = ?1 ORDER BY id"))?;
        let rows = stmt.query_map(params![session_id], row_to_event)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or_default())
    }
}

pub(crate) const SELECT: &str = "SELECT id, ts_ms, host, session_id, call_id, cwd, tool, action, verdict, rules, reasons, latency_us FROM events";

pub(crate) fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    fn decode<T: serde::de::DeserializeOwned>(
        row: &rusqlite::Row<'_>,
        index: usize,
    ) -> rusqlite::Result<T> {
        let text: String = row.get(index)?;
        serde_json::from_str(&text).map_err(|e| json_error(e, row))
    }
    let action: Option<Action> = decode(row, 7)?;
    let verdict = match row.get::<_, String>(8)?.as_str() {
        "allow" => Verdict::Allow,
        "ask" => Verdict::Ask,
        _ => Verdict::Deny,
    };
    Ok(Event {
        id: EventId(row.get(0)?),
        ts_ms: row.get(1)?,
        host: row.get(2)?,
        session_id: row.get(3)?,
        call_id: row.get(4)?,
        cwd: row.get(5)?,
        tool: row.get(6)?,
        action,
        verdict,
        rules: decode(row, 9)?,
        reasons: decode(row, 10)?,
        latency_us: row.get(11)?,
    })
}

fn json_error(e: serde_json::Error, row: &rusqlite::Row<'_>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        row.as_ref().column_count(),
        rusqlite::types::Type::Text,
        Box::new(e),
    )
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(verdict: Verdict, rule: &str, reason: &str) -> Decision {
        let mut d = Decision::new(verdict);
        d.rules.push(rule.to_owned());
        d.reasons.push(reason.to_owned());
        d
    }

    fn sample<'a>(decision: &'a Decision, action: &'a Action) -> NewEvent<'a> {
        NewEvent {
            host: "claude-code",
            session_id: "s1",
            call_id: Some("c1"),
            cwd: Some("/p"),
            tool: "Bash",
            action: Some(action),
            decision,
            latency_us: 1200,
        }
    }

    #[test]
    fn record_and_read_back() {
        let store = Store::open_in_memory().unwrap();
        let d = decision(
            Verdict::Deny,
            "secrets-paths",
            "secret material: read /h/.ssh/id_rsa",
        );
        let a = Action::Shell {
            command: "cat ~/.ssh/id_rsa".into(),
        };
        let id = store.record(&sample(&d, &a)).unwrap();
        let event = store.get(id).unwrap().expect("stored");
        assert_eq!(event.verdict, Verdict::Deny);
        assert_eq!(event.rules, ["secrets-paths"]);
        assert_eq!(event.action, Some(a));
        assert_eq!(event.tool, "Bash");
        assert_eq!(event.latency_us, 1200);
        assert_eq!(store.count().unwrap(), 1);
        assert!(store.get(EventId(999)).unwrap().is_none());
    }

    #[test]
    fn secrets_are_redacted_before_storage() {
        let store = Store::open_in_memory().unwrap();
        let d = decision(
            Verdict::Allow,
            "dev-shell",
            "shell with token=ghp_abcdefghijklmnopqrstuvwxyz0123",
        );
        let a = Action::Shell {
            command: "curl -H 'Authorization: Bearer abcdefghijkl' https://api.github.com".into(),
        };
        let id = store.record(&sample(&d, &a)).unwrap();
        let event = store.get(id).unwrap().unwrap();
        let Some(Action::Shell { command }) = event.action else {
            panic!("shell action")
        };
        assert!(command.contains("Bearer [redacted]"), "{command}");
        assert!(event.reasons[0].contains("[redacted]"));
    }

    #[test]
    fn recent_and_session_queries() {
        let store = Store::open_in_memory().unwrap();
        let d = decision(Verdict::Allow, "dev-shell", "ok");
        let a = Action::Shell {
            command: "git status".into(),
        };
        for session in ["s1", "s2", "s1"] {
            store
                .record(&NewEvent {
                    session_id: session,
                    ..sample(&d, &a)
                })
                .unwrap();
        }
        let recent = store.recent(2).unwrap();
        assert_eq!(recent.len(), 2);
        assert!(recent[0].id.0 > recent[1].id.0);
        assert_eq!(store.session("s1").unwrap().len(), 2);
        assert!(store.session("none").unwrap().is_empty());
    }

    #[test]
    fn ungoverned_event_has_no_action() {
        let store = Store::open_in_memory().unwrap();
        let d = decision(Verdict::Allow, "ungoverned", "tool outside policy scope");
        let id = store
            .record(&NewEvent {
                action: None,
                tool: "TodoWrite",
                ..sample(
                    &d,
                    &Action::Shell {
                        command: String::new(),
                    },
                )
            })
            .unwrap();
        assert_eq!(store.get(id).unwrap().unwrap().action, None);
    }

    #[test]
    fn event_ids_are_hex() {
        assert_eq!(EventId(31).to_string(), "1f");
        assert_eq!("1f".parse::<EventId>().unwrap(), EventId(31));
        assert_eq!("#1F".parse::<EventId>().unwrap(), EventId(31));
        assert!("zz".parse::<EventId>().is_err());
        assert!("0".parse::<EventId>().is_err());
    }

    #[test]
    fn file_store_round_trip_and_reopen() {
        let dir = std::env::temp_dir().join(format!("moat-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.db");
        let d = decision(Verdict::Ask, "installs", "new dependency");
        let a = Action::Shell {
            command: "npm install x".into(),
        };
        let id = Store::open(&path).unwrap().record(&sample(&d, &a)).unwrap();
        let reopened = Store::open_read_only(&path).unwrap();
        assert_eq!(reopened.get(id).unwrap().unwrap().verdict, Verdict::Ask);
        std::fs::remove_dir_all(&dir).ok();
    }
}
