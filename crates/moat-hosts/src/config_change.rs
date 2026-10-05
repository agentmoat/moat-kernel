//! Claude Code `ConfigChange` hook: fired when a settings file changes on disk.
//!
//! Blocking refuses to load the new settings into the running session; the
//! file itself is left as written. The kernel uses this to keep a tampered hook
//! file from taking effect even before the next tool call.

use moat_core::{Action, Decision, Verdict};
use serde::{Deserialize, Serialize};

use crate::{HookEvent, HookRequest, Host, HostError};

pub(crate) const EVENT: &str = "ConfigChange";

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    source: String,
    change_type: String,
    file_path: String,
}

#[derive(Serialize)]
struct Block<'a> {
    decision: &'static str,
    reason: &'a str,
}

pub(crate) fn parse(host: Host, payload: &str) -> Result<HookRequest, HostError> {
    let p: Payload = serde_json::from_str(payload)?;
    if p.file_path.is_empty() {
        return Err(HostError::MissingField {
            tool: EVENT.to_owned(),
            field: "file_path",
        });
    }
    Ok(HookRequest {
        host,
        session_id: crate::session_or_unknown(p.session_id),
        call_id: None,
        cwd: p.cwd,
        tool: EVENT.to_owned(),
        action: Some(Action::FsWrite { path: p.file_path }),
        event: HookEvent::ConfigChange {
            source: p.source,
            change_type: p.change_type,
        },
    })
}

/// `{}` lets the change load; anything else blocks it with a reason.
pub(crate) fn render(decision: &Decision) -> String {
    match decision.verdict {
        Verdict::Allow => "{}".to_owned(),
        Verdict::Ask | Verdict::Deny => {
            let reason = crate::reason_line(decision);
            serde_json::to_string(&Block {
                decision: "block",
                reason: &reason,
            })
            .expect("response is plain data")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str = r#"{
        "session_id": "abc123", "cwd": "/p", "hook_event_name": "ConfigChange",
        "source": "user_settings", "change_type": "modified",
        "file_path": "/Users/me/.claude/settings.json"
    }"#;

    #[test]
    fn parses_into_a_file_write_with_event_details() {
        let req = Host::ClaudeCode.parse_request(PAYLOAD).unwrap();
        assert_eq!(req.tool, "ConfigChange");
        assert_eq!(
            req.action,
            Some(Action::FsWrite {
                path: "/Users/me/.claude/settings.json".into()
            })
        );
        assert!(matches!(
            req.event,
            HookEvent::ConfigChange { ref source, ref change_type }
                if source == "user_settings" && change_type == "modified"
        ));
    }

    #[test]
    fn missing_path_is_an_error() {
        let bad = r#"{"hook_event_name":"ConfigChange","source":"user_settings","change_type":"deleted","file_path":""}"#;
        assert!(matches!(
            Host::ClaudeCode.parse_request(bad),
            Err(HostError::MissingField {
                field: "file_path",
                ..
            })
        ));
    }

    #[test]
    fn allow_is_empty_and_deny_blocks_with_reason() {
        let event = HookEvent::ConfigChange {
            source: "user_settings".into(),
            change_type: "modified".into(),
        };
        assert_eq!(
            Host::ClaudeCode.render_response(&event, &Decision::new(Verdict::Allow)),
            "{}"
        );
        let mut deny = Decision::new(Verdict::Deny);
        deny.rules.push("kernel-integrity".into());
        deny.reasons
            .push("settings.json changed outside moat".into());
        let out: serde_json::Value =
            serde_json::from_str(&Host::ClaudeCode.render_response(&event, &deny)).unwrap();
        assert_eq!(out["decision"], "block");
        assert!(out["reason"].as_str().unwrap().contains("kernel-integrity"));
    }
}
