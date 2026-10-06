//! Best-effort removal of credential material before anything is persisted.
//!
//! The audit log records *what was attempted*, never the secret itself. The
//! patterns cover the token formats that routinely appear in shell commands;
//! policy still blocks the dangerous cases regardless of what is logged here.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

const REPLACEMENT: &str = "[redacted]";

static PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let rules: &[(&str, &str)] = &[
        // Named credentials in key=value or key: value form; keep the key.
        (
            r"(?i)\b((?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|authorization|private[_-]?key)\s*[=:]\s*)(['\x22]?)((?:bearer|basic)\s+)?[^\s'\x22&;]+(['\x22]?)",
            "${1}${2}${3}[redacted]${4}",
        ),
        (
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}",
            "Bearer [redacted]",
        ),
        (r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}", "Basic [redacted]"),
        // Well-known token shapes.
        (r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b", REPLACEMENT),
        (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", REPLACEMENT),
        (r"\bsk-(?:[a-z]+-)?[A-Za-z0-9]{16,}\b", REPLACEMENT),
        (r"\bAKIA[0-9A-Z]{16}\b", REPLACEMENT),
        (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", REPLACEMENT),
        (r"\bAIza[0-9A-Za-z_-]{30,}\b", REPLACEMENT),
        (r"\bnpm_[A-Za-z0-9]{30,}\b", REPLACEMENT),
        (r"\bglpat-[A-Za-z0-9_-]{20,}\b", REPLACEMENT),
        (
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            REPLACEMENT,
        ),
        // Credentials embedded in URLs.
        (r"(://[^/\s:@]+:)[^@/\s]+@", "${1}[redacted]@"),
    ];
    rules
        .iter()
        .map(|(pattern, replacement)| (Regex::new(pattern).expect("static pattern"), *replacement))
        .collect()
});

/// Replace credential-looking substrings. Idempotent.
#[must_use]
pub fn redact(text: &str) -> String {
    PATTERNS
        .iter()
        .fold(text.to_owned(), |acc, (re, replacement)| {
            re.replace_all(&acc, *replacement).into_owned()
        })
}

/// Redact every string leaf of a JSON document. Used on the structured action
/// before it is serialised, so patterns see the raw text rather than
/// JSON-escaped quotes and the result is re-encoded as valid JSON.
#[must_use]
pub fn redact_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| (key, redact_value(item)))
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{redact, redact_value};
    use serde_json::json;

    #[test]
    fn redacts_string_leaves_of_a_document() {
        let doc = json!({"shell": {"command": "curl -H \"X-Api-Key: abc123def456\" https://x", "n": 1, "list": ["token=ghp_abcdefghijklmnopqrstuvwxyz0123"]}});
        let out = redact_value(doc);
        let text = out.to_string();
        assert!(!text.contains("abc123def456"), "{text}");
        assert!(!text.contains("ghp_abc"), "{text}");
        assert!(text.contains("X-Api-Key: [redacted]"), "{text}");
        assert_eq!(out["shell"]["n"], 1);
    }

    #[test]
    fn named_credentials_keep_their_key() {
        assert_eq!(
            redact("curl -H 'X-Api-Key: abc123def'"),
            "curl -H 'X-Api-Key: [redacted]'"
        );
        assert_eq!(
            redact("export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123"),
            "export TOKEN=[redacted]"
        );
        assert_eq!(
            redact("password=hunter2 user=bob"),
            "password=[redacted] user=bob"
        );
    }

    #[test]
    fn well_known_token_shapes() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "[redacted]");
        assert_eq!(
            redact("Authorization: Bearer abc.def-ghi_jkl"),
            "Authorization: Bearer [redacted]"
        );
        assert!(redact("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX").contains("[redacted]"));
        assert_eq!(
            redact("https://user:s3cret@host.example/x"),
            "https://user:[redacted]@host.example/x"
        );
    }

    #[test]
    fn ordinary_commands_are_untouched() {
        for cmd in [
            "git status --short",
            "cargo test -p openmoat-core",
            "echo token",
            "cat ~/.ssh/id_rsa",
        ] {
            assert_eq!(redact(cmd), cmd);
        }
    }

    #[test]
    fn idempotent() {
        let once = redact("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123");
        assert_eq!(redact(&once), once);
    }
}
