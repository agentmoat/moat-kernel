//! Derive the files and hosts an MCP call touches from its arguments.
//!
//! Servers are not standardised, so this is key-based: arguments named like a
//! path become `fs.read` (or `fs.write` for write-shaped tools), arguments named
//! like a URL become `net`, at any depth of nesting. Unknown shapes add nothing
//! and the call is judged by its name alone. Adding resources can only make a
//! verdict stricter, so arguments that cannot be read are an error (the guard
//! fails closed) rather than silently ignored.

use moat_core::Action;
use serde_json::Value;

use crate::HostError;

const PATH_KEYS: &[&str] = &[
    "path",
    "paths",
    "file",
    "files",
    "file_path",
    "filepath",
    "filename",
    "directory",
    "dir",
    "source",
    "destination",
    "target",
    "root",
    "cwd",
];
const URL_KEYS: &[&str] = &["url", "urls", "uri", "endpoint", "href"];
const WRITE_TOOL_PREFIXES: &[&str] = &[
    "write", "edit", "create", "move", "rename", "delete", "remove", "append", "mkdir", "copy",
    "save", "patch", "update",
];

/// Nesting below this is not searched; arguments are rarely more than two deep.
const MAX_DEPTH: usize = 8;
/// More derived resources than this is refused rather than half-checked.
const MAX_RESOURCES: usize = 1024;

/// Build the action for `mcp__<server>__<tool>` from the host's `tool_input`.
/// Cursor sends the input as a JSON string, Claude Code and Codex as an object.
pub(crate) fn action(name: &str, input: &Value) -> Result<Action, HostError> {
    let parsed;
    let args = match input {
        Value::String(text) => {
            parsed =
                serde_json::from_str::<Value>(text).map_err(|e| HostError::MalformedArguments {
                    tool: name.to_owned(),
                    problem: e.to_string(),
                })?;
            &parsed
        }
        other => other,
    };
    let tool = name
        .rsplit("__")
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let mut found = Resources {
        writes_by_default: WRITE_TOOL_PREFIXES.iter().any(|p| tool.starts_with(p)),
        ..Resources::default()
    };
    found.walk(args, 0);
    if found.count() > MAX_RESOURCES {
        return Err(HostError::MalformedArguments {
            tool: name.to_owned(),
            problem: format!("more than {MAX_RESOURCES} paths and URLs"),
        });
    }
    Ok(Action::McpTool {
        name: name.to_owned(),
        reads: found.reads,
        writes: found.writes,
        hosts: found.hosts,
    })
}

#[derive(Default)]
struct Resources {
    writes_by_default: bool,
    reads: Vec<String>,
    writes: Vec<String>,
    hosts: Vec<String>,
}

impl Resources {
    fn count(&self) -> usize {
        self.reads.len() + self.writes.len() + self.hosts.len()
    }

    fn walk(&mut self, value: &Value, depth: usize) {
        if depth > MAX_DEPTH || self.count() > MAX_RESOURCES {
            return;
        }
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    self.key(&key.to_ascii_lowercase(), value);
                    self.walk(value, depth + 1);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.walk(item, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn key(&mut self, key: &str, value: &Value) {
        if URL_KEYS.contains(&key) {
            self.hosts.extend(strings(value));
        } else if PATH_KEYS.contains(&key) || key.ends_with("_path") || key.ends_with("_dir") {
            let is_write = self.writes_by_default || matches!(key, "destination" | "target");
            let sink = if is_write {
                &mut self.writes
            } else {
                &mut self.reads
            };
            sink.extend(strings(value));
        }
    }
}

fn strings(value: &Value) -> impl Iterator<Item = String> + '_ {
    let one = value.as_str().map(str::to_owned).into_iter();
    let many = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned);
    one.chain(many).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{MAX_RESOURCES, action};
    use moat_core::Action;
    use serde_json::json;

    fn ok(name: &str, input: &serde_json::Value) -> Action {
        action(name, input).unwrap()
    }

    fn parts(a: Action) -> (Vec<String>, Vec<String>, Vec<String>) {
        match a {
            Action::McpTool {
                reads,
                writes,
                hosts,
                ..
            } => (reads, writes, hosts),
            other => panic!("not an mcp action: {other:?}"),
        }
    }

    #[test]
    fn filesystem_read_tools_yield_reads() {
        let a = ok(
            "mcp__filesystem__read_file",
            &json!({"path": "~/.aws/credentials"}),
        );
        assert_eq!(
            parts(a),
            (vec!["~/.aws/credentials".into()], vec![], vec![])
        );
        let a = ok(
            "mcp__filesystem__read_multiple_files",
            &json!({"paths": ["/p/a", "/p/b"]}),
        );
        assert_eq!(parts(a).0, ["/p/a", "/p/b"]);
    }

    #[test]
    fn write_shaped_tools_and_destinations_yield_writes() {
        let a = ok(
            "mcp__filesystem__write_file",
            &json!({"path": "~/.zshrc", "content": "x"}),
        );
        assert_eq!(parts(a).1, ["~/.zshrc"]);
        let a = ok(
            "mcp__filesystem__move_file",
            &json!({"source": "/p/a", "destination": "/p/b"}),
        );
        let (_, mut writes, _) = parts(a);
        writes.sort();
        assert_eq!(writes, ["/p/a", "/p/b"]);
    }

    #[test]
    fn url_arguments_yield_hosts_and_cursor_strings_are_parsed() {
        let a = ok("mcp__fetch__fetch", &json!({"url": "https://evil.com/x"}));
        assert_eq!(parts(a).2, ["https://evil.com/x"]);
        let a = ok(
            "mcp__fetch__fetch",
            &json!("{\"url\":\"https://evil.com/x\"}"),
        );
        assert_eq!(parts(a).2, ["https://evil.com/x"]);
    }

    #[test]
    fn unrelated_arguments_add_nothing() {
        let a = ok(
            "mcp__github__get_pull_request",
            &json!({"owner": "x", "repo": "y", "number": 42}),
        );
        assert_eq!(a, Action::mcp("mcp__github__get_pull_request"));
    }

    #[test]
    fn nested_arguments_and_bare_hosts_are_found() {
        let a = ok(
            "mcp__custom__run",
            &json!({"options": {"files": [{"path": "~/.ssh/id_rsa"}]}, "endpoint": "intranet:8080"}),
        );
        let (reads, _, hosts) = parts(a);
        assert_eq!(reads, ["~/.ssh/id_rsa"]);
        assert_eq!(
            hosts,
            ["intranet:8080"],
            "a URL argument without a scheme is still a host"
        );
    }

    #[test]
    fn unreadable_arguments_are_errors_not_silence() {
        let err = action("mcp__filesystem__read_file", &json!("{not json")).unwrap_err();
        assert!(
            err.to_string().contains("mcp__filesystem__read_file"),
            "{err}"
        );
        let many: Vec<String> = (0..=MAX_RESOURCES).map(|i| format!("/p/{i}")).collect();
        assert!(action("mcp__fs__read_multiple_files", &json!({"paths": many})).is_err());
    }
}
