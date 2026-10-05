//! Derive the files and hosts an MCP call touches from its arguments.
//!
//! Servers are not standardised, so this is key-based: arguments named like a
//! path become `fs.read` (or `fs.write` for write-shaped tools), arguments named
//! like a URL become `net`. Unknown shapes add nothing and the call is judged by
//! its name alone, exactly as before. Adding resources can only make a verdict
//! stricter.

use moat_core::Action;
use serde_json::Value;

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

/// Build the action for `mcp__<server>__<tool>` from the host's `tool_input`.
/// Cursor sends the input as a JSON string, Claude Code as an object.
#[must_use]
pub fn action(name: &str, input: &Value) -> Action {
    let parsed;
    let args = match input {
        Value::String(text) => {
            parsed = serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
            &parsed
        }
        other => other,
    };
    let tool = name
        .rsplit("__")
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let writes_by_default = WRITE_TOOL_PREFIXES.iter().any(|p| tool.starts_with(p));

    let mut reads = Vec::new();
    let mut writes = Vec::new();
    let mut hosts = Vec::new();
    for (key, value) in args.as_object().into_iter().flatten() {
        let key = key.to_ascii_lowercase();
        if URL_KEYS.contains(&key.as_str()) {
            hosts.extend(strings(value).filter(|v| v.contains("://")));
        } else if PATH_KEYS.contains(&key.as_str())
            || key.ends_with("_path")
            || key.ends_with("_dir")
        {
            let is_write = writes_by_default || matches!(key.as_str(), "destination" | "target");
            let sink = if is_write { &mut writes } else { &mut reads };
            sink.extend(strings(value));
        }
    }
    Action::McpTool {
        name: name.to_owned(),
        reads,
        writes,
        hosts,
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
    use super::action;
    use moat_core::Action;
    use serde_json::json;

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
        let a = action(
            "mcp__filesystem__read_file",
            &json!({"path": "~/.aws/credentials"}),
        );
        assert_eq!(
            parts(a),
            (vec!["~/.aws/credentials".into()], vec![], vec![])
        );
        let a = action(
            "mcp__filesystem__read_multiple_files",
            &json!({"paths": ["/p/a", "/p/b"]}),
        );
        assert_eq!(parts(a).0, ["/p/a", "/p/b"]);
    }

    #[test]
    fn write_shaped_tools_and_destinations_yield_writes() {
        let a = action(
            "mcp__filesystem__write_file",
            &json!({"path": "~/.zshrc", "content": "x"}),
        );
        assert_eq!(parts(a).1, ["~/.zshrc"]);
        let a = action(
            "mcp__filesystem__move_file",
            &json!({"source": "/p/a", "destination": "/p/b"}),
        );
        let (_, mut writes, _) = parts(a);
        writes.sort();
        assert_eq!(writes, ["/p/a", "/p/b"]);
    }

    #[test]
    fn url_arguments_yield_hosts_and_cursor_strings_are_parsed() {
        let a = action("mcp__fetch__fetch", &json!({"url": "https://evil.com/x"}));
        assert_eq!(parts(a).2, ["https://evil.com/x"]);
        let a = action(
            "mcp__fetch__fetch",
            &json!("{\"url\":\"https://evil.com/x\"}"),
        );
        assert_eq!(parts(a).2, ["https://evil.com/x"]);
    }

    #[test]
    fn unrelated_arguments_add_nothing() {
        let a = action(
            "mcp__github__get_pull_request",
            &json!({"owner": "x", "repo": "y", "number": 42}),
        );
        assert_eq!(a, Action::mcp("mcp__github__get_pull_request"));
    }
}
