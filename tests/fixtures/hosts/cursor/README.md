# Cursor hook payloads

What each fixture is based on, so a guess is never mistaken for a capture.

| Fixture | Source |
|---|---|
| `preToolUse-shell-3.13.json` | Shape of a real Cursor 3.13.25 `preToolUse` payload posted in <https://forum.cursor.com/t/inconsistent-hook-payload/166997> (values replaced): top-level `cwd` may be empty, `tool_input` carries `cwd`, not the documented `working_directory`. |
| `preToolUse-*.json`, `before*.json` | Field names from <https://cursor.com/docs/hooks> (common fields, `beforeReadFile` `file_path`, `preToolUse` `tool_name`/`tool_input`/`tool_use_id`/`cwd`). |

## Not verified (#138)

As of 2026-10, <https://cursor.com/docs/hooks> lists the `preToolUse` matcher tool
names as `Shell`, `Read`, `Write`, `Grep`, `Delete`, `Task` and `MCP:<tool>`. It gives no
`tool_input` for any tool but `Shell`. So:

- `Grep`'s `path` key and `Read`/`Write`/`Delete`'s `file_path` key are assumptions,
  the same keys Claude Code uses. `preToolUse-grep.json` and `preToolUse-write.json`
  are not captures.
- `Glob`, `Edit`, `MultiEdit` and `StrReplace` are not named in the docs. The adapter
  maps them in case a build sends them.
- A Grep with no `path` is read as a search of `cwd`, else the first workspace root.
  If Cursor names the directory under another key, that key is ignored.

Replace these fixtures with a captured payload once one is available.
