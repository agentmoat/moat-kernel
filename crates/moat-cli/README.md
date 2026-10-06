# moat-kernel (binary: `moat`)

The command-line kernel. This crate owns all I/O: files, environment, terminal,
host configuration. Decisions come from `moat-core`.

| Command | Purpose |
|---|---|
| `moat init [--hosts …] [--dry-run]` | create `~/.moat`, write the default policy, create the audit log, install hooks idempotently |
| `moat guard --host <id>` | hook entry point: payload on stdin, decision on stdout; fail-closed |
| `moat show [<id> \| --session <id> \| --recent N] [--format json]` | inspect audit events |
| `moat replay [--since 24h \| --session <id>] [--host …] [--format json]` | per-session timeline of decisions |
| `moat report [--since 7d] [--host …] [--format json]` | verdict totals, sessions, hosts, top ask/deny rules, asks per active hour |
| `moat status` | policy hash and counts, lock state, hook health per host, recent events; exit 64 when unhealthy |
| `moat allow [--last \| <command> --host … --session …] [--always]` | grant one command to a session, or add a permanent allow rule (terminal only) |
| `moat doctor [--accept]` | verify state dir, policy, lock, hooks, binary, audit; `--accept` re-pins (terminal only) |
| `moat policy lint [file]` | validate a policy |
| `moat policy check <action> [--kind …] [--policy …]` | explain a decision |
| `moat policy compile [--policy …] [--format json]` | print what OS layers enforce (the compiled IR) and its losses |

Exit codes are a contract (ADR-004): 0 allow/ok, 2 deny, 3 unresolved ask,
64 usage or configuration error.

Environment: `MOAT_HOME` (state directory, default `~/.moat`), `CLAUDE_CONFIG_DIR`,
`CODEX_HOME`, `CURSOR_CONFIG_DIR` (host configuration directories).
