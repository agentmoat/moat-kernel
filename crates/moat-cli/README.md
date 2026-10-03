# moat-kernel (binary: `moat`)

The command-line kernel. This crate owns all I/O: files, environment, terminal,
host configuration. Decisions come from `moat-core`.

| Command | Purpose |
|---|---|
| `moat init [--hosts …] [--dry-run]` | create `~/.moat`, write the default policy, create the audit log, install hooks idempotently |
| `moat guard --host <id>` | hook entry point: payload on stdin, decision on stdout; fail-closed |
| `moat show [<id> \| --session <id> \| --recent N] [--format json]` | inspect audit events |
| `moat status` | policy hash and counts, lock state, hook health per host, recent events; exit 64 when unhealthy |
| `moat doctor [--accept]` | verify state dir, policy, lock, hooks, binary, audit; `--accept` re-pins (terminal only) |
| `moat policy lint [file]` | validate a policy |
| `moat policy check <action> [--kind …] [--policy …]` | explain a decision |

Exit codes are a contract (ADR-004): 0 allow/ok, 2 deny, 3 unresolved ask,
64 usage or configuration error.

Environment: `MOAT_HOME` (state directory, default `~/.moat`), `CLAUDE_CONFIG_DIR`,
`CODEX_HOME` (host configuration directories).
