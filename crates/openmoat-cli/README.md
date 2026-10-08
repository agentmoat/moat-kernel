# openmoat (binary: `moat`)

The command-line tool of [OpenMoat](https://github.com/crocodile-labs/openmoat):
it checks the tool calls Claude Code, Codex and Cursor report through their hooks
against one policy
(allow, ask or deny), configures Claude Code's and Codex's own sandboxes from that
policy, and keeps a local, tamper-evident audit log. This crate owns all I/O: files,
environment, terminal, host configuration. Decisions come from `openmoat-core`.

```bash
cargo install openmoat --locked --version 0.1.0-alpha.6   # pre-releases install only by version
moat init      # policy, lock, audit log, and hooks for every agent found on this machine
moat status
```

Installers, Homebrew and the full guide: the
[project README](https://github.com/crocodile-labs/openmoat#readme).

| Command | Purpose |
|---|---|
| `moat init [--hosts …] [--dry-run]` | create `~/.moat`, write the default policy, create the audit log, install hooks idempotently, configure the host sandboxes |
| `moat status` · `moat doctor [--accept]` | installation health (exit 64 when unhealthy) · verify and re-pin (terminal only) |
| `moat show [<id> \| --session <id> \| --since … \| --recent N]` | inspect audit events |
| `moat replay` · `moat report` | per-session timeline · verdict totals, hosts, top rules, asks per active hour |
| `moat audit export \| verify \| report` | export the log as JSON Lines with chain hashes, verify an export, report over several machines |
| `moat allow [--last \| <command> --host … --session …] [--always]` | grant one command to a session, or add a permanent allow rule (terminal only) |
| `moat trust [<repo>] [--revoke]` | let a repository's `.moat/policy.yaml` allow, until the file changes (terminal only) |
| `moat policy lint \| check \| compile` | validate a policy · explain a decision · print what OS layers enforce |
| `moat sandbox show \| sync` | the host sandbox settings the policy compiles to · write and re-pin them |
| `moat run [--write PATH]… -- <agent> [args]` | run an agent in a sandbox generated from the policy (macOS, Linux) |
| `moat proxy [--listen 127.0.0.1:<port>]` | run the default-deny egress proxy |
| `moat guard --host <id>` | hook entry point: payload on stdin, decision on stdout; fail-closed |

Exit codes are a contract (ADR-004): 0 allow/ok, 1 the agent `moat run` started
exited non-zero, 2 deny, 3 unresolved ask, 64 usage or configuration error.

Environment: `MOAT_HOME` (state directory, default `~/.moat`), `CLAUDE_CONFIG_DIR`,
`CODEX_HOME`, `CURSOR_CONFIG_DIR` (host configuration directories).
