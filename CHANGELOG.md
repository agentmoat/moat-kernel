# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- `moat guard` denies (`kernel-error`, exit 2) when the audit log cannot be opened or written, when the hook response cannot be written to stdout, or when the kernel itself panics; previously an unavailable log printed a warning and the call proceeded unrecorded, and a panic exited 101, which Claude Code treats as non-blocking. `guard` no longer recreates a deleted `audit.db`; only `moat init` creates it.
- Policy lock: a pinned file replaced by a symlink (or a re-pointed link) is now reported as modified and denies with `kernel-integrity`; previously the swapped file was treated as unpinned and the kernel ran under the attacker's policy.
- Shell classification: tokens that traverse (`src/../x`) or name a hidden entry (`.env`, `config/.env.local`, `.ssh/id_rsa`) are now treated as paths, so `cat .env` and `cat src/../../.ssh/id_rsa` produce file-read atoms and hit `secrets-paths`; previously only tokens starting with `/`, `~`, `./` or `../` did and such commands were allowed by `dev-shell`.

### Added
- Policy engine: schema v1 with `deny → allow → ask → defaults` evaluation, per-kind defaults, absolute deny, strictest-wins across atomic actions.
- Shell classification: POSIX lexer (quotes, escapes, redirects, `$(…)`, backticks, here-documents), sub-commands, subshells, `eval`, `sh -c`, wrappers, inline interpreters, environment reads/sets, path and host extraction.
- Host adapters for Claude Code and Codex `PreToolUse` hooks, and for Cursor (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`; `moat init` writes a fail-closed `~/.cursor/hooks.json`).
- Audit log in SQLite (WAL) with credential redaction; `moat show`, `moat status`, `moat replay` (per-session timeline) and `moat report` (verdict totals, hosts, top rules, asks per active hour).
- `moat init` (policy, audit log, idempotent hook installation), `moat guard` (fail-closed), `moat policy lint|check`.
- Default policy v1 and 83 conformance fixtures.

### Added (self-protection)
- `policy.lock`: `moat init` pins SHA-256 digests of the policy and every installed host hook file; `moat guard` verifies them on every call and denies everything with rule `kernel-integrity` when a pinned file changed or disappeared.
- `moat status` reports lock state; re-running `moat init` re-pins.
- Claude Code `ConfigChange` hook: when a settings file pinned by the lock is edited or deleted outside `moat`, the change is refused for the running session (rule `kernel-integrity`); unpinned settings files load and are audited.
- Executable pinning: `moat init` snapshots the search path and the location of common programs in `~/.moat/environment.json` (pinned by the lock); `moat guard` resolves every shell command's program through the snapshot and denies pinned programs that resolve elsewhere (rule `executables`). Policy `executables:` pins are now enforced.
- Approvals: `moat allow --last` (or `moat allow <command> --host … --session …`) grants one exact command to one host session; `moat allow … --always` appends a permanent allow rule to `~/.moat/policy.d/approved.yaml`, merged into the policy at load. Both files are pinned by the lock; `moat allow` is terminal-only and denied to agents by the default policy.
- `moat doctor [--accept]`: verifies state directory, policy, lock, hooks, binary path and audit log; `--accept` re-pins and is refused outside an interactive terminal.

### Changed
- Project standards: `AGENTS.md` contract, CONTRIBUTING, SECURITY, Code of Conduct, pinned-SHA workflows, Conventional Commits PR titles, Dependabot, CODEOWNERS, issue forms, PR template, single quality-gate script, clippy thresholds, rustdoc `-D warnings`, architecture tests, ADR-001…004.
- Dependencies: rusqlite 0.40, sha2 0.11, actions/checkout v7.0.1, action-semantic-pull-request v6.1.1.
- Windows: canonical slash-separated paths keep `C:/` and UNC roots.

### Security
- Exit code 2 is reserved for `deny`; usage errors use 64 so a host never mistakes a crash for a block.
- Secret paths are protected against writes as well as reads.
