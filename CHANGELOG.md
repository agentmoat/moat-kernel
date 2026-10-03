# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Policy engine: schema v1 with `deny → allow → ask → defaults` evaluation, per-kind defaults, absolute deny, strictest-wins across atomic actions.
- Shell classification: POSIX lexer (quotes, escapes, redirects, `$(…)`, backticks, here-documents), sub-commands, subshells, `eval`, `sh -c`, wrappers, inline interpreters, environment reads/sets, path and host extraction.
- Host adapters for Claude Code and Codex `PreToolUse` hooks.
- Audit log in SQLite (WAL) with credential redaction; `moat show` and `moat status`.
- `moat init` (policy, audit log, idempotent hook installation), `moat guard` (fail-closed), `moat policy lint|check`.
- Default policy v1 and 83 conformance fixtures.

### Added (self-protection)
- `policy.lock`: `moat init` pins SHA-256 digests of the policy and every installed host hook file; `moat guard` verifies them on every call and denies everything with rule `kernel-integrity` when a pinned file changed or disappeared.
- `moat status` reports lock state; re-running `moat init` re-pins.

### Changed
- Project standards: `AGENTS.md` contract, CONTRIBUTING, SECURITY, Code of Conduct, pinned-SHA workflows, Conventional Commits PR titles, Dependabot, CODEOWNERS, issue forms, PR template, single quality-gate script, clippy thresholds, rustdoc `-D warnings`, architecture tests, ADR-001…004.
- Dependencies: rusqlite 0.40, sha2 0.11, actions/checkout v7.0.1, action-semantic-pull-request v6.1.1.
- Windows: canonical slash-separated paths keep `C:/` and UNC roots.

### Security
- Exit code 2 is reserved for `deny`; usage errors use 64 so a host never mistakes a crash for a block.
- Secret paths are protected against writes as well as reads.
