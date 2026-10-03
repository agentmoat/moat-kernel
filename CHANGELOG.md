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

### Security
- Exit code 2 is reserved for `deny`; usage errors use 64 so a host never mistakes a crash for a block.
- Secret paths are protected against writes as well as reads.
