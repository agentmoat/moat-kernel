# Working in this repository

Read this first, whether you are a person or a coding agent.

## What this is

`moat` is a security kernel for AI agents: it decides, enforces and records what
agent tool calls may do on a machine. Correctness and fail-closed behaviour matter
more than features. When in doubt, the safe answer is `ask`, never `allow`.

## Layout

| Path | Contents | Rules |
|---|---|---|
| `crates/moat-core` | policy model, shell lexer/classifier, decision engine | pure: no I/O, no `unsafe`, no internal deps; builds for wasm32 |
| `crates/moat-hosts` | host hook adapters (Claude Code, Codex) | translate only; never decide |
| `crates/moat-audit` | SQLite audit log, redaction | typed errors; redact before persisting |
| `crates/moat-cli` | the `moat` binary | the only crate that touches files, env, terminal; `anyhow` allowed |
| `policies/` | default policy | every change needs a conformance fixture |
| `tests/conformance/` | attack / benign / ask fixtures | executable security claims |
| `tests/fixtures/hosts/` | real host payloads | golden inputs for adapters |
| `docs/` | OVERVIEW, DESIGN, STRENGTH, TECH_STACK, REPO_STRUCTURE, PROGRESS, `adr/` | design is the spec |

## Invariants (do not break)

- Deny is absolute: an allow rule can never override a deny rule.
- Strictest verdict wins across everything one tool call touches.
- Unparseable input is `ask`.
- Every error path in `moat guard` produces `deny` and exit code 2.
- Exit codes: 0 allow/ok, 2 deny, 3 unresolved ask, 64 usage or configuration error.
- Secrets are never written to the audit log.
- `moat-core` stays dependency-light and I/O-free.

## Workflow

```bash
scripts/ci/quality-gate.sh     # fmt, clippy -D warnings, doc, tests, policy lint — same as CI
```

- Add tests at the level that proves the change (unit, conformance fixture, e2e).
- Keep files under 500 lines and functions under 200; split by concern, not by size alone.
- Comments explain why; names and types explain what. No TODO/FIXME left in `main`.
- Conventional Commits for titles. One concern per PR. Fill in Testing and Security impact.
- Do not add dependencies, change exit codes, or change policy semantics without an ADR in `docs/adr/`.

## For coding agents specifically

- Do not edit `policies/default-v1.yaml` to make a failing fixture pass; fix the classifier or the fixture.
- Do not disable lints or tests to get green.
- Never commit credentials, host payloads containing real tokens, or personal paths.
