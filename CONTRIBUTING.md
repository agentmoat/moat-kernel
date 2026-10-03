# Contributing to moat

Thank you for helping build the kernel AI agents run on. This file is short on
purpose; the detail lives in `docs/`.

## Before you start

- Read `AGENTS.md` (the contract for humans and coding agents working here) and
  `docs/DESIGN.md` §6–7 if you touch policy or shell classification.
- Security-relevant findings go through a private advisory, never a public issue.
  See `SECURITY.md`.

## Setup

```bash
git clone https://github.com/agentmoat/moat-kernel && cd moat-kernel
git config core.hooksPath .githooks        # runs the quality gate before every push
scripts/ci/quality-gate.sh                 # fmt, clippy -D warnings, doc, tests, policy lint
```

Rust 1.95 (pinned in `rust-toolchain.toml`). No other tooling is required.

## Making a change

1. Open an issue first for anything that changes what an agent is allowed to do.
2. Branch from `main`; keep the PR to one concern.
3. Behaviour changes come with tests at the right level:
   - unit tests next to the code (`#[cfg(test)]`),
   - conformance fixtures in `tests/conformance/` for every rule or parser change,
   - end-to-end tests in `crates/moat-cli/tests/` for CLI and hook behaviour,
   - architecture tests (`crates/*/tests/architecture.rs`) when crate boundaries move.
4. Run `scripts/ci/quality-gate.sh`. CI runs the same script on macOS, Linux and Windows.
5. Fill in the PR template: **Testing** and **Security impact** are required sections.

## Conventions

- Commit and PR titles follow Conventional Commits:
  `feat`, `fix`, `sec`, `policy`, `host(claude-code)`, `docs`, `test`, `refactor`, `ci`, `build`, `chore`.
  Squash-merge; the PR title becomes the commit.
- Library crates (`moat-core`, `moat-hosts`, `moat-audit`) use typed `thiserror`
  errors and never print. `anyhow` and terminal output live only in `moat-cli`.
- `moat-core` has no I/O, no `unsafe`, and no internal dependencies; CI builds it
  for `wasm32` to prove it.
- Files stay under 500 lines; functions under 200 (clippy enforces the latter).
- Comments explain *why*. Code says *what*.
- A new dependency needs a sentence in the PR on why the standard library or an
  existing dependency does not cover it. `cargo-deny` checks licences and advisories.

## Decisions

Non-obvious decisions are recorded as ADRs in `docs/adr/`. Propose one in the PR
when you change an invariant (policy semantics, exit codes, crate boundaries).

## Governance

Single maintainer during v0.x. CODEOWNERS routes review; the trusted core, the
default policy and CI require maintainer approval. A maintainer team and a public
roadmap board follow with v0.2.

## License

By contributing you agree your work is licensed under MIT or Apache-2.0, at the
user's option, like the rest of the project. No CLA.
