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

Every change lands through a pull request, including maintainers' own work; nothing
is pushed to `main` directly.

1. Open an issue first for anything that changes what an agent is allowed to do.
2. Branch from `main` as `<type>/<short-topic>` (for example `feat/doctor-command`,
   `fix/windows-paths`); keep the PR to one concern and under 500 changed lines.
   Larger changes are split into a stack of PRs or justified with the `size: override` label.
3. Behaviour changes come with tests at the right level:
   - unit tests next to the code (`#[cfg(test)]`),
   - conformance fixtures in `tests/conformance/` for every rule or parser change,
   - end-to-end tests in `crates/moat-cli/tests/` for CLI and hook behaviour,
   - architecture tests (`crates/*/tests/architecture.rs`) when crate boundaries move.
4. Run `scripts/ci/quality-gate.sh`. CI runs the same script on macOS, Linux and Windows.
5. Fill in the PR template: **Testing** and **Security impact** are required sections.

## Pull request standards

`pr-standards.yml` labels every PR and fails it when the standards are not met:

| Label group | How it is set | Meaning |
|---|---|---|
| `type: *` | from the Conventional Commits title | what kind of change |
| `area: *` | from changed paths | `core`, `hosts`, `audit`, `cli`, `policy`, `ci`, `docs`, `deps` |
| `size: *` | additions + deletions | `XS` ≤ 10 · `S` ≤ 50 · `M` ≤ 200 · `L` ≤ 500 · `XL` fails without `size: override` |
| `risk: *` | from changed paths | `high`: engine, lexer/classifier, policy, guard, exit codes, workflows, SECURITY · `medium`: adapters, install, audit · `low`: the rest |
| `needs: fixture` | core or policy changed without `tests/conformance/` | add a fixture |

Checks that must pass before merge (enforced by the `main` ruleset; names as shown on the
PR): `macos-14`, `macos-15-intel`, `ubuntu-latest`, `windows-latest` (the quality gate),
`moat-core builds for wasm32 (no I/O)`, `cargo-deny`, `conventional` (title) and
`labels · size · risk · body` (pr-standards). The PR body must have
non-empty **Testing** and **Security impact** sections. `risk: high` PRs need
maintainer review (CODEOWNERS). Squash-merge; the PR title becomes the commit subject
and the **Release note** line feeds `CHANGELOG.md`.

Labels are defined in `scripts/ci/sync-labels.sh`; edit that script, not the GitHub UI.

Every pull request also gets a first-pass review from `moat-reviewer`, an automated
reviewer that checks the diff against `AGENTS.md` and posts inline comments tagged
`🔴 blocker` · `🟠 should fix` · `🟡 nit` · `💡 idea` plus one summary per revision. It is
advisory: address or answer its 🔴/🟠 items, push back in a reply when it is wrong, and
expect a maintainer to make the final call. Comment `@moat-reviewer` to run it again
(this is also how maintainers trigger it on fork PRs). Details and setup:
`.github/moat-reviewer/README.md`.

## AI-assisted contributions

Built with Claude Code, Codex, Cursor, OpenClaw or any other tool? Welcome. No disclosure,
label or attribution is required, and none is forbidden; commit trailers and PR footers are
your choice. The bar is the same for every change: you have read and understood what you
are submitting, you ran the quality gate, the Testing and Security impact sections are
true, and you can answer review questions about it. Keep PR descriptions the size a
reviewer can read; a generated wall of text is a reason to ask for a rewrite, not a merit.
`AGENTS.md` is written for coding agents as much as for people; point your tool at it.

## Conventions

- Commit and PR titles follow Conventional Commits:
  `feat`, `fix`, `sec`, `policy`, `host(claude-code)`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
  Squash-merge; the PR title becomes the commit.
- Library crates (`moat-core`, `moat-hosts`, `moat-audit`) use typed `thiserror`
  errors and never print. `anyhow` and terminal output live only in `moat-cli`.
- `moat-core` has no I/O, no `unsafe`, and no internal dependencies; CI builds it
  for `wasm32` to prove it.
- Files stay under 500 lines; functions under 200 (clippy enforces the latter).
- Comments explain *why*. Code says *what*.
- A new dependency needs a sentence in the PR on why the standard library or an
  existing dependency does not cover it. `cargo-deny` checks licences and advisories.
- Workflows pin every action to a commit SHA, check out with `persist-credentials: false`,
  pass expressions to `run:` blocks through `env:`, and give tokens only the permissions
  they use. CI runs `actionlint` and `zizmor` on `.github/workflows/`.

## Fuzzing

`fuzz/` holds `cargo fuzz` targets for every surface that takes untrusted input:
`decide_shell` (any command line through the lexer, classifier and engine),
`policy_parse` (any policy file), `host_payload` (any hook payload, every host) and
`literal_pattern` (`moat allow --always` must produce a rule that lints and matches its
command). It is a separate workspace built with nightly:

```bash
cargo install cargo-fuzz --version 0.13.1 --locked
python3 fuzz/seed_corpus.py          # seeds from the conformance fixtures and host payloads
cd fuzz && cargo fuzz run -O decide_shell corpus/decide_shell   # fuzz/rust-toolchain.toml selects the pinned nightly
```

CI runs each target for a minute on pull requests and ten minutes in the weekly run. A
crash becomes a unit test or fixture next to the fix.

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
