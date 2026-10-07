# Contributing to OpenMoat

Thank you for helping build the kernel AI agents run on. This file is short on
purpose; the detail lives in `docs/`.

## Before you start

- Read `AGENTS.md` (the contract for humans and coding agents working here) and
  `docs/POLICY.md` and `docs/ARCHITECTURE.md` §3–4 if you touch policy or shell
  classification.
- To support another AI coding agent, follow `docs/ADDING_AN_AGENT.md`.
- Security-relevant findings go through a private advisory, never a public issue.
  See `SECURITY.md`.
- A safe command the default policy denies or asks about is a *false positive*: open an
  issue with the false-positive form and paste `moat policy check` output. A dangerous
  command it allows is a vulnerability: report it privately.
- Changes to semantics, invariants or crate boundaries start as a design proposal issue
  and land with an ADR.

## Setup

```bash
git clone https://github.com/crocodile-labs/openmoat && cd openmoat
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
   - end-to-end tests in `crates/openmoat-cli/tests/` for CLI and hook behaviour,
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
`openmoat-core builds for wasm32 (no I/O)`, `cargo-deny`, `crates package and build from
their tarballs`, `workflows (actionlint, zizmor)`, `conventional` (title) and
`labels · size · risk · body` (pr-standards). The branch must be up to date with `main`
(strict checks), so rebase before merging. `fuzz (smoke)` and `latency` run on every PR
but are not required: a fuzz finding or a noisy runner should not block an unrelated
change, so read them before merging. The PR body must have non-empty **Testing** and
**Security impact** sections. CODEOWNERS requests the maintainer's review on `risk:
high` paths; with one maintainer it is not enforced by the ruleset (two-maintainer
review is a v1.0 item). Squash-merge; the PR title becomes the commit subject and the
**Release note** line feeds `CHANGELOG.md`.

Release tags (`v*`) can only be created, moved or deleted by repository admins (the
`release tags` ruleset), because pushing one starts the release workflow. Publishing to
crates.io additionally waits for approval on the `release` environment.

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
- Library crates (`openmoat-core`, `openmoat-hosts`, `openmoat-audit`) use typed `thiserror`
  errors and never print. `anyhow` and terminal output live only in `openmoat-cli`.
- `openmoat-core` has no I/O, no `unsafe`, and no internal dependencies; CI builds it
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

## Releasing

`.github/workflows/release.yml` is driven by [dist](https://opensource.axo.dev/cargo-dist/)
(config in `dist-workspace.toml`). A `v*` tag builds the seven targets, writes the shell and
PowerShell installers, the Homebrew formula and `sha256.sum`, attests every file, creates
the GitHub release, pushes `Formula/moat.rb` to `crocodile-labs/homebrew-tap` and, after an owner
approves the `release` environment, publishes the crates to crates.io. Pull requests that
touch the manifests or the workflow run `dist plan` only. Running the workflow by hand
(Actions → release → Run workflow) is a dry run: it builds every target and publishes nothing.

1. Dry-run the workflow on `main` if the build changed since the last release.
2. In a PR (`build: release vX.Y.Z-alpha.N`): bump `version` in `[workspace.package]` and
   the four `openmoat-*` entries of `[workspace.dependencies]` in `Cargo.toml`, run
   `cargo check` to update `Cargo.lock`, move the `[Unreleased]` entries of `CHANGELOG.md`
   under `## [X.Y.Z-alpha.N] - YYYY-MM-DD`, and update the version in the README install
   commands and in `crates/openmoat-cli/README.md`. The release fails without that
   CHANGELOG section; its text becomes the release notes, after a line saying what the
   operating system does and does not enforce (ADR-013). For the first release, also
   drop the "not yet released" wording: the README status note and the first paragraph
   of its Install section, `docs/ROADMAP.md` "Where it is today", and the supported
   versions note in `SECURITY.md`.
3. After the merge, tag the merge commit: `git tag -s vX.Y.Z-alpha.N -m vX.Y.Z-alpha.N`
   and `git push origin vX.Y.Z-alpha.N`.
4. Check the GitHub release and the tap commit, then approve the `release` environment in
   the workflow run; `publish-crates` publishes openmoat-core, then openmoat-hosts,
   openmoat-audit and openmoat-proxy, then openmoat.

The first crates.io publish is manual, because trusted publishing can only be configured
for a crate that exists. Reject the `release` deployment in the workflow run, then:

1. On crates.io (account with a verified email), create an API token that expires in a
   day, with the scopes `publish-new` and `publish-update` and the crate pattern
   `openmoat*`.
2. From a clean checkout of the tag:

   ```bash
   git checkout vX.Y.Z-alpha.N
   cargo login                                   # paste the token
   cargo publish --locked --workspace --dry-run
   cargo publish --locked --workspace            # openmoat-core, then openmoat-hosts,
                                                 # openmoat-audit, openmoat-proxy, then openmoat
   ```

   If it stops halfway, publish the rest one by one in that order with
   `cargo publish --locked -p <crate>`; a published version cannot be replaced.
3. For each of the five crates, open Settings → Trusted Publishing on crates.io and add a
   GitHub publisher: owner `crocodile-labs`, repository `openmoat`, workflow `release.yml`,
   environment `release`.
4. Revoke the token on crates.io and run `cargo logout`.

Later releases need no crates.io token: `publish-crates` exchanges the workflow's OIDC
token after the `release` environment is approved.

One-time repository setup: a `release` environment with the maintainer as required
reviewer and deployments limited to `v*` tags, and `HOMEBREW_TAP_TOKEN`, a fine-grained
token with contents write on `crocodile-labs/homebrew-tap` only (the tap needs one commit).

## Decisions

Non-obvious decisions are recorded as ADRs in `docs/adr/`. Propose one in the PR
when you change an invariant (policy semantics, exit codes, crate boundaries).

A shell-classifier bypass is not such a decision. The classifier triages; OS
enforcement is the boundary (ADR-013). Report the bypass, add an attack fixture, and
make the smallest change that turns it into `ask`.

## Governance

Single maintainer during v0.x. CODEOWNERS routes review; the trusted core, the
default policy and CI require maintainer approval. A maintainer team and a public
roadmap board follow with v0.2.

## License

By contributing you agree your work is licensed under MIT or Apache-2.0, at the
user's option, like the rest of the project. No CLA.
