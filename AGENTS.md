# Working in this repository

The contract for everyone who changes this code, human or coding agent. Short on
purpose; each section links to the detail. `CLAUDE.md` points here.

## 1. What this is

`moat` is a security kernel for AI agents. It sits between an agent (Claude Code,
Codex, …) and the machine, decides whether each tool call may run, and records it.
The alpha is decide-only: the operating system does not enforce the decision yet
(ADR-013). Correctness and fail-closed behaviour outrank features.
If a change makes you choose, choose `ask` over `allow` and `deny` over a crash.

Specs: `docs/ARCHITECTURE.md` (crates, data flow, hooks, self-protection),
`docs/POLICY.md` (policy semantics), `docs/THREAT_MODEL.md` (threats, known limitations),
`docs/ROADMAP.md` (stages; live order in issue #144), `docs/adr/README.md` (decisions).

## 2. Layout

| Path | Contents | Rules |
|---|---|---|
| `crates/moat-core` | policy model (`policy.rs`, `lint.rs`), lexer (`lexer/`), classifier (`shell/`), patterns (`pattern/`), URL hosts (`host.rs`), paths, engine (session taint in `engine/taint.rs`), policy compiler (`ir/`), executable pins (`programs.rs`, `ProgramResolver`), symlink resolution (`realpath.rs`, `PathResolver`), actions, verdict | **pure**: no I/O, no `unsafe`, no internal deps; builds for `wasm32`; architecture tests enforce it |
| `crates/moat-hosts` | host adapters: `pre_tool_use.rs` (Claude Code, Codex), `config_change.rs` (Claude Code), `cursor.rs`; `mcp.rs` (MCP arguments), `patch.rs` (Codex `apply_patch`) | translate payload ⇄ `Action`/`Decision`; never decide |
| `crates/moat-audit` | SQLite store (`store/`: schema, hash chain, export), time-window and session queries (`query.rs`), redaction (`redact.rs`) | typed `thiserror` errors; redact before persisting; never log secrets |
| `crates/moat-proxy` | egress proxy behind `moat proxy`: `request.rs` (HTTP head), `sni.rs` (ClientHello), `decide.rs` (host and address checks), `upstream.rs` (DNS, connect), `server.rs`, `tunnel.rs`, `audit.rs` (`Recorder` trait), `broker.rs` (secret injection and leak blocking) | network through `std::net` only; no async runtime, no storage; a connection that cannot be recorded is refused |
| `crates/moat-cli` | the `moat` binary: `cli.rs` grammar, `commands/{init,guard,show,status,doctor,allow,replay,report,audit,team,policy,proxy,sandbox}.rs`, `install/{mod,hook_file,binary}.rs`, `sandbox/` (Standard tier: `claude`, `codex` backends from the IR, `install.rs` file I/O), `home.rs`, `context.rs`, `project.rs`, `time.rs`, `environment.rs` (search-path snapshot), `realpath.rs` (symlink resolution), `integrity.rs` (policy lock), `approvals.rs` (grants and overlay), `secrets/` (brokered secret sources), `taint.rs` (session taint from the audit log), `terminal.rs` (terminal check), `render.rs`, `exit.rs` | the only crate that touches files, env, terminal; `anyhow` allowed; all user output goes through `render.rs` or the command module |
| `crates/moat-core/policies/default-v1.yaml` | shipped default policy | every change needs a conformance fixture and a CHANGELOG line |
| `tests/conformance/{attacks,benign,ask}.yaml` | executable security claims | ids unique, one action each, `rules` must appear in the decision; attacks and asks carry `threat: T1…T12`; `docs/COVERAGE.md` is generated from them (`MOAT_UPDATE_COVERAGE=1 cargo test -p moat-core --test conformance`) and every threat needs an attack |
| `tests/fixtures/hosts/<host>/*.json` | real host payloads | golden inputs; never include real tokens or personal paths |
| `tests/fixtures/sandbox/` | generated host sandbox settings for the default policy | golden outputs; `MOAT_UPDATE_GOLDEN=1` rewrites them, review the diff |
| `crates/*/tests/` | end-to-end tests of the binary in one target, `crates/moat-cli/tests/e2e/` (one module per area: `cli`, `guard`, `cursor`, `config_change`, `lock`, `install_path`, `approvals`, `allow`, `audit`, `export`, `team`, `paths`, `replay_report`, `sandbox`, `sandbox_sync`, `sandbox_exec`), conformance runner, architecture invariants | isolated `HOME`/`MOAT_HOME`; no network |
| `docs/` | ARCHITECTURE, POLICY, THREAT_MODEL, ROADMAP, COVERAGE (generated), `adr/` | describe what the code does today; ADRs are immutable, superseded by new ADRs |
| `scripts/ci/quality-gate.sh` | the one gate | CI and the pre-push hook run exactly this |

## 3. Invariants (never break; add a test if you touch one)

1. **Deny is absolute.** An allow rule can never override a deny rule. Kind-wide denial is `defaults: {kind: deny}` (ADR-002).
2. **Strictest wins** across every atomic action one tool call produces.
3. **Unparseable ⇒ ask.** Anything the lexer or classifier cannot understand is `ask`, never `allow`.
4. **Fail closed.** Every error path in `moat guard` yields a `deny` response and exit 2 (ADR-004).
5. **Exit codes:** 0 allow/ok, 2 deny, 3 unresolved ask (`policy check`), 64 usage/config. Nothing else may use 2 or 3.
6. **No secrets in the audit log.** Everything persisted passes `moat_audit::redact`.
7. **Pure core.** `moat-core` depends only on `serde`, `serde_yaml_ng`, `globset`, `thiserror`. Anything that needs the filesystem (program resolution, hashing) is injected from the CLI through a trait (`ProgramResolver`, `PathResolver`).
8. **Idempotent install.** `moat init` never overwrites a policy, never duplicates a hook, always backs up before editing a host file.
9. **Lock before decide.** `moat guard` verifies `policy.lock` first; drift ⇒ `deny` (`kernel-integrity`). A Claude Code `ConfigChange` for a pinned file that no longer matches the lock is blocked for the session. Only a person may re-pin: `moat init`, or `moat doctor --accept` from an interactive terminal.

## 4. Engineering rules

- **Errors:** `thiserror` enums in library crates; `anyhow` with `bail!`/`ensure!`/`.context()` in the CLI. `anyhow!` is banned by clippy. No `unwrap`/`expect` outside tests unless the invariant is stated in a comment.
- **Size:** files ≤ 500 lines (architecture test), functions ≤ 200 lines, cognitive complexity ≤ 30 (clippy). Split by concern: `mod.rs` + one file per responsibility + `tests.rs`.
- **Comments** explain *why* and *what the host/OS does*; names and types explain *what the code does*. No commented-out code, no TODO/FIXME on `main` (open an issue).
- **Platform code** lives in dedicated files/modules selected by `cfg` in one place (`#[cfg(unix)]` helpers in `home.rs`, future `moat-sandbox/{seatbelt,landlock,windows}.rs`); never scatter `cfg` through business logic. Paths are handled in slash-separated canonical form everywhere (`paths.rs`).
- **Dependencies:** adding one needs a sentence in the PR on why std or an existing dep does not cover it; `cargo-deny` must stay green; `moat-core` additions need an ADR.
- **Lints:** workspace `clippy::pedantic`, `unsafe_code = "forbid"`, rustdoc `-D warnings`. Every public item of a library crate has a doc comment (`missing_docs`, enforced in `moat-core`). Do not `#[allow]` to get green; fix or justify in the PR.
- **Formatting:** `cargo fmt` (max width 100). `.editorconfig` for everything else.
- **PR-only:** nothing is pushed to `main` directly. Branch `<type>/<topic>`, open a PR, let `pr-standards` label it (`type: …`, `area: …`, `size: …`, `risk: …`), keep it ≤ 500 lines, squash-merge. Conventional Commits title (`feat`, `fix`, `sec`, `policy`, `host(codex)`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`), lowercase subject. PR body sections **Testing** and **Security impact** are required (`pr-standards` fails without them); **Release note** is recommended and feeds `CHANGELOG.md`.
- **Docs are code:** behaviour change ⇒ same PR updates `docs/POLICY.md` / `ARCHITECTURE.md` / `THREAT_MODEL.md` / `CHANGELOG.md` as applicable.

## 5. Skills (how to do the common jobs)

### Run the gate
```bash
scripts/ci/quality-gate.sh        # fmt, clippy -D warnings, doc, tests, policy lint
```
Claim "done" only after it passes locally. CI runs the same script on macOS (arm64, x64), Linux and Windows.

### Add or change a policy rule
1. Edit `crates/moat-core/policies/default-v1.yaml` (keep rule ids stable; they appear in audit logs and user output).
2. Add fixtures: at least one attack that must be denied/asked and one benign action that must still be allowed, in `tests/conformance/`.
3. If the semantics change (not just a pattern), update `docs/POLICY.md`, and add an ADR if an invariant moves.
4. Add a `### Security` or `### Changed` line to `CHANGELOG.md`.

### Teach the classifier something new (new wrapper, interpreter, write-program, builtin)
The shell classifier is a triage layer, not the security boundary (ADR-013); OS
enforcement is. Under the parser freeze, a newly found bypass gets an attack fixture
and the smallest change that makes it `ask`, not a new grammar or an ADR, unless an
invariant moves. Put the saved time into enforcement (#119, #126).
1. Data goes in `crates/moat-core/src/shell/tables.rs`; behaviour in `commands.rs` or `tokens.rs`.
2. Unit test in `shell/tests/` asserting the atomic actions produced.
3. Conformance fixture showing the end-to-end verdict.
4. Never widen `looks_like_path` or `host_of` without a negative test for the false positive you might introduce.

### Add a host adapter
1. New module in `crates/moat-hosts/src/<host>.rs`; add the variant to `Host` and its `id()`/`display_name()`.
2. Golden payloads in `tests/fixtures/hosts/<host>/`; tests cover every tool kind the host exposes, a malformed payload, and an ungoverned tool.
3. Installer config in `crates/moat-cli/src/install/mod.rs` (settings path, matcher, env override). If the host is fail-open by default, the installer must set its fail-closed flag.
4. End-to-end test in `crates/moat-cli/tests/e2e/guard.rs` running the real binary against the fixture.
5. Document the coverage honestly: the hosts table in `README.md`, `docs/ARCHITECTURE.md` §2–3, and ungoverned tools in `docs/THREAT_MODEL.md` §5.

### Add a CLI command
1. Grammar in `cli.rs` (clap derive, `///` doc on every arg), dispatch in `commands/mod.rs`, implementation in `commands/<name>.rs`.
2. Output through `render.rs`; machine-readable `--format json` for anything a script might consume.
3. Exit codes via `exit::Code` only.
4. End-to-end test in `crates/moat-cli/tests/e2e/cli.rs` using an isolated `HOME`.

### Change the audit schema
Bump `SCHEMA_VERSION` in `store/schema.rs`, add a migration step, keep `Event` deserialisation backward compatible, and add a test that opens a database written by the previous version.

### Record a decision
Copy the shape of `docs/adr/ADR-004-exit-code-contract.md`: Context, Decision, Consequences, status, date. Number sequentially. Never edit an accepted ADR; supersede it.

## 6. Definition of done

- Gate passes locally; CI green on all platforms.
- Tests exist at the level that proves the change (unit, fixture, e2e, architecture).
- Docs and CHANGELOG updated in the same PR.
- PR describes Testing and Security impact.
- No new `allow` outcome was introduced without a fixture that shows it is intended.

## 7. For coding agents specifically

- Do not edit the default policy, a fixture's `expect`, or a test to make a failing check pass; fix the classifier or explain why the expectation was wrong.
- Do not disable lints, delete tests, or add `#[allow]`/`#[ignore]` to get green.
- `moat allow` and `moat doctor --accept` refuse to run without a terminal. End-to-end tests set `MOAT_ASSUME_TTY=1`, which only debug builds honour (`crates/moat-cli/src/terminal.rs`); never add another way around the terminal check.
- Do not run `moat init` against the real `~/.claude` of a machine where a Claude Code session is active; use `MOAT_HOME`, `CLAUDE_CONFIG_DIR` and a scratch project, and run every `moat` command with the same `CLAUDE_CONFIG_DIR` (README "Non-default config directories").
- Never commit credentials, real host payloads with tokens, or personal absolute paths.
- Prefer small PRs: one concern, one title, ≤ 500 lines. Never push to `main`; never merge your own PR while a required check is red.
- `moat-reviewer` posts an automated first-pass review on every PR (inline `🔴/🟠/🟡/💡` comments and a summary). Resolve or answer each 🔴 and 🟠 item before asking a maintainer to review; it is advisory and does not replace that review.
