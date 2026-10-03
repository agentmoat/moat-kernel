# agentmoat — Progress and Next Steps

Updated: 2026-10-03. Plan of record: `DESIGN.md` §10 (v0.1 spec),
`STRENGTH.md` §3 (benchmark gate), `REPO_STRUCTURE.md` (layout and conventions).

## 1. Where we are in one line

The kernel decides and records: Claude Code and Codex tool calls pass through
`moat guard`, are evaluated against a committed policy, blocked with a rule id and
reason when dangerous, and written to a redacted local audit log. OS enforcement
(`moat exec`), self-protection, Cursor/OpenClaw and the public benchmark are not
built yet.

## 2. Completed

### 2.1 Decisions and documents (`docs/`)
| Item | Status |
|---|---|
| Product direction: security kernel, not an assistant (`OVERVIEW.md`) | done |
| Threat model T1–T12 with real 2026 incidents; verified hook formats for Claude Code, Codex, Cursor, OpenClaw (`DESIGN.md` §3–4) | done |
| Policy semantics: deny → allow → ask → per-kind defaults, deny absolute, strictest wins (`DESIGN.md` §6) | done, enforced by tests |
| Strength plan: five layers, MoatBench, release gates (`STRENGTH.md`) | done |
| Language decision Rust, scored (`TECH_STACK.md`) | done |
| Monorepo layout, crate rules, CI/release conventions (`REPO_STRUCTURE.md`) | done |

### 2.2 Code (`crates/`)
| Crate | Delivered | Evidence |
|---|---|---|
| `moat-core` | Policy schema v1 + loader + lint (duplicate ids, empty rules, bad globs, unknown keys, version). Own POSIX shell lexer: quotes, escapes, line continuation, comments, unspaced operators, redirects with descriptors, `$( … )`/backticks, here-documents as data, 64 KB limit. Classifier: sub-commands, subshells, `eval`, `sh -c` nesting, wrappers (`sudo`, `env`, `xargs`, `timeout`, `nohup`, …), inline interpreters (`python -c`, `node -e`, …), env set/read, path read/write detection (`cp`/`scp` destination, `sed -i`, `dd of=`, `tee`, redirects), host/IP detection, depth and size limits. Engine with `CompiledPolicy::decide` (compile once), pipeline-aware shell rules (`curl * \| sh`), per-kind defaults, negated allow globs, unparseable ⇒ `ask`. | 32 unit tests, 83 conformance fixtures, builds for `wasm32` (no I/O), `#![forbid(unsafe_code)]` |
| `moat-hosts` | `PreToolUse` adapter for Claude Code and Codex: tool → action mapping, ungoverned tools, malformed payload errors, response document, `reason_line`. | 8 tests on golden payloads in `tests/fixtures/hosts/` |
| `moat-audit` | SQLite WAL store (busy timeout, schema version, 0600), `record`/`get`/`recent`/`session`/`count`, hex event ids. Redaction before storage: bearer/basic auth, `key=value` credentials, GitHub/OpenAI/AWS/Slack/Google/npm/GitLab/JWT token shapes, URL passwords; idempotent. | 10 tests |
| `moat-cli` (`moat`) | `init` (state dir 0700, default policy never overwritten, audit db, hook install for present hosts; idempotent, backup, atomic write, `--dry-run`, `--hosts`), `guard --host` (stdin → decision → host JSON; fail-closed `deny` on any error; git-root project detection; trace id on stderr), `show` (id / `--session` / `--recent`, text or JSON), `status` (policy sha256 + counts, hook health per host, recent events; exit 64 when unhealthy), `policy lint`, `policy check` (`--kind`, `--format json`). Exit-code contract 0/2/3/64 (usage errors mapped away from 2). Env: `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`. | 7 unit + 16 end-to-end tests in isolated HOMEs |
| Default policy `policies/default-v1.yaml` | 7 deny groups (secrets read+write, env secrets, env poison, pipe-to-shell, destructive, kernel-self, shell rc), 4 allow (project fs, dev shell, registries, safe MCP), 2 ask (installs, push); `defaults: {"*": ask, net: deny}` | linted in CI, exercised by every fixture |
| Tooling | Workspace lints (clippy pedantic, `unsafe` forbidden), rustfmt, `deny.toml` (licences, advisories, I/O crates banned from core), CI matrix macOS/Linux/Windows + wasm purity + cargo-deny, dual MIT/Apache-2.0 | `cargo clippy` 0 warnings |

Totals: ~5,400 lines including tests; guard latency ≈ 11 ms including SQLite open
(budget 15 ms).

### 2.3 Live test (2026-10-03)
Real Claude Code 2.1.288 session, project-scoped `PreToolUse` hook, isolated `MOAT_HOME`:
`git status --short` allowed (`dev-shell`), `curl -sI https://example.com` denied (`default.net`),
`cat ~/.ssh/id_rsa` denied (`secrets-paths`). The agent reported each block verbatim and all
three decisions were in the audit log. CI is green on macOS (arm64, x64), Linux and Windows.

### 2.4 Engineering standards (2026-10-03, after surveying OpenHands, OpenCode, OpenClaw, ZeroClaw, NanoClaw)
`AGENTS.md` + `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md` (scope tables), `CODE_OF_CONDUCT.md`,
`CHANGELOG.md`, `.editorconfig`; `.github/` with pinned-SHA workflows, PR-title lint (Conventional
Commits), dependabot with cooldown, CODEOWNERS, issue forms, PR template requiring Testing and
Security impact; `scripts/ci/quality-gate.sh` used by CI and the pre-push hook; clippy thresholds
(200-line functions, cognitive complexity 30) and `anyhow!` banned; rustdoc `-D warnings`;
architecture tests (dependency allowlist, no `unsafe`, 500-line file budget); `docs/adr/` ADR-001…004;
`shell` and `lexer` split into module directories.

### 2.5 Design decisions made while building (now in `DESIGN.md`)
- Deny is absolute; "deny by default with holes" is `defaults: {net: deny}` + allow rules, never `deny: ["*"]`.
- Shell rule `*` matches any number of tokens; pipelines are matched per sub-command and as whole suffixes.
- `ask` from `guard` returns the host's own `ask` decision (the host prompts the user); our own terminal/Telegram approval comes later.
- Exit code 2 is reserved for `deny`; usage/config errors are 64 so a host never mistakes a crash for a block.
- Secret paths are protected for writes too (`authorized_keys` planting).

## 3. Not done (honest list)
- Self-protection is partial: `policy.lock` verified on every `guard` call is in; `moat doctor --accept` and the Claude Code `ConfigChange` veto are not.
- No OS enforcement: a wrong parse or an unknown obfuscation is still only a policy decision. `moat exec` (Seatbelt / Landlock+seccomp) is week 5.
- No egress proxy; `net` rules are pattern-based.
- No session taint, no approvals of our own, no `replay` timeline (only `show`).
- Cursor and OpenClaw adapters not written; MCP proxy not written.
- Executable pinning (`executables:` in policy) is parsed and linted but not enforced.
- Repo-level policy (`<repo>/.moat/policy.yaml`) and `moat trust` not implemented; only the user policy is loaded.
- Windows: builds in CI, PowerShell is not tokenised (any PowerShell command is `ask`).
- Nothing committed or pushed; `agentmoat/moat-kernel` repository not created.

## 4. Next, in order (DESIGN.md §10.9, weeks 2–6)

| # | Work | Done when |
|---|---|---|
| 2 | **Self-protection, part 2**: `moat doctor [--accept]` (terminal-only re-pin), Claude Code `ConfigChange` hook returning block for host settings edits not made by `moat` | tamper tests |
| 3 | **Executable pinning + PATH snapshot** at `init`; resolve programs against the snapshot, not the inherited PATH | T6 fixtures extended |
| 4 | **Cursor adapter** (`beforeShellExecution`, `beforeMCPExecution`, `preToolUse`; `permission` response; `failClosed: true` at init) | golden fixtures + e2e |
| 5 | **`moat replay`** (session timeline with step detail) and `moat report` (asks/hour, top rules) | e2e |
| 6 | **Approvals**: TTY prompt with once/session/permanent, session cache, `moat allow`; `permanent` appends a provenance-commented rule to the user policy | e2e |
| 7 | **OpenClaw plugin** (TypeScript shim → `moat guard`/`serve`) and `moat serve` socket mode | plugin fixture |
| 8 | **MCP stdio proxy** with tool-description pinning | e2e with a fake MCP server |
| 9 | **`moat exec`**: Seatbelt profile and Landlock+seccomp (+bwrap) launcher derived from policy, kernel-controlled env; adapters rewrite allowed shell commands via `updatedInput`; executing fixtures | obfuscated exfil fails at OS level |
| 10 | **Egress proxy** + minimal **session taint** (secret read ⇒ later `net` is `ask`) | read-then-exfil fixtures |
| 11 | **MoatBench v0**: ≥ 40 scenarios, Linux containers, Claude Code + Codex, 4 conditions, published results with CIs | gate in `STRENGTH.md` §3.3 |
| 12 | **Release**: `cargo-dist`, Homebrew tap, installers, `THREAT_MODEL.md`, coverage matrix, README chart, Show HN | v0.1 tag only if the gate passes |

Housekeeping done: repository `agentmoat/moat-kernel` is public, CI is green on all three
operating systems, Dependabot alerts/updates, secret scanning and push protection are on, a
branch ruleset enforces PR-only squash merges with all checks required, and `pr-standards`
auto-labels every PR (type/area/size/risk). Remaining: a release workflow.

## 5. How to verify the current state yourself
```bash
cargo test --workspace                                  # 82 unit/e2e + 83 fixtures
cargo clippy --workspace --all-targets                  # 0 warnings
cargo build -p moat-core --target wasm32-unknown-unknown
HOME=$(mktemp -d) sh -c 'mkdir -p $HOME/.claude && moat init && moat guard --host claude-code < tests/fixtures/hosts/claude-code/bash.json; moat show; moat status'
```
