# agentmoat — Progress and Next Steps

Updated: 2026-10-05 (main after #28). Plan of record: `DESIGN.md` §10 (v0.1 spec),
`STRENGTH.md` §3 (benchmark gate), `REPO_STRUCTURE.md` (layout and conventions).

## 1. Where we are in one line

The kernel decides and records: Claude Code, Codex and Cursor tool calls pass through
`moat guard`, are evaluated against a locked policy, blocked with a rule id and
reason when dangerous, and written to a redacted local audit log. OS enforcement
(`moat exec`), OpenClaw, the MCP proxy and the public benchmark are not
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
| `moat-core` | Policy schema v1 + loader + lint (version, missing/duplicate ids, empty rules, bad globs and shell patterns, unknown keys, `executables` paths). Own POSIX shell lexer: quotes, escapes, line continuation, comments, unspaced operators, redirects with descriptors, `$( … )`/backticks, here-documents as data, 64 KB limit. Classifier: sub-commands, subshells, `eval`, `sh -c` nesting, wrappers (`sudo`, `env`, `xargs`, `timeout`, `nohup`, …), inline interpreter payloads scanned for paths/hosts/env (`python -c`, `node -e`, …), env set/read, path read/write detection (`cp`/`scp` destination, `sed -i`, `dd of=`, `tee`, redirects), host/IP detection, depth, size and `MAX_ATOMS` (2048) limits. Engine with `CompiledPolicy::decide`/`decide_with` (compile once), pipeline-aware shell rules (`curl * \| sh`), per-kind defaults, negated globs, unparseable ⇒ `ask`, `executables` pins checked through a caller-supplied `ProgramResolver`. | 41 unit tests, 3 architecture tests (dependency allowlist, no `unsafe`, 500-line budget), conformance runner over 95 fixtures (63 attacks / 20 benign / 12 ask), builds for `wasm32` (no I/O), `#![forbid(unsafe_code)]` |
| `moat-hosts` | `PreToolUse` adapter for Claude Code and Codex (tool → action mapping, ungoverned tools, malformed payload errors, `hookSpecificOutput` response, `reason_line`); Claude Code `ConfigChange` adapter (`{}` or `{"decision":"block"}`); Cursor adapter for `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` (`{"permission": …}` response; `Shell` under `preToolUse` deliberately ungoverned). | 15 tests on golden payloads in `tests/fixtures/hosts/` |
| `moat-audit` | SQLite WAL store (busy timeout, schema version, 0600), `record`/`get`/`recent`/`session`/`count`, hex event ids; time-window queries (`since`, `sessions_since`, `summary` with verdict totals, hosts, top rules, asks per active hour). Redaction before storage: bearer/basic auth, `key=value` credentials, GitHub/OpenAI/AWS/Slack/Google/npm/GitLab/JWT token shapes, URL passwords; redaction is applied to the command, path and URL fields before encoding and corrupt rows are skipped, not fatal. | 16 tests |
| `moat-cli` (`moat`) | `init` (state dir 0700, default policy never overwritten, audit db, `environment.json` snapshot of `PATH` and common program locations, `policy.lock`, hook install for present hosts incl. Cursor's fail-closed `hooks.json`; idempotent, backup, atomic write, `--dry-run`, `--hosts`), `guard --host` (stdin → lock check → policy + `policy.d/approved.yaml` overlay → decision with executable pins and session grants → host JSON; fail-closed `deny` on any error; git-root project detection; trace id on stderr; Claude Code `ConfigChange` veto), `show` (id / `--session` / `--since` / `--recent`, text or JSON), `replay --since|--session` (per-session timeline), `report --since` (totals, hosts, top rules, asks per hour), `status` (policy sha256 + counts, lock state, hook health per host, recent events; exit 64 when unhealthy), `doctor [--accept]` (state dir, policy, lock, hooks, binary path, audit; `--accept` re-pins, terminal only), `allow --last [--always]` / `allow <cmd> --host --session` (session grant in `approvals.json` or permanent rule in `policy.d/approved.yaml`; terminal only), `policy lint` (errors exit 64; warnings for unreachable ask/allow patterns and unknown `defaults` kinds), `policy check` (`--kind`, `--format json`; no environment snapshot, see POLICY.md §8.1). Exit-code contract 0/2/3/64 (usage errors mapped away from 2). Env: `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CURSOR_CONFIG_DIR`. | 18 unit + 42 end-to-end tests (`cli`, `guard`, `cursor`, `config_change`, `lock`, `approvals`, `replay_report`) in isolated HOMEs |
| Default policy `policies/default-v1.yaml` | 7 deny groups (secrets read+write, env secrets, env poison, pipe-to-shell, destructive, kernel-self incl. `moat policy/init/doctor/allow`, shell rc), 4 allow (project fs, dev shell, registries, safe MCP), 2 ask (installs, push); `defaults: {"*": ask, net: deny}`; `executables: {}` | linted in CI, exercised by every fixture |
| Tooling | Workspace lints (clippy pedantic, `unsafe` forbidden), rustfmt, `deny.toml` (licences, advisories, I/O crates banned from core), CI matrix macOS (arm64, x64)/Linux/Windows + wasm purity + cargo-deny, `pr-title`, `pr-standards` (auto labels, size and body checks), `moat-reviewer` first-pass review, dual MIT/Apache-2.0 | `cargo clippy` 0 warnings |

Totals: 136 tests (`cargo test --workspace`), 95 conformance fixtures, 9,312 lines of Rust
including tests; guard latency ≈ 11 ms including SQLite open (budget 15 ms, measured by
hand, no benchmark in CI yet).

### 2.3 Live test (2026-10-03)
Real Claude Code 2.1.288 session, project-scoped `PreToolUse` hook, isolated `MOAT_HOME`:
`git status --short` allowed (`dev-shell`), `curl -sI https://example.com` denied (`default.net`),
`cat ~/.ssh/id_rsa` denied (`secrets-paths`). The agent reported each block verbatim and all
three decisions were in the audit log. CI is green on macOS (arm64, x64), Linux and Windows.

### 2.3b Live test 2 (2026-10-03, after #8–#21)
Real Claude Code 2.1.288 sessions against the merged binary, project-scoped hook, isolated
`MOAT_HOME`. Observed in the audit log and in the agent's own reports: `git status` allowed
(`dev-shell`); `curl` to an unlisted host denied (`default.net`); `cat ~/.ssh/id_rsa` denied
(`secrets-paths`); `npm install …` asked (`installs`; Claude Code's non-interactive mode treats
`ask` as blocked). `moat allow --last --always` from a pseudo-terminal wrote `approved-1` and the
next session ran the command (`allow [approved-1]`). Appending a comment to `policy.yaml` made
every following call `deny [kernel-integrity]` with the file named in the reason; `moat doctor`
listed the drift; `moat doctor --accept` re-pinned and the next session was allowed again.
`moat replay --since 1h` grouped four sessions with the right glyphs and rules; `moat report`
counted 1 allowed / 2 asked / 4 denied with `installs` and `kernel-integrity` on top.

Harness notes: hooks must be invoked with the same `CLAUDE_CONFIG_DIR` the lock was pinned under;
`doctor` reports a present-but-uninstalled host (Codex on this machine) as a problem by design.

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
- Self-protection: `policy.lock`, `moat doctor --accept` and the Claude Code `ConfigChange` veto are in; Codex and Cursor have no equivalent event, so for them the lock is checked on the next tool call only. Cursor file edits made by its own edit tools are governed through `preToolUse`; Cursor has no pre-write hook for edits that bypass that tool.
- No OS enforcement: a wrong parse or an unknown obfuscation is still only a policy decision. `moat exec` (Seatbelt / Landlock+seccomp) is week 5.
- No egress proxy; `net` rules are pattern-based.
- No session taint yet; approvals exist as `moat allow` (session grants and a permanent overlay) but there is no prompt of our own: hosts prompt, `moat allow` makes the answer stick.
- OpenClaw adapter and MCP proxy not written.
- Repo-level policy (`<repo>/.moat/policy.yaml`) and `moat trust` not implemented; only the user policy is loaded.
- Windows: builds in CI, PowerShell is not tokenised (a PowerShell command line falls through to the `ask` default). Canonical paths drop the `\\?\` verbatim prefix (`policy check --project`, lock keys, symlink resolution) and program resolution follows the `PATHEXT` recorded at `moat init`; Windows-only e2e tests push `C:/…` payloads through `guard` and `policy check`.

### 3.1 Known gaps (audit 2026-10-05)
From `moat-notes/docs/05-audit-2026-10-05.md`, verified against the binary. Fixes land as
`sec:`/`fix:` PRs in the order listed there; status as of this update is given per item.

P0 (allow where deny is promised):
- Policy lock did not detect a pinned file swapped for a symlink (fixed in #26).
- Package-manager wrappers hide arbitrary shell: `pnpm exec sh -c …`, `yarn exec …`, `npx`, `npm exec`, `make SHELL=…` are not in the wrapper table and `pnpm *`/`yarn *`/`cargo *`/`make *` are allowed by `dev-shell` (fixed: wrapper table #30, `dev-shell` split #33, `make` arguments `shell/make.rs`).
- Relative paths without `./` (`cat .env`, `cat src/../../../.ssh/id_rsa`) produced no `fs` atom (fixed in #29).
- MCP tool arguments are dropped: `mcp__filesystem__read_file {path: ~/.aws/credentials}` matches `safe-mcp`.
- Dead `ask` rules: `installs` for `pnpm add`/`yarn add`/`cargo add`/`cargo install` and `push` for `cargo publish` are unreachable behind the `dev-shell` allows (fixed in #33; `policy lint` now warns about such shadowing).
- No symlink/realpath resolution of action paths (`ln -s ~/.ssh ./s` then `cat ./s/id_rsa`) (fixed: `PathResolver`, ADR-009; residual TOCTOU and hard links).
- Audit failure was non-fatal: an unopenable `audit.db` printed a warning and the verdict proceeded; `guard` recreated a deleted database (fixed in #27).
- Redaction runs on the JSON-encoded action: escaped quotes can break patterns, corrupt stored rows and make `show`/`replay`/`report` failed for the whole query (fixed in #28).
- A panic in `guard` exited 101, which Claude Code treats as non-blocking (fail-open) (fixed in #27: `catch_unwind` ⇒ deny, exit 2); clap usage errors still exit 64.
- Policy-only: bare `env`/`printenv`/`set` ask instead of deny (fixed: `$` end anchor and `env-dump`, ADR-010); `base64 -d file | bash`, `base64 -D`, `openssl enc -d` have no decoder→interpreter rule (fixed: canonical decoder pipeline atom, `shell/decoders.rs`); `kernel-self` matches `moat` by literal argv0 only (fixed in #33; `script`/`expect`/`unbuffer` pty wrappers denied too, ADR-011; other pty helpers remain a known gap); `git branch -D`, `git stash clear` allowed.

- Options of allowed programs that run code or write files (`find -exec/-delete`, `rg --pre`, `git fetch --upload-pack`, `git diff --output=~/.zshrc`, `go test -exec`, `cargo --config`) were allowed by `dev-shell` (found 2026-10-05 while building the benign corpus; fixed: shell `!` exclusions, ADR-012, `shell/options.rs`).

- The state and host directories themselves were not protected (`mv ~/.moat …`, `ln -sfn /tmp/evil ~/.moat`, `rm -rf ~/.claude` asked) and the lock reported a pinned file as intact when a parent directory was swapped for a link (found 2026-10-05; fixed: directory patterns in `kernel-self`, `mv` source is a write, lock compares stored keys).

- `moat allow` success paths were untestable behind the terminal check (fixed: debug-only `MOAT_ASSUME_TTY`, `tests/allow.rs`).

- The `moat` binary that every hook runs was not protected (`cp /tmp/evil ~/.cargo/bin/moat` asked) and T10 had no attack fixture (fixed: `**/bin/moat` in `kernel-self`, `curl -o`/`wget -O` are writes).

P1 (false denies):
- `rm -rf /tmp/build` is denied because `rm -rf /*` is a per-token glob matching any absolute path.
- Dotted identifiers inside interpreter payloads and arguments (`python3 -c "import sys; …"`, `git commit -m fix.bug`) are treated as hosts and denied by `default.net`.
- `cd src && cargo build`, `echo $PATH` and `curl https://api.github.com/x` ask; the benign corpus is 18 fixtures against ≥ 60 planned (now 87, with a `dev-readonly` allow group for read-only docker/gh/inspection).
- Codex hook matcher is `Bash` only, so Codex file edits are never seen (fixed: matcher `Bash|apply_patch|mcp__.*`, `Action::Patch`); the Claude Code matcher omits `WebSearch`.

## 4. Next, in order (DESIGN.md §10.9, weeks 2–6)

| # | Work | Done when |
|---|---|---|
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
cargo test --workspace                                  # 136 unit/e2e tests incl. the 95-fixture conformance runner
cargo clippy --workspace --all-targets                  # 0 warnings
cargo build -p moat-core --target wasm32-unknown-unknown
HOME=$(mktemp -d) sh -c 'mkdir -p $HOME/.claude && moat init && moat guard --host claude-code < tests/fixtures/hosts/claude-code/bash.json; moat show; moat status'
```
