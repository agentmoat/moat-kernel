# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- `moat guard` resolves symlinks in every path a tool call reads or writes and checks the resolved path as well as the literal one, strictest wins: after `ln -s ~/.ssh ./s`, `cat ./s/id_rsa`, `echo … >> s/authorized_keys` and a `Read` of `proj/s/id_rsa` are denied by `secrets-paths`; previously they were allowed by `project-fs`. New files resolve through their directory, dangling links through their target. Conformance fixtures accept `links:` (ADR-009).
- Default policy: new deny group `env-dump` for `env`, `printenv`, `set`, `export`, `declare` and `typeset` run with no arguments (or only `-0`/`-p`/`-x`), including `/usr/bin/env`; they printed every secret in the environment and only asked. `printenv NAME` is now an `env.read` of `NAME`, so `printenv GITHUB_TOKEN` is denied by `env-secrets`.

### Fixed
- Shell classification: `make`/`gmake` arguments that run code (`--eval`/`-E`, `-e`, `SHELL=`, `.SHELLFLAGS=`, `MAKEFLAGS=`, `NAME!=cmd`, `$(shell …)` in variable values) are classified on their own, so `make test SHELL=/tmp/x` and `make test --eval 'x:;cat ~/.ssh/id_rsa'` no longer pass as `make test*` (`dev-shell`); embedded commands are evaluated like any other, `--file=`/`--directory=` values are file reads.
- `moat guard` denies (`kernel-error`, exit 2) when the audit log cannot be opened or written, when the hook response cannot be written to stdout, or when the kernel itself panics; previously an unavailable log printed a warning and the call proceeded unrecorded, and a panic exited 101, which Claude Code treats as non-blocking. `guard` no longer recreates a deleted `audit.db`; only `moat init` creates it.
- Host detection: a bare dotted token without a scheme is a host only when its last label is a known top-level domain, so `python -c "import sys; print(sys.version)"`, `node -e "console.log(process.version)"` and `git commit -m fix.bug` no longer produce a network atom (and a false `default.net` deny). Tokens with a scheme and IPv4 literals are unchanged.
- Shell classification: `pnpm exec|dlx`, `yarn exec|dlx`, `npm exec|x`, `bun x`, `npx` and `bunx` are treated as wrappers, so the program they run is classified on its own (`pnpm exec sh -c '…'` parses the shell string); `-c`/`--call` strings given to package runners are parsed as shell. Previously the whole command matched the outer `pnpm *` allow rule.
- Policy lock: a pinned file replaced by a symlink (or a re-pointed link) is now reported as modified and denies with `kernel-integrity`; previously the swapped file was treated as unpinned and the kernel ran under the attacker's policy.
- Shell classification: tokens that traverse (`src/../x`) or name a hidden entry (`.env`, `config/.env.local`, `.ssh/id_rsa`) are now treated as paths, so `cat .env` and `cat src/../../.ssh/id_rsa` produce file-read atoms and hit `secrets-paths`; previously only tokens starting with `/`, `~`, `./` or `../` did and such commands were allowed by `dev-shell`.
- Audit redaction now runs on the structured action before it is JSON-encoded. Previously it ran on the encoded text, where escaped quotes broke the patterns: a command such as `curl -H "X-Api-Key: …"` was stored as invalid JSON (making `moat show`, `replay` and `report` fail for the whole window) and `export PASSWORD="…"` kept the secret. Rows with an unparsable action cell are now read with the action omitted instead of failing the query.

### Added (MCP arguments)
- `Action::McpTool` carries the paths and hosts an adapter derived from the call's arguments (`reads`, `writes`, `hosts`); the engine turns them into `fs.read`, `fs.write` and `net` atoms, so an allowed MCP tool name can no longer read `~/.aws/credentials` or fetch an unlisted host. Conformance fixtures accept `mcp_tool: { name, reads, writes, hosts }`.
- Claude Code and Cursor adapters derive those paths and hosts from MCP `tool_input` by argument name (`path`, `paths`, `file_path`, `source`, `destination`, `url`, …); write-shaped tool names (`write_*`, `edit_*`, `move_*`, `delete_*`) and `destination`/`target` arguments produce `fs.write`.

### Changed
- Shell patterns: a trailing bare `$` anchors the end of argv (`env $` matches `env` but not `env FOO=1 cmd`); `$` elsewhere is literal and a pattern of only `$` fails lint (ADR-010).
- Default policy: `dev-shell` lists explicit subcommands instead of `pnpm *`, `yarn *`, `cargo *`, `make *`, so the `installs` and `push` ask rules are reachable again (`cargo add/install/publish`, `pnpm add/install`, `yarn add/install` now ask; `npx`/`dlx` ask). New `dev-tools` allow group (`tsc`, `eslint`, `prettier`, `vitest`, `jest`, `ruff`, `mypy`, …). `destructive` matches `rm -rf /*` literally (no longer every absolute path), adds `-fr` variants, `--no-preserve-root`, `git branch -D`, `git stash drop/clear`. `kernel-self` also matches `moat` run by absolute path. `secrets-paths` adds `.envrc`.

### Added
- Policy engine: schema v1 with `deny → allow → ask → defaults` evaluation, per-kind defaults, absolute deny, strictest-wins across atomic actions.
- Shell classification: POSIX lexer (quotes, escapes, redirects, `$(…)`, backticks, here-documents), sub-commands, subshells, `eval`, `sh -c`, wrappers, inline interpreters, environment reads/sets, path and host extraction.
- Host adapters for Claude Code and Codex `PreToolUse` hooks, and for Cursor (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`; `moat init` writes a fail-closed `~/.cursor/hooks.json`).
- Audit log in SQLite (WAL) with credential redaction; time-window and per-session queries (`since`, `sessions_since`, `summary`); `moat show [id | --session | --since | --recent]`, `moat replay` (per-session timeline, `--since`/`--session`/`--host`) and `moat report` (verdict totals, hosts, top rules, asks per active hour). Windows accept `all`, `today`, `yesterday`, `12h`, `7d`, `2w` or `YYYY-MM-DD`.
- `moat status` exits 64 when the installation is unhealthy (missing policy, lock drift, broken hook, missing audit log) so scripts can test it.
- `moat init` (policy, audit log, idempotent hook installation), `moat guard` (fail-closed), `moat policy lint|check`.
- Default policy v1 and 95 conformance fixtures (63 attacks, 20 benign, 12 ask).
- Host configuration directories can be overridden for tests and unusual installs: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CURSOR_CONFIG_DIR`; state directory via `MOAT_HOME`.

### Added (self-protection)
- `policy.lock`: `moat init` pins SHA-256 digests of the policy and every installed host hook file; `moat guard` verifies them on every call and denies everything with rule `kernel-integrity` when a pinned file changed or disappeared.
- `moat status` reports lock state; re-running `moat init` re-pins.
- Claude Code `ConfigChange` hook: when a settings file pinned by the lock is edited or deleted outside `moat`, the change is refused for the running session (rule `kernel-integrity`); unpinned settings files load and are audited.
- Executable pinning: `moat init` snapshots the search path and the location of common programs in `~/.moat/environment.json` (pinned by the lock); `moat guard` resolves every shell command's program through the snapshot and denies pinned programs that resolve elsewhere (rule `executables`). Policy `executables:` pins are now enforced.
- Approvals: `moat allow --last` (or `moat allow <command> --host … --session …`) grants one exact command to one host session; `moat allow … --always` appends a permanent allow rule to `~/.moat/policy.d/approved.yaml`, merged into the policy at load. Both files are pinned by the lock; `moat allow` is terminal-only and denied to agents by the default policy.
- `moat doctor [--accept]`: verifies state directory, policy, lock, hooks, binary path and audit log; `--accept` re-pins and is refused outside an interactive terminal.

### Changed
- Project standards: `AGENTS.md` contract, CONTRIBUTING, SECURITY, Code of Conduct, pinned-SHA workflows, Conventional Commits PR titles, Dependabot, CODEOWNERS, issue forms, PR template, single quality-gate script, clippy thresholds, rustdoc `-D warnings`, architecture tests, ADR-001…004.
- CI: `pr-standards` applies `type:`/`area:`/`size:`/`risk:` labels from the title and changed paths, fails PRs over 500 lines (unless `size: override`) or without Testing and Security impact sections; labels are defined in `scripts/ci/sync-labels.sh`.
- CI: `moat-reviewer` GitHub App posts an advisory first-pass review on every pull request (`pr-review.yml`); `@moat-reviewer` re-runs it.
- Dependencies: rusqlite 0.40, sha2 0.11, actions/checkout v7.0.1, action-semantic-pull-request v6.1.1.
- Windows: canonical slash-separated paths keep `C:/` and UNC roots.

### Security
- Exit code 2 is reserved for `deny`; usage errors use 64 so a host never mistakes a crash for a block.
- Secret paths are protected against writes as well as reads.
