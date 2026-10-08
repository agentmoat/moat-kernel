# Install and set up OpenMoat

## Install

Release builds cover macOS (arm64, x64), Linux (x64, arm64; glibc and static musl)
and Windows (x64). Every alpha is a GitHub pre-release, so installer
URLs name the version; take the newest from
[Releases](https://github.com/crocodile-labs/openmoat/releases).

```bash
# macOS and Linux: installs moat into ~/.cargo/bin
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/crocodile-labs/openmoat/releases/download/v0.1.0-alpha.4/openmoat-installer.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/crocodile-labs/openmoat/releases/download/v0.1.0-alpha.4/openmoat-installer.ps1 | iex"

# Homebrew (macOS, Linux)
brew install crocodile-labs/tap/moat

# From crates.io (Rust 1.95); cargo installs a pre-release only when asked by version
cargo install openmoat --locked --version 0.1.0-alpha.4
```

To build from a clone instead (Rust 1.95, pinned by `rust-toolchain.toml`):

```bash
git clone https://github.com/crocodile-labs/openmoat && cd openmoat
cargo install --locked --path crates/openmoat-cli    # installs the `moat` binary
```

Each release carries `sha256.sum` and GitHub build attestations:
`gh attestation verify <archive> --repo crocodile-labs/openmoat`.

### Upgrade

```bash
brew update && brew upgrade moat                              # Homebrew: update the tap first
cargo install openmoat --locked --force --version <version>   # crates.io
```

With the installers, run the installer of the new release. Hooks keep working after an
upgrade in the same place; `moat doctor` confirms it.

## Set up with `moat init`

```bash
moat init      # policy, lock, audit log; asks before hooking each agent it finds
moat status    # policy, lock, hooks per agent, recent decisions
```

`moat init` writes `~/.moat/policy.yaml` (the default policy), pins it and the hook
files in `~/.moat/policy.lock` and creates the audit log. Then it lists each agent
whose configuration directory exists, with the files it would change, and asks once
per agent:

```
Found these agents:
  Claude Code  /Users/you/.claude (changes settings.json)
  Codex        /Users/you/.codex (changes hooks.json, config.toml)
Protect Claude Code (/Users/you/.claude)? [Y/n]
Protect Codex (/Users/you/.codex)? [Y/n]
```

Only the agents you accept get the hook and sandbox settings. The last lines name the
backups and how to undo: `Undo anytime: moat uninstall`. `init` never overwrites an
existing policy, never duplicates a hook and backs up a host file before editing it
(`<file>.moat-backup` for hooks, `<file>.moat-sandbox-backup` for sandbox settings), so
it is safe to run again.

To choose without questions, name the agents: `moat init --hosts claude-code` (or
`codex`, `cursor`, comma-separated). `moat init --yes` sets up every agent found, for
scripts. Without a terminal and without `--yes` or `--hosts`, `init` changes no agent's
files and says how to go on. `moat init --dry-run` prints what would change first.

Hooks run the `moat` you ran `moat init` with, by its stable path (ADR-016). After
moving or reinstalling the binary somewhere else, run `moat init` again; `moat doctor`
names a hook whose binary is missing or is a different `moat`.

On native Windows, `init` does not turn on Claude Code's sandbox: it runs on macOS,
Linux and WSL2 only, and Claude Code would not start with it required. The hook still
checks every Claude Code call, and `init`, `doctor` and `status` say so. For OS
confinement, run Claude Code and `moat` inside WSL2. Codex's sandbox is set up as on
other systems.

| Agent | What is hooked | Hook file |
|---|---|---|
| Claude Code | `PreToolUse`: `Bash`, `Monitor`, `PowerShell` (always asks), `Read`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, `LSP`, `SendFile`, `WebFetch` (as `fetch`), MCP tools. `ConfigChange`: user, project and local settings | `~/.claude/settings.json` |
| Codex | `PreToolUse`: shell commands, `apply_patch` (every file the patch names), MCP tools. Codex hooks cannot ask (`PermissionRequest` runs only when Codex itself prompts), so an `ask` blocks the call until you run `moat` or `moat allow --last`, for `apply_patch` too. Codex does not hook web search or hosted tools | `~/.codex/hooks.json` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` (`Read`, `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete`, `Grep`, `Glob`, and any other tool that names a path); installed with `failClosed`. Cursor prompts on `ask` only for shell and MCP calls, so an `ask` on `preToolUse` or `beforeReadFile` is sent as a deny until you run `moat` or `moat allow --last`. `moat init` does not configure Cursor's own sandbox, so in the editor only the hook applies the policy; the Cursor CLI can run under `moat run` ([SANDBOX.md](SANDBOX.md#cursor-cli-under-moat-run)) | `~/.cursor/hooks.json` |
| Continue CLI (`cn`) | Runs the Claude Code hook, recorded as host `continue`. `cn` ignores an `ask`, so an `ask` blocks the call until you run `moat allow --last`. The released `cn` does not run hooks, so nothing is checked until it does; use `moat run` (`moat doctor` warns) | Claude Code's |

## Undo with `moat uninstall`

```bash
moat uninstall                    # every agent; --hosts codex for one
moat uninstall --purge            # also delete ~/.moat (policy, lock, audit log)
```

`moat uninstall` removes OpenMoat's hooks and sandbox settings from each agent and
prints what it did per file. When the file is otherwise unchanged since `moat init`,
the backup `init` took is written back byte for byte; a file `init` created is
deleted; a file you changed since keeps your changes and only loses OpenMoat's
entries (its backup stays next to it). The lock stops pinning those files. `~/.moat`
stays unless you pass `--purge`. Like `moat allow`, it runs only from a terminal, and
the default policy denies it to agents (`kernel-self`).

## Non-default config directories

`moat` finds each agent's configuration the way the agent does: `CLAUDE_CONFIG_DIR`,
`CODEX_HOME` and `CURSOR_CONFIG_DIR` replace `~/.claude`, `~/.codex` and `~/.cursor`,
and `MOAT_HOME` replaces `~/.moat`. If you start Claude Code with `CLAUDE_CONFIG_DIR`
set, run `moat init` once with the same value. `init` records the directory of each
agent it sets up in `~/.moat/hosts.json` (pinned by the lock), and every later command
(`status`, `doctor`, `allow`, `sandbox sync`, `uninstall`) uses the recorded directory,
so you do not export the variables again. When a variable in your shell names another
directory than the record, `moat doctor` reports it instead of following it; run
`moat init` with the variable set to move OpenMoat to that directory. `MOAT_HOME` is
not recorded: it says where the record is.

Next: [USAGE.md](USAGE.md) for daily use, [SANDBOX.md](SANDBOX.md) for the OS sandboxes.
