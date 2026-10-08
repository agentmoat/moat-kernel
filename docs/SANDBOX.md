# OS sandboxes: Standard and Lightweight tiers

OpenMoat decides each tool call in the agent's hook. The sandboxes below make the operating system enforce the same policy on everything those calls start.

## Host sandboxes (Standard tier)

`moat init` also turns on each agent's own sandbox and configures it from the policy
(ADR-018). Commands the agent runs, and every script they start (`npm test`,
`build.rs`, `make`), are then confined by the operating system: no secrets, no reads
outside the project and `sandbox.read_roots`, no writes outside the project, and
network only to allowlisted hosts, through a proxy ([POLICY.md §9](POLICY.md)).

- **Claude Code** (`settings.json`): the `sandbox` block (`enabled`,
  `failIfUnavailable: true`, `allowUnsandboxedCommands: false`, `excludedCommands: []`,
  read and write lists, `network.allowedDomains` with `strictAllowlist`) and
  `permissions.blockReadsOutsideWorkingDirectories: true`. Claude Code's file tools
  then refuse reads outside the working directories; `/add-dir` adds one. On Linux
  (and WSL2) it also adds `Read(./**/.env)`, `Read(./**/.env.*)` and
  `Read(./**/.envrc)` to `permissions.deny`. There, bubblewrap needs concrete paths,
  and Claude Code's sandbox expands a `denyRead` glob from its first literal directory
  when each command starts, so it skips `/**/.env`. A `Read` deny rule is expanded
  under the session's working directory instead, so a script reading one gets
  `EACCES`. A `.env` created after a command starts, or one in another readable
  directory, is not covered, and Claude Code's file tools also refuse `.env.example`.
  `moat sandbox show` lists both.
  Write lists get no expansion on Linux: Claude Code's sandbox drops every glob in
  `denyWrite`, `Edit(…)` deny rules included. A rule without a glob is kept and
  resolved against the working directory, so `moat init` also adds `Edit(./.env)`,
  `Edit(./.envrc)` and `Edit(./.moat)`. Only names directly in the working directory
  get such a rule: where a denied path is missing, bubblewrap mounts its first
  missing component read-only for the command (an empty `.envrc` or `.moat` shows up
  there meanwhile), and `Edit(./bin/moat)` would do that to a missing `bin`. Claude
  Code itself keeps the working directory's `.git/hooks`, `.git/config` and
  `.claude` settings read-only. Everything else the policy denies by a `**/` glob
  (a `.env` in a subdirectory, `.env.local`, `.git/info/attributes`, submodule hooks,
  `bin/moat`) stays writable for sandboxed commands on Linux; `moat sandbox show`
  lists it (`claude-code.linux-write-globs`).
- **Codex** (`config.toml`): a `[permissions.moat]` profile, `default_permissions =
  "moat"` and `features.network_proxy = true`. The `**/` denies (`.env` files) cover
  the project and the read roots inside the home, not system read roots such as
  `/etc`, `/usr` and `/tmp`: on Linux Codex lists every directory below a deny glob
  before each command and runs none when one is unreadable, and those hold root-only
  directories. `moat sandbox show` lists these roots (`codex.outside-home`); the hook
  still denies the agent's own reads there. A directory you cannot list inside the
  project or a home read root still stops Codex on Linux. Codex on Linux also runs its
  own executable inside the sandbox, so on Linux the profile lets commands read the
  executable `codex` on `PATH` starts (through npm's launcher, the platform binary),
  listed as `codex.own-binary`. Run `moat sandbox sync` after installing or moving
  Codex. When `codex` is not on `PATH`, `moat sandbox show` says so and Codex starts
  commands only when installed under a read root. An executable inside a denied path,
  such as the Codex home where Codex's standalone installer puts it, stays denied
  (a deny wins), so Codex on Linux starts no command; `show` says that too.
- **Cursor** (`sandbox.json` next to `hooks.json`: `~/.cursor`, or `$CURSOR_CONFIG_DIR`):
  `type: "workspace_readwrite"`, `readBoundary: "workspace"`, `additionalReadPaths`
  (the read roots and read allow rules), `additionalReadwritePaths` (write allow rules
  outside the project) and `networkPolicy` (`default: "deny"`, the allowed and denied
  domains). Cursor's file tools then ask before reading outside the workspace. See
  [Cursor's sandbox](#cursors-sandbox) for what its schema cannot express.

Claude Code's sandbox runs on macOS, Linux and WSL2 only, and with `failIfUnavailable`
Claude Code exits at startup where it cannot run. On native Windows, OpenMoat therefore
writes neither the `sandbox` block nor `blockReadsOutsideWorkingDirectories`; `moat
init`, `sandbox sync`, `sandbox show`, `doctor` and `status` print `sandbox not
available on native Windows; the hook still applies the policy (use WSL2 for OS
confinement)` for Claude Code instead. `moat init` and `moat sandbox sync` remove those
settings where an older version wrote them, keep the rest of the file and re-pin it.
Codex is configured as on other systems. `moat status` reports such an agent as
`hook only`, and a sandbox that is missing, weakened or out of date the same way, with
the reason ([USAGE.md](USAGE.md#how-each-agent-is-protected)).

Network has two modes:

- **Default:** each agent's own proxy enforces the allowlist.
- **Opt-in:** set `sandbox.proxy_port: 18080` in the policy, run `moat sandbox sync`,
  and keep `moat proxy` running (a user service works). Sandboxed commands then reach
  the network through `moat proxy`, which records every connection, injects brokered
  secrets and refuses private addresses.
  - Claude Code's `network.httpProxyPort` and `socksProxyPort` name the proxy. While
    it is stopped, its sandboxed commands have no network, and `moat doctor` and
    `moat status` warn.
  - Codex's proxy passes what it allows on to `moat proxy` when you start Codex with
    `HTTP_PROXY` and `HTTPS_PROXY` set to `http://127.0.0.1:18080`. Codex's own API
    hosts then need an allow rule.

Other settings and comments are kept, and each file is copied to
`<file>.moat-sandbox-backup` before moat changes it. `moat sandbox show` prints what
the policy compiles to, with every place a host is stricter or wider than the policy;
`moat sandbox sync` rewrites them after you edit the policy and re-pins them. Editing
the generated parts by hand is drift (`kernel-integrity`), and `moat doctor` names any
weakened setting. Under Claude Code, sandboxed commands can run `git commit` but cannot
write `.git/hooks`, `.git/config` or the other paths that make git run code (ADR-021);
on Linux only in the working directory's own repository, `info/attributes` and
submodules aside (above).
Codex keeps `.git` read-only: commit outside its sandbox (Codex asks to).

[EVIDENCE.md](EVIDENCE.md) lists what each agent's sandbox, configured this way, does
to hostile project scripts on macOS and Linux. CI runs them on every pull request with
pinned Claude Code and Codex binaries and no account: Claude Code headless against a
local fake API, Codex through `codex sandbox -P moat`.

To undo, delete the `sandbox` key, `permissions.blockReadsOutsideWorkingDirectories`
and the `Read(./**/…)` and `Edit(./…)` rules in `permissions.deny` from Claude Code's settings,
`default_permissions`, `[permissions.moat]` and `features.network_proxy` from Codex's
`config.toml`, and `type`, `readBoundary`, `additionalReadPaths`,
`additionalReadwritePaths` and `networkPolicy` from Cursor's `sandbox.json` (or restore
the backups), then run `moat doctor --accept`. `moat uninstall` does this for you.

### Cursor's sandbox

Cursor's sandbox (Seatbelt on macOS, Landlock and seccomp on Linux) confines the
terminal commands its agent runs. The keys are those of Cursor 3.23's
[`sandbox.json` reference](https://cursor.com/docs/reference/sandbox) and
[Run Modes](https://cursor.com/docs/agent/security/run-modes) page; OpenMoat follows
the documentation, and the generated file has not yet been run under a Cursor build.

`sandbox.json` has no key that denies a path. A read root with a denied path below it
(`~/.cargo` holds `~/.cargo/credentials.toml`) is therefore left out, which is stricter
and is listed as such, and what the policy denies by name inside the workspace
(`**/.env`, `.moat`, `.git`) stays readable and writable to sandboxed commands, listed
as wider. Cursor itself keeps `.cursor/*.json`, `.claude/**/*.json`, `.vscode`,
`.git/hooks`, `.git/config` and `.git/info/attributes` unwritable. With the
workspace read boundary, sandboxed commands read only the workspace, the listed paths,
the system paths tools need and, of `~/.ssh`, only `known_hosts`.

What no key in `sandbox.json` changes, and `moat sandbox show` lists as wider:

- Cursor runs a command outside its sandbox when its Auto-review classifier approves
  it (a command that cannot use the sandbox, or a rerun after a sandbox error), in Run
  Everything mode, in Allowlist mode with sandboxing off, and in the Cursor CLI unless
  it starts with `--sandbox enabled`. On Linux without Landlock v3 Cursor asks instead.
- Cursor's Network access setting: its default, "sandbox.json + Defaults", adds
  Cursor's package-manager domains, and "Allow All" ignores `sandbox.json`. Choose
  "sandbox.json Only".
- A project's own `.cursor/sandbox.json` replaces the read boundary and the read list
  and adds paths and hosts. The default policy denies the agent writes to it, and Cursor
  keeps sandboxed commands from writing it, but a cloned repository can ship one.
- `sandbox.proxy_port` has no Cursor equivalent: Cursor's own allowlist decides, and
  that traffic does not reach `moat proxy`.

Cursor documents its sandbox for macOS and Linux only, so on native Windows `moat init`
leaves `sandbox.json` alone and `moat status` reports Cursor as `hook only`.

## `moat run` (Lightweight tier)

Without a container or VM runtime, `moat run` puts a whole agent in a sandbox generated
from the policy, with network only through a `moat proxy` it starts (ADR-018):

```bash
moat run --write ~/.claude --write ~/.claude.json -- claude
```

- **macOS:** a Seatbelt profile, started with `/usr/bin/sandbox-exec`.
- **Linux 6.7 or later:** Landlock rules, plus a seccomp filter that allows only TCP
  sockets (no UDP, Unix sockets or `ptrace`). Windows refuses.
- The agent and every command it starts may read the project, `sandbox.read_roots`,
  the temp directory and the agent's own executable; never the keychain. They may
  write the project, the temp directory and each `--write` path (the agent's state).
  Deny rules still win (`~/.claude/settings.json` stays unwritable).
- Network goes only to the proxy on a loopback port (`HTTP_PROXY`, `HTTPS_PROXY`),
  which allows the hosts the policy allows. A tool that ignores those variables has
  no network.
- Turn the agent's own sandbox off inside: sandboxes do not nest, so Claude Code's
  `sandbox.enabled` (which `moat init` turns on) fails there and Codex needs
  `--sandbox danger-full-access`. Credentials must not come from the keychain: use
  an API key or `apiKeyHelper`.
- Before the agent starts, `moat run` prints how many places the sandbox is stricter
  or wider than the policy; `moat run --verbose` lists each one (`moat sandbox show`
  prints the same for the current directory). Linux is wider than macOS (secrets inside the project stay
  readable, and the proxy's port is reachable on any host); see [THREAT_MODEL.md](THREAT_MODEL.md).

It is weaker per command than the Standard tier: the agent and its scripts share one
sandbox, so whatever the agent needs, `npm test` gets too.

[EVIDENCE.md](EVIDENCE.md) lists what `moat run` does to hostile project scripts on
macOS and Linux (reading keys and credentials, writing outside the project, direct
connections, DNS, symlinks out of the project, editing the policy), as CI asserts it on
every pull request, with the Linux gaps marked.

### Cursor CLI under `moat run`

Cursor's CLI (`agent`, formerly `cursor-agent`) needs three things the default policy
does not give it:

1. Its installation directory readable: it is a script that starts the Node.js and
   JavaScript files beside it. Add `~/.local/share/cursor-agent` to
   `sandbox.read_roots` (`moat edit`).
2. Its API host allowed: add an allow rule with `net: ["api2.cursor.sh"]`. The
   audit log names any other host the proxy refused.
3. Its state directory writable, and credentials from `CURSOR_API_KEY`: on macOS
   `agent login` keeps them in the keychain, which the sandbox blocks.

```bash
CURSOR_API_KEY=… moat run --write ~/.cursor -- agent --sandbox disabled
```

`--sandbox disabled` turns Cursor's own sandbox off for this run only, because
sandboxes do not nest; it does not change `~/.cursor/cli-config.json`. `~/.cursor`
must already exist, and `~/.cursor/hooks.json` stays unwritable. Checked on macOS
with Cursor CLI `2026.10.01`: it starts, writes only `~/.cursor`, and reaches
`api2.cursor.sh` through the proxy; a session with an account and the commands it runs
were not checked, nor was Linux, where the CLI keeps its settings in
`$XDG_CONFIG_HOME/cursor` when that variable is set.
