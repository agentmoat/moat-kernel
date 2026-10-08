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
  then refuse reads outside the working directories; `/add-dir` adds one.
- **Codex** (`config.toml`): a `[permissions.moat]` profile, `default_permissions =
  "moat"` and `features.network_proxy = true`.
- **Cursor:** not configured. Cursor has a sandbox of its own (Seatbelt on macOS,
  Landlock and seccomp on Linux, set in `~/.cursor/sandbox.json`), but `moat init`
  does not generate its settings, and Cursor can rerun a command outside it once its
  own classifier approves. In the Cursor editor only the hook applies the policy; the
  Cursor CLI can run under [`moat run`](#cursor-cli-under-moat-run).

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
`moat sandbox sync` rewrites both after you edit the policy and re-pins them. Editing
the generated parts by hand is drift (`kernel-integrity`), and `moat doctor` names any
weakened setting. Under Claude Code, sandboxed commands can run `git commit` but cannot
write `.git/hooks`, `.git/config` or the other paths that make git run code (ADR-021).
Codex keeps `.git` read-only: commit outside its sandbox (Codex asks to).

To undo, delete the `sandbox` key and `permissions.blockReadsOutsideWorkingDirectories`
from Claude Code's settings, and `default_permissions`, `[permissions.moat]` and
`features.network_proxy` from Codex's `config.toml` (or restore the backups), then run
`moat doctor --accept`.

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
