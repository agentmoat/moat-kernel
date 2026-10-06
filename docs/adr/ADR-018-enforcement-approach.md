# ADR-018: Enforce through the host's sandbox by default, moat's own sandbox as strict mode

Status: proposed · Date: 2026-10-05 · Refines the `moat exec` part of ADR-003 and the beta scope of ADR-013

## Context

ADR-003 planned enforcement as `moat exec`: the host adapter rewrites each allowed shell
command to run under a Seatbelt or Landlock profile derived from the policy. ADR-013 made
that the beta's exit criterion. A decision on a command string cannot see what `npm test`,
`cargo build` (`build.rs`), `make` or `conftest.py` run, so only an OS sandbox stops a
malicious project script.

The sandbox spike (#119, `spikes/sandbox/` on branch `spike/sandbox`, macOS 26.7, Claude Code
2.1.290, codex-cli 0.160.0) found:

1. **Seatbelt does not nest.** A process already in a sandbox can apply only a profile that
   compiles to the policy it already has; any other profile, stricter or looser, fails with
   `sandbox_apply: Operation not permitted`. Verified inside `codex sandbox -P :workspace`, and in
   reverse: Claude Code's sandbox cannot start inside a moat profile. So `moat exec` cannot run
   while Codex's or Claude Code's sandbox is on, which is their default or recommended mode.
2. **A profile generated from the default policy works** (option a). It denied the fake
   `~/.ssh`, `~/.aws` and `.env` to an `npm test` payload, a node script, a Makefile and a
   `build.rs`; denied `~/.zshrc` persistence, writes outside the project, `.git/hooks` and
   host config files; allowed edit, `git commit`, `cargo build/run`. SBPL cannot name a host or
   an IP (`host must be * or localhost`), so the profile allows only `localhost:<port>` and a
   proxy enforces the `net` allowlist; that pairing was demonstrated (allowlisted host 200,
   other hosts 403, direct sockets and DNS blocked).
3. **Claude Code runs inside that profile** given a writable state dir, its API host through
   the proxy and non-keychain credentials, and its own Bash tool was confined. But the agent
   and every script it starts share one profile: what the agent needs (API host, and the
   keychain if it reads its OAuth token there) is available to `npm test` too.
4. **Both hosts' sandboxes can be configured from the policy** (option b). Codex's built-in
   `workspace-write` lets `npm test` read `~/.ssh` and `~/.aws`; it only stops the upload
   because the network is off entirely. A generated Codex `[permissions]` profile (deny paths,
   domain allowlist through Codex's proxy) and generated Claude Code `sandbox` settings
   (`denyRead`/`denyWrite`, `allowedDomains` + `strictAllowlist`, `allowUnsandboxedCommands:
   false`, `failIfUnavailable: true`) blocked every payload. The translation is lossy in
   places (see the README's mapping table) and has silent traps: a relative glob in Claude
   Code user settings resolves against `~/.claude`, and a directory in `denyWrite` covers its
   whole subtree.

## Decision

- **Default: generate the host's sandbox configuration (b).** `moat init` (and a new
  `moat sandbox sync`) writes, from the same policy:
  - Claude Code: the `sandbox` block in user settings (`enabled`, `failIfUnavailable: true`,
    `allowUnsandboxedCommands: false`, `excludedCommands: []`, `filesystem.denyRead/allowRead/
    denyWrite`, `network.allowedDomains/deniedDomains/strictAllowlist: true`).
  - Codex: a `[permissions.moat]` profile extending `:workspace`, `default_permissions = "moat"`,
    `network.domains`, `features.network_proxy = true`.
  - The generated files are pinned in `policy.lock` (ADR-006), so drift is `kernel-integrity`
    and the existing `kernel-self` and `ConfigChange` protections cover them. `moat doctor`
    reports a disabled sandbox, a non-empty `excludedCommands`, `allowUnsandboxedCommands: true`
    or a missing `failIfUnavailable` as findings.
  - The generator is tested against the hosts' real sandboxes with executing fixtures
    (`codex sandbox -P`, and `claude -p` against a local fake API), because the traps above are
    silent.
- **Strict mode: moat is the outer sandbox (a).** `moat run -- <agent>` starts the agent with its
  own sandbox off, under a moat-generated Seatbelt (macOS) or Landlock + seccomp / bubblewrap
  (Linux) profile, with `moat proxy` as the only network exit. Used for hosts without a usable
  sandbox (Cursor, OpenClaw, any CLI agent) and for users who do not want to trust a host's
  sandbox configuration. The agent's credentials come from an API key or `apiKeyHelper`, never
  from a keychain the profile opens, and its API host is on the proxy allowlist with a reason.
- **Per-command `moat exec` stays** for adapters that can rewrite commands while the host's
  sandbox is off (it gives the tool subprocess a stricter profile than the agent's). It is not
  the default, because it requires turning the host sandbox off.
- **One egress proxy for both.** `moat proxy` is the network exit in (a) and is offered to
  Claude Code as `sandbox.network.httpProxyPort` in (b), so the `net` allowlist, the
  `cloud-metadata` deny and the connection log live in one place for every host. It checks the
  TLS SNI against the CONNECT host.
- **What stays decide-only** (the hook layer remains the only control): `shell` rules
  (destructive git, push, installs, `sudo`), `mcp` rules, `executables` pins, `ask` (an OS
  sandbox can only allow or deny; reads outside the project are allowed and writes denied),
  in-process host tools under (b) (Claude Code's sandbox covers Bash only; `Read`, `Edit` and
  `WebFetch`/`fetch` run in the agent's process, outside it; whether Codex's `apply_patch` is
  sandboxed was not verified), and Windows until Phase 2.
- **Linux follow-up** (separate spike before beta): Codex uses Landlock + seccomp, Claude Code
  bubblewrap + a socat bridge. Landlock rulesets stack (each layer only narrows), so `moat exec`
  may nest under Codex on Linux, unlike Seatbelt; bubblewrap inside bubblewrap depends on user
  namespaces being allowed by the outer seccomp filter. Landlock (ABI 4+) restricts TCP ports
  but not hosts, so the proxy design carries over. Verify both with the same fixtures.

## Consequences

- Enforcement reaches users without asking them to change how they start their agent, and
  the host keeps its own UX for violations (Claude Code reports `<sandbox_violations>` to the
  model; Codex escalates through approval).
- moat's guarantee in (b) is only as good as the host's sandbox and our translation of the
  policy into it. Every host version bump needs the executing fixtures to pass; a host that
  renames a key fails `moat doctor`, not silently.
- Some policy semantics are lost in (b) and must be stated in `docs/STRENGTH.md` §2.5:
  Codex cannot re-allow `.env.example` inside a deny glob, cannot express `**/` outside known
  roots, and makes all of `.git` read-only; neither host can deny the directory node alone.
- (a) gives the strongest and most uniform guarantee but confines the agent and its children
  together, so anything the agent needs, every script gets. Keychain access is never granted.
- A parser bug becomes a usability bug (ADR-003, ADR-013) only for what the sandbox covers:
  file paths and network. Shell, MCP and `ask` rules keep the classifier as the boundary, so
  bypass reports against them stay in scope after beta.
- `sandbox-exec` is deprecated by Apple but is what Codex, Claude Code and Chromium use; if it
  goes, (a) and (b) on macOS go with it, and the hosts will have to move first.
- Open risks: covert channels through allowlisted hosts (out of scope per DESIGN.md §3);
  proxy-unaware tools lose network; Seatbelt rule precedence surprises (a specific-operation
  deny beats a later wildcard allow); secrets outside `secrets-paths` (browser profiles,
  cookies) stay readable under both options until the policy lists them.
