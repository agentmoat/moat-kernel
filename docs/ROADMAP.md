# Roadmap

Where OpenMoat is, what comes next, and in which order. The release stages and their
exit criteria come from ADR-013. The live, ordered work list is the pinned issue
[#144](https://github.com/crocodile-labs/openmoat/issues/144), and each stage is a
GitHub milestone. Neither carries dates.

## Where it is today

The latest release is `0.1.0-alpha.6`, from GitHub Releases, the Homebrew tap and
crates.io (README, Install). What exists:

- One policy for Claude Code, Codex and Cursor, checked through each host's own hooks.
- Policy kinds `shell`, `fs.read`, `fs.write`, `net`, `fetch`, `env.read`, `env.set`, `mcp`.
- An own POSIX lexer and shell classifier, executable pins (ADR-008) and symlink
  resolution (ADR-009).
- A redacted, hash-chained local audit log with `show`, `replay` and `report`, and
  `moat audit export`, `verify` and `report` for a team (#129).
- Approvals through `moat allow` (ADR-007).
- Self-protection: a policy lock checked on every call (ADR-006), `kernel-self`
  rules, the Claude Code `ConfigChange` veto, and stable hook binary paths (ADR-016).
- Session taint: after a secret read or untrusted content, risky follow-up calls ask
  (ADR-020).
- Repository policy (`<repo>/.moat/policy.yaml`) that only tightens until `moat trust`
  (ADR-022).
- Standard tier: Claude Code's and Codex's own sandboxes configured and pinned from
  the policy (ADR-018).
- Lightweight tier: `moat run` with a generated Seatbelt profile (macOS), or Landlock
  rules and a seccomp filter (Linux), around the whole agent.
- `moat proxy`: default-deny egress with an SNI check, its own DNS and an audit row
  per connection, and a secrets broker that blocks a brokered secret on its way to the
  wrong host (ADR-020). HTTPS injection is not built yet (#247).
- Fail-closed exit codes (ADR-004, ADR-015), a conformance suite tagged by threat
  ([COVERAGE.md](COVERAGE.md)), a differential suite across the hook and the host
  sandboxes, MoatBench mini, and fuzz targets that run in CI.

What it is not yet: enforcement for every call. The hook's decision is not backed by
the operating system; only commands inside the host sandboxes or `moat run` are
confined. Outside them an allowed command runs with your permissions, so a classifier
mistake is a security bug.

## Positioning

The shell classifier triages and the operating system is the boundary. A policy
decision on a command string can be wrong (quoting, encodings, interpreters, programs
that run other programs), and no amount of parser work closes that gap. So:

- Where no OS layer applies (Claude Code's file tools, `WebFetch` and MCP calls, and
  Cursor, unless the agent runs under `moat run`), the classifier is the only layer.
  Bypass reports are in scope ([SECURITY.md](../SECURITY.md)) and become fixtures.
- The parser is frozen (AGENTS.md §5, CONTRIBUTING.md "Decisions"). A newly found
  bypass gets an attack fixture and the smallest change that turns it into `ask`, not
  a new grammar. The time saved goes into enforcement.
- From the beta on, allowed commands run under OS enforcement derived from the same
  policy. A parser mistake then costs a prompt or a confusing message, not a breach.
  Every layer is generated from the one policy and the layers are tested against each
  other (ADR-018 to ADR-020): the host's own sandbox, configured and pinned by OpenMoat, by
  default; a container or VM with OpenMoat outside it for strict use; one egress proxy and a
  secrets broker so the agent never holds credentials.

## Stages

### Alpha: `0.1.0-alpha.N`, decide-only

Milestone `v0.1.0-alpha`; #144 section P1.

| Issue | Work |
|---|---|
| #89 | Release workflow: installers for macOS (arm64, x64), Linux (x64, arm64, musl) and Windows (x64), Homebrew tap, crates.io trusted publishing, attestations |
| #91 | Tag ruleset and strict required checks |
| #94 | This documentation restructure |
| #95 | `moat guard` p95 within 15 ms, with a CI latency check |
| #137–#143 | Host and CLI follow-ups: Claude Code `SendFile`, Cursor payload schema, `Glob` patterns with a directory, `.proposed-*` settings files, exit on a closed pipe, Scoop path in `kernel-self`, shell hardening |
| #124 | A week of daily use by the maintainer, every false positive turned into a fixture |
| #125 | Tag `v0.1.0-alpha.0` |

Exit (ADR-013): installs from a tag on every target, the conformance suite green on
every CI platform, and a week of daily use with every false positive turned into a
fixture.

ADR-013 also listed repo-level policy and a conservative PowerShell tokenizer under
the alpha. #144 now orders repo-level policy (#128) in the beta milestone. A
PowerShell tokenizer has no issue in #144. Until one lands, Claude Code `PowerShell`
always asks.

### Beta: `0.1.0-beta.N`, enforcement

Milestone `v0.1.0-beta`; #144 section P2.

| Issue | Work |
|---|---|
| #119 | Spike (done): Seatbelt does not nest, host defaults leak; outcome in ADR-018, evidence in `spikes/sandbox/` |
| #167 | Policy compiler: one IR, the hook backend over it, "never widens" property tests (ADR-019) |
| #168, #169 | Standard tier: generated and pinned Claude Code `sandbox` settings and Codex permissions (ADR-018) |
| #170 | Executing differential fixtures across the hook, both host sandboxes and every tier, with public CVE replays (ADR-019) |
| #171, #172, #173 | `moat proxy` (default deny, SNI, own DNS), secrets broker, minimal session taint (ADR-020) |
| #174, #175 | Isolated tier: `moat run --isolate` in a rootless container (Linux) or an Apple Virtualization guest (macOS) |
| #176 | Lightweight tier: generated Seatbelt or Landlock and seccomp around the agent |
| #177, #129 | Hash-chained audit log; audit export and a team report |
| #178 | Codex asks through its own `PermissionRequest` prompt: investigated; Codex runs that hook only after it decides to prompt, so a Codex `ask` stays a deny (ARCHITECTURE §5) |
| #128 | Repo-level policy (`<repo>/.moat/policy.yaml`) and `moat trust` |
| #131 | Bypass challenge with 5–10 security people |
| #132 | MoatBench mini (about 40 scenarios) and the launch demo |

Exit (ADR-013): executing fixtures show obfuscated exfiltration failing at the OS
level, and read-then-exfiltrate fixtures are blocked.

### 1.0

Milestone `v1.0.0`; #144 section P3.

| Issue | Work |
|---|---|
| #133 | MCP stdio proxy with tool description pinning, for hosts whose hooks skip MCP |
| #134 | OpenClaw plugin and `moat serve` |
| #135 | Windows enforcement |
| #136 | Stable policy schema, `moat policy migrate`, signed policy packs |

Exit (ADR-013): MoatBench meets its gate and the policy schema is stable.

### More agents

Tracking issue #267 lists every agent checked, with the hook API each one offers.
Until an agent has an adapter, `moat run` can still sandbox it.

| Issue | Agent | Hook it would use |
|---|---|---|
| #264 | Continue CLI (`cn`) | Claude Code-compatible `PreToolUse`. Security: `cn` already loads OpenMoat's Claude Code hooks but ignores `ask` |
| #257 | Gemini CLI | `BeforeTool` |
| #258 | GitHub Copilot (CLI, cloud agent, VS Code) | `preToolUse` in `.github/hooks` |
| #259 | Windsurf | `pre_run_command`, `pre_read_code`, `pre_write_code`, `pre_mcp_tool_use` |
| #260 | Cline | `PreToolUse` script hook |
| #261 | Kiro | `PreToolUse` command hook |
| #262 | Amp | plugin `tool.call` event |
| #263 | goose | `PreToolUse` |
| #265 | OpenCode | plugin `tool.execute.before` and `permission.ask` |
| #266 | Junie (CLI) | `PreToolUse` |

Aider and the Zed agent have no pre-execution hook, and Roo Code has shut down; use
`moat run` for those.

## The team wedge

A team gets value when one policy and one record cover everyone's agents:

1. **Repo policy** (#128). A committed `.moat/policy.yaml` adds rules for everyone who
   works in the repository, whatever agent they use. A cloned repository must not be
   able to loosen a person's policy, so by itself it only adds deny and ask rules; its
   allow rules load only after `moat trust <path>` pins the file by hash (ADR-022).
2. **Audit export** (#129). Decisions exported in a stable format, plus a team report
   built from them.

Both exist on `main`: `moat trust` for repository policy, and `moat audit export`,
`verify` and `report` for a team report over several machines.

## Not planned

- A chat assistant, channel integration, memory system, skills marketplace or UI.
- A model runtime. The kernel does not know which model is running.
- A new tool protocol. MCP is the protocol.
- A replacement for VM or container isolation of whole workloads. OpenMoat composes with them.
- Model-based decisions or intent detection. Decisions are deterministic rules over
  actions.
- Agents that run in a vendor's cloud rather than on the machine OpenMoat runs on.
