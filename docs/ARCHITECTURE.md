# Architecture

How `moat` turns one agent tool call into a decision, a hook response and an audit
record. This describes the code on `main`. The working rules for changing it are in
[AGENTS.md](../AGENTS.md); the policy language is in [POLICY.md](POLICY.md); what
it defends against is in [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Crates

```
moat-cli ──► moat-hosts ──► moat-core
   │                            ▲
   ├──► moat-audit ─────────────┤
   ├──► moat-proxy ─────────────┘
   └──► moat-core
```

| Crate | Role | Rules |
|---|---|---|
| `moat-core` | Policy model and lint, POSIX lexer (`lexer/`), shell classifier (`shell/`), URL host parser (`host.rs`), patterns, path normalisation, the engine, the policy compiler (`ir/`), the repository policy merge (`repo.rs`), `ProgramResolver` and `PathResolver` traits | Pure: no I/O, no `unsafe`, depends only on `serde`, `serde_yaml_ng`, `globset`, `thiserror`. Builds for `wasm32-unknown-unknown` in CI; `tests/architecture.rs` enforces the dependency allowlist and the 500-line file budget |
| `moat-hosts` | Host adapters: `pre_tool_use.rs` (Claude Code and Codex `PreToolUse`), `config_change.rs` (Claude Code `ConfigChange`), `cursor.rs`, `mcp.rs` (MCP arguments to paths and URLs), `patch.rs` (Codex `apply_patch` file list) | Translate payload to `Action` and `Decision` to response. Never decide |
| `moat-audit` | SQLite store, time-window and session queries, redaction | Redact before persisting. Typed `thiserror` errors |
| `moat-proxy` | The egress proxy behind `moat proxy` (§12): request and `ClientHello` parsers, host decisions through moat-core, the address guard, connection relay, the `Recorder` trait the CLI implements over `moat-audit` | Network I/O only through `std::net`; no async runtime; no storage. Depends on `moat-core`, `httparse`, `thiserror` |
| `moat-cli` | The `moat` binary (crate `moat-kernel`): commands, hook installation, the policy lock, approvals, the repository policy file, the environment snapshot, the filesystem resolvers, rendering, exit codes | The only crate that touches files, the environment and the terminal |

No crate depends on `moat-cli`. Planned crates for enforcement are on the
[roadmap](ROADMAP.md); none exist yet.

## 2. One tool call, end to end

```
host payload (stdin)
  └─► adapter (moat-hosts)                 Action, or none for an ungoverned tool
        └─► policy lock check              drift ⇒ deny [kernel-integrity]
              └─► load policy + overlay    ~/.moat/policy.yaml + policy.d/approved.yaml
                    + repository policy    <project>/.moat/policy.yaml, tightening only
                    └─► classify (moat-core)    Action ⇒ atomic actions
                          └─► engine            per atom: deny → allow → ask → defaults
                                └─► combine     strictest wins ⇒ Decision
                                      └─► session grant   ask on a granted shell command ⇒ allow
                                            └─► session taint     earlier calls in the audit log ⇒ allow may become ask
                                                  └─► audit record      failure ⇒ deny [kernel-error]
                                                        └─► hook response (stdout) + exit code
```

`moat guard --host <id>` (`commands/guard.rs`) runs this once per tool call and
exits. There is no daemon.

1. **Read.** At most 1 MiB of UTF-8 from stdin. An empty or unreadable payload is a
   `kernel-error` deny.
2. **Adapt.** The host adapter parses the payload into a `HookRequest`: host, session
   id, call id, working directory, tool name, and an `Action` (`Shell`,
   `ForeignShell`, `FsRead`, `FsWrite`, `Net`, `Fetch`, `Patch`, `McpTool`). A tool
   the adapter does not govern yields no action and is allowed with rule `ungoverned`
   and recorded. A malformed payload is a `kernel-error` deny.
3. **ConfigChange.** A Claude Code `ConfigChange` takes its own path: the changed file
   is compared with `policy.lock`, and a pinned file that drifted is blocked for the
   session (§6).
4. **Lock.** `integrity::violation` recomputes every digest in `policy.lock`. Any drift
   denies the call with `kernel-integrity` before the policy is read.
5. **Context.** `EvalContext` carries the home directory, the project root (git root
   above the call's working directory, never the home directory, an ancestor of it or
   a filesystem root; `project.rs`), their symlink-resolved spellings, the working
   directory and whether paths compare case-insensitively.
6. **Policy.** `~/.moat/policy.yaml` is parsed and linted (1 MiB limit). Rules from
   `policy.d/approved.yaml` are appended to `allow` and the result is linted again.
   When the project has a repository policy (`<project>/.moat/policy.yaml`, ADR-022),
   `repo.rs` reads it and `moat_core::RepoPolicy::merge`, a pure function, merges it:
   its deny groups join `deny`, its ask groups go into `repo_ask`, which the engine tries
   between `deny` and `allow`. Its allow groups are appended to `allow` only when
   `~/.moat/trust.json` is pinned by the lock and records the SHA-256 of these exact
   bytes for this project root (symlinks resolved); otherwise they are dropped. Its
   rule ids get the prefix `repo:`. A repository policy that is not a regular file,
   cannot be read or does not parse is a `kernel-error` deny.
7. **Decide.** `CompiledPolicy::compile(policy, ctx).decide_with(action, snapshot,
   FsPathResolver)` classifies and evaluates (§3, §4).
8. **Grant.** An `ask` for a shell command whose exact text was granted for this host
   session with `moat allow` becomes `allow` with rule `approved-session`. A grant
   never touches a `deny` and expires 24 h after it was given; expired grants are
   ignored and pruned.
9. **Taint.** `taint::of_session` (`taint.rs`) reads this host session's earlier events
   from the audit log. It folds `CompiledPolicy::exposure` over the calls that may have
   run: allowed calls, and asks on a host that can ask. Each call is resolved from its
   own recorded working directory. `CompiledPolicy::with_taint` then tightens the
   decision (POLICY.md §4.1). This runs after the grant, so a grant cannot lift a taint
   ask. A log or session event that cannot be read is a `kernel-error` deny. An edited
   or deleted event is found by the hash chain (`moat doctor`), not on every call.
10. **Record.** The event is appended to the audit log's hash chain (§7). If it cannot
   be written, the decision becomes a `kernel-error` deny: an unrecorded call is not
   allowed.
11. **Respond.** The adapter renders the host's response document. `deny` also prints
    the reason line on stderr and exits 2.

A panic inside steps 1–10 is caught and answered with a deny and exit 2, because
Claude Code treats exit 101 as a non-blocking error.

## 3. Classification

`moat-core` turns an `Action` into atomic actions (`AtomicAction`): `Shell`,
`Pipeline`, `FsRead`, `FsWrite`, `Net`, `Fetch`, `EnvRead`, `EnvSet`, `McpTool`.

- **Shell** (ADR-005). The lexer (`lexer/`) reads words, quotes, escapes, operators,
  redirections, `$( … )`, backticks, here-documents and here-strings, up to 64 KB. The
  classifier (`shell/`) emits one `Shell` atom per simple command and one `Pipeline`
  atom per pipeline suffix. It recurses into `sh -c`, `eval`, substitutions and
  wrappers (`sudo`, `env`, `xargs`, `timeout`, …) to depth 4. It adds `fs.read`/`fs.write`
  atoms for redirections and file operands (`operands.rs`), relative paths resolved
  through `cd`/`pushd` (`cwd.rs`), `net` atoms for URLs and hosts, and `env.*` atoms
  for assignments and `$VAR` reads. Shell options are read per shell
  (`invocation.rs`), git's global options are unwrapped (`git.rs`), `make` arguments
  that run code (`make.rs`), options that run programs (`options.rs`) and decoder
  pipelines (`decoders.rs`) are surfaced. Inline interpreter code (`python -c`,
  `node -e`) is scanned for paths, hosts and variable names, not parsed. Output is
  capped at 2048 atoms.
- **ForeignShell** (Claude Code `PowerShell`). Always `ask` with rule `unparseable`;
  there is no PowerShell parser.
- **ReadFiles** (Claude Code `SendFile`, absolute Glob patterns). One `fs.read` per
  path; an empty list asks.
- **Patch** (Codex `apply_patch`). One `fs.write` per added, updated, deleted or
  moved-to file; a patch naming no file asks.
- **McpTool.** An `mcp` atom for the tool name, plus `fs.*` and `net` atoms for path-
  and URL-shaped arguments found at any depth (`moat-hosts/src/mcp.rs`).
- **Fetch** (Claude Code `WebFetch`). A `fetch` atom for the URL's host (ADR-017).

Anything the lexer or classifier cannot make sense of is `unparseable`, which the
engine turns into `ask`, never `allow`.

### Host tool mapping

| Host tool | Field read | Action |
|---|---|---|
| Claude Code, Codex `Bash`; Cursor `beforeShellExecution` | `command` | `Shell` |
| Claude Code `Monitor` | `command`, or `ws.url` (exactly one) | `Shell`, or `Net` |
| Claude Code `PowerShell` | `command` | `ForeignShell` |
| Claude Code `Read`; Cursor `beforeReadFile`, `preToolUse` `Read` | `file_path` | `FsRead` |
| Claude Code `LSP` | `filePath` | `FsRead` |
| Claude Code `Glob`, `Grep`; Cursor `preToolUse` `Glob`, `Grep` | `path`, else the working directory; an absolute or `~` Glob `pattern` also reads its directory part (Claude Code searches that instead of `path`) | `FsRead`, `ReadFiles` |
| Claude Code `SendFile` | every path in `files` (the contents go to another session; an empty or non-string list is an adapter error, so `deny`) | `ReadFiles` |
| Claude Code `Edit`, `Write`, `MultiEdit`; `NotebookEdit` | `file_path`; `notebook_path` | `FsWrite` |
| Cursor `preToolUse` `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete` | `file_path` | `FsWrite` |
| Claude Code `WebFetch` | `url` | `Fetch` |
| Codex `apply_patch` | `command` (the patch envelope) | `Patch` |
| `mcp__<server>__<tool>` (Claude Code, Codex); Cursor `beforeMCPExecution` | tool name and arguments (Cursor: `mcp_server_name`, `tool_name`, `tool_input`) | `McpTool` |
| anything else (Claude Code `Task`, Codex `update_plan`, Cursor `preToolUse` `Shell`) | — | none: `ungoverned` |

Claude Code calls only reach `moat` for tools in the installed matcher
(`crates/moat-cli/src/install/mod.rs`); a tool outside it is never seen.
Cursor's hook documentation names `Grep` but not `Glob` and gives no file tool's
arguments, so those keys are unverified (`tests/fixtures/hosts/cursor/README.md`).

## 4. Decision

For each atomic action, the lists are tried in order `deny → allow → ask`; the first
list with a match decides that atom. A repository policy's ask groups (`repo_ask`) are
tried between `deny` and `allow`. If none matches, `defaults` decides (rule id
`default.<kind>` or `default`). The verdict for the tool call is the strictest across
its atoms: `deny > ask > allow`. Deny is absolute (ADR-002). A `fetch` atom also
matches `net` patterns and falls back to the `net` default (ADR-017). The decision
carries the rule ids that produced the final verdict and weaker matches as context.

### Resolvers

The engine needs two facts that live on the filesystem. `moat-core` defines a trait
for each and the CLI implements it:

| Trait | ADR | Implementation | What it adds |
|---|---|---|---|
| `ProgramResolver` | ADR-008 | `environment.rs` (`Snapshot`) | The first word of each command is resolved through the search path recorded at `moat init` (`environment.json`), not the hook's inherited `PATH`. A pinned program (policy `executables:` or the snapshot) that now resolves elsewhere is a deny with rule `executables` |
| `PathResolver` | ADR-009 | `realpath.rs` (`FsPathResolver`) | Every `fs.read`/`fs.write` path is also checked at its symlink-resolved location; both are evaluated and the strictest wins. New files resolve through their deepest existing ancestor |

Patterns naming `${project}` or `~` are compiled for both the written and the resolved
spelling of the root, so a project under macOS `/tmp` → `/private/tmp` matches either
way. `moat policy check` uses the same resolvers (the snapshot only when an
installation exists) and, against the installed policy, the same lock check.

### Policy compiler

ADR-019 makes `policy.yaml` the single source for every enforcement point.
`moat_core::ir::lower(policy, ctx)` derives the `Enforcement` IR from the same policy
and `EvalContext` the engine compiles. The engine is the hook backend. Claude Code's and
Codex's sandbox settings are generated from the IR (§13); Seatbelt, Landlock and the
egress proxy will be (#176).

| IR part | Contents |
|---|---|
| `fs.read`, `fs.write` | per kind: a default (`allow`/`deny`), deny rules, allow rules. Each rule is one policy group's list, expanded like the engine's patterns (both root spellings, `!` exclusions kept) |
| `egress.net`, `egress.fetch` | the same for hosts. `fetch` takes rules from `fetch` and `net` lists. Both always deny `moat.cloud-metadata` (ADR-020) |
| `secrets`, `limits` | empty until the policy schema defines them (#172) |
| `decide_only` | rule ids per kind the IR cannot carry: `shell`, `env.read`, `env.set`, `mcp`, and `executables` program names |
| `losses` | every place the IR is stricter than the hook, with a message |
| `allowances` | where OS layers may be wider than the hook: `sandbox.read_roots` (ADR-021). Kept out of `fs.read`, so the IR's own verdicts never widen; `Checker::check_os` applies them after the deny rules |

Per access the IR applies deny rules, then allow rules, then the default.
`ir::Checker` is that reference evaluation.

**Lowering never widens.** An `ask` default lowers to deny. An `ask` rule disappears
under a deny default, where the outcome is the same. Under an allow default it becomes a
deny rule, which also denies where an allow matches. Each case is a loss.

Two tests prove agreement with the engine:
- `tests/ir_consistency.rs` checks every fs, net, fetch and patch conformance fixture.
  The IR verdict on the engine's own atoms (`CompiledPolicy::atoms`, symlinks included)
  must equal the engine verdict, with `ask` read as deny.
- `tests/ir_never_widens.rs` lowers generated policies and checks that an IR allow is
  always an engine allow.

`moat policy compile` prints the IR.

## 5. Hook responses and exit codes

| Host event | Response | Exit |
|---|---|---|
| Claude Code, Codex `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":…,"permissionDecisionReason":…}}` | 0, or 2 on deny |
| Cursor `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` | `{"permission":…,"user_message":…,"agent_message":…}` | 0, or 2 on deny |
| Claude Code `ConfigChange` | `{}` or `{"decision":"block","reason":…}` | 0, or 2 on block |

`ask` is the host's own prompt; `moat` has no prompt of its own. Codex cannot ask:
its `PreToolUse` rejects `permissionDecision: "ask"` as unsupported and then runs the
call. So for Codex an `ask` is sent as a `deny` (exit 2) whose reason says to approve
it with `moat allow --last`. The audit log keeps the `ask`, which is what `--last` finds
(`Host::answer`).

Codex's `PermissionRequest` hook does not change this (#178, checked against
openai/codex `ff9ab4a` and codex-cli 0.160.1). Codex runs it only from
`Session::request_approval` (`core/src/tools/approvals.rs`), after its own approval
policy and sandbox have decided to prompt. The hook can answer allow, deny or nothing;
nothing shows Codex's prompt. No hook can send a call into that path, so a `PreToolUse`
`ask` that let the call through would run unprompted whenever Codex itself does not
prompt. `moat init` therefore does not install `PermissionRequest`. `guard` refuses that
event as a wrong event (deny, exit 2, reason on stderr), which Codex reads as a deny
(`tests/fixtures/hosts/codex/permission-request-shell.json`, built from Codex's
`permission-request.command.input.schema.json`). Exit codes follow
ADR-004 and ADR-015: 0 allow or ask, 2 deny, 3 unresolved ask from `moat policy
check`, 64 usage or configuration error. `guard` never exits 64: an argument it cannot
parse is a deny with exit 2, because Claude Code and Codex proceed on any other
non-zero exit. Cursor is fail-open unless a hook sets `failClosed: true`, so
`moat init` sets it on every Cursor hook.

## 6. Self-protection

- **Policy lock** (ADR-006). `~/.moat/policy.lock` pins SHA-256 digests of the policy,
  `environment.json`, `approvals.json`, `policy.d/approved.yaml`, `trust.json` and every
  hook file `moat` installed, keyed by location so a swap for a symlink is a
  modification, and the part of Codex's `config.toml` that holds moat's sandbox profile
  (§13). It is verified on every `guard` call. Only a person re-pins: `moat init`, or
  `moat doctor --accept`, `moat allow`, `moat trust` and `moat sandbox sync` from an
  interactive terminal.
- **ConfigChange veto.** Claude Code reports settings changes; a pinned file that no
  longer matches the lock is blocked for the session. Codex and Cursor have no such
  event, so there the next tool call is denied instead. A `/settings-review` accept
  writes the new contents to `<file>.proposed-<8 hex>`, fires `ConfigChange` for that
  copy and renames it over the file only if no hook blocks; when `<file>` is pinned,
  the copy is blocked unless the file still matches the lock and the copy's bytes equal
  the pinned ones, so a reviewed edit of a pinned file cannot pass the hook.
- **`kernel-self` rules.** The default policy denies agent writes to the state and
  host directories, hook files and any `bin/moat`, and denies `moat
  allow|doctor|init|policy|trust` from an agent, including under pseudo-terminal
  wrappers (ADR-011, ADR-014).
- **Terminal check.** `moat allow`, `moat trust` and `moat doctor --accept` refuse to
  run without a terminal (`terminal.rs`). The debug-only `MOAT_ASSUME_TTY` override exists for tests.
- **Stable hook path** (ADR-016). Hooks run the package manager's stable link to
  `moat`, not a versioned file an upgrade deletes; `doctor` and `status` name a hook
  whose binary is missing or is a different `moat`.

## 7. Audit log

`~/.moat/audit.db` is SQLite in WAL mode, created with mode 0600, with one `events`
table (time, host, session, call id, working directory, tool, action, verdict, rules,
reasons, latency). Every governed and ungoverned call is recorded. Command, path and
URL fields pass through `moat_audit::redact` first (bearer and basic auth,
`key=value` credentials, common token shapes, URL passwords). `show`, `replay` and
`report` read it; nothing leaves the machine unless a person runs `moat audit export`.

**Hash chain** (schema 2, `crates/moat-audit/src/store/chain.rs`). Each event also
stores `prev_hash`, the `hash` of the event before it, and `hash`, the lowercase hex
SHA-256 of its canonical encoding. The encoding (version 1) is the concatenation of:
the domain tag `moat-audit-chain-v1` as a string; `id` and `ts_ms` as integers;
`host` and `session_id` as strings; `call_id` and `cwd` as optional strings; `tool`,
`action`, `verdict`, `rules` and `reasons` as strings, exactly as stored (the redacted
JSON text for `action`, `rules`, `reasons`); `latency_us` as an integer; `prev_hash`
as a string. An integer is 8 bytes big-endian; a string is its UTF-8 byte length as
8 bytes big-endian followed by the bytes; an optional string is `0x00` when absent,
else `0x01` and the string. The first chained event's `prev_hash` is 64 zeros. The
encoding hashes stored cells, not re-serialised values, so a later build that
serialises actions differently still verifies old events; changing the encoding
needs a new domain tag.

`guard` appends in one `BEGIN IMMEDIATE` transaction: read the newest event's id and
hash, insert the next event with `id + 1` linked to it, commit. Concurrent `guard`
processes serialise on SQLite's write lock (busy timeout 2 s), so the chain never
forks; a write that fails or times out is a `kernel-error` deny as before. The
transaction adds about 0.1 ms to a guard call. `moat doctor` re-hashes the whole log
oldest first (about 0.15 s per 100 000 events) and reports the first event that was
edited (contents do not match its hash), unlinked (an event before it was deleted or
inserted, or events were reordered) or unhashed, and exits 64.

**Export** (`moat audit export`, `crates/moat-audit/src/store/export.rs`). JSON Lines,
oldest first, one object per chained event with the filters `--since`, `--host` and
`--session`. Every line has `"format": "moat-audit-export-v1"` and the fields `id`
(hex), `ts_ms`, `host`, `session_id`, `call_id`, `cwd`, `tool`, `action`, `verdict`,
`rules`, `reasons`, `latency_us`, `prev_hash` and `hash`. `action`, `rules` and
`reasons` are the stored JSON text embedded byte for byte, not re-serialised, so the
line holds exactly the cells the chain hashed; a field outside this list makes the
line invalid. Cells are already redacted in the store and are not touched again, so
an export holds no more than the database. Events from before the chain have no hash
and are left out. A new line format gets a new `format` value.

**Verify** (`moat audit verify`, `store/export_verify.rs`). It works without the
database. Every line must hash to its `hash`, ids must rise, and a line whose id
follows the previous line's id must carry that line's hash as `prev_hash`. A jump in
ids is a gap, which is counted and not failed: a filtered export has gaps, and so
does deleting events. The first failing line is named and the command exits 64. The
head is the last line's `hash`. `moat doctor` prints the database head. With
`--anchor <hash>`, verify also fails unless a verified line carries that hash.

**Team report** (`moat audit report <file>…`, `crates/moat-cli/src/commands/team.rs`).
It verifies every file first and refuses (exit 64) if one fails. Events with the
same `hash` are counted once, so overlapping exports do not double-count. The report
starts with the `moat report` summary (`Summary::of`), then shows each file's head,
verdicts per host, asks and denies per rule, and the most frequent asked and denied
actions. False-positive candidates are actions that asked and were also allowed by
an `approved-…` rule (`moat allow`), which suggests the asking rule is too broad.
`--format json` gives the same data.

The upgrade from schema 1 adds the two columns and records the last existing id as
`legacy_last_id` in a `meta` table. Existing events are not hashed: they were written
unprotected, and hashing them during the migration would vouch for whatever they hold
at that moment. `doctor` counts them as not covered; an event without a hash after
`legacy_last_id` is a break. What the chain does not detect is in [THREAT_MODEL.md](THREAT_MODEL.md) §5.

## 8. Files on disk

```
~/.moat/                       ($MOAT_HOME overrides; directory 0700, files 0600)
  policy.yaml                  user policy (moat init writes the default once)
  policy.d/approved.yaml       permanent approvals from `moat allow --always`
  approvals.json               session grants from `moat allow` (24 h each)
  trust.json                   repository policies trusted with `moat trust`: root → SHA-256
  environment.json             search path and program locations recorded at init
  policy.lock                  digests of the files above and of installed hook files
  audit.db                     audit log
~/.claude/settings.json        Claude Code hooks and sandbox block ($CLAUDE_CONFIG_DIR overrides)
~/.codex/hooks.json            Codex hooks ($CODEX_HOME overrides)
~/.codex/config.toml           Codex [permissions.moat] profile, default_permissions
<file>.moat-sandbox-backup     each host file before moat's last sandbox edit
~/.cursor/hooks.json           Cursor hooks ($CURSOR_CONFIG_DIR overrides)
<project>/.moat/policy.yaml    repository policy, committed by the team (ADR-022)
```

Host sandboxes and `moat proxy` are generated from the user policy only. Repository
rules apply in the hook.

## 9. Invariants

The full list, with the tests that hold each one, is AGENTS.md §3. In short: deny is
absolute; strictest wins; unparseable is `ask`; every error path in `guard` is a deny
with exit 2; exit codes 2 and 3 mean nothing else; nothing persisted skips
redaction; the core stays pure; `moat init` never overwrites a policy or duplicates a
hook; the lock is checked before any decision.

## 10. Repository layout

```
crates/moat-core/              decision core; policies/default-v1.yaml is the shipped policy
crates/moat-hosts/             host adapters
crates/moat-audit/             audit store
crates/moat-proxy/             egress proxy; tests/proxy/ runs it on loopback
crates/moat-cli/               the moat binary; tests/e2e/ runs it in isolated homes
tests/conformance/             attacks.yaml, ask.yaml, benign.yaml: one tool call each,
                               with the verdict the default policy must give
tests/fixtures/hosts/          real host payloads (claude-code, codex, cursor)
fuzz/                          cargo-fuzz targets: decide_shell, policy_parse,
                               host_payload, literal_pattern, proxy_parse
                               (separate workspace)
docs/                          this document, POLICY, THREAT_MODEL, ROADMAP,
                               COVERAGE (generated), adr/
scripts/ci/quality-gate.sh     the one gate CI and the pre-push hook run
scripts/ci/guard-latency.py    times `moat guard` per process in CI (the `latency` job)
scripts/ci/sync-labels.sh      the repository's label set
```

## 11. Testing layers

| Layer | Where | Runs |
|---|---|---|
| Unit | next to the code (`#[cfg(test)]`, `tests.rs` modules) | every PR, all OS |
| Architecture invariants | `crates/moat-core/tests/architecture.rs` | every PR |
| Conformance (decide) | `tests/conformance/` through `crates/moat-core/tests/conformance.rs`; generates `docs/COVERAGE.md` and fails on a threat class without an attack fixture | every PR, all OS |
| Policy compiler | `crates/moat-core/tests/ir_consistency.rs` (IR against the engine on the conformance fixtures), `ir_never_widens.rs` (generated policies) | every PR, all OS |
| Golden host payloads | `tests/fixtures/hosts/` | every PR |
| End to end | `crates/moat-cli/tests/e2e/` (real binary, isolated `HOME`/`MOAT_HOME`) | every PR, all OS |
| Proxy | `crates/moat-proxy/tests/proxy/`: a real listener and a local upstream on loopback, names mapped by a test resolver, no external network | every PR, all OS |
| `wasm32` purity build | CI job | every PR |
| Fuzz | `fuzz/`, one minute per target on PRs, ten minutes weekly | CI |
| Guard latency | `scripts/ci/guard-latency.py`: one process per call, end to end and as recorded by guard; warns above the 15 ms p95 budget, fails above 45 ms (about 3 ms deciding and 8 ms end to end on Apple silicon) | every PR, `latency` job (not required) |

CI runs `scripts/ci/quality-gate.sh` on macOS (arm64, x64), Linux and Windows, plus
`cargo-deny`, the crate packaging check and `actionlint`/`zizmor` on workflows.

## 12. Egress proxy

`moat proxy [--listen 127.0.0.1:18080]` is the default-deny network exit from ADR-020.
Nothing routes traffic through it yet. The hosts' sandbox settings (`httpProxyPort`,
Codex's proxy) will. Why it is our own code on `std::net` and
`httparse`, rather than `codex-network-proxy` or `sandbox-runtime`, is in
[notes/proxy-evaluation.md](notes/proxy-evaluation.md).

- **Start-up.** It refuses a non-loopback listen address, a missing installation and a
  drifted policy lock (exit 64). It compiles the policy once, so restart it after a policy
  change. It writes to the audit log under one session id per run (`proxy-<ms>`).
- **Brokered secrets** (POLICY.md §2.1). `commands/proxy.rs` has `secrets/` read each
  source (a file, an env var, or a keychain item through the OS tool by absolute path)
  into a zeroed-on-drop buffer and hand it to `moat_proxy::Broker`. A source that cannot
  be read stops start-up. Only ids, hosts, headers and placeholders are printed.
- **Per connection,** in this order:
  1. Read the request head, at most 16 KiB within 10 s. Two forms are served:
     - `CONNECT host:port`
     - one absolute-form `http://` request

     Refuse (`proxy-secret`) a request whose head, or body bytes read with it, carries a
     brokered secret's placeholder or value when the host is not that secret's own.
  2. Decide the host as a `fetch` atom through `CompiledPolicy` (POLICY.md §4). Only
     `allow` passes. An `ask` is refused, because the proxy cannot prompt.
     `metadata.google.internal` and `metadata.goog` are refused by name whatever the
     policy says.
  3. Resolve the name with the system resolver (IP literals skip it). Refuse the
     connection when any resolved address is loopback, link-local, a cloud metadata
     address (`100.100.100.200`, `fd00:ec2::254`, NAT64 and IPv4-mapped forms included)
     or not unicast. Also refuse it when an address is private, CGNAT, benchmarking or
     unique-local and no allow rule names that address (POLICY.md §5.2). Those rules are
     compiled once at start-up into a second policy that holds only address patterns.
     Connect only to an address that was checked.
  4. For CONNECT:
     - answer `200`, then read the TLS `ClientHello` (up to 64 KiB, reassembled across
       records);
     - its SNI must equal the CONNECT host. For an IP-literal host there must be no SNI.
     - Anything else, including non-TLS bytes, closes the tunnel before one byte is
       forwarded.
  5. For plain HTTP:
     - rewrite to origin form;
     - the `Host` header must match the target;
     - drop hop-by-hop headers (`Connection` and the headers it names, `Proxy-*`, `TE`,
       `Trailer`, `Upgrade`, `Keep-Alive`) and add `Connection: close`;
     - refuse `Content-Length` with `Transfer-Encoding`, or more than one `Content-Length`;
     - after the row is recorded, put the value of each brokered secret the host owns
       and that sets `plain_http` into the head (POLICY.md §2.1). The head is zeroed once
       it is written. A secret without `plain_http` is not injected, and the row's reasons
       say so.
  6. Record one audit row: host `proxy`, the method as the tool, the action
     `net` `connect://host:port` or `http://host:port` (never the path), and the verdict
     and rules. If the row cannot be written, the connection is refused.
  7. Relay bytes both ways. A connection is closed after 120 s with no bytes in either
     direction. A plain-HTTP client stream keeps being checked for brokered secrets,
     across read boundaries. A chunk that completes one is not forwarded: the
     connection closes and a second row (`proxy-secret`) is recorded.
- **Rule ids of its own:**
  - `proxy-address`: refused destination
  - `proxy-sni`: SNI missing or mismatched, or not TLS
  - `proxy-request`: unparseable or unsupported request
  - `proxy-upstream`: DNS or connect failure
  - `proxy-secret`: a brokered secret sent towards a host other than its own
  - `proxy-audit`: written to stderr only, since the audit log is what failed
- **Limits:**
  - 256 concurrent connections; the next is answered `503`.
  - 10 s to connect upstream.
  - One thread per direction of each connection.
- **Not yet:** TLS termination for per-host method and path rules and for injecting
  secrets into HTTPS (opt-in, ADR-020), session taint for proxied connections (they carry
  no host session; the hook applies taint, §2 step 9), and a policy reload without
  restart.

## 13. Standard tier: host sandboxes

ADR-018's default tier configures each host's own sandbox from the policy, through the
one IR of ADR-019 (`moat_core::ir`, `crates/moat-cli/src/sandbox/`).

```
policy.yaml ─► ir::lower (project = placeholder) ─► Enforcement ─┬─► claude::generate ─► settings.json "sandbox"
                                                                 └─► codex::generate  ─► config.toml [permissions.moat]
```

- **One host-wide lowering.** Host settings are per user, not per session, so the IR
  is lowered once with a placeholder project. Each backend maps project patterns to
  the host's own workspace: Claude Code's working directories (implicit), Codex
  `:workspace_roots`.
- **Reads.** `sandbox.read_roots` lowers to an `Allowance`, kept apart from the IR's
  read rules so the IR's own verdicts stay the hook's or stricter.
  `Checker::check_os` is the reference for OS layers: deny rules, then allowances,
  then the IR's rules. Claude Code gets `allowRead` plus
  `permissions.blockReadsOutsideWorkingDirectories`; Codex gets an explicit profile
  (`:minimal`, the roots, the workspace) that does not extend `:workspace`, which reads
  the whole disk.
- **Writes** stay in the project, the temp directory and paths an allow rule names as
  a literal tree. Deny rules become `denyWrite` (Claude Code) or `deny`/`read` entries
  (Codex, which has no write-only glob).
- **Network.** The `net` rules' domain names become `allowedDomains` with
  `strictAllowlist` (Claude Code) and `network.domains` behind
  `features.network_proxy` (Codex). Hosts that are not domain names
  (`169.254.*`) stay unlisted, so they stay denied. `httpProxyPort` is not set yet:
  pointing the hosts at `moat proxy` (§12) is a follow-up of ADR-020.
- **Losses and allowances.** A backend narrows what it cannot express and reports it
  as a loss. It may widen only where the host cannot run otherwise (the read roots,
  Codex `:minimal` and `:tmpdir`, Claude Code's working directories and unblocked
  system paths, directory nodes left out of `denyWrite`, `.git` outside its
  code-execution paths so `git commit` works), and each of those is
  listed. `moat sandbox show`, `sandbox sync` and `doctor` print both.
- **Traps the generators handle** (found in the spike, re-verified on Claude Code
  2.1.290 and codex-cli 0.160.1): a relative pattern in Claude Code user settings
  resolves against `~/.claude`, so every pattern is absolute (`/**/.env`); a directory
  in `denyWrite` covers its subtree, so `**/.claude` (a directory-node rule) is left
  out and `.claude/worktrees/*` stays writable; Claude Code's `allowRead` of a `**/`
  exception re-opens it everywhere, so exceptions are dropped; Codex accepts globs
  only for `deny` and not under `:tmpdir`, and keeps `.git` read-only.
- **Writing and pinning.** `moat init` and `moat sandbox sync` merge the generated
  keys into the files, keeping every other key (JSON values; TOML through `toml_edit`,
  comments included), and back each file up first. `policy.lock` pins Claude Code's
  `settings.json` whole and Codex's `config.toml` by the canonical text of the part
  moat owns (`default_permissions`, `[permissions.moat]`, `features.network_proxy`),
  because Codex writes trusted projects into that file itself. Drift is
  `kernel-integrity`; `doctor` also fails on a weakened or out-of-date setting.
