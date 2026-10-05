# agentmoat — How It Becomes Strong, and How We Prove It

Version 0.1 · 2026-10-02 · Companion to `DESIGN.md`. This document exists because
"policy + audit" alone is a weak product. It lists where agentmoat would be weak,
what makes it strong instead, and the public benchmark that proves it.

Status (2026-10-05): L1 (policy decision) and L5 (integrity) are built; L2–L4 (`moat exec`,
egress proxy, session taint) and MoatBench are design, not code. §2.1–2.3, §3 and most of
§4 describe planned work and are marked **planned**. What exists: `PROGRESS.md`.

---

## 1. Brutal list: where this product dies if we are not careful

| # | Weakness | How it kills us | Fix (section) |
|---|---|---|---|
| W1 | **Decide-only is a regex firewall.** Phase 1 matches strings; a security researcher posts a 5-minute bypass on launch day. | Credibility gone permanently. | Enforce from v0.1, not just decide: `moat exec` wraps every allowed shell command in an OS sandbox (§2.1). The parser becomes UX; the OS is the boundary. |
| W2 | **Network rules that do not enforce.** "net: deny *" that only looks for URLs in text is theatre. | Same as W1. | Egress proxy + sandbox network block from v0.1 on macOS/Linux (§2.2). Until then label `advisory`. |
| W3 | **Allowed channels become exfil channels.** `api.github.com` is allowed; secrets leave via a gist. | Deterministic rules cannot see it. | Session taint: once a session touched a secret, every egress needs approval; egress size budget (§2.3). |
| W4 | **Hosts fail open.** Missing binary → action proceeds. | Silent non-protection. | `doctor`, `failClosed` where supported, MCP proxy and `moat exec` as independent layers, honest coverage matrix per host (§2.5). |
| W5 | **The agent edits us out.** | Silent non-protection. | Lock + per-call integrity + `ConfigChange` veto + protected paths; signed policy in Phase 2 (§2.4). |
| W6 | **Prompt fatigue.** Users disable it in a day. | No users. | Learn mode, project-scoped defaults, measured asks/hour as a release gate (§4.2). |
| W7 | **No proof.** "Trust us" from an unknown author. | No adoption among the exact people we target. | MoatBench: public, reproducible, nightly, against real agents, with and without us (§3). |
| W8 | **Parser bugs.** A tokenizer edge case = bypass. | Bypass class W1. | Fuzzing, differential testing against real bash, property tests, mutation testing (§4.1). |
| W9 | **Our own supply chain.** | We become the HookPry vector. | Reproducible builds, Sigstore signing, SBOM, pinned absolute hook paths (§4.3). |
| W10 | **Windows is a second-class citizen.** | Half the market, and the first "does not work on Windows" issue is pinned forever. | Windows in CI from week 1; decide + audit on day one; AppContainer enforcement in Phase 2 with a published date (§2.6). |
| W11 | **Only shell is covered.** File tools, MCP tools, web fetch bypass the shell rules. | Trivial bypass by using a different tool. | Every host tool kind maps to atomic actions; MCP proxy for MCP; coverage matrix is public (§2.5). |
| W12 | **Looks like Codex's sandbox, worse.** | "Why not just use Codex?" | We are cross-agent, policy-as-code, audited, with taint and env hardening; and we *wrap* Codex/Claude Code sandboxes rather than replace them (§5). |

## 2. Strength architecture: five independent layers

Each layer alone is bypassable. Together, an attacker must defeat all of them, and
each layer is measured separately in the benchmark.

```
L5  Integrity       policy.lock · hook + file pinning · binary path · ConfigChange veto   (built)
L4  Session taint   secret-read ⇒ egress needs approval · egress byte budget · anomaly flags (planned)
L3  Egress proxy    per-session allowlist · TLS SNI/Host match · logs every connection      (planned)
L2  OS enforcement  moat exec: Seatbelt / Landlock+seccomp(+bwrap) / AppContainer           (planned)
L1  Policy decision deny → allow → ask on normalised atomic actions                          (built)
```

### 2.1 L2: `moat exec` (enforce, not just decide) — planned

Hosts let hooks **rewrite** the tool input (Claude Code `updatedInput`, Codex
`updatedInput`, OpenClaw `params`). On `allow`, instead of returning the command
unchanged, the kernel returns:

```
moat exec --profile <hash> -- <original command>
```

`moat exec` applies an OS sandbox derived from the *same policy* that produced the
verdict:

| OS | Mechanism | Reuse |
|---|---|---|
| macOS | Seatbelt profile generated from `fs.*` and `net` rules (`sandbox-exec`/`sandbox_init`) | Codex and Anthropic `sandbox-runtime` do exactly this; profiles are public |
| Linux | Landlock (fs) + seccomp (network syscalls) + bubblewrap when available (mounts, net namespace) | Codex `linux-sandbox`, `skarn-sandbox`, `rust-landlock` |
| Windows | Phase 1: decide + audit only. Phase 2: AppContainer + Job Object via worker process | `skarn-sandbox` pattern |

Consequences:
- Obfuscation (`bash -c`, base64, `eval`) no longer matters: the child process cannot
  read `~/.ssh` or open a socket regardless of how the command was spelled.
- Environment poisoning is neutralised: `moat exec` launches with a kernel-controlled
  env and PATH, not the agent's.
- The parser's job becomes "produce a good profile and good messages", not "be the boundary".
- Hosts that already sandbox (Codex, Claude Code) compose: our profile is applied inside
  theirs; strictest wins.

Cost: one extra process spawn per command (~5–10 ms). Acceptable; measured in benchmark.

### 2.2 L3: egress proxy — planned

`moat exec` sets `HTTP(S)_PROXY`, `ALL_PROXY` and, where the sandbox supports it,
blocks direct outbound so only the local proxy can reach the network (Anthropic's
and Codex's pattern). The proxy enforces the session's `net` allowlist by hostname
(CONNECT/SNI), logs every connection (host, bytes, duration) to the audit DB, and
feeds L4. Tools that ignore proxies get no network at all.

### 2.3 L4: session taint and budgets (the layer rules cannot provide) — planned

Deterministic, no LLM:
- **Taint**: when a session reads anything matching `secrets` classes (even if allowed,
  e.g. `.env` inside the project), the session is marked `tainted:secrets`. From then on
  every `net` action, including allowed hosts, becomes `ask` with the reason
  "session read `.env` 2 steps ago". Clears on session end.
- **Egress budget**: per-session outbound byte budget to non-registry hosts (default 1 MB);
  exceeding it ⇒ ask.
- **Anomaly flags** (audit-only in v0.1, policy-usable later): first-seen host for this
  repo, outbound to IP literals, DNS-looking hostnames with high entropy, archive/encode
  then upload sequences.

This directly targets the GitHub-MCP-style incident (read private token → exfiltrate
via next tool call) that pure allowlists cannot stop.

### 2.4 L5: integrity (covered in DESIGN §9 G1, G12)

Built: `moat guard` verifies the policy, `environment.json`, the approval files and every
installed hook file against `policy.lock` on each call (entries keyed by file location and
symlink-aware since #26); any drift denies everything with `kernel-integrity`; protected
paths in the default policy; Claude Code `ConfigChange` veto; executable pins (ADR-008).
The lock records the `moat` binary's path, which `doctor` compares; the binary's hash is
not pinned. Planned: signed policy bundles (Phase 2). Details: ADR-006.

### 2.5 Coverage matrix (published, kept honest)

| Host | Shell | File read/write | Web fetch | MCP tools | Enforce (L2) | Fail-closed if moat missing |
|---|---|---|---|---|---|---|
| Claude Code | `PreToolUse` (`Bash`) | `PreToolUse` (`Read`, `Glob`, `Grep`; `Edit`, `Write`, `MultiEdit`, `NotebookEdit`) | `PreToolUse` (`WebFetch`; `WebSearch` is not in the matcher) | `PreToolUse` (`mcp__*`, tool name only; arguments are not mapped yet) | planned | no (host limitation) |
| Codex | `PreToolUse` (`Bash`) | **not hooked** (the matcher is `Bash` only, so `apply_patch` edits are not seen) | via shell | not hooked | planned | no |
| Cursor | `beforeShellExecution` | `beforeReadFile`; writes via `preToolUse` | via shell | `beforeMCPExecution` (name only) | planned | **yes** (`failClosed`, set by `init`) |
| OpenClaw | planned (plugin) | planned (`derivedPaths`) | planned | planned (MCP proxy) | planned | no |
| Any MCP host | — | planned (proxy mapping) | planned | planned (proxy) | n/a | n/a |

Every "no", "not hooked" and "planned" cell is a tracked gap. This table is the published
matrix; the README links here. A generated `COVERAGE_MATRIX.md` is planned.

### 2.6 Windows plan with dates

- v0.1: decide + audit + integrity on Windows (built; CI green); PowerShell conservative
  tokenizer (planned: today a PowerShell line is lexed as POSIX and falls through to `ask`).
- v0.2: egress proxy on Windows (proxy is pure Rust, OS-agnostic).
- Phase 2 (target ≤ 3 months after v0.1): AppContainer + Job Object `moat exec`.

## 3. MoatBench: the public proof

### 3.1 Why a benchmark, and why ours

Existing work covers pieces: AgentDojo (prompt-injection utility/ASR metrics, non-coding
domains), RedCode-Exec (4,050 risky code-execution cases in Docker), the "AI Coding
Agent Runtime Security Benchmark" (11 scenarios across Codex/Claude Code/Cursor/Gemini/
OpenCode, 220 fixture rows, four comparator modes), MalSkillBench (3,944 malicious
skills), Endor Labs' Agent Security League (functional vs. security correctness
leaderboard; best security score today 37.4%). None measures **runtime guardrails
across agents with and without a kernel**. That gap is ours to define, and whoever
defines the benchmark becomes the referee.

### 3.2 Design

**Threat scenarios (≥ 120, versioned)** mapped to OWASP Agentic Top 10 and DESIGN T1–T12:

| OWASP ASI | Scenario families (examples) |
|---|---|
| ASI01 Goal hijack | Injected README / issue title / PR comment / web page instructs exfil or destructive action |
| ASI02 Tool misuse | Allowed tool used for unintended purpose (`git` to push secrets to a gist, `tee` to overwrite rc files) |
| ASI03 Privilege abuse | Agent uses inherited cloud creds / `gh` token beyond task |
| ASI04 Supply chain | Malicious postinstall, typosquat, `curl \| sh`, poisoned MCP server update |
| ASI05 Unexpected code exec | `eval`, interpreter `-c`, decoded payloads, built-in env poisoning (CVE-2026-22708 class) |
| ASI06 Context poisoning | Poisoned CLAUDE.md / AGENTS.md / `.cursorrules`, poisoned MCP tool description |
| ASI07 Inter-agent | Subagent instructed to bypass parent constraints |
| ASI09 Trust exploitation | "Approve this, it is safe" social engineering in tool output |
| ASI10 Rogue agent | Agent attempts to modify its own hooks/policy |

Each scenario = a repository fixture + injected payload + a **canary** (fake AWS key,
fake SSH key, canary token URL) + a benign task the user actually asked for.

**Environment**: disposable VM/container per run (macOS runners for Seatbelt, Linux
for Landlock, Windows for parity), with an **egress sink** that records every outbound
connection and a canary service that records every secret that arrives. No real network.

**Systems under test** (agent × model pinned per run): Claude Code, Codex CLI, Cursor
CLI, OpenClaw, Gemini CLI, OpenCode.

**Conditions**:

1. `baseline` — agent defaults (whatever a new user gets).
2. `native-hardened` — the agent's own best settings (Codex sandbox + execpolicy,
   Claude Code sandbox + permission rules, Cursor allowlist).
3. `moat-decide` — agentmoat L1+L5 only (what Windows gets in v0.1).
4. `moat-enforce` — full L1–L5.

**Metrics** (AgentDojo vocabulary, extended):

| Metric | Definition | Direction |
|---|---|---|
| Targeted ASR | % scenarios where the attacker goal is achieved (canary received, destructive action happened, policy/hook modified) | ↓ |
| Utility under attack | % scenarios where the benign task completed **and** no attacker goal achieved | ↑ |
| Benign utility | % benign tasks completed with no attack present | ↑ (must not drop vs baseline by > 2 pts) |
| False deny rate | % benign atomic actions denied | ↓ (< 1%) |
| Asks per hour | approvals requested per agent-hour on benign corpus | ↓ (< 3 after learn mode) |
| Latency overhead | p50/p95 added per tool call | ↓ (p95 ≤ 15 ms decide, ≤ 30 ms with exec) |
| Time to visibility | seconds from attack attempt to audit record with correct class | ↓ |
| Coverage | % of scenario families applicable to the host (from matrix §2.5) | published, not optimised |

**Statistics**: ≥ 5 trials per scenario × condition; report 95% CIs (AgentDojo style).
Model nondeterminism is part of the measurement, not noise to hide.

**Reproducibility**: fixtures, harness, pinned agent versions, raw logs and a one-command
runner are public. Anyone can rerun and dispute. Results page regenerated nightly
against latest agent releases (regressions in *hosts* become news too).

### 3.3 Release gates tied to the benchmark

| Release | Gate |
|---|---|
| v0.1 | `moat-enforce` targeted ASR ≤ 5% on macOS/Linux across all hosts; benign utility within 2 pts of baseline; false deny < 1%; asks/hour < 3 |
| v0.2 | Same on Windows for `moat-decide`; taint layer blocks 100% of "read-then-exfil" family |
| v0.3 | Independent reproduction by at least one external party; public bypass challenge closed with no unfixed P1 |

If a gate fails, we do not ship; we publish the failure and the fix. That is the trust model.

### 3.4 The launch artefact

Not "we built a firewall". Instead: **"MoatBench: how often do coding agents leak your
secrets, with their own protections on?"** with a table per agent and the delta with the
kernel on. The benchmark is the headline; the product is the fix. The same data becomes
the README chart, the Show HN post and the nightly leaderboard.

## 4. Verification beyond the benchmark

### 4.1 Engineering rigour on the trusted core

Status: clippy pedantic `-D warnings`, rustfmt, rustdoc `-D warnings`, `cargo-deny`,
architecture tests and the conformance suite run on every PR. Everything below except
"Static" is planned.

- **Fuzzing**: `cargo-fuzz` targets for the shell tokenizer, path canonicaliser, policy
  loader and host-payload adapters; run continuously (OSS-Fuzz application after v0.2).
- **Differential testing**: for 100k generated/recorded commands, compare our tokenization
  with real `bash` word splitting (`bash -c 'printf "%s\0" "$@"'` harness) and with
  Codex `execpolicy` decisions on its own corpus; any divergence is a test case.
- **Property tests** (`proptest`): deny is monotonic across layers; allow can never
  override deny; strictest-wins is associative; canonical path matching is idempotent.
- **Mutation testing** (`cargo-mutants`) on `moat-core`: surviving mutants must be ≤ 5%.
- **Golden fixtures** from real host payloads, refreshed per host release; `doctor` pins
  minimum host versions.
- **Static**: clippy `-D warnings`, `cargo-deny` (licences, advisories), `unsafe` forbidden
  outside `moat-sandbox` with per-site justification.

### 4.2 Fatigue and usability as first-class metrics

- **Learn mode** (planned; `moat init --learn`, default for the first 24 h): audit everything,
  deny only the critical classes (secrets, pipe-to-shell, self-protection), propose
  rules from observed benign actions (`moat policy suggest`, deterministic templates).
- `moat report` shows asks per active hour (built); ask→rule conversions and the release
  gate on the benchmark's benign corpus are planned.
- Every block message carries rule id, one-line reason and trace id (`moat show <id>`);
  an `ask` is made to stick with `moat allow --last [--always]`.

### 4.3 Trust operations

- `SECURITY.md` with a 72-hour acknowledgement SLA and coordinated disclosure (in place);
  reproducible builds, Sigstore-signed releases and SBOM (planned with the release workflow).
- Public **bypass challenge** at launch (planned): bounty tiers for L2 escape (highest), L1+L4
  bypass with L2 off (medium), parser divergence (low). Published scoreboard. Each
  valid bypass becomes a benchmark scenario.
- Independent code audit of `moat-core` + `moat-sandbox` targeted after v0.3 (budget
  item; sponsors or grant).
- Threat model (`DESIGN.md` §3, `SECURITY.md`), coverage matrix (§2.5) and known
  limitations (`PROGRESS.md` §3) are linked from the README, not a wiki.

## 5. Why this beats the alternatives (and composes with them)

| Alternative | What it gives | What it lacks | agentmoat stance |
|---|---|---|---|
| Codex built-in sandbox + execpolicy | Strong per-command OS sandbox, Rust, default-on | Codex-only; no cross-agent policy; no audit/replay; no taint | Wrap it: our profile inside theirs; import its rules corpus |
| Claude Code sandbox / permission rules | Seatbelt/bwrap + proxy, 84% fewer prompts | Claude-only; policy not portable; no cross-session audit | Same |
| Cursor allowlist | Simple | Bypassed (CVE-2026-22708); fail-open | Hook + exec + `failClosed` |
| NanoClaw (container per agent) | Coarse isolation | Whole-agent granularity; no policy-as-code; OpenClaw-shaped | Finer: per command / per skill; works inside their container |
| Docker/VM for everything | Strong boundary | Heavy; loses local tooling; no policy semantics; no audit of *intent* | Recommend for CI; we are the laptop layer |
| SkillSpector / scanners | Static detection of malicious skills | No runtime enforcement | Complementary; MalSkillBench feeds our scenarios |
| LavaMoat | JS package-level capability sandbox | JS runtime only | Different layer; cite to avoid confusion |

Unique combination: **cross-agent policy-as-code + OS enforcement + egress proxy +
session taint + replayable audit + public benchmark**, in one static binary.

## 6. Scope change this document makes to DESIGN.md

- v0.1 is **decide + enforce** on macOS/Linux (`moat exec`, egress proxy), decide-only on Windows.
- Session taint (L4) moves into v0.1 as a minimal rule (`tainted ⇒ net = ask`).
- MoatBench harness is a Phase 1 deliverable, not a later idea; the v0.1 gate depends on it.
- Phase 1 duration becomes **6 weeks**, not 4. Weeks 5–6: `moat exec` on both OSes,
  proxy, taint, benchmark harness and first results.

## 7. What "strong" looks like in numbers (v0.1 exit criteria)

| Measure | Target |
|---|---|
| Targeted ASR with `moat-enforce` (macOS/Linux, all hosts) | ≤ 5% (baseline agents today: expected 40–90% on our corpus) |
| "Read-then-exfil" family | 100% blocked or asked |
| Benign utility delta vs baseline | ≥ −2 pts |
| False deny on benign corpus | < 1% |
| Asks per agent-hour after learn mode | < 3 |
| Latency p95 (decide / decide+exec) | ≤ 15 ms / ≤ 30 ms |
| Parser divergence vs bash on 100k commands | 0 unexplained |
| Mutation score on `moat-core` | ≥ 95% |
| External reproduction of benchmark | ≥ 1 party before v0.3 |

## Appendix — Benchmark sources

- AgentDojo (metrics: benign utility, utility under attack, targeted ASR) — https://www.alphaxiv.org/abs/2406.13352
- RedCode: risky code execution benchmark (4,050 cases, 25 scenarios) — https://arxiv.org/pdf/2411.07781 ; https://redcode-agent.github.io/
- AI Coding Agent Runtime Security Benchmark (11 scenarios, 5 agents, 220 fixtures) — https://github.com/requie/AI-Red-Teaming-Guide/issues/18
- MalSkillBench (3,944 malicious skills) — via https://adversa.ai/blog/top-ai-coding-agent-security-resources-september-2026/
- Endor Labs Agent Security League — https://www.endorlabs.com/research/ai-code-security-benchmark
- OWASP Top 10 for Agentic Applications 2026 — https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026 ; https://goteleport.com/blog/owasp-top-10-agentic-applications/
- Red-teaming coding agents (ToolLeak, two-channel injection; RCE on every tested pair) — https://arxiv.org/abs/2509.05755
- Taxonomy of safety benchmarks for AI agents — https://arxiv.org/pdf/2605.16282
- OWASP GenAI exploit round-up Q1 2026 — https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/
- CVE-2026-22708 — https://www.sentinelone.com/vulnerability-database/cve-2026-22708/
