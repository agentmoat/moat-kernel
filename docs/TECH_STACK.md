# Tech Stack Decision — Kernel Language

Date: 2026-10-02. Status: **decided — Rust.**

This document records *why*, with the evidence, so the decision can be challenged
later with new evidence rather than re-argued from taste.

## Candidates

Rust, Go, TypeScript (Node/Bun), Zig, C/C++. Zig (pre-1.0) and C/C++ (memory safety,
contributor friction) were excluded early. TypeScript was excluded for the kernel
because a per-tool-call hook needs millisecond start-up and a security kernel in a
GC'd scripting runtime is not credible to the audience; it remains the first-class
language for userland skills and SDKs.

## Criteria and weights

| # | Criterion | Weight | Why it matters for agentmoat |
|---|---|---|---|
| 1 | Cross-platform OS sandbox primitives available today | 25 | Phase 2 is the product. Seatbelt (macOS), Landlock + seccomp (Linux), AppContainer / restricted token (Windows). |
| 2 | Credibility with the security / systems audience | 15 | A "kernel" must be trusted. Launch audience is HN, security engineers, platform teams. |
| 3 | Relevant contributor pool | 15 | Who will actually send PRs to a sandbox/policy engine. |
| 4 | MCP SDK maturity | 10 | Kernel is a secure MCP host. |
| 5 | WASM runtime for pure-logic skills | 10 | Jail without a process when possible. |
| 6 | Distribution / cross-compilation | 10 | Single binary on macOS, Linux, Windows, ARM. |
| 7 | Solo-developer velocity | 10 | One person for the first 3–6 months. |
| 8 | Hook latency and binary footprint | 5 | Invoked on every tool call. |

## Evidence

### 1. Sandbox primitives (25)

**Rust**
- OpenAI Codex CLI (128k stars, Apache-2.0) is written in Rust and ships production
  sandboxing on all three OSes: crates `linux-sandbox`, `bwrap`, `sandboxing`,
  `execpolicy`, `process-hardening`, `mxc-sandbox`. Seatbelt on macOS, Landlock +
  seccomp (+ bubblewrap) on Linux, restricted token + ACLs on Windows. Default-on.
  This is reusable, audited reference code.
- `skarn-sandbox` 1.0.1 (Sept 2026, MIT/Apache-2.0): one `Policy` API over Seatbelt,
  Landlock + seccomp-bpf, AppContainer + Job Object.
- `rust-landlock` is the official Landlock binding; `sandlock-core`, `zecor-sandbox`,
  `cap-std` (capability-based std) also exist.
- Firecracker, Cloud Hypervisor, libkrun, youki, Wasmtime, Deno: the current
  generation of isolation infrastructure is Rust.

**Go**
- `go-landlock` is official. gVisor is Go but Linux-only and a different scale.
- Cross-platform libraries are beta: `agentbox` (Seatbelt via `sandbox-exec`,
  namespaces + Landlock + seccomp, Windows restricted token + Job Object; "beta,
  breaking changes possible", original repo small), `looprig/sandbox`, `windows-sandbox`.
- macOS `sandbox_init` is a C API; Go must shell out to `sandbox-exec` or use cgo
  (which breaks easy cross-compilation).

**Verdict:** Rust, clearly. Go would re-implement what Codex already shipped.
Score: Rust 25 / Go 12.

### 2. Credibility (15)

Rust is the language of Codex's sandbox, Firecracker, youki, Wasmtime, Deno, and of
the memory-safety guidance from CISA/NSA. Go is credible too (gVisor, Docker,
Kubernetes, Tailscale, Teleport, Trivy) but reads as "infrastructure service", not
"security boundary". For a project whose entire pitch is the boundary, Rust's optics
are measurably better with the target audience.
Score: Rust 15 / Go 10.

### 3. Contributor pool (15)

- GitHub Octoverse 2025: Go is a top-10 language by contributors; Rust is growing
  ~50% YoY vs Go ~25% (both well behind TypeScript/Python in absolute numbers).
- Stack Overflow 2025: Rust most admired language, 72.4% (Go 56.5%); desired 29.2%
  (Go 23.4%).
- The subset that matters here (people who contribute to sandboxes, syscall filters,
  policy engines) skews heavily Rust in 2026, as the project list above shows.
Score: Rust 12 / Go 11. Go has more total developers; Rust has more of the right ones.

### 4. MCP SDK (10)

Both `modelcontextprotocol/rust-sdk` (`rmcp`, tokio, spec 2026-07-28) and
`modelcontextprotocol/go-sdk` are official Tier 1, production-ready.
Score: Rust 10 / Go 10.

### 5. WASM for pure-logic skills (10)

Wasmtime (Rust) is the reference implementation for WASI 0.2 and the Component Model.
wazero (Go) is pure-Go, zero-cgo, excellent, but trails on Component Model. Extism
uses Wasmtime under the hood.
Score: Rust 10 / Go 7.

### 6. Distribution and cross-compilation (10)

Go cross-compiles trivially when cgo is off; sandboxing on macOS pushes toward cgo
or shelling out. Rust cross-compiles well with `cross` / `cargo-zigbuild`, and
`cargo-dist` generates `curl | sh` installers, Homebrew taps, MSI/winget and
GitHub Releases from one config. In practice both ship via a GitHub Actions matrix
of native builders, so the difference is small.
Score: Rust 8 / Go 9.

### 7. Solo velocity (10)

Go is faster to write and compile; Rust's borrow checker and compile times cost
time early. Two mitigations specific to this project: the author's primary language
is Swift, whose `enum` with payloads, `Optional`, `Result`, protocols and value
semantics map closely to Rust (far closer than to Go); and AI coding agents work
unusually well with Rust because compiler errors are precise.
Score: Rust 6 / Go 9.

### 8. Hook latency and footprint (5)

Both start in ~1–3 ms and ship a single static binary. Rust binaries are smaller;
Go binaries are ~10 MB. Not a deciding factor.
Score: Rust 5 / Go 4.

## Result

| Criterion (weight) | Rust | Go |
|---|---|---|
| Sandbox primitives (25) | 25 | 12 |
| Credibility (15) | 15 | 10 |
| Contributor pool (15) | 12 | 11 |
| MCP SDK (10) | 10 | 10 |
| WASM (10) | 10 | 7 |
| Distribution (10) | 8 | 9 |
| Solo velocity (10) | 6 | 9 |
| Latency / footprint (5) | 5 | 4 |
| **Total (100)** | **91** | **72** |

Go wins only on velocity and marginally on distribution. Rust wins on everything
the product actually is.

A note on the earlier draft: an earlier version of the plan proposed Go partly
because "ZeroClaw already occupies Rust". That reasoning was wrong: ZeroClaw is an
assistant, not a kernel, and language choice should follow the problem, not the
neighbours.

## Chosen stack

| Layer | Choice |
|---|---|
| Kernel language | Rust (stable toolchain, edition 2024) |
| Async runtime | tokio |
| CLI | clap |
| MCP | `rmcp` (official) |
| Sandbox | Phase 2: `skarn-sandbox` and/or crates adapted from Codex (`linux-sandbox`, `bwrap`, `execpolicy`), `rust-landlock`; evaluate `cap-std` for in-kernel file handling |
| WASM skills | Wasmtime + Component Model (Phase 2/3) |
| Storage | `rusqlite` (bundled SQLite) for audit; `keyring` crate for OS keychain |
| Policy format | YAML via `serde_yaml_ng` (maintained fork of `serde_yaml`); JSON Schema for editors planned |
| Release | `cargo-dist` → `curl \| sh`, Homebrew tap, winget/MSI, GitHub Releases; `cargo install moat` |
| Lint / CI | clippy (deny warnings), rustfmt, `cargo-deny` (licenses + advisories), GitHub Actions matrix: macOS arm64/x64, Linux x64/arm64 (musl), Windows x64 |
| Embedding | `moat-core` crate + C ABI (`libmoat`) so Go / TypeScript / Swift hosts can link the policy engine |
| Userland SDKs | TypeScript first, Python second (skills, channels, providers) |

## Repository layout

See `REPO_STRUCTURE.md` (single source of truth for the monorepo layout and crate rules).

## Sources

- OpenAI Codex sandbox analysis — https://simonwillison.net/2025/Nov/9/codex-sandbox-investigation/
- codex-rs architecture — https://codex.danielvaughan.com/2026/03/28/codex-rs-rust-rewrite-architecture/
- Codex sandboxing implementation — https://deepwiki.com/openai/codex/5.6-sandboxing-implementation
- List of coding agent sandboxes (2026-05) — https://gist.github.com/wincent/2752d8d97727577050c043e4ff9e386e
- skarn-sandbox — https://docs.rs/skarn-sandbox/latest/skarn_sandbox/
- agentbox (Go) — https://github.com/Alan-123185/agentbox
- Anthropic sandbox-runtime — https://code.claude.com/docs/en/sandboxing
- Official MCP SDKs — https://modelcontextprotocol.io/docs/2026-07-28/sdk ; https://github.com/modelcontextprotocol/rust-sdk
- GitHub Octoverse 2025 — https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/
- Stack Overflow Developer Survey 2025 — https://www.frameworktraining.co.uk/news-insights/stackoverflow-developer-survey-results-2025-overview
- Rust vs Go for CLI tools — https://futurion.blog/rust-vs-go-for-cli-tools-picking-a-runtime-without-starting-a-tribal-war/
- Rust vs Go 2026 — https://www.javacodegeeks.com/2026/05/rust-vs-go-in-2026-the-systems-vs-services-split-is-finally-clear-which-one-should-you-actually-learn.html
- WASM runtime comparison 2026 — https://github.com/wasmruntime-io/wasm-runtime-comparison
- Cross-compiling Rust — https://oneuptime.com/blog/post/2026-03-02-how-to-cross-compile-rust-applications-on-ubuntu/view
- Landlock — https://landlock.io/
