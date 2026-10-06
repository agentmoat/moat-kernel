# Egress proxy: reuse or write (issue #171)

ADR-020 asks us to evaluate two existing proxies before writing `moat proxy`. This note
records what we checked on 2026-10-06 and why we chose to write a small proxy ourselves.

## What `moat proxy` must do (beta scope)

- CONNECT tunnelling, with the TLS ClientHello's SNI checked against the CONNECT host.
- Plain HTTP forwarding of absolute-form requests.
- DNS resolved by the proxy, and the resolved address checked (rebinding guard).
- Host allow and deny with the policy's globs, using the same matcher as `moat guard`.
- One audit record per connection, and fail closed when it cannot be written.
- Later and opt-in: per-host method and path rules with TLS termination, and the secrets broker (#172).

The constraints come from the repository:

- License: dependencies must be compatible with `MIT OR Apache-2.0` and on the `deny.toml` list.
- `deny.toml` allows `tokio` and `reqwest` only as direct dependencies of the binary crate.
- `unknown-git = "deny"`: every dependency must come from crates.io.

## (a) OpenAI `codex-network-proxy` (Rust, Apache-2.0)

Source: <https://github.com/openai/codex/tree/main/codex-rs/network-proxy>.

- **License:** Apache-2.0 (repository license), compatible.
- **Maintenance:** active. 100+ commits touch the directory between 2026-02-24 and 2026-10-01.
  It changes with Codex's needs (credential broker, Windows ingress, MXC).
- **Distribution:** not published to crates.io (`crates.io/api/v1/crates/codex-network-proxy`
  returns "does not exist"). It depends on unpublished path crates (`codex-utils-absolute-path`,
  `codex-utils-home-dir`, `codex-utils-path-uri`, `codex-utils-rustls-provider`). So it cannot be
  a crates.io dependency. A git dependency would break `unknown-git = "deny"`, and vendoring
  means maintaining a fork.
- **Dependency weight:** `tokio` with `features = ["full"]`, seven `rama-*` crates pinned to
  `=0.3.0-alpha.4` (rama is at 0.4.0 on crates.io), `rustls`, `opentelemetry`, `tracing`,
  `tracing-subscriber`, `schemars`, `chrono`, `time`, `rand_regex`, and platform crates
  (`security-framework`, `schannel`, `windows-sys`). That would add over a hundred crates to a
  security kernel whose binary has about 70 today.
- **Size:** about 830 KB of Rust source in `src/`. `proxy.rs` alone is 115 KB, `runtime.rs`
  84 KB and `http_proxy.rs` 73 KB.
- **Features:**
  - Its domain allow and deny uses its own glob dialect (`*.x`, `**.x`, global `*` refused),
    not ours.
  - It blocks local and private addresses after DNS resolution
    (`connect_policy.rs`, `system_dns.rs`).
  - It has a "limited" read-only mode with MITM, plus SOCKS5, unix sockets, a credential
    broker and OpenTelemetry audit events.
  - We searched `http_proxy.rs` and `mitm.rs` for `sni` and `server_name` and found no check
    of the client's SNI against the CONNECT host outside TLS termination.
- **Attack surface:** large. SOCKS5 (with UDP), unix-socket proxying, MITM with a generated
  CA, remote config and a credential broker are all compiled in, whether or not we use them.

**Verdict:** a good design reference, especially the post-resolution address check and the MITM
hook model. It cannot be a dependency, and vendoring 830 KB of code tied to another product's
release cycle is the opposite of a small trusted base.

## (b) Anthropic `@anthropic-ai/sandbox-runtime` (TypeScript, Apache-2.0)

Source: <https://github.com/anthropic-experimental/sandbox-runtime> (npm
`@anthropic-ai/sandbox-runtime`, version 0.0.78).

- **License:** Apache-2.0, compatible.
- **Maintenance:** active. 100 commits between 2026-08-25 and 2026-10-05, and it backs Claude
  Code's sandbox.
- **Embedding:** not possible in a Rust binary. It needs Node.js 22.12 or later and npm
  dependencies (`node-forge`, `@pondwader/socks5-server`, `commander`, `zod`). Running it as a
  sidecar would put a Node runtime and its npm tree inside the trusted base. Every user would
  also need Node installed.
- **Features:**
  - `src/sandbox/http-proxy.ts` handles CONNECT and HTTP with a domain filter.
  - `resolved-address-guard.ts` refuses allowlisted names that resolve to local addresses.
  - `tls-terminate-proxy.ts` and `mitm-ca.ts` do TLS termination, and `credential-*.ts`
    masks credentials.
  - It sniffs the ClientHello only on the TLS-termination path.
- **Attack surface:** the proxy is mixed with sandbox orchestration (`sandbox-manager.ts` is
  102 KB). It is designed as a library for Node hosts, not a standalone exit.

**Verdict:** the best reference for the secrets broker (#172) and for TLS termination. It is
not usable as code.

## (c) A minimal proxy we write

Two options:

- **On tokio and hyper.** This needs a new crate, `deny.toml` wrappers that allow `tokio` and
  `hyper` there, and an async runtime for a workload of a few dozen local connections. hyper's
  client also does its own connection pooling and header handling, which we would have to
  work around to forward bytes exactly and to check the resolved address.
- **On the standard library.** `std::net` for sockets and DNS (`ToSocketAddrs`, which is the
  system resolver), one thread per connection with a hard cap, and socket timeouts for idle
  limits. Two parsers on top:
  - [`httparse`](https://crates.io/crates/httparse) parses the request head. It is MIT OR
    Apache-2.0, has no dependencies, is hyper's own parser (766 M downloads) and is fuzzed
    upstream.
  - A small ClientHello parser of our own reads the SNI. It is about 100 lines and fuzzed
    here, because no small crate parses a ClientHello without pulling a TLS stack.

| | (a) codex-network-proxy | (b) sandbox-runtime | (c) std + httparse |
|---|---|---|---|
| License | Apache-2.0 ✓ | Apache-2.0 ✓ | MIT/Apache ✓ |
| Usable as a crates.io dependency | no (unpublished, path deps) | no (Node) | yes |
| New crates | 100+ incl. tokio, rama alpha | Node runtime + npm | 1 (`httparse`) |
| `deny.toml` change | wrappers + git source | n/a | none |
| SNI = CONNECT host | not found | MITM path only | yes |
| Same host matcher as `moat guard` | no (own globs) | no | yes (openmoat-core) |
| Code we must trust | ~830 KB | ~1 MB TS + runtime | ~1.5 k lines, fuzzed parsers |

## Recommendation

Choose **(c) on the standard library plus `httparse`**, in a new library crate,
`crates/openmoat-proxy`. The CLI exposes it as `moat proxy`. Reasons:

- It decides with openmoat-core's `CompiledPolicy`, so a host the proxy allows is exactly a host
  `moat guard` allows for a fetch (`fetch` and `net` lists, deny first).
- It adds one dependency with no transitive crates, needs no `deny.toml` change and keeps the
  async-runtime ban intact.
- The security checks this proxy exists for are a few hundred lines that we can read, test and
  fuzz: the SNI check, the post-resolution address guard and the audit record that fails closed.

Costs we accept:

- Thread-per-connection scales to hundreds of connections, not tens of thousands. That is
  enough for the agents on one workstation, and `--max-connections` caps it.
- TLS termination for method and path rules is not included. When it comes (opt-in, ADR-020),
  rustls works with blocking sockets, so it does not by itself require an async runtime.
  We will revisit tokio then if the connection model needs it.
