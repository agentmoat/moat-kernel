# ADR-001: Rust for the kernel

Status: accepted · Date: 2026-10-02

## Context

The kernel must ship OS-level sandboxing on macOS, Linux and Windows, be credible to
a security audience, start in milliseconds on every tool call, and build as a single
static binary. Go, TypeScript, Zig and C/C++ were considered. Full scoring:
`docs/TECH_STACK.md`.

## Decision

Rust (stable, pinned MSRV) for every kernel crate. TypeScript and Python are used
only for userland SDKs and host plugins that must run inside those ecosystems.

## Consequences

- Production cross-platform sandbox code already exists in Rust (OpenAI Codex
  crates, `skarn-sandbox`, `rust-landlock`) and can be reused in `moat exec`.
- The contributor pool for sandbox and policy work skews Rust.
- Compile times and the borrow checker slow early iteration; mitigated by small
  crates and a pure core.
- Memory-unsafe code is forbidden workspace-wide; platform crates may opt in per
  site with a `SAFETY:` justification.
