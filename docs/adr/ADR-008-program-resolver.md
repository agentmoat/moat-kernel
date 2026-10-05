# ADR-008: Executable pinning through a caller-supplied `ProgramResolver`

Status: accepted · Date: 2026-10-03 (#13, #14)

## Context

A shell rule names a program by its first word. `git` may be `/usr/bin/git`, a copy in
`node_modules/.bin` planted by a dependency, or a file in a directory an earlier command
prepended to `PATH` (`DESIGN.md` G3, T5). Checking this needs the filesystem, and
`moat-core` must stay pure: no I/O, builds for `wasm32`, dependency allowlist enforced by
an architecture test.

## Decision

- `moat-core` defines `trait ProgramResolver { fn resolve(&self, name) -> Option<path>;
  fn pinned(&self, name) -> Option<path> }` and `programs::check`, which compares the
  path a command's program resolves to with its pins: the policy's `executables:` table
  plus the installation pin. A mismatch, or a pinned program that cannot be resolved, is
  `deny` with rule `executables`. Unpinned programs are not checked. An argv0 that
  contains a path separator is compared literally.
- `CompiledPolicy::decide_with(action, &resolver)` takes the resolver;
  `CompiledPolicy::decide` uses `NoResolver` (unit tests, `moat policy check`).
- `moat init` captures `PATH` and the absolute location of a fixed list of
  security-relevant programs (`sh`, `git`, `curl`, `node`, `npm`, `python3`, `cargo`,
  `sudo`, …) into `~/.moat/environment.json`, pinned by the lock. `moat guard` loads the
  snapshot and resolves through *that* search path, never the hook's inherited
  environment.

## Consequences

- Planted binaries and `PATH` poisoning are caught at decision time for pinned programs,
  including absolute-path invocations of a copy elsewhere.
- Installing a tool in a new location requires `moat init` or `moat doctor --accept`.
- `moat policy check` has no snapshot: policy `executables:` pins deny bare program names
  as "not found" there; testing pins needs `guard` or a real hook.
- Known gaps (audit 2026-10-05): an empty `PATH` at init pins nothing and still reports
  success; on Windows only `.exe`, `.cmd` and `.bat` are tried, `PATHEXT` is ignored.
- Core purity holds; the only filesystem code is `crates/moat-cli/src/environment.rs`.
