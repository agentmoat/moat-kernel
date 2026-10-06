# ADR-016: Hooks run the stable install path of `moat`

Status: accepted · Date: 2026-10-05 (#90) · Refines ADR-006

## Context

`moat init` wrote `std::env::current_exe()` into every hook and into `policy.lock`.
Package managers install into versioned directories and point a stable link at the
current one: Homebrew and Linuxbrew (`<prefix>/bin/moat` → `<prefix>/Cellar/moat/<v>/bin/moat`),
Scoop (`apps/moat/current` → `apps/moat/<v>`), Nix profiles (`~/.nix-profile/bin/moat` →
`/nix/store/…`). Linux reports the resolved file as `current_exe()` even when `moat` was
started through the link. After an upgrade and cleanup that file is gone: the hook command
cannot start, Claude Code and Codex treat that as a non-blocking hook error and run the
tool call anyway (fail open), and the lock names a binary that no longer exists.

## Decision

- Hooks and the lock record the first of these paths that resolves to the same file as the
  running executable: the package manager's stable link (`Cellar/<name>/<version>/` dropped,
  or `apps/<name>/<version>/` replaced by `apps/<name>/current/`), the path `moat` was
  invoked by (`argv[0]`, looked up in `PATH` when it is a bare name), the executable path
  itself. A candidate that resolves to another file, or to nothing, is never written.
- The binary is still recorded by path only. Its digest is not pinned: a replaced binary is
  the one that would verify it (ADR-006), and pinning it would make every package upgrade
  look like tampering. An upgrade that replaces the target of the stable link is therefore
  transparent: hooks keep working and `moat doctor` stays healthy.
- `moat doctor` and `moat status` name a hook whose binary does not exist, and a hook that
  runs a different `moat` than the one checking, with `run moat init` as the fix. The hook
  files themselves stay pinned, so a re-pointed hook command is still `kernel-integrity`.

## Consequences

- Whoever can re-point the stable link decides what the hooks run, as whoever could replace
  the versioned file did before. `kernel-self` denies agent writes to `**/bin/moat` (the
  Homebrew link and the Cellar file); the Scoop `apps/moat/current/moat.exe` path is not
  matched by that pattern, as the versioned Scoop path was not before.
- Installs from a lock written by an earlier build that recorded a Cellar path report the
  binary and hooks as stale once; `moat init` rewrites them.
- Kernel binary self-verification stays a Phase 2 item (`DESIGN.md` G1); signed releases
  would let `doctor` tell an upgrade from a swap by signature instead of by path.
