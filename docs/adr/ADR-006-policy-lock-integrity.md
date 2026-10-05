# ADR-006: Policy lock keyed by file location, symlink-aware

Status: accepted · Date: 2026-10-03 (#8), amended 2026-10-05 (#26)

## Context

An agent that can edit `~/.moat/policy.yaml` or a host's hook file can switch the kernel
off (`DESIGN.md` G1, T10). Protected-path rules stop the agent's own tool calls, but not
a script it ran, a sync tool, or an edit through a path the policy does not name. The
kernel has to notice that its inputs changed and refuse to run on inputs no person
accepted.

## Decision

- `~/.moat/policy.lock` (JSON, version 1) records the `moat` binary path and a map of
  pinned file → SHA-256. `moat init` pins the policy, `environment.json`,
  `approvals.json`, `policy.d/approved.yaml` and every installed host hook file;
  `moat allow` and `moat doctor --accept` re-pin the same set.
- `moat guard` verifies every entry on every call before loading the policy. Any drift
  (modified, missing, unreadable) denies every action with `kernel-integrity`; a Claude
  Code `ConfigChange` for a pinned settings file that no longer matches is blocked for the
  session.
- Entries are keyed by location: canonical parent directory plus file name, not the
  resolved target. A symlink's digest is computed over `symlink:` plus its target path,
  so replacing a pinned file with a link, or re-pointing a link, is `Modified`, and a
  deleted file keeps its key. (#26 closed the symlink swap found by the 2026-10-05 audit;
  the original leaf-canonical key made the lookup miss and report "intact".)
- Only a person may re-pin: `moat init`, or `moat doctor --accept` from an interactive
  terminal. There is no `--force` and no re-pin from a hook.
- The binary is recorded by path and compared by `doctor`; its hash is not pinned, since
  a replaced binary would be the one doing the verifying.

## Consequences

- Editing the policy means running `moat doctor --accept` afterwards; until then every
  call is denied. The README says so where it tells people to edit the policy.
- Codex and Cursor have no `ConfigChange` equivalent, so a tampered hook file there is
  caught on the next tool call, not when it is written.
- Signed policy bundles (Phase 2) can replace the digest map without changing the key
  scheme.
- The lock protects files, not the process that reads them: a root attacker or a
  replaced `moat` binary is out of scope (`SECURITY.md`).
