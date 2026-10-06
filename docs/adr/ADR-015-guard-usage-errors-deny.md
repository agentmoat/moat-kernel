# ADR-015: `moat guard` denies when it cannot parse its own arguments

Status: accepted · Date: 2026-10-05 · Amends: ADR-004

## Context

ADR-004 reserves exit 2 for deny and maps clap usage errors to 64 so that a mistyped
flag is never read as a deliberate block. The same rule turned out to fail open for
the one command hosts run automatically. Claude Code and Codex block a tool call only
on exit 2; every other non-zero exit is a non-blocking hook error and the call
proceeds. Dogfooding showed `moat guard --host <unknown>` exiting 64. The same happens
for a hook line written by a newer or older `moat` whose flags the installed binary
does not understand, or a hand-edited hook with a typo: in each case the agent's tool
call runs unchecked.

## Decision

- When the first argument is `guard`, a usage error (unknown host, missing or unknown
  flag, extra operand) prints the reason on stderr and exits **2**. An error returned
  from the guard command itself does the same; `guard` already answers internal
  failures with a `deny` response and exit 2 (ADR-004).
- `moat guard --help` and `--version` stay informational: exit 0.
- Every other command keeps ADR-004 unchanged: usage and configuration errors exit 64,
  and nothing but `guard`'s deny uses 2.

## Consequences

- A broken hook command line blocks tool calls until it is fixed, which a person sees
  at once and `moat doctor` reports. Failing open would have stayed silent.
- No JSON response is written for an argument error: before parsing, `guard` does not
  know which host's response shape to use. Exit 2 with a stderr reason is the blocking
  signal for Claude Code and Codex. Cursor hooks are installed with `failClosed`, so any
  failure blocks there.
- Still out of reach: a hook whose `moat` binary is missing never runs at all. Hosts
  that proceed in that case are listed as a known limitation in SECURITY.md.
