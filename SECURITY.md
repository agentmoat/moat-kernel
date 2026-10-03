# Security policy

moat is a security control. Reports about it are handled as such.

## Reporting

Use GitHub's private advisory form:
https://github.com/agentmoat/moat-kernel/security/advisories/new

Do not open public issues for bypasses. We acknowledge within 72 hours, keep you
informed, and credit you in the advisory unless you prefer otherwise. Every valid
bypass becomes a conformance fixture before the fix is published.

## What counts as a vulnerability

| In scope | Example |
|---|---|
| Policy bypass | a command the default policy should deny is allowed, or evaluated as a different action than the one that executes |
| Parser confusion | quoting, operators, substitutions or encodings that make the classifier see something other than what the shell runs |
| Fail-open | any error path in `moat guard` that results in `allow` |
| Self-protection gap | an agent tool call that can modify `~/.moat`, host hook configuration or the `moat` binary without a `deny` |
| Audit integrity | decisions missing from the log, or secrets persisted un-redacted |
| Supply chain | malicious or vulnerable dependencies, unsigned release artefacts |

## Out of scope (today)

These are known limits, documented in `docs/DESIGN.md` §9 and `docs/PROGRESS.md`,
and are being built rather than being bugs:

| Not yet covered | Status |
|---|---|
| OS-level enforcement of a decision (a parse the policy misjudges is still only a decision) | `moat exec` sandbox, planned |
| Network enforcement beyond pattern matching | egress proxy, planned |
| PowerShell / cmd tokenisation on Windows | any such command is `ask` |
| Hosts that proceed when the hook binary is missing | host limitation; `moat status` reports it |
| Agents running in a vendor's cloud rather than on the host | not a target |

## Threat model in one paragraph

The attacker controls any text the agent reads (files, issues, web pages, MCP tool
descriptions, dependencies) and may publish packages and MCP servers. The attacker
does not have root on the machine. The kernel's job is to keep such an attacker
from reading secrets, exfiltrating data, poisoning the environment, running remote
code, destroying work, or disabling the kernel, and to leave a trustworthy record of
every attempt. Full version: `docs/DESIGN.md` §3.

## Hardening already in place

Deterministic decisions (no model in the loop); a policy lock verified on every call (edits to the policy or hook files deny everything until a person re-pins); fail-closed on every error path;
exit code 2 reserved for `deny`; protected paths for the kernel's own configuration;
redaction before audit storage; owner-only permissions on state files; a pure core
with no I/O and no `unsafe`; dependency and licence auditing in CI.
