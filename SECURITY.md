# Security policy

moat is a security control. Reports about it are handled as such.

## Supported versions

moat has not had a release yet. Until 1.0, only the latest release (and `main`) receives
security fixes; there are no backports.

## Reporting

Use GitHub's private advisory form:
https://github.com/agentmoat/moat-kernel/security/advisories/new

Do not open public issues or pull requests for bypasses. A useful report contains:

- the `moat --version` or commit, the host and the operating system;
- the exact tool call: the hook payload, or the command line for `moat policy check`;
- the policy in use (default, or the file) and the verdict and rule ids you got;
- what actually executes and why that crosses a boundary the policy promises.

A report is accepted when it shows a concrete crossing of the boundaries in the table
below. Scanner or model output without a reproduction is read, but it is not triaged
ahead of reports that have one.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement | 72 hours |
| Triage: confirmed or not, severity | 7 days |
| Fix for a confirmed critical or high issue | 30 days |
| Public disclosure | when the fix ships, and at most 90 days after the report unless we agree otherwise |

Every valid bypass becomes a conformance fixture before the fix is published. Confirmed
issues in a released version get a GitHub Security Advisory, with a CVE requested
through GitHub, and you are credited unless you prefer otherwise.

## Safe harbour

Research on your own machine and your own accounts, against your own copy of moat, is
welcome and will not be pursued. Do not test against systems or data that are not
yours.

## What counts as a vulnerability

| In scope | Example |
|---|---|
| Policy bypass | a command the default policy should deny is allowed, or evaluated as a different action than the one that executes |
| Parser confusion | quoting, operators, substitutions or encodings that make the classifier see something other than what the shell runs |
| Fail-open | any error path in `moat guard` that results in `allow` |
| Self-protection gap | an agent tool call that can modify `~/.moat`, host hook configuration or the `moat` binary without a `deny` |
| Audit integrity | decisions missing from the log, or secrets persisted un-redacted |
| Supply chain | malicious or vulnerable dependencies; from the first release, artefacts whose checksum or attestation does not verify |

## Out of scope (today)

These are known limits, documented in `docs/DESIGN.md` §9 and `docs/PROGRESS.md`,
and are being built rather than being bugs:

| Not yet covered | Status |
|---|---|
| OS-level enforcement of a decision (a parse the policy misjudges is still only a decision) | `moat exec` sandbox, planned |
| Network enforcement beyond pattern matching | egress proxy, planned |
| PowerShell / cmd tokenisation on Windows | lexed as POSIX; falls through to the `ask` default |
| Hosts that proceed when the hook binary is missing | host limitation; `moat status` reports it |
| Agents running in a vendor's cloud rather than on the host | not a target |

## Threat model in one paragraph

The attacker controls any text the agent reads (files, issues, web pages, MCP tool
descriptions, dependencies) and may publish packages and MCP servers. The attacker
does not have root on the machine. The kernel's job is to keep such an attacker
from reading secrets, exfiltrating data, poisoning the environment, running remote
code, destroying work, or disabling the kernel, and to leave a trustworthy record of
every attempt. Full version: `docs/DESIGN.md` §3.

## Verifying a release

Releases will carry SHA-256 checksums and GitHub build provenance attestations. Verify a
downloaded artefact with `gh attestation verify <file> --repo agentmoat/moat-kernel`
before installing it by hand.

## Hardening already in place

Deterministic decisions (no model in the loop); a policy lock verified on every call (edits to the policy or hook files deny everything until a person re-pins); fail-closed on every error path;
exit code 2 reserved for `deny`; protected paths for the kernel's own configuration;
redaction before audit storage; owner-only permissions on state files; a pure core
with no I/O and no `unsafe`; dependency and licence auditing in CI.
