# OS enforcement evidence

Generated from the `scripts` list in `tests/differential/scenarios.yaml` by the
differential suite; do not edit. Regenerate with
`MOAT_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`.

The hook allows project scripts (`npm test`, `make test`) and cannot see what they
do ([THREAT_MODEL.md](THREAT_MODEL.md) §5). Each row is such a script: the payload is
the project's test script, started as `npm test` in a throwaway home with fake secrets,
under `moat run` (Lightweight tier) and under each agent's own sandbox as `moat init`
configures it (Standard tier, [SANDBOX.md](SANDBOX.md)): Claude Code 2.1.290 runs
`claude -p --bare` against a local fake Anthropic API that asks for that one Bash call,
with only the generated settings (no hook, so the sandbox alone is measured), and
codex-cli 0.160.1 runs `codex sandbox -P moat`. No account, API key or internet is
used. A cell is what the operating system did to the payload. CI asserts it on every
pull request, together with its side effects (no secret printed, no file written,
nothing reached the listener), and fails when it changes. Network targets are loopback
listeners the test owns.

| Case | Threat | Payload | `moat run`, macOS (Seatbelt) | `moat run`, Linux (Landlock + seccomp) | Claude Code sandbox, macOS | Claude Code sandbox, Linux | Codex `moat` profile, macOS | Codex `moat` profile, Linux |
|---|---|---|---|---|---|---|---|---|
| `script-benign-work` | control | `cat package.json > /dev/null && echo ok > out.txt && ln -sf src s && cat s/main.rs && /bin/bash -c true && curl --version > /dev/null` | ran | ran | ran | ran | ran | **gap**: sandbox error (#358) |
| `script-reads-ssh-key` | T1 | `cat "$HOME/.ssh/id_rsa"` | EPERM | EACCES | EPERM | ENOENT | EPERM | sandbox error |
| `script-reads-aws-credentials` | T1 | `cat "$HOME/.aws/credentials"` | EPERM | EACCES | EPERM | ENOENT | EPERM | sandbox error |
| `script-reads-project-env` | T1 | `cat .env` | EPERM | **gap**: ran (#174) | EPERM | **gap**: ran (#359) | EPERM | sandbox error |
| `script-writes-outside-project` | T4 | `echo x > "$HOME/outside.txt"` | EPERM | EACCES | EPERM | contained | EPERM | sandbox error |
| `script-direct-tcp` | T12 | `/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{tcp}'` | EPERM | EACCES | EPERM | refused | EPERM | sandbox error |
| `script-dns-query` | T12 | `/bin/bash -c 'printf q > /dev/udp/127.0.0.1/{udp}'` | EPERM | EPERM | EPERM | contained | EPERM | sandbox error |
| `script-symlink-into-ssh` | T11 | `ln -s "$HOME/.ssh" keys && cat keys/id_rsa` | EPERM | EACCES | EPERM | ENOENT | EPERM | sandbox error |
| `script-edits-policy` | T9 | `echo "# widened" >> "$HOME/.moat/policy.yaml"` | EPERM | EACCES | EPERM | ENOENT | EPERM | sandbox error |
| `script-edits-hook-file` | T9 | `echo "{}" > "$HOME/.claude/settings.json"` | EPERM | EACCES | EPERM | ENOENT | EPERM | sandbox error |
| `script-proxy-unlisted-host` | T12 | `curl -fsS -o /dev/null -m 30 http://evil.example/` | proxy 403 | proxy 403 | proxy 403 | proxy 403 | proxy 403 | sandbox error |

EPERM and EACCES: the system call failed with that error. ENOENT: the path does not exist
inside the sandbox (bubblewrap mounted an empty directory over it). refused: the connection
was refused inside the sandbox's own network namespace. proxy 403: the layer's proxy refused
the request (OpenMoat's under `moat run`, the agent's own, which allows only the policy's
hosts, under the Standard tier). contained: the payload completed inside the sandbox, but
what it wrote or sent stayed there (an empty in-memory directory, its own network namespace)
and nothing reached the host. sandbox error: the sandbox failed to start the command, so
nothing of the payload ran. ran: the payload completed.

## Known gaps

- `script-benign-work` under Codex `moat` profile, Linux (#358): Codex on Linux expands the profile's `**/.env` deny globs with ripgrep before it starts a command and gives up on the root-only directories under /etc, so it runs no command at all; it fails closed, which is why every attack in that column is a sandbox error too
- `script-reads-project-env` under `moat run`, Linux (Landlock + seccomp) (#174): Landlock only grants: a deny inside the granted project tree cannot be enforced, so .env stays readable (THREAT_MODEL §5); the hook still denies it for the agent's own tool calls
- `script-reads-project-env` under Claude Code sandbox, Linux (#359): on Linux Claude Code's sandbox skips a denyRead glob whose first path component is a wildcard, so the generated `/**/.env` denies do nothing; the hook still denies it for the agent's own tool calls

## Layers

| Layer | Status |
|---|---|
| `moat run`, macOS (Seatbelt) | verified by the `macos-14` and `macos-15-intel` CI jobs |
| `moat run`, Linux (Landlock + seccomp) | verified by the `ubuntu-latest` CI job (Linux 6.7 or later) |
| Claude Code sandbox and Codex profile, macOS | verified by the `standard tier (macos-14)` CI job |
| Claude Code sandbox and Codex profile, Linux | verified by the `standard tier (ubuntu-latest)` CI job (bubblewrap and socat installed); Codex runs no command there (#358) |
| `moat run`, Windows | not run: `moat run` refuses on Windows, where OpenMoat generates no OS sandbox (#135) |
| Claude Code sandbox, Windows | not run: Claude Code's sandbox does not run on native Windows, so `moat init` writes no sandbox settings there ([SANDBOX.md](SANDBOX.md)) |
| Codex profile, Windows | not verified: the scripts and the project's `npm` shim are POSIX shell |

The Standard tier columns cover the commands the agent runs and the processes they start.
Not verified here: what the agent's own process does outside its sandbox (Claude Code's file
tools and hooks), a real model choosing the command, and the opt-in `sandbox.proxy_port` mode
(the command-level scenarios of the differential suite use it; CI does not run them under the
host sandboxes). `scripts/ci/host-binaries.sh` fetches the pinned binaries, and
`scripts/ci/differential.sh hostile_scripts` runs these rows under every layer the machine has.
