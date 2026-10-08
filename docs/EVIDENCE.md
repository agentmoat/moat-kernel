# OS enforcement evidence

Generated from the `scripts` list in `tests/differential/scenarios.yaml` by the
differential suite; do not edit. Regenerate with
`MOAT_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`.

The hook allows project scripts (`npm test`, `make test`) and cannot see what they
do ([THREAT_MODEL.md](THREAT_MODEL.md) §5). Each row is such a script: the payload is
the project's test script, started as `npm test` under `moat run`, in a throwaway home
with fake secrets. A cell is what the operating system did to the payload. CI asserts
it on every pull request, together with its side effects (no secret printed, no file
written, nothing reached the listener), and fails when it changes. Network targets are
loopback listeners the test owns.

| Case | Threat | Payload | `moat run`, macOS (Seatbelt) | `moat run`, Linux (Landlock + seccomp) |
|---|---|---|---|---|
| `script-benign-work` | control | `cat package.json > /dev/null && echo ok > out.txt && ln -sf src s && cat s/main.rs && /bin/bash -c true && curl --version > /dev/null` | ran | ran |
| `script-reads-ssh-key` | T1 | `cat "$HOME/.ssh/id_rsa"` | EPERM | EACCES |
| `script-reads-aws-credentials` | T1 | `cat "$HOME/.aws/credentials"` | EPERM | EACCES |
| `script-reads-project-env` | T1 | `cat .env` | EPERM | **gap**: ran (#174) |
| `script-writes-outside-project` | T4 | `echo x > "$HOME/outside.txt"` | EPERM | EACCES |
| `script-direct-tcp` | T12 | `/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{tcp}'` | EPERM | EACCES |
| `script-dns-query` | T12 | `/bin/bash -c 'printf q > /dev/udp/127.0.0.1/{udp}'` | EPERM | EPERM |
| `script-symlink-into-ssh` | T11 | `ln -s "$HOME/.ssh" keys && cat keys/id_rsa` | EPERM | EACCES |
| `script-edits-policy` | T9 | `echo "# widened" >> "$HOME/.moat/policy.yaml"` | EPERM | EACCES |
| `script-edits-hook-file` | T9 | `echo "{}" > "$HOME/.claude/settings.json"` | EPERM | EACCES |
| `script-proxy-unlisted-host` | T12 | `curl -fsS -o /dev/null -m 30 http://evil.example/` | proxy 403 | proxy 403 |

EPERM and EACCES: the system call failed with that error. proxy 403: OpenMoat's proxy
refused the request. ran: the payload completed.

## Known gaps

- `script-reads-project-env` under `moat run`, Linux (Landlock + seccomp) (#174): Landlock only grants: a deny inside the granted project tree cannot be enforced, so .env stays readable (THREAT_MODEL §5); the hook still denies it for the agent's own tool calls

## Layers

| Layer | Status |
|---|---|
| `moat run`, macOS (Seatbelt) | verified by the `macos-14` and `macos-15-intel` CI jobs |
| `moat run`, Linux (Landlock + seccomp) | verified by the `ubuntu-latest` CI job (Linux 6.7 or later) |
| `moat run`, Windows | not run: `moat run` refuses on Windows, where OpenMoat generates no OS sandbox (#135) |
| Codex profile (`codex sandbox -P moat`) | not verified headlessly in CI, which has no `codex` binary; `scripts/ci/differential.sh` runs the command-level scenarios (`npm-test-reads-ssh` among them) under it where one is installed |
| Claude Code sandbox settings | not verified headlessly in CI, which has no `claude` binary; `scripts/ci/differential.sh` runs the command-level attacks under it where one is installed, and headless `claude -p` cannot verify benign project work (#238) |
