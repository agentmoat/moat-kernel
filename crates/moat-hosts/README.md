# moat-hosts

Host adapters: the only code that knows each agent's hook wire format.

An adapter turns a host payload into a `HookRequest` (session, tool, normalised
`Action`) and a `Decision` back into the host's response document. Adapters never
decide; `moat-core` does.

Supported today: Claude Code and Codex, which share the `PreToolUse` JSON contract
(`hookSpecificOutput.permissionDecision`). Golden payloads live in
`tests/fixtures/hosts/`.

Adding a host: see `AGENTS.md` §5 "Add a host adapter".
