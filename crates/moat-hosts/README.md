# openmoat-hosts

Host adapters: the only code that knows each agent's hook wire format.

An adapter turns a host payload into a `HookRequest` (session, tool, normalised
`Action`) and a `Decision` back into the host's response document. Adapters never
decide; `openmoat-core` does.

Supported today: Claude Code and Codex (shared `PreToolUse` contract,
`hookSpecificOutput.permissionDecision`), Claude Code `ConfigChange`, and Cursor
(`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`;
`{"permission": …}` responses). Golden payloads live in `tests/fixtures/hosts/`.

Adding a host: see `AGENTS.md` §5 "Add a host adapter".
