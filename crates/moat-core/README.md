# moat-core

The trusted decision core of agentmoat: policy model, POSIX shell lexer and
classifier, pattern matching, path normalisation and the decision engine.

**Pure by construction.** No I/O, no OS calls, no `unsafe`, no internal
dependencies. The crate builds for `wasm32-unknown-unknown` in CI, and
`tests/architecture.rs` pins the dependency allowlist and a 500-line file budget.

```rust
use moat_core::{Action, CompiledPolicy, EvalContext, Policy};

let policy = Policy::parse(include_str!("../../policies/default-v1.yaml"))?;
let ctx = EvalContext { home: "/Users/me".into(), project: "/p".into(), cwd: "/p".into() };
let compiled = CompiledPolicy::compile(&policy, &ctx)?;
let decision = compiled.decide(&Action::Shell { command: "cat ~/.ssh/id_rsa".into() });
assert_eq!(decision.verdict, moat_core::Verdict::Deny);
```

Modules: `policy` (schema, lint), `lexer/` (tokens), `shell/` (classification),
`pattern` (globs and shell patterns), `paths` (canonical paths), `engine`
(deny → allow → ask → defaults, strictest wins), `verdict`, `action`.

Semantics are specified in `docs/POLICY.md` and `docs/DESIGN.md` §6–7 and
enforced by `tests/conformance/`.
