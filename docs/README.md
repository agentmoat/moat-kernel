# Documentation map

Start with the top-level `README.md` for what `moat` is and how to install it. The
alpha is decide-only (ADR-013); every document here describes the code on `main`.

| Document | Read it when you want to… |
|---|---|
| [POLICY.md](POLICY.md) | write or understand a policy file: schema, rule kinds, pattern syntax, evaluation order, the default policy |
| [THREAT_MODEL.md](THREAT_MODEL.md) | know what is defended, how the alpha answers each threat class, and the known limitations |
| [COVERAGE.md](COVERAGE.md) | see the conformance fixtures per threat class (generated; do not edit) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | find where code lives and how a tool call becomes a decision, a hook response and an audit record |
| [ROADMAP.md](ROADMAP.md) | see the alpha, beta and 1.0 stages; the live order is issue #144 |
| [adr/](adr/README.md) | read the decisions that constrain the code |

Contributor files live at the repository root: `AGENTS.md` (working contract),
`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`.

Conventions: documents are updated in the same pull request as the behaviour they
describe. ADRs are immutable and superseded, never edited.
