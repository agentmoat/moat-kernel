# Documentation map

Start with the top-level `README.md` for what `moat` is and how to install it.

| Document | Read it when you want to… |
|---|---|
| [POLICY.md](POLICY.md) | write or understand a policy file: schema, rule kinds, pattern syntax, evaluation order, defaults |
| [OVERVIEW.md](OVERVIEW.md) | understand the problem, positioning, where the kernel applies and where it does not, the roadmap |
| [DESIGN.md](DESIGN.md) | see the engineering spec: threat model, verified host hook formats, architecture, decision pipeline, hard problems, v0.1 spec |
| [STRENGTH.md](STRENGTH.md) | see how the product is kept strong: five defense layers, coverage matrix, MoatBench benchmark and release gates |
| [TECH_STACK.md](TECH_STACK.md) | see why Rust and the chosen crates (scored comparison) |
| [REPO_STRUCTURE.md](REPO_STRUCTURE.md) | find where code lives, crate dependency rules, CI/release and contribution conventions |
| [PROGRESS.md](PROGRESS.md) | know exactly what is built, what is not, and what comes next |
| [adr/](adr/) | read the record of decisions that constrain the code (Rust, deny-absolute, decide-and-enforce, exit codes) |

Contributor files live at the repository root: `AGENTS.md` (working contract),
`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`.

Conventions: documents are updated in the same pull request as the behaviour they
describe. ADRs are immutable and superseded, never edited. `PROGRESS.md` is the only
document that is expected to churn.
