# Documentation map

Start with the top-level `README.md` for what OpenMoat is. Every document here
describes the code on `main`.

| Document | Read it when you want to… |
|---|---|
| [INSTALL.md](INSTALL.md) | install on any platform, run `moat init`, see what each agent's hook covers, use other config directories |
| [USAGE.md](USAGE.md) | handle a deny or an ask, review what the agent did, change the policy, share rules with a team; every command and exit code |
| [SANDBOX.md](SANDBOX.md) | make the OS enforce the policy: the agents' own sandboxes (Standard tier) and `moat run` (Lightweight tier) |
| [POLICY.md](POLICY.md) | write or understand a policy file: schema, rule kinds, pattern syntax, evaluation order, the default policy |
| [THREAT_MODEL.md](THREAT_MODEL.md) | know what is defended, how the alpha answers each threat class, and the known limitations |
| [COVERAGE.md](COVERAGE.md) | see the conformance fixtures per threat class (generated; do not edit) |
| [MOATBENCH.md](MOATBENCH.md) | run the attack and everyday scenarios per host and read the scorecard |
| [DEMO.md](DEMO.md) | run the launch demo in a throwaway home |
| [ARCHITECTURE.md](ARCHITECTURE.md) | find where code lives and how a tool call becomes a decision, a hook response and an audit record |
| [ADDING_AN_AGENT.md](ADDING_AN_AGENT.md) | add support for another AI coding agent: adapter, installer, fixtures, tests, docs |
| [ROADMAP.md](ROADMAP.md) | see the alpha, beta and 1.0 stages; the live order is issue #144 |
| [adr/](adr/README.md) | read the decisions that constrain the code |

Contributor files live at the repository root: `AGENTS.md` (working contract),
`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`.

Conventions: documents are updated in the same pull request as the behaviour they
describe. ADRs are immutable and superseded, never edited.
