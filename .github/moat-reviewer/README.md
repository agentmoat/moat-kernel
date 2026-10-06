# moat-reviewer

`moat-reviewer` is the automated first-pass reviewer for pull requests. It is a GitHub
App owned by the `crocodile-labs` organisation that runs `.github/workflows/pr-review.yml`
(Claude Code on GitHub Actions) and posts under its own name and avatar.

What it does:

- reads `AGENTS.md` and reviews the diff against the invariants, engineering rules and
  definition of done, running the quality gate or targeted tests when a claim needs proof;
- posts inline comments tagged `🔴 blocker` · `🟠 should fix` · `🟡 nit` · `💡 idea`, each
  with what / why / fix and a suggestion block when the fix is small;
- posts one summary per revision: verdict, findings table, what was checked and found
  fine, and engineering gaps beyond the PR.

What it does not do: approve, request changes, push, or count as the maintainer review
required by CODEOWNERS. Address or answer its 🔴/🟠 items; disagree in a reply when it is
wrong. Re-run it on the current head by commenting `@moat-reviewer`.

When it runs: same-repository pull requests on open, push, reopen and ready-for-review
(drafts and Dependabot are skipped). Fork PRs have no access to secrets, so a maintainer
triggers the review with `@moat-reviewer` after a first look at the change. That run has the model credential and the app token while the fork's code is checked out, so it only gets the read-only `gh` tools: building or testing a fork PR would execute its build scripts and tests next to those secrets.

## Setup (maintainers, once)

1. **Create the GitHub App** in the org (prefilled form):

   <https://github.com/organizations/crocodile-labs/settings/apps/new?name=moat-reviewer&description=Automated%20first-pass%20reviewer%20for%20OpenMoat%20pull%20requests&url=https://github.com/crocodile-labs/openmoat&public=false&webhook_active=false&contents=read&pull_requests=write&issues=write&metadata=read>

   Permissions: Contents read, Pull requests write, Issues write, Metadata read. No
   webhook. After creating it: upload `avatar.png` from this directory as the app
   avatar, note the **App ID**, generate a **private key** (`.pem`), and **install** the
   app on `crocodile-labs/openmoat`.

2. **Secrets and the enable switch** (run as an org admin):

   ```bash
   gh secret set MOAT_REVIEWER_APP_ID      -R crocodile-labs/openmoat -b '<app id>'
   gh secret set MOAT_REVIEWER_PRIVATE_KEY -R crocodile-labs/openmoat < moat-reviewer.<date>.private-key.pem
   # one of the two model credentials:
   gh secret set CLAUDE_CODE_OAUTH_TOKEN   -R crocodile-labs/openmoat -b "$(claude setup-token)"   # Claude subscription
   gh secret set ANTHROPIC_API_KEY         -R crocodile-labs/openmoat -b '<key>'                   # or API key
   gh variable set MOAT_REVIEWER_ENABLED   -R crocodile-labs/openmoat -b true
   ```

   The workflow is a no-op until `MOAT_REVIEWER_ENABLED` is `true`, so the repository
   stays green while the app is being set up. Set it to `false` to pause the reviewer.

3. **Verify**: open a PR and expect a tracking comment from `moat-reviewer[bot]` within a
   minute, inline comments as it reads, and a summary at the end.

## Changing the review

The checklist and output format live in the `prompt:` of `pr-review.yml`; the standards it
enforces live in `AGENTS.md`. Change the standard first, then the prompt. Tools the reviewer
may use are the `--allowedTools` list: read-only `gh` commands, plus the quality gate, tests,
clippy and `moat policy check` on same-repository PRs only. Keep it that way; the reviewer must never be able to edit the
PR, merge, or reach other repositories.

Actions are pinned by commit SHA like every other workflow here. Bump
`anthropics/claude-code-action` and `actions/create-github-app-token` through Dependabot.
