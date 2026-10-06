#!/usr/bin/env bash
# Q4 / issue Q1: Codex's own sandbox (`codex sandbox`, the Seatbelt policy Codex applies to
# its tool calls), configured from the moat policy, against the same malicious project.
# CODEX_HOME is a temp dir and HOME the fake home: the real ~/.codex is never read.
#   CODEX=/path/to/codex q4-codex.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$HERE/.work"
bash "$HERE/setup.sh" >/dev/null
CODEX="${CODEX:-$(command -v codex)}"
[[ -x "$CODEX" ]] || { echo "codex not found; set CODEX=/path/to/codex"; exit 1; }
export CODEX_HOME="$W/codex-home"
mkdir -p "$CODEX_HOME"
echo "codex: $("$CODEX" --version)"

probe() { # label, config-args..., -- cmd...
  local label="$1"; shift
  local cfg=(); while [[ "$1" != -- ]]; do cfg+=("$1"); shift; done; shift
  printf '\n$ %s\n' "$label"
  (cd "$W/project" && env -i HOME="$W/home" PATH="$PATH" CODEX_HOME="$CODEX_HOME" TMPDIR="${TMPDIR:-/tmp}" \
    "$CODEX" sandbox "${cfg[@]+"${cfg[@]}"}" -C "$W/project" -- "$@") 2>&1 | tail -6
  echo "[exit ${PIPESTATUS[0]}]"
}
attacks() { # config-args...
  probe "  npm run test:loud (issue payload)" "$@" -- npm run --silent test:loud
  probe "  node attack.js (fs read, ~/.zshrc write, raw IP connect)" "$@" -- node attack.js
  probe "  make test (credentials, .env, outside write)" "$@" -- make -s test
  probe "  curl https://example.com (harmless egress check)" "$@" -- curl -sS -o /dev/null -m 8 -w 'http=%{http_code}\n' https://example.com
  probe "  plant a git hook" "$@" -- sh -c 'echo x > .git/hooks/pre-commit && echo PLANTED'
  probe "  write .codex/hooks.json in the project" "$@" -- sh -c 'mkdir -p .codex && echo {} > .codex/hooks.json && echo WROTE'
  probe "  git commit (ordinary work)" "$@" -- sh -c 'echo "// e" >> src/main.rs && git -c user.name=s -c user.email=s@example.invalid commit -qam e && echo committed'
}

echo; echo "##### built-in :workspace profile (= legacy sandbox_mode = \"workspace-write\", network off)"
attacks -P :workspace

echo; echo "##### permissions profile generated from the moat policy (codex-moat.config.toml)"
python3 "$HERE/gen_host_config.py" codex --project "$W/project" > "$CODEX_HOME/config.toml"
# harmless demo host, so an allowed request can be shown next to the denied ones
python3 - "$CODEX_HOME/config.toml" <<'PY'
import sys; p = sys.argv[1]; s = open(p).read()
open(p, "w").write(s.replace('[permissions.moat.network.domains]\n', '[permissions.moat.network.domains]\n"example.com" = "allow"\n'))
PY
attacks -P moat --enable network_proxy
probe "  curl https://example.org (not allowlisted)" -P moat --enable network_proxy -- curl -sS -o /dev/null -m 8 -w 'http=%{http_code}\n' https://example.org
probe "  curl --noproxy '*' https://example.com (bypass the Codex proxy)" -P moat --enable network_proxy -- curl -sS --noproxy '*' -o /dev/null -m 8 -w 'http=%{http_code}\n' https://example.com
probe "  read .env.example (template; moat allows it)" -P moat --enable network_proxy -- cat .env.example
