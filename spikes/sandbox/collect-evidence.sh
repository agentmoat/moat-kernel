#!/usr/bin/env bash
# Re-runs every probe and stores its output under evidence/, with personal paths redacted.
#   CODEX=/path/to/codex collect-evidence.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
E="$HERE/evidence"
mkdir -p "$E"
redact() {
  # shellcheck disable=SC2016 # "$SPIKE" and "$REALHOME" are literal placeholders
  python3 -c 'import os,sys; s=sys.stdin.read(); s=s.replace(sys.argv[1], "$SPIKE").replace(os.path.expanduser("~"), "$REALHOME"); sys.stdout.write(s)' "$HERE"
}
for job in q1-nesting q2-sbpl-network-probe "attacks baseline" "attacks sandbox" q2-proxy q3-claude q4-codex q4-claude demo; do
  name="$(echo "$job" | tr ' ' '-')"
  echo "== $job"
  read -r script arg <<< "$job"
  bash "$HERE/$script.sh" ${arg:+"$arg"} 2>&1 | redact > "$E/$name.txt"
done
# the generated artefacts themselves
bash "$HERE/setup.sh" >/dev/null
python3 "$HERE/gen_profile.py" --project "$HERE/.work/project" --home "$HERE/.work/home" \
  --writable "${TMPDIR:-/tmp}" --writable /tmp --writable "$HERE/.work/home/.agent-state" \
  --proxy-port 18080 | redact > "$E/generated-profile.sb"
python3 "$HERE/gen_host_config.py" codex --project "$HERE/.work/project" | redact > "$E/generated-codex-config.toml"
python3 "$HERE/gen_host_config.py" claude --project "$HERE/.work/project" | redact > "$E/generated-claude-settings.json"
