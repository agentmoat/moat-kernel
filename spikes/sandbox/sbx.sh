#!/usr/bin/env bash
# Run a command inside the policy-derived Seatbelt profile, as `moat exec` would:
#   sbx.sh [--proxy-port N]... -- <cmd...>
# Extra variables to pass in: SBX_PASS="NAME1 NAME2" (the environment is otherwise rebuilt).
# HOME is the fake home from setup.sh; the real toolchains stay readable (reads are open)
# and are pointed at explicitly so nothing writes into the real HOME.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$HERE/.work"
PROXY=()
while [[ "${1:-}" == --proxy-port ]]; do PROXY+=(--proxy-port "$2"); shift 2; done
PASS=()
for v in ${SBX_PASS:-}; do PASS+=("$v=${!v}"); done
[[ "${1:-}" == -- ]] && shift
[[ -d "$W/home" ]] || bash "$HERE/setup.sh" >/dev/null

PROFILE="$W/profile.sb"
python3 "$HERE/gen_profile.py" --project "$W/project" \
  --home "$W/home" --home "$HOME" \
  --writable "${TMPDIR:-/tmp}" --writable /tmp \
  --writable "$W/home/.agent-state" --writable "$W/home/.npm" \
  "${PROXY[@]+"${PROXY[@]}"}" > "$PROFILE"

cd "$W/project"
exec /usr/bin/env -i \
  HOME="$W/home" USER="$USER" PATH="$PATH" TERM="${TERM:-dumb}" TMPDIR="${TMPDIR:-/tmp}" NPM_CONFIG_UPDATE_NOTIFIER=false \
  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
  ${HTTPS_PROXY:+HTTPS_PROXY="$HTTPS_PROXY" HTTP_PROXY="$HTTPS_PROXY"} "${PASS[@]+"${PASS[@]}"}" \
  /usr/bin/sandbox-exec -f "$PROFILE" "$@"
