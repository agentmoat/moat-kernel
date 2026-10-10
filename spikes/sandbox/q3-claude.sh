#!/usr/bin/env bash
# Q3: can Claude Code itself run inside the policy-derived profile (option a)?
# Never touches the real HOME or real credentials: HOME is the fake home, the keychain
# is unreachable (mach deny), the API key is a fake string, and the "API" is fake_api.py
# on localhost. The egress proxy allows no host at all (--no-policy), so nothing leaves
# the machine; its DENY lines show which hosts the agent would need.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$HERE/.work"
bash "$HERE/setup.sh" >/dev/null
PROXY=18080 API=18090
python3 "$HERE/proxy.py" --port $PROXY --no-policy & P1=$!
python3 "$HERE/fake_api.py" --port $API & P2=$!
trap 'kill $P1 $P2 2>/dev/null' EXIT
sleep 1
CLAUDE_BIN="$(command -v claude)"
CLAUDE_BIN="$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$CLAUDE_BIN")"
export HTTPS_PROXY="http://127.0.0.1:$PROXY"
export ANTHROPIC_API_KEY="sk-ant-FAKE-moat-spike" ANTHROPIC_BASE_URL="http://127.0.0.1:$API" NO_PROXY="127.0.0.1,localhost"
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
in_sbx() { printf '\n$ %s\n' "$1"; shift; limit 90 bash "$HERE/sbx.sh" --proxy-port $PROXY --proxy-port $API -- "$@" 2>&1 | tail -15; echo "[exit ${PIPESTATUS[0]}]"; }

SBX_PASS="" in_sbx "claude --version (fake HOME, no state dir)" "$CLAUDE_BIN" --version

SBX_PASS="NO_PROXY ANTHROPIC_API_KEY ANTHROPIC_BASE_URL" \
  in_sbx "claude -p 'say ok' with the default state dir (~/.claude in the fake HOME)" \
  "$CLAUDE_BIN" -p "say ok"
echo "fake HOME after: $(find "$W/home" -mindepth 1 -maxdepth 1 -exec basename {} \; | tr '\n' ' ')"

export CLAUDE_CONFIG_DIR="$W/home/.agent-state/claude"
SBX_PASS="NO_PROXY ANTHROPIC_API_KEY ANTHROPIC_BASE_URL CLAUDE_CONFIG_DIR" \
  in_sbx "claude -p 'say ok' with CLAUDE_CONFIG_DIR in the writable state dir" \
  "$CLAUDE_BIN" -p "say ok"
echo "state dir after: $(find "$CLAUDE_CONFIG_DIR" -mindepth 1 -maxdepth 1 -exec basename {} \; 2>/dev/null | tr '\n' ' ')"

SBX_PASS="NO_PROXY ANTHROPIC_API_KEY ANTHROPIC_BASE_URL CLAUDE_CONFIG_DIR" \
  in_sbx "claude --bare -p 'say ok' (no keychain reads, no background prefetches)" \
  "$CLAUDE_BIN" --bare -p "say ok"

# the agent's own Bash tool inherits the profile: the fake model asks for `cat ~/.ssh/id_rsa`
python3 "$HERE/fake_api.py" --port 18091 --bash 'cat ~/.ssh/id_rsa; echo exit=$?' & P3=$!
trap 'kill $P1 $P2 $P3 2>/dev/null' EXIT
sleep 1
export ANTHROPIC_BASE_URL="http://127.0.0.1:18091"
SBX_PASS="NO_PROXY ANTHROPIC_API_KEY ANTHROPIC_BASE_URL CLAUDE_CONFIG_DIR" \
  limit 90 bash "$HERE/sbx.sh" --proxy-port $PROXY --proxy-port 18091 -- \
  "$CLAUDE_BIN" --bare -p "read my ssh key" --permission-mode default --allowedTools Bash 2>&1 | tail -5 \
  | sed 's/^/  /' | { printf '\n$ claude --bare -p ... --allowedTools Bash (fake model calls Bash: cat ~/.ssh/id_rsa)\n'; cat; }
