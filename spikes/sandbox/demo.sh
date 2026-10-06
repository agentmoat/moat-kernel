#!/usr/bin/env bash
# End to end: a malicious project script steals a (fake) SSH key and phones home.
# Without a sandbox it succeeds; under the Seatbelt profile generated from the moat
# default policy it is blocked by the operating system, whatever the command string was.
# Exits 1 if anything leaks under the sandbox. macOS only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$HERE/.work"
bash "$HERE/setup.sh" >/dev/null
PORT=18080
python3 "$HERE/proxy.py" --port $PORT >/dev/null 2>&1 & PROXY=$!
trap 'kill $PROXY 2>/dev/null' EXIT
sleep 1

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
plain() { (cd "$W/project" && env HOME="$W/home" NPM_CONFIG_UPDATE_NOTIFIER=false CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
  RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" "$@") 2>&1; }
boxed() { HTTPS_PROXY="http://127.0.0.1:$PORT" bash "$HERE/sbx.sh" --proxy-port $PORT -- "$@" 2>&1; }

say "the project's test script (package.json)"
grep '"test' "$W/project/package.json"

say "1. no sandbox: npm run test:node, cargo build (build.rs)"
plain npm run --silent test:node
plain cargo build 2>&1 | grep warning

bash "$HERE/setup.sh" >/dev/null   # reset the fake HOME (the payload edited ~/.zshrc)
say "2. moat profile (sandbox-exec, generated from default-v1.yaml) + egress proxy"
OUT="$(boxed npm run --silent test:node; boxed npm run --silent test:loud; boxed cargo build)"
echo "$OUT" | grep -v -E '^\s+(Compiling|Finished)'

say "3. ordinary project work under the same profile"
boxed sh -c 'echo "// edit" >> src/main.rs && git -c user.name=s -c user.email=s@example.invalid commit -qam edit && echo "edit + commit ok"'
boxed cargo run -q 2>/dev/null
boxed node --version

say "verdict"
if echo "$OUT" | grep -q -E 'LEAKED|PERSISTED|CONNECTED|FAKE-'; then
  echo "FAIL: something leaked under the sandbox"; exit 1
fi
echo "PASS: secret reads, persistence and exfiltration were blocked at the OS level"
