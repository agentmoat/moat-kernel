#!/usr/bin/env bash
# Q2 (network): sandbox allows only localhost:<port>; proxy.py allows only policy hosts
# (+ example.com for this harmless demo). Exfil hosts and direct connections must fail.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=18080
bash "$HERE/setup.sh" >/dev/null
python3 "$HERE/proxy.py" --port "$PORT" --allow example.com &
PROXY_PID=$!
python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 &   # a local service on another port
OTHER_PID=$!
trap 'kill $PROXY_PID $OTHER_PID 2>/dev/null' EXIT
sleep 1
export HTTPS_PROXY="http://127.0.0.1:$PORT"

in_sbx() { printf '\n$ %s\n' "$1"; shift; bash "$HERE/sbx.sh" --proxy-port "$PORT" -- "$@" 2>&1; echo "[exit $?]"; }

in_sbx "GET https://example.com via proxy (allowlisted for the demo)" \
  curl -sS -o /dev/null -m 10 -w 'http=%{http_code}\n' https://example.com
in_sbx "GET https://example.org via proxy (not on the allowlist)" \
  curl -sS -o /dev/null -m 10 -w 'http=%{http_code}\n' https://example.org
in_sbx "issue payload via proxy: npm run test:loud (exfil to example.invalid)" npm run --silent test:loud
in_sbx "bypass the proxy: curl --noproxy '*' https://example.com" \
  curl -sS --noproxy '*' -o /dev/null -m 8 -w 'http=%{http_code}\n' https://example.com
in_sbx "bypass the proxy: node raw socket to an IP (attack.js)" node attack.js
in_sbx "localhost on another port (allowed port is $PORT only)" \
  curl -sS --noproxy "*" -o /dev/null -m 3 -w "http=%{http_code}\n" http://127.0.0.1:18081/
echo; echo "\$ same request outside the sandbox (control: the service on 18081 is up)"
curl -sS --noproxy '*' -o /dev/null -m 3 -w 'http=%{http_code}\n' http://127.0.0.1:18081/
