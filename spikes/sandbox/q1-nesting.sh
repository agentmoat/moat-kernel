#!/usr/bin/env bash
# Q1: can a Seatbelt profile be applied inside a process that is already sandboxed?
# Each case runs an outer profile, and inside it an inner `sandbox-exec -p`.
set -u
SX=/usr/bin/sandbox-exec
ALLOW='(version 1)(allow default)'
# restrictive: deny reading one file, allow everything else
DENY_ONE='(version 1)(allow default)(deny file-read* (literal "/private/etc/hosts"))'
DENY_NET='(version 1)(allow default)(deny network-outbound)'
DENY_DEFAULT='(version 1)(deny default)(allow process*)(allow file-read*)(allow sysctl-read)(allow mach-lookup)'

run() { # label outer inner
  printf '\n### outer=%s inner=%s\n' "$1" "$2"
  "$SX" -p "$3" "$SX" -p "$4" /bin/echo inner-ran 2>&1
  echo "exit=$?"
}

echo "## baseline: no outer sandbox"
"$SX" -p "$DENY_ONE" /bin/echo inner-ran; echo "exit=$?"

run allow-all allow-all "$ALLOW" "$ALLOW"
run allow-all deny-one "$ALLOW" "$DENY_ONE"
run deny-one deny-one "$DENY_ONE" "$DENY_ONE"
run deny-one allow-all "$DENY_ONE" "$ALLOW"
run deny-net deny-net "$DENY_NET" "$DENY_NET"
run deny-net deny-one "$DENY_NET" "$DENY_ONE"
run deny-default deny-default "$DENY_DEFAULT" "$DENY_DEFAULT"

echo
echo "## is the current shell already sandboxed? (71 = sandbox_apply failed; 1 = cat denied, so the profile applied)"
"$SX" -p "$DENY_ONE" /bin/cat /private/etc/hosts >/dev/null 2>&1; echo "exit=$?"

echo
echo "## same rules, different text (whitespace + comment): byte equality or semantic?"
DENY_ONE_WS='(version 1) (allow default) (deny file-read* (literal "/private/etc/hosts")) ; same rule'
"$SX" -p "$DENY_ONE" "$SX" -p "$DENY_ONE_WS" /bin/echo inner-ran 2>&1; echo "exit=$?"

echo
echo "## identical nest: is the restriction still enforced inside? (1 = still denied)"
"$SX" -p "$DENY_ONE" "$SX" -p "$DENY_ONE" /bin/cat /private/etc/hosts >/dev/null 2>&1; echo "exit=$?"

echo
echo "## moat exec inside a real host sandbox: codex sandbox -P :workspace -- sandbox-exec -p <restrictive>"
if [[ -x "${CODEX:-}" ]]; then
  CODEX_HOME="$(mktemp -d)" "$CODEX" sandbox -P :workspace -C /tmp -- "$SX" -p "$DENY_ONE" /bin/echo inner-ran 2>&1
  echo "exit=$?"
else
  echo "skipped: set CODEX=/path/to/codex"
fi
