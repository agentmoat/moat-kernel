#!/usr/bin/env bash
# Q2: what can a Seatbelt network filter express? Each profile is compiled by running
# /usr/bin/true under it; a compile error means SBPL cannot express that filter.
set -u
SX=/usr/bin/sandbox-exec
try() {
  printf '%-58s ' "$1"
  out=$("$SX" -p "(version 1)(allow default)(deny network-outbound)$1" /usr/bin/true 2>&1)
  echo "exit=$? ${out}"
}
echo "## filter accepted by the SBPL compiler?"
try '(allow network-outbound (remote ip "localhost:8080"))'
try '(allow network-outbound (remote ip "*:443"))'
try '(allow network-outbound (remote tcp "*:443"))'
try '(allow network-outbound (remote ip "example.com:443"))'
try '(allow network-outbound (remote ip "104.20.23.154:443"))'
try '(allow network-outbound (remote ip "104.20.0.0/16:443"))'
try '(allow network-outbound (remote ip "127.0.0.1:8080"))'
try '(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))'

echo
echo "## behaviour: GET https://example.com (harmless) under each network rule"
get() {
  printf '%-58s ' "$1"
  "$SX" -p "(version 1)(allow default)$1" /usr/bin/curl -sS -o /dev/null -m 8 -w 'http=%{http_code}' https://example.com 2>&1 | tr '\n' ' '
  echo " exit=${PIPESTATUS[0]}"
}
get ''
get '(deny network-outbound)'
get '(deny network-outbound)(allow network-outbound (remote ip "*:443"))'
get '(deny network-outbound)(allow network-outbound (remote unix-socket))(allow network-outbound (remote ip "*:443"))'
get '(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
