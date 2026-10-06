#!/usr/bin/env python3
"""Minimal egress proxy for the spike: HTTP CONNECT (and plain-HTTP absolute-URI) on
127.0.0.1 with a host allowlist taken from the policy's `allow` net rules.

The Seatbelt profile allows network only to localhost:<port>, so this proxy is the one
way out; it decides by the host name the client asks for (CONNECT host:port), which is
what SBPL cannot do. Spike code: no TLS inspection, no SNI check against the CONNECT
host, no logging to the audit store.

  proxy.py --port 18080 [--allow example.com ...] [--no-policy]
"""
import argparse
import socket
import sys
import threading

sys.path.insert(0, __import__("os").path.dirname(__file__))
from gen_profile import DEFAULT_POLICY, load_policy  # noqa: E402


def allowed_hosts(extra, use_policy=True):
    if not use_policy:
        return set(extra)
    pol = load_policy(DEFAULT_POLICY)
    hosts = {h for r in pol.get("allow", []) for h in r.get("net", [])}
    return hosts | set(extra)


def pipe(a, b):
    try:
        while data := a.recv(65536):
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, hosts):
    head = b""
    while b"\r\n\r\n" not in head and len(head) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            return client.close()
        head += chunk
    method, target, _ = head.split(b"\r\n", 1)[0].decode("latin1").split(" ", 2)
    if method == "CONNECT":
        host, _, port = target.rpartition(":")
    else:  # absolute-URI plain HTTP: GET http://host[:port]/path
        rest = target.split("://", 1)[-1].split("/", 1)[0]
        host, _, port = rest.partition(":")
        port = port or "80"
    host = host.strip("[]").lower()
    if host not in hosts:
        print(f"proxy: DENY {method} {host}:{port}", flush=True)
        client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        return client.close()
    print(f"proxy: ALLOW {method} {host}:{port}", flush=True)
    try:
        upstream = socket.create_connection((host, int(port)), timeout=10)
    except OSError:
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return client.close()
    if method == "CONNECT":
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    else:
        upstream.sendall(head)
    threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
    pipe(client, upstream)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--allow", action="append", default=[])
    ap.add_argument("--no-policy", action="store_true", help="allow only --allow hosts")
    a = ap.parse_args()
    hosts = allowed_hosts(a.allow, not a.no_policy)
    srv = socket.create_server(("127.0.0.1", a.port))
    print(f"proxy: listening on 127.0.0.1:{a.port}, {len(hosts)} hosts allowed", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, hosts), daemon=True).start()


if __name__ == "__main__":
    main()
