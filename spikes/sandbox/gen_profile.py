#!/usr/bin/env python3
"""Turn the OpenMoat default policy into a macOS Seatbelt (SBPL) profile.

Spike code, not product code. It maps the parts of the policy that an OS sandbox can
enforce on every process the agent spawns:

  deny  secrets-paths   fs.read + fs.write   -> (deny file-read* / file-write* ...)
  deny  kernel-self     fs.write             -> (deny file-write* ...)
  deny  shell-rc        fs.write             -> (deny file-write* ...)
  allow project-fs      fs.write             -> (allow file-write* (subpath project))
  defaults net: deny + allow registries net  -> no direct network; with --proxy-port only
                                                localhost:<port> (the proxy enforces hosts)

SBPL evaluates the *last* matching rule, so the profile is emitted as
  1. deny default, then the platform basics a process needs to start at all,
  2. the allow holes (reads everywhere, writes to project/temp/state dirs),
  3. every policy deny last, so no allow can override it (ADR-002 "deny is absolute").

Usage:
  gen_profile.py --project DIR --home DIR [--home DIR ...] [--writable DIR ...]
                 [--proxy-port N] [--policy FILE] > profile.sb
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY = os.path.join(HERE, "..", "..", "crates", "openmoat-core", "policies", "default-v1.yaml")


def load_policy(path):
    """PyYAML when present, else the YAML parser that ships with macOS's system Ruby."""
    try:
        import yaml  # type: ignore

        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        ruby = shutil.which("ruby") or sys.exit("need PyYAML or ruby to read the policy")
        out = subprocess.run(
            [ruby, "-ryaml", "-rjson", "-e", "puts YAML.load_file(ARGV[0]).to_json", path],
            check=True, capture_output=True, text=True,
        ).stdout
        return json.loads(out)


def rule(policy, section, rule_id):
    return next(r for r in policy[section] if r["id"] == rule_id)


def q(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def glob_to_regex(glob):
    """`**/x/*` style glob (relative tail only) -> POSIX ERE fragment."""
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out, i = out + "(.*/)?", i + 3
        elif glob.startswith("**", i):
            out, i = out + ".*", i + 2
        elif glob[i] == "*":
            out, i = out + "[^/]*", i + 1
        else:
            out, i = out + ("\\" + glob[i] if glob[i] in ".+?()[]{}|^$\\" else glob[i]), i + 1
    return out


def filters(pattern, homes, project):
    """One policy glob -> SBPL path filters. Returns [] for patterns SBPL cannot scope."""
    pattern = pattern.replace("${project}", project)
    if pattern.startswith("**/"):
        # anywhere on disk: match on the trailing components
        tail = pattern[3:]
        if tail.endswith("/**"):
            return [f'(regex #"/{glob_to_regex(tail[:-3])}(/.*)?$")']
        return [f'(regex #"/{glob_to_regex(tail)}$")']
    bases = [pattern.replace("~", h, 1) for h in homes] if pattern.startswith("~") else [pattern]
    out = []
    for b in bases:
        if b.endswith("/**") and "*" not in b[:-3]:
            out.append(f"(subpath {q(b[:-3])})")
        elif "*" not in b:
            out.append(f"(literal {q(b)})")
        else:
            out.append(f'(regex #"^{glob_to_regex(b)}$")')
    return out


def split(patterns):
    pos = [p for p in patterns if not p.startswith("!")]
    neg = [p[1:] for p in patterns if p.startswith("!")]
    return pos, neg


BASICS = """\
(version 1)
(deny default)
; --- platform basics: enough for shells, node, git, cargo/rustc to start ---
(allow process-exec process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(allow file-read*)                       ; reads are open; secrets are denied below
(allow file-ioctl)
(allow pseudo-tty)
(allow ipc-posix-shm* ipc-posix-sem)
(allow user-preference-read)
(allow iokit-open (iokit-registry-entry-class "RootDomainUserClient"))
; mach services a CLI toolchain needs. Not the keychain (com.apple.SecurityServer,
; com.apple.securityd) and not the pasteboard: a project script gets neither.
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.logd")
  (global-name "com.apple.diagnosticd")
  (global-name "com.apple.CoreServices.coreservicesd")
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.lsd.mapdb")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.analyticsd")
  (global-name "com.apple.dnssd.service"))
(allow file-write-data file-write-create
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/tty") (literal "/dev/dtracehelper")
  (regex #"^/dev/ttys[0-9]+$") (regex #"^/dev/fd/[0-9]+$"))
"""


def build(policy, project, homes, writable, proxy_ports):
    secrets_pos, secrets_neg = split(rule(policy, "deny", "secrets-paths")["fs.read"])
    proj_w_pos, proj_w_neg = split(rule(policy, "allow", "project-fs")["fs.write"])
    kernel_self = rule(policy, "deny", "kernel-self")["fs.write"]
    shell_rc = rule(policy, "deny", "shell-rc")["fs.write"]
    hosts = rule(policy, "allow", "registries")["net"]

    def block(verb, patterns, comment):
        fs = [f for p in patterns for f in filters(p, homes, project)]
        return f"; {comment}\n({verb}\n  " + "\n  ".join(fs) + ")\n" if fs else ""

    out = [BASICS]
    out.append("; --- allow holes ---\n")
    out.append(block("allow file-write*", proj_w_pos, "allow project-fs: writes inside the project"))
    out.append(block("allow file-write*", [w.rstrip("/") + "/**" for w in writable],
                     "writes the agent and toolchains need: temp dirs, the agent's own state dir, caches"))

    # project-fs excludes .git/**: the OS layer cannot tell `git commit` (allowed by
    # dev-shell) from a script editing hooks, so it protects only the code-execution
    # paths of .git (hooks, config) and lets git write its object store. Lossy, see README.
    proj_w_neg = [n for n in proj_w_neg if not n.endswith("/.git/**")]
    git_exec = [f"{project}/.git/hooks/**", f"{project}/.git/config"]

    out.append("\n; --- policy denies, last so nothing above overrides them (ADR-002) ---\n")
    out.append(block("deny file-write*", proj_w_neg + git_exec, "project-fs exclusions (.moat) and git code-execution paths"))
    out.append(block("deny file-write*", kernel_self, "deny kernel-self"))
    out.append(block("deny file-write*", shell_rc, "deny shell-rc"))
    out.append(block("deny file-read-data file-write*", secrets_pos, "deny secrets-paths (contents; stat metadata stays visible so git status works)"))
    # SBPL regex is last-match too: re-open the committed templates after the .env deny
    out.append(block("allow file-read-data", secrets_neg, "secrets-paths negations (!**/.env.example ...)"))
    out.append("(deny mach-lookup (global-name \"com.apple.SecurityServer\") (global-name \"com.apple.securityd\"))\n")

    out.append("\n; --- network: defaults net: deny ---\n")
    out.append(f"; policy allowlist (registries): {', '.join(hosts)}\n")
    out.append("; SBPL cannot name a host or an IP (only `*` or `localhost`), so the allowlist\n")
    out.append("; is enforced by the proxy; the sandbox only guarantees the proxy is the sole way out.\n")
    out.append("(deny network*)\n")
    for port in proxy_ports:
        out.append(f'(allow network-outbound (remote ip "localhost:{port}"))\n')
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--project", required=True)
    ap.add_argument("--home", action="append", required=True, help="every HOME whose ~ paths to protect")
    ap.add_argument("--writable", action="append", default=[], help="extra writable roots")
    ap.add_argument("--proxy-port", type=int, action="append", default=[],
                    help="localhost port the sandbox may connect to (the egress proxy); repeatable")
    a = ap.parse_args()
    # Seatbelt matches the resolved path (/var -> /private/var, /tmp -> /private/tmp)
    real = lambda p: os.path.realpath(os.path.expanduser(p))
    sys.stdout.write(build(load_policy(a.policy), real(a.project), [real(h) for h in a.home],
                           [real(w) for w in a.writable], a.proxy_port))


if __name__ == "__main__":
    main()
