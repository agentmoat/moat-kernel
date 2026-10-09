# ADR-023: Isolated tier on macOS: an Apple Virtualization guest, built on Apple's `containerization`

Status: accepted · Date: 2026-10-09 · Decided by the owner · Refines ADR-018 for macOS; implementation of #175

## Context

ADR-018 defined three enforcement tiers. The Isolated tier runs the agent in a
Linux guest with OpenMoat's kernel, proxy and secrets broker on the host; the
guest's only network route is the proxy. On Linux it ships (#174, released in
0.1.1): bubblewrap starts the agent rootless, with the Lightweight tier's
Landlock rules and seccomp filter inside. On macOS it does not: Seatbelt does
not nest (ADR-018), and `sandbox-exec` is deprecated. For the Isolated tier to
mean the same thing on macOS it needs a Linux guest, so bubblewrap, Landlock
and seccomp still apply inside.

Apple ships [Virtualization.framework](https://developer.apple.com/documentation/virtualization)
on macOS 11 and up (Apple silicon and recent Intel): hypervisor-backed, no
daemon, user-mode launched, with native `VZVirtioFileSystemDevice` (virtiofs)
and `VZVirtioSocketDevice` (vsock). It is what Docker Desktop, OrbStack, Podman
Machine, Lima, Finch and Apple's own `container` CLI use.

Three real options are on the table today:

**(a) Direct Virtualization.framework usage from Rust.** The `objc2` and
`block2` crates give a safe Objective-C bridge; a `moat-vz` module would own
`VZVirtualMachineConfiguration`, boot a Linux kernel we ship, mount the project
over virtiofs and expose the proxy over vsock. Dependency surface: the two
`objc2` crates and the system framework. Licensing: MIT or Apache-2.0 for
`objc2`; the framework is Apple's. Start-up: ~1.0–1.5 s cold on an M-series
machine (measured in `spikes/vz/`, kernel 6.6, 512 MiB, no init). We own the
kernel acquisition story: pin an `.img.gz` by SHA-256 in `policy.lock`, host
it next to the release, and fail closed on a mismatch. virtiofs mounts the
project with the same deny coverage bubblewrap gives on Linux: a placeholder
file (`mode 0`) for every denied read, a read-only bind for every denied
write. The proxy relay is a vsock listener that `moat isolated` inside connects
to; the guest keeps its own network namespace empty, as on Linux. bubblewrap
nests inside the guest kernel exactly as under `moat run --isolate` on Linux,
with the same Landlock rules and seccomp filter.

**(b) Reuse Lima.** Apache-2.0, mature virtiofs through `virtiofsd`, declarative
YAML, and a known `limactl start` ~5–8 s cold path. Dependency surface: a Go
runtime binary on the user's `PATH`, `qemu` or Apple's VZ backend, and the
Lima guest-agent (which runs inside and would need auditing or disabling for
our threat model). Licensing is fine. Kernel acquisition: Lima downloads an
Ubuntu or Alma cloud image at first use; we would have to pin a specific
image by digest and ship a stricter `lima.yaml`. Proxy relay: Lima's forwarded
ports can carry the proxy, but port-forwarding is wider than vsock (any
localhost listener on the host becomes reachable from the guest unless
`portForwards` are narrowed; the proxy must still be the only route). The
bubblewrap-inside-guest composition works because the guest is a full Linux.

**(c) Apple's `containerization` toolchain.** At WWDC 2026 Apple shipped
[`container`](https://github.com/apple/container), a Swift CLI built on the new
[`Containerization`](https://github.com/apple/containerization) framework, which
is itself a thin layer over Virtualization.framework. One lightweight VM per
container, Apple-signed, Apple-maintained kernel; native virtiofs; native
vsock; sub-second cold start on Apple silicon (Apple's own number, confirmed
in `spikes/vz/` at ~0.8 s). Apache-2.0, no daemon, no system extension.
Dependency surface: a Swift framework and a CLI that is `brew install`-able or
downloadable from Apple's release page; our Rust code calls it over a
documented API. Licensing is fine. Kernel acquisition: Apple ships and signs
it, and the framework fails closed on an unsigned image. virtiofs is first
class and matches the mount model bubblewrap uses on Linux: we tell it which
host paths to project into the guest; everything else is simply absent. The
proxy relay is vsock. bubblewrap-inside-guest composes because `container`
boots a real Linux kernel, so `moat isolated` inside the guest is unchanged
from Linux.

The sandbox spike (#119) also showed that one process we do not control inside
the agent's confinement (a Go runtime binary, a daemon, a system extension) is
one more thing to audit, patch and defend. The Isolated tier is the strongest
sandbox we ship: the simpler the host-side surface, the fewer paths into it.

## Decision

**Pick (c): build the macOS Isolated tier on Apple's `containerization`
toolchain (`container` CLI as the first implementation; move to the Swift
framework directly once the Rust FFI stabilises).**

Top three reasons:

1. **Apple owns the kernel.** The Isolated tier's trust base shrinks from "a
   Linux kernel OpenMoat ships" to "the Linux kernel Apple ships and signs for
   `container`". Apple patches it on the same cadence as the OS. We still pin
   the exact version in `policy.lock` so drift fails closed.
2. **Shortest surface we control.** No Go runtime, no daemon, no system
   extension, no `qemu`. Boot time is Apple's; virtiofs and vsock are
   first-class, so the proxy relay and the mount model mirror what bubblewrap
   does on Linux.
3. **Fastest cold start.** ~0.8 s measured in `spikes/vz/`, close enough to
   bubblewrap's ~0.1 s that `moat run --isolate` stays interactive on macOS.
   Lima's 5–8 s would push users to the Lightweight tier, where the ADR-018
   claims are weaker.

What the owner must accept:

- **Minimum macOS version: 26.0** (`containerization` is 26.0+). On macOS 25
  and earlier, `moat run --isolate` keeps refusing with the stub this PR
  ships: documented, exit 64, never a silent fallback to Lightweight.
- **Dependency: `container` on `PATH`**, Apple-signed, pinned by minimum
  version in `moat doctor`. `brew install --cask container`, or Apple's
  download. Where it is missing, `moat run --isolate` refuses with a clear
  install hint (exit 64).
- **Kernel image hosting:** none on our side — Apple ships the kernel and the
  `container` binary. We pin the kernel's reported version string and the
  `container` binary's SHA-256 in `policy.lock`; drift denies for the session
  (ADR-006), as a drifted policy does.
- **Update story:** a new `container` release is picked up by `moat doctor`,
  which re-pins after an owner-approved `--accept` in a terminal. Never
  silently.
- **Binary size:** OpenMoat gains a thin FFI wrapper (one file, feature-gated
  under `#[cfg(target_os = "macos")]`), no new Rust dependency crate at
  release time. The implementation will cross-check `container`'s process
  status over its JSON API, not screen-scrape its logs.

## Composition inside the guest

The Isolated-tier guest is a Linux VM; everything OpenMoat does inside is what
`moat run --isolate` already does on Linux today:

- The project is projected into the guest at its original path over virtiofs,
  read-write; a denied read is covered by an empty placeholder (mode `0`); a
  denied write is covered by a read-only bind. `.env`, `.envrc` and `.moat`
  directly in the project get placeholder files for the session.
- `sandbox.read_roots` are projected read-only. The `--write` paths are
  projected read-write. The agent's executable is projected read-only.
- Inside the guest, `moat isolated` runs first: it serves the proxy's port on
  the guest's loopback and relays each connection over vsock to `moat run`
  outside, which forwards it to `moat proxy`. The guest has no other network.
- `moat isolated` then starts bubblewrap around the agent with the same
  Landlock rules and seccomp filter as `moat run --isolate` on Linux. The
  agent's own sandbox stays off, as under `moat run`.

The guest kernel, rootfs and `container` binary are pinned in `policy.lock`.
Drift denies for the session, as a drifted policy does.

## Threat-model consequences

- **VM escape.** Virtualization.framework is Apple's hypervisor; a public
  escape would also compromise Docker Desktop, OrbStack and Apple's own
  `container`. We inherit that attack surface and nothing more. Covered as a
  stated residual risk in docs/THREAT_MODEL.md.
- **Kernel version pinning.** `policy.lock` records the kernel version
  `container` reports and the `container` binary's SHA-256. A new kernel
  version denies the session until `moat doctor --accept` re-pins, so a
  silent kernel downgrade cannot slip in.
- **Side-channels.** Shared caches, timing on the hypervisor, and SMT between
  guest and host remain. They are out of scope for this ADR and listed in
  THREAT_MODEL as covert-channel residual risk, like Lightweight and
  Standard.
- **VM state leakage between sessions.** Each `moat run --isolate` on macOS
  creates a one-shot VM: a fresh rootfs, no persistent disk image, teardown
  on exit (`container stop`). No session's writes are visible to the next
  session's guest; the project's writes land on the host filesystem through
  virtiofs, as on Linux.
- **virtiofs shared-permissions bug.** virtiofs projects host inodes, so a
  misconfigured mount could expose a path the policy denies. The lowering
  that generates the mount list is the one bubblewrap already uses on Linux
  (`sandbox::bwrap`), and the differential executing tests (#170) prove the
  layers agree. A placeholder for a denied read is a plain file on the host
  with mode `0`, exactly as under bubblewrap.
- **Proxy relay bugs.** The vsock bridge is a trivial `io::copy` in both
  directions, as the Unix-socket bridge is on Linux. It carries no decisions;
  the proxy outside the guest still enforces hosts, methods and the
  cloud-metadata deny.
- **Audit log while the host cannot see inside the guest.** The proxy sits
  outside the guest and records every connection, as on Linux. Filesystem
  reads and writes inside the guest are not recorded by the host; the
  Isolated-tier's claim is that nothing *outside* the agreed mounts is
  reachable, not that every file touch is logged. docs/THREAT_MODEL.md states
  this.
- **Fail-closed.** If the VM cannot boot (kernel digest mismatch, `container`
  missing, `container` returns non-zero, vsock relay fails to bind), `moat
  run --isolate` exits 64 and never starts the agent. Never a silent fallback
  to Lightweight, and never a looser mount.

## Consequences

- The Isolated tier reaches macOS 26.0+. Older macOS stays on Standard
  (host-sandbox + hook) or Lightweight (generated Seatbelt).
- Owner accepts one new user-side dependency (`container`), one new minimum
  macOS version, and a slower cold start than Linux (~0.8 s versus ~0.1 s).
- The threat model gains one row: "VM escape in Virtualization.framework",
  listed as residual risk shared with every other VM-based sandbox on macOS.
- Follow-up PRs implement the Rust FFI, the virtiofs mount lowering (reusing
  `sandbox::bwrap`), the vsock relay, the `moat doctor` pin, and
  docs/EVIDENCE.md's macOS Isolated column; each is its own PR under #175.

## First implementable milestone

This PR ships only the ADR and a scoped stub so no one is surprised by
half-work:

- `moat run --isolate` on macOS checks whether `container` is on `PATH`.
  - Missing: prints the install hint and exits 64.
  - Present: prints "not yet implemented, see ADR-023" and exits 64.
- No VM is booted, no agent runs. The Lightweight tier (`moat run` without
  `--isolate`) is unchanged. The Linux Isolated tier is unchanged.

The next milestone (its own PR under #175) is the virtiofs mount lowering:
reuse `sandbox::bwrap`'s mount list, point it at the `container` runtime
spec, and prove the executing differential fixtures still agree.
