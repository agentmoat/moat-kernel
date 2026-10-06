//! Which hosts and addresses the proxy may reach.
//!
//! A host is decided exactly as `moat guard` decides a fetch tool's URL: one
//! `fetch` atom through moat-core's [`CompiledPolicy`], so `fetch` and `net`
//! lists both apply and deny rules come first. The proxy cannot prompt, so an
//! `ask` is refused. Cloud metadata and link-local addresses are refused
//! whatever the policy says, by name and again after DNS resolution.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use moat_core::{AtomicAction, CompiledPolicy, Decision, Verdict};

/// Rule id for a destination refused whatever the policy says.
pub const RULE_ADDRESS: &str = "proxy-address";
/// Rule id for a tunnel whose TLS SNI is missing or names another host.
pub const RULE_SNI: &str = "proxy-sni";
/// Rule id for a request the proxy could not parse or does not serve.
pub const RULE_REQUEST: &str = "proxy-request";
/// Rule id for a destination that could not be resolved or reached.
pub const RULE_UPSTREAM: &str = "proxy-upstream";
/// Rule id for a connection refused because it could not be recorded.
pub const RULE_AUDIT: &str = "proxy-audit";

/// Metadata services reachable by name on cloud instances.
const METADATA_NAMES: &[&str] = &["metadata.google.internal", "metadata.goog"];
const ALIBABA_METADATA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);
const AWS_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
/// RFC 6052 well-known NAT64 prefix: `64:ff9b::a.b.c.d` reaches `a.b.c.d`.
const NAT64: [u16; 6] = [0x64, 0xff9b, 0, 0, 0, 0];

/// Decide whether `host`, normalised as [`Request::host`](crate::Request::host)
/// reports it, may be reached. Only an `allow` lets the connection proceed.
#[must_use]
pub fn host(policy: &CompiledPolicy<'_>, host: &str) -> Decision {
    if METADATA_NAMES
        .iter()
        .any(|m| host == *m || host.strip_suffix(m).is_some_and(|p| p.ends_with('.')))
    {
        return Decision::single(
            Verdict::Deny,
            RULE_ADDRESS,
            format!("{host} is a cloud metadata service"),
        );
    }
    let atom = AtomicAction::Fetch {
        host: host.to_owned(),
    };
    let mut decision = policy.evaluate_atomic(&atom).unwrap_or_else(|| {
        Decision::single(
            Verdict::Deny,
            RULE_REQUEST,
            format!("no rule decided {host}"),
        )
    });
    if decision.verdict == Verdict::Ask {
        decision.verdict = Verdict::Deny;
        decision
            .reasons
            .push("the proxy cannot ask, so a host that would ask is refused".to_owned());
    }
    decision
}

/// Why the proxy never connects to `ip`, if it does not. Checked on every
/// resolved address, so a name the policy allows cannot be pointed at a local
/// or metadata service (DNS rebinding).
#[must_use]
pub fn forbidden(ip: IpAddr) -> Option<Forbidden> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

/// The classes of address the proxy refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forbidden {
    /// This machine (`127.0.0.0/8`, `::1`), including the proxy itself.
    Loopback,
    /// Link-local (`169.254.0.0/16`, `fe80::/10`): where cloud metadata lives.
    LinkLocal,
    /// A cloud metadata address outside the link-local ranges.
    Metadata,
    /// Unspecified, broadcast, multicast or `0.0.0.0/8`: never a server.
    NotUnicast,
}

impl Forbidden {
    /// A short phrase for reasons and the audit log.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Loopback => "a loopback address",
            Self::LinkLocal => "a link-local address",
            Self::Metadata => "a cloud metadata address",
            Self::NotUnicast => "not a unicast address",
        }
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<Forbidden> {
    if ip.is_loopback() {
        Some(Forbidden::Loopback)
    } else if ip.is_link_local() {
        Some(Forbidden::LinkLocal)
    } else if ip == ALIBABA_METADATA {
        Some(Forbidden::Metadata)
    } else if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.octets()[0] == 0 {
        Some(Forbidden::NotUnicast)
    } else {
        None
    }
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<Forbidden> {
    let seg = ip.segments();
    if ip.is_loopback() {
        Some(Forbidden::Loopback)
    } else if ip.is_unspecified() || ip.is_multicast() {
        Some(Forbidden::NotUnicast)
    } else if seg[0] & 0xffc0 == 0xfe80 {
        Some(Forbidden::LinkLocal)
    } else if ip == AWS_METADATA_V6 {
        Some(Forbidden::Metadata)
    } else if seg[..6] == NAT64 || seg[..6] == [0; 6] {
        // NAT64 and the deprecated IPv4-compatible form carry an IPv4 address.
        let [a, b] = seg[6].to_be_bytes();
        let [c, d] = seg[7].to_be_bytes();
        forbidden_v4(Ipv4Addr::new(a, b, c, d))
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
