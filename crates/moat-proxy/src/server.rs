//! Accepting connections and deciding each one.
//!
//! Order per connection: read the head → decide the host → resolve and check
//! the addresses → connect → (CONNECT) answer 200, read the `ClientHello` and
//! check its SNI → record → relay. Nothing reaches the destination before the
//! record is written; a failed record closes the connection.

use std::io::{self, ErrorKind, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use moat_core::{CompiledPolicy, Decision, Verdict};

use crate::audit::{Connection, Recorder};
use crate::decide::{self, RULE_AUDIT, RULE_REQUEST, RULE_SNI};
use crate::request::{self, Request, Target};
use crate::sni::{self, Hello};
use crate::tunnel;
use crate::upstream::{self, Refusal, Resolve};

/// Bounds on what one client can make the proxy hold.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest request head, in bytes.
    pub max_head_bytes: usize,
    /// Time allowed for the request head, and for the `ClientHello` after it.
    pub handshake_timeout: Duration,
    /// A relayed connection with no bytes either way for this long is closed.
    pub idle_timeout: Duration,
    /// Time allowed to connect to the destination.
    pub connect_timeout: Duration,
    /// Connections served at once; more are answered 503 and closed.
    pub max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_bytes: 16 * 1024,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(2),
            connect_timeout: Duration::from_secs(10),
            max_connections: 256,
        }
    }
}

/// The proxy: a policy, a resolver, an audit sink and limits.
#[derive(Clone, Copy)]
pub struct Proxy<'a> {
    /// The policy hosts are decided by.
    pub policy: &'a CompiledPolicy<'a>,
    /// Name resolution.
    pub resolver: &'a dyn Resolve,
    /// Where every decision is recorded.
    pub recorder: &'a dyn Recorder,
    /// Resource limits.
    pub limits: &'a Limits,
    /// Loopback addresses the proxy may connect to despite the loopback ban.
    /// Empty in `moat proxy`; integration tests list their local server.
    pub loopback_ok: &'a [SocketAddr],
}

impl std::fmt::Debug for Proxy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("limits", &self.limits)
            .field("loopback_ok", &self.loopback_ok)
            .finish_non_exhaustive()
    }
}

impl Proxy<'_> {
    /// Serve connections from `listener` until accepting fails.
    pub fn serve(&self, listener: &TcpListener) -> io::Result<()> {
        let active = AtomicUsize::new(0);
        thread::scope(|scope| {
            loop {
                let client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(e) if is_transient(&e) => continue,
                    Err(e) => return Err(e),
                };
                let _ = client.set_write_timeout(Some(self.limits.handshake_timeout));
                let slot = Slot::take(&active, self.limits.max_connections);
                let Some(slot) = slot else {
                    respond(&client, 503, "too many connections");
                    continue;
                };
                // A thread that cannot start drops (closes) this connection;
                // `scope.spawn` would panic and take the proxy down instead.
                let _ = thread::Builder::new().spawn_scoped(scope, move || {
                    let _slot = slot;
                    self.handle(&client);
                });
            }
        })
    }

    fn handle(&self, client: &TcpStream) {
        let started = Instant::now();
        let timeout = Some(self.limits.handshake_timeout);
        if client.set_read_timeout(timeout).is_err() || client.set_write_timeout(timeout).is_err() {
            return;
        }
        let mut buf = Vec::new();
        let deadline = started + self.limits.handshake_timeout;
        let request = match read_head(client, &mut buf, self.limits.max_head_bytes, deadline) {
            Ok(request) => request,
            Err(why) => {
                let decision = Decision::single(Verdict::Deny, RULE_REQUEST, why);
                self.record(None, &decision, started);
                respond(client, 400, &decision.reasons[0]);
                return;
            }
        };
        let rest = buf.split_off(request.head_len);
        let decision = decide::host(self.policy, request.host());
        if decision.verdict != Verdict::Allow {
            self.record(Some(&request), &decision, started);
            respond(client, 403, &summary(&decision));
            return;
        }
        let upstream = match upstream::connect(
            self.resolver,
            request.host(),
            request.port(),
            self.loopback_ok,
            self.limits.connect_timeout,
        ) {
            Ok(upstream) => upstream,
            Err(refusal) => {
                let decision = refusal.decision(request.host());
                self.record(Some(&request), &decision, started);
                let status = if matches!(refusal, Refusal::Address(..)) {
                    403
                } else {
                    502
                };
                respond(client, status, &summary(&decision));
                return;
            }
        };
        let first_bytes = match &request.target {
            Target::Connect { host, .. } => {
                match self.check_tunnel(client, host, rest, &decision, &request, started) {
                    Some(hello) => hello,
                    None => return,
                }
            }
            Target::Http { head, .. } => {
                if !self.record(Some(&request), &decision, started) {
                    respond(client, 403, "audit log unavailable");
                    return;
                }
                [head.as_slice(), &rest].concat()
            }
        };
        if (&upstream).write_all(&first_bytes).is_ok() {
            tunnel::relay(client, &upstream, self.limits.idle_timeout);
        }
    }

    /// Answer the CONNECT, then hold the tunnel's first bytes until its SNI
    /// is known to name the CONNECT host. Returns the bytes to forward.
    fn check_tunnel(
        &self,
        client: &TcpStream,
        host: &str,
        mut hello: Vec<u8>,
        allowed: &Decision,
        request: &Request,
        started: Instant,
    ) -> Option<Vec<u8>> {
        if (&*client)
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return None;
        }
        let deadline = Instant::now() + self.limits.handshake_timeout;
        let refusal = match read_hello(client, &mut hello, deadline) {
            Ok(Some(name)) if name == host => None,
            Ok(Some(name)) => Some(format!(
                "TLS server name {name} does not match CONNECT {host}"
            )),
            // An IP literal is never sent as SNI (RFC 6066 §3).
            Ok(None) if host.parse::<std::net::IpAddr>().is_ok() => None,
            Ok(None) => Some(format!(
                "TLS ClientHello for CONNECT {host} has no server name"
            )),
            Err(why) => Some(why),
        };
        if let Some(why) = refusal {
            let decision = Decision::single(Verdict::Deny, RULE_SNI, why);
            self.record(Some(request), &decision, started);
            return None;
        }
        self.record(Some(request), allowed, started)
            .then_some(hello)
    }

    /// Record a decision; `false` when it could not be recorded, which the
    /// caller must treat as a deny.
    fn record(&self, request: Option<&Request>, decision: &Decision, started: Instant) -> bool {
        let connection = Connection {
            method: request.map(|r| r.method.as_str()),
            destination: request.map(|r| (r.host(), r.port())),
            decision,
            latency_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        match self.recorder.record(&connection) {
            Ok(()) => true,
            Err(error) => {
                // The caller refuses the connection; the failure itself can
                // only go to stderr, since the audit log is what failed.
                eprintln!("moat proxy: {RULE_AUDIT}: {error}");
                false
            }
        }
    }
}

/// One of the `max_connections` slots, released when dropped, even if the
/// connection's thread panics.
struct Slot<'a>(&'a AtomicUsize);

impl<'a> Slot<'a> {
    fn take(active: &'a AtomicUsize, max: usize) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(active))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Read until a complete request head is in `buf`.
fn read_head(
    client: &TcpStream,
    buf: &mut Vec<u8>,
    max: usize,
    deadline: Instant,
) -> Result<Request, String> {
    loop {
        match request::parse(buf) {
            Ok(Some(request)) => return Ok(request),
            Ok(None) if buf.len() >= max => {
                return Err(format!("request head larger than {max} bytes"));
            }
            Ok(None) => read_more(client, buf, max, deadline)?,
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Read until `buf` holds a complete `ClientHello`; its SNI, if any.
fn read_hello(
    client: &TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Result<Option<String>, String> {
    // Records add 5 bytes per 16 KiB of handshake, so this covers MAX_HELLO.
    let max = sni::MAX_HELLO + 1024;
    loop {
        match sni::server_name(buf) {
            Ok(Hello::ServerName(name)) => return Ok(name),
            Ok(Hello::Incomplete) if buf.len() >= max => {
                return Err(sni::HelloError::TooLarge.to_string());
            }
            Ok(Hello::Incomplete) => read_more(client, buf, max, deadline)?,
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// One read, bounded by `deadline` for the whole head or `ClientHello`, so a
/// client trickling one byte at a time cannot hold its slot indefinitely.
fn read_more(
    client: &TcpStream,
    buf: &mut Vec<u8>,
    max: usize,
    deadline: Instant,
) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() || client.set_read_timeout(Some(left)).is_err() {
        return Err("the client did not finish its handshake in time".to_owned());
    }
    let mut chunk = [0u8; 4096];
    let want = chunk.len().min(max.saturating_sub(buf.len())).max(1);
    match (&*client).read(&mut chunk[..want]) {
        Ok(0) => Err("client closed the connection early".to_owned()),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::Interrupted => Ok(()),
        Err(e) => Err(format!("reading from the client: {e}")),
    }
}

fn summary(decision: &Decision) -> String {
    format!(
        "{} ({})",
        decision.reasons.join("; "),
        decision.rules.join(", ")
    )
}

fn respond(client: &TcpStream, status: u16, message: &str) {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        _ => "Service Unavailable",
    };
    let body = format!("moat proxy: {message}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = (&*client).write_all(response.as_bytes());
}

fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::Interrupted | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    )
}
