//! `moat proxy [--listen 127.0.0.1:<port>]`: the default-deny egress proxy
//! (ADR-020, `moat-proxy`).
//!
//! Starts only from an intact installation: the policy lock must match, so a
//! tampered policy is never compiled into a long-running proxy. The policy is
//! read once; restart the proxy after changing it. Every brokered secret
//! (`secrets:`) is read at start-up; one that cannot be read stops it. `moat run`
//! serves the same proxy, secrets included, from a thread of its own.

use std::io::Write as _;
use std::net::TcpListener;
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use moat_audit::{NewEvent, Store};
use moat_core::{Action, CompiledPolicy, EvalContext, Policy, Secret};
use moat_proxy::{Broker, Connection, Limits, Proxy, RecordError, Recorder, SystemResolver};

use crate::cli::ProxyArgs;
use crate::context;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity;
use crate::secrets;

pub fn run(args: &ProxyArgs) -> Result<Code> {
    if !args.listen.ip().is_loopback() {
        bail!(
            "--listen {} is not a loopback address; the proxy would serve other machines",
            args.listen
        );
    }
    let home = installed()?;
    let exit = Exit::open(
        &home,
        home.load_policy()?,
        context::eval_context(None, None)?,
    )?;
    let listener =
        TcpListener::bind(args.listen).with_context(|| format!("listening on {}", args.listen))?;
    let addr = listener
        .local_addr()
        .context("reading the listening address")?;
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "moat proxy: listening on {addr} (audit session {})",
        exit.session()
    )?;
    // Only what the agent may know: the id, host, header and placeholder.
    for s in exit.secrets() {
        writeln!(
            stdout,
            "moat proxy: secret `{}` goes to {} in {}; give the agent {}",
            s.id,
            s.host,
            s.header,
            s.placeholder()
        )?;
    }
    stdout.flush()?;
    drop(stdout);
    exit.serve(&listener)?;
    Ok(Code::Ok)
}

/// The installation, refused when it is missing or its policy lock shows
/// drift, so a tampered policy is never compiled into a sandbox or a proxy.
pub(super) fn installed() -> Result<Home> {
    let home = Home::locate()?;
    if !home.exists() {
        bail!("{} does not exist; run `moat init`", home.root().display());
    }
    if let Some(drift) = integrity::violation(&home)? {
        bail!("policy lock drift: {}", drift.reasons.join("; "));
    }
    Ok(home)
}

/// What one proxy serves with: the policy, the brokered secrets and the audit
/// log. It owns them, so `moat run` can serve from another thread.
pub(super) struct Exit {
    policy: Policy,
    ctx: EvalContext,
    broker: Broker,
    recorder: AuditLog,
}

impl Exit {
    /// Fails when the policy does not compile, a secret's source cannot be read,
    /// or the audit log cannot be opened.
    pub(super) fn open(home: &Home, policy: Policy, ctx: EvalContext) -> Result<Self> {
        CompiledPolicy::compile(&policy, &ctx)?;
        let broker = secrets::broker(&policy.secrets, &ctx.home)?;
        let audit_path = home.audit_path();
        let store = Store::open_existing(&audit_path)
            .with_context(|| format!("opening {}", audit_path.display()))?;
        Ok(Self {
            policy,
            ctx,
            broker,
            recorder: AuditLog {
                store: Mutex::new(store),
                session: format!("proxy-{}", crate::time::now_ms()),
            },
        })
    }

    /// The audit session the proxy records under.
    pub(super) fn session(&self) -> &str {
        &self.recorder.session
    }

    /// The policy's brokered secrets: ids, hosts, headers and placeholders only;
    /// their values stay in the broker.
    pub(super) fn secrets(&self) -> &[Secret] {
        &self.policy.secrets
    }

    /// Serve `listener` until accepting fails.
    pub(super) fn serve(&self, listener: &TcpListener) -> Result<()> {
        let compiled = CompiledPolicy::compile(&self.policy, &self.ctx)?;
        let proxy = Proxy {
            policy: &compiled,
            resolver: &SystemResolver,
            recorder: &self.recorder,
            limits: &Limits::default(),
            loopback_ok: &[],
            broker: &self.broker,
        };
        proxy.serve(listener).context("accepting connections")
    }
}

/// Proxy decisions in the audit log: host `proxy`, the method as the tool, and
/// a `net` action naming `connect://host:port` or `http://host:port`. Never the
/// path: it may carry secrets, and no rule looks at it yet.
struct AuditLog {
    store: Mutex<Store>,
    session: String,
}

impl Recorder for AuditLog {
    fn record(&self, c: &Connection<'_>) -> Result<(), RecordError> {
        let action = c.destination.map(|(host, port)| {
            let scheme = if c.method == Some("CONNECT") {
                "connect"
            } else {
                "http"
            };
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            Action::Net {
                url: format!("{scheme}://{host}:{port}"),
            }
        });
        let event = NewEvent {
            host: "proxy",
            session_id: &self.session,
            call_id: None,
            cwd: None,
            tool: c.method.unwrap_or("unknown"),
            action: action.as_ref(),
            decision: c.decision,
            latency_us: c.latency_us,
        };
        let store = self
            .store
            .lock()
            .map_err(|_| RecordError("audit writer poisoned by an earlier panic".to_owned()))?;
        store
            .record(&event)
            .map(drop)
            .map_err(|e| RecordError(e.to_string()))
    }
}
