//! The Claude Code host-sandbox layer of the differential suite (#170): each
//! attack runs under Claude Code's own sandbox, configured from the settings
//! `moat sandbox show` generates. The real `claude` binary runs fully isolated,
//! the way `spikes/sandbox/q4-claude.sh` does it: a temp `CLAUDE_CONFIG_DIR`
//! holding only the generated sandbox settings (no OpenMoat hook, so this measures
//! the host sandbox, not the hook), a fake `HOME`, `--bare`, a fake API key and
//! a local fake Anthropic API (`tests/differential/fake_api.py`) that drives one
//! Bash tool call. `moat proxy` runs on the port the settings name. Nothing
//! leaves the machine.
//!
//! The binary is `MOAT_CLAUDE_BIN` only (never `claude` from `PATH`) and the fake API is
//! `MOAT_FAKE_API` (else `python3`); without either the layer skips visibly.
//!
//! Scope: the layer asserts that every attack is **blocked**. Claude Code grants
//! reads and writes in the session's working directories, which it establishes
//! interactively; a headless `claude -p --bare` has none, so benign project work
//! cannot be verified here and those rows are skipped with a notice (#238). A
//! readiness check (an allowed system read) proves the sandbox discriminates
//! rather than denying everything.

use std::fmt::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use crate::common::{json, text};

use super::{Fixtures, Verdict, scenarios};

/// What bounds each `claude` run (`claude_output`).
const PERL: &str = "/usr/bin/perl";

/// The issue tracking the headless benign-verification limitation.
const BENIGN_GAP: u32 = 238;

/// `MOAT_CLAUDE_BIN` only (scripts/ci/differential.sh sets it from `PATH`): the
/// quality gate must not run whatever Claude Code a developer has installed.
fn claude_binary() -> Option<PathBuf> {
    std::env::var_os("MOAT_CLAUDE_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn python() -> Option<PathBuf> {
    which("MOAT_FAKE_API", "python3")
}

fn which(var: &str, name: &str) -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(explicit));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// Markers Claude Code's sandbox (or the tools under it) emit when it blocks a
/// command. Any one of them means the command did not complete: a `Deny`.
const BLOCKED: &[&str] = &[
    "peration not permitted",
    "sandbox_violation",
    "Failed to connect",
    "Could not resolve host",
    // Claude Code's Bash tool prefixes any non-zero exit with this; a sandbox
    // that denies a file read, a write or a connection makes the command fail.
    "Exit code ",
];

/// The fake Anthropic API, serving one Bash command, on a loopback port.
struct FakeApi {
    child: Child,
    port: u16,
}

impl FakeApi {
    fn start(python: &Path, script: &Path, command: &str) -> Self {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(python)
            .arg("-I")
            .arg(script)
            .args(["--port", &port.to_string(), "--bash", command])
            .spawn()
            .expect("starting fake api");
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpListener::bind(("127.0.0.1", port)).is_ok() {
            assert!(Instant::now() < deadline, "fake api did not bind");
            std::thread::sleep(Duration::from_millis(30));
        }
        Self { child, port }
    }
}

impl Drop for FakeApi {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Fixtures {
    /// The Claude Code sandbox settings `moat sandbox show` generates, written
    /// as `settings.json` in a fresh config dir (no hook).
    fn write_claude_settings(&self, dir: &Path) {
        let out = self.sb.moat(&["sandbox", "show", "--format", "json"]);
        let settings = json(&out)["hosts"]["claude-code"]["settings"]
            .as_str()
            .expect("claude settings")
            .to_owned();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("settings.json"), settings).unwrap();
    }

    /// Run `command` under Claude Code's sandbox and return what the tool
    /// reported: `Deny` if the sandbox blocked it, `Allow` if it completed.
    fn claude_run(
        &self,
        claude: &Path,
        python: &Path,
        script: &Path,
        id: &str,
        command: &str,
    ) -> Verdict {
        let perl = Command::new(PERL);
        let reported = text(&self.claude_output(perl, claude, python, script, id, command));
        if BLOCKED.iter().any(|m| reported.contains(m)) {
            Verdict::Deny
        } else {
            Verdict::Allow
        }
    }

    /// Run `command` in the evil project as the one Bash call of a `claude -p`
    /// session under Claude Code's sandbox; the output quotes the tool result.
    /// `perl` starts [`PERL`], which bounds the run and execs claude.
    fn claude_output(
        &self,
        mut perl: Command,
        claude: &Path,
        python: &Path,
        script: &Path,
        id: &str,
        command: &str,
    ) -> Output {
        let project = self.tree(super::Project::Evil);
        let config_dir = self.sb.home.join(format!(".cfg-{id}"));
        self.write_claude_settings(&config_dir);
        let wrapped = format!("set -eo pipefail; {command}");
        let api = FakeApi::start(python, script, &wrapped);

        // perl's alarm bounds a hung run; claude execs in its place.
        perl.args(["-e", "alarm 90; exec @ARGV"])
            .arg(claude)
            .args([
                "--bare",
                "-p",
                "run it",
                "--permission-mode",
                "default",
                "--allowedTools",
                "Bash",
            ])
            .current_dir(project)
            .env_clear()
            .env("PATH", format!("{}/bin:/usr/bin:/bin", project.display()))
            .env("HOME", &self.sb.home)
            .env("CLAUDE_CONFIG_DIR", &config_dir)
            .env("ANTHROPIC_API_KEY", "sk-ant-FAKE-moat-differential")
            .env(
                "ANTHROPIC_BASE_URL",
                format!("http://127.0.0.1:{}", api.port),
            )
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
            .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
            .output()
            .expect("running claude")
    }
}

#[test]
fn claude_layer_blocks_every_attack() {
    let (Some(claude), Some(python)) = (claude_binary(), python()) else {
        eprintln!(
            "skipped: claude layer (set MOAT_CLAUDE_BIN and MOAT_FAKE_API) — other layers ran; \
             scripts/ci/differential.sh runs every layer"
        );
        return;
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/fake_api.py");
    let fx = Fixtures::build();
    // The generated settings send sandboxed traffic to `moat proxy` on this port.
    fx.sb.use_free_proxy_port();
    let _proxy = fx.sb.start_proxy();

    // Readiness: an allowed system read must run, or the sandbox is denying
    // everything and "blocked" would be meaningless.
    let ready = fx.claude_run(&claude, &python, &script, "ready", "cat /etc/hosts");
    assert_eq!(
        ready,
        Verdict::Allow,
        "claude sandbox denied an allowed read (harness broken)"
    );

    let mut matrix = String::from("\ndifferential matrix (claude code sandbox):\n");
    let mut mismatches = Vec::new();
    for s in scenarios().iter().filter(|s| s.is_attack()) {
        let got = fx.claude_run(&claude, &python, &script, &s.id, &s.command);
        let _ = writeln!(matrix, "  {:<30} claude={}", s.id, got.symbol());
        // Every attack must be blocked; its recorded `claude` verdict is `deny`.
        if got != Verdict::Deny || s.claude != Verdict::Deny {
            mismatches.push(format!(
                "{}: claude {} (expected deny; scenarios.yaml says {})",
                s.id,
                got.symbol().trim(),
                s.claude.symbol().trim()
            ));
        }
    }
    // The unlisted host reached `moat proxy`, which refused and recorded it: the
    // sandbox sent it there, not to Claude Code's own proxy. (curl connects to
    // the metadata address directly, and the sandbox refuses that connection.)
    let shown = json(&fx.sb.moat(&["show", "--since", "all", "--format", "json"]));
    let refused: Vec<&str> = shown
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["host"] == "proxy" && row["verdict"] == "deny")
        .filter_map(|row| row["action"]["net"]["url"].as_str())
        .collect();
    if !refused.contains(&"connect://evil.example:443") {
        mismatches.push(format!(
            "evil.example did not reach moat proxy: {refused:?}"
        ));
    }
    let _ = writeln!(
        matrix,
        "  (benign rows skipped: headless claude has no working directory, #{BENIGN_GAP})"
    );
    eprintln!("{matrix}");
    assert!(
        mismatches.is_empty(),
        "claude disagreements:\n{}",
        mismatches.join("\n")
    );
}

/// The hostile project scripts (#346) under Claude Code's sandbox with the
/// settings `moat init` generates for the default policy: network through
/// Claude Code's own proxy, which allows only the policy's hosts.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn hostile_scripts_meet_the_claude_code_sandbox() {
    use super::scripts::executing::{NPM_TEST, OS, Run, fixtures, meet};
    use super::start;

    let (Some(claude), Some(python)) = (claude_binary(), python()) else {
        eprintln!("skipped: hostile scripts under claude (set MOAT_CLAUDE_BIN and MOAT_FAKE_API)");
        return;
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/fake_api.py");
    let fx = fixtures();
    meet(&format!("claude-{OS}"), &fx, |terminal| {
        let perl = start(PERL, terminal);
        let out = fx.claude_output(perl, &claude, &python, &script, "scripts", NPM_TEST);
        let shown = text(&out);
        // Claude Code's Bash tool reports a non-zero exit as "Exit code N".
        let completed = out.status.success() && !shown.contains("Exit code ");
        Some(Run { completed, shown })
    });
}
