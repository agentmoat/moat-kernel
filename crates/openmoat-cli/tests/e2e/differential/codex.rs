//! The Codex host-sandbox layer of the differential suite (#170): each scenario
//! runs under `codex sandbox -P moat`, the Seatbelt (macOS) or Landlock (Linux)
//! profile Codex derives from the `[permissions.moat]` profile `moat init`
//! generates, with `moat proxy` running as Codex's upstream. The binary is
//! `MOAT_CODEX_BIN`, else `codex` on `PATH`; without one the layer prints a
//! visible skip and the suite passes on the other layers.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use super::{Fixtures, Scenario, Verdict, scenarios};

/// The codex binary, or `None` to skip the layer.
fn binary() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("MOAT_CODEX_BIN").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(explicit));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("codex"))
        .find(|p| p.is_file())
}

impl Fixtures {
    /// Run `scenario` under `codex sandbox -P moat`: `Allow` if the command (and
    /// every step of it, `set -eo pipefail`) completed, `Deny` if the sandbox
    /// stopped it. The project's own `bin/` holds the `npm`/`cargo` shims.
    /// Codex runs with `HTTP(S)_PROXY` naming `moat proxy` on `proxy_port`, so its
    /// own proxy hands what it allows on to OpenMoat's.
    fn codex_verdict(
        &self,
        codex: &std::path::Path,
        proxy_port: u16,
        scenario: &Scenario,
    ) -> Verdict {
        let project = self.tree(scenario.project);
        let path = format!("{}/bin:/usr/bin:/bin", project.display());
        // bash (not dash) for `pipefail`, so a blocked `curl … | sh` is a Deny
        // rather than the trailing shell's exit 0.
        let script = format!("set -eo pipefail; {}", scenario.command);
        let proxy = format!("http://127.0.0.1:{proxy_port}");
        let out = Command::new(codex)
            .args(["sandbox", "-P", "moat", "-C"])
            .arg(project)
            .args(["--", "/bin/bash", "-c", &script])
            .env_clear()
            .env("PATH", path)
            .env("HOME", &self.sb.home)
            .env("CODEX_HOME", self.sb.home.join(".codex"))
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .output()
            .expect("running codex sandbox");
        if out.status.success() {
            Verdict::Allow
        } else {
            Verdict::Deny
        }
    }
}

#[test]
fn codex_layer_agrees_with_every_scenario() {
    let Some(codex) = binary() else {
        eprintln!(
            "skipped: codex layer (set MOAT_CODEX_BIN) — the hook layer still ran; \
             scripts/ci/differential.sh runs every layer"
        );
        return;
    };
    let fx = Fixtures::build();
    let port = fx.sb.use_free_proxy_port();
    let _proxy = fx.sb.start_proxy();
    let mut matrix = String::from("\ndifferential matrix (codex sandbox):\n");
    let mut mismatches = Vec::new();
    for s in &scenarios() {
        let got = fx.codex_verdict(&codex, port, s);
        if let Some(gap) = s.gap_at("codex") {
            let _ = writeln!(
                matrix,
                "  {:<30} codex={} GAP(#{}: {})",
                s.id,
                got.symbol(),
                gap.issue,
                gap.why
            );
            continue;
        }
        let _ = writeln!(matrix, "  {:<30} codex={}", s.id, got.symbol());
        if got != s.codex {
            mismatches.push(format!(
                "{}: codex {} but scenarios.yaml expects {} ({})",
                s.id,
                got.symbol().trim(),
                s.codex.symbol().trim(),
                s.why
            ));
        }
    }
    eprintln!("{matrix}");
    assert!(
        mismatches.is_empty(),
        "codex disagreements:\n{}",
        mismatches.join("\n")
    );
}
