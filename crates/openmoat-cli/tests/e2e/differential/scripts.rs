//! Hostile project scripts against the OS layer (#335). The hook allows `npm
//! test` and cannot see the project's scripts, so whatever stops a payload in
//! them is the operating system. Each `scripts` entry of
//! `tests/differential/scenarios.yaml` becomes the evil project's test script
//! and runs as `npm test` under `moat run` (Seatbelt on macOS, Landlock and
//! seccomp on Linux); the test asserts what the OS did to it (EPERM, EACCES,
//! the proxy's 403) and the side effects, and `docs/EVIDENCE.md` is the table
//! generated from the same list.

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use super::{Gap, scenarios, suite};

/// What the operating system did to a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// A call failed with `EPERM` ("Operation not permitted").
    Eperm,
    /// A call failed with `EACCES` ("Permission denied").
    Eacces,
    /// OpenMoat's proxy answered the request with 403.
    #[serde(rename = "proxy-403")]
    Proxy403,
    /// The payload completed.
    Ran,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Eperm => "EPERM",
            Self::Eacces => "EACCES",
            Self::Proxy403 => "proxy 403",
            Self::Ran => "ran",
        }
    }
}

/// One hostile (or, for the control, ordinary) project test script.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Script {
    pub id: String,
    /// `T1…T12` for attacks; absent for the control.
    #[serde(default)]
    pub threat: Option<String>,
    pub why: String,
    /// The script body; `{tcp}` and `{udp}` name the test's loopback listeners.
    pub payload: String,
    /// The outcome under `moat run` on macOS.
    pub seatbelt: Outcome,
    /// The outcome under `moat run` on Linux.
    pub landlock: Outcome,
    #[serde(default)]
    pub gap: Option<Gap>,
}

/// The executing layers: id (as `gap.layer` names it) and the column heading.
const LAYERS: [(&str, &str); 2] = [
    ("seatbelt", "`moat run`, macOS (Seatbelt)"),
    ("landlock", "`moat run`, Linux (Landlock + seccomp)"),
];

impl Script {
    fn expected(&self, layer: &str) -> Outcome {
        if layer == "seatbelt" {
            self.seatbelt
        } else {
            self.landlock
        }
    }

    fn gap_at(&self, layer: &str) -> Option<&Gap> {
        self.gap.as_ref().filter(|g| g.layer == layer)
    }
}

pub fn scripts() -> Vec<Script> {
    suite().scripts
}

#[test]
fn script_list_is_well_formed() {
    let mut ids: std::collections::BTreeSet<String> =
        scenarios().into_iter().map(|s| s.id).collect();
    for s in scripts() {
        assert!(ids.insert(s.id.clone()), "duplicate id {}", s.id);
        assert!(!s.why.trim().is_empty(), "{}: empty why", s.id);
        if let Some(gap) = &s.gap {
            assert!(LAYERS.iter().any(|(id, _)| *id == gap.layer), "{}", s.id);
            assert!(gap.issue > 0 && !gap.why.trim().is_empty(), "{}", s.id);
        }
        for (layer, _) in LAYERS {
            let ran = s.expected(layer) == Outcome::Ran;
            match &s.threat {
                // An attack the layer lets through is a known gap, never silent.
                Some(_) => assert!(!ran || s.gap_at(layer).is_some(), "{}: {layer}", s.id),
                None => assert!(ran, "{}: the control must run at {layer}", s.id),
            }
        }
    }
}

/// `docs/EVIDENCE.md` is the table generated from the script list. Regenerate
/// with `MOAT_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`.
#[test]
fn evidence_table_is_current() {
    let mut doc = String::from(
        "# OS enforcement evidence\n\n\
         Generated from the `scripts` list in `tests/differential/scenarios.yaml` by the\n\
         differential suite; do not edit. Regenerate with\n\
         `MOAT_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`.\n\n\
         The hook allows project scripts (`npm test`, `make test`) and cannot see what they\n\
         do ([THREAT_MODEL.md](THREAT_MODEL.md) §5). Each row is such a script: the payload is\n\
         the project's test script, started as `npm test` under `moat run`, in a throwaway home\n\
         with fake secrets. A cell is what the operating system did to the payload. CI asserts\n\
         it on every pull request, together with its side effects (no secret printed, no file\n\
         written, nothing reached the listener), and fails when it changes. Network targets are\n\
         loopback listeners the test owns.\n\n",
    );
    doc.push_str("| Case | Threat | Payload |");
    for (_, heading) in LAYERS {
        let _ = write!(doc, " {heading} |");
    }
    doc.push_str("\n|---|---|---|---|---|\n");
    let mut gaps = String::new();
    for s in scripts() {
        let threat = s.threat.as_deref().unwrap_or("control");
        let payload = s.payload.replace('|', "\\|");
        let _ = write!(doc, "| `{}` | {threat} | `{payload}` |", s.id);
        for (layer, heading) in LAYERS {
            let outcome = s.expected(layer).label();
            match s.gap_at(layer) {
                Some(gap) => {
                    let _ = write!(doc, " **gap**: {outcome} (#{}) |", gap.issue);
                    let _ = writeln!(
                        gaps,
                        "- `{}` under {heading} (#{}): {}",
                        s.id, gap.issue, gap.why
                    );
                }
                None => {
                    let _ = write!(doc, " {outcome} |");
                }
            }
        }
        doc.push('\n');
    }
    doc.push_str(
        "\nEPERM and EACCES: the system call failed with that error. proxy 403: OpenMoat's \
         proxy\nrefused the request. ran: the payload completed.\n\n## Known gaps\n\n",
    );
    doc.push_str(&gaps);
    doc.push_str(
        "\n## Layers\n\n| Layer | Status |\n|---|---|\n\
         | `moat run`, macOS (Seatbelt) | verified by the `macos-14` and `macos-15-intel` CI jobs |\n\
         | `moat run`, Linux (Landlock + seccomp) | verified by the `ubuntu-latest` CI job (Linux 6.7 or later) |\n\
         | `moat run`, Windows | not run: `moat run` refuses on Windows, where OpenMoat generates no OS sandbox (#135) |\n\
         | Codex profile (`codex sandbox -P moat`) | not verified headlessly in CI, which has no `codex` binary; `scripts/ci/differential.sh` runs the command-level scenarios (`npm-test-reads-ssh` among them) under it where one is installed |\n\
         | Claude Code sandbox settings | not verified headlessly in CI, which has no `claude` binary; `scripts/ci/differential.sh` runs the command-level attacks under it where one is installed, and headless `claude -p` cannot verify benign project work (#238) |\n",
    );
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/EVIDENCE.md");
    if std::env::var_os("MOAT_UPDATE_EVIDENCE").is_some() {
        std::fs::write(&path, &doc).unwrap();
    }
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        current.replace("\r\n", "\n") == doc,
        "docs/EVIDENCE.md is out of date; run \
         `MOAT_UPDATE_EVIDENCE=1 cargo test -p openmoat --test e2e differential`"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod executing {
    use std::fmt::Write as _;
    use std::io::ErrorKind;
    use std::net::{TcpListener, UdpSocket};
    use std::path::Path;
    use std::process::Output;

    use super::super::{Fixtures, Project, Verdict};
    use super::{Outcome, scripts};
    use crate::common::{output, text};
    use crate::run::confined::ran;

    #[cfg(target_os = "macos")]
    const LAYER: &str = "seatbelt";
    #[cfg(target_os = "linux")]
    const LAYER: &str = "landlock";

    /// What the agent runs; the project's `bin/npm` shim starts its test script.
    const NPM_TEST: &str = "npm test --silent";

    /// The fake secrets' contents: printed only where a read went through.
    const SECRETS: [&str; 3] = ["FAKE-PRIVATE-KEY", "key=FAKE", "TOKEN=secret"];

    impl Fixtures {
        /// `payload` as the evil project's test script, run as `npm test` under
        /// `moat run`, with the temp directory outside the home so that a home
        /// write is not a temp-directory write.
        fn run_script(&self, payload: &str) -> Output {
            let project = self.tree(Project::Evil);
            std::fs::write(project.join(".build.sh"), format!("{payload}\n")).unwrap();
            let tmp = self.sb.home.with_file_name("tmp");
            std::fs::create_dir_all(&tmp).unwrap();
            output(
                self.sb
                    .command()
                    .current_dir(project)
                    .env("PATH", format!("{}/bin:/usr/bin:/bin", project.display()))
                    .env("TMPDIR", &tmp)
                    .args(["run", "--", "/bin/sh", "-c", NPM_TEST]),
                None,
            )
        }
    }

    /// The outcome the payload's exit status and messages show, if any.
    fn observe(out: &Output) -> Option<Outcome> {
        let shown = text(out);
        if out.status.success() {
            Some(Outcome::Ran)
        } else if shown.contains("returned error: 403") {
            Some(Outcome::Proxy403)
        } else if shown.contains("Operation not permitted") {
            Some(Outcome::Eperm)
        } else if shown.contains("Permission denied") {
            Some(Outcome::Eacces)
        } else {
            None
        }
    }

    #[test]
    fn hostile_scripts_meet_the_os_layer() {
        // Landlock cannot deny inside a granted tree, and `/tmp` is a read root,
        // so the home lives outside it, as a real home does.
        let fx = Fixtures::build_in(Path::new(env!("CARGO_TARGET_TMPDIR")));
        let hook = fx.hook_decision("scripts", Project::Evil, NPM_TEST);
        assert_eq!(hook, Verdict::Allow, "the hook allows `npm test`");
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        tcp.set_nonblocking(true).unwrap();
        udp.set_nonblocking(true).unwrap();
        let pinned = [".moat/policy.yaml", ".claude/settings.json"]
            .map(|file| (file, std::fs::read(fx.sb.home.join(file)).unwrap()));

        let mut matrix = format!("\nhostile scripts under moat run ({LAYER}):\n");
        let mut mismatches = Vec::new();
        for s in scripts() {
            let payload = s
                .payload
                .replace("{tcp}", &tcp.local_addr().unwrap().port().to_string())
                .replace("{udp}", &udp.local_addr().unwrap().port().to_string());
            let out = fx.run_script(&payload);
            if !ran(&out) {
                return;
            }
            let got = observe(&out);
            let expected = s.expected(LAYER);
            let leaked = SECRETS.iter().any(|secret| text(&out).contains(secret));
            let label = got.map_or("unexpected", Outcome::label);
            let _ = writeln!(matrix, "  {:<30} {label}", s.id);
            if got != Some(expected) || (leaked && got != Some(Outcome::Ran)) {
                mismatches.push(format!(
                    "{}: {label} (leaked: {leaked}) but scenarios.yaml expects {}:\n{}",
                    s.id,
                    expected.label(),
                    text(&out)
                ));
            }
        }
        eprintln!("{matrix}");
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        // What the refused calls would have done did not happen.
        assert!(!fx.sb.home.join("outside.txt").exists());
        for (file, before) in pinned {
            let after = std::fs::read(fx.sb.home.join(file)).unwrap();
            assert!(after == before, "{file} changed");
        }
        let accepted = tcp.accept().map(drop).map_err(|e| e.kind());
        assert_eq!(
            accepted,
            Err(ErrorKind::WouldBlock),
            "a TCP connection arrived"
        );
        let received = udp.recv(&mut [0; 16]).map(drop).map_err(|e| e.kind());
        assert_eq!(received, Err(ErrorKind::WouldBlock), "a datagram arrived");
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn hostile_scripts_are_not_run_without_an_os_layer() {
    eprintln!(
        "skipped: hostile scripts — `moat run` refuses on {}, where OpenMoat generates no OS \
         sandbox (#135); run.rs checks that it refuses",
        std::env::consts::OS
    );
}
