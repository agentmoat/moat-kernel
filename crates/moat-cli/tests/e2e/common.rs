//! The harness every end-to-end module shares: an isolated home and the real
//! `moat` binary.
//!
//! Each command runs with the environment cleared except `PATH`, `HOME`,
//! `USERPROFILE` and (Windows) `SYSTEMROOT`, so nothing from the developer's machine (a real `~/.moat`,
//! `CLAUDE_CONFIG_DIR`, a terminal) leaks into a test.

use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

/// A throwaway home directory.
pub struct Sandbox {
    _dir: TempDir,
    pub home: PathBuf,
}

impl Sandbox {
    /// A home containing the given host configuration directories
    /// (`.claude`, `.codex`, `.cursor`); nothing is installed.
    pub fn bare(host_dirs: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        for host_dir in host_dirs {
            std::fs::create_dir_all(home.join(host_dir)).unwrap();
        }
        Self { _dir: dir, home }
    }

    /// `bare(host_dirs)` followed by a successful `moat init`.
    pub fn installed(host_dirs: &[&str]) -> Self {
        let sb = Self::bare(host_dirs);
        let out = sb.moat(&["init"]);
        assert_eq!(out.status.code(), Some(0), "moat init: {}", text(&out));
        sb
    }

    /// A git project inside the home, created on first use.
    pub fn project(&self) -> PathBuf {
        let project = self.home.join("proj");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        project
    }

    /// The command with the isolated environment; callers add arguments.
    pub fn command(&self) -> Command {
        self.command_at(Path::new(env!("CARGO_BIN_EXE_moat")))
    }

    /// [`Sandbox::command`] running the binary at `program` (a copy or a link).
    pub fn command_at(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home);
        // Windows sockets cannot start without it (`moat proxy` binds one).
        if let Some(root) = std::env::var_os("SYSTEMROOT") {
            cmd.env("SYSTEMROOT", root);
        }
        cmd
    }

    /// Run `moat` with no input.
    pub fn moat(&self, args: &[&str]) -> Output {
        output(self.command().args(args), None)
    }

    /// Run `moat` with `stdin` as its input (a hook payload).
    pub fn moat_stdin(&self, args: &[&str], stdin: &str) -> Output {
        output(self.command().args(args), Some(stdin))
    }

    /// Run `moat` as a person at a terminal would (`MOAT_ASSUME_TTY`, honoured
    /// by debug builds only).
    pub fn moat_as_person(&self, args: &[&str]) -> Output {
        output(self.command().args(args).env("MOAT_ASSUME_TTY", "1"), None)
    }

    /// Run the hook for `host` with `payload`.
    pub fn guard(&self, host: &str, payload: &str) -> Output {
        self.moat_stdin(&["guard", "--host", host], payload)
    }
}

/// Run a prepared command (see [`Sandbox::command`]) with optional input.
pub fn output(cmd: &mut Command, stdin: Option<&str>) -> Output {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A binary a test has just copied can be busy for a moment on Linux: a
    // process forked by another test holds the copy's write handle until it
    // execs. Retry instead of failing on that race.
    let mut tries = 0;
    let mut child = loop {
        match cmd.spawn() {
            Err(e) if e.kind() == ErrorKind::ExecutableFileBusy && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            spawned => break spawned.expect("spawning moat"),
        }
    };
    let mut pipe = child.stdin.take().expect("stdin is piped");
    if let Some(input) = stdin {
        // A command may exit before reading its input (`guard` refusing its own
        // arguments); its exit status is what the test checks, not this write.
        if let Err(error) = pipe.write_all(input.as_bytes()) {
            assert_eq!(
                error.kind(),
                ErrorKind::BrokenPipe,
                "writing stdin: {error}"
            );
        }
    }
    drop(pipe);
    child.wait_with_output().unwrap()
}

/// A golden payload under `tests/fixtures/hosts/`, e.g. `cursor/beforeReadFile.json`.
pub fn fixture(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hosts")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Standard output as text.
pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Standard error as text.
pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Standard output followed by standard error, for assertion messages.
pub fn text(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

/// Standard output parsed as one JSON document (`Null` when it is not JSON).
pub fn json(out: &Output) -> Value {
    serde_json::from_str(stdout(out).trim()).unwrap_or(Value::Null)
}

/// `hookSpecificOutput` of a Claude Code or Codex hook response.
pub fn hook_output(out: &Output) -> Value {
    json(out)["hookSpecificOutput"].clone()
}

/// A Claude Code `PreToolUse` payload for one Bash command.
pub fn bash_payload(session: &str, cwd: &Path, command: &str) -> String {
    serde_json::json!({
        "session_id": session, "cwd": cwd.to_string_lossy(), "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "t1"
    })
    .to_string()
}
