//! `moat run` (Lightweight tier, ADR-018). On macOS the payloads really run
//! under the generated Seatbelt profile; they are `/bin/sh` scripts, never an
//! agent, in an isolated home with fake secrets.

use std::path::{Path, PathBuf};
use std::process::Output;

use crate::common::{Sandbox, output, stderr, text};

/// `moat run -- /bin/sh -c <script>` in the project, with the temp directory
/// outside the home so that writing the home is not a temp-directory write.
fn run_sh(sb: &Sandbox, project: &Path, script: &str) -> Output {
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    output(
        sb.command()
            .current_dir(project)
            .env("TMPDIR", &tmp)
            .args(["run", "--", "/bin/sh", "-c", script]),
        None,
    )
}

fn installed_with_secret() -> (Sandbox, PathBuf) {
    let sb = Sandbox::installed(&[]);
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::write(sb.home.join(".ssh/id_rsa"), "FAKE-SSH-KEY").unwrap();
    let project = sb.project();
    (sb, project)
}

#[test]
fn refuses_to_start_over_a_drifted_lock() {
    let (sb, project) = installed_with_secret();
    let policy = sb.home.join(".moat/policy.yaml");
    let edited = std::fs::read_to_string(&policy).unwrap() + "\n# edited\n";
    std::fs::write(&policy, edited).unwrap();
    let out = run_sh(&sb, &project, "echo ran");
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    assert!(stderr(&out).contains("drift"), "{}", text(&out));
    assert!(!text(&out).contains("ran\n"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn refuses_where_no_sandbox_can_be_generated() {
    let (sb, project) = installed_with_secret();
    let out = run_sh(&sb, &project, "echo ran");
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    assert!(stderr(&out).contains("needs an operating-system sandbox"));
    assert!(!text(&out).contains("ran\n"));
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::process::Command;

    use super::*;
    use crate::common::stdout;

    #[test]
    fn secrets_and_writes_outside_the_project_are_refused_and_work_goes_on() {
        let (sb, project) = installed_with_secret();
        let git_init = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .status();
        assert!(git_init.is_ok_and(|s| s.success()));
        let out = run_sh(
            &sb,
            &project,
            "cat \"$HOME/.ssh/id_rsa\"; echo \"read=$?\"
             echo x > \"$HOME/outside.txt\"; echo \"write=$?\"
             echo y > inside.txt; echo \"project=$?\"
             git status --short > /dev/null; echo \"git=$?\"",
        );
        let shown = text(&out);
        assert_eq!(out.status.code(), Some(0), "{shown}");
        for expected in ["read=1", "write=1", "project=0", "git=0"] {
            assert!(stdout(&out).contains(expected), "{expected}: {shown}");
        }
        assert!(shown.contains("Operation not permitted"), "EPERM: {shown}");
        assert!(!shown.contains("FAKE-SSH-KEY"), "{shown}");
        assert!(!sb.home.join("outside.txt").exists());
        assert!(project.join("inside.txt").exists());
        assert!(
            stderr(&out).contains("turn the agent's own sandbox off"),
            "{shown}"
        );
    }

    #[test]
    fn network_goes_only_to_the_proxy_which_refuses_loopback() {
        let (sb, project) = installed_with_secret();
        let local = TcpListener::bind("127.0.0.1:0").unwrap();
        local.set_nonblocking(true).unwrap();
        let url = format!("http://127.0.0.1:{}/", local.local_addr().unwrap().port());
        let out = run_sh(
            &sb,
            &project,
            &format!(
                "curl -s -m 5 --noproxy '*' {url}; echo \"direct=$?\"
                 curl -s -m 5 -o /dev/null -w 'proxy=%{{http_code}}\\n' {url}"
            ),
        );
        let shown = text(&out);
        assert!(stdout(&out).contains("direct=7"), "{shown}");
        assert!(stdout(&out).contains("proxy=403"), "{shown}");
        assert_eq!(
            local.accept().map(drop).map_err(|e| e.kind()),
            Err(ErrorKind::WouldBlock),
            "nothing reached the local service"
        );
    }

    #[test]
    fn a_failing_agent_exits_1() {
        let (sb, project) = installed_with_secret();
        let out = run_sh(&sb, &project, "exit 2");
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    }
}
