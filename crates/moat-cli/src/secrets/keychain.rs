//! Keychain sources, through the operating system's own command-line tool,
//! started by absolute path so a planted program earlier on `PATH` is not run:
//!
//! - macOS: `/usr/bin/security find-generic-password -s <service> -a <account> -w`
//! - Linux and other Unix: `/usr/bin/secret-tool lookup service <service> account <account>`
//!   (libsecret, the GNOME keyring or `KWallet` behind it)
//! - Windows: not supported yet; use a `file` or `env` source.

use anyhow::Result;
use zeroize::Zeroizing;

/// The value of the keychain item `service`/`account`.
#[cfg(unix)]
pub fn read(service: &str, account: &str) -> Result<Zeroizing<String>> {
    use anyhow::{Context as _, ensure};

    let mut command = command(service, account);
    let out = command
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .with_context(|| format!("starting {}", command.get_program().display()))?;
    let stdout = Zeroizing::new(out.stdout);
    ensure!(
        out.status.success(),
        "keychain item {service}/{account} was not found or could not be read"
    );
    let text = std::str::from_utf8(&stdout)
        .ok()
        .with_context(|| format!("keychain item {service}/{account} is not UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Keychain sources are refused where no tool is wired up.
#[cfg(not(unix))]
pub fn read(_service: &str, _account: &str) -> Result<Zeroizing<String>> {
    anyhow::bail!("keychain sources are not supported on this platform; use a file or env source")
}

#[cfg(target_os = "macos")]
fn command(service: &str, account: &str) -> std::process::Command {
    let mut c = std::process::Command::new("/usr/bin/security");
    c.args(["find-generic-password", "-s", service, "-a", account, "-w"]);
    c
}

#[cfg(all(unix, not(target_os = "macos")))]
fn command(service: &str, account: &str) -> std::process::Command {
    let mut c = std::process::Command::new("/usr/bin/secret-tool");
    c.args(["lookup", "service", service, "account", account]);
    c
}

#[cfg(test)]
mod tests {
    // Builds the command only: tests never query a real keychain.
    #[cfg(unix)]
    #[test]
    fn the_tool_is_started_by_absolute_path_with_the_item_as_arguments() {
        let c = super::command("moat", "gh");
        assert!(c.get_program().to_str().unwrap().starts_with("/usr/bin/"));
        let args: Vec<_> = c.get_args().map(|a| a.to_str().unwrap()).collect();
        assert!(args.contains(&"moat") && args.contains(&"gh"), "{args:?}");
    }

    #[cfg(not(unix))]
    #[test]
    fn keychains_are_refused_where_unsupported() {
        assert!(super::read("moat", "gh").is_err());
    }
}
