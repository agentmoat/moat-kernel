//! Writing and reading back the host sandbox settings (the only file I/O of
//! the Standard tier).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use openmoat_hosts::Host;
use toml_edit::DocumentMut;

use super::{Plan, Report, claude, codex, codex_config_path};
use crate::home::write_private;
use crate::install::{HostConfig, read_or_empty};
use crate::integrity::Lock;

/// The copy of a host file taken before OpenMoat's sandbox edit changes it.
const BACKUP_SUFFIX: &str = "moat-sandbox-backup";

/// Hosts with a sandbox backend, in the order OpenMoat writes them.
pub const HOSTS: [Host; 2] = [Host::ClaudeCode, Host::Codex];

/// The file `host`'s sandbox settings live in.
pub fn settings_path(host: Host) -> Result<PathBuf> {
    match host {
        Host::Codex => codex_config_path(),
        _ => Ok(HostConfig::for_host(host)?.settings_path),
    }
}

/// Merge the plan's settings for `host` into its file. Returns whether the file
/// changed (or would, with `dry_run`).
pub fn write(host: Host, plan: &Plan, dry_run: bool) -> Result<bool> {
    let path = settings_path(host)?;
    let changed;
    let text = if host == Host::Codex {
        let mut doc = read_toml(&path)?;
        changed = codex::apply(&mut doc, &plan.codex)?;
        doc.to_string()
    } else {
        let mut root = read_or_empty(&path)?;
        changed = claude::apply(&mut root, &plan.claude)
            .with_context(|| format!("updating {}", path.display()))?;
        serde_json::to_string_pretty(&root)? + "\n"
    };
    if !changed {
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }
    if path.exists() {
        let backup = PathBuf::from(format!("{}.{BACKUP_SUFFIX}", path.display()));
        fs::copy(&path, &backup).with_context(|| format!("backing up {}", path.display()))?;
    }
    write_private(&path, text.as_bytes())?;
    Ok(true)
}

/// The backend report for `host`.
pub fn report(host: Host, plan: &Plan) -> &Report {
    match host {
        Host::Codex => &plan.codex.report,
        _ => &plan.claude.report,
    }
}

/// Codex config files under this shell's environment that carry OpenMoat's
/// profile, which the lock pins by their owned part.
pub fn codex_profile_files() -> Result<Vec<PathBuf>> {
    let path = codex_config_path()?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let doc = read_toml(&path)?;
    let ours = doc.get("permissions").and_then(|p| p.get(codex::PROFILE));
    Ok(ours.map(|_| path).into_iter().collect())
}

/// SHA-256 of the part of a Codex config OpenMoat owns ([`codex::owned_part`]).
pub fn codex_part_digest(path: &Path) -> Result<String> {
    Ok(crate::integrity::sha256_hex(
        codex::owned_part(&read_toml(path)?).as_bytes(),
    ))
}

/// Problems with `host`'s sandbox settings for `moat doctor` and `moat status`;
/// `None` when the host is not on this machine.
pub fn problems(host: Host, plan: &Plan, lock: Option<&Lock>) -> Result<Option<Vec<String>>> {
    let path = settings_path(host)?;
    if !path.parent().is_some_and(Path::is_dir) {
        return Ok(None);
    }
    let out_of_date = "differs from the policy; run `moat sandbox sync`".to_owned();
    let mut problems = if host == Host::Codex {
        let doc = read_toml(&path)?;
        let mut found = codex::weaknesses(&doc);
        if !codex::in_sync(&doc, &plan.codex) {
            found.push(out_of_date);
        }
        if lock.is_some_and(|l| !l.pins_codex_profile(&path)) {
            found.push("not pinned by the lock; run `moat sandbox sync`".to_owned());
        }
        found
    } else {
        let root = read_or_empty(&path)?;
        let mut found = claude::weaknesses(&root, plan.claude.block_reads, plan.proxy_port);
        if !claude::in_sync(&root, &plan.claude) {
            found.push(out_of_date);
        }
        found
    };
    problems.dedup();
    Ok(Some(problems))
}

fn read_toml(path: &Path) -> Result<DocumentMut> {
    if !path.exists() {
        return Ok(DocumentMut::new());
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.parse()
        .with_context(|| format!("parsing {}", path.display()))
}
