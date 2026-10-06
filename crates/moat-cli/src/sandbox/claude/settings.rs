//! Merging the generated block into Claude Code's user settings, and reading
//! it back for `moat doctor`.

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use super::{BLOCK_READS, Generated};

/// Merge `generated` into the settings document `root`, keeping every key
/// moat does not own. Returns whether anything changed.
pub fn apply(root: &mut Value, generated: &Generated) -> Result<bool> {
    let Value::Object(top) = root else {
        bail!("the settings file is not a JSON object");
    };
    let before = top.clone();
    let sandbox = object_at(top, "sandbox")?;
    for (key, value) in &generated.sandbox {
        match value {
            Value::Object(owned) => {
                let nested = object_at(sandbox, key)?;
                for (sub, v) in owned {
                    nested.insert(sub.clone(), v.clone());
                }
            }
            other => {
                sandbox.insert(key.clone(), other.clone());
            }
        }
    }
    if generated.block_reads {
        object_at(top, "permissions")?.insert(BLOCK_READS.into(), json!(true));
    }
    Ok(*top != before)
}

/// Deny sandboxed writes to the settings files next to `settings`, wherever
/// `CLAUDE_CONFIG_DIR` puts them: the policy names only `~/.claude`, and moat
/// pins this file.
pub fn protect(generated: &mut Generated, settings: &Path) {
    let Some(dir) = settings.parent() else {
        return;
    };
    let deny = generated
        .sandbox
        .get_mut("filesystem")
        .and_then(|f| f.get_mut("denyWrite"))
        .and_then(Value::as_array_mut);
    if let Some(deny) = deny {
        for name in ["settings.json", "settings.local.json"] {
            let path = json!(crate::context::path_string(&dir.join(name)));
            if !deny.contains(&path) {
                deny.push(path);
            }
        }
    }
}

/// Whether every key moat owns in `root` has its generated value.
pub fn in_sync(root: &Value, generated: &Generated) -> bool {
    let owned = generated.sandbox.iter().all(|(key, value)| match value {
        Value::Object(owned) => owned
            .iter()
            .all(|(sub, v)| root.pointer(&format!("/sandbox/{key}/{sub}")) == Some(v)),
        other => root.pointer(&format!("/sandbox/{key}")) == Some(other),
    });
    owned && (!generated.block_reads || block_reads_on(root))
}

fn block_reads_on(root: &Value) -> bool {
    root.pointer(&format!("/permissions/{BLOCK_READS}")) == Some(&json!(true))
}

/// Settings in `root` that weaken the sandbox, worded for `moat doctor`.
pub fn weaknesses(root: &Value, expect_block_reads: bool) -> Vec<String> {
    let at = |path: &str| root.pointer(path);
    let is = |path: &str, value: bool| at(path) == Some(&json!(value));
    let mut out = Vec::new();
    let mut flag = |bad: bool, text: &str| {
        if bad {
            out.push(text.to_owned());
        }
    };
    flag(
        !is("/sandbox/enabled", true),
        "sandbox.enabled is not true: Bash runs unsandboxed",
    );
    flag(
        !is("/sandbox/failIfUnavailable", true),
        "sandbox.failIfUnavailable is not true: commands run unsandboxed when the sandbox cannot start",
    );
    flag(
        !is("/sandbox/allowUnsandboxedCommands", false),
        "sandbox.allowUnsandboxedCommands is not false: the model may run a command outside the sandbox",
    );
    flag(
        at("/sandbox/excludedCommands")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty()),
        "sandbox.excludedCommands is not empty: those commands run unsandboxed",
    );
    flag(
        !is("/sandbox/network/strictAllowlist", true),
        "sandbox.network.strictAllowlist is not true: unlisted hosts prompt instead of failing",
    );
    for (path, text) in [
        (
            "/sandbox/filesystem/disabled",
            "sandbox.filesystem.disabled turns file isolation off",
        ),
        (
            "/sandbox/network/allowAllUnixSockets",
            "sandbox.network.allowAllUnixSockets opens every Unix socket",
        ),
        (
            "/sandbox/enableWeakerNetworkIsolation",
            "sandbox.enableWeakerNetworkIsolation is on",
        ),
        (
            "/sandbox/enableWeakerNestedSandbox",
            "sandbox.enableWeakerNestedSandbox is on",
        ),
    ] {
        flag(is(path, true), text);
    }
    flag(
        at("/sandbox/ignoreViolations").is_some_and(|v| !v.is_null()),
        "sandbox.ignoreViolations hides sandbox violations",
    );
    flag(
        expect_block_reads && !block_reads_on(root),
        "permissions.blockReadsOutsideWorkingDirectories is not true: sandboxed commands read the whole home directory",
    );
    out
}

fn object_at<'a>(map: &'a mut Map<String, Value>, key: &str) -> Result<&'a mut Map<String, Value>> {
    match map.entry(key).or_insert_with(|| Value::Object(Map::new())) {
        Value::Object(nested) => Ok(nested),
        _ => bail!("`{key}` in the settings file is not an object"),
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::DEFAULT_POLICY;
    use serde_json::{Value, json};

    use super::super::tests::generated;
    use super::*;

    #[test]
    fn apply_keeps_user_keys_and_is_idempotent() {
        let out = generated(DEFAULT_POLICY);
        let mut root = json!({
            "theme": "dark",
            "hooks": { "PreToolUse": [] },
            "permissions": { "allow": ["Bash(ls)"] },
            "sandbox": { "autoAllowBashIfSandboxed": false, "network": { "allowUnixSockets": ["/x.sock"] } },
        });
        assert!(!in_sync(&root, &out));
        assert!(apply(&mut root, &out).unwrap());
        assert!(
            !apply(&mut root, &out).unwrap(),
            "second apply changes nothing"
        );
        assert!(in_sync(&root, &out));
        assert_eq!(root["theme"], "dark");
        assert_eq!(root["permissions"]["allow"], json!(["Bash(ls)"]));
        assert_eq!(root["permissions"][BLOCK_READS], json!(true));
        assert_eq!(root["sandbox"]["autoAllowBashIfSandboxed"], json!(false));
        assert_eq!(
            root["sandbox"]["network"]["allowUnixSockets"],
            json!(["/x.sock"])
        );
        assert!(
            weaknesses(&root, true).is_empty(),
            "{:?}",
            weaknesses(&root, true)
        );
        assert!(apply(&mut json!([]), &out).is_err());
        assert!(apply(&mut json!({"sandbox": 1}), &out).is_err());
    }

    #[test]
    fn weaknesses_name_every_weakened_setting() {
        let out = generated(DEFAULT_POLICY);
        let mut root = json!({});
        apply(&mut root, &out).unwrap();
        root["sandbox"]["enabled"] = json!(false);
        root["sandbox"]["failIfUnavailable"] = Value::Null;
        root["sandbox"]["allowUnsandboxedCommands"] = json!(true);
        root["sandbox"]["excludedCommands"] = json!(["curl"]);
        root["sandbox"]["network"]["allowAllUnixSockets"] = json!(true);
        root["permissions"][BLOCK_READS] = json!(false);
        let found = weaknesses(&root, true).join("\n");
        for key in [
            "sandbox.enabled",
            "failIfUnavailable",
            "allowUnsandboxedCommands",
            "excludedCommands",
            "allowAllUnixSockets",
            BLOCK_READS,
        ] {
            assert!(found.contains(key), "{key}: {found}");
        }
        assert!(!in_sync(&root, &out));
    }

    #[test]
    fn protect_denies_writes_to_the_settings_moat_pins() {
        let mut out = generated(DEFAULT_POLICY);
        protect(&mut out, Path::new("/cfg/claude/settings.json"));
        protect(&mut out, Path::new("/cfg/claude/settings.json"));
        let deny = &out.sandbox["filesystem"]["denyWrite"];
        let count = |p: &str| deny.as_array().unwrap().iter().filter(|v| *v == p).count();
        assert_eq!(count("/cfg/claude/settings.json"), 1, "once, however often");
        assert_eq!(count("/cfg/claude/settings.local.json"), 1);
    }
}
