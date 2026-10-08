//! Merging the generated keys into Cursor's `sandbox.json`, and reading them
//! back for `moat doctor`.

use anyhow::{Result, bail};
use serde_json::{Map, Value};

use super::Generated;

/// Every top-level key [`apply`] may write, with the sub-keys it owns in an object.
const OWNED: &[(&str, &[&str])] = &[
    ("type", &[]),
    ("readBoundary", &[]),
    ("additionalReadPaths", &[]),
    ("additionalReadwritePaths", &[]),
    ("networkPolicy", &["default", "allow", "deny"]),
];

/// Merge `generated` into the `sandbox.json` document `root`, keeping every key
/// OpenMoat does not own. Returns whether anything changed.
pub fn apply(root: &mut Value, generated: &Generated) -> Result<bool> {
    let Value::Object(top) = root else {
        bail!("the sandbox file is not a JSON object");
    };
    let before = top.clone();
    for (key, value) in &generated.settings {
        match value {
            Value::Object(owned) => {
                let entry = top
                    .entry(key.as_str())
                    .or_insert_with(|| Value::Object(Map::new()));
                let Value::Object(nested) = entry else {
                    bail!("`{key}` in the sandbox file is not an object");
                };
                for (sub, v) in owned {
                    nested.insert(sub.clone(), v.clone());
                }
            }
            other => {
                top.insert(key.clone(), other.clone());
            }
        }
    }
    Ok(*top != before)
}

/// The inverse of [`apply`]: remove every key OpenMoat writes, then an object
/// that leaves empty. Works without a policy, so `moat uninstall` never needs
/// one. Returns whether anything was removed.
pub fn remove(root: &mut Value) -> bool {
    let Value::Object(top) = root else {
        return false;
    };
    let mut removed = false;
    for (key, subs) in OWNED {
        if subs.is_empty() {
            removed |= top.remove(*key).is_some();
        } else if let Some(Value::Object(nested)) = top.get_mut(*key) {
            let before = nested.len();
            nested.retain(|sub, _| !subs.contains(&sub.as_str()));
            if nested.len() != before {
                removed = true;
                if nested.is_empty() {
                    top.remove(*key);
                }
            }
        }
    }
    removed
}

/// Whether every key OpenMoat owns in `root` has its generated value.
pub fn in_sync(root: &Value, generated: &Generated) -> bool {
    generated.settings.iter().all(|(key, value)| match value {
        Value::Object(owned) => owned
            .iter()
            .all(|(sub, v)| root.pointer(&format!("/{key}/{sub}")) == Some(v)),
        other => root.get(key) == Some(other),
    })
}

/// Settings in `root` that weaken the sandbox, worded for `moat doctor`.
pub fn weaknesses(root: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if root.get("type").and_then(Value::as_str) == Some("insecure_none") {
        out.push("type is insecure_none: commands run without Cursor's sandbox".to_owned());
    }
    if root.get("readBoundary").and_then(Value::as_str) != Some("workspace") {
        out.push(
            "readBoundary is not workspace: sandboxed commands read the whole disk, ~/.ssh included"
                .to_owned(),
        );
    }
    if root
        .pointer("/networkPolicy/default")
        .and_then(Value::as_str)
        == Some("allow")
    {
        out.push("networkPolicy.default is allow: sandboxed commands reach every host".to_owned());
    }
    if root
        .get("additionalReadonlyPaths")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        out.push(
            "additionalReadonlyPaths is not empty: sandboxed commands read those paths".to_owned(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use openmoat_core::DEFAULT_POLICY;
    use serde_json::json;

    use super::super::tests::generated;
    use super::*;

    #[test]
    fn apply_keeps_user_keys_and_is_idempotent() {
        let out = generated(DEFAULT_POLICY);
        let mut root = json!({
            "enableSharedBuildCache": true,
            "networkPolicy": { "default": "allow", "extra": 1 },
        });
        assert!(!in_sync(&root, &out));
        assert!(apply(&mut root, &out).unwrap());
        assert!(
            !apply(&mut root, &out).unwrap(),
            "second apply changes nothing"
        );
        assert!(in_sync(&root, &out));
        assert_eq!(root["enableSharedBuildCache"], json!(true));
        assert_eq!(root["networkPolicy"]["extra"], json!(1));
        assert_eq!(root["networkPolicy"]["default"], json!("deny"));
        assert!(weaknesses(&root).is_empty(), "{:?}", weaknesses(&root));
        assert!(apply(&mut json!([]), &out).is_err());
        assert!(apply(&mut json!({"networkPolicy": 1}), &out).is_err());
    }

    #[test]
    fn remove_undoes_apply_and_keeps_user_keys() {
        let original = json!({ "disableTmpWrite": true, "networkPolicy": { "extra": 1 } });
        let mut root = original.clone();
        apply(&mut root, &generated(DEFAULT_POLICY)).unwrap();
        assert!(remove(&mut root));
        assert_eq!(root, original);
        assert!(!remove(&mut root));

        let mut root = json!({});
        apply(&mut root, &generated(DEFAULT_POLICY)).unwrap();
        assert!(remove(&mut root));
        assert_eq!(root, json!({}), "every key apply writes is owned");
    }

    #[test]
    fn weaknesses_name_every_weakened_setting() {
        let out = generated(DEFAULT_POLICY);
        let mut root = json!({});
        apply(&mut root, &out).unwrap();
        root["type"] = json!("insecure_none");
        root["readBoundary"] = json!("system");
        root["networkPolicy"]["default"] = json!("allow");
        root["additionalReadonlyPaths"] = json!(["/Users/me/.aws"]);
        let found = weaknesses(&root).join("\n");
        for key in [
            "insecure_none",
            "readBoundary",
            "networkPolicy.default",
            "additionalReadonlyPaths",
        ] {
            assert!(found.contains(key), "{key}: {found}");
        }
        assert!(!in_sync(&root, &out));
    }
}
