//! Per-key digests of pinned JSON and TOML files, so drift can name the
//! top-level keys that changed (#288). They only describe drift; whether a file
//! drifted is still decided by its digest in [`super::Lock::entries`].

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::sha256_hex;

/// Top-level key → SHA-256 of its value, for a `.json` file holding an object or
/// a `.toml` file. `None` for any other file, or one that cannot be read or parsed.
pub(super) fn key_digests(path: &Path) -> Option<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).ok()?;
    match path.extension()?.to_str()? {
        "json" => {
            let value: serde_json::Value = serde_json::from_str(&text).ok()?;
            let object = value.as_object()?;
            let digest = |v| serde_json::to_vec(v).ok().map(|b| sha256_hex(&b));
            object
                .iter()
                .map(|(k, v)| Some((k.clone(), digest(v)?)))
                .collect()
        }
        "toml" => {
            let doc: toml_edit::DocumentMut = text.parse().ok()?;
            // A table's own `Display` leaves out its sub-tables; a document
            // holding only that key prints all of it.
            let digests = doc.as_table().iter().map(|(k, item)| {
                let mut one = toml_edit::DocumentMut::new();
                one.insert(k, item.clone());
                (k.to_owned(), sha256_hex(one.to_string().as_bytes()))
            });
            Some(digests.collect())
        }
        _ => None,
    }
}

/// `changed hooks; added theme`: the top-level keys that differ between the
/// pinned digests and the current ones. `None` when no top-level key differs.
/// Key names come from a file an agent may have written, so they are escaped
/// before they reach a terminal.
pub(super) fn describe(
    pinned: &BTreeMap<String, String>,
    now: &BTreeMap<String, String>,
) -> Option<String> {
    let changed = pinned
        .iter()
        .filter(|(k, v)| now.get(*k).is_some_and(|n| n != *v))
        .map(|(k, _)| k);
    let added = now.keys().filter(|k| !pinned.contains_key(*k));
    let removed = pinned.keys().filter(|k| !now.contains_key(*k));
    let groups: [(&str, Vec<&String>); 3] = [
        ("changed", changed.collect()),
        ("added", added.collect()),
        ("removed", removed.collect()),
    ];
    let parts: Vec<String> = groups
        .into_iter()
        .filter(|(_, keys)| !keys.is_empty())
        .map(|(verb, keys)| {
            let names: Vec<String> = keys.iter().map(|k| k.escape_debug().to_string()).collect();
            format!("{verb} {}", names.join(", "))
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::{Drift, Lock};
    use super::*;

    fn pinned(name: &str, contents: &str) -> (tempfile::TempDir, PathBuf, Lock) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, contents).unwrap();
        let lock = Lock::pin(Path::new("/x/moat"), std::slice::from_ref(&path)).unwrap();
        (dir, path, lock)
    }

    fn message(lock: &Lock, path: &Path) -> String {
        lock.verify_one(path).unwrap().to_string()
    }

    #[test]
    fn json_drift_names_changed_added_and_removed_keys() {
        let (_dir, path, lock) = pinned("settings.json", r#"{"hooks":{"a":1},"env":{}}"#);
        fs::write(&path, r#"{"hooks":{"a":2},"theme":"light","model":"x"}"#).unwrap();
        assert!(
            message(&lock, &path).ends_with(
                "settings.json was modified: changed hooks; added model, theme; removed env"
            ),
            "{}",
            message(&lock, &path)
        );
    }

    #[test]
    fn toml_drift_names_changed_tables() {
        let (_dir, path, lock) =
            pinned("config.toml", "model = \"a\"\n[permissions.moat]\nx = 1\n");
        fs::write(&path, "model = \"a\"\n[permissions.moat]\nx = 2\n").unwrap();
        assert!(message(&lock, &path).ends_with("was modified: changed permissions"));
    }

    #[test]
    fn without_a_baseline_the_message_stays_plain() {
        let (_dir, path, mut lock) = pinned("settings.json", r#"{"hooks":{}}"#);
        lock.keys.clear();
        fs::write(&path, r#"{"hooks":{"a":1}}"#).unwrap();
        assert!(matches!(lock.verify_one(&path), Some(Drift::Modified(_))));

        let (_dir, path, lock) = pinned("settings.json", r#"{"hooks":{}}"#);
        fs::write(&path, r#"{"hooks":"#).unwrap();
        assert!(
            matches!(lock.verify_one(&path), Some(Drift::Modified(_))),
            "a file that no longer parses has no keys to compare"
        );
    }

    #[test]
    fn a_lock_without_keys_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("policy.lock");
        fs::write(
            &lock_path,
            r#"{"version":1,"pinned_at_ms":0,"binary":"","entries":{}}"#,
        )
        .unwrap();
        assert!(Lock::load(&lock_path).unwrap().keys.is_empty());
    }

    #[test]
    fn key_names_are_escaped() {
        let pinned = BTreeMap::new();
        let now = BTreeMap::from([("\u{1b}[2Jx".to_owned(), String::new())]);
        assert_eq!(describe(&pinned, &now).unwrap(), r"added \u{1b}[2Jx");
    }
}
