//! The keys of the `sandbox` object OpenMoat owns in Claude Code's user
//! settings, and the pre-pass that drops stale sub-keys before [`super::apply`]
//! writes the new ones.

use serde_json::{Map, Value};

use super::Generated;

/// Every key of the `sandbox` object [`super::apply`] may write, with the
/// sub-keys it owns in `filesystem`, `network` and `credentials` (the proxy
/// ports only with `proxy_port`; `tlsTerminate` and `credentials` only with
/// `secrets`).
pub(super) const OWNED: &[(&str, &[&str])] = &[
    ("enabled", &[]),
    ("failIfUnavailable", &[]),
    ("allowUnsandboxedCommands", &[]),
    ("excludedCommands", &[]),
    (
        "filesystem",
        &["denyRead", "allowRead", "denyWrite", "allowWrite"],
    ),
    (
        "network",
        &[
            "allowedDomains",
            "deniedDomains",
            "strictAllowlist",
            "httpProxyPort",
            "socksProxyPort",
            "tlsTerminate",
        ],
    ),
    ("credentials", &["envVars", "files", "allowPlaintextInject"]),
];

/// Remove OpenMoat-owned sub-keys that aren't in `generated`, so a secret
/// dropped from the policy (or opting out of `moat proxy`) does not leave
/// stale `credentials` entries, `tlsTerminate`, or `httpProxyPort` behind.
/// Scalar owned keys ([`OWNED`] with empty subs) are overwritten by
/// [`super::apply`], so only objects with sub-keys need pruning here. An
/// object that empties out is removed; [`super::remove`] is the inverse that
/// also strips keys OpenMoat wrote when there is no policy at all.
pub(super) fn strip_stale(sandbox: &mut Map<String, Value>, generated: &Generated) {
    for (key, subs) in OWNED {
        if subs.is_empty() {
            continue;
        }
        let keep: Vec<&str> = generated
            .sandbox
            .get(*key)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|m| m.keys().map(String::as_str))
            .collect();
        if let Some(Value::Object(nested)) = sandbox.get_mut(*key) {
            nested.retain(|sub, _| !subs.contains(&sub.as_str()) || keep.contains(&sub.as_str()));
            if nested.is_empty() {
                sandbox.remove(*key);
            }
        }
    }
}
