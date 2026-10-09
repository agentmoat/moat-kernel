//! `sandbox.credentials` for Claude Code's native broker (ADR-020, #363).

use openmoat_core::{Kind, Secret, SecretSource};
use serde_json::{Map, Value, json};

use crate::sandbox::Report;

/// One `mask` entry per policy `Secret` whose host appears in `network`'s
/// `allowedDomains` and whose source Claude Code can read (`env` or `file`;
/// `keychain` is skipped with a loss). Returns `None` when no entry is
/// produced, so no `credentials` block is written at all. When at least one
/// entry is produced `network.tlsTerminate` is turned on in `network`, which
/// Claude Code requires for `mask`.
///
/// Policy's `header` field is unused here: Claude Code's proxy substitutes the
/// sentinel wherever it appears in a sandboxed command's outbound request
/// (headers and body), which `moat proxy` cannot do without TLS termination.
pub(super) fn credentials(
    secrets: &[Secret],
    network: &mut Value,
    report: &mut Report,
) -> Option<Value> {
    let allowed: Vec<String> = network
        .pointer("/allowedDomains")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    let mut env_vars = Vec::new();
    let mut files = Vec::new();
    let mut plain_http = false;
    let mut masked = Vec::new();
    for secret in secrets {
        if !allowed.iter().any(|h| h == &secret.host) {
            report.loss(
                Kind::Net,
                &format!("secrets.{}", secret.id),
                format!(
                    "`{}` is not in `net` allow, so Claude Code's broker cannot inject it; the \
                     secret still works through `moat proxy`",
                    secret.host
                ),
            );
            continue;
        }
        match &secret.source {
            SecretSource::Env(name) => env_vars.push(json!({
                "name": name,
                "mode": "mask",
                "injectHosts": [&secret.host],
            })),
            SecretSource::File(path) => files.push(json!({
                "path": path,
                "mode": "mask",
                "injectHosts": [&secret.host],
            })),
            SecretSource::Keychain { .. } => {
                report.loss(
                    Kind::Net,
                    &format!("secrets.{}", secret.id),
                    "Claude Code's broker reads env and file sources only, not the keychain; the \
                     secret still works through `moat proxy`"
                        .into(),
                );
                continue;
            }
        }
        plain_http |= secret.plain_http;
        masked.push(secret.id.clone());
    }
    if masked.is_empty() {
        return None;
    }
    network["tlsTerminate"] = json!({});
    let mut credentials = Map::new();
    if !env_vars.is_empty() {
        credentials.insert("envVars".into(), Value::Array(env_vars));
    }
    if !files.is_empty() {
        credentials.insert("files".into(), Value::Array(files));
    }
    if plain_http {
        credentials.insert("allowPlaintextInject".into(), json!(true));
        report.allowance(
            Kind::Net,
            "claude-code.plain-http-inject",
            masked.clone(),
            "sandboxed commands may send one of these masked secrets to a plain-HTTP destination; \
             the value then goes in clear text",
        );
    }
    report.allowance(
        Kind::Net,
        "claude-code.mask-credentials",
        masked,
        "Claude Code's own broker substitutes these inside HTTPS for sandboxed commands \
         (`sandbox.credentials` with `tlsTerminate`); on macOS a `file` source is denied \
         instead of masked, so the tool that reads it does not authenticate",
    );
    Some(Value::Object(credentials))
}
