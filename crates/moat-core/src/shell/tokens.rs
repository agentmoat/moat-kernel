//! Recognisers for what a single shell word can name: an assignment or
//! variable references. Hosts are recognised by `crate::host`.

use super::tables::{IGNORED_VARS, SPECIAL_PARAMS};

/// `NAME=value` or `NAME+=value` → `NAME`.
pub fn assignment_name(word: &str) -> Option<&str> {
    let (name, _) = word.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    chars
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        .then_some(name)
}

/// Names referenced as `$NAME` or `${NAME…}`, excluding special and positional
/// parameters and well-known non-secret variables. Order-preserving, unique.
pub fn env_refs(token: &str) -> Vec<String> {
    let is_name_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut names: Vec<String> = Vec::new();
    let mut rest = token;
    while let Some(pos) = rest.find('$') {
        rest = &rest[pos + 1..];
        let body = rest.strip_prefix('{').unwrap_or(rest);
        if body
            .chars()
            .next()
            .is_some_and(|c| SPECIAL_PARAMS.contains(&c))
        {
            continue;
        }
        let end = body.find(|c: char| !is_name_char(c)).unwrap_or(body.len());
        let name = &body[..end];
        let skip = name.is_empty()
            || IGNORED_VARS.contains(&name)
            || name.chars().all(|c| c.is_ascii_digit());
        if !skip && !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    }
    names
}

/// `curl -d @file` names `file`.
pub fn strip_at(token: &str) -> &str {
    token.strip_prefix('@').unwrap_or(token)
}

/// The argument following the first of `flags`, if any.
pub fn flag_payload<'a>(argv: &'a [String], flags: &[&str]) -> Option<&'a str> {
    let pos = argv.iter().position(|a| flags.contains(&a.as_str()))?;
    argv.get(pos + 1).map(String::as_str)
}

pub fn basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}
