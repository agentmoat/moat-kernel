//! Recognisers for what a single shell word can name: an assignment, variable
//! references, or a network host.

use super::tables::{FILE_EXTENSIONS, IGNORED_VARS, KNOWN_TLDS, SPECIAL_PARAMS};

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

/// Lowercase host from a URL, `user@host:port/path`, dotted name or IPv4 literal.
pub fn host_of(token: &str) -> Option<String> {
    let (authority, has_scheme) = match token.split_once("://") {
        Some((scheme, rest)) => {
            let valid = !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
            if !valid {
                return None;
            }
            (rest, true)
        }
        None if token.starts_with(['-', '.', '=']) => return None,
        None => (token, false),
    };
    let host_port = authority
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?;
    let host = host_port.split(':').next()?.trim_end_matches('.');
    if host.is_empty() || !host.contains('.') || host.starts_with('.') || host.contains("..") {
        return None;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    let is_ipv4 = host.split('.').count() == 4 && host.split('.').all(|o| o.parse::<u8>().is_ok());
    if !is_ipv4 {
        let tld = host.rsplit('.').next()?.to_ascii_lowercase();
        if !(2..=24).contains(&tld.len()) || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        if !has_scheme
            && (FILE_EXTENSIONS.contains(&tld.as_str()) || !KNOWN_TLDS.contains(&tld.as_str()))
        {
            return None;
        }
    }
    Some(host.to_ascii_lowercase())
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
