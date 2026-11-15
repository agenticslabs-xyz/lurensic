//! Request normalisation and safe text handling.
//!
//! Everything an attacker controls is treated as hostile twice, once when it is
//! matched (decode layers, collapse evasions) and once when it is logged
//! (strip control and bidi characters, truncate, redact sensitive names).

use crate::engine::Request;
use serde_json::Value;

pub const MAX_PARAMS: usize = 256;
pub const MAX_VALUE: usize = 8 * 1024;
pub const MAX_BODY: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loc {
    Path,
    Query,
    Body,
    Cookie,
    Header,
}

impl Loc {
    pub fn as_str(self) -> &'static str {
        match self {
            Loc::Path => "path",
            Loc::Query => "query",
            Loc::Body => "body",
            Loc::Cookie => "cookie",
            Loc::Header => "header",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Param {
    pub loc: Loc,
    pub name: String,
    pub value: String,
}

fn hexval(c: u8) -> Option<u8> {
    crate::crypto::hexval(c)
}

pub fn pct_decode(s: &str, plus_as_space: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hexval(b[i + 1]), hexval(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Repeatedly percent-decode (double/triple encoding is a classic evasion).
pub fn deep_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut cur = s.to_string();
    for _ in 0..3 {
        let next = pct_decode(&cur, false);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Canonical form for pattern matching. The value is decoded and lowercased,
/// SQL inline comments are removed and whitespace is collapsed.
pub fn for_match(s: &str) -> String {
    let decoded = deep_decode(s).to_lowercase().replace("/**/", " ");
    let mut out = String::with_capacity(decoded.len());
    let mut space = false;
    for c in decoded.chars() {
        if c.is_whitespace() {
            if !space {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(c);
            space = false;
        }
    }
    out
}

/// For an absolute-form request target such as `http://host:80/a/b`, the
/// scheme and authority. Servers route these on the path alone, so Kagami
/// must too, or every path rule and decoy can be skipped with one request.
pub fn absolute_prefix(target: &str) -> Option<&str> {
    let scheme_end = target.find("://")?;
    let scheme = &target[..scheme_end];
    if scheme.is_empty()
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let rest = &target[scheme_end + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&target[..scheme_end + 3 + end])
}

/// Decoded, lowercased path used for route and bait matching.
pub fn norm_path(path: &str) -> String {
    let path = absolute_prefix(path).map_or(path, |p| &path[p.len()..]);
    let p = deep_decode(path).to_lowercase();
    let p = p.replace('\\', "/");
    let mut out = String::with_capacity(p.len());
    let mut prev_slash = false;
    for c in p.chars() {
        if c == '/' {
            if !prev_slash {
                out.push(c);
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    out
}

pub fn parse_pairs(s: &str, out: &mut Vec<(String, String)>) {
    for part in s.split('&') {
        if part.is_empty() || out.len() >= MAX_PARAMS {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        out.push((pct_decode(k, true), cap(pct_decode(v, true), MAX_VALUE)));
    }
}

fn cap(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

const SKIP_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "content-length",
    "connection",
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "pragma",
    "content-type",
];

pub fn extract(req: &Request) -> Vec<Param> {
    let mut v: Vec<Param> = Vec::new();

    v.push(Param {
        loc: Loc::Path,
        name: String::new(),
        // The scheme and host of an absolute-form target are not attacker
        // payload in the path. `request.absolute_target` reports them.
        value: cap(
            pct_decode(
                absolute_prefix(&req.path).map_or(&req.path[..], |p| &req.path[p.len()..]),
                false,
            ),
            MAX_VALUE,
        ),
    });

    let mut pairs = Vec::new();
    parse_pairs(&req.query, &mut pairs);
    v.extend(pairs.drain(..).map(|(name, value)| Param {
        loc: Loc::Query,
        name,
        value,
    }));

    if !req.body.is_empty() {
        let body = cap(req.body.clone(), MAX_BODY);
        let ct = if req.content_type.is_empty() {
            req.header("content-type")
                .unwrap_or("")
                .to_ascii_lowercase()
        } else {
            req.content_type.to_ascii_lowercase()
        };
        if ct.contains("json") {
            match serde_json::from_str::<Value>(&body) {
                Ok(val) => flatten_json(&val, "", &mut v, 0),
                Err(_) => v.push(Param {
                    loc: Loc::Body,
                    name: String::new(),
                    value: body,
                }),
            }
        } else if ct.contains("x-www-form-urlencoded") {
            parse_pairs(&body, &mut pairs);
            v.extend(pairs.drain(..).map(|(name, value)| Param {
                loc: Loc::Body,
                name,
                value,
            }));
        } else {
            v.push(Param {
                loc: Loc::Body,
                name: String::new(),
                value: body,
            });
        }
    }

    if let Some(cookie) = req.header("cookie") {
        for part in cookie.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (k, val) = part.split_once('=').unwrap_or((part, ""));
            v.push(Param {
                loc: Loc::Cookie,
                name: k.to_string(),
                value: cap(pct_decode(val, false), MAX_VALUE),
            });
        }
    }

    for (k, val) in &req.headers {
        let lk = k.to_ascii_lowercase();
        if SKIP_HEADERS.contains(&lk.as_str()) {
            continue;
        }
        v.push(Param {
            loc: Loc::Header,
            name: lk,
            value: cap(val.clone(), MAX_VALUE),
        });
    }

    v.truncate(MAX_PARAMS);
    v
}

fn flatten_json(val: &Value, name: &str, out: &mut Vec<Param>, depth: usize) {
    if depth > 8 || out.len() >= MAX_PARAMS {
        return;
    }
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                match v {
                    Value::Object(_) | Value::Array(_) => {
                        // Record the key itself so decoy / operator names nested
                        // inside objects are still visible to the rules.
                        out.push(Param {
                            loc: Loc::Body,
                            name: k.clone(),
                            value: String::new(),
                        });
                        flatten_json(v, k, out, depth + 1);
                    }
                    _ => flatten_json(v, k, out, depth + 1),
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter().take(64) {
                flatten_json(item, name, out, depth + 1);
            }
        }
        Value::String(s) => out.push(Param {
            loc: Loc::Body,
            name: name.to_string(),
            value: cap(s.clone(), MAX_VALUE),
        }),
        Value::Number(n) => out.push(Param {
            loc: Loc::Body,
            name: name.to_string(),
            value: n.to_string(),
        }),
        Value::Bool(b) => out.push(Param {
            loc: Loc::Body,
            name: name.to_string(),
            value: b.to_string(),
        }),
        Value::Null => out.push(Param {
            loc: Loc::Body,
            name: name.to_string(),
            value: String::new(),
        }),
    }
}

const SENSITIVE: &[&str] = &[
    "pass",
    "pwd",
    "secret",
    "token",
    "auth",
    "key",
    "session",
    "cookie",
    "credential",
    "otp",
    "ssn",
    "card",
    "cvv",
    "cvc",
    "pin",
    "iban",
];

pub fn is_sensitive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SENSITIVE.iter().any(|s| n.contains(s))
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{061C}')
}

/// Make attacker-controlled text safe to log. Control characters (log forging,
/// terminal escapes) and bidi overrides (display spoofing) are replaced, and
/// the length is bounded.
pub fn sanitize(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars * 2));
    for (n, c) in s.chars().enumerate() {
        if n >= max_chars {
            out.push('…');
            break;
        }
        if c.is_control() || is_bidi_control(c) {
            out.push('\u{FFFD}');
        } else {
            out.push(c);
        }
    }
    out
}

/// Query string for logs, with sensitive parameter values replaced.
pub fn redacted_query(q: &str) -> String {
    let mut pairs = Vec::new();
    parse_pairs(q, &mut pairs);
    let parts: Vec<String> = pairs
        .iter()
        .take(32)
        .map(|(k, v)| {
            let val = if is_sensitive(k) {
                "[REDACTED]".to_string()
            } else {
                sanitize(v, 128)
            };
            format!("{}={}", sanitize(k, 64), val)
        })
        .collect();
    sanitize(&parts.join("&"), 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_and_matching_form() {
        assert_eq!(pct_decode("a%20b+c", true), "a b c");
        assert_eq!(pct_decode("100%", false), "100%");
        assert_eq!(pct_decode("%zz", false), "%zz");
        assert_eq!(deep_decode("%252e%252e%252f"), "../");
        assert_eq!(for_match("UNION/**/SELECT\t\t1"), "union select 1");
    }

    #[test]
    fn path_normalisation() {
        assert_eq!(norm_path("//Internal//Export/"), "/internal/export");
        assert_eq!(norm_path("%2e%65nv"), "/.env");
        assert_eq!(norm_path("/"), "/");
    }

    #[test]
    fn sanitize_strips_dangerous_characters() {
        let s = sanitize("ok\x1b[31mred\r\nfake-line\u{202E}txt", 100);
        assert!(!s.chars().any(|c| c.is_control() || c == '\u{202E}'));
        assert_eq!(sanitize("abcdef", 3), "abc…");
    }

    #[test]
    fn redaction() {
        let q = redacted_query("q=shoes&password=hunter2&api_key=abc");
        assert_eq!(q, "q=shoes&password=[REDACTED]&api_key=[REDACTED]");
    }
}
