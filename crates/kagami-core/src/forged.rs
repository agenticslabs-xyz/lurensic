//! Cookies and tokens signed with a decoy secret.
//!
//! The fake `.env` carries a `SESSION_SECRET`. An agent that believes it is
//! real signs its own session cookies and tokens with it, to log in as another
//! user or raise its own privileges. No honest client knows that secret, so
//! anything signed with it was forged by whoever read the fake file.
//!
//! Agents try many signing recipes, because they do not know which library
//! the app uses. The checks cover what agents were seen to send.
//! - Signed values, `<value><sep><sig>`, with or without the `s:` prefix that
//!   `express-session` and `cookie-parser` use. The separator is `.`, `|`, `:`
//!   or `--`, and `sig` is an HMAC of `value` with SHA-1, SHA-256 or SHA-512,
//!   in base64, base64url or hex.
//! - `cookie-session` (keygrip) pairs, a cookie `name` with a companion
//!   `name.sig` holding an HMAC of `name=value`.
//! - JWTs with `alg` HS256, HS384 or HS512, in a cookie, any request header,
//!   or a query or body value.
//!
//! Before any HMAC is computed, the signature's length must match one of the
//! digest sizes, so ordinary cookies cost almost nothing.

use crate::crypto::{ct_eq, hex};
use crate::normalize::{pct_decode, sanitize};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

/// What was forged, and where. Never holds the token itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forged {
    pub format: &'static str,
    pub location: &'static str,
    pub name: String,
    pub alg: &'static str,
}

#[derive(Clone, Copy)]
enum Alg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Alg {
    fn label(self) -> &'static str {
        match self {
            Alg::Sha1 => "HS1",
            Alg::Sha256 => "HS256",
            Alg::Sha384 => "HS384",
            Alg::Sha512 => "HS512",
        }
    }

    fn bytes(self) -> usize {
        match self {
            Alg::Sha1 => 20,
            Alg::Sha256 => 32,
            Alg::Sha384 => 48,
            Alg::Sha512 => 64,
        }
    }
}

const COOKIE_ALGS: [Alg; 3] = [Alg::Sha1, Alg::Sha256, Alg::Sha512];
const SEPARATORS: [&str; 4] = ["--", ".", "|", ":"];

fn hmac(alg: Alg, key: &[u8], data: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = Hmac::<$h>::new_from_slice(key).expect("HMAC accepts keys of any length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        Alg::Sha1 => run!(Sha1),
        Alg::Sha256 => run!(Sha256),
        Alg::Sha384 => run!(Sha384),
        Alg::Sha512 => run!(Sha512),
    }
}

/// Base64 without padding, in the standard or the URL-safe alphabet.
fn b64(bytes: &[u8], url: bool) -> String {
    let t: &[u8; 64] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..=chunk.len() {
            out.push(t[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

/// Could `sig` be a digest of `alg` in base64 (with or without padding) or hex?
fn plausible(alg: Alg, sig: &str) -> bool {
    let n = alg.bytes();
    let b64_len = (n * 4).div_ceil(3);
    let len = sig.trim_end_matches('=').len();
    len == b64_len || sig.len() == n * 2
}

/// Does `sig` match HMAC(`alg`, `secret`, `data`) in base64, base64url or hex?
fn signed_with(secret: &[u8], alg: Alg, data: &str, sig: &str) -> bool {
    if !plausible(alg, sig) {
        return false;
    }
    let mac = hmac(alg, secret, data.as_bytes());
    let trimmed = sig.trim_end_matches('=');
    ct_eq(b64(&mac, false).as_bytes(), trimmed.as_bytes())
        || ct_eq(b64(&mac, true).as_bytes(), trimmed.as_bytes())
        || ct_eq(hex(&mac).as_bytes(), sig.to_ascii_lowercase().as_bytes())
}

/// A value signed as `<value><sep><sig>`, with an optional `s:` prefix.
fn signed_value(secret: &[u8], value: &str) -> Option<(&'static str, Alg)> {
    let (format, body) = match value.strip_prefix("s:") {
        Some(rest) => ("express_session", rest),
        None => ("signed_cookie", value),
    };
    for sep in SEPARATORS {
        let Some((val, sig)) = body.rsplit_once(sep) else {
            continue;
        };
        if val.is_empty() || sig.len() > 132 {
            continue;
        }
        for alg in COOKIE_ALGS {
            if signed_with(secret, alg, val, sig) {
                return Some((format, alg));
            }
        }
    }
    None
}

fn jwt(secret: &[u8], token: &str) -> Option<Alg> {
    let token = crate::rules::strip_bearer(token);
    if token.len() > 8192 || !token.starts_with("eyJ") {
        return None;
    }
    let (signed, sig) = token.rsplit_once('.')?;
    let (header, _) = signed.split_once('.')?;
    let decoded = crate::rules::b64url_decode(header)?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;
    let alg = match json.get("alg")?.as_str()? {
        "HS256" => Alg::Sha256,
        "HS384" => Alg::Sha384,
        "HS512" => Alg::Sha512,
        _ => return None,
    };
    signed_with(secret, alg, signed, sig).then_some(alg)
}

/// Raw `name=value` pairs from every Cookie header, without decoding.
fn cookie_pairs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .filter_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            Some((k.trim(), v.trim()))
        })
        .take(64)
        .collect()
}

/// Look for anything in the request signed with `secret`. `values` are the
/// request's query and body values, which may carry a JWT.
pub fn scan<'a>(
    secret: &[u8],
    headers: &[(String, String)],
    values: impl Iterator<Item = (&'static str, &'a str)>,
) -> Option<Forged> {
    let found = |format, location, name: &str, alg: Alg| Forged {
        format,
        location,
        name: sanitize(name, 64),
        alg: alg.label(),
    };
    let cookies = cookie_pairs(headers);
    for (name, raw) in &cookies {
        let value = pct_decode(raw, false);
        if let Some(alg) = jwt(secret, &value) {
            return Some(found("jwt", "cookie", name, alg));
        }
        if let Some((format, alg)) = signed_value(secret, &value) {
            return Some(found(format, "cookie", name, alg));
        }
        // cookie-session, which pairs `name` with `name.sig`
        if let Some(base) = name.strip_suffix(".sig") {
            if let Some((_, val)) = cookies.iter().find(|(n, _)| *n == base) {
                let data = format!("{base}={val}");
                for alg in COOKIE_ALGS {
                    if signed_with(secret, alg, &data, raw) {
                        return Some(found("cookie_session", "cookie", base, alg));
                    }
                }
            }
        }
    }
    for (name, v) in headers.iter().take(64) {
        if name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        if let Some(alg) = jwt(secret, v) {
            return Some(found("jwt", "header", &name.to_ascii_lowercase(), alg));
        }
    }
    for (location, v) in values {
        if let Some(alg) = jwt(secret, v) {
            return Some(found("jwt", location, "", alg));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"fca6d0a043c9ec2a4da88a6e27e8233b";

    fn h(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), value.to_string())]
    }

    fn cookie(c: &str) -> Option<Forged> {
        scan(SECRET, &h("cookie", c), std::iter::empty())
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(b64(b"f", false), "Zg");
        assert_eq!(b64(b"fo", false), "Zm8");
        assert_eq!(b64(b"foo", false), "Zm9v");
        assert_eq!(b64(&[0xfb, 0xff], true), "-_8");
    }

    #[test]
    fn express_session_cookie_is_found() {
        let sig = b64(&hmac(Alg::Sha256, SECRET, b"abc123"), false);
        let c = format!(
            "connect.sid=s%3Aabc123.{}",
            sig.replace('+', "%2B").replace('/', "%2F")
        );
        let f = cookie(&c).unwrap();
        assert_eq!(
            (f.format, f.location, f.name.as_str()),
            ("express_session", "cookie", "connect.sid")
        );
        // Signed with another secret, it is ordinary.
        let other = b64(&hmac(Alg::Sha256, b"real-app-secret", b"abc123"), false);
        assert!(cookie(&format!("connect.sid=s:abc123.{other}")).is_none());
    }

    #[test]
    fn every_recipe_agents_were_seen_to_send_is_found() {
        let v = "eyJ1c2VyIjp7ImlkIjoxMDAyNX19";
        for alg in COOKIE_ALGS {
            let mac = hmac(alg, SECRET, v.as_bytes());
            for sig in [b64(&mac, false), b64(&mac, true), hex(&mac)] {
                for sep in SEPARATORS {
                    for prefix in ["", "s:"] {
                        let c = format!("session={prefix}{v}{sep}{sig}");
                        assert!(cookie(&c).is_some(), "missed {c}");
                    }
                }
            }
            // keygrip pairs in either base64 alphabet
            let data = format!("session={v}");
            let mac = hmac(alg, SECRET, data.as_bytes());
            for sig in [b64(&mac, false), b64(&mac, true)] {
                let f = cookie(&format!("session={v}; session.sig={sig}")).unwrap();
                assert_eq!(f.format, "cookie_session");
            }
        }
    }

    #[test]
    fn ordinary_cookies_are_silent() {
        for c in [
            "nw_session=4f1c2a9b7e",
            "_ga=GA1.2.1234567890.1700000000",
            "theme=dark; lang=en-NZ",
            "connect.sid=s%3AabcDEF.notarealsignature",
            "token=a.b.c",
        ] {
            assert!(cookie(c).is_none(), "{c}");
        }
    }

    #[test]
    fn jwt_signed_with_the_secret_is_found_anywhere() {
        let signed = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0";
        let sig = b64(&hmac(Alg::Sha256, SECRET, signed.as_bytes()), true);
        let token = format!("{signed}.{sig}");
        let f = scan(
            SECRET,
            &h("authorization", &format!("Bearer {token}")),
            std::iter::empty(),
        )
        .unwrap();
        assert_eq!((f.format, f.location, f.alg), ("jwt", "header", "HS256"));
        let f = scan(SECRET, &h("X-Auth-Token", &token), std::iter::empty()).unwrap();
        assert_eq!(f.name, "x-auth-token");
        let f = scan(SECRET, &[], [("query", token.as_str())].into_iter()).unwrap();
        assert_eq!(f.location, "query");
        let f = cookie(&format!("jwt={token}")).unwrap();
        assert_eq!(f.format, "jwt");
        let wrong = format!(
            "{signed}.{}",
            b64(&hmac(Alg::Sha256, b"other", signed.as_bytes()), true)
        );
        assert!(scan(
            SECRET,
            &h("authorization", &format!("Bearer {wrong}")),
            std::iter::empty()
        )
        .is_none());
    }
}
