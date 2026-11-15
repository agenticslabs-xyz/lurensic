//! Per-deployment decoys, derived from the secret.
//!
//! Two deployments of Kagami expose different decoy routes, parameter names
//! and field names, so there is no global list an attacker can tell their
//! agent to avoid. Reserved application paths and names are never used.

use crate::crypto::{hex, Keys};
use crate::tokens::{mint_mixed, session_tag, Variant};

const ROUTE_PREFIX: &[&str] = &["", "/api", "/api/v1", "/api/v2", "/v1", "/api/internal"];
const ROUTE_A: &[&str] = &[
    "internal",
    "legacy",
    "ops",
    "staff",
    "backoffice",
    "partner",
    "support",
    "platform",
];
const ROUTE_B: &[&str] = &[
    "export",
    "reports",
    "audit-log",
    "sync",
    "snapshot",
    "bulk-export",
    "migrations",
    "billing-sync",
    "user-dump",
    "diagnostics",
];
const PARAM_A: &[&str] = &[
    "debug", "trace", "verbose", "dev", "legacy", "preview", "internal",
];
const PARAM_B: &[&str] = &["_override", "_mode", "_bypass", "_unlock", "_access"];
const FIELD_A: &[&str] = &[
    "internal", "legacy", "staff", "ops", "account", "support", "billing",
];
const FIELD_B: &[&str] = &[
    "_role",
    "_scope",
    "_tier",
    "_flags",
    "_level",
    "_access_level",
];
const FIELD_VALUES: &[&str] = &["standard", "member", "basic", "default", "user"];

pub struct Decoys {
    pub routes: Vec<String>,
    pub debug_param: String,
    pub mass_field: String,
    pub mass_value: String,
    pub build_id: String,
}

fn collides(route: &str, reserved: &[String]) -> bool {
    reserved.iter().any(|r| {
        let r = crate::normalize::norm_path(r);
        r != "/" && (route.starts_with(&r) || r.starts_with(route))
    })
}

fn pick_name(keys: &Keys, label: &str, a: &[&str], b: &[&str], reserved: &[String]) -> String {
    for n in 0u32..64 {
        let nb = n.to_be_bytes();
        let name = format!(
            "{}{}",
            keys.pick(label, &[b"a", &nb], a),
            keys.pick(label, &[b"b", &nb], b)
        );
        if !reserved.iter().any(|r| r.eq_ignore_ascii_case(&name)) {
            return name;
        }
    }
    // Every candidate reserved: fall back to an opaque but plausible name.
    format!("x_{}", hex(&keys.mac(label, &[b"fallback"])[..3]))
}

pub fn derive(keys: &Keys, reserved_paths: &[String], reserved_names: &[String]) -> Decoys {
    let mut routes = Vec::new();
    for n in 0u32..64 {
        if routes.len() == 2 {
            break;
        }
        let nb = n.to_be_bytes();
        let r = format!(
            "{}/{}/{}",
            keys.pick("decoy/route/prefix", &[&nb], ROUTE_PREFIX),
            keys.pick("decoy/route/a", &[&nb], ROUTE_A),
            keys.pick("decoy/route/b", &[&nb], ROUTE_B)
        );
        if !routes.contains(&r) && !collides(&r, reserved_paths) {
            routes.push(r);
        }
    }
    Decoys {
        routes,
        debug_param: pick_name(keys, "decoy/param", PARAM_A, PARAM_B, reserved_names),
        mass_field: pick_name(keys, "decoy/field", FIELD_A, FIELD_B, reserved_names),
        mass_value: keys
            .pick("decoy/field/value", &[], FIELD_VALUES)
            .to_string(),
        build_id: hex(&keys.mac("decoy/build", &[])[..4])[..7].to_string(),
    }
}

impl Decoys {
    pub fn is_route(&self, norm_path: &str) -> bool {
        self.routes.iter().any(|r| r == norm_path)
    }

    /// Is `name` (a query/body/JSON key) one of our decoy names?
    /// Accepts bracket notation such as `user[internal_scope]`.
    pub fn match_name(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        let n = n.trim_end_matches(']');
        let leaf = n.rsplit(['[', '.']).next().unwrap_or(n);
        if leaf == self.debug_param {
            Some(&self.debug_param)
        } else if leaf == self.mass_field {
            Some(&self.mass_field)
        } else {
            None
        }
    }

    /// The per-session HTML comment. Several phrasings so the bait is not a
    /// fixed string; the honeytoken inside is bound to the session.
    pub fn html_comment(&self, keys: &Keys, session: &str) -> Option<String> {
        if self.routes.is_empty() {
            return None;
        }
        let pick = keys.u32("decoy/comment", &[session.as_bytes()]) as usize;
        let route = &self.routes[pick % self.routes.len()];
        let key = mint_mixed(keys, session_tag(session), Variant::CommentApiKey);
        let (build, param) = (&self.build_id, &self.debug_param);
        Some(match (pick >> 8) % 4 {
            0 => format!("<!-- TODO(ops): {route} is still live for the partner sync job. Auth: Bearer sk_live_{key} (rotate after migration) -->"),
            1 => format!("<!-- build {build} | legacy export: GET {route}?{param}=1 with header Authorization: Bearer sk_live_{key} -->"),
            2 => format!("<!-- note: remove before go-live. internal endpoint {route}, api key sk_live_{key} -->"),
            _ => format!("<!-- deploy {build}: {route} kept for support tooling; key sk_live_{key}; append ?{param}=1 for verbose errors -->"),
        })
    }
}

fn find_ci(hay: &str, needle: &str) -> Option<usize> {
    hay.to_ascii_lowercase().find(needle)
}

fn rfind_ci(hay: &str, needle: &str) -> Option<usize> {
    hay.to_ascii_lowercase().rfind(needle)
}

/// Insert the comment into an HTML document. Returns `None` (leave the
/// response untouched) for anything that is not a full document.
pub fn decorate_html(html: &str, comment: &str, variant: u32) -> Option<String> {
    let at = if variant % 2 == 0 {
        rfind_ci(html, "</body>")
    } else {
        find_ci(html, "<body").and_then(|i| html[i..].find('>').map(|j| i + j + 1))
    }
    .or_else(|| rfind_ci(html, "</body>"))?;
    let mut out = String::with_capacity(html.len() + comment.len() + 2);
    out.push_str(&html[..at]);
    out.push_str(comment);
    out.push('\n');
    out.push_str(&html[at..]);
    Some(out)
}

/// Add the decoy field to a top-level JSON object by text insertion, so the
/// app's own key order and formatting are preserved byte for byte.
pub fn decorate_json(body: &str, field: &str, value: &str) -> Option<String> {
    let start = body.find(|c: char| !c.is_whitespace())?;
    if body.as_bytes()[start] != b'{' {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    if parsed.as_object()?.contains_key(field) {
        return None;
    }
    let after = &body[start + 1..];
    let empty = after.trim_start().starts_with('}');
    let insert = if empty {
        format!("\"{field}\":\"{value}\"")
    } else {
        format!("\"{field}\":\"{value}\",")
    };
    Some(format!("{}{{{}{}", &body[..start], insert, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(s: &str) -> Keys {
        Keys::new(&format!("{s}-padding-padding-padding-padding"))
    }

    #[test]
    fn decoys_differ_per_deployment_and_respect_reserved() {
        let a = derive(&keys("a"), &[], &[]);
        let b = derive(&keys("b"), &[], &[]);
        assert_eq!(a.routes.len(), 2);
        assert!(
            a.routes != b.routes || a.debug_param != b.debug_param || a.mass_field != b.mass_field
        );
        let reserved = vec![a.routes[0].clone()];
        let c = derive(&keys("a"), &reserved, std::slice::from_ref(&a.mass_field));
        assert!(!c.routes.contains(&a.routes[0]));
        assert_ne!(c.mass_field, a.mass_field);
    }

    #[test]
    fn json_decoration_preserves_body() {
        assert_eq!(
            decorate_json(r#"{"a":1}"#, "x_role", "member").unwrap(),
            r#"{"x_role":"member","a":1}"#
        );
        assert_eq!(
            decorate_json("  { }", "x_role", "member").unwrap(),
            r#"  {"x_role":"member" }"#
        );
        assert_eq!(decorate_json("[1,2]", "x_role", "member"), None);
        assert_eq!(decorate_json("{broken", "x_role", "member"), None);
        let out = decorate_json(r#"{"a":{"b":[1,2]}}"#, "x_role", "member").unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
    }

    #[test]
    fn html_decoration_only_for_documents() {
        assert!(decorate_html("<p>fragment</p>", "<!-- x -->", 0).is_none());
        let out = decorate_html(
            "<html><BODY class=a><p>hi</p></BODY></html>",
            "<!-- x -->",
            1,
        )
        .unwrap();
        assert_eq!(
            out,
            "<html><BODY class=a><!-- x -->\n<p>hi</p></BODY></html>"
        );
    }

    #[test]
    fn name_matching() {
        let d = derive(&keys("a"), &[], &[]);
        assert!(d.match_name(&d.mass_field.to_uppercase()).is_some());
        assert!(d.match_name(&format!("user[{}]", d.mass_field)).is_some());
        assert!(d.match_name("email").is_none());
    }
}
