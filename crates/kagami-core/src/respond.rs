//! Deceptive responses (protect mode only): fake secret files and decoy API
//! routes. Everything returned is fabricated; every credential in it is a
//! honeytoken bound to the requesting session.

use crate::crypto::{b32_encode, hex, Keys, ALPHA_MIXED};
use crate::tokens::{aws_secret_key, mint_aws_key_id, mint_mixed, session_tag, Variant};
use serde_json::{json, Value};

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

fn text(body: String) -> Reply {
    Reply {
        status: 200,
        headers: vec![
            ("content-type".into(), "text/plain; charset=utf-8".into()),
            ("cache-control".into(), "no-store".into()),
        ],
        body,
    }
}

fn json_reply(status: u16, body: Value, extra: &[(&str, &str)]) -> Reply {
    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        ),
        ("cache-control".to_string(), "no-store".to_string()),
    ];
    headers.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    Reply {
        status,
        headers,
        body: body.to_string(),
    }
}

/// A plausible mail/domain name for fake data.
pub fn domain(host: &str) -> String {
    let h = host
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let is_name =
        h.contains('.') && h.chars().any(|c| c.is_ascii_alphabetic()) && !h.starts_with('[');
    if is_name
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        h.trim_start_matches("www.").to_string()
    } else {
        "corp.internal".to_string()
    }
}

fn db_name(d: &str) -> String {
    let base = d.split('.').next().unwrap_or("app").replace('-', "_");
    format!("{base}_prod")
}

/// Fake secret files for classic probes. `None` = not one of ours.
pub fn bait_file(keys: &Keys, norm_path: &str, session: &str, host: &str) -> Option<Reply> {
    let tag = session_tag(session);
    let d = domain(host);
    if norm_path == "/.env" || norm_path.starts_with("/.env.") {
        let jwt = hex(&keys.mac("bait/jwt", &[&tag])[..24]);
        return Some(text(format!(
            "# Production environment. Do not commit.\n\
             NODE_ENV=production\n\
             APP_URL=https://{d}\n\
             DATABASE_URL=postgres://app_admin:{db}@db-primary.internal:5432/{dbn}\n\
             REDIS_URL=redis://cache.internal:6379/0\n\
             ADMIN_EMAIL=admin@{d}\n\
             ADMIN_PASSWORD={admin}\n\
             INTERNAL_API_KEY=sk_live_{api}\n\
             JWT_SECRET={jwt}\n\
             AWS_ACCESS_KEY_ID={aws}\n\
             AWS_SECRET_ACCESS_KEY={aws_secret}\n\
             AWS_REGION=us-east-1\n\
             S3_BUCKET={bucket}-uploads-prod\n",
            db = mint_mixed(keys, tag, Variant::DbPassword),
            dbn = db_name(&d),
            admin = mint_mixed(keys, tag, Variant::AdminPassword),
            api = mint_mixed(keys, tag, Variant::EnvApiKey),
            aws = mint_aws_key_id(keys, tag),
            aws_secret = aws_secret_key(keys, tag),
            bucket = d.split('.').next().unwrap_or("app"),
        )));
    }
    if norm_path == "/.git/config" {
        let org = d.split('.').next().unwrap_or("app");
        return Some(text(format!(
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n\
             [remote \"origin\"]\n\turl = https://deploy-bot:{pw}@git.{d}/{org}/web-platform.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n\
             [branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
            pw = mint_mixed(keys, tag, Variant::GitDeployPassword),
        )));
    }
    if norm_path == "/.aws/credentials" {
        return Some(text(format!(
            "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\nregion = us-east-1\n",
            mint_aws_key_id(keys, tag),
            aws_secret_key(keys, tag)
        )));
    }
    None
}

const FIRST: &[&str] = &[
    "james", "olivia", "liam", "emma", "noah", "ava", "lucas", "mia", "ethan", "sophia", "mason",
    "isla", "logan", "amelia", "henry", "grace", "jack", "chloe", "leo", "zoe", "aria", "ruby",
    "oscar", "harper",
];
const LAST: &[&str] = &[
    "smith", "patel", "nguyen", "brown", "wilson", "taylor", "anderson", "thomas", "moore",
    "martin", "lee", "walker", "hall", "young", "king", "wright", "scott", "green", "baker",
    "adams", "turner", "parker",
];
const PLANS: &[&str] = &["starter", "pro", "business", "enterprise"];

/// Decoy API route. Without a valid honeytoken it asks for one; with one it
/// returns endless, deterministic, fabricated records (cursor pagination
/// never ends, so an agent that keeps paging keeps paying).
pub fn decoy_route(keys: &Keys, session: &str, host: &str, authorised: bool, page: u32) -> Reply {
    if !authorised {
        return json_reply(
            401,
            json!({"error": "unauthorized", "message": "Missing or invalid API key. Send Authorization: Bearer <key>."}),
            &[("www-authenticate", "Bearer realm=\"internal\"")],
        );
    }
    let d = domain(host);
    let page = page.max(1);
    let records: Vec<Value> = (0..25u32)
        .map(|i| {
            let n = page.wrapping_mul(25).wrapping_add(i);
            let r = keys.mac("decoy/record", &[session.as_bytes(), &n.to_be_bytes()]);
            let first = FIRST[r[0] as usize % FIRST.len()];
            let last = LAST[r[1] as usize % LAST.len()];
            json!({
                "id": 10_000 + n,
                "email": format!("{first}.{last}@{d}"),
                "name": format!("{} {}", capitalise(first), capitalise(last)),
                "plan": PLANS[r[2] as usize % PLANS.len()],
                "mfa_enabled": r[3] % 3 != 0,
                "created_at": format!("202{}-{:02}-{:02}T{:02}:{:02}:00Z", 3 + r[4] % 3, 1 + r[5] % 12, 1 + r[6] % 28, r[7] % 24, r[8] % 60),
            })
        })
        .collect();
    let cursor = b32_encode(
        &keys.mac("decoy/cursor", &[session.as_bytes(), &page.to_be_bytes()])[..10],
        ALPHA_MIXED,
    );
    json_reply(
        200,
        json!({"data": records, "page": page, "per_page": 25, "has_more": true, "next_cursor": format!("{}{cursor}", page + 1)}),
        &[],
    )
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

/// Page number from `?page=N` or a `cursor` produced above (leading digits).
pub fn page_from_query(q: &str) -> u32 {
    let mut pairs = Vec::new();
    crate::normalize::parse_pairs(q, &mut pairs);
    for (k, v) in pairs {
        if k == "page" || k == "cursor" {
            let digits: String = v
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .take(6)
                .collect();
            if let Ok(n) = digits.parse::<u32>() {
                return n.max(1);
            }
        }
    }
    1
}
