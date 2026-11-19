//! Deceptive responses for protect mode, namely fake secret files and decoy API
//! routes. Everything returned is fabricated, and every credential in it is a
//! honeytoken bound to the requesting session.

use crate::crypto::{b32_encode, hex, Keys, ALPHA_MIXED};
use crate::tokens::{aws_secret_key, mint_aws_key_id, mint_mixed, session_tag, Tag, Variant};
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

const SMTP_HOSTS: &[&str] = &[
    "smtp.sendgrid.net",
    "smtp.mailgun.org",
    "smtp.postmarkapp.com",
    "email-smtp.eu-west-1.amazonaws.com",
];

/// The `SESSION_SECRET` in the fake `.env`. It is fixed per deployment. A
/// cookie or token signed with it was forged by whoever read the fake file.
pub fn decoy_session_secret(keys: &Keys) -> String {
    hex(&keys.mac("bait/env/session-secret", &[])[..16])
}

/// The fake `.env`. A file holding a database, an admin password, an API
/// key, a JWT secret and AWS keys at once reads as bait to an agent that
/// expects one, so this file is short and ordinary. Its layout is fixed per
/// deployment and holds one or two service credentials. Only the credential
/// values differ between sources.
fn env_file(keys: &Keys, tag: Tag, d: &str) -> String {
    let base = d.split('.').next().unwrap_or("app").replace('-', "_");
    let layout = keys.u32("bait/env/layout", &[]);
    let bit = |n: u32| layout >> n & 1 == 1;
    let mut out = String::from("NODE_ENV=production\n");
    out.push_str(&format!(
        "PORT={}\n",
        ["3000", "8080", "5000", "3001"][(layout % 4) as usize]
    ));
    if bit(4) {
        out.push_str(if bit(5) {
            "LOG_LEVEL=info\n"
        } else {
            "LOG_LEVEL=warn\n"
        });
    }
    out.push_str(&format!("APP_URL=https://{d}\n"));
    out.push_str(&format!("SESSION_SECRET={}\n", decoy_session_secret(keys)));
    if bit(6) {
        out.push_str("REDIS_URL=redis://localhost:6379\n");
    }
    let services = 1 + (layout >> 8) % 2;
    let first = (layout >> 9) % 3;
    for n in 0..services {
        out.push('\n');
        match (first + n) % 3 {
            0 => out.push_str(&format!(
                "DATABASE_URL=postgres://{base}:{}@localhost:5432/{base}\n",
                mint_mixed(keys, tag, Variant::DbPassword)
            )),
            1 => out.push_str(&format!(
                "SMTP_HOST={}\nSMTP_PORT=587\nSMTP_USER=no-reply@{d}\nSMTP_PASS={}\n",
                keys.pick("bait/env/smtp", &[], SMTP_HOSTS),
                mint_mixed(keys, tag, Variant::SmtpPassword)
            )),
            _ => out.push_str(&format!(
                "STRIPE_SECRET_KEY=sk_live_{}\n",
                mint_mixed(keys, tag, Variant::EnvApiKey)
            )),
        }
    }
    out
}

/// Fake secret files for classic probes. Returns `None` for paths that are not ours.
pub fn bait_file(keys: &Keys, norm_path: &str, session: &str, host: &str) -> Option<Reply> {
    let tag = session_tag(session);
    let d = domain(host);
    // Only `/.env` itself. In the fourth live round an informed agent noticed
    // that `.env`, `.env.local` and `.env.production` were byte for byte the
    // same file and took that as proof of bait. A real leak is one file, and
    // the other names get the app's own 404. Probing them still raises
    // `bait.path`.
    if norm_path == "/.env" {
        return Some(text(env_file(keys, tag, &d)));
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

/// Decoy API route. Without a valid honeytoken it answers 401 with the same
/// body the app uses for its own 401 responses (`app_401`, learned at run
/// time), so the decoy cannot be told apart by its error format. With a
/// honeytoken it returns endless, deterministic, fabricated records (cursor
/// pagination never ends, so an agent that keeps paging keeps spending
/// requests and tokens).
pub fn decoy_route(
    keys: &Keys,
    session: &str,
    host: &str,
    authorised: bool,
    page: Option<u32>,
    app_401: Option<&str>,
) -> Reply {
    if !authorised {
        let mut r = json_reply(401, json!({"error": "unauthorized"}), &[]);
        if let Some(body) = app_401 {
            r.body = body.to_string();
        }
        return r;
    }
    let Some(page) = page else {
        return json_reply(400, json!({"error": "invalid cursor"}), &[]);
    };
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
    let cursor = cursor_suffix(keys, session, page);
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

/// The suffix of the cursor that leads from `page` to the next page.
fn cursor_suffix(keys: &Keys, session: &str, page: u32) -> String {
    b32_encode(
        &keys.mac("decoy/cursor", &[session.as_bytes(), &page.to_be_bytes()])[..10],
        ALPHA_MIXED,
    )
}

/// The page a decoy route request asks for. `page=N` is read leniently, as
/// most APIs read it. A `cursor` must be exactly one this route issued to the
/// same machine, as a real API refuses a cursor it did not issue, so an
/// edited cursor gets `None`.
pub fn page_from_query(keys: &Keys, session: &str, q: &str) -> Option<u32> {
    let mut pairs = Vec::new();
    crate::normalize::parse_pairs(q, &mut pairs);
    if let Some((_, c)) = pairs.iter().find(|(k, _)| k == "cursor") {
        let digits: String = c
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .take(7)
            .collect();
        let page = digits.parse::<u32>().ok().filter(|p| *p >= 2)?;
        let issued = format!("{page}{}", cursor_suffix(keys, session, page - 1));
        return (c.as_str() == issued).then_some(page);
    }
    for (k, v) in pairs {
        if k == "page" {
            let digits: String = v
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .take(6)
                .collect();
            if let Ok(n) = digits.parse::<u32>() {
                return Some(n.max(1));
            }
        }
    }
    Some(1)
}

const SPEC_TITLES: &[&str] = &[
    "Partner API",
    "Integrations API",
    "Data Sync API",
    "Operations API",
];

/// The decoy API description. It describes a separate partner API whose
/// operations are exactly the deployment's decoy routes, so every operation an
/// agent tries is a `decoy.route` hit. Its wording is fixed per deployment.
/// The sandbox key in it is a honeytoken bound to the machine that fetched it.
pub fn decoy_spec(keys: &Keys, source: &str, host: &str, routes: &[String]) -> Reply {
    let d = domain(host);
    let org = capitalise(d.split('.').next().unwrap_or("app"));
    let title = keys.pick("decoy/spec/title", &[], SPEC_TITLES);
    let v = keys.mac("decoy/spec/version", &[]);
    let key = mint_mixed(keys, session_tag(source), Variant::SpecSandboxKey);
    let description = match keys.u32("decoy/spec/wording", &[]) % 3 {
        0 => format!("Server-to-server API for approved partners. Send your key as a bearer token. For integration testing use the sandbox key pk_sandbox_{key}."),
        1 => format!("Read-only data access for {org} partners. Authenticate with a bearer key. Sandbox key for development is pk_sandbox_{key}, rotate before go-live."),
        _ => format!("Internal integration endpoints. Bearer authentication. Shared test key pk_sandbox_{key} (rate limited)."),
    };
    let mut paths = serde_json::Map::new();
    for route in routes {
        let leaf = route
            .rsplit('/')
            .next()
            .unwrap_or("records")
            .replace('-', " ");
        let id = leaf
            .split(' ')
            .enumerate()
            .map(|(i, w)| if i == 0 { w.to_string() } else { capitalise(w) })
            .collect::<String>();
        paths.insert(
            route.clone(),
            json!({
                "get": {
                    "operationId": format!("list{}", capitalise(&id)),
                    "summary": format!("List {leaf} records"),
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1}},
                        {"name": "cursor", "in": "query", "schema": {"type": "string"}}
                    ],
                    "responses": {
                        "200": {"description": "A page of records", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RecordPage"}}}},
                        "401": {"description": "Missing or invalid key"}
                    }
                }
            }),
        );
    }
    json_reply(
        200,
        json!({
            "openapi": "3.0.3",
            "info": {
                "title": format!("{org} {title}"),
                "version": format!("1.{}.{}", v[0] % 9, v[1] % 20),
                "description": description,
            },
            "servers": [{"url": "/"}],
            "security": [{"partnerKey": []}],
            "paths": paths,
            "components": {
                "securitySchemes": {"partnerKey": {"type": "http", "scheme": "bearer"}},
                "schemas": {
                    "Record": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "email": {"type": "string", "format": "email"},
                            "name": {"type": "string"},
                            "plan": {"type": "string"},
                            "mfa_enabled": {"type": "boolean"},
                            "created_at": {"type": "string", "format": "date-time"}
                        }
                    },
                    "RecordPage": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "array", "items": {"$ref": "#/components/schemas/Record"}},
                            "page": {"type": "integer"},
                            "per_page": {"type": "integer"},
                            "has_more": {"type": "boolean"},
                            "next_cursor": {"type": "string"}
                        }
                    }
                }
            }
        }),
        &[],
    )
}

/// A redirect in the form Express sends, used for the decoy description's
/// aliases.
pub fn redirect(location: &str) -> Reply {
    Reply {
        status: 302,
        headers: vec![
            ("content-type".into(), "text/plain; charset=utf-8".into()),
            ("location".into(), location.to_string()),
            ("vary".into(), "Accept".into()),
        ],
        body: format!("Found. Redirecting to {location}"),
    }
}
