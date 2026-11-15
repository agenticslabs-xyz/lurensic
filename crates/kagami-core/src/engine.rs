//! The engine takes a request and returns a verdict and events.

use crate::config::{Config, ConfigError, ContainAction, IpLogging, Mode, Trigger};
use crate::contain::{Contained, Entry, ResponseMeta, Shadow};
use crate::crypto::{hex, Keys};
use crate::decoys::{self, Decoys};
use crate::event::{Draft, EventCtx, EventLog, ReqSummary, SessionInfo, Source};
use crate::net::{self, Cidr};
use crate::normalize::{self, is_sensitive, sanitize, Loc, Param};
use crate::respond;
use crate::rules::{self, RuleDef, Severity};
use crate::session::{State, Store};
use crate::tokens::{self, session_tag};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// A request as seen by the host adapter. Every field is optional on the wire.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Request {
    pub now_ms: u64,
    pub ip: String,
    pub method: String,
    pub host: String,
    /// Raw path, without query string.
    pub path: String,
    /// Raw query string, without the leading `?`.
    pub query: String,
    pub headers: Vec<(String, String)>,
    /// Overrides the content-type header (adapters that pass a re-serialised
    /// parsed body set this to `application/json`).
    pub content_type: String,
    /// Body as text, truncated by the host.
    pub body: String,
    /// Set by the host when its body parser rejected the body (for example
    /// invalid JSON or an unsupported charset). `body` then holds the raw text.
    pub body_error: String,
    /// Response status (for `response` calls).
    pub status: u16,
    /// Response headers (for `response` calls). Hosts send `content-type`,
    /// `cache-control`, `location` and, as a presence marker only,
    /// `set-cookie`. They are needed when the host sends `response_body`.
    pub response_headers: Vec<(String, String)>,
    /// Response body (for `response` calls). Sent only when the inspection
    /// asked for it (`capture`), or for a 401 while `learned_401` is false.
    pub response_body: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn response_header(&self, name: &str) -> Option<&str> {
        self.response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// A request a shared cache could answer: GET without credentials.
    fn anonymous_get(&self) -> bool {
        self.method.eq_ignore_ascii_case("GET")
            && self.header("cookie").is_none()
            && self.header("authorization").is_none()
    }

    /// A browser sent this request on behalf of another site, for example an
    /// auto-submitting form or an image tag on a page the visitor opened.
    /// Browsers say so with `Sec-Fetch-Site: cross-site` or with an `Origin`
    /// whose host differs from the request's. Attack tools send neither.
    fn cross_site(&self) -> bool {
        if self
            .header("sec-fetch-site")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("cross-site"))
        {
            return true;
        }
        let Some(origin) = self.header("origin").map(str::trim) else {
            return false;
        };
        if origin.is_empty() || origin.eq_ignore_ascii_case("null") {
            return false;
        }
        let origin_host = origin.split_once("://").map_or(origin, |(_, h)| h);
        let host = self.header("host").unwrap_or(&self.host);
        !origin_host.eq_ignore_ascii_case(host.trim())
    }

    pub fn user_agent(&self) -> &str {
        self.header("user-agent").unwrap_or("")
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Action {
    Pass,
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub session: String,
    /// Keyed hash of the client address, shared by all sessions from one machine.
    pub source: String,
    pub score: u32,
    pub state: State,
    pub action: Action,
    pub delay_ms: u32,
    pub decorate_html: bool,
    pub decorate_json: bool,
    /// Every rule this request matched, including repeats that produce no
    /// new event. Hosts can record it per request for analysis.
    pub rules: Vec<&'static str>,
    /// The machine is contained. In protect mode its request was answered by
    /// Kagami and never reaches the application.
    pub contained: bool,
    /// The host should pass the response headers and body to `response`, so
    /// the shadow can replay this public response to contained machines.
    pub capture: bool,
    /// Machines contained by this request, for enforcers such as an edge
    /// firewall. Empty in observe mode, where containment is a dry run.
    pub contain: Vec<Entry>,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseOutcome {
    pub score: u32,
    pub state: State,
    /// True once the app's 401 body is known, so hosts can stop sending it.
    pub learned_401: bool,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyOutcome {
    pub valid: bool,
    pub value: Option<String>,
    /// Machines contained because of a tampered value, for enforcers.
    pub contain: Vec<Entry>,
    pub events: Vec<String>,
}

struct Hit {
    rule: &'static RuleDef,
    evidence: Map<String, Value>,
}

#[derive(Default)]
struct Hits(Vec<Hit>);

impl Hits {
    /// One hit per rule per request; the first evidence wins.
    fn add(&mut self, rule: &'static RuleDef, evidence: Map<String, Value>) {
        if !self.0.iter().any(|h| h.rule.id == rule.id) {
            self.0.push(Hit { rule, evidence });
        }
    }
}

fn ev(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn param_evidence(p: &Param) -> Map<String, Value> {
    let redact = p.loc == Loc::Cookie || is_sensitive(&p.name);
    let snippet = if redact {
        "[REDACTED]".to_string()
    } else {
        sanitize(&p.value, 160)
    };
    ev(&[
        ("location", p.loc.as_str().into()),
        ("param", sanitize(&p.name, 64).into()),
        ("snippet", snippet.into()),
    ])
}

pub struct Engine {
    cfg: Config,
    keys: Keys,
    decoys: Decoys,
    sessions: Store,
    log: EventLog,
    deployment: String,
    /// The body of the first JSON 401 the app sent itself. Decoy routes
    /// answer with the same body so their errors match the app's format.
    app_401: Option<String>,
    contained: Contained,
    shadow: Shadow,
    allow: Vec<Cidr>,
}

/// The part of a user agent that identifies a session. Scanners such as
/// sqlmap inject payloads into the User-Agent header, and with the full
/// header in the session key every payload started a new, clean session (the
/// fourth live round produced 4,335 sessions from one machine). sqlmap both
/// appends payloads to its own name and replaces the whole header, so no
/// prefix of the header is stable. A user agent that holds characters no
/// real one uses, or that matches a payload rule, is attacker data, and all
/// such user agents from one address share a single session and its score.
fn session_user_agent(ua: &str) -> &str {
    const PAYLOAD: &[char] = &['\'', '"', '<', '>', '=', '$', '`', '{', '}', '|', '\\'];
    // SQL fragments that are too common in search text to be payload rules,
    // but never appear in a real user agent.
    const SQL: &[&str] = &[
        "))", "--", ";select", "; select", "order by", "union ", "select ", "sleep(",
    ];
    const INJECTED: &str = "\u{0}injected-user-agent";
    if ua.contains(PAYLOAD) || ua.trim_end().ends_with('#') {
        return INJECTED;
    }
    let lower = ua.to_ascii_lowercase();
    if SQL.iter().any(|m| lower.contains(m)) {
        return INJECTED;
    }
    let p = Param {
        loc: Loc::Header,
        name: "user-agent".into(),
        value: ua.to_string(),
    };
    if rules::payload_rules(&p).is_empty() {
        ua
    } else {
        INJECTED
    }
}

/// Accept an app's 401 body as a template only if it is a small, flat JSON
/// object. Anything larger may hold request-specific data.
fn usable_401(content_type: &str, body: &str) -> bool {
    if body.len() > 256 || !content_type.to_ascii_lowercase().contains("json") {
        return false;
    }
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(m)) => {
            !m.is_empty() && m.values().all(|v| !v.is_object() && !v.is_array())
        }
        _ => false,
    }
}

impl Engine {
    /// Build an engine. Also returns the `system.started` event.
    pub fn new(
        cfg: Config,
        now_ms: u64,
        instance: &str,
    ) -> Result<(Engine, Vec<String>), ConfigError> {
        cfg.validate()?;
        let keys = Keys::new(&cfg.secret);
        let deployment = hex(&keys.mac("deployment", &[])[..6]);
        let decoys = decoys::derive(&keys, &cfg.reserved_paths, &cfg.reserved_names);
        let mut log = EventLog::new(
            deployment.clone(),
            sanitize(instance, 64),
            cfg.mode,
            cfg.max_events_per_minute,
        );
        let mut out = Vec::new();
        log.push(
            &mut out,
            now_ms,
            Draft {
                rule: &rules::SYSTEM_STARTED,
                session: None,
                ctx: None,
                evidence: ev(&[
                    ("version", crate::VERSION.into()),
                    ("decoy_routes", decoys.routes.len().into()),
                    (
                        "html_decoys",
                        (cfg.mode == Mode::Protect && cfg.html_decoys).into(),
                    ),
                    (
                        "json_decoys",
                        (cfg.mode == Mode::Protect && cfg.json_decoys).into(),
                    ),
                    (
                        "form_decoys",
                        (cfg.mode == Mode::Protect && cfg.form_decoys).into(),
                    ),
                    (
                        "bait_files",
                        (cfg.mode == Mode::Protect && cfg.bait_files).into(),
                    ),
                    (
                        "containment",
                        if !cfg.containment.enabled {
                            "off".into()
                        } else if cfg.mode == Mode::Protect {
                            json!(cfg.containment.action)
                        } else {
                            "dry_run".into()
                        },
                    ),
                ]),
            },
        );
        let sessions = Store::new(cfg.max_sessions, cfg.session_ttl_secs);
        let contained = Contained::new(cfg.containment.max_entries);
        let shadow_budget = if cfg.containment.enabled
            && cfg.mode == Mode::Protect
            && cfg.containment.action == ContainAction::Shadow
        {
            cfg.containment.shadow_cache_bytes
        } else {
            0
        };
        let allow = cfg
            .containment
            .allow
            .iter()
            .filter_map(|r| Cidr::parse(r))
            .collect();
        Ok((
            Engine {
                cfg,
                keys,
                decoys,
                sessions,
                log,
                deployment,
                app_401: None,
                contained,
                shadow: Shadow::new(shadow_budget),
                allow,
            },
            out,
        ))
    }

    pub fn mode(&self) -> Mode {
        self.cfg.mode
    }

    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    pub fn session_id(&self, ip: &str, ua: &str) -> String {
        let ua = session_user_agent(ua);
        let machine = net::machine(ip);
        hex(&self
            .keys
            .mac("session", &[machine.as_bytes(), ua.as_bytes()])[..8])
    }

    /// Keyed hash of the client's machine, shared by every session from it.
    /// A machine is an IPv4 address or an IPv6 /64. Honeytokens, bait files,
    /// fake records and containment are keyed on it.
    pub fn source_id(&self, ip: &str) -> String {
        let machine = net::machine(ip);
        hex(&self.keys.mac("source", &[machine.as_bytes()])[..8])
    }

    /// Contain the machine behind `source`, unless its address is allowlisted.
    /// Emits `containment.started` the first time. Returns the entry for
    /// enforcers when the containment is new and enforced.
    /// `sid` is the session whose request triggered it. With `linked` the
    /// contained machine is a different one, reached through a honeytoken
    /// that was issued to it.
    #[allow(clippy::too_many_arguments)]
    fn start_containment(
        &mut self,
        source: &str,
        ip: &str,
        reason: &'static str,
        sid: &str,
        linked: bool,
        now: u64,
        ctx: &EventCtx,
        out: &mut Vec<String>,
    ) -> Option<Entry> {
        let c = &self.cfg.containment;
        if !c.enabled || (!ip.is_empty() && net::allowed(&self.allow, ip)) {
            return None;
        }
        let target = if ip.is_empty() {
            String::new()
        } else {
            net::machine(ip)
        };
        let public = net::parse_ip(ip).is_some_and(|a| net::is_public(&a));
        let enforced = self.cfg.mode == Mode::Protect;
        let (action, ttl) = (c.action, c.ttl_secs);
        let entry = self
            .contained
            .contain(source, &target, public, reason, now, ttl * 1000)?;
        let evidence = ev(&[
            ("reason", reason.into()),
            ("action", json!(action)),
            ("ttl_secs", ttl.into()),
            ("enforced", enforced.into()),
            ("contained_source", source.into()),
            ("linked", linked.into()),
        ]);
        let (score, state) = self.sessions.peek(sid);
        let session = SessionInfo {
            id: sid.to_string(),
            source: self.sessions.source_of(sid).unwrap_or(source).to_string(),
            score,
            state,
        };
        self.log.push(
            out,
            now,
            Draft {
                rule: &rules::CONTAINMENT_STARTED,
                session: Some(session),
                ctx: Some(ctx.clone()),
                evidence,
            },
        );
        enforced.then_some(entry)
    }

    fn ignored(&self, norm_path: &str) -> bool {
        self.cfg.ignore_paths.iter().any(|p| {
            let p = normalize::norm_path(p);
            norm_path == p || (p != "/" && norm_path.starts_with(&format!("{p}/")))
        })
    }

    fn ctx(&self, req: &Request) -> EventCtx {
        let ip = match self.cfg.ip_logging {
            IpLogging::Raw => Some(sanitize(&req.ip, 64)),
            IpLogging::Hashed => Some(format!(
                "h:{}",
                hex(&self.keys.mac("ip", &[req.ip.as_bytes()])[..8])
            )),
            IpLogging::Omit => None,
        };
        EventCtx {
            source: Source {
                ip,
                user_agent: sanitize(req.user_agent(), 256),
            },
            request: ReqSummary {
                method: sanitize(&req.method.to_ascii_uppercase(), 16),
                host: sanitize(&req.host, 255),
                path: sanitize(&req.path, 512),
                query: normalize::redacted_query(&req.query),
            },
        }
    }

    /// Inspect an incoming request.
    pub fn inspect(&mut self, req: &Request) -> Inspection {
        let now = req.now_ms;
        let sid = self.session_id(&req.ip, req.user_agent());
        let path = normalize::norm_path(&req.path);

        if self.ignored(&path) {
            let (score, state) = self.sessions.peek(&sid);
            return Inspection {
                session: sid,
                source: self.source_id(&req.ip),
                score,
                state,
                action: Action::Pass,
                delay_ms: 0,
                decorate_html: false,
                decorate_json: false,
                rules: Vec::new(),
                contained: false,
                capture: false,
                contain: Vec::new(),
                events: Vec::new(),
            };
        }

        let source = self.source_id(&req.ip);
        let mut hits = Hits::default();

        if let Some((header, value)) = rules::forged_forwarding(&req.headers) {
            hits.add(
                &rules::FORGED_FORWARDING,
                ev(&[
                    ("header", header.into()),
                    ("snippet", sanitize(&value, 160).into()),
                ]),
            );
        }
        if !req.body_error.is_empty() {
            hits.add(
                &rules::MALFORMED_BODY,
                ev(&[("error", sanitize(&req.body_error, 64).into())]),
            );
        }
        // Browsers send absolute URLs only to proxies, never to a website.
        if let Some(prefix) = normalize::absolute_prefix(&req.path) {
            hits.add(
                &rules::ABSOLUTE_TARGET,
                ev(&[("snippet", sanitize(prefix, 160).into())]),
            );
        }
        if let Some(pattern) = rules::bait_path(&path) {
            hits.add(&rules::BAIT_PATH, ev(&[("pattern", pattern.into())]));
        }
        let decoy_route = self.decoys.is_route(&path);
        if decoy_route {
            hits.add(&rules::DECOY_ROUTE, Map::new());
        }

        let params = normalize::extract(req);
        for p in &params {
            for rule in rules::payload_rules(p) {
                hits.add(rule, param_evidence(p));
            }
            if matches!(p.loc, Loc::Query | Loc::Body) {
                if let Some(name) = self.decoys.match_name(&p.name) {
                    // The JSON decoy field is echoed back unchanged by honest
                    // clients that PUT whole objects; only a changed value is
                    // a mass-assignment attempt.
                    let echoed =
                        name == self.decoys.mass_field && p.value == self.decoys.mass_value;
                    if !echoed {
                        hits.add(
                            &rules::DECOY_PARAM,
                            ev(&[
                                ("location", p.loc.as_str().into()),
                                ("param", sanitize(&p.name, 64).into()),
                                ("snippet", sanitize(&p.value, 64).into()),
                            ]),
                        );
                    }
                }
            }
        }

        let mut found = Vec::new();
        for p in &params {
            tokens::scan(&self.keys, &p.value, &mut found);
        }
        for h in ["authorization", "proxy-authorization"] {
            if let Some(v) = req.header(h) {
                tokens::scan(&self.keys, v, &mut found);
            }
        }
        let my_tag = session_tag(&source);
        let mut linked = Vec::new();
        for f in &found {
            let cross = f.tag != my_tag;
            hits.add(
                &rules::HONEYTOKEN_USED,
                ev(&[
                    ("token_kind", f.kind.into()),
                    ("token", f.masked.clone().into()),
                    ("issued_to_source", f.issued_to().into()),
                    ("cross_source", cross.into()),
                ]),
            );
            if cross && !linked.contains(&f.issued_to()) {
                linked.push(f.issued_to());
            }
        }
        let authorised = !found.is_empty();

        for (rule, matched) in rules::classify_ua(req.user_agent()) {
            hits.add(rule, ev(&[("matched", matched.into())]));
        }

        let ctx = self.ctx(req);
        let mut events = Vec::new();
        let rules: Vec<&'static str> = hits.0.iter().map(|h| h.rule.id).collect();
        let (score, state) = self.apply(&sid, &source, now, hits.0, &ctx, &mut events);
        self.sessions.note_ip(&sid, &req.ip);
        for prefix in &linked {
            self.flag_linked(prefix, &sid, now, &ctx, &mut events);
        }

        // Containment. A tripwire contains the machine that tripped it, and a
        // honeytoken used from elsewhere also contains the machine it was
        // issued to. Checked after the hits, so the tripping request itself
        // is already contained.
        let mut contain = Vec::new();
        if self.cfg.containment.enabled {
            let tripwire = rules
                .iter()
                .copied()
                .find(|r| rules::CONTAINMENT_TRIPWIRES.contains(r));
            let reason = tripwire.or_else(|| {
                (self.cfg.containment.trigger == Trigger::Flagged && state == State::Flagged)
                    .then_some(rules::SESSION_FLAGGED.id)
            });
            // A cross-site request may be a forgery that makes an innocent
            // visitor's browser trip the wire. It is still detected and
            // logged, but it does not contain the visitor's machine.
            if let Some(reason) = reason.filter(|_| !req.cross_site()) {
                contain.extend(self.start_containment(
                    &source,
                    &req.ip,
                    reason,
                    &sid,
                    false,
                    now,
                    &ctx,
                    &mut events,
                ));
            }
            for prefix in &linked {
                for (src, ip) in self.sessions.sources_with_prefix(prefix) {
                    if src != source {
                        contain.extend(self.start_containment(
                            &src,
                            &ip,
                            rules::HONEYTOKEN_USED.id,
                            &sid,
                            true,
                            now,
                            &ctx,
                            &mut events,
                        ));
                    }
                }
            }
        }
        let contained = self.cfg.containment.enabled
            && self.contained.is_contained(&source, now)
            && !net::allowed(&self.allow, &req.ip);

        let mut inspection = Inspection {
            session: sid,
            source: source.clone(),
            score,
            state,
            action: Action::Pass,
            delay_ms: 0,
            decorate_html: false,
            decorate_json: false,
            rules,
            contained,
            capture: false,
            contain,
            events,
        };
        if self.cfg.mode == Mode::Protect {
            self.protect(
                req,
                &path,
                &source,
                decoy_route,
                authorised,
                &mut inspection,
            );
        }
        inspection
    }

    /// The answer for a contained machine. With `block`, a plain 403. With
    /// `shadow`, a stored public response for the same URL or its bare path,
    /// or the app's own 404, carrying the same bait as live pages.
    fn contained_reply(&self, req: &Request, path: &str, source: &str) -> respond::Reply {
        if self.cfg.containment.action == ContainAction::Block {
            return respond::Reply {
                status: 403,
                headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
                body: "Forbidden".into(),
            };
        }
        let get = matches!(req.method.to_ascii_uppercase().as_str(), "GET" | "HEAD");
        let bare = Shadow::key(path, "");
        let hit = if get {
            self.shadow
                .get(&Shadow::key(path, &req.query))
                .or_else(|| self.shadow.get(&bare))
        } else {
            self.shadow.get(&bare)
        };
        let wants_json = path.starts_with("/api/")
            || req
                .header("accept")
                .is_some_and(|a| a.to_ascii_lowercase().contains("json"));
        let Some(s) = hit.or_else(|| self.shadow.not_found(wants_json)) else {
            return respond::Reply {
                status: 404,
                headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
                body: "Not Found".into(),
            };
        };
        let mut body = s.body.clone();
        if s.status == 200 {
            let ct = s.content_type.to_ascii_lowercase();
            if ct.contains("text/html") {
                if let Some(b) = self.decorate_for_source(source, path, &body) {
                    body = b;
                }
            } else if ct.contains("json") {
                if let Some(b) = self.decorate_json(&body) {
                    body = b;
                }
            }
        }
        let mut headers = Vec::new();
        if !s.content_type.is_empty() {
            headers.push(("content-type".to_string(), s.content_type.clone()));
        }
        if !s.location.is_empty() {
            headers.push(("location".to_string(), s.location.clone()));
        }
        respond::Reply {
            status: s.status,
            headers,
            body,
        }
    }

    /// Protect-mode actions. Never called in observe mode.
    fn protect(
        &self,
        req: &Request,
        path: &str,
        source: &str,
        decoy_route: bool,
        authorised: bool,
        i: &mut Inspection,
    ) {
        let method = req.method.to_ascii_uppercase();
        let get = method == "GET" || method == "HEAD";
        let reply = if decoy_route && self.cfg.decoy_routes {
            let page = respond::page_from_query(&req.query);
            Some(respond::decoy_route(
                &self.keys,
                source,
                &req.host,
                authorised,
                page,
                self.app_401.as_deref(),
            ))
        } else if get && self.cfg.bait_files {
            respond::bait_file(&self.keys, path, source, &req.host)
        } else {
            None
        };
        // Decoys and bait keep answering a contained machine, so it stays
        // busy with them. Everything else it asks for comes from the shadow
        // or is refused, and never reaches the application.
        let reply = reply.or_else(|| i.contained.then(|| self.contained_reply(req, path, source)));
        i.capture = reply.is_none()
            && !i.contained
            && req.anonymous_get()
            && self.cfg.containment.enabled
            && self.cfg.containment.action == ContainAction::Shadow
            && self
                .shadow
                .wants(&Shadow::key(path, &req.query), req.now_ms);
        if let Some(r) = reply {
            i.action = Action::Respond {
                status: r.status,
                headers: r.headers,
                body: r.body,
            };
        }
        let t = &self.cfg.tarpit;
        if t.enabled && i.state == State::Flagged {
            let span = t.max_ms - t.min_ms + 1;
            let jitter = self
                .keys
                .u32("tarpit", &[i.session.as_bytes(), &req.now_ms.to_be_bytes()])
                % span;
            i.delay_ms = t.min_ms + jitter;
        }
        let comment = self.cfg.html_decoys
            && !self.decoys.routes.is_empty()
            && self.decoys.comment_on(&self.keys, path);
        i.decorate_html = get && (comment || self.cfg.form_decoys);
        i.decorate_json = self.cfg.json_decoys;
    }

    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        sid: &str,
        source: &str,
        now: u64,
        hits: Vec<Hit>,
        ctx: &EventCtx,
        out: &mut Vec<String>,
    ) -> (u32, State) {
        let thresholds = self.cfg.thresholds.clone();
        let mut drafts = Vec::new();
        let (score, state, prev, rule_ids) = {
            let s = self.sessions.get_mut(sid, source, now);
            let prev = s.state;
            let mut instant = false;
            for h in hits {
                let first = s.record(h.rule.id);
                s.add(if first { h.rule.first } else { h.rule.repeat });
                instant |= h.rule.instant_flag;
                if first && h.rule.severity > Severity::Info {
                    drafts.push((h.rule, h.evidence));
                }
            }
            s.update_state(&thresholds, instant);
            (s.score, s.state, prev, s.rule_ids())
        };
        let info = SessionInfo {
            id: sid.to_string(),
            source: source.to_string(),
            score,
            state,
        };
        for (rule, evidence) in drafts {
            self.log.push(
                out,
                now,
                Draft {
                    rule,
                    session: Some(info.clone()),
                    ctx: Some(ctx.clone()),
                    evidence,
                },
            );
        }
        if state == State::Flagged && prev != State::Flagged {
            let rules: Vec<Value> = rule_ids.into_iter().map(Value::from).collect();
            self.log.push(
                out,
                now,
                Draft {
                    rule: &rules::SESSION_FLAGGED,
                    session: Some(info),
                    ctx: Some(ctx.clone()),
                    evidence: ev(&[
                        ("previous_state", json!(prev)),
                        ("rules", Value::Array(rules)),
                    ]),
                },
            );
        }
        (score, state)
    }

    /// A honeytoken came back from a different network than the one it was
    /// issued to. Sessions from the issuing network that already did
    /// something suspicious belong to the same attacker, so flag them too.
    fn flag_linked(
        &mut self,
        prefix: &str,
        from: &str,
        now: u64,
        ctx: &EventCtx,
        out: &mut Vec<String>,
    ) {
        let thresholds = self.cfg.thresholds.clone();
        for id in self.sessions.active_from_source(prefix, from) {
            let source = self.sessions.source_of(&id).unwrap_or_default().to_string();
            let (score, state, prev) = {
                let s = self.sessions.get_mut(&id, &source, now);
                let prev = s.state;
                s.record("session.linked");
                s.add(rules::HONEYTOKEN_USED.first);
                s.update_state(&thresholds, true);
                (s.score, s.state, prev)
            };
            if prev != State::Flagged {
                self.log.push(
                    out,
                    now,
                    Draft {
                        rule: &rules::SESSION_FLAGGED,
                        session: Some(SessionInfo {
                            id,
                            source,
                            score,
                            state,
                        }),
                        ctx: Some(ctx.clone()),
                        evidence: ev(&[
                            ("previous_state", json!(prev)),
                            ("linked_from_session", from.into()),
                        ]),
                    },
                );
            }
        }
    }

    /// Record the response status, which drives the enumeration and brute force signals.
    /// For a 401, the host may pass the app's response body in `body` and its
    /// content type in `content_type`. The first usable one becomes the body
    /// of decoy route 401s.
    pub fn response(&mut self, req: &Request) -> ResponseOutcome {
        let now = req.now_ms;
        let content_type = req.response_header("content-type").unwrap_or("");
        if req.status == 401
            && self.app_401.is_none()
            && usable_401(content_type, &req.response_body)
        {
            self.app_401 = Some(req.response_body.clone());
        }
        let learned_401 = self.app_401.is_some();
        let sid = self.session_id(&req.ip, req.user_agent());
        let path = normalize::norm_path(&req.path);
        // Keep public responses for the shadow. The request is checked again
        // here rather than trusting the host, and Kagami's own replies (decoy
        // routes and bait files) are never stored.
        if !req.response_headers.is_empty()
            && req.anonymous_get()
            && !self.ignored(&path)
            && !self.decoys.is_route(&path)
            && rules::bait_path(&path).is_none()
        {
            let meta = ResponseMeta {
                status: req.status,
                content_type,
                location: req.response_header("location").unwrap_or(""),
                cache_control: req.response_header("cache-control").unwrap_or(""),
                set_cookie: req.response_header("set-cookie").is_some(),
                body: &req.response_body,
            };
            self.shadow
                .remember(&Shadow::key(&path, &req.query), &meta, now);
        }
        if self.ignored(&path) {
            let (score, state) = self.sessions.peek(&sid);
            return ResponseOutcome {
                score,
                state,
                learned_401,
                events: Vec::new(),
            };
        }
        let source = self.source_id(&req.ip);
        let window = self.cfg.behavior_window_secs * 1000;
        let (enum_t, auth_t) = (
            self.cfg.enumeration_threshold as usize,
            self.cfg.auth_failure_threshold as usize,
        );
        let mut hits = Hits::default();
        {
            let s = self.sessions.get_mut(&sid, &source, now);
            let queue = match req.status {
                404 => Some((&mut s.not_found, enum_t, &rules::BEHAVIOR_ENUM)),
                401 | 403 => Some((&mut s.auth_fail, auth_t, &rules::BEHAVIOR_AUTH)),
                _ => None,
            };
            if let Some((q, threshold, rule)) = queue {
                q.push_back(now);
                while q.front().is_some_and(|t| now.saturating_sub(*t) > window) {
                    q.pop_front();
                }
                if q.len() >= threshold {
                    let n = q.len();
                    q.clear();
                    hits.add(
                        rule,
                        ev(&[("count", n.into()), ("window_secs", (window / 1000).into())]),
                    );
                }
            }
        }
        let mut events = Vec::new();
        let (score, state) = if hits.0.is_empty() {
            self.sessions.peek(&sid)
        } else {
            let ctx = self.ctx(req);
            self.apply(&sid, &source, now, hits.0, &ctx, &mut events)
        };
        ResponseOutcome {
            score,
            state,
            learned_401,
            events,
        }
    }

    /// Add bait to an HTML document served at `path`. Protect mode only. The
    /// bait comment goes on the pages `Decoys::comment_on` selects, and the
    /// hidden decoy field goes into POST forms when form decoys are enabled.
    pub fn decorate_html(&self, session: &str, path: &str, html: &str) -> Option<String> {
        if self.cfg.mode != Mode::Protect {
            return None;
        }
        let source = self.sessions.source_of(session).unwrap_or(session);
        self.decorate_for_source(source, path, html)
    }

    /// `decorate_html` for a known source. The shadow uses it so replayed
    /// pages carry the same bait as live ones.
    fn decorate_for_source(&self, source: &str, path: &str, html: &str) -> Option<String> {
        if self.cfg.mode != Mode::Protect {
            return None;
        }
        let path = normalize::norm_path(path);
        let mut out: Option<String> = None;
        if self.cfg.html_decoys && self.decoys.comment_on(&self.keys, &path) {
            if let Some(comment) = self.decoys.html_comment(&self.keys, source) {
                let variant = self.keys.u32("decoy/placement", &[]);
                out = decoys::decorate_html(html, &comment, variant);
            }
        }
        if self.cfg.form_decoys {
            let current = out.as_deref().unwrap_or(html);
            if let Some(with_forms) =
                decoys::decorate_forms(current, &self.decoys.mass_field, &self.decoys.mass_value)
            {
                out = Some(with_forms);
            }
        }
        out
    }

    /// Add the decoy field to a JSON object response. Protect mode only.
    pub fn decorate_json(&self, body: &str) -> Option<String> {
        if self.cfg.mode != Mode::Protect || !self.cfg.json_decoys {
            return None;
        }
        decoys::decorate_json(body, &self.decoys.mass_field, &self.decoys.mass_value)
    }

    pub fn seal(&self, value: &str) -> String {
        tokens::seal(&self.keys, value)
    }

    /// Verify a sealed value from a request. Invalid seals are tampering.
    pub fn verify_sealed(&mut self, req: &Request, sealed: &str, name: &str) -> VerifyOutcome {
        if let Some(value) = tokens::unseal(&self.keys, sealed) {
            return VerifyOutcome {
                valid: true,
                value: Some(value),
                contain: Vec::new(),
                events: Vec::new(),
            };
        }
        let sid = self.session_id(&req.ip, req.user_agent());
        let source = self.source_id(&req.ip);
        let ctx = self.ctx(req);
        let hit = Hit {
            rule: &rules::TAMPER_SEALED,
            evidence: ev(&[
                ("param", sanitize(name, 64).into()),
                ("snippet", sanitize(sealed, 96).into()),
            ]),
        };
        let mut events = Vec::new();
        self.apply(&sid, &source, req.now_ms, vec![hit], &ctx, &mut events);
        self.sessions.note_ip(&sid, &req.ip);
        // The request is already inside the application, which is calling
        // verify, so containment applies from the next request on.
        let contain = self
            .start_containment(
                &source,
                &req.ip,
                rules::TAMPER_SEALED.id,
                &sid,
                false,
                req.now_ms,
                &ctx,
                &mut events,
            )
            .into_iter()
            .collect();
        VerifyOutcome {
            valid: false,
            value: None,
            contain,
            events,
        }
    }

    /// Machines contained right now, soonest expiry first. Holds addresses,
    /// so hosts must keep it away from untrusted callers.
    pub fn contained_list(&mut self, now: u64) -> Vec<Entry> {
        self.contained.list(now)
    }

    /// End containment for a machine, given its address, IPv6 /64, or source.
    pub fn release(&mut self, key: &str) -> Vec<Entry> {
        let machine = net::machine(key);
        let mut out = self.contained.release(key);
        if machine != key {
            out.extend(self.contained.release(&machine));
        }
        out
    }

    /// Deployment manifest for the host (dashboard, self-test). Contains decoy
    /// names, so hosts must never expose it publicly.
    pub fn manifest(&self) -> Value {
        json!({
            "version": crate::VERSION,
            "abi": crate::ABI_VERSION,
            "deployment": self.deployment,
            "mode": self.cfg.mode,
            "decoys": {
                "routes": self.decoys.routes,
                "debug_param": self.decoys.debug_param,
                "json_field": self.decoys.mass_field,
                "json_value": self.decoys.mass_value,
            },
            "sessions": self.sessions.len(),
            "containment": {
                "enabled": self.cfg.containment.enabled,
                "enforced": self.cfg.containment.enabled && self.cfg.mode == Mode::Protect,
                "trigger": self.cfg.containment.trigger,
                "action": self.cfg.containment.action,
                "ttl_secs": self.cfg.containment.ttl_secs,
            },
        })
    }
}
