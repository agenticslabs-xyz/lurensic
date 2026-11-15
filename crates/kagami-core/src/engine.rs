//! The engine: request in, verdict + events out.

use crate::config::{Config, ConfigError, IpLogging, Mode};
use crate::crypto::{hex, Keys};
use crate::decoys::{self, Decoys};
use crate::event::{Draft, EventCtx, EventLog, ReqSummary, SessionInfo, Source};
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
    /// Response status (for `response` calls).
    pub status: u16,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
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
    pub score: u32,
    pub state: State,
    pub action: Action,
    pub delay_ms: u32,
    pub decorate_html: bool,
    pub decorate_json: bool,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseOutcome {
    pub score: u32,
    pub state: State,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyOutcome {
    pub valid: bool,
    pub value: Option<String>,
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
                        "bait_files",
                        (cfg.mode == Mode::Protect && cfg.bait_files).into(),
                    ),
                ]),
            },
        );
        let sessions = Store::new(cfg.max_sessions, cfg.session_ttl_secs);
        Ok((
            Engine {
                cfg,
                keys,
                decoys,
                sessions,
                log,
                deployment,
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
        hex(&self.keys.mac("session", &[ip.as_bytes(), ua.as_bytes()])[..8])
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
                score,
                state,
                action: Action::Pass,
                delay_ms: 0,
                decorate_html: false,
                decorate_json: false,
                events: Vec::new(),
            };
        }

        let mut hits = Hits::default();

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
        let my_tag = session_tag(&sid);
        let mut linked = Vec::new();
        for f in &found {
            let cross = f.tag != my_tag;
            hits.add(
                &rules::HONEYTOKEN_USED,
                ev(&[
                    ("token_kind", f.kind.into()),
                    ("token", f.masked.clone().into()),
                    ("issued_to_session", f.issued_to().into()),
                    ("cross_session", cross.into()),
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
        let (score, state) = self.apply(&sid, now, hits.0, &ctx, &mut events);
        for prefix in linked {
            self.flag_linked(&prefix, &sid, now, &ctx, &mut events);
        }

        let mut inspection = Inspection {
            session: sid,
            score,
            state,
            action: Action::Pass,
            delay_ms: 0,
            decorate_html: false,
            decorate_json: false,
            events,
        };
        if self.cfg.mode == Mode::Protect {
            self.protect(req, &path, decoy_route, authorised, &mut inspection);
        }
        inspection
    }

    /// Protect-mode actions. Never called in observe mode.
    fn protect(
        &self,
        req: &Request,
        path: &str,
        decoy_route: bool,
        authorised: bool,
        i: &mut Inspection,
    ) {
        let method = req.method.to_ascii_uppercase();
        let get = method == "GET" || method == "HEAD";
        let reply = if decoy_route && self.cfg.decoy_routes {
            let page = respond::page_from_query(&req.query);
            Some(respond::decoy_route(
                &self.keys, &i.session, &req.host, authorised, page,
            ))
        } else if get && self.cfg.bait_files {
            respond::bait_file(&self.keys, path, &i.session, &req.host)
        } else {
            None
        };
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
        i.decorate_html = self.cfg.html_decoys && get && !self.decoys.routes.is_empty();
        i.decorate_json = self.cfg.json_decoys;
    }

    fn apply(
        &mut self,
        sid: &str,
        now: u64,
        hits: Vec<Hit>,
        ctx: &EventCtx,
        out: &mut Vec<String>,
    ) -> (u32, State) {
        let thresholds = self.cfg.thresholds.clone();
        let mut drafts = Vec::new();
        let (score, state, prev, rule_ids) = {
            let s = self.sessions.get_mut(sid, now);
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

    /// A honeytoken came back from a different session: the session it was
    /// issued to belongs to the same attacker, so flag it too.
    fn flag_linked(
        &mut self,
        prefix: &str,
        from: &str,
        now: u64,
        ctx: &EventCtx,
        out: &mut Vec<String>,
    ) {
        let Some(id) = self.sessions.find_prefix(prefix) else {
            return;
        };
        let thresholds = self.cfg.thresholds.clone();
        let (score, state, prev) = {
            let s = self.sessions.get_mut(&id, now);
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
                    session: Some(SessionInfo { id, score, state }),
                    ctx: Some(ctx.clone()),
                    evidence: ev(&[
                        ("previous_state", json!(prev)),
                        ("linked_from_session", from.into()),
                    ]),
                },
            );
        }
    }

    /// Record the response status (behavioural signals: enumeration, brute force).
    pub fn response(&mut self, req: &Request) -> ResponseOutcome {
        let now = req.now_ms;
        let sid = self.session_id(&req.ip, req.user_agent());
        let path = normalize::norm_path(&req.path);
        if self.ignored(&path) {
            let (score, state) = self.sessions.peek(&sid);
            return ResponseOutcome {
                score,
                state,
                events: Vec::new(),
            };
        }
        let window = self.cfg.behavior_window_secs * 1000;
        let (enum_t, auth_t) = (
            self.cfg.enumeration_threshold as usize,
            self.cfg.auth_failure_threshold as usize,
        );
        let mut hits = Hits::default();
        {
            let s = self.sessions.get_mut(&sid, now);
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
            self.apply(&sid, now, hits.0, &ctx, &mut events)
        };
        ResponseOutcome {
            score,
            state,
            events,
        }
    }

    /// Add per-session bait to an HTML document. Protect mode only.
    pub fn decorate_html(&self, session: &str, html: &str) -> Option<String> {
        if self.cfg.mode != Mode::Protect || !self.cfg.html_decoys {
            return None;
        }
        let comment = self.decoys.html_comment(&self.keys, session)?;
        let variant = self.keys.u32("decoy/placement", &[session.as_bytes()]);
        decoys::decorate_html(html, &comment, variant)
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
                events: Vec::new(),
            };
        }
        let sid = self.session_id(&req.ip, req.user_agent());
        let ctx = self.ctx(req);
        let hit = Hit {
            rule: &rules::TAMPER_SEALED,
            evidence: ev(&[
                ("param", sanitize(name, 64).into()),
                ("snippet", sanitize(sealed, 96).into()),
            ]),
        };
        let mut events = Vec::new();
        self.apply(&sid, req.now_ms, vec![hit], &ctx, &mut events);
        VerifyOutcome {
            valid: false,
            value: None,
            events,
        }
    }

    /// Deployment manifest for the host (dashboard, self-test). Contains decoy
    /// names: hosts must never expose it publicly.
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
        })
    }
}
