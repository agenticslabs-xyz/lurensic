//! Audit events: structured, sanitised, rate limited and hash-chained.
//!
//! Each event is serialised once, inside the core, and handed to the host as
//! an opaque JSON line. Hosts must write the line verbatim. The `hash` field is
//! always the last field: `hash = sha256(prev_hash || "\n" || body)`, where
//! `body` is the line with `,"hash":"…"` removed. Any edit, deletion or
//! reordering of a stored log breaks the chain (`verify_chain`).

use crate::config::Mode;
use crate::crypto::sha256_hex;
use crate::rules::{Confidence, RuleDef, Severity, SYSTEM_SUPPRESSED};
use crate::session::State;
use serde::Serialize;
use serde_json::{Map, Value};

pub const SCHEMA: &str = "kagami.event/v1";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Fields that carry attacker-controlled text. Consumers (SIEM rules, chat
/// alerts, AI triage assistants) must treat them as data, never instructions.
const UNTRUSTED: &[&str] = &[
    "source.user_agent",
    "request.host",
    "request.path",
    "request.query",
    "evidence",
];

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub score: u32,
    pub state: State,
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReqSummary {
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
}

#[derive(Debug, Clone)]
pub struct EventCtx {
    pub source: Source,
    pub request: ReqSummary,
}

pub struct Draft {
    pub rule: &'static RuleDef,
    pub session: Option<SessionInfo>,
    pub ctx: Option<EventCtx>,
    pub evidence: Map<String, Value>,
}

#[derive(Serialize)]
struct Out<'a> {
    schema: &'static str,
    id: String,
    seq: u64,
    ts: String,
    deployment: &'a str,
    instance: &'a str,
    mode: Mode,
    kind: &'static str,
    rule: &'static str,
    title: &'static str,
    severity: Severity,
    confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<&'a SessionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<&'a ReqSummary>,
    evidence: &'a Map<String, Value>,
    mitre_attack: &'static [&'static str],
    untrusted: &'static [&'static str],
    prev_hash: &'a str,
}

pub struct EventLog {
    prev: String,
    seq: u64,
    deployment: String,
    instance: String,
    mode: Mode,
    max_per_minute: u32,
    minute: u64,
    count: u32,
    critical_count: u32,
    suppressed: u32,
}

impl EventLog {
    pub fn new(deployment: String, instance: String, mode: Mode, max_per_minute: u32) -> Self {
        EventLog {
            prev: GENESIS.to_string(),
            seq: 0,
            deployment,
            instance,
            mode,
            max_per_minute: max_per_minute.max(1),
            minute: 0,
            count: 0,
            critical_count: 0,
            suppressed: 0,
        }
    }

    /// Queue an event, enforcing the per-minute budget. Critical events have a
    /// separate budget so a flood of noise can never crowd them out.
    pub fn push(&mut self, out: &mut Vec<String>, now_ms: u64, draft: Draft) {
        let minute = now_ms / 60_000;
        if minute != self.minute {
            self.minute = minute;
            self.count = 0;
            self.critical_count = 0;
            if self.suppressed > 0 {
                let mut ev = Map::new();
                ev.insert("count".into(), Value::from(self.suppressed));
                self.suppressed = 0;
                self.write(
                    out,
                    now_ms,
                    Draft {
                        rule: &SYSTEM_SUPPRESSED,
                        session: None,
                        ctx: None,
                        evidence: ev,
                    },
                );
            }
        }
        let critical = draft.rule.severity == Severity::Critical;
        let budget = if critical {
            &mut self.critical_count
        } else {
            &mut self.count
        };
        if *budget >= self.max_per_minute && draft.rule.kind != "system" {
            self.suppressed += 1;
            return;
        }
        *budget += 1;
        self.write(out, now_ms, draft);
    }

    fn write(&mut self, out: &mut Vec<String>, now_ms: u64, d: Draft) {
        let seq = self.seq;
        self.seq += 1;
        let id = sha256_hex(&[
            self.deployment.as_bytes(),
            b"/",
            self.instance.as_bytes(),
            b"/",
            &seq.to_be_bytes(),
        ]);
        let body = Out {
            schema: SCHEMA,
            id: id[..20].to_string(),
            seq,
            ts: crate::time::rfc3339(now_ms),
            deployment: &self.deployment,
            instance: &self.instance,
            mode: self.mode,
            kind: d.rule.kind,
            rule: d.rule.id,
            title: d.rule.title,
            severity: d.rule.severity,
            confidence: d.rule.confidence,
            session: d.session.as_ref(),
            source: d.ctx.as_ref().map(|c| &c.source),
            request: d.ctx.as_ref().map(|c| &c.request),
            evidence: &d.evidence,
            mitre_attack: d.rule.attack,
            untrusted: UNTRUSTED,
            prev_hash: &self.prev,
        };
        let body = serde_json::to_string(&body).expect("event serialisation cannot fail");
        let hash = sha256_hex(&[self.prev.as_bytes(), b"\n", body.as_bytes()]);
        let mut line = body;
        line.pop(); // trailing '}'
        line.push_str(",\"hash\":\"");
        line.push_str(&hash);
        line.push_str("\"}");
        self.prev = hash;
        out.push(line);
    }
}

/// Verify a sequence of event lines from one engine instance. Returns the
/// index of the first line that breaks the chain.
pub fn verify_chain(lines: &[&str]) -> Result<(), usize> {
    const SUFFIX_LEN: usize = 9 + 64 + 2; // ,"hash":" + hex + "}
    let mut expected_prev: Option<String> = None;
    for (i, line) in lines.iter().enumerate() {
        let line = line.trim_end();
        if line.len() < SUFFIX_LEN || !line.ends_with("\"}") {
            return Err(i);
        }
        let cut = line.len() - SUFFIX_LEN;
        if !line.is_char_boundary(cut) || !line[cut..].starts_with(",\"hash\":\"") {
            return Err(i);
        }
        let hash = &line[cut + 9..line.len() - 2];
        let body = format!("{}}}", &line[..cut]);
        let parsed: Value = serde_json::from_str(&body).map_err(|_| i)?;
        let prev = parsed.get("prev_hash").and_then(Value::as_str).ok_or(i)?;
        if let Some(exp) = &expected_prev {
            if exp != prev {
                return Err(i);
            }
        }
        if sha256_hex(&[prev.as_bytes(), b"\n", body.as_bytes()]) != hash {
            return Err(i);
        }
        expected_prev = Some(hash.to_string());
    }
    Ok(())
}
