//! Containment. Once a machine has shown itself to be an attacker, it is cut
//! off from the live application for a while.
//!
//! Deception alone cannot protect a site that has real flaws, because an
//! agent that believes a decoy can still find the real issue later. In every
//! live benchmark round the attacker's machine was identified within its
//! first 35 requests, and over 99 % of its traffic came after that point.
//! Containment acts on that identification. A contained machine never
//! reaches the application's handlers again until the containment expires.
//!
//! Two stores live here. [`Contained`] records which machines are cut off.
//! [`Shadow`] holds copies of public responses that a contained machine is
//! served instead of the live application.

use serde::Serialize;
use std::collections::HashMap;

/// One contained machine.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// Keyed hash of the machine's address (the session source).
    pub source: String,
    /// What an edge firewall should block. An IPv4 address or an IPv6 /64.
    /// Empty when the address is unknown, for example for a machine linked
    /// through a honeytoken before Lurensic saw its address.
    pub target: String,
    /// The target is a public address. Enforcers outside the application,
    /// such as an edge firewall, act only on public targets, so a bench run
    /// from loopback or a visitor on a private network is never pushed out.
    pub public: bool,
    /// Rule that started the containment.
    pub reason: &'static str,
    pub since_ms: u64,
    pub until_ms: u64,
}

/// Contained machines, bounded in size. When full, the entry closest to
/// expiry is dropped first.
pub struct Contained {
    map: HashMap<String, Entry>,
    max: usize,
}

impl Contained {
    pub fn new(max: usize) -> Self {
        Contained {
            map: HashMap::new(),
            max,
        }
    }

    pub fn is_contained(&mut self, source: &str, now: u64) -> bool {
        match self.map.get(source) {
            Some(e) if e.until_ms > now => true,
            Some(_) => {
                self.map.remove(source);
                false
            }
            None => false,
        }
    }

    /// Contain `source` until `now + ttl_ms`. Returns the entry when the
    /// machine was not contained before, so the caller can announce it. A
    /// machine that is already contained has its expiry extended silently.
    pub fn contain(
        &mut self,
        source: &str,
        target: &str,
        public: bool,
        reason: &'static str,
        now: u64,
        ttl_ms: u64,
    ) -> Option<Entry> {
        let until = now.saturating_add(ttl_ms);
        if self.is_contained(source, now) {
            let e = self.map.get_mut(source).expect("checked above");
            e.until_ms = e.until_ms.max(until);
            if e.target.is_empty() {
                e.target = target.to_string();
                e.public = public;
            }
            return None;
        }
        if self.map.len() >= self.max {
            self.map.retain(|_, e| e.until_ms > now);
            if self.map.len() >= self.max {
                let oldest = self
                    .map
                    .iter()
                    .min_by_key(|(k, e)| (e.until_ms, (*k).clone()))
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    self.map.remove(&k);
                }
            }
        }
        let e = Entry {
            source: source.to_string(),
            target: target.to_string(),
            public,
            reason,
            since_ms: now,
            until_ms: until,
        };
        self.map.insert(source.to_string(), e.clone());
        Some(e)
    }

    /// Add a containment that another instance recorded in a shared store.
    /// Nothing is announced, because the instance that contained the machine
    /// already did. A machine that is already contained keeps the later
    /// expiry. Returns true when the machine was not contained here before.
    pub fn restore(&mut self, e: &Entry, now: u64) -> bool {
        if e.source.is_empty() || e.until_ms <= now {
            return false;
        }
        let fresh = self
            .contain(
                &e.source,
                &e.target,
                e.public,
                e.reason,
                now,
                e.until_ms - now,
            )
            .is_some();
        if fresh {
            if let Some(cur) = self.map.get_mut(&e.source) {
                cur.since_ms = e.since_ms.min(now);
            }
        }
        fresh
    }

    /// Release machines whose source or target equals `key`.
    pub fn release(&mut self, key: &str) -> Vec<Entry> {
        let keys: Vec<String> = self
            .map
            .iter()
            .filter(|(s, e)| s.as_str() == key || (!e.target.is_empty() && e.target == key))
            .map(|(s, _)| s.clone())
            .collect();
        keys.iter().filter_map(|k| self.map.remove(k)).collect()
    }

    /// Live entries, soonest expiry first.
    pub fn list(&mut self, now: u64) -> Vec<Entry> {
        self.map.retain(|_, e| e.until_ms > now);
        let mut v: Vec<Entry> = self.map.values().cloned().collect();
        v.sort_by(|a, b| (a.until_ms, &a.source).cmp(&(b.until_ms, &b.source)));
        v
    }
}

/// A stored public response.
#[derive(Debug, Clone)]
pub struct Stored {
    pub status: u16,
    pub content_type: String,
    pub location: String,
    pub body: String,
    stored_ms: u64,
}

/// How the app answers failed posts to one method and path.
#[derive(Debug, Default)]
struct Failure {
    /// The first answer seen, with the hash of the request body that got it.
    pending: Option<(String, Stored)>,
    /// An answer two different submissions both received.
    confirmed: Option<Stored>,
}

/// Statuses a failed form post may answer with and that are safe to replay.
const FAILURE_STATUSES: &[u16] = &[200, 302, 303, 400, 401, 403, 404, 405, 409, 422];
/// The largest failure answer kept, and how many paths are remembered.
const MAX_FAILURE_BODY: usize = 16 * 1024;
const MAX_FAILURES: usize = 64;

/// Statuses a shared cache may keep and that are safe to replay.
const REPLAYABLE: &[u16] = &[200, 301, 302, 303, 307, 308, 401, 404, 410];
/// The largest body the shadow keeps.
pub const MAX_BODY: usize = 64 * 1024;
/// How long a stored response is kept before it is refreshed from live traffic.
const REFRESH_MS: u64 = 5 * 60 * 1000;

/// Copies of public responses for contained machines.
///
/// Only responses that a shared HTTP cache could store are kept. That means
/// a GET request without a cookie or an `Authorization` header, a response
/// without `Set-Cookie`, and no `Cache-Control: private` or `no-store`.
/// Anything Lurensic replays was already public, so a contained attacker sees
/// nothing that any anonymous visitor could not see.
///
/// The one exception is how the app answers a failed form post, such as a
/// wrong password, so a contained attacker's login looks like the app's own.
/// That answer is kept only for anonymous posts, and only after two
/// submissions with different bodies received byte-identical responses, which
/// shows the page does not repeat what the visitor sent. Lurensic keeps a hash
/// of each request body for that comparison and never the body itself.
pub struct Shadow {
    map: HashMap<String, Stored>,
    failures: HashMap<String, Failure>,
    not_found_html: Option<Stored>,
    not_found_json: Option<Stored>,
    bytes: usize,
    budget: usize,
}

/// Response headers the host passes with a response, lowercased.
pub struct ResponseMeta<'a> {
    pub status: u16,
    pub content_type: &'a str,
    pub location: &'a str,
    pub cache_control: &'a str,
    pub set_cookie: bool,
    pub body: &'a str,
}

fn replayable_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ["text/html", "json", "text/plain", "xml"]
        .iter()
        .any(|t| ct.contains(t))
}

fn same_origin(location: &str) -> bool {
    location.is_empty() || (location.starts_with('/') && !location.starts_with("//"))
}

impl Shadow {
    pub fn new(budget: usize) -> Self {
        Shadow {
            map: HashMap::new(),
            failures: HashMap::new(),
            not_found_html: None,
            not_found_json: None,
            bytes: 0,
            budget,
        }
    }

    pub fn key(norm_path: &str, query: &str) -> String {
        if query.is_empty() {
            norm_path.to_string()
        } else {
            format!("{norm_path}?{query}")
        }
    }

    /// Should the host send the response for this key? True when nothing is
    /// stored yet or the copy is older than the refresh interval.
    pub fn wants(&self, key: &str, now: u64) -> bool {
        self.budget > 0
            && self
                .map
                .get(key)
                .map_or(true, |s| now.saturating_sub(s.stored_ms) > REFRESH_MS)
    }

    /// Store a response if it may be replayed. Returns whether it was kept.
    pub fn remember(&mut self, key: &str, m: &ResponseMeta, now: u64) -> bool {
        let cc = m.cache_control.to_ascii_lowercase();
        let ok = REPLAYABLE.contains(&m.status)
            && !m.set_cookie
            && !cc.contains("private")
            && !cc.contains("no-store")
            && m.body.len() <= MAX_BODY
            && (!m.body.is_empty() || (300..400).contains(&m.status))
            && same_origin(m.location)
            && (replayable_type(m.content_type)
                || (m.body.is_empty() && (300..400).contains(&m.status)));
        if !ok || self.budget == 0 {
            return false;
        }
        let stored = Stored {
            status: m.status,
            content_type: m.content_type.to_string(),
            location: m.location.to_string(),
            body: m.body.to_string(),
            stored_ms: now,
        };
        if m.status == 404 {
            if m.content_type.to_ascii_lowercase().contains("json") {
                self.not_found_json = Some(stored.clone());
            } else {
                self.not_found_html = Some(stored.clone());
            }
        }
        let size =
            key.len() + stored.body.len() + stored.content_type.len() + stored.location.len();
        if size > self.budget {
            return false;
        }
        if let Some(old) = self.map.remove(key) {
            self.bytes -= key.len() + old.body.len() + old.content_type.len() + old.location.len();
        }
        while self.bytes + size > self.budget && !self.map.is_empty() {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(k, s)| (s.stored_ms, (*k).clone()))
                .map(|(k, _)| k.clone())
                .expect("map is not empty");
            let s = self.map.remove(&oldest).expect("present");
            self.bytes -= oldest.len() + s.body.len() + s.content_type.len() + s.location.len();
        }
        self.bytes += size;
        self.map.insert(key.to_string(), stored);
        true
    }

    pub fn get(&self, key: &str) -> Option<&Stored> {
        self.map.get(key)
    }

    /// The key for how the app answers failed posts to one method and path.
    pub fn failure_key(method: &str, norm_path: &str) -> String {
        format!("{} {norm_path}", method.to_ascii_uppercase())
    }

    /// Should the host send the response to this post? True until the app's
    /// failure answer is confirmed, and again when it is due for a refresh.
    pub fn wants_failure(&self, key: &str, now: u64) -> bool {
        if self.budget == 0 {
            return false;
        }
        match self.failures.get(key) {
            None => self.failures.len() < MAX_FAILURES,
            Some(f) => f
                .confirmed
                .as_ref()
                .map_or(true, |s| now.saturating_sub(s.stored_ms) > REFRESH_MS),
        }
    }

    /// Note the app's answer to an anonymous post. `request_hash` identifies
    /// the request body. Returns true when this answer confirms a failure
    /// answer, because a different submission received the same bytes.
    pub fn remember_failure(
        &mut self,
        key: &str,
        request_hash: &str,
        m: &ResponseMeta,
        now: u64,
    ) -> bool {
        let cc = m.cache_control.to_ascii_lowercase();
        let ok = FAILURE_STATUSES.contains(&m.status)
            && !m.set_cookie
            && !cc.contains("private")
            && !cc.contains("no-store")
            && m.body.len() <= MAX_FAILURE_BODY
            && same_origin(m.location)
            && (replayable_type(m.content_type)
                || (m.body.is_empty() && (300..400).contains(&m.status)));
        if !ok || self.budget == 0 {
            return false;
        }
        if !self.failures.contains_key(key) && self.failures.len() >= MAX_FAILURES {
            return false;
        }
        let stored = Stored {
            status: m.status,
            content_type: m.content_type.to_string(),
            location: m.location.to_string(),
            body: m.body.to_string(),
            stored_ms: now,
        };
        let f = self.failures.entry(key.to_string()).or_default();
        let confirms = f.pending.as_ref().is_some_and(|(hash, s)| {
            hash != request_hash
                && s.status == stored.status
                && s.content_type == stored.content_type
                && s.location == stored.location
                && s.body == stored.body
        });
        if confirms {
            f.confirmed = Some(stored);
            f.pending = None;
        } else {
            f.pending = Some((request_hash.to_string(), stored));
        }
        confirms
    }

    /// The app's confirmed answer to a failed post, if any.
    pub fn failure(&self, key: &str) -> Option<&Stored> {
        self.failures.get(key)?.confirmed.as_ref()
    }

    pub fn not_found(&self, json: bool) -> Option<&Stored> {
        if json {
            self.not_found_json
                .as_ref()
                .or(self.not_found_html.as_ref())
        } else {
            self.not_found_html
                .as_ref()
                .or(self.not_found_json.as_ref())
        }
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(status: u16, body: &str) -> ResponseMeta<'_> {
        ResponseMeta {
            status,
            content_type: "text/html; charset=utf-8",
            location: "",
            cache_control: "",
            set_cookie: false,
            body,
        }
    }

    #[test]
    fn containment_expires_extends_and_releases() {
        let mut c = Contained::new(10);
        assert!(c
            .contain("s1", "198.51.100.4", true, "decoy.param", 0, 1000)
            .is_some());
        assert!(c.is_contained("s1", 999));
        assert!(c
            .contain("s1", "198.51.100.4", true, "honeytoken.used", 500, 1000)
            .is_none());
        assert!(c.is_contained("s1", 1400), "extended by the later trigger");
        assert!(!c.is_contained("s1", 1500));
        c.contain("s2", "198.51.100.5", true, "decoy.route", 0, 1000);
        assert_eq!(c.release("198.51.100.5").len(), 1);
        assert!(!c.is_contained("s2", 1));
    }

    #[test]
    fn containment_is_bounded() {
        let mut c = Contained::new(10);
        for i in 0..25u64 {
            c.contain(&format!("s{i}"), "", false, "decoy.param", i, 1000);
        }
        assert_eq!(c.list(0).len(), 10);
        assert!(c.is_contained("s24", 30), "the newest entries survive");
    }

    #[test]
    fn shadow_keeps_only_what_a_shared_cache_may_keep() {
        let mut s = Shadow::new(1 << 20);
        assert!(s.remember("/", &meta(200, "<html>home</html>"), 0));
        assert_eq!(s.get("/").unwrap().body, "<html>home</html>");
        let mut m = meta(200, "secret");
        m.set_cookie = true;
        assert!(!s.remember("/account", &m, 0));
        let mut m = meta(200, "secret");
        m.cache_control = "private, max-age=0";
        assert!(!s.remember("/account", &m, 0));
        assert!(!s.remember("/err", &meta(500, "oops"), 0));
        let mut m = meta(302, "");
        m.location = "https://evil.example/";
        m.content_type = "";
        assert!(!s.remember("/go", &m, 0), "only same-origin redirects");
        m.location = "/login";
        assert!(s.remember("/account", &m, 0));
        assert!(s.remember("/missing", &meta(404, "<h1>Not found</h1>"), 0));
        assert_eq!(s.not_found(true).unwrap().body, "<h1>Not found</h1>");
    }

    #[test]
    fn shadow_respects_its_budget_and_refreshes() {
        let mut s = Shadow::new(100);
        let body = "x".repeat(40);
        assert!(s.remember("/a", &meta(200, &body), 0));
        assert!(s.remember("/b", &meta(200, &body), 1));
        assert!(s.remember("/c", &meta(200, &body), 2));
        assert!(s.get("/a").is_none(), "oldest entry evicted");
        assert!(s.bytes() <= 100);
        assert!(!s.remember("/big", &meta(200, &"y".repeat(200)), 3));
        assert!(!s.wants("/c", 10));
        assert!(s.wants("/c", 10 + REFRESH_MS));
        assert!(s.wants("/new", 10));
    }
}
