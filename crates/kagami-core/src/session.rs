//! Bounded in-memory session store. Sessions are keyed by a keyed hash of
//! (IP, user agent); scores only ever go up within a session's lifetime.

use crate::config::Thresholds;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum State {
    #[default]
    Clean,
    Suspicious,
    Flagged,
}

pub const SCORE_CAP: u32 = 10_000;

pub struct Session {
    pub score: u32,
    pub state: State,
    pub last_seen: u64,
    rules: Vec<(&'static str, u32)>,
    pub not_found: VecDeque<u64>,
    pub auth_fail: VecDeque<u64>,
}

impl Session {
    fn new(now: u64) -> Self {
        Session {
            score: 0,
            state: State::Clean,
            last_seen: now,
            rules: Vec::new(),
            not_found: VecDeque::new(),
            auth_fail: VecDeque::new(),
        }
    }

    /// Record a rule hit; returns true the first time this rule fires.
    pub fn record(&mut self, rule: &'static str) -> bool {
        if let Some(e) = self.rules.iter_mut().find(|(r, _)| *r == rule) {
            e.1 += 1;
            false
        } else {
            self.rules.push((rule, 1));
            true
        }
    }

    pub fn add(&mut self, points: u32) {
        self.score = (self.score + points).min(SCORE_CAP);
    }

    pub fn update_state(&mut self, t: &Thresholds, instant_flag: bool) {
        let next = if instant_flag || self.score >= t.flagged {
            State::Flagged
        } else if self.score >= t.suspicious {
            State::Suspicious
        } else {
            State::Clean
        };
        self.state = self.state.max(next);
    }

    pub fn rule_ids(&self) -> Vec<&'static str> {
        self.rules.iter().map(|(r, _)| *r).collect()
    }
}

pub struct Store {
    map: HashMap<String, Session>,
    max: usize,
    ttl_ms: u64,
}

impl Store {
    pub fn new(max: usize, ttl_secs: u64) -> Self {
        Store {
            map: HashMap::new(),
            max,
            ttl_ms: ttl_secs * 1000,
        }
    }

    pub fn get_mut(&mut self, id: &str, now: u64) -> &mut Session {
        let expired = self
            .map
            .get(id)
            .is_some_and(|s| now.saturating_sub(s.last_seen) > self.ttl_ms);
        if expired {
            self.map.remove(id);
        }
        if !self.map.contains_key(id) {
            if self.map.len() >= self.max {
                self.evict(now);
            }
            self.map.insert(id.to_string(), Session::new(now));
        }
        let s = self.map.get_mut(id).expect("inserted above");
        s.last_seen = s.last_seen.max(now);
        s
    }

    pub fn peek(&self, id: &str) -> (u32, State) {
        self.map
            .get(id)
            .map(|s| (s.score, s.state))
            .unwrap_or((0, State::Clean))
    }

    /// Find a live session whose id starts with the given hex prefix.
    pub fn find_prefix(&self, prefix: &str) -> Option<String> {
        self.map.keys().find(|k| k.starts_with(prefix)).cloned()
    }

    fn evict(&mut self, now: u64) {
        let ttl = self.ttl_ms;
        self.map
            .retain(|_, s| now.saturating_sub(s.last_seen) <= ttl);
        if self.map.len() >= self.max {
            // Drop the least recently seen 10%, but never evict flagged
            // sessions before clean ones: attackers cannot flush their record
            // by flooding new sessions.
            let mut order: Vec<(State, u64, String)> = self
                .map
                .iter()
                .map(|(k, s)| (s.state, s.last_seen, k.clone()))
                .collect();
            order.sort();
            for (_, _, k) in order.into_iter().take(self.max / 10 + 1) {
                self.map.remove(&k);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_prefers_clean_sessions() {
        let mut st = Store::new(100, 3600);
        st.get_mut("attacker", 0).state = State::Flagged;
        for i in 0..200u64 {
            st.get_mut(&format!("s{i}"), i + 1);
        }
        assert!(st.len() <= 100);
        assert_eq!(st.peek("attacker").1, State::Flagged);
    }

    #[test]
    fn state_never_downgrades() {
        let mut s = Session::new(0);
        let t = Thresholds::default();
        s.add(80);
        s.update_state(&t, false);
        assert_eq!(s.state, State::Flagged);
        s.score = 0;
        s.update_state(&t, false);
        assert_eq!(s.state, State::Flagged);
    }
}
