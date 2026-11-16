//! Reads the JSON blocklist that Kagami adapters write.
//!
//! ```json
//! {
//!   "generated_at": "2026-11-16T09:30:00.000Z",
//!   "entries": [
//!     { "target": "198.51.100.4", "reason": "decoy.param",
//!       "since": "2026-11-16T09:29:58.000Z", "until": "2026-11-17T09:29:58.000Z" }
//!   ]
//! }
//! ```
//!
//! `target` is an address or an IPv6 /64. Entries that have expired, or whose
//! target is not a public address, are dropped, so a private network or a
//! loopback test is never pushed to an edge provider.

use kagami_core::net::{is_public, parse_ip};
use kagami_core::time::parse_rfc3339;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contained {
    pub target: String,
    pub reason: String,
    pub until_ms: u64,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    entries: Vec<RawEntry>,
}

#[derive(Deserialize)]
struct RawEntry {
    #[serde(default)]
    target: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    until: String,
}

/// The address part of a target, for `198.51.100.4` or `2001:db8:1:2::/64`.
fn target_is_public(target: &str) -> bool {
    let addr = target.split('/').next().unwrap_or("");
    parse_ip(addr).is_some_and(|ip| is_public(&ip))
}

/// A reason is a rule id such as `decoy.param`. Anything else is replaced, so
/// the file cannot inject text into provider comments.
fn clean_reason(r: &str) -> String {
    if !r.is_empty()
        && r.len() <= 64
        && r.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
    {
        r.to_string()
    } else {
        "unknown".to_string()
    }
}

/// Parse the blocklist and keep the live, public entries, one per target.
pub fn parse(text: &str, now_ms: u64) -> Result<Vec<Contained>, String> {
    let file: File =
        serde_json::from_str(text).map_err(|e| format!("the blocklist is not valid JSON ({e})"))?;
    let mut out: Vec<Contained> = Vec::new();
    for e in file.entries {
        let Some(until_ms) = parse_rfc3339(&e.until) else {
            continue;
        };
        if until_ms <= now_ms || !target_is_public(&e.target) {
            continue;
        }
        let entry = Contained {
            target: e.target.trim().to_string(),
            reason: clean_reason(&e.reason),
            until_ms,
        };
        match out.iter_mut().find(|c| c.target == entry.target) {
            Some(c) if c.until_ms < entry.until_ms => *c = entry,
            Some(_) => {}
            None => out.push(entry),
        }
    }
    out.sort_by(|a, b| a.target.cmp(&b.target));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_794_787_200_000; // 2026-11-16T00:00:00Z

    #[test]
    fn keeps_live_public_entries() {
        let text = r#"{"entries":[
            {"target":"8.8.8.8","reason":"decoy.param","until":"2026-11-17T00:00:00.000Z"},
            {"target":"8.8.8.8","reason":"honeytoken.used","until":"2026-11-18T00:00:00.000Z"},
            {"target":"2a01:4f8:1:2::/64","reason":"decoy.route","until":"2026-11-17T00:00:00Z"},
            {"target":"9.9.9.9","reason":"decoy.param","until":"2026-11-15T00:00:00.000Z"},
            {"target":"10.0.0.5","reason":"decoy.param","until":"2026-11-17T00:00:00.000Z"},
            {"target":"127.0.0.1","reason":"decoy.param","until":"2026-11-17T00:00:00.000Z"},
            {"target":"1.1.1.1","reason":"x\" by=evil","until":"2026-11-17T00:00:00.000Z"},
            {"target":"bad","until":"2026-11-17T00:00:00.000Z"},
            {"target":"4.4.4.4","until":"not a date"}
        ]}"#;
        let got = parse(text, NOW).unwrap();
        let targets: Vec<&str> = got.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(targets, ["1.1.1.1", "2a01:4f8:1:2::/64", "8.8.8.8"]);
        assert_eq!(got[0].reason, "unknown", "reasons cannot inject text");
        assert_eq!(got[2].reason, "honeytoken.used", "the later expiry wins");
    }

    #[test]
    fn rejects_broken_files() {
        assert!(parse("not json", NOW).is_err());
        assert_eq!(parse("{}", NOW).unwrap(), vec![]);
    }
}
