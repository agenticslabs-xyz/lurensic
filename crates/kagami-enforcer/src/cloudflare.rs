//! Cloudflare provider. Contained machines go into a custom IP list, and a
//! WAF custom rule with the expression `ip.src in $kagami_contained` blocks
//! or challenges them at the edge. IP lists and custom rules are available on
//! every Cloudflare plan.
//!
//! API reference: https://developers.cloudflare.com/waf/tools/lists/lists-api/endpoints/
//!
//! Items Kagami adds carry a comment such as
//! `kagami until=2026-11-17T09:30:00.000Z reason=decoy.param by=web-1`.
//! Items without the `kagami ` prefix are never changed, so the list can be
//! shared with entries you manage yourself. `by` names the enforcer that
//! added the item, so several enforcers, one per server, can share a list.

use crate::blocklist::Contained;
use crate::http::Http;
use kagami_core::time::{parse_rfc3339, rfc3339};
use serde_json::{json, Value};

pub const API_BASE: &str = "https://api.cloudflare.com/client/v4";
pub const COMMENT_PREFIX: &str = "kagami ";
const MAX_BATCH: usize = 1000;

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_id(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A list item Kagami added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: String,
    pub ip: String,
    pub until_ms: u64,
    pub by: Option<String>,
}

pub fn comment(c: &Contained, by: &str) -> String {
    format!(
        "{COMMENT_PREFIX}until={} reason={} by={by}",
        rfc3339(c.until_ms),
        c.reason
    )
    .chars()
    .take(500)
    .collect()
}

/// Read a Kagami comment. Returns `None` for items Kagami did not add.
pub fn parse_comment(comment: &str) -> Option<(u64, Option<String>)> {
    let rest = comment.strip_prefix(COMMENT_PREFIX)?;
    let mut until = None;
    let mut by = None;
    for part in rest.split_whitespace() {
        if let Some(v) = part.strip_prefix("until=") {
            until = parse_rfc3339(v);
        } else if let Some(v) = part.strip_prefix("by=") {
            by = Some(v.to_string());
        }
    }
    Some((until?, by))
}

pub struct Client<'a> {
    http: &'a dyn Http,
    token: String,
    account: String,
    base: String,
    sleep: Box<dyn Fn(u64) + 'a>,
}

impl<'a> Client<'a> {
    pub fn new(http: &'a dyn Http, token: &str, account: &str) -> Result<Self, Error> {
        if token.trim().is_empty() {
            return Err(Error("Set CLOUDFLARE_API_TOKEN to an API token with the account permission \"Account Filter Lists Edit\".".into()));
        }
        if !is_id(account) {
            return Err(Error("The Cloudflare account id must be 32 hex characters (CLOUDFLARE_ACCOUNT_ID or --account).".into()));
        }
        Ok(Client {
            http,
            token: token.trim().to_string(),
            account: account.to_string(),
            base: API_BASE.to_string(),
            sleep: Box::new(|ms| std::thread::sleep(std::time::Duration::from_millis(ms))),
        })
    }

    /// For tests. Point at another base URL and skip real waiting.
    pub fn for_test(mut self, base: &str) -> Self {
        self.base = base.to_string();
        self.sleep = Box::new(|_| {});
        self
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, Error> {
        let url = format!("{}/accounts/{}{path}", self.base, self.account);
        let mut last = Error("no attempt was made".into());
        for attempt in 0..4u32 {
            match self.http.send(method, &url, &self.token, body) {
                Err(e) => {
                    last = Error(format!("Cloudflare API {method} failed. {e}"));
                }
                Ok(r) if (200..300).contains(&r.status) && r.body["success"] == json!(true) => {
                    return Ok(r.body);
                }
                Ok(r) => {
                    let errors: Vec<String> = r.body["errors"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .map(|e| {
                                    format!("{} {}", e["code"], e["message"].as_str().unwrap_or(""))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let detail = if errors.is_empty() {
                        format!("HTTP {}", r.status)
                    } else {
                        errors.join("; ")
                    };
                    last = Error(format!("Cloudflare API {method} failed. {detail}"));
                    if r.status != 429 && r.status < 500 {
                        return Err(last);
                    }
                    if let Some(s) = r.retry_after {
                        (self.sleep)(s.min(60) * 1000);
                        continue;
                    }
                }
            }
            (self.sleep)(1000 * 2u64.pow(attempt));
        }
        Err(last)
    }

    /// Wait until an asynchronous list operation has finished.
    fn wait(&self, operation_id: &str) -> Result<(), Error> {
        let mut delay = 250u64;
        for _ in 0..60 {
            let r = self.call(
                "GET",
                &format!("/rules/lists/bulk_operations/{operation_id}"),
                None,
            )?;
            match r["result"]["status"].as_str() {
                Some("completed") => return Ok(()),
                Some("failed") => {
                    return Err(Error(format!(
                        "Cloudflare list operation failed. {}",
                        r["result"]["error"].as_str().unwrap_or("")
                    )))
                }
                _ => {
                    (self.sleep)(delay);
                    delay = (delay * 2).min(4000);
                }
            }
        }
        Err(Error(
            "Cloudflare list operation did not finish in time.".into(),
        ))
    }

    pub fn find_list(&self, name: &str) -> Result<Option<String>, Error> {
        let r = self.call("GET", "/rules/lists", None)?;
        Ok(r["result"]
            .as_array()
            .and_then(|a| a.iter().find(|l| l["name"] == json!(name)))
            .and_then(|l| l["id"].as_str().map(str::to_string)))
    }

    pub fn create_list(&self, name: &str) -> Result<String, Error> {
        let body = json!({
            "name": name,
            "kind": "ip",
            "description": "Machines contained by Kagami. Entries expire and are removed automatically.",
        });
        let r = self.call("POST", "/rules/lists", Some(&body))?;
        r["result"]["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error("Cloudflare did not return the new list id.".into()))
    }

    /// Every item in the list, following cursor pagination.
    pub fn items(&self, list: &str) -> Result<Vec<(String, String, String)>, Error> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..1000 {
            let mut path = format!("/rules/lists/{list}/items?per_page=500");
            if let Some(c) = &cursor {
                path.push_str("&cursor=");
                path.push_str(c);
            }
            let r = self.call("GET", &path, None)?;
            let page = r["result"].as_array().cloned().unwrap_or_default();
            for i in &page {
                out.push((
                    i["id"].as_str().unwrap_or("").to_string(),
                    i["ip"].as_str().unwrap_or("").to_string(),
                    i["comment"].as_str().unwrap_or("").to_string(),
                ));
            }
            cursor = r["result_info"]["cursors"]["after"]
                .as_str()
                .filter(|c| {
                    c.chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "-_=".contains(ch))
                })
                .map(str::to_string);
            if cursor.is_none() || page.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    /// Items Kagami added.
    pub fn kagami_items(&self, list: &str) -> Result<Vec<Item>, Error> {
        Ok(self
            .items(list)?
            .into_iter()
            .filter_map(|(id, ip, c)| {
                let (until_ms, by) = parse_comment(&c)?;
                Some(Item {
                    id,
                    ip,
                    until_ms,
                    by,
                })
            })
            .collect())
    }

    pub fn add(&self, list: &str, items: &[(String, String)]) -> Result<(), Error> {
        for chunk in items.chunks(MAX_BATCH) {
            let body: Value = chunk
                .iter()
                .map(|(ip, comment)| json!({"ip": ip, "comment": comment}))
                .collect();
            let r = self.call("POST", &format!("/rules/lists/{list}/items"), Some(&body))?;
            self.wait(r["result"]["operation_id"].as_str().unwrap_or(""))?;
        }
        Ok(())
    }

    pub fn delete(&self, list: &str, ids: &[String]) -> Result<(), Error> {
        for chunk in ids.chunks(MAX_BATCH) {
            let body =
                json!({"items": chunk.iter().map(|id| json!({"id": id})).collect::<Vec<_>>()});
            let r = self.call("DELETE", &format!("/rules/lists/{list}/items"), Some(&body))?;
            self.wait(r["result"]["operation_id"].as_str().unwrap_or(""))?;
        }
        Ok(())
    }
}

/// What a sync changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub added: usize,
    pub removed_expired: usize,
    pub removed_released: usize,
    pub removed_duplicates: usize,
    pub active: usize,
}

/// Make the list match the blocklist.
///
/// - Every live, public entry in the blocklist is in the list, with an expiry
///   at least as late.
/// - Expired Kagami items are removed, whoever added them.
/// - Duplicate Kagami items for one address are reduced to the latest.
/// - Items this enforcer (`by`) added are removed once they leave the
///   blocklist, which is how an early release reaches Cloudflare. Items other
///   enforcers added are left to them.
pub fn sync(
    client: &Client,
    list: &str,
    desired: &[Contained],
    by: &str,
    now_ms: u64,
) -> Result<SyncReport, Error> {
    if !is_id(list) {
        return Err(Error(
            "The list id must be 32 hex characters (KAGAMI_CLOUDFLARE_LIST_ID or --list).".into(),
        ));
    }
    let items = client.kagami_items(list)?;
    let mut report = SyncReport::default();
    let mut remove: Vec<String> = Vec::new();
    let mut latest: Vec<Item> = Vec::new();
    for i in items {
        if i.until_ms <= now_ms {
            report.removed_expired += 1;
            remove.push(i.id);
            continue;
        }
        match latest.iter_mut().find(|k| k.ip == i.ip) {
            Some(k) if k.until_ms < i.until_ms => {
                report.removed_duplicates += 1;
                remove.push(std::mem::replace(k, i).id);
            }
            Some(_) => {
                report.removed_duplicates += 1;
                remove.push(i.id);
            }
            None => latest.push(i),
        }
    }
    for k in &latest {
        let wanted = desired.iter().any(|d| d.target == k.ip);
        if !wanted && k.by.as_deref() == Some(by) {
            report.removed_released += 1;
            remove.push(k.id.clone());
        }
    }
    let mut add: Vec<(String, String)> = Vec::new();
    for d in desired {
        match latest.iter().find(|k| k.ip == d.target) {
            Some(k) if k.until_ms >= d.until_ms => {}
            Some(k) => {
                // Replace the item with a later expiry.
                remove.push(k.id.clone());
                add.push((d.target.clone(), comment(d, by)));
            }
            None => add.push((d.target.clone(), comment(d, by))),
        }
    }
    report.added = add.len();
    report.active = desired.len();
    // Add first, so a replaced address is never briefly missing from the list.
    if !add.is_empty() {
        client.add(list, &add)?;
    }
    remove.sort();
    remove.dedup();
    if !remove.is_empty() {
        client.delete(list, &remove)?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use std::cell::RefCell;

    const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LIST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NOW: u64 = 1_794_787_200_000; // 2026-11-16T00:00:00Z
    const HOUR: u64 = 3_600_000;

    /// A pending bulk operation. Its id, whether it was polled once, and the change it applies.
    type PendingOp = (String, bool, Box<dyn Fn(&FakeCloudflare)>);

    /// An in-memory model of the Cloudflare Lists API. Bulk operations stay
    /// pending for one poll, and the first call can be rate limited.
    #[derive(Default)]
    struct FakeCloudflare {
        items: RefCell<Vec<(String, String, String)>>,
        ops: RefCell<Vec<PendingOp>>,
        calls: RefCell<Vec<String>>,
        throttle_once: RefCell<bool>,
        seq: RefCell<u32>,
    }

    impl FakeCloudflare {
        fn next(&self) -> u32 {
            *self.seq.borrow_mut() += 1;
            *self.seq.borrow()
        }
        fn ok(body: Value) -> Result<Response, String> {
            Ok(Response {
                status: 200,
                body,
                retry_after: None,
            })
        }
        fn op(&self, apply: Box<dyn Fn(&FakeCloudflare)>) -> Result<Response, String> {
            let id = format!("op{}", self.next());
            self.ops.borrow_mut().push((id.clone(), false, apply));
            Self::ok(json!({"success": true, "result": {"operation_id": id}}))
        }
        fn ips(&self) -> Vec<String> {
            let mut v: Vec<String> = self.items.borrow().iter().map(|i| i.1.clone()).collect();
            v.sort();
            v
        }
    }

    impl Http for FakeCloudflare {
        fn send(
            &self,
            method: &str,
            url: &str,
            token: &str,
            body: Option<&Value>,
        ) -> Result<Response, String> {
            assert_eq!(token, "token");
            self.calls.borrow_mut().push(format!("{method} {url}"));
            if *self.throttle_once.borrow() {
                *self.throttle_once.borrow_mut() = false;
                return Ok(Response {
                    status: 429,
                    body: json!({"success": false}),
                    retry_after: Some(1),
                });
            }
            let path = url
                .trim_start_matches("https://test/accounts/")
                .trim_start_matches(ACCOUNT);
            let items_path = format!("/rules/lists/{LIST}/items");
            if let Some(id) = path.strip_prefix("/rules/lists/bulk_operations/") {
                let mut ops = self.ops.borrow_mut();
                let pos = ops.iter().position(|o| o.0 == id).expect("known op");
                if !ops[pos].1 {
                    ops[pos].1 = true;
                    return Self::ok(
                        json!({"success": true, "result": {"id": id, "status": "pending"}}),
                    );
                }
                let (_, _, apply) = ops.remove(pos);
                drop(ops);
                apply(self);
                return Self::ok(
                    json!({"success": true, "result": {"id": id, "status": "completed"}}),
                );
            }
            match (method, path) {
                ("POST", p) if p == items_path => {
                    let new: Vec<(String, String)> = body
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|i| {
                            (
                                i["ip"].as_str().unwrap().to_string(),
                                i["comment"].as_str().unwrap().to_string(),
                            )
                        })
                        .collect();
                    self.op(Box::new(move |cf: &FakeCloudflare| {
                        for (ip, c) in &new {
                            let id = format!("{:0>32}", cf.next());
                            cf.items.borrow_mut().push((id, ip.clone(), c.clone()));
                        }
                    }))
                }
                ("DELETE", p) if p == items_path => {
                    let ids: Vec<String> = body.unwrap()["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|i| i["id"].as_str().unwrap().to_string())
                        .collect();
                    self.op(Box::new(move |cf: &FakeCloudflare| {
                        cf.items.borrow_mut().retain(|i| !ids.contains(&i.0));
                    }))
                }
                ("GET", p) if p.starts_with(&items_path) => {
                    // Two items per page, to exercise cursor pagination.
                    let start: usize = p
                        .split("cursor=")
                        .nth(1)
                        .and_then(|c| c.parse().ok())
                        .unwrap_or(0);
                    let all = self.items.borrow();
                    let page: Vec<Value> = all
                        .iter()
                        .skip(start)
                        .take(2)
                        .map(|(id, ip, c)| json!({"id": id, "ip": ip, "comment": c}))
                        .collect();
                    let after = if start + 2 < all.len() {
                        json!({"after": (start + 2).to_string()})
                    } else {
                        json!({})
                    };
                    Self::ok(
                        json!({"success": true, "result": page, "result_info": {"cursors": after}}),
                    )
                }
                ("GET", "/rules/lists") => Self::ok(
                    json!({"success": true, "result": [{"id": LIST, "name": "kagami_contained"}]}),
                ),
                ("POST", "/rules/lists") => {
                    Self::ok(json!({"success": true, "result": {"id": LIST}}))
                }
                _ => Ok(Response {
                    status: 403,
                    body: json!({"success": false, "errors": [{"code": 10000, "message": "Authentication error"}]}),
                    retry_after: None,
                }),
            }
        }
    }

    fn client(cf: &FakeCloudflare) -> Client<'_> {
        Client::new(cf, "token", ACCOUNT)
            .unwrap()
            .for_test("https://test")
    }

    fn entry(target: &str, hours: u64) -> Contained {
        Contained {
            target: target.into(),
            reason: "decoy.param".into(),
            until_ms: NOW + hours * HOUR,
        }
    }

    #[test]
    fn comments_round_trip_and_foreign_items_are_ignored() {
        let c = comment(&entry("8.8.8.8", 24), "web-1");
        assert_eq!(
            c,
            "kagami until=2026-11-17T00:00:00.000Z reason=decoy.param by=web-1"
        );
        assert_eq!(
            parse_comment(&c),
            Some((NOW + 24 * HOUR, Some("web-1".into())))
        );
        assert_eq!(parse_comment("office VPN"), None);
        assert_eq!(
            parse_comment("kagami until=2026-11-17T00:00:00Z reason=x"),
            Some((NOW + 24 * HOUR, None))
        );
    }

    #[test]
    fn sync_adds_once_and_is_idempotent() {
        let cf = FakeCloudflare::default();
        *cf.throttle_once.borrow_mut() = true;
        let c = client(&cf);
        let desired = [entry("8.8.8.8", 24), entry("2a01:4f8:1:2::/64", 24)];
        let r = sync(&c, LIST, &desired, "web-1", NOW).unwrap();
        assert_eq!(r.added, 2);
        assert_eq!(cf.ips(), ["2a01:4f8:1:2::/64", "8.8.8.8"]);
        let again = sync(&c, LIST, &desired, "web-1", NOW).unwrap();
        assert_eq!(
            again,
            SyncReport {
                active: 2,
                ..Default::default()
            },
            "nothing to do the second time"
        );
    }

    #[test]
    fn sync_removes_expired_duplicates_and_own_releases_only() {
        let cf = FakeCloudflare::default();
        let c = client(&cf);
        sync(
            &c,
            LIST,
            &[entry("8.8.8.8", 1), entry("8.8.4.4", 24)],
            "web-1",
            NOW,
        )
        .unwrap();
        sync(&c, LIST, &[entry("9.9.9.9", 24)], "web-2", NOW).unwrap();
        cf.items
            .borrow_mut()
            .push(("f".repeat(32), "1.2.3.4".into(), "office, keep".into()));

        // Two hours later web-1 extends 8.8.8.8 and releases 8.8.4.4.
        let later = NOW + 2 * HOUR;
        let r = sync(&c, LIST, &[entry("8.8.8.8", 48)], "web-1", later).unwrap();
        assert_eq!(r.removed_expired, 1, "the first 8.8.8.8 item expired");
        assert_eq!(r.removed_released, 1, "8.8.4.4 was released by web-1");
        assert_eq!(r.added, 1);
        assert_eq!(
            cf.ips(),
            ["1.2.3.4", "8.8.8.8", "9.9.9.9"],
            "web-2's entry and the manual entry stay"
        );
    }

    #[test]
    fn a_later_expiry_replaces_the_item() {
        let cf = FakeCloudflare::default();
        let c = client(&cf);
        sync(&c, LIST, &[entry("8.8.8.8", 24)], "web-1", NOW).unwrap();
        sync(&c, LIST, &[entry("8.8.8.8", 48)], "web-1", NOW).unwrap();
        let items = c.kagami_items(LIST).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].until_ms, NOW + 48 * HOUR);
    }

    #[test]
    fn errors_are_clear_and_never_contain_the_token() {
        let cf = FakeCloudflare::default();
        assert!(Client::new(&cf, "", ACCOUNT).is_err());
        assert!(Client::new(&cf, "token", "short").is_err());
        let c = client(&cf);
        assert!(sync(&c, "not-a-list", &[], "web-1", NOW).is_err());
        let err = c.call("GET", "/somewhere/else", None).unwrap_err().0;
        assert!(err.contains("10000 Authentication error"), "{err}");
        assert!(!err.contains("token"));
        assert_eq!(
            c.find_list("kagami_contained").unwrap().as_deref(),
            Some(LIST)
        );
    }
}
