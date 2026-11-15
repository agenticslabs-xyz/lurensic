use kagami_core::{verify_chain, Action, Config, Engine, Mode, Request, State};
use serde_json::Value;

const SECRET: &str = "kagami-test-secret-0123456789abcdef0123";
const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
const T0: u64 = 1_794_700_800_000;

fn engine(mode: Mode, tweak: impl FnOnce(&mut Config)) -> (Engine, Vec<String>) {
    let mut cfg = Config {
        secret: SECRET.into(),
        mode,
        ..Config::default()
    };
    tweak(&mut cfg);
    Engine::new(cfg, T0, "test-1").expect("valid config")
}

fn req(ip: &str, ua: &str, method: &str, target: &str) -> Request {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Request {
        now_ms: T0 + 1000,
        ip: ip.into(),
        method: method.into(),
        host: "shop.example.co.nz".into(),
        path: path.into(),
        query: query.into(),
        headers: vec![
            ("user-agent".into(), ua.into()),
            ("host".into(), "shop.example.co.nz".into()),
        ],
        ..Request::default()
    }
}

fn with_body(mut r: Request, ct: &str, body: &str) -> Request {
    r.headers.push(("content-type".into(), ct.into()));
    r.body = body.into();
    r
}

fn rules_of(events: &[String]) -> Vec<String> {
    events
        .iter()
        .map(|e| {
            serde_json::from_str::<Value>(e).unwrap()["rule"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

fn attack_battery() -> Vec<Request> {
    vec![
        req("203.0.113.9", "sqlmap/1.8", "GET", "/.env"),
        req(
            "203.0.113.9",
            "sqlmap/1.8",
            "GET",
            "/search?q=1'%20OR%20'1'%3D'1",
        ),
        req("203.0.113.9", "sqlmap/1.8", "GET", "/.git/config"),
        req(
            "203.0.113.9",
            "sqlmap/1.8",
            "GET",
            "/files?name=../../etc/passwd",
        ),
        with_body(
            req("203.0.113.9", "sqlmap/1.8", "POST", "/api/render"),
            "application/json",
            r#"{"tpl":"{{7*7}}"}"#,
        ),
    ]
}

#[test]
fn observe_mode_never_changes_anything() {
    let (mut e, _) = engine(Mode::Observe, |c| {
        c.tarpit.enabled = true;
        c.json_decoys = true;
    });
    let routes: Vec<String> =
        serde_json::from_value(e.manifest()["decoys"]["routes"].clone()).unwrap();
    let mut battery = attack_battery();
    battery.push(req("203.0.113.9", "sqlmap/1.8", "GET", &routes[0]));
    let mut saw_events = false;
    for r in &battery {
        let i = e.inspect(r);
        assert_eq!(
            i.action,
            Action::Pass,
            "observe mode must never answer a request"
        );
        assert_eq!(i.delay_ms, 0);
        assert!(!i.decorate_html && !i.decorate_json);
        saw_events |= !i.events.is_empty();
    }
    assert!(saw_events, "observe mode still detects");
    assert_eq!(e.inspect(&battery[0]).state, State::Flagged);
    assert!(e
        .decorate_html("abcd", "<html><body>x</body></html>")
        .is_none());
    assert!(e.decorate_json(r#"{"a":1}"#).is_none());
}

#[test]
fn ordinary_browsing_is_silent() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let traffic = vec![
        req("198.51.100.7", BROWSER, "GET", "/"),
        req(
            "198.51.100.7",
            BROWSER,
            "GET",
            "/products?category=jackets&sort=price_asc&page=2",
        ),
        req(
            "198.51.100.7",
            BROWSER,
            "GET",
            "/search?q=O%27Brien+rain+jacket+50%25+off",
        ),
        req("198.51.100.7", BROWSER, "GET", "/static/app.3f9a1c.js"),
        with_body(
            req("198.51.100.7", BROWSER, "POST", "/login"),
            "application/x-www-form-urlencoded",
            "email=alice%40example.com&password=Tr0ub4dor%26%273",
        ),
        with_body(
            req("198.51.100.7", BROWSER, "POST", "/api/cart"),
            "application/json",
            r#"{"items":[{"sku":"JKT-001","qty":1}],"note":"Gift wrap please; it's for my mum!"}"#,
        ),
    ];
    for r in &traffic {
        let i = e.inspect(r);
        assert!(
            i.events.is_empty(),
            "false positive on {} {}: {:?}",
            r.method,
            r.path,
            i.events
        );
        assert_eq!(i.state, State::Clean);
        assert_eq!(i.action, Action::Pass);
    }
}

#[test]
fn bait_file_honeytoken_is_attributed_across_sessions() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let probe = e.inspect(&req("203.0.113.9", "python-requests/2.32", "GET", "/.env"));
    let Action::Respond { status, body, .. } = &probe.action else {
        panic!("expected fake .env")
    };
    assert_eq!(*status, 200);
    assert_eq!(rules_of(&probe.events), vec!["bait.path"]);
    assert_eq!(probe.state, State::Suspicious);

    let password = body
        .lines()
        .find_map(|l| l.strip_prefix("ADMIN_PASSWORD="))
        .unwrap();
    // The attacker rotates IP and user agent before using the stolen password.
    let login = with_body(
        req("192.0.2.200", BROWSER, "POST", "/login"),
        "application/x-www-form-urlencoded",
        &format!("email=admin%40example.co.nz&password={password}"),
    );
    let i = e.inspect(&login);
    assert_eq!(i.state, State::Flagged);
    let rules = rules_of(&i.events);
    assert!(rules.contains(&"honeytoken.used".to_string()), "{rules:?}");
    let hit: Value = serde_json::from_str(&i.events[0]).unwrap();
    assert_eq!(hit["severity"], "critical");
    assert_eq!(hit["evidence"]["token_kind"], "env_admin_password");
    assert_eq!(hit["evidence"]["cross_source"], true);
    let probe_event: Value = serde_json::from_str(&probe.events[0]).unwrap();
    let probe_source = probe_event["session"]["source"].as_str().unwrap();
    assert_eq!(hit["evidence"]["issued_to_source"], &probe_source[..8]);
    // The original (probing) session is linked and flagged too.
    assert!(i
        .events
        .iter()
        .any(|ev| ev.contains("linked_from_session") && ev.contains(&probe.session)));
    // No secret material reaches the log, because the password is masked.
    assert!(i.events.iter().all(|ev| !ev.contains(password)));
}

#[test]
fn html_comment_leads_to_decoy_route() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let page = e.inspect(&req("203.0.113.50", "Mozilla/5.0 agent", "GET", "/"));
    assert!(page.decorate_html);
    let html = e
        .decorate_html(
            &page.session,
            "<!doctype html><html><head></head><body><h1>Shop</h1></body></html>",
        )
        .unwrap();
    let comment = &html[html.find("<!--").unwrap()..html.find("-->").unwrap()];
    let route = comment
        .split_whitespace()
        .find(|w| w.starts_with('/'))
        .unwrap()
        .trim_end_matches([',', '?', ';']);
    let route = route.split('?').next().unwrap();
    let key = comment.split("sk_live_").nth(1).unwrap()[..24].to_string();

    let mut no_auth = req("203.0.113.50", "Mozilla/5.0 agent", "GET", route);
    let i = e.inspect(&no_auth);
    assert!(matches!(i.action, Action::Respond { status: 401, .. }));
    assert_eq!(rules_of(&i.events), vec!["decoy.route"]);

    no_auth
        .headers
        .push(("authorization".into(), format!("Bearer sk_live_{key}")));
    let i = e.inspect(&no_auth);
    let Action::Respond { status, body, .. } = &i.action else {
        panic!()
    };
    assert_eq!(*status, 200);
    let data: Value = serde_json::from_str(body).unwrap();
    assert_eq!(data["data"].as_array().unwrap().len(), 25);
    assert_eq!(data["has_more"], true);
    assert_eq!(i.state, State::Flagged);
    assert!(rules_of(&i.events).contains(&"honeytoken.used".to_string()));
}

#[test]
fn json_decoy_detects_mass_assignment_but_not_echo() {
    let (mut e, _) = engine(Mode::Protect, |c| c.json_decoys = true);
    let m = e.manifest();
    let field = m["decoys"]["json_field"].as_str().unwrap().to_string();
    let value = m["decoys"]["json_value"].as_str().unwrap().to_string();
    let decorated = e.decorate_json(r#"{"id":7,"email":"a@b.c"}"#).unwrap();
    assert!(decorated.contains(&field));

    let honest = with_body(
        req("198.51.100.7", BROWSER, "PUT", "/api/me"),
        "application/json",
        &format!(r#"{{"{field}":"{value}","id":7,"email":"new@b.c"}}"#),
    );
    assert!(
        e.inspect(&honest).events.is_empty(),
        "echoing the decoy value unchanged is not an attack"
    );

    let attack = with_body(
        req("203.0.113.9", "curl/8.9", "PATCH", "/api/me"),
        "application/json",
        &format!(r#"{{"{field}":"admin"}}"#),
    );
    let i = e.inspect(&attack);
    assert_eq!(i.state, State::Flagged);
    assert_eq!(rules_of(&i.events), vec!["decoy.param", "session.flagged"]);
}

#[test]
fn enumeration_and_seal_tampering() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    let mut events = Vec::new();
    for n in 0..20 {
        let mut r = req(
            "203.0.113.9",
            "Mozilla/5.0",
            "GET",
            &format!("/old-page-{n}"),
        );
        r.status = 404;
        events.extend(e.response(&r).events);
    }
    assert_eq!(rules_of(&events), vec!["behavior.enumeration"]);

    let sealed = e.seal("1043");
    let r = req("198.51.100.7", BROWSER, "GET", "/orders");
    assert_eq!(
        e.verify_sealed(&r, &sealed, "order").value.as_deref(),
        Some("1043")
    );
    let forged = sealed.replace("1043", "1044");
    let out = e.verify_sealed(&r, &forged, "order");
    assert!(!out.valid);
    assert_eq!(
        rules_of(&out.events),
        vec!["tamper.sealed_value", "session.flagged"]
    );
}

#[test]
fn event_log_is_hash_chained_and_tamper_evident() {
    let (mut e, mut lines) = engine(Mode::Protect, |_| {});
    for r in attack_battery() {
        lines.extend(e.inspect(&r).events);
    }
    assert!(lines.len() >= 5);
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    assert_eq!(verify_chain(&refs), Ok(()));

    let mut edited = refs.clone();
    // An intruder quietly downgrades an event.
    let tampered = lines[2].replacen("\"severity\":\"", "\"severity\":\"info\",\"was\":\"", 1);
    assert_ne!(tampered, lines[2]);
    edited[2] = &tampered;
    assert_eq!(verify_chain(&edited), Err(2));

    let mut deleted = refs.clone();
    deleted.remove(2);
    assert_eq!(verify_chain(&deleted), Err(2));
}

#[test]
fn logs_are_safe_against_hostile_input() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    let mut r = req(
        "203.0.113.9",
        "evil\x1b[2J\r\n{\"rule\":\"fake\"}\u{202E}agent sqlmap",
        "GET",
        "/search?q=%27%20OR%201%3D1--&password=hunter2&session_token=abc",
    );
    r.headers
        .push(("cookie".into(), "sid=1'%20OR%201=1--".into()));
    let i = e.inspect(&r);
    assert!(!i.events.is_empty());
    for line in &i.events {
        assert!(!line.contains('\n') && !line.contains('\r'));
        let v: Value = serde_json::from_str(line).unwrap();
        let ua = v["source"]["user_agent"].as_str().unwrap();
        assert!(!ua.chars().any(|c| c.is_control() || c == '\u{202E}'));
        assert!(
            !line.contains("hunter2"),
            "sensitive query values must be redacted"
        );
        assert!(!line.contains("abc&"), "token values must be redacted");
        assert_eq!(v["untrusted"].as_array().unwrap().len(), 5);
    }
}

#[test]
fn rate_limit_protects_the_pipeline() {
    let (mut e, _) = engine(Mode::Observe, |c| c.max_events_per_minute = 5);
    let mut events = Vec::new();
    for n in 0..50 {
        events.extend(
            e.inspect(&req(&format!("203.0.113.{n}"), "nuclei", "GET", "/.env"))
                .events,
        );
    }
    assert!(events.len() <= 6, "got {}", events.len());
    let mut later = req("203.0.113.250", "nuclei", "GET", "/.env");
    later.now_ms += 60_000;
    let next = e.inspect(&later).events;
    assert_eq!(rules_of(&next)[0], "system.events_suppressed");
}

#[test]
fn config_errors_are_helpful() {
    let err = Engine::new(
        Config {
            secret: "short".into(),
            ..Config::default()
        },
        0,
        "x",
    )
    .err()
    .unwrap();
    assert_eq!(err.code, "secret_too_short");
    assert!(err.message.contains("npx @agenticslabs/kagami secret"));
    let err = Engine::new(Config::default(), 0, "x").err().unwrap();
    assert_eq!(err.code, "secret_missing");
}

#[test]
fn decoys_are_per_deployment() {
    let (a, _) = engine(Mode::Protect, |_| {});
    let (b, _) = engine(Mode::Protect, |c| {
        c.secret = "a-completely-different-secret-for-deploy-2".into()
    });
    assert_ne!(a.manifest()["decoys"], b.manifest()["decoys"]);
    assert_ne!(a.deployment(), b.deployment());
}

// Regression tests from the first live benchmark round (2026-11-15).

#[test]
fn forged_forwarding_headers_are_detected() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    // Values the attacking agent actually sent in X-Forwarded-For.
    for (n, forged) in [
        "<script>alert(1)</script>",
        "ZZZMARKER999",
        "127.0.0.1%0d%0aX-Injected: yes",
        "localhost",
        "127.0.0.1/8",
        "999.999.999.999",
        "${7*7}",
    ]
    .into_iter()
    .enumerate()
    {
        // A separate client per case, because each rule reports once per session.
        let mut r = req(&format!("203.0.113.{n}"), "curl/8.9", "GET", "/");
        r.headers.push(("x-forwarded-for".into(), forged.into()));
        let rules = rules_of(&e.inspect(&r).events);
        assert!(
            rules.contains(&"client.forged_forwarding".to_string()),
            "{forged:?} not detected: {rules:?}"
        );
    }
    // Headers real proxy chains produce must stay clean.
    for real in [
        "203.0.113.5",
        "203.0.113.5, 10.0.0.1",
        "unknown, 198.51.100.4",
        "[2001:db8::1]:4711",
        "198.51.100.4:8443",
    ] {
        let mut r = req("198.51.100.77", BROWSER, "GET", "/");
        r.headers.push(("x-forwarded-for".into(), real.into()));
        assert!(
            e.inspect(&r).events.is_empty(),
            "false positive on {real:?}"
        );
    }
    let mut r = req("198.51.100.78", BROWSER, "GET", "/");
    r.headers.push((
        "forwarded".into(),
        "for=\"[2001:db8:cafe::17]:4711\";proto=https, for=unknown, for=_hidden".into(),
    ));
    assert!(e.inspect(&r).events.is_empty());
}

#[test]
fn malformed_bodies_are_inspected_and_signalled() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    let mut r = with_body(
        req("203.0.113.9", "curl/8.9", "POST", "/login"),
        "text/plain",
        "{\"email\":\"' OR 1=1--\",",
    );
    r.body_error = "entity.parse.failed".into();
    let rules = rules_of(&e.inspect(&r).events);
    assert!(
        rules.contains(&"request.malformed_body".to_string()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"payload.sqli".to_string()),
        "payload inside a broken body: {rules:?}"
    );
}

#[test]
fn bait_comment_is_identical_across_tools_on_one_machine() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let page = "<!doctype html><html><body><h1>Shop</h1></body></html>";
    let html = |e: &mut Engine, ip: &str, ua: &str| {
        let i = e.inspect(&req(ip, ua, "GET", "/"));
        let out = e.decorate_html(&i.session, page).unwrap();
        out[out.find("<!--").unwrap()..out.find("-->").unwrap()].to_string()
    };
    let curl = html(&mut e, "203.0.113.9", "curl/8.9");
    let python = html(&mut e, "203.0.113.9", "Python-urllib/3.12");
    let empty = html(&mut e, "203.0.113.9", "");
    assert_eq!(
        curl, python,
        "same machine, different tool: comment must not change"
    );
    assert_eq!(curl, empty);
    // Another network gets the same wording and route with a different key.
    let other = html(&mut e, "198.51.100.4", "curl/8.9");
    assert_ne!(curl, other);
    let strip_key = |s: &str| {
        let k = s.find("sk_live_").unwrap();
        format!("{}{}", &s[..k], &s[k + 8 + 24..])
    };
    assert_eq!(strip_key(&curl), strip_key(&other));
}

#[test]
fn nested_jndi_lookup_is_detected() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    let r = req(
        "203.0.113.9",
        "curl/8.9",
        "GET",
        "/search?q=%24%7B%7Bjndi%3Aldap%3A%2F%2Fx%7D%7D",
    );
    assert!(rules_of(&e.inspect(&r).events).contains(&"payload.jndi".to_string()));
}
