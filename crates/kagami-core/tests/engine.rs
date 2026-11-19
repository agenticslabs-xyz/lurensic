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

/// The honeytoken in a fake .env, whichever service the deployment's layout uses.
fn env_credential(env: &str) -> &str {
    env.lines()
        .find_map(|l| {
            l.strip_prefix("SMTP_PASS=")
                .or_else(|| l.strip_prefix("STRIPE_SECRET_KEY=sk_live_"))
                .or_else(|| {
                    l.strip_prefix("DATABASE_URL=postgres://")
                        .and_then(|r| r.split_once(':'))
                        .and_then(|(_, r)| r.split_once('@'))
                        .map(|(pw, _)| pw)
                })
        })
        .expect("a credential in the fake .env")
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
        .decorate_html("abcd", "/", "<html><body>x</body></html>")
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

    // The fake .env holds one or two service credentials. An agent tries
    // whichever it finds as a password elsewhere on the site.
    let password = env_credential(body);
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
    assert!(hit["evidence"]["token_kind"]
        .as_str()
        .unwrap()
        .starts_with("env_"));
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
            "/",
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
    let Action::Respond {
        status: 401,
        body,
        headers,
    } = &i.action
    else {
        panic!("expected 401")
    };
    // A plain error with no hint about how to authenticate, and no realm
    // header the app itself does not send.
    assert_eq!(body, r#"{"error":"unauthorized"}"#);
    assert!(!headers.iter().any(|(k, _)| k == "www-authenticate"));
    // Only the bait leads to a decoy route, so one request flags the session.
    assert_eq!(rules_of(&i.events), vec!["decoy.route", "session.flagged"]);
    assert_eq!(i.state, State::Flagged);

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
        assert_eq!(v["untrusted"].as_array().unwrap().len(), 6);
    }
}

#[test]
fn events_name_the_subject_without_keying_on_it() {
    let (mut e, _) = engine(Mode::Protect, |c| c.json_decoys = true);
    let field = e.manifest()["decoys"]["json_field"]
        .as_str()
        .unwrap()
        .to_string();
    let mut attack = with_body(
        req("203.0.113.9", "curl/8.9", "PATCH", "/api/me"),
        "application/json",
        &format!(r#"{{"{field}":"admin"}}"#),
    );
    attack.subject = "  acct_42\r\n{\"rule\":\"x\"}  ".into();
    let i = e.inspect(&attack);
    assert!(!i.events.is_empty());
    for line in &i.events {
        let v: Value = serde_json::from_str(line).unwrap();
        let subject = v["subject"].as_str().unwrap();
        assert!(subject.starts_with("acct_42"));
        assert!(!subject.chars().any(char::is_control));
        assert!(v["untrusted"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "subject"));
    }
    let refs: Vec<&str> = i.events.iter().map(String::as_str).collect();
    assert_eq!(verify_chain(&refs), Ok(()));

    // The subject is a label. Another account on the same machine still
    // shares the session, and requests without one carry no subject field.
    let mut other = req("203.0.113.9", "curl/8.9", "GET", "/api/me");
    other.subject = "acct_7".into();
    assert_eq!(e.inspect(&other).session, i.session);
    let plain = e.inspect(&req("203.0.113.9", "curl/8.9", "GET", "/.env"));
    let v: Value = serde_json::from_str(&plain.events[0]).unwrap();
    assert!(v.get("subject").is_none());
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
        let out = e.decorate_html(&i.session, "/", page).unwrap();
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

// Regression tests from the second live benchmark round (2026-11-15). An
// agent told that Kagami might be present recognised the side bait but
// treated the decoy field in JSON as real app data.

#[test]
fn decoy_route_401_copies_the_app_401_body() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let route = e.manifest()["decoys"]["routes"][0]
        .as_str()
        .unwrap()
        .to_string();
    let mut app_401 = req("203.0.113.9", "curl/8.9", "GET", "/api/orders");
    app_401.status = 401;
    app_401.response_headers = vec![(
        "content-type".into(),
        "application/json; charset=utf-8".into(),
    )];
    app_401.response_body = r#"{"error":"Not signed in","code":40101}"#.into();
    assert!(e.response(&app_401).learned_401);

    let i = e.inspect(&req("203.0.113.9", "curl/8.9", "GET", &route));
    let Action::Respond { status, body, .. } = &i.action else {
        panic!("expected a decoy reply")
    };
    assert_eq!(*status, 401);
    assert_eq!(body, r#"{"error":"Not signed in","code":40101}"#);

    // Only small flat JSON objects are used, and the first one wins.
    let (mut e, _) = engine(Mode::Protect, |_| {});
    for (ct, body) in [
        ("text/html", "<h1>Sign in</h1>"),
        (
            "application/json",
            r#"{"error":{"user":"alice@example.com"}}"#,
        ),
        ("application/json", "[]"),
    ] {
        let mut r = app_401.clone();
        r.response_headers = vec![("content-type".into(), ct.into())];
        r.response_body = body.into();
        assert!(!e.response(&r).learned_401, "{body} must not be learned");
    }
}

#[test]
fn hidden_form_field_catches_privilege_edits_but_not_browsers() {
    let (mut e, _) = engine(Mode::Protect, |c| c.form_decoys = true);
    let m = e.manifest();
    let field = m["decoys"]["json_field"].as_str().unwrap().to_string();
    let value = m["decoys"]["json_value"].as_str().unwrap().to_string();
    let page = e.inspect(&req("198.51.100.7", BROWSER, "GET", "/login"));
    assert!(page.decorate_html);
    let html = e
        .decorate_html(
            &page.session,
            "/login",
            r#"<!doctype html><html><body><form method="post" action="/login"><input name="email"></form></body></html>"#,
        )
        .unwrap();
    assert!(html.contains(&format!(
        r#"<input type="hidden" name="{field}" value="{value}">"#
    )));

    let browser = with_body(
        req("198.51.100.7", BROWSER, "POST", "/login"),
        "application/x-www-form-urlencoded",
        &format!("{field}={value}&email=a%40b.c&password=hunter2"),
    );
    assert!(e.inspect(&browser).events.is_empty());

    let agent = with_body(
        req("203.0.113.9", "curl/8.9", "POST", "/login"),
        "application/x-www-form-urlencoded",
        &format!("{field}=admin&email=a%40b.c&password=hunter2"),
    );
    let i = e.inspect(&agent);
    assert!(rules_of(&i.events).contains(&"decoy.param".to_string()));
    assert_eq!(i.state, State::Flagged);
}

#[test]
fn bait_comment_is_on_some_pages_only() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let doc = "<!doctype html><html><body><h1>x</h1></body></html>";
    let i = e.inspect(&req("203.0.113.9", "curl/8.9", "GET", "/"));
    let with: Vec<bool> = (0..60)
        .map(|n| {
            e.decorate_html(&i.session, &format!("/products/{n}"), doc)
                .is_some()
        })
        .collect();
    assert!(with.iter().any(|w| *w) && with.iter().any(|w| !*w));
    // The same page always gets the same answer.
    let again = e.decorate_html(&i.session, "/products/7", doc).is_some();
    assert_eq!(again, with[7]);
}

#[test]
fn fake_env_is_short_and_has_the_same_layout_for_every_source() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let body = |e: &mut Engine, ip: &str| {
        let Action::Respond { body, .. } = e.inspect(&req(ip, "curl/8.9", "GET", "/.env")).action
        else {
            panic!("expected fake .env")
        };
        body
    };
    let a = body(&mut e, "203.0.113.9");
    let b = body(&mut e, "198.51.100.4");
    for jackpot in ["ADMIN_PASSWORD", "AWS_SECRET_ACCESS_KEY", "JWT_SECRET"] {
        assert!(!a.contains(jackpot), "{jackpot} should not be in the .env");
    }
    assert!(a.lines().count() <= 14, "{a}");
    let keys = |s: &str| -> Vec<String> {
        s.lines()
            .map(|l| l.split('=').next().unwrap().to_string())
            .collect()
    };
    assert_eq!(keys(&a), keys(&b), "the layout is fixed per deployment");
    assert_ne!(
        env_credential(&a),
        env_credential(&b),
        "credentials differ per source"
    );
}

// Regression test from the third live benchmark round (2026-11-16). The
// agent sent absolute-form request targets (`GET http://host/healthz`).
// Kagami matched paths on the full URL, so the ignored /healthz got the JSON
// decoy field and the home page lost the bait comment. Comparing the two
// forms told the agent which parts of the site were Kagami.

#[test]
fn absolute_form_targets_are_treated_like_their_path() {
    let (mut e, _) = engine(Mode::Protect, |c| {
        c.json_decoys = true;
        c.ignore_paths = vec!["/healthz".into()];
    });
    for (origin, absolute) in [
        ("/.env", "http://127.0.0.1:41837/.env"),
        ("/healthz", "http://example.com/healthz"),
        ("/", "http://host.docker.internal:41837/"),
        ("/", "HTTP://127.0.0.1:41837"),
    ] {
        let a = e.inspect(&req("203.0.113.9", "curl/8.9", "GET", origin));
        let b = e.inspect(&req("203.0.113.9", "curl/8.9", "GET", absolute));
        let body = |i: &kagami_core::Inspection| match &i.action {
            Action::Respond { status, body, .. } => format!("{status} {body}"),
            Action::Pass => "pass".into(),
        };
        assert_eq!(body(&a), body(&b), "{absolute}");
        assert_eq!(a.decorate_html, b.decorate_html, "{absolute}");
        assert_eq!(a.decorate_json, b.decorate_json, "{absolute}");
        assert_eq!(
            e.decorate_html(&a.session, origin, "<html><body></body></html>"),
            e.decorate_html(&b.session, absolute, "<html><body></body></html>"),
            "{absolute}"
        );
    }
    let i = e.inspect(&req(
        "198.51.100.4",
        "raw",
        "GET",
        "http://127.0.0.1:41837/search",
    ));
    let rules = rules_of(&i.events);
    assert!(
        rules.contains(&"request.absolute_target".to_string()),
        "{rules:?}"
    );
    assert!(!rules.contains(&"payload.ssrf".to_string()), "{rules:?}");
    // An origin-form path that merely contains a URL is not absolute-form.
    let i = e.inspect(&req(BROWSER, BROWSER, "GET", "/redirect/http://x.example/"));
    assert!(!rules_of(&i.events).contains(&"request.absolute_target".to_string()));
}

// Regression tests from the fourth live benchmark round (2026-11-16).

#[test]
fn payloads_injected_into_the_user_agent_share_one_session() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    let base = "sqlmap/1.10.11#pip (https://sqlmap.org)";
    let injected: Vec<String> = [
        "' AND 2017=7063-- WVrd",
        ") AND 4540=1248-- NouK",
        "',.))))()\"",
        "'vBKFQT<'\">)WthlSo",
        " AND 3647=4499-- fJIG",
    ]
    .iter()
    .map(|p| format!("{base}{p}"))
    .collect();
    let sessions: std::collections::HashSet<String> = injected
        .iter()
        .map(|ua| {
            e.inspect(&req("203.0.113.9", ua, "GET", "/search?q=x"))
                .session
        })
        .collect();
    assert_eq!(
        sessions.len(),
        1,
        "every injected variant lands in one session"
    );
    // sqlmap also replaces the whole header with a payload.
    for ua in [
        "-1015 ORDER BY 1#",
        "sqlmap/1.10.11#pip (https://sqlmap.org));SELECT SLEEP(5)#",
        "(SELECT (CASE WHEN (1551=4503) THEN 1 ELSE 0 END))",
    ] {
        let s = e.inspect(&req("203.0.113.9", ua, "GET", "/")).session;
        assert!(
            sessions.contains(&s),
            "{ua} should join the injected session"
        );
    }

    // Different payload types sent under different injected user agents add
    // up in the one session, as the separate attacks of one scanner should.
    let (mut e, _) = engine(Mode::Observe, |_| {});
    let mut last = None;
    for (ua, q) in injected.iter().zip([
        "%27%20OR%201%3D1--",
        "%7B%7B7*7%7D%7D",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "..%2F..%2F..%2Fetc%2Fpasswd",
    ]) {
        last = Some(e.inspect(&req("203.0.113.9", ua, "GET", &format!("/search?q={q}"))));
    }
    assert_eq!(last.unwrap().state, State::Flagged);

    // Ordinary user agents keep their own sessions.
    let a = e.inspect(&req("203.0.113.9", BROWSER, "GET", "/")).session;
    let b = e
        .inspect(&req("203.0.113.9", "curl/8.9", "GET", "/"))
        .session;
    assert_ne!(a, b);
    assert!(!sessions.contains(&a) && !sessions.contains(&b));
}

#[test]
fn only_the_plain_env_file_is_served() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let served = |e: &mut Engine, p: &str| {
        matches!(
            e.inspect(&req("203.0.113.9", "curl/8.9", "GET", p)).action,
            Action::Respond { .. }
        )
    };
    assert!(served(&mut e, "/.env"));
    for p in ["/.env.local", "/.env.production", "/.env.bak"] {
        assert!(!served(&mut e, p), "{p} should get the app's own 404");
    }
    let i = e.inspect(&req("198.51.100.4", "curl/8.9", "GET", "/.env.local"));
    assert_eq!(rules_of(&i.events), vec!["bait.path"]);
}

// Containment. A machine that trips a tripwire is cut off from the live
// application. These tests cover the trigger, the scope, both actions, the
// shadow's cache rules, dry runs, allowlists, expiry and release.

fn contain_engine(
    mode: Mode,
    tweak: impl FnOnce(&mut kagami_core::Containment),
) -> (Engine, String, String) {
    let (e, _) = engine(mode, |c| {
        c.json_decoys = true;
        c.containment.enabled = true;
        tweak(&mut c.containment);
    });
    let m = e.manifest();
    let field = m["decoys"]["json_field"].as_str().unwrap().to_string();
    let route = m["decoys"]["routes"][0].as_str().unwrap().to_string();
    (e, field, route)
}

fn respond_status(i: &kagami_core::Inspection) -> Option<u16> {
    match &i.action {
        Action::Respond { status, .. } => Some(*status),
        Action::Pass => None,
    }
}

fn trip_url(field: &str) -> String {
    format!("/api/products?{field}=admin")
}

#[test]
fn containment_is_off_by_default() {
    let (mut e, _) = engine(Mode::Protect, |c| c.json_decoys = true);
    let field = e.manifest()["decoys"]["json_field"]
        .as_str()
        .unwrap()
        .to_string();
    let i = e.inspect(&req("198.51.100.4", "curl/8.9", "GET", &trip_url(&field)));
    assert!(!i.contained && i.contain.is_empty());
    let next = e.inspect(&req("198.51.100.4", "curl/8.9", "GET", "/"));
    assert_eq!(next.action, Action::Pass);
}

#[test]
fn a_tripwire_cuts_the_whole_machine_off_from_the_app() {
    let (mut e, field, _) = contain_engine(Mode::Protect, |c| {
        c.action = kagami_core::ContainAction::Block
    });
    let trip = e.inspect(&req("198.51.100.4", "curl/8.9", "GET", &trip_url(&field)));
    assert!(trip.contained, "the tripping request itself is contained");
    assert_eq!(respond_status(&trip), Some(403));
    assert_eq!(trip.contain.len(), 1);
    let c = &trip.contain[0];
    assert_eq!(c.target, "198.51.100.4");
    assert_eq!(c.reason, "decoy.param");
    assert!(!c.public, "documentation range addresses are not public");
    let started: Value = serde_json::from_str(
        trip.events
            .iter()
            .find(|e| e.contains("containment.started"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(started["evidence"]["enforced"], true);
    assert_eq!(started["evidence"]["reason"], "decoy.param");

    // Every tool on that machine is cut off, other machines are not.
    let other_tool = e.inspect(&req("198.51.100.4", "python-requests/2.32", "GET", "/"));
    assert_eq!(respond_status(&other_tool), Some(403));
    assert!(other_tool.contain.is_empty(), "announced once");
    let neighbour = e.inspect(&req("198.51.100.5", BROWSER, "GET", "/"));
    assert_eq!(neighbour.action, Action::Pass);
}

/// A second instance of the same deployment loads the first one's
/// containment from a shared store, without announcing it again.
#[test]
fn a_containment_from_a_shared_store_holds_on_another_instance() {
    let block = |c: &mut kagami_core::Containment| c.action = kagami_core::ContainAction::Block;
    let (mut first, field, _) = contain_engine(Mode::Protect, block);
    let (mut second, _, _) = contain_engine(Mode::Protect, block);
    let trip = first.inspect(&req("203.0.113.9", "curl/8.9", "GET", &trip_url(&field)));
    let c = &trip.contain[0];
    let stored = kagami_core::StoredEntry {
        source: c.source.clone(),
        target: c.target.clone(),
        reason: c.reason.to_string(),
        since_ms: c.since_ms,
        until_ms: c.until_ms,
    };

    let attacker = req("203.0.113.9", "curl/8.9", "GET", "/");
    let (source, target) = second.machine_of(&attacker);
    assert_eq!(
        (source.as_str(), target.as_str()),
        (c.source.as_str(), "203.0.113.9"),
        "both instances key the machine the same way"
    );
    assert_eq!(second.restore(std::slice::from_ref(&stored), T0 + 1000), 1);
    assert_eq!(
        second.restore(std::slice::from_ref(&stored), T0 + 1000),
        0,
        "loading it twice changes nothing"
    );

    let next = second.inspect(&attacker);
    assert_eq!(respond_status(&next), Some(403));
    assert!(
        next.contain.is_empty(),
        "the second instance does not announce it again"
    );
    assert!(!rules_of(&next.events)
        .iter()
        .any(|r| r == "containment.started"));
    assert_eq!(second.contained_list(T0 + 1000)[0].reason, "decoy.param");

    // An expired entry, or one from another deployment, has no effect.
    let (mut third, _, _) = contain_engine(Mode::Protect, block);
    let expired = kagami_core::StoredEntry {
        until_ms: T0,
        ..stored.clone()
    };
    assert_eq!(third.restore(&[expired], T0 + 1000), 0);
    let (mut other, _) = engine(Mode::Protect, |c| {
        c.secret = "another-deployment-secret-0123456789abcdef".into();
        c.containment.enabled = true;
    });
    other.restore(&[stored], T0 + 1000);
    assert_eq!(other.inspect(&attacker).action, Action::Pass);
}

#[test]
fn an_ipv6_slash_64_is_one_machine() {
    let (mut e, field, _) = contain_engine(Mode::Protect, |_| {});
    let trip = e.inspect(&req(
        "2a01:4f8:1:2::10",
        "curl/8.9",
        "GET",
        &trip_url(&field),
    ));
    assert_eq!(trip.contain[0].target, "2a01:4f8:1:2::/64");
    assert!(trip.contain[0].public);
    let rotated = e.inspect(&req("2a01:4f8:1:2:dead:beef::1", "curl/8.9", "GET", "/"));
    assert!(
        rotated.contained,
        "a new address in the same /64 stays contained"
    );
    let elsewhere = e.inspect(&req("2a01:4f8:1:3::10", "curl/8.9", "GET", "/"));
    assert!(!elsewhere.contained);
}

#[test]
fn the_shadow_replays_only_public_responses() {
    let (mut e, field, _) = contain_engine(Mode::Protect, |_| {});
    let page = "<!doctype html><html><body><h1>Shop</h1><form method=post action=/login></form></body></html>";
    // An anonymous visitor's request is captured.
    let visit = e.inspect(&req("198.51.100.20", BROWSER, "GET", "/"));
    assert!(visit.capture);
    let mut r = req("198.51.100.20", BROWSER, "GET", "/");
    r.status = 200;
    r.response_headers = vec![("content-type".into(), "text/html; charset=utf-8".into())];
    r.response_body = page.into();
    e.response(&r);
    let mut nf = req("198.51.100.20", BROWSER, "GET", "/missing");
    nf.status = 404;
    nf.response_headers = vec![("content-type".into(), "text/html; charset=utf-8".into())];
    nf.response_body = "<h1>Not found</h1>".into();
    e.response(&nf);
    // A signed-in visitor's page is never captured, even if the host sends it.
    let mut signed_in = req("198.51.100.21", BROWSER, "GET", "/account");
    signed_in.headers.push(("cookie".into(), "sid=abc".into()));
    assert!(!e.inspect(&signed_in).capture);
    signed_in.status = 200;
    signed_in.response_headers = vec![("content-type".into(), "text/html".into())];
    signed_in.response_body = "<h1>Orders of Alice</h1>".into();
    e.response(&signed_in);

    // The attacker trips a wire, then only ever sees the shadow.
    e.inspect(&req("203.0.113.66", "curl/8.9", "GET", &trip_url(&field)));
    let home = e.inspect(&req("203.0.113.66", "curl/8.9", "GET", "/"));
    let Action::Respond { status, body, .. } = &home.action else {
        panic!("the shadow answers")
    };
    assert_eq!(*status, 200);
    assert!(body.contains("<h1>Shop</h1>"));
    assert!(
        body.contains("sk_live_"),
        "replayed pages carry the bait comment"
    );
    assert!(
        !body.contains("type=\"hidden\""),
        "form decoys are off in this engine"
    );
    assert!(!home.capture, "contained traffic is never stored");

    let account = e.inspect(&req("203.0.113.66", "curl/8.9", "GET", "/account"));
    let Action::Respond { status, body, .. } = &account.action else {
        panic!()
    };
    assert_eq!(
        *status, 404,
        "a page only signed-in users saw is not replayed"
    );
    assert!(!body.contains("Alice"));

    let login = with_body(
        req("203.0.113.66", "curl/8.9", "POST", "/login"),
        "application/x-www-form-urlencoded",
        "email=admin%40x.y&password=x",
    );
    assert_eq!(respond_status(&e.inspect(&login)), Some(404));
}

#[test]
fn decoys_keep_answering_a_contained_machine() {
    let (mut e, field, route) = contain_engine(Mode::Protect, |_| {});
    e.inspect(&req("203.0.113.66", "curl/8.9", "GET", &trip_url(&field)));
    assert_eq!(
        respond_status(&e.inspect(&req("203.0.113.66", "curl/8.9", "GET", &route))),
        Some(401)
    );
    let env = e.inspect(&req("203.0.113.66", "curl/8.9", "GET", "/.env"));
    let Action::Respond { body, .. } = &env.action else {
        panic!()
    };
    assert!(body.contains("NODE_ENV=production"));
}

#[test]
fn observe_mode_runs_containment_as_a_dry_run() {
    let (mut e, field, _) = contain_engine(Mode::Observe, |_| {});
    let trip = e.inspect(&req("198.51.100.4", "curl/8.9", "GET", &trip_url(&field)));
    assert_eq!(trip.action, Action::Pass);
    assert!(trip.contain.is_empty(), "nothing is pushed to enforcers");
    let started: Value = serde_json::from_str(
        trip.events
            .iter()
            .find(|e| e.contains("containment.started"))
            .expect("the dry run still reports"),
    )
    .unwrap();
    assert_eq!(started["evidence"]["enforced"], false);
    assert_eq!(
        e.inspect(&req("198.51.100.4", "curl/8.9", "GET", "/"))
            .action,
        Action::Pass
    );
}

#[test]
fn allowlisted_addresses_are_never_contained() {
    let (mut e, field, _) = contain_engine(Mode::Protect, |c| {
        c.allow = vec!["198.51.100.0/24".into(), "2001:db8::/32".into()];
    });
    for ip in ["198.51.100.4", "::ffff:198.51.100.9", "2001:db8::5"] {
        let i = e.inspect(&req(ip, "curl/8.9", "GET", &trip_url(&field)));
        assert!(!i.contained && i.contain.is_empty(), "{ip}");
        assert!(rules_of(&i.events).contains(&"decoy.param".to_string()));
    }
}

#[test]
fn a_stolen_honeytoken_contains_the_machine_it_was_issued_to() {
    let (mut e, _, _) = contain_engine(Mode::Protect, |_| {});
    // Machine A collects the fake .env but never uses it itself.
    let probe = e.inspect(&req("192.0.2.10", "curl/8.9", "GET", "/.env"));
    assert!(!probe.contained, "probing a bait path is not a tripwire");
    let Action::Respond { body, .. } = &probe.action else {
        panic!()
    };
    let secret = env_credential(body).to_string();
    // Machine B uses it.
    let login = with_body(
        req("198.51.100.30", "python-httpx/0.27", "POST", "/login"),
        "application/x-www-form-urlencoded",
        &format!("email=a%40b.c&password={secret}"),
    );
    let i = e.inspect(&login);
    assert!(i.contained);
    let targets: Vec<&str> = i.contain.iter().map(|c| c.target.as_str()).collect();
    assert!(
        targets.contains(&"198.51.100.30") && targets.contains(&"192.0.2.10"),
        "{targets:?}"
    );
    assert!(
        e.inspect(&req("192.0.2.10", "curl/8.9", "GET", "/"))
            .contained
    );
}

#[test]
fn containment_expires_and_can_be_released() {
    let (mut e, field, _) = contain_engine(Mode::Protect, |c| c.ttl_secs = 60);
    e.inspect(&req("198.51.100.4", "curl/8.9", "GET", &trip_url(&field)));
    let mut later = req("198.51.100.4", "curl/8.9", "GET", "/");
    later.now_ms = T0 + 1000 + 59_000;
    assert!(e.inspect(&later).contained);
    later.now_ms = T0 + 1000 + 61_000;
    assert!(!e.inspect(&later).contained, "expired after the TTL");

    e.inspect(&req("198.51.100.7", "curl/8.9", "GET", &trip_url(&field)));
    assert_eq!(e.contained_list(T0).len(), 1);
    assert_eq!(e.release("::ffff:198.51.100.7").len(), 1);
    assert!(
        !e.inspect(&req("198.51.100.7", "curl/8.9", "GET", "/"))
            .contained
    );
}

#[test]
fn the_flagged_trigger_also_contains_on_accumulated_signals() {
    let attack = [
        "/search?q=%27%20OR%201%3D1--",
        "/search?q=%7B%7B7*7%7D%7D",
        "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/search?q=..%2F..%2Fetc%2Fpasswd",
    ];
    for (trigger, expect) in [
        (kagami_core::Trigger::Tripwire, false),
        (kagami_core::Trigger::Flagged, true),
    ] {
        let (mut e, _, _) = contain_engine(Mode::Protect, |c| c.trigger = trigger);
        let mut last = None;
        for a in attack {
            last = Some(e.inspect(&req("198.51.100.4", "curl/8.9", "GET", a)));
        }
        let last = last.unwrap();
        assert_eq!(last.state, State::Flagged);
        assert_eq!(last.contained, expect, "{trigger:?}");
    }
}

#[test]
fn a_tampered_sealed_value_contains_from_the_next_request() {
    let (mut e, _, _) = contain_engine(Mode::Protect, |_| {});
    let r = req("198.51.100.4", BROWSER, "GET", "/api/orders/5001");
    let v = e.verify_sealed(&r, "5001~AAAAAAAAAAAAAAAA", "order_id");
    assert!(!v.valid);
    assert_eq!(v.contain.len(), 1);
    assert!(
        e.inspect(&req("198.51.100.4", BROWSER, "GET", "/"))
            .contained
    );
}

#[test]
fn containment_settings_are_validated() {
    let tweaks: [fn(&mut Config); 3] = [
        |c| c.containment.allow = vec!["not a range".into()],
        |c| c.containment.ttl_secs = 5,
        |c| c.containment.max_entries = 1,
    ];
    for tweak in tweaks {
        let mut cfg = Config {
            secret: SECRET.into(),
            ..Config::default()
        };
        tweak(&mut cfg);
        let err = Engine::new(cfg, T0, "t").err().expect("rejected");
        assert_eq!(err.code, "invalid_containment");
    }
}

#[test]
fn a_cross_site_forgery_cannot_get_a_visitor_contained() {
    let (mut e, field, _) = contain_engine(Mode::Protect, |_| {});
    // An attacker's page makes the visitor's browser submit the changed field.
    let mut forged = with_body(
        req("198.51.100.80", BROWSER, "POST", "/login"),
        "application/x-www-form-urlencoded",
        &format!("{field}=admin&email=a%40b.c&password=x"),
    );
    forged
        .headers
        .push(("sec-fetch-site".into(), "cross-site".into()));
    let i = e.inspect(&forged);
    assert!(
        rules_of(&i.events).contains(&"decoy.param".to_string()),
        "still detected"
    );
    assert!(!i.contained && i.contain.is_empty(), "but not contained");

    // Older browsers send only Origin. A foreign origin counts as cross-site.
    let mut old = req("198.51.100.81", BROWSER, "GET", &trip_url(&field));
    old.headers
        .push(("origin".into(), "https://evil.example".into()));
    assert!(!e.inspect(&old).contained);

    // The site's own origin, and tools that send no such headers, are contained.
    let mut same = req("198.51.100.82", BROWSER, "GET", &trip_url(&field));
    same.headers
        .push(("origin".into(), "https://shop.example.co.nz".into()));
    same.headers
        .push(("sec-fetch-site".into(), "same-origin".into()));
    assert!(e.inspect(&same).contained);
    assert!(
        e.inspect(&req("198.51.100.83", "curl/8.9", "GET", &trip_url(&field)))
            .contained
    );
}

#[test]
fn the_core_resolves_the_client_address_from_the_peer() {
    let (e, _) = engine(Mode::Protect, |c| {
        c.client_ip.cloudflare = true;
        c.client_ip.trusted_proxies = vec!["127.0.0.1".into()];
    });
    let mut r = req("", "curl/8.9", "GET", "/");
    r.peer = "127.0.0.1".into();
    r.headers
        .push(("x-forwarded-for".into(), "6.6.6.6, 173.245.48.10".into()));
    r.headers
        .push(("cf-connecting-ip".into(), "8.8.8.8".into()));
    e.resolve_client_ip(&mut r);
    assert_eq!(r.ip, "8.8.8.8");

    // A forged Cloudflare header from outside Cloudflare is ignored.
    let mut forged = req("", "curl/8.9", "GET", "/");
    forged.peer = "198.51.100.66".into();
    forged
        .headers
        .push(("cf-connecting-ip".into(), "8.8.8.8".into()));
    e.resolve_client_ip(&mut forged);
    assert_eq!(forged.ip, "198.51.100.66");

    // Without a peer, the host's own address is kept.
    let mut host = req("203.0.113.9", "curl/8.9", "GET", "/");
    e.resolve_client_ip(&mut host);
    assert_eq!(host.ip, "203.0.113.9");

    let mut cfg = Config {
        secret: SECRET.into(),
        ..Config::default()
    };
    cfg.client_ip.trusted_proxies = vec!["proxy.local".into()];
    assert_eq!(
        Engine::new(cfg, T0, "t").err().unwrap().code,
        "invalid_client_ip"
    );
}

fn respond_body(i: &kagami_core::Inspection) -> Option<(u16, String)> {
    match &i.action {
        Action::Respond { status, body, .. } => Some((*status, body.clone())),
        _ => None,
    }
}

#[test]
fn decoy_spec_is_opt_in_and_every_operation_is_a_decoy_route() {
    // Off by default, the spec path reaches the app.
    let (mut off, _) = engine(Mode::Protect, |_| {});
    let path = off.manifest()["decoys"]["spec_path"].clone();
    assert!(path.is_null());

    let (mut e, _) = engine(Mode::Protect, |c| c.spec_decoy = true);
    let spec_path = e.manifest()["decoys"]["spec_path"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(off
        .inspect(&req("203.0.113.9", "curl/8.9", "GET", &spec_path))
        .events
        .is_empty());

    let i = e.inspect(&req("203.0.113.9", "curl/8.9", "GET", &spec_path));
    assert_eq!(rules_of(&i.events), vec!["decoy.spec"]);
    assert_ne!(i.state, State::Flagged, "fetching a spec is only a signal");
    let (status, body) = respond_body(&i).expect("the decoy spec is served");
    assert_eq!(status, 200);
    let spec: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(spec["openapi"], "3.0.3");

    let routes: Vec<String> = e.manifest()["decoys"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect();
    let listed: Vec<&String> = spec["paths"].as_object().unwrap().keys().collect();
    assert_eq!(listed.len(), routes.len());
    for p in listed {
        assert!(routes.contains(p), "{p} is not a decoy route");
        let hit = e.inspect(&req("198.51.100.20", "python-httpx/0.27", "GET", p));
        assert!(
            hit.rules.contains(&"decoy.route"),
            "{p} must trip decoy.route"
        );
    }

    // The sandbox key is a honeytoken bound to the machine that fetched it.
    let desc = spec["info"]["description"].as_str().unwrap();
    let key = desc
        .split("pk_sandbox_")
        .nth(1)
        .unwrap()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect::<String>();
    let mut used = req("198.51.100.20", "python-httpx/0.27", "GET", &routes[0]);
    used.headers
        .push(("authorization".into(), format!("Bearer pk_sandbox_{key}")));
    let i = e.inspect(&used);
    let ev: Vec<Value> = i
        .events
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let token = ev.iter().find(|v| v["rule"] == "honeytoken.used").unwrap();
    assert_eq!(token["evidence"]["token_kind"], "spec_sandbox_key");
    assert_eq!(token["evidence"]["cross_source"], true);
    let (status, _) = respond_body(&i).unwrap();
    assert_eq!(status, 200, "the key unlocks fake records");
}

#[test]
fn decoy_spec_avoids_reserved_paths() {
    let (mut e, _) = engine(Mode::Protect, |c| {
        c.spec_decoy = true;
        c.reserved_paths = [
            "/openapi.json",
            "/swagger.json",
            "/api/openapi.json",
            "/api/swagger.json",
            "/v3/api-docs",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
    });
    assert_eq!(e.manifest()["decoys"]["spec_path"], "/v2/api-docs");
    assert_eq!(
        e.manifest()["decoys"]["spec_aliases"],
        serde_json::json!(["/api-docs.json"])
    );
    let i = e.inspect(&req("203.0.113.9", "curl/8.9", "GET", "/openapi.json"));
    assert!(
        respond_body(&i).is_none(),
        "a reserved path is never answered"
    );
}

#[test]
fn decoy_spec_lives_where_agents_look_and_other_paths_redirect() {
    let (mut e, _) = engine(Mode::Protect, |c| c.spec_decoy = true);
    let m = e.manifest();
    let path = m["decoys"]["spec_path"].as_str().unwrap().to_string();
    assert!(path == "/openapi.json" || path == "/swagger.json");
    let aliases: Vec<String> = m["decoys"]["spec_aliases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    assert_eq!(aliases.len(), 6);
    assert!(!aliases.contains(&path));
    for (n, alias) in aliases.iter().enumerate() {
        let i = e.inspect(&req(
            &format!("203.0.113.{}", 100 + n),
            "curl/8.9",
            "GET",
            alias,
        ));
        let Action::Respond {
            status, headers, ..
        } = &i.action
        else {
            panic!("{alias} is not answered");
        };
        assert_eq!(*status, 302);
        assert!(headers.iter().any(|(k, v)| k == "location" && *v == path));
        assert!(rules_of(&i.events).contains(&"decoy.spec".to_string()));
    }
    // In observe mode nothing is answered.
    let (mut o, _) = engine(Mode::Observe, |c| c.spec_decoy = true);
    assert!(
        respond_body(&o.inspect(&req("203.0.113.9", "curl/8.9", "GET", &aliases[0]))).is_none()
    );
}

#[test]
fn unsigned_jwts_are_a_tripwire() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    // {"alg":"none","typ":"JWT"} . {"sub":"1","role":"admin"} . (empty)
    let none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.";
    let mut r = req("203.0.113.9", "python-httpx/0.27", "GET", "/api/me");
    r.headers
        .push(("authorization".into(), format!("Bearer {none}")));
    let i = e.inspect(&r);
    assert_eq!(i.state, State::Flagged);
    let v: Value = serde_json::from_str(&i.events[0]).unwrap();
    assert_eq!(v["rule"], "tamper.unsigned_jwt");
    assert_eq!(v["evidence"]["alg"], "none");
    assert_eq!(v["evidence"]["location"], "header");
    assert!(
        !i.events[0].contains("eyJzdWIi"),
        "the token is never logged"
    );

    // {"alg":"NoNe"} in a cookie, with a junk signature.
    let mut c = req("203.0.113.10", "python-httpx/0.27", "GET", "/api/me");
    c.headers.push((
        "cookie".into(),
        "token=eyJhbGciOiJOb05lIn0.eyJzdWIiOiIxIn0.abc".into(),
    ));
    assert!(rules_of(&e.inspect(&c).events).contains(&"tamper.unsigned_jwt".to_string()));

    // A signed HS256 token, as honest clients send, is silent.
    let signed = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWJ5dGVz";
    let mut ok = req("198.51.100.7", BROWSER, "GET", "/api/me");
    ok.headers
        .push(("authorization".into(), format!("Bearer {signed}")));
    assert!(e.inspect(&ok).events.is_empty());
}

#[test]
fn events_say_when_a_browser_was_sent_from_another_site() {
    let (mut e, _) = engine(Mode::Observe, |_| {});
    let param = e.manifest()["decoys"]["debug_param"]
        .as_str()
        .unwrap()
        .to_string();
    let target = format!("/account?{param}=1");

    // A signed-in visitor clicks a link on another site that carries the decoy parameter.
    let mut lured = req("198.51.100.30", BROWSER, "GET", &target);
    lured
        .headers
        .push(("sec-fetch-site".into(), "cross-site".into()));
    lured
        .headers
        .push(("sec-fetch-mode".into(), "navigate".into()));
    lured.subject = "acct_7".into();
    let i = e.inspect(&lured);
    let v: Value = serde_json::from_str(&i.events[0]).unwrap();
    assert_eq!(v["rule"], "decoy.param");
    assert_eq!(v["request"]["site"], "cross-site");
    assert_eq!(v["request"]["navigate"], true);

    // A script sends the same request. It has no browser headers, so neither field appears.
    let i = e.inspect(&req("203.0.113.30", "python-httpx/0.27", "GET", &target));
    let v: Value = serde_json::from_str(&i.events[0]).unwrap();
    assert!(v["request"].get("site").is_none());
    assert!(v["request"].get("navigate").is_none());

    // An Origin from another site counts as cross-site, and unknown values are dropped.
    let mut posted = req("198.51.100.31", BROWSER, "POST", "/login");
    posted
        .headers
        .push(("origin".into(), "https://evil.example".into()));
    posted
        .headers
        .push(("sec-fetch-site".into(), "<script>".into()));
    posted.body = format!("{param}=1");
    posted.headers.push((
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    ));
    let v: Value = serde_json::from_str(&e.inspect(&posted).events[0]).unwrap();
    assert_eq!(v["request"]["site"], "cross-site");
}

#[test]
fn hostile_encodings_never_panic() {
    let nasty = [
        "/..%c0%af..%c0%afetc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/%ff%fe%fd",
        "/%e2%80",
        "/%ed%a0%80",
        "/a%",
        "/a%2",
        "/%%32%65",
        "/x%0d%0aSet-Cookie:%20a=b",
    ];
    let queries = [
        "key=%c0%af",
        "key=%ff",
        "key=%e2%80",
        "key=abc%0d%0aX:%20y",
        "key=%",
        "key=%c0",
        "%c0%af=1",
        "key=sk_live_%c0%af%c0%af",
        "key=%E2%80%A8%E2%80%A9",
        "key=%F0%9F%98",
    ];
    for mode in [Mode::Observe, Mode::Protect] {
        let (mut e, _) = engine(mode, |c| {
            c.json_decoys = true;
            c.spec_decoy = true;
            c.containment.enabled = true;
        });
        let route = e.manifest()["decoys"]["routes"][0]
            .as_str()
            .unwrap()
            .to_string();
        for p in nasty {
            let mut r = req("203.0.113.9", "curl/7.88.1", "GET", p);
            r.status = 404;
            e.inspect(&r);
            e.response(&r);
        }
        for q in queries {
            for path in [route.as_str(), "/search"] {
                let mut r = req("203.0.113.9", "curl/7.88.1", "GET", &format!("{path}?{q}"));
                r.status = 401;
                e.inspect(&r);
                e.response(&r);
                r.headers.push(("cookie".into(), format!("a={q}")));
                r.headers
                    .push(("authorization".into(), format!("Bearer {q}")));
                e.inspect(&r);
            }
        }
    }
}

/// Random hostile input in every place an attacker controls. The engine must
/// never panic, because a panic is an internal error that drops its state.
#[test]
fn random_hostile_input_never_panics() {
    const PIECES: &[&str] = &[
        "%c0%af",
        "%c0%ae",
        "%ff",
        "%fe",
        "%e2%80",
        "%ed%a0%80",
        "%F0%9F%98",
        "%",
        "%2",
        "%%",
        "%00",
        "%0d%0a",
        "\u{fffd}",
        "é",
        "日本",
        "😀",
        "\u{202e}",
        "Bearer ",
        "bearer\u{a0}",
        "eyJ",
        "eyJhbGciOiJub25lIn0",
        ".",
        "..",
        "/",
        "\\",
        "s:",
        ".sig",
        "=",
        ";",
        "&",
        "?",
        "#",
        "'",
        "\"",
        "<script>",
        "{{7*7}}",
        "${jndi:",
        "|",
        ":",
        "--",
        "[",
        "]",
        "$ne",
        "sk_live_",
        "AKIA",
        " ",
        "\t",
        "a",
        "Z",
        "9",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ];
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut text = |n: u64| -> String {
        let len = (next() % n) as usize;
        (0..len)
            .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
            .collect()
    };
    for mode in [Mode::Observe, Mode::Protect] {
        let (mut e, _) = engine(mode, |c| {
            c.json_decoys = true;
            c.form_decoys = true;
            c.spec_decoy = true;
            c.containment.enabled = true;
        });
        for i in 0..3000u32 {
            let path = format!("/{}", text(8));
            let query = text(8);
            let mut r = req(
                &format!("203.0.113.{}", i % 250),
                &text(4),
                ["GET", "POST", "PUT", "OPTIONS"][(i % 4) as usize],
                &format!("{path}?{query}"),
            );
            r.headers.push((
                "cookie".into(),
                format!("{}={}; {}.sig={}", text(3), text(6), text(3), text(4)),
            ));
            r.headers.push(("authorization".into(), text(6)));
            r.headers.push(("x-forwarded-for".into(), text(4)));
            r.headers.push(("origin".into(), text(3)));
            r.headers.push(("sec-fetch-site".into(), text(2)));
            r.headers.push((
                "content-type".into(),
                [
                    "application/json",
                    "application/x-www-form-urlencoded",
                    "text/plain",
                ][(i % 3) as usize]
                    .into(),
            ));
            r.body = text(10);
            r.subject = text(3);
            r.status = [200u16, 302, 401, 404, 500][(i % 5) as usize];
            let v = e.inspect(&r);
            e.response(&r);
            e.verify_sealed(&r, &text(4), &text(2));
            e.decorate_html(
                &v.session,
                &path,
                &format!(
                    "<html><body>{}<form method=\"post\">{}</form></body></html>",
                    text(4),
                    text(3)
                ),
            );
            e.decorate_json(&format!("{{\"a\":\"{}\"}}", text(3)));
        }
    }
}

#[test]
fn decoys_never_change_with_the_host_header() {
    let (mut e, _) = engine(Mode::Protect, |c| c.spec_decoy = true);
    let route = e.manifest()["decoys"]["routes"][0]
        .as_str()
        .unwrap()
        .to_string();
    let spec = e.manifest()["decoys"]["spec_path"]
        .as_str()
        .unwrap()
        .to_string();
    let with_host = |path: &str, host: &str| {
        let mut r = req("203.0.113.9", "curl/8.9", "GET", path);
        r.host = host.into();
        r.headers.retain(|(k, _)| k != "host");
        r.headers.push(("host".into(), host.into()));
        r
    };
    // A local name first, then the real one, then an address and a forged name.
    let hosts = [
        "localhost:3000",
        "shop.example.co.nz",
        "127.0.0.1:3000",
        "evil.example",
    ];
    let mut bodies: Vec<Vec<String>> = Vec::new();
    for h in hosts {
        let mut seen = Vec::new();
        for p in ["/.env", "/.git/config", spec.as_str()] {
            seen.push(respond_body(&e.inspect(&with_host(p, h))).unwrap().1);
        }
        let mut keyed = with_host(&route, h);
        // The sandbox key from the decoy description opens the decoy route.
        let key = format!(
            "pk_sandbox_{}",
            seen[2]
                .split("pk_sandbox_")
                .nth(1)
                .unwrap()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
        );
        keyed
            .headers
            .push(("authorization".into(), format!("Bearer {key}")));
        let (status, records) = respond_body(&e.inspect(&keyed)).unwrap();
        assert_eq!(status, 200, "the planted key unlocks fake records");
        seen.push(records);
        bodies.push(seen);
    }
    // Everything after the first real host name is identical, whatever the Host header says.
    assert_eq!(bodies[1], bodies[2]);
    assert_eq!(bodies[1], bodies[3]);
    assert!(bodies[1][0].contains("shop.example.co.nz"));

    // The site setting wins from the first request.
    let (mut fixed, _) = engine(Mode::Protect, |c| c.site = "www.northwind.example".into());
    let a = respond_body(&fixed.inspect(&with_host("/.env", "127.0.0.1")))
        .unwrap()
        .1;
    let b = respond_body(&fixed.inspect(&with_host("/.env", "other.example")))
        .unwrap()
        .1;
    assert_eq!(a, b);
    assert!(a.contains("northwind.example"));
}

#[test]
fn the_shadow_answers_a_failed_post_the_way_the_app_does() {
    let (mut e, _) = engine(Mode::Protect, |c| c.containment.enabled = true);
    let failed = r#"<!doctype html><html><body><h1>Sign in</h1><p>Invalid email or password.</p></body></html>"#;
    let post = |ip: &str, body: &str| {
        with_body(
            req(ip, BROWSER, "POST", "/login"),
            "application/x-www-form-urlencoded",
            body,
        )
    };
    let answer = |e: &mut Engine, mut r: Request, status: u16, html: &str| {
        let i = e.inspect(&r);
        assert!(i.capture, "the host is asked for the response");
        r.status = status;
        r.response_headers = vec![("content-type".into(), "text/html; charset=utf-8".into())];
        r.response_body = html.into();
        e.response(&r);
    };
    // One failed sign-in is not enough. A second, different one with the same answer confirms it.
    answer(
        &mut e,
        post("198.51.100.1", "email=a%40b.c&password=one"),
        401,
        failed,
    );
    answer(
        &mut e,
        post("198.51.100.2", "email=d%40e.f&password=two"),
        401,
        failed,
    );

    // A page that repeats what the visitor typed is never confirmed.
    let echo = |who: &str| format!("<html><body>No account for {who}</body></html>");
    let reset = |ip: &str, who: &str| {
        with_body(
            req(ip, BROWSER, "POST", "/reset"),
            "application/x-www-form-urlencoded",
            &format!("email={who}"),
        )
    };
    answer(&mut e, reset("198.51.100.3", "ann"), 404, &echo("ann"));
    answer(&mut e, reset("198.51.100.4", "bob"), 404, &echo("bob"));

    // A request carrying a cookie is never used.
    let mut signed_in = post("198.51.100.5", "email=x&password=y");
    signed_in.headers.push(("cookie".into(), "sid=abc".into()));
    assert!(!e.inspect(&signed_in).capture);

    // The attacker trips a wire and is contained.
    let route = e.manifest()["decoys"]["routes"][0]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        e.inspect(&req("203.0.113.9", "curl/8.9", "GET", &route))
            .contained
    );
    let (status, body) =
        respond_body(&e.inspect(&post("203.0.113.9", "email=admin&password=x"))).unwrap();
    assert_eq!((status, body.as_str()), (401, failed));
    let (_, body) =
        respond_body(&e.inspect(&reset("203.0.113.9", "eve"))).unwrap_or((0, String::new()));
    assert!(
        !body.contains("ann") && !body.contains("bob"),
        "an echoing page is never replayed"
    );
}

#[test]
fn the_shadow_never_echoes_a_query_for_some_values_only() {
    let (mut e, _) = engine(Mode::Protect, |c| c.containment.enabled = true);
    let page = |q: &str| {
        format!(
            "<html><body><form><input name=\"q\" value=\"{q}\"></form><p>Results</p></body></html>"
        )
    };
    let visit = |e: &mut Engine, target: &str, html: &str| {
        let mut r = req("198.51.100.1", BROWSER, "GET", target);
        let i = e.inspect(&r);
        assert!(i.capture);
        r.status = 200;
        r.response_headers = vec![("content-type".into(), "text/html; charset=utf-8".into())];
        r.response_body = html.into();
        e.response(&r);
    };
    // Honest visitors searched for two words, and once with no query.
    visit(&mut e, "/search", &page(""));
    visit(&mut e, "/search?q=jacket", &page("jacket"));
    visit(&mut e, "/search?q=beanie", &page("beanie"));
    // A page that does not repeat its query is still replayed for that exact URL.
    visit(
        &mut e,
        "/products?page=2",
        "<html><body>Second page of products</body></html>",
    );

    let route = e.manifest()["decoys"]["routes"][0]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        e.inspect(&req("203.0.113.9", "curl/8.9", "GET", &route))
            .contained
    );
    for q in ["jacket", "beanie", "hello", "%3Cscript%3E"] {
        let (_, body) = respond_body(&e.inspect(&req(
            "203.0.113.9",
            "curl/8.9",
            "GET",
            &format!("/search?q={q}"),
        )))
        .unwrap();
        assert!(
            body.contains("value=\"\""),
            "q={q} must get the same page as any other query"
        );
    }
    let (_, body) =
        respond_body(&e.inspect(&req("203.0.113.9", "curl/8.9", "GET", "/products?page=2")))
            .unwrap();
    assert!(body.contains("Second page"));
}

#[test]
fn decoy_routes_take_keys_and_cursors_the_way_a_real_api_does() {
    let (mut e, _) = engine(Mode::Protect, |_| {});
    let route = e.manifest()["decoys"]["routes"][0]
        .as_str()
        .unwrap()
        .to_string();
    let visit = e.inspect(&req("203.0.113.9", "Mozilla/5.0 agent", "GET", "/"));
    let home = e
        .decorate_html(
            &visit.session,
            "/",
            "<!doctype html><html><head></head><body><h1>Shop</h1></body></html>",
        )
        .unwrap();
    let key = home
        .split("sk_live_")
        .nth(1)
        .unwrap()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect::<String>();
    let full = format!("sk_live_{key}");
    let ask = |e: &mut Engine, ip: &str, target: &str, header: Option<(&str, String)>| {
        let mut r = req(ip, "curl/8.9", "GET", target);
        if let Some((k, v)) = header {
            r.headers.push((k.into(), v));
        }
        let i = e.inspect(&r);
        let used = i.rules.contains(&"honeytoken.used");
        (respond_body(&i).unwrap(), used)
    };
    // The key anywhere but where APIs take keys is detected, and the route stays shut.
    let wrong = [
        ("user-agent", full.clone()),
        ("cookie", format!("key={full}")),
        ("authorization", format!("Bearer pk_live_{key}")),
        ("authorization", format!("Bearer {key}")),
    ];
    for (n, (k, v)) in wrong.into_iter().enumerate() {
        let ((status, _), used) = ask(
            &mut e,
            &format!("203.0.113.{}", 10 + n),
            &route,
            Some((k, v)),
        );
        assert_eq!(status, 401, "{k}");
        assert!(used, "the planted key is still detected in {k}");
    }
    let ((status, _), _) = ask(&mut e, "203.0.113.20", &format!("{route}?key={full}"), None);
    assert_eq!(status, 401);
    // The places a real API reads a key.
    for (n, h) in [
        ("authorization", format!("Bearer {full}")),
        ("authorization", full.clone()),
        ("x-api-key", full.clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let ((status, _), _) = ask(&mut e, &format!("203.0.113.{}", 30 + n), &route, Some(h));
        assert_eq!(status, 200);
    }
    // An issued cursor leads on. An edited one, or another machine's, is refused.
    let auth = || Some(("authorization", format!("Bearer {full}")));
    let ((_, page1), _) = ask(&mut e, "203.0.113.40", &route, auth());
    let next = serde_json::from_str::<Value>(&page1).unwrap()["next_cursor"]
        .as_str()
        .unwrap()
        .to_string();
    let ((status, page2), _) = ask(
        &mut e,
        "203.0.113.40",
        &format!("{route}?cursor={next}"),
        auth(),
    );
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_str::<Value>(&page2).unwrap()["page"], 2);
    let edited = format!("25{}", &next[1..]);
    for (ip, cursor) in [
        ("203.0.113.40", edited.as_str()),
        ("203.0.113.40", "25"),
        ("198.51.100.41", next.as_str()),
    ] {
        let ((status, body), _) = ask(&mut e, ip, &format!("{route}?cursor={cursor}"), auth());
        assert_eq!(
            (status, body.as_str()),
            (400, r#"{"error":"invalid cursor"}"#),
            "cursor {cursor} from {ip}"
        );
    }
    // Pages are read leniently, as most APIs do.
    let ((status, body), _) = ask(&mut e, "203.0.113.40", &format!("{route}?page=3"), auth());
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["page"], 3);
}
