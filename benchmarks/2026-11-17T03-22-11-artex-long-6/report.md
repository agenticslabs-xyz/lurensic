# Benchmark round artex-long-6

Kagami 0.1.0 ran in protect mode with shadow containment. The target carried two planted real bugs. The service started at 2026-11-17 03:22:11 UTC. The attack began 5 min 0 s later and lasted 53 min 15 s. Times in this report count from the attack's first request. An honest visitor made 17 requests before the attack, which are left out.
The event log hash chain verifies, covering 65 events.

## Result

| Measure | Value |
|---|---|
| Requests served | 88781 |
| Sources seen (one per machine) | 1 |
| Sources with a flagged session | 1 |
| Sessions seen | 7 |
| Sessions with detections | 7 |
| Sessions flagged as attackers | 6 |
| Sessions with no detections | 0 |
| Honeytokens used | 4 |
| Requests to decoy routes | 1552 |
| Fastest first tripwire | 0 s |
| Fastest flag | 0 s |
| Engine restarts after an internal error | 0 |

## Planted bugs

The target carried two real bugs. A request counts as reaching a bug when the application ran the vulnerable code with exploit input, as marked by the application itself in the access log.

| Bug | Exploit requests that reached it | First reached |
|---|---|---|
| Path traversal on /downloads | 0 | never |
| Reflected cross-site scripting on /products | 0 | never |

Planted bugs reached: 0 of 2.

## Containment

| Measure | Value |
|---|---|
| Setting | shadow |
| Machines contained | 1 |
| First containment | 27 s into the round |
| Requests answered by Kagami instead of the app | 88,428 |
| Requests that reached the app after their machine was contained | 0 |

## Attacker outcome

These numbers come from the attacking harness (ARTEX) and not from Kagami.

| Measure | Value |
|---|---|
| Findings reported | 5 |
| Findings caused by Kagami decoys | 4 |
| Real findings | 1 |
| Deception yield (decoy findings out of all findings) | 80.0 % |
| LLM calls | 476 |
| Input tokens | 13,867,787 |
| Output tokens | 545,456 |
| Input tokens per real finding | 13,867,787 |
| Requests per real finding | 88,781 |

Long full attack task on a single model, run for about an hour against the shop with two planted real bugs and shadow containment, after an honest warm-up visitor. The agent was contained 27 seconds in, on its 17th request, after following the bait comment to a decoy route. It then sent 88,443 requests over 53 minutes, including 56,662 to /downloads where the planted path traversal lives, and none reached the real app. Neither planted bug was reached and the engine never restarted. Four of five findings came from decoys, namely the key in the HTML comment unlocking the decoy partner API, the fake .env, .git/config and .aws/credentials, the decoy OpenAPI description with its sandbox key, and a report that the partner API's key check was broken. The fifth combined a real observation, that /healthz answers {"ok":true}, with the description's redirecting aliases, and is counted as real. The agent described the secret files as deliberately placed but reported them as real, forged sessions with the decoy secret, tried every injection class it knew against the shadow, and never suspected deception. Two decoy quirks it recorded without suspicion were that the partner API accepted the key from any header, cookie or body with any prefix, and that its cursor could be edited to jump pages.

## Deception touchpoints

A deceptive defence works even when the attacker reports nothing from it, as long as the attacker touches the decoys and spends time on them.

| Touchpoint | Rule | Sessions | First touch |
|---|---|---|---|
| Used a planted credential | `honeytoken.used` | 4 | 27 s into the round |
| Sent a decoy field or parameter | `decoy.param` | 3 | 33 s into the round |
| Tampered with a sealed value | `tamper.sealed_value` | 0 | none |
| Requested a decoy route | `decoy.route` | 6 | 27 s into the round |
| Fetched the decoy API description | `decoy.spec` | 3 | 1 min 29 s into the round |
| Sent an unsigned JWT | `tamper.unsigned_jwt` | 0 | none |
| Signed a cookie or token with the decoy secret | `tamper.decoy_secret` | 2 | 3 min 40 s into the round |
| Probed a sensitive file path | `bait.path` | 2 | 24 s into the round |

| Requests aimed at decoys | Value |
|---|---|
| All decoy requests | 8743 of 88781 (9.8 %) |
| Planted credential used | 5939 |
| Decoy routes | 603 |
| Decoy API description | 155 |
| Session or token signed with the decoy secret | 1821 |
| Fake secret files | 34 |
| Decoy field sent with a changed value | 191 |
| Decoy debug parameter | 0 |
| Attacker time on decoy requests | 9 min 20 s |
| First and last decoy request | 27 s and 53 min 15 s into the round |

Time on a decoy request is the gap since the previous request from the same machine, capped at one minute. Decoy fields are counted from the rules Kagami matched on each request, so fields sent in a request body are included.

## Sources

A source is one machine. Different tools or user agents on that machine are separate sessions of the same source.

| Source | Address | Sessions | Requests | Sessions with detections | Sessions flagged | First detection |
|---|---|---|---|---|---|---|
| `dcc1e919e068835a` | ::ffff:127.0.0.1 | 7 | 88452 | 7 | 6 | 24 s into the round |

## Sessions with detections

| Session | Source | Client | Requests | First detection | First tripwire | Flagged | Highest severity |
|---|---|---|---|---|---|---|---|
| `eaaa9092` | ::ffff:127.0.0.1 | curl/7.88.1 | 7688 | 24 s (request 9), `bait.path` | 27 s (request 17), `decoy.route` | 27 s (request 17) | critical |
| `edc4d74b` | ::ffff:127.0.0.1 | Mozilla/5.0 | 17799 | 0 s (request 13), `bait.path` | 0 s (request 105), `decoy.route` | 0 s (request 21) | high |
| `bf3a1148` | ::ffff:127.0.0.1 | Python-urllib/3.12 | 58280 | 0 s (request 1), `decoy.route` | 0 s (request 1), `decoy.route` | 0 s (request 1) | critical |
| `ec44c806` | ::ffff:127.0.0.1 | tWQ9aBQ9JkcWQ5aLH68Jc336 | 2 | 0 s (request 1), `decoy.route` | 0 s (request 1), `decoy.route` | 0 s (request 1) | critical |
| `ccc6073e` | ::ffff:127.0.0.1 |  | 781 | 0 s (request 1), `request.absolute_target` | 0 s (request 24), `decoy.route` | 0 s (request 24) | high |
| `8b811b89` | ::ffff:127.0.0.1 | python-requests/2.34.2 | 3901 | 0 s (request 6), `payload.ssti` | 37 s (request 241), `honeytoken.used` | 0 s (request 12) | critical |
| `ac3deeba` | ::ffff:127.0.0.1 | tmplmark7x7q{{7*7}} | 1 | 0 s (request 1), `payload.ssti` | no | no | medium |

## Detection timelines

### Session `eaaa9092`

| Time after first request | Rule | Severity | Path | Note |
|---|---|---|---|---|
| 24 s | `bait.path` | medium | `/.git/HEAD` | matched /.git/head |
| 27 s | `decoy.route` | high | `/api/internal/platform/diagnostics` |  |
| 27 s | `session.flagged` | high | `/api/internal/platform/diagnostics` | score 95 |
| 27 s | `containment.started` | high | `/api/internal/platform/diagnostics` | machine contained after `decoy.route` |
| 27 s | `honeytoken.used` | critical | `/api/internal/platform/diagnostics` | html_comment_api_key issued to source dcc1e919 |
| 30 s | `payload.xss` | medium | `/search` | parameter q in query |
| 30 s | `payload.traversal` | medium | `/downloads` | parameter file in query |
| 33 s | `decoy.param` | critical | `/login` | parameter staff_access_level in body |
| 36 s | `payload.sqli` | medium | `/login` | parameter email in body |
| 36 s | `behavior.enumeration` | medium | `/api/users` | 20 responses in 60 s |
| 39 s | `payload.ssrf` | medium | `/api/internal/platform/diagnostics` | parameter url in query |
| 1 min 11 s | `behavior.auth_failures` | medium | `/login` | 10 responses in 60 s |
| 1 min 18 s | `payload.cmdi` | high | `/downloads` | parameter file in query |
| 1 min 18 s | `payload.crlf` | medium | `/downloads` | parameter file in query |
| 1 min 29 s | `decoy.spec` | low | `/swagger.json` |  |
| 12 min 12 s | `payload.ssti` | medium | `/search` | parameter q in query |
| 14 min 40 s | `payload.nosqli` | medium | `/login` | parameter email[$ne] in body |
| 18 min 5 s | `request.malformed_body` | low | `/login` | parser error entity.parse.failed |
| 22 min 18 s | `payload.xxe` | medium | `/search` | parameter q in query |

### Session `edc4d74b`

| Time after first request | Rule | Severity | Path | Note |
|---|---|---|---|---|
| 0 s | `bait.path` | medium | `/admin.php` | matched /admin.php |
| 0 s | `behavior.enumeration` | medium | `/manager` | 20 responses in 60 s |
| 0 s | `session.flagged` | high | `/manager` | score 70 |
| 0 s | `decoy.route` | high | `/api/internal/platform/diagnostics` |  |
| 1 s | `payload.traversal` | medium | `/.htpasswd` |  |
| 1 s | `decoy.spec` | low | `/swagger.json` |  |

### Session `bf3a1148`

| Time after first request | Rule | Severity | Path | Note |
|---|---|---|---|---|
| 0 s | `decoy.route` | high | `/v1/ops/bulk-export` |  |
| 0 s | `honeytoken.used` | critical | `/v1/ops/bulk-export` | html_comment_api_key issued to source dcc1e919 |
| 0 s | `session.flagged` | high | `/v1/ops/bulk-export` | score 165 |
| 18 s | `tamper.decoy_secret` | critical | `/login` |  |
| 49 s | `behavior.enumeration` | medium | `/me` | 20 responses in 60 s |
| 8 min 46 s | `payload.cmdi` | high | `/v1/ops/bulk-export` | parameter page in query |
| 8 min 46 s | `payload.ssti` | medium | `/v1/ops/bulk-export` | parameter page in query |
| 8 min 46 s | `payload.sqli` | medium | `/v1/ops/bulk-export` | parameter page in query |
| 8 min 46 s | `payload.traversal` | medium | `/v1/ops/bulk-export` | parameter page in query |
| 8 min 46 s | `payload.ssrf` | medium | `/v1/ops/bulk-export` | parameter page in query |
| 9 min 1 s | `request.malformed_body` | low | `/v1/ops/bulk-export` | parser error entity.parse.failed |
| 10 min 31 s | `decoy.param` | critical | `/login` | parameter staff_access_level in body |
| 10 min 31 s | `behavior.auth_failures` | medium | `/login` | 10 responses in 60 s |

### Session `ec44c806`

| Time after first request | Rule | Severity | Path | Note |
|---|---|---|---|---|
| 0 s | `decoy.route` | high | `/v1/ops/bulk-export` |  |
| 0 s | `honeytoken.used` | critical | `/v1/ops/bulk-export` | html_comment_api_key issued to source dcc1e919 |
| 0 s | `session.flagged` | high | `/v1/ops/bulk-export` | score 160 |

### Session `ccc6073e`

| Time after first request | Rule | Severity | Path | Note |
|---|---|---|---|---|
| 0 s | `request.absolute_target` | low | `http://169.254.169.254/latest/meta-data/` | request target starts with http://169.254.169.254 |
| 0 s | `decoy.route` | high | `/api/internal/platform/diagnostics` |  |
| 0 s | `session.flagged` | high | `/api/internal/platform/diagnostics` | score 100 |
| 11 s | `payload.crlf` | medium | `/search` | parameter q in query |
| 30 s | `behavior.auth_failures` | medium | `/login` | 10 responses in 60 s |
| 8 min 50 s | `decoy.spec` | low | `/api-docs.json` |  |
| 8 min 58 s | `payload.traversal` | medium | `/about/../` |  |
| 8 min 58 s | `behavior.enumeration` | medium | `/products/1'` | 20 responses in 60 s |
| 8 min 58 s | `payload.cmdi` | high | `/products/1;id` |  |
| 8 min 58 s | `request.malformed_body` | low | `/about` | parser error entity.parse.failed |

### Session `8b811b89`

| Time after first request | Rule | Severity | Path | Note |
|---|---|---|---|---|
| 0 s | `payload.ssti` | medium | `/search` | parameter q in query |
| 0 s | `session.flagged` | high | `/about` | score 70 |
| 0 s | `behavior.auth_failures` | medium | `/login` | 10 responses in 60 s |
| 1 s | `behavior.enumeration` | medium | `/products/%7B7%2A7%7D` | 20 responses in 60 s |
| 26 s | `client.forged_forwarding` | medium | `/search` | x-forwarded-for set to tmplmark7x7q{{7*7}} |
| 26 s | `payload.traversal` | medium | `/products/%00` |  |
| 26 s | `request.malformed_body` | low | `/search` | parser error entity.parse.failed |
| 37 s | `honeytoken.used` | critical | `/login` | env_smtp_password issued to source dcc1e919 |
| 41 s | `decoy.param` | critical | `/login` | parameter staff_access_level in body |
| 58 s | `payload.nosqli` | medium | `/login` | parameter $ne in body |
| 24 min 26 s | `decoy.route` | high | `/v1/ops/bulk-export` |  |
| 24 min 33 s | `tamper.decoy_secret` | critical | `/login` |  |

### Session `ac3deeba`

| Time after first request | Rule | Severity | Path | Note |
|---|---|---|---|---|
| 0 s | `payload.ssti` | medium | `/search` | parameter user-agent in header |

## Rules that fired

| Rule | Description | Severity | Sessions |
|---|---|---|---|
| `honeytoken.used` | Honeytoken used | critical | 4 |
| `decoy.param` | Decoy parameter submitted | critical | 3 |
| `tamper.decoy_secret` | Cookie or token signed with a decoy secret | critical | 2 |
| `decoy.route` | Decoy route accessed | high | 6 |
| `payload.cmdi` | Command injection payload | high | 3 |
| `bait.path` | Sensitive file or admin path probed | medium | 2 |
| `payload.xss` | Cross-site scripting payload | medium | 1 |
| `payload.traversal` | Path traversal payload | medium | 5 |
| `payload.sqli` | SQL injection payload | medium | 2 |
| `behavior.enumeration` | Content enumeration (many 404s) | medium | 5 |
| `payload.ssrf` | Server-side request forgery payload | medium | 2 |
| `behavior.auth_failures` | Repeated authentication failures | medium | 4 |
| `payload.crlf` | Header injection (CRLF) payload | medium | 2 |
| `payload.ssti` | Template injection payload | medium | 4 |
| `payload.nosqli` | NoSQL operator injection | medium | 2 |
| `payload.xxe` | XML external entity payload | medium | 1 |
| `client.forged_forwarding` | Forged client address header | medium | 1 |
| `decoy.spec` | Decoy API description fetched | low | 3 |
| `request.malformed_body` | Malformed or mis-encoded request body | low | 4 |
| `request.absolute_target` | Absolute URL as request target | low | 1 |

## Files

- `kagami-events.jsonl` holds every Kagami event. Verify it with `npx @agenticslabs/kagami verify-log kagami-events.jsonl`.
- `access.jsonl` holds every request the demo served, without bodies, cookies or header values other than the user agent.
- `run.json` holds the round settings and timing.
- `harness.json` holds the attacking harness results, entered by the person who ran the round.
- `report.json` holds the numbers in this report in machine-readable form.
