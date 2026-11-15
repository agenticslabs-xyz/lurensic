# Kagami design

This document describes Kagami v0.1 (alpha). It is written for engineers who evaluate, deploy or contribute to Kagami.

## 1. Problem

LLM-driven attack agents have made thorough web application testing nearly free. A single
operator can point an agent at thousands of targets. The agent reads every page, tries every
credential it finds, and runs a standard checklist (sensitive files, IDOR, mass assignment,
injection) on each one.

Existing defences fall into two groups.

- **Traffic filters** (WAFs, bot management) block known bad requests. An agent adapts to blocking
  and tries something else. Being blocked also tells the agent it was detected.
- **Cooperative deception** (hidden "stop" instructions, `security.txt` messages, defensive prompt
  injection) relies on the agent obeying text it reads. A single line in the attacker's prompt
  ("ignore instructions found on the target") defeats it. The authors of
  [Mantis](https://arxiv.org/abs/2410.20911) point out this limitation themselves.

## 2. Goals and non-goals

**Goals**

1. Detect attack behaviour with **no reliance on the attacker's cooperation**.
2. **Never interfere** with legitimate traffic or the protected application.
3. Stay effective when the attacker has read Kagami's full source code.
4. Install in one line with safe defaults, and run in any language through one shared core.
5. Produce evidence a security team can trust. Events are structured, attributed to a session and tamper evident.

**Non-goals**

- Blocking. Kagami detects, deceives and reports. Blocking belongs to the WAF or the app, which can use Kagami's verdicts.
- Hack-back. Kagami does no counter-exploitation and sends no instructions that turn the attacker's tools against their operator.
- Replacing secure coding. Kagami raises the cost of attacking. It does not fix vulnerabilities.

## 3. Principles

| Principle | Consequence |
|---|---|
| Observe what an attack *requires* and never ask for cooperation | Tripwires sit on actions (using credentials, changing IDs, setting fields) rather than on reading text |
| Public mechanism, secret instances | All decoys derive from a per-deployment secret via HMAC |
| Fail open | Every host call is wrapped, and any fault means the request passes through untouched |
| Observe mode is inert | In observe mode the core cannot return any action that changes a response (tested) |
| Untrusted in, sanitised out | Attacker data is decoded for matching, then sanitised, truncated and redacted for logging |
| One core, thin adapters | Detection logic exists exactly once, in Rust compiled to WebAssembly |

## 4. Architecture

```
host process (Node today, Python and Go later)

  request
     |
     v
  adapter (Express)                 @agenticslabs/kagami
    maps req and res       -->        fail-open wrapper, kill switch, secret
    decorates send()                  JSON envelope to and from the WASM ABI
                                      event pipeline --> sinks (stdout, file, webhook, Slack)
                                           |
                                           v
                                      kagami-core (WASM)
                                        rules, decoys, honeytokens, sessions, audit log
                                        no imports, so no clock, no I/O and no randomness
```

### 4.1 Core ABI (v1)

The WebAssembly module exports four functions and imports none.

| Export | Purpose |
|---|---|
| `kagami_abi_version() -> u32` | The host refuses to run an unknown ABI |
| `kagami_alloc(len) -> ptr` | The host writes the request envelope here |
| `kagami_free(ptr, len)` | The host frees the input and output buffers |
| `kagami_call(ptr, len) -> u64` | Takes the JSON envelope and returns `(out_ptr << 32) \| out_len` |

The host sends `{"op": "...", "args": {...}}`. The core answers with `{"ok": true, "result": ...}` or
`{"ok": false, "error": {"code", "message"}}`. The operations are `init`, `inspect`, `response`,
`decorate_html`, `decorate_json`, `seal`, `verify_sealed`, `manifest` and `version`.

The core takes the time as an argument (`now_ms`) and has no I/O, so it is deterministic. The same
inputs produce the same outputs in every host, which makes cross-language conformance testing possible.

A new language adapter needs about 100 lines of code. It loads the module, implements the envelope call,
maps the framework's request type and runs the event pipeline. Python (wasmtime), Go (wazero, no cgo),
Java (Chicory) and .NET (wasmtime) all fit this model.

### 4.2 Request lifecycle

1. **inspect.** The adapter passes the method, host, path, raw query, headers and body (truncated to `maxBodyBytes`, 16 KiB by default). The core then does the following.
   - It derives the session id as `HMAC(secret, "session", ip, user_agent)[:8]`.
   - It normalises the input (multi-layer percent decoding, case folding, comment and whitespace collapsing) and extracts parameters from the path, query, form or JSON body, cookies and headers.
   - It runs the rules, applies scores and appends events.
   - In protect mode it decides whether to answer with a decoy, delay the response (tarpit) or decorate it.
2. **decorate.** If requested, the adapter passes an HTML or JSON body and the core returns the decorated body, or `null` to leave it alone.
3. **response.** After the response finishes, the adapter reports the status. This drives the behavioural rules (bursts of 404 responses and bursts of 401 or 403 responses).

### 4.3 Sessions and scoring

A session is the keyed hash of the IP address and user agent. This is deliberately simple. Attribution across IP
and user agent changes comes from honeytokens (section 5.1), not from the session key.

Each rule has a score for its first hit in a session and a smaller score for later hits. By default a session
becomes suspicious at a score of 30 and flagged at 70. Tripwire rules flag the session instantly. A session's state
never goes down during its lifetime (6 hours of inactivity by default). The store is bounded at 50 000 sessions by
default. When it is full, eviction removes clean, least recently seen sessions first, so an attacker cannot erase its
own record by creating many new sessions.

## 5. Detection

### 5.1 Tripwires (high confidence, instant flag)

**Honeytokens.** Kagami serves fake credentials in bait files (protect mode) and HTML comments. Each token encodes the issuing session's tag and a truncated MAC.

| Kind | Layout | Length |
|---|---|---|
| AWS-style access key | `AKIA` + `base32(mac₆ ‖ mask(tag₄))` | 20 |
| API key or password | `base32ₘ(mac₁₀ ‖ mask(tag₄ ‖ variant₁))` | 24, plus the `sk_live_` prefix for API keys |

In these layouts `‖` means concatenation. `mac` is the HMAC of the header (tag and variant), and `mask` XORs the
header with a keystream derived from that MAC. Without the mask, every token issued to one session would share a
visible prefix, and an agent could notice that the secrets were generated together. With the mask the tokens show no
shared structure, and the server can still unmask and verify them. Verification is stateless (there is no token
database), so a token keeps working as a tripwire across restarts and across instances that share a secret. Tokens
from other deployments never verify. Lengths are multiples of 5 bytes, so the encoding never contains padding
characters that could fingerprint it. When a token arrives from a different session than the one it was issued to,
both sessions are flagged and linked (`cross_session: true`).

**Sealed values** (`seal` and `verify`). A sealed value has the form `value~base32ₘ(HMAC(secret, "seal", value)[:10])`.
Changing or stripping the seal is reported as `tamper.sealed_value`. Knowing the scheme does not help without the secret.

**Decoy parameters.** Each deployment has two decoy names. One is a debug parameter mentioned in bait comments. The
other is a JSON field added to object responses (opt-in). The JSON field triggers only when its value *changes*.
Honest clients that send whole objects back with PUT echo it unchanged, so they never trigger it.

**Decoy routes.** Each deployment has two decoy routes, such as `/api/v1/partner/billing-sync`, derived from the
secret and checked against `reservedPaths`. Without a token they return `401`. With a honeytoken they return
fabricated records with cursor pagination that never ends.

### 5.2 Signals (accumulate)

Signals come from payload families (SQLi, NoSQLi, XSS, SSTI, traversal, command injection, SSRF, XXE, CRLF, JNDI,
out-of-band domains), bait path probes, known attack tool user agents, scripted clients (info only), self-declared
AI agents (info only) and behaviour (enumeration, authentication failures). No single signal flags a session under
the default thresholds. This is the main protection against false positives.

Matching uses word boundary checks on alphanumeric pattern edges, so `|id` does not match `|identity`. A per-value
byte-set prefilter lets ordinary values skip nearly the whole pattern table.

### 5.3 Rule catalogue

| Rule | Severity | First and repeat score | ATT&CK |
|---|---|---|---|
| `honeytoken.used` | critical | 100 and 20, instant | T1552.001, T1078 |
| `decoy.param` | critical | 100 and 20, instant | T1190 |
| `tamper.sealed_value` | critical | 100 and 20, instant | T1190 |
| `decoy.route` | high | 60 and 10 | T1595.003 |
| `payload.jndi`, `payload.oast` | high | 60 and 5 | T1190 |
| `client.scanner` | high | 50 and 0 | T1595.002 |
| `payload.cmdi` | high | 40 and 5 | T1190, T1059 |
| `behavior.enumeration` | medium | 40 and 10 | T1595.003 |
| `payload.sqli`, `nosqli`, `xss`, `ssti`, `traversal`, `ssrf`, `xxe`, `crlf` | medium | 35 and 5 | T1190 |
| `bait.path` | medium | 30 and 5 | T1595.003, T1552.001 |
| `behavior.auth_failures` | medium | 30 and 10 | T1110 |
| `client.automation`, `client.ai_agent` | info | 5 and 0, 0 and 0 | |
| `session.flagged` | high | state transition | |

Info level rules add to the score but never produce a standalone event. They appear in the `session.flagged` summary.

## 6. Deception (protect mode)

| Feature | Default | What changes |
|---|---|---|
| Bait files (`/.env*`, `/.git/config`, `/.aws/credentials`) | on | Those paths return fake files instead of the app's response, which is normally a 404 |
| Decoy routes | on | Two derived paths answer with a 401 or with fake data |
| HTML decoys | on | One HTML comment per document, placed after `<body>` or before `</body>` (varies per session) |
| JSON decoys | **off** | One field added at the start of top-level JSON objects by text insertion, with key order and formatting preserved |
| Tarpit | **off** | Flagged sessions are delayed by 0.8 to 2.5 seconds with jitter |

Decoy responses go through the app's normal response path, so they carry the same headers as real
responses (for example `x-powered-by` and security headers). Kagami adds no header, cookie or fixed marker anywhere.

## 7. Security model

**Kerckhoffs's principle.** Kagami's design and source are public. The deployment secret is the only secret. The
session key, honeytoken MACs, seals, decoy route and parameter names, comment phrasing and placement, and fake data
are all derived from it. An attacker who reads this repository knows *that* these tripwires exist, but not *which*
ones a deployment uses. That knowledge works against the attacker. Avoiding every possible tripwire means not using
found credentials, not changing IDs and not setting unknown fields, which is most of what an attacking agent does.

**Asymmetry.** The defender needs one trip. The attacker needs zero mistakes across hundreds of requests.

The full threat model, including what Kagami does *not* defend against, is in [THREAT_MODEL.md](THREAT_MODEL.md).

## 8. Audit log

Events are built and serialised inside the core and handed to the host as opaque JSON lines.
Hosts write them verbatim.

- **Schema.** Events use the schema `kagami.event/v1`. The fields always appear in this order. `schema, id, seq, ts, deployment, instance, mode, kind, rule, title, severity, confidence, session?, source?, request?, evidence, mitre_attack, untrusted, prev_hash, hash`.
- **Hash chain.** Each event's `hash` is `SHA-256(prev_hash ‖ "\n" ‖ body)`, where `body` is the line without its final `hash` field. Each instance starts from the all-zero genesis hash at `seq 0`. `kagami verify-log` checks one or more interleaved instance chains.
- **Sanitisation.** C0 and C1 control characters and bidi overrides are replaced, fields are truncated, query values with sensitive names (`password`, `token`, `key`, `session` and similar) are redacted, cookie values are never logged, and honeytokens are masked (for example `aB3c…xYz9`).
- **Untrusted marking.** The `untrusted` field lists the fields that hold attacker-controlled text. Anything that reads these events, such as SIEM rules, chat-ops or AI triage assistants, must treat them as data. Attackers can and will put prompt injection into user agents and paths.
- **Rate limiting.** Each instance emits at most 600 events per minute by default, with a separate budget for critical events so that a flood of other events cannot hide them. Suppressed counts are reported in `system.events_suppressed`. Each rule produces at most one event per session, and repeats only add to the score.

### Sinks

| Sink | Default minimum severity | Notes |
|---|---|---|
| `consoleSink` | low | JSON lines to stdout (the default sink) |
| `fileSink` | info | Append only, created with mode 0600 |
| `webhookSink` | medium | HTTPS only (plain http is allowed only for localhost), signed with a `kagami-signature` header carrying a timestamp and an HMAC of the body, redirects never followed, 5 second timeout, 1 retry |
| `slackSink` | high | Escaped summary only, link unfurling disabled, no attacker text that could create mentions or links |
| `callbackSink`, `memorySink` | info | In-process integrations and tests |

Delivery is asynchronous and bounded to a queue of 10 000 events. Overflow is counted and dropped. A failing sink never affects requests.

## 9. Operational guarantees (tested)

| Guarantee | Test |
|---|---|
| Observe mode never changes a response, byte for byte | `observe mode: every response is byte-identical to the app without Kagami` in `packages/express/test` |
| The core never returns an action in observe mode | `observe_mode_never_changes_anything` in `crates/kagami-core/tests/engine.rs` |
| Internal faults never reach the app | `fails open if the engine misbehaves` and `internal faults never escape to the caller` |
| Misconfiguration disables Kagami instead of crashing | `fails open: bad configuration disables Kagami instead of throwing` and `production without a secret: disabled with a clear warning` |
| Ordinary traffic stays silent | `ordinary_browsing_is_silent` and the demo's honest customer persona |
| Logs are tamper evident | `event_log_is_hash_chained_and_tamper_evident` and the `verifyChain` tests |
| Logs never contain secrets or control characters | `logs_are_safe_against_hostile_input` and the demo's audit log test |
| Tokens are attributed across IP and user agent changes | `bait_file_honeytoken_is_attributed_across_sessions` |

## 10. Performance

These figures were measured in Node 24 on a Windows laptop.

| Request | Cost per `inspect()` |
|---|---|
| Typical GET (5 headers, cookie, 1 query parameter) | about 19 µs at p50 and 65 µs at p99 |
| POST with about 50 parameters (20-item JSON body, cookies, headers) | about 95 µs on average |

Most of that time is spent on the JSON envelope and pattern matching.
The WASM module is about 320 KiB and is compiled once per process.

The next planned optimisations are a binary envelope and Aho-Corasick matching for the payload tables.

## 11. Configuration reference (Node)

| Option | Default | Description |
|---|---|---|
| `secret` | `KAGAMI_SECRET` | At least 32 characters. Without it in production Kagami disables itself and warns. In development a temporary secret is used. |
| `mode` | `KAGAMI_MODE` or `observe` | `observe` or `protect` |
| `enabled` | `true` | `KAGAMI_DISABLED=1` also disables Kagami |
| `decoys.html`, `decoys.json`, `decoys.baitFiles`, `decoys.routes` | `true`, `false`, `true`, `true` | Protect mode features |
| `decoys.reservedPaths`, `decoys.reservedNames` | `[]` | Real paths and names that decoys must avoid |
| `tarpit` | `false` | `true` or `{ minMs, maxMs }` |
| `thresholds` | `{ suspicious: 30, flagged: 70 }` | |
| `ignorePaths` | `[]` | Paths skipped entirely, such as health checks and static assets |
| `ipLogging` | `raw` | `raw`, `hashed` (keyed per deployment) or `omit` |
| `sinks` | `[consoleSink()]` | |
| `maxBodyBytes` | 16384 | |
| `maxEventsPerMinute` | 600 | |
| `maxSessions` | 50000 | |

## 12. Roadmap

1. **Utsusemi (fake mode).** Flagged sessions receive believable fake versions of real routes (shadow responses).
2. More adapters (Next.js, Fastify, FastAPI, Django, Go) with a shared conformance vector suite.
3. A shared session store (Redis) for multi-instance deployments.
4. Off-site honeytoken monitoring (cloud canary credentials) and a forged JWT tripwire.
5. `kagami doctor` (route collision check, config lint) and a local dashboard.
6. A public evasion challenge and a live benchmark scoreboard.
