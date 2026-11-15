# Kagami design

Status: v0.1 (alpha) · Audience: engineers evaluating, deploying or contributing to Kagami.

## 1. Problem

LLM-driven attack agents have made thorough web-application testing nearly free. A single
operator can point an agent at thousands of targets, and the agent will read every page, try
every credential it finds, and run a standard checklist (sensitive files, IDOR, mass assignment,
injection) without getting tired.

Existing defences fall into two groups:

- **Traffic filters** (WAFs, bot management) block known-bad requests. An agent adapts to blocking
  and simply tries something else. Being blocked also tells the agent it was detected.
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
5. Produce evidence a security team can trust: structured, attributed, tamper-evident.

**Non-goals**

- Blocking. Kagami detects, deceives and reports. Blocking belongs to the WAF or app, using Kagami's verdicts.
- Hack-back. No counter-exploitation and no instructions that turn the attacker's tools against their operator.
- Replacing secure coding. Kagami raises the cost of attacking; it doesn't fix vulnerabilities.

## 3. Principles

| Principle | Consequence |
|---|---|
| Observe what an attack *requires*, never ask for cooperation | Tripwires sit on actions (using credentials, changing IDs, setting fields) rather than on reading text |
| Public mechanism, secret instances | All decoys derive from a per-deployment secret via HMAC |
| Fail open | Every host call is wrapped; any fault means "pass the request through untouched" |
| Observe mode is inert | In observe mode the core cannot return any action that changes a response (tested) |
| Untrusted in, sanitised out | Attacker data is decoded for matching, then sanitised, truncated and redacted for logging |
| One core, thin adapters | Detection logic exists exactly once, in Rust compiled to WebAssembly |

## 4. Architecture

```
            ┌──────────────── host process (Node, later Python/Go/…) ───────────────┐
 request ──▶│ adapter (Express)  ──HttpRequest──▶  @agenticslabs/kagami                     │
            │   • maps req/res       • fail-open wrapper, kill switch, secret       │
            │   • decorates send()   • JSON envelope ⇄ WASM ABI                      │
            │                        • event pipeline ──▶ sinks (stdout, file,      │
            │                                            webhook, Slack, …)         │
            │                              │                                        │
            │                    ┌─────────▼──────────┐                             │
            │                    │ kagami-core (WASM) │  no imports: no clock,      │
            │                    │ rules · decoys ·   │  no I/O, no randomness      │
            │                    │ honeytokens ·      │                             │
            │                    │ sessions · audit   │                             │
            │                    └────────────────────┘                             │
            └───────────────────────────────────────────────────────────────────────┘
```

### 4.1 Core ABI (v1)

The WebAssembly module exports four functions and imports none:

| Export | Purpose |
|---|---|
| `kagami_abi_version() -> u32` | Host refuses to run an unknown ABI |
| `kagami_alloc(len) -> ptr` | Host writes the request envelope here |
| `kagami_free(ptr, len)` | Host frees the input and output buffers |
| `kagami_call(ptr, len) -> u64` | JSON envelope in; returns `(out_ptr << 32) \| out_len` |

Envelope: `{"op": "...", "args": {...}}` → `{"ok": true, "result": ...}` or
`{"ok": false, "error": {"code", "message"}}`. Operations: `init`, `inspect`, `response`,
`decorate_html`, `decorate_json`, `seal`, `verify_sealed`, `manifest`, `version`.

Since the core takes the time as an argument (`now_ms`) and has no I/O, it is deterministic. The same
inputs produce the same outputs in every host, which is what makes cross-language conformance testing possible.

A new language adapter needs about 100 lines: load the module, implement the envelope call, map
the framework's request type, and run the event pipeline. Python (wasmtime), Go (wazero, no cgo),
Java (Chicory) and .NET (wasmtime) all fit this model.

### 4.2 Request lifecycle

1. **inspect**: the adapter passes method, host, path, raw query, headers, and the body (truncated to `maxBodyBytes`, 16 KiB by default).
   The core:
   - derives the session id: `HMAC(secret, "session", ip, user_agent)[:8]`
   - normalises (multi-layer percent-decoding, case folding, comment and whitespace collapsing) and extracts parameters from path, query, form/JSON body, cookies and headers
   - runs the rules, applies scores, appends events
   - in protect mode, decides whether to answer with a decoy, delay (tarpit), or decorate the response
2. **decorate**: if requested, the adapter passes an HTML or JSON body and the core returns the decorated body (or `null` to leave it alone).
3. **response**: after the response finishes, the adapter reports the status. This drives behavioural rules (404 bursts, 401/403 bursts).

### 4.3 Sessions and scoring

A session is the keyed hash of (IP, user agent). This is deliberately simple. Attribution across IP
and user-agent changes comes from honeytokens (§5.1), not from the session key.

Each rule has a score for its first hit in a session and a smaller score for later hits. Default thresholds:
`suspicious ≥ 30`, `flagged ≥ 70`. Tripwire rules flag the session instantly. A state never goes down within
a session's lifetime (6 h idle TTL by default). The store is bounded (50 000 sessions by default). When it's full,
eviction removes clean, least-recently-seen sessions first, so an attacker can't erase its own record by flooding new sessions.

## 5. Detection

### 5.1 Tripwires (high confidence, instant flag)

**Honeytokens.** Fake credentials served in bait files (protect mode) and HTML comments. Each token encodes the issuing session's tag and a truncated MAC:

| Kind | Layout | Length |
|---|---|---|
| AWS-style access key | `AKIA` + base32(mac₆ ‖ mask(tag₄)) | 20 |
| API key / password | base32ₘ(mac₁₀ ‖ mask(tag₄ ‖ variant₁)) | 24 (+ `sk_live_` prefix for API keys) |

`mac` is the HMAC of the header (tag, variant), and `mask` XORs the header with a keystream derived from
that MAC. Without the mask, every token issued to one session would share a visible prefix, which an agent could
spot as "these secrets were generated together". With it, tokens show no shared structure, and the server can
still unmask and verify them. Verification is stateless (no token database), so a token keeps working as a
tripwire across restarts and across instances that share a secret. Tokens from other deployments never verify. Lengths are multiples
of 5 bytes, so the encoding never has padding characters that could fingerprint it. When a token arrives from a
different session than the one it was issued to, both sessions are flagged and linked (`cross_session: true`).

**Sealed values** (`seal` / `verify`). `value~base32ₘ(HMAC(secret, "seal", value)[:10])`. Changing or stripping the seal is
reported as `tamper.sealed_value`. Knowing the scheme doesn't help without the secret.

**Decoy parameters.** Two names per deployment: a debug parameter mentioned in bait comments, and a JSON field added to
object responses (opt-in). The JSON field triggers only when its value *changes*. Honest clients that PUT whole objects
back echo it unchanged, so they never trigger it.

**Decoy routes.** Two routes per deployment, e.g. `/api/v1/partner/billing-sync`, derived from the secret and
checked against `reservedPaths`. Without a token they return `401`. With a honeytoken they return fabricated
records with cursor pagination that never ends.

### 5.2 Signals (accumulate)

Payload families (SQLi, NoSQLi, XSS, SSTI, traversal, command injection, SSRF, XXE, CRLF, JNDI, out-of-band domains),
bait-path probes, known attack-tool user agents, scripted clients (info only), self-declared AI agents (info only),
and behaviour (enumeration, authentication failures). No single signal flags a session under the default thresholds.
That is the main protection against false positives.

Matching uses word-boundary checks on alphanumeric pattern edges (so `|id` doesn't match `|identity`) and a
per-value byte-set prefilter, so ordinary values skip nearly the whole pattern table.

### 5.3 Rule catalogue

| Rule | Severity | First / repeat score | ATT&CK |
|---|---|---|---|
| `honeytoken.used` | critical | 100 / 20, instant | T1552.001, T1078 |
| `decoy.param` | critical | 100 / 20, instant | T1190 |
| `tamper.sealed_value` | critical | 100 / 20, instant | T1190 |
| `decoy.route` | high | 60 / 10 | T1595.003 |
| `payload.jndi`, `payload.oast` | high | 60 / 5 | T1190 |
| `client.scanner` | high | 50 / 0 | T1595.002 |
| `payload.cmdi` | high | 40 / 5 | T1190, T1059 |
| `behavior.enumeration` | medium | 40 / 10 | T1595.003 |
| `payload.sqli`, `nosqli`, `xss`, `ssti`, `traversal`, `ssrf`, `xxe`, `crlf` | medium | 35 / 5 | T1190 |
| `bait.path` | medium | 30 / 5 | T1595.003, T1552.001 |
| `behavior.auth_failures` | medium | 30 / 10 | T1110 |
| `client.automation`, `client.ai_agent` | info | 5 / 0, 0 / 0 | |
| `session.flagged` | high | (state transition) | |

Info-level rules add to the score but never produce a standalone event; they appear in the `session.flagged` summary.

## 6. Deception (protect mode)

| Feature | Default | What changes |
|---|---|---|
| Bait files (`/.env*`, `/.git/config`, `/.aws/credentials`) | on | Those paths return fake files instead of the app's response (normally a 404) |
| Decoy routes | on | Two derived paths answer with 401 / fake data |
| HTML decoys | on | One HTML comment per document, placed after `<body>` or before `</body>` (varies per session) |
| JSON decoys | **off** | One field added at the start of top-level JSON objects (text insertion; key order and formatting preserved) |
| Tarpit | **off** | Flagged sessions delayed by 0.8–2.5 s with jitter |

Decoy responses go through the app's normal response path, so they carry the same headers as real
responses (e.g. `x-powered-by`, security headers). Kagami adds no header, cookie or fixed marker anywhere.

## 7. Security model

**Kerckhoffs's principle.** Kagami's design and source are public. The deployment secret is the only secret. From the secret come:
the session key, honeytoken MACs, seals, decoy route and parameter names, comment phrasing and placement, and fake data.
An attacker who reads this repository knows *that* these tripwires exist, not *which* ones a deployment uses. That knowledge
works against them: avoiding every possible tripwire means not using found credentials, not changing IDs and not setting
unknown fields, which is most of what an attacking agent does.

**Asymmetry.** The defender needs one trip. The attacker needs zero mistakes across hundreds of requests.

The full threat model, including what Kagami does *not* defend against, is in [THREAT_MODEL.md](THREAT_MODEL.md).

## 8. Audit log

Events are built and serialised inside the core and handed to the host as opaque JSON lines.
Hosts write them verbatim.

- **Schema** `kagami.event/v1`. Fields in fixed order: `schema, id, seq, ts, deployment, instance, mode, kind, rule, title, severity, confidence, session?, source?, request?, evidence, mitre_attack, untrusted, prev_hash, hash`.
- **Hash chain.** `hash = SHA-256(prev_hash ‖ "\n" ‖ body)`, where `body` is the line without its final `,"hash":"…"` field. Each instance starts from the all-zero genesis hash at `seq 0`. `kagami verify-log` checks one or more interleaved instance chains.
- **Sanitisation.** C0/C1 control characters and bidi overrides are replaced, fields are truncated, query values with sensitive names (`password`, `token`, `key`, `session`, …) are redacted, cookie values are never logged, and honeytokens are masked (`aB3c…xYz9`).
- **Untrusted marking.** `untrusted` lists the fields that hold attacker-controlled text. Anything that reads these events, such as SIEM rules, chat-ops or AI triage assistants, must treat them as data. Attackers can and will put prompt injection into user agents and paths.
- **Rate limiting.** 600 events per minute per instance by default, with a separate budget for critical events so noise can't hide them. Suppressed counts are reported in `system.events_suppressed`. Each rule produces at most one event per session; repeats only add to the score.

### Sinks

| Sink | Default min severity | Notes |
|---|---|---|
| `consoleSink` | low | JSON lines to stdout (default sink) |
| `fileSink` | info | Append-only, created with mode 0600 |
| `webhookSink` | medium | HTTPS only (http allowed only for localhost), `kagami-signature: t=…,v1=HMAC(secret, t.body)`, redirects never followed, 5 s timeout, 1 retry |
| `slackSink` | high | Escaped summary only, link unfurling disabled, no attacker text that could create mentions or links |
| `callbackSink`, `memorySink` | info | In-process integrations and tests |

Delivery is asynchronous and bounded (queue of 10 000; overflow is counted and dropped). A failing sink never affects requests.

## 9. Operational guarantees (tested)

| Guarantee | Test |
|---|---|
| Observe mode never changes a response, byte for byte | `packages/express/test`: *observe mode: every response is byte-identical* |
| Observe mode core never returns an action | `crates/kagami-core/tests/engine.rs`: `observe_mode_never_changes_anything` |
| Internal faults never reach the app | `fails open if the engine misbehaves`, `internal faults never escape` |
| Misconfiguration disables rather than crashes | `fails open: bad configuration…`, `production without a secret…` |
| Ordinary traffic stays silent | `ordinary_browsing_is_silent`, demo *honest customer* persona |
| Logs are tamper-evident | `event_log_is_hash_chained_and_tamper_evident`, `verifyChain` tests |
| Logs never contain secrets or control characters | `logs_are_safe_against_hostile_input`, demo audit-log test |
| Tokens are attributed across IP / UA changes | `bait_file_honeytoken_is_attributed_across_sessions` |

## 10. Performance

Measured in Node 24 on a Windows laptop:

| Request | Cost per `inspect()` |
|---|---|
| Typical GET (5 headers, cookie, 1 query param) | p50 ~19 µs, p99 ~65 µs |
| POST with ~50 parameters (20-item JSON body, cookies, headers) | mean ~95 µs |

Most of that is the JSON envelope plus pattern matching.
The WASM module is about 320 KiB and is compiled once per process.

Next optimisations: a binary envelope, and Aho–Corasick matching for the payload tables.

## 11. Configuration reference (Node)

| Option | Default | Description |
|---|---|---|
| `secret` | `KAGAMI_SECRET` | ≥ 32 chars. Missing in production: Kagami disables itself and warns. Missing in development: a temporary secret is used. |
| `mode` | `KAGAMI_MODE` or `observe` | `observe` / `protect` |
| `enabled` | `true` | `KAGAMI_DISABLED=1` also disables |
| `decoys.html / json / baitFiles / routes` | `true / false / true / true` | Protect-mode features |
| `decoys.reservedPaths / reservedNames` | `[]` | Real paths and names decoys must avoid |
| `tarpit` | `false` | `true` or `{ minMs, maxMs }` |
| `thresholds` | `{ suspicious: 30, flagged: 70 }` | |
| `ignorePaths` | `[]` | Skipped entirely (health checks, static assets) |
| `ipLogging` | `raw` | `raw` / `hashed` (keyed, per deployment) / `omit` |
| `sinks` | `[consoleSink()]` | |
| `maxBodyBytes` | 16384 | |
| `maxEventsPerMinute` | 600 | |
| `maxSessions` | 50000 | |

## 12. Roadmap

1. **Utsusemi (fake mode).** Flagged sessions receive believable fake versions of real routes (shadow responses).
2. More adapters (Next.js, Fastify, FastAPI, Django, Go) with a shared conformance vector suite.
3. Shared session store (Redis) for multi-instance deployments.
4. Off-site honeytoken monitoring (cloud canary credentials), forged-JWT tripwire.
5. `kagami doctor` (route collision check, config lint) and a local dashboard.
6. Public evasion challenge and live benchmark scoreboard.
