<div align="center">

# Kagami

**Deception-based defence against AI-driven attacks.**

An open-source project by [Agentics Labs](https://agenticslabs.xyz).

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)
![Core](https://img.shields.io/badge/core-Rust%20and%20WebAssembly-informational.svg)

</div>

---

Kagami (鏡) is Japanese for mirror.

AI pentest agents are fast, cheap and thorough. They read every page, try every credential they find,
and run the same checklist on thousands of targets. Most AI defences today hide text in a page that asks
the agent to stop. That works until the attacker tells the agent to ignore instructions found on the target.

Kagami never asks the agent for anything. It places tripwires in your app that only an attacker
touches, ties each one to the session that found it, and records the attack. The tripwires sit on
actions an attacking agent has to take to succeed. An attacker who tells the agent to avoid them
also gives up the attack.

```js
import express from 'express';
import { kagami } from '@agenticslabs/kagami-express';

const app = express();
app.use(express.json());
app.use(kagami());            // observe mode by default
```

## Why instructions don't get around it

| An attacking agent will... | Kagami's tripwire | Why instructions don't help |
|---|---|---|
| probe for `.env`, `.git/config`, `.aws/credentials` | Serves short, ordinary fake files whose credentials are **honeytokens** bound to that machine | Trying found credentials is the reason to look for them. Use them anywhere on your site and the session is flagged and traced back, even after an IP change. |
| read page source for leaked endpoints and keys | An HTML comment on the home page and some other pages, leading to a **decoy API** that answers errors in your app's own format and serves endless fake data | The leak looks like any real leak. Route names are derived from your secret, so there is no global list to avoid. |
| test IDOR by changing IDs | **Sealed values**, where each ID carries an HMAC the client can't forge | Knowing exactly how it works doesn't help without the secret. The only way to avoid it is to stop testing IDOR. |
| test mass assignment with privileged-looking fields | A **decoy field** in JSON responses and, if you enable it, as a hidden input in POST forms. Honest clients send it back unchanged | Changing it is the attack, and honest round trips are ignored. |
| spray payloads and wordlists | Payload, enumeration and brute-force **signals** add up to a session score | These are the behaviours that define an attack. |

Once a session sets off a tripwire, everything it does is linked to it, and you get one alert with the whole timeline.

## Cut attackers off

Deception alone does not protect a site with real flaws. An agent that believes a decoy can still find
the real issue later. So Kagami can act on what it detects. With **containment** on, the first tripwire
cuts the attacker's whole machine off from your application. In every live benchmark round so far the
attacker's machine was identified within its first 35 requests, and over 99 % of its traffic came after
that point.

```js
app.use(kagami({
  mode: 'protect',
  containment: true,                 // contain on tripwires that honest visitors never touch
  enforcers: [blocklistFile({ path: '/etc/nginx/kagami-blocked.conf', format: 'nginx' })],
}));
```

- **Shadow by default.** A contained machine is served copies of your public pages and your own 404s, never the live application. It keeps working against a copy and does not learn it was cut off. Only responses a shared HTTP cache could store are copied, so it sees nothing an anonymous visitor could not. `action: 'block'` answers `403` instead.
- **One machine, every tool.** Containment covers the address the attacker used, or its whole IPv6 /64, across every tool and user agent on it. A honeytoken used from a new address also contains the machine it was issued to.
- **Hard to turn against your visitors.** Only tripwires contain by default, never accumulated signals. A request a browser sent on behalf of another site (`Sec-Fetch-Site: cross-site` or a foreign `Origin`) is logged but contains nobody, so a forged form cannot get a real visitor locked out. Allowlist your offices and testers with `allow`. Containment expires (one day by default) and `kagami.release(ip)` ends it early.
- **Dry run first.** In observe mode containment only reports `containment.started` events, so you can see who would have been contained before you enforce it.

**Enforcers** push each containment to the systems in front of your app, so attackers are stopped before
they reach your servers. They are provider neutral and run off the request path.

| Enforcer | Package | Use it with |
|---|---|---|
| `blocklistFile` | `@agenticslabs/kagami` | nginx (`deny` include), ipset, iptables, AWS WAF IP set imports, any tool that reads a list. Written atomically and kept across restarts. |
| `webhookEnforcer` | `@agenticslabs/kagami` | Your own endpoint, a SOAR, or a function that updates a cloud WAF. Signed with HMAC. |
| `callbackEnforcer` | `@agenticslabs/kagami` | Anything in process. |
| `cloudflareEnforcer` | [`@agenticslabs/kagami-cloudflare`](packages/cloudflare/README.md) | A Cloudflare IP list and a WAF custom rule, available on every Cloudflare plan. |

`kagami.contained()` returns the current list for any other integration, and `formatBlocklist` renders it.

## Built to be safe in production

- **Observe mode by default.** Kagami only detects, and a test proves every response stays **byte-identical** to your app without Kagami. Turn on `protect` once you trust it.
- **Fails open.** A bad config, a missing secret or an internal error lets requests through untouched. Kagami can't take your site down.
- **No fingerprint.** There are no Kagami headers, cookies or fixed paths. Decoy names, routes and tokens are derived from your deployment secret ([Kerckhoffs's principle](docs/DESIGN.md#7-security-model)).
- **Logs that can't be turned against you.** Events are structured JSON with secrets redacted, control and bidi characters stripped, attacker-controlled fields labelled `untrusted`, and a **SHA-256 hash chain** that makes edited or deleted entries detectable.
- **Fast.** The engine is pure Rust compiled to WebAssembly with zero imports (no clock, network or filesystem). A typical GET takes about 20 µs at p50 and about 65 µs at p99. A heavy POST with 50 parameters takes about 95 µs.
- **No data leaves your servers.** There is no telemetry and no cloud dependency.

## Quick start

```bash
npm install @agenticslabs/kagami-express
npx @agenticslabs/kagami secret          # put the output in KAGAMI_SECRET
```

```js
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami());                   // after body parsers, before your routes

// kagami() returns the middleware and an error handler as a pair, so requests
// that a body parser rejects (broken JSON, odd charsets) are still inspected.
```

Watch the events, which go to stdout as JSON lines by default. Then switch on deception.

```js
app.use(kagami({
  mode: 'protect',                   // or KAGAMI_MODE=protect
  decoys: { json: true, forms: true }, // opt in to a decoy field in JSON responses and POST forms
  ignorePaths: ['/healthz', '/static'],
  sinks: [
    consoleSink(),
    webhookSink({ url: 'https://siem.example.com/hook', secret: process.env.KAGAMI_WEBHOOK_SECRET }),
    slackSink({ webhookUrl: process.env.SLACK_WEBHOOK, minSeverity: 'high' }),
  ],
}));
```

Seal the IDs you hand to clients.

```js
app.get('/api/orders', (req, res) =>
  res.json(orders.map((o) => ({ ...o, id: req.kagami.seal(o.id) }))));

app.get('/api/orders/:id', (req, res) => {
  const id = req.kagami.verify(req.params.id, 'order_id');   // null means forged, and it is already reported
  if (id === null) return res.status(404).end();
  ...
});
```

Set `KAGAMI_DISABLED=1` to switch Kagami off.

## What an alert looks like

```json
{
  "schema": "kagami.event/v1",
  "rule": "honeytoken.used",
  "title": "Honeytoken used",
  "severity": "critical",
  "session": { "id": "c2c7a1f09e4b5d36", "source": "51d0e3a7b2c94f18", "score": 135, "state": "flagged" },
  "source": { "ip": "192.0.2.77", "user_agent": "python-httpx/0.27" },
  "request": { "method": "POST", "host": "shop.example.com", "path": "/login", "query": "" },
  "evidence": {
    "token_kind": "env_smtp_password",
    "token": "aB3c…xYz9",
    "issued_to_source": "9f2e40aa",
    "cross_source": true
  },
  "mitre_attack": ["T1552.001", "T1078"],
  "untrusted": ["source.user_agent", "request.host", "request.path", "request.query", "evidence"],
  "prev_hash": "35ad43ff…",
  "hash": "a1874cda…"
}
```

This event means the password used to log in came from the fake `.env` that Kagami served to the
machine with source `9f2e40aa`. The login came from a different address, and it is the same attacker.
Sessions from that machine that had already probed the site are flagged and linked as well.

Check that a log hasn't been tampered with.

```bash
npx @agenticslabs/kagami verify-log kagami-events.jsonl
# Chain intact. Checked 1824 events across 3 instance(s).
```

## Benchmarks

Kagami is developed against **real AI pentest agents** as well as scripted personas. The scripted
suite in [`examples/demo-shop/test/agent-sim.test.mjs`](examples/demo-shop/test/agent-sim.test.mjs) runs in CI.

| Persona | Behaviour | Caught by |
|---|---|---|
| Honest customer | browses, searches, logs in, edits profile, views orders | *no alerts (must stay at zero)* |
| Curious agent | reads page source, follows a leaked endpoint and key | `honeytoken.used`, `decoy.route` |
| Instruction-hardened agent | ignores page text, probes `.env`, tries found credentials from a new IP | `bait.path` then `honeytoken.used`, cross-session link |
| Careful agent | uses a real account only, tests IDOR and mass assignment | `tamper.sealed_value`, `decoy.param` |
| Noisy scanner | sprays payloads and enumerates with a wordlist | `payload.*`, `behavior.enumeration` |

Results against live AI pentest agents, with the raw logs, are in [benchmarks/](benchmarks/README.md). The method is in [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Repository layout

```
crates/kagami-core     Rust engine compiled to WebAssembly (detection, decoys, honeytokens, audit log)
packages/node          @agenticslabs/kagami, the WASM bridge, event sinks and CLI (framework-agnostic)
packages/express       @agenticslabs/kagami-express, the Express middleware
packages/cloudflare    @agenticslabs/kagami-cloudflare, the Cloudflare enforcer and client address helper
examples/demo-shop     Demo target and attacker persona tests
docs/                  Design, threat model, benchmark method
```

## Development

You need Rust (with the `wasm32-unknown-unknown` target), Node 20 or newer, and pnpm.

```bash
pnpm install
pnpm test          # Rust tests, WASM build and all JS suites
pnpm demo          # demo shop on http://localhost:41837 in protect mode
```

## Roadmap

- **Utsusemi**, a richer shadow that also answers personalised routes with consistent fake data
- More enforcers, such as AWS WAF IP sets, Fastly and Akamai
- Reporting contained machines to Cloudflare's Bot Feedback Loop (Enterprise Bot Management)
- Next.js, Fastify, FastAPI and Django (via wasmtime) and Go (via wazero) adapters, sharing one core
- Cloudflare Worker and edge deployment
- Off-site honeytoken alerts using cloud canary credentials
- A public **"evade Kagami"** challenge with a live scoreboard

## Responsible use

Kagami is purely defensive. It deceives and records, and it never attacks back. It does no
counter-exploitation and sends no instructions that make an attacker's tools act against their operator.
See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache-2.0](LICENSE). Copyright Agentics Labs.
