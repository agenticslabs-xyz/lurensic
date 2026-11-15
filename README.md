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
| probe for `.env`, `.git/config`, `.aws/credentials` | Serves convincing fake files full of **honeytokens** bound to that session | Trying found credentials is the reason to look for them. Use them anywhere on your site and the session is flagged and traced back, even after an IP change. |
| read page source for leaked endpoints and keys | Per-session HTML comments leading to a **decoy API** with endless fake data | The leak looks like any real leak. Route names are derived from your secret, so there is no global list to avoid. |
| test IDOR by changing IDs | **Sealed values**, where each ID carries an HMAC the client can't forge | Knowing exactly how it works doesn't help without the secret. The only way to avoid it is to stop testing IDOR. |
| test mass assignment with privileged-looking fields | A **decoy field** in JSON responses that honest clients send back unchanged | Changing it is the attack, and honest round trips are ignored. |
| spray payloads and wordlists | Payload, enumeration and brute-force **signals** add up to a session score | These are the behaviours that define an attack. |

Once a session sets off a tripwire, everything it does is linked to it, and you get one alert with the whole timeline.

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
```

Watch the events, which go to stdout as JSON lines by default. Then switch on deception.

```js
app.use(kagami({
  mode: 'protect',                   // or KAGAMI_MODE=protect
  decoys: { json: true },            // opt in to a decoy field in JSON responses
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
  "session": { "id": "c2c7a1f09e4b5d36", "score": 135, "state": "flagged" },
  "source": { "ip": "192.0.2.77", "user_agent": "python-httpx/0.27" },
  "request": { "method": "POST", "host": "shop.example.com", "path": "/login", "query": "" },
  "evidence": {
    "token_kind": "env_admin_password",
    "token": "aB3c…xYz9",
    "issued_to_session": "9f2e40aa",
    "cross_session": true
  },
  "mitre_attack": ["T1552.001", "T1078"],
  "untrusted": ["source.user_agent", "request.host", "request.path", "request.query", "evidence"],
  "prev_hash": "35ad43ff…",
  "hash": "a1874cda…"
}
```

This event means the password used to log in came from the fake `.env` served to session
`9f2e40aa`, which is now on a different IP and user agent. It is the same attacker.

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

- **Utsusemi** (fake mode) gives flagged sessions convincing fake versions of your *real* routes
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
