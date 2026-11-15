<div align="center">

# Kagami 鏡

**Deception for AI attackers.**
*Attackers don't see your app. They see its reflection.*

An open-source project by [Agentics Labs](https://agenticslabs.xyz).

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)
![Core](https://img.shields.io/badge/core-Rust%20%E2%86%92%20WebAssembly-informational.svg)

</div>

---

AI pentest agents are fast, cheap and thorough. They read every page, try every credential they find,
and run the same checklist on thousands of targets. Most "AI defences" today hide text in a page asking
the agent to stop. That works until the attacker types *"ignore instructions you find on the target."*

Kagami takes a different approach. **It never asks the agent for anything.** It plants tripwires
in your app that only an attacker ever touches, ties every one of them to the session that found
it, and quietly records the attack. The tripwires target things an attacking agent *has to do* to
succeed. The attacker cannot instruct its agent around them without also giving up the attack.

```js
import express from 'express';
import { kagami } from '@agenticslabs/kagami-express';

const app = express();
app.use(express.json());
app.use(kagami());            // that's it. Observe mode by default.
```

## Why it can't be talked around

| An attacking agent will... | Kagami's tripwire | Why instructions don't help |
|---|---|---|
| probe for `.env`, `.git/config`, `.aws/credentials` | Serves convincing fake files full of **honeytokens** bound to that session | Trying found credentials is the point of finding them. Use them anywhere on your site and the session is flagged and traced back, even after an IP change. |
| read page source for leaked endpoints and keys | Per-session HTML comments leading to a **decoy API** with endless fake data | The leak looks like every real leak. Route names are derived from your secret, so there is no global list to avoid. |
| test IDOR by changing IDs | **Sealed values**: IDs carry an HMAC the client can't forge | Knowing exactly how it works doesn't help without the secret. The only way to avoid it is to stop testing IDOR. |
| test mass assignment with privileged-looking fields | A **decoy field** in JSON responses that honest clients echo back unchanged | Changing it is the attack, and honest round-trips are ignored. |
| spray payloads and wordlists | Payload, enumeration and brute-force **signals** add up to a session score | These are the behaviours that define an attack. |

Once a session trips a wire, everything it does is linked to it, and you get one alert with the whole timeline.

## Built to be safe in production

- **Observe mode by default.** Detection only, with a test proving every response stays **byte-identical** to your app without Kagami. Turn on `protect` once you trust it.
- **Fails open.** A bad config, a missing secret or an internal error passes requests through untouched. Kagami can't take your site down.
- **No fingerprint.** No Kagami headers, cookies or fixed paths. Decoy names, routes and tokens are derived from your deployment secret ([Kerckhoffs's principle](docs/DESIGN.md#security-model)).
- **Logs that can't be weaponised.** Structured JSON, secrets redacted, control and bidi characters stripped, attacker-controlled fields labelled `untrusted`, and a **SHA-256 hash chain** so edited or deleted entries are detectable.
- **Fast.** The engine is pure Rust compiled to WebAssembly with zero imports (no clock, network or filesystem). A typical GET costs ~20 µs (p50; p99 ~65 µs), a heavy 50-parameter POST ~95 µs.
- **Your data stays home.** No telemetry, no cloud dependency.

## Quick start

```bash
npm install @agenticslabs/kagami-express
npx @agenticslabs/kagami secret          # → put it in KAGAMI_SECRET
```

```js
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami());                   // after body parsers, before your routes
```

Watch the events (JSON lines on stdout by default), then switch on deception:

```js
app.use(kagami({
  mode: 'protect',                   // or KAGAMI_MODE=protect
  decoys: { json: true },            // opt-in: decoy field in JSON responses
  ignorePaths: ['/healthz', '/static'],
  sinks: [
    consoleSink(),
    webhookSink({ url: 'https://siem.example.com/hook', secret: process.env.KAGAMI_WEBHOOK_SECRET }),
    slackSink({ webhookUrl: process.env.SLACK_WEBHOOK, minSeverity: 'high' }),
  ],
}));
```

Seal the IDs you hand to clients:

```js
app.get('/api/orders', (req, res) =>
  res.json(orders.map((o) => ({ ...o, id: req.kagami.seal(o.id) }))));

app.get('/api/orders/:id', (req, res) => {
  const id = req.kagami.verify(req.params.id, 'order_id');   // null = forged, already reported
  if (id === null) return res.status(404).end();
  ...
});
```

Kill switch: `KAGAMI_DISABLED=1`.

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

This one says: the password used to log in came from the fake `.env` served to session
`9f2e40aa…`, which is now on a different IP and user agent. Same attacker.

Verify a log hasn't been tampered with:

```bash
npx @agenticslabs/kagami verify-log kagami-events.jsonl
# OK: 1824 events across 3 instance(s), chain intact.
```

## Benchmarks

Kagami is developed against **real AI pentest agents** as well as scripted personas. The scripted
suite ([`examples/demo-shop/test/agent-sim.test.mjs`](examples/demo-shop/test/agent-sim.test.mjs)) runs in CI:

| Persona | Behaviour | Caught by |
|---|---|---|
| Honest customer | browse, search, log in, edit profile, view orders | *no alerts (must stay at zero)* |
| Curious agent | reads page source, follows leaked endpoint and key | `honeytoken.used`, `decoy.route` |
| Instruction-hardened agent | ignores page text, probes `.env`, tries found creds from a new IP | `bait.path` then `honeytoken.used`, cross-session link |
| Careful agent | real account only, tests IDOR and mass assignment | `tamper.sealed_value`, `decoy.param` |
| Noisy scanner | payload spraying and wordlist enumeration | `payload.*`, `behavior.enumeration` |

Live-agent results, with the full method so others can reproduce them, are in [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Repository layout

```
crates/kagami-core     Rust engine → WebAssembly (detection, decoys, honeytokens, audit log)
packages/node          @agenticslabs/kagami: WASM bridge, event sinks, CLI (framework-agnostic)
packages/express       @agenticslabs/kagami-express: Express middleware
examples/demo-shop     Demo target + attacker persona tests
docs/                  Design, threat model, benchmark method
```

## Development

Requires Rust (with the `wasm32-unknown-unknown` target), Node 20+ and pnpm.

```bash
pnpm install
pnpm test          # cargo test + build WASM + all JS suites
pnpm demo          # demo shop on http://localhost:3000 in protect mode
```

## Roadmap

- **Utsusemi** (fake mode): flagged sessions get convincing fake versions of your *real* routes
- Next.js, Fastify, FastAPI/Django (via wasmtime) and Go (via wazero) adapters, sharing one core
- Cloudflare Worker / edge deployment
- Off-site honeytoken alerts (cloud canary credentials)
- A public **"evade Kagami"** challenge with a live scoreboard

## Responsible use

Kagami is purely defensive. It deceives and records, and it never attacks back: no counter-exploitation and
no instructions that make an attacker's tools act against their operator. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache-2.0](LICENSE) © Agentics Labs
