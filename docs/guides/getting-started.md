# Getting started

This guide adds Kagami to an Express app in four steps. Each step is safe to deploy on its own, and each one ends
with a check. The same four steps apply to Hono, Cloudflare Workers, Bun and Deno. Only the install and the one line
differ, as shown in [Choose your setup](choose-your-setup.md).

```mermaid
flowchart LR
    A["1. Install<br/>and set the secret"] --> B["2. Observe<br/>detect only"]
    B --> C["3. Protect<br/>add decoys"]
    C --> D["4. Contain<br/>cut attackers off"]
```

## 1. Install and set the secret

```bash
npm install @agenticslabs/kagami-express
npx @agenticslabs/kagami secret
```

The second command prints a random value. Set it as the environment variable `KAGAMI_SECRET` wherever the app runs,
the same way you set other secrets such as a database password. Keep it out of source control. It is the only
credential Kagami needs. It is not an account or an API key, and nothing is sent anywhere.

Every decoy name, honeytoken and seal is derived from this secret. Changing it changes all of them, and honeytokens
handed out under the old secret stop working as tripwires.

## 2. Observe

```js
import express from 'express';
import { kagami } from '@agenticslabs/kagami-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami());          // after the body parsers, before your routes and static files

app.get('/', (req, res) => res.send('...'));
```

**Order matters.** Kagami must come after the body parsers, so it can read request bodies, and before your routes and
static file middleware, so it sees every request first. `kagami()` returns the middleware and an error handler as a
pair, so requests that a body parser rejects are inspected too.

In observe mode Kagami never changes a response. It writes events as JSON lines to stdout. Run the doctor.

```bash
npx @agenticslabs/kagami doctor --url http://localhost:3000
```

Then try an attack against your own app and watch an event appear.

```bash
curl "http://localhost:3000/search?q=%27%20OR%201%3D1--"
```

### Act on detections

Pass `onDetect` to run your own code for each detection, and `subject` so each event names the account
that sent the request. Never return a cookie, token or session secret, because the value is written to the logs. Mount Kagami after your auth middleware if `subject` reads `req.user`.

```js
import { kagami, safeToActOnSubject } from '@agenticslabs/kagami-express';

app.use(kagami({
  subject: (req) => req.user?.id,
  onDetect: async (event) => {
    if (event.severity === 'critical' && safeToActOnSubject(event)) await accounts.lock(event.subject);
    else await alerts.send(`${event.rule} from ${event.source?.ip ?? 'an unknown address'}`);
  },
}));
```

`safeToActOnSubject(event)` is true only when the event names an account and the request was the account
holder's own. It is false when a browser was lured to the request from another site, which is how a visitor can be
tricked into touching a decoy (`wasLured(event)` tells you that case on its own), and when the evidence was in a cookie, which a sibling subdomain can plant. Those
events are still real detections. Alert on them or block the address instead of acting on the account.

`onDetect` runs after the request, off the request path, so a slow handler never slows a visitor. It receives
detection and session events at `low` severity and above, and `detectSeverity` changes the floor. Text in the fields
listed in `untrusted`, including `evidence` and `subject`, comes from the attacker. Treat it as data.

To keep events in a file or send them on as well, add sinks. `onDetect` keeps working next to them.

```js
import { consoleSink, fileSink, kagami, slackSink, webhookSink } from '@agenticslabs/kagami-express';

app.use(kagami({
  sinks: [
    consoleSink(),
    fileSink({ path: '/var/log/myapp/kagami-events.jsonl' }),
    webhookSink({ url: 'https://siem.example.com/hook', secret: process.env.KAGAMI_WEBHOOK_SECRET }),
    slackSink({ webhookUrl: process.env.SLACK_WEBHOOK, minSeverity: 'high' }),
  ],
}));
```

**If your app runs behind a proxy, a load balancer or a CDN**, read [Behind a proxy or CDN](behind-a-proxy.md) now.
Kagami keys everything on the client address, so it has to be right before you go further.

## 3. Protect

Protect mode turns on deception. Attackers get fake files, a decoy API and planted credentials. Honest visitors never
see any of it.

```js
app.use(kagami({
  mode: 'protect',
  decoys: {
    json: true,           // a decoy field in JSON object responses
    forms: true,          // the same field as a hidden input in POST forms
  },
  ignorePaths: ['/healthz', '/static'],
}));
```

Add `spec: true` to the decoys to serve a decoy API description, which agents read first and which lists only decoy
routes. Leave it off if your app publishes its own OpenAPI or Swagger description, or list that path in
`reservedPaths`. The doctor checks this for you. All three optional decoys can also be turned on without code, with
`KAGAMI_DECOYS=json,forms,spec`.

`decoys.json` and `decoys.forms` are off by default because they add one field to your responses and your forms.
Leave them off if a client validates responses strictly, or if a form handler rejects unknown fields. They are the
tripwires that worked best against AI agents, so turn them on where you can.

Seal the IDs you hand to clients. A changed or forged ID is then caught.

```js
app.get('/api/orders', (req, res) =>
  res.json(orders.map((o) => ({ ...o, id: req.kagami.seal(o.id) }))));

app.get('/api/orders/:id', (req, res) => {
  const id = req.kagami.verify(req.params.id, 'order_id');   // null means forged, and it is already reported
  if (id === null) return res.status(404).end();
  // ...
});
```

Run the doctor again. It should now report that Kagami answered a probe for `/.env` in protect mode.

## 4. Optional. Let Kagami contain attackers itself

Most apps act on detections in `onDetect`. If you would rather Kagami acted on its own, containment cuts a machine
off from your app the moment it touches a tripwire. It is off by default.

```js
import { blocklistFile, kagami } from '@agenticslabs/kagami-express';

app.use(kagami({
  mode: 'protect',
  decoys: { json: true, forms: true },
  containment: {
    allow: ['203.0.113.0/24'],        // your office or monitoring, never contained
  },
  enforcers: [
    blocklistFile({ path: '/var/lib/myapp/contained.json', format: 'json' }),
  ],
}));
```

Try it in observe mode first. With `mode: 'observe'` and `containment: true`, Kagami only reports
`containment.started` events, so you can see who would have been contained.

The blocklist file is optional. It is for a firewall or a WAF that reads a list, such as nginx. For a CDN such as
Cloudflare or a cloud WAF, see [Blocking at your firewall or CDN](firewall.md).

Containment can also be switched on without code changes, with `KAGAMI_MODE=protect` and `KAGAMI_CONTAINMENT=on`.

## Switching off

Set `KAGAMI_DISABLED=1` and restart. Kagami then lets every request through untouched.
