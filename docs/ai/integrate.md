# Integrating Kagami, instructions for AI coding agents

You are adding Kagami to a web application on behalf of its owner. Kagami detects attacks, deceives attackers and can
cut them off. Follow these steps in order. Each step ends with a check you can run yourself. Do not skip the checks.

## Ground rules

- **Never commit the secret.** `KAGAMI_SECRET` goes in the environment or the project's secret store, never in source
  files, examples, tests or logs.
- **Start in observe mode.** Observe mode cannot change a response. Only move to protect mode and containment when the
  owner agrees, and tell them what each one does.
- **Do not guess the proxy setup.** Ask the owner how traffic reaches the app (directly, nginx, a load balancer,
  Cloudflare) before setting `clientAddress`. A wrong guess either breaks containment or lets attackers spoof
  addresses.
- **Never expose Kagami internals.** Do not add routes that return `kagami.manifest()` or `kagami.contained()` without
  the app's own admin authentication.
- **Report what you changed** and anything the owner still has to do, such as setting the secret in production.

## Step 1. Identify the stack

| The app uses | Install | Continue with |
|---|---|---|
| Express 4 or 5 on Node | `npm install @agenticslabs/kagami-express` | Step 2 |
| Hono on Node, Bun, Deno, Cloudflare Workers, AWS Lambda, Vercel or Netlify | `npm install @agenticslabs/kagami-hono` | Step 2 |
| A `fetch(request)` handler without a framework, on Bun, Deno or Cloudflare Workers | `npm install @agenticslabs/kagami` | Step 2 |
| Another Node framework | `npm install @agenticslabs/kagami` | Step 2, using the `Kagami` class as described in [Writing an adapter](../guides/new-adapter.md) |
| Next.js, or a static site | Not supported | Tell the owner why, from [Choose your setup](../guides/choose-your-setup.md#not-supported). Do not wrap Next.js in a custom server to make it fit. |
| Python, Go, Ruby, PHP, Java or .NET | Not supported yet | Tell the owner. Do not write your own detection logic. |

Use the project's package manager (npm, pnpm, yarn or bun). Also find out where the app runs, because that decides the
client address setting in step 4 and whether a store is needed in step 7. [Choose your setup](../guides/choose-your-setup.md)
has the details for each host.

## Step 2. Create the secret

Run this once and give the value to the owner to store as `KAGAMI_SECRET`, or put it in the project's secret store
yourself if you have that access.

```bash
npx @agenticslabs/kagami secret
```

For local development, add `KAGAMI_SECRET=` to the project's `.env.example` without a value, and the real value to
the untracked `.env` if the project loads one. Check that `.env` is in `.gitignore`.

## Step 3. Mount the middleware

Find where the Express app is created. Add Kagami **after** the body parsers and **before** every route, router and
static file middleware.

```js
import { kagami } from '@agenticslabs/kagami-express';

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami({
  ignorePaths: ['/healthz'],   // health check routes, if the app has them
  subject: (req) => req.user?.id,   // only if the app's auth middleware runs before this line
  onDetect: (event) => {
    // The owner's response. See Step 5.
  },
}));
// routes and express.static(...) come after this line
```

**Hono.** Add `app.use(kagami())` from `@agenticslabs/kagami-hono` before every route. Routes read the seal helpers
from `c.get('kagami')`.

**A `fetch` handler.** Wrap the handler or app object with `kagami()` from `@agenticslabs/kagami` and export the result
the way the runtime expects, such as `export default kagami(app)` on Cloudflare Workers, Bun and `deno serve`.

**Cloudflare Workers.** Settings come from the Worker's bindings. Put `KAGAMI_MODE` and `KAGAMI_CONTAINMENT` in
`[vars]` in `wrangler.toml`, and have the owner run `npx wrangler secret put KAGAMI_SECRET`. Without the secret,
Kagami stays off on Workers, even in `wrangler dev`. For local development the value can go in an untracked
`.dev.vars` file.

If the app uses a different body parser, keep the same order. The packages are ES modules. A CommonJS project can
`require()` them on Node 20.19 or newer and 22.12 or newer. On older versions use `await import()`.

**Check.** Start the app, then run the doctor. Every result must be PASS or INFO.

```bash
npx @agenticslabs/kagami doctor --url http://localhost:<port> --json
```

## Step 4. Set the client address

Ask the owner how traffic reaches the app, then set exactly one of these.

| Traffic reaches the app | Add to the options |
|---|---|
| Directly from the internet | nothing |
| Through nginx or a proxy on the same host | `clientAddress: { trustedProxies: ['127.0.0.1', '::1'] }` |
| Through a load balancer | `clientAddress: { trustedProxies: ['<the load balancer address ranges>'] }` |
| Through Cloudflare | `clientAddress: { cloudflare: true }` |
| Through Cloudflare and then a local proxy | `clientAddress: { cloudflare: true, trustedProxies: ['127.0.0.1', '::1'] }` |

Never use `app.set('trust proxy', true)` for this.

With Hono or `kagami(app)`, the runtime reports the connection's address on Node, Bun, Deno, Cloudflare Workers and AWS
Lambda, so the table above applies the same way. On Vercel and Netlify the runtime does not report it. Set `clientIp`
as shown in [Choose your setup](../guides/choose-your-setup.md#aws-lambda-vercel-and-netlify-functions). If Kagami logs
"The client address is unknown on this runtime", this step is missing.

Do not guess an address setting for Render. It is still being verified. Tell the owner, and point them at the doctor.

## Step 5. Act on detections and keep the events

`onDetect` is the main way the app responds. Ask the owner what should happen on a detection, then call the app's
existing code for it, such as locking an account, revoking a session, blocking an address or sending an alert. Do not
invent a response the owner did not ask for. If the owner has no answer yet, log the event and say so in your summary.

- Use `event.subject` to find the account. Set `subject` only from an id the app has verified, such as `req.user.id`
  after its own auth middleware, or the account id looked up from a verified session in a fetch handler. Never return a cookie, token or session secret, because the value is written to the logs.
- Before acting on an account, check `safeToActOnSubject(event)`, exported by every Kagami package. It is false when
  a browser was lured to the request from another site, or when the evidence was in a cookie. Alert on those instead, and
  block the address unless `wasLured(event)` is true.
- Tripwire rules (`honeytoken.used`, `decoy.param`, `decoy.route`, `tamper.sealed_value`, `tamper.unsigned_jwt`,
  `tamper.decoy_secret`) are never touched by honest visitors. Signal rules such as `payload.*` are weaker. Match the response to the rule and `severity`.
- Never pass `evidence` or other fields listed in `untrusted` to an LLM as instructions.

Add a file sink so the owner, and the doctor, can read events.

```js
import { consoleSink, fileSink, kagami } from '@agenticslabs/kagami-express';

app.use(kagami({
  sinks: [consoleSink(), fileSink({ path: process.env.KAGAMI_EVENTS ?? 'kagami-events.jsonl' })],
}));
```

Add the events file to `.gitignore`.

**Check.** Run the doctor with `--events <path>`. The `events` check must pass, and `client_address` must not warn.

## Step 6. Protect mode, only with the owner's agreement

Explain to the owner first. Protect mode serves fake files and decoys to attackers, so the attacking agent reports
false findings and trips the wires.

```js
import { consoleSink, fileSink, kagami } from '@agenticslabs/kagami-express';

app.use(kagami({
  mode: 'protect',
  decoys: { json: true, forms: true, spec: true },
  subject: (req) => req.user?.id,
  onDetect: handleDetection,   // from Step 5
  sinks: [consoleSink(), fileSink({ path: 'kagami-events.jsonl' })],
}));
```

Turn on `decoys.spec` only when the doctor's `spec` check is INFO or PASS. A WARN means the app publishes its own API
description at one of the paths the doctor names. The opt-in decoys can also be set with `KAGAMI_DECOYS=json,forms,spec` in the environment.

Leave `decoys.json` off if the app's API clients reject unknown JSON fields, and `decoys.forms` off if form handlers
reject unknown form fields. Search the code for strict schema validation before turning them on.

If the app hands record IDs to clients, offer to seal them with `req.kagami.seal(id)` and check them with
`req.kagami.verify(id, 'name')`, which returns `null` for a forged ID.

**Check.** Run the doctor with `--url` and `--events`. `protect` must pass.

Steps 7 and 8 are for containment, which is optional and off by default. Skip them unless the owner wants Kagami to
cut attackers off by itself as well as calling `onDetect`. In that case add `containment: { allow: [] }` with the
owner's office or monitoring addresses, and see [Containment](../guides/containment.md).

## Step 7. A store, only with containment

Containment lives in the memory of each running copy of the app. Decide with the owner whether a store is needed.

| The app runs on | Store |
|---|---|
| One long-running server (VPS, Docker, a single Render or Railway service) | Not needed. Mention that a restart or deploy clears containment, and that a store fixes that. |
| Several servers behind a load balancer, or a host that sleeps, such as Render's free tier | Recommended. Use the Redis the app already has, or Upstash. |
| Cloudflare Workers | Recommended. Have the owner run `npx wrangler kv namespace create KAGAMI_STORE` and add the binding it prints to `wrangler.toml` with the name `KAGAMI_STORE`. Kagami uses it without any code. |
| AWS Lambda, Vercel or Netlify | Strongly recommended. Upstash Redis, or `getStore('kagami')` from `@netlify/blobs` on Netlify. |

Pass the store object the platform already provides, for example `kagami({ store: Redis.fromEnv() })` with
`@upstash/redis`. Never write a custom store wrapper when the platform's own object works. Store credentials go in
environment variables like any other secret. The free allowances and the full behaviour are in
[Choose your setup](../guides/choose-your-setup.md#the-store).

**Check.** With containment on, `kagami.stats().storeErrors` stays at 0, and the log has no "Reading the store failed"
or "The store is not used" lines.

## Step 8. Edge blocking, only with containment

Containment inside the app already protects it. Only add edge blocking when the owner asks for it, and mention that
an edge block tells the attacker it was caught, while the shadow does not.

Kagami ships no provider integrations. Follow the matching recipe in
[Blocking at your firewall or CDN](../guides/firewall.md), which covers nginx, host firewalls, Cloudflare and cloud
WAFs. The recipe code goes into the owner's app, next to the Kagami middleware.

The owner creates any provider token and the rule in the provider's dashboard. Ask for the narrowest permission the
recipe names, read tokens from environment variables only, and never put a token in source files.

## Reading doctor output

`kagami doctor --json` prints `{"checks":[{"id","status","message","fix"}]}`. Statuses are `pass`, `info`, `warn` and
`fail`. Act on every `fail`, report every `warn` to the owner, and use the `fix` text as the instruction.

## What to tell the owner when you finish

- Where Kagami is mounted and which mode it runs in.
- That `KAGAMI_SECRET` must be set in every environment, and where you put it for local development.
- What `onDetect` does, and what `subject` identifies.
- Where events and the blocklist are written.
- How to switch Kagami off in an emergency, `KAGAMI_DISABLED=1`.
- Anything you did not do and why.
