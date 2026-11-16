# Choose your setup

Kagami runs inside your app. Find the row that matches how your app is built and where it runs, then follow that
section. Every path is one package, one line of code and a few environment variables. Nothing else has to be installed
or run.

## What Kagami does on every path

1. **Detects.** It inspects every request and scores each visitor for scanning, attack payloads and enumeration.
2. **Deceives.** It plants things only an attacker would touch, such as a fake `.env` file, decoy API routes, fake
   credentials, a decoy field in JSON responses and a hidden field in forms. Touching one proves an attack, because an
   honest visitor never sees them.
3. **Contains.** The machine that touched a decoy is cut off from your real app. It gets copies of public pages and more
   decoys (the shadow), or a `403` in block mode.

Start in observe mode, which never changes a response, and switch to protect mode when the events look right.

## Pick your path

| Your app | Install | Add | Containment memory | Tested |
|---|---|---|---|---|
| [Express on a server](#express-on-a-server) (VPS, Docker, Railway, Fly.io) | `@agenticslabs/kagami-express` | `app.use(kagami())` | The server's memory | Yes |
| [Render](#render) | `@agenticslabs/kagami-express` or `@agenticslabs/kagami-hono` | `app.use(kagami())` | The server's memory, lost when the service sleeps | Locally. Render's address handling is being verified |
| [Hono on Node, Bun or Deno](#hono-on-node-bun-or-deno) | `@agenticslabs/kagami-hono` | `app.use(kagami())` | The server's memory | Yes, with real servers on all three |
| [Any `fetch` app on Bun or Deno](#any-fetch-app-on-bun-or-deno) | `@agenticslabs/kagami` | `export default kagami(app)` | The server's memory | Yes |
| [Cloudflare Workers](#cloudflare-workers) | `@agenticslabs/kagami-hono` or `@agenticslabs/kagami` | `app.use(kagami())` or `export default kagami(app)` | Each copy of the Worker. A KV store makes it shared | In `wrangler dev`. A live deploy test is next |
| [AWS Lambda, Vercel and Netlify functions](#aws-lambda-vercel-and-netlify-functions) | `@agenticslabs/kagami-hono` | `app.use(kagami())` | Each copy of the function. A store makes it shared | Not yet on these hosts |
| Next.js, static sites, Vercel Edge | [Not supported](#not-supported) | | | |

## Settings every path uses

| Variable | What it does |
|---|---|
| `KAGAMI_SECRET` | Required in production. A random value you generate once with `npx @agenticslabs/kagami secret`. Every decoy is derived from it, so all copies of your app must share it. It is not an account or an API key. |
| `KAGAMI_MODE` | `observe` (the default) or `protect` |
| `KAGAMI_CONTAINMENT` | `on` (the shadow), `block` (a `403`), or unset for off |
| `KAGAMI_DISABLED` | `1` switches Kagami off completely |

Without `KAGAMI_SECRET`, Kagami uses a temporary secret during local development on Node, Bun and Deno. In production
(`NODE_ENV=production`) and on Cloudflare Workers it switches itself off instead and lets every request through, because
each copy of the app would otherwise invent a different secret.

## Express on a server

```bash
npm install @agenticslabs/kagami-express
```

```js
import express from 'express';
import { kagami } from '@agenticslabs/kagami-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami());            // after the body parsers, before your routes
```

Set `KAGAMI_SECRET`, then `KAGAMI_MODE=protect` and `KAGAMI_CONTAINMENT=on` when you are ready.

**The visitor's address.** Directly on the internet, nothing is needed. Behind nginx, a load balancer or Cloudflare, set
`clientAddress` as described in [Behind a proxy or CDN](behind-a-proxy.md). This matters, because containment acts on the
address.

**Containment memory.** Contained machines are kept in the server's memory. That covers a single long-running server. A
restart or a deploy clears it. To keep containment across restarts, or across several servers behind a load balancer,
add a [store](#the-store), such as the Redis client you already use.

The full walkthrough is in [Getting started](getting-started.md).

## Render

Use a Render **Web Service** running Node, with Express or Hono as above. A Render static site cannot run Kagami,
because no server code runs there.

**The visitor's address.** Render puts its own proxy in front of your service, and Cloudflare may sit in front of that.
We are verifying exactly how Render passes the visitor's address before publishing a Render setting. Until then, deploy
the [test app](../../examples/hono-app) with `ECHO_PATH` set and look at what your service receives, or run
`npx @agenticslabs/kagami doctor --url https://your-service.example`.

**Containment memory.** Render's free tier sleeps after 15 minutes without traffic, and waking up starts with empty
memory. A deploy does the same. To keep containment through that, add a [store](#the-store). Render's free Key Value
instance keeps data in memory only and can restart at any time, so it is fine for trying things out. For data that
lasts, use a paid Key Value instance or Upstash's free tier.

## Hono on Node, Bun or Deno

```bash
npm install hono @agenticslabs/kagami-hono
```

```js
import { Hono } from 'hono';
import { kagami } from '@agenticslabs/kagami-hono';

const app = new Hono();
app.use(kagami());            // before your routes

app.get('/api/orders', (c) => {
  const k = c.get('kagami');  // seal and verify helpers, and what Kagami knows about this visitor
  return c.json({ orders: [k?.seal(1043) ?? '1043'] });
});
```

Then serve it the way your runtime expects.

```js
// Node
import { serve } from '@hono/node-server';
serve({ fetch: app.fetch, port: 3000 });

// Bun
export default app;

// Deno
Deno.serve(app.fetch);
```

**The visitor's address** comes from the runtime itself. On Node it is the connection's address from
`@hono/node-server`, on Bun it is `server.requestIP()`, and on Deno it is the connection's `remoteAddr`. Behind a proxy,
set `clientAddress` as for Express.

**Containment memory** works as for Express.

## Any `fetch` app on Bun or Deno

Apps without a framework, or with another framework that exposes a `fetch(request)` handler, use the runtime package
directly.

```bash
npm install @agenticslabs/kagami
```

```js
import { kagami, kagamiContext } from '@agenticslabs/kagami';

async function handler(request) {
  const k = kagamiContext(request); // seal and verify helpers
  return new Response('Hello');
}

export default kagami(handler);     // Bun and `deno serve` both accept this
```

`kagami()` also accepts an object with a `fetch` method, such as a Hono app or any web-standard router.

## Cloudflare Workers

```bash
npm install hono @agenticslabs/kagami-hono
```

```js
// worker.js
import { Hono } from 'hono';
import { kagami } from '@agenticslabs/kagami-hono';

const app = new Hono();
app.use(kagami());
app.get('/', (c) => c.html('<!doctype html><html><body>Shop</body></html>'));

export default app;
```

Without Hono, wrap the Worker itself with `export default kagami({ fetch(request, env, ctx) { ... } })` from
`@agenticslabs/kagami`.

```toml
# wrangler.toml
[vars]
KAGAMI_MODE = "protect"
KAGAMI_CONTAINMENT = "on"
```

```bash
npx wrangler secret put KAGAMI_SECRET
```

Kagami reads its settings from the Worker's bindings, so nothing else is needed. The package has a separate entry for
Workers, which Wrangler picks by itself. It adds about 150 KB compressed to the Worker.

**The visitor's address** is `CF-Connecting-IP`. Cloudflare sets it and replaces any value a client sends, so it is
safe to use. No setting is needed.

**Containment memory.** Cloudflare runs many copies of a Worker, and each copy has its own memory. Requests from one
attacker often reach the same copy, and Kagami contains it again on any copy where it touches a decoy, but a contained
attacker can still reach a fresh copy that does not know it. A KV store closes that gap.

```bash
npx wrangler kv namespace create KAGAMI_STORE
```

```toml
# wrangler.toml, with the id the command printed
[[kv_namespaces]]
binding = "KAGAMI_STORE"
id = "<namespace id>"
```

A binding named `KAGAMI_STORE` is used without any code. To use a binding with another name, pass
`kagami({ store: (env) => env.MY_KV })`.

**Limits on Workers.** Workers have no file system, so `fileSink` and `blocklistFile` are not available. Use
`webhookSink`, `callbackSink`, `webhookEnforcer` or `callbackEnforcer` instead. Events go to the console, which ends up
in the Worker's logs. Kagami needs well under a millisecond of CPU per request, so it fits the free plan's 10 ms limit.
Static assets that Cloudflare serves without running the Worker never reach Kagami, which is fine, because they are
the same for everyone.

## AWS Lambda, Vercel and Netlify functions

Use Hono with Kagami as above, and the host's own Hono adapter. These hosts run many short-lived copies of a function, so
a [store](#the-store) is strongly recommended. We have not yet tested Kagami on these hosts, so check your setup with
the doctor before relying on it.

**AWS Lambda.** Use `handle(app)` from `hono/aws-lambda`. Kagami reads the visitor's address from the request context
API Gateway passes, so no setting is needed. For a store, use Upstash or your own Redis.

**Vercel.** Use the Node.js runtime, which is Vercel's default for functions. The Edge runtime is not supported. The
runtime does not tell Kagami the visitor's address, so read it from the header Vercel sets. Vercel overwrites
`X-Forwarded-For` on every request, so a client cannot fake it.

```js
app.use(kagami({ clientIp: (request) => request.headers.get('x-forwarded-for')?.split(',')[0].trim() }));
```

For a store, use Upstash Redis, which Vercel offers through its marketplace.

**Netlify Functions.** Netlify guarantees the visitor's address only in `x-nf-client-connection-ip`.

```js
app.use(kagami({ clientIp: (request) => request.headers.get('x-nf-client-connection-ip') }));
```

For a store, pass `getStore('kagami')` from `@netlify/blobs`.

**Without an address.** If Kagami cannot find the visitor's address on a host, it lets every request through untouched
and logs one warning that names `clientIp`. It never guesses, because a wrong guess would treat every visitor as one
machine.

## The store

A store is optional. It keeps contained machines in a key-value store your platform already provides, so containment
survives restarts and holds across every copy of your app.

| You need a store when | You do not need one when |
|---|---|
| The app runs on Workers, Lambda, Vercel or Netlify | The app is one long-running server |
| Several servers sit behind a load balancer | Losing containment on a restart is acceptable |
| The host sleeps or restarts often, as Render's free tier does | |

**Passing a store.** Pass the store object you already have. Kagami recognises it by its methods and contains no code
for any particular platform.

| Platform | Pass | Setup |
|---|---|---|
| Cloudflare Workers | Nothing, with a binding named `KAGAMI_STORE`. Otherwise `store: (env) => env.MY_KV` | One KV namespace |
| Deno | `store: await Deno.openKv()` | None where Deno KV is available |
| Netlify | `store: getStore('kagami')` from `@netlify/blobs` | None |
| Vercel, Lambda, Render or any server | `store: redis`, your client from ioredis, node-redis or `@upstash/redis` | A Redis or Upstash database |
| Anything else | An object with `get(key)`, `put(key, value, { expirationTtl })` and `delete(key)` | Your own |

```js
import { Redis } from '@upstash/redis';
app.use(kagami({ store: Redis.fromEnv() }));
```

**What it stores.** One entry per contained machine. The key is a keyed hash of the machine's address, so the store's
keys reveal nothing. The value holds the address to block, the rule that caught it, and when the containment started
and ends. Each value records its own expiry, so stores without expiry work too. Keep the store private to your app,
because the values hold attackers' addresses.

**How it behaves.**

- **Memory first.** A machine a copy already knows costs nothing extra.
- **One read per new visitor.** Each copy reads the store the first time it sees a machine, then at most once a minute
  for that machine. A read waits at most 300 ms.
- **One write per containment.** The write happens after the response, off the request path.
- **Fail-open.** If the store is slow or down, Kagami carries on with memory alone and never blocks the request.
  Failures are counted in `kagami.stats().storeErrors`.
- **No repeated alerts.** A copy that loads a containment from the store does not report it again.
- **Release.** `kagami.release(address)` removes the machine from the store too. Copies that already loaded it keep it
  until it expires.
- **Some stores lag.** Workers KV can take up to about a minute to reach every region. The copy that caught the
  attacker contains it at once, and the others catch up.

**Cost.** For most apps a store costs nothing. Free allowances at the time of writing (November 2026), so check the
providers' pages for current figures.

| Store | Free allowance | Enough? |
|---|---|---|
| Cloudflare Workers KV | 100,000 reads and 1,000 writes a day | Yes. Reads match the Workers free plan's 100,000 requests a day, and writes only happen per containment |
| Upstash Redis | 500,000 commands a month, about 16,000 a day | For small and medium sites. A busy site can outgrow it, at $0.20 per 100,000 commands after that |
| Netlify Blobs, Deno KV | Included with the platform, within its limits | Yes |
| Render Key Value | One free instance, in memory only | For testing. It loses its data when it restarts |

A site with many first-time visitors costs about one read per visitor per copy. Returning visitors cost almost nothing.

## Not supported

- **Next.js.** Next.js middleware cannot see or change responses. Kagami's strongest tripwires, the decoy JSON field and
  the hidden form field, work by changing responses, and the shadow needs copies of them. Kagami on Next.js would lose
  exactly the parts that catch careful agents, so it is not offered.
- **Static sites.** A static site has no server, so there is no application for an attacker to probe beyond the files
  themselves. Protecting those is a CDN's job.
- **Vercel Edge and similar edge runtimes.** They only run WebAssembly prepared at build time, in a way Kagami supports
  on Cloudflare Workers only. Use Vercel's Node.js runtime instead.

## Checking your setup

```bash
npx @agenticslabs/kagami doctor --url https://your-site.example
```

The doctor sends harmless probes and reports what works, with a fix for anything that does not. Also watch the app's log
for lines that start with `[kagami]`. Kagami explains every problem it finds there, such as a missing secret, an
unusable store or an unknown visitor address. Use `--json` for scripts and AI agents.

To try containment, switch on protect mode and containment, then touch a decoy from a network you can afford to have
cut off, such as your phone's hotspot. Your own connection stays unaffected.
