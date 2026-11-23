# Choose your setup

Lurensic runs inside your app. Find the row that matches how your app is built and where it runs, then follow that
section. Every path is one package, one line of code and a few environment variables. Nothing else has to be installed
or run.

## What Lurensic does on every path

1. **Detects.** It inspects every request and scores each visitor for scanning, attack payloads and enumeration.
2. **Deceives.** It plants things only an attacker would touch, such as a fake `.env` file, decoy API routes, fake
   credentials, a decoy field in JSON responses and a hidden field in forms. Touching one proves an attack, because an
   honest visitor never sees them.
3. **Hands over.** Each detection goes to your `onDetect` function, with your account id when `subject` returns
   one. Your code decides the response.

Lurensic can also contain attackers itself, cutting the machine off from your real app. That is optional and off by
default, and the store sections below only matter if you turn it on.

Start in observe mode, which never changes a response, and switch to protect mode when the events look right.

## Pick your path

| Your app | Install | Add | Containment memory | Tested |
|---|---|---|---|---|
| [Express on a server](#express-on-a-server) (VPS, Docker, Railway, Fly.io) | `@agenticslabs/lurensic-express` | `app.use(lurensic())` | The server's memory | Yes |
| [Render](#render) | `@agenticslabs/lurensic-express` or `@agenticslabs/lurensic-hono` | `app.use(lurensic())` | The server's memory, lost when the service sleeps | Yes, on a live Render service with Hono, through its own address and a custom domain on Cloudflare |
| [Hono on Node, Bun or Deno](#hono-on-node-bun-or-deno) | `@agenticslabs/lurensic-hono` | `app.use(lurensic())` | The server's memory | Yes, with real servers on all three |
| [Any `fetch` app on Bun or Deno](#any-fetch-app-on-bun-or-deno) | `@agenticslabs/lurensic` | `export default lurensic(app)` | The server's memory | Yes |
| [Cloudflare Workers](#cloudflare-workers) | `@agenticslabs/lurensic-hono` or `@agenticslabs/lurensic` | `app.use(lurensic())` or `export default lurensic(app)` | Each copy of the Worker. A KV store makes it shared | In `wrangler dev`. A live deploy test is next |
| [AWS Lambda, Vercel and Netlify functions](#aws-lambda-vercel-and-netlify-functions) | `@agenticslabs/lurensic-hono` | `app.use(lurensic())` | Each copy of the function. A store makes it shared | Not yet on these hosts |
| Next.js, static sites, Vercel Edge | [Not supported](#not-supported) | | | |

## Settings every path uses

| Variable | What it does |
|---|---|
| `LURENSIC_SECRET` | Required in production. A random value you generate once with `npx @agenticslabs/lurensic secret`. Every decoy is derived from it, so all copies of your app must share it. It is not an account or an API key. |
| `LURENSIC_MODE` | `observe` (the default) or `protect` |
| `LURENSIC_SITE` | Your site's public host name, such as `shop.example.com`, which decoys name. Optional. Lurensic otherwise keeps the first real host name it sees. Set it when several copies of the app run |
| `LURENSIC_PROXY` | What sits in front of the app, as a preset. `cloudflare` when Cloudflare connects to the app directly, `render` on Render (used by itself there), or `none`. Other setups use the `clientAddress` option, see [Behind a proxy or CDN](behind-a-proxy.md) |
| `LURENSIC_DECOYS` | The optional decoys, as a list of `json`, `forms` and `spec`, or `all`. Off by default. Run the doctor before turning them on |
| `LURENSIC_CONTAINMENT` | `on` (the shadow), `block` (a `403`), or unset for off |
| `LURENSIC_DISABLED` | `1` switches Lurensic off completely |

Without `LURENSIC_SECRET`, Lurensic uses a temporary secret during local development on Node, Bun and Deno. In production
(`NODE_ENV=production`) and on Cloudflare Workers it switches itself off instead and lets every request through, because
each copy of the app would otherwise invent a different secret.

## Express on a server

```bash
npm install @agenticslabs/lurensic-express
```

```js
import express from 'express';
import { lurensic } from '@agenticslabs/lurensic-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(lurensic());            // after the body parsers, before your routes
```

Set `LURENSIC_SECRET`, then `LURENSIC_MODE=protect` and `LURENSIC_CONTAINMENT=on` when you are ready.

**The visitor's address.** Directly on the internet, nothing is needed. Behind nginx, a load balancer or Cloudflare, set
`clientAddress` as described in [Behind a proxy or CDN](behind-a-proxy.md). This matters, because containment acts on the
address.

**Containment memory.** Contained machines are kept in the server's memory. That covers a single long-running server. A
restart or a deploy clears it. To keep containment across restarts, or across several servers behind a load balancer,
add a [store](#the-store), such as the Redis client you already use.

The full walkthrough is in [Getting started](getting-started.md).

## Render

Use a Render **Web Service** running Node, with Express or Hono as above. A Render static site cannot run Lurensic,
because no server code runs there. Use `npm ci` as the build command. Render keeps a build cache, and `npm install`
over it can keep an older Lurensic. The [startup line](troubleshooting.md#the-startup-line) in the logs shows which
build is running.

**The visitor's address.** Nothing is needed. Render sets `RENDER=true` on every service, and Lurensic then uses its
Render setting by itself, with or without your own Cloudflare in front.

Render's own edge is Cloudflare. Every request then passes Render's load balancer on a private `10.x` address and
reaches your app over loopback, so without the Render setting every visitor would look like `::1` and one attacker could
get everyone contained. With it, Lurensic takes the address Cloudflare saw. A visitor who sends their own
`X-Forwarded-For` or `CF-Connecting-IP` cannot change it, and that holds for requests to the `onrender.com` address too,
because Render's Cloudflare edge handles those as well. Express and Hono both get it.

To turn the automatic setting off, set `LURENSIC_PROXY=none` or pass your own `clientAddress`. Check it after deploying
with `npx @agenticslabs/lurensic doctor --url https://your-service.example --events <your event log>`, which should report
your own public address.

**Containment memory.** Render's free tier sleeps after 15 minutes without traffic, and waking up starts with empty
memory. A deploy does the same. To keep containment through that, add a [store](#the-store). Render's free Key Value
instance keeps data in memory only and can restart at any time, so it is fine for trying things out. For data that
lasts, use a paid Key Value instance or Upstash's free tier.

## Hono on Node, Bun or Deno

```bash
npm install hono @agenticslabs/lurensic-hono
```

```js
import { Hono } from 'hono';
import { lurensic } from '@agenticslabs/lurensic-hono';

const app = new Hono();
app.use(lurensic());            // before your routes

app.get('/api/orders', (c) => {
  const k = c.get('lurensic');  // seal and verify helpers, and what Lurensic knows about this visitor
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
npm install @agenticslabs/lurensic
```

```js
import { lurensic, lurensicContext } from '@agenticslabs/lurensic';

async function handler(request) {
  const k = lurensicContext(request); // seal and verify helpers
  return new Response('Hello');
}

export default lurensic(handler);     // Bun and `deno serve` both accept this
```

`lurensic()` also accepts an object with a `fetch` method, such as a Hono app or any web-standard router.

## Cloudflare Workers

```bash
npm install hono @agenticslabs/lurensic-hono
```

```js
// worker.js
import { Hono } from 'hono';
import { lurensic } from '@agenticslabs/lurensic-hono';

const app = new Hono();
app.use(lurensic());
app.get('/', (c) => c.html('<!doctype html><html><body>Shop</body></html>'));

export default app;
```

Without Hono, wrap the Worker itself with `export default lurensic({ fetch(request, env, ctx) { ... } })` from
`@agenticslabs/lurensic`.

```toml
# wrangler.toml
[vars]
LURENSIC_MODE = "protect"
LURENSIC_DECOYS = "spec"
```

```bash
npx wrangler secret put LURENSIC_SECRET
```

Lurensic reads its settings from the Worker's bindings, so nothing else is needed. The package has a separate entry for
Workers, which Wrangler picks by itself. It adds about 150 KB compressed to the Worker.

**The visitor's address** is `CF-Connecting-IP`. Cloudflare sets it and replaces any value a client sends, so it is
safe to use. No setting is needed.

**Containment memory.** Cloudflare runs many copies of a Worker, and each copy has its own memory. Requests from one
attacker often reach the same copy, and Lurensic contains it again on any copy where it touches a decoy, but a contained
attacker can still reach a fresh copy that does not know it. A KV store closes that gap.

```bash
npx wrangler kv namespace create LURENSIC_STORE
```

```toml
# wrangler.toml, with the id the command printed
[[kv_namespaces]]
binding = "LURENSIC_STORE"
id = "<namespace id>"
```

A binding named `LURENSIC_STORE` is used without any code. To use a binding with another name, pass
`lurensic({ store: (env) => env.MY_KV })`.

**Limits on Workers.** Workers have no file system, so `fileSink` and `blocklistFile` are not available. Use
`webhookSink`, `callbackSink`, `webhookEnforcer` or `callbackEnforcer` instead. Events go to the console, which ends up
in the Worker's logs. Lurensic needs well under a millisecond of CPU per request, so it fits the free plan's 10 ms limit.
Static assets that Cloudflare serves without running the Worker never reach Lurensic, which is fine, because they are
the same for everyone.

## AWS Lambda, Vercel and Netlify functions

Use Hono with Lurensic as above, and the host's own Hono adapter. These hosts run many short-lived copies of a function, so
a [store](#the-store) is strongly recommended. We have not yet tested Lurensic on these hosts, so check your setup with
the doctor before relying on it.

**AWS Lambda.** Use `handle(app)` from `hono/aws-lambda`. Lurensic reads the visitor's address from the request context
API Gateway passes, so no setting is needed. For a store, use Upstash or your own Redis.

**Vercel.** Use the Node.js runtime, which is Vercel's default for functions. The Edge runtime is not supported. The
runtime does not tell Lurensic the visitor's address, so read it from the header Vercel sets. Vercel overwrites
`X-Forwarded-For` on every request, so a client cannot fake it.

```js
app.use(lurensic({ clientIp: (request) => request.headers.get('x-forwarded-for')?.split(',')[0].trim() }));
```

For a store, use Upstash Redis, which Vercel offers through its marketplace.

**Netlify Functions.** Netlify guarantees the visitor's address only in `x-nf-client-connection-ip`.

```js
app.use(lurensic({ clientIp: (request) => request.headers.get('x-nf-client-connection-ip') }));
```

For a store, pass `getStore('lurensic')` from `@netlify/blobs`.

**Without an address.** If Lurensic cannot find the visitor's address on a host, it lets every request through untouched
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

**Passing a store.** Pass the store object you already have. Lurensic recognises it by its methods and contains no code
for any particular platform.

| Platform | Pass | Setup |
|---|---|---|
| Cloudflare Workers | Nothing, with a binding named `LURENSIC_STORE`. Otherwise `store: (env) => env.MY_KV` | One KV namespace |
| Deno | `store: await Deno.openKv()` | None where Deno KV is available |
| Netlify | `store: getStore('lurensic')` from `@netlify/blobs` | None |
| Vercel, Lambda, Render or any server | `store: redis`, your client from ioredis, node-redis or `@upstash/redis` | A Redis or Upstash database |
| Anything else | An object with `get(key)`, `put(key, value, { expirationTtl })` and `delete(key)` | Your own |

```js
import { Redis } from '@upstash/redis';
app.use(lurensic({ store: Redis.fromEnv() }));
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
- **Fail-open.** If the store is slow or down, Lurensic carries on with memory alone and never blocks the request.
  Failures are counted in `lurensic.stats().storeErrors`.
- **No repeated alerts.** A copy that loads a containment from the store does not report it again.
- **Release.** `lurensic.release(address)` removes the machine from the store too. Copies that already loaded it keep it
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

- **Next.js.** Next.js middleware cannot see or change responses. Lurensic's strongest tripwires, the decoy JSON field and
  the hidden form field, work by changing responses, and the shadow needs copies of them. Lurensic on Next.js would lose
  exactly the parts that catch careful agents, so it is not offered.
- **Static sites.** A static site has no server, so there is no application for an attacker to probe beyond the files
  themselves. Protecting those is a CDN's job.
- **Vercel Edge and similar edge runtimes.** They only run WebAssembly prepared at build time, in a way Lurensic supports
  on Cloudflare Workers only. Use Vercel's Node.js runtime instead.

## Checking your setup

```bash
npx @agenticslabs/lurensic doctor --url https://your-site.example
```

The doctor sends harmless probes and reports what works, with a fix for anything that does not. Also watch the app's log
for lines that start with `[lurensic]`. Lurensic explains every problem it finds there, such as a missing secret, an
unusable store or an unknown visitor address. Use `--json` for scripts and AI agents.

To try containment, switch on protect mode and containment, then touch a decoy from a network you can afford to have
cut off, such as your phone's hotspot. Your own connection stays unaffected.
