# @agenticslabs/kagami

The runtime for [Kagami](https://github.com/agenticslabs-xyz/kagami), a deception-based defence against AI-driven
attacks. It runs on Node, Bun, Deno and Cloudflare Workers, and includes the WebAssembly engine, event sinks,
enforcers, the optional store and the CLI.

With Express, install [`@agenticslabs/kagami-express`](https://www.npmjs.com/package/@agenticslabs/kagami-express).
With Hono, install [`@agenticslabs/kagami-hono`](https://www.npmjs.com/package/@agenticslabs/kagami-hono). Both bring
this package with them. [Choose your setup](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/choose-your-setup.md) shows the path for every framework and host.

## Any app with a fetch handler

On Cloudflare Workers, Bun and Deno, wrap the app or the handler.

```js
import { kagami, kagamiContext } from '@agenticslabs/kagami';

async function handler(request) {
  const k = kagamiContext(request);   // seal and verify helpers
  return new Response('Hello');
}

export default kagami(handler);       // reads KAGAMI_SECRET, starts in observe mode
```

The visitor's address comes from the runtime. On Cloudflare Workers, settings come from the Worker's bindings, and the
package's `workerd` entry loads the engine the way Workers require. Wrangler picks it by itself.

## Building another adapter

```js
import { Kagami, consoleSink } from '@agenticslabs/kagami';

const kagami = new Kagami({ secret: process.env.KAGAMI_SECRET, sinks: [consoleSink()] });
const verdict = kagami.inspect({ ip, method, host, path, query, headers, body });
```

For a framework built on the web-standard Request and Response API, use `FetchGuard`, as the Hono adapter does.

## CLI

```bash
npx @agenticslabs/kagami secret                    # generate a deployment secret
npx @agenticslabs/kagami doctor --url http://localhost:3000   # check the setup (add --json for agents)
npx @agenticslabs/kagami verify-log events.jsonl   # check a log's hash chain
```

## Sinks

The package includes `consoleSink`, `fileSink`, `webhookSink` (HMAC-signed), `slackSink` (escaped, with link
previews disabled), `callbackSink` and `memorySink`.

## Containment and enforcers

With `containment: true`, a machine that trips a tripwire is answered by Kagami (`verdict.action` is a
response and `verdict.contained` is true), so an adapter must not pass the request on to the application.
Adapters should also pass response headers and bodies to `kagami.response()` when `verdict.capture` is true,
so contained machines can be served copies of public pages.

Enforcers receive each newly contained machine, off the request path. The package includes
`blocklistFile` (plain, nginx or JSON, written atomically, kept across restarts), `webhookEnforcer`
(HMAC-signed) and `callbackEnforcer`. Recipes for nginx, host firewalls, Cloudflare and cloud WAFs are in
[Blocking at your firewall or CDN](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/firewall.md). Write your own by implementing the `Enforcer` interface.
`kagami.contained()` lists contained machines and `kagami.release(ip)` ends a containment early.

## The store

Contained machines live in each running copy's memory. Pass the key-value store your platform already provides to keep
containment through restarts and across every copy of the app.

```js
kagami(app, { containment: true, store: redis });   // Workers KV, Deno KV, Netlify Blobs or a Redis client
```

On Cloudflare Workers a KV binding named `KAGAMI_STORE` is used without any code. See [the store](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/choose-your-setup.md#the-store).

`fileSink` and `blocklistFile` need a file system, so they are not available on Cloudflare Workers.

The full documentation, design and threat model are at https://github.com/agenticslabs-xyz/kagami

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
