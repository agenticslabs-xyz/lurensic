# @agenticslabs/lurensic

The runtime for [Lurensic](https://github.com/agenticslabs-xyz/lurensic), a deception-based defence against AI-driven
attacks. It runs on Node, Bun, Deno and Cloudflare Workers, and includes the WebAssembly engine, the `onDetect`
callback, event sinks and the CLI.

With Express, install [`@agenticslabs/lurensic-express`](https://www.npmjs.com/package/@agenticslabs/lurensic-express).
With Hono, install [`@agenticslabs/lurensic-hono`](https://www.npmjs.com/package/@agenticslabs/lurensic-hono). Both bring
this package with them. [Choose your setup](https://github.com/agenticslabs-xyz/lurensic/blob/main/docs/guides/choose-your-setup.md) shows the path for every framework and host.

## Any app with a fetch handler

On Cloudflare Workers, Bun and Deno, wrap the app or the handler.

```js
import { lurensic, lurensicContext } from '@agenticslabs/lurensic';

async function handler(request) {
  const k = lurensicContext(request);   // seal and verify helpers
  return new Response('Hello');
}

export default lurensic(handler, {
  subject: (request) => accountIdFrom(request),   // your id for the sender, optional
  onDetect: (event) => {
    // Your response, such as locking event.subject or blocking event.source.ip.
  },
});                                   // reads LURENSIC_SECRET, starts in observe mode
```

`onDetect` receives detection and session events at `low` severity and above (`detectSeverity` changes the floor),
off the request path. An error it throws is counted and never reaches a request.

The visitor's address comes from the runtime. On Cloudflare Workers, settings come from the Worker's bindings, and the
package's `workerd` entry loads the engine the way Workers require. Wrangler picks it by itself.

## Building another adapter

```js
import { Lurensic, consoleSink } from '@agenticslabs/lurensic';

const lurensic = new Lurensic({ secret: process.env.LURENSIC_SECRET, sinks: [consoleSink()], onDetect });
const verdict = lurensic.inspect({ ip, method, host, path, query, headers, body, subject });
```

For a framework built on the web-standard Request and Response API, use `FetchGuard`, as the Hono adapter does.

## CLI

```bash
npx @agenticslabs/lurensic secret                    # generate a deployment secret
npx @agenticslabs/lurensic doctor --url http://localhost:3000   # check the setup (add --json for agents)
npx @agenticslabs/lurensic verify-log events.jsonl   # check a log's hash chain
```

## Sinks

The package includes `consoleSink`, `fileSink`, `webhookSink` (HMAC-signed), `slackSink` (escaped, with link
previews disabled), `callbackSink`, `detectSink` (behind `onDetect`) and `memorySink`.

## Optional containment

Most apps act on detections in `onDetect`. Lurensic can also act by itself, which is off by default.

With `containment: true`, a machine that trips a tripwire is answered by Lurensic (`verdict.action` is a
response and `verdict.contained` is true), so an adapter must not pass the request on to the application.
Adapters should also pass response headers and bodies to `lurensic.response()` when `verdict.capture` is true,
so contained machines can be served copies of public pages.

Enforcers receive each newly contained machine, off the request path. The package includes
`blocklistFile` (plain, nginx or JSON, written atomically, kept across restarts), `webhookEnforcer`
(HMAC-signed) and `callbackEnforcer`. Recipes for nginx, host firewalls, Cloudflare and cloud WAFs are in
[Blocking at your firewall or CDN](https://github.com/agenticslabs-xyz/lurensic/blob/main/docs/guides/firewall.md). Write your own by implementing the `Enforcer` interface.
`lurensic.contained()` lists contained machines and `lurensic.release(ip)` ends a containment early.

## The store

Contained machines live in each running copy's memory. Pass the key-value store your platform already provides to keep
containment through restarts and across every copy of the app.

```js
lurensic(app, { containment: true, store: redis });   // Workers KV, Deno KV, Netlify Blobs or a Redis client
```

On Cloudflare Workers a KV binding named `LURENSIC_STORE` is used without any code. See [the store](https://github.com/agenticslabs-xyz/lurensic/blob/main/docs/guides/choose-your-setup.md#the-store).

`fileSink` and `blocklistFile` need a file system, so they are not available on Cloudflare Workers.

The full documentation, design and threat model are at https://github.com/agenticslabs-xyz/lurensic

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
