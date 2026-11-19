# @agenticslabs/kagami-hono

Hono middleware for [Kagami](https://github.com/agenticslabs-xyz/kagami), a deception-based defence against AI-driven
attacks. It detects attacking agents with tripwires that instructions to the agent can't get around, misleads them
with decoys, and hands each detection to your code. It runs wherever Hono runs, on Node, Bun, Deno, Cloudflare
Workers and serverless hosts.

```bash
npm install hono @agenticslabs/kagami-hono
npx @agenticslabs/kagami secret        # put the output in KAGAMI_SECRET
```

```js
import { Hono } from 'hono';
import { kagami } from '@agenticslabs/kagami-hono';

const app = new Hono();
app.use(kagami({     // before your routes. Observe mode by default, which never changes a response.
  subject: (request) => accountIdFrom(request),   // your id for the sender, read from the raw request
  onDetect: (event) => {
    // Your response, such as locking event.subject or blocking event.source.ip.
  },
}));

app.get('/api/orders/:id', (c) => {
  const id = c.get('kagami')?.verify(c.req.param('id'), 'order_id');   // null if the client forged it
  return id === null ? c.json({ error: 'not found' }, 404) : c.json({ id });
});
```

For TypeScript, add `KagamiVariables` to the app's type, `new Hono<{ Variables: KagamiVariables }>()`.

- **Observe mode by default.** Responses stay identical until `KAGAMI_MODE=protect`.
- **Fails open.** Misconfiguration or internal errors let requests through untouched. `KAGAMI_DISABLED=1` switches
  Kagami off.
- **Off the request path.** `onDetect` runs after the response for each detection at `low` severity and above, and
  on Cloudflare Workers it finishes through `waitUntil`.
- **The visitor's address** comes from the runtime on Node (`@hono/node-server`), Bun, Deno, Cloudflare Workers and
  AWS Lambda. On Vercel and Netlify, pass `clientIp`.
- **Cloudflare Workers.** Settings come from the Worker's bindings.

[Choose your setup](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/choose-your-setup.md) has the full
steps for each host and what each path supports. Kagami can also cut attacking machines off by itself, which is
optional and off by default. See [Containment](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/containment.md).

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
