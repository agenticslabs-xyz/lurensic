# @agenticslabs/kagami-hono

Hono middleware for [Kagami](https://github.com/agenticslabs-xyz/kagami), a deception-based defence against AI-driven
attacks. It detects attacking agents with tripwires that instructions to the agent can't get around. It runs wherever
Hono runs, on Node, Bun, Deno, Cloudflare Workers and serverless hosts.

```bash
npm install hono @agenticslabs/kagami-hono
npx @agenticslabs/kagami secret        # put the output in KAGAMI_SECRET
```

```js
import { Hono } from 'hono';
import { kagami } from '@agenticslabs/kagami-hono';

const app = new Hono();
app.use(kagami());   // before your routes. Observe mode by default, which never changes a response.

app.get('/api/orders/:id', (c) => {
  const id = c.get('kagami')?.verify(c.req.param('id'), 'order_id');   // null if the client forged it
  return id === null ? c.json({ error: 'not found' }, 404) : c.json({ id });
});
```

For TypeScript, add `KagamiVariables` to the app's type, `new Hono<{ Variables: KagamiVariables }>()`.

- **Observe mode by default.** Responses stay identical until `KAGAMI_MODE=protect`.
- **Fails open.** Misconfiguration or internal errors let requests through untouched. `KAGAMI_DISABLED=1` switches
  Kagami off.
- **Containment.** With `KAGAMI_CONTAINMENT=on` in protect mode, a machine that trips a tripwire never reaches your
  routes again. It is served copies of your public pages instead.
- **The visitor's address** comes from the runtime on Node (`@hono/node-server`), Bun, Deno, Cloudflare Workers and
  AWS Lambda. On Vercel and Netlify, pass `clientIp`.
- **Cloudflare Workers.** Settings come from the Worker's bindings, and a KV binding named `KAGAMI_STORE` keeps
  containment across every copy of the Worker without any code.

[Choose your setup](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/choose-your-setup.md) has the full
steps for each host, the optional store and what each path supports.

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
