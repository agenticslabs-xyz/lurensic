# @agenticslabs/kagami-express

Express middleware for [Kagami](https://github.com/agenticslabs-xyz/kagami), a deception-based defence
against AI-driven attacks. It detects attacking agents with tripwires that instructions to the agent can't get around.

```bash
npm install @agenticslabs/kagami-express
npx @agenticslabs/kagami secret        # put the output in KAGAMI_SECRET
```

```js
import express from 'express';
import { kagami } from '@agenticslabs/kagami-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami());   // observe mode by default, which detects and never changes a response
```

- **Observe mode by default.** Responses stay byte-identical until you enable `mode: 'protect'`.
- **Fails open.** Misconfiguration or internal errors let requests through untouched. Set `KAGAMI_DISABLED=1` to switch Kagami off.
- **Sealed IDs.** `req.kagami.seal(id)` and `req.kagami.verify(sealed)` turn IDOR attempts into alerts.
- **Containment.** With `containment: true` in protect mode, a machine that trips a tripwire never reaches your routes again. It is served copies of your public pages instead, and enforcers can block it at your firewall, WAF or CDN.

```js
import { blocklistFile, kagami } from '@agenticslabs/kagami-express';

app.use(kagami({
  mode: 'protect',
  containment: true,
  enforcers: [blocklistFile({ path: '/etc/nginx/kagami-blocked.conf', format: 'nginx' })],
}));
```

Behind a proxy or Cloudflare, set `clientAddress: { trustedProxies: ['127.0.0.1'], cloudflare: true }`. Kagami then works out the visitor's address itself and cannot be fooled by a forged `X-Forwarded-For` or `CF-Connecting-IP`. To block contained machines at your firewall or CDN as well, see [Blocking at your firewall or CDN](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/firewall.md).

The full documentation, design and threat model are at https://github.com/agenticslabs-xyz/kagami

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
