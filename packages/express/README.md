# @agenticslabs/lurensic-express

Express middleware for [Lurensic](https://lurensic.com), a deception-based defence
against AI-driven attacks. It detects attacking agents with tripwires that instructions to the agent can't get around,
misleads them with decoys, and hands each detection to your code.

```bash
npm install @agenticslabs/lurensic-express
npx @agenticslabs/lurensic secret        # put the output in LURENSIC_SECRET
```

```js
import express from 'express';
import { lurensic } from '@agenticslabs/lurensic-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(yourAuth);   // optional, so req.user is set
app.use(lurensic({
  subject: (req) => req.user?.id,          // your id for whoever sent the request
  onDetect: (event) => {
    // Your response, such as locking event.subject or blocking event.source.ip.
  },
}));                 // observe mode by default, which detects and never changes a response
```

`onDetect` runs off the request path for each detection at `low` severity and above. Events also go to stdout as
JSON lines. `subject` runs again when the response finishes, so ids your routes set are included too.

- **Observe mode by default.** Responses stay byte-identical until you enable `mode: 'protect'`.
- **Fails open.** Misconfiguration or internal errors let requests through untouched. Set `LURENSIC_DISABLED=1` to switch Lurensic off.
- **Sealed IDs.** `req.lurensic.seal(id)` and `req.lurensic.verify(sealed)` turn IDOR attempts into alerts.
- **Decoys.** With `mode: 'protect'`, probes for secrets get fake files whose credentials are honeytokens, and `decoys: { json: true, forms: true }` adds a decoy field that only a mass-assignment attempt changes. `decoys: { spec: true }` serves a decoy API description whose every operation is a decoy. `LURENSIC_DECOYS=json,forms,spec` does the same from the environment.

On Render nothing is needed, because Lurensic detects Render. With Cloudflare in front, set `LURENSIC_PROXY=cloudflare`. Behind your own proxy, set `clientAddress: { trustedProxies: ['127.0.0.1'], cloudflare: true }`. Lurensic then works out the visitor's address itself and cannot be fooled by a forged `X-Forwarded-For` or `CF-Connecting-IP`. See [Choose your setup](https://lurensic.com/docs/#/setup) for every path.

Lurensic can also cut attacking machines off by itself. That is optional and off by default. See [Containment](https://lurensic.com/docs/#/containment).

The full documentation is at https://lurensic.com/docs/

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
