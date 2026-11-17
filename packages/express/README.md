# @agenticslabs/kagami-express

Express middleware for [Kagami](https://github.com/agenticslabs-xyz/kagami), a deception-based defence
against AI-driven attacks. It detects attacking agents with tripwires that instructions to the agent can't get around,
misleads them with decoys, and hands each detection to your code.

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
app.use(yourAuth);   // optional, so req.user is set
app.use(kagami({
  subject: (req) => req.user?.id,          // your id for whoever sent the request
  onDetect: (event) => {
    // Your response, such as locking event.subject or blocking event.source.ip.
  },
}));                 // observe mode by default, which detects and never changes a response
```

`onDetect` runs off the request path for each detection at `low` severity and above. Events also go to stdout as
JSON lines. `subject` runs again when the response finishes, so ids your routes set are included too.

- **Observe mode by default.** Responses stay byte-identical until you enable `mode: 'protect'`.
- **Fails open.** Misconfiguration or internal errors let requests through untouched. Set `KAGAMI_DISABLED=1` to switch Kagami off.
- **Sealed IDs.** `req.kagami.seal(id)` and `req.kagami.verify(sealed)` turn IDOR attempts into alerts.
- **Decoys.** With `mode: 'protect'`, probes for secrets get fake files whose credentials are honeytokens, and `decoys: { json: true, forms: true }` adds a decoy field that only a mass-assignment attempt changes. `decoys: { spec: true }` serves a decoy API description whose every operation is a decoy. `KAGAMI_DECOYS=json,forms,spec` does the same from the environment.

Behind a proxy or Cloudflare, set `clientAddress: { trustedProxies: ['127.0.0.1'], cloudflare: true }`. Kagami then works out the visitor's address itself and cannot be fooled by a forged `X-Forwarded-For` or `CF-Connecting-IP`. See [Choose your setup](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/choose-your-setup.md) for every path.

Kagami can also cut attacking machines off by itself. That is optional and off by default. See [Containment](https://github.com/agenticslabs-xyz/kagami/blob/main/docs/guides/containment.md).

The full documentation, design and threat model are at https://github.com/agenticslabs-xyz/kagami

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
