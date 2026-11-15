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

The full documentation, design and threat model are at https://github.com/agenticslabs-xyz/kagami

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
