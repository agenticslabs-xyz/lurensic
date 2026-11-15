# @agenticslabs/kagami-express

Express middleware for [Kagami](https://github.com/agenticslabs-xyz/kagami): deception-based defence
against AI-driven attacks. It catches attacking agents with tripwires they can't be instructed around.

```bash
npm install @agenticslabs/kagami-express
npx @agenticslabs/kagami secret        # → KAGAMI_SECRET
```

```js
import express from 'express';
import { kagami } from '@agenticslabs/kagami-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami());   // observe mode by default: detects, never changes a response
```

- **Observe mode by default.** Responses stay byte-identical until you enable `mode: 'protect'`.
- **Fails open.** Misconfiguration or internal errors pass requests through untouched. `KAGAMI_DISABLED=1` is the kill switch.
- **Sealed IDs:** `req.kagami.seal(id)` / `req.kagami.verify(sealed)` turn IDOR attempts into alerts.

Full documentation, design and threat model: https://github.com/agenticslabs-xyz/kagami

Apache-2.0 © [Agentics Labs](https://agenticslabs.xyz)
