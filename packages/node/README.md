# @agenticslabs/kagami

The framework-agnostic Node.js engine for [Kagami](https://github.com/agenticslabs-xyz/kagami),
a deception-based defence against AI-driven attacks. It includes the WebAssembly core, event sinks and the CLI.

If you use Express, install [`@agenticslabs/kagami-express`](https://www.npmjs.com/package/@agenticslabs/kagami-express) instead.
This package is for building adapters for other frameworks.

```js
import { Kagami, consoleSink } from '@agenticslabs/kagami';

const kagami = new Kagami({ secret: process.env.KAGAMI_SECRET, sinks: [consoleSink()] });
const verdict = kagami.inspect({ ip, method, host, path, query, headers, body });
```

## CLI

```bash
npx @agenticslabs/kagami secret                    # generate a deployment secret
npx @agenticslabs/kagami verify-log events.jsonl   # check a log's hash chain
```

## Sinks

The package includes `consoleSink`, `fileSink`, `webhookSink` (HMAC-signed), `slackSink` (escaped, with link
previews disabled), `callbackSink` and `memorySink`.

The full documentation, design and threat model are at https://github.com/agenticslabs-xyz/kagami

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
