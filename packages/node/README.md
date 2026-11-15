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

## Containment and enforcers

With `containment: true`, a machine that trips a tripwire is answered by Kagami (`verdict.action` is a
response and `verdict.contained` is true), so an adapter must not pass the request on to the application.
Adapters should also pass response headers and bodies to `kagami.response()` when `verdict.capture` is true,
so contained machines can be served copies of public pages.

Enforcers receive each newly contained machine, off the request path. The package includes
`blocklistFile` (plain, nginx or JSON, written atomically, kept across restarts), `webhookEnforcer`
(HMAC-signed) and `callbackEnforcer`. Write your own by implementing the `Enforcer` interface.
`kagami.contained()` lists contained machines and `kagami.release(ip)` ends a containment early.

The full documentation, design and threat model are at https://github.com/agenticslabs-xyz/kagami

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz).
