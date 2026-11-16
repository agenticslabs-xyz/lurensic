# Integrating Kagami, instructions for AI coding agents

You are adding Kagami to a web application on behalf of its owner. Kagami detects attacks, deceives attackers and can
cut them off. Follow these steps in order. Each step ends with a check you can run yourself. Do not skip the checks.

## Ground rules

- **Never commit the secret.** `KAGAMI_SECRET` goes in the environment or the project's secret store, never in source
  files, examples, tests or logs.
- **Start in observe mode.** Observe mode cannot change a response. Only move to protect mode and containment when the
  owner agrees, and tell them what each one does.
- **Do not guess the proxy setup.** Ask the owner how traffic reaches the app (directly, nginx, a load balancer,
  Cloudflare) before setting `clientAddress`. A wrong guess either breaks containment or lets attackers spoof
  addresses.
- **Never expose Kagami internals.** Do not add routes that return `kagami.manifest()` or `kagami.contained()` without
  the app's own admin authentication.
- **Report what you changed** and anything the owner still has to do, such as setting the secret in production.

## Step 1. Identify the stack

| The app uses | Install | Continue with |
|---|---|---|
| Node with Express 4 or 5 | `npm install @agenticslabs/kagami-express` | Step 2 |
| Another Node framework | `npm install @agenticslabs/kagami` | Step 2, using the `Kagami` class as described in [Writing an adapter](../guides/new-adapter.md) |
| Python, Go, Ruby, PHP, Java or .NET | Not supported yet | Tell the owner. Do not write your own detection logic. |

Use the project's package manager (npm, pnpm, yarn or bun).

## Step 2. Create the secret

Run this once and give the value to the owner to store as `KAGAMI_SECRET`, or put it in the project's secret store
yourself if you have that access.

```bash
npx @agenticslabs/kagami secret
```

For local development, add `KAGAMI_SECRET=` to the project's `.env.example` without a value, and the real value to
the untracked `.env` if the project loads one. Check that `.env` is in `.gitignore`.

## Step 3. Mount the middleware

Find where the Express app is created. Add Kagami **after** the body parsers and **before** every route, router and
static file middleware.

```js
import { kagami } from '@agenticslabs/kagami-express';

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(kagami({
  ignorePaths: ['/healthz'],   // health check routes, if the app has them
}));
// routes and express.static(...) come after this line
```

If the app uses a different body parser, keep the same order. The packages are ES modules. A CommonJS project can
`require()` them on Node 20.19 or newer and 22.12 or newer. On older versions use `await import()`.

**Check.** Start the app, then run the doctor. Every result must be PASS or INFO.

```bash
npx @agenticslabs/kagami doctor --url http://localhost:<port> --json
```

## Step 4. Set the client address

Ask the owner how traffic reaches the app, then set exactly one of these.

| Traffic reaches the app | Add to the options |
|---|---|
| Directly from the internet | nothing |
| Through nginx or a proxy on the same host | `clientAddress: { trustedProxies: ['127.0.0.1', '::1'] }` |
| Through a load balancer | `clientAddress: { trustedProxies: ['<the load balancer address ranges>'] }` |
| Through Cloudflare | `clientAddress: { cloudflare: true }` |
| Through Cloudflare and then a local proxy | `clientAddress: { cloudflare: true, trustedProxies: ['127.0.0.1', '::1'] }` |

Never use `app.set('trust proxy', true)` for this.

## Step 5. Keep the events

Add a file sink so the owner, and the doctor, can read events.

```js
import { consoleSink, fileSink, kagami } from '@agenticslabs/kagami-express';

app.use(kagami({
  sinks: [consoleSink(), fileSink({ path: process.env.KAGAMI_EVENTS ?? 'kagami-events.jsonl' })],
}));
```

Add the events file to `.gitignore`.

**Check.** Run the doctor with `--events <path>`. The `events` check must pass, and `client_address` must not warn.

## Step 6. Protect mode and containment, only with the owner's agreement

Explain to the owner first. Protect mode serves fake files and decoys to attackers. Containment cuts a machine off from
the app after it touches a tripwire, for one day by default.

```js
import { blocklistFile, consoleSink, fileSink, kagami } from '@agenticslabs/kagami-express';

app.use(kagami({
  mode: 'protect',
  decoys: { json: true, forms: true },
  containment: { allow: [] },   // add the owner's office or monitoring addresses here
  enforcers: [blocklistFile({ path: 'contained.json', format: 'json' })],
  sinks: [consoleSink(), fileSink({ path: 'kagami-events.jsonl' })],
}));
```

Leave `decoys.json` off if the app's API clients reject unknown JSON fields, and `decoys.forms` off if form handlers
reject unknown form fields. Search the code for strict schema validation before turning them on.

If the app hands record IDs to clients, offer to seal them with `req.kagami.seal(id)` and check them with
`req.kagami.verify(id, 'name')`, which returns `null` for a forged ID.

**Check.** Run the doctor with `--url`, `--events` and `--blocklist contained.json`. `protect` must pass.

## Step 7. Edge blocking, optional

If the app is behind Cloudflare and the owner wants attackers blocked at the edge, nothing extra is installed. The
owner does these steps. Do not create tokens or run setup with a token yourself unless the owner asks you to.

1. The owner runs `npx @agenticslabs/kagami cloudflare setup` with no token. It prints which two tokens to create and a
   link to the Create Token page.
2. With the one-time setup token in `CLOUDFLARE_API_TOKEN`, the owner runs
   `npx @agenticslabs/kagami cloudflare setup --zone <their domain>`. It creates the IP list and the WAF custom rule,
   and prints `CLOUDFLARE_ACCOUNT_ID` and `KAGAMI_CLOUDFLARE_LIST_ID`. It is safe to run again.
3. The owner deletes the setup token and gives the app a runtime token with only **Account Filter Lists Edit**.

The app then needs three environment variables, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` and
`KAGAMI_CLOUDFLARE_LIST_ID`, plus `KAGAMI_CONTAINMENT=on` and `clientAddress: { cloudflare: true }` from step 4. Kagami
adds the Cloudflare enforcer by itself when they are set.

If setup reports that it could not add the rule, pass on its message to the owner. It names the missing permission and
prints the rule to add by hand.

Never ask for broader token permissions for the runtime token, never put a token in source files, and follow the
[Cloudflare guide](../guides/cloudflare.md) for the details.

## Reading doctor output

`kagami doctor --json` prints `{"checks":[{"id","status","message","fix"}]}`. Statuses are `pass`, `info`, `warn` and
`fail`. Act on every `fail`, report every `warn` to the owner, and use the `fix` text as the instruction.

## What to tell the owner when you finish

- Where Kagami is mounted and which mode it runs in.
- That `KAGAMI_SECRET` must be set in every environment, and where you put it for local development.
- Where events and the blocklist are written.
- How to switch Kagami off in an emergency, `KAGAMI_DISABLED=1`.
- Anything you did not do and why.
