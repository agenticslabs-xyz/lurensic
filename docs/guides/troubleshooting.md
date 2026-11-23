# Troubleshooting

Start with the doctor. It checks the setup and tells you how to fix what it finds.

```bash
npx @agenticslabs/lurensic doctor --url http://localhost:3000 --events lurensic-events.jsonl --blocklist contained.json
```

Add `--json` for machine-readable output. The doctor exits with status 1 if anything failed.

The doctor never touches a tripwire, so running it never contains your machine. Its only probe of the app is a
request for `/.env`, sent with the user agent `lurensic-doctor`. That request records one `bait.path` event in protect
mode, which is expected.

## Doctor results

| Check | Result | What it means and what to do |
|---|---|---|
| `secret` | FAIL or WARN | `LURENSIC_SECRET` is missing or shorter than 32 characters. Without it in production Lurensic switches itself off. Generate one with `npx @agenticslabs/lurensic secret`. |
| `kill_switch` | WARN | `LURENSIC_DISABLED` is set, so Lurensic does nothing. |
| `engine` | FAIL | The engine did not load. Reinstall `@agenticslabs/lurensic` and use Node 20 or newer. |
| `reachable` | FAIL | The app did not answer at `--url`. |
| `protect` | PASS | Lurensic answered the `/.env` probe with a fake file, so it is mounted and in protect mode. |
| `protect` | INFO | Lurensic did not answer the probe. Expected in observe mode. In protect mode, Lurensic is mounted after your routes or static files, or bait files are off. |
| `protect` | FAIL | Your app serves a real `/.env`. That is a leak. Stop serving dotfiles, rotate every secret in the file, then mount Lurensic before your routes. |
| `spec` | PASS | The decoy API description is served at this deployment's spec path, and the other common description paths redirect to it. |
| `spec` | WARN | Your app publishes its own API description at one of the paths the decoy would use or redirect. Leave `decoys.spec` off, or add the paths the doctor names to `decoys.reservedPaths` so Lurensic leaves them alone. |
| `spec` | INFO | The decoy description is off or Lurensic is in observe mode, and the app has no description at any of those paths, so `LURENSIC_DECOYS=spec` is safe to turn on. |
| `events` | PASS | The event log holds a `system.started` event, with the mode and features the engine started with. |
| `client_address` | WARN | Lurensic saw your requests as coming from a private address. You are behind a proxy that Lurensic does not know about. See [Behind a proxy or CDN](behind-a-proxy.md). |
| `blocklist` | WARN | The file is not a JSON blocklist. The doctor only checks `blocklistFile({ format: 'json' })` files. |

## The startup line

When Lurensic starts it logs one line, such as the following.

```
[lurensic] Lurensic 0.1.0 (build f4cf99f44aba) started in protect mode. Visitor addresses use the render preset, because RENDER=true. Containment is on and answers with block.
```

The build id changes whenever the engine or the runtime changes, even when the version number does not. After a
deploy, check that it is the build you expect. If it is not, the host reused an old install, for example from a build
cache. Install with `npm ci`, or clear the host's build cache. The line goes to `console.info`, or to `logger.info`
when you pass a `logger`. A `logger` without `info` turns it off. With Hono and `lurensic(app)`, Lurensic starts on the
first request, so the line appears then. A health check usually sends one straight after a deploy.

## Common problems

**Every visitor has the same address in events.** Look at the startup line. If it says no address setting is in use,
Lurensic is behind a proxy it does not know about. Set `LURENSIC_PROXY` or `clientAddress`, see
[Behind a proxy or CDN](behind-a-proxy.md).

**No events at all.** Lurensic is mounted after the route that answered, or the sink filters by severity.
`consoleSink()` shows `low` and above by default. Mount Lurensic before your routes and static file middleware.

**Bodies are not inspected.** Lurensic is mounted before the body parsers. Mount it after `express.json()` and
`express.urlencoded()`.

**"The client address is unknown on this runtime".** The fetch or Hono adapter could not find the visitor's address,
so Lurensic lets requests through untouched. This happens on hosts such as Vercel and Netlify, whose runtime does not
report it. Pass `clientIp` as shown in [Choose your setup](choose-your-setup.md#aws-lambda-vercel-and-netlify-functions).

**Lurensic does nothing on Cloudflare Workers.** Look in the Worker's logs for a `[lurensic]` line. Without
`LURENSIC_SECRET` Lurensic switches itself off on Workers, even during `wrangler dev`. Set it with
`npx wrangler secret put LURENSIC_SECRET`, or in `.dev.vars` for local development.

**"The Lurensic engine was not loaded".** A bundler dropped the package entry that loads the engine. Import Lurensic from
`@agenticslabs/lurensic` or an adapter package, not from a file inside it, and keep the bundler from removing modules the
package marks as having side effects.

**A contained machine reaches another copy of the app.** Each copy keeps its own memory. Add a store, see
[Containment and enforcement](containment.md#across-restarts-and-instances).

**"Reading the store failed".** The store was slow or unreachable, so that request was checked against the instance's
memory only. Check the store's credentials and limits. Failures are counted in `lurensic.stats().storeErrors`.

**"The store is not used".** The `store` option got something Lurensic does not recognise. Pass Workers KV, Deno KV,
Netlify Blobs, a Redis client, or an object with `get`, `put` and `delete`.

**A colleague was contained.** Release them with `lurensic.release('<address>')`, and add your office to
`containment.allow`. Check the `containment.started` event to see which tripwire fired.

**A client breaks after turning on `decoys.json` or `decoys.forms`.** The client rejects unknown JSON fields, or a form
handler rejects unknown form fields. Turn that decoy off, or list the field's route in `ignorePaths`.

**A firewall or CDN list does not change.** Check that containment is on and the mode is protect, and look at
`lurensic.stats().enforcerErrors` and the `[lurensic]` warnings in the log. Private and loopback addresses are never sent to
enforcers, so a local test produces no entries. Test from a public network you can afford to have blocked.

**Machines are in the CDN's list but still reach the app.** The CDN has no rule that uses the list, or the rule is off.
For Cloudflare, check the WAF custom rule in each zone. See [Blocking at your firewall or CDN](firewall.md).

**Lurensic seems to do nothing in protect mode.** Run the doctor. If `protect` is INFO, check the order of your
middleware and that `LURENSIC_MODE` or `mode` is `protect`.
