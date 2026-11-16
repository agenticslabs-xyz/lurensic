# Troubleshooting

Start with the doctor. It checks the setup and tells you how to fix what it finds.

```bash
npx @agenticslabs/kagami doctor --url http://localhost:3000 --events kagami-events.jsonl --blocklist contained.json
```

Add `--json` for machine-readable output. The doctor exits with status 1 if anything failed.

The doctor never touches a tripwire, so running it never contains your machine. Its only probe of the app is a
request for `/.env`, sent with the user agent `kagami-doctor`. That request records one `bait.path` event in protect
mode, which is expected.

## Doctor results

| Check | Result | What it means and what to do |
|---|---|---|
| `secret` | FAIL or WARN | `KAGAMI_SECRET` is missing or shorter than 32 characters. Without it in production Kagami switches itself off. Generate one with `npx @agenticslabs/kagami secret`. |
| `kill_switch` | WARN | `KAGAMI_DISABLED` is set, so Kagami does nothing. |
| `engine` | FAIL | The engine did not load. Reinstall `@agenticslabs/kagami` and use Node 20 or newer. |
| `reachable` | FAIL | The app did not answer at `--url`. |
| `protect` | PASS | Kagami answered the `/.env` probe with a fake file, so it is mounted and in protect mode. |
| `protect` | INFO | Kagami did not answer the probe. Expected in observe mode. In protect mode, Kagami is mounted after your routes or static files, or bait files are off. |
| `protect` | FAIL | Your app serves a real `/.env`. That is a leak. Stop serving dotfiles, rotate every secret in the file, then mount Kagami before your routes. |
| `events` | PASS | The event log holds a `system.started` event, with the mode and features the engine started with. |
| `client_address` | WARN | Kagami saw your requests as coming from a private address. You are behind a proxy that Kagami does not know about. See [Behind a proxy or CDN](behind-a-proxy.md). |
| `blocklist` | WARN | The file is not a JSON blocklist. The doctor only checks `blocklistFile({ format: 'json' })` files. |

## Common problems

**No events at all.** Kagami is mounted after the route that answered, or the sink filters by severity.
`consoleSink()` shows `low` and above by default. Mount Kagami before your routes and static file middleware.

**Bodies are not inspected.** Kagami is mounted before the body parsers. Mount it after `express.json()` and
`express.urlencoded()`.

**Every visitor has the same address in events.** The app is behind a proxy. Set `clientAddress`.

**"The client address is unknown on this runtime".** The fetch or Hono adapter could not find the visitor's address,
so Kagami lets requests through untouched. This happens on hosts such as Vercel and Netlify, whose runtime does not
report it. Pass `clientIp` as shown in [Choose your setup](choose-your-setup.md#aws-lambda-vercel-and-netlify-functions).

**Kagami does nothing on Cloudflare Workers.** Look in the Worker's logs for a `[kagami]` line. Without
`KAGAMI_SECRET` Kagami switches itself off on Workers, even during `wrangler dev`. Set it with
`npx wrangler secret put KAGAMI_SECRET`, or in `.dev.vars` for local development.

**"The Kagami engine was not loaded".** A bundler dropped the package entry that loads the engine. Import Kagami from
`@agenticslabs/kagami` or an adapter package, not from a file inside it, and keep the bundler from removing modules the
package marks as having side effects.

**A contained machine reaches another copy of the app.** Each copy keeps its own memory. Add a store, see
[Containment and enforcement](containment.md#across-restarts-and-instances).

**"Reading the store failed".** The store was slow or unreachable, so that request was checked against the instance's
memory only. Check the store's credentials and limits. Failures are counted in `kagami.stats().storeErrors`.

**"The store is not used".** The `store` option got something Kagami does not recognise. Pass Workers KV, Deno KV,
Netlify Blobs, a Redis client, or an object with `get`, `put` and `delete`.

**A colleague was contained.** Release them with `kagami.release('<address>')`, and add your office to
`containment.allow`. Check the `containment.started` event to see which tripwire fired.

**A client breaks after turning on `decoys.json` or `decoys.forms`.** The client rejects unknown JSON fields, or a form
handler rejects unknown form fields. Turn that decoy off, or list the field's route in `ignorePaths`.

**A firewall or CDN list does not change.** Check that containment is on and the mode is protect, and look at
`kagami.stats().enforcerErrors` and the `[kagami]` warnings in the log. Private and loopback addresses are never sent to
enforcers, so a local test produces no entries. Test from a public network you can afford to have blocked.

**Machines are in the CDN's list but still reach the app.** The CDN has no rule that uses the list, or the rule is off.
For Cloudflare, check the WAF custom rule in each zone. See [Blocking at your firewall or CDN](firewall.md).

**Kagami seems to do nothing in protect mode.** Run the doctor. If `protect` is INFO, check the order of your
middleware and that `KAGAMI_MODE` or `mode` is `protect`.
