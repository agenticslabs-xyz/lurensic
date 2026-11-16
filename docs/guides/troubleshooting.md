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
| `blocklist` | WARN | The file is not JSON. `kagami-enforcer` reads `blocklistFile({ format: 'json' })`. |

## Common problems

**No events at all.** Kagami is mounted after the route that answered, or the sink filters by severity.
`consoleSink()` shows `low` and above by default. Mount Kagami before your routes and static file middleware.

**Bodies are not inspected.** Kagami is mounted before the body parsers. Mount it after `express.json()` and
`express.urlencoded()`.

**Every visitor has the same address in events.** The app is behind a proxy. Set `clientAddress`.

**A colleague was contained.** Release them with `kagami.release('<address>')`, and add your office to
`containment.allow`. Check the `containment.started` event to see which tripwire fired.

**A client breaks after turning on `decoys.json` or `decoys.forms`.** The client rejects unknown JSON fields, or a form
handler rejects unknown form fields. Turn that decoy off, or list the field's route in `ignorePaths`.

**The Cloudflare list does not change.** Run `kagami-enforcer cloudflare status`, check that the enforcer reads the
same file the app writes, and that the file is in JSON format. Private and loopback addresses are never added, so a
local test produces no Cloudflare entries.

**Kagami seems to do nothing in protect mode.** Run the doctor. If `protect` is INFO, check the order of your
middleware and that `KAGAMI_MODE` or `mode` is `protect`.
