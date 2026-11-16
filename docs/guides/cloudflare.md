# Cloudflare

Kagami contains attackers inside your app. With Cloudflare in front of the app, Kagami can also stop them at
Cloudflare's edge, before they reach your server. It is built into the Kagami package. There is nothing else to
install or run.

```mermaid
flowchart LR
    ATT["Attacker"] -->|"touches a tripwire"| APP["Your app with Kagami"]
    APP -->|"adds the machine,<br/>Lists API"| LIST["Cloudflare IP list<br/>kagami_contained"]
    LIST --> RULE["WAF custom rule<br/>ip.src in $kagami_contained"]
    RULE -->|"blocks or challenges<br/>every later request"| ATT
```

This works on every Cloudflare plan, including Free. It uses two standard Cloudflare features, a custom IP list and a
WAF custom rule.

## What you need

| Environment variable | Where it comes from |
|---|---|
| `CLOUDFLARE_API_TOKEN` | A runtime token with one account permission, **Account Filter Lists Edit**. It cannot change DNS, zones, rules or anything else. See step 1. |
| `CLOUDFLARE_ACCOUNT_ID` | The account ID shown on your Cloudflare dashboard. Setup prints it too. |
| `KAGAMI_CLOUDFLARE_LIST_ID` | Printed by `npx @agenticslabs/kagami cloudflare setup` |

When all three are set and containment is on, Kagami sends contained machines to Cloudflare by itself.

## 1. Create the tokens

Kagami recommends two API tokens, so the token your app keeps can do as little as possible.

| Token | Permissions | Lifetime |
|---|---|---|
| Setup token | **Account Filter Lists Edit**, **Zone Read**, **Zone WAF Edit**, limited to the zones you protect | Used once by `cloudflare setup`, then deleted |
| Runtime token | **Account Filter Lists Edit** only | Kept by the app as `CLOUDFLARE_API_TOKEN` |

Create both under Manage Account, Account API Tokens, Create Token. Run setup without a token and it prints a link that
opens Create Token with the zone permissions already selected.

```bash
npx @agenticslabs/kagami cloudflare setup
```

Cloudflare publishes no link key for Account Filter Lists, so add that permission by hand on the Create Token page.

One token with all three permissions also works. It is simpler, but the app then holds a token that can change your WAF
rules.

## 2. Run setup

Put the setup token in the environment and name the domain you protect.

```bash
export CLOUDFLARE_API_TOKEN=<setup token>
export CLOUDFLARE_ACCOUNT_ID=<account id>
npx @agenticslabs/kagami cloudflare setup --zone example.com
```

The command does three things.

1. It creates the IP list `kagami_contained`, or finds it when it already exists.
2. It adds a WAF custom rule with the expression `(ip.src in $kagami_contained)` and the action Block to the zone.
3. It prints the settings for the app and lists the permissions it used.

| Option | Meaning |
|---|---|
| `--zone <domain or zone id>` | The zone to protect. A host inside the zone such as `shop.example.com`, or a pasted URL, also works. Repeat it for several zones. |
| `--action managed_challenge` | Use Managed Challenge instead of Block, for a softer response |
| `--name <list name>` | Use another list name than `kagami_contained` |

Setup is safe to run again. It never replaces rules you already have. It adds one rule at the end of the zone's custom
rules, and when a rule with the Kagami expression or a description starting with "Kagami" is already there, it changes
nothing. If `CLOUDFLARE_ACCOUNT_ID` is not set and the token can see exactly one account, setup uses that account.

The token is read from the environment only, never from the command line, so it does not end up in shell history.

When setup is done, delete the setup token and give the app the runtime token.

### Adding the rule by hand

Without `--zone`, setup only creates the list and prints the rule to add yourself. In each zone you protect, go to
Security, WAF, Custom rules, Create rule.

| Field | Value |
|---|---|
| Expression | `(ip.src in $kagami_contained)` |
| Action | Block, or Managed Challenge for a softer response |

Free plans allow five custom rules per zone. The Kagami rule uses one of them.

## 3. Configure the app

Set the three variables where the app runs, plus these.

```bash
KAGAMI_MODE=protect
KAGAMI_CONTAINMENT=on
```

Tell Kagami the app is behind Cloudflare, so it uses the visitor's address instead of Cloudflare's.

```js
app.use(kagami({
  clientAddress: { cloudflare: true },
}));
```

Kagami then trusts `CF-Connecting-IP` only on connections from Cloudflare's published address ranges, so nobody can
forge it to get someone else blocked. If your own proxy sits between Cloudflare and the app, see
[Behind a proxy or CDN](behind-a-proxy.md).

You can pass everything in code instead of the environment.

```js
app.use(kagami({
  mode: 'protect',
  containment: true,
  clientAddress: { cloudflare: true },
  cloudflare: {
    apiToken: process.env.CLOUDFLARE_API_TOKEN,
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
    listId: process.env.KAGAMI_CLOUDFLARE_LIST_ID,
  },
}));
```

`cloudflare: false` keeps Cloudflare off even when the variables are set.

## 4. Check it

```bash
npx @agenticslabs/kagami doctor --url https://your-site.example
npx @agenticslabs/kagami cloudflare status
```

If a setting is missing, Kagami says which one when the app starts, and sends nothing to Cloudflare.

## How it behaves

- **It never slows a request.** Machines are sent to Cloudflare in the background, in batches. A Cloudflare outage
  never affects your app. Failures are counted in `kagami.stats().enforcerErrors`.
- **It only adds public addresses.** Private, loopback and documentation addresses are never sent. IPv6 attackers are
  added as their /64.
- **It removes entries when they expire.** Each item carries a comment such as
  `kagami until=2026-11-17T09:30:00.000Z reason=decoy.param`. Every ten minutes, expired and duplicate Kagami items are
  removed. `kagami.release(ip)` removes an address at once.
- **It never touches entries it did not add.** Items without the `kagami ` prefix are left alone, so you can share the
  list with entries you manage yourself.
- **It works across restarts and servers.** The list in Cloudflare is the shared record, so several app instances can
  use one list.
- **It is careful with the API.** Cloudflare applies list changes asynchronously and allows one pending change per
  account. Kagami waits for each change to finish before the next and retries rate limits.

```bash
npx @agenticslabs/kagami cloudflare sweep     # remove expired entries now
```

## Limits

Cloudflare limits the items across all custom lists by plan (10,000 on Free, Pro and Business at the time of writing).
Entries expire, one day by default, which keeps the list small in normal use.

Cloudflare's Bot Feedback Loop, which reports missed bots to Cloudflare's detection models, needs Enterprise Bot
Management. Support for it is on the roadmap.

Cloudflare is a trademark of Cloudflare, Inc. Kagami is not affiliated with or endorsed by Cloudflare.
