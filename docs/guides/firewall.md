# Blocking at your firewall or CDN

Kagami already cuts a contained machine off from your application. You do not need anything else for that. This page
is for when you also want the machine stopped before it reaches your server, at nginx, a host firewall, a CDN or a
cloud WAF.

Kagami does not ship integrations for particular providers. It hands you the list of contained machines in three
neutral ways, and you connect that list to whatever you already run. The recipes below show how.

## Should you block at the edge at all?

Think about it before you do. In shadow mode, a contained attacker keeps receiving copies of public pages and decoys,
and has no sign that it was caught. An edge block answers with an error page instead. The attacker then knows it was
detected and can move to a new address and start again.

Edge blocking is worth it when the traffic itself costs you, for example in server load or bandwidth, or when your
policy requires attackers to be blocked outright. Otherwise containment inside the app is often the better defence.

## What Kagami gives you

| Way | What you get | Details |
|---|---|---|
| `blocklistFile({ path, format })` | A file of contained addresses, replaced atomically, kept across restarts, with expired entries removed | Formats `plain`, `nginx` and `json`. `onChange` runs after every rewrite, and `.entries()` returns the live list. |
| `webhookEnforcer({ url, secret })` | A signed HTTPS POST to your endpoint for every batch of contained and released machines | Payload and signature in the [containment guide](containment.md#enforcers) |
| `callbackEnforcer(contain, { release })` | Your own function, called in process | Anything else |

All three only receive public addresses, never private or loopback ones, unless you pass `includePrivate: true`. They
run off the request path, so a slow or failing firewall API never slows or breaks a request. Failures are counted in
`kagami.stats().enforcerErrors`.

Each contained machine looks like this. `target` is what to block, an IPv4 address or an IPv6 /64.

```json
{ "source": "51d0e3a7b2c94f18", "target": "198.51.100.4", "public": true,
  "reason": "decoy.param", "since": 1794787200000, "until": 1794873600000 }
```

Before blocking anything, make sure Kagami sees the real visitor address. See [Behind a proxy or CDN](behind-a-proxy.md).

## nginx

```js
import { execFile } from 'node:child_process';
import { blocklistFile } from '@agenticslabs/kagami-express';

const reloadNginx = () => new Promise((resolve) => execFile('nginx', ['-s', 'reload'], () => resolve()));

app.use(kagami({
  mode: 'protect',
  containment: true,
  enforcers: [blocklistFile({ path: '/etc/nginx/kagami-blocked.conf', format: 'nginx', onChange: reloadNginx })],
}));
```

Add `include /etc/nginx/kagami-blocked.conf;` to the `server` block. The file holds one `deny` line per machine. The app
needs permission to write the file and to reload nginx. If it has neither, write the file somewhere the app can and let
a cron job or a file watcher copy it and reload nginx.

## ipset, iptables and other host firewalls

Use `format: 'plain'`, which writes one address or range per line, and load it from a script.

```bash
ipset create kagami hash:net -exist
ipset create kagami6 hash:net family inet6 -exist
ipset flush kagami
ipset flush kagami6
while read -r ip; do
  case "$ip" in
    *:*) ipset add kagami6 "$ip" -exist ;;
    *) ipset add kagami "$ip" -exist ;;
  esac
done < /var/lib/myapp/kagami-blocked.txt
```

Run the script from `onChange` or on a timer. Add the sets to the firewall once, with
`iptables -I INPUT -m set --match-set kagami src -j DROP` and
`ip6tables -I INPUT -m set --match-set kagami6 src -j DROP`.

## Cloudflare

This recipe keeps a Cloudflare IP list equal to Kagami's list. A WAF custom rule then blocks or challenges everything
on it at Cloudflare's edge. It works on every Cloudflare plan, including Free.

**1. Create the list and the rule in the Cloudflare dashboard.**

- In the account Settings, go to Lists and create a list of type IP, for example `kagami_contained`. Use it only for
  Kagami, because the recipe replaces its whole content on every change.
- In each zone you protect, go to Security, WAF, Custom rules, and create a rule with the expression
  `(ip.src in $kagami_contained)` and the action Block or Managed Challenge.

**2. Create an API token** with the single account permission **Account Filter Lists Edit**. It can change your IP lists
and nothing else.

**3. Find the list ID** with the token.

```bash
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/rules/lists"
```

**4. Add the enforcer.** `blocklistFile` keeps the list, removes expired machines and survives restarts. Its `onChange`
sends the whole current list to Cloudflare, so machines that expire also leave Cloudflare at the next change.

```js
import { blocklistFile } from '@agenticslabs/kagami-express';

const { CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_LIST_ID } = process.env;

const contained = blocklistFile({
  path: '/tmp/kagami-contained.json',
  format: 'json',
  // Replaces every item in the Cloudflare list with Kagami's current list.
  onChange: async () => {
    const items = contained.entries().map((m) => ({ ip: m.target, comment: `kagami ${m.reason}` }));
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/rules/lists/${CLOUDFLARE_LIST_ID}/items`,
      {
        method: 'PUT',
        headers: { authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify(items),
      },
    );
    if (!res.ok) throw new Error(`Cloudflare list update failed with HTTP ${res.status}`);
  },
});

app.use(kagami({
  mode: 'protect',
  containment: true,
  clientAddress: { cloudflare: true },
  enforcers: [contained],
}));
```

`clientAddress: { cloudflare: true }` makes Kagami read the visitor address from `CF-Connecting-IP`, but only on
connections from Cloudflare's published ranges. Without it, Kagami would contain Cloudflare's own addresses.

Cloudflare applies list changes asynchronously and allows one pending change per account. If an update is refused
because another one is still running, the next change sends the full list again, so nothing is lost for long.

The file in `/tmp` keeps the list across restarts on a normal server. On hosts with a fresh disk on every deploy, the
list starts empty after a deploy and Cloudflare is brought in line at the next change.

## AWS WAF, Azure WAF, Google Cloud Armor and others

Cloud WAFs take an IP set or a list of address ranges. Two approaches work.

- **Webhook.** Point `webhookEnforcer` at a small function in your cloud, such as an AWS Lambda or an Azure Function.
  The function verifies the `kagami-signature` header and adds or removes the addresses in the IP set. This keeps
  cloud credentials out of the app.
- **Callback.** Call your cloud SDK from `callbackEnforcer`, in the same shape as the Cloudflare recipe. Use
  `blocklistFile` with `onChange` when the provider replaces the whole set in one call, as AWS WAF's `UpdateIPSet`
  does.

Give the credentials only the permission to change that one IP set.

## Checking it

`guard` is the value `kagami()` returns, as in the [containment guide](containment.md#managing-contained-machines).

```js
guard.kagami.contained();             // what Kagami holds now
guard.kagami.release('198.51.100.4'); // ends a containment early and tells every enforcer
guard.kagami.stats().enforcerErrors;  // failed deliveries
```

In observe mode, containment is a dry run and enforcers receive nothing. Turn on protect mode to test a recipe, and
trip a decoy from a network you can afford to have blocked, such as a phone hotspot.
