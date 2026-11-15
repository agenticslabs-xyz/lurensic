# @agenticslabs/kagami-cloudflare

Cloudflare support for [Kagami](https://github.com/agenticslabs-xyz/kagami), a deception-based defence
against AI-driven attacks.

When Kagami contains a machine (an attacker that tripped a tripwire), this package adds its address to a
Cloudflare custom IP list. A WAF custom rule that matches the list then blocks or challenges the machine at
Cloudflare's edge, before it reaches your server. IP lists and WAF custom rules are available on every
Cloudflare plan, including Free.

Kagami is provider neutral. This package is one enforcer among several. If you do not use Cloudflare, see
`blocklistFile` and `webhookEnforcer` in [`@agenticslabs/kagami`](https://www.npmjs.com/package/@agenticslabs/kagami).

## Setup

1. Create an API token in the Cloudflare dashboard (My Profile, then API Tokens) with one permission,
   **Account Filter Lists Edit**, scoped to your account. Nothing else is needed.

2. Create the list.

   ```bash
   export CLOUDFLARE_API_TOKEN=...        # read from the environment only, never from the command line
   export CLOUDFLARE_ACCOUNT_ID=...
   npx @agenticslabs/kagami-cloudflare setup
   ```

   The command creates the IP list `kagami_contained` (or reuses it) and prints its id.

3. Add a WAF custom rule in each zone you protect (Security, then WAF, then Custom rules).

   | Field | Value |
   |---|---|
   | Expression | `(ip.src in $kagami_contained)` |
   | Action | Block, or Managed Challenge for a softer response |

4. Configure Kagami.

   ```js
   import { kagami } from '@agenticslabs/kagami-express';
   import { cloudflareClientIp, cloudflareEnforcer } from '@agenticslabs/kagami-cloudflare';

   app.use(kagami({
     mode: 'protect',
     containment: true,
     clientIp: cloudflareClientIp(),
     enforcers: [
       cloudflareEnforcer({
         apiToken: process.env.CLOUDFLARE_API_TOKEN,
         accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
         listId: process.env.KAGAMI_CLOUDFLARE_LIST_ID,
       }),
     ],
   }));
   ```

## How it works

- **Batched and off the request path.** Containments that arrive while a list update is running are sent
  together in the next update. Requests never wait for Cloudflare, and a Cloudflare outage never affects them.
- **Waits for completion.** List changes are asynchronous in Cloudflare and an account allows one pending
  change at a time. Each change is polled until Cloudflare reports it complete before the next one starts.
  Rate limits (HTTP 429) and server errors are retried with backoff.
- **Expires on its own.** Each item carries a comment such as
  `kagami until=2026-11-17T09:30:00.000Z reason=decoy.param`. A sweep every ten minutes removes expired items
  and duplicates. The list is the shared state, so this works across restarts and across several app instances.
- **Leaves your own entries alone.** Only items whose comment starts with `kagami ` are ever changed or removed.
- **Only public addresses.** Private, loopback, link-local, documentation and carrier-grade NAT addresses are
  never added. IPv6 attackers are added as their /64.
- **Release.** `kagami.release(ip)` removes the address from the list as well.

```bash
npx @agenticslabs/kagami-cloudflare status --list <id>   # how many machines are contained
npx @agenticslabs/kagami-cloudflare sweep  --list <id>   # remove expired entries now
```

## The real client address

Behind Cloudflare, every connection to your server comes from Cloudflare, and the visitor's address is in
`CF-Connecting-IP`. Anyone can send that header. If Kagami trusted it from any connection, an attacker could
forge it and get an innocent address added to your block list. `cloudflareClientIp()` trusts the header only
when the connection comes from Cloudflare's published address ranges.

If a proxy of your own (for example nginx on the same host) sits between Cloudflare and the app, name it.

```js
clientIp: cloudflareClientIp({ trustedProxies: ['127.0.0.1/32'] })
```

The proxy must append the Cloudflare peer to `X-Forwarded-For`. The ranges are built in
(`CLOUDFLARE_RANGES`, from cloudflare.com/ips) and can be overridden with `ranges`. For stronger origin
protection, also accept traffic only from Cloudflare, for example with Authenticated Origin Pulls or a
Cloudflare Tunnel.

## Limits

Cloudflare limits the number of items across all custom lists (10,000 on Free, Pro and Business at the time
of writing, more on Enterprise). Contained machines expire, one day by default, which keeps the list well
below that in normal use. Check `kagami.stats().enforcerErrors` and your logs if the list ever fills up.

Reporting contained machines to Cloudflare's Bot Feedback Loop, which trains Cloudflare's bot detection
models, needs Enterprise Bot Management and is on the roadmap.

Apache-2.0. Copyright [Agentics Labs](https://agenticslabs.xyz). Cloudflare is a trademark of Cloudflare, Inc.
This package is not affiliated with or endorsed by Cloudflare.
