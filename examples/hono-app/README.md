# Hono test app

A small shop API with Kagami, used to test Kagami on real hosts. The same `app.mjs` runs on Node (`server.mjs`) and on
Cloudflare Workers (`worker.mjs`).

## Settings

| Variable | Value |
|---|---|
| `KAGAMI_SECRET` | From `npx @agenticslabs/kagami secret`. Required. |
| `KAGAMI_MODE` | `protect` for testing |
| `KAGAMI_CONTAINMENT` | `on` or `block`. `block` makes containment easy to see, because the contained machine gets a `403`. |
| `ECHO_PATH` | Optional. A random word. The app then answers `/<ECHO_PATH>` with the request headers, the address the runtime reported, and the contained machines. Leave it unset outside of testing. |

## Run it on Node

```bash
pnpm install
pnpm --filter hono-app start      # listens on PORT, 3000 by default
```

On a host such as Render, use a Web Service with the start command `node server.mjs`.

## Run it on Cloudflare Workers

```bash
npx wrangler dev                  # local, with a local KV store
npx wrangler secret put KAGAMI_SECRET
npx wrangler kv namespace create KAGAMI_STORE   # put the id in wrangler.toml
npx wrangler deploy
```

## Test containment

1. Open the home page and find the HTML comment. It names an API route and a key.
2. From a network you can afford to have cut off, such as a phone hotspot, call that route with the key as a bearer
   token. The machine is now contained.
3. Any further request from that network gets a `403`. Your normal connection still works.

## Test the store

1. Contain a machine as above.
2. Restart or redeploy the app, which clears Kagami's memory.
3. Request again from the contained network. With a store, the answer is still `403`. Without one, the app answers
   normally again.

Locally, `wrangler dev` keeps its KV store on disk between runs, so stopping and starting it is enough.

## See how the host passes the visitor's address

Set `ECHO_PATH`, open `/<ECHO_PATH>` through your own domain and through the host's own address, and compare `peer` and
the forwarding headers. That shows which `clientAddress` setting the host needs.
