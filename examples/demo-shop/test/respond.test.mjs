// The demo shop acting on Lurensic's events through onDetect, as a developer
// would. A tripwire blocks the sender's address, and locks the account only
// when safeToActOnSubject allows it.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { memorySink } from '@agenticslabs/lurensic-express';
import { createApp } from '../app.js';

const BROWSER = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
const AGENT_UA = 'python-httpx/0.27';

let base;
let server;
let app;
const access = [];

before(async () => {
  app = createApp(
    { secret: 'demo-shop-respond-secret-0123456789abcdef-012', sinks: [memorySink()], logger: { warn() {} } },
    { respond: true, accessLog: (r) => access.push(r) },
  );
  server = await new Promise((r) => {
    const s = app.listen(0, '127.0.0.1', () => r(s));
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await app.lurensic.close();
  await new Promise((r) => server.close(r));
});

const send = (path, ip, ua, init = {}) =>
  fetch(base + path, { ...init, headers: { 'user-agent': ua, 'x-forwarded-for': ip, ...(init.headers ?? {}) }, redirect: 'manual' });

async function signIn(ip) {
  const res = await send('/login', ip, BROWSER, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email: 'sam.taylor@northwind-outfitters.com', password: 'Ridgeline!2024' }).toString(),
  });
  assert.equal(res.status, 303);
  return res.headers.get('set-cookie').split(';')[0];
}

test('a tripwire blocks the attacker while honest customers carry on', async () => {
  const route = app.lurensic.manifest().decoys.routes[0];
  assert.equal((await send('/', '203.0.113.80', AGENT_UA)).status, 200);
  await send(route, '203.0.113.80', AGENT_UA);
  await app.lurensic.flush();
  const after = await send('/', '203.0.113.80', AGENT_UA);
  assert.equal(after.status, 403);
  assert.equal((await send('/', '198.51.100.80', BROWSER)).status, 200);
  assert.ok(access.some((a) => a.blocked === 'decoy.route' && a.ip === '203.0.113.80'));
});

test('a visitor lured by another site keeps their account and address, and a scripted attack locks the account', async () => {
  const cookie = await signIn('198.51.100.81');
  const field = app.lurensic.manifest().decoys.json_field;
  const param = app.lurensic.manifest().decoys.debug_param;

  // Another site sends the signed-in visitor to a link carrying the decoy parameter.
  await send(`/account?${param}=1`, '198.51.100.82', BROWSER, {
    headers: { cookie, 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate' },
  });
  await app.lurensic.flush();
  assert.equal((await send('/api/me', '198.51.100.81', BROWSER, { headers: { cookie } })).status, 200, 'the account is not locked');
  assert.equal((await send('/', '198.51.100.82', BROWSER)).status, 200, 'the lured address is not blocked');

  // A script using the stolen session changes the decoy field.
  await send('/api/me', '203.0.113.83', AGENT_UA, {
    method: 'PATCH',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({ [field]: 'admin' }),
  });
  await app.lurensic.flush();
  assert.equal((await send('/api/me', '198.51.100.81', BROWSER, { headers: { cookie } })).status, 401, 'the account is locked');
  assert.equal((await send('/', '198.51.100.81', BROWSER)).status, 200, 'the honest address is not blocked');
});
