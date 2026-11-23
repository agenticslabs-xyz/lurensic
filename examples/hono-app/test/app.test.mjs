// The example app on Node. The same app runs on Cloudflare Workers through
// worker.mjs, which was checked with `wrangler dev`.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createApp } from '../app.mjs';

const SECRET = 'hono-app-test-secret-0123456789abcdef-012345';
const quiet = { warn() {} };
const from = (ip) => ({ incoming: { socket: { remoteAddress: ip } } });

test('the shop works and Lurensic protects it', async () => {
  const app = createApp({ secret: SECRET, mode: 'protect', containment: { action: 'block' }, sinks: [], logger: quiet });
  const products = await app.request('/api/products', {}, from('198.51.100.20'));
  assert.equal(products.status, 200);
  assert.equal((await products.json()).products.length, 3);
  // The attacker reads the page, which carries the bait comment.
  const home = await (await app.request('/', {}, from('203.0.113.50'))).text();
  // The comment's wording depends on the secret, so only its route and key are read.
  const comment = /<!--([\s\S]*?)-->/.exec(home)?.[1] ?? '';
  const route = /\/api\/[\w/-]+/.exec(comment)?.[0];
  const token = /sk_live_\w+/.exec(comment)?.[0];
  assert.ok(route && token, 'the home page carries the bait comment');

  const trip = await app.request(route, { headers: { authorization: `Bearer ${token}` } }, from('203.0.113.50'));
  assert.equal(trip.status, 200, 'the decoy route answers like a real one');
  assert.equal((await app.request('/api/products', {}, from('203.0.113.50'))).status, 403, 'the attacker is blocked');
  assert.equal((await app.request('/api/products', {}, from('198.51.100.20'))).status, 200, 'other visitors are not');
});

test('the diagnostics route only exists when ECHO_PATH is set', async () => {
  const app = createApp({ secret: SECRET, sinks: [], logger: quiet });
  assert.equal((await app.request('/diag-test', {}, from('198.51.100.21'))).status, 404);
  process.env.ECHO_PATH = 'diag-test';
  try {
    const res = await app.request('/diag-test', { headers: { 'x-forwarded-for': '192.0.2.1' } }, from('198.51.100.21'));
    const body = await res.json();
    assert.equal(body.peer, '198.51.100.21');
    assert.equal(body.headers['x-forwarded-for'], '192.0.2.1');
  } finally {
    delete process.env.ECHO_PATH;
  }
});
