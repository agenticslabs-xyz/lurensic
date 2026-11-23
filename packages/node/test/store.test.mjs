// The optional shared store. Two Lurensic instances sharing one store stand in
// for two copies of an app, or for one app before and after a restart.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { lurensic, memorySink, storeDriver, STORE_HELP } from '../dist/index.js';

const SECRET = 'store-test-secret-0123456789abcdef-01234567';
const quiet = { warn() {} };
const HTML = '<!doctype html><html><body>Home</body></html>';
const from = (ip) => ({ remoteAddr: { hostname: ip } });

/** An in-memory store with the Workers KV interface, including expiry. */
function fakeKv({ delayMs = 0, fail = false } = {}) {
  const map = new Map();
  const calls = [];
  const wait = () => new Promise((r) => setTimeout(r, delayMs));
  return {
    map,
    calls,
    async get(key) {
      calls.push(['get', key]);
      if (delayMs) await wait();
      if (fail) throw new Error('store unavailable');
      const v = map.get(key);
      return v && v.expires > Date.now() ? v.value : null;
    },
    async put(key, value, opts) {
      calls.push(['put', key, opts]);
      map.set(key, { value, expires: Date.now() + opts.expirationTtl * 1000 });
    },
    async delete(key) {
      calls.push(['delete', key]);
      map.delete(key);
    },
  };
}

const app = (hits) => async (request) => {
  hits.count = (hits.count ?? 0) + 1;
  const path = new URL(request.url).pathname;
  if (path === '/api/products') return Response.json({ products: [] });
  return new Response(HTML, { headers: { 'content-type': 'text/html' } });
};

function instance(store, extra = {}) {
  const hits = {};
  const mem = memorySink();
  const guarded = lurensic(app(hits), { secret: SECRET, mode: 'protect', decoys: { json: true }, containment: { action: 'block' }, store, sinks: [mem], logger: quiet, ...extra });
  const get = (path, ip) => guarded.fetch(new Request(`https://shop.example.com${path}`), from(ip));
  return { guarded, hits, mem, get };
}

async function trip(inst, ip) {
  const field = inst.guarded.lurensic.manifest().decoys.json_field;
  await inst.get(`/api/products?${field}=admin`, ip);
  await inst.guarded.lurensic.flush();
}

test('a machine contained by one instance is contained by another, or after a restart', async () => {
  const kv = fakeKv();
  const first = instance(kv);
  await trip(first, '203.0.113.30');
  assert.equal(kv.map.size, 1, 'the containment was written to the store');
  const [key, { value }] = [...kv.map][0];
  assert.match(key, /^lurensic:contained:[0-9a-f]{16}$/, 'keyed by the machine hash, not the address');
  assert.equal(JSON.parse(value).target, '203.0.113.30');
  assert.ok(kv.calls.find((c) => c[0] === 'put')[2].expirationTtl >= 60, 'Workers KV needs an expiry of at least 60 seconds');

  const second = instance(kv);
  assert.equal((await second.get('/', '203.0.113.30')).status, 403, 'blocked on its first request to the other instance');
  assert.equal(second.hits.count ?? 0, 0, 'the app never ran for it');
  assert.equal((await second.get('/', '198.51.100.30')).status, 200, 'other visitors are unaffected');
  await second.guarded.lurensic.flush();
  assert.ok(!second.mem.events.some((e) => e.rule === 'containment.started'), 'the second instance does not announce it again');
});

test('without a store, a fresh instance does not know the machine', async () => {
  const first = instance(undefined);
  await trip(first, '203.0.113.31');
  const second = instance(undefined);
  assert.equal((await second.get('/', '203.0.113.31')).status, 200);
});

test('each machine is looked up at most once a minute per instance', async () => {
  const kv = fakeKv();
  const inst = instance(kv);
  for (let i = 0; i < 5; i++) await inst.get('/', '198.51.100.32');
  assert.equal(kv.calls.filter((c) => c[0] === 'get').length, 1);
});

test('a slow or broken store never holds up or breaks a request', async () => {
  for (const kv of [fakeKv({ delayMs: 5_000 }), fakeKv({ fail: true })]) {
    const inst = instance(kv);
    const started = Date.now();
    const res = await inst.get('/', '198.51.100.33');
    assert.equal(res.status, 200);
    assert.ok(Date.now() - started < 1_500, 'gave up on the store quickly');
    assert.equal(inst.guarded.lurensic.stats().storeErrors, 1);
  }
});

test('release removes the machine from the store', async () => {
  const kv = fakeKv();
  const first = instance(kv);
  await trip(first, '203.0.113.34');
  assert.equal(kv.map.size, 1);
  first.guarded.lurensic.release('203.0.113.34');
  await first.guarded.lurensic.flush();
  assert.equal(kv.map.size, 0);
  assert.equal((await instance(kv).get('/', '203.0.113.34')).status, 200);
});

test('the store object each platform provides is recognised by its methods', async () => {
  const log = [];
  const rec = (name) => async (...args) => (log.push([name, ...args]), name === 'get' ? null : undefined);

  const deno = storeDriver({ atomic() {}, get: async (k) => (log.push(['get', k]), { value: 'v' }), set: rec('set'), delete: rec('delete') });
  assert.equal(await deno.get('k'), 'v');
  await deno.put('k', 'v', 90);
  assert.deepEqual(log.at(-1), ['set', ['lurensic', 'k'], 'v', { expireIn: 90_000 }], 'Deno KV');

  const workers = storeDriver({ get: rec('get'), put: rec('put'), delete: rec('delete') });
  await workers.put('k', 'v', 10);
  assert.deepEqual(log.at(-1), ['put', 'k', 'v', { expirationTtl: 60 }], 'Workers KV');

  const netlify = storeDriver({ get: rec('get'), set: rec('set'), setJSON() {}, delete: rec('delete') });
  await netlify.put('k', 'v', 90);
  assert.deepEqual(log.at(-1), ['set', 'k', 'v'], 'Netlify Blobs');

  const ioredis = storeDriver({ get: rec('get'), set: rec('set'), del: rec('del'), defineCommand() {} });
  await ioredis.put('k', 'v', 90);
  assert.deepEqual(log.at(-1), ['set', 'k', 'v', 'PX', 90_000], 'ioredis');

  const redis = storeDriver({ get: rec('get'), set: rec('set'), del: rec('del') });
  await redis.put('k', 'v', 90);
  assert.deepEqual(log.at(-1), ['set', 'k', 'v', { PX: 90_000, px: 90_000 }], 'node-redis and Upstash');
  await redis.delete('k');
  assert.deepEqual(log.at(-1), ['del', 'k']);

  assert.throws(() => storeDriver({ get() {} }), (err) => err.message === STORE_HELP);
});

test('values that come back already parsed, as from Upstash, work too', async () => {
  const kv = fakeKv();
  const first = instance(kv);
  await trip(first, '203.0.113.35');
  const parsed = { ...kv, get: async (key) => JSON.parse((await kv.get(key)) ?? 'null') };
  assert.equal((await instance(parsed).get('/', '203.0.113.35')).status, 403);
});

test('an unusable store is ignored with a warning, and Lurensic keeps working', async () => {
  const warnings = [];
  const inst = instance({ nope: true }, { logger: { warn: (m) => warnings.push(m) } });
  assert.equal((await inst.get('/', '198.51.100.36')).status, 200);
  assert.match(warnings.join('\n'), /The store is not used/, 'warned when the engine started on the first request');
});

test('on Workers, a KV binding named LURENSIC_STORE is used without any code', async () => {
  const kv = fakeKv();
  const bindings = (ip) => ({ LURENSIC_SECRET: SECRET, LURENSIC_MODE: 'protect', LURENSIC_CONTAINMENT: 'block', LURENSIC_STORE: kv, ip });
  const worker = () => lurensic(app({}), { decoys: { json: true }, sinks: [], logger: quiet });
  // Workers pass the bindings as the second argument and Cloudflare sets CF-Connecting-IP.
  const call = (w, path, ip) => {
    const req = new Request(`https://shop.example.com${path}`, { headers: { 'cf-connecting-ip': ip } });
    Object.defineProperty(req, 'cf', { value: {} });
    return w.fetch(req, bindings(ip), { waitUntil() {} });
  };
  const first = worker();
  await call(first, '/', '203.0.113.40');
  const field = first.lurensic.manifest().decoys.json_field;
  await call(first, `/api/products?${field}=admin`, '203.0.113.40');
  await first.lurensic.flush();
  assert.equal(kv.map.size, 1);
  assert.equal((await call(worker(), '/', '203.0.113.40')).status, 403, 'a fresh Worker copy knows the machine');
});

test('store can be a function that picks a binding', async () => {
  const kv = fakeKv();
  const guarded = lurensic(app({}), { secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, store: (env) => env.MY_KV, sinks: [], logger: quiet });
  await guarded.fetch(new Request('https://shop.example.com/'), { MY_KV: kv, remoteAddr: { hostname: '198.51.100.41' } });
  assert.equal(kv.calls.filter((c) => c[0] === 'get').length, 1);
});
