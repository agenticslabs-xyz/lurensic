// Kagami for Hono. The app is called through Hono's own app.request(), and the
// third argument stands in for what the runtime passes as c.env.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Hono } from 'hono';
import { kagami, memorySink } from '../dist/index.js';

const SECRET = 'hono-adapter-secret-0123456789abcdef-012345';
const quiet = { warn() {} };
const HTML = '<!doctype html><html><head><title>Shop</title></head><body><h1>Welcome</h1></body></html>';
const NOT_FOUND = '<!doctype html><html><body>Not found</body></html>';

function buildApp(mw, hits = {}) {
  const count = (name) => (hits[name] = (hits[name] ?? 0) + 1);
  const app = new Hono();
  if (mw) app.use(mw);
  // An inner middleware that sets a header, to check decoration keeps it.
  app.use(async (c, next) => {
    c.header('x-inner', 'kept');
    await next();
  });
  // An explicit Content-Length, to check decoration never carries a stale one over.
  app.get('/', (c) => (count('home'), c.body(HTML, 200, { 'content-type': 'text/html; charset=utf-8', 'content-length': String(Buffer.byteLength(HTML)) })));
  app.get('/api/me', (c) => c.json({ id: 7, email: 'alice@example.com' }));
  app.get('/api/products', (c) => c.json({ products: [] }));
  app.get('/search', (c) => (count('search'), c.text(`<p>Results for ${(c.req.query('q') ?? '').replace(/[<>&]/g, '')}</p>`)));
  app.post('/login', async (c) => {
    count('login');
    const body = await c.req.text();
    return c.json({ ok: true, echo: body.length }, body.includes('password=correct-horse') ? 200 : 401);
  });
  app.get('/orders', (c) => c.json({ orders: [c.get('kagami')?.seal(1043) ?? '1043'] }));
  app.get('/orders/:id', (c) => {
    const k = c.get('kagami');
    const id = k ? k.verify(c.req.param('id'), 'order_id') : c.req.param('id');
    return id === null ? c.json({ error: 'not found' }, 404) : c.json({ id });
  });
  app.notFound((c) => c.html(NOT_FOUND, 404));
  return app;
}

const from = (ip) => ({ remoteAddr: { hostname: ip, port: 40000 } });

async function call(app, path, init = {}, ip = '198.51.100.10') {
  const res = await app.request(path, init, from(ip));
  return { status: res.status, headers: Object.fromEntries(res.headers), body: await res.text() };
}

test('in observe mode every response is identical to the app without Kagami', async () => {
  const mem = memorySink();
  const attacks = [
    ['/', {}],
    ['/api/me', {}],
    ['/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--', { headers: { 'user-agent': 'sqlmap/1.8' } }],
    ['/.env', {}],
    ['/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"user":"admin","password":{"$ne":null}}' }],
  ];
  const plain = buildApp();
  const mw = kagami({ secret: SECRET, mode: 'observe', sinks: [mem], logger: quiet });
  const guarded = buildApp(mw);
  for (const [path, init] of attacks) assert.deepEqual(await call(guarded, path, init), await call(plain, path, init), path);
  await mw.kagami.flush();
  const rules = new Set(mem.events.map((e) => e.rule));
  for (const r of ['payload.sqli', 'client.scanner', 'bait.path', 'payload.nosqli']) assert.ok(rules.has(r), `${r} missing, saw ${[...rules]}`);
});

test('protect mode serves bait and decorates responses without breaking their headers', async () => {
  const mw = kagami({ secret: SECRET, mode: 'protect', decoys: { json: true }, sinks: [], logger: quiet });
  const app = buildApp(mw);
  assert.match((await call(app, '/.env')).body, /^NODE_ENV=production$/m);
  const home = await call(app, '/');
  assert.match(home.body, /<!-- .*sk_live_[A-Za-z0-9]{24}.* -->/);
  assert.equal(home.headers['x-inner'], 'kept', 'headers from other middleware survive decoration');
  assert.notEqual(home.headers['content-length'], String(Buffer.byteLength(HTML)), 'the original Content-Length is not carried over');
  const me = await call(app, '/api/me');
  assert.ok(mw.kagami.manifest().decoys.json_field in JSON.parse(me.body));
  assert.equal(me.headers['x-inner'], 'kept');
  assert.equal((await call(app, '/search?q=boots')).body, '<p>Results for boots</p>');
});

test('c.get("kagami") seals and verifies values', async () => {
  const mem = memorySink();
  const mw = kagami({ secret: SECRET, sinks: [mem], logger: quiet });
  const app = buildApp(mw);
  const { orders } = JSON.parse((await call(app, '/orders')).body);
  assert.notEqual(orders[0], '1043', 'the ID is sealed');
  assert.deepEqual(JSON.parse((await call(app, `/orders/${encodeURIComponent(orders[0])}`)).body), { id: '1043' });
  assert.equal((await call(app, `/orders/${encodeURIComponent(orders[0].replace('1043', '1044'))}`)).status, 404);
  await mw.kagami.flush();
  assert.ok(mem.events.some((e) => e.rule === 'tamper.sealed_value'));
});

test('the app can still read a request body that Kagami inspected', async () => {
  const app = buildApp(kagami({ secret: SECRET, mode: 'protect', sinks: [], logger: quiet }));
  const body = 'user=admin&password=correct-horse';
  const res = await call(app, '/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  assert.equal(res.status, 200);
  assert.equal(JSON.parse(res.body).echo, body.length);
});

test('a contained machine never reaches the routes', async () => {
  const hits = {};
  const mw = kagami({ secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, sinks: [], logger: quiet });
  const app = buildApp(mw, hits);
  const home = await call(app, '/', {}, '198.51.100.40');
  await call(app, '/nothing-here', {}, '198.51.100.40');
  const field = mw.kagami.manifest().decoys.json_field;
  assert.equal((await call(app, `/api/products?${field}=admin`, {}, '203.0.113.77')).status, 404);
  const before = { ...hits };
  const strip = (s) => s.replace(/<!--[\s\S]*?-->\n?/g, '');
  assert.equal(strip((await call(app, '/', {}, '203.0.113.77')).body), strip(home.body), 'the shadow serves the public page');
  assert.equal((await call(app, '/admin', {}, '203.0.113.77')).body, NOT_FOUND, "the app's own 404");
  assert.equal((await call(app, '/login', { method: 'POST', body: 'a=b' }, '203.0.113.77')).status, 404);
  assert.deepEqual(hits, before, 'no route ran for the contained machine');
  await call(app, '/', {}, '198.51.100.40');
  assert.equal(hits.home, before.home + 1, 'other visitors are unaffected');
  await mw.kagami.close();
});

test('on Workers, settings come from the bindings and background work goes to waitUntil', async () => {
  let waited = 0;
  const mw = kagami({ sinks: [], logger: quiet });
  const app = buildApp(mw);
  const bindings = { KAGAMI_SECRET: SECRET, KAGAMI_MODE: 'protect' };
  const executionCtx = { waitUntil: (p) => (waited++, p), passThroughOnException() {} };
  // On Workers, Cloudflare sets CF-Connecting-IP and the request carries `cf`.
  const req = new Request('http://localhost/.env', { headers: { 'cf-connecting-ip': '198.51.100.12' } });
  Object.defineProperty(req, 'cf', { value: {} });
  const res = await app.request(req, undefined, bindings, executionCtx);
  assert.match(await res.text(), /^NODE_ENV=production$/m);
  assert.equal(waited, 1);
});

test('on Render behind Cloudflare the visitor address is the one Cloudflare saw, and forged headers do not change it', async () => {
  // Headers recorded from a real Render service, through a custom domain on
  // Cloudflare and through the onrender.com address. Render's own edge is
  // Cloudflare, and its proxy reaches the app over loopback.
  const clientAddress = { cloudflare: true, trustedProxies: ['::1', '127.0.0.1', '10.0.0.0/8'] };
  const cases = [
    ['custom domain', '198.51.100.23,198.51.100.23, 162.159.114.45, 10.30.197.182', '198.51.100.23', '198.51.100.23'],
    ['onrender.com', '198.51.100.23, 162.159.114.84, 10.24.84.0', '198.51.100.23', '198.51.100.23'],
    ['forged X-Forwarded-For', '9.9.9.9, 203.0.113.50, 162.159.114.84, 10.24.84.0', '203.0.113.50', '203.0.113.50'],
    ['forged CF-Connecting-IP without Cloudflare', '9.9.9.9, 203.0.113.77, 10.24.84.0', '9.9.9.9', '203.0.113.77'],
  ];
  for (const [name, xff, cf, want] of cases) {
    const mem = memorySink();
    const mw = kagami({ secret: SECRET, mode: 'protect', clientAddress, sinks: [mem], logger: quiet });
    const app = buildApp(mw);
    await app.request('/.env', { headers: { 'x-forwarded-for': xff, 'cf-connecting-ip': cf } }, { incoming: { socket: { remoteAddress: '::1' } } });
    await mw.kagami.flush();
    const ips = [...new Set(mem.events.filter((e) => e.kind !== 'system').map((e) => e.source?.ip))];
    assert.deepEqual(ips, [want], name);
  }
});
