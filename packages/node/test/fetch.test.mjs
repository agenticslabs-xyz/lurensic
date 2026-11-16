// The web-standard adapter, kagami(app). The same behaviour as the Express
// adapter, checked by calling the wrapped fetch handler directly. The second
// argument stands in for what each runtime passes next to the request.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { kagami, kagamiContext, memorySink, peerAddress } from '../dist/index.js';

const SECRET = 'fetch-adapter-secret-0123456789abcdef-01234';
const quiet = { warn() {} };
const HTML = '<!doctype html><html><head><title>Shop</title></head><body><h1>Welcome</h1></body></html>';
const NOT_FOUND = '<!doctype html><html><body>Not found</body></html>';

const html = (body, status = 200) => new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8' } });
const json = (value, status = 200) => Response.json(value, { status });

/** A small app with the routes the Express tests use. `hits` counts handler runs. */
function buildApp(hits = {}) {
  const count = (name) => (hits[name] = (hits[name] ?? 0) + 1);
  return async (request) => {
    const url = new URL(request.url);
    const ctx = kagamiContext(request);
    if (url.pathname === '/') return count('home'), html(HTML);
    if (url.pathname === '/api/me') return json({ id: 7, email: 'alice@example.com' });
    if (url.pathname === '/api/products') return json({ products: [] });
    if (url.pathname === '/search') {
      count('search');
      return new Response(`<p>Results for ${(url.searchParams.get('q') ?? '').replace(/[<>&]/g, '')}</p>`, { headers: { 'content-type': 'text/plain' } });
    }
    if (url.pathname === '/login' && request.method === 'POST') {
      count('login');
      const body = await request.text();
      return json({ ok: true, echo: body.length }, body.includes('password=correct-horse') ? 200 : 401);
    }
    if (url.pathname === '/orders') return json({ orders: [ctx ? ctx.seal(1043) : '1043'] });
    if (url.pathname.startsWith('/orders/')) {
      const raw = decodeURIComponent(url.pathname.slice('/orders/'.length));
      const id = ctx ? ctx.verify(raw, 'order_id') : raw;
      return id === null ? json({ error: 'not found' }, 404) : json({ id });
    }
    if (url.pathname === '/signup' && request.method === 'GET') {
      return html('<!doctype html><html><body><form method="post" action="/signup"><input name="email"></form><form action="/search"></form></body></html>');
    }
    if (url.pathname === '/signup' && request.method === 'POST') return new Response('ok', { status: 201 });
    return html(NOT_FOUND, 404);
  };
}

/** Deno passes `{ remoteAddr }` as the second argument. */
const from = (ip) => ({ remoteAddr: { hostname: ip, port: 40000 } });

async function call(app, path, init = {}, ip = '198.51.100.10') {
  const res = await app.fetch(new Request(`https://shop.example.com${path}`, { redirect: 'manual', ...init }), from(ip));
  return { status: res.status, headers: Object.fromEntries(res.headers), body: await res.text() };
}

const ATTACKS = [
  ['/', {}],
  ['/api/me', {}],
  ['/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--', { headers: { 'user-agent': 'sqlmap/1.8' } }],
  ['/.env', { headers: { 'user-agent': 'python-requests/2.32' } }],
  ['/.git/config', {}],
  ['/search?q=%7B%7B7*7%7D%7D', {}],
  ['/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"user":"admin","password":{"$ne":null}}' }],
];

test('in observe mode every response is identical to the app without Kagami', async () => {
  const mem = memorySink();
  const plain = { fetch: buildApp() };
  const guarded = kagami(buildApp(), { secret: SECRET, mode: 'observe', sinks: [mem], logger: quiet });
  for (const [path, init] of ATTACKS) {
    assert.deepEqual(await call(guarded, path, init), await call(plain, path, init), `response differs for ${path}`);
  }
  await guarded.kagami.flush();
  const rules = new Set(mem.events.map((e) => e.rule));
  for (const r of ['payload.sqli', 'client.scanner', 'bait.path', 'payload.ssti', 'payload.nosqli']) {
    assert.ok(rules.has(r), `observe mode should still detect ${r}, saw ${[...rules]}`);
  }
});

test('protect mode serves bait files and adds HTML and JSON decoys', async () => {
  const app = kagami(buildApp(), { secret: SECRET, mode: 'protect', decoys: { json: true }, sinks: [], logger: quiet });
  const env = await call(app, '/.env');
  assert.equal(env.status, 200);
  assert.match(env.body, /^NODE_ENV=production$/m);
  const home = await call(app, '/');
  assert.match(home.body, /<!-- .*sk_live_[A-Za-z0-9]{24}.* -->/);
  assert.ok(home.body.startsWith('<!doctype html>') && home.body.endsWith('</html>'));
  assert.equal(home.headers['content-length'], undefined, 'no stale length after decoration');
  assert.ok(!Object.keys(home.headers).some((h) => h.includes('kagami')), 'no Kagami headers');
  assert.equal((await call(app, '/search?q=boots')).body, '<p>Results for boots</p>', 'non-documents are never modified');
  const field = app.kagami.manifest().decoys.json_field;
  assert.ok(field in JSON.parse((await call(app, '/api/me')).body));
});

test('the app can still read a request body that Kagami inspected', async () => {
  const app = kagami(buildApp(), { secret: SECRET, mode: 'protect', sinks: [], logger: quiet });
  const body = 'user=admin&password=correct-horse';
  const res = await call(app, '/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  assert.equal(res.status, 200);
  assert.equal(JSON.parse(res.body).echo, body.length);
});

test('seal helpers reject and flag tampered IDs', async () => {
  const mem = memorySink();
  const app = kagami(buildApp(), { secret: SECRET, sinks: [mem], logger: quiet });
  const { orders } = JSON.parse((await call(app, '/orders')).body);
  assert.deepEqual(JSON.parse((await call(app, `/orders/${encodeURIComponent(orders[0])}`)).body), { id: '1043' });
  assert.equal((await call(app, `/orders/${encodeURIComponent(orders[0].replace('1043', '1044'))}`)).status, 404);
  await app.kagami.flush();
  assert.ok(mem.events.some((e) => e.rule === 'tamper.sealed_value'));
});

test('fails open if the engine misbehaves', async () => {
  const app = kagami(buildApp(), { secret: SECRET, mode: 'protect', sinks: [], logger: quiet });
  app.kagami.inspect = () => {
    throw new Error('engine exploded');
  };
  const home = await call(app, '/');
  assert.equal(home.status, 200);
  assert.equal(home.body, HTML);
});

test('form decoys add a hidden field to POST forms and catch an edited value', async () => {
  const mem = memorySink();
  const app = kagami(buildApp(), { secret: SECRET, mode: 'protect', decoys: { forms: true }, sinks: [mem], logger: quiet });
  const page = (await call(app, '/signup')).body;
  const [, name, value] = /<input type="hidden" name="([^"]+)" value="([^"]+)">/.exec(page);
  assert.equal(page.match(/type="hidden"/g).length, 1, 'only the POST form gets the field');
  const post = (body, ua) => call(app, '/signup', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': ua }, body });
  await post(`${name}=${value}&email=a%40b.c`, 'browser');
  await post(`${name}=admin&email=a%40b.c`, 'agent');
  await app.kagami.flush();
  assert.deepEqual(mem.events.filter((e) => e.rule === 'decoy.param').map((e) => e.source.user_agent), ['agent']);
});

test('a contained machine never reaches the application handlers', async () => {
  const hits = {};
  const app = kagami(buildApp(hits), { secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, sinks: [], logger: quiet });
  const visitor = (path, init) => call(app, path, init, '198.51.100.40');
  const attacker = (path, init) => call(app, path, init, '203.0.113.77');
  const home = await visitor('/');
  await visitor('/nothing-here');

  const field = app.kagami.manifest().decoys.json_field;
  assert.equal((await attacker(`/api/products?${field}=admin`)).status, 404, 'the tripping request is answered by the shadow');
  const before = { ...hits };
  const shadowHome = await attacker('/');
  assert.equal(shadowHome.status, 200);
  const strip = (s) => s.replace(/<!--[\s\S]*?-->\n?/g, '');
  assert.equal(strip(shadowHome.body), strip(home.body), 'same page as the public one');
  assert.equal((await attacker('/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'a=b' })).status, 404);
  assert.equal((await attacker('/admin')).body, NOT_FOUND, "the app's own 404");
  assert.deepEqual(hits, before, 'no handler ran for the contained machine');

  await visitor('/');
  assert.equal(hits.home, before.home + 1, 'other visitors are unaffected');
  assert.deepEqual(app.kagami.contained().map((m) => m.target), ['203.0.113.77']);
  await app.kagami.close();
});

test('block containment answers 403 and observe mode never contains', async () => {
  for (const [mode, expected] of [['protect', 403], ['observe', 200]]) {
    const app = kagami(buildApp(), { secret: SECRET, mode, decoys: { json: true }, containment: { action: 'block' }, sinks: [], logger: quiet });
    const field = app.kagami.manifest().decoys.json_field;
    await call(app, `/api/me?${field}=admin`);
    assert.equal((await call(app, '/')).status, expected, mode);
    await app.kagami.close();
  }
});

test('large, streamed, compressed and event-stream responses pass through untouched', async () => {
  const big = '<!doctype html><html><body>' + 'x'.repeat(2 * 1024 * 1024) + '</body></html>';
  const routes = {
    '/big': () => html(big),
    '/events': () => new Response('data: hello\n\n', { headers: { 'content-type': 'text/event-stream' } }),
    '/gz': () => new Response(new Uint8Array([31, 139, 8, 0]), { headers: { 'content-type': 'text/html', 'content-encoding': 'gzip' } }),
  };
  const app = kagami((request) => routes[new URL(request.url).pathname](), { secret: SECRET, mode: 'protect', sinks: [], logger: quiet });
  const res = await app.fetch(new Request('https://shop.example.com/big'), from('198.51.100.11'));
  assert.equal(await res.text(), big, 'a body over the decoration limit streams through unchanged');
  assert.equal((await call(app, '/events')).body, 'data: hello\n\n');
  const gz = await app.fetch(new Request('https://shop.example.com/gz'), from('198.51.100.11'));
  assert.deepEqual([...new Uint8Array(await gz.arrayBuffer())], [31, 139, 8, 0]);
});

test('the client address comes from what each runtime passes', () => {
  const req = (headers = {}) => new Request('https://shop.example.com/', { headers });
  assert.equal(peerAddress(req(), { remoteAddr: { hostname: '198.51.100.1' } }), '198.51.100.1', 'Deno');
  assert.equal(peerAddress(req(), { requestIP: () => ({ address: '198.51.100.2' }) }), '198.51.100.2', 'Bun');
  assert.equal(peerAddress(req(), { incoming: { socket: { remoteAddress: '198.51.100.3' } } }), '198.51.100.3', '@hono/node-server');
  const workers = req({ 'cf-connecting-ip': '198.51.100.4' });
  Object.defineProperty(workers, 'cf', { value: { colo: 'AMS' } });
  assert.equal(peerAddress(workers, {}), '198.51.100.4', 'Cloudflare Workers');
  assert.equal(peerAddress(req({ 'cf-connecting-ip': '198.51.100.5' }), {}), '', 'a client cannot claim an address on other runtimes');
});

test('settings can arrive with the request, as Cloudflare Workers bindings do', async () => {
  let waited = 0;
  const app = kagami(buildApp(), { sinks: [], logger: quiet });
  const bindings = { KAGAMI_SECRET: SECRET, KAGAMI_MODE: 'protect', SOME_KV: {} };
  const ctx = { waitUntil: (p) => (waited++, p) };
  // On Workers, Cloudflare sets CF-Connecting-IP and the request carries `cf`.
  const req = new Request('https://shop.example.com/.env', { headers: { 'cf-connecting-ip': '198.51.100.12' } });
  Object.defineProperty(req, 'cf', { value: {} });
  const res = await app.fetch(req, bindings, ctx);
  assert.match(await res.text(), /^NODE_ENV=production$/m, 'protect mode and the secret came from the bindings');
  assert.equal(waited, 1, 'background work is handed to waitUntil');
});

test('AWS Lambda through Hono passes the address in the request context', () => {
  const req = new Request('https://shop.example.com/');
  assert.equal(peerAddress(req, { event: { requestContext: { http: { sourceIp: '198.51.100.6' } } } }), '198.51.100.6', 'API Gateway HTTP API and function URLs');
  assert.equal(peerAddress(req, { event: { requestContext: { identity: { sourceIp: '198.51.100.7' } } } }), '198.51.100.7', 'API Gateway REST API');
});

test('without a client address Kagami steps aside instead of treating everyone as one machine', async () => {
  const warnings = [];
  const app = kagami(buildApp(), { secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, sinks: [], logger: { warn: (m) => warnings.push(m) } });
  const field = app.kagami.manifest().decoys.json_field;
  const bare = (path) => app.fetch(new Request(`https://shop.example.com${path}`));
  await bare(`/api/products?${field}=admin`);
  assert.equal((await bare('/')).status, 200, 'nobody is contained');
  assert.equal(app.kagami.contained().length, 0);
  assert.equal(warnings.filter((w) => w.includes('client address is unknown')).length, 1, 'warned once');
  const withIp = kagami(buildApp(), { secret: SECRET, mode: 'protect', clientIp: (r) => r.headers.get('x-nf-client-connection-ip'), sinks: [], logger: quiet });
  const res = await withIp.fetch(new Request('https://shop.example.com/.env', { headers: { 'x-nf-client-connection-ip': '198.51.100.8' } }));
  assert.match(await res.text(), /^NODE_ENV=production$/m, 'clientIp makes Kagami work');
});
