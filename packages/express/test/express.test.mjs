import assert from 'node:assert/strict';
import { test } from 'node:test';
import express from 'express';
import { kagami, memorySink } from '../dist/index.js';

const SECRET = 'express-test-secret-0123456789abcdef-012345';
const quiet = { warn() {} };

const HTML = '<!doctype html><html><head><title>Shop</title></head><body><h1>Welcome</h1></body></html>';

function buildApp(middleware) {
  const app = express();
  app.set('etag', false);
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  if (middleware) app.use(middleware);
  app.get('/', (_req, res) => res.type('html').send(HTML));
  app.get('/api/me', (_req, res) => res.json({ id: 7, email: 'alice@example.com' }));
  app.get('/search', (req, res) => res.send(`<p>Results for ${String(req.query.q ?? '').replace(/[<>&]/g, '')}</p>`));
  app.post('/login', (req, res) => res.status(req.body?.password === 'correct-horse' ? 200 : 401).json({ ok: true }));
  app.get('/orders', (req, res) => res.json({ orders: [req.kagami ? req.kagami.seal(1043) : '1043'] }));
  app.get('/orders/:id', (req, res) => {
    const id = req.kagami ? req.kagami.verify(req.params.id, 'order_id') : req.params.id;
    if (id === null) return res.status(404).json({ error: 'not found' });
    res.json({ id });
  });
  return app;
}

async function listen(app) {
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

async function fetchRaw(base, path, init = {}) {
  const res = await fetch(base + path, { redirect: 'manual', ...init });
  const headers = Object.fromEntries([...res.headers].filter(([k]) => k !== 'date' && k !== 'keep-alive' && k !== 'connection'));
  return { status: res.status, headers, body: await res.text() };
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

test('in observe mode every response is byte-identical to the app without Kagami', async () => {
  const mem = memorySink();
  const plain = await listen(buildApp());
  const guarded = await listen(buildApp(kagami({ secret: SECRET, mode: 'observe', sinks: [mem], logger: quiet })));
  try {
    for (const [path, init] of ATTACKS) {
      const a = await fetchRaw(plain.base, path, init);
      const b = await fetchRaw(guarded.base, path, init);
      assert.deepEqual(b, a, `response differs for ${path}`);
    }
  } finally {
    await plain.close();
    await guarded.close();
  }
  const rules = new Set(mem.events.map((e) => e.rule));
  for (const r of ['payload.sqli', 'client.scanner', 'bait.path', 'payload.ssti', 'payload.nosqli']) {
    assert.ok(rules.has(r), `observe mode should still detect ${r}; saw ${[...rules]}`);
  }
});

test('protect mode serves bait files and adds HTML and JSON decoys', async () => {
  const mw = kagami({ secret: SECRET, mode: 'protect', decoys: { json: true }, sinks: [], logger: quiet });
  const app = await listen(buildApp(mw));
  try {
    const env = await fetchRaw(app.base, '/.env');
    assert.equal(env.status, 200);
    assert.match(env.body, /^NODE_ENV=production$/m);
    assert.match(env.body, /^(SMTP_PASS=|STRIPE_SECRET_KEY=sk_live_|DATABASE_URL=postgres:\/\/[^:]+:)[A-Za-z0-9]{24}/m);
    const aws = await fetchRaw(app.base, '/.aws/credentials');
    assert.match(aws.body, /^aws_access_key_id = AKIA[A-Z2-7]{16}$/m);
    assert.equal(env.headers['x-powered-by'], 'Express', 'bait goes through the app like any response (no Kagami fingerprint)');

    const home = await fetchRaw(app.base, '/');
    assert.match(home.body, /<!-- .*sk_live_[A-Za-z0-9]{24}.* -->/);
    assert.ok(home.body.startsWith('<!doctype html>') && home.body.endsWith('</html>'));
    assert.ok(!Object.keys(home.headers).some((h) => h.includes('kagami')), 'no Kagami headers');

    const fragment = await fetchRaw(app.base, '/search?q=boots');
    assert.equal(fragment.body, '<p>Results for boots</p>', 'non-documents are never modified');

    const me = await fetchRaw(app.base, '/api/me');
    const field = mw.kagami.manifest().decoys.json_field;
    assert.ok(field in JSON.parse(me.body));
  } finally {
    await app.close();
  }
});

test('seal helpers reject and flag tampered IDs', async () => {
  const mem = memorySink();
  const app = await listen(buildApp(kagami({ secret: SECRET, sinks: [mem], logger: quiet })));
  try {
    const { orders } = JSON.parse((await fetchRaw(app.base, '/orders')).body);
    const ok = await fetchRaw(app.base, `/orders/${encodeURIComponent(orders[0])}`);
    assert.deepEqual(JSON.parse(ok.body), { id: '1043' });
    const forged = await fetchRaw(app.base, `/orders/${encodeURIComponent(orders[0].replace('1043', '1044'))}`);
    assert.equal(forged.status, 404);
    await settle();
    assert.ok(mem.events.some((e) => e.rule === 'tamper.sealed_value'));
  } finally {
    await app.close();
  }
});

async function settle() {
  await new Promise((r) => setTimeout(r, 20));
}

test('fails open if the engine misbehaves', async () => {
  const mw = kagami({ secret: SECRET, mode: 'protect', sinks: [], logger: quiet });
  mw.kagami.inspect = () => {
    throw new Error('engine exploded');
  };
  const app = await listen(buildApp(mw));
  try {
    const home = await fetchRaw(app.base, '/');
    assert.equal(home.status, 200);
    assert.equal(home.body, HTML);
  } finally {
    await app.close();
  }
});

test('brute force and enumeration are detected from response codes', async () => {
  const mem = memorySink();
  const app = await listen(buildApp(kagami({ secret: SECRET, sinks: [mem], logger: quiet })));
  try {
    for (let i = 0; i < 10; i++) {
      await fetchRaw(app.base, '/login', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `user=admin&password=guess${i}`,
      });
    }
    for (let i = 0; i < 20; i++) await fetchRaw(app.base, `/backup-${i}.zip`);
    await settle();
    const rules = mem.events.map((e) => e.rule);
    assert.ok(rules.includes('behavior.auth_failures'), String(rules));
    assert.ok(rules.includes('behavior.enumeration'), String(rules));
    assert.ok(!mem.lines.some((l) => l.includes('guess')), 'passwords never reach the log');
  } finally {
    await app.close();
  }
});

// Regression tests from the first live benchmark round (2026-11-15).

test('requests rejected by the body parser are still inspected', async () => {
  const mem = memorySink();
  const plain = await listen(buildApp());
  const guarded = await listen(buildApp(kagami({ secret: SECRET, mode: 'observe', sinks: [mem], logger: quiet })));
  const broken = [
    { headers: { 'content-type': 'application/json' }, body: '{"email":"x\' OR 1=1--","password":' },
    { headers: { 'content-type': 'application/json; charset=latin1' }, body: '{"email":"a@b.c"}' },
  ];
  try {
    for (const init of broken) {
      const a = await fetch(plain.base + '/login', { method: 'POST', ...init });
      const b = await fetch(guarded.base + '/login', { method: 'POST', ...init });
      assert.equal(b.status, a.status, 'observe mode leaves the app error response alone');
    }
  } finally {
    await plain.close();
    await guarded.close();
  }
  await settle();
  const rules = mem.events.map((e) => e.rule);
  assert.ok(rules.includes('request.malformed_body'), String(rules));
  assert.ok(rules.includes('payload.sqli'), `payloads inside a broken body are still found, saw ${rules}`);
});

test('protect mode answers decoy routes even when the body is malformed', async () => {
  const mw = kagami({ secret: SECRET, mode: 'protect', sinks: [], logger: quiet });
  const app = await listen(buildApp(mw));
  try {
    const route = mw.kagami.manifest().decoys.routes[0];
    const res = await fetchRaw(app.base, route, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"a":' });
    assert.equal(res.status, 401);
    assert.match(res.body, /unauthorized/);
  } finally {
    await app.close();
  }
});

// Regression tests from the second live benchmark round (2026-11-15).

test('decoy routes answer 401 with the body the app uses for its own 401s', async () => {
  const mw = kagami({ secret: SECRET, mode: 'protect', sinks: [], logger: quiet });
  const app = express();
  app.use(mw);
  app.get('/api/account', (_req, res) => res.status(401).json({ message: 'Login required', status: 401 }));
  const server = await listen(app);
  try {
    const route = mw.kagami.manifest().decoys.routes[0];
    const before = await fetchRaw(server.base, route);
    assert.equal(before.body, '{"error":"unauthorized"}');
    assert.equal((await fetchRaw(server.base, '/api/account')).status, 401);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(mw.kagami.wants401Body, false);
    const after = await fetchRaw(server.base, route);
    assert.equal(after.status, 401);
    assert.equal(after.body, '{"message":"Login required","status":401}');
    assert.equal(after.headers['content-type'], 'application/json; charset=utf-8');
  } finally {
    await server.close();
  }
});

test('form decoys add a hidden field to POST forms and catch an edited value', async () => {
  const mem = memorySink();
  const mw = kagami({ secret: SECRET, mode: 'protect', decoys: { forms: true }, sinks: [mem], logger: quiet });
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(mw);
  const page = '<!doctype html><html><body><form method="post" action="/signup"><input name="email"></form><form action="/search"></form></body></html>';
  app.get('/signup', (_req, res) => res.type('html').send(page));
  app.post('/signup', (_req, res) => res.status(201).send('ok'));
  const server = await listen(app);
  try {
    const html = (await fetchRaw(server.base, '/signup')).body;
    const [, name, value] = /<input type="hidden" name="([^"]+)" value="([^"]+)">/.exec(html);
    assert.equal(html.match(/type="hidden"/g).length, 1, 'only the POST form gets the field');
    const post = (body, ua) =>
      fetchRaw(server.base, '/signup', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': ua }, body });
    await post(`${name}=${value}&email=a%40b.c`, 'browser');
    await post(`${name}=admin&email=a%40b.c`, 'agent');
    await mw.kagami.flush();
    const hits = mem.events.filter((e) => e.rule === 'decoy.param');
    assert.deepEqual(hits.map((e) => e.source.user_agent), ['agent'], 'only the edited value is a detection');
  } finally {
    await server.close();
  }
});

// Containment. After a tripwire the machine never reaches the app again.

test('a contained machine never reaches the application handlers', async () => {
  const hits = { home: 0, login: 0, search: 0 };
  const mw = kagami({ secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, sinks: [], logger: quiet });
  const app = express();
  app.set('trust proxy', 'loopback');
  app.use(express.urlencoded({ extended: false }));
  app.use(mw);
  app.get('/', (_req, res) => {
    hits.home++;
    res.type('html').send(HTML);
  });
  app.get('/search', (req, res) => {
    hits.search++;
    res.type('html').send(`<!doctype html><html><body>Results for ${String(req.query.q ?? '').replace(/[<>&]/g, '')}</body></html>`);
  });
  app.post('/login', (_req, res) => {
    hits.login++;
    res.status(401).type('html').send('<!doctype html><html><body>Invalid</body></html>');
  });
  app.get('/api/products', (_req, res) => res.json({ products: [] }));
  app.use((_req, res) => res.status(404).type('html').send('<!doctype html><html><body>Not found</body></html>'));
  const server = await listen(app);
  const as = (ip) => (path, init = {}) => fetchRaw(server.base, path, { ...init, headers: { 'x-forwarded-for': ip, ...(init.headers ?? {}) } });
  try {
    const visitor = as('198.51.100.40');
    const home = await visitor('/');
    await visitor('/search');
    await visitor('/nothing-here');
    await new Promise((r) => setTimeout(r, 20));

    const attacker = as('203.0.113.77');
    const field = mw.kagami.manifest().decoys.json_field;
    const trip = await attacker(`/api/products?${field}=admin`);
    assert.equal(trip.status, 404, 'the tripping request is answered by the shadow');
    const before = { ...hits };

    const shadowHome = await attacker('/');
    assert.equal(shadowHome.status, 200);
    assert.equal(shadowHome.body.replace(/<!--[\s\S]*?-->\n?/g, ''), home.body.replace(/<!--[\s\S]*?-->\n?/g, ''), 'same page as the public one');
    assert.equal((await attacker('/search?q=%27%20OR%201%3D1--')).status, 200, 'replayed from the bare path');
    assert.equal((await attacker('/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'email=a&password=b' })).status, 404);
    assert.equal((await attacker('/admin')).body, '<!doctype html><html><body>Not found</body></html>', "the app's own 404");
    assert.deepEqual(hits, before, 'no handler ran for the contained machine');

    await visitor('/');
    assert.equal(hits.home, before.home + 1, 'other visitors are unaffected');
    assert.equal(mw.kagami.contained().length, 1);
  } finally {
    await server.close();
    await mw.kagami.close();
  }
});

test('block containment answers 403 and observe mode never contains', async () => {
  for (const [mode, expected] of [['protect', 403], ['observe', 200]]) {
    const mw = kagami({ secret: SECRET, mode, decoys: { json: true }, containment: { action: 'block' }, sinks: [], logger: quiet });
    const server = await listen(buildApp(mw));
    try {
      const field = mw.kagami.manifest().decoys.json_field;
      await fetchRaw(server.base, `/api/me?${field}=admin`);
      const res = await fetchRaw(server.base, '/');
      assert.equal(res.status, expected, mode);
    } finally {
      await server.close();
      await mw.kagami.close();
    }
  }
});

test('clientAddress lets the core resolve the client address and ignores forged headers', async () => {
  const cases = [
    // Trusted local proxy: the address it forwards is used.
    [{ trustedProxies: ['127.0.0.1', '::1'] }, { 'x-forwarded-for': '198.51.100.9' }, '198.51.100.9'],
    // Cloudflare enabled, but the connection is not from Cloudflare: the forged header is ignored.
    [{ cloudflare: true }, { 'cf-connecting-ip': '8.8.8.8', 'x-forwarded-for': '8.8.4.4' }, '127.0.0.1'],
  ];
  for (const [clientAddress, headers, expected] of cases) {
    const mw = kagami({ secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, clientAddress, sinks: [], logger: quiet });
    const server = await listen(buildApp(mw));
    try {
      const field = mw.kagami.manifest().decoys.json_field;
      await fetchRaw(server.base, `/api/me?${field}=admin`, { headers });
      assert.deepEqual(mw.kagami.contained().map((m) => m.target), [expected], JSON.stringify(clientAddress));
    } finally {
      await server.close();
      await mw.kagami.close();
    }
  }
});

test('on Render, Kagami uses the Render setting by itself, and KAGAMI_PROXY names a preset', async () => {
  // Headers as recorded on a live Render service. Render's edge is Cloudflare
  // and its proxy reaches the app over loopback.
  const headers = { 'x-forwarded-for': '198.51.100.23, 162.159.114.84, 10.24.84.0', 'cf-connecting-ip': '198.51.100.23' };
  const cases = [
    [{ env: { RENDER: 'true' } }, '198.51.100.23'],
    [{ env: { KAGAMI_PROXY: 'render' } }, '198.51.100.23'],
    [{ env: {}, clientAddress: 'render' }, '198.51.100.23'],
    [{ env: { RENDER: 'true', KAGAMI_PROXY: 'none' } }, '127.0.0.1'],
    [{ env: {} }, '127.0.0.1'],
  ];
  for (const [options, expected] of cases) {
    const mw = kagami({ secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, sinks: [], logger: quiet, ...options });
    const server = await listen(buildApp(mw));
    try {
      const field = mw.kagami.manifest().decoys.json_field;
      await fetchRaw(server.base, `/api/me?${field}=admin`, { headers });
      assert.deepEqual(mw.kagami.contained().map((m) => m.target), [expected], JSON.stringify(options));
    } finally {
      await server.close();
      await mw.kagami.close();
    }
  }
});

// The optional shared store. Two app instances share one store.
test('with a store, a machine contained by one instance is blocked by another', async () => {
  const map = new Map();
  const kv = {
    get: async (k) => map.get(k) ?? null,
    put: async (k, v) => void map.set(k, v),
    delete: async (k) => void map.delete(k),
  };
  const opts = { secret: SECRET, mode: 'protect', decoys: { json: true }, containment: { action: 'block' }, store: kv, sinks: [], logger: quiet };
  const start = (mw) => {
    const app = express();
    app.set('trust proxy', 'loopback');
    app.use(mw);
    app.get('/', (_req, res) => res.type('html').send(HTML));
    app.get('/api/products', (_req, res) => res.json({ products: [] }));
    return listen(app);
  };
  const firstMw = kagami(opts);
  const first = await start(firstMw);
  const second = await start(kagami(opts));
  const as = (ip) => ({ headers: { 'x-forwarded-for': ip } });
  try {
    const field = firstMw.kagami.manifest().decoys.json_field;
    await fetchRaw(first.base, `/api/products?${field}=admin`, as('203.0.113.60'));
    await firstMw.kagami.flush();
    assert.equal(map.size, 1);
    assert.equal((await fetchRaw(second.base, '/', as('203.0.113.60'))).status, 403);
    assert.equal((await fetchRaw(second.base, '/', as('198.51.100.60'))).status, 200);
  } finally {
    await first.close();
    await second.close();
  }
});

test('onDetect receives each detection with the subject, next to the other sinks', async () => {
  const seen = [];
  const sink = memorySink();
  const app = express();
  app.use(express.json());
  // A stand-in for the app's own auth middleware.
  app.use((req, _res, next) => {
    const id = req.get('x-account');
    if (id) req.user = { id };
    next();
  });
  const mw = kagami({
    secret: SECRET,
    mode: 'protect',
    sinks: [sink],
    logger: quiet,
    subject: (req) => req.user?.id,
    onDetect: (event) => {
      seen.push(event);
    },
  });
  app.use(mw);
  app.get('/', (_req, res) => res.type('html').send(HTML));
  const srv = await listen(app);
  try {
    assert.equal((await fetchRaw(srv.base, '/')).status, 200);
    await fetchRaw(srv.base, '/.env', { headers: { 'x-account': 'acct_9', 'user-agent': 'python-requests/2.32' } });
    await fetchRaw(srv.base, '/.git/config');
    await mw.kagami.flush();
  } finally {
    await srv.close();
  }
  assert.ok(seen.length > 0, 'detections reach onDetect');
  assert.ok(seen.every((e) => e.kind !== 'system'));
  assert.ok(seen.every((e) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(e.severity) >= 1));
  const bait = seen.filter((e) => e.request?.path === '/.env');
  assert.ok(bait.length > 0);
  assert.ok(bait.every((e) => e.subject === 'acct_9'));
  assert.ok(seen.filter((e) => e.request?.path === '/.git/config').every((e) => e.subject === undefined));
  assert.ok(sink.events.length >= seen.length, 'the other sinks still receive every event');
});

test('a failing onDetect or subject function never affects requests', async () => {
  const warnings = [];
  const mw = kagami({
    secret: SECRET,
    mode: 'protect',
    sinks: [],
    logger: { warn: (m) => warnings.push(m) },
    subject: () => {
      throw new Error('auth exploded');
    },
    onDetect: () => {
      throw new Error('handler exploded');
    },
  });
  const srv = await listen(buildApp(mw));
  try {
    assert.equal((await fetchRaw(srv.base, '/')).status, 200);
    const bait = await fetchRaw(srv.base, '/.env', { headers: { 'user-agent': 'python-requests/2.32' } });
    assert.equal(bait.status, 200);
    await mw.kagami.flush();
  } finally {
    await srv.close();
  }
  assert.ok(mw.kagami.stats().sinkErrors >= 1);
  assert.ok(warnings.some((m) => m.includes('onDetect')));
});
