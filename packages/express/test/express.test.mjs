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
    assert.match(env.body, /^AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}$/m);
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
