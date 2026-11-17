import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { escapeSlack, formatSlack, Kagami, memorySink, verifyChain, webhookSink } from '../dist/index.js';

const SECRET = 'node-test-secret-0123456789abcdef-0123456789';
const quiet = { warn() {} };

function request(overrides = {}) {
  return {
    ip: '203.0.113.9',
    method: 'GET',
    host: 'shop.example.com',
    path: '/',
    query: '',
    headers: [['user-agent', 'Mozilla/5.0']],
    ...overrides,
  };
}

test('bad configuration disables Kagami instead of throwing', () => {
  const warnings = [];
  const k = new Kagami({ secret: 'too-short', logger: { warn: (m) => warnings.push(m) }, sinks: [] });
  assert.equal(k.isEnabled, false);
  const v = k.inspect(request({ path: '/.env' }));
  assert.deepEqual(v.action, { type: 'pass' });
  assert.match(warnings.join('\n'), /at least 32 characters/);
});

test('KAGAMI_DISABLED=1 switches Kagami off', () => {
  process.env.KAGAMI_DISABLED = '1';
  try {
    const k = new Kagami({ secret: SECRET, mode: 'protect', sinks: [], logger: quiet });
    assert.equal(k.isEnabled, false);
    assert.deepEqual(k.inspect(request({ path: '/.env' })).action, { type: 'pass' });
  } finally {
    delete process.env.KAGAMI_DISABLED;
  }
});

test('production without a secret disables Kagami with a clear warning', () => {
  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    const warnings = [];
    const k = new Kagami({ sinks: [], logger: { warn: (m) => warnings.push(m) } });
    assert.equal(k.isEnabled, false);
    assert.match(warnings[0], /KAGAMI_SECRET is not set/);
  } finally {
    process.env.NODE_ENV = prev;
  }
});

test('internal faults never escape to the caller', () => {
  const k = new Kagami({ secret: SECRET, sinks: [], logger: quiet });
  // Simulate a corrupted core.
  k['core'].call = () => {
    throw new Error('boom');
  };
  assert.deepEqual(k.inspect(request()).action, { type: 'pass' });
  assert.equal(k.decorateHtml({ decorateHtml: true, session: 'ab' }, '<html></html>'), '<html></html>');
  assert.equal(k.stats().faults, 2);
});

test('events flow to sinks and form a verifiable chain', async () => {
  const mem = memorySink();
  const k = new Kagami({ secret: SECRET, sinks: [mem], logger: quiet });
  k.inspect(request({ path: '/.env', headers: [['user-agent', 'nuclei']] }));
  k.inspect(request({ query: 'q=1%27%20OR%20%271%27%3D%271', headers: [['user-agent', 'nuclei']] }));
  await k.flush();
  const rules = mem.events.map((e) => e.rule);
  assert.deepEqual(rules, ['system.started', 'bait.path', 'client.scanner', 'session.flagged', 'payload.sqli']);
  assert.deepEqual(await verifyChain(mem.lines), { ok: true, events: 5, instances: 1 });

  const edited = [...mem.lines];
  edited[1] = edited[1].replace('"severity":"medium"', '"severity":"low"');
  assert.equal((await verifyChain(edited)).ok, false);
  const removed = mem.lines.filter((_, i) => i !== 2);
  assert.deepEqual(await verifyChain(removed), { ok: false, line: 3, reason: 'chain broken (event missing, reordered or inserted)' });
});

test('sinks filter by severity', async () => {
  const highOnly = memorySink('high');
  const k = new Kagami({ secret: SECRET, sinks: [highOnly], logger: quiet });
  k.inspect(request({ path: '/.env' })); // medium
  await k.flush();
  assert.equal(highOnly.events.length, 0);
});

test('slack formatting neutralises attacker-controlled text', () => {
  const nasty = '<!channel> `rm -rf` <https://evil.example|click> ‮gnp.exe\n@here';
  const out = escapeSlack(nasty);
  assert.ok(!out.includes('<') && !out.includes('>') && !out.includes('`') && !out.includes('\n') && !out.includes('‮'));
  const msg = formatSlack({
    severity: 'critical',
    title: 'Honeytoken used',
    rule: 'honeytoken.used',
    session: { id: 'abc', score: 100, state: 'flagged' },
    request: { method: 'GET', path: nasty, host: 'x', query: '' },
    deployment: 'd',
    id: 'e',
  });
  assert.ok(!msg.includes('<!channel>'));
});

test('webhook sink enforces https, signs requests and does not follow redirects', async () => {
  assert.throws(() => webhookSink({ url: 'http://example.com/hook' }), /must use https/);

  const received = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      received.push({ headers: req.headers, body });
      res.writeHead(204).end();
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/hook`;
  try {
    const k = new Kagami({ secret: SECRET, sinks: [webhookSink({ url, secret: 'whsec', minSeverity: 'info' })], logger: quiet });
    k.inspect(request({ path: '/.env' }));
    await k.flush();
    assert.equal(received.length, 1);
    const { headers, body } = received[0];
    const [, t, sig] = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(headers['kagami-signature']);
    assert.equal(sig, createHmac('sha256', 'whsec').update(`${t}.${body}`).digest('hex'));
    const parsed = JSON.parse(body);
    assert.deepEqual(parsed.events.map((e) => e.rule), ['system.started', 'bait.path']);
  } finally {
    server.close();
  }
});

test('seal and verify', async () => {
  const mem = memorySink();
  const k = new Kagami({ secret: SECRET, sinks: [mem], logger: quiet });
  const sealed = k.seal(1043);
  assert.equal(k.verify(request(), sealed, 'order'), '1043');
  assert.equal(k.verify(request(), sealed.replace('1043', '1044'), 'order'), null);
  await k.flush();
  assert.ok(mem.events.some((e) => e.rule === 'tamper.sealed_value' && e.severity === 'critical'));
});

test('a non-trivial request costs well under a millisecond', () => {
  const k = new Kagami({ secret: SECRET, sinks: [], logger: quiet });
  const req = request({
    method: 'POST',
    path: '/api/cart',
    query: 'ref=homepage&utm_source=newsletter',
    headers: [
      ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0'],
      ['accept', 'application/json'],
      ['cookie', 'sid=abc123; theme=dark'],
      ['referer', 'https://shop.example.com/products/42'],
    ],
    body: JSON.stringify({ items: Array.from({ length: 20 }, (_, i) => ({ sku: `SKU-${i}`, qty: 1 })) }),
    contentType: 'application/json',
  });
  for (let i = 0; i < 200; i++) k.inspect(req);
  const n = 2000;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < n; i++) k.inspect(req);
  const perReqUs = Number(process.hrtime.bigint() - t0) / n / 1000;
  console.log(`  inspect(): ${perReqUs.toFixed(1)} µs per request`);
  assert.ok(perReqUs < 1000, `too slow at ${perReqUs} µs per request`);
});

test('KAGAMI_DECOYS turns on opt-in decoys, and settings in code win', () => {
  const secret = 'env-decoys-secret-0123456789abcdef-0123456';
  const on = new Kagami({ mode: 'protect', sinks: [], logger: { warn() {} }, env: { KAGAMI_SECRET: secret, KAGAMI_DECOYS: 'json, spec' } });
  assert.equal(typeof on.manifest().decoys.spec_path, 'string');
  const off = new Kagami({ mode: 'protect', sinks: [], logger: { warn() {} }, decoys: { spec: false }, env: { KAGAMI_SECRET: secret, KAGAMI_DECOYS: 'all' } });
  assert.equal(off.manifest().decoys.spec_path, null);
  const none = new Kagami({ mode: 'protect', sinks: [], logger: { warn() {} }, env: { KAGAMI_SECRET: secret } });
  assert.equal(none.manifest().decoys.spec_path, null);
});

test('safeToActOnSubject only allows first-party requests with an account', async () => {
  const { safeToActOnSubject, wasLured } = await import('../dist/index.js');
  const base = { subject: 'acct_1', request: { method: 'GET', host: 'h', path: '/', query: '' }, evidence: {} };
  assert.equal(safeToActOnSubject(base), true);
  assert.equal(safeToActOnSubject({ ...base, subject: undefined }), false);
  assert.equal(safeToActOnSubject({ ...base, request: { ...base.request, site: 'same-origin' } }), true);
  assert.equal(safeToActOnSubject({ ...base, request: { ...base.request, site: 'cross-site' } }), false);
  assert.equal(safeToActOnSubject({ ...base, request: { ...base.request, site: 'same-site' } }), false);
  // Following a link on the same site is ordinary browsing, by people and by agents driving a browser.
  assert.equal(safeToActOnSubject({ ...base, request: { ...base.request, site: 'same-origin', navigate: true } }), true);
  assert.equal(wasLured({ ...base, request: { ...base.request, site: 'cross-site', navigate: true } }), true);
  assert.equal(wasLured(base), false);
  assert.equal(safeToActOnSubject({ ...base, evidence: { location: 'cookie' } }), false);
});

test('after an engine trap the rebuilt engine keeps every containment and starts a fresh chain', async () => {
  const mem = memorySink();
  const k = new Kagami({ secret: SECRET, mode: 'protect', containment: true, sinks: [mem], logger: quiet });
  const route = k.manifest().decoys.routes[0];
  const attacker = { ip: '203.0.113.90', headers: [['user-agent', 'curl/7.88.1']] };
  assert.equal(k.inspect(request({ ...attacker, path: route })).contained, true);

  // A trap inside the engine, as an attacker might trigger with hostile input.
  k['core'].call = () => {
    throw new WebAssembly.RuntimeError('unreachable');
  };
  assert.deepEqual(k.inspect(request(attacker)).action, { type: 'pass' }, 'the request fails open');
  assert.equal(k['core'], null);

  // The next request rebuilds the engine, and the machine is still contained.
  const v = k.inspect(request({ ...attacker, path: '/' }));
  assert.equal(v.contained, true);
  assert.equal(k.contained().length, 1);
  assert.equal(k.inspect(request({ ip: '198.51.100.90', path: '/' })).contained, false);

  await k.flush();
  const started = mem.events.filter((e) => e.rule === 'system.started');
  assert.equal(started.length, 2);
  assert.notEqual(started[0].instance, started[1].instance);
  assert.equal(new Set(mem.events.map((e) => e.id)).size, mem.events.length, 'event ids never repeat');
  assert.equal((await verifyChain(mem.lines)).ok, true);
});
