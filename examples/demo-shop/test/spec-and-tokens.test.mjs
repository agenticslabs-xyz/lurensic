// Personas for API-first agents, run against the demo shop with the decoy API
// description turned on. A spec-driven agent looks for the API description
// first and tests every operation it lists. A token forger sends a JWT with no
// signature. An honest customer must still raise nothing.
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { after, before, test } from 'node:test';
import { memorySink } from '@agenticslabs/kagami-express';
import { createApp } from '../app.js';

const BROWSER = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
const AGENT_UA = 'python-httpx/0.27';
const SPEC_PATHS = ['/openapi.json', '/swagger.json', '/api/openapi.json', '/api/swagger.json', '/v3/api-docs', '/api-docs.json'];

let base;
let server;
let app;
const sink = memorySink();

before(async () => {
  app = createApp({
    secret: 'demo-shop-spec-secret-0123456789abcdef-01234',
    sinks: [sink],
    logger: { warn() {} },
    decoys: { json: true, forms: true, spec: true, reservedNames: ['name', 'email', 'role'] },
  });
  server = await new Promise((r) => {
    const s = app.listen(0, '127.0.0.1', () => r(s));
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await app.kagami.close();
  await new Promise((r) => server.close(r));
});

const get = (path, ip, ua, headers = {}) =>
  fetch(base + path, { headers: { 'user-agent': ua, 'x-forwarded-for': ip, ...headers }, redirect: 'manual' });

async function eventsFor(ip) {
  await app.kagami.flush();
  return sink.events.filter((e) => e.source?.ip === ip);
}

test('an honest customer raises nothing with the decoy description on', async () => {
  const ip = '198.51.100.60';
  for (const path of ['/', '/products', '/products/1', '/search?q=boots', '/about', '/login', '/api/products']) {
    assert.ok((await get(path, ip, BROWSER)).status < 500);
  }
  assert.deepEqual(await eventsFor(ip), []);
});

test('persona 6, the spec-driven agent, reads the description and is caught by its own key', async () => {
  const ip = '203.0.113.60';
  let spec;
  for (const path of SPEC_PATHS) {
    const res = await get(path, ip, AGENT_UA);
    if (res.status === 200) {
      spec = await res.json();
      break;
    }
  }
  assert.ok(spec, 'one common spec path serves a description');
  assert.equal(spec.openapi, '3.0.3');
  const ops = Object.keys(spec.paths);
  assert.ok(ops.length >= 1);

  // Every operation without the key answers like the app's own 401.
  for (const op of ops) assert.equal((await get(op, ip, AGENT_UA)).status, 401);

  // The sandbox key from the description unlocks fake records.
  const key = /pk_sandbox_[A-Za-z0-9]+/.exec(spec.info.description)[0];
  const res = await get(ops[0], ip, AGENT_UA, { authorization: `Bearer ${key}` });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).data.length, 25);

  const rules = (await eventsFor(ip)).map((e) => e.rule);
  for (const r of ['decoy.spec', 'decoy.route', 'honeytoken.used', 'session.flagged']) assert.ok(rules.includes(r), `missing ${r}`);
  const token = sink.events.find((e) => e.rule === 'honeytoken.used' && e.source?.ip === ip);
  assert.equal(token.evidence.token_kind, 'spec_sandbox_key');
});

test('persona 7, the token forger, sends an unsigned JWT and is flagged at once', async () => {
  const ip = '203.0.113.61';
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: '1', role: 'admin' })).toString('base64url');
  await get('/api/me', ip, AGENT_UA, { authorization: `Bearer ${header}.${payload}.` });
  const events = await eventsFor(ip);
  const forged = events.find((e) => e.rule === 'tamper.unsigned_jwt');
  assert.ok(forged);
  assert.equal(forged.severity, 'critical');
  assert.equal(forged.evidence.alg, 'none');
  assert.ok(!JSON.stringify(events).includes(payload), 'the token itself is never logged');
  assert.ok(events.some((e) => e.rule === 'session.flagged'));
});

test('persona 8, the secret reuser, forges sessions with the fake .env secret and is caught each way', async () => {
  const env = await (await get('/.env', '203.0.113.70', AGENT_UA)).text();
  const secret = env.split('\n').find((l) => l.startsWith('SESSION_SECRET=')).slice('SESSION_SECRET='.length);
  const sign = (alg, data, enc) => createHmac(alg, secret).update(data).digest(enc).replace(/=+$/, '');

  // express-session, as connect.sid=s:<id>.<sig>
  const sid = 'forged-session-id';
  const express = `connect.sid=${encodeURIComponent(`s:${sid}.${sign('sha256', sid, 'base64')}`)}`;
  // cookie-session with keygrip's default SHA-1
  const value = Buffer.from(JSON.stringify({ user: { id: 1, role: 'admin' } })).toString('base64');
  const cookieSession = `session=${value}; session.sig=${sign('sha1', `session=${value}`, 'base64url')}`;
  // An HS256 JWT
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({ sub: '1', role: 'admin' })).toString('base64url');
  const jwt = `${h}.${p}.${sign('sha256', `${h}.${p}`, 'base64url')}`;

  const cases = [
    ['203.0.113.71', { cookie: express }, 'express_session'],
    ['203.0.113.72', { cookie: cookieSession }, 'cookie_session'],
    ['203.0.113.73', { authorization: `Bearer ${jwt}` }, 'jwt'],
  ];
  for (const [ip, headers, format] of cases) {
    await get('/api/me', ip, AGENT_UA, headers);
    const forged = (await eventsFor(ip)).find((e) => e.rule === 'tamper.decoy_secret');
    assert.ok(forged, `${format} was not detected`);
    assert.equal(forged.evidence.format, format);
    assert.equal(forged.severity, 'critical');
    assert.ok(!JSON.stringify(forged).includes(secret), 'the secret is never logged');
  }

  // The same formats signed with a different secret are ordinary traffic.
  const other = createHmac('sha256', 'the-apps-real-secret').update(sid).digest('base64').replace(/=+$/, '');
  await get('/api/me', '198.51.100.74', BROWSER, { cookie: `connect.sid=${encodeURIComponent(`s:${sid}.${other}`)}` });
  assert.deepEqual(await eventsFor('198.51.100.74'), []);
});
