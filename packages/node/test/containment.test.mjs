// Containment and enforcers in the Node layer. Enforcers are provider
// neutral. These tests cover the pipeline, the public-address rule, release,
// failure isolation, and the built-in blocklist file and webhook.
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { blocklistFile, callbackEnforcer, formatBlocklist, Lurensic, webhookEnforcer } from '../dist/index.js';

const SECRET = 'containment-test-secret-0123456789abcdef-01';
const quiet = { warn() {} };
const dir = mkdtempSync(join(tmpdir(), 'lurensic-contain-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const request = (ip, query = '', path = '/api/products') => ({
  ip,
  method: 'GET',
  host: 'shop.example.com',
  path,
  query,
  headers: [['user-agent', 'curl/8.9']],
});

function guard(extra = {}) {
  const k = new Lurensic({ secret: SECRET, mode: 'protect', decoys: { json: true }, containment: true, sinks: [], logger: quiet, ...extra });
  const field = k.manifest().decoys.json_field;
  return { k, trip: (ip) => k.inspect(request(ip, `${field}=admin`)) };
}

test('a tripwire contains the machine and hands it to enforcers once', async () => {
  const got = [];
  const { k, trip } = guard({ enforcers: [callbackEnforcer((m) => got.push(...m))] });
  const v = trip('8.8.4.4');
  assert.equal(v.contained, true);
  assert.equal(v.action.type, 'respond');
  assert.equal(v.containment.length, 1);
  assert.equal(v.containment[0].target, '8.8.4.4');
  assert.equal(v.containment[0].reason, 'decoy.param');
  assert.ok(v.containment[0].until > Date.now());
  const again = k.inspect(request('8.8.4.4', '', '/'));
  assert.equal(again.contained, true);
  assert.equal(again.containment.length, 0, 'announced only once');
  await k.flush();
  assert.deepEqual(got.map((m) => m.target), ['8.8.4.4']);
  assert.equal(k.stats().enforced, 1);
  await k.close();
});

test('private addresses never reach edge enforcers unless asked for', async () => {
  const edge = [];
  const lan = [];
  const { k, trip } = guard({
    enforcers: [callbackEnforcer((m) => edge.push(...m)), callbackEnforcer((m) => lan.push(...m), { includePrivate: true })],
  });
  trip('10.1.2.3');
  trip('::ffff:127.0.0.1');
  await k.flush();
  assert.deepEqual(edge, [], 'nothing private is pushed out');
  assert.deepEqual(lan.map((m) => m.target).sort(), ['10.1.2.3', '127.0.0.1']);
  assert.equal(k.inspect(request('10.1.2.3', '', '/')).contained, true, 'Lurensic itself still contains it');
  await k.close();
});

test('release ends containment and tells the enforcers', async () => {
  const released = [];
  const { k, trip } = guard({ enforcers: [callbackEnforcer(() => {}, { release: (m) => released.push(...m) })] });
  trip('8.8.8.8');
  assert.equal(k.contained().length, 1);
  assert.equal(k.release('8.8.8.8').length, 1);
  assert.equal(k.contained().length, 0);
  assert.equal(k.inspect(request('8.8.8.8', '', '/')).contained, false);
  await k.flush();
  assert.deepEqual(released.map((m) => m.target), ['8.8.8.8']);
  await k.close();
});

test('a failing enforcer never affects requests or other enforcers', async () => {
  const ok = [];
  const { k, trip } = guard({
    enforcers: [
      { name: 'broken', contain: async () => { throw new Error('down'); } },
      callbackEnforcer((m) => ok.push(...m)),
    ],
  });
  const v = trip('1.1.1.1');
  assert.equal(v.contained, true);
  await k.flush();
  assert.equal(ok.length, 1);
  assert.equal(k.stats().enforcerErrors, 1);
  await k.close();
});

test('enforcers without containment produce a clear warning', async () => {
  const warnings = [];
  const k = new Lurensic({ secret: SECRET, mode: 'protect', sinks: [], enforcers: [callbackEnforcer(() => {})], logger: { warn: (m) => warnings.push(m) } });
  assert.match(warnings.join('\n'), /containment is off/);
  await k.close();
});

test('observe mode is a dry run that enforces nothing', async () => {
  const got = [];
  const { k, trip } = guard({ mode: 'observe', enforcers: [callbackEnforcer((m) => got.push(...m))] });
  const v = trip('8.8.4.4');
  assert.equal(v.action.type, 'pass');
  assert.equal(v.containment.length, 0);
  await k.flush();
  assert.equal(got.length, 0);
  await k.close();
});

test('formatBlocklist renders plain, nginx and json and drops expired entries', () => {
  const now = Date.now();
  const m = [
    { source: 'a', target: '198.51.100.4', public: true, reason: 'decoy.param', since: now, until: now + 1000 },
    { source: 'b', target: '2001:db8:1::/64', public: true, reason: 'honeytoken.used', since: now, until: now + 1000 },
    { source: 'c', target: '192.0.2.1', public: true, reason: 'decoy.route', since: now - 2000, until: now - 1000 },
  ];
  assert.equal(formatBlocklist(m, 'plain', now), '198.51.100.4\n2001:db8:1::/64\n');
  assert.equal(formatBlocklist(m, 'nginx', now), 'deny 198.51.100.4;\ndeny 2001:db8:1::/64;\n');
  const json = JSON.parse(formatBlocklist(m, 'json', now));
  assert.equal(json.entries.length, 2);
  assert.equal(json.entries[0].reason, 'decoy.param');
  assert.equal(formatBlocklist([], 'plain', now), '');
});

test('blocklistFile writes atomically and survives a restart', async () => {
  const path = join(dir, 'blocked.conf');
  const changes = [];
  const file = blocklistFile({ path, format: 'nginx', onChange: (p) => changes.push(p) });
  const { k, trip } = guard({ enforcers: [file] });
  trip('8.8.8.8');
  trip('2a01:4f8:1:2::10');
  await k.flush();
  await k.close();
  assert.equal(readFileSync(path, 'utf8'), 'deny 2a01:4f8:1:2::/64;\ndeny 8.8.8.8;\n');
  assert.ok(changes.length >= 1);

  // A new process loads the state, so the list does not empty on restart.
  const reopened = blocklistFile({ path, format: 'plain' });
  reopened.start();
  await reopened.contain([]);
  assert.equal(readFileSync(path, 'utf8'), '2a01:4f8:1:2::/64\n8.8.8.8\n');
  await reopened.release([{ source: 'x', target: '8.8.8.8', public: true, reason: 'decoy.param', since: 0, until: 0 }]);
  assert.equal(readFileSync(path, 'utf8'), '2a01:4f8:1:2::/64\n');
  await reopened.close();
});

// The firewall guide syncs a remote list from onChange with entries(). A
// remote call that fails once must not stop later syncs.
test('blocklistFile keeps working after a failed onChange, and entries() holds only live machines', async () => {
  const synced = [];
  let failNext = true;
  const file = blocklistFile({
    path: join(dir, 'synced.json'),
    format: 'json',
    onChange: () => {
      if (failNext) {
        failNext = false;
        throw new Error('remote list unavailable');
      }
      synced.push(file.entries().map((m) => m.target).sort());
    },
  });
  const now = Date.now();
  const m = (target, until) => ({ source: target, target, public: true, reason: 'decoy.param', since: now, until });
  await assert.rejects(file.contain([m('8.8.8.8', now + 60_000)]), /remote list unavailable/);
  await file.contain([m('8.8.4.4', now + 60_000), m('9.9.9.9', now - 1)]);
  assert.deepEqual(synced, [['8.8.4.4', '8.8.8.8']], 'the second sync carries both live machines and drops the expired one');
  await file.close();
});

test('webhookEnforcer signs its payload and reports releases', async () => {
  const received = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      received.push({ body, sig: req.headers['lurensic-signature'] });
      res.writeHead(204).end();
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const url = `http://127.0.0.1:${server.address().port}/hook`;
    const { k, trip } = guard({ enforcers: [webhookEnforcer({ url, secret: 'hook-secret' })] });
    trip('9.9.9.9');
    await k.flush();
    k.release('9.9.9.9');
    await k.flush();
    await k.close();
    assert.equal(received.length, 2);
    const [first, second] = received;
    assert.equal(JSON.parse(first.body).type, 'containment.started');
    assert.equal(JSON.parse(first.body).machines[0].target, '9.9.9.9');
    assert.equal(JSON.parse(second.body).type, 'containment.released');
    const [, t, v1] = /^t=(\d+),v1=([a-f0-9]{64})$/.exec(first.sig);
    assert.equal(v1, createHmac('sha256', 'hook-secret').update(`${t}.${first.body}`).digest('hex'));
    assert.throws(() => webhookEnforcer({ url: 'http://example.com/hook' }), /https/);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

