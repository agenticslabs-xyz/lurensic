// Tests for the Cloudflare enforcer against an in-memory model of the
// Cloudflare Lists API (create list, add items, delete items, list items with
// search and cursor pagination, and asynchronous bulk operations).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  cloudflareEnforcer,
  cloudflareSetup,
  isKagamiRule,
  itemComment,
  itemExpiry,
  Kagami,
  ListsClient,
  SETUP_PERMISSION_KEYS,
  tokenLink,
  zoneCandidates,
} from '../dist/index.js';

const ACCOUNT = 'a'.repeat(32);
const LIST = 'b'.repeat(32);
const ZONE = 'c'.repeat(32);
const RULESET = 'd'.repeat(32);
const TOKEN = 'test-token-never-logged';
const fast = () => Promise.resolve();

/** A fake Cloudflare API. Bulk operations stay pending for one poll. */
function fakeCloudflare({
  pageSize = 2,
  failFirst429 = false,
  accounts = [{ id: ACCOUNT, name: 'Main' }],
  zones = [{ id: ZONE, name: 'example.com', status: 'active', account: { id: ACCOUNT, name: 'Main' } }],
  entrypoint = undefined,
  denyZones = false,
} = {}) {
  const items = [];
  const lists = [];
  const ops = new Map();
  const calls = [];
  // The zone's custom rules entry point ruleset, or undefined while the zone has none.
  const waf = { entrypoint: entrypoint && { ...entrypoint, rules: [...(entrypoint.rules ?? [])] } };
  let seq = 0;
  let throttled = !failFirst429;
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  const ok = (result, extra = {}) => json(200, { success: true, errors: [], result, ...extra });
  const op = (apply) => {
    const id = `op${++seq}`;
    ops.set(id, { polls: 0, apply });
    return ok({ operation_id: id });
  };
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, search: u.search, body, auth: init.headers?.authorization });
    assert.equal(init.headers?.authorization, `Bearer ${TOKEN}`);
    if (!throttled) {
      throttled = true;
      return json(429, { success: false, errors: [{ code: 10000, message: 'rate limited' }] }, { 'retry-after': '1' });
    }
    const p = u.pathname.replace('/client/v4', '');
    const itemsPath = `/accounts/${ACCOUNT}/rules/lists/${LIST}/items`;
    const bulk = /^\/accounts\/[a]{32}\/rules\/lists\/bulk_operations\/(\w+)$/.exec(p);
    if (bulk) {
      const o = ops.get(bulk[1]);
      if (o.polls++ === 0) return ok({ id: bulk[1], status: 'pending' });
      if (!o.done) {
        o.done = true;
        o.apply();
      }
      return ok({ id: bulk[1], status: 'completed', completed: new Date().toISOString() });
    }
    if (p === itemsPath && method === 'POST') {
      return op(() => {
        for (const it of body) items.push({ id: `i${++seq}`.padEnd(32, '0'), ip: it.ip, comment: it.comment });
      });
    }
    if (p === itemsPath && method === 'DELETE') {
      return op(() => {
        const ids = new Set(body.items.map((i) => i.id));
        for (let i = items.length - 1; i >= 0; i--) if (ids.has(items[i].id)) items.splice(i, 1);
      });
    }
    if (p === itemsPath && method === 'GET') {
      const search = u.searchParams.get('search');
      const all = items.filter((i) => !search || i.ip.includes(search));
      const start = Number(u.searchParams.get('cursor') ?? 0);
      const page = all.slice(start, start + pageSize);
      const after = start + pageSize < all.length ? String(start + pageSize) : undefined;
      return ok(page, { result_info: { cursors: after ? { after } : {} } });
    }
    if (p === `/accounts/${ACCOUNT}/rules/lists` && method === 'GET') return ok(lists);
    if (p === `/accounts/${ACCOUNT}/rules/lists` && method === 'POST') {
      const list = { id: LIST, name: body.name, kind: body.kind };
      lists.push(list);
      return ok(list);
    }
    if (p === '/accounts' && method === 'GET') return ok(accounts);
    if (p.startsWith('/zones') && denyZones) return json(403, { success: false, errors: [{ code: 10000, message: 'Authentication error' }] });
    if (p === '/zones' && method === 'GET') return ok(zones.filter((z) => z.name === u.searchParams.get('name')));
    const zoneById = /^\/zones\/(\w+)$/.exec(p);
    if (zoneById && method === 'GET') {
      const z = zones.find((x) => x.id === zoneById[1]);
      return z ? ok(z) : json(404, { success: false, errors: [{ code: 1001, message: 'Invalid zone identifier' }] });
    }
    if (p === `/zones/${ZONE}/rulesets/phases/http_request_firewall_custom/entrypoint`) {
      if (method === 'GET') {
        return waf.entrypoint
          ? ok(waf.entrypoint)
          : json(404, { success: false, errors: [{ code: 10003, message: 'could not find entrypoint ruleset in the http_request_firewall_custom phase' }] });
      }
      if (method === 'PUT') {
        assert.equal(waf.entrypoint, undefined, 'PUT must never replace an existing entry point ruleset');
        waf.entrypoint = { id: RULESET, phase: 'http_request_firewall_custom', rules: body.rules.map((r, i) => ({ id: `r${i}`, ...r })) };
        return ok(waf.entrypoint);
      }
    }
    if (p === `/zones/${ZONE}/rulesets/${RULESET}/rules` && method === 'POST') {
      waf.entrypoint.rules.push({ id: `r${waf.entrypoint.rules.length}`, ...body });
      return ok(waf.entrypoint);
    }
    return json(404, { success: false, errors: [{ code: 7003, message: 'not found' }] });
  };
  return { fetch, items, lists, calls, waf };
}

const enforcer = (cf, extra = {}) =>
  cloudflareEnforcer({ apiToken: TOKEN, accountId: ACCOUNT, listId: LIST, fetch: cf.fetch, sleep: fast, logger: { warn() {} }, ...extra });

const machine = (target, untilOffset = 60_000, reason = 'decoy.param') => ({
  source: 's',
  target,
  public: true,
  reason,
  since: Date.now(),
  until: Date.now() + untilOffset,
});

test('comments carry the expiry and only Kagami items are recognised', () => {
  const m = machine('198.51.100.4');
  const c = itemComment(m);
  assert.match(c, /^kagami until=\d{4}-\d\d-\d\dT.* reason=decoy\.param$/);
  assert.equal(itemExpiry({ id: 'x', comment: c }), m.until);
  assert.equal(itemExpiry({ id: 'x', comment: 'office VPN' }), undefined);
  assert.equal(itemExpiry({ id: 'x' }), undefined);
});

test('contain adds items in one call and waits for the bulk operation', async () => {
  const cf = fakeCloudflare({ failFirst429: true });
  const e = enforcer(cf);
  await e.contain([machine('8.8.8.8'), machine('2a01:4f8:1:2::/64')]);
  assert.deepEqual(cf.items.map((i) => i.ip), ['8.8.8.8', '2a01:4f8:1:2::/64']);
  const posts = cf.calls.filter((c) => c.method === 'POST');
  assert.equal(posts.length, 2, 'one retry after the 429, then one successful POST');
  assert.ok(cf.calls.some((c) => c.path.includes('bulk_operations')), 'polled until the operation completed');
});

test('sweep removes expired and duplicate Kagami items and leaves others alone', async () => {
  const cf = fakeCloudflare();
  const e = enforcer(cf);
  await e.contain([machine('8.8.8.8', 60_000), machine('9.9.9.9', -1000)]);
  await e.contain([machine('8.8.8.8', 120_000)]);
  cf.items.push({ id: 'manual'.padEnd(32, '0'), ip: '1.2.3.4', comment: 'office, keep' });
  const { removed } = await e.sweep();
  assert.equal(removed, 2, 'one expired item and one older duplicate');
  assert.deepEqual(cf.items.map((i) => i.ip).sort(), ['1.2.3.4', '8.8.8.8']);
  assert.equal(itemExpiry(cf.items.find((i) => i.ip === '8.8.8.8')) > Date.now() + 100_000, true, 'the later expiry is kept');
});

test('release deletes only the Kagami items for that address', async () => {
  const cf = fakeCloudflare();
  const e = enforcer(cf);
  await e.contain([machine('8.8.8.8'), machine('8.8.4.4')]);
  cf.items.push({ id: 'manual'.padEnd(32, '0'), ip: '8.8.8.8', comment: 'set by hand' });
  await e.release([machine('8.8.8.8')]);
  assert.deepEqual(cf.items.map((i) => `${i.ip} ${i.comment.startsWith('kagami') ? 'kagami' : 'manual'}`).sort(), ['8.8.4.4 kagami', '8.8.8.8 manual']);
});

test('end to end, a tripwire in the app puts the machine on the Cloudflare list', async () => {
  const cf = fakeCloudflare();
  const k = new Kagami({
    secret: 'cloudflare-e2e-secret-0123456789abcdef-012',
    mode: 'protect',
    decoys: { json: true },
    containment: true,
    enforcers: [enforcer(cf)],
    sinks: [],
    logger: { warn() {} },
  });
  const field = k.manifest().decoys.json_field;
  const req = (ip) => ({ ip, method: 'GET', host: 'shop.example.com', path: '/api/products', query: `${field}=admin`, headers: [['user-agent', 'curl/8.9']] });
  k.inspect(req('8.8.8.8'));
  k.inspect(req('10.0.0.5'));
  await k.flush();
  await k.close();
  assert.deepEqual(cf.items.map((i) => i.ip), ['8.8.8.8'], 'the private address is never pushed to the edge');
  assert.match(cf.items[0].comment, /reason=decoy\.param/);
});

test('the client rejects bad ids and never puts the token in errors', async () => {
  assert.throws(() => new ListsClient({ apiToken: TOKEN, accountId: 'nope' }), /32 hex/);
  assert.throws(() => cloudflareEnforcer({ apiToken: TOKEN, accountId: ACCOUNT, listId: 'x' }), /list id must be 32 hex/);
  const client = new ListsClient({
    apiToken: TOKEN,
    accountId: ACCOUNT,
    sleep: fast,
    fetch: async () => new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: 'Authentication error' }] }), { status: 403 }),
  });
  await assert.rejects(client.items(LIST), (err) => {
    assert.match(err.message, /10000 Authentication error/);
    assert.ok(!err.message.includes(TOKEN));
    return true;
  });
});

// Plug and play. With the three Cloudflare settings in the environment and
// containment on, Kagami adds the Cloudflare enforcer by itself.

const ENV_KEYS = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'KAGAMI_CLOUDFLARE_LIST_ID', 'KAGAMI_CONTAINMENT'];

async function withEnv(vars, fn) {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  const savedFetch = globalThis.fetch;
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, vars);
  try {
    return await fn();
  } finally {
    globalThis.fetch = savedFetch;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const FULL_ENV = { CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_ACCOUNT_ID: ACCOUNT, KAGAMI_CLOUDFLARE_LIST_ID: LIST };

function tripFrom(k, ip) {
  const field = k.manifest().decoys.json_field;
  k.inspect({ ip, method: 'GET', host: 'shop.example.com', path: '/api/products', query: `${field}=admin`, headers: [['user-agent', 'curl/8.9']] });
}

test('the three environment variables and KAGAMI_CONTAINMENT are all it takes', async () => {
  await withEnv({ ...FULL_ENV, KAGAMI_CONTAINMENT: 'on' }, async () => {
    const cf = fakeCloudflare();
    globalThis.fetch = cf.fetch;
    const warnings = [];
    const k = new Kagami({ secret: 'cloudflare-env-secret-0123456789abcdef-0123', mode: 'protect', decoys: { json: true }, sinks: [], logger: { warn: (m) => warnings.push(m) } });
    tripFrom(k, '8.8.8.8');
    await k.flush();
    await k.close();
    assert.deepEqual(cf.items.map((i) => i.ip), ['8.8.8.8']);
    assert.deepEqual(warnings, []);
  });
});

test('incomplete or unused Cloudflare settings explain themselves and send nothing', async () => {
  const cases = [
    [{ CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_ACCOUNT_ID: ACCOUNT, KAGAMI_CONTAINMENT: 'on' }, /KAGAMI_CLOUDFLARE_LIST_ID is not set/],
    [FULL_ENV, /containment is off/],
    [{ ...FULL_ENV, CLOUDFLARE_ACCOUNT_ID: 'nope', KAGAMI_CONTAINMENT: 'on' }, /account id must be 32 hex/],
  ];
  for (const [vars, expected] of cases) {
    await withEnv(vars, async () => {
      const cf = fakeCloudflare();
      globalThis.fetch = cf.fetch;
      const warnings = [];
      const k = new Kagami({ secret: 'cloudflare-env-secret-0123456789abcdef-0123', mode: 'protect', decoys: { json: true }, sinks: [], logger: { warn: (m) => warnings.push(m) } });
      tripFrom(k, '8.8.8.8');
      await k.flush();
      await k.close();
      assert.match(warnings.join('\n'), expected);
      assert.equal(cf.items.length, 0);
    });
  }
});

test('cloudflare: false keeps Cloudflare off even with the settings present', async () => {
  await withEnv({ ...FULL_ENV, KAGAMI_CONTAINMENT: 'on' }, async () => {
    const cf = fakeCloudflare();
    globalThis.fetch = cf.fetch;
    const k = new Kagami({ secret: 'cloudflare-env-secret-0123456789abcdef-0123', mode: 'protect', decoys: { json: true }, cloudflare: false, sinks: [], logger: { warn() {} } });
    tripFrom(k, '8.8.8.8');
    await k.flush();
    await k.close();
    assert.equal(cf.items.length, 0);
    assert.equal(k.contained().length, 1, 'Kagami itself still contains the machine');
  });
});

// kagami cloudflare setup. Creates the list and the WAF custom rule, never
// replaces existing rules, and changes nothing on a second run.

const setup = (cf, extra = {}) =>
  cloudflareSetup({ apiToken: TOKEN, accountId: ACCOUNT, fetch: cf.fetch, sleep: fast, zones: ['example.com'], ...extra });

const OTHER_RULE = { id: 'mine', action: 'block', expression: '(ip.src.country eq "XX")', description: 'set by hand', enabled: true };

test('setup without a token explains the two tokens and links to Create Token', async () => {
  const res = await cloudflareSetup({ apiToken: '' });
  assert.equal(res.ok, false);
  assert.match(res.output, /CLOUDFLARE_API_TOKEN is not set/);
  assert.match(res.output, /Account Filter Lists Edit, Zone Read, Zone WAF Edit/);
  const link = res.output.split('\n').map((l) => l.trim()).find((l) => l.includes('permissionGroupKeys='));
  const url = new URL(link);
  assert.equal(url.origin + url.pathname, 'https://dash.cloudflare.com/');
  assert.equal(url.searchParams.get('to'), '/:account/api-tokens');
  assert.deepEqual(JSON.parse(url.searchParams.get('permissionGroupKeys')), SETUP_PERMISSION_KEYS);
  assert.equal(url.searchParams.get('name'), 'Kagami setup');
  assert.ok(!link.includes('+'), 'spaces are encoded as %20');
  assert.equal(
    tokenLink([{ key: 'zone', type: 'read' }], 'x'),
    'https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=%5B%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%5D&name=x',
  );
});

test('setup creates the entry point ruleset when the zone has none', async () => {
  const cf = fakeCloudflare();
  const res = await setup(cf);
  assert.equal(res.ok, true, res.output);
  assert.deepEqual(cf.lists.map((l) => l.name), ['kagami_contained']);
  assert.deepEqual(
    cf.waf.entrypoint.rules.map(({ expression, action, enabled }) => ({ expression, action, enabled })),
    [{ expression: '(ip.src in $kagami_contained)', action: 'block', enabled: true }],
  );
  assert.match(res.output, /Added the WAF custom rule to example\.com/);
  assert.ok(res.output.includes(`KAGAMI_CLOUDFLARE_LIST_ID=${LIST}`));
  assert.match(res.output, /Zone WAF Edit, to add the custom rule/);
  assert.match(res.output, /delete it now/);
  assert.ok(!res.output.includes(TOKEN));
});

test('setup adds one rule with POST and keeps the rules already there', async () => {
  const cf = fakeCloudflare({ entrypoint: { id: RULESET, rules: [OTHER_RULE] } });
  const res = await setup(cf, { action: 'managed_challenge' });
  assert.equal(res.ok, true, res.output);
  assert.equal(cf.calls.filter((c) => c.method === 'PUT').length, 0, 'never PUT over existing rules');
  const posts = cf.calls.filter((c) => c.method === 'POST' && c.path.endsWith('/rules'));
  assert.equal(posts.length, 1);
  assert.deepEqual(posts[0].body, {
    description: 'Kagami blocks contained machines',
    expression: '(ip.src in $kagami_contained)',
    action: 'managed_challenge',
    enabled: true,
  });
  assert.deepEqual(cf.waf.entrypoint.rules.map((r) => r.id), ['mine', 'r1']);
});

test('a second setup run changes nothing', async () => {
  const cf = fakeCloudflare();
  await setup(cf);
  const before = cf.calls.length;
  const res = await setup(cf, { action: 'managed_challenge' });
  assert.equal(res.ok, true, res.output);
  const writes = cf.calls.slice(before).filter((c) => c.method !== 'GET');
  assert.deepEqual(writes, [], 'no list or rule is created twice');
  assert.match(res.output, /already exists/);
  assert.match(res.output, /already has the Kagami WAF custom rule, with action block\. Nothing was changed/);
  assert.match(res.output, /To use managed_challenge instead, edit the rule in the dashboard/);
  assert.equal(cf.waf.entrypoint.rules.length, 1);
});

test('an existing Kagami rule is recognised by expression or description', () => {
  assert.ok(isKagamiRule({ action: 'block', expression: 'ip.src in $kagami_contained' }, 'kagami_contained'));
  assert.ok(isKagamiRule({ action: 'block', expression: '( ( ip.src  in $kagami_contained ) )' }, 'kagami_contained'));
  assert.ok(isKagamiRule({ action: 'block', expression: 'ip.src in $other', description: 'Kagami edge block' }, 'kagami_contained'));
  assert.ok(!isKagamiRule(OTHER_RULE, 'kagami_contained'));
  assert.ok(!isKagamiRule({ action: 'block', expression: 'ip.src in $kagami_contained2' }, 'kagami_contained'));
});

test('a disabled Kagami rule is reported and left alone', async () => {
  const cf = fakeCloudflare({ entrypoint: { id: RULESET, rules: [{ id: 'k', action: 'block', expression: '(ip.src in $kagami_contained)', enabled: false }] } });
  const res = await setup(cf);
  assert.match(res.output, /is turned off/);
  assert.equal(cf.calls.filter((c) => c.method === 'POST' && c.path.endsWith('/rules')).length, 0);
});

test('zones are found by domain, by a host inside them, by URL and by id', async () => {
  assert.deepEqual(zoneCandidates('https://Shop.Example.com/path'), ['shop.example.com', 'example.com']);
  assert.deepEqual(zoneCandidates('example.com.'), ['example.com']);
  for (const zone of ['shop.example.com', 'https://example.com/', ZONE]) {
    const cf = fakeCloudflare();
    const res = await setup(cf, { zones: [zone] });
    assert.equal(res.ok, true, `${zone} ${res.output}`);
    assert.equal(cf.waf.entrypoint.rules.length, 1);
  }
  const cf = fakeCloudflare();
  const res = await setup(cf, { zones: ['nothing.test'] });
  assert.equal(res.ok, false);
  assert.match(res.output, /No zone named nothing\.test was found/);
  assert.match(res.output, /Add the WAF custom rule by hand/);
});

test('a token without zone permissions still creates the list and says what is missing', async () => {
  const cf = fakeCloudflare({ denyZones: true });
  const res = await setup(cf);
  assert.equal(res.ok, false);
  assert.deepEqual(cf.lists.map((l) => l.name), ['kagami_contained']);
  assert.match(res.output, /needs Zone Read and Zone WAF Edit/);
  assert.ok(res.output.includes('Expression       (ip.src in $kagami_contained)'));
  assert.ok(res.output.includes(`KAGAMI_CLOUDFLARE_LIST_ID=${LIST}`));
});

test('a zone in another account is refused', async () => {
  const cf = fakeCloudflare({ zones: [{ id: ZONE, name: 'example.com', account: { id: 'f'.repeat(32) } }] });
  const res = await setup(cf);
  assert.equal(res.ok, false);
  assert.match(res.output, /belongs to another Cloudflare account/);
  assert.equal(cf.waf.entrypoint, undefined);
});

test('setup without --zone prints the rule to add by hand and only uses the lists permission', async () => {
  const cf = fakeCloudflare();
  const res = await setup(cf, { zones: [] });
  assert.equal(res.ok, true);
  assert.match(res.output, /Add the WAF custom rule by hand/);
  assert.match(res.output, /--zone <your domain>/);
  assert.ok(!cf.calls.some((c) => c.path.includes('/zones')));
  assert.ok(!/Zone WAF Edit, to add/.test(res.output));
});

test('the account id is found when the token sees exactly one account', async () => {
  const cf = fakeCloudflare();
  const res = await setup(cf, { accountId: '' });
  assert.match(res.output, /Using the account Main/);
  assert.ok(res.output.includes(`CLOUDFLARE_ACCOUNT_ID=${ACCOUNT}`));
  const two = fakeCloudflare({ accounts: [{ id: ACCOUNT, name: 'A' }, { id: 'e'.repeat(32), name: 'B' }] });
  await assert.rejects(setup(two, { accountId: '' }), /can see 2 accounts/);
});

test('a token Cloudflare rejects is named as the problem', async () => {
  const fetch = async () => new Response(JSON.stringify({ success: false, errors: [{ code: 9106, message: 'Authentication failed (status: 400)' }] }), { status: 400 });
  await assert.rejects(cloudflareSetup({ apiToken: TOKEN, accountId: ACCOUNT, fetch, sleep: fast }), /Cloudflare rejected the token/);
  await assert.rejects(cloudflareSetup({ apiToken: TOKEN, fetch, sleep: fast }), /Cloudflare rejected the token/);
});

test('setup rejects a bad action or list name before calling Cloudflare', async () => {
  const cf = fakeCloudflare();
  await assert.rejects(setup(cf, { action: 'allow' }), /block or managed_challenge/);
  await assert.rejects(setup(cf, { listName: 'bad name' }), /letters, digits and underscores/);
  assert.equal(cf.calls.length, 0);
});
