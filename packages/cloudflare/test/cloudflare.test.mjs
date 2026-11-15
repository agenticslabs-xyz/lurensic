// Tests for the Cloudflare enforcer against an in-memory model of the
// Cloudflare Lists API (create list, add items, delete items, list items with
// search and cursor pagination, and asynchronous bulk operations).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Kagami } from '@agenticslabs/kagami';
import { cloudflareClientIp, cloudflareEnforcer, isCloudflareAddress, itemComment, itemExpiry, ListsClient } from '../dist/index.js';

const ACCOUNT = 'a'.repeat(32);
const LIST = 'b'.repeat(32);
const TOKEN = 'test-token-never-logged';
const fast = () => Promise.resolve();

/** A fake Cloudflare API. Bulk operations stay pending for one poll. */
function fakeCloudflare({ pageSize = 2, failFirst429 = false } = {}) {
  const items = [];
  const ops = new Map();
  const calls = [];
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
    if (p === `/accounts/${ACCOUNT}/rules/lists` && method === 'GET') return ok([]);
    if (p === `/accounts/${ACCOUNT}/rules/lists` && method === 'POST') return ok({ id: LIST, name: body.name, kind: body.kind });
    return json(404, { success: false, errors: [{ code: 7003, message: 'not found' }] });
  };
  return { fetch, items, calls };
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
  assert.throws(() => cloudflareEnforcer({ apiToken: TOKEN, accountId: ACCOUNT, listId: 'x' }), /listId/);
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

test('CF-Connecting-IP is trusted only from Cloudflare', () => {
  const ip = cloudflareClientIp();
  const req = (remote, cf, xff) => ({ socket: { remoteAddress: remote }, headers: { 'cf-connecting-ip': cf, 'x-forwarded-for': xff } });
  assert.equal(ip(req('::ffff:173.245.48.10', '8.8.8.8')), '8.8.8.8', 'from Cloudflare, the header is used');
  assert.equal(ip(req('2606:4700::1', '2001:4860::8888')), '2001:4860::8888');
  assert.equal(ip(req('198.51.100.66', '8.8.8.8')), '198.51.100.66', 'a forged header from elsewhere is ignored');
  assert.equal(ip(req('173.245.48.10', 'not-an-ip')), '173.245.48.10');
  // Behind a local proxy, the proxy's X-Forwarded-For names the Cloudflare peer.
  const viaNginx = cloudflareClientIp({ trustedProxies: ['127.0.0.1/32'] });
  assert.equal(viaNginx(req('127.0.0.1', '8.8.8.8', '203.0.113.5, 173.245.48.10')), '8.8.8.8');
  assert.equal(viaNginx(req('127.0.0.1', '8.8.8.8', '198.51.100.66')), '198.51.100.66', 'a non-Cloudflare peer behind the proxy is not trusted');
  assert.equal(isCloudflareAddress('104.16.1.1'), true);
  assert.equal(isCloudflareAddress('8.8.8.8'), false);
});
