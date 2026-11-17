// `kagami doctor` against real Express apps. The most important property is
// that running the doctor never gets its own machine contained.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import express from 'express';
import { blocklistFile, fileSink, kagami, runDoctor } from '../dist/index.js';

const SECRET = 'doctor-test-secret-0123456789abcdef-0123456';
const dir = mkdtempSync(join(tmpdir(), 'kagami-doctor-'));
after(() => rmSync(dir, { recursive: true, force: true }));

async function serve(app) {
  const server = await new Promise((r) => {
    const s = app.listen(0, '127.0.0.1', () => r(s));
  });
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

const byId = (checks) => Object.fromEntries(checks.map((c) => [c.id, c]));

test('a correct protect-mode setup passes and the doctor is never contained', async () => {
  const events = join(dir, 'events.jsonl');
  const blocklist = join(dir, 'contained.json');
  const mw = kagami({
    secret: SECRET,
    mode: 'protect',
    containment: true,
    sinks: [fileSink({ path: events })],
    enforcers: [blocklistFile({ path: blocklist, format: 'json', includePrivate: true })],
    logger: { warn() {} },
  });
  const app = express();
  app.use(mw);
  app.get('/', (_req, res) => res.send('<!doctype html><html><body>shop</body></html>'));
  const { url, close } = await serve(app);
  try {
    const env = { KAGAMI_SECRET: SECRET, NODE_ENV: 'production' };
    await runDoctor({ url, env });
    await mw.kagami.flush();
    await new Promise((r) => setTimeout(r, 50));
    const checks = byId(await runDoctor({ url, events, blocklist, env }));
    for (const id of ['secret', 'engine', 'reachable', 'protect', 'events', 'client_address', 'blocklist']) {
      assert.equal(checks[id]?.status, 'pass', `${id}: ${checks[id]?.message}`);
    }
    assert.match(checks.events.message, /protect mode \(containment shadow/);
    assert.deepEqual(mw.kagami.contained(), [], 'the doctor never trips a wire');
  } finally {
    await close();
    await mw.kagami.close();
  }
});

test('observe mode is reported as information, not a failure', async () => {
  const mw = kagami({ secret: SECRET, mode: 'observe', sinks: [], logger: { warn() {} } });
  const app = express();
  app.use(mw);
  app.get('/', (_req, res) => res.send('ok'));
  const { url, close } = await serve(app);
  try {
    const checks = byId(await runDoctor({ url, env: { KAGAMI_SECRET: SECRET } }));
    assert.equal(checks.protect.status, 'info');
  } finally {
    await close();
    await mw.kagami.close();
  }
});

test('a real leaked .env and a bad secret are failures with a fix', async () => {
  const app = express();
  app.get('/.env', (_req, res) => res.type('text/plain').send('DATABASE_URL=postgres://real\n'));
  app.get('/', (_req, res) => res.send('ok'));
  const { url, close } = await serve(app);
  try {
    const checks = byId(await runDoctor({ url, env: { KAGAMI_SECRET: 'short', NODE_ENV: 'production' } }));
    assert.equal(checks.protect.status, 'fail');
    assert.match(checks.protect.fix, /rotate every secret/);
    assert.equal(checks.secret.status, 'fail');
    const missing = byId(await runDoctor({ env: { NODE_ENV: 'production' } }));
    assert.equal(missing.secret.status, 'fail');
    assert.match(missing.secret.fix, /npx @agenticslabs\/kagami secret/);
  } finally {
    await close();
  }
});

test('the doctor reports the decoy description, a real spec in its place, or that it is safe to turn on', async () => {
  const spec = { openapi: '3.0.3', info: { title: 'Real API', version: '1' }, paths: {} };
  for (const [decoys, real, status] of [
    [{ spec: true }, false, 'pass'],
    [{}, 'main', 'warn'],
    [{}, 'alias', 'warn'],
    [{}, false, 'info'],
  ]) {
    const mw = kagami({ secret: SECRET, mode: 'protect', decoys, sinks: [], logger: { warn() {} } });
    const d = kagami({ secret: SECRET, mode: 'protect', decoys: { spec: true }, sinks: [], logger: { warn() {} } }).kagami.manifest().decoys;
    const app = express();
    app.use(mw);
    if (real) app.get(real === 'main' ? d.spec_path : d.spec_aliases.at(-1), (_req, res) => res.json(spec));
    app.get('/', (_req, res) => res.send('ok'));
    const { url, close } = await serve(app);
    try {
      const checks = byId(await runDoctor({ url, env: { KAGAMI_SECRET: SECRET } }));
      assert.equal(checks.spec?.status, status, checks.spec?.message);
    } finally {
      await close();
      await mw.kagami.close();
    }
  }
});
