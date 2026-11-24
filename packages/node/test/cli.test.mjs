// Runs the real command line tool the way `npx lurensic` does, as its own
// process, so it catches an entry that forgets to load the engine.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
const SECRET = 'cli-test-secret-0123456789abcdef-0123456789';

test('lurensic doctor finds a working engine', () => {
  const run = spawnSync(process.execPath, [CLI, 'doctor', '--json'], {
    env: { ...process.env, LURENSIC_SECRET: SECRET },
    encoding: 'utf8',
  });
  const { checks } = JSON.parse(run.stdout);
  const engine = checks.find((c) => c.id === 'engine');
  assert.equal(engine?.status, 'pass', engine?.message);
});

test('lurensic secret prints a secret long enough to use', () => {
  const secret = execFileSync(process.execPath, [CLI, 'secret'], { encoding: 'utf8' }).trim();
  assert.ok(secret.length >= 32);
});
