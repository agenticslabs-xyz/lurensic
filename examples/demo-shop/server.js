// Demo shop entry point. Run it with `pnpm demo`, or with `pnpm bench` for a
// benchmark round. Settings come from environment variables, which
// scripts/bench-serve.mjs sets.
import { randomBytes } from 'node:crypto';
import { appendFile, chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { blocklistFile, consoleSink, fileSink } from '@agenticslabs/lurensic-express';
import { createApp } from './app.js';

const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const port = Number(env.PORT ?? 41837);
const mode = env.LURENSIC_MODE === 'observe' ? 'observe' : 'protect';
const dataDir = env.LURENSIC_DATA_DIR ?? here;
// LURENSIC_CONTAINMENT is shadow, block, or empty for off. PLANTED_BUGS=1 adds the two planted flaws.
const containment = ['shadow', 'block'].includes(env.LURENSIC_CONTAINMENT) ? env.LURENSIC_CONTAINMENT : null;
const plantedBugs = env.PLANTED_BUGS === '1';
// DEMO_RESPOND=1 makes the shop act on tripwires through onDetect, blocking the address and locking the account.
const respond = env.DEMO_RESPOND === '1';

// The secret comes from LURENSIC_SECRET, or else from a file created once in the data folder.
function loadSecret() {
  if (env.LURENSIC_SECRET) return env.LURENSIC_SECRET;
  const file = join(dataDir, '.lurensic-secret');
  if (!existsSync(file)) writeFileSync(file, randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
  try {
    chmodSync(file, 0o600);
  } catch {
    /* best effort on Windows */
  }
  return readFileSync(file, 'utf8').trim();
}

function parseTrustProxy(value) {
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  return /^\d+$/.test(value) ? Number(value) : value;
}

const eventsPath = join(dataDir, 'lurensic-events.jsonl');
const accessPath = join(dataDir, 'access.jsonl');
const blocklistPath = join(dataDir, 'contained.txt');

const app = createApp(
  {
    secret: loadSecret(),
    mode,
    sinks: [consoleSink({ minSeverity: 'medium' }), fileSink({ path: eventsPath })],
    ...(containment && {
      containment: { action: containment },
      // A provider-neutral enforcer. The bench runs on loopback, so private
      // addresses are included to show what an edge firewall would receive.
      enforcers: [blocklistFile({ path: blocklistPath, includePrivate: true })],
    }),
  },
  {
    // The demo runs without a proxy in front of it, so client address
    // headers are never trusted. Set TRUST_PROXY when a real proxy is added.
    trustProxy: parseTrustProxy(process.env.TRUST_PROXY),
    // Full request log for benchmark analysis. It holds no bodies, cookies or header values except the user agent.
    accessLog: (record) => appendFile(accessPath, JSON.stringify(record) + '\n', { mode: 0o600 }, () => {}),
    plantedBugs,
    respond,
  },
);

const server = app.listen(port, () => {
  console.log(`Northwind Outfitters is running on http://localhost:${port} with Lurensic in ${mode} mode (deployment ${app.lurensic.deployment ?? 'DISABLED'})`);
  console.log(`Lurensic events are written to ${eventsPath} and requests to ${accessPath}`);
  console.log(`Containment ${containment ?? 'off'}${containment ? `, blocklist ${blocklistPath}` : ''}. Planted bugs ${plantedBugs ? 'on' : 'off'}. Response through onDetect ${respond ? 'on' : 'off'}.`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close();
    app.lurensic.close().finally(() => process.exit(0));
  });
}
