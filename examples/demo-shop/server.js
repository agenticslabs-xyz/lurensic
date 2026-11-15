// Demo shop entry point. Run it with `pnpm demo`, or with `pnpm bench` for a
// benchmark round. Settings come from environment variables, which
// scripts/bench-serve.mjs sets.
import { randomBytes } from 'node:crypto';
import { appendFile, chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { consoleSink, fileSink } from '@agenticslabs/kagami-express';
import { createApp } from './app.js';

const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const port = Number(env.PORT ?? 41837);
const mode = env.KAGAMI_MODE === 'observe' ? 'observe' : 'protect';
const dataDir = env.KAGAMI_DATA_DIR ?? here;

// The secret comes from KAGAMI_SECRET, or else from a file created once in the data folder.
function loadSecret() {
  if (env.KAGAMI_SECRET) return env.KAGAMI_SECRET;
  const file = join(dataDir, '.kagami-secret');
  if (!existsSync(file)) writeFileSync(file, randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
  try {
    chmodSync(file, 0o600);
  } catch {
    /* best effort on Windows */
  }
  return readFileSync(file, 'utf8').trim();
}

const eventsPath = join(dataDir, 'kagami-events.jsonl');
const accessPath = join(dataDir, 'access.jsonl');

const app = createApp(
  {
    secret: loadSecret(),
    mode,
    sinks: [consoleSink({ minSeverity: 'medium' }), fileSink({ path: eventsPath })],
  },
  {
    // Full request log for benchmark analysis. It holds no bodies, cookies or header values except the user agent.
    accessLog: (record) => appendFile(accessPath, JSON.stringify(record) + '\n', { mode: 0o600 }, () => {}),
  },
);

const server = app.listen(port, () => {
  console.log(`Northwind Outfitters is running on http://localhost:${port} with Kagami in ${mode} mode (deployment ${app.kagami.deployment ?? 'DISABLED'})`);
  console.log(`Kagami events are written to ${eventsPath} and requests to ${accessPath}`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close();
    app.kagami.close().finally(() => process.exit(0));
  });
}
