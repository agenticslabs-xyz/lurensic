// Demo shop entry point: `pnpm demo`, or `pnpm bench` for a benchmark round.
// Settings come from environment variables (set by scripts/bench-serve.mjs).
import { randomBytes } from 'node:crypto';
import { appendFile, chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { consoleSink, fileSink } from '@agenticslabs/kagami-express';
import { createApp } from './app.js';

const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const port = Number(env.PORT ?? 3000);
const mode = env.KAGAMI_MODE === 'observe' ? 'observe' : 'protect';
const dataDir = env.KAGAMI_DATA_DIR ?? here;

// Secret: env var, else a file created once in the data folder.
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
    // Full request log for benchmark analysis (no bodies, cookies or header values except the user agent).
    accessLog: (record) => appendFile(accessPath, JSON.stringify(record) + '\n', { mode: 0o600 }, () => {}),
  },
);

const server = app.listen(port, () => {
  console.log(`Northwind Outfitters on http://localhost:${port} (Kagami ${mode} mode, deployment ${app.kagami.deployment ?? 'DISABLED'})`);
  console.log(`Logs: ${eventsPath}, ${accessPath}`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close();
    app.kagami.close().finally(() => process.exit(0));
  });
}
