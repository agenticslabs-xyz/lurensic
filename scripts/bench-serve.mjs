// Starts the demo shop for one benchmark round:
//   pnpm bench                 (port 3000, protect mode)
//   pnpm bench -- --port 3001 --mode observe --label "suzaku-hardened"
//
// Each round gets its own folder bench-runs/<timestamp>[-label]/ with a fresh
// deployment secret (new decoys), the Kagami event log, the full request log
// and run.json describing the round. Stop with Ctrl+C.
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({
  // pnpm forwards the `--` separator literally
  args: process.argv.slice(2).filter((a) => a !== '--'),
  options: {
    port: { type: 'string', default: '3000' },
    mode: { type: 'string', default: 'protect' },
    label: { type: 'string', default: '' },
  },
});
if (!['protect', 'observe'].includes(values.mode)) throw new Error('--mode must be protect or observe');

const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const slug = values.label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const runDir = join(root, 'bench-runs', slug ? `${stamp}-${slug}` : stamp);
mkdirSync(runDir, { recursive: true });

const version = JSON.parse(readFileSync(join(root, 'packages', 'node', 'package.json'), 'utf8')).version;
const run = {
  started_at: new Date().toISOString(),
  label: values.label || null,
  kagami_version: version,
  mode: values.mode,
  port: Number(values.port),
  target_from_docker: `http://host.docker.internal:${values.port}`,
  files: { events: 'kagami-events.jsonl', access: 'access.jsonl', secret: '.kagami-secret' },
};
writeFileSync(join(runDir, 'run.json'), JSON.stringify(run, null, 2) + '\n');

console.log(`\nBenchmark round → ${relative(root, runDir)}`);
console.log(`Suzaku target   → ${run.target_from_docker}`);
console.log(`Browser         → http://localhost:${values.port}\n`);

const env = { ...process.env, PORT: values.port, KAGAMI_MODE: values.mode, KAGAMI_DATA_DIR: runDir };
delete env.KAGAMI_SECRET; // fresh secret per round, stored in the run folder
const child = spawn(process.execPath, [join(root, 'examples', 'demo-shop', 'server.js')], { env, stdio: 'inherit' });

const stop = (sig) => child.kill(sig);
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
child.on('exit', (code) => {
  const finished = { ...run, finished_at: new Date().toISOString() };
  writeFileSync(join(runDir, 'run.json'), JSON.stringify(finished, null, 2) + '\n');
  console.log(`\nRound saved in ${relative(root, runDir)}`);
  process.exit(code ?? 0);
});
