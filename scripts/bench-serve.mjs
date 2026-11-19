// Starts the demo shop for one benchmark round. Examples
//   pnpm bench                 (port 41837, protect mode)
//   pnpm bench -- --port 3001 --mode observe --label "artex-hardened"
//   pnpm bench -- --planted --contain shadow --port 41840 --label "artex-contain-1"
//   pnpm bench -- --planted --mode off --port 41841 --label "artex-baseline-1"
//
// Options
//   --mode      protect (default), observe, or off (Kagami disabled, the baseline)
//   --contain   off (default), shadow or block
//   --planted   add the two planted real bugs (see examples/demo-shop/app.js)
//   --respond   the demo acts on tripwires through onDetect, blocking the
//               address and locking the account, as a developer would
//   --warmup    on (default) or off. An honest visitor browses the site before
//               the attack, as on a live site, so the shadow has pages to learn
//   --decoys    extra opt-in decoys as KAGAMI_DECOYS, default spec (the demo
//               shop publishes no API description). Use none to turn it off
//   --port      use a new port for every round, because some harnesses keep
//               their memory per target URL
//
// Each round gets its own folder bench-runs/<timestamp>[-label]/ with a fresh
// deployment secret (new decoys), the Kagami event log, the full request log
// and run.json describing the round. Stop with Ctrl+C.
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { warmup } from './bench-warmup.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({
  // pnpm forwards the `--` separator literally
  args: process.argv.slice(2).filter((a) => a !== '--'),
  options: {
    port: { type: 'string', default: '41837' },
    mode: { type: 'string', default: 'protect' },
    contain: { type: 'string', default: 'off' },
    planted: { type: 'boolean', default: false },
    respond: { type: 'boolean', default: false },
    decoys: { type: 'string', default: 'spec' },
    warmup: { type: 'string', default: 'on' },
    label: { type: 'string', default: '' },
  },
});
if (!['protect', 'observe', 'off'].includes(values.mode)) throw new Error('--mode must be protect, observe or off');
if (!['off', 'shadow', 'block'].includes(values.contain)) throw new Error('--contain must be off, shadow or block');

// Refuse to start a round on a port another program already uses. Otherwise
// the demo exits at once and the attacker reaches the other program instead.
const portFree = await new Promise((resolve) => {
  const probe = createServer();
  probe.once('error', () => resolve(false));
  probe.listen(Number(values.port), () => probe.close(() => resolve(true)));
});
if (!portFree) {
  console.error(`Port ${values.port} is already in use by another program. Pick a free one with --port, for example pnpm bench -- --port 41838`);
  process.exit(1);
}

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
  containment: values.mode === 'off' ? 'off' : values.contain,
  planted_bugs: values.planted,
  respond_on_detect: values.respond,
  extra_decoys: values.decoys === 'none' ? '' : values.decoys,
  port: Number(values.port),
  target_from_docker: `http://host.docker.internal:${values.port}`,
  files: { events: 'kagami-events.jsonl', access: 'access.jsonl', secret: '.kagami-secret' },
};
writeFileSync(join(runDir, 'run.json'), JSON.stringify(run, null, 2) + '\n');

console.log(`\nBenchmark round folder   ${relative(root, runDir)}`);
console.log(`Target for the attacker  ${run.target_from_docker}`);
console.log(`Open in a browser        http://localhost:${values.port}\n`);

// Production mode, like a real deployment. Express then hides error details.
const env = {
  ...process.env,
  NODE_ENV: 'production',
  PORT: values.port,
  KAGAMI_MODE: values.mode === 'off' ? 'protect' : values.mode,
  KAGAMI_DATA_DIR: runDir,
  KAGAMI_CONTAINMENT: values.contain === 'off' ? '' : values.contain,
  PLANTED_BUGS: values.planted ? '1' : '',
  DEMO_RESPOND: values.respond ? '1' : '',
  KAGAMI_DECOYS: values.decoys === 'none' ? '' : values.decoys,
};
delete env.KAGAMI_SECRET; // a fresh secret per round, stored in the run folder
if (values.mode === 'off') env.KAGAMI_DISABLED = '1';
else delete env.KAGAMI_DISABLED;
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

// The honest visitor, once the shop answers.
if (values.mode !== 'off' && values.warmup !== 'off') {
  const base = `http://127.0.0.1:${values.port}`;
  let up = false;
  for (let i = 0; i < 60 && !up; i++) {
    try {
      up = (await fetch(base + '/healthz')).ok;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  if (up) {
    try {
      run.warmup = await warmup(base);
      writeFileSync(join(runDir, 'run.json'), JSON.stringify(run, null, 2) + '\n');
      console.log(`Warm-up visitor          ${run.warmup.pages} pages and ${run.warmup.form_posts} form posts. The round is ready.\n`);
    } catch (err) {
      console.error(`The warm-up visitor failed. ${err?.message ?? err}`);
    }
  }
}
