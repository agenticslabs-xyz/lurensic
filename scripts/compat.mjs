// Checks the packages the way users get them. It packs the three packages (or
// takes tarballs that were packed already), installs them into a new project
// outside the workspace, and runs each check against that install.
//
//   pnpm build && node scripts/compat.mjs                 every check this machine can run
//   node scripts/compat.mjs --tarballs .pack              use tarballs packed earlier
//   node scripts/compat.mjs --only bun,deno               only these checks
//
// Checks: express5, express4, hono, cli, require, types, bundle, bun, deno.
// bun and deno are skipped when that runtime is not installed, unless they are
// named with --only, which turns a missing runtime into a failure.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { values: args } = parseArgs({ options: { tarballs: { type: 'string' }, only: { type: 'string' }, keep: { type: 'boolean' } } });
const ALL = ['express5', 'express4', 'hono', 'cli', 'require', 'types', 'bundle', 'bun', 'deno'];
const only = args.only ? args.only.split(',').map((s) => s.trim()) : null;
for (const name of only ?? []) if (!ALL.includes(name)) throw new Error(`Unknown check "${name}". Known: ${ALL.join(', ')}`);
const wanted = (name) => !only || only.includes(name);

const win = process.platform === 'win32';
// On Windows, npm and pnpm are .cmd files that need a shell. A full path to an
// executable such as process.execPath runs without one.
function run(cmd, argv, opts = {}) {
  const shell = win && !/[\\/]/.test(cmd);
  if (!shell) return spawnSync(cmd, argv, { encoding: 'utf8', ...opts });
  const line = [cmd, ...argv.map((a) => (/[\s"]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a))].join(' ');
  return spawnSync(line, { encoding: 'utf8', shell: true, ...opts });
}
const has = (cmd) => run(cmd, ['--version']).status === 0;

const SECRET = 'compat-check-secret-0123456789abcdef-012345';
const dir = mkdtempSync(join(tmpdir(), 'lurensic-compat-'));
const results = [];
const record = (name, status, detail = '') => {
  results.push({ name, status, detail });
  console.log(`${status.padEnd(4)} ${name}${detail ? `  ${detail}` : ''}`);
};

try {
  // 1. Tarballs.
  let tgzDir = args.tarballs ? resolve(args.tarballs) : join(dir, 'tgz');
  if (!args.tarballs) {
    for (const pkg of ['node', 'express', 'hono']) {
      const r = run('pnpm', ['pack', '--pack-destination', tgzDir], { cwd: join(root, 'packages', pkg) });
      if (r.status !== 0) throw new Error(`pnpm pack failed in packages/${pkg}. Run pnpm build first.\n${r.stderr}`);
    }
  }
  const tgz = readdirSync(tgzDir).filter((f) => f.endsWith('.tgz')).map((f) => join(tgzDir, f));
  if (tgz.length !== 3) throw new Error(`Expected 3 tarballs in ${tgzDir}, found ${tgz.length}`);

  // The adapters must name a real version of the core, never a workspace range.
  for (const f of tgz) {
    const r = run('tar', ['-xzOf', f, 'package/package.json', ...(win ? ['--force-local'] : [])]);
    const deps = JSON.parse(r.stdout).dependencies ?? {};
    for (const [name, range] of Object.entries(deps)) if (String(range).startsWith('workspace:')) throw new Error(`${f} depends on ${name}@${range}`);
  }

  // 2. A new project that installs the tarballs from npm's point of view.
  const app = join(dir, 'app');
  cpSync(join(root, 'scripts', 'compat'), app, { recursive: true });
  writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'lurensic-compat', private: true, type: 'module' }));
  const install = run('npm', ['install', '--no-audit', '--no-fund', '--loglevel=error', ...tgz,
    'express@5', 'express4@npm:express@4', 'hono@4', '@hono/node-server', 'typescript@5', '@types/node', '@types/express', 'esbuild'], { cwd: app });
  if (install.status !== 0) throw new Error(`npm install failed\n${install.stderr}`);
  const env = { ...process.env, LURENSIC_SECRET: SECRET };
  const node = (file, extra = {}) => run(process.execPath, [file], { cwd: app, env, ...extra });
  const report = (name, r) => record(name, r.status === 0 ? 'ok' : 'FAIL', (r.status === 0 ? r.stdout : r.stdout + r.stderr).trim().split('\n').slice(-3).join(' | '));

  if (wanted('express5')) report('express5', node('express.mjs', { env: { ...env, EXPRESS: 'express' } }));
  if (wanted('express4')) report('express4', node('express.mjs', { env: { ...env, EXPRESS: 'express4' } }));
  if (wanted('hono')) report('hono', node('hono.mjs'));

  if (wanted('cli')) {
    const bin = join(app, 'node_modules', '@agenticslabs', 'lurensic', 'dist', 'cli.js');
    const doctor = run(process.execPath, [bin, 'doctor', '--json'], { cwd: app, env });
    const engine = (() => { try { return JSON.parse(doctor.stdout).checks.find((c) => c.id === 'engine'); } catch { return null; } })();
    const secret = run(process.execPath, [bin, 'secret'], { cwd: app }).stdout.trim();
    const ok = engine?.status === 'pass' && secret.length >= 32;
    record('cli', ok ? 'ok' : 'FAIL', ok ? 'doctor finds the engine, secret prints' : `engine ${engine?.status ?? 'missing'}: ${engine?.message ?? doctor.stderr}`);
  }

  if (wanted('require')) {
    // Node can require() an ES module from 20.19 and 22.12 on.
    if (process.features.require_module === false || (process.features.require_module === undefined && !supportsRequireEsm())) {
      record('require', 'skip', `Node ${process.version} cannot require() ES modules; users need 20.19, 22.12 or newer for that`);
    } else report('require', node('require.cjs'));
  }

  if (wanted('types')) {
    const tsc = join(app, 'node_modules', 'typescript', 'bin', 'tsc');
    const modes = [['nodenext', 'nodenext'], ['esnext', 'bundler']];
    const fails = modes.map(([module, resolution]) => [resolution, run(process.execPath, [tsc, '--noEmit', '--strict', '--types', 'node', '--module', module, '--moduleResolution', resolution, 'types.ts'], { cwd: app })])
      .filter(([, r]) => r.status !== 0);
    record('types', fails.length ? 'FAIL' : 'ok', fails.length ? fails.map(([m, r]) => `${m}: ${r.stdout.split('\n')[0]}`).join(' | ') : 'nodenext and bundler resolution');
  }

  if (wanted('bundle')) {
    const b = node('bundle.mjs');
    if (b.status !== 0) record('bundle', 'FAIL', b.stderr.trim());
    else report('bundle', node(join('bundle', 'app.mjs'), { env: { ...env, EXPRESS: 'express' } }));
  }

  for (const rt of ['bun', 'deno']) {
    if (!wanted(rt)) continue;
    if (!has(rt)) {
      record(rt, only?.includes(rt) ? 'FAIL' : 'skip', `${rt} is not installed`);
      continue;
    }
    const smoke = readFileSync(join(root, 'packages', 'node', 'test', 'runtime-smoke.mjs'), 'utf8').replace("'../dist/index.js'", "'@agenticslabs/lurensic'");
    writeFileSync(join(app, 'runtime-smoke.mjs'), smoke);
    report(rt, run(rt, rt === 'deno' ? ['run', '-A', 'runtime-smoke.mjs'] : ['runtime-smoke.mjs'], { cwd: app, env }));
  }
} finally {
  if (args.keep) console.log(`kept ${dir}`);
  else rmSync(dir, { recursive: true, force: true });
}

function supportsRequireEsm() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  return major > 22 || (major === 22 && minor >= 12) || (major === 20 && minor >= 19);
}

const failed = results.filter((r) => r.status === 'FAIL');
console.log(`\n${results.filter((r) => r.status === 'ok').length} passed, ${failed.length} failed, ${results.filter((r) => r.status === 'skip').length} skipped on Node ${process.version}`);
if (failed.length) process.exit(1);
