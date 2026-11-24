// Runs examples/hono-app on the Cloudflare Workers runtime with `wrangler dev`
// and checks that Lurensic works there. Workers load the engine through the
// `workerd` export, as a compiled .wasm module, so this covers the one entry
// that Node, Bun and Deno never use.
//
//   pnpm build && node scripts/workers-smoke.mjs
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cwd = join(root, 'examples', 'hono-app');
const PORT = 8799;
const base = `http://127.0.0.1:${PORT}`;
const wrangler = join(cwd, 'node_modules', 'wrangler', 'bin', 'wrangler.js');

const child = spawn(
  process.execPath,
  [wrangler, 'dev', '--ip', '127.0.0.1', '--port', String(PORT), '--var', 'LURENSIC_SECRET:workers-smoke-secret-0123456789abcdef-012', '--show-interactive-dev-session=false'],
  { cwd, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: '1' }, stdio: ['ignore', 'pipe', 'pipe'] },
);
let output = '';
child.stdout.on('data', (d) => (output += d));
child.stderr.on('data', (d) => (output += d));

const stop = () => new Promise((r) => (child.exitCode !== null ? r() : (child.once('exit', r), child.kill())));
const failures = [];
const check = (ok, what) => (ok ? console.log(`ok   ${what}`) : (failures.push(what), console.log(`FAIL ${what}`)));

try {
  // Wait for the dev server to answer, for up to 90 seconds.
  const deadline = Date.now() + 90_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`wrangler exited early\n${output}`);
    try {
      await fetch(`${base}/api/products`);
      break;
    } catch {
      if (Date.now() > deadline) throw new Error(`wrangler dev did not start\n${output}`);
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  const products = await fetch(`${base}/api/products`);
  check(products.status === 200, 'the app answers on Workers');
  const home = await (await fetch(`${base}/`)).text();
  // The bait route and key change with the secret, so both are read from the comment.
  const comment = /<!--([\s\S]*?)-->/.exec(home)?.[1] ?? '';
  const route = /\b(?:GET|POST)\s+(\/\S+)/.exec(comment)?.[1];
  const token = /sk_live_\w+/.exec(comment)?.[0];
  check(Boolean(route && token), 'the home page carries the bait comment');
  const env = await (await fetch(`${base}/.env`, { headers: { 'user-agent': 'python-requests/2.32' } })).text();
  check(/^NODE_ENV=production$/m.test(env), 'serves the bait .env file');
  // An SQL injection probe is answered, and the engine decides how.
  const probe = await fetch(`${base}/api/products?id=1'%20OR%20'1'%3D'1`);
  check(probe.status < 500, `the engine handles an attack without crashing (${probe.status})`);
  if (route && token) {
    await fetch(`${base}${route}`, { headers: { authorization: `Bearer ${token}` } });
    check((await fetch(`${base}/api/products`)).status === 403, 'the machine that used the bait key is blocked');
  }
} finally {
  await stop();
}
console.log(failures.length ? `${failures.length} check(s) failed on Workers` : 'all checks passed on Workers');
if (failures.length) process.exit(1);
