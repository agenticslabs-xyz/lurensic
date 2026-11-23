// A quick check that the package works on Bun and Deno with a real server.
// Run it with `bun test/runtime-smoke.mjs` or `deno run -A test/runtime-smoke.mjs`.
// It starts a server, sends a few requests, and exits non-zero on a failure.
import { lurensic } from '../dist/index.js';

const SECRET = 'runtime-smoke-secret-0123456789abcdef-012345';
const runtime = typeof Bun !== 'undefined' ? 'bun' : typeof Deno !== 'undefined' ? 'deno' : 'node';
const app = (request) => {
  const path = new URL(request.url).pathname;
  if (path === '/') return new Response('<!doctype html><html><body>Home</body></html>', { headers: { 'content-type': 'text/html' } });
  if (path === '/api/products') return Response.json({ products: [] });
  return new Response('not found', { status: 404 });
};
const guarded = lurensic(app, { secret: SECRET, mode: 'protect', decoys: { json: true }, containment: { action: 'block' }, sinks: [], logger: { warn() {} } });

let base;
let stop;
if (runtime === 'bun') {
  const server = Bun.serve({ port: 0, hostname: '127.0.0.1', fetch: guarded.fetch });
  base = `http://127.0.0.1:${server.port}`;
  stop = () => server.stop(true);
} else if (runtime === 'deno') {
  const server = Deno.serve({ port: 0, hostname: '127.0.0.1', onListen() {} }, guarded.fetch);
  base = `http://127.0.0.1:${server.addr.port}`;
  stop = () => server.shutdown();
} else {
  throw new Error('Run this file with Bun or Deno. Node is covered by fetch.test.mjs.');
}

const failures = [];
const check = (ok, what) => (ok ? console.log(`ok   ${what}`) : (failures.push(what), console.log(`FAIL ${what}`)));
try {
  const env = await fetch(`${base}/.env`);
  check((await env.text()).includes('NODE_ENV=production'), 'serves the bait .env file');
  const home = await fetch(`${base}/`);
  check(/<!-- .* -->/.test(await home.text()), 'adds the HTML bait comment');
  const field = guarded.lurensic.manifest().decoys.json_field;
  const products = await (await fetch(`${base}/api/products`)).json();
  check(field in products, 'adds the decoy JSON field');
  await fetch(`${base}/api/products?${field}=admin`);
  const contained = guarded.lurensic.contained().map((m) => m.target);
  check(contained.length === 1 && contained[0] === '127.0.0.1', `contains the real connection address (${contained.join(', ')})`);
  check((await fetch(`${base}/`)).status === 403, 'blocks the contained machine');
} finally {
  await stop();
  await guarded.lurensic.close();
}
console.log(failures.length ? `${failures.length} check(s) failed on ${runtime}` : `all checks passed on ${runtime}`);
if (failures.length) (typeof Deno !== 'undefined' ? Deno : process).exit(1);
