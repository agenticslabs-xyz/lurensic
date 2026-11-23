// A small Hono shop API with Lurensic, used to test Lurensic on real hosts. The
// same app runs on Node (server.mjs, for Render, a VPS or Docker) and on
// Cloudflare Workers (worker.mjs).
//
// Settings come from the environment: LURENSIC_SECRET, LURENSIC_MODE and
// LURENSIC_CONTAINMENT. ECHO_PATH turns on a route that shows how the host
// passes the visitor's address. Leave it unset outside of testing.
import { Hono } from 'hono';
import { lurensic, peerAddress } from '@agenticslabs/lurensic-hono';

const PRODUCTS = [
  { id: 1, name: 'Trail Runner 2', price: 129 },
  { id: 2, name: 'Rain Shell', price: 189 },
  { id: 3, name: 'Merino Base Layer', price: 74 },
];

const PAGE = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Northfield Outdoor</title></head>
<body>
<h1>Northfield Outdoor</h1>
<ul>${PRODUCTS.map((p) => `<li><a href="/api/products/${p.id}">${p.name}</a></li>`).join('')}</ul>
<form method="post" action="/newsletter"><input name="email" type="email"><button>Sign up</button></form>
</body>
</html>`;

/** Settings from process.env on Node, Bun and Deno, or from the bindings on Workers. */
const setting = (c, name) => (typeof c.env?.[name] === 'string' ? c.env[name] : globalThis.process?.env?.[name]);

export function createApp(options = {}) {
  const app = new Hono();
  const guard = lurensic(options);
  app.use(guard);

  app.get('/', (c) => c.html(PAGE));
  app.get('/api/products', (c) => c.json({ products: PRODUCTS }));
  app.get('/api/products/:id', (c) => {
    const product = PRODUCTS.find((p) => String(p.id) === c.req.param('id'));
    return product ? c.json(product) : c.json({ error: 'not found' }, 404);
  });
  app.post('/newsletter', (c) => c.html('<!doctype html><html><body><p>Thanks for signing up.</p></body></html>', 201));

  // Diagnostics for testing a host. Shows the request headers, the address
  // the runtime reports, and whether Lurensic has contained this visitor.
  app.get('/:echo', async (c, next) => {
    const echo = setting(c, 'ECHO_PATH');
    if (!echo || c.req.param('echo') !== echo) return next();
    const headers = {};
    c.req.raw.headers.forEach((v, k) => (headers[k] = v));
    return c.json({
      peer: peerAddress(c.req.raw, c.env),
      headers,
      lurensic: c.get('lurensic') ? { contained: c.get('lurensic').contained, state: c.get('lurensic').state } : null,
      contained: guard.lurensic.contained().map((m) => ({ target: m.target, reason: m.reason, until: new Date(m.until).toISOString() })),
    });
  });

  app.notFound((c) => c.json({ error: 'not found' }, 404));
  return app;
}
