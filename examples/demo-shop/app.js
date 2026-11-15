// Northwind Outfitters: a deliberately ordinary web shop used to demonstrate
// and benchmark Kagami. It has a login, a JSON API, a search page and order
// IDs that are sealed with Kagami. It contains no real vulnerabilities; any
// "finding" an attacking agent reports against it came from Kagami's decoys.
import express from 'express';
import { kagami } from '@agenticslabs/kagami-express';

const PRODUCTS = [
  { id: 1, name: 'Ridgeline Rain Shell', price: 189, category: 'jackets' },
  { id: 2, name: 'Harbour Wool Beanie', price: 35, category: 'accessories' },
  { id: 3, name: 'Summit Down Vest', price: 149, category: 'jackets' },
  { id: 4, name: 'Trailhead Merino Tee', price: 79, category: 'tops' },
  { id: 5, name: 'Coastal Canvas Tote', price: 49, category: 'accessories' },
];
const USERS = new Map([['demo@northwind.test', { id: 101, name: 'Demo Customer', password: 'demo1234', role: 'customer' }]]);
const ORDERS = [
  { id: 5001, user: 101, total: 224, items: [1, 2] },
  { id: 5002, user: 101, total: 79, items: [4] },
];
const sessions = new Map();

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(title, body, user) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)} · Northwind Outfitters</title>
<style>
  body{font-family:system-ui,sans-serif;margin:0;color:#1d2433;background:#f6f7f9}
  header{background:#1d2433;color:#fff;padding:14px 24px;display:flex;gap:24px;align-items:center}
  header a{color:#fff;text-decoration:none} header .brand{font-weight:700;margin-right:auto}
  main{max-width:960px;margin:24px auto;padding:0 16px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px}
  .card{background:#fff;border-radius:10px;padding:16px;box-shadow:0 1px 3px #0001}
  input,button{font:inherit;padding:8px 10px;border-radius:6px;border:1px solid #c8ccd4}
  button{background:#1d2433;color:#fff;border:0;cursor:pointer}
</style>
</head>
<body>
<header><a class="brand" href="/">Northwind Outfitters</a><a href="/products">Shop</a><a href="/search">Search</a>${
    user ? `<a href="/account">${esc(user.name)}</a>` : '<a href="/login">Sign in</a>'
  }</header>
<main>
${body}
</main>
<footer style="max-width:960px;margin:40px auto;padding:0 16px;color:#6b7280;font-size:13px">Demo store for security research. No real products, accounts or orders.</footer>
</body>
</html>`;
}

function currentUser(req) {
  const sid = /(?:^|;\s*)nw_session=([a-f0-9]+)/.exec(req.headers.cookie ?? '')?.[1];
  return sid ? sessions.get(sid) : undefined;
}

const SENSITIVE = /pass|pwd|secret|token|key|auth|session|cookie/i;

function redactQuery(q) {
  if (!q) return '';
  return q
    .split('&')
    .map((pair) => {
      const [k] = pair.split('=');
      return SENSITIVE.test(decodeURIComponent(k ?? '')) ? `${k}=[REDACTED]` : pair;
    })
    .join('&')
    .slice(0, 2048);
}

/**
 * @param kagamiOptions options for the Kagami middleware
 * @param demo.trustProxy Express "trust proxy" setting (default: loopback)
 * @param demo.accessLog optional fn(record): full request log for research.
 *   Records header *names* in arrival order (client fingerprinting), never
 *   header values other than the user agent, never bodies.
 */
export function createApp(kagamiOptions = {}, demo = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', demo.trustProxy ?? 'loopback');

  // Keep the fake shop out of search engines. Set before Kagami so decoy
  // responses carry the same headers as real ones.
  app.use((_req, res, next) => {
    res.setHeader('x-robots-tag', 'noindex, nofollow');
    next();
  });

  if (demo.accessLog) {
    app.use((req, res, next) => {
      const start = process.hrtime.bigint();
      res.once('finish', () => {
        try {
          const url = req.originalUrl ?? req.url;
          const q = url.indexOf('?');
          const names = [];
          for (let i = 0; i < req.rawHeaders.length; i += 2) names.push(req.rawHeaders[i]);
          demo.accessLog({
            ts: new Date().toISOString(),
            ip: kagamiOptions.clientIp?.(req) ?? req.ip,
            method: req.method,
            path: (q === -1 ? url : url.slice(0, q)).slice(0, 1024),
            query: q === -1 ? '' : redactQuery(url.slice(q + 1)),
            status: res.statusCode,
            ms: Number(process.hrtime.bigint() - start) / 1e6,
            ua: (req.get('user-agent') ?? '').slice(0, 512),
            header_order: names,
            http_version: req.httpVersion,
            kagami: req.kagami ? { session: req.kagami.session, state: req.kagami.state, score: req.kagami.score } : null,
          }, req);
        } catch {
          /* research logging must never affect the app */
        }
      });
      next();
    });
  }

  app.use(express.json({ limit: '64kb' }));
  app.use(express.urlencoded({ extended: false, limit: '64kb' }));

  const guard = kagami({
    mode: 'protect',
    decoys: { json: true, reservedNames: ['name', 'email', 'role'] },
    ignorePaths: ['/healthz'],
    ...kagamiOptions,
  });
  app.use(guard);

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  app.get('/', (req, res) => {
    const cards = PRODUCTS.slice(0, 3)
      .map((p) => `<div class="card"><h3><a href="/products/${p.id}">${esc(p.name)}</a></h3><p>$${p.price}</p></div>`)
      .join('');
    res.send(page('Home', `<h1>Gear for wild weather</h1><div class="grid">${cards}</div>`, currentUser(req)));
  });

  app.get('/products', (req, res) => {
    const cat = String(req.query.category ?? '');
    const list = PRODUCTS.filter((p) => !cat || p.category === cat);
    const cards = list
      .map((p) => `<div class="card"><h3><a href="/products/${p.id}">${esc(p.name)}</a></h3><p>$${p.price}</p></div>`)
      .join('');
    res.send(page('Shop', `<h1>Shop</h1><div class="grid">${cards}</div>`, currentUser(req)));
  });

  app.get('/products/:id', (req, res) => {
    const p = PRODUCTS.find((x) => String(x.id) === req.params.id);
    if (!p) return res.status(404).send(page('Not found', '<h1>Not found</h1>', currentUser(req)));
    res.send(page(p.name, `<h1>${esc(p.name)}</h1><p>$${p.price}</p><button>Add to cart</button>`, currentUser(req)));
  });

  app.get('/search', (req, res) => {
    const q = String(req.query.q ?? '');
    const hits = PRODUCTS.filter((p) => q && p.name.toLowerCase().includes(q.toLowerCase()));
    const list = hits.map((p) => `<li><a href="/products/${p.id}">${esc(p.name)}</a></li>`).join('');
    res.send(
      page(
        'Search',
        `<h1>Search</h1><form><input name="q" value="${esc(q)}"> <button>Search</button></form>` +
          (q ? `<p>${hits.length} result(s) for “${esc(q)}”</p><ul>${list}</ul>` : ''),
        currentUser(req),
      ),
    );
  });

  app.get('/login', (req, res) => {
    res.send(
      page(
        'Sign in',
        `<h1>Sign in</h1><form method="post" action="/login" class="card">
<p><input name="email" type="email" placeholder="Email" required></p>
<p><input name="password" type="password" placeholder="Password" required></p>
<p><button>Sign in</button></p></form>`,
        currentUser(req),
      ),
    );
  });

  app.post('/login', (req, res) => {
    const email = String(req.body?.email ?? '');
    const password = String(req.body?.password ?? '');
    const user = USERS.get(email);
    if (!user || user.password !== password) {
      return res.status(401).send(page('Sign in', '<h1>Sign in</h1><p>Invalid email or password.</p>', undefined));
    }
    const sid = crypto.randomUUID().replace(/-/g, '');
    sessions.set(sid, user);
    res.setHeader('set-cookie', `nw_session=${sid}; HttpOnly; SameSite=Lax; Path=/`);
    res.redirect(303, '/account');
  });

  app.get('/account', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.redirect(303, '/login');
    res.send(page('Account', `<h1>Hi ${esc(user.name)}</h1><p><a href="/api/orders">Your orders (JSON)</a></p>`, user));
  });

  // JSON API
  app.get('/api/products', (_req, res) => res.json({ products: PRODUCTS }));

  app.get('/api/me', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    res.json({ id: user.id, name: user.name, email: [...USERS].find(([, u]) => u === user)?.[0], role: user.role });
  });

  app.patch('/api/me', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    if (typeof req.body?.name === 'string') user.name = req.body.name.slice(0, 80);
    res.json({ id: user.id, name: user.name, role: user.role });
  });

  // Order IDs are sealed: clients can read them but cannot forge neighbours.
  app.get('/api/orders', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    const orders = ORDERS.filter((o) => o.user === user.id).map((o) => ({ ...o, id: req.kagami?.seal(o.id) ?? String(o.id) }));
    res.json({ orders });
  });

  app.get('/api/orders/:id', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    const id = req.kagami ? req.kagami.verify(req.params.id, 'order_id') : req.params.id;
    const order = id && ORDERS.find((o) => String(o.id) === id && o.user === user.id);
    if (!order) return res.status(404).json({ error: 'not found' });
    res.json({ ...order, id: req.params.id });
  });

  app.use((req, res) => res.status(404).send(page('Not found', '<h1>Not found</h1>', currentUser(req))));

  return Object.assign(app, { kagami: guard.kagami });
}
