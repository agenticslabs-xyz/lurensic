// An Express app with the published middleware. EXPRESS names the express
// package to load, so the same file checks Express 4 and Express 5. The bundle
// check runs this file after esbuild has bundled it.
import express4 from 'express4';
import express5 from 'express';
import { lurensic } from '@agenticslabs/lurensic-express';

const express = process.env.EXPRESS === 'express4' ? express4 : express5;
const app = express();
app.use(express.json());
const mw = lurensic({ secret: process.env.LURENSIC_SECRET, mode: 'protect', sinks: [], logger: { warn() {} } });
app.use(mw);
app.get('/', (req, res) => res.type('html').send('<!doctype html><html><body><h1>Shop</h1></body></html>'));
app.get('/api/products', (req, res) => res.json({ products: [] }));

const server = await new Promise((r) => {
  const s = app.listen(0, '127.0.0.1', () => r(s));
});
const base = `http://127.0.0.1:${server.address().port}`;
const problems = [];
try {
  const home = await fetch(`${base}/`);
  if (home.status !== 200) problems.push(`home answered ${home.status}`);
  if (!/<!--[\s\S]*-->/.test(await home.text())) problems.push('home page has no bait comment');
  const env = await (await fetch(`${base}/.env`, { headers: { 'user-agent': 'python-requests/2.32' } })).text();
  if (!/^NODE_ENV=production$/m.test(env)) problems.push('/.env bait not served');
} finally {
  server.close();
  await mw.lurensic?.close?.();
}
const version = process.env.EXPRESS === 'express4' ? '4' : '5';
if (problems.length) {
  console.error(`Express ${version}: ${problems.join('; ')}`);
  process.exit(1);
}
console.log(`Express ${version} serves the app and the bait`);
