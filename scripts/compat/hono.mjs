// A Hono app with the published middleware, called through app.request().
import { Hono } from 'hono';
import { lurensic } from '@agenticslabs/lurensic-hono';

const app = new Hono();
app.use(lurensic({ secret: process.env.LURENSIC_SECRET, mode: 'protect', sinks: [], logger: { warn() {} } }));
app.get('/', (c) => c.html('<!doctype html><html><body><h1>Shop</h1></body></html>'));

const env = { incoming: { socket: { remoteAddress: '203.0.113.9' } } };
const problems = [];
const home = await app.request('/', {}, env);
if (home.status !== 200) problems.push(`home answered ${home.status}`);
if (!/<!--[\s\S]*-->/.test(await home.text())) problems.push('home page has no bait comment');
const bait = await (await app.request('/.env', { headers: { 'user-agent': 'python-requests/2.32' } }, env)).text();
if (!/^NODE_ENV=production$/m.test(bait)) problems.push('/.env bait not served');
if (problems.length) {
  console.error(`Hono: ${problems.join('; ')}`);
  process.exit(1);
}
console.log('Hono serves the app and the bait');
