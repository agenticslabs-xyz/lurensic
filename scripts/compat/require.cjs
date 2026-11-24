// A CommonJS app that loads the packages with require().
const { Lurensic } = require('@agenticslabs/lurensic');
const { lurensic: express } = require('@agenticslabs/lurensic-express');
const { lurensic: hono } = require('@agenticslabs/lurensic-hono');

const k = new Lurensic({ secret: process.env.LURENSIC_SECRET, mode: 'observe', sinks: [], logger: { warn() {} } });
const v = k.inspect({ ip: '198.51.100.1', method: 'GET', host: 'app.local', path: '/search', query: "q=1'%20OR%20'1'%3D'1", headers: [['user-agent', 'Mozilla/5.0']] });
if (typeof express !== 'function' || typeof hono !== 'function' || !v.rules.includes('payload.sqli')) {
  console.error('require() loaded the packages but the engine did not detect a test attack');
  process.exit(1);
}
console.log('require() loads all three packages and the engine detects');
