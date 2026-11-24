// Type checks a small app against the published declarations.
import express from 'express';
import { Hono } from 'hono';
import { Lurensic, type Verdict } from '@agenticslabs/lurensic';
import { lurensic as lurensicExpress } from '@agenticslabs/lurensic-express';
import { lurensic as lurensicHono } from '@agenticslabs/lurensic-hono';

const secret = 'types-check-secret-0123456789abcdef-0123456';

const app = express();
app.use(lurensicExpress({ secret }));

const hono = new Hono();
hono.use(lurensicHono({ secret }));

const k = new Lurensic({ secret });
const v: Verdict = k.inspect({ ip: '198.51.100.1', method: 'GET', host: 'app.local', path: '/', query: '', headers: [] });
export const rules: string[] = v.rules;
