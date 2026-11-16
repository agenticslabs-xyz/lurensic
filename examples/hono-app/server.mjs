// Node entry, for Render, a VPS or Docker. `npm start`.
import { serve } from '@hono/node-server';
import { createApp } from './app.mjs';

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: createApp().fetch, port }, (info) => console.log(`Listening on port ${info.port}`));
