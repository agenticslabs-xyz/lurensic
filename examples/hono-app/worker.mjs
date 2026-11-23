// Cloudflare Workers entry. `wrangler dev` locally, `wrangler deploy` to publish.
// Set LURENSIC_SECRET with `wrangler secret put LURENSIC_SECRET`.
import { createApp } from './app.mjs';

export default createApp();
