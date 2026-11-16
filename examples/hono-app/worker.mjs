// Cloudflare Workers entry. `wrangler dev` locally, `wrangler deploy` to publish.
// Set KAGAMI_SECRET with `wrangler secret put KAGAMI_SECRET`.
import { createApp } from './app.mjs';

export default createApp();
