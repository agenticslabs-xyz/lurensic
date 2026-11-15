/**
 * Cloudflare support for Kagami.
 *
 *   import { kagami } from '@agenticslabs/kagami-express';
 *   import { cloudflareClientIp, cloudflareEnforcer } from '@agenticslabs/kagami-cloudflare';
 *
 *   app.use(kagami({
 *     mode: 'protect',
 *     containment: true,
 *     clientIp: cloudflareClientIp(),
 *     enforcers: [cloudflareEnforcer({
 *       apiToken: process.env.CLOUDFLARE_API_TOKEN,
 *       accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
 *       listId: process.env.KAGAMI_CLOUDFLARE_LIST_ID,
 *     })],
 *   }));
 *
 * Kagami itself is provider neutral. This package is one enforcer among
 * several; see `blocklistFile` and `webhookEnforcer` in `@agenticslabs/kagami`.
 */
export { CloudflareApiError, ListsClient, type CloudflareList, type ListItem } from './api.js';
export { CLOUDFLARE_RANGES, cloudflareClientIp, isCloudflareAddress, type ClientIpOptions } from './client-ip.js';
export { cloudflareEnforcer, COMMENT_PREFIX, itemComment, itemExpiry, type CloudflareEnforcerOptions } from './enforcer.js';
