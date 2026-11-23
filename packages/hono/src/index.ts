/**
 * Lurensic for Hono, on Node, Bun, Deno and Cloudflare Workers.
 *
 *   import { Hono } from 'hono';
 *   import { lurensic } from '@agenticslabs/lurensic-hono';
 *
 *   const app = new Hono();
 *   app.use(lurensic());          // reads LURENSIC_SECRET, starts in observe mode
 *
 * Register it before your routes. Every code path fails open. If anything
 * inside Lurensic goes wrong, the request continues to your app untouched.
 */
import type { MiddlewareHandler } from 'hono';
import { FetchGuard, type FetchAdapterOptions, type Lurensic, type LurensicContext } from '@agenticslabs/lurensic';

export * from '@agenticslabs/lurensic';

/** Add to your app's type, `new Hono<{ Variables: LurensicVariables }>()`, to type `c.get('lurensic')`. */
export type LurensicVariables = { lurensic: LurensicContext };

export type LurensicHonoOptions = FetchAdapterOptions;

export type LurensicMiddleware = MiddlewareHandler & { readonly lurensic: Lurensic };

export function lurensic(options: LurensicHonoOptions = {}): LurensicMiddleware {
  const guard = new FetchGuard(options);
  const middleware: MiddlewareHandler = async (c, next) => {
    let waitUntil: ((p: Promise<unknown>) => void) | undefined;
    try {
      const ec = c.executionCtx;
      waitUntil = ec.waitUntil.bind(ec);
    } catch {
      // Only Cloudflare Workers and similar runtimes have an execution context.
    }
    let ranApp = false;
    const res = await guard.handle(
      c.req.raw,
      c.env,
      async () => {
        try {
          const ctx = guard.context(c.req.raw);
          if (ctx) c.set('lurensic' as never, ctx as never);
        } catch {
          /* fail open */
        }
        ranApp = true;
        await next();
        return c.res;
      },
      waitUntil,
    );
    if (!ranApp) return res;
    if (res !== c.res) {
      // Hono copies the old response's headers onto a new one, which would
      // bring back a stale Content-Length after decoration. Clearing it first
      // keeps the new response's own headers.
      c.res = undefined as unknown as Response;
      c.res = res;
    }
    return undefined;
  };
  Object.defineProperty(middleware, 'lurensic', { get: () => guard.lurensic(), enumerable: false });
  return middleware as LurensicMiddleware;
}

export default lurensic;
