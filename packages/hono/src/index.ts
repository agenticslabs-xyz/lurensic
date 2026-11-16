/**
 * Kagami for Hono, on Node, Bun, Deno and Cloudflare Workers.
 *
 *   import { Hono } from 'hono';
 *   import { kagami } from '@agenticslabs/kagami-hono';
 *
 *   const app = new Hono();
 *   app.use(kagami());          // reads KAGAMI_SECRET, starts in observe mode
 *
 * Register it before your routes. Every code path fails open. If anything
 * inside Kagami goes wrong, the request continues to your app untouched.
 */
import type { MiddlewareHandler } from 'hono';
import { FetchGuard, type FetchAdapterOptions, type Kagami, type KagamiContext } from '@agenticslabs/kagami';

export * from '@agenticslabs/kagami';

/** Add to your app's type, `new Hono<{ Variables: KagamiVariables }>()`, to type `c.get('kagami')`. */
export type KagamiVariables = { kagami: KagamiContext };

export type KagamiHonoOptions = FetchAdapterOptions;

export type KagamiMiddleware = MiddlewareHandler & { readonly kagami: Kagami };

export function kagami(options: KagamiHonoOptions = {}): KagamiMiddleware {
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
          if (ctx) c.set('kagami' as never, ctx as never);
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
  Object.defineProperty(middleware, 'kagami', { get: () => guard.kagami(), enumerable: false });
  return middleware as KagamiMiddleware;
}

export default kagami;
