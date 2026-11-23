/**
 * The optional shared store. Contained machines are written to a key-value
 * store, so containment survives restarts and holds across every instance of
 * an app, such as many copies of a Cloudflare Worker or a serverless function.
 *
 * Lurensic has no code for any particular platform. It takes the store object
 * the platform already provides and recognises it by its methods.
 *
 * - Cloudflare Workers KV, or any object with get, put and delete
 * - Deno KV, from `Deno.openKv()`
 * - Netlify Blobs, from `getStore()`
 * - Redis clients such as ioredis, node-redis and Upstash
 *
 * Each value records its own expiry, so a store without expiry works too.
 */

import type { Enforcer } from './types.js';

/** A store as Lurensic uses it. */
export interface StoreDriver {
  readonly kind: string;
  get(key: string): Promise<unknown>;
  put(key: string, value: string, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}

type Fn = (...args: unknown[]) => unknown;
const has = (o: unknown, name: string): boolean => typeof (o as Record<string, unknown>)?.[name] === 'function';
const call = (o: unknown, name: string, ...args: unknown[]): Promise<unknown> =>
  Promise.resolve(((o as Record<string, Fn>)[name] as Fn).apply(o, args));

/** Turns whatever store the platform provides into a StoreDriver, or explains why it cannot. */
export function storeDriver(store: unknown): StoreDriver {
  if (!store || typeof store !== 'object') throw new TypeError(STORE_HELP);
  // Deno KV keys are arrays and values come back wrapped in { value }.
  if (has(store, 'atomic') && has(store, 'get') && has(store, 'set')) {
    return {
      kind: 'Deno KV',
      get: async (key) => ((await call(store, 'get', ['lurensic', key])) as { value?: unknown } | null)?.value ?? null,
      put: async (key, value, ttl) => void (await call(store, 'set', ['lurensic', key], value, { expireIn: ttl * 1000 })),
      delete: async (key) => void (await call(store, 'delete', ['lurensic', key])),
    };
  }
  // Cloudflare Workers KV, and the shape Lurensic documents for any other store.
  if (has(store, 'put') && has(store, 'get') && has(store, 'delete')) {
    return {
      kind: 'key-value store',
      get: (key) => call(store, 'get', key),
      // Workers KV accepts an expiry of 60 seconds or more.
      put: async (key, value, ttl) => void (await call(store, 'put', key, value, { expirationTtl: Math.max(60, ttl) })),
      delete: async (key) => void (await call(store, 'delete', key)),
    };
  }
  // Netlify Blobs has no expiry. The expiry inside each value is used instead.
  if (has(store, 'setJSON') && has(store, 'get') && has(store, 'set')) {
    return {
      kind: 'Netlify Blobs',
      get: (key) => call(store, 'get', key),
      put: async (key, value) => void (await call(store, 'set', key, value)),
      delete: async (key) => void (await call(store, 'delete', key)),
    };
  }
  // Redis clients. ioredis takes the expiry as arguments, node-redis and
  // Upstash take an options object (PX and px).
  if (has(store, 'get') && has(store, 'set') && has(store, 'del')) {
    const ioredis = has(store, 'defineCommand');
    return {
      kind: 'Redis',
      get: (key) => call(store, 'get', key),
      put: async (key, value, ttl) =>
        void (ioredis ? await call(store, 'set', key, value, 'PX', ttl * 1000) : await call(store, 'set', key, value, { PX: ttl * 1000, px: ttl * 1000 })),
      delete: async (key) => void (await call(store, 'del', key)),
    };
  }
  throw new TypeError(STORE_HELP);
}

export const STORE_HELP =
  'The store option takes a key-value store such as Cloudflare Workers KV, Deno KV, Netlify Blobs or a Redis client, or an object with get(key), put(key, value, { expirationTtl }) and delete(key).';

/** What Lurensic keeps per contained machine. The key is the machine's keyed hash, not its address. */
export interface StoredMachine {
  source: string;
  target: string;
  reason: string;
  since_ms: number;
  until_ms: number;
}

export const storeKey = (source: string): string => `lurensic:contained:${source}`;

/** Reads a stored value, which may come back as a string or, from Upstash, already parsed. */
export function parseStored(raw: unknown): StoredMachine | undefined {
  let v: unknown = raw;
  if (typeof raw === 'string') {
    try {
      v = JSON.parse(raw);
    } catch {
      return undefined;
    }
  }
  const m = v as Partial<StoredMachine> | null;
  if (!m || typeof m.source !== 'string' || typeof m.until_ms !== 'number') return undefined;
  return {
    source: m.source,
    target: typeof m.target === 'string' ? m.target : '',
    reason: typeof m.reason === 'string' ? m.reason : '',
    since_ms: typeof m.since_ms === 'number' ? m.since_ms : m.until_ms,
    until_ms: m.until_ms,
  };
}

/**
 * Writes each new containment to the store and removes released ones. It is
 * an enforcer, so writes happen off the request path and a failing store
 * never affects requests. Private addresses are stored too, because the
 * store only serves this app's own instances.
 */
export function storeEnforcer(store: StoreDriver): Enforcer {
  return {
    name: `store (${store.kind})`,
    publicOnly: false,
    async contain(machines) {
      const now = Date.now();
      await Promise.all(
        machines.map((m) =>
          store.put(
            storeKey(m.source),
            JSON.stringify({ source: m.source, target: m.target, reason: m.reason, since_ms: m.since, until_ms: m.until } satisfies StoredMachine),
            Math.max(1, Math.ceil((m.until - now) / 1000)),
          ),
        ),
      );
    },
    async release(machines) {
      await Promise.all(machines.map((m) => store.delete(storeKey(m.source))));
    },
  };
}

/** Resolves with the promise's value, or rejects after `ms`. */
export function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`the store did not answer within ${ms} ms`)), ms);
    p.then(
      (v) => (clearTimeout(t), resolve(v)),
      (e) => (clearTimeout(t), reject(e)),
    );
  });
}
