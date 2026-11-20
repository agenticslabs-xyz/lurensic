/**
 * Kagami for any app built on the web-standard Request and Response API.
 * That covers Cloudflare Workers, Deno, Bun, and frameworks such as Hono
 * that expose a `fetch(request)` handler.
 *
 *   import { kagami } from '@agenticslabs/kagami';
 *   export default kagami(app);
 *
 * Every code path fails open. If anything inside Kagami goes wrong, the
 * request goes to the app untouched.
 */
import { Kagami } from './kagami.js';
import { processEnv, type Env } from './platform.js';
import type { HttpRequest, KagamiOptions, Verdict } from './types.js';

export interface FetchAdapterOptions extends KagamiOptions {
  /** Reuse an existing engine instead of creating one. */
  instance?: Kagami;
  /**
   * Find the client address yourself. Prefer `clientAddress`, which lets
   * Kagami do it safely. Without either, the address comes from the runtime.
   * That is `CF-Connecting-IP` on Cloudflare Workers, the connection's
   * address on Deno, Bun and @hono/node-server, and nothing elsewhere.
   */
  clientIp?: (request: Request, platform: unknown) => string | undefined;
  /**
   * Return your app's id for whoever sent the request, such as an account id,
   * so each event says whom to act on. It runs before your app, so it sees
   * only the raw request. Look the account up from your verified session.
   * Never return a cookie, token or session secret, because events are
   * logged. Return undefined for anonymous visitors. An error is ignored.
   */
  subject?: (request: Request, platform: unknown) => string | number | null | undefined;
}

/** Call a developer's `subject` function safely. Kagami never fails because of it. */
export function subjectOf<A extends unknown[]>(fn: ((...args: A) => unknown) | undefined, ...args: A): string | undefined {
  if (typeof fn !== 'function') return undefined;
  try {
    const v = fn(...args);
    if (typeof v === 'string' || typeof v === 'number') {
      const s = String(v).slice(0, 256);
      return s.trim() ? s : undefined;
    }
  } catch {
    /* fail open */
  }
  return undefined;
}

/** What the app can read about the current request, and the seal helpers. */
export interface KagamiContext {
  readonly session: string;
  readonly source: string;
  readonly state: Verdict['state'];
  readonly score: number;
  readonly rules: readonly string[];
  readonly contained: boolean;
  /** Seal a value you hand to the client (ID, price, role). */
  seal(value: string | number): string;
  /** Unseal a value the client sent back. Returns `null` if it was tampered with. */
  verify(sealed: string, name?: string): string | null;
}

type Next = (request: Request) => Promise<Response>;

/** Bodies above this size are passed through without decoration. */
const MAX_DECORATE = 1024 * 1024;
/** The largest body kept for the shadow, as in the Express adapter. */
const MAX_CAPTURE = 64 * 1024;
const ENV_KEYS = ['KAGAMI_SECRET', 'KAGAMI_MODE', 'KAGAMI_DECOYS', 'KAGAMI_SITE', 'KAGAMI_CONTAINMENT', 'KAGAMI_PROXY', 'KAGAMI_DISABLED', 'NODE_ENV', 'RENDER'] as const;
const decoder = new TextDecoder();
const contexts = new WeakMap<Request, KagamiContext>();

/** The Kagami context for a request handled by the fetch or Hono adapter. */
export function kagamiContext(request: Request): KagamiContext | undefined {
  return contexts.get(request);
}

const isWorkers = (): boolean => (globalThis as { navigator?: { userAgent?: string } }).navigator?.userAgent === 'Cloudflare-Workers';

/**
 * The connection's address, from whatever the runtime passes next to the
 * request. Deno passes `{ remoteAddr }`, Bun passes its server, which has
 * `requestIP()`, and @hono/node-server passes `{ incoming }`. On Cloudflare
 * Workers, Cloudflare sets `CF-Connecting-IP` itself and replaces any value
 * a client sends, so it is the connection's address.
 */
export function peerAddress(request: Request, platform: unknown): string {
  try {
    const p = platform as {
      remoteAddr?: { hostname?: string };
      requestIP?: (r: Request) => { address?: string } | null;
      incoming?: { socket?: { remoteAddress?: string } };
      event?: { requestContext?: { http?: { sourceIp?: string }; identity?: { sourceIp?: string } } };
    } | null;
    if (p?.remoteAddr?.hostname) return p.remoteAddr.hostname;
    if (typeof p?.requestIP === 'function') return p.requestIP(request)?.address ?? '';
    if (p?.incoming?.socket?.remoteAddress) return p.incoming.socket.remoteAddress;
    // AWS Lambda through Hono's adapter. API Gateway sets the source address.
    const rc = p?.event?.requestContext;
    if (rc?.http?.sourceIp || rc?.identity?.sourceIp) return rc.http?.sourceIp ?? rc.identity?.sourceIp ?? '';
    if (isWorkers() || 'cf' in request) return request.headers.get('cf-connecting-ip') ?? '';
  } catch {
    /* fall through */
  }
  return '';
}

/** Kagami settings from Cloudflare Workers bindings, which arrive with each request instead of in process.env. */
function bindingsEnv(platform: unknown): Env {
  const out: Env = {};
  if (!platform || typeof platform !== 'object') return out;
  for (const key of ENV_KEYS) {
    const v = (platform as Record<string, unknown>)[key];
    if (typeof v === 'string') out[key] = v;
  }
  return out;
}

async function readText(stream: ReadableStream<Uint8Array>, limit: number): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (size < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.byteLength;
    }
  } finally {
    reader.cancel().catch(() => undefined);
  }
  return decoder.decode(concat(chunks, size)).slice(0, limit);
}

function concat(chunks: Uint8Array[], size: number): Uint8Array {
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

/**
 * Read a response body up to `limit` bytes. When it is longer, the bytes
 * already read are put back in front of the rest, so the body still streams
 * to the client unchanged.
 */
async function readUpTo(
  stream: ReadableStream<Uint8Array>,
  limit: number,
): Promise<{ complete: true; bytes: Uint8Array } | { complete: false; stream: ReadableStream<Uint8Array> }> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return { complete: true, bytes: concat(chunks, size) };
    chunks.push(value);
    size += value.byteLength;
    if (size > limit) {
      return {
        complete: false,
        stream: new ReadableStream<Uint8Array>({
          start(controller) {
            for (const c of chunks) controller.enqueue(c);
          },
          async pull(controller) {
            const r = await reader.read();
            if (r.done) controller.close();
            else controller.enqueue(r.value);
          },
          cancel(reason) {
            return reader.cancel(reason);
          },
        }),
      };
    }
  }
}

/** The response headers the shadow uses. Only the presence of `set-cookie` matters. */
function sampleHeaders(headers: Headers): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const name of ['content-type', 'cache-control', 'location', 'set-cookie']) {
    const v = headers.get(name);
    if (v !== null) out.push([name, v]);
  }
  return out;
}

/**
 * The shared request handling behind `kagami(app)` and the Hono middleware.
 * Adapters for other web-standard frameworks can use it the same way.
 */
export class FetchGuard {
  private engine: Kagami | undefined;

  constructor(private readonly options: FetchAdapterOptions = {}) {
    this.engine = options.instance;
  }

  /**
   * With `clientAddress`, `KAGAMI_PROXY` or the automatic Render setting,
   * the core resolves the client address from the peer and the headers. A
   * custom `clientIp` function takes precedence.
   */
  private get resolveInCore(): boolean {
    return !this.options.clientIp && (this.engine?.resolvesClientAddress ?? false);
  }

  /**
   * The engine. It is created on first use, so on Cloudflare Workers it can
   * read the settings that arrive with the first request.
   */
  kagami(platform?: unknown): Kagami {
    if (!this.engine) {
      // On Cloudflare Workers, bindings arrive with the request. `store` can
      // be a function that picks one, and a binding named KAGAMI_STORE is
      // used without any code.
      let store: unknown = this.options.store;
      try {
        if (typeof store === 'function') store = (store as (platform: unknown) => unknown)(platform);
        else if (store === undefined && platform && typeof platform === 'object') {
          const binding = (platform as Record<string, unknown>).KAGAMI_STORE;
          if (binding && typeof binding === 'object') store = binding;
        }
      } catch {
        store = undefined;
      }
      this.engine = new Kagami({ ...this.options, store, env: this.options.env ?? { ...processEnv(), ...bindingsEnv(platform) } });
    }
    return this.engine;
  }

  /** The Kagami context of a request this guard is handling. */
  context(request: Request): KagamiContext | undefined {
    return contexts.get(request);
  }

  async handle(request: Request, platform: unknown, next: Next, waitUntil?: (p: Promise<unknown>) => void): Promise<Response> {
    let k: Kagami;
    let info: HttpRequest;
    let verdict: Verdict;
    try {
      k = this.kagami(platform);
      if (!k.isEnabled) return next(request);
      info = await this.describe(request, platform, k.maxBodyBytes);
      // Without a client address every visitor would look like one machine,
      // and one tripwire would contain everybody. Kagami steps aside instead.
      if (!info.ip && !info.peer) {
        this.noAddress();
        return next(request);
      }
      if (k.usesStore) await k.prepare(info);
      verdict = k.inspect(info);
    } catch {
      return next(request);
    }
    try {
      if (verdict.delayMs > 0) await new Promise((r) => setTimeout(r, verdict.delayMs));
      contexts.set(request, {
        session: verdict.session,
        source: verdict.source,
        state: verdict.state,
        score: verdict.score,
        rules: verdict.rules,
        contained: verdict.contained,
        seal: (value) => k.seal(value),
        verify: (sealed, name) => k.verify(info, sealed, name),
      });
    } catch {
      /* fail open */
    }

    const action = verdict.action;
    if (action.type === 'respond') {
      try {
        const res = new Response(action.body, { status: action.status, headers: action.headers });
        k.response(info, action.status);
        this.background(k, waitUntil);
        return res;
      } catch {
        /* fall through to the app */
      }
    }

    const res = await next(request);
    try {
      return await this.afterResponse(k, info, verdict, res);
    } catch {
      return res;
    } finally {
      this.background(k, waitUntil);
    }
  }

  /** Kagami's view of the request. The app still receives the original, unread body. */
  private async describe(request: Request, platform: unknown, maxBody: number): Promise<HttpRequest> {
    const url = new URL(request.url);
    const headers: Array<[string, string]> = [];
    request.headers.forEach((value, name) => headers.push([name, value]));
    const peer = peerAddress(request, platform);
    let body: string | undefined;
    if (request.body && request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        const clone = request.clone();
        if (clone.body) body = await readText(clone.body, maxBody);
      } catch {
        body = undefined;
      }
    }
    const contentType = request.headers.get('content-type') ?? undefined;
    const subject = subjectOf(this.options.subject, request, platform);
    return {
      ip: this.options.clientIp?.(request, platform) ?? peer,
      ...(this.resolveInCore && { peer }),
      ...(subject !== undefined && { subject }),
      method: request.method,
      host: request.headers.get('host') ?? url.host,
      path: url.pathname,
      query: url.search.slice(1),
      headers,
      ...(body !== undefined && { body }),
      ...(body !== undefined && contentType !== undefined && { contentType }),
    };
  }

  /** Decorate the app's response and give the shadow a copy when the core asks for one. */
  private async afterResponse(k: Kagami, info: HttpRequest, verdict: Verdict, res: Response): Promise<Response> {
    const status = res.status;
    const ct = (res.headers.get('content-type') ?? '').toLowerCase();
    const wanted = verdict.capture || (status === 401 && k.wants401Body);
    const redirect = status >= 300 && status < 400;
    const decorate = status === 200 && ((verdict.decorateJson && ct.includes('json')) || (verdict.decorateHtml && ct.includes('text/html')));
    const charsetOk = !/charset=/.test(ct) || /charset="?utf-8/.test(ct);
    const readable = Boolean(res.body) && !res.headers.get('content-encoding') && !ct.includes('event-stream') && charsetOk;

    if (!(wanted || decorate) || !readable) {
      k.response(info, status, wanted && redirect ? { headers: sampleHeaders(res.headers), body: '' } : undefined);
      return res;
    }
    const read = await readUpTo(res.body!, MAX_DECORATE);
    if (!read.complete) {
      k.response(info, status);
      return new Response(read.stream, { status, statusText: res.statusText, headers: res.headers });
    }
    const text = decoder.decode(read.bytes);
    let out = text;
    if (decorate) {
      try {
        out = verdict.decorateJson && ct.includes('json') ? k.decorateJson(verdict, text) : k.decorateHtml(verdict, text, info.path);
      } catch {
        out = text;
      }
    }
    // The shadow keeps the app's own body, never Kagami's bait.
    const sample = wanted && (text.length <= MAX_CAPTURE || redirect) ? { headers: sampleHeaders(res.headers), body: text.length <= MAX_CAPTURE ? text : '' } : undefined;
    k.response(info, status, sample);
    const headers = new Headers(res.headers);
    headers.delete('content-length');
    return new Response(out === text ? read.bytes : out, { status, statusText: res.statusText, headers });
  }

  private warnedNoAddress = false;

  private noAddress(): void {
    if (this.warnedNoAddress) return;
    this.warnedNoAddress = true;
    try {
      (this.options.logger ?? console).warn(
        '[kagami] The client address is unknown on this runtime, so Kagami lets requests through untouched. ' +
          'Pass clientIp, for example clientIp: (request) => request.headers.get("x-nf-client-connection-ip") on Netlify. ' +
          'See docs/guides/choose-your-setup.md.',
      );
    } catch {
      /* never throw from logging */
    }
  }

  /** On Cloudflare Workers, events and enforcers finish after the response is sent. */
  private background(k: Kagami, waitUntil?: (p: Promise<unknown>) => void): void {
    if (!waitUntil) return;
    try {
      waitUntil(k.flush());
    } catch {
      /* fail open */
    }
  }
}

type FetchHandler = (request: Request, ...rest: never[]) => Response | Promise<Response>;

/** A `fetch` handler wrapped by Kagami. `kagami` gives access to the engine. */
export interface GuardedApp {
  fetch(request: Request, ...rest: unknown[]): Promise<Response>;
  readonly kagami: Kagami;
}

/**
 * Wrap any app with a `fetch(request)` handler, such as a Hono app, or the
 * handler function itself. On Cloudflare Workers, Deno and Bun the result can
 * be the module's default export.
 */
export function kagami(app: FetchHandler | { fetch: FetchHandler }, options: FetchAdapterOptions = {}): GuardedApp {
  const guard = new FetchGuard(options);
  const handler = (typeof app === 'function' ? app : app.fetch.bind(app)) as (request: Request, ...rest: unknown[]) => Response | Promise<Response>;
  const wrapped = {
    fetch(request: Request, ...rest: unknown[]): Promise<Response> {
      const ctx = rest[1] as { waitUntil?: (p: Promise<unknown>) => void } | undefined;
      const waitUntil = typeof ctx?.waitUntil === 'function' ? ctx.waitUntil.bind(ctx) : undefined;
      return guard.handle(request, rest[0], async (req) => handler(req, ...rest), waitUntil);
    },
  };
  // Not enumerable, so platforms that look at the default export's handlers
  // only see `fetch`. Reading it creates the engine from process.env if no
  // request has created it yet.
  Object.defineProperty(wrapped, 'kagami', { get: () => guard.kagami(), enumerable: false });
  return wrapped as GuardedApp;
}
