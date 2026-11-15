/**
 * Kagami for Express.
 *
 *   app.use(express.json());
 *   app.use(express.urlencoded({ extended: false }));
 *   app.use(kagami());          // reads KAGAMI_SECRET, starts in observe mode
 *
 * Mount it after the body parsers, so bodies are inspected, and before your
 * routes. Every code path fails open. If anything inside Kagami goes wrong,
 * the request continues to your app untouched.
 */
import type { ErrorRequestHandler, Request, RequestHandler, Response } from 'express';
import { Kagami, type HttpRequest, type KagamiOptions, type Verdict } from '@agenticslabs/kagami';

export * from '@agenticslabs/kagami';

export interface KagamiRequestContext {
  /** Opaque session id (keyed hash of IP and user agent). */
  readonly session: string;
  /** Keyed hash of the client address. All sessions from one machine share it. */
  readonly source: string;
  readonly state: Verdict['state'];
  readonly score: number;
  /** Seal a value you hand to the client (ID, price, role). */
  seal(value: string | number): string;
  /**
   * Unseal a value the client sent back. Returns `null` if it was tampered
   * with; Kagami records the tampering and flags the session.
   */
  verify(sealed: string, name?: string): string | null;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      kagami?: KagamiRequestContext;
    }
  }
}

export interface KagamiExpressOptions extends KagamiOptions {
  /** Reuse an existing engine instead of creating one. */
  instance?: Kagami;
  /**
   * How to find the real client IP. Defaults to Express's `req.ip` (configure
   * `app.set('trust proxy', ...)` for your proxy chain). Behind a CDN, use its
   * header, e.g. `(req) => req.get('cf-connecting-ip') ?? req.ip`.
   * Getting this right matters because sessions are keyed on IP and user agent.
   */
  clientIp?: (req: Request) => string | undefined;
}

function toHttpRequest(req: Request, maxBody: number, clientIp?: (req: Request) => string | undefined): HttpRequest {
  const url = req.originalUrl ?? req.url ?? '/';
  const q = url.indexOf('?');
  const headers: Array<[string, string]> = [];
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers.push([k, Array.isArray(v) ? v.join(', ') : String(v)]);
  }
  let body: string | undefined;
  let contentType: string | undefined;
  const b: unknown = req.body;
  if (typeof b === 'string') {
    body = b.slice(0, maxBody);
  } else if (Buffer.isBuffer(b)) {
    body = b.subarray(0, maxBody).toString('utf8');
  } else if (b && typeof b === 'object' && Object.keys(b).length > 0) {
    body = JSON.stringify(b).slice(0, maxBody);
    contentType = 'application/json';
  }
  return {
    ip: clientIp?.(req) ?? req.ip ?? req.socket?.remoteAddress ?? '',
    method: req.method,
    host: req.get('host') ?? '',
    path: q === -1 ? url : url.slice(0, q),
    query: q === -1 ? '' : url.slice(q + 1),
    headers,
    ...(body !== undefined && { body }),
    ...(contentType !== undefined && { contentType }),
  };
}

function looksLikeHtml(s: string): boolean {
  const head = s.slice(0, 512).trimStart().toLowerCase();
  return head.startsWith('<!doctype html') || head.startsWith('<html');
}

function wrapSend(res: Response, k: Kagami, verdict: Verdict): void {
  const original = res.send;
  res.send = function patchedSend(this: Response, body?: unknown) {
    let out = body;
    try {
      if (typeof body === 'string' && this.statusCode === 200) {
        const ct = String(this.get('Content-Type') ?? '').toLowerCase();
        if (verdict.decorateJson && ct.includes('json')) {
          out = k.decorateJson(verdict, body);
        } else if (verdict.decorateHtml && (ct.includes('text/html') || (!ct && looksLikeHtml(body)))) {
          out = k.decorateHtml(verdict, body);
        }
      }
    } catch {
      out = body;
    }
    return original.call(this, out);
  } as Response['send'];
}

export type KagamiMiddleware = [RequestHandler, ErrorRequestHandler] & { kagami: Kagami };

/** Body parser failures carry a `type` such as `entity.parse.failed` or `charset.unsupported`. */
function bodyError(err: unknown): { type: string; body: string } | null {
  if (!err || typeof err !== 'object') return null;
  const e = err as { type?: unknown; body?: unknown; status?: unknown };
  const type = typeof e.type === 'string' ? e.type : '';
  if (!/^(entity.|encoding.|charset.|request.)/.test(type)) return null;
  return { type, body: typeof e.body === 'string' ? e.body : '' };
}

/**
 * Returns the middleware and an error handler as a pair, which `app.use`
 * accepts as one argument. The error handler covers requests that a body
 * parser rejected before the middleware ran, so malformed bodies are still
 * inspected. Attackers send them on purpose.
 */
export function kagami(options: KagamiExpressOptions = {}): KagamiMiddleware {
  const k = options.instance ?? new Kagami(options);

  /** Attach the verdict to the request and apply its action. Returns true if Kagami answered. */
  const apply = (req: Request, res: Response, info: HttpRequest, verdict: Verdict, decorate: boolean): boolean => {
    req.kagami = {
      session: verdict.session,
      source: verdict.source,
      state: verdict.state,
      score: verdict.score,
      seal: (value) => k.seal(value),
      verify: (sealed, name) => k.verify(info, sealed, name),
    };
    res.once('finish', () => k.response(info, res.statusCode));
    const action = verdict.action;
    if (action.type === 'respond') {
      try {
        res.status(action.status);
        for (const [name, value] of action.headers) res.setHeader(name, value);
        res.send(action.body);
        return true;
      } catch {
        if (res.headersSent) return true;
      }
    }
    if (decorate && (verdict.decorateHtml || verdict.decorateJson)) {
      try {
        wrapSend(res, k, verdict);
      } catch {
        /* fail open */
      }
    }
    return false;
  };

  const middleware: RequestHandler = (req, res, next) => {
    let info: HttpRequest;
    let verdict: Verdict;
    try {
      info = toHttpRequest(req, k.maxBodyBytes, options.clientIp);
      verdict = k.inspect(info);
    } catch {
      next();
      return;
    }
    const proceed = (): void => {
      if (!apply(req, res, info, verdict, true)) next();
    };
    if (verdict.delayMs > 0) setTimeout(proceed, verdict.delayMs);
    else proceed();
  };

  const errors: ErrorRequestHandler = (err, req, res, next) => {
    const parsed = bodyError(err);
    if (req.kagami || !parsed || res.headersSent) {
      next(err);
      return;
    }
    let info: HttpRequest;
    let verdict: Verdict;
    try {
      info = {
        ...toHttpRequest(req, k.maxBodyBytes, options.clientIp),
        body: parsed.body.slice(0, k.maxBodyBytes),
        contentType: 'text/plain',
        bodyError: parsed.type,
      };
      verdict = k.inspect(info);
    } catch {
      next(err);
      return;
    }
    const proceed = (): void => {
      if (!apply(req, res, info, verdict, false)) next(err);
    };
    if (verdict.delayMs > 0) setTimeout(proceed, verdict.delayMs);
    else proceed();
  };

  return Object.assign([middleware, errors] as [RequestHandler, ErrorRequestHandler], { kagami: k });
}

export default kagami;
