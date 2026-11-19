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
import { Kagami, subjectOf, type HttpRequest, type KagamiOptions, type Verdict } from '@agenticslabs/kagami';

export * from '@agenticslabs/kagami';

export interface KagamiRequestContext {
  /** Opaque session id (keyed hash of IP and user agent). */
  readonly session: string;
  /** Keyed hash of the client address. All sessions from one machine share it. */
  readonly source: string;
  readonly state: Verdict['state'];
  readonly score: number;
  /** Every rule this request matched, including repeats that produce no new event. */
  readonly rules: readonly string[];
  /** The client's machine is contained. In protect mode Kagami answered and the app never sees the request. */
  readonly contained: boolean;
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
   * How to find the real client IP yourself. Prefer `clientAddress`, which
   * lets Kagami do it safely and the same way in every language. Without
   * either, Express's `req.ip` is used (configure `app.set('trust proxy', ...)`).
   * Getting this right matters because sessions and containment are keyed on it.
   */
  clientIp?: (req: Request) => string | undefined;
  /**
   * Return your app's id for whoever sent the request, such as `req.user?.id`,
   * so each event says whom to act on. Never return a cookie, token or session
   * secret, because events are logged. Mount Kagami after your auth
   * middleware for `req.user` to be set when the request is inspected. The
   * function runs again when the response finishes, so events raised then
   * also see ids your routes set. Return undefined for anonymous visitors.
   * An error is ignored.
   */
  subject?: (req: Request) => string | number | null | undefined;
}

function toHttpRequest(
  req: Request,
  maxBody: number,
  clientIp?: (req: Request) => string | undefined,
  resolveInCore = false,
  subjectFn?: (req: Request) => unknown,
): HttpRequest {
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
  const subject = subjectOf(subjectFn, req);
  return {
    ip: clientIp?.(req) ?? req.ip ?? req.socket?.remoteAddress ?? '',
    ...(resolveInCore && { peer: req.socket?.remoteAddress ?? '' }),
    ...(subject !== undefined && { subject }),
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

/** The app's own response body, before any decoration. */
interface Captured {
  body?: string;
}

const MAX_CAPTURE = 64 * 1024;

function wrapSend(res: Response, k: Kagami, verdict: Verdict, path: string, captured: Captured): void {
  const original = res.send;
  res.send = function patchedSend(this: Response, body?: unknown) {
    let out = body;
    try {
      if (typeof body === 'string') {
        // Keep the app's original body for the shadow (`capture`) and for
        // learning the app's 401 format. Kagami's own bait is never stored.
        const wanted = verdict.capture || (this.statusCode === 401 && k.wants401Body);
        if (wanted && body.length <= MAX_CAPTURE) captured.body = body;
      }
      if (typeof body === 'string' && this.statusCode === 200) {
        const ct = String(this.get('Content-Type') ?? '').toLowerCase();
        if (verdict.decorateJson && ct.includes('json')) {
          out = k.decorateJson(verdict, body);
        } else if (verdict.decorateHtml && (ct.includes('text/html') || (!ct && looksLikeHtml(body)))) {
          out = k.decorateHtml(verdict, body, path);
        }
      }
    } catch {
      out = body;
    }
    return original.call(this, out);
  } as Response['send'];
}

/** The response headers the core uses. Only the presence of `set-cookie` matters. */
function responseHeaders(res: Response): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const name of ['content-type', 'cache-control', 'location', 'set-cookie']) {
    const v = res.getHeader(name);
    if (v !== undefined) out.push([name, Array.isArray(v) ? v.join(', ') : String(v)]);
  }
  return out;
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
  // With `clientAddress`, the core resolves the client address from the raw
  // peer and the headers. A custom `clientIp` function takes precedence.
  const resolveInCore = !options.clientIp && Boolean(options.clientAddress);

  /** Attach the verdict to the request and apply its action. Returns true if Kagami answered. */
  const apply = (req: Request, res: Response, info: HttpRequest, verdict: Verdict, decorate: boolean): boolean => {
    req.kagami = {
      session: verdict.session,
      source: verdict.source,
      state: verdict.state,
      rules: verdict.rules,
      contained: verdict.contained,
      score: verdict.score,
      seal: (value) => k.seal(value),
      verify: (sealed, name) => k.verify(info, sealed, name),
    };
    const captured: Captured = {};
    res.once('finish', () => {
      try {
        const status = res.statusCode;
        const wanted = verdict.capture || (status === 401 && k.wants401Body);
        // Redirects are often sent with `res.end`, so they have no captured
        // body. Their headers are all the shadow needs.
        const usable = captured.body !== undefined || (status >= 300 && status < 400);
        // Routes and later middleware may have identified the sender by now.
        const subject = subjectOf(options.subject, req) ?? info.subject;
        k.response({ ...info, ...(subject !== undefined && { subject }) }, status, wanted && usable ? { headers: responseHeaders(res), body: captured.body ?? '' } : undefined);
      } catch {
        /* fail open */
      }
    });
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
    if (decorate && (verdict.decorateHtml || verdict.decorateJson || verdict.capture || k.wants401Body)) {
      try {
        wrapSend(res, k, verdict, info.path, captured);
      } catch {
        /* fail open */
      }
    }
    return false;
  };

  const middleware: RequestHandler = (req, res, next) => {
    let info: HttpRequest;
    try {
      info = toHttpRequest(req, k.maxBodyBytes, options.clientIp, resolveInCore, options.subject);
    } catch {
      next();
      return;
    }
    const run = (): void => {
      let verdict: Verdict;
      try {
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
    // With a shared store, a machine contained by another instance is loaded
    // first. `prepare` never rejects and gives up quickly.
    if (k.usesStore) k.prepare(info).then(run, run);
    else run();
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
        ...toHttpRequest(req, k.maxBodyBytes, options.clientIp, resolveInCore, options.subject),
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
