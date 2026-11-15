/**
 * The framework-agnostic Kagami guard. Framework adapters (Express, Next.js,
 * Fastify, ...) translate their request objects into `HttpRequest` and call
 * `inspect` / `response` / `decorate*`.
 *
 * Fail-open is a hard rule. No public method throws, and any internal fault
 * results in the request passing through untouched.
 */
import { randomBytes } from 'node:crypto';
import { Core, KagamiCoreError } from './core.js';
import { consoleSink, Pipeline } from './sinks.js';
import type { HttpRequest, KagamiOptions, KagamiStats, Mode, Verdict } from './types.js';

const PASS: Omit<Verdict, 'session' | 'source'> = {
  score: 0,
  state: 'clean',
  action: { type: 'pass' },
  delayMs: 0,
  decorateHtml: false,
  decorateJson: false,
  rules: [],
};

interface CoreInspection {
  session: string;
  source: string;
  score: number;
  state: Verdict['state'];
  action: Verdict['action'];
  delay_ms: number;
  decorate_html: boolean;
  decorate_json: boolean;
  rules?: string[];
  events: string[];
}

function envFlag(name: string): boolean {
  const v = process.env[name];
  return v === '1' || v === 'true' || v === 'yes';
}

function buildCoreConfig(o: KagamiOptions, secret: string, mode: Mode): Record<string, unknown> {
  const cfg: Record<string, unknown> = { secret, mode };
  const d = o.decoys ?? {};
  if (d.html !== undefined) cfg.html_decoys = d.html;
  if (d.json !== undefined) cfg.json_decoys = d.json;
  if (d.forms !== undefined) cfg.form_decoys = d.forms;
  if (d.baitFiles !== undefined) cfg.bait_files = d.baitFiles;
  if (d.routes !== undefined) cfg.decoy_routes = d.routes;
  if (d.reservedPaths) cfg.reserved_paths = d.reservedPaths;
  if (d.reservedNames) cfg.reserved_names = d.reservedNames;
  if (o.tarpit !== undefined) {
    const t = typeof o.tarpit === 'boolean' ? { enabled: o.tarpit } : { enabled: true, ...o.tarpit };
    cfg.tarpit = {
      enabled: t.enabled,
      ...('minMs' in t && t.minMs !== undefined ? { min_ms: t.minMs } : {}),
      ...('maxMs' in t && t.maxMs !== undefined ? { max_ms: t.maxMs } : {}),
    };
  }
  if (o.thresholds) cfg.thresholds = { ...(o.thresholds.suspicious !== undefined && { suspicious: o.thresholds.suspicious }), ...(o.thresholds.flagged !== undefined && { flagged: o.thresholds.flagged }) };
  if (o.ignorePaths) cfg.ignore_paths = o.ignorePaths;
  if (o.ipLogging) cfg.ip_logging = o.ipLogging;
  if (o.maxEventsPerMinute !== undefined) cfg.max_events_per_minute = o.maxEventsPerMinute;
  if (o.maxSessions !== undefined) cfg.max_sessions = o.maxSessions;
  return cfg;
}

export class Kagami {
  readonly mode: Mode;
  readonly maxBodyBytes: number;
  private core: Core | null = null;
  private enabled: boolean;
  private deploymentId: string | null = null;
  private readonly pipeline: Pipeline;
  private readonly warn: (m: string) => void;
  private readonly coreConfig: Record<string, unknown> | null = null;
  private readonly instanceId: string;
  private faults = 0;
  private lastRebuild = 0;
  private lastFaultWarn = 0;
  private learned401 = false;

  constructor(options: KagamiOptions = {}) {
    const logger = options.logger ?? console;
    this.warn = (m) => {
      try {
        logger.warn(m);
      } catch {
        /* never throw from logging */
      }
    };
    const envMode = process.env.KAGAMI_MODE;
    this.mode = options.mode ?? (envMode === 'protect' || envMode === 'observe' ? envMode : 'observe');
    this.maxBodyBytes = options.maxBodyBytes ?? 16 * 1024;
    this.instanceId = options.instanceId ?? randomBytes(6).toString('hex');
    this.pipeline = new Pipeline(options.sinks ?? [consoleSink()], this.warn);
    this.enabled = options.enabled !== false && !envFlag('KAGAMI_DISABLED');
    if (!this.enabled) return;

    let secret = options.secret ?? process.env.KAGAMI_SECRET ?? '';
    if (!secret) {
      if (process.env.NODE_ENV === 'production') {
        this.warn(
          '[kagami] KAGAMI_SECRET is not set, so Kagami is disabled and requests pass through untouched. ' +
            'Generate a secret with `npx @agenticslabs/kagami secret`.',
        );
        this.enabled = false;
        return;
      }
      secret = randomBytes(32).toString('hex');
      this.warn('[kagami] No KAGAMI_SECRET set. Using a temporary development secret, so decoys change on every restart.');
    }
    this.coreConfig = buildCoreConfig(options, secret, this.mode);
    try {
      this.boot();
    } catch (err) {
      this.enabled = false;
      const msg = err instanceof KagamiCoreError ? err.message : String(err);
      this.warn(`[kagami] Kagami is disabled and requests pass through untouched. ${msg}`);
    }
  }

  private boot(): void {
    const core = new Core();
    const res = core.call<{ deployment: string; events: string[] }>('init', {
      config: this.coreConfig,
      now_ms: Date.now(),
      instance: this.instanceId,
    });
    this.core = core;
    this.learned401 = false; // a rebuilt core starts without the app's 401 body
    this.deploymentId = res.deployment;
    this.pipeline.push(res.events);
  }

  /** Records an unexpected error. After a trap the core is dropped and rebuilt later. */
  private fault(err: unknown): void {
    this.faults++;
    if (err instanceof WebAssembly.RuntimeError) this.core = null;
    const now = Date.now();
    if (now - this.lastFaultWarn > 60_000) {
      this.lastFaultWarn = now;
      this.warn(`[kagami] Internal error. The request passed through untouched. ${(err as Error)?.message ?? err}`);
    }
  }

  private live(): Core | null {
    if (!this.enabled) return null;
    if (!this.core && Date.now() - this.lastRebuild > 30_000) {
      this.lastRebuild = Date.now();
      try {
        this.boot();
      } catch (err) {
        this.fault(err);
      }
    }
    return this.core;
  }

  get isEnabled(): boolean {
    return this.enabled;
  }

  get deployment(): string | null {
    return this.deploymentId;
  }

  private wire(req: HttpRequest, extra: Record<string, unknown> = {}): Record<string, unknown> {
    let body = req.body ?? '';
    if (body.length > this.maxBodyBytes) body = body.slice(0, this.maxBodyBytes);
    return {
      now_ms: Date.now(),
      ip: req.ip,
      method: req.method,
      host: req.host,
      path: req.path,
      query: req.query,
      headers: req.headers,
      content_type: req.contentType ?? '',
      body_error: req.bodyError ?? '',
      body,
      ...extra,
    };
  }

  /** Inspect a request. Never throws; on any problem returns a pass verdict. */
  inspect(req: HttpRequest): Verdict {
    const core = this.live();
    if (!core) return { session: '', source: '', ...PASS };
    try {
      const r = core.call<CoreInspection>('inspect', this.wire(req));
      if (r.events.length) this.pipeline.push(r.events);
      return {
        session: r.session,
        source: r.source,
        score: r.score,
        state: r.state,
        action: r.action,
        delayMs: r.delay_ms,
        decorateHtml: r.decorate_html,
        decorateJson: r.decorate_json,
        rules: r.rules ?? [],
      };
    } catch (err) {
      this.fault(err);
      return { session: '', source: '', ...PASS };
    }
  }

  /**
   * True until Kagami has seen one of the app's own JSON 401 responses. While
   * it is true, adapters pass the body of 401 responses to `response`, and
   * decoy routes then answer 401 with the same body as the app.
   */
  get wants401Body(): boolean {
    return this.mode === 'protect' && !this.learned401 && this.core !== null;
  }

  /**
   * Report the response status. Enumeration and brute-force detection use it.
   * For a 401, pass the response body and content type while `wants401Body` is true.
   */
  response(req: HttpRequest, status: number, body?: { contentType: string; body: string }): void {
    const core = this.live();
    if (!core) return;
    try {
      const sample = status === 401 && body ? { contentType: body.contentType, body: body.body.slice(0, 1024) } : { body: '' };
      const r = core.call<{ events: string[]; learned_401?: boolean }>('response', this.wire({ ...req, ...sample }, { status }));
      if (r.learned_401) this.learned401 = true;
      if (r.events.length) this.pipeline.push(r.events);
    } catch (err) {
      this.fault(err);
    }
  }

  /**
   * Returns the HTML with bait added, or the original HTML. `path` is the
   * request path. It selects the pages that carry the bait comment.
   */
  decorateHtml(verdict: Verdict, html: string, path = ''): string {
    if (!verdict.decorateHtml || !verdict.session) return html;
    const core = this.live();
    if (!core) return html;
    try {
      return core.call<{ body: string | null }>('decorate_html', { session: verdict.session, path, body: html }).body ?? html;
    } catch (err) {
      this.fault(err);
      return html;
    }
  }

  /** Returns the JSON body with the decoy field added, or the original body. */
  decorateJson(verdict: Verdict, body: string): string {
    if (!verdict.decorateJson) return body;
    const core = this.live();
    if (!core) return body;
    try {
      return core.call<{ body: string | null }>('decorate_json', { session: verdict.session, body }).body ?? body;
    } catch (err) {
      this.fault(err);
      return body;
    }
  }

  /**
   * Seal a server-issued value (an ID, a price, a role) before handing it to a
   * client. Seals are authenticated with the deployment secret, so a client
   * can read them but cannot change them. When Kagami is disabled the value is
   * returned unchanged and `verify` accepts plain values.
   */
  seal(value: string | number): string {
    const core = this.live();
    if (!core) return String(value);
    try {
      return core.call<{ sealed: string }>('seal', { value: String(value) }).sealed;
    } catch (err) {
      this.fault(err);
      return String(value);
    }
  }

  /** Returns the original value, or `null` if the seal was forged (and records the tampering). */
  verify(req: HttpRequest, sealed: string, name = ''): string | null {
    const core = this.live();
    if (!core) return sealed.includes('~') ? sealed.slice(0, sealed.lastIndexOf('~')) : sealed;
    try {
      const r = core.call<{ valid: boolean; value: string | null; events: string[] }>('verify_sealed', {
        request: this.wire({ ...req, body: '' }),
        sealed,
        name,
      });
      if (r.events.length) this.pipeline.push(r.events);
      return r.valid ? r.value : null;
    } catch (err) {
      this.fault(err);
      return null;
    }
  }

  /**
   * Deployment manifest including decoy names. It is for local tooling and
   * tests only and must never be exposed over HTTP.
   */
  manifest(): Record<string, unknown> | null {
    const core = this.live();
    if (!core) return null;
    try {
      return core.call<Record<string, unknown>>('manifest', {});
    } catch (err) {
      this.fault(err);
      return null;
    }
  }

  stats(): KagamiStats {
    return {
      enabled: this.enabled,
      mode: this.mode,
      deployment: this.deploymentId,
      events: this.pipeline.delivered,
      dropped: this.pipeline.dropped,
      sinkErrors: this.pipeline.sinkErrors,
      faults: this.faults,
    };
  }

  /** Wait for queued events to reach every sink. */
  flush(): Promise<void> {
    return this.pipeline.flush();
  }

  /** Flush and close sinks. Call this on shutdown. */
  close(): Promise<void> {
    return this.pipeline.close();
  }
}
