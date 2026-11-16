/**
 * The framework-agnostic Kagami guard. Framework adapters (Express, Hono,
 * Fastify, ...) translate their request objects into `HttpRequest` and call
 * `inspect` / `response` / `decorate*`.
 *
 * Fail-open is a hard rule. No public method throws, and any internal fault
 * results in the request passing through untouched.
 */
import { Core, KagamiCoreError } from './core.js';
import { EnforcerPipeline } from './enforce.js';
import { processEnv, hasProcess, randomHex, type Env } from './platform.js';
import { consoleSink, Pipeline } from './sinks.js';
import type { ContainedMachine, Enforcer, HttpRequest, KagamiOptions, KagamiStats, Mode, ResponseSample, Verdict } from './types.js';

const PASS: Omit<Verdict, 'session' | 'source'> = {
  score: 0,
  state: 'clean',
  action: { type: 'pass' },
  delayMs: 0,
  decorateHtml: false,
  decorateJson: false,
  rules: [],
  contained: false,
  capture: false,
  containment: [],
};

interface CoreEntry {
  source: string;
  target: string;
  public: boolean;
  reason: string;
  since_ms: number;
  until_ms: number;
}

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
  contained?: boolean;
  capture?: boolean;
  contain?: CoreEntry[];
  events: string[];
}

const machine = (e: CoreEntry): ContainedMachine => ({
  source: e.source,
  target: e.target,
  public: e.public,
  reason: e.reason,
  since: e.since_ms,
  until: e.until_ms,
});

/** Response headers the core needs. Values of `set-cookie` are never passed on, only its presence. */
const SAMPLE_HEADERS = new Set(['content-type', 'cache-control', 'location']);

function sampleHeaders(headers: Array<[string, string]>): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const [k, v] of headers) {
    const name = k.toLowerCase();
    if (SAMPLE_HEADERS.has(name)) out.push([name, String(v).slice(0, 1024)]);
    else if (name === 'set-cookie') out.push(['set-cookie', '1']);
  }
  return out;
}

/** KAGAMI_CONTAINMENT is on, true, 1, shadow or block. Anything else leaves containment off. */
function envContainment(env: Env): KagamiOptions['containment'] {
  const v = env.KAGAMI_CONTAINMENT?.trim().toLowerCase() ?? '';
  if (v === 'shadow' || v === 'block') return { action: v };
  return ['on', 'true', '1', 'yes'].includes(v) ? true : undefined;
}

function envFlag(env: Env, name: string): boolean {
  const v = env[name];
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
  if (o.clientAddress) {
    const c = o.clientAddress;
    cfg.client_ip = {
      ...(c.trustedProxies && { trusted_proxies: c.trustedProxies }),
      ...(c.cloudflare !== undefined && { cloudflare: c.cloudflare }),
      ...(c.cloudflareRanges && { cloudflare_ranges: c.cloudflareRanges }),
    };
  }
  if (o.maxEventsPerMinute !== undefined) cfg.max_events_per_minute = o.maxEventsPerMinute;
  if (o.maxSessions !== undefined) cfg.max_sessions = o.maxSessions;
  if (o.containment) {
    const c = o.containment === true ? {} : o.containment;
    cfg.containment = {
      enabled: true,
      ...(c.trigger !== undefined && { trigger: c.trigger }),
      ...(c.action !== undefined && { action: c.action }),
      ...(c.ttlSeconds !== undefined && { ttl_secs: c.ttlSeconds }),
      ...(c.allow !== undefined && { allow: c.allow }),
      ...(c.maxEntries !== undefined && { max_entries: c.maxEntries }),
      ...(c.shadowCacheBytes !== undefined && { shadow_cache_bytes: c.shadowCacheBytes }),
    };
  }
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
  private readonly enforcement: EnforcerPipeline;

  constructor(options: KagamiOptions = {}) {
    const logger = options.logger ?? console;
    this.warn = (m) => {
      try {
        logger.warn(m);
      } catch {
        /* never throw from logging */
      }
    };
    const env = options.env ?? processEnv();
    const envMode = env.KAGAMI_MODE;
    this.mode = options.mode ?? (envMode === 'protect' || envMode === 'observe' ? envMode : 'observe');
    this.maxBodyBytes = options.maxBodyBytes ?? 16 * 1024;
    this.instanceId = options.instanceId ?? randomHex(6);
    this.pipeline = new Pipeline(options.sinks ?? [consoleSink()], this.warn);
    this.enabled = options.enabled !== false && !envFlag(env, 'KAGAMI_DISABLED');
    // Containment can be switched on from the environment as well, so a
    // deployment can be configured without code changes.
    options = { ...options, containment: options.containment ?? envContainment(env) };
    // Enforcers only start when Kagami runs, so the kill switch also stops them.
    const enforcers = this.enabled ? [...(options.enforcers ?? [])] : [];
    this.enforcement = new EnforcerPipeline(enforcers, this.warn);
    if ((options.enforcers?.length ?? 0) > 0 && !options.containment) {
      this.warn('[kagami] Enforcers are configured but containment is off, so they will receive nothing. Set `containment: true` or KAGAMI_CONTAINMENT=on.');
    }
    if (!this.enabled) return;

    let secret = options.secret ?? env.KAGAMI_SECRET ?? '';
    if (!secret) {
      // A temporary secret is only for local development. In production, and
      // on runtimes without a process such as Cloudflare Workers, where every
      // copy of the app would get a different secret, Kagami stays off instead.
      if (env.NODE_ENV === 'production' || !hasProcess()) {
        this.warn(
          '[kagami] KAGAMI_SECRET is not set, so Kagami is disabled and requests pass through untouched. ' +
            'Generate a secret with `npx @agenticslabs/kagami secret`.',
        );
        this.enabled = false;
        return;
      }
      secret = randomHex(32);
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
      peer: req.peer ?? '',
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
      const containment = (r.contain ?? []).map(machine);
      if (containment.length) this.enforcement.push('contain', containment);
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
        contained: r.contained ?? false,
        capture: r.capture ?? false,
        containment,
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
   * Report the response. Enumeration and brute-force detection use the status.
   * Pass `sample` (headers and body) when the verdict asked for it with
   * `capture`, and for a 401 while `wants401Body` is true. The core keeps
   * only what a shared cache could keep, and only the presence of
   * `set-cookie`, never its value.
   */
  response(req: HttpRequest, status: number, sample?: ResponseSample): void {
    const core = this.live();
    if (!core) return;
    try {
      const extra: Record<string, unknown> = { status };
      // Bodies over 64 KiB are never replayed, so they are not sent at all.
      if (sample && sample.body.length <= 65_536) {
        extra.response_headers = sampleHeaders(sample.headers);
        extra.response_body = sample.body;
      }
      const r = core.call<{ events: string[]; learned_401?: boolean }>('response', this.wire({ ...req, body: '' }, extra));
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
      const r = core.call<{ valid: boolean; value: string | null; contain?: CoreEntry[]; events: string[] }>('verify_sealed', {
        request: this.wire({ ...req, body: '' }),
        sealed,
        name,
      });
      if (r.events.length) this.pipeline.push(r.events);
      if (r.contain?.length) this.enforcement.push('contain', r.contain.map(machine));
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

  /**
   * Machines contained right now, soonest expiry first. The list holds
   * client addresses, so keep it away from untrusted callers. Use it to feed
   * your own firewall, WAF or dashboard, or see `formatBlocklist`.
   */
  contained(): ContainedMachine[] {
    const core = this.live();
    if (!core) return [];
    try {
      return core.call<{ entries: CoreEntry[] }>('contained', { now_ms: Date.now() }).entries.map(machine);
    } catch (err) {
      this.fault(err);
      return [];
    }
  }

  /**
   * End containment early for an address, an IPv6 /64, or a source id, and
   * tell every enforcer. Returns the machines that were released.
   */
  release(key: string): ContainedMachine[] {
    const core = this.live();
    if (!core) return [];
    try {
      const released = core.call<{ released: CoreEntry[] }>('release', { key: String(key) }).released.map(machine);
      this.enforcement.push('release', released);
      return released;
    } catch (err) {
      this.fault(err);
      return [];
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
      enforced: this.enforcement.enforced,
      enforcerErrors: this.enforcement.errors,
      faults: this.faults,
    };
  }

  /** Wait for queued events and enforcement to finish. */
  async flush(): Promise<void> {
    await Promise.all([this.pipeline.flush(), this.enforcement.flush()]);
  }

  /** Flush and close sinks and enforcers. Call this on shutdown. */
  async close(): Promise<void> {
    await Promise.all([this.pipeline.close(), this.enforcement.close()]);
  }
}
