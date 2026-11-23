/**
 * The framework-agnostic Lurensic guard. Framework adapters (Express, Hono,
 * Fastify, ...) translate their request objects into `HttpRequest` and call
 * `inspect` / `response` / `decorate*`.
 *
 * Fail-open is a hard rule. No public method throws, and any internal fault
 * results in the request passing through untouched.
 */
import { Core, LurensicCoreError } from './core.js';
import { EnforcerPipeline } from './enforce.js';
import { describeClientAddress, resolveClientAddress } from './address.js';
import { BUILD_ID, PACKAGE_VERSION } from './build-info.js';
import { processEnv, hasProcess, randomHex, type Env } from './platform.js';
import { consoleSink, detectSink, Pipeline } from './sinks.js';
import { parseStored, storeDriver, storeEnforcer, storeKey, withTimeout, type StoreDriver } from './store.js';

/** How long a machine's store lookup is remembered before it is checked again. */
const STORE_RECHECK_MS = 60_000;
/** How long a request waits for the store before Lurensic carries on without it. */
const STORE_TIMEOUT_MS = 300;
const STORE_CACHE_MAX = 10_000;
import type { ContainedMachine, Enforcer, HttpRequest, LurensicOptions, LurensicStats, Mode, ResponseSample, Verdict } from './types.js';

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

/** LURENSIC_CONTAINMENT is on, true, 1, shadow or block. Anything else leaves containment off. */
function envContainment(env: Env): LurensicOptions['containment'] {
  const v = env.LURENSIC_CONTAINMENT?.trim().toLowerCase() ?? '';
  if (v === 'shadow' || v === 'block') return { action: v };
  return ['on', 'true', '1', 'yes'].includes(v) ? true : undefined;
}

/**
 * LURENSIC_DECOYS turns on the opt-in decoys from the environment, as a list
 * such as `json,forms,spec` or `all`. Settings in code take precedence.
 */
function envDecoys(env: Env): NonNullable<LurensicOptions['decoys']> {
  const names = (env.LURENSIC_DECOYS ?? '').toLowerCase().split(/[\s,]+/).filter(Boolean);
  const all = names.includes('all');
  const out: NonNullable<LurensicOptions['decoys']> = {};
  if (all || names.includes('json')) out.json = true;
  if (all || names.includes('forms')) out.forms = true;
  if (all || names.includes('spec')) out.spec = true;
  return out;
}

function envFlag(env: Env, name: string): boolean {
  const v = env[name];
  return v === '1' || v === 'true' || v === 'yes';
}

function buildCoreConfig(o: LurensicOptions, secret: string, mode: Mode): Record<string, unknown> {
  const cfg: Record<string, unknown> = { secret, mode };
  const d = o.decoys ?? {};
  if (d.html !== undefined) cfg.html_decoys = d.html;
  if (d.json !== undefined) cfg.json_decoys = d.json;
  if (d.forms !== undefined) cfg.form_decoys = d.forms;
  if (d.baitFiles !== undefined) cfg.bait_files = d.baitFiles;
  if (d.routes !== undefined) cfg.decoy_routes = d.routes;
  if (d.spec !== undefined) cfg.spec_decoy = d.spec;
  if (o.site) cfg.site = o.site;
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
  // By now a preset name has been turned into its setting.
  if (o.clientAddress && typeof o.clientAddress === 'object') {
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

export class Lurensic {
  readonly mode: Mode;
  readonly maxBodyBytes: number;
  /**
   * True when Lurensic works out the visitor's address itself, from the
   * `clientAddress` option, `LURENSIC_PROXY` or the automatic Render setting.
   * Adapters then pass the connection's address as `peer`.
   */
  readonly resolvesClientAddress: boolean;
  private core: Core | null = null;
  private enabled: boolean;
  private deploymentId: string | null = null;
  private readonly pipeline: Pipeline;
  private readonly warn: (m: string) => void;
  private readonly coreConfig: Record<string, unknown> | null = null;
  private readonly instanceId: string;
  private faults = 0;
  private lastRebuild = 0;
  private boots = 0;
  /**
   * Contained machines, kept outside the engine. If the engine ever has to be
   * rebuilt after an internal error, they are restored into the new one, so
   * an attacker who triggers the error is not released.
   */
  private readonly containedCopy = new Map<string, ContainedMachine>();
  private lastFaultWarn = 0;
  private learned401 = false;
  private readonly enforcement: EnforcerPipeline;
  private readonly store: StoreDriver | null = null;
  private readonly storeChecked = new Map<string, number>();
  private storeErrors = 0;
  private lastStoreWarn = 0;

  constructor(options: LurensicOptions = {}) {
    const logger = options.logger ?? console;
    this.warn = (m) => {
      try {
        logger.warn(m);
      } catch {
        /* never throw from logging */
      }
    };
    const env = options.env ?? processEnv();
    const envMode = env.LURENSIC_MODE;
    this.mode = options.mode ?? (envMode === 'protect' || envMode === 'observe' ? envMode : 'observe');
    this.maxBodyBytes = options.maxBodyBytes ?? 16 * 1024;
    this.instanceId = options.instanceId ?? randomHex(6);
    const sinks = [...(options.sinks ?? [consoleSink()])];
    if (typeof options.onDetect === 'function') sinks.push(detectSink(options.onDetect, options.detectSeverity));
    this.pipeline = new Pipeline(sinks, this.warn);
    this.enabled = options.enabled !== false && !envFlag(env, 'LURENSIC_DISABLED');
    // Containment, decoys, the site and the address setting can come from the
    // environment as well, so a deployment can be configured without code changes.
    const address = resolveClientAddress(options.clientAddress, env, this.warn);
    this.resolvesClientAddress = address.setting !== undefined;
    options = {
      ...options,
      containment: options.containment ?? envContainment(env),
      decoys: { ...envDecoys(env), ...options.decoys },
      site: options.site ?? env.LURENSIC_SITE,
      clientAddress: address.setting,
    };
    if (options.store !== undefined && options.store !== null) {
      try {
        this.store = storeDriver(options.store);
      } catch (err) {
        this.warn(`[lurensic] The store is not used. ${(err as Error)?.message ?? err}`);
      }
      if (this.store && !options.containment) {
        this.warn('[lurensic] A store is set but containment is off, so nothing is stored. Set `containment: true` or LURENSIC_CONTAINMENT=on.');
      }
    }
    // Enforcers only start when Lurensic runs, so the kill switch also stops them.
    const enforcers = this.enabled ? [...(options.enforcers ?? []), ...(this.store ? [storeEnforcer(this.store)] : [])] : [];
    this.enforcement = new EnforcerPipeline(enforcers, this.warn);
    if ((options.enforcers?.length ?? 0) > 0 && !options.containment) {
      this.warn('[lurensic] Enforcers are configured but containment is off, so they will receive nothing. Set `containment: true` or LURENSIC_CONTAINMENT=on.');
    }
    if (!this.enabled) return;

    let secret = options.secret ?? env.LURENSIC_SECRET ?? '';
    if (!secret) {
      // A temporary secret is only for local development. In production, and
      // on runtimes without a process such as Cloudflare Workers, where every
      // copy of the app would get a different secret, Lurensic stays off instead.
      if (env.NODE_ENV === 'production' || !hasProcess()) {
        this.warn(
          '[lurensic] LURENSIC_SECRET is not set, so Lurensic is disabled and requests pass through untouched. ' +
            'Generate a secret with `npx @agenticslabs/lurensic secret`.',
        );
        this.enabled = false;
        return;
      }
      secret = randomHex(32);
      this.warn('[lurensic] No LURENSIC_SECRET set. Using a temporary development secret, so decoys change on every restart.');
    }
    this.coreConfig = buildCoreConfig(options, secret, this.mode);
    try {
      this.boot();
      // One line at startup, so a deployment's logs show which build runs
      // and how it is set up. A custom logger without `info` stays quiet.
      const info = options.logger ? options.logger.info?.bind(options.logger) : console.info;
      const containment = options.containment
        ? `Containment is on and answers with ${(options.containment === true ? undefined : options.containment.action) ?? 'shadow'}.`
        : 'Containment is off.';
      try {
        info?.(
          `[lurensic] Lurensic ${PACKAGE_VERSION} (build ${BUILD_ID}) started in ${this.mode} mode. ` +
            `${describeClientAddress(address)} ${containment}`,
        );
      } catch {
        /* never throw from logging */
      }
    } catch (err) {
      this.enabled = false;
      const msg = err instanceof LurensicCoreError ? err.message : String(err);
      this.warn(`[lurensic] Lurensic is disabled and requests pass through untouched. ${msg}`);
    }
  }

  private boot(): void {
    const core = new Core();
    // A rebuilt engine gets its own instance id, so its events start a new
    // hash chain and never repeat the ids of the engine it replaces.
    const instance = this.boots === 0 ? this.instanceId : `${this.instanceId}-${this.boots}`;
    const res = core.call<{ deployment: string; events: string[] }>('init', {
      config: this.coreConfig,
      now_ms: Date.now(),
      instance,
    });
    this.boots++;
    this.learned401 = false; // a rebuilt core starts without the app's 401 body
    this.deploymentId = res.deployment;
    this.pipeline.push(res.events);
    const now = Date.now();
    const entries = [...this.containedCopy.values()]
      .filter((m) => m.until > now)
      .map((m) => ({ source: m.source, target: m.target, reason: m.reason, since_ms: m.since, until_ms: m.until }));
    if (entries.length) core.call('restore', { entries, now_ms: now });
    this.core = core;
  }

  /** Keep a copy of newly contained machines, and hand them to the enforcers. */
  private contain(machines: ContainedMachine[]): void {
    if (!machines.length) return;
    const now = Date.now();
    if (this.containedCopy.size >= 10_000) {
      for (const [k, m] of this.containedCopy) if (m.until <= now) this.containedCopy.delete(k);
    }
    for (const m of machines) if (this.containedCopy.size < 10_000 || this.containedCopy.has(m.source)) this.containedCopy.set(m.source, m);
    this.enforcement.push('contain', machines);
  }

  /** Records an unexpected error. After a trap the core is dropped and rebuilt later. */
  private fault(err: unknown): void {
    this.faults++;
    if (err instanceof WebAssembly.RuntimeError) this.core = null;
    const now = Date.now();
    if (now - this.lastFaultWarn > 60_000) {
      this.lastFaultWarn = now;
      this.warn(`[lurensic] Internal error. The request passed through untouched. ${(err as Error)?.message ?? err}`);
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
      subject: req.subject ?? '',
      body,
      ...extra,
    };
  }

  /** True when a shared store is configured. Adapters then await `prepare` before `inspect`. */
  get usesStore(): boolean {
    return this.store !== null && this.enabled;
  }

  /**
   * With a shared store, load this request's machine from it, so a machine
   * contained by another instance of the app is contained here too. Each
   * machine is looked up at most once a minute per instance. Never throws,
   * and gives up after a short wait, so a slow store never holds up a request.
   */
  async prepare(req: HttpRequest): Promise<void> {
    const store = this.store;
    const core = this.live();
    if (!store || !core) return;
    let source: string;
    try {
      source = core.call<{ source: string }>('source', this.wire(req)).source;
    } catch (err) {
      this.fault(err);
      return;
    }
    const now = Date.now();
    const last = this.storeChecked.get(source);
    if (last !== undefined && now - last < STORE_RECHECK_MS) return;
    if (this.storeChecked.size >= STORE_CACHE_MAX) this.storeChecked.clear();
    this.storeChecked.set(source, now);
    try {
      const stored = parseStored(await withTimeout(store.get(storeKey(source)), STORE_TIMEOUT_MS));
      if (stored && stored.source === source && stored.until_ms > Date.now()) {
        this.live()?.call('restore', { entries: [stored], now_ms: Date.now() });
        if (this.containedCopy.size < 10_000) {
          // `public` only matters to enforcers, which never see restored entries.
          this.containedCopy.set(stored.source, {
            source: stored.source,
            target: stored.target,
            public: false,
            reason: stored.reason,
            since: stored.since_ms,
            until: stored.until_ms,
          });
        }
      }
    } catch (err) {
      this.storeErrors++;
      if (Date.now() - this.lastStoreWarn > 60_000) {
        this.lastStoreWarn = Date.now();
        this.warn(`[lurensic] Reading the store failed, so this request was checked against this instance's memory only. ${(err as Error)?.message ?? err}`);
      }
    }
  }

  /** Inspect a request. Never throws; on any problem returns a pass verdict. */
  inspect(req: HttpRequest): Verdict {
    const core = this.live();
    if (!core) return { session: '', source: '', ...PASS };
    try {
      const r = core.call<CoreInspection>('inspect', this.wire(req));
      if (r.events.length) this.pipeline.push(r.events);
      const containment = (r.contain ?? []).map(machine);
      this.contain(containment);
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
   * True until Lurensic has seen one of the app's own JSON 401 responses. While
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
      // A post's body goes with its sample only so the core can hash it, to
      // tell two submissions apart. The core never keeps or logs it.
      const post = 'response_body' in extra && !/^(GET|HEAD)$/i.test(req.method);
      const r = core.call<{ events: string[]; learned_401?: boolean }>('response', this.wire(post ? req : { ...req, body: '' }, extra));
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
   * can read them but cannot change them. When Lurensic is disabled the value is
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
      if (r.contain?.length) this.contain(r.contain.map(machine));
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
      for (const m of released) this.containedCopy.delete(m.source);
      this.enforcement.push('release', released);
      return released;
    } catch (err) {
      this.fault(err);
      return [];
    }
  }

  stats(): LurensicStats {
    return {
      enabled: this.enabled,
      mode: this.mode,
      deployment: this.deploymentId,
      events: this.pipeline.delivered,
      dropped: this.pipeline.dropped,
      sinkErrors: this.pipeline.sinkErrors,
      enforced: this.enforcement.enforced,
      enforcerErrors: this.enforcement.errors,
      storeErrors: this.storeErrors,
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
