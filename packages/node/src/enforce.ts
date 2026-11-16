/**
 * Enforcement outside the application. When Kagami contains a machine, the
 * machine is already cut off from the app. Enforcers push the same decision
 * to the places that see traffic first, such as a CDN, a WAF, a firewall or
 * a load balancer, so the machine is stopped before it reaches the server.
 *
 * Every enforcer follows the same rules as event sinks.
 * - It runs off the request path, in batches.
 * - It never blocks or crashes the app. Failures are counted and reported.
 * - By default it only receives public addresses, so a private network,
 *   a loopback test or a misconfigured proxy is never pushed out.
 */
import { createHmac, randomBytes } from 'node:crypto';
import { readFile, rename, writeFile } from 'node:fs/promises';
import type { ContainedMachine, Enforcer } from './types.js';

const MAX_QUEUE = 10_000;

type Job = { kind: 'contain' | 'release'; machines: ContainedMachine[] };

export class EnforcerPipeline {
  private queue: Job[] = [];
  private running: Promise<void> | null = null;
  enforced = 0;
  errors = 0;
  private lastWarn = 0;

  constructor(
    private readonly enforcers: Enforcer[],
    private readonly warn: (msg: string) => void,
  ) {
    for (const e of enforcers) {
      try {
        e.start?.();
      } catch (err) {
        this.fail(e, err);
      }
    }
  }

  get size(): number {
    return this.enforcers.length;
  }

  push(kind: Job['kind'], machines: ContainedMachine[]): void {
    if (this.enforcers.length === 0 || machines.length === 0) return;
    if (this.queue.length >= MAX_QUEUE) {
      this.errors++;
      return;
    }
    this.queue.push({ kind, machines });
    this.schedule();
  }

  private schedule(): void {
    if (this.running || this.queue.length === 0) return;
    const run = new Promise<void>((resolve) => setImmediate(resolve)).then(() => this.drain());
    this.running = run;
    const done = (): void => {
      if (this.running === run) this.running = null;
      this.schedule();
    };
    run.then(done, done);
  }

  /**
   * Everything queued while the previous batch was being enforced goes out
   * together. Consecutive jobs of the same kind are merged, keeping the
   * latest entry per target, so an enforcer that calls a remote API makes
   * one call per batch without any timers of its own.
   */
  private nextBatch(): Job | undefined {
    const first = this.queue.shift();
    if (!first) return undefined;
    const merged = new Map(first.machines.map((m) => [m.target, m]));
    while (this.queue[0]?.kind === first.kind) {
      for (const m of this.queue.shift()!.machines) {
        const prev = merged.get(m.target);
        merged.set(m.target, prev && prev.until > m.until ? prev : m);
      }
    }
    return { kind: first.kind, machines: [...merged.values()] };
  }

  private async drain(): Promise<void> {
    for (let job = this.nextBatch(); job; job = this.nextBatch()) {
      for (const e of this.enforcers) {
        const machines = job.machines.filter((m) => m.target && (e.publicOnly === false || m.public));
        if (!machines.length) continue;
        try {
          if (job.kind === 'contain') {
            await e.contain(machines);
            this.enforced += machines.length;
          } else {
            await e.release?.(machines);
          }
        } catch (err) {
          this.fail(e, err);
        }
      }
    }
  }

  private fail(e: Enforcer, err: unknown): void {
    this.errors++;
    const now = Date.now();
    if (now - this.lastWarn > 60_000) {
      this.lastWarn = now;
      this.warn(`[kagami] enforcer "${e.name}" failed. ${(err as Error)?.message ?? err} (further enforcer errors suppressed for 60s)`);
    }
  }

  async flush(): Promise<void> {
    while (this.running) await this.running;
  }

  async close(): Promise<void> {
    await this.flush();
    await Promise.all(this.enforcers.map((e) => e.close?.().catch(() => undefined)));
  }
}

export type BlocklistFormat = 'plain' | 'nginx' | 'json';

/**
 * Render contained machines in a format other tools read. `plain` is one
 * address or CIDR per line (for ipset, iptables scripts, AWS WAF IP set
 * imports and most firewalls). `nginx` is `deny <target>;` lines for an
 * `include`. `json` carries the reason and expiry of each entry.
 */
export function formatBlocklist(machines: ContainedMachine[], format: BlocklistFormat = 'plain', now = Date.now()): string {
  const live = machines.filter((m) => m.target && m.until > now).sort((a, b) => a.target.localeCompare(b.target));
  if (format === 'json') {
    return (
      JSON.stringify(
        {
          generated_at: new Date(now).toISOString(),
          entries: live.map((m) => ({ target: m.target, reason: m.reason, since: new Date(m.since).toISOString(), until: new Date(m.until).toISOString() })),
        },
        null,
        2,
      ) + '\n'
    );
  }
  const lines = live.map((m) => (format === 'nginx' ? `deny ${m.target};` : m.target));
  return lines.length ? lines.join('\n') + '\n' : '';
}

/**
 * Keep a blocklist file up to date for any firewall, proxy or WAF that reads
 * one. The file is replaced atomically (write then rename), so a reader never
 * sees a half-written list. Expired entries are removed on a timer. State is
 * kept in `<path>.state.json`, so the list survives restarts of the app.
 *
 * Reload the consumer after a change, for example with a file watcher, a
 * cron job, or `onChange`.
 */
export function blocklistFile(opts: {
  path: string;
  format?: BlocklistFormat;
  /** Include private addresses. Default false. */
  includePrivate?: boolean;
  /** How often expired entries are removed. Default 60000 (one minute). */
  sweepMs?: number;
  /** Called after the file has been rewritten. */
  onChange?: (path: string) => void | Promise<void>;
}): Enforcer & { entries(): ContainedMachine[] } {
  if (!opts?.path) throw new TypeError('blocklistFile requires a `path` option');
  const format = opts.format ?? 'plain';
  const statePath = `${opts.path}.state.json`;
  const entries = new Map<string, ContainedMachine>();
  let loaded: Promise<void> | null = null;
  let timer: NodeJS.Timeout | undefined;
  let writing: Promise<void> = Promise.resolve();

  const load = (): Promise<void> =>
    (loaded ??= readFile(statePath, 'utf8').then(
      (text) => {
        const parsed = JSON.parse(text) as { entries?: ContainedMachine[] };
        for (const m of parsed.entries ?? []) if (m?.target && m.until > Date.now()) entries.set(m.target, m);
      },
      () => undefined,
    ));

  const atomicWrite = async (path: string, text: string): Promise<void> => {
    const tmp = `${path}.${randomBytes(4).toString('hex')}.tmp`;
    await writeFile(tmp, text, { mode: 0o640 });
    await rename(tmp, path);
  };

  const persist = (): Promise<void> => {
    // A failed write or onChange must not stop later writes, so the chain
    // continues after a rejection. The caller still sees this write's error.
    writing = writing.catch(() => undefined).then(async () => {
      const now = Date.now();
      for (const [k, m] of entries) if (m.until <= now) entries.delete(k);
      const list = [...entries.values()];
      await atomicWrite(statePath, JSON.stringify({ entries: list }) + '\n');
      await atomicWrite(opts.path, formatBlocklist(list, format, now));
      await opts.onChange?.(opts.path);
    });
    return writing;
  };

  return {
    name: 'blocklist-file',
    publicOnly: !opts.includePrivate,
    entries: () => [...entries.values()],
    start() {
      void load().then(persist).catch(() => undefined);
      timer = setInterval(() => {
        const now = Date.now();
        if ([...entries.values()].some((m) => m.until <= now)) void persist().catch(() => undefined);
      }, opts.sweepMs ?? 60_000);
      timer.unref();
    },
    async contain(machines) {
      await load();
      for (const m of machines) {
        const prev = entries.get(m.target);
        entries.set(m.target, prev ? { ...m, until: Math.max(prev.until, m.until) } : m);
      }
      await persist();
    },
    async release(machines) {
      await load();
      for (const m of machines) entries.delete(m.target);
      await persist();
    },
    async close() {
      if (timer) clearInterval(timer);
      await writing.catch(() => undefined);
    },
  };
}

/**
 * POST each batch as JSON to your own endpoint, for a SOAR, a serverless
 * function that updates a cloud WAF, or a firewall API.
 *
 *   {"type":"containment.started","machines":[{"target":"198.51.100.4", ...}]}
 *
 * The type is `containment.started` or `containment.released`. With `secret`
 * set, requests carry `kagami-signature: t=<unix>,v1=<hex hmac-sha256(secret, t + "." + body)>`,
 * the same scheme as `webhookSink`. Redirects are never followed.
 */
export function webhookEnforcer(opts: {
  url: string;
  secret?: string;
  /** Include private addresses. Default false. */
  includePrivate?: boolean;
  timeoutMs?: number;
  headers?: Record<string, string>;
}): Enforcer {
  let url: URL;
  try {
    url = new URL(opts.url);
  } catch {
    throw new TypeError('webhookEnforcer was given an invalid URL');
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    throw new TypeError('webhookEnforcer URL must use https. Plain http is only allowed for localhost.');
  }
  const send = async (type: string, machines: ContainedMachine[]): Promise<void> => {
    const body = JSON.stringify({ type, machines });
    const headers: Record<string, string> = { 'content-type': 'application/json', ...(opts.headers ?? {}) };
    if (opts.secret) {
      const t = Math.floor(Date.now() / 1000);
      headers['kagami-signature'] = `t=${t},v1=${createHmac('sha256', opts.secret).update(`${t}.${body}`).digest('hex')}`;
    }
    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const res = await fetch(url, { method: 'POST', headers, body, redirect: 'manual', signal: AbortSignal.timeout(opts.timeoutMs ?? 5000) });
        if (res.status >= 200 && res.status < 300) return;
        lastErr = new Error(`HTTP ${res.status}`);
        if (res.status < 500 && res.status !== 429) break;
      } catch (err) {
        lastErr = err;
      }
      await new Promise((r) => setTimeout(r, 250 * 2 ** attempt));
    }
    throw lastErr;
  };
  return {
    name: 'webhook',
    publicOnly: !opts.includePrivate,
    contain: (machines) => send('containment.started', machines),
    release: (machines) => send('containment.released', machines),
  };
}

/** Call your own functions, for in-process integrations and tests. */
export function callbackEnforcer(
  contain: (machines: ContainedMachine[]) => void | Promise<void>,
  opts: { release?: (machines: ContainedMachine[]) => void | Promise<void>; includePrivate?: boolean } = {},
): Enforcer {
  return {
    name: 'callback',
    publicOnly: !opts.includePrivate,
    async contain(machines) {
      await contain(machines);
    },
    async release(machines) {
      await opts.release?.(machines);
    },
  };
}
