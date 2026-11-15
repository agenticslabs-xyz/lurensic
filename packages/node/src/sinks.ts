/**
 * Event delivery. Every sink follows these rules.
 * - Delivery never runs on the request path. It is asynchronous and bounded.
 * - A sink never blocks or crashes the app. Failures are counted and dropped.
 * - A sink never leaks data. Lines are written verbatim because the core has
 *   already redacted secrets. Chat alerts are escaped and never unfurl links
 *   supplied by an attacker. Webhooks never follow redirects.
 */
import { createHmac } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import { SEVERITY_RANK, type EventRecord, type KagamiEvent, type Severity, type Sink } from './types.js';

const MAX_QUEUE = 10_000;
const BATCH = 500;

export class Pipeline {
  private queue: EventRecord[] = [];
  private scheduled = false;
  private draining: Promise<void> | null = null;
  dropped = 0;
  sinkErrors = 0;
  delivered = 0;
  private lastWarn = 0;

  constructor(
    private readonly sinks: Sink[],
    private readonly warn: (msg: string) => void,
  ) {}

  push(lines: string[]): void {
    for (const line of lines) {
      if (this.queue.length >= MAX_QUEUE) {
        this.dropped++;
        continue;
      }
      let event: KagamiEvent;
      try {
        event = JSON.parse(line) as KagamiEvent;
      } catch {
        this.dropped++;
        continue;
      }
      this.queue.push({ line, event });
    }
    this.schedule();
  }

  private schedule(): void {
    if (this.scheduled || this.queue.length === 0) return;
    this.scheduled = true;
    setImmediate(() => {
      this.scheduled = false;
      void this.drain();
    });
  }

  private drain(): Promise<void> {
    if (this.draining) return this.draining;
    // The async body can complete synchronously, for example when every sink
    // filters the batch out. That is why `draining` is cleared through the
    // promise and never inside it.
    const run = (async () => {
      while (this.queue.length > 0) {
          const batch = this.queue.splice(0, BATCH);
          for (const sink of this.sinks) {
            const min = SEVERITY_RANK[sink.minSeverity] ?? 0;
            const records = batch.filter((r) => (SEVERITY_RANK[r.event.severity] ?? 0) >= min);
            if (records.length === 0) continue;
            try {
              await sink.write(records);
            } catch (err) {
              this.sinkErrors++;
              this.rateLimitedWarn(`sink "${sink.name}" failed. ${(err as Error)?.message ?? err}`);
            }
          }
          this.delivered += batch.length;
      }
    })();
    this.draining = run;
    const clear = (): void => {
      if (this.draining === run) this.draining = null;
    };
    run.then(clear, clear);
    return run;
  }

  private rateLimitedWarn(msg: string): void {
    const now = Date.now();
    if (now - this.lastWarn > 60_000) {
      this.lastWarn = now;
      this.warn(`[kagami] ${msg} (further sink errors suppressed for 60s)`);
    }
  }

  /** Wait until everything queued so far has been handed to every sink. */
  async flush(): Promise<void> {
    while (this.queue.length > 0 || this.draining) {
      await (this.draining ?? this.drain());
    }
  }

  async close(): Promise<void> {
    await this.flush();
    await Promise.all(this.sinks.map((s) => s.close?.().catch(() => undefined)));
  }
}

/** JSON lines on stdout. This is the default sink, and any log shipper can collect it. */
export function consoleSink(opts: { minSeverity?: Severity; stream?: NodeJS.WritableStream } = {}): Sink {
  const stream = opts.stream ?? process.stdout;
  return {
    name: 'console',
    minSeverity: opts.minSeverity ?? 'low',
    async write(records) {
      stream.write(records.map((r) => r.line).join('\n') + '\n');
    },
  };
}

/** Append JSON lines to a file. The file is created with owner-only permissions. */
export function fileSink(opts: { path: string; minSeverity?: Severity }): Sink {
  if (!opts?.path) throw new TypeError('fileSink requires a `path` option');
  return {
    name: 'file',
    minSeverity: opts.minSeverity ?? 'info',
    async write(records) {
      await appendFile(opts.path, records.map((r) => r.line).join('\n') + '\n', { mode: 0o600 });
    },
  };
}

function assertSafeUrl(raw: string, who: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError(`${who} was given an invalid URL`);
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    throw new TypeError(`${who} URL must use https. Plain http is only allowed for localhost.`);
  }
  return url;
}

async function post(url: URL, body: string, headers: Record<string, string>, timeoutMs: number): Promise<void> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status >= 200 && res.status < 300) return;
      lastErr = new Error(`HTTP ${res.status}`);
      if (res.status < 500 && res.status !== 429) break;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

/**
 * POST batches as `{"events":[...]}`. With `secret` set, each request carries
 * the header `kagami-signature: t=<unix>,v1=<hex hmac-sha256(secret, t + "." + body)>`
 * so receivers can reject forged or replayed alerts.
 */
export function webhookSink(opts: {
  url: string;
  secret?: string;
  minSeverity?: Severity;
  timeoutMs?: number;
  headers?: Record<string, string>;
}): Sink {
  const url = assertSafeUrl(opts.url, 'webhookSink');
  return {
    name: 'webhook',
    minSeverity: opts.minSeverity ?? 'medium',
    async write(records) {
      const body = `{"events":[${records.map((r) => r.line).join(',')}]}`;
      const headers: Record<string, string> = { ...(opts.headers ?? {}) };
      if (opts.secret) {
        const t = Math.floor(Date.now() / 1000);
        const sig = createHmac('sha256', opts.secret).update(`${t}.${body}`).digest('hex');
        headers['kagami-signature'] = `t=${t},v1=${sig}`;
      }
      await post(url, body, headers, opts.timeoutMs ?? 5000);
    },
  };
}

/** Escape attacker-controlled text for Slack mrkdwn so it cannot create mentions, links or broken code spans. */
export function escapeSlack(text: unknown, max = 200): string {
  const s = String(text ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, '�')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/`/g, "'");
  return s.length > max ? s.slice(0, max) + '...' : s;
}

export function formatSlack(e: KagamiEvent): string {
  const lines = [
    `*Kagami ${e.severity.toUpperCase()}* ${escapeSlack(e.title)} (\`${escapeSlack(e.rule, 64)}\`)`,
  ];
  if (e.session) lines.push(`session \`${escapeSlack(e.session.id, 32)}\`, score ${e.session.score}, state ${e.session.state}`);
  if (e.request) lines.push(`request \`${escapeSlack(e.request.method, 16)} ${escapeSlack(e.request.path, 160)}\``);
  if (e.source?.ip) lines.push(`source \`${escapeSlack(e.source.ip, 64)}\``);
  lines.push(`deployment ${escapeSlack(e.deployment, 32)}, event ${escapeSlack(e.id, 32)}`);
  return lines.join('\n');
}

/** Sends short, escaped summaries to a Slack incoming webhook. Full events belong in your log store. */
export function slackSink(opts: { webhookUrl: string; minSeverity?: Severity; timeoutMs?: number }): Sink {
  const url = assertSafeUrl(opts.webhookUrl, 'slackSink');
  return {
    name: 'slack',
    minSeverity: opts.minSeverity ?? 'high',
    async write(records) {
      const text = records.slice(0, 20).map((r) => formatSlack(r.event)).join('\n\n');
      const more = records.length > 20 ? `\n\nand ${records.length - 20} more events` : '';
      await post(url, JSON.stringify({ text: text + more, unfurl_links: false, unfurl_media: false }), {}, opts.timeoutMs ?? 5000);
    },
  };
}

/** Call a function for each event. Useful for in-process integrations and tests. */
export function callbackSink(fn: (event: KagamiEvent, line: string) => void | Promise<void>, minSeverity: Severity = 'info'): Sink {
  return {
    name: 'callback',
    minSeverity,
    async write(records) {
      for (const r of records) await fn(r.event, r.line);
    },
  };
}

/** Keeps events in memory for tests and local tooling. */
export function memorySink(minSeverity: Severity = 'info'): Sink & { events: KagamiEvent[]; lines: string[] } {
  const events: KagamiEvent[] = [];
  const lines: string[] = [];
  return {
    name: 'memory',
    minSeverity,
    events,
    lines,
    async write(records) {
      for (const r of records) {
        events.push(r.event);
        lines.push(r.line);
      }
    },
  };
}
