/**
 * Features that write files. They need a file system, so they work on Node,
 * Bun and Deno. The Cloudflare Workers entry replaces them with versions that
 * explain what to use instead.
 */
import { appendFile, readFile, rename, writeFile } from 'node:fs/promises';
import { formatBlocklist, type BlocklistFormat } from './enforce.js';
import { randomHex, unref } from './platform.js';
import type { ContainedMachine, Enforcer, Severity, Sink } from './types.js';

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
  let timer: ReturnType<typeof setInterval> | undefined;
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
    const tmp = `${path}.${randomHex(4)}.tmp`;
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
      unref(timer);
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
