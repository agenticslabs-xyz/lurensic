/**
 * Cloudflare enforcement. Contained machines are added to a Cloudflare custom
 * IP list. A WAF custom rule with the expression `ip.src in $kagami_contained`
 * then blocks or challenges them at Cloudflare's edge, before they reach your
 * server. IP lists and custom rules are available on every Cloudflare plan.
 *
 * It is built into the Node package. When CLOUDFLARE_API_TOKEN,
 * CLOUDFLARE_ACCOUNT_ID and KAGAMI_CLOUDFLARE_LIST_ID are set and containment
 * is on, Kagami adds it automatically. `npx @agenticslabs/kagami cloudflare
 * setup` creates the list.
 *
 * The list is the shared state, so this works across restarts and across
 * several app instances. Each item Kagami adds carries a comment such as
 * `kagami until=2026-11-17T09:30:00.000Z reason=decoy.param`, and a periodic
 * sweep removes expired items. Items without the `kagami ` prefix are never
 * touched, so the list can be shared with entries you manage yourself.
 */
import type { ContainedMachine, Enforcer } from '../types.js';
import { ListsClient, type ClientOptions, type ListItem } from './api.js';

export const COMMENT_PREFIX = 'kagami ';
const MAX_BATCH = 1000;

export function itemComment(m: ContainedMachine): string {
  return `${COMMENT_PREFIX}until=${new Date(m.until).toISOString()} reason=${m.reason}`.slice(0, 500);
}

/** The expiry in an item comment written by Kagami, or undefined for any other item. */
export function itemExpiry(item: ListItem): number | undefined {
  const c = item.comment ?? '';
  if (!c.startsWith(COMMENT_PREFIX)) return undefined;
  const until = /(?:^|\s)until=(\S+)/.exec(c)?.[1];
  const t = until ? Date.parse(until) : NaN;
  return Number.isFinite(t) ? t : undefined;
}

export interface CloudflareEnforcerOptions extends ClientOptions {
  /** The id of the IP list, from `npx @agenticslabs/kagami cloudflare setup` or the dashboard. */
  listId: string;
  /** How often expired and duplicate Kagami items are removed. Default 600000 (ten minutes). */
  sweepMs?: number;
  /** Where sweep problems are reported. Defaults to `console`. */
  logger?: { warn(message: string): void };
}

export function cloudflareEnforcer(opts: CloudflareEnforcerOptions): Enforcer & { sweep(): Promise<{ removed: number }> } {
  if (!/^[a-f0-9]{32}$/i.test(opts?.listId ?? '')) throw new TypeError('The Cloudflare list id must be 32 hex characters (KAGAMI_CLOUDFLARE_LIST_ID).');
  const client = new ListsClient(opts);
  const logger = opts.logger ?? console;
  let lastWarn = 0;
  const warn = (msg: string): void => {
    if (Date.now() - lastWarn < 60_000) return;
    lastWarn = Date.now();
    try {
      logger.warn(`[kagami] Cloudflare ${msg}`);
    } catch {
      /* never throw from logging */
    }
  };
  let timers: NodeJS.Timeout[] = [];

  const ours = (items: ListItem[]): Array<ListItem & { until: number }> =>
    items.flatMap((i) => {
      const until = itemExpiry(i);
      return until === undefined || !i.ip ? [] : [{ ...i, until }];
    });

  const sweep = async (): Promise<{ removed: number }> => {
    const now = Date.now();
    const items = ours(await client.items(opts.listId));
    // Keep the latest live item per address. Remove expired ones and
    // duplicates left by several instances or by Cloudflare accepting the
    // same address twice.
    const keep = new Map<string, ListItem & { until: number }>();
    const remove: string[] = [];
    for (const i of items) {
      if (i.until <= now) {
        remove.push(i.id);
        continue;
      }
      const prev = keep.get(i.ip!);
      if (!prev) keep.set(i.ip!, i);
      else if (i.until > prev.until) {
        remove.push(prev.id);
        keep.set(i.ip!, i);
      } else remove.push(i.id);
    }
    await client.deleteItems(opts.listId, remove);
    return { removed: remove.length };
  };

  const runSweep = (): void => {
    sweep().catch((err) => warn(`Sweeping the IP list failed. ${(err as Error)?.message ?? err}`));
  };

  return {
    name: 'cloudflare',
    publicOnly: true,
    sweep,
    start() {
      const first = setTimeout(runSweep, 5_000);
      const every = setInterval(runSweep, opts.sweepMs ?? 600_000);
      first.unref();
      every.unref();
      timers = [first, every];
    },
    async contain(machines) {
      for (let i = 0; i < machines.length; i += MAX_BATCH) {
        const batch = machines.slice(i, i + MAX_BATCH).map((m) => ({ ip: m.target, comment: itemComment(m) }));
        await client.addItems(opts.listId, batch);
      }
    },
    async release(machines) {
      const ids: string[] = [];
      for (const m of machines) {
        const found = ours(await client.items(opts.listId, m.target));
        ids.push(...found.filter((i) => i.ip === m.target).map((i) => i.id));
      }
      await client.deleteItems(opts.listId, ids);
    },
    async close() {
      for (const t of timers) clearTimeout(t);
      timers = [];
    },
  };
}

export const CLOUDFLARE_ENV = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'KAGAMI_CLOUDFLARE_LIST_ID'] as const;

/**
 * The Cloudflare settings found in the environment. `complete` when all three
 * are set, `partial` when only some are (a likely mistake), `none` otherwise.
 */
export function cloudflareEnv(env: NodeJS.ProcessEnv = process.env): { state: 'complete' | 'partial' | 'none'; missing: string[] } {
  const missing = CLOUDFLARE_ENV.filter((k) => !env[k]?.trim());
  return { state: missing.length === 0 ? 'complete' : missing.length === CLOUDFLARE_ENV.length ? 'none' : 'partial', missing };
}
