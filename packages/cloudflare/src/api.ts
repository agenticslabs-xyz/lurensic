/**
 * A minimal client for the Cloudflare Lists API, covering only what Kagami
 * needs. https://developers.cloudflare.com/waf/tools/lists/lists-api/endpoints/
 *
 * Item changes are asynchronous. Each returns an `operation_id`, and an
 * account can have only one pending bulk operation, so every change is
 * awaited to completion before the next one starts.
 */

export const API_BASE = 'https://api.cloudflare.com/client/v4';

export interface ListItem {
  id: string;
  ip?: string;
  comment?: string;
}

export interface CloudflareList {
  id: string;
  name: string;
  kind: string;
  num_items?: number;
}

export class CloudflareApiError extends Error {
  readonly status: number;
  readonly codes: number[];
  constructor(status: number, message: string, codes: number[] = []) {
    super(message);
    this.name = 'CloudflareApiError';
    this.status = status;
    this.codes = codes;
  }
}

interface Envelope<T> {
  success: boolean;
  errors?: Array<{ code: number; message: string }>;
  result: T;
  result_info?: { cursors?: { after?: string } };
}

export interface ClientOptions {
  apiToken: string;
  accountId: string;
  /** Override for tests or a proxy. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  baseUrl?: string;
  timeoutMs?: number;
  /** Waits between retries and bulk operation polls. Tests pass a fast one. */
  sleep?: (ms: number) => Promise<void>;
}

const ID = /^[a-f0-9]{32}$/i;

export class ListsClient {
  private readonly f: typeof fetch;
  private readonly base: string;
  private readonly sleep: (ms: number) => Promise<void>;
  /** Serialises bulk operations, because an account allows only one at a time. */
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly o: ClientOptions) {
    if (!o.apiToken) throw new TypeError('A Cloudflare API token is required.');
    if (!ID.test(o.accountId ?? '')) throw new TypeError('The Cloudflare account id must be 32 hex characters.');
    this.f = o.fetch ?? fetch;
    this.base = (o.baseUrl ?? API_BASE).replace(/\/$/, '');
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<Envelope<T>> {
    let last: unknown;
    for (let attempt = 0; attempt < 4; attempt++) {
      let res: Response;
      try {
        res = await this.f(`${this.base}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.o.apiToken}`,
            ...(body !== undefined && { 'content-type': 'application/json' }),
          },
          ...(body !== undefined && { body: JSON.stringify(body) }),
          redirect: 'error',
          signal: AbortSignal.timeout(this.o.timeoutMs ?? 10_000),
        });
      } catch (err) {
        last = err;
        await this.sleep(500 * 2 ** attempt);
        continue;
      }
      let env: Envelope<T> | undefined;
      try {
        env = (await res.json()) as Envelope<T>;
      } catch {
        env = undefined;
      }
      if (res.ok && env?.success) return env;
      const codes = env?.errors?.map((e) => e.code) ?? [];
      // Never echo the request or token. Cloudflare's own messages are safe to surface.
      const msg = env?.errors?.map((e) => `${e.code} ${e.message}`).join('; ') || `HTTP ${res.status}`;
      last = new CloudflareApiError(res.status, `Cloudflare API ${method} failed. ${msg}`, codes);
      if (res.status === 429 || res.status >= 500) {
        const retryAfter = Number(res.headers.get('retry-after'));
        await this.sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter, 60) * 1000 : 1000 * 2 ** attempt);
        continue;
      }
      break;
    }
    throw last;
  }

  /** Wait for a bulk operation to finish. Throws if it failed or did not finish in time. */
  private async waitFor(operationId: string, timeoutMs = 60_000): Promise<void> {
    const started = Date.now();
    let delay = 250;
    for (;;) {
      const env = await this.call<{ status: string; error?: string }>(
        'GET',
        `/accounts/${this.o.accountId}/rules/lists/bulk_operations/${encodeURIComponent(operationId)}`,
      );
      if (env.result.status === 'completed') return;
      if (env.result.status === 'failed') throw new CloudflareApiError(200, `Cloudflare list operation failed. ${env.result.error ?? ''}`.trim());
      if (Date.now() - started > timeoutMs) throw new CloudflareApiError(0, 'Cloudflare list operation did not finish in time.');
      await this.sleep(delay);
      delay = Math.min(delay * 2, 4000);
    }
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  async findList(name: string): Promise<CloudflareList | undefined> {
    const env = await this.call<CloudflareList[]>('GET', `/accounts/${this.o.accountId}/rules/lists`);
    return env.result.find((l) => l.name === name);
  }

  async createList(name: string, description: string): Promise<CloudflareList> {
    const env = await this.call<CloudflareList>('POST', `/accounts/${this.o.accountId}/rules/lists`, { name, kind: 'ip', description });
    return env.result;
  }

  async items(listId: string, search?: string): Promise<ListItem[]> {
    const out: ListItem[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 1000; page++) {
      const q = new URLSearchParams({ per_page: '500' });
      if (cursor) q.set('cursor', cursor);
      if (search) q.set('search', search);
      const env = await this.call<ListItem[]>('GET', `/accounts/${this.o.accountId}/rules/lists/${listId}/items?${q}`);
      out.push(...env.result);
      cursor = env.result_info?.cursors?.after;
      if (!cursor || env.result.length === 0) break;
    }
    return out;
  }

  addItems(listId: string, items: Array<{ ip: string; comment: string }>): Promise<void> {
    return this.serial(async () => {
      const env = await this.call<{ operation_id: string }>('POST', `/accounts/${this.o.accountId}/rules/lists/${listId}/items`, items);
      await this.waitFor(env.result.operation_id);
    });
  }

  deleteItems(listId: string, ids: string[]): Promise<void> {
    if (!ids.length) return Promise.resolve();
    return this.serial(async () => {
      const env = await this.call<{ operation_id: string }>('DELETE', `/accounts/${this.o.accountId}/rules/lists/${listId}/items`, {
        items: ids.map((id) => ({ id })),
      });
      await this.waitFor(env.result.operation_id);
    });
  }
}
