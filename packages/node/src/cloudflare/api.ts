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

export interface ApiOptions {
  apiToken: string;
  /** Override for tests or a proxy. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  baseUrl?: string;
  timeoutMs?: number;
  /** Waits between retries and bulk operation polls. Tests pass a fast one. */
  sleep?: (ms: number) => Promise<void>;
}

export interface ClientOptions extends ApiOptions {
  accountId: string;
}

/** Cloudflare account, zone, list and ruleset ids are 32 hex characters. */
export const CLOUDFLARE_ID = /^[a-f0-9]{32}$/i;

/** Authenticated calls to the Cloudflare API, with retries on rate limits and server errors. */
export class CloudflareClient {
  private readonly f: typeof fetch;
  private readonly base: string;
  protected readonly sleep: (ms: number) => Promise<void>;

  constructor(private readonly api: ApiOptions) {
    if (!api.apiToken) throw new TypeError('A Cloudflare API token is required.');
    this.f = api.fetch ?? fetch;
    this.base = (api.baseUrl ?? API_BASE).replace(/\/$/, '');
    this.sleep = api.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  protected async call<T>(method: string, path: string, body?: unknown): Promise<Envelope<T>> {
    let last: unknown;
    for (let attempt = 0; attempt < 4; attempt++) {
      let res: Response;
      try {
        res = await this.f(`${this.base}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.api.apiToken}`,
            ...(body !== undefined && { 'content-type': 'application/json' }),
          },
          ...(body !== undefined && { body: JSON.stringify(body) }),
          redirect: 'error',
          signal: AbortSignal.timeout(this.api.timeoutMs ?? 10_000),
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
}

export class ListsClient extends CloudflareClient {
  /** Serialises bulk operations, because an account allows only one at a time. */
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly o: ClientOptions) {
    super(o);
    if (!CLOUDFLARE_ID.test(o.accountId ?? '')) throw new TypeError('The Cloudflare account id must be 32 hex characters.');
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

export interface CloudflareAccount {
  id: string;
  name: string;
}

export interface CloudflareZone {
  id: string;
  name: string;
  status?: string;
  account?: { id: string; name?: string };
}

export interface RulesetRule {
  id?: string;
  action: string;
  expression: string;
  description?: string;
  enabled?: boolean;
}

export interface Ruleset {
  id: string;
  phase?: string;
  rules?: RulesetRule[];
}

/** The phase that holds WAF custom rules. */
export const WAF_CUSTOM_PHASE = 'http_request_firewall_custom';

/**
 * Zone lookups and WAF custom rules, used once by `kagami cloudflare setup`.
 * https://developers.cloudflare.com/waf/custom-rules/create-api/
 *
 * Rules are only ever added one at a time with POST. The entry point ruleset is
 * written with PUT only when the zone has none yet, because PUT replaces every
 * rule in it.
 */
export class ZonesClient extends CloudflareClient {
  async accounts(): Promise<CloudflareAccount[]> {
    return (await this.call<CloudflareAccount[]>('GET', '/accounts?per_page=50')).result;
  }

  async zone(zoneId: string): Promise<CloudflareZone> {
    return (await this.call<CloudflareZone>('GET', `/zones/${encodeURIComponent(zoneId)}`)).result;
  }

  async zonesNamed(name: string): Promise<CloudflareZone[]> {
    return (await this.call<CloudflareZone[]>('GET', `/zones?${new URLSearchParams({ name })}`)).result;
  }

  /** The zone's custom rules entry point ruleset, or undefined when the zone has none yet. */
  async customRules(zoneId: string): Promise<Ruleset | undefined> {
    try {
      return (await this.call<Ruleset>('GET', `/zones/${encodeURIComponent(zoneId)}/rulesets/phases/${WAF_CUSTOM_PHASE}/entrypoint`)).result;
    } catch (err) {
      if (err instanceof CloudflareApiError && err.status === 404) return undefined;
      throw err;
    }
  }

  /** Create the entry point ruleset. Only call this when `customRules` found none. */
  async createCustomRules(zoneId: string, rules: RulesetRule[]): Promise<Ruleset> {
    return (await this.call<Ruleset>('PUT', `/zones/${encodeURIComponent(zoneId)}/rulesets/phases/${WAF_CUSTOM_PHASE}/entrypoint`, { rules })).result;
  }

  /** Add one rule at the end of a ruleset, leaving the existing rules as they are. */
  async addRule(zoneId: string, rulesetId: string, rule: RulesetRule): Promise<Ruleset> {
    return (await this.call<Ruleset>('POST', `/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(rulesetId)}/rules`, rule)).result;
  }
}
