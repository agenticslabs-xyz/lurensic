/**
 * `kagami cloudflare setup`. Creates the IP list, adds the WAF custom rule to
 * each zone given with --zone, and explains which token permissions it used.
 *
 * Two tokens are recommended. A one-time setup token holds Account Filter
 * Lists Edit plus Zone Read and Zone WAF Edit, and is deleted after setup. The
 * runtime token the app keeps holds only Account Filter Lists Edit. One token
 * with all three permissions also works.
 */
import { CLOUDFLARE_ID, CloudflareApiError, ListsClient, ZonesClient, type ApiOptions, type CloudflareZone, type RulesetRule } from './api.js';

export const DEFAULT_LIST_NAME = 'kagami_contained';
export const RULE_DESCRIPTION = 'Kagami blocks contained machines';
export type RuleAction = 'block' | 'managed_challenge';
export const RULE_ACTIONS: readonly RuleAction[] = ['block', 'managed_challenge'];

/** The account API tokens page. The dashboard asks which account when `:account` is in the path. */
export const TOKENS_PAGE = 'https://dash.cloudflare.com/?to=/:account/api-tokens';

/**
 * Permission keys for a pre-filled Create Token link. Cloudflare publishes keys
 * for the zone permissions. It publishes no key for Account Filter Lists, so
 * that one is added by hand until its permission group id is confirmed on a
 * real account (account token links accept ids too). Unknown keys are dropped
 * by the dashboard without an error.
 * https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/
 */
export const SETUP_PERMISSION_KEYS: ReadonlyArray<{ key: string; type: 'read' | 'edit' }> = [
  { key: 'zone', type: 'read' },
  { key: 'firewall_services', type: 'edit' },
];

/** A dashboard link that opens Create Token for an account token with these permissions selected. */
export function tokenLink(keys: ReadonlyArray<{ key: string; type: string }>, name: string): string {
  return `${TOKENS_PAGE}&permissionGroupKeys=${encodeURIComponent(JSON.stringify(keys))}&name=${encodeURIComponent(name)}`;
}

export function ruleExpression(listName: string): string {
  return `(ip.src in $${listName})`;
}

const bare = (expr: string): string => {
  let e = expr.replace(/\s+/g, ' ').trim();
  while (e.startsWith('(') && e.endsWith(')')) e = e.slice(1, -1).trim();
  return e.toLowerCase();
};

/** True for a rule that Kagami added, matched by its expression or its description. */
export function isKagamiRule(rule: RulesetRule, listName: string): boolean {
  return bare(rule.expression ?? '') === bare(ruleExpression(listName)) || /^kagami\b/i.test(rule.description ?? '');
}

/**
 * The zone names to try for what the user typed. Accepts a domain, a host
 * inside the zone such as shop.example.com, or a pasted URL.
 */
export function zoneCandidates(input: string): string[] {
  let host = input.trim().toLowerCase();
  if (host.includes('://')) {
    try {
      host = new URL(host).hostname;
    } catch {
      /* keep as typed */
    }
  }
  host = host.replace(/\/.*$/, '').replace(/\.$/, '');
  const labels = host.split('.').filter(Boolean);
  const out: string[] = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join('.'));
  return out;
}

export async function resolveZone(client: ZonesClient, input: string): Promise<CloudflareZone> {
  if (CLOUDFLARE_ID.test(input.trim())) return client.zone(input.trim());
  const names = zoneCandidates(input);
  for (const name of names) {
    const [found] = await client.zonesNamed(name);
    if (found) return found;
  }
  throw new Error(`No zone named ${names[0] ?? input} was found. Check the domain, and that the token has Zone Read for it.`);
}

export interface RuleResult {
  zone: CloudflareZone;
  status: 'created' | 'exists';
  action: string;
  enabled: boolean;
}

/**
 * Make sure the zone has the Kagami WAF custom rule. Does nothing when a rule
 * with the Kagami expression or description is already there. Never replaces
 * existing rules.
 */
export async function ensureWafRule(client: ZonesClient, zone: CloudflareZone, listName: string, action: RuleAction): Promise<RuleResult> {
  const rule: RulesetRule = { description: RULE_DESCRIPTION, expression: ruleExpression(listName), action, enabled: true };
  const ruleset = await client.customRules(zone.id);
  const existing = ruleset?.rules?.find((r) => isKagamiRule(r, listName));
  if (existing) return { zone, status: 'exists', action: existing.action, enabled: existing.enabled !== false };
  if (ruleset) await client.addRule(zone.id, ruleset.id, rule);
  else await client.createCustomRules(zone.id, [rule]);
  return { zone, status: 'created', action, enabled: true };
}

export interface SetupOptions extends Omit<ApiOptions, 'apiToken'> {
  apiToken?: string;
  accountId?: string;
  listName?: string;
  zones?: string[];
  action?: RuleAction;
}

export interface SetupResult {
  ok: boolean;
  output: string;
}

/** Printed when CLOUDFLARE_API_TOKEN is missing. */
export function tokenGuidance(): string {
  return [
    'CLOUDFLARE_API_TOKEN is not set.',
    '',
    'Kagami recommends two Cloudflare API tokens. One token with all three permissions also works.',
    '',
    '1. A one-time setup token. Delete it once setup is done.',
    '   Permissions   Account Filter Lists Edit, Zone Read, Zone WAF Edit',
    '   This link opens Create Token with the two zone permissions already selected.',
    `   ${tokenLink(SETUP_PERMISSION_KEYS, 'Kagami setup')}`,
    '   Add Account Filter Lists Edit by hand. Under Zone Resources, pick the zones you protect.',
    '',
    '2. A runtime token for the app.',
    '   Permissions   Account Filter Lists Edit, nothing else',
    `   Create it at ${TOKENS_PAGE}`,
    '   This token can change your IP lists only. It cannot touch DNS, zones or rules.',
    '',
    'Then put the setup token in CLOUDFLARE_API_TOKEN and run this, with your own domain.',
    '  npx @agenticslabs/kagami cloudflare setup --zone example.com',
    '',
    'Set the token in the environment, not on the command line, so it stays out of shell history.',
    '',
  ].join('\n');
}

const describe = (err: unknown): string => (err as Error)?.message ?? String(err);
/** Cloudflare's answers to a token that is malformed, deleted or expired. */
const rejectedToken = (err: unknown): boolean => err instanceof CloudflareApiError && [6003, 6111, 9106, 1000].some((c) => err.codes.includes(c));
const REJECTED =
  'Cloudflare rejected the token. Check that CLOUDFLARE_API_TOKEN holds the whole token, with no spaces or quotes, and that the token has not expired or been deleted.';
const denied = (err: unknown): boolean => err instanceof CloudflareApiError && (err.status === 401 || err.status === 403 || err.codes.includes(10000) || err.codes.includes(9109));

function manualRule(listName: string): string[] {
  return [
    'Add the WAF custom rule by hand in each zone you protect.',
    '  Dashboard path   Security, then WAF, then Custom rules, then Create rule',
    `  Expression       ${ruleExpression(listName)}`,
    '  Action           Block, or Managed Challenge for a softer response',
  ];
}

/** The whole setup flow. The CLI prints `output` and exits with 1 when `ok` is false. */
export async function cloudflareSetup(o: SetupOptions): Promise<SetupResult> {
  if (!o.apiToken) return { ok: false, output: tokenGuidance() };
  const listName = o.listName ?? DEFAULT_LIST_NAME;
  if (!/^[a-z0-9_]{1,50}$/i.test(listName)) throw new Error('The list name may only hold letters, digits and underscores, up to 50 characters.');
  const action = o.action ?? 'block';
  if (!RULE_ACTIONS.includes(action)) throw new Error(`The rule action must be ${RULE_ACTIONS.join(' or ')}.`);
  const api: ApiOptions = { ...o, apiToken: o.apiToken };
  const zones = new ZonesClient(api);
  const out: string[] = [];
  let ok = true;

  // The account id. Taken from the environment, or found when the token can see exactly one account.
  let accountId = o.accountId?.trim() ?? '';
  if (!accountId) {
    let accounts;
    try {
      accounts = await zones.accounts();
    } catch (err) {
      if (rejectedToken(err)) throw new Error(`${REJECTED} ${describe(err)}`);
      throw new Error(`CLOUDFLARE_ACCOUNT_ID is not set and the token could not list accounts. Set it to the account ID shown on your Cloudflare dashboard. ${describe(err)}`);
    }
    const [only] = accounts;
    if (!only || accounts.length > 1) {
      throw new Error(`CLOUDFLARE_ACCOUNT_ID is not set and the token can see ${accounts.length} accounts. Set it to the account ID shown on your Cloudflare dashboard.`);
    }
    accountId = only.id;
    out.push(`Using the account ${only.name}, the only one this token can see.`);
  }
  if (!CLOUDFLARE_ID.test(accountId)) throw new Error('CLOUDFLARE_ACCOUNT_ID must be 32 hex characters.');

  // The list.
  const lists = new ListsClient({ ...api, accountId });
  let existing;
  try {
    existing = await lists.findList(listName);
  } catch (err) {
    if (rejectedToken(err)) throw new Error(`${REJECTED} ${describe(err)}`);
    if (denied(err)) throw new Error(`The token cannot read IP lists. Give it the account permission Account Filter Lists Edit. ${describe(err)}`);
    throw err;
  }
  const list = existing ?? (await lists.createList(listName, 'Machines contained by Kagami. Entries expire and are removed automatically.'));
  out.push(existing ? `The IP list "${listName}" already exists.` : `Created the IP list "${listName}".`);

  // The WAF rule in each zone.
  const used = ['Account Filter Lists Edit, to find or create the list'];
  if (o.zones?.length) {
    used.push('Zone Read, to look up the zone', 'Zone WAF Edit, to add the custom rule');
    for (const input of o.zones) {
      try {
        const zone = await resolveZone(zones, input);
        if (zone.account?.id && zone.account.id !== accountId) {
          throw new Error(`The zone ${zone.name} belongs to another Cloudflare account. The list and the zone must be in the same account.`);
        }
        const r = await ensureWafRule(zones, zone, listName, action);
        if (r.status === 'created') out.push(`Added the WAF custom rule to ${zone.name}. Expression ${ruleExpression(listName)}, action ${r.action}.`);
        else {
          out.push(`${zone.name} already has the Kagami WAF custom rule, with action ${r.action}. Nothing was changed.`);
          if (r.action !== action) out.push(`  To use ${action} instead, edit the rule in the dashboard.`);
        }
        if (!r.enabled) out.push(`  The rule in ${zone.name} is turned off. Turn it on in the dashboard, or contained machines are not blocked there.`);
      } catch (err) {
        ok = false;
        out.push(`Could not add the WAF rule to ${input}. ${describe(err)}`);
        if (denied(err)) out.push('  The token needs Zone Read and Zone WAF Edit for this zone.');
        if (/limit|quota|exceed/i.test(describe(err))) out.push('  The zone may have reached its custom rule limit. Free plans allow five custom rules.');
        out.push(...manualRule(listName).map((l) => `  ${l}`));
      }
    }
  } else {
    out.push('', ...manualRule(listName), 'Or run this again with --zone <your domain> and a token that also has Zone Read and Zone WAF Edit.');
  }

  out.push(
    '',
    'Set these where the app runs.',
    `  CLOUDFLARE_ACCOUNT_ID=${accountId}`,
    `  KAGAMI_CLOUDFLARE_LIST_ID=${list.id}`,
    '  CLOUDFLARE_API_TOKEN=<a token with only Account Filter Lists Edit>',
    '  KAGAMI_CONTAINMENT=on',
    '',
    'This run needed these permissions.',
    ...used.map((u) => `  ${u}`),
  );
  if (o.zones?.length) {
    out.push(
      '',
      'If this was a one-time setup token, delete it now in the dashboard under Manage Account, then Account API Tokens.',
      'The app only needs a token with Account Filter Lists Edit. If you use one token for both, keep it as it is.',
    );
  }
  out.push('With containment on, Kagami adds contained machines to the list by itself.', '');
  return { ok, output: out.join('\n') };
}
