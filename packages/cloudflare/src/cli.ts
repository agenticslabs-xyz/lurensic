#!/usr/bin/env node
/**
 * kagami-cloudflare setup    Create the IP list and print the WAF rule to add
 * kagami-cloudflare status   Show how many machines are in the list
 * kagami-cloudflare sweep    Remove expired and duplicate Kagami entries now
 *
 * The API token is read from CLOUDFLARE_API_TOKEN only, never from the command
 * line, so it does not end up in shell history or process listings. The token
 * needs the account permission "Account Filter Lists Edit".
 */
import { parseArgs } from 'node:util';
import { CloudflareApiError, ListsClient } from './api.js';
import { cloudflareEnforcer, itemExpiry } from './enforcer.js';

const HELP = `Cloudflare setup for Kagami.

Commands
  kagami-cloudflare setup  [--account <id>] [--name kagami_contained]
  kagami-cloudflare status [--account <id>] --list <id>
  kagami-cloudflare sweep  [--account <id>] --list <id>

Environment
  CLOUDFLARE_API_TOKEN   API token with the account permission "Account Filter Lists Edit" (required)
  CLOUDFLARE_ACCOUNT_ID  Account id, used when --account is not given
`;

const { values, positionals } = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  options: {
    account: { type: 'string' },
    list: { type: 'string' },
    name: { type: 'string', default: 'kagami_contained' },
    help: { type: 'boolean', short: 'h', default: false },
  },
});
const cmd = positionals[0];

function fail(msg: string): never {
  process.stderr.write(`${msg}\n`);
  process.exit(2);
}

async function main(): Promise<void> {
  if (!cmd || values.help || cmd === 'help') {
    process.stdout.write(HELP);
    return;
  }
  const apiToken = process.env.CLOUDFLARE_API_TOKEN ?? '';
  const accountId = values.account ?? process.env.CLOUDFLARE_ACCOUNT_ID ?? '';
  if (!apiToken) fail('Set CLOUDFLARE_API_TOKEN to an API token with the account permission "Account Filter Lists Edit".');
  if (!/^[a-f0-9]{32}$/i.test(accountId)) fail('Give the 32 character account id with --account or CLOUDFLARE_ACCOUNT_ID.');
  const client = new ListsClient({ apiToken, accountId });

  if (cmd === 'setup') {
    const name = values.name!;
    if (!/^[a-z0-9_]{1,50}$/i.test(name)) fail('The list name may only hold letters, digits and underscores, up to 50 characters.');
    const existing = await client.findList(name);
    const list = existing ?? (await client.createList(name, 'Machines contained by Kagami. Entries expire and are removed automatically.'));
    process.stdout.write(
      [
        existing ? `The IP list "${name}" already exists.` : `Created the IP list "${name}".`,
        '',
        `  KAGAMI_CLOUDFLARE_LIST_ID=${list.id}`,
        '',
        'Now add a WAF custom rule in each zone you protect.',
        '  Dashboard path   Security, then WAF, then Custom rules, then Create rule',
        `  Expression       (ip.src in $${name})`,
        '  Action           Block, or Managed Challenge if you prefer a softer response',
        '',
        'Then pass the list id to cloudflareEnforcer({ apiToken, accountId, listId }).',
        '',
      ].join('\n'),
    );
    return;
  }

  const listId = values.list ?? process.env.KAGAMI_CLOUDFLARE_LIST_ID ?? '';
  if (!/^[a-f0-9]{32}$/i.test(listId)) fail('Give the list id with --list or KAGAMI_CLOUDFLARE_LIST_ID.');

  if (cmd === 'status') {
    const items = await client.items(listId);
    const now = Date.now();
    const ours = items.filter((i) => itemExpiry(i) !== undefined);
    const live = ours.filter((i) => itemExpiry(i)! > now);
    process.stdout.write(`${items.length} items in the list. ${ours.length} were added by Kagami, ${live.length} of them still active.\n`);
    return;
  }
  if (cmd === 'sweep') {
    const { removed } = await cloudflareEnforcer({ apiToken, accountId, listId }).sweep();
    process.stdout.write(`Removed ${removed} expired or duplicate Kagami entries.\n`);
    return;
  }
  fail(`Unknown command "${cmd}".\n\n${HELP}`);
}

main().catch((err) => {
  const msg = err instanceof CloudflareApiError ? err.message : String((err as Error)?.message ?? err);
  process.stderr.write(`${msg}\n`);
  process.exit(1);
});
