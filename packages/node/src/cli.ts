#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { verifyChain } from './chain.js';
import { ListsClient } from './cloudflare/api.js';
import { cloudflareEnforcer, itemExpiry } from './cloudflare/enforcer.js';
import { formatChecks, runDoctor } from './doctor.js';

const HELP = `Kagami command line tool. Deception-based defence against AI-driven attacks.

Commands
  kagami secret              Print a new random deployment secret for KAGAMI_SECRET
  kagami doctor [options]    Check that Kagami is installed and working
      --url <url>            Also probe the running app, for example http://localhost:3000
      --events <file>        Also read the event log written by fileSink
      --blocklist <file>     Also check a JSON blocklist written by blocklistFile
      --json                 Print the results as JSON, for scripts and AI agents
  kagami verify-log <file>   Verify the hash chain of a Kagami JSON-lines event log
  kagami cloudflare setup    Create the Cloudflare IP list and print the WAF rule to add
  kagami cloudflare status   Show how many machines are in the Cloudflare list
  kagami cloudflare sweep    Remove expired and duplicate Kagami entries from the list now
      Cloudflare commands read CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID from the
      environment, and the list from KAGAMI_CLOUDFLARE_LIST_ID. The token needs the account
      permission "Account Filter Lists Edit".
  kagami help                Show this help
`;

const { values, positionals } = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  options: {
    url: { type: 'string' },
    events: { type: 'string' },
    blocklist: { type: 'string' },
    json: { type: 'boolean', default: false },
    name: { type: 'string', default: 'kagami_contained' },
    help: { type: 'boolean', short: 'h', default: false },
  },
});
const [cmd, ...args] = positionals;

async function main(): Promise<void> {
  if (values.help) {
    process.stdout.write(HELP);
    return;
  }
  switch (cmd) {
    case 'secret':
      process.stdout.write(randomBytes(32).toString('hex') + '\n');
      return;
    case 'doctor': {
      const checks = await runDoctor({ url: values.url, events: values.events, blocklist: values.blocklist });
      process.stdout.write(values.json ? JSON.stringify({ checks }, null, 2) + '\n' : formatChecks(checks));
      if (checks.some((c) => c.status === 'fail')) process.exitCode = 1;
      return;
    }
    case 'cloudflare':
      await cloudflareCommand(args[0]);
      return;
    case 'verify-log': {
      const file = args[0];
      if (!file) {
        process.stderr.write('Give the log file to check, for example kagami verify-log kagami-events.jsonl\n');
        process.exitCode = 2;
        return;
      }
      const res = verifyChain(readFileSync(file, 'utf8').split('\n'));
      if (res.ok) {
        process.stdout.write(`Chain intact. Checked ${res.events} events across ${res.instances} instance(s).\n`);
      } else {
        process.stdout.write(`Tampering detected at line ${res.line}. Reason is ${res.reason}.\n`);
        process.exitCode = 1;
      }
      return;
    }
    case undefined:
    case 'help':
      process.stdout.write(HELP);
      return;
    default:
      process.stderr.write(`Unknown command "${cmd}".\n\n${HELP}`);
      process.exitCode = 2;
  }
}

async function cloudflareCommand(sub: string | undefined): Promise<void> {
  // The token is read from the environment only, never from the command line,
  // so it does not end up in shell history or process listings.
  const apiToken = process.env.CLOUDFLARE_API_TOKEN ?? '';
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID ?? '';
  if (!apiToken) throw new Error('Set CLOUDFLARE_API_TOKEN to an API token with the account permission "Account Filter Lists Edit".');
  const client = new ListsClient({ apiToken, accountId });
  if (sub === 'setup') {
    const name = values.name!;
    if (!/^[a-z0-9_]{1,50}$/i.test(name)) throw new Error('The list name may only hold letters, digits and underscores, up to 50 characters.');
    const existing = await client.findList(name);
    const list = existing ?? (await client.createList(name, 'Machines contained by Kagami. Entries expire and are removed automatically.'));
    process.stdout.write(
      [
        existing ? `The IP list "${name}" already exists.` : `Created the IP list "${name}".`,
        '',
        'Set this next to CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID where the app runs.',
        `  KAGAMI_CLOUDFLARE_LIST_ID=${list.id}`,
        '',
        'Then add a WAF custom rule in each zone you protect.',
        '  Dashboard path   Security, then WAF, then Custom rules, then Create rule',
        `  Expression       (ip.src in $${name})`,
        '  Action           Block, or Managed Challenge for a softer response',
        '',
        'With containment on, Kagami adds contained machines to the list by itself.',
        '',
      ].join('\n'),
    );
    return;
  }
  const listId = process.env.KAGAMI_CLOUDFLARE_LIST_ID ?? '';
  if (!/^[a-f0-9]{32}$/i.test(listId)) throw new Error('Set KAGAMI_CLOUDFLARE_LIST_ID. Run npx @agenticslabs/kagami cloudflare setup to create the list.');
  if (sub === 'status') {
    const items = await client.items(listId);
    const now = Date.now();
    const ours = items.filter((i) => itemExpiry(i) !== undefined);
    const live = ours.filter((i) => itemExpiry(i)! > now);
    process.stdout.write(`${items.length} items in the list. ${ours.length} were added by Kagami, ${live.length} of them still active.\n`);
    return;
  }
  if (sub === 'sweep') {
    const { removed } = await cloudflareEnforcer({ apiToken, accountId, listId }).sweep();
    process.stdout.write(`Removed ${removed} expired or duplicate Kagami entries.\n`);
    return;
  }
  throw new Error('Use kagami cloudflare setup, status or sweep.');
}

main().catch((err) => {
  process.stderr.write(`${(err as Error)?.message ?? err}\n`);
  process.exitCode = 1;
});
