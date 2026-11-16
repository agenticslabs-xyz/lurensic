#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { verifyChain } from './chain.js';
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

main().catch((err) => {
  process.stderr.write(`${(err as Error)?.message ?? err}\n`);
  process.exitCode = 1;
});
