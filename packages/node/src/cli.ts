#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyChain } from './chain.js';

const HELP = `Kagami command line tool. Deception-based defence against AI-driven attacks.

Commands
  kagami secret              Print a new random deployment secret for KAGAMI_SECRET
  kagami verify-log <file>   Verify the hash chain of a Kagami JSON-lines event log
  kagami help                Show this help
`;

const [cmd, ...args] = process.argv.slice(2);

switch (cmd) {
  case 'secret':
    process.stdout.write(randomBytes(32).toString('hex') + '\n');
    break;
  case 'verify-log': {
    const file = args[0];
    if (!file) {
      process.stderr.write('Give the log file to check, for example kagami verify-log kagami-events.jsonl\n');
      process.exit(2);
    }
    const res = verifyChain(readFileSync(file, 'utf8').split('\n'));
    if (res.ok) {
      process.stdout.write(`Chain intact. Checked ${res.events} events across ${res.instances} instance(s).\n`);
    } else {
      process.stdout.write(`Tampering detected at line ${res.line}. Reason is ${res.reason}.\n`);
      process.exit(1);
    }
    break;
  }
  case undefined:
  case 'help':
  case '--help':
  case '-h':
    process.stdout.write(HELP);
    break;
  default:
    process.stderr.write(`Unknown command "${cmd}".\n\n${HELP}`);
    process.exit(2);
}
