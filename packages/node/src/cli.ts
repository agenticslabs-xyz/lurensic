#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyChain } from './chain.js';

const HELP = `kagami - deception-based defence against AI-driven attacks

Usage:
  kagami secret              Print a new random deployment secret (KAGAMI_SECRET)
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
      process.stderr.write('Usage: kagami verify-log <file>\n');
      process.exit(2);
    }
    const res = verifyChain(readFileSync(file, 'utf8').split('\n'));
    if (res.ok) {
      process.stdout.write(`OK: ${res.events} events across ${res.instances} instance(s), chain intact.\n`);
    } else {
      process.stdout.write(`TAMPERED: line ${res.line}: ${res.reason}\n`);
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
