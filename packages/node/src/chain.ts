/**
 * Verify a Kagami event log's hash chain (see docs/DESIGN.md#audit-log).
 * Works on the raw JSON lines exactly as written by the sinks.
 */
import { createHash } from 'node:crypto';

export type ChainResult =
  | { ok: true; events: number; instances: number }
  | { ok: false; line: number; reason: string };

const SUFFIX = /,"hash":"([0-9a-f]{64})"\}$/;
const GENESIS = '0'.repeat(64);

export function verifyChain(lines: string[]): ChainResult {
  // A log may interleave several processes; each `instance` has its own chain.
  const prevByInstance = new Map<string, string>();
  let count = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trimEnd();
    if (!line) continue;
    const m = SUFFIX.exec(line);
    if (!m) return { ok: false, line: i + 1, reason: 'missing or malformed hash field' };
    const body = line.slice(0, line.length - m[0].length) + '}';
    let parsed: { prev_hash?: string; instance?: string; seq?: number };
    try {
      parsed = JSON.parse(body);
    } catch {
      return { ok: false, line: i + 1, reason: 'not valid JSON' };
    }
    const key = `${parsed.instance ?? ''}`;
    const expected = prevByInstance.get(key);
    // A restart begins a fresh chain at seq 0 from the genesis hash.
    const restart = parsed.seq === 0 && parsed.prev_hash === GENESIS;
    if (expected !== undefined && parsed.prev_hash !== expected && !restart) {
      return { ok: false, line: i + 1, reason: 'chain broken (event missing, reordered or inserted)' };
    }
    const digest = createHash('sha256').update(`${parsed.prev_hash}\n${body}`).digest('hex');
    if (digest !== m[1]) return { ok: false, line: i + 1, reason: 'hash mismatch (event was modified)' };
    prevByInstance.set(key, m[1]!);
    count++;
  }
  return { ok: true, events: count, instances: prevByInstance.size };
}
