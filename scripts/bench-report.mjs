// Turns a benchmark round folder into a readable report, and optionally
// publishes it into benchmarks/ for the public repository.
//
//   pnpm bench:report bench-runs/<round>              writes report.md and report.json into the round folder
//   pnpm bench:report bench-runs/<round> --publish    also copies the report and logs into benchmarks/<round>/
//
// Before publishing, every file is checked against the words listed in
// .bench-private-words (one per line, git-ignored). Publishing stops if any
// of them appear, so private names never reach the public repository.
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { verifyChain } from '../packages/node/dist/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { values, positionals } = parseArgs({
  args: process.argv.slice(2).filter((a) => a !== '--'),
  allowPositionals: true,
  options: { publish: { type: 'boolean', default: false } },
});
const runDir = positionals[0] ? resolve(positionals[0]) : null;
if (!runDir || !existsSync(join(runDir, 'run.json'))) {
  console.error('Give the round folder, for example pnpm bench:report bench-runs/2026-11-16T09-00-00-artex-default');
  process.exit(2);
}

const readLines = (file) =>
  existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter((l) => l.trim() !== '') : [];

const run = JSON.parse(readFileSync(join(runDir, 'run.json'), 'utf8'));
const eventLines = readLines(join(runDir, 'kagami-events.jsonl'));
const events = eventLines.map((l) => JSON.parse(l));
const access = readLines(join(runDir, 'access.jsonl')).map((l) => JSON.parse(l));
const chain = verifyChain(eventLines);

// ---------- analysis ----------

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const TRIPWIRES = new Set(['honeytoken.used', 'decoy.param', 'tamper.sealed_value']);

const ms = (iso) => Date.parse(iso);
const start = ms(run.started_at);
const finish = run.finished_at ? ms(run.finished_at) : Math.max(start, ...access.map((a) => ms(a.ts)));

function duration(msValue) {
  if (!Number.isFinite(msValue) || msValue < 0) return 'n/a';
  const s = Math.round(msValue / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${s % 60} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

const cell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').slice(0, 80);

const sessions = new Map();
const session = (id) => {
  if (!sessions.has(id)) sessions.set(id, { id, source: '', requests: [], events: [] });
  return sessions.get(id);
};
for (const a of access) {
  if (!a.kagami?.session) continue;
  const s = session(a.kagami.session);
  s.requests.push(a);
  s.source ||= a.kagami.source ?? '';
}
for (const e of events) {
  if (!e.session?.id) continue;
  const s = session(e.session.id);
  s.events.push(e);
  s.source ||= e.session.source ?? '';
}

// Access records are written when a response finishes. Subtracting the
// recorded duration gives the moment the request arrived, which is when
// Kagami stamps its events.
const arrived = (a) => ms(a.ts) - (a.ms ?? 0);

function note(e) {
  const ev = e.evidence ?? {};
  if (e.rule === 'honeytoken.used') return `${ev.token_kind} issued to source ${ev.issued_to_source ?? ev.issued_to_session}`;
  if (e.rule === 'client.forged_forwarding') return `${ev.header} set to ${ev.snippet}`;
  if (e.rule === 'request.malformed_body') return `parser error ${ev.error}`;
  if (e.rule === 'session.flagged' && ev.linked_from_session) return `linked by a honeytoken used in session ${String(ev.linked_from_session).slice(0, 8)}`;
  if (e.rule === 'session.flagged') return `score ${e.session?.score}`;
  if (ev.param) return `parameter ${ev.param} in ${ev.location}`;
  if (ev.pattern) return `matched ${ev.pattern}`;
  if (ev.count) return `${ev.count} responses in ${ev.window_secs} s`;
  if (ev.matched) return `client ${ev.matched}`;
  return '';
}

const rows = [];
for (const s of sessions.values()) {
  s.requests.sort((a, b) => arrived(a) - arrived(b));
  const first = s.requests[0];
  const detections = s.events.filter((e) => e.kind === 'detection');
  const firstSeen = Math.min(
    s.requests.length ? arrived(s.requests[0]) : Infinity,
    s.events.length ? ms(s.events[0].ts) : Infinity,
  );
  const flagged = s.events.find((e) => e.rule === 'session.flagged');
  const firstDetection = detections[0];
  const firstTripwire = detections.find((e) => TRIPWIRES.has(e.rule));
  const before = (t) => Math.max(1, s.requests.filter((r) => arrived(r) <= t + 1).length);
  const ip = first?.ip ?? s.events[0]?.source?.ip ?? '';
  rows.push({
    id: s.id,
    // Rounds recorded before sources existed fall back to the address.
    source: s.source || `address ${ip}`,
    ip,
    client: first?.ua ?? s.events[0]?.source?.user_agent ?? '',
    requests: s.requests.length,
    detected: detections.length > 0,
    flagged: Boolean(flagged),
    maxSeverity: detections.reduce((m, e) => (SEVERITY_RANK[e.severity] > SEVERITY_RANK[m] ? e.severity : m), 'info'),
    firstDetection: firstDetection && { rule: firstDetection.rule, after: ms(firstDetection.ts) - firstSeen, request: before(ms(firstDetection.ts)) },
    firstTripwire: firstTripwire && { rule: firstTripwire.rule, after: ms(firstTripwire.ts) - firstSeen, request: before(ms(firstTripwire.ts)) },
    flaggedAt: flagged && { after: ms(flagged.ts) - firstSeen, request: before(ms(flagged.ts)) },
    rules: [...new Set(detections.map((e) => e.rule))],
    firstSeen,
    timeline: s.events
      .filter((e) => e.kind === 'detection' || e.rule === 'session.flagged')
      .map((e) => ({ after: ms(e.ts) - firstSeen, rule: e.rule, severity: e.severity, path: e.request?.path ?? '', note: note(e) })),
    crossSession: detections.some((e) => e.rule === 'honeytoken.used' && e.evidence?.cross_session),
  });
}
const detected = rows.filter((r) => r.detected || r.flagged).sort((a, b) => a.firstSeen - b.firstSeen);
const quiet = rows.filter((r) => !r.detected && !r.flagged);

// One source is one machine. An agent that switches tools or user agents
// shows up as several sessions but a single source.
const sources = new Map();
for (const r of rows) {
  const g = sources.get(r.source) ?? { source: r.source, ip: r.ip, sessions: 0, requests: 0, detected: 0, flagged: 0, firstDetection: Infinity };
  g.sessions++;
  g.requests += r.requests;
  if (r.detected) g.detected++;
  if (r.flagged) g.flagged++;
  if (r.firstDetection) g.firstDetection = Math.min(g.firstDetection, r.firstSeen + r.firstDetection.after);
  sources.set(r.source, g);
}
const sourceRows = [...sources.values()].sort((a, b) => b.requests - a.requests);

const ruleCounts = new Map();
for (const e of events.filter((e) => e.kind === 'detection')) {
  const c = ruleCounts.get(e.rule) ?? { rule: e.rule, title: e.title, severity: e.severity, sessions: new Set() };
  c.sessions.add(e.session?.id);
  ruleCounts.set(e.rule, c);
}
const honeytokens = events.filter((e) => e.rule === 'honeytoken.used');
const decoyHits = access.filter((a) => events.some((e) => e.rule === 'decoy.route' && e.request?.path === a.path)).length;

const summary = {
  label: run.label,
  kagami_version: run.kagami_version,
  mode: run.mode,
  started_at: run.started_at,
  duration_ms: finish - start,
  chain_ok: chain.ok,
  events: events.length,
  requests: access.length,
  sessions: rows.length,
  sessions_detected: detected.length,
  sessions_flagged: rows.filter((r) => r.flagged).length,
  sessions_quiet: quiet.length,
  sources: sourceRows.length,
  sources_flagged: sourceRows.filter((g) => g.flagged > 0).length,
  honeytokens_used: honeytokens.length,
  decoy_route_requests: decoyHits,
  fastest_tripwire_ms: Math.min(...detected.filter((r) => r.firstTripwire).map((r) => r.firstTripwire.after)),
  fastest_flag_ms: Math.min(...detected.filter((r) => r.flaggedAt).map((r) => r.flaggedAt.after)),
  sources_detail: sourceRows.map((g) => ({ ...g, firstDetection: Number.isFinite(g.firstDetection) ? g.firstDetection - start : null })),
  sessions_detail: detected.map(({ timeline, firstSeen, ...r }) => r),
};

// ---------- report ----------

const md = [];
const label = run.label ?? basename(runDir);
md.push(`# Benchmark round ${label}`, '');
md.push(
  `Kagami ${run.kagami_version} ran in ${run.mode} mode. The round started at ${run.started_at.replace('T', ' ').replace(/\.\d+Z$/, ' UTC')} and lasted ${duration(finish - start)}.`,
  chain.ok
    ? `The event log hash chain verifies, covering ${chain.events} events.`
    : `The event log hash chain does not verify. It breaks at line ${chain.line} because of ${chain.reason}.`,
  '',
);

md.push('## Result', '', '| Measure | Value |', '|---|---|');
md.push(`| Requests served | ${access.length} |`);
md.push(`| Sources seen (one per machine) | ${sourceRows.length} |`);
md.push(`| Sources with a flagged session | ${summary.sources_flagged} |`);
md.push(`| Sessions seen | ${rows.length} |`);
md.push(`| Sessions with detections | ${detected.length} |`);
md.push(`| Sessions flagged as attackers | ${summary.sessions_flagged} |`);
md.push(`| Sessions with no detections | ${quiet.length} |`);
md.push(`| Honeytokens used | ${honeytokens.length}${honeytokens.some((e) => e.evidence?.cross_session) ? ', including use from a different session than the one they were issued to' : ''} |`);
md.push(`| Requests to decoy routes | ${decoyHits} |`);
md.push(`| Fastest first tripwire | ${Number.isFinite(summary.fastest_tripwire_ms) ? duration(summary.fastest_tripwire_ms) : 'none'} |`);
md.push(`| Fastest flag | ${Number.isFinite(summary.fastest_flag_ms) ? duration(summary.fastest_flag_ms) : 'none'} |`);
md.push('');

if (sourceRows.length) {
  md.push('## Sources', '');
  md.push('A source is one machine. Different tools or user agents on that machine are separate sessions of the same source.', '');
  md.push('| Source | Address | Sessions | Requests | Sessions with detections | Sessions flagged | First detection |', '|---|---|---|---|---|---|---|');
  for (const g of sourceRows.slice(0, 25)) {
    const first = Number.isFinite(g.firstDetection) ? `${duration(g.firstDetection - start)} into the round` : 'none';
    md.push(`| \`${cell(g.source).slice(0, 24)}\` | ${cell(g.ip)} | ${g.sessions} | ${g.requests} | ${g.detected} | ${g.flagged} | ${first} |`);
  }
  if (sourceRows.length > 25) md.push('', `${sourceRows.length - 25} more sources are listed in report.json.`);
  md.push('');
}

if (detected.length) {
  md.push('## Sessions with detections', '');
  md.push('| Session | Source | Client | Requests | First detection | First tripwire | Flagged | Highest severity |', '|---|---|---|---|---|---|---|---|');
  for (const r of detected) {
    const at = (x) => (x ? `${duration(x.after)} (request ${x.request})` : 'no');
    md.push(
      `| \`${r.id.slice(0, 8)}\` | ${cell(r.ip)} | ${cell(r.client)} | ${r.requests} | ${r.firstDetection ? `${at(r.firstDetection)}, \`${r.firstDetection.rule}\`` : 'no'} | ${r.firstTripwire ? `${at(r.firstTripwire)}, \`${r.firstTripwire.rule}\`` : 'no'} | ${at(r.flaggedAt)} | ${r.maxSeverity} |`,
    );
  }
  md.push('');

  md.push('## Detection timelines', '');
  for (const r of detected) {
    md.push(`### Session \`${r.id.slice(0, 8)}\``, '');
    md.push('| Time after first request | Rule | Severity | Path | Note |', '|---|---|---|---|---|');
    for (const t of r.timeline) md.push(`| ${duration(t.after)} | \`${t.rule}\` | ${t.severity} | \`${cell(t.path)}\` | ${cell(t.note)} |`);
    md.push('');
  }
}

if (ruleCounts.size) {
  md.push('## Rules that fired', '', '| Rule | Description | Severity | Sessions |', '|---|---|---|---|');
  for (const c of [...ruleCounts.values()].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]))
    md.push(`| \`${c.rule}\` | ${c.title} | ${c.severity} | ${c.sessions.size} |`);
  md.push('');
}

md.push('## Files', '');
md.push('- `kagami-events.jsonl` holds every Kagami event. Verify it with `npx @agenticslabs/kagami verify-log kagami-events.jsonl`.');
md.push('- `access.jsonl` holds every request the demo served, without bodies, cookies or header values other than the user agent.');
md.push('- `run.json` holds the round settings and timing.');
md.push('- `report.json` holds the numbers in this report in machine-readable form.', '');

const reportMd = md.join('\n');
writeFileSync(join(runDir, 'report.md'), reportMd);
writeFileSync(join(runDir, 'report.json'), JSON.stringify(summary, (k, v) => (v === Infinity ? null : v), 2) + '\n');
console.log(`Report written to ${relative(root, join(runDir, 'report.md'))}`);

// ---------- publish ----------

if (values.publish) {
  if (!chain.ok) {
    console.error('Not publishing because the event log hash chain does not verify.');
    process.exit(1);
  }
  const privateFile = join(root, '.bench-private-words');
  const words = existsSync(privateFile)
    ? readFileSync(privateFile, 'utf8').split('\n').map((w) => w.trim().toLowerCase()).filter((w) => w && !w.startsWith('#'))
    : [];
  const files = ['report.md', 'report.json', 'run.json', 'kagami-events.jsonl', 'access.jsonl'].filter((f) => existsSync(join(runDir, f)));
  const leaks = [];
  for (const f of files) {
    const text = readFileSync(join(runDir, f), 'utf8').toLowerCase();
    for (const w of words) if (text.includes(w)) leaks.push(`${f} contains a private word (line ${text.slice(0, text.indexOf(w)).split('\n').length})`);
  }
  if (leaks.length) {
    console.error('Not publishing. Private words were found.\n' + leaks.map((l) => '  ' + l).join('\n'));
    process.exit(1);
  }
  if (!words.length) console.warn('No .bench-private-words file found, so no private-word check was done.');

  const dest = join(root, 'benchmarks', basename(runDir));
  mkdirSync(dest, { recursive: true });
  for (const f of files) copyFileSync(join(runDir, f), join(dest, f));

  // Rebuild the index of published rounds.
  const index = ['# Benchmark results', '', 'Each round below was run with the method in [docs/BENCHMARK.md](../docs/BENCHMARK.md). Every folder holds the full report and the raw, hash-chained logs.', ''];
  index.push('| Round | Date | Mode | Requests | Sessions detected | Sessions flagged | Fastest tripwire | Fastest flag |', '|---|---|---|---|---|---|---|---|');
  const rounds = readdirSync(join(root, 'benchmarks'), { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(root, 'benchmarks', d.name, 'report.json')))
    .map((d) => ({ dir: d.name, r: JSON.parse(readFileSync(join(root, 'benchmarks', d.name, 'report.json'), 'utf8')) }))
    .sort((a, b) => b.r.started_at.localeCompare(a.r.started_at));
  for (const { dir, r } of rounds) {
    index.push(
      `| [${r.label ?? dir}](${dir}/report.md) | ${r.started_at.slice(0, 10)} | ${r.mode} | ${r.requests} | ${r.sessions_detected} of ${r.sessions} | ${r.sessions_flagged} | ${r.fastest_tripwire_ms == null ? 'none' : duration(r.fastest_tripwire_ms)} | ${r.fastest_flag_ms == null ? 'none' : duration(r.fastest_flag_ms)} |`,
    );
  }
  writeFileSync(join(root, 'benchmarks', 'README.md'), index.join('\n') + '\n');
  console.log(`Published to ${relative(root, dest)} and updated benchmarks/README.md`);
}
