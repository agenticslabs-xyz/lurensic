// Turns a benchmark round folder into a readable report, and optionally
// publishes it into benchmarks/ for the public repository.
//
//   pnpm bench:report bench-runs/<round>              writes report.md and report.json into the round folder
//   pnpm bench:report bench-runs/<round> --publish    also copies the report and logs into benchmarks/<round>/
//
// Before publishing, every file is checked against the words listed in
// .bench-private-words (one per line, git-ignored). Publishing stops if any
// of them appear, so private names never reach the public repository.
//
// An optional harness.json in the round folder adds the attacker's side of
// the round, which Lurensic cannot see. All fields are optional.
//   {
//     "harness": "ARTEX",
//     "findings": { "decoy": 0, "real": 1, "lurensic_artefact": 0 },
//     "llm_calls": 205, "input_tokens": 5881433, "output_tokens": 240257,
//     "notes": "Free text about how the attacker treated the decoys."
//   }
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { Lurensic, verifyChain } from '../packages/node/dist/index.js';

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
// Rounds recorded before the project was renamed keep their original log file name.
const EVENTS_FILE = ['lurensic-events.jsonl', 'kagami-events.jsonl'].find((f) => existsSync(join(runDir, f))) ?? 'lurensic-events.jsonl';
const eventLines = readLines(join(runDir, EVENTS_FILE));
const events = eventLines.map((l) => JSON.parse(l));
// The warm-up visitor's requests are the operator's own and are left out.
const isWarmup = (a) => (a.header_order ?? []).some((h) => String(h).toLowerCase() === 'x-bench-warmup');
const allAccess = readLines(join(runDir, 'access.jsonl')).map((l) => JSON.parse(l));
const access = allAccess.filter((a) => !isWarmup(a));
const warmupRequests = allAccess.length - access.length;
// Each engine announces itself once. More than one start means the engine was
// rebuilt after an internal error, and its in-memory state was lost.
const engineRestarts = Math.max(0, events.filter((e) => e.rule === 'system.started').length - 1);
const chain = await verifyChain(eventLines);

// ---------- analysis ----------

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const TRIPWIRES = new Set(['honeytoken.used', 'decoy.param', 'decoy.route', 'tamper.sealed_value', 'tamper.unsigned_jwt', 'tamper.decoy_secret']);

const ms = (iso) => Date.parse(iso);
// Times count from the attacker's first request, because the operator may
// start the attack long after the service. Health checks are left out, since
// they are the operator's own.
const serviceStart = ms(run.started_at);
const attackTimes = access.filter((a) => a.path !== '/healthz').map((a) => ms(a.ts) - (a.ms ?? 0));
const start = attackTimes.length ? attackTimes.reduce((x, y) => Math.min(x, y)) : serviceStart;
const finish = access.length
  ? access.reduce((x, a) => Math.max(x, ms(a.ts)), start)
  : run.finished_at
    ? ms(run.finished_at)
    : start;

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
  // Health checks are the operator's own and are skipped by Lurensic.
  if (!a.lurensic?.session || a.path === '/healthz') continue;
  const s = session(a.lurensic.session);
  s.requests.push(a);
  s.source ||= a.lurensic.source ?? '';
}
for (const e of events) {
  if (!e.session?.id) continue;
  const s = session(e.session.id);
  s.events.push(e);
  s.source ||= e.session.source ?? '';
}

// Access records are written when a response finishes. Subtracting the
// recorded duration gives the moment the request arrived, which is when
// Lurensic stamps its events.
const arrived = (a) => ms(a.ts) - (a.ms ?? 0);

function note(e) {
  const ev = e.evidence ?? {};
  if (e.rule === 'honeytoken.used') return `${ev.token_kind} issued to source ${ev.issued_to_source ?? ev.issued_to_session}`;
  if (e.rule === 'client.forged_forwarding') return `${ev.header} set to ${ev.snippet}`;
  if (e.rule === 'request.malformed_body') return `parser error ${ev.error}`;
  if (e.rule === 'request.absolute_target') return `request target starts with ${ev.snippet}`;
  if (e.rule === 'containment.started') return `${ev.linked ? 'linked machine' : 'machine'} contained after \`${ev.reason}\`${ev.enforced ? '' : ', dry run'}`;
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
      .filter((e) => e.kind === 'detection' || e.rule === 'session.flagged' || e.rule === 'containment.started')
      .map((e) => ({ after: ms(e.ts) - firstSeen, rule: e.rule, severity: e.severity, path: e.request?.path ?? '', note: note(e) })),
    crossSession: detections.some((e) => e.rule === 'honeytoken.used' && (e.evidence?.cross_source ?? e.evidence?.cross_session)),
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

// ---------- deception engagement ----------
//
// Which requests went to Lurensic's decoys, and how much of the attacker's
// time they took. Decoy names are derived from the round's secret, so they
// are recomputed here from .lurensic-secret, which never leaves the round folder.

async function loadDecoys() {
  const file = join(runDir, '.lurensic-secret');
  if (!existsSync(file)) return null;
  const k = new Lurensic({ secret: readFileSync(file, 'utf8').trim(), mode: 'observe', sinks: [], logger: { warn() {} } });
  const decoys = k.manifest()?.decoys ?? null;
  await k.close();
  return decoys;
}
const decoys = await loadDecoys();

const BAIT_FILE = /^\/(\.env(\..*)?|\.git\/config|\.aws\/credentials)$/;
const DECOY_KINDS = {
  honeytoken: 'Planted credential used',
  decoy_route: 'Decoy routes',
  decoy_spec: 'Decoy API description',
  forged_session: 'Session or token signed with the decoy secret',
  bait_file: 'Fake secret files',
  decoy_field: 'Decoy field sent with a changed value',
  decoy_param: 'Decoy debug parameter',
};
const decode = (s) => {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
};
// Absolute-form targets (`http://host/path`) are routed on the path alone.
const normPath = (p) => decode(p.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, '') || '/').toLowerCase().replace(/\\/g, '/').replace(/\/+/g, '/').replace(/(.)\/$/, '$1');
const queryNames = (q) =>
  (q ? q.split('&') : []).map((pair) => decode(pair.split('=')[0]).toLowerCase().replace(/\]+$/, '').split(/[[.]/).pop());

function decoyKind(a) {
  const p = normPath(a.path);
  const rules = a.lurensic?.rules;
  if (rules?.includes('honeytoken.used')) return 'honeytoken';
  if (rules?.includes('tamper.decoy_secret')) return 'forged_session';
  if (rules?.includes('decoy.route') || decoys?.routes?.includes(p)) return 'decoy_route';
  if (rules?.includes('decoy.spec')) return 'decoy_spec';
  if (run.mode === 'protect' && a.status === 200 && BAIT_FILE.test(p)) return 'bait_file';
  // Rounds from 2026-11-16 on log the rules each request matched, which
  // covers decoy fields sent in a request body. Older rounds fall back to
  // matching decoy names in the query string.
  if (rules) return rules.includes('decoy.param') ? 'decoy_field' : null;
  const names = decoys ? queryNames(a.query) : [];
  if (names.includes(decoys?.json_field)) return 'decoy_field';
  if (names.includes(decoys?.debug_param)) return 'decoy_param';
  return null;
}

// Time spent on a decoy request is the gap since the previous request from
// the same source, capped at one minute. That gap is when the agent decided
// to send it. Bodies are not logged, so decoy fields sent in a body are only
// visible as `decoy.param` events and are not counted here.
const GAP_CAP_MS = 60_000;
const lastBySource = new Map();
const engagement = { requests: 0, time_ms: 0, first_ms: null, last_ms: null, by_kind: {} };
for (const a of [...access].sort((x, y) => arrived(x) - arrived(y))) {
  const src = a.lurensic?.source ?? a.ip;
  const t = arrived(a);
  const prev = lastBySource.get(src);
  lastBySource.set(src, t);
  const kind = decoyKind(a);
  if (!kind) continue;
  engagement.requests++;
  engagement.by_kind[kind] = (engagement.by_kind[kind] ?? 0) + 1;
  engagement.time_ms += prev === undefined ? 0 : Math.min(GAP_CAP_MS, Math.max(0, t - prev));
  engagement.first_ms ??= t - start;
  engagement.last_ms = t - start;
}

// Deception touchpoints. Each row counts the sessions that touched it and
// when the first touch happened in the round.
const TOUCHPOINTS = [
  ['honeytoken.used', 'Used a planted credential'],
  ['decoy.param', 'Sent a decoy field or parameter'],
  ['tamper.sealed_value', 'Tampered with a sealed value'],
  ['decoy.route', 'Requested a decoy route'],
  ['decoy.spec', 'Fetched the decoy API description'],
  ['tamper.unsigned_jwt', 'Sent an unsigned JWT'],
  ['tamper.decoy_secret', 'Signed a cookie or token with the decoy secret'],
  ['bait.path', 'Probed a sensitive file path'],
];
const touchpoints = TOUCHPOINTS.map(([rule, label]) => {
  const hits = events.filter((e) => e.rule === rule);
  return { rule, label, sessions: new Set(hits.map((e) => e.session?.id)).size, first_ms: hits.length ? ms(hits[0].ts) - start : null };
});

// ---------- containment and planted bugs ----------
//
// Containment cuts a machine off from the application after a tripwire. The
// access log marks every contained request, and every request that exploited
// a planted bug (rounds run with --planted). Together they answer the
// question that matters, whether the attacker reached real bugs.

const containmentEvents = events.filter((e) => e.rule === 'containment.started');
const containedRequests = access.filter((a) => a.lurensic?.contained).length;
const firstContained = new Map();
for (const e of containmentEvents) {
  const src = e.evidence?.contained_source;
  if (src && !firstContained.has(src)) firstContained.set(src, ms(e.ts));
}
// Requests from a machine that reached the app after it was contained.
// The demo shop's health check is in Lurensic's ignorePaths, which match by
// prefix, so it and everything under it is never contained by design.
const healthCheck = (a) => normPath(a.path) === '/healthz' || normPath(a.path).startsWith('/healthz/');
const leaked = access.filter((a) => {
  const t = firstContained.get(a.lurensic?.source);
  return t !== undefined && arrived(a) > t + 1 && !a.lurensic?.contained && a.lurensic?.session && !healthCheck(a);
}).length;
const containment = {
  setting: run.containment ?? (containmentEvents.length ? 'on' : 'off'),
  machines: firstContained.size,
  enforced: containmentEvents.some((e) => e.evidence?.enforced),
  first_ms: containmentEvents.length ? ms(containmentEvents[0].ts) - start : null,
  contained_requests: containedRequests,
  reached_app_after_containment: leaked,
};

const PLANTED = { path_traversal: 'Path traversal on /downloads', reflected_xss: 'Reflected cross-site scripting on /products' };
const plantedHits = access.filter((a) => a.planted);
const planted = run.planted_bugs
  ? Object.entries(PLANTED).map(([bug, label]) => {
      const hits = plantedHits.filter((a) => a.planted === bug).sort((a, b) => arrived(a) - arrived(b));
      return { bug, label, requests: hits.length, first_ms: hits.length ? arrived(hits[0]) - start : null };
    })
  : null;

// The app's own response through onDetect (rounds run with --respond). The
// access log marks every request the app refused because it had blocked the
// sender, with the rule that caused the block.
const blockedRequests = access.filter((a) => a.blocked).sort((a, b) => arrived(a) - arrived(b));
const firstBlock = blockedRequests[0];
const response = run.respond_on_detect
  ? {
      blocked_requests: blockedRequests.length,
      first_block_ms: firstBlock ? arrived(firstBlock) - start : null,
      first_block_rule: firstBlock?.blocked ?? null,
      reached_app_after_block: firstBlock ? access.filter((a) => !a.blocked && arrived(a) > arrived(firstBlock) && a.path !== '/healthz').length : 0,
      planted_after_block: firstBlock ? plantedHits.filter((a) => arrived(a) > arrived(firstBlock)).length : 0,
    }
  : null;

const harnessFile = join(runDir, 'harness.json');
const harness = existsSync(harnessFile) ? JSON.parse(readFileSync(harnessFile, 'utf8')) : null;
let attacker = null;
if (harness) {
  const f = harness.findings ?? {};
  const [decoy, real, artefact] = [f.decoy ?? 0, f.real ?? 0, f.lurensic_artefact ?? 0];
  const total = decoy + real + artefact;
  attacker = {
    harness: harness.harness ?? null,
    findings_total: total,
    findings_decoy: decoy,
    findings_real: real,
    findings_lurensic_artefact: artefact,
    deception_yield: total ? decoy / total : null,
    llm_calls: harness.llm_calls ?? null,
    input_tokens: harness.input_tokens ?? null,
    output_tokens: harness.output_tokens ?? null,
    input_tokens_per_real_finding: real && harness.input_tokens ? Math.round(harness.input_tokens / real) : null,
    requests_per_real_finding: real ? Math.round(access.length / real) : null,
    notes: harness.notes ?? null,
  };
}

const summary = {
  label: run.label,
  lurensic_version: run.lurensic_version,
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
  decoy_engagement: decoys ? { ...engagement, share: access.length ? engagement.requests / access.length : 0 } : null,
  touchpoints: touchpoints.map(({ label, ...t }) => t),
  containment,
  response,
  engine_restarts: engineRestarts,
  planted_bugs: planted && { reached: planted.filter((p) => p.requests > 0).length, of: planted.length, detail: planted.map(({ label, ...p }) => p) },
  attacker,
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
  `${run.mode === 'off' ? `Lurensic ${run.lurensic_version} was switched off for this baseline round.` : `Lurensic ${run.lurensic_version} ran in ${run.mode} mode${run.containment && run.containment !== 'off' ? ` with ${run.containment} containment` : ''}.`}${run.planted_bugs ? ' The target carried two planted real bugs.' : ''} The service started at ${run.started_at.replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}. The attack began ${duration(start - serviceStart)} later and lasted ${duration(finish - start)}. Times in this report count from the attack's first request.${warmupRequests ? ` An honest visitor made ${warmupRequests} requests before the attack, which are left out.` : ''}`,
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
md.push(`| Honeytokens used | ${honeytokens.length}${honeytokens.some((e) => e.evidence?.cross_source ?? e.evidence?.cross_session) ? ', including use from a different machine than the one they were issued to' : ''} |`);
md.push(`| Requests to decoy routes | ${decoyHits} |`);
md.push(`| Fastest first tripwire | ${Number.isFinite(summary.fastest_tripwire_ms) ? duration(summary.fastest_tripwire_ms) : 'none'} |`);
md.push(`| Fastest flag | ${Number.isFinite(summary.fastest_flag_ms) ? duration(summary.fastest_flag_ms) : 'none'} |`);
md.push(`| Engine restarts after an internal error | ${engineRestarts} |`);
md.push('');

const pct = (x) => `${(x * 100).toFixed(1)} %`;
const num = (x) => (x == null ? 'n/a' : Number(x).toLocaleString('en-US'));

if (planted) {
  md.push('## Planted bugs', '');
  md.push(
    'The target carried two real bugs. A request counts as reaching a bug when the application ran the vulnerable code with exploit input, as marked by the application itself in the access log.',
    '',
  );
  md.push('| Bug | Exploit requests that reached it | First reached |', '|---|---|---|');
  for (const p of planted) md.push(`| ${p.label} | ${p.requests} | ${p.first_ms == null ? 'never' : `${duration(p.first_ms)} into the round`} |`);
  md.push('', `Planted bugs reached: ${summary.planted_bugs.reached} of ${summary.planted_bugs.of}.`, '');
}

if (response) {
  md.push('## Response through onDetect', '');
  md.push(
    "The app acted on Lurensic's events itself, as a developer would. A tripwire blocked the sender's address for the rest of the round, and locked the account when the event named one and `safeToActOnSubject` allowed it.",
    '',
  );
  md.push('| Measure | Value |', '|---|---|');
  md.push(`| First refused request | ${response.first_block_ms == null ? 'none' : `${duration(response.first_block_ms)} into the round, after \`${response.first_block_rule}\``} |`);
  md.push(`| Requests refused by the app | ${num(response.blocked_requests)} |`);
  md.push(`| Requests that still reached the app after the first refusal | ${num(response.reached_app_after_block)} |`);
  if (planted) md.push(`| Planted bug exploits after the first refusal | ${num(response.planted_after_block)} |`);
  md.push('');
}

if (containment.setting !== 'off' || containmentEvents.length) {
  md.push('## Containment', '');
  md.push('| Measure | Value |', '|---|---|');
  md.push(`| Setting | ${containment.setting}${containment.enforced ? '' : ' (dry run, nothing enforced)'} |`);
  md.push(`| Machines contained | ${containment.machines} |`);
  md.push(`| First containment | ${containment.first_ms == null ? 'none' : `${duration(containment.first_ms)} into the round`} |`);
  md.push(`| Requests answered by Lurensic instead of the app | ${num(containment.contained_requests)} |`);
  md.push(`| Requests that reached the app after their machine was contained | ${num(containment.reached_app_after_containment)} |`);
  md.push('');
}

if (attacker) {
  md.push('## Attacker outcome', '');
  md.push(`These numbers come from the attacking harness${attacker.harness ? ` (${cell(attacker.harness)})` : ''} and not from Lurensic.`, '');
  md.push('| Measure | Value |', '|---|---|');
  md.push(`| Findings reported | ${attacker.findings_total} |`);
  md.push(`| Findings caused by Lurensic decoys | ${attacker.findings_decoy} |`);
  md.push(`| Real findings | ${attacker.findings_real} |`);
  if (attacker.findings_lurensic_artefact) md.push(`| Findings about Lurensic itself | ${attacker.findings_lurensic_artefact} |`);
  md.push(`| Deception yield (decoy findings out of all findings) | ${attacker.deception_yield == null ? 'n/a' : pct(attacker.deception_yield)} |`);
  md.push(`| LLM calls | ${num(attacker.llm_calls)} |`);
  md.push(`| Input tokens | ${num(attacker.input_tokens)} |`);
  md.push(`| Output tokens | ${num(attacker.output_tokens)} |`);
  md.push(`| Input tokens per real finding | ${attacker.findings_real ? num(attacker.input_tokens_per_real_finding) : 'no real findings'} |`);
  md.push(`| Requests per real finding | ${attacker.findings_real ? num(attacker.requests_per_real_finding) : 'no real findings'} |`);
  md.push('');
  if (attacker.notes) md.push(String(attacker.notes).replace(/[\r\n]+/g, ' '), '');
}

md.push('## Deception touchpoints', '');
md.push('A deceptive defence works even when the attacker reports nothing from it, as long as the attacker touches the decoys and spends time on them.', '');
md.push('| Touchpoint | Rule | Sessions | First touch |', '|---|---|---|---|');
for (const t of touchpoints) md.push(`| ${t.label} | \`${t.rule}\` | ${t.sessions} | ${t.first_ms == null ? 'none' : `${duration(t.first_ms)} into the round`} |`);
md.push('');
if (decoys) {
  md.push('| Requests aimed at decoys | Value |', '|---|---|');
  md.push(`| All decoy requests | ${engagement.requests} of ${access.length} (${pct(access.length ? engagement.requests / access.length : 0)}) |`);
  for (const [kind, label] of Object.entries(DECOY_KINDS)) md.push(`| ${label} | ${engagement.by_kind[kind] ?? 0} |`);
  md.push(`| Attacker time on decoy requests | ${duration(engagement.time_ms)} |`);
  md.push(
    `| First and last decoy request | ${engagement.first_ms == null ? 'none' : `${duration(engagement.first_ms)} and ${duration(engagement.last_ms)} into the round`} |`,
  );
  md.push('');
  md.push(
    'Time on a decoy request is the gap since the previous request from the same machine, capped at one minute. ' +
      (access.some((a) => a.lurensic?.rules)
        ? 'Decoy fields are counted from the rules Lurensic matched on each request, so fields sent in a request body are included.'
        : 'This round was recorded before per-request rules were logged. Request bodies are not logged, so decoy fields sent in a body show up only as `decoy.param` events above.'),
    '',
  );
}

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
  // Keep the report readable when an attacker spreads over many sessions.
  // The busiest sessions are shown, in the order they appeared, and every
  // session is still listed in report.json.
  const MAX_SESSIONS = 25;
  const MAX_TIMELINES = 10;
  const busiest = [...detected].sort((a, b) => b.requests - a.requests);
  const shown = busiest.slice(0, MAX_SESSIONS).sort((a, b) => a.firstSeen - b.firstSeen);
  const rest = busiest.slice(MAX_SESSIONS);
  md.push('## Sessions with detections', '');
  if (rest.length) md.push(`The ${MAX_SESSIONS} busiest of ${detected.length} sessions are shown.`, '');
  md.push('| Session | Source | Client | Requests | First detection | First tripwire | Flagged | Highest severity |', '|---|---|---|---|---|---|---|---|');
  for (const r of shown) {
    const at = (x) => (x ? `${duration(x.after)} (request ${x.request})` : 'no');
    md.push(
      `| \`${r.id.slice(0, 8)}\` | ${cell(r.ip)} | ${cell(r.client)} | ${r.requests} | ${r.firstDetection ? `${at(r.firstDetection)}, \`${r.firstDetection.rule}\`` : 'no'} | ${r.firstTripwire ? `${at(r.firstTripwire)}, \`${r.firstTripwire.rule}\`` : 'no'} | ${at(r.flaggedAt)} | ${r.maxSeverity} |`,
    );
  }
  if (rest.length) {
    const sum = (f) => rest.filter(f).length;
    md.push(
      `| ${rest.length} more | | | ${rest.reduce((n, r) => n + r.requests, 0)} | ${rest.length} | ${sum((r) => r.firstTripwire)} | ${sum((r) => r.flaggedAt)} | |`,
    );
  }
  md.push('');

  md.push('## Detection timelines', '');
  if (detected.length > MAX_TIMELINES) md.push(`Timelines for the ${MAX_TIMELINES} busiest sessions.`, '');
  for (const r of busiest.slice(0, MAX_TIMELINES).sort((a, b) => a.firstSeen - b.firstSeen)) {
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
md.push('- `lurensic-events.jsonl` holds every Lurensic event. Verify it with `npx @agenticslabs/lurensic verify-log lurensic-events.jsonl`.');
md.push('- `access.jsonl` holds every request the demo served, without bodies, cookies or header values other than the user agent.');
md.push('- `run.json` holds the round settings and timing.');
if (harness) md.push('- `harness.json` holds the attacking harness results, entered by the person who ran the round.');
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
  const files = ['report.md', 'report.json', 'run.json', 'harness.json', EVENTS_FILE, 'access.jsonl'].filter((f) => existsSync(join(runDir, f)));
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
  // A long round's request log runs to tens of megabytes, which would stay in
  // the repository's history for good. It is published gzipped. The event log,
  // which the hash chain covers, is always published as it is.
  const accessCopy = join(dest, 'access.jsonl');
  if (existsSync(accessCopy) && statSync(accessCopy).size > 5 * 1024 * 1024) {
    writeFileSync(accessCopy + '.gz', gzipSync(readFileSync(accessCopy), { level: 9 }));
    rmSync(accessCopy);
  }

  // Rebuild the index of published rounds.
  const index = ['# Benchmark results', '', 'Each round below was run with the method in [docs/BENCHMARK.md](../docs/BENCHMARK.md). Every folder holds the full report and the raw, hash-chained logs.', ''];
  index.push('| Round | Date | Mode | Containment | Requests | Sessions flagged | Fastest flag | Planted bugs reached |', '|---|---|---|---|---|---|---|---|');
  const rounds = readdirSync(join(root, 'benchmarks'), { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(root, 'benchmarks', d.name, 'report.json')))
    .map((d) => ({ dir: d.name, r: JSON.parse(readFileSync(join(root, 'benchmarks', d.name, 'report.json'), 'utf8')) }))
    .sort((a, b) => b.r.started_at.localeCompare(a.r.started_at));
  for (const { dir, r } of rounds) {
    index.push(
      `| [${r.label ?? dir}](${dir}/report.md) | ${r.started_at.slice(0, 10)} | ${r.mode} | ${r.containment?.setting ?? 'off'} | ${r.requests} | ${r.sessions_flagged} | ${r.fastest_flag_ms == null ? 'none' : duration(r.fastest_flag_ms)} | ${r.planted_bugs ? `${r.planted_bugs.reached} of ${r.planted_bugs.of}` : 'none planted'} |`,
    );
  }
  writeFileSync(join(root, 'benchmarks', 'README.md'), index.join('\n') + '\n');
  console.log(`Published to ${relative(root, dest)} and updated benchmarks/README.md`);
}
