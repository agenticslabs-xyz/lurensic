/**
 * `kagami doctor` checks that Kagami is installed and working, for people and
 * for AI coding agents that integrate it. Every check reports a status and,
 * when something is wrong, the fix.
 *
 * The doctor never touches a tripwire. With containment on, a tripwire would
 * cut off the machine running the doctor. Its live probes ask for `/.env`,
 * which Kagami answers with a fake file in protect mode and which records one
 * `bait.path` event, and for the deployment's decoy API description, which
 * records one low `decoy.spec` event. Neither ever contains. Requests carry the
 * user agent `kagami-doctor/<version>` so they are easy to recognise in logs.
 */
import { existsSync, readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { Kagami } from './kagami.js';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface Check {
  id: string;
  status: CheckStatus;
  message: string;
  /** What to do about a warning or failure. */
  fix?: string;
}

export interface DoctorOptions {
  /** Base URL of the running app, such as http://localhost:3000. Enables the live checks. */
  url?: string;
  /** Path of the Kagami event log written by `fileSink`, to confirm events arrive. */
  events?: string;
  /** Path of a JSON blocklist written by `blocklistFile({ format: 'json' })`, to check enforcement output. */
  blocklist?: string;
  /** Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

const VERSION = '0.1.0';
const UA = `kagami-doctor/${VERSION}`;

function isPrivate(ip: string): boolean {
  const a = ip.replace(/^::ffff:/i, '');
  if (isIP(a) === 4) {
    const [p, q] = a.split('.').map(Number) as [number, number];
    return p === 10 || p === 127 || (p === 172 && q >= 16 && q < 32) || (p === 192 && q === 168) || (p === 100 && q >= 64 && q < 128);
  }
  return a === '::1' || /^f[cd]/i.test(a) || /^fe80/i.test(a);
}

/**
 * Where this deployment's decoy API description goes, the paths that
 * redirect to it, and what the app answers there. A real description at any
 * of them must not be shadowed.
 */
async function checkSpec(base: URL, secret: string, f: typeof fetch, add: (c: Check) => void): Promise<void> {
  let path: string | undefined;
  let aliases: string[] = [];
  try {
    const k = new Kagami({ secret, mode: 'protect', decoys: { spec: true }, sinks: [], logger: { warn() {} } });
    const d = k.manifest()?.decoys as { spec_path?: string; spec_aliases?: string[] } | undefined;
    path = d?.spec_path ?? undefined;
    aliases = d?.spec_aliases ?? [];
    await k.close();
  } catch {
    return;
  }
  if (!path) return;
  const fetchText = async (p: string): Promise<{ status: number; text: string }> => {
    const res = await f(new URL(p, base), { headers: { 'user-agent': UA }, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
    return { status: res.status, text: res.status === 200 ? await res.text() : '' };
  };
  const main = await fetchText(path);
  if (main.text.includes('pk_sandbox_')) {
    add({ id: 'spec', status: 'pass', message: `The decoy API description is served at ${path}, and ${aliases.length} other common paths redirect to it.` });
    return;
  }
  const real: string[] = [];
  for (const p of [path, ...aliases]) {
    const r = p === path ? main : await fetchText(p);
    if (r.status === 200 && /"(openapi|swagger)"\s*:/.test(r.text)) real.push(p);
  }
  if (real.length > 0) {
    add({
      id: 'spec',
      status: 'warn',
      message: `The app publishes its own API description at ${real.join(', ')}. The decoy description would take that place.`,
      fix: `Leave decoys.spec off, or add ${real.map((p) => `'${p}'`).join(', ')} to decoys.reservedPaths so Kagami leaves them alone.`,
    });
  } else {
    add({
      id: 'spec',
      status: 'info',
      message: `The decoy API description is off or Kagami is in observe mode. The app serves no description at ${path} or the ${aliases.length} other common paths, so it is safe to turn on.`,
      fix: 'Set KAGAMI_DECOYS=spec, or decoys: { spec: true }, in protect mode.',
    });
  }
}

export async function runDoctor(o: DoctorOptions = {}): Promise<Check[]> {
  const env = o.env ?? process.env;
  const f = o.fetch ?? fetch;
  const checks: Check[] = [];
  const add = (c: Check): void => {
    checks.push(c);
  };

  // 1. Configuration in the environment.
  const secret = env.KAGAMI_SECRET ?? '';
  if (!secret) {
    add({
      id: 'secret',
      status: env.NODE_ENV === 'production' ? 'fail' : 'warn',
      message: 'KAGAMI_SECRET is not set in this environment. In production Kagami then switches itself off and lets every request through.',
      fix: 'Generate one with `npx @agenticslabs/kagami secret` and set it as KAGAMI_SECRET wherever the app runs. Keep it out of source control.',
    });
  } else if (secret.length < 32) {
    add({ id: 'secret', status: 'fail', message: 'KAGAMI_SECRET is shorter than 32 characters, so Kagami will refuse it.', fix: 'Replace it with the output of `npx @agenticslabs/kagami secret`.' });
  } else {
    add({ id: 'secret', status: 'pass', message: 'KAGAMI_SECRET is set and long enough.' });
  }
  if (['1', 'true', 'yes'].includes(env.KAGAMI_DISABLED ?? '')) {
    add({ id: 'kill_switch', status: 'warn', message: 'KAGAMI_DISABLED is set, so Kagami is switched off.', fix: 'Unset KAGAMI_DISABLED to turn Kagami back on.' });
  }
  const mode = env.KAGAMI_MODE;
  if (mode && mode !== 'observe' && mode !== 'protect') {
    add({ id: 'mode', status: 'fail', message: `KAGAMI_MODE is "${mode}", which is not a mode.`, fix: 'Use observe or protect.' });
  }

  // 2. The engine loads and detects.
  try {
    const k = new Kagami({ secret: secret.length >= 32 ? secret : 'kagami-doctor-temporary-secret-0123456789', mode: 'observe', sinks: [], logger: { warn() {} } });
    const v = k.inspect({ ip: '198.51.100.1', method: 'GET', host: 'doctor.local', path: '/search', query: "q=1'%20OR%20'1'%3D'1", headers: [['user-agent', UA]] });
    await k.close();
    if (k.isEnabled && v.rules.includes('payload.sqli')) add({ id: 'engine', status: 'pass', message: 'The Kagami engine loads and detects a test attack.' });
    else add({ id: 'engine', status: 'fail', message: 'The Kagami engine did not detect a test attack.', fix: 'Reinstall @agenticslabs/kagami. If you bundle the app, check that the bundler keeps the package entry, which loads the engine.' });
  } catch (err) {
    add({ id: 'engine', status: 'fail', message: `The Kagami engine failed to load. ${(err as Error)?.message ?? err}`, fix: 'Reinstall @agenticslabs/kagami. Node 20 or newer is required.' });
  }

  // 3. The running app.
  if (o.url) {
    let base: URL | undefined;
    try {
      base = new URL(o.url);
    } catch {
      add({ id: 'url', status: 'fail', message: `"${o.url}" is not a URL.`, fix: 'Pass the app address, for example --url http://localhost:3000' });
    }
    if (base) {
      try {
        const home = await f(new URL('/', base), { headers: { 'user-agent': UA }, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
        add({ id: 'reachable', status: 'pass', message: `The app answers at ${base.origin} (HTTP ${home.status}).` });
        const env = await f(new URL('/.env', base), { headers: { 'user-agent': UA }, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
        const text = env.status === 200 ? await env.text() : '';
        if (/^NODE_ENV=production$/m.test(text) && /^SESSION_SECRET=/m.test(text)) {
          add({ id: 'protect', status: 'pass', message: 'Kagami is mounted and running in protect mode. It answered a probe for /.env with a fake file.' });
        } else if (env.status === 200) {
          add({
            id: 'protect',
            status: 'fail',
            message: 'The app serves a real /.env file to anyone. That is a serious leak, and Kagami is not answering for it.',
            fix: 'Stop serving dotfiles (check static file middleware), rotate every secret in that file, then mount Kagami before your routes.',
          });
        } else {
          add({
            id: 'protect',
            status: 'info',
            message: 'Kagami did not answer a probe for /.env. That is expected in observe mode. In protect mode it means the middleware is not mounted before your routes, or bait files are turned off.',
            fix: 'In protect mode, mount Kagami after the body parsers and before your routes and static files.',
          });
        }
        if (secret.length >= 32) await checkSpec(base, secret, f, add);
      } catch (err) {
        add({ id: 'reachable', status: 'fail', message: `The app did not answer at ${base.origin}. ${(err as Error)?.message ?? err}`, fix: 'Start the app, or pass the right --url.' });
      }
    }
  }

  // 4. Events.
  if (o.events) {
    if (!existsSync(o.events)) {
      add({ id: 'events', status: 'fail', message: `The event log ${o.events} does not exist.`, fix: 'Add fileSink({ path }) to the sinks, or pass the path your sink writes to.' });
    } else {
      const lines = readFileSync(o.events, 'utf8').split('\n').filter((l) => l.trim());
      const parsed = lines.flatMap((l) => {
        try {
          return [JSON.parse(l) as Record<string, any>];
        } catch {
          return [];
        }
      });
      const started = parsed.filter((e) => e.rule === 'system.started').pop();
      if (!started) {
        add({ id: 'events', status: 'warn', message: 'The event log has no system.started event, so the engine has not started with this log.', fix: 'Check that the app uses this sink and restart it.' });
      } else {
        const ev = started.evidence ?? {};
        add({
          id: 'events',
          status: 'pass',
          message: `The engine started in ${started.mode} mode (containment ${ev.containment ?? 'off'}, bait files ${ev.bait_files ? 'on' : 'off'}, JSON decoys ${ev.json_decoys ? 'on' : 'off'}).`,
        });
      }
      const mine = parsed.filter((e) => e.source?.user_agent === UA);
      const seen = mine.map((e) => e.source?.ip).filter(Boolean).pop();
      if (o.url && mine.length === 0) {
        add({ id: 'detection', status: 'info', message: 'No events from the doctor\'s probes are in the log yet. Sinks write asynchronously, so run the doctor again in a few seconds.' });
      } else if (seen) {
        const remote = o.url ? !['localhost', '127.0.0.1', '[::1]'].includes(new URL(o.url).hostname) : false;
        if (remote && isPrivate(seen)) {
          add({
            id: 'client_address',
            status: 'warn',
            message: `Kagami saw the doctor's requests as coming from ${seen}, a private address. Behind a proxy or load balancer that usually means every visitor looks like the proxy, so one attacker could get everyone contained.`,
            fix: "Set KAGAMI_PROXY=cloudflare when Cloudflare connects to the app directly, or KAGAMI_PROXY=render on Render. For other proxies set clientAddress: { trustedProxies: ['<your proxy addresses>'] }, and add cloudflare: true behind Cloudflare.",
          });
        } else {
          add({ id: 'client_address', status: 'pass', message: `Kagami saw the doctor's requests as coming from ${seen}.` });
        }
      }
    }
  }

  // 5. Enforcement output.
  if (o.blocklist) {
    if (!existsSync(o.blocklist)) {
      add({ id: 'blocklist', status: 'info', message: `${o.blocklist} does not exist yet. blocklistFile creates it when Kagami starts.`, fix: 'Check that containment is on and blocklistFile points at this path.' });
    } else {
      try {
        const parsed = JSON.parse(readFileSync(o.blocklist, 'utf8')) as { entries?: unknown[] };
        add({ id: 'blocklist', status: 'pass', message: `${o.blocklist} is a valid JSON blocklist with ${parsed.entries?.length ?? 0} entries.` });
      } catch {
        add({
          id: 'blocklist',
          status: 'warn',
          message: `${o.blocklist} is not a JSON blocklist, so the doctor cannot check it.`,
          fix: "Pass the path of a blocklistFile({ path, format: 'json' }) file, or leave --blocklist out.",
        });
      }
    }
  }
  return checks;
}

const LABEL: Record<CheckStatus, string> = { pass: 'PASS', warn: 'WARN', fail: 'FAIL', info: 'INFO' };

export function formatChecks(checks: Check[]): string {
  const lines = checks.map((c) => `${LABEL[c.status]}  ${c.message}${c.fix ? `\n      ${c.fix}` : ''}`);
  const fails = checks.filter((c) => c.status === 'fail').length;
  const warns = checks.filter((c) => c.status === 'warn').length;
  lines.push('', fails ? `${fails} problem(s) to fix.` : warns ? `No failures, ${warns} warning(s).` : 'Everything checked is in order.');
  return lines.join('\n') + '\n';
}
