/**
 * The few platform features the runtime needs, written against web-standard
 * APIs so the same code runs on Node, Bun, Deno and Cloudflare Workers.
 * Nothing here imports a Node module.
 */

/** Settings Kagami reads, such as KAGAMI_SECRET. */
export type Env = Record<string, string | undefined>;

declare const process: { env?: Env; stdout?: { write(s: string): unknown } } | undefined;

/** `process.env` where it exists (Node, Bun, Deno), otherwise an empty object (Workers). */
export function processEnv(): Env {
  try {
    return typeof process !== 'undefined' && process?.env ? process.env : {};
  } catch {
    return {};
  }
}

/** True on runtimes without a `process` object, such as Cloudflare Workers. */
export function hasProcess(): boolean {
  return typeof process !== 'undefined' && !!process?.env;
}

/** Writes a line to stdout where there is one, otherwise to the console. */
export function writeLine(text: string): void {
  if (typeof process !== 'undefined' && process?.stdout?.write) process.stdout.write(text);
  else console.log(text.endsWith('\n') ? text.slice(0, -1) : text);
}

/** Runs `fn` after the current work, without holding up the request. */
export function defer(fn: () => void): void {
  const g = globalThis as { setImmediate?: (fn: () => void) => unknown };
  if (typeof g.setImmediate === 'function') g.setImmediate(fn);
  else setTimeout(fn, 0);
}

/** A timer that does not keep the process alive, where the runtime supports that. */
export function unref<T>(timer: T): T {
  (timer as { unref?: () => void })?.unref?.();
  return timer;
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** `n` random bytes as hex. */
export function randomHex(n: number): string {
  return hex(crypto.getRandomValues(new Uint8Array(n)));
}

const enc = new TextEncoder();

export async function sha256Hex(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text))));
}

export async function hmacSha256Hex(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(text))));
}

/** Decodes base64 without Node's Buffer. */
export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Thrown by features that need a file system on a runtime without one. */
export function needsFileSystem(name: string): never {
  throw new TypeError(
    `${name} needs a file system, which this runtime does not have. On Cloudflare Workers use webhookEnforcer, callbackEnforcer, webhookSink or callbackSink instead.`,
  );
}
