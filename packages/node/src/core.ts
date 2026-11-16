/**
 * Bridge to the WebAssembly core (ABI v1). The module imports nothing, so it
 * has no clock, randomness, filesystem or network access. All I/O stays in
 * this package.
 *
 * The engine is handed in by the package entry point. On Node, Bun and Deno
 * it is embedded in the JavaScript as base64. On Cloudflare Workers, which
 * only run WebAssembly that was compiled at deploy time, the `workerd` entry
 * imports the .wasm file and the bundler compiles it.
 */

const SUPPORTED_ABI = 1;

type EngineSource = WebAssembly.Module | (() => WebAssembly.Module | Uint8Array);
let source: EngineSource | undefined;

/** Called once by the package entry point. */
export function setEngine(s: EngineSource): void {
  source = s;
  compiled = undefined;
}

interface CoreExports {
  memory: WebAssembly.Memory;
  kagami_abi_version(): number;
  kagami_alloc(len: number): number;
  kagami_free(ptr: number, len: number): void;
  kagami_call(ptr: number, len: number): bigint;
}

export class KagamiCoreError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'KagamiCoreError';
    this.code = code;
  }
}

let compiled: WebAssembly.Module | undefined;

function wasmModule(): WebAssembly.Module {
  if (compiled) return compiled;
  if (!source) throw new KagamiCoreError('wasm_missing', 'The Kagami engine was not loaded. Import Kagami from @agenticslabs/kagami or an adapter package.');
  if (source instanceof WebAssembly.Module) return (compiled = source);
  const loaded = source();
  compiled = loaded instanceof WebAssembly.Module ? loaded : new WebAssembly.Module(loaded);
  return compiled;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class Core {
  private readonly ex: CoreExports;

  constructor() {
    const instance = new WebAssembly.Instance(wasmModule(), {});
    this.ex = instance.exports as unknown as CoreExports;
    const abi = this.ex.kagami_abi_version();
    if (abi !== SUPPORTED_ABI) {
      throw new KagamiCoreError('abi_mismatch', `Kagami core ABI ${abi} is not supported (expected ${SUPPORTED_ABI}).`);
    }
  }

  call<T>(op: string, args: unknown): T {
    const ex = this.ex;
    const input = encoder.encode(JSON.stringify({ op, args }));
    const inPtr = ex.kagami_alloc(input.length) >>> 0;
    new Uint8Array(ex.memory.buffer, inPtr, input.length).set(input);
    let packed: bigint;
    try {
      packed = ex.kagami_call(inPtr, input.length);
    } finally {
      try {
        ex.kagami_free(inPtr, input.length);
      } catch {
        // A trap has already left the instance unusable. The caller rebuilds it.
      }
    }
    const outPtr = Number(packed >> 32n) >>> 0;
    const outLen = Number(packed & 0xffffffffn);
    const text = decoder.decode(new Uint8Array(ex.memory.buffer, outPtr, outLen));
    ex.kagami_free(outPtr, outLen);
    const res = JSON.parse(text) as { ok: true; result: T } | { ok: false; error: { code: string; message: string } };
    if (!res.ok) throw new KagamiCoreError(res.error.code, res.error.message);
    return res.result;
  }
}
