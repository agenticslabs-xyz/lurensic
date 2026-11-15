/**
 * Bridge to the WebAssembly core (ABI v1). The module imports nothing, so it
 * has no clock, randomness, filesystem or network access. All I/O stays in
 * this package.
 */
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SUPPORTED_ABI = 1;

/**
 * Locate the core module. Checks `KAGAMI_WASM_PATH` first, then the package
 * layout (`dist/../wasm/`), then the folder of the running file (single-file
 * bundles).
 */
function wasmPath(): string {
  const candidates: string[] = [];
  if (process.env.KAGAMI_WASM_PATH) candidates.push(process.env.KAGAMI_WASM_PATH);
  for (const rel of ['../wasm/kagami_core.wasm', './kagami_core.wasm']) {
    try {
      candidates.push(fileURLToPath(new URL(rel, import.meta.url)));
    } catch {
      /* import.meta.url unavailable in some bundles */
    }
  }
  const found = candidates.find((p) => existsSync(p));
  if (!found) {
    throw new KagamiCoreError(
      'wasm_missing',
      `kagami_core.wasm not found. Looked in ${candidates.join(', ')}. Set KAGAMI_WASM_PATH to its location.`,
    );
  }
  return found;
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
  compiled ??= new WebAssembly.Module(readFileSync(wasmPath()));
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
