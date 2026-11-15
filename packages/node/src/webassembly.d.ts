// Minimal WebAssembly typings (Node ships the runtime; TypeScript only types it
// through the DOM lib, which a server package should not pull in).
declare namespace WebAssembly {
  class Module {
    constructor(bytes: ArrayBufferView | ArrayBuffer);
  }
  class Instance {
    constructor(module: Module, imports?: Record<string, unknown>);
    readonly exports: Record<string, unknown>;
  }
  class Memory {
    readonly buffer: ArrayBuffer;
  }
  class RuntimeError extends Error {}
}
