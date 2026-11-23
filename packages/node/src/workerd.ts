/**
 * The entry for Cloudflare Workers, picked through the `workerd` export
 * condition. Workers only run WebAssembly compiled at deploy time, so the
 * engine is imported as a .wasm module, which wrangler compiles. Workers have
 * no file system, so the features that write files explain what to use instead.
 */
import engine from '../wasm/lurensic_core.wasm';
import { setEngine } from './core.js';
import { needsFileSystem } from './platform.js';

setEngine(engine);

export * from './universal.js';

export function fileSink(): never {
  return needsFileSystem('fileSink');
}

export function blocklistFile(): never {
  return needsFileSystem('blocklistFile');
}

export function runDoctor(): never {
  throw new TypeError('lurensic doctor runs on your own machine with Node. Run npx @agenticslabs/lurensic doctor --url <your Worker URL>.');
}

export function formatChecks(): never {
  return runDoctor();
}
