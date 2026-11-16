/**
 * The entry for Node, Bun and Deno. The engine is embedded as base64, so no
 * file has to be found at runtime and bundlers need no special setup.
 */
import { setEngine } from './core.js';
import { ENGINE_BASE64 } from './engine-bytes.js';
import { fromBase64 } from './platform.js';

setEngine(() => fromBase64(ENGINE_BASE64));

export * from './universal.js';
export { blocklistFile, fileSink } from './files.js';
export { formatChecks, runDoctor, type Check, type CheckStatus, type DoctorOptions } from './doctor.js';
