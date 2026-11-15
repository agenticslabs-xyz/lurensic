// Builds the Rust core for wasm32 and copies it into @agenticslabs/kagami.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
execFileSync('cargo', ['build', '--release', '--target', 'wasm32-unknown-unknown', '-p', 'kagami-core'], {
  cwd: root,
  stdio: 'inherit',
});
const src = join(root, 'target', 'wasm32-unknown-unknown', 'release', 'kagami_core.wasm');
const destDir = join(root, 'packages', 'node', 'wasm');
mkdirSync(destDir, { recursive: true });
copyFileSync(src, join(destDir, 'kagami_core.wasm'));
console.log(`Copied kagami_core.wasm (${(statSync(src).size / 1024).toFixed(0)} KiB) to packages/node/wasm/`);
