// Bundles express.mjs with esbuild, the way an app built with a bundler ships,
// so the compatibility check can run the bundle and see that the engine survives.
import { build } from 'esbuild';

await build({
  entryPoints: ['express.mjs'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: 'bundle/app.mjs',
  logLevel: 'error',
  // Express is CommonJS, and its require() calls need a require in an ES module bundle.
  banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" },
});
