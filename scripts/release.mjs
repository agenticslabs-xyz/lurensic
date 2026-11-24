// Release helpers. The three packages always share one version.
//
//   node scripts/release.mjs version 0.2.0    sets the version of all three packages
//   node scripts/release.mjs check v0.2.0     fails unless the tag and every package agree
//
// The release workflow runs `check` with the pushed tag before it publishes.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGES = ['node', 'express', 'hono'].map((p) => join(root, 'packages', p, 'package.json'));
const CORE = '@agenticslabs/lurensic';
const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

const read = (file) => JSON.parse(readFileSync(file, 'utf8'));
const [command, value] = process.argv.slice(2);

if (command === 'version') {
  if (!SEMVER.test(value ?? '')) fail(`Give a version such as 0.2.0, not "${value ?? ''}".`);
  for (const file of PACKAGES) {
    const pkg = read(file);
    pkg.version = value;
    writeFileSync(file, `${JSON.stringify(pkg, null, 2)}\n`);
  }
  console.log(`All three packages are now ${value}. Commit, then tag v${value} and push the tag to publish.`);
} else if (command === 'check') {
  const version = (value ?? '').replace(/^v/, '');
  if (!SEMVER.test(version)) fail(`"${value ?? ''}" is not a version tag such as v0.2.0.`);
  const problems = [];
  for (const file of PACKAGES) {
    const pkg = read(file);
    if (pkg.version !== version) problems.push(`${pkg.name} is ${pkg.version}, the tag is ${version}`);
    const range = pkg.dependencies?.[CORE];
    if (range && range !== 'workspace:^') problems.push(`${pkg.name} depends on ${CORE}@${range}; use workspace:^ so patch releases of the core reach it`);
    if (pkg.publishConfig?.access !== 'public') problems.push(`${pkg.name} is missing publishConfig.access "public"`);
  }
  if (problems.length) fail(problems.join('\n'));
  console.log(`Ready to publish ${version}.`);
} else {
  fail('Usage: node scripts/release.mjs version <x.y.z> | check <vx.y.z>');
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
