# Contributing to Lurensic

Thanks for helping. These rules keep Lurensic trustworthy.

## Requirements for every change

1. **Fail open.** No code path may throw into, block, or crash the host application.
2. **Observe mode changes nothing.** It must never change a response. The byte-identity test must keep passing.
3. **No detection that depends on cooperation.** Rules that need the attacker's agent to obey text are not accepted as a foundation.
4. **No hack-back.** Nothing may attack, exploit or instruct the attacker's own systems.
5. **One implementation.** Detection logic lives only in `crates/lurensic-core`. Adapters translate requests and don't make decisions.
6. **Logs are safe against hostile input.** New event fields that carry attacker text must be sanitised and listed in `untrusted`.

## Development

```bash
rustup target add wasm32-unknown-unknown
pnpm install
pnpm test              # Rust tests, WASM build, all JS suites
cargo clippy --all-targets -- -D warnings
pnpm compat            # installs the packed packages into a new project and checks them
pnpm smoke:workers     # runs the example app on the Cloudflare Workers runtime
```

`pnpm compat` checks Express 4 and 5, Hono, the CLI, `require()` from CommonJS, the TypeScript types under
`nodenext` and `bundler` resolution, an esbuild bundle, and Bun and Deno when they are installed. CI runs it on
Node 20, 22 and 24.

## Releasing

The three packages always share one version and are published together by the release workflow.

1. Set the version with `pnpm release:version 0.2.0`. It updates all three packages.
2. Commit, merge to `main` and wait for CI to pass.
3. Tag the commit and push the tag with `git tag v0.2.0 && git push origin v0.2.0`.

The workflow checks that the tag matches every package, runs the tests and the compatibility checks, publishes with
pnpm, which puts out the core before the adapters, and creates a GitHub release with notes for the tag. Never publish
with plain `npm publish`, which would ship the `workspace:^` ranges as they are.

npm trusts `release.yml` in this repository as the publisher of all three packages, so no npm token is stored
anywhere, and every release carries provenance. Only repository admins can push `v*` tags.

## Adding a detection rule

1. Add the rule in `crates/lurensic-core/src/rules.rs` with severity, confidence, scores and ATT&CK mapping.
2. Add positive **and negative** test cases. Every new signature needs ordinary inputs that must stay clean.
3. Update the rule catalogue in `docs/DESIGN.md`.

## Adding a language adapter

Follow [Writing an adapter](docs/guides/new-adapter.md). It describes the contract with the engine, the requests a
framework rejects, the JSON blocklist every adapter writes, and the test suites every adapter must pass.

## Adding an enforcer

Lurensic ships only provider-neutral enforcers, in `packages/node/src/enforce.ts`. Integrations with a particular
firewall, CDN or WAF belong in the recipes in `docs/guides/firewall.md`, not in the package. A new built-in enforcer
receives contained machines through the `Enforcer` interface, runs off the request path, must never push private
addresses unless asked, keeps any credentials out of logs and errors, and comes with tests.

## Commits

Keep commits small and focused, with clear messages. By contributing you agree your work is licensed under Apache-2.0.
