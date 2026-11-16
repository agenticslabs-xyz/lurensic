# Contributing to Kagami

Thanks for helping. These rules keep Kagami trustworthy.

## Requirements for every change

1. **Fail open.** No code path may throw into, block, or crash the host application.
2. **Observe mode changes nothing.** It must never change a response. The byte-identity test must keep passing.
3. **No detection that depends on cooperation.** Rules that need the attacker's agent to obey text are not accepted as a foundation.
4. **No hack-back.** Nothing may attack, exploit or instruct the attacker's own systems.
5. **One implementation.** Detection logic lives only in `crates/kagami-core`. Adapters translate requests and don't make decisions.
6. **Logs are safe against hostile input.** New event fields that carry attacker text must be sanitised and listed in `untrusted`.

## Development

```bash
rustup target add wasm32-unknown-unknown
pnpm install
pnpm test              # Rust tests, WASM build, all JS suites
cargo clippy --all-targets -- -D warnings
```

## Adding a detection rule

1. Add the rule in `crates/kagami-core/src/rules.rs` with severity, confidence, scores and ATT&CK mapping.
2. Add positive **and negative** test cases. Every new signature needs ordinary inputs that must stay clean.
3. Update the rule catalogue in `docs/DESIGN.md`.

## Adding a language adapter

Follow [Writing an adapter](docs/guides/new-adapter.md). It describes the contract with the engine, the requests a
framework rejects, the JSON blocklist every adapter writes, and the test suites every adapter must pass.

## Adding an enforcer

Enforcers live in `packages/node/src`, next to `cloudflare/`. An enforcer receives contained machines through the
`Enforcer` interface, runs off the request path, must only change entries it created, must never push private
addresses unless asked, keeps its credentials out of logs and errors, and comes with tests against an in-memory model
of the provider's API. Built-in enforcers that need credentials switch on from environment variables, as Cloudflare
does.

## Commits

Keep commits small and focused, with clear messages. By contributing you agree your work is licensed under Apache-2.0.
