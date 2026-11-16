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
pnpm test:enforcer     # the standalone enforcer
```

The enforcer's TLS library needs a C compiler. On Linux and macOS that is usually present. On Windows, use the MSVC
Rust toolchain, or run the enforcer's tests in a container.

```bash
docker run --rm -v "$PWD:/work" -w /work -e CARGO_TARGET_DIR=/work/target/linux rust:1-bookworm   sh -c "cargo test -p kagami-enforcer && cargo clippy -p kagami-enforcer --all-targets -- -D warnings"
```

## Adding a detection rule

1. Add the rule in `crates/kagami-core/src/rules.rs` with severity, confidence, scores and ATT&CK mapping.
2. Add positive **and negative** test cases. Every new signature needs ordinary inputs that must stay clean.
3. Update the rule catalogue in `docs/DESIGN.md`.

## Adding a language adapter

Follow [Writing an adapter](docs/guides/new-adapter.md). It describes the contract with the engine, the requests a
framework rejects, the JSON blocklist every adapter writes, and the test suites every adapter must pass.

## Adding an enforcer provider

Add a module to `crates/kagami-enforcer` next to `cloudflare.rs`. A provider reads the same parsed blocklist and
must only change entries it created, never push private addresses, keep its credentials out of logs and errors, and
come with tests against an in-memory model of the provider's API.

## Commits

Keep commits small and focused, with clear messages. By contributing you agree your work is licensed under Apache-2.0.
