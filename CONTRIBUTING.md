# Contributing to Kagami

Thanks for helping. A few ground rules keep Kagami trustworthy.

## Non-negotiables

1. **Fail open.** No code path may throw into, block, or crash the host application.
2. **Observe mode is inert.** It must never change a response. The byte-identity test must keep passing.
3. **No cooperation-based detection as a foundation.** Rules that need the attacker's agent to obey text are not accepted.
4. **No hack-back.** Nothing that attacks, exploits or instructs the attacker's own systems.
5. **One implementation.** Detection logic lives in `crates/kagami-core` only. Adapters translate, they don't decide.
6. **Logs are hostile-input safe.** New event fields that carry attacker text must be sanitised and listed in `untrusted`.

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

Implement the ABI in [docs/DESIGN.md §4.1](docs/DESIGN.md#41-core-abi-v1), map the framework's request,
run the event pipeline off the request path, and reproduce the Express adapter's test suite (byte identity,
fail-open, decoration, seals).

## Commits

Small, focused commits with clear messages. By contributing you agree your work is licensed under Apache-2.0.
