# Working on the Kagami repository

Instructions for AI coding agents and people changing Kagami itself. To add Kagami to an application, read
[docs/ai/integrate.md](docs/ai/integrate.md) instead.

## Layout

| Path | What it is |
|---|---|
| `crates/kagami-core` | The engine in Rust, compiled to WebAssembly. All detection, deception and containment logic lives here and nowhere else. |
| `crates/kagami-enforcer` | The standalone enforcer for edge providers. Not a default workspace member. |
| `packages/node` | `@agenticslabs/kagami`, the Node runtime, sinks, enforcers and CLI |
| `packages/express` | `@agenticslabs/kagami-express`, the Express adapter |
| `examples/demo-shop` | The benchmark target and the attacker persona tests |
| `scripts` | Benchmark round runner and report generator |
| `docs` | Guides, design, threat model, benchmark method and the AI integration guide |

## Commands

```bash
pnpm install
pnpm test                                   # engine tests, WebAssembly build, every JS suite
cargo fmt --all && cargo clippy --all-targets -- -D warnings
pnpm test:enforcer                          # needs a C compiler for TLS, see CONTRIBUTING.md
```

JS tests run against built packages, so `pnpm test` rebuilds the WebAssembly engine and the TypeScript first.

## Rules

1. **Fail open.** Nothing may throw into, block or crash the host application.
2. **Observe mode changes nothing.** The byte-identity test must keep passing.
3. **No detection that needs the attacker's cooperation.** Text that asks an agent to stop is never a foundation.
4. **No hack-back.** Nothing may attack or instruct the attacker's systems.
5. **One implementation.** Decisions live in `kagami-core`. Adapters and runtimes only move data.
6. **Containment must not be easy to turn against visitors.** New tripwires must be actions honest visitors cannot
   take, and cross-site requests must never contain.
7. **Logs are safe against hostile input.** New fields with attacker text are sanitised and listed in `untrusted`.
8. **Every fix comes with a regression test**, ideally reproduced from benchmark traffic.
9. **Plain writing.** Docs, comments and messages use plain, direct sentences without figures of speech.

## Benchmarks

`pnpm bench -- --port <new port> --label artex-<name>` starts a round, and `pnpm bench:report bench-runs/<round>` turns
it into a report. Round folders are git-ignored. Read [docs/BENCHMARK.md](docs/BENCHMARK.md) before running one.
