# Working on the Kagami repository

Instructions for AI coding agents and people changing Kagami itself. To add Kagami to an application, read
[docs/ai/integrate.md](docs/ai/integrate.md) instead.

## Layout

| Path | What it is |
|---|---|
| `crates/kagami-core` | The engine in Rust, compiled to WebAssembly. All detection, deception and containment logic lives here and nowhere else. |
| `packages/node` | `@agenticslabs/kagami`, the runtime for Node, Bun, Deno and Workers, the fetch adapter, `onDetect`, sinks and CLI. Also the optional containment extras (enforcers and the store). |
| `packages/hono` | `@agenticslabs/kagami-hono`, the Hono middleware |
| `examples/hono-app` | One app that runs on Node and on Cloudflare Workers, for testing hosts |
| `packages/express` | `@agenticslabs/kagami-express`, the Express adapter |
| `examples/demo-shop` | The benchmark target and the attacker persona tests |
| `scripts` | Benchmark round runner and report generator |
| `docs` | Guides, design, threat model, benchmark method and the AI integration guide |

## Commands

```bash
pnpm install
pnpm test                                   # engine tests, WebAssembly build, every JS suite
cargo fmt --all && cargo clippy --all-targets -- -D warnings
```

JS tests run against built packages, so `pnpm test` rebuilds the WebAssembly engine and the TypeScript first.

## Focus

Kagami is an engine. It detects attacks, misleads the attacker with decoys, and hands each detection to the
developer's code through `onDetect(event)`. Judge new work by whether it makes detection, deception or the event
better. Containment, the store and the enforcers are optional extras that stay off by default and out of the main docs.

## Rules

1. **Fail open.** Nothing may throw into, block or crash the host application.
2. **Observe mode changes nothing.** The byte-identity test must keep passing.
3. **No detection that needs the attacker's cooperation.** Text that asks an agent to stop is never a foundation.
4. **No hack-back.** Nothing may attack or instruct the attacker's systems.
5. **One implementation.** Decisions live in `kagami-core`. Adapters and runtimes only move data.
6. **One package to install.** Users install one package per framework. Do not add components they must install or run separately.
7. **Tripwires must not be easy to turn against visitors.** New tripwires must be actions honest visitors cannot
   take, and cross-site requests must never contain.
8. **Logs are safe against hostile input.** New fields with attacker text are sanitised and listed in `untrusted`.
9. **Every fix comes with a regression test**, ideally reproduced from benchmark traffic.
10. **Plain writing.** Docs, comments and messages use plain, direct sentences without figures of speech.

## Benchmarks

`pnpm bench -- --port <new port> --label artex-<name>` starts a round, and `pnpm bench:report bench-runs/<round>` turns
it into a report. Round folders are git-ignored. Read [docs/BENCHMARK.md](docs/BENCHMARK.md) before running one.
