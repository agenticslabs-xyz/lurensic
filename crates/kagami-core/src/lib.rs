//! # kagami-core
//!
//! The portable detection and deception engine behind Kagami.
//!
//! The core is pure logic. It never touches the network, the filesystem or a
//! clock. Hosts (language adapters) pass in requests and the current time, and
//! get back verdicts plus pre-serialised, hash-chained audit events. That keeps
//! the engine deterministic, testable with shared conformance vectors, and
//! byte-identical across every language that embeds the WebAssembly build.
//!
//! All decoys, honeytokens and seals are derived from a per-deployment secret
//! (Kerckhoffs's principle). Reading this source tells an attacker *that*
//! tripwires exist, never *which* ones a deployment uses.

#![deny(unsafe_code)]

pub mod api;
mod config;
mod contain;
mod crypto;
mod decoys;
mod engine;
mod event;
pub mod net;
mod normalize;
mod respond;
mod rules;
mod session;
pub mod time;
mod tokens;

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod wasm;

pub use config::{
    Config, ConfigError, ContainAction, Containment, IpLogging, Mode, Tarpit, Thresholds, Trigger,
};
pub use contain::Entry as ContainedMachine;
pub use engine::{Action, Engine, Inspection, Request, ResponseOutcome, VerifyOutcome};
pub use event::verify_chain;
pub use session::State;

/// Engine version, embedded in `system.started` events.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the host ABI (see `wasm.rs` and `docs/DESIGN.md`).
pub const ABI_VERSION: u32 = 1;
