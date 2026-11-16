//! # kagami-enforcer
//!
//! Kagami contains attackers inside the application, in any language. This
//! program pushes the same decisions to the systems in front of the
//! application, so contained machines are stopped before they reach it.
//!
//! The contract with the application is a file. Every Kagami adapter can
//! write the contained machines to a JSON blocklist (`blocklistFile` with
//! `format: 'json'` in Node). The enforcer reads that file and makes the
//! provider match it. One enforcer serves apps written in any language, and a
//! new provider is added in one place.
//!
//! ```text
//!   app (any language) --writes--> contained.json --read by--> kagami-enforcer --syncs--> Cloudflare IP list
//! ```

pub mod blocklist;
pub mod cloudflare;
pub mod http;
