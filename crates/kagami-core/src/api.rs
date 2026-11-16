//! JSON envelope API shared by the WebAssembly ABI and native tests.
//!
//! A request has the form `{"op": "<name>", "args": {...}}`. A response is
//! either `{"ok": true, "result": ...}` or
//! `{"ok": false, "error": {"code": "...", "message": "..."}}`.
//!
//! Using one envelope keeps the host ABI to four exported functions, so a new
//! language adapter needs very little code.

use crate::config::Config;
use crate::engine::{Engine, Request};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Default)]
pub struct Runtime {
    engine: Option<Engine>,
}

#[derive(Deserialize)]
struct Envelope {
    op: String,
    #[serde(default)]
    args: Value,
}

#[derive(Deserialize)]
struct InitArgs {
    config: Config,
    #[serde(default)]
    now_ms: u64,
    #[serde(default)]
    instance: String,
}

#[derive(Deserialize)]
struct DecorateArgs {
    #[serde(default)]
    session: String,
    /// Request path of the page being decorated. It selects the pages that
    /// carry the bait comment.
    #[serde(default)]
    path: String,
    body: String,
}

#[derive(Deserialize)]
struct SealArgs {
    value: String,
}

#[derive(Deserialize)]
struct VerifyArgs {
    request: Request,
    sealed: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct ContainedArgs {
    #[serde(default)]
    now_ms: u64,
}

#[derive(Deserialize)]
struct ReleaseArgs {
    /// An address, an IPv6 /64, or a source id.
    key: String,
}

fn ok(result: Value) -> String {
    json!({"ok": true, "result": result}).to_string()
}

fn err(code: &str, message: impl Into<String>) -> String {
    json!({"ok": false, "error": {"code": code, "message": message.into()}}).to_string()
}

fn parse<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, String> {
    serde_json::from_value(v).map_err(|e| err("invalid_args", e.to_string()))
}

impl Runtime {
    pub fn handle(&mut self, input: &[u8]) -> String {
        match self.dispatch(input) {
            Ok(s) | Err(s) => s,
        }
    }

    fn dispatch(&mut self, input: &[u8]) -> Result<String, String> {
        let env: Envelope =
            serde_json::from_slice(input).map_err(|e| err("invalid_request", e.to_string()))?;
        if env.op == "version" {
            return Ok(ok(
                json!({"version": crate::VERSION, "abi": crate::ABI_VERSION}),
            ));
        }
        if env.op == "init" {
            let args: InitArgs = parse(env.args)?;
            return match Engine::new(args.config, args.now_ms, &args.instance) {
                Ok((engine, events)) => {
                    let result = json!({"deployment": engine.deployment(), "mode": engine.mode(), "events": events});
                    self.engine = Some(engine);
                    Ok(ok(result))
                }
                Err(e) => Err(err(e.code, e.message)),
            };
        }
        let engine = self
            .engine
            .as_mut()
            .ok_or_else(|| err("not_initialised", "call init first"))?;
        let result = match env.op.as_str() {
            "inspect" => {
                let mut r: Request = parse(env.args)?;
                engine.resolve_client_ip(&mut r);
                json!(engine.inspect(&r))
            }
            "response" => {
                let mut r: Request = parse(env.args)?;
                engine.resolve_client_ip(&mut r);
                json!(engine.response(&r))
            }
            "decorate_html" => {
                let a: DecorateArgs = parse(env.args)?;
                json!({"body": engine.decorate_html(&a.session, &a.path, &a.body)})
            }
            "decorate_json" => {
                let a: DecorateArgs = parse(env.args)?;
                json!({"body": engine.decorate_json(&a.body)})
            }
            "seal" => {
                let a: SealArgs = parse(env.args)?;
                json!({"sealed": engine.seal(&a.value)})
            }
            "verify_sealed" => {
                let mut a: VerifyArgs = parse(env.args)?;
                engine.resolve_client_ip(&mut a.request);
                json!(engine.verify_sealed(&a.request, &a.sealed, &a.name))
            }
            "manifest" => engine.manifest(),
            "contained" => {
                let a: ContainedArgs = parse(env.args)?;
                json!({"entries": engine.contained_list(a.now_ms)})
            }
            "release" => {
                let a: ReleaseArgs = parse(env.args)?;
                json!({"released": engine.release(&a.key)})
            }
            other => return Err(err("unknown_op", format!("unknown op `{other}`"))),
        };
        Ok(ok(result))
    }
}
