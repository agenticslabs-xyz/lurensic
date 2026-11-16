//! The HTTP layer, behind a trait so provider logic can be tested without a
//! network.

use serde_json::Value;
use std::time::Duration;

pub struct Response {
    pub status: u16,
    /// The parsed JSON body, or `Null` when there was none or it was not JSON.
    pub body: Value,
    /// `Retry-After` in seconds, when the server sent one.
    pub retry_after: Option<u64>,
}

pub trait Http {
    /// Send a request with a bearer token. Transport failures are errors.
    /// HTTP error statuses are not; they come back as a `Response`.
    fn send(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Response, String>;
}

/// The real client. TLS is verified, redirects are refused, and every
/// request has a timeout.
pub struct Ureq {
    agent: ureq::Agent,
}

impl Default for Ureq {
    fn default() -> Self {
        Ureq {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(20))
                .redirects(0)
                .user_agent(concat!("kagami-enforcer/", env!("CARGO_PKG_VERSION")))
                .build(),
        }
    }
}

impl Http for Ureq {
    fn send(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Response, String> {
        let req = self
            .agent
            .request(method, url)
            .set("authorization", &format!("Bearer {token}"));
        let result = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        let resp = match result {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            // Never include the request in the message, because it carries the token.
            Err(ureq::Error::Transport(t)) => return Err(format!("network error ({})", t.kind())),
        };
        let status = resp.status();
        let retry_after = resp
            .header("retry-after")
            .and_then(|v| v.trim().parse().ok());
        let body = resp.into_json::<Value>().unwrap_or(Value::Null);
        Ok(Response {
            status,
            body,
            retry_after,
        })
    }
}
