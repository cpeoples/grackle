//! Shared HTTP plumbing for the comment subsystem: a configured agent, the
//! GitHub header set, and GET/send helpers that redact the token from errors.

use crate::comment::context::{redact, PlatformContext};
use serde_json::Value;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);

pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .into()
}

pub fn github_headers(ctx: &PlatformContext) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", format!("Bearer {}", ctx.token)),
        ("Accept", "application/vnd.github+json".to_string()),
        ("X-GitHub-Api-Version", "2022-11-28".to_string()),
    ]
}

pub fn gitlab_headers(ctx: &PlatformContext) -> Vec<(&'static str, String)> {
    vec![("PRIVATE-TOKEN", ctx.token.clone())]
}

/// GET a URL and parse the JSON body, mapping a non-2xx status or transport
/// error into a redacted `Err(String)`.
pub fn get_json(
    agent: &ureq::Agent,
    url: &str,
    headers: &[(&str, String)],
    token: &str,
) -> Result<Value, String> {
    let mut req = agent.get(url);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    match req.call() {
        Ok(mut resp) => resp
            .body_mut()
            .read_json::<Value>()
            .map_err(|e| redact(&e.to_string(), token)),
        Err(e) => Err(redact(&e.to_string(), token)),
    }
}

/// Send a JSON body on a POST/PUT/PATCH request and parse the JSON response,
/// mapping failures into a redacted `Err(String)`.
pub fn send_json(
    req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    headers: &[(&str, String)],
    payload: Value,
    token: &str,
) -> Result<Value, String> {
    let mut req = req;
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    match req.send_json(payload) {
        Ok(mut resp) => Ok(resp.body_mut().read_json::<Value>().unwrap_or(Value::Null)),
        Err(e) => Err(redact(&e.to_string(), token)),
    }
}
