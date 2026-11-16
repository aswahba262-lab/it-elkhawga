use crate::common::*;
use serde_json::{json, Value};

/// Transport abstraction so the agent can talk to a LAN admin server or a managed HTTPS relay
/// through the same code path. The relay is the default for internet access; the LAN server
/// remains available when both are on the same network.
#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    Lan,
    Relay,
}

impl Transport {
    /// Unchanged from the original design: an explicit choice wins, otherwise a
    /// configured relay URL means relay, else a LAN server URL means LAN.
    pub fn from_link(link: &ClientLink) -> Self {
        match link.transport.as_str() {
            "relay" => Transport::Relay,
            "lan" => Transport::Lan,
            _ => {
                if link.relay_url.starts_with("https://") || link.relay_url.starts_with("http://") {
                    Transport::Relay
                } else if link.server_url.starts_with("http://") {
                    Transport::Lan
                } else {
                    Transport::Lan
                }
            }
        }
    }


}

pub struct RelayClient {
    http: ureq::Agent,
}

impl RelayClient {
    pub fn new() -> Self {
        RelayClient { http: tls_agent(30) }
    }

    fn post(&self, base: &str, path: &str, token: &str, body: Value) -> Option<Value> {
        let url = format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'));
        let resp = self
            .http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/json")
            .send_json(body);
        resp.ok().and_then(|r| r.into_json().ok())
    }

    /// One-time enrollment: consumes a pairing token and returns a per-device token.
    pub fn enroll(&self, relay_url: &str, pairing_token: &str) -> Option<(String, String)> {
        let body = json!({
            "device_id": read_client().device_id,
            "hostname": hostname(),
            "os": "windows",
            "app_version": APP_VERSION,
        });
        let v = self.post(relay_url, "/api/v1/enroll", pairing_token, body)?;
        if !v["ok"].as_bool().unwrap_or(false) {
            return None;
        }
        Some((
            v["device_id"].as_str().unwrap_or("").to_string(),
            v["device_token"].as_str().unwrap_or("").to_string(),
        ))
    }

    /// Outbound poll: sends state, ACKs any previous command, receives pending command + policy.
    /// Uploads a base64 screenshot captured in the user session.
    pub fn upload_screen(&self, relay_url: &str, device_token: &str, image: &str) -> Option<Value> {
        self.post(relay_url, "/api/v1/device/screen", device_token, json!({"image": image}))
    }

    pub fn poll(
        &self,
        relay_url: &str,
        device_token: &str,
        state: &Value,
        ack_command_id: Option<&str>,
    ) -> Option<(Option<Value>, Option<Value>, bool)> {
        let mut body = state.clone();
        if let Some(id) = ack_command_id {
            body["ack_command_id"] = json!(id);
        }
        let v = self.post(relay_url, "/api/v1/device/poll", device_token, body)?;
        if !v["ok"].as_bool().unwrap_or(false) {
            return None;
        }
        let command = v.get("command").and_then(|c| if c.is_null() { None } else { Some(c.clone()) });
        let policy = v.get("policy").and_then(|p| if p.is_null() { None } else { Some(p.clone()) });
        let screen = v.get("screen").and_then(|s| s.as_bool()).unwrap_or(false);
        Some((command, policy, screen))
    }
}

/// LAN admin server poll. Carries the same state as the relay poll so LAN devices
/// get identical features (site log, denied log, events, alerts, throttle, screen).
pub fn lan_poll(http: &ureq::Agent, link: &ClientLink, ack_command_id: Option<&str>) -> Option<Value> {
    let alert = serde_json::from_str::<Value>(&link.pending_alert).unwrap_or(Value::Null);
    let body = json!({
        "device_id": link.device_id,
        "hostname": hostname(),
        "blocked": is_blocked(),
        "mode": read_config().mode,
        "policy_version": link.policy_version,
        "app_version": APP_VERSION,
        "rustdesk_id": link.rustdesk_id.clone(),
        "ack_command_id": ack_command_id,
        "sites": crate::proxy::recent_sites(),
        "denied": crate::proxy::recent_denied(),
        "event": link.pending_event.clone(),
        "alert": alert,
    });
    let resp = http
        .post(&format!("{}/api/poll", link.server_url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", link.token))
        .send_json(body);
    resp.ok().and_then(|r| r.into_json().ok())
}

/// Upload a screenshot to the LAN admin server.
pub fn lan_upload_screen(http: &ureq::Agent, link: &ClientLink, image: &str) -> Option<Value> {
    let body = json!({ "image": image, "device_id": link.device_id });
    let resp = http
        .post(&format!("{}/api/v1/device/screen", link.server_url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", link.token))
        .set("Content-Type", "application/json")
        .send_json(body);
    resp.ok().and_then(|r| r.into_json().ok())
}