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
                // Prefer the local admin server whenever it is explicitly configured.
                // Relay is only used when the device is intentionally linked to one.
                if !link.server_url.trim().is_empty() {
                    Transport::Lan
                } else if !link.relay_url.trim().is_empty() {
                    Transport::Relay
                } else {
                    Transport::Lan
                }
            }
        }
    }


}

pub enum RelayPollOutcome {
    Ok(Option<Value>, Option<Value>, bool, String, Option<Value>, bool, Option<Value>),
    Unauthorized,
    NetworkError,
}

pub struct RelayClient {
    http: ureq::Agent,
    fast_http: ureq::Agent,
    upload_http: ureq::Agent,
}

impl RelayClient {
    pub fn new() -> Self {
        RelayClient {
            http: tls_agent(30),
            fast_http: tls_agent(10),
            upload_http: tls_agent(180),
        }
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
    /// Uploads a base64 frame or stream status (`screen` or `camera`) captured in the user session.
    pub fn upload_screen_frame(
        &self,
        relay_url: &str,
        device_token: &str,
        image: &str,
        kind: &str,
        error: &str,
    ) -> Option<Value> {
        self.post(
            relay_url,
            "/api/v1/device/screen",
            device_token,
            json!({"image": image, "kind": kind, "error": error}),
        )
    }

    pub fn upload_screen(&self, relay_url: &str, device_token: &str, image: &str) -> Option<Value> {
        self.upload_screen_frame(relay_url, device_token, image, "screen", "")
    }

    /// Uploads an exact archived copy of a user-uploaded file (up to 64 MB raw) to the relay.
    pub fn upload_file(&self, relay_url: &str, device_token: &str, payload: &Value) -> Option<Value> {
        let url = format!("{}/api/v1/device/file", relay_url.trim_end_matches('/'));
        let resp = self
            .upload_http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", device_token))
            .set("Content-Type", "application/json")
            .send_json(payload.clone());
        resp.ok().and_then(|r| r.into_json().ok())
    }

    /// Reports a security alert (usb, tamper, exfil) to the relay.
    pub fn report_alert(&self, relay_url: &str, device_token: &str, alert: &Value) -> Option<Value> {
        if alert.is_null() {
            return None;
        }
        let url = format!("{}/api/v1/device/alert", relay_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", device_token))
            .set("Content-Type", "application/json")
            .send_json(alert.clone());
        resp.ok().and_then(|r| r.into_json().ok())
    }

    /// Uploads a live Dahua CCTV JPEG frame (or error) from a branch bridge PC to the Relay.
    pub fn upload_cctv_frame(&self, relay_url: &str, device_token: &str, payload: &Value) -> Option<Value> {
        let url = format!("{}/api/v1/device/cctv-frame", relay_url.trim_end_matches('/'));
        let resp = self
            .fast_http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", device_token))
            .set("Content-Type", "application/json")
            .send_json(payload.clone());
        resp.ok().and_then(|r| r.into_json().ok())
    }

    /// Uploads local subnet Dahua DVR auto-discovery results from a branch bridge PC.
    pub fn upload_cctv_scan(&self, relay_url: &str, device_token: &str, found: &[Value]) -> Option<Value> {
        let url = format!("{}/api/v1/device/cctv-scan", relay_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", device_token))
            .set("Content-Type", "application/json")
            .send_json(json!({ "found": found }));
        resp.ok().and_then(|r| r.into_json().ok())
    }

    /// Uploads an on-demand Dahua CGI response (HDD health, ChannelTitle, playback search/clip, PTZ) from a branch PC.
    pub fn upload_cctv_cgi(&self, relay_url: &str, device_token: &str, payload: &Value) -> Option<Value> {
        let url = format!("{}/api/v1/device/cctv-cgi", relay_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", device_token))
            .set("Content-Type", "application/json")
            .send_json(payload.clone());
        resp.ok().and_then(|r| r.into_json().ok())
    }

    /// Uploads a live micro-chunk of Dahua camera audio (`~1-3 KB` AAC/G.711) while an admin has unmuted a camera.
    pub fn upload_cctv_audio(&self, relay_url: &str, device_token: &str, payload: &Value) -> Option<Value> {
        let url = format!("{}/api/v1/device/cctv-audio", relay_url.trim_end_matches('/'));
        let resp = self
            .fast_http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", device_token))
            .set("Content-Type", "application/json")
            .send_json(payload.clone());
        resp.ok().and_then(|r| r.into_json().ok())
    }

    pub fn poll_status(
        &self,
        relay_url: &str,
        device_token: &str,
        state: &Value,
        ack_command_id: Option<&str>,
    ) -> RelayPollOutcome {
        let mut body = state.clone();
        if let Some(id) = ack_command_id {
            body["ack_command_id"] = json!(id);
        }
        let url = format!("{}/api/v1/device/poll", relay_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .set("Authorization", &format!("Bearer {}", device_token))
            .set("Content-Type", "application/json")
            .send_json(body);
        match resp {
            Ok(r) => match r.into_json::<Value>() {
                Ok(v) => {
                    if !v["ok"].as_bool().unwrap_or(false) {
                        return RelayPollOutcome::Unauthorized;
                    }
                    let command = v.get("command").and_then(|c| if c.is_null() { None } else { Some(c.clone()) });
                    let policy = v.get("policy").and_then(|p| if p.is_null() { None } else { Some(p.clone()) });
                    let screen = v.get("screen").and_then(|s| s.as_bool()).unwrap_or(false);
                    let stream_mode = v
                        .get("stream_mode")
                        .and_then(|s| s.as_str())
                        .unwrap_or(if screen { "once" } else { "" })
                        .to_string();
                    let cctv_tasks = v.get("cctv_tasks").and_then(|t| if t.is_null() { None } else { Some(t.clone()) });
                    let cctv_scan = v.get("cctv_scan").and_then(|s| s.as_bool()).unwrap_or(false);
                    let cctv_cgi = v.get("cctv_cgi").and_then(|c| if c.is_null() { None } else { Some(c.clone()) });
                    RelayPollOutcome::Ok(command, policy, screen, stream_mode, cctv_tasks, cctv_scan, cctv_cgi)
                }
                Err(_) => RelayPollOutcome::NetworkError,
            },
            Err(ureq::Error::Status(401 | 403, _)) => RelayPollOutcome::Unauthorized,
            Err(_) => RelayPollOutcome::NetworkError,
        }
    }
}

/// LAN admin server poll. Carries the same state as the relay poll so LAN devices
/// get identical features (site log, denied log, events, alerts, throttle, screen).
pub fn lan_poll(http: &ureq::Agent, link: &ClientLink, ack_command_id: Option<&str>) -> Option<Value> {
    let cfg = read_config();
    let alert = serde_json::from_str::<Value>(&link.pending_alert).unwrap_or(Value::Null);
    let body = json!({
        "device_id": link.device_id,
        "hostname": hostname(),
        "blocked": is_blocked(),
        "usb_blocked": crate::common::is_usb_effectively_blocked(&cfg, link),
        "mode": cfg.mode,
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

/// Upload a screenshot or camera stream frame to the LAN admin server.
pub fn lan_upload_screen_frame(
    http: &ureq::Agent,
    link: &ClientLink,
    image: &str,
    kind: &str,
    error: &str,
) -> Option<Value> {
    let body = json!({
        "image": image,
        "kind": kind,
        "error": error,
        "device_id": link.device_id
    });
    let resp = http
        .post(&format!("{}/api/v1/device/screen", link.server_url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", link.token))
        .set("Content-Type", "application/json")
        .send_json(body);
    resp.ok().and_then(|r| r.into_json().ok())
}

pub fn lan_upload_screen(http: &ureq::Agent, link: &ClientLink, image: &str) -> Option<Value> {
    lan_upload_screen_frame(http, link, image, "screen", "")
}

/// Upload an archived copy of a user-uploaded file to the LAN admin server.
pub fn lan_upload_file(http: &ureq::Agent, link: &ClientLink, payload: &Value) -> Option<Value> {
    let resp = http
        .post(&format!("{}/api/v1/device/file", link.server_url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", link.token))
        .set("Content-Type", "application/json")
        .send_json(payload.clone());
    resp.ok().and_then(|r| r.into_json().ok())
}