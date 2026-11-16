use crate::common::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};

const ONLINE_WINDOW_MS: u64 = 45_000;

#[derive(Clone, Serialize)]
pub struct Device {
    pub device_id: String,
    pub hostname: String,
    pub ip: String,
    pub blocked: bool,
    pub mode: String,
    pub app_version: String,
    pub last_seen: u64,
    pub rustdesk_id: String,
    pub throttle_kbps: u64,
    pub sites: Vec<String>,
    pub denied: Vec<String>,
    pub group_id: String,
    pub label: String,
    pub last_event: String,
    pub last_event_at: u64,
    pub rustdesk_password: String,
    pub screen_requested: bool,
    /// Last command id applied by the device (so a restart never re-applies it).
    pub last_command_id: String,
}

#[derive(Serialize)]
pub struct DeviceView {
    #[serde(flatten)]
    pub device: Device,
    pub online: bool,
}

#[derive(Default)]
pub struct Registry {
    pub devices: HashMap<String, Device>,
    pub pending: HashMap<String, String>,
    pub pending_throttle: HashMap<String, u64>,
    pub groups: HashMap<String, Group>,
    pub group_policies: HashMap<String, GroupPolicy>,
    pub alerts: Vec<Alert>,
    pub audit_log: Vec<AuditEntry>,
    pub screens: HashMap<String, ScreenData>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub version: String,
    pub mode: String,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub updated_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub device_id: String,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub meta: String,
    pub created_at: u64,
    pub acked_at: Option<u64>,
    pub acked_by: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub result: String,
    pub meta: String,
    pub created_at: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ScreenData {
    pub image: String,
    pub at: u64,
}

#[derive(Clone)]
pub struct ServerHandle {
    pub registry: Arc<Mutex<Registry>>,
    pub port: u16,
    pub token: String,
}

#[derive(Deserialize)]
struct PollIn {
    device_id: String,
    hostname: String,
    #[serde(default)]
    ack_command_id: Option<String>,
    #[serde(default)]
    blocked: bool,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    policy_version: String,
    #[serde(default)]
    app_version: String,
    #[serde(default)]
    rustdesk_id: String,
    #[serde(default)]
    throttle: Option<u64>,
    #[serde(default)]
    sites: Vec<String>,
    #[serde(default)]
    denied: Vec<String>,
    #[serde(default)]
    event: String,
    #[serde(default)]
    alert: serde_json::Value,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rid(prefix: &str) -> String {
    format!("{}{}", prefix, uuid::Uuid::new_v4().to_string().replace('-', ""))
}

/// Binds the first free port starting at `preferred` and serves clients on a background thread.
pub fn start(token: String, preferred: u16) -> Result<ServerHandle, String> {
    let mut last_err = String::new();
    for port in preferred..preferred.saturating_add(10) {
        match Server::http(("0.0.0.0", port)) {
            Ok(server) => {
                let registry = Arc::new(Mutex::new(Registry::default()));
                let handle = ServerHandle { registry: registry.clone(), port, token: token.clone() };
                std::thread::spawn(move || {
                    for req in server.incoming_requests() {
                        handle_request(req, &registry, &token);
                    }
                });
                return Ok(handle);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

fn json_response(body: serde_json::Value, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(body.to_string()).with_status_code(status).with_header(header)
}

fn get_group_policy(reg: &Registry, group_id: &str) -> Option<GroupPolicy> {
    reg.group_policies.get(group_id).cloned()
}

fn current_policy_full(cfg: &Config) -> serde_json::Value {
    let mut policy = json!({
        "mode": cfg.mode,
        "allowed": read_list(&allowed_path()),
        "blocked": read_list(&blocked_path()),
        "password_hash": cfg.password_hash,
        "auto_start": cfg.auto_start,
        "exfil_threshold_mb": cfg.exfil_threshold_mb,
        "exfil_window_secs": cfg.exfil_window_secs,
        "exfil_suspicious": cfg.exfil_suspicious,
        "usb_block": cfg.usb_block,
        "rustdesk_server": cfg.rustdesk_server,
        "rustdesk_key": cfg.rustdesk_key,
    });
    let digest = Sha256::digest(policy.to_string().as_bytes());
    let version: String = digest.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    policy["version"] = json!(version);
    policy
}

fn handle_request(mut req: Request, registry: &Arc<Mutex<Registry>>, token: &str) {
    let authorized = req
        .headers()
        .iter()
        .any(|h| h.field.equiv("Authorization") && h.value.as_str() == format!("Bearer {}", token));
    if !authorized {
        let _ = req.respond(json_response(json!({"ok": false, "error": "unauthorized"}), 401));
        return;
    }

    let url = req.url().to_string();
    let method = req.method().clone();

    // Health check
    if method == Method::Get && url == "/healthz" {
        let _ = req.respond(json_response(json!({"ok": true, "ts": now()}), 200));
        return;
    }

    // Device poll endpoint
    if method == Method::Post && url == "/api/poll" {
        handle_poll(req, registry);
        return;
    }

    // Device screen upload endpoint (for both LAN and relay clients)
    if method == Method::Post && url == "/api/v1/device/screen" {
        handle_device_screen_upload(req, registry);
        return;
    }

    // Admin endpoints
    if url.starts_with("/api/admin/") {
        handle_admin(req, registry, &url, &method);
        return;
    }

    let _ = req.respond(json_response(json!({"ok": false, "error": "not found"}), 404));
}

fn handle_poll(mut req: Request, registry: &Arc<Mutex<Registry>>) {
    let ip = req.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let mut body = String::new();
    let _ = req.as_reader().take(65_536).read_to_string(&mut body);

    let poll: PollIn = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => {
            let _ = req.respond(json_response(json!({"ok": false, "error": "bad request"}), 400));
            return;
        }
    };
    if poll.device_id.is_empty() || poll.device_id.len() > 64 || poll.hostname.len() > 64 {
        let _ = req.respond(json_response(json!({"ok": false, "error": "bad request"}), 400));
        return;
    }

    let (command, policy, screen, rustdesk_password) = {
        let mut reg = registry.lock().unwrap();
        // Acknowledge the previously applied command (mirrors the relay protocol).
        if let Some(id) = poll.ack_command_id.as_deref().filter(|s| !s.is_empty()) {
            if let Some(d) = reg.devices.get_mut(&poll.device_id) {
                d.last_command_id = id.to_string();
            }
        }
        let old = reg.devices.get(&poll.device_id).cloned();
        let throttle = poll.throttle.unwrap_or_else(|| old.as_ref().map(|d| d.throttle_kbps).unwrap_or(0));
        let sites = if poll.sites.is_empty() {
            old.as_ref().map(|d| d.sites.clone()).unwrap_or_default()
        } else {
            poll.sites.clone()
        };
        let denied = if poll.denied.is_empty() {
            old.as_ref().map(|d| d.denied.clone()).unwrap_or_default()
        } else {
            poll.denied.clone()
        };
        let rustdesk_id = if poll.rustdesk_id.is_empty() {
            old.as_ref().map(|d| d.rustdesk_id.clone()).unwrap_or_default()
        } else {
            poll.rustdesk_id.clone()
        };
        let group_id = old.as_ref().map(|d| d.group_id.clone()).unwrap_or_default();
        let group_id_for_policy = group_id.clone();
        let label = old.as_ref().map(|d| d.label.clone()).unwrap_or_default();
        let last_event = if !poll.event.is_empty() { poll.event.clone() } else { old.as_ref().map(|d| d.last_event.clone()).unwrap_or_default() };
        let last_event_at = if !poll.event.is_empty() { now() } else { old.as_ref().map(|d| d.last_event_at).unwrap_or(0) };
        let rustdesk_password = old.as_ref().map(|d| d.rustdesk_password.clone()).unwrap_or_default();
        let screen_requested = old.as_ref().map(|d| d.screen_requested).unwrap_or(false);

        // Handle incoming alert from device
        if !poll.alert.is_null() {
            let alert = Alert {
                id: rid("alt_"),
                device_id: poll.device_id.clone(),
                alert_type: poll.alert["type"].as_str().unwrap_or("tamper").to_string(),
                severity: poll.alert["severity"].as_str().unwrap_or("medium").to_string(),
                message: poll.alert["message"].as_str().unwrap_or("").to_string(),
                meta: poll.alert["meta"].to_string(),
                created_at: now(),
                acked_at: None,
                acked_by: None,
            };
            reg.alerts.push(alert);
        }

        reg.devices.insert(
            poll.device_id.clone(),
            Device {
                device_id: poll.device_id.clone(),
                hostname: poll.hostname.clone(),
                ip,
                blocked: poll.blocked,
                mode: poll.mode.clone(),
                app_version: poll.app_version.clone(),
                last_seen: now_ms(),
                rustdesk_id,
                throttle_kbps: throttle,
                sites,
                denied,
                group_id,
                label,
                last_event,
                last_event_at,
                rustdesk_password: rustdesk_password.clone(),
                screen_requested,
                last_command_id: old.as_ref().map(|d| d.last_command_id.clone()).unwrap_or_default(),
            },
        );

        // Get pending command
        let command = reg.pending.remove(&poll.device_id);
        let throttle_cmd = reg.pending_throttle.remove(&poll.device_id).map(|kbps| format!("throttle:{}", kbps));

        // Determine policy to send
        let cfg = read_config();
        let full_policy = current_policy_full(&cfg);
        let group_policy = group_id_for_policy.as_str();
        let effective_policy = if !group_policy.is_empty() {
            if let Some(gp) = get_group_policy(&reg, group_policy) {
                let mut p = json!({
                    "mode": gp.mode,
                    "allowed": gp.allowed,
                    "blocked": gp.blocked,
                });
                let digest = Sha256::digest(p.to_string().as_bytes());
                let version: String = digest.iter().take(8).map(|b| format!("{:02x}", b)).collect();
                p["version"] = json!(version);
                if poll.policy_version != version { Some(p) } else { None }
            } else { None }
        } else {
            let version = full_policy["version"].as_str().unwrap_or("");
            if poll.policy_version != version { Some(full_policy) } else { None }
        };

        (command.or(throttle_cmd), effective_policy, screen_requested, rustdesk_password)
    };

    let _ = req.respond(json_response(
        json!({
            "ok": true,
            "command": command,
            "policy": policy,
            "poll_seconds": 3,
            "screen": screen,
            "rustdesk_password": rustdesk_password,
        }),
        200,
    ));
}

fn handle_device_screen_upload(mut req: Request, registry: &Arc<Mutex<Registry>>) {
    // Extract device token from Authorization header
    let auth_header = req.headers().iter().find(|h| h.field.equiv("Authorization"));
    let token = auth_header.map(|h| h.value.as_str()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if token.is_empty() {
        let _ = req.respond(json_response(json!({"ok": false, "error": "unauthorized"}), 401));
        return;
    }

    // Find device by token (in LAN, token is the api_token from config)
    let cfg = read_config();
    if token != cfg.api_token {
        let _ = req.respond(json_response(json!({"ok": false, "error": "invalid token"}), 401));
        return;
    }

    // Read the image from body - we need to get device_id somehow
    // For LAN, the device sends to /api/v1/device/screen with the same token as poll
    // We'll extract device_id from the body or use the first device
    let mut body = String::new();
    let _ = req.as_reader().take(10 * 1024 * 1024).read_to_string(&mut body); // 10MB limit
    let body_val: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            let _ = req.respond(json_response(json!({"ok": false, "error": "bad request"}), 400));
            return;
        }
    };

    let image = body_val["image"].as_str().unwrap_or("");
    if image.is_empty() {
        let _ = req.respond(json_response(json!({"ok": false, "error": "missing image"}), 400));
        return;
    }

    // For LAN, we'll store the image for the most recent device that requested a screenshot
    // or we can add device_id to the request body
    let device_id = body_val["device_id"].as_str().unwrap_or("");

    let mut reg = registry.lock().unwrap();
    // Prefer an explicit device_id, otherwise attach the image to the first device
    // that is still waiting for its screenshot (the LAN agent does not send an id).
    let target = if !device_id.is_empty() && reg.devices.contains_key(device_id) {
        Some(device_id.to_string())
    } else {
        let mut found = None;
        for (id, d) in reg.devices.iter() {
            if d.screen_requested {
                found = Some(id.clone());
                break;
            }
        }
        found
    };
    if let Some(id) = target {
        let entry = reg.screens.entry(id.clone()).or_insert_with(ScreenData::default);
        entry.image = image.to_string();
        entry.at = now();
        if let Some(d) = reg.devices.get_mut(&id) {
            d.screen_requested = false;
        }
    }

    let _ = req.respond(json_response(json!({"ok": true}), 200));
}

fn handle_admin(mut req: Request, registry: &Arc<Mutex<Registry>>, url: &str, method: &Method) {
    let mut body = String::new();
    let _ = req.as_reader().take(65_536).read_to_string(&mut body);
    let body_val: serde_json::Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_str(&body).unwrap_or(json!({}))
    };

    let path = url.strip_prefix("/api/admin/").unwrap_or("");

    // Stats
    if method == &Method::Get && path == "stats" {
        let reg = registry.lock().unwrap();
        let total = reg.devices.len() as u64;
        let online = reg.devices.values().filter(|d| now_ms().saturating_sub(d.last_seen) < ONLINE_WINDOW_MS).count() as u64;
        let pending = reg.pending.len() as u64;
        let engagement = if total > 0 { (online as f64 / total as f64 * 1000.0).round() / 10.0 } else { 0.0 };
        let _ = req.respond(json_response(json!({
            "ok": true,
            "stats": {
                "users": { "value": total, "growth": 12.5 },
                "profit": { "value": 128450, "growth": 8.2 },
                "orders": { "value": pending, "growth": -3.1 },
                "engagement": { "value": engagement, "growth": 4.4 }
            }
        }), 200));
        return;
    }

    // Alerts
    if method == &Method::Get && path == "alerts" {
        let reg = registry.lock().unwrap();
        let alerts: Vec<_> = reg.alerts.iter().rev().take(200).cloned().collect();
        let unacked = reg.alerts.iter().filter(|a| a.acked_at.is_none()).count();
        let _ = req.respond(json_response(json!({"ok": true, "alerts": alerts, "unacked": unacked}), 200));
        return;
    }
    if method == &Method::Post && path.starts_with("alerts/") && path.ends_with("/ack") {
        let alert_id = path.strip_prefix("alerts/").unwrap().strip_suffix("/ack").unwrap();
        let mut reg = registry.lock().unwrap();
        if let Some(a) = reg.alerts.iter_mut().find(|a| a.id == alert_id) {
            if a.acked_at.is_none() {
                a.acked_at = Some(now());
                a.acked_by = Some("admin".into());
            }
        }
        let _ = req.respond(json_response(json!({"ok": true}), 200));
        return;
    }

    // Audit log
    if method == &Method::Get && path == "audit" {
        let reg = registry.lock().unwrap();
        let entries: Vec<_> = reg.audit_log.iter().rev().take(200).cloned().collect();
        let _ = req.respond(json_response(json!({"ok": true, "entries": entries}), 200));
        return;
    }

    // Devices list
    if method == &Method::Get && path == "devices" {
        let reg = registry.lock().unwrap();
        let devices: Vec<_> = reg.devices.values().map(|d| {
            json!({
                "device_id": d.device_id,
                "hostname": d.hostname,
                "os": d.mode.clone(), // placeholder
                "app_version": d.app_version,
                "enrolled_at": d.last_seen,
                "last_seen": d.last_seen,
                "ip": d.ip,
                "blocked": d.blocked,
                "mode": d.mode,
                "policy_version": "",
                "group_id": d.group_id,
                "label": d.label,
                "last_event": d.last_event,
                "last_event_at": d.last_event_at,
                "throttle_kbps": d.throttle_kbps,
                "sites": d.sites,
                "denied": d.denied,
                "rustdesk_id": d.rustdesk_id,
                "rustdesk_password": d.rustdesk_password,
                "screen_requested": d.screen_requested,
                "online": now_ms().saturating_sub(d.last_seen) < ONLINE_WINDOW_MS,
            })
        }).collect();
        let _ = req.respond(json_response(json!({"ok": true, "devices": devices}), 200));
        return;
    }

    // Device command (block/unblock/throttle)
    if method == &Method::Post && path.starts_with("devices/") && path.ends_with("/command") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/command").unwrap();
        let raw = body_val["command"].as_str().unwrap_or("");
        let command_type = match raw {
            "block" => "block",
            "unblock" => "unblock",
            s if s.starts_with("throttle:") => s,
            _ => {
                let _ = req.respond(json_response(json!({"ok": false, "error": "invalid command"}), 400));
                return;
            }
        };
        let mut reg = registry.lock().unwrap();
        let targets = if device_id == "*" {
            reg.devices.keys().cloned().collect()
        } else if reg.devices.contains_key(device_id) {
            vec![device_id.to_string()]
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no device"}), 404));
            return;
        };
        let mut count = 0;
        for id in targets {
            if command_type.starts_with("throttle:") {
                let kbps = command_type.strip_prefix("throttle:").unwrap().parse::<u64>().unwrap_or(0);
                reg.pending_throttle.insert(id, kbps);
            } else {
                reg.pending.insert(id, command_type.to_string());
            }
            count += 1;
        }
        let _ = req.respond(json_response(json!({"ok": true, "queued": count}), 200));
        return;
    }

    // Device delete
    if method == &Method::Delete && path.starts_with("devices/") && !path.contains("/") {
        let device_id = path.strip_prefix("devices/").unwrap();
        let mut reg = registry.lock().unwrap();
        reg.devices.remove(device_id);
        reg.pending.remove(device_id);
        reg.pending_throttle.remove(device_id);
        reg.screens.remove(device_id);
        let _ = req.respond(json_response(json!({"ok": true, "deleted": true}), 200));
        return;
    }

    // Device label
    if method == &Method::Post && path.starts_with("devices/") && path.ends_with("/label") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/label").unwrap();
        let label = body_val["label"].as_str().unwrap_or("").to_string();
        let mut reg = registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(device_id) {
            d.label = label;
            let _ = req.respond(json_response(json!({"ok": true}), 200));
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no device"}), 404));
        }
        return;
    }

    // Device group assignment
    if method == &Method::Post && path.starts_with("devices/") && path.ends_with("/group") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/group").unwrap();
        let group_id = body_val["group_id"].as_str().unwrap_or("").to_string();
        let mut reg = registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(device_id) {
            d.group_id = group_id;
            let _ = req.respond(json_response(json!({"ok": true}), 200));
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no device"}), 404));
        }
        return;
    }

    // Device screen request
    if method == &Method::Post && path.starts_with("devices/") && path.ends_with("/screen/request") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/screen/request").unwrap();
        let mut reg = registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(device_id) {
            d.screen_requested = true;
            reg.screens.insert(device_id.to_string(), ScreenData { image: String::new(), at: 0 });
            let _ = req.respond(json_response(json!({"ok": true}), 200));
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no device"}), 404));
        }
        return;
    }

    // Device screen get
    if method == &Method::Get && path.starts_with("devices/") && path.ends_with("/screen") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/screen").unwrap();
        let reg = registry.lock().unwrap();
        let screen = reg.screens.get(device_id).cloned().unwrap_or_default();
        let dev = reg.devices.get(device_id);
        let _ = req.respond(json_response(json!({
            "ok": true,
            "requested": dev.map(|d| d.screen_requested).unwrap_or(false),
            "image": screen.image,
            "at": screen.at,
        }), 200));
        return;
    }

    // Device RustDesk password
    if method == &Method::Post && path.starts_with("devices/") && path.ends_with("/rustdesk_password") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/rustdesk_password").unwrap();
        let password = body_val["password"].as_str().unwrap_or("").to_string();
        let mut reg = registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(device_id) {
            d.rustdesk_password = password;
            let _ = req.respond(json_response(json!({"ok": true}), 200));
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no device"}), 404));
        }
        return;
    }

    // Policy get/put
    if path == "policy" {
        if method == &Method::Get {
            let cfg = read_config();
            let _ = req.respond(json_response(json!({"ok": true, "policy": current_policy_full(&cfg)}), 200));
            return;
        }
        if method == &Method::Put {
            let cfg = read_config();
            let full = current_policy_full(&cfg);
            let _ = req.respond(json_response(json!({"ok": true, "policy": full}), 200));
            return;
        }
    }

    // Groups
    if path == "groups" {
        if method == &Method::Get {
            let reg = registry.lock().unwrap();
            let groups: Vec<_> = reg.groups.values().map(|g| {
                let policy = reg.group_policies.get(&g.id);
                let count = reg.devices.values().filter(|d| d.group_id == g.id).count();
                json!({
                    "id": g.id,
                    "name": g.name,
                    "created_at": g.created_at,
                    "devices": count,
                    "version": policy.as_ref().map(|p| p.version.clone()).unwrap_or_default(),
"mode": policy.as_ref().map(|p| p.mode.clone()).unwrap_or_else(|| "whitelist".to_string()),
                    "allowed": policy.as_ref().map(|p| p.allowed.clone()).unwrap_or_default(),
                    "blocked": policy.as_ref().map(|p| p.blocked.clone()).unwrap_or_default(),
                })
            }).collect();
            let _ = req.respond(json_response(json!({"ok": true, "groups": groups}), 200));
            return;
        }
        if method == &Method::Post {
            let name = body_val["name"].as_str().unwrap_or("").trim().to_string();
            if name.is_empty() {
                let _ = req.respond(json_response(json!({"ok": false, "error": "name required"}), 400));
                return;
            }
            let mut reg = registry.lock().unwrap();
            let gid = rid("grp_");
            let group = Group { id: gid.clone(), name: name.clone(), created_at: now() };
            let policy = GroupPolicy {
                version: rid("gv_"),
                mode: body_val["mode"].as_str().unwrap_or("whitelist").to_string(),
                allowed: body_val["allowed"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
                blocked: body_val["blocked"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
                updated_at: now(),
            };
            reg.groups.insert(gid.clone(), group);
            reg.group_policies.insert(gid.clone(), policy);
            let _ = req.respond(json_response(json!({"ok": true, "group": gid}), 200));
            return;
        }
    }
    if path.starts_with("groups/") && !path.contains("/command") {
        let gid = path.strip_prefix("groups/").unwrap();
        let mut reg = registry.lock().unwrap();
        if !reg.groups.contains_key(gid) {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no group"}), 404));
            return;
        }
        if method == &Method::Put {
            if let Some(name) = body_val["name"].as_str() {
                if let Some(g) = reg.groups.get_mut(gid) {
                    g.name = name.trim().to_string();
                }
            }
            if body_val["mode"].is_string() || body_val["allowed"].is_array() || body_val["blocked"].is_array() {
                let mut policy = reg.group_policies.get(gid).cloned().unwrap_or(GroupPolicy {
                    version: rid("gv_"),
                    mode: "whitelist".into(),
                    allowed: vec![],
                    blocked: vec![],
                    updated_at: now(),
                });
                if let Some(mode) = body_val["mode"].as_str() {
                    policy.mode = if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() };
                }
                if let Some(allowed) = body_val["allowed"].as_array() {
                    policy.allowed = allowed.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                }
                if let Some(blocked) = body_val["blocked"].as_array() {
                    policy.blocked = blocked.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                }
                policy.version = rid("gv_");
                policy.updated_at = now();
                reg.group_policies.insert(gid.to_string(), policy);
            }
            let _ = req.respond(json_response(json!({"ok": true}), 200));
            return;
        }
        if method == &Method::Delete {
            reg.groups.remove(gid);
            reg.group_policies.remove(gid);
            for d in reg.devices.values_mut() {
                if d.group_id == gid { d.group_id.clear(); }
            }
            let _ = req.respond(json_response(json!({"ok": true}), 200));
            return;
        }
    }

    // Group command
    if method == &Method::Post && path.starts_with("groups/") && path.ends_with("/command") {
        let gid = path.strip_prefix("groups/").unwrap().strip_suffix("/command").unwrap();
        let mut reg = registry.lock().unwrap();
        if !reg.groups.contains_key(gid) {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no group"}), 404));
            return;
        }
        let raw = body_val["command"].as_str().unwrap_or("");
        let command_type = match raw {
            "block" => "block",
            "unblock" => "unblock",
            _ => { let _ = req.respond(json_response(json!({"ok": false, "error": "invalid command"}), 400)); return; }
        };
        let targets: Vec<_> = reg.devices.values().filter(|d| d.group_id == gid).map(|d| d.device_id.clone()).collect();
        let mut count = 0;
        for id in targets {
            reg.pending.insert(id, command_type.to_string());
            count += 1;
        }
        let _ = req.respond(json_response(json!({"ok": true, "queued": count}), 200));
        return;
    }

    let _ = req.respond(json_response(json!({"ok": false, "error": "not found"}), 404));
}

impl ServerHandle {
    pub fn devices(&self) -> Vec<DeviceView> {
        let now = now_ms();
        let reg = self.registry.lock().unwrap();
        let mut list: Vec<DeviceView> = reg
            .devices
            .values()
            .map(|d| DeviceView { online: now.saturating_sub(d.last_seen) < ONLINE_WINDOW_MS, device: d.clone() })
            .collect();
        list.sort_by(|a, b| a.device.hostname.to_lowercase().cmp(&b.device.hostname.to_lowercase()));
        list
    }

    /// Queues a one-shot command for a device, or for every online device when `device_id` is "*".
    /// Supports: "block", "unblock", "throttle:<kbps>"
    pub fn send_command(&self, device_id: &str, command: &str) -> Result<(), String> {
        let valid = command == "block" || command == "unblock" || command.starts_with("throttle:");
        if !valid {
            return Err("أمر غير معروف".into());
        }
        let now = now_ms();
        let mut reg = self.registry.lock().unwrap();
        if device_id == "*" {
            let ids: Vec<String> = reg
                .devices
                .values()
                .filter(|d| now.saturating_sub(d.last_seen) < ONLINE_WINDOW_MS)
                .map(|d| d.device_id.clone())
                .collect();
            for id in ids {
                if command.starts_with("throttle:") {
                    let kbps = command.strip_prefix("throttle:").unwrap().parse::<u64>().unwrap_or(0);
                    reg.pending_throttle.insert(id.clone(), kbps);
                } else {
                    reg.pending.insert(id.clone(), command.to_string());
                }
                if let Some(d) = reg.devices.get_mut(&id) {
                    if command == "block" { d.blocked = true; }
                    else if command == "unblock" { d.blocked = false; }
                }
            }
        } else if reg.devices.contains_key(device_id) {
            if command.starts_with("throttle:") {
                let kbps = command.strip_prefix("throttle:").unwrap().parse::<u64>().unwrap_or(0);
                reg.pending_throttle.insert(device_id.to_string(), kbps);
            } else {
                reg.pending.insert(device_id.to_string(), command.to_string());
            }
            if let Some(d) = reg.devices.get_mut(device_id) {
                if command == "block" { d.blocked = true; }
                else if command == "unblock" { d.blocked = false; }
            }
        } else {
            return Err("الجهاز غير موجود".into());
        }
        Ok(())
    }

    // Admin helper methods
    pub fn get_groups(&self) -> Vec<serde_json::Value> {
        let reg = self.registry.lock().unwrap();
        reg.groups.values().map(|g| {
            let policy = reg.group_policies.get(&g.id);
            let count = reg.devices.values().filter(|d| d.group_id == g.id).count();
            json!({
                "id": g.id,
                "name": g.name,
                "created_at": g.created_at,
                "devices": count,
                "version": policy.as_ref().map(|p| p.version.clone()).unwrap_or_default(),
                "mode": policy.as_ref().map(|p| p.mode.clone()).unwrap_or_else(|| "whitelist".to_string()),
                "allowed": policy.as_ref().map(|p| p.allowed.clone()).unwrap_or_default(),
                "blocked": policy.as_ref().map(|p| p.blocked.clone()).unwrap_or_default(),
            })
        }).collect()
    }

    pub fn create_group(&self, name: String, mode: String, allowed: Vec<String>, blocked: Vec<String>) -> Result<serde_json::Value, String> {
        let mut reg = self.registry.lock().unwrap();
        let gid = rid("grp_");
        let group = Group { id: gid.clone(), name: name.clone(), created_at: now() };
        let policy = GroupPolicy {
            version: rid("gv_"),
            mode: if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() },
            allowed,
            blocked,
            updated_at: now(),
        };
        reg.groups.insert(gid.clone(), group);
        reg.group_policies.insert(gid.clone(), policy.clone());
        Ok(json!({
            "id": gid,
            "name": name,
            "created_at": now(),
            "devices": 0,
            "version": policy.version,
            "mode": policy.mode,
            "allowed": policy.allowed,
            "blocked": policy.blocked,
        }))
    }

    pub fn update_group(&self, group_id: String, name: String, mode: String, allowed: Vec<String>, blocked: Vec<String>) -> Result<serde_json::Value, String> {
        let mut reg = self.registry.lock().unwrap();
        if !reg.groups.contains_key(&group_id) {
            return Err("no group".into());
        }
        if let Some(g) = reg.groups.get_mut(&group_id) {
            g.name = name.trim().to_string();
        }
        let mut policy = reg.group_policies.get(&group_id).cloned().unwrap_or(GroupPolicy {
            version: rid("gv_"),
            mode: "whitelist".into(),
            allowed: vec![],
            blocked: vec![],
            updated_at: now(),
        });
        policy.mode = if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() };
        policy.allowed = allowed;
        policy.blocked = blocked;
        policy.version = rid("gv_");
        policy.updated_at = now();
        reg.group_policies.insert(group_id.clone(), policy.clone());
        Ok(json!({
            "id": group_id,
            "name": name,
            "version": policy.version,
            "mode": policy.mode,
            "allowed": policy.allowed,
            "blocked": policy.blocked,
        }))
    }

    pub fn delete_group(&self, group_id: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        reg.groups.remove(&group_id);
        reg.group_policies.remove(&group_id);
        for d in reg.devices.values_mut() {
            if d.group_id == group_id { d.group_id.clear(); }
        }
        Ok(())
    }

    pub fn assign_device_group(&self, device_id: String, group_id: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            d.group_id = group_id;
            Ok(())
        } else {
            Err("no device".into())
        }
    }

    pub fn get_alerts(&self, alert_type: Option<String>, acked: Option<String>) -> serde_json::Value {
        let reg = self.registry.lock().unwrap();
        let mut alerts: Vec<_> = reg.alerts.iter().cloned().collect();
        if let Some(t) = alert_type { alerts.retain(|a| a.alert_type == t); }
        if let Some(a) = acked {
            if a == "0" { alerts.retain(|a| a.acked_at.is_none()); }
            else if a == "1" { alerts.retain(|a| a.acked_at.is_some()); }
        }
        alerts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let unacked = reg.alerts.iter().filter(|a| a.acked_at.is_none()).count();
        json!({"ok": true, "alerts": alerts.into_iter().take(200).collect::<Vec<_>>(), "unacked": unacked})
    }

    pub fn ack_alert(&self, alert_id: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(a) = reg.alerts.iter_mut().find(|a| a.id == alert_id) {
            if a.acked_at.is_none() {
                a.acked_at = Some(now());
                a.acked_by = Some("admin".into());
            }
            Ok(())
        } else {
            Err("alert not found".into())
        }
    }

    pub fn get_audit_log(&self) -> serde_json::Value {
        let reg = self.registry.lock().unwrap();
        let entries: Vec<_> = reg.audit_log.iter().rev().take(200).cloned().collect();
        json!({"ok": true, "entries": entries})
    }

    pub fn request_screenshot(&self, device_id: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            d.screen_requested = true;
            reg.screens.insert(device_id, ScreenData { image: String::new(), at: 0 });
            Ok(())
        } else {
            Err("no device".into())
        }
    }

    pub fn get_screenshot(&self, device_id: String) -> serde_json::Value {
        let reg = self.registry.lock().unwrap();
        let screen = reg.screens.get(&device_id).cloned().unwrap_or(ScreenData { image: String::new(), at: 0 });
        let dev = reg.devices.get(&device_id);
        json!({
            "ok": true,
            "requested": dev.map(|d| d.screen_requested).unwrap_or(false),
            "image": screen.image,
            "at": screen.at,
        })
    }

    pub fn set_rustdesk_password(&self, device_id: String, password: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            d.rustdesk_password = password;
            Ok(())
        } else {
            Err("no device".into())
        }
    }

    pub fn delete_device(&self, device_id: String) -> Result<bool, String> {
        let mut reg = self.registry.lock().unwrap();
        let existed = reg.devices.remove(&device_id).is_some();
        reg.pending.remove(&device_id);
        reg.pending_throttle.remove(&device_id);
        reg.screens.remove(&device_id);
        Ok(existed)
    }

    pub fn rename_device(&self, device_id: String, label: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            d.label = label;
            Ok(())
        } else {
            Err("no device".into())
        }
    }

    pub fn send_group_command(&self, group_id: String, command: String) -> Result<u64, String> {
        let mut reg = self.registry.lock().unwrap();
        if !reg.groups.contains_key(&group_id) {
            return Err("no group".into());
        }
        let cmd_type = match command.as_str() {
            "block" => "block",
            "unblock" => "unblock",
            _ => return Err("invalid command".into()),
        };
        let targets: Vec<_> = reg.devices.values().filter(|d| d.group_id == group_id).map(|d| d.device_id.clone()).collect();
        let mut count = 0;
        for id in targets {
            reg.pending.insert(id, cmd_type.to_string());
            count += 1;
        }
        Ok(count)
    }
}
