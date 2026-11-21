use crate::common::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};

const ONLINE_WINDOW_MS: u64 = 45_000;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
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
    pub stream_mode: String,
    pub stream_until: u64,
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
    #[serde(default)]
    pub ephemeral_browser: bool,
    pub updated_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(rename = "type", alias = "alert_type")]
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub meta: String,
    pub created_at: u64,
    pub acked_at: Option<u64>,
    pub acked_by: Option<String>,
    #[serde(default)]
    pub acked: bool,
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
#[serde(default)]
pub struct ScreenData {
    pub image: String,
    pub at: u64,
    pub kind: String,
    pub error: String,
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

fn record_audit(reg: &mut Registry, actor: &str, action: &str, target: Option<&str>, result: &str, meta: &str) {
    let actor_name = actor.trim();
    let entry = AuditEntry {
        id: rid("act_"),
        actor: if actor_name.is_empty() { "admin".to_string() } else { actor_name.to_string() },
        action: action.to_string(),
        target: target.map(str::to_string),
        result: result.to_string(),
        meta: meta.to_string(),
        created_at: now(),
    };
    reg.audit_log.push(entry);
    if reg.audit_log.len() > 500 {
        reg.audit_log.drain(..reg.audit_log.len().saturating_sub(500));
    }
}

fn lan_devices_path() -> std::path::PathBuf {
    data_dir().join("lan-devices.json")
}

fn lan_alerts_path() -> std::path::PathBuf {
    data_dir().join("lan-alerts.json")
}

fn save_lan_alerts(reg: &Registry) {
    let start = reg.alerts.len().saturating_sub(200);
    let slice = &reg.alerts[start..];
    if let Ok(s) = serde_json::to_string_pretty(slice) {
        let _ = std::fs::write(lan_alerts_path(), s);
    }
}

fn strip_alert_media_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') {
        return raw.to_string();
    }
    let Ok(mut val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return raw.to_string();
    };
    if let Some(obj) = val.as_object_mut() {
        let has_sc = obj
            .get("screenshot")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if has_sc {
            obj.insert("has_screenshot".to_string(), json!(true));
            obj.remove("screenshot");
        }
        let has_cam = obj
            .get("camera_photo")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if has_cam {
            obj.insert("has_camera_photo".to_string(), json!(true));
            obj.remove("camera_photo");
        }
    }
    val.to_string()
}

fn mirror_lan_alert_to_relay(alert: &Alert) {
    let a = alert.clone();
    std::thread::spawn(move || {
        let cfg = read_config();
        if cfg.admin_key.trim().is_empty() {
            return;
        }
        let mut bases: Vec<String> = vec!["http://127.0.0.1:8790".to_string()];
        let configured = cfg.relay_url.trim().trim_end_matches('/').to_string();
        if !configured.is_empty() && !bases.iter().any(|b| b == &configured) {
            bases.push(configured);
        }
        let payload = json!({
            "id": a.id,
            "device_id": a.device_id,
            "device_name": a.device_name,
            "type": a.alert_type,
            "severity": a.severity,
            "message": a.message,
            "meta": a.meta,
            "created_at": a.created_at,
        });
        let http = tls_agent(15);
        for base in bases {
            let url = format!("{}/api/v1/admin/alerts", base);
            if let Ok(resp) = http
                .post(&url)
                .set("Authorization", &format!("Bearer {}", cfg.admin_key))
                .set("Content-Type", "application/json")
                .send_json(payload.clone())
            {
                if resp.status() == 200 {
                    break;
                }
            }
        }
    });
}

fn save_lan_devices(reg: &Registry) {
    let list: Vec<&Device> = reg.devices.values().collect();
    if let Ok(s) = serde_json::to_string_pretty(&list) {
        let _ = std::fs::write(lan_devices_path(), s);
    }
}

fn lan_groups_path() -> std::path::PathBuf {
    data_dir().join("lan-groups.json")
}

fn save_lan_groups(reg: &Registry) {
    let list: Vec<serde_json::Value> = reg.groups.values().map(|g| {
        let pol = reg.group_policies.get(&g.id);
        json!({
            "id": g.id,
            "name": g.name,
            "created_at": g.created_at,
            "version": pol.map(|p| p.version.clone()).unwrap_or_default(),
            "mode": pol.map(|p| p.mode.clone()).unwrap_or_else(|| "whitelist".to_string()),
            "allowed": pol.map(|p| p.allowed.clone()).unwrap_or_default(),
            "blocked": pol.map(|p| p.blocked.clone()).unwrap_or_default(),
            "ephemeral_browser": pol.map(|p| p.ephemeral_browser).unwrap_or(false),
        })
    }).collect();
    if let Ok(s) = serde_json::to_string_pretty(&list) {
        let _ = std::fs::write(lan_groups_path(), s);
    }
}

fn apply_groups_slice(reg: &mut Registry, groups: &[serde_json::Value]) {
    for item in groups {
        let id = item["id"].as_str().unwrap_or("").trim().to_string();
        if id.is_empty() { continue; }
        let name = item["name"].as_str().unwrap_or("").trim().to_string();
        let created_at = item["created_at"].as_u64().unwrap_or_else(now);
        let mode = if item["mode"].as_str() == Some("blacklist") { "blacklist".to_string() } else { "whitelist".to_string() };
        let allowed: Vec<String> = item["allowed"].as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let blocked: Vec<String> = item["blocked"].as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let ephemeral_browser = item["ephemeral_browser"].as_bool().unwrap_or(false);
        let version = item["version"].as_str().filter(|s| !s.is_empty()).map(String::from).unwrap_or_else(|| rid("gv_"));
        reg.groups.insert(id.clone(), Group { id: id.clone(), name, created_at });
        reg.group_policies.insert(id, GroupPolicy {
            version,
            mode,
            allowed,
            blocked,
            ephemeral_browser,
            updated_at: now(),
        });
    }
}

pub fn server_archive_root() -> std::path::PathBuf {
    let preferred = std::path::PathBuf::from(r"C:\IT-ELKHAWGA-Archive");
    if std::fs::create_dir_all(&preferred).is_ok() {
        return preferred;
    }
    let fallback = std::path::PathBuf::from(r"C:\Users\Public\IT-ELKHAWGA-Archive");
    let _ = std::fs::create_dir_all(&fallback);
    fallback
}

fn ensure_server_archive_dirs() {
    let root = server_archive_root();
    let _ = std::fs::create_dir_all(root.join("WhatsApp"));
    let _ = std::fs::create_dir_all(root.join("Web-Uploads"));
}

fn sanitize_archive_segment(raw: &str, fallback: &str, max_chars: usize) -> String {
    let mut s: String = raw
        .trim()
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0'..='\x1f' => '_',
            _ => c,
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(|c| c == '.' || c == ' ')
        .to_string();
    if s.is_empty() {
        s = fallback.to_string();
    }
    let upper = s.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    ) {
        s.insert(0, '_');
    }
    s.chars().take(max_chars).collect()
}

pub fn build_archive_file_path(
    channel: &str,
    device_name: &str,
    recipient_name: &str,
    recipient_phone: &str,
    orig_name: &str,
) -> std::path::PathBuf {
    let local_now = chrono::Local::now();
    let day_str = local_now.format("%Y-%m-%d").to_string();
    let time_str = local_now.format("%H-%M-%S").to_string();
    let chan_dir = if channel.contains("whatsapp") { "WhatsApp" } else { "Web-Uploads" };
    let dev_dir = sanitize_archive_segment(device_name, "Unknown-Device", 60);
    let dir = server_archive_root().join(chan_dir).join(&day_str).join(&dev_dir);
    let _ = std::fs::create_dir_all(&dir);

    let recip_raw = if !recipient_phone.trim().is_empty() {
        recipient_phone.trim()
    } else {
        recipient_name.trim()
    };
    let recip_tag = if recip_raw.is_empty() {
        String::new()
    } else {
        format!("{}__", sanitize_archive_segment(recip_raw, "", 40))
    };

    let clean_orig = sanitize_archive_segment(orig_name, "file.bin", 130);
    let (stem, ext) = match clean_orig.rfind('.') {
        Some(idx) if idx > 0 => (&clean_orig[..idx], &clean_orig[idx..]),
        _ => (clean_orig.as_str(), ""),
    };
    let mut candidate = dir.join(format!("{}__{}{}{}", time_str, recip_tag, stem, ext));
    if candidate.exists() {
        candidate = dir.join(format!("{}__{}{}__{}{}", time_str, recip_tag, stem, random_hex(2), ext));
    }
    candidate
}

fn archive_log_path() -> std::path::PathBuf {
    server_archive_root().join("archive-log.jsonl")
}

fn append_local_archive_log(entry: &serde_json::Value) {
    use std::io::Write;
    let p = archive_log_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{}", entry);
    }
}

pub fn read_local_archive_entries() -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Ok(raw) = std::fs::read_to_string(archive_log_path()) else {
        return out;
    };
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            out.push(v);
        }
    }
    out
}

fn encode_rfc5987_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Binds the first free port starting at `preferred` and serves clients on a background thread.
pub fn start(token: String, preferred: u16) -> Result<ServerHandle, String> {
    ensure_server_archive_dirs();
    let mut last_err = String::new();
    for port in preferred..preferred.saturating_add(10) {
        match Server::http(("0.0.0.0", port)) {
            Ok(server) => {
                let mut reg_init = Registry::default();
                if let Ok(raw) = std::fs::read_to_string(lan_groups_path()) {
                    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(raw.trim_start_matches('\u{feff}')) {
                        apply_groups_slice(&mut reg_init, &arr);
                    }
                }
                if let Ok(raw) = std::fs::read_to_string(lan_devices_path()) {
                    if let Ok(list) = serde_json::from_str::<Vec<Device>>(raw.trim_start_matches('\u{feff}')) {
                        for mut d in list {
                            if d.device_id.is_empty() { continue; }
                            d.screen_requested = false;
                            reg_init.devices.insert(d.device_id.clone(), d);
                        }
                    }
                }
                if let Ok(raw) = std::fs::read_to_string(lan_alerts_path()) {
                    if let Ok(list) = serde_json::from_str::<Vec<Alert>>(raw.trim_start_matches('\u{feff}')) {
                        for a in &list {
                            mirror_lan_alert_to_relay(a);
                        }
                        reg_init.alerts = list;
                    }
                }
                let registry = Arc::new(Mutex::new(reg_init));
                let handle = ServerHandle { registry: registry.clone(), port, token: token.clone() };
                std::thread::spawn(move || {
                    for req in server.incoming_requests() {
                        let reg = registry.clone();
                        let tok = token.clone();
                        std::thread::spawn(move || {
                            handle_request(req, &reg, &tok, port);
                        });
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

fn bytes_response(bytes: Vec<u8>, content_type: &[u8], status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(&b"Content-Type"[..], content_type).unwrap();
    Response::from_data(bytes).with_status_code(status).with_header(header)
}

fn uploaded_files_dir() -> std::path::PathBuf {
    let dir = data_dir().join("uploaded-files");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn mime_for_filename(name: &str) -> &'static [u8] {
    let lower = name.trim().to_ascii_lowercase();
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        b"image/jpeg"
    } else if lower.ends_with(".png") {
        b"image/png"
    } else if lower.ends_with(".webp") {
        b"image/webp"
    } else if lower.ends_with(".gif") {
        b"image/gif"
    } else if lower.ends_with(".pdf") {
        b"application/pdf"
    } else {
        b"application/octet-stream"
    }
}

pub(crate) fn fetch_uploaded_file_bytes(fid: &str) -> Option<(String, Vec<u8>)> {
    if let Some(hit) = find_local_uploaded_file(fid) {
        if !hit.1.is_empty() {
            return Some(hit);
        }
    }
    let safe_id: String = fid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if safe_id.is_empty() {
        return None;
    }
    let cfg = read_config();
    let mut bases: Vec<String> = Vec::new();
    if "127.0.0.1:8790"
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(60)).is_ok())
        .unwrap_or(false)
    {
        bases.push("http://127.0.0.1:8790".to_string());
    }
    let configured = if cfg.relay_url.trim().is_empty() {
        DEFAULT_RELAY_URL.to_string()
    } else {
        cfg.relay_url.trim().trim_end_matches('/').to_string()
    };
    if !configured.is_empty() && !bases.iter().any(|b| b == &configured) {
        bases.push(configured);
    }

    let http = tls_agent(60);
    for base in bases {
        let url = format!("{}/api/v1/uploads/{}", base, safe_id);
        let Ok(resp) = http.get(&url).call() else { continue };
        if resp.status() != 200 {
            continue;
        }
        let ct = resp.header("Content-Type").unwrap_or("").to_ascii_lowercase();
        if ct.contains("application/json") || ct.contains("text/html") {
            continue;
        }
        let mut fname = format!("{}.bin", safe_id);
        if let Some(cd) = resp.header("Content-Disposition") {
            if let Some(pos) = cd.find("filename*=UTF-8''") {
                let raw_utf8 = cd[pos + 17..].split(';').next().unwrap_or("").trim();
                let decoded = percent_decode_utf8(raw_utf8);
                if !decoded.is_empty() {
                    fname = decoded;
                }
            } else if let Some(pos) = cd.find("filename=\"") {
                let rest = &cd[pos + 10..];
                if let Some(end) = rest.find('"') {
                    let candidate = rest[..end].trim();
                    if !candidate.is_empty() {
                        fname = candidate.to_string();
                    }
                }
            }
        }
        let mut buf = Vec::new();
        if resp.into_reader().take(70 * 1024 * 1024).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            return Some((fname, buf));
        }
    }
    None
}

fn percent_decode_utf8(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find_local_uploaded_file(file_id: &str) -> Option<(String, Vec<u8>)> {
    let safe_id: String = file_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    if safe_id.is_empty() {
        return None;
    }
    for entry in read_local_archive_entries().into_iter().rev() {
        if entry["file_id"].as_str() == Some(safe_id.as_str()) {
            let sp = entry["stored_path"].as_str().unwrap_or("");
            if !sp.is_empty() {
                if let Ok(bytes) = std::fs::read(sp) {
                    let orig = entry["file_name"].as_str().unwrap_or("file.bin").to_string();
                    return Some((orig, bytes));
                }
            }
        }
    }
    let prefix = format!("{}__", safe_id);
    let dirs = [
        uploaded_files_dir(),
        std::path::PathBuf::from(r"C:\ProgramData\IT-ELKHAWGA-Relay\uploads"),
    ];
    for dir in dirs {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                if let Some(orig_name) = name.strip_prefix(&prefix) {
                    if let Ok(bytes) = std::fs::read(ent.path()) {
                        return Some((orig_name.to_string(), bytes));
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn serve_web_asset(path: &str) -> Option<(Vec<u8>, &'static [u8], u16)> {
    match path {
        "/" | "/index.html" => {
            let html = include_str!("../../web/index.html").replace(
                "<script src=\"tauri-shim.js\"></script>",
                "<script>window.__ITK_WEB_ADMIN__=true;</script><script src=\"tauri-shim.js\"></script>",
            );
            Some((html.into_bytes(), b"text/html; charset=utf-8", 200))
        }
        "/theme.js" => Some((include_bytes!("../../web/theme.js").to_vec(), b"application/javascript; charset=utf-8", 200)),
        "/tauri-shim.js" => Some((include_bytes!("../../web/tauri-shim.js").to_vec(), b"application/javascript; charset=utf-8", 200)),
        "/index.inline.js" => Some((include_bytes!("../../web/index.inline.js").to_vec(), b"application/javascript; charset=utf-8", 200)),
        "/styles/theme.css" => Some((include_bytes!("../../web/styles/theme.css").to_vec(), b"text/css; charset=utf-8", 200)),
        "/styles/redesign.css" => Some((include_bytes!("../../web/styles/redesign.css").to_vec(), b"text/css; charset=utf-8", 200)),
        "/styles/dark.css" => Some((include_bytes!("../../web/styles/dark.css").to_vec(), b"text/css; charset=utf-8", 200)),
        "/assets/company-logo-tight.png" => Some((include_bytes!("../../web/assets/company-logo-tight.png").to_vec(), b"image/png", 200)),
        "/assets/company-logo.jpg" => Some((include_bytes!("../../web/assets/company-logo.jpg").to_vec(), b"image/jpeg", 200)),
        "/favicon.ico" => Some((Vec::new(), b"image/x-icon", 204)),
        _ => None,
    }
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
        "ephemeral_browser": false,
    });
    let digest = Sha256::digest(policy.to_string().as_bytes());
    let version: String = digest.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    policy["version"] = json!(version);
    policy
}

fn read_client_installer_bytes() -> Option<Vec<u8>> {
    let name = "IT ELKHAWGA Client_1.0.0_x64-setup.exe";
    let candidates = [
        std::path::PathBuf::from(r"C:\Users\IT APP\Desktop\blockwebsite\final-release").join(name),
        std::path::PathBuf::from(r"C:\Users\IT APP\Desktop\tools").join(name),
        resource_dir().join(name),
        data_dir().join(name),
    ];
    for p in candidates {
        if let Ok(bytes) = std::fs::read(&p) {
            if bytes.len() > 500_000 && bytes.starts_with(b"MZ") {
                return Some(bytes);
            }
        }
    }
    None
}

fn handle_request(mut req: Request, registry: &Arc<Mutex<Registry>>, token: &str, port: u16) {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or(&url).to_string();
    let method = req.method().clone();

    // Health check
    if method == Method::Get && path == "/healthz" {
        let _ = req.respond(json_response(json!({"ok": true, "ts": now()}), 200));
        return;
    }

    // Loopback-only RustDesk launcher so an Admin laptop running IT ELKHAWGA Admin locally
    // can configure peers/<id>.toml (view_only=true/false) and launch rustdesk.exe even when
    // the dashboard is opened in Chrome/Edge against a remote LAN/Relay URL.
    if path == "/api/local/rustdesk-session" {
        let is_loopback = req
            .remote_addr()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        let cors = |resp: Response<std::io::Cursor<Vec<u8>>>| {
            resp.with_header(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap())
                .with_header(Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"POST, OPTIONS"[..]).unwrap())
                .with_header(Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap())
                .with_header(Header::from_bytes(&b"Access-Control-Allow-Private-Network"[..], &b"true"[..]).unwrap())
        };
        if !is_loopback {
            let _ = req.respond(cors(json_response(json!({"success": false, "error": "loopback only"}), 403)));
            return;
        }
        if method == Method::Options {
            let _ = req.respond(cors(json_response(json!({"ok": true}), 200)));
            return;
        }
        if method == Method::Post {
            let mut body = String::new();
            let _ = req.as_reader().take(16_384).read_to_string(&mut body);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));
            let rd_id = parsed["rustdeskId"].as_str().unwrap_or("").to_string();
            let pw = parsed["password"].as_str().map(|s| s.to_string());
            let mode = parsed["mode"].as_str().map(|s| s.to_string());
            let payload = match crate::commands::open_support_session_inner(rd_id, pw, mode) {
                Ok(_) => json!({"success": true}),
                Err(e) => json!({"success": false, "error": e}),
            };
            let _ = req.respond(cors(json_response(payload, 200)));
            return;
        }
    }

    // Serve latest Client NSIS installer so remote devices can self-update silently.
    if method == Method::Get && (path == "/api/client-setup.exe" || path == "/api/v1/client-setup.exe") {
        if let Some(bytes) = read_client_installer_bytes() {
            let _ = req.respond(bytes_response(bytes, b"application/octet-stream", 200));
        } else {
            let _ = req.respond(json_response(json!({"error": "client installer not found on server"}), 404));
        }
        return;
    }

    // Serve archived uploaded DLP files (checks local store, local Relay data dir, then remote Relay).
    if method == Method::Get && (path.starts_with("/api/uploads/") || path.starts_with("/api/v1/uploads/")) {
        let fid = path
            .strip_prefix("/api/v1/uploads/")
            .or_else(|| path.strip_prefix("/api/uploads/"))
            .unwrap_or("");
        if let Some((orig_name, bytes)) = fetch_uploaded_file_bytes(fid) {
            let safe_ascii: String = orig_name
                .chars()
                .map(|c| if c.is_ascii() && c != '"' && c != '\r' && c != '\n' && c != '\\' && c != '/' { c } else { '_' })
                .collect();
            let utf8_enc = encode_rfc5987_component(&orig_name);
            let disp = format!(
                "attachment; filename=\"{}\"; filename*=UTF-8''{}",
                if safe_ascii.is_empty() { "file.bin" } else { &safe_ascii },
                utf8_enc
            );
            let ct = Header::from_bytes(&b"Content-Type"[..], mime_for_filename(&orig_name)).unwrap();
            let cd = Header::from_bytes(&b"Content-Disposition"[..], disp.as_bytes()).unwrap();
            let cors = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
            let _ = req.respond(
                Response::from_data(bytes)
                    .with_status_code(200)
                    .with_header(ct)
                    .with_header(cd)
                    .with_header(cors),
            );
        } else {
            let _ = req.respond(json_response(json!({"error": "uploaded file not found"}), 404));
        }
        return;
    }

    // Web Admin dashboard static assets (gated client-side + server-side via JWT login on /api/rpc)
    if method == Method::Get {
        if let Some((bytes, ct, status)) = serve_web_asset(&path) {
            let _ = req.respond(bytes_response(bytes, ct, status));
            return;
        }
    }

    // Web Admin JSON RPC endpoint (authenticated by admin JWT)
    if method == Method::Post && path == "/api/rpc" {
        let auth_hdr = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str().to_string());
        let mut body = String::new();
        let _ = req.as_reader().take(262_144).read_to_string(&mut body);
        let handle = ServerHandle {
            registry: registry.clone(),
            port,
            token: token.to_string(),
        };
        let (status, payload) = crate::commands::dispatch_web_rpc(&handle, &body, auth_hdr.as_deref());
        let _ = req.respond(json_response(payload, status));
        return;
    }

    let authorized = req
        .headers()
        .iter()
        .any(|h| h.field.equiv("Authorization") && h.value.as_str() == format!("Bearer {}", token));
    if !authorized {
        let _ = req.respond(json_response(json!({"ok": false, "error": "unauthorized"}), 401));
        return;
    }

    // Device poll endpoint
    if method == Method::Post && path == "/api/poll" {
        handle_poll(req, registry);
        return;
    }

    // Device screen upload endpoint (for both LAN and relay clients)
    if method == Method::Post && path == "/api/v1/device/screen" {
        handle_device_screen_upload(req, registry);
        return;
    }

    // Device uploaded file archive endpoint (for LAN clients)
    if method == Method::Post && path == "/api/v1/device/file" {
        handle_device_file_upload(req, registry);
        return;
    }

    // Admin endpoints
    if path.starts_with("/api/admin/") {
        handle_admin(req, registry, &url, &method);
        return;
    }

    let _ = req.respond(json_response(json!({"ok": false, "error": "not found"}), 404));
}

fn handle_poll(mut req: Request, registry: &Arc<Mutex<Registry>>) {
    let ip = req.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let mut body = String::new();
    let _ = req.as_reader().take(25 * 1024 * 1024).read_to_string(&mut body);

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
        if !poll.denied.is_empty() {
            for host in &poll.denied {
                if !host.trim().is_empty() {
                    reg.audit_log.push(AuditEntry {
                        id: rid("denied_"),
                        actor: format!("device:{}", poll.device_id),
                        action: "site_denied".to_string(),
                        target: Some(host.clone()),
                        result: "denied".to_string(),
                        meta: poll.hostname.clone(),
                        created_at: now(),
                    });
                }
            }
        }
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
        let stream_mode = old.as_ref().map(|d| d.stream_mode.clone()).unwrap_or_default();
        let stream_until = old.as_ref().map(|d| d.stream_until).unwrap_or(0);

        // Handle incoming alert from device
        if !poll.alert.is_null() && poll.alert["message"].as_str().map(|s| !s.is_empty()).unwrap_or(false) {
            let dev_name = if !label.trim().is_empty() {
                label.clone()
            } else if !poll.hostname.trim().is_empty() {
                poll.hostname.clone()
            } else {
                poll.device_id.clone()
            };
            let alert = Alert {
                id: rid("alt_"),
                device_id: poll.device_id.clone(),
                device_name: dev_name,
                alert_type: poll.alert["type"].as_str().unwrap_or("tamper").to_string(),
                severity: poll.alert["severity"].as_str().unwrap_or("medium").to_string(),
                message: poll.alert["message"].as_str().unwrap_or("").to_string(),
                meta: poll.alert["meta"].to_string(),
                created_at: now(),
                acked_at: None,
                acked_by: None,
                acked: false,
            };
            mirror_lan_alert_to_relay(&alert);
            reg.alerts.push(alert);
            if reg.alerts.len() > 200 {
                let drop_n = reg.alerts.len() - 200;
                reg.alerts.drain(0..drop_n);
            }
            save_lan_alerts(&reg);
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
                stream_mode: stream_mode.clone(),
                stream_until,
                last_command_id: old.as_ref().map(|d| d.last_command_id.clone()).unwrap_or_default(),
            },
        );
        let should_persist = match (old.as_ref(), reg.devices.get(&poll.device_id)) {
            (None, _) => true,
            (Some(prev), Some(cur)) => {
                prev.hostname != cur.hostname
                    || prev.ip != cur.ip
                    || prev.blocked != cur.blocked
                    || prev.mode != cur.mode
                    || prev.rustdesk_id != cur.rustdesk_id
                    || prev.throttle_kbps != cur.throttle_kbps
                    || prev.sites != cur.sites
                    || prev.denied != cur.denied
                    || prev.group_id != cur.group_id
                    || prev.label != cur.label
                    || cur.last_seen.saturating_sub(prev.last_seen) >= 30_000
            }
            _ => false,
        };
        if should_persist {
            save_lan_devices(&reg);
        }

        // Get pending command
        let command = reg.pending.remove(&poll.device_id);
        let throttle_cmd = reg.pending_throttle.remove(&poll.device_id).map(|kbps| format!("throttle:{}", kbps));

        // Determine policy to send
        let cfg = read_config();
        let full_policy = current_policy_full(&cfg);
        let group_policy = group_id_for_policy.as_str();
        let effective_policy = if !group_policy.is_empty() {
            if let Some(gp) = get_group_policy(&reg, group_policy) {
                let mut p = full_policy.clone();
                p["mode"] = json!(gp.mode);
                p["allowed"] = json!(gp.allowed);
                p["blocked"] = json!(gp.blocked);
                p["ephemeral_browser"] = json!(gp.ephemeral_browser);
                p["group_id"] = json!(group_policy);
                let digest = Sha256::digest(p.to_string().as_bytes());
                let version: String = digest.iter().take(8).map(|b| format!("{:02x}", b)).collect();
                p["version"] = json!(version);
                if poll.policy_version != version { Some(p) } else { None }
            } else {
                let version = full_policy["version"].as_str().unwrap_or("");
                if poll.policy_version != version { Some(full_policy) } else { None }
            }
        } else {
            let version = full_policy["version"].as_str().unwrap_or("");
            if poll.policy_version != version { Some(full_policy) } else { None }
        };

        let active_stream = if stream_until > now_ms() {
            stream_mode
        } else if screen_requested {
            "once".to_string()
        } else {
            String::new()
        };
        (command.or(throttle_cmd), effective_policy, active_stream, rustdesk_password)
    };

    let _ = req.respond(json_response(
        json!({
            "ok": true,
            "command": command,
            "policy": policy,
            "poll_seconds": 3,
            "screen": !screen.is_empty(),
            "stream_mode": screen,
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
    let kind = body_val["kind"].as_str().unwrap_or("screen");
    let err_str = body_val["error"].as_str().unwrap_or("");
    if image.is_empty() && err_str.is_empty() {
        let _ = req.respond(json_response(json!({"ok": false, "error": "missing image"}), 400));
        return;
    }

    let device_id = body_val["device_id"].as_str().unwrap_or("");

    let mut reg = registry.lock().unwrap();
    let now_t = now_ms();
    let target = if !device_id.is_empty() && reg.devices.contains_key(device_id) {
        Some(device_id.to_string())
    } else {
        let mut found = None;
        for (id, d) in reg.devices.iter() {
            if d.screen_requested || d.stream_until > now_t {
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
        entry.kind = kind.to_string();
        entry.error = err_str.to_string();
        if let Some(d) = reg.devices.get_mut(&id) {
            if d.stream_until <= now_t {
                d.screen_requested = false;
            }
        }
    }

    let _ = req.respond(json_response(json!({"ok": true}), 200));
}

fn handle_device_file_upload(mut req: Request, registry: &Arc<Mutex<Registry>>) {
    let auth_header = req.headers().iter().find(|h| h.field.equiv("Authorization"));
    let token = auth_header.map(|h| h.value.as_str()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if token.is_empty() || token != read_config().api_token {
        let _ = req.respond(json_response(json!({"ok": false, "error": "unauthorized"}), 401));
        return;
    }

    let mut body = String::new();
    let _ = req.as_reader().take(95 * 1024 * 1024).read_to_string(&mut body);
    let body_val: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            let _ = req.respond(json_response(json!({"ok": false, "error": "bad request"}), 400));
            return;
        }
    };
    let b64 = body_val["file_base64"].as_str().unwrap_or("");
    let Some(bytes) = base64_decode(b64) else {
        let _ = req.respond(json_response(json!({"ok": false, "error": "invalid base64"}), 400));
        return;
    };
    if bytes.is_empty() || bytes.len() > 66 * 1024 * 1024 {
        let _ = req.respond(json_response(json!({"ok": false, "error": "invalid size"}), 413));
        return;
    }
    let raw_id = body_val["file_id"].as_str().unwrap_or("");
    let safe_id: String = raw_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    let fid = if safe_id.is_empty() { rid("upl_") } else { safe_id };
    let orig_name = body_val["file_name"].as_str().unwrap_or("file.bin").trim();
    let device_id = body_val["device_id"].as_str().unwrap_or("").trim().to_string();
    let hostname_body = body_val["hostname"].as_str().unwrap_or("").trim().to_string();
    let device_name = {
        let reg = registry.lock().unwrap();
        reg.devices
            .get(&device_id)
            .map(|d| {
                if !d.label.trim().is_empty() {
                    d.label.trim().to_string()
                } else if !d.hostname.trim().is_empty() {
                    d.hostname.trim().to_string()
                } else {
                    device_id.clone()
                }
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if !hostname_body.is_empty() {
                    hostname_body
                } else if !device_id.is_empty() {
                    device_id.clone()
                } else {
                    "Unknown-Device".to_string()
                }
            })
    };
    let win_user = body_val["windows_user"].as_str().unwrap_or("").trim().to_string();
    let channel = body_val["channel"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("whatsapp_web")
        .to_string();
    let recip_name = body_val["recipient_name"].as_str().unwrap_or("").trim().to_string();
    let recip_phone = body_val["recipient_phone"].as_str().unwrap_or("").trim().to_string();
    let page_url = body_val["page_url"].as_str().unwrap_or("").trim().to_string();
    let sha256_hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    if let Some((_existing_name, existing_bytes)) = find_local_uploaded_file(&fid) {
        if existing_bytes.len() == bytes.len() {
            let _ = req.respond(json_response(
                json!({"ok": true, "file_id": fid, "size": bytes.len(), "sha256": sha256_hex}),
                200,
            ));
            return;
        }
    }

    let archive_dest = build_archive_file_path(&channel, &device_name, &recip_name, &recip_phone, orig_name);
    let stored_path = match std::fs::write(&archive_dest, &bytes) {
        Ok(_) => archive_dest,
        Err(_) => {
            let safe_name = sanitize_archive_segment(orig_name, "file.bin", 120);
            let fb = uploaded_files_dir().join(format!("{}__{}", fid, safe_name));
            if let Err(e) = std::fs::write(&fb, &bytes) {
                let _ = req.respond(json_response(json!({"ok": false, "error": e.to_string()}), 500));
                return;
            }
            fb
        }
    };
    let stored_str = stored_path.to_string_lossy().to_string();
    let created_ts = now();
    append_local_archive_log(&json!({
        "file_id": fid,
        "device_id": device_id,
        "device_name": device_name,
        "windows_user": win_user,
        "channel": channel,
        "file_name": if orig_name.is_empty() { "file.bin" } else { orig_name },
        "file_size": bytes.len(),
        "sha256": sha256_hex,
        "recipient_name": recip_name,
        "recipient_phone": recip_phone,
        "page_url": page_url,
        "stored_path": stored_str,
        "created_at": created_ts,
    }));
    let _ = req.respond(json_response(
        json!({
            "ok": true,
            "file_id": fid,
            "size": bytes.len(),
            "sha256": sha256_hex,
            "stored_path": stored_str,
        }),
        200,
    ));
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
        let alerts: Vec<_> = reg
            .alerts
            .iter()
            .rev()
            .take(200)
            .map(|a| {
                let mut c = a.clone();
                c.meta = strip_alert_media_str(&c.meta);
                c
            })
            .collect();
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

    // Device command (block/unblock/throttle/power/update)
    if method == &Method::Post && path.starts_with("devices/") && path.ends_with("/command") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/command").unwrap();
        let raw = body_val["command"].as_str().unwrap_or("");
        let command_type = match raw {
            "block" => "block",
            "unblock" => "unblock",
            "restart" => "restart",
            "shutdown" => "shutdown",
            "cancel_power" => "cancel_power",
            "update_client" => "update_client",
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
        let actor = body_val["actor"].as_str().unwrap_or("admin");
        let mut count = 0;
        for id in targets {
            if command_type.starts_with("throttle:") {
                let kbps = command_type.strip_prefix("throttle:").unwrap().parse::<u64>().unwrap_or(0);
                reg.pending_throttle.insert(id.clone(), kbps);
            } else {
                reg.pending.insert(id.clone(), command_type.to_string());
            }
            count += 1;
            record_audit(&mut reg, actor, command_audit_action(command_type), Some(&id), "ok", raw);
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
        save_lan_devices(&reg);
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
            save_lan_devices(&reg);
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
            save_lan_devices(&reg);
            let _ = req.respond(json_response(json!({"ok": true}), 200));
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "no device"}), 404));
        }
        return;
    }

    // Device screen request
    if method == &Method::Post && path.starts_with("devices/") && path.ends_with("/screen/request") {
        let device_id = path.strip_prefix("devices/").unwrap().strip_suffix("/screen/request").unwrap();
        let mode = body_val["mode"].as_str().unwrap_or("once").trim().to_ascii_lowercase();
        let mut reg = registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(device_id) {
            if mode == "stop" {
                d.screen_requested = false;
                d.stream_mode.clear();
                d.stream_until = 0;
            } else if mode == "screen" || mode == "camera" {
                let switched = d.stream_mode != mode;
                d.screen_requested = true;
                d.stream_mode = mode.clone();
                d.stream_until = now_ms() + 12_000;
                if switched {
                    reg.screens.insert(
                        device_id.to_string(),
                        ScreenData { image: String::new(), at: 0, kind: mode, error: String::new() },
                    );
                }
            } else {
                d.screen_requested = true;
                d.stream_mode.clear();
                d.stream_until = 0;
                reg.screens.insert(
                    device_id.to_string(),
                    ScreenData { image: String::new(), at: 0, kind: "screen".into(), error: String::new() },
                );
            }
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
        let lease_on = dev.map(|d| d.stream_until > now_ms()).unwrap_or(false);
        let _ = req.respond(json_response(json!({
            "ok": true,
            "requested": dev.map(|d| d.screen_requested || d.stream_until > now_ms()).unwrap_or(false),
            "stream_mode": if lease_on { dev.map(|d| d.stream_mode.clone()).unwrap_or_default() } else { String::new() },
            "image": screen.image,
            "at": screen.at,
            "kind": if screen.kind.is_empty() { "screen".to_string() } else { screen.kind },
            "error": screen.error,
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
            save_lan_devices(&reg);
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
                    "ephemeral_browser": policy.as_ref().map(|p| p.ephemeral_browser).unwrap_or(false),
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
                ephemeral_browser: body_val["ephemeral_browser"].as_bool().unwrap_or(false),
                updated_at: now(),
            };
            reg.groups.insert(gid.clone(), group);
            reg.group_policies.insert(gid.clone(), policy);
            save_lan_groups(&reg);
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
            if body_val["mode"].is_string()
                || body_val["allowed"].is_array()
                || body_val["blocked"].is_array()
                || body_val["ephemeral_browser"].is_boolean()
            {
                let mut policy = reg.group_policies.get(gid).cloned().unwrap_or(GroupPolicy {
                    version: rid("gv_"),
                    mode: "whitelist".into(),
                    allowed: vec![],
                    blocked: vec![],
                    ephemeral_browser: false,
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
                if let Some(ephem) = body_val["ephemeral_browser"].as_bool() {
                    policy.ephemeral_browser = ephem;
                }
                policy.version = rid("gv_");
                policy.updated_at = now();
                reg.group_policies.insert(gid.to_string(), policy);
            }
            save_lan_groups(&reg);
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
            "update_client" => "update_client",
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
    pub fn send_command(&self, device_id: &str, command: &str, actor: &str, actor_role: &str) -> Result<(), String> {
        let valid = command == "block" || command == "unblock" || command.starts_with("throttle:")
            || command == "restart" || command == "shutdown" || command == "cancel_power"
            || command == "update_client";
        if !valid {
            return Err("أمر غير معروف".into());
        }
        // Power commands are only allowed for a single device, never broadcast to all.
        if device_id == "*" && (command == "restart" || command == "shutdown") {
            return Err("لا يمكن إعادة تشغيل/إيقاف كل الأجهزة مرة واحدة".into());
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
                record_audit(&mut reg, actor, command_audit_action(command), Some(&id), "queued", actor_role);
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
            record_audit(&mut reg, actor, command_audit_action(command), Some(device_id), "queued", actor_role);
        } else {
            return Err("الجهاز غير موجود".into());
        }
        save_lan_devices(&reg);
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
                "ephemeral_browser": policy.as_ref().map(|p| p.ephemeral_browser).unwrap_or(false),
            })
        }).collect()
    }

    pub fn create_group(&self, name: String, mode: String, allowed: Vec<String>, blocked: Vec<String>, ephemeral_browser: bool) -> Result<serde_json::Value, String> {
        let mut reg = self.registry.lock().unwrap();
        let gid = rid("grp_");
        let group = Group { id: gid.clone(), name: name.clone(), created_at: now() };
        let policy = GroupPolicy {
            version: rid("gv_"),
            mode: if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() },
            allowed,
            blocked,
            ephemeral_browser,
            updated_at: now(),
        };
        reg.groups.insert(gid.clone(), group);
        reg.group_policies.insert(gid.clone(), policy.clone());
        save_lan_groups(&reg);
        Ok(json!({
            "id": gid,
            "name": name,
            "created_at": now(),
            "devices": 0,
            "version": policy.version,
            "mode": policy.mode,
            "allowed": policy.allowed,
            "blocked": policy.blocked,
            "ephemeral_browser": policy.ephemeral_browser,
        }))
    }

    pub fn update_group(&self, group_id: String, name: String, mode: String, allowed: Vec<String>, blocked: Vec<String>, ephemeral_browser: bool) -> Result<serde_json::Value, String> {
        let mut reg = self.registry.lock().unwrap();
        let trimmed = name.trim().to_string();
        if let Some(g) = reg.groups.get_mut(&group_id) {
            if !trimmed.is_empty() {
                g.name = trimmed.clone();
            }
        } else {
            reg.groups.insert(
                group_id.clone(),
                Group {
                    id: group_id.clone(),
                    name: trimmed.clone(),
                    created_at: now(),
                },
            );
        }
        let mut policy = reg.group_policies.get(&group_id).cloned().unwrap_or(GroupPolicy {
            version: rid("gv_"),
            mode: "whitelist".into(),
            allowed: vec![],
            blocked: vec![],
            ephemeral_browser: false,
            updated_at: now(),
        });
        policy.mode = if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() };
        policy.allowed = allowed;
        policy.blocked = blocked;
        policy.ephemeral_browser = ephemeral_browser;
        policy.version = rid("gv_");
        policy.updated_at = now();
        reg.group_policies.insert(group_id.clone(), policy.clone());
        save_lan_groups(&reg);
        Ok(json!({
            "id": group_id,
            "name": name,
            "version": policy.version,
            "mode": policy.mode,
            "allowed": policy.allowed,
            "blocked": policy.blocked,
            "ephemeral_browser": policy.ephemeral_browser,
        }))
    }

    pub fn delete_group(&self, group_id: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        reg.groups.remove(&group_id);
        reg.group_policies.remove(&group_id);
        for d in reg.devices.values_mut() {
            if d.group_id == group_id { d.group_id.clear(); }
        }
        save_lan_groups(&reg);
        save_lan_devices(&reg);
        Ok(())
    }

    pub fn sync_groups(&self, groups: &[serde_json::Value]) {
        let mut reg = self.registry.lock().unwrap();
        apply_groups_slice(&mut reg, groups);
        save_lan_groups(&reg);
    }

    pub fn has_group(&self, group_id: &str) -> bool {
        let reg = self.registry.lock().unwrap();
        reg.groups.contains_key(group_id)
    }

    pub fn group_device_counts(&self) -> HashMap<String, usize> {
        let reg = self.registry.lock().unwrap();
        let mut counts = HashMap::new();
        for d in reg.devices.values() {
            if !d.group_id.is_empty() {
                *counts.entry(d.group_id.clone()).or_insert(0) += 1;
            }
        }
        counts
    }

    pub fn assign_device_group(&self, device_id: String, group_id: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            d.group_id = group_id;
            save_lan_devices(&reg);
            Ok(())
        } else {
            Err("no device".into())
        }
    }

    pub fn get_alerts(&self, alert_type: Option<String>, acked: Option<String>) -> serde_json::Value {
        let reg = self.registry.lock().unwrap();
        let mut alerts: Vec<_> = reg.alerts.iter().cloned().collect();
        if let Some(t) = alert_type.filter(|s| !s.is_empty()) {
            alerts.retain(|a| a.alert_type == t);
        }
        if let Some(a) = acked.filter(|s| !s.is_empty()) {
            if a == "0" { alerts.retain(|a| a.acked_at.is_none()); }
            else if a == "1" { alerts.retain(|a| a.acked_at.is_some()); }
        }
        alerts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let unacked = reg.alerts.iter().filter(|a| a.acked_at.is_none()).count();
        let light: Vec<_> = alerts
            .into_iter()
            .take(200)
            .map(|mut a| {
                a.meta = strip_alert_media_str(&a.meta);
                a
            })
            .collect();
        json!({"ok": true, "alerts": light, "unacked": unacked})
    }

    pub fn get_alert_media(&self, alert_id: &str) -> Option<serde_json::Value> {
        let reg = self.registry.lock().unwrap();
        let found = reg.alerts.iter().find(|a| a.id == alert_id)?;
        let parsed: serde_json::Value = serde_json::from_str(found.meta.trim()).unwrap_or_else(|_| json!({}));
        let sc = parsed["screenshot"].as_str().unwrap_or("");
        let cam = parsed["camera_photo"].as_str().unwrap_or("");
        if sc.is_empty() && cam.is_empty() {
            return None;
        }
        Some(json!({
            "ok": true,
            "id": found.id,
            "screenshot": sc,
            "camera_photo": cam,
        }))
    }

    pub fn ack_alert(&self, alert_id: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(a) = reg.alerts.iter_mut().find(|a| a.id == alert_id) {
            if a.acked_at.is_none() {
                a.acked_at = Some(now());
                a.acked_by = Some("admin".into());
                a.acked = true;
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

    pub fn request_screenshot(&self, device_id: String, mode: Option<String>) -> Result<(), String> {
        let m = mode.unwrap_or_else(|| "once".to_string()).trim().to_ascii_lowercase();
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            if m == "stop" {
                d.screen_requested = false;
                d.stream_mode.clear();
                d.stream_until = 0;
            } else if m == "screen" || m == "camera" {
                let switched = d.stream_mode != m;
                d.screen_requested = true;
                d.stream_mode = m.clone();
                d.stream_until = now_ms() + 12_000;
                if switched {
                    reg.screens.insert(
                        device_id,
                        ScreenData { image: String::new(), at: 0, kind: m, error: String::new() },
                    );
                }
            } else {
                d.screen_requested = true;
                d.stream_mode.clear();
                d.stream_until = 0;
                reg.screens.insert(
                    device_id,
                    ScreenData { image: String::new(), at: 0, kind: "screen".into(), error: String::new() },
                );
            }
            Ok(())
        } else {
            Err("no device".into())
        }
    }

    pub fn get_screenshot(&self, device_id: String) -> serde_json::Value {
        let reg = self.registry.lock().unwrap();
        let screen = reg.screens.get(&device_id).cloned().unwrap_or_default();
        let dev = reg.devices.get(&device_id);
        let lease_on = dev.map(|d| d.stream_until > now_ms()).unwrap_or(false);
        json!({
            "ok": true,
            "requested": dev.map(|d| d.screen_requested || d.stream_until > now_ms()).unwrap_or(false),
            "stream_mode": if lease_on { dev.map(|d| d.stream_mode.clone()).unwrap_or_default() } else { String::new() },
            "image": screen.image,
            "at": screen.at,
            "kind": if screen.kind.is_empty() { "screen".to_string() } else { screen.kind },
            "error": screen.error,
        })
    }

    pub fn set_rustdesk_password(&self, device_id: String, password: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            d.rustdesk_password = password;
            save_lan_devices(&reg);
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
        if existed {
            save_lan_devices(&reg);
        }
        Ok(existed)
    }

    pub fn rename_device(&self, device_id: String, label: String) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if let Some(d) = reg.devices.get_mut(&device_id) {
            d.label = label;
            save_lan_devices(&reg);
            Ok(())
        } else {
            Err("no device".into())
        }
    }

    pub fn send_group_command(&self, group_id: String, command: String, actor: &str, actor_role: &str) -> Result<u64, String> {
        let mut reg = self.registry.lock().unwrap();
        if !reg.groups.contains_key(&group_id) {
            return Err("no group".into());
        }
        let cmd_type = match command.as_str() {
            "block" => "block",
            "unblock" => "unblock",
            "update_client" => "update_client",
            _ => return Err("invalid command".into()),
        };
        let audit_act = match cmd_type {
            "block" => "group_block",
            "unblock" => "group_unblock",
            "update_client" => "group_update_client",
            _ => "group_command",
        };
        let targets: Vec<_> = reg.devices.values().filter(|d| d.group_id == group_id).map(|d| d.device_id.clone()).collect();
        let mut count = 0;
        for id in targets {
            reg.pending.insert(id.clone(), cmd_type.to_string());
            count += 1;
            record_audit(&mut reg, actor, audit_act, Some(&id), "queued", actor_role);
        }
        Ok(count)
    }
}

/// Audit-log action name for a device command.
fn command_audit_action(command: &str) -> &'static str {
    match command {
        "block" => "device_block",
        "unblock" => "device_unblock",
        "restart" => "device_restart",
        "shutdown" => "device_shutdown",
        "cancel_power" => "device_cancel_power",
        "update_client" => "device_update_client",
        _ => "device_throttle",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_assets_inject_flag_and_serve_known_paths() {
        let (bytes, ct, status) = serve_web_asset("/index.html").expect("index.html");
        assert_eq!(status, 200);
        assert_eq!(ct, b"text/html; charset=utf-8");
        let html = String::from_utf8(bytes).expect("utf8");
        assert!(html.contains("window.__ITK_WEB_ADMIN__=true"));
        assert!(serve_web_asset("/tauri-shim.js").is_some());
        assert_eq!(serve_web_asset("/favicon.ico").map(|x| x.2), Some(204));
        assert!(serve_web_asset("/does-not-exist").is_none());
    }

    #[test]
    fn web_rpc_enforces_jwt_and_hides_token_before_login() {
        let handle = ServerHandle {
            registry: Arc::new(Mutex::new(Registry::default())),
            port: 8787,
            token: "secret-lan-token".into(),
        };

        let (st, info) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_server_info","args":{}}"#,
            None,
        );
        assert_eq!(st, 200);
        assert_eq!(info["result"]["port"], 8787);
        assert_eq!(info["result"]["token"], "");

        let (st_unauth, _) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_devices","args":{}}"#,
            None,
        );
        assert_eq!(st_unauth, 401);

        let jwt = crate::auth::make_jwt("tester", "viewer").expect("jwt");
        let hdr = format!("Bearer {}", jwt);

        let (st_auth, info_auth) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_server_info","args":{}}"#,
            Some(&hdr),
        );
        assert_eq!(st_auth, 200);
        assert_eq!(info_auth["result"]["token"], "secret-lan-token");

        let (st_dev, _) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_devices","args":{}}"#,
            Some(&hdr),
        );
        assert_eq!(st_dev, 200);

        let (st_viewer_mut, viewer_res) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"add_site","args":{"site":"example.com"}}"#,
            Some(&hdr),
        );
        assert_eq!(st_viewer_mut, 200);
        assert_eq!(viewer_res["result"]["success"], false);
    }

    #[test]
    fn base64_decode_roundtrip_and_dlp_classification() {
        let sample = b"IT ELKHAWGA Confidential PDF-1.7 \x00\xff bytes";
        let enc = crate::common::base64_encode(sample);
        assert_eq!(crate::common::base64_decode(&enc).as_deref(), Some(&sample[..]));
        let with_prefix = format!("data:application/pdf;base64,{}", enc);
        assert_eq!(crate::common::base64_decode(&with_prefix).as_deref(), Some(&sample[..]));
        assert_eq!(crate::common::classify_dlp_file("salaries.xlsx", 4096).1, "critical");
        assert_eq!(crate::common::classify_dlp_file("photo.png", 1024).1, "medium");
    }

    #[test]
    fn exact_copy_archive_paths_preserve_extension_and_utf8_disposition() {
        let p = build_archive_file_path(
            "whatsapp_web",
            "Sales:PC/01",
            "أحمد المبيعات",
            "+201001234567",
            "كشف_العملاء_CON?.xlsx",
        );
        let p_str = p.to_string_lossy();
        assert!(p_str.contains("WhatsApp"), "expected WhatsApp folder: {}", p_str);
        assert!(p_str.ends_with(".xlsx"), "extension lost: {}", p_str);
        assert!(!p_str.contains('?'), "unsafe char remained: {}", p_str);

        let sample = b"PK\x03\x04exact-binary-payload-\x00\xff";
        let digest1: String = Sha256::digest(sample).iter().map(|b| format!("{:02x}", b)).collect();
        let digest2: String = Sha256::digest(crate::common::base64_decode(&crate::common::base64_encode(sample)).unwrap())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(digest1, digest2);

        let disp = encode_rfc5987_component("تقرير المبيعات.xlsx");
        assert!(disp.ends_with(".xlsx"));
        assert!(disp.contains("%D8%"));
    }
}
