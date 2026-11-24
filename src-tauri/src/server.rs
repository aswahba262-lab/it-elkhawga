use crate::common::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

const ONLINE_WINDOW_MS: u64 = 45_000;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Device {
    pub device_id: String,
    pub hostname: String,
    pub ip: String,
    pub blocked: bool,
    #[serde(default)]
    pub usb_blocked: bool,
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
    #[serde(default)]
    pub usb_block: bool,
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
    usb_blocked: bool,
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

fn lan_alert_media_dir() -> std::path::PathBuf {
    data_dir().join("alert-media")
}

fn lan_alert_media_file(alert_id: &str) -> Option<std::path::PathBuf> {
    let safe: String = alert_id
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if safe.is_empty() {
        return None;
    }
    Some(lan_alert_media_dir().join(format!("{}.json", safe)))
}

fn extract_and_save_lan_alert_media(alert_id: &str, raw_meta: &str) -> String {
    let trimmed = raw_meta.trim();
    if !trimmed.starts_with('{') {
        return raw_meta.to_string();
    }
    let Ok(mut val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return raw_meta.to_string();
    };
    if let Some(obj) = val.as_object_mut() {
        let sc = obj
            .get("screenshot")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let cam = obj
            .get("camera_photo")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !sc.is_empty() || !cam.is_empty() {
            if let Some(media_path) = lan_alert_media_file(alert_id) {
                let _ = std::fs::create_dir_all(lan_alert_media_dir());
                let media_json = json!({
                    "screenshot": sc,
                    "camera_photo": cam,
                });
                let _ = std::fs::write(&media_path, media_json.to_string());
            }
            if !sc.is_empty() {
                obj.insert("has_screenshot".to_string(), json!(true));
                obj.remove("screenshot");
            }
            if !cam.is_empty() {
                obj.insert("has_camera_photo".to_string(), json!(true));
                obj.remove("camera_photo");
            }
        }
    }
    val.to_string()
}

fn read_lan_alert_media(alert_id: &str, fallback_meta: Option<&str>) -> Option<(String, String)> {
    if let Some(media_path) = lan_alert_media_file(alert_id) {
        if let Ok(raw) = std::fs::read_to_string(&media_path) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw.trim()) {
                let sc = parsed["screenshot"].as_str().unwrap_or("").to_string();
                let cam = parsed["camera_photo"].as_str().unwrap_or("").to_string();
                if !sc.is_empty() || !cam.is_empty() {
                    return Some((sc, cam));
                }
            }
        }
    }
    if let Some(meta) = fallback_meta {
        let trimmed = meta.trim();
        if trimmed.starts_with('{') {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let sc = parsed["screenshot"].as_str().unwrap_or("").to_string();
                let cam = parsed["camera_photo"].as_str().unwrap_or("").to_string();
                if !sc.is_empty() || !cam.is_empty() {
                    return Some((sc, cam));
                }
            }
        }
    }
    None
}

fn prune_lan_alert_media_files(max_keep: usize) {
    let dir = lan_alert_media_dir();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                return None;
            }
            let mtime = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            Some((mtime, p))
        })
        .collect();
    if entries.len() <= max_keep {
        return;
    }
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, old_path) in entries.into_iter().skip(max_keep) {
        let _ = std::fs::remove_file(old_path);
    }
}

fn save_lan_alerts(reg: &Registry) {
    let start = reg.alerts.len().saturating_sub(200);
    let slim: Vec<Alert> = reg.alerts[start..]
        .iter()
        .map(|a| {
            let mut c = a.clone();
            if c.meta.len() > 1024 {
                c.meta = extract_and_save_lan_alert_media(&c.id, &c.meta);
            }
            c
        })
        .collect();
    if let Ok(s) = serde_json::to_string(&slim) {
        let target = lan_alerts_path();
        let tmp = data_dir().join(format!("lan-alerts.tmp.{}.json", std::process::id()));
        if std::fs::write(&tmp, &s).is_ok() {
            if std::fs::rename(&tmp, &target).is_err() {
                let _ = std::fs::write(&target, &s);
                let _ = std::fs::remove_file(&tmp);
            }
        } else {
            let _ = std::fs::write(&target, &s);
        }
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

fn notify_wa_bot_erp_event(
    ok: bool,
    file_name: String,
    size_bytes: u64,
    format_label: String,
    error: String,
    reason: String,
) {
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
            "kind": "erp_backup",
            "ok": ok,
            "file_name": file_name,
            "size_bytes": size_bytes,
            "format_label": format_label,
            "error": error,
            "reason": reason,
        });
        let http = tls_agent(10);
        for base in bases {
            let url = format!("{}/api/v1/admin/wa-bot/event", base);
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
            "usb_block": pol.map(|p| p.usb_block).unwrap_or(false),
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
        let usb_block = item["usb_block"].as_bool().unwrap_or(false);
        let version = item["version"].as_str().filter(|s| !s.is_empty()).map(String::from).unwrap_or_else(|| rid("gv_"));
        reg.groups.insert(id.clone(), Group { id: id.clone(), name, created_at });
        reg.group_policies.insert(id, GroupPolicy {
            version,
            mode,
            allowed,
            blocked,
            ephemeral_browser,
            usb_block,
            updated_at: now(),
        });
    }
}

pub fn normalize_custom_storage_dir(raw: &str, default_subfolder: &str) -> Result<std::path::PathBuf, String> {
    let mut cleaned = raw.trim().trim_matches('"').replace('/', "\\");
    while cleaned.len() > 3 && cleaned.ends_with('\\') {
        cleaned.pop();
    }
    if cleaned.is_empty() {
        return Err("المسار فارغ".into());
    }
    if cleaned.len() == 2 && cleaned.as_bytes()[1] == b':' && cleaned.as_bytes()[0].is_ascii_alphabetic() {
        cleaned.push('\\');
        cleaned.push_str(default_subfolder);
    } else if cleaned.len() == 3
        && cleaned.as_bytes()[1] == b':'
        && cleaned.as_bytes()[2] == b'\\'
        && cleaned.as_bytes()[0].is_ascii_alphabetic()
    {
        cleaned.push_str(default_subfolder);
    }
    let p = std::path::PathBuf::from(&cleaned);
    if !p.is_absolute() {
        return Err(format!("يرجى إدخال مسار كامل يبدأ بحرف القرص مثل D:\\{}", default_subfolder));
    }
    let lower = cleaned.to_ascii_lowercase();
    for forbidden in [
        r"c:\windows",
        r"c:\program files",
        r"c:\program files (x86)",
        r"c:\programdata\internetblocker",
        r"c:\users",
    ] {
        if lower == forbidden {
            return Err("لا يمكن استخدام مجلد النظام مباشرة؛ اختر مجلداً فرعياً مخصصاً على القرص".into());
        }
    }
    let has_normal_leaf = p
        .components()
        .any(|c| matches!(c, std::path::Component::Normal(_)));
    if !has_normal_leaf {
        return Ok(p.join(default_subfolder));
    }
    Ok(p)
}

pub fn normalize_archive_dir_path(raw: &str) -> Result<std::path::PathBuf, String> {
    if raw.trim().is_empty() {
        return Ok(std::path::PathBuf::from(r"C:\IT-ELKHAWGA-Archive"));
    }
    normalize_custom_storage_dir(raw, "IT-ELKHAWGA-Archive")
}

pub fn normalize_backup_dir_path(raw: &str) -> Result<std::path::PathBuf, String> {
    if raw.trim().is_empty() {
        return Ok(server_archive_root().join("Backups"));
    }
    normalize_custom_storage_dir(raw, "IT-ELKHAWGA-Backups")
}

pub fn list_server_drives() -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        for letter in b'C'..=b'Z' {
            let root_str = format!("{}:\\", letter as char);
            let p = std::path::Path::new(&root_str);
            if p.exists() {
                let (free_b, total_b) = disk_space_for_path(p);
                if total_b > 0 {
                    out.push(json!({
                        "letter": format!("{}:", letter as char),
                        "root": root_str,
                        "free_bytes": free_b,
                        "total_bytes": total_b,
                    }));
                }
            }
        }
    }
    out
}

pub fn server_archive_root() -> std::path::PathBuf {
    let cfg_dir = read_config().archive_dir;
    if !cfg_dir.trim().is_empty() {
        if let Ok(custom) = normalize_archive_dir_path(&cfg_dir) {
            if std::fs::create_dir_all(&custom).is_ok() {
                return custom;
            }
        }
    }
    let preferred = std::path::PathBuf::from(r"C:\IT-ELKHAWGA-Archive");
    if std::fs::create_dir_all(&preferred).is_ok() {
        return preferred;
    }
    let fallback = std::path::PathBuf::from(r"C:\Users\Public\IT-ELKHAWGA-Archive");
    let _ = std::fs::create_dir_all(&fallback);
    fallback
}

pub fn harden_archive_acl(root: &std::path::Path) {
    #[cfg(windows)]
    {
        let has_leaf = root
            .components()
            .any(|c| matches!(c, std::path::Component::Normal(_)));
        if !has_leaf {
            return;
        }
        let mut cmd = std::process::Command::new("icacls");
        cmd.arg(root)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg("*S-1-5-18:(OI)(CI)F")
            .arg("*S-1-5-32-544:(OI)(CI)F");
        if let Ok(user) = std::env::var("USERNAME") {
            let u = user.trim();
            if !u.is_empty() && !u.ends_with('$') && !u.eq_ignore_ascii_case("SYSTEM") {
                let dom = std::env::var("USERDOMAIN").unwrap_or_default();
                let acct = if dom.trim().is_empty() {
                    format!("{}:(OI)(CI)F", u)
                } else {
                    format!("{}\\{}:(OI)(CI)F", dom.trim(), u)
                };
                cmd.arg(acct);
            }
        }
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let _ = hidden(&mut cmd).status();
    }
}

pub fn ensure_server_archive_dirs() {
    let root = server_archive_root();
    let _ = std::fs::create_dir_all(root.join("WhatsApp"));
    let _ = std::fs::create_dir_all(root.join("Web-Uploads"));
    harden_archive_acl(&root);
}

pub fn disk_space_for_path(path: &std::path::Path) -> (u64, u64) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetDiskFreeSpaceExW(
                lpDirectoryName: *const u16,
                lpFreeBytesAvailableToCaller: *mut u64,
                lpTotalNumberOfBytes: *mut u64,
                lpTotalNumberOfFreeBytes: *mut u64,
            ) -> i32;
        }
        let target = if path.exists() {
            path.to_path_buf()
        } else {
            path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| std::path::PathBuf::from(r"C:\"))
        };
        let wide: Vec<u16> = target.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut free_avail = 0u64;
        let mut total = 0u64;
        let mut total_free = 0u64;
        let ok = unsafe {
            GetDiskFreeSpaceExW(wide.as_ptr(), &mut free_avail, &mut total, &mut total_free)
        };
        if ok != 0 {
            return (free_avail, total);
        }
    }
    (0, 0)
}

fn copy_and_move_dir_recursive(
    src: &std::path::Path,
    dst: &std::path::Path,
    moved_files: &mut usize,
    moved_bytes: &mut u64,
) -> Result<(), String> {
    if !src.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    let rd = std::fs::read_dir(src).map_err(|e| e.to_string())?;
    for ent in rd.flatten() {
        let p = ent.path();
        let name = ent.file_name();
        if name.to_string_lossy().eq_ignore_ascii_case("archive-log.jsonl") {
            continue;
        }
        let target = dst.join(&name);
        if p.is_dir() {
            copy_and_move_dir_recursive(&p, &target, moved_files, moved_bytes)?;
            let _ = std::fs::remove_dir(&p);
        } else if p.is_file() {
            let src_len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            std::fs::copy(&p, &target).map_err(|e| format!("فشل نقل {}: {}", p.display(), e))?;
            let dst_len = std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
            if dst_len == src_len {
                let _ = std::fs::remove_file(&p);
                *moved_files += 1;
                *moved_bytes += dst_len;
            }
        }
    }
    Ok(())
}

pub fn migrate_archive_directory(
    old_root: &std::path::Path,
    new_root: &std::path::Path,
) -> Result<(usize, u64), String> {
    let old_clean = old_root.to_string_lossy().trim_end_matches('\\').to_string();
    let new_clean = new_root.to_string_lossy().trim_end_matches('\\').to_string();
    if old_clean.eq_ignore_ascii_case(&new_clean) {
        return Ok((0, 0));
    }
    std::fs::create_dir_all(new_root.join("WhatsApp")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(new_root.join("Web-Uploads")).map_err(|e| e.to_string())?;
    harden_archive_acl(new_root);

    let mut moved_files = 0usize;
    let mut moved_bytes = 0u64;
    if old_root.is_dir() {
        copy_and_move_dir_recursive(old_root, new_root, &mut moved_files, &mut moved_bytes)?;
    }

    // Merge and rewrite archive-log.jsonl with updated stored_path prefixes
    let old_log = old_root.join("archive-log.jsonl");
    let new_log = new_root.join("archive-log.jsonl");
    let mut by_id: Vec<serde_json::Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for log_p in [&new_log, &old_log] {
        if let Ok(raw) = std::fs::read_to_string(log_p) {
            for line in raw.lines() {
                let t = line.trim();
                if t.is_empty() {
                    continue;
                }
                if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(t) {
                    let fid = v["file_id"].as_str().unwrap_or("").to_string();
                    let sp = v["stored_path"].as_str().unwrap_or("").replace('/', "\\");
                    if sp.len() > old_clean.len()
                        && sp.get(..old_clean.len()).map_or(false, |p| p.eq_ignore_ascii_case(&old_clean))
                    {
                        let updated = format!("{}{}", new_clean, sp.get(old_clean.len()..).unwrap_or(""));
                        if std::path::Path::new(&updated).is_file() {
                            v["stored_path"] = json!(updated);
                        }
                    }
                    if fid.is_empty() || seen.insert(fid) {
                        by_id.push(v);
                    }
                }
            }
        }
    }
    if !by_id.is_empty() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::File::create(&new_log) {
            for item in &by_id {
                let _ = writeln!(f, "{}", item);
            }
        }
        if new_log.is_file() && old_log.is_file() {
            let _ = std::fs::remove_file(&old_log);
        }
    }
    Ok((moved_files, moved_bytes))
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
    let mut seen = std::collections::HashSet::new();
    let primary = archive_log_path();
    let legacy = std::path::PathBuf::from(r"C:\IT-ELKHAWGA-Archive\archive-log.jsonl");
    let mut paths = vec![primary.clone()];
    if !primary.to_string_lossy().eq_ignore_ascii_case(&legacy.to_string_lossy()) {
        paths.push(legacy);
    }
    for p in paths {
        let Ok(raw) = std::fs::read_to_string(&p) else { continue };
        for line in raw.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
                let fid = v["file_id"].as_str().unwrap_or("").to_string();
                if fid.is_empty() || seen.insert(fid) {
                    out.push(v);
                }
            }
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

pub fn backups_root_dir() -> std::path::PathBuf {
    let cfg_bk = read_config().backup_dir;
    if !cfg_bk.trim().is_empty() {
        if let Ok(custom) = normalize_backup_dir_path(&cfg_bk) {
            if std::fs::create_dir_all(&custom).is_ok() {
                return custom;
            }
        }
    }
    let dir = server_archive_root().join("Backups");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn change_server_archive_dir(new_path: &str, move_existing: bool) -> Result<serde_json::Value, String> {
    let old_root = server_archive_root();
    let target_root = if new_path.trim().is_empty() {
        std::path::PathBuf::from(r"C:\IT-ELKHAWGA-Archive")
    } else {
        normalize_archive_dir_path(new_path)?
    };

    std::fs::create_dir_all(&target_root)
        .map_err(|e| format!("تعذر إنشاء أو الوصول للمجلد المحدد ({}): {}", target_root.display(), e))?;
    let probe = target_root.join(format!(".itk_write_test_{}", random_hex(3)));
    std::fs::write(&probe, b"ok")
        .map_err(|e| format!("لا توجد صلاحية كتابة في هذا المجلد ({}): {}", target_root.display(), e))?;
    let _ = std::fs::remove_file(&probe);

    let mut moved_files = 0usize;
    let mut moved_bytes = 0u64;
    if move_existing {
        let (nf, nb) = migrate_archive_directory(&old_root, &target_root)
            .map_err(|e| format!("حدث خطأ أثناء نقل الملفات الحالية: {}", e))?;
        moved_files = nf;
        moved_bytes = nb;
    }

    let mut cfg = read_config();
    let default_str = r"C:\IT-ELKHAWGA-Archive";
    cfg.archive_dir = if target_root.to_string_lossy().eq_ignore_ascii_case(default_str) {
        String::new()
    } else {
        target_root.to_string_lossy().to_string()
    };
    write_config(&cfg)?;
    ensure_server_archive_dirs();

    let (free_b, total_b) = disk_space_for_path(&target_root);
    Ok(json!({
        "ok": true,
        "success": true,
        "old_root": old_root.to_string_lossy().to_string(),
        "archive_root": target_root.to_string_lossy().to_string(),
        "moved_files": moved_files,
        "moved_bytes": moved_bytes,
        "disk_free_bytes": free_b,
        "disk_total_bytes": total_b,
    }))
}

pub fn change_server_backup_dir(new_path: &str, move_existing: bool) -> Result<serde_json::Value, String> {
    let old_root = backups_root_dir();
    let target_root = if new_path.trim().is_empty() {
        server_archive_root().join("Backups")
    } else {
        normalize_backup_dir_path(new_path)?
    };

    std::fs::create_dir_all(&target_root)
        .map_err(|e| format!("تعذر إنشاء أو الوصول لمجلد الباكاب ({}): {}", target_root.display(), e))?;
    let probe = target_root.join(format!(".itk_bk_test_{}", random_hex(3)));
    std::fs::write(&probe, b"ok")
        .map_err(|e| format!("لا توجد صلاحية كتابة في مجلد الباكاب ({}): {}", target_root.display(), e))?;
    let _ = std::fs::remove_file(&probe);
    harden_archive_acl(&target_root);

    let mut moved_files = 0usize;
    let mut moved_bytes = 0u64;
    if move_existing
        && !old_root
            .to_string_lossy()
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(target_root.to_string_lossy().trim_end_matches('\\'))
        && old_root.is_dir()
    {
        if let Ok(rd) = std::fs::read_dir(&old_root) {
            for ent in rd.flatten() {
                let p = ent.path();
                let fname = ent.file_name();
                if p.is_dir() && fname.to_string_lossy().starts_with("Backup_") {
                    copy_and_move_dir_recursive(&p, &target_root.join(&fname), &mut moved_files, &mut moved_bytes)?;
                    let _ = std::fs::remove_dir_all(&p);
                }
            }
        }
    }

    let mut cfg = read_config();
    cfg.backup_dir = if new_path.trim().is_empty() {
        String::new()
    } else {
        target_root.to_string_lossy().to_string()
    };
    write_config(&cfg)?;

    let (free_b, total_b) = disk_space_for_path(&target_root);
    Ok(json!({
        "ok": true,
        "success": true,
        "backups_dir": target_root.to_string_lossy().to_string(),
        "moved_files": moved_files,
        "moved_bytes": moved_bytes,
        "disk_free_bytes": free_b,
        "disk_total_bytes": total_b,
    }))
}

pub fn create_server_backup(reason: &str) -> Result<serde_json::Value, String> {
    let root = backups_root_dir();
    harden_archive_acl(&root);
    let stamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let mut folder_id = format!("Backup_{}", stamp);
    if root.join(&folder_id).exists() {
        folder_id = format!("Backup_{}_{}", stamp, random_hex(2));
    }
    let snap_dir = root.join(&folder_id);
    std::fs::create_dir_all(&snap_dir).map_err(|e| format!("تعذر إنشاء مجلد النسخة الاحتياطية: {}", e))?;

    let ddir = data_dir();
    let relay_dir = std::path::PathBuf::from(r"C:\ProgramData\IT-ELKHAWGA-Relay");
    let candidates: Vec<(&str, std::path::PathBuf)> = vec![
        ("config.json", ddir.join("config.json")),
        ("allowed-sites.txt", ddir.join("allowed-sites.txt")),
        ("blocked-sites.txt", ddir.join("blocked-sites.txt")),
        ("lan-devices.json", ddir.join("lan-devices.json")),
        ("lan-groups.json", ddir.join("lan-groups.json")),
        ("lan-alerts.json", ddir.join("lan-alerts.json")),
        ("relay.db", relay_dir.join("relay.db")),
        ("relay.db-wal", relay_dir.join("relay.db-wal")),
        ("archive-log.jsonl", archive_log_path()),
    ];

    let mut copied_files = 0usize;
    let mut total_bytes = 0u64;
    let mut checksums = serde_json::Map::new();

    for (dest_name, src_path) in candidates {
        if src_path.is_file() {
            if let Ok(bytes) = std::fs::read(&src_path) {
                let dst = snap_dir.join(dest_name);
                if std::fs::write(&dst, &bytes).is_ok() {
                    let sha: String = Sha256::digest(&bytes).iter().map(|b| format!("{:02x}", b)).collect();
                    checksums.insert(dest_name.to_string(), json!(sha));
                    copied_files += 1;
                    total_bytes += bytes.len() as u64;
                }
            }
        }
    }

    let created_ms = now_ms();
    let manifest = json!({
        "id": folder_id,
        "created_at": created_ms,
        "reason": reason,
        "files_count": copied_files,
        "total_bytes": total_bytes,
        "version": APP_VERSION,
        "checksums": checksums,
    });
    let _ = std::fs::write(
        snap_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    );

    prune_old_backups(&root, 14);

    Ok(json!({
        "ok": true,
        "success": true,
        "id": folder_id,
        "created_at": created_ms,
        "reason": reason,
        "files_count": copied_files,
        "total_bytes": total_bytes,
        "path": snap_dir.to_string_lossy().to_string(),
    }))
}

fn prune_old_backups(root: &std::path::Path, keep_max: usize) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    let mut dirs: Vec<(u64, std::path::PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if !p.is_dir() {
                return None;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with("Backup_") {
                return None;
            }
            let mtime = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            Some((mtime, p))
        })
        .collect();
    dirs.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, old_dir) in dirs.into_iter().skip(keep_max) {
        let _ = std::fs::remove_dir_all(old_dir);
    }
}

pub fn list_server_backups() -> serde_json::Value {
    let root = backups_root_dir();
    let mut items: Vec<serde_json::Value> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&root) {
        for ent in rd.flatten() {
            let p = ent.path();
            if !p.is_dir() {
                continue;
            }
            let folder_name = ent.file_name().to_string_lossy().to_string();
            if !folder_name.starts_with("Backup_") {
                continue;
            }
            let manifest_path = p.join("manifest.json");
            if let Ok(raw) = std::fs::read_to_string(&manifest_path) {
                if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&raw) {
                    v["path"] = json!(p.to_string_lossy().to_string());
                    items.push(v);
                    continue;
                }
            }
            let mtime = ent
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            items.push(json!({
                "id": folder_name,
                "created_at": mtime,
                "reason": "manual",
                "files_count": 0,
                "total_bytes": 0,
                "path": p.to_string_lossy().to_string(),
            }));
        }
    }
    items.sort_by(|a, b| b["created_at"].as_u64().unwrap_or(0).cmp(&a["created_at"].as_u64().unwrap_or(0)));
    items.truncate(30);
    let (free_b, total_b) = disk_space_for_path(&root);
    json!({
        "ok": true,
        "backups_dir": root.to_string_lossy().to_string(),
        "disk_free_bytes": free_b,
        "disk_total_bytes": total_b,
        "drives": list_server_drives(),
        "backups": items,
    })
}

pub fn restore_server_backup(
    backup_id: &str,
    registry: Option<&Arc<Mutex<Registry>>>,
) -> Result<serde_json::Value, String> {
    let safe_id: String = backup_id
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if safe_id.is_empty() || !safe_id.starts_with("Backup_") {
        return Err("معرّف النسخة الاحتياطية غير صالح".into());
    }
    let snap_dir = backups_root_dir().join(&safe_id);
    if !snap_dir.is_dir() {
        return Err("لم يتم العثور على مجلد النسخة الاحتياطية المحددة".into());
    }

    // Take a safety snapshot before restoring
    let _ = create_server_backup("pre_restore");

    let ddir = data_dir();
    let _ = std::fs::create_dir_all(&ddir);
    let mut restored_files = 0usize;
    for fname in [
        "config.json",
        "allowed-sites.txt",
        "blocked-sites.txt",
        "lan-devices.json",
        "lan-groups.json",
        "lan-alerts.json",
    ] {
        let src = snap_dir.join(fname);
        if src.is_file() {
            if std::fs::copy(&src, ddir.join(fname)).is_ok() {
                restored_files += 1;
            }
        }
    }

    if let Some(reg_arc) = registry {
        if let Ok(mut reg) = reg_arc.lock() {
            if let Ok(raw) = std::fs::read_to_string(lan_groups_path()) {
                if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(raw.trim_start_matches('\u{feff}')) {
                    reg.groups.clear();
                    reg.group_policies.clear();
                    apply_groups_slice(&mut reg, &arr);
                }
            }
            if let Ok(raw) = std::fs::read_to_string(lan_devices_path()) {
                if let Ok(list) = serde_json::from_str::<Vec<Device>>(raw.trim_start_matches('\u{feff}')) {
                    reg.devices.clear();
                    for d in list {
                        if !d.device_id.is_empty() {
                            reg.devices.insert(d.device_id.clone(), d);
                        }
                    }
                }
            }
        }
    }

    Ok(json!({
        "ok": true,
        "success": true,
        "restored_id": safe_id,
        "restored_files": restored_files,
    }))
}

// ============================================================================
// Automated Company ERP Website Backup Engine (elkhawaga.uk)
// ============================================================================

#[derive(Default, Clone, Serialize)]
struct ErpBackupLiveState {
    running: bool,
    stage: String,
    last_attempt_at: u64,
    last_ok_at: u64,
    last_error: String,
}

static ERP_BACKUP_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ERP_BACKUP_STATE: std::sync::OnceLock<Mutex<ErpBackupLiveState>> = std::sync::OnceLock::new();

fn erp_live_state() -> &'static Mutex<ErpBackupLiveState> {
    ERP_BACKUP_STATE.get_or_init(|| Mutex::new(ErpBackupLiveState::default()))
}

fn set_erp_stage(stage: &str) {
    if let Ok(mut st) = erp_live_state().lock() {
        st.stage = stage.to_string();
    }
}

pub fn erp_backups_root_dir() -> std::path::PathBuf {
    let cfg_dir = read_config().erp_backup_dir;
    if !cfg_dir.trim().is_empty() {
        if let Ok(custom) = normalize_backup_dir_path(&cfg_dir) {
            if std::fs::create_dir_all(&custom).is_ok() {
                return custom;
            }
        }
    }
    let dir = server_archive_root().join("ERP-Backups");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn erp_backups_log_path(root: &std::path::Path) -> std::path::PathBuf {
    root.join("erp-backups-log.jsonl")
}

pub fn change_erp_backup_dir(new_path: &str, move_existing: bool) -> Result<serde_json::Value, String> {
    let old_root = erp_backups_root_dir();
    let target_root = if new_path.trim().is_empty() {
        server_archive_root().join("ERP-Backups")
    } else {
        normalize_backup_dir_path(new_path)?
    };

    std::fs::create_dir_all(&target_root)
        .map_err(|e| format!("تعذر إنشاء أو الوصول لمجلد نسخ الموقع ({}): {}", target_root.display(), e))?;
    let probe = target_root.join(format!(".itk_erpbk_test_{}", random_hex(3)));
    std::fs::write(&probe, b"ok")
        .map_err(|e| format!("لا توجد صلاحية كتابة في مجلد نسخ الموقع ({}): {}", target_root.display(), e))?;
    let _ = std::fs::remove_file(&probe);
    harden_archive_acl(&target_root);

    let mut moved_files = 0usize;
    let mut moved_bytes = 0u64;
    if move_existing
        && !old_root
            .to_string_lossy()
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(target_root.to_string_lossy().trim_end_matches('\\'))
        && old_root.is_dir()
    {
        if let Ok(rd) = std::fs::read_dir(&old_root) {
            for ent in rd.flatten() {
                let sp = ent.path();
                let fname = ent.file_name();
                let fstr = fname.to_string_lossy();
                if sp.is_file() && (fstr.starts_with("ERP_Backup_") || fstr == "erp-backups-log.jsonl") {
                    let dp = target_root.join(&fname);
                    if let Ok(sz) = std::fs::copy(&sp, &dp) {
                        moved_files += 1;
                        moved_bytes += sz;
                        let _ = std::fs::remove_file(&sp);
                    }
                }
            }
        }
    }

    let mut cfg = read_config();
    cfg.erp_backup_dir = if new_path.trim().is_empty() {
        String::new()
    } else {
        target_root.to_string_lossy().to_string()
    };
    write_config(&cfg)?;

    let (free_b, total_b) = disk_space_for_path(&target_root);
    Ok(json!({
        "ok": true,
        "success": true,
        "erp_backups_dir": target_root.to_string_lossy().to_string(),
        "moved_files": moved_files,
        "moved_bytes": moved_bytes,
        "disk_free_bytes": free_b,
        "disk_total_bytes": total_b,
    }))
}

pub fn save_erp_backup_settings(body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let mut cfg = read_config();
    if let Some(en) = body["enabled"].as_bool() {
        cfg.erp_backup_enabled = en;
    }
    if let Some(mins) = body["interval_mins"].as_u64() {
        cfg.erp_backup_interval_mins = mins.clamp(15, 10_080);
    }
    if let Some(u) = body["url"].as_str() {
        let clean = u.trim().trim_end_matches('/').to_string();
        if !clean.is_empty() {
            if !clean.starts_with("https://") && !clean.starts_with("http://") {
                cfg.erp_backup_url = format!("https://{}", clean);
            } else {
                cfg.erp_backup_url = clean;
            }
        }
    }
    if let Some(un) = body["username"].as_str() {
        cfg.erp_backup_username = un.trim().to_string();
    }
    if let Some(pw) = body["password"].as_str() {
        if !pw.is_empty() {
            cfg.erp_backup_password = pw.to_string();
        }
    }
    if let Some(did) = body["did_cookie"].as_str() {
        cfg.erp_backup_did_cookie = did.trim().to_string();
    }
    if let Some(dtok) = body["device_token"].as_str() {
        cfg.erp_backup_device_token = dtok.trim().to_string();
    }
    if cfg.erp_backup_enabled && (cfg.erp_backup_username.trim().is_empty() || cfg.erp_backup_password.is_empty()) {
        return Err("يرجى إدخال اسم المستخدم وكلمة مرور أدمن الموقع قبل تفعيل الجدولة التلقائية".into());
    }
    write_config(&cfg)?;
    Ok(json!({
        "ok": true,
        "success": true,
        "has_password": !cfg.erp_backup_password.is_empty(),
        "enabled": cfg.erp_backup_enabled,
        "interval_mins": cfg.erp_backup_interval_mins,
    }))
}

fn read_erp_backup_entries(root: &std::path::Path) -> Vec<serde_json::Value> {
    let mut by_file: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
    if let Ok(raw) = std::fs::read_to_string(erp_backups_log_path(root)) {
        for line in raw.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
                if let Some(fnm) = v["file_name"].as_str() {
                    by_file.insert(fnm.to_string(), v);
                }
            }
        }
    }
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            let p = ent.path();
            if !p.is_file() {
                continue;
            }
            let fname = ent.file_name().to_string_lossy().to_string();
            if !fname.starts_with("ERP_Backup_") {
                continue;
            }
            let Ok(meta) = p.metadata() else { continue };
            let mtime_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Some(mut logged) = by_file.remove(&fname) {
                logged["size_bytes"] = json!(meta.len());
                if logged["created_at"].as_u64().unwrap_or(0) == 0 {
                    logged["created_at"] = json!(mtime_ms);
                }
                out.push(logged);
            } else {
                out.push(json!({
                    "id": fname.clone(),
                    "file_name": fname,
                    "size_bytes": meta.len(),
                    "format": "Archive",
                    "verified": true,
                    "sha256": "",
                    "reason": "manual",
                    "duration_ms": 0,
                    "created_at": mtime_ms,
                }));
            }
        }
    }
    out.sort_by(|a, b| b["created_at"].as_u64().unwrap_or(0).cmp(&a["created_at"].as_u64().unwrap_or(0)));
    out
}

fn apply_erp_backup_retention(root: &std::path::Path) {
    let entries = read_erp_backup_entries(root);
    if entries.len() <= 48 {
        return;
    }
    let now_t = now_ms();
    let cutoff_48h = now_t.saturating_sub(48 * 3600 * 1000);
    let cutoff_30d = now_t.saturating_sub(30 * 24 * 3600 * 1000);
    let mut kept_days: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut keep_files: std::collections::HashSet<String> = std::collections::HashSet::new();

    for item in &entries {
        let fname = item["file_name"].as_str().unwrap_or("");
        if fname.is_empty() {
            continue;
        }
        let ts = item["created_at"].as_u64().unwrap_or(0);
        if ts >= cutoff_48h {
            keep_files.insert(fname.to_string());
        } else if ts >= cutoff_30d {
            // Extract YYYY-MM-DD from ERP_Backup_YYYY-MM-DD_...
            let day_key = fname
                .strip_prefix("ERP_Backup_")
                .and_then(|s| s.get(..10))
                .unwrap_or("")
                .to_string();
            if !day_key.is_empty() && kept_days.insert(day_key) {
                keep_files.insert(fname.to_string());
            }
        }
    }

    for item in &entries {
        if let Some(fname) = item["file_name"].as_str() {
            if !fname.is_empty() && !keep_files.contains(fname) {
                let _ = std::fs::remove_file(root.join(fname));
            }
        }
    }

    // Compact JSONL log to retained entries only
    let remaining: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|v| v["file_name"].as_str().map_or(false, |f| keep_files.contains(f)))
        .collect();
    use std::io::Write;
    if let Ok(mut f) = std::fs::File::create(erp_backups_log_path(root)) {
        for v in remaining {
            let _ = writeln!(f, "{}", v);
        }
    }
}

pub fn list_erp_backups() -> serde_json::Value {
    let root = erp_backups_root_dir();
    let cfg = read_config();
    let entries = read_erp_backup_entries(&root);
    let (free_b, total_b) = disk_space_for_path(&root);
    let st = erp_live_state().lock().map(|g| g.clone()).unwrap_or_default();
    json!({
        "ok": true,
        "erp_backups_dir": root.to_string_lossy().to_string(),
        "disk_free_bytes": free_b,
        "disk_total_bytes": total_b,
        "drives": list_server_drives(),
        "config": {
            "enabled": cfg.erp_backup_enabled,
            "interval_mins": cfg.erp_backup_interval_mins,
            "url": cfg.erp_backup_url,
            "username": cfg.erp_backup_username,
            "has_password": !cfg.erp_backup_password.is_empty(),
            "did_cookie": cfg.erp_backup_did_cookie,
            "device_token": cfg.erp_backup_device_token,
        },
        "status": {
            "running": st.running || ERP_BACKUP_RUNNING.load(std::sync::atomic::Ordering::SeqCst),
            "stage": st.stage,
            "last_attempt_at": st.last_attempt_at,
            "last_ok_at": st.last_ok_at,
            "last_error": st.last_error,
        },
        "backups": entries.into_iter().take(40).collect::<Vec<_>>(),
    })
}

pub fn fetch_erp_backup_file_bytes(raw_name: &str) -> Option<(String, Vec<u8>)> {
    let clean: String = raw_name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect();
    if !clean.starts_with("ERP_Backup_") || clean.contains("..") {
        return None;
    }
    let path = erp_backups_root_dir().join(&clean);
    if let Ok(bytes) = std::fs::read(&path) {
        return Some((clean, bytes));
    }
    // Fallback for remote Admin Desktop installs: stream from Main Server via Cloud Relay
    let cfg = read_config();
    if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
        let remote_url = format!("{}/api/v1/erp-backups/download/{}", cfg.relay_url.trim_end_matches('/'), clean);
        if let Ok(resp) = tls_agent_builder()
            .timeout_read(Duration::from_secs(180))
            .build()
            .get(&remote_url)
            .set("Authorization", &format!("Bearer {}", cfg.admin_key.trim()))
            .call()
        {
            if resp.status() == 200 {
                let mut bytes = Vec::new();
                if resp.into_reader().take(512 * 1024 * 1024).read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
                    return Some((clean, bytes));
                }
            }
        }
    }
    None
}

struct ErpHttpSession {
    agent: ureq::Agent,
    base_url: String,
    cookies: HashMap<String, String>,
}

impl ErpHttpSession {
    fn new(base_url: &str, did_cookie: &str) -> Self {
        let agent = tls_agent_builder()
            .redirects(0)
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(300))
            .timeout_write(Duration::from_secs(30))
            .build();
        let mut cookies = HashMap::new();
        if !did_cookie.trim().is_empty() {
            cookies.insert("elkhawaga_did".to_string(), did_cookie.trim().to_string());
        }
        Self {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
            cookies,
        }
    }

    fn resolve_url(&self, href_or_url: &str) -> String {
        let t = href_or_url.trim();
        if t.starts_with("https://") || t.starts_with("http://") {
            t.to_string()
        } else if t.starts_with('/') {
            format!("{}{}", self.base_url, t)
        } else {
            format!("{}/{}", self.base_url, t)
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn absorb_cookies(&mut self, resp: &ureq::Response) {
        for raw_sc in resp.all("set-cookie") {
            if let Some(first_pair) = raw_sc.split(';').next() {
                if let Some((k, v)) = first_pair.split_once('=') {
                    let key = k.trim();
                    let val = v.trim();
                    if !key.is_empty() {
                        if val.is_empty() || raw_sc.to_ascii_lowercase().contains("max-age=0") {
                            self.cookies.remove(key);
                        } else {
                            self.cookies.insert(key.to_string(), val.to_string());
                        }
                    }
                }
            }
        }
    }

    fn apply_common_headers(&self, req: ureq::Request, referer: Option<&str>) -> ureq::Request {
        let mut r = req
            .set(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            )
            .set("Accept", "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8")
            .set("Accept-Language", "ar,en-US;q=0.9,en;q=0.8");
        let ch = self.cookie_header();
        if !ch.is_empty() {
            r = r.set("Cookie", &ch);
        }
        if let Some(ref_url) = referer {
            r = r.set("Referer", ref_url);
        }
        r
    }

    fn get_html(&mut self, path_or_url: &str) -> Result<(String, String), String> {
        let mut cur_url = self.resolve_url(path_or_url);
        for _ in 0..8 {
            let req = self.apply_common_headers(self.agent.get(&cur_url), Some(&self.base_url));
            let resp = match req.call() {
                Ok(r) => r,
                Err(ureq::Error::Status(_code, r)) => r,
                Err(e) => return Err(format!("تعذر الاتصال بموقع الشركة ({}): {}", cur_url, e)),
            };
            self.absorb_cookies(&resp);
            let status = resp.status();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if let Some(loc) = resp.header("location") {
                    cur_url = self.resolve_url(loc);
                    continue;
                }
            }
            if status >= 400 {
                return Err(format!("رد الموقع بكود خطأ HTTP {} عند فتح {}", status, cur_url));
            }
            let body = resp.into_string().map_err(|e| format!("تعذر قراءة صفحة الموقع: {}", e))?;
            return Ok((cur_url, body));
        }
        Err("تجاوز الحد الأقصى لإعادة التوجيه على موقع الشركة".into())
    }

    fn post_form(&mut self, path_or_url: &str, referer: &str, fields: &[(String, String)]) -> Result<(u16, String, String), String> {
        let target = self.resolve_url(path_or_url);
        let encoded = fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode_form(k), url_encode_form(v)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = self
            .apply_common_headers(self.agent.post(&target), Some(&self.resolve_url(referer)))
            .set("Origin", &self.base_url)
            .set("Content-Type", "application/x-www-form-urlencoded");
        if let Some((_, csrf)) = fields.iter().find(|(k, _)| k == "csrfmiddlewaretoken") {
            req = req.set("X-CSRFToken", csrf);
        } else if let Some(c) = self.cookies.get("elkhawaga_csrftoken").or_else(|| self.cookies.get("csrftoken")) {
            req = req.set("X-CSRFToken", c);
        }
        let resp = match req.send_string(&encoded) {
            Ok(r) => r,
            Err(ureq::Error::Status(_code, r)) => r,
            Err(e) => return Err(format!("فشل إرسال الطلب إلى {}: {}", target, e)),
        };
        self.absorb_cookies(&resp);
        let status = resp.status();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let loc = resp.header("location").unwrap_or("").to_string();
            let resolved_loc = if loc.is_empty() { target } else { self.resolve_url(&loc) };
            let (final_url, html) = self.get_html(&resolved_loc)?;
            return Ok((status, final_url, html));
        }
        let body = resp.into_string().unwrap_or_default();
        Ok((status, target, body))
    }

    fn download_bytes(&mut self, path_or_url: &str, referer: &str) -> Result<(Vec<u8>, String, String), String> {
        let mut cur_url = self.resolve_url(path_or_url);
        for _ in 0..8 {
            let req = self.apply_common_headers(self.agent.get(&cur_url), Some(&self.resolve_url(referer)));
            let resp = match req.call() {
                Ok(r) => r,
                Err(ureq::Error::Status(_code, r)) => r,
                Err(e) => return Err(format!("تعذر تحميل ملف النسخة الاحتياطية: {}", e)),
            };
            self.absorb_cookies(&resp);
            let status = resp.status();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if let Some(loc) = resp.header("location") {
                    cur_url = self.resolve_url(loc);
                    continue;
                }
            }
            if status >= 400 {
                return Err(format!("فشل تحميل ملف النسخة من الموقع (HTTP {})", status));
            }
            let ct = resp.header("content-type").unwrap_or("").to_string();
            let disp = resp.header("content-disposition").unwrap_or("").to_string();
            let mut bytes = Vec::new();
            resp.into_reader()
                .take(1024 * 1024 * 1024) // up to 1 GB safety cap
                .read_to_end(&mut bytes)
                .map_err(|e| format!("انقطع تحميل ملف النسخة الاحتياطية: {}", e))?;
            return Ok((bytes, ct, disp));
        }
        Err("تجاوز عدد تحويلات التحميل المسموح بها".into())
    }
}

fn url_encode_form(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn decode_basic_html_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn extract_html_attr(tag: &str, attr_name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{}=", attr_name.to_ascii_lowercase());
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find(&needle) {
        let pos = search_from + rel;
        let prev_ok = pos == 0 || {
            let b = lower.as_bytes()[pos - 1];
            b.is_ascii_whitespace() || b == b'<' || b == b'"' || b == b'\''
        };
        let val_start = pos + needle.len();
        if !prev_ok || val_start >= tag.len() {
            search_from = val_start;
            continue;
        }
        let rest = &tag[val_start..];
        let trimmed = rest.trim_start();
        if let Some(stripped) = trimmed.strip_prefix('"') {
            if let Some(end_q) = stripped.find('"') {
                return Some(decode_basic_html_entities(&stripped[..end_q]));
            }
        } else if let Some(stripped) = trimmed.strip_prefix('\'') {
            if let Some(end_q) = stripped.find('\'') {
                return Some(decode_basic_html_entities(&stripped[..end_q]));
            }
        } else {
            let end_u = trimmed
                .find(|c: char| c.is_ascii_whitespace() || c == '>')
                .unwrap_or(trimmed.len());
            return Some(decode_basic_html_entities(&trimmed[..end_u]));
        }
        search_from = val_start;
    }
    None
}

pub(crate) fn extract_csrf_token_from_html(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find("<input") {
        let start = from + rel;
        let Some(end_rel) = lower[start..].find('>') else { break };
        let tag = &html[start..=start + end_rel];
        if let Some(nm) = extract_html_attr(tag, "name") {
            if nm.eq_ignore_ascii_case("csrfmiddlewaretoken") {
                if let Some(val) = extract_html_attr(tag, "value") {
                    if !val.trim().is_empty() {
                        return Some(val);
                    }
                }
            }
        }
        from = start + end_rel + 1;
    }
    // Fallback: <meta name="csrf-token" content="...">
    from = 0;
    while let Some(rel) = lower[from..].find("<meta") {
        let start = from + rel;
        let Some(end_rel) = lower[start..].find('>') else { break };
        let tag = &html[start..=start + end_rel];
        if let Some(nm) = extract_html_attr(tag, "name") {
            if nm.eq_ignore_ascii_case("csrf-token") {
                if let Some(val) = extract_html_attr(tag, "content") {
                    if !val.trim().is_empty() {
                        return Some(val);
                    }
                }
            }
        }
        from = start + end_rel + 1;
    }
    None
}

pub(crate) fn extract_create_backup_form(html: &str, default_action: &str, backup_title: &str) -> (String, Vec<(String, String)>) {
    let lower = html.to_ascii_lowercase();
    let mut chosen_form = html;
    let mut chosen_action = default_action.to_string();

    let mut f_pos = 0usize;
    while let Some(rel) = lower[f_pos..].find("<form") {
        let start = f_pos + rel;
        let Some(open_end_rel) = lower[start..].find('>') else { break };
        let open_tag = &html[start..=start + open_end_rel];
        let close_pos = lower[start + open_end_rel + 1..]
            .find("</form>")
            .map(|r| start + open_end_rel + 1 + r)
            .unwrap_or(html.len());
        let inner = &html[start..close_pos];
        let act = extract_html_attr(open_tag, "action").unwrap_or_default();
        let inner_low = inner.to_ascii_lowercase();
        let is_logout_or_nav = act.contains("logout") || act.contains("save-theme");
        if !is_logout_or_nav
            && (inner_low.contains("backup")
                || inner.contains("نسخة")
                || act.contains("backup")
                || inner_low.contains("<select"))
        {
            chosen_form = inner;
            if !act.trim().is_empty() {
                chosen_action = act;
            }
            break;
        }
        f_pos = close_pos.min(html.len());
        if f_pos == start {
            break;
        }
    }

    let mut fields: Vec<(String, String)> = Vec::new();
    let form_low = chosen_form.to_ascii_lowercase();

    // Parse <input ...>
    let mut pos = 0usize;
    while let Some(rel) = form_low[pos..].find("<input") {
        let start = pos + rel;
        let Some(end_rel) = form_low[start..].find('>') else { break };
        let tag = &chosen_form[start..=start + end_rel];
        let tag_low = tag.to_ascii_lowercase();
        if let Some(name) = extract_html_attr(tag, "name") {
            let typ = extract_html_attr(tag, "type").unwrap_or_else(|| "text".into()).to_ascii_lowercase();
            let skip = matches!(typ.as_str(), "submit" | "button" | "reset" | "file" | "image")
                || ((typ == "checkbox" || typ == "radio") && !tag_low.contains("checked"));
            if !skip && !fields.iter().any(|(k, _)| k == &name) {
                let val = extract_html_attr(tag, "value").unwrap_or_default();
                fields.push((name, val));
            }
        }
        pos = start + end_rel + 1;
    }

    // Parse <select ...> ... </select>
    pos = 0;
    while let Some(rel) = form_low[pos..].find("<select") {
        let start = pos + rel;
        let Some(open_end_rel) = form_low[start..].find('>') else { break };
        let open_tag = &chosen_form[start..=start + open_end_rel];
        let close_rel = form_low[start + open_end_rel + 1..]
            .find("</select>")
            .unwrap_or(chosen_form.len() - (start + open_end_rel + 1));
        let select_body = &chosen_form[start + open_end_rel + 1..start + open_end_rel + 1 + close_rel];
        if let Some(sel_name) = extract_html_attr(open_tag, "name") {
            let sb_low = select_body.to_ascii_lowercase();
            let mut o_pos = 0usize;
            let mut selected_val: Option<String> = None;
            let mut first_non_empty: Option<String> = None;
            let mut full_match: Option<String> = None;
            while let Some(o_rel) = sb_low[o_pos..].find("<option") {
                let o_start = o_pos + o_rel;
                let Some(o_end_rel) = sb_low[o_start..].find('>') else { break };
                let o_tag = &select_body[o_start..=o_start + o_end_rel];
                let o_tag_low = o_tag.to_ascii_lowercase();
                let o_close = sb_low[o_start + o_end_rel + 1..]
                    .find("</option>")
                    .map(|r| o_start + o_end_rel + 1 + r)
                    .unwrap_or(select_body.len());
                let o_label = &select_body[o_start + o_end_rel + 1..o_close];
                let val = extract_html_attr(o_tag, "value").unwrap_or_else(|| o_label.trim().to_string());
                if !val.trim().is_empty() {
                    if first_non_empty.is_none() {
                        first_non_empty = Some(val.clone());
                    }
                    if val.eq_ignore_ascii_case("full")
                        || val.eq_ignore_ascii_case("complete")
                        || o_label.contains("كاملة")
                    {
                        full_match = Some(val.clone());
                    }
                    if o_tag_low.contains("selected") {
                        selected_val = Some(val);
                    }
                }
                o_pos = o_start + o_end_rel + 1;
            }
            if let Some(chosen_v) = full_match.or(selected_val).or(first_non_empty) {
                fields.retain(|(k, _)| k != &sel_name);
                fields.push((sel_name, chosen_v));
            }
        }
        pos = start + open_end_rel + 1 + close_rel;
    }

    // Parse <textarea ...>
    pos = 0;
    while let Some(rel) = form_low[pos..].find("<textarea") {
        let start = pos + rel;
        let Some(open_end_rel) = form_low[start..].find('>') else { break };
        let open_tag = &chosen_form[start..=start + open_end_rel];
        if let Some(t_name) = extract_html_attr(open_tag, "name") {
            if !fields.iter().any(|(k, _)| k == &t_name) {
                fields.push((t_name, "نسخة تلقائية دورية محفوظة على سيرفر IT ELKHAWGA".to_string()));
            }
        }
        pos = start + open_end_rel + 1;
    }

    // Ensure CSRF token is present
    if !fields.iter().any(|(k, _)| k == "csrfmiddlewaretoken") {
        if let Some(csrf) = extract_csrf_token_from_html(html) {
            fields.insert(0, ("csrfmiddlewaretoken".to_string(), csrf));
        }
    }

    // Override backup name/title field with our unique timestamped marker
    let mut name_set = false;
    for (k, v) in fields.iter_mut() {
        let kl = k.to_ascii_lowercase();
        if kl == "name" || kl == "title" || kl == "backup_name" {
            *v = backup_title.to_string();
            name_set = true;
        }
    }
    if !name_set {
        fields.push(("name".to_string(), backup_title.to_string()));
    }

    (chosen_action, fields)
}

fn extract_erp_backup_links(html: &str) -> (Vec<String>, Vec<String>) {
    let mut downloads: Vec<String> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    let lower = html.to_ascii_lowercase();

    for attr in ["href", "data-download-url", "data-url"] {
        let needle = format!("{}=", attr);
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(&needle) {
            let start = from + rel;
            let raw_end = (start + 512).min(html.len());
            let slice_end = (start..=raw_end)
                .rev()
                .find(|&i| html.is_char_boundary(i))
                .unwrap_or(start);
            if let Some(val) = html.get(start..slice_end).and_then(|s| extract_html_attr(s, attr)) {
                let v = val.trim();
                let vl = v.to_ascii_lowercase();
                let is_download = (vl.contains("/backup-system/") && vl.contains("download"))
                    || (vl.contains("/media/") && vl.contains("backup"))
                    || vl.ends_with(".zip")
                    || vl.ends_with(".tar.gz")
                    || vl.ends_with(".sql.gz")
                    || vl.ends_with(".json.gz")
                    || vl.ends_with(".gz")
                    || vl.ends_with(".sql");
                if is_download && !vl.contains("restore") && !vl.contains("delete") {
                    if !downloads.contains(&v.to_string()) {
                        downloads.push(v.to_string());
                    }
                } else if vl.contains("/backup-system/backups/")
                    && !vl.contains("/create")
                    && !vl.contains("/restore")
                    && !vl.contains("/delete")
                    && vl.trim_end_matches('/') != "/backup-system/backups"
                    && !vl.ends_with("/backup-system/backups")
                {
                    if !details.contains(&v.to_string()) {
                        details.push(v.to_string());
                    }
                }
            }
            from = start + needle.len();
        }
    }
    (downloads, details)
}

fn find_link_near_marker(html: &str, marker: &str) -> (Option<String>, Option<String>) {
    let Some(m_pos) = html.find(marker) else {
        return (None, None);
    };
    let win_start = m_pos.saturating_sub(800);
    let win_end = (m_pos + marker.len() + 1800).min(html.len());
    // Align UTF-8 char boundaries safely
    let s = (0..=win_start).rev().find(|&i| html.is_char_boundary(i)).unwrap_or(0);
    let e = (win_end..=html.len()).find(|&i| html.is_char_boundary(i)).unwrap_or(html.len());
    let snippet = &html[s..e];
    let (dls, dets) = extract_erp_backup_links(snippet);
    (dls.into_iter().next(), dets.into_iter().next())
}

pub(crate) fn verify_backup_payload(
    bytes: &[u8],
    content_type: &str,
    content_disposition: &str,
) -> Result<(&'static str, String), String> {
    if bytes.len() < 64 {
        return Err(format!("الملف المحمّل صغير جداً أو فارغ ({} بايت فقط)", bytes.len()));
    }
    let ct_low = content_type.to_ascii_lowercase();
    let head_sample = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).trim_start().to_ascii_lowercase();
    if ct_low.starts_with("text/html") || head_sample.starts_with("<!doctype html") || head_sample.starts_with("<html") {
        return Err("أعاد الموقع صفحة ويب (HTML) بدلاً من ملف النسخة الاحتياطية — تأكد من اكتمال النسخة وصلاحية الأدمن".into());
    }

    // Check filename suffix from Content-Disposition if available
    let disp_ext = content_disposition
        .split(';')
        .find_map(|part| {
            let p = part.trim();
            p.strip_prefix("filename=").or_else(|| p.strip_prefix("filename*="))
        })
        .map(|raw| raw.trim_matches('"').trim_matches('\'').to_ascii_lowercase())
        .unwrap_or_default();

    // 1. ZIP magic: PK\x03\x04 + verify End-of-Central-Directory PK\x05\x06 at tail
    if bytes.starts_with(b"PK\x03\x04") {
        let tail_start = bytes.len().saturating_sub(65_558);
        let tail = &bytes[tail_start..];
        let has_eocd = tail.windows(4).any(|w| w == b"PK\x05\x06");
        if !has_eocd {
            return Err("ملف ZIP غير مكتمل أو تالف (نهاية الأرشيف مفقودة)".into());
        }
        return Ok(("ZIP مضغوط ومفحوص ✓", ".zip".to_string()));
    }

    // 2. GZIP magic: 1F 8B 08
    if bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        let ext = if disp_ext.ends_with(".tar.gz") {
            ".tar.gz"
        } else if disp_ext.ends_with(".sql.gz") {
            ".sql.gz"
        } else if disp_ext.ends_with(".json.gz") {
            ".json.gz"
        } else {
            ".gz"
        };
        return Ok(("GZIP مضغوط ومفحوص ✓", ext.to_string()));
    }

    // 3. SQLite 3 database
    if bytes.starts_with(b"SQLite format 3\0") {
        return Ok(("قاعدة SQLite سليمة ✓", ".sqlite3".to_string()));
    }

    // 4. PostgreSQL custom dump
    if bytes.starts_with(b"PGDMP") {
        return Ok(("PostgreSQL Dump سليم ✓", ".dump".to_string()));
    }

    // 5. JSON backup
    let trimmed_ascii = std::str::from_utf8(bytes).ok().map(str::trim);
    if let Some(txt) = trimmed_ascii {
        if (txt.starts_with('{') && txt.ends_with('}')) || (txt.starts_with('[') && txt.ends_with(']')) {
            return Ok(("ملف JSON سليم ✓", ".json".to_string()));
        }
        let max_up = txt.len().min(256);
        let safe_up_end = (0..=max_up).rev().find(|&i| txt.is_char_boundary(i)).unwrap_or(0);
        let up = txt.get(..safe_up_end).unwrap_or("").to_ascii_uppercase();
        if up.starts_with("--") || up.contains("CREATE TABLE") || up.contains("INSERT INTO") || up.starts_with("BEGIN;") {
            return Ok(("قاعدة SQL سليمة ✓", ".sql".to_string()));
        }
    }

    // 6. Tar or custom encrypted/compressed archive
    if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        return Ok(("أرشيف TAR سليم ✓", ".tar".to_string()));
    }

    if bytes.len() >= 512 && !ct_low.starts_with("text/") {
        let ext = if let Some(dot) = disp_ext.rfind('.') {
            let cand = &disp_ext[dot..];
            if cand.len() <= 10 && cand.chars().skip(1).all(|c| c.is_ascii_alphanumeric()) {
                cand.to_string()
            } else {
                ".bak".to_string()
            }
        } else {
            ".bak".to_string()
        };
        return Ok(("أرشيف نسخ احتياطي مفحوص ✓", ext));
    }

    Err("صيغة الملف المحمّل غير معروفة أو تالفة".into())
}

pub fn run_erp_site_backup_blocking(
    reason: &str,
    registry: Option<&Arc<Mutex<Registry>>>,
) -> Result<serde_json::Value, String> {
    if ERP_BACKUP_RUNNING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err("توجد عملية سحب نسخة احتياطية قيد التنفيذ حالياً — يرجى الانتظار".into());
    }
    struct RunGuard;
    impl Drop for RunGuard {
        fn drop(&mut self) {
            ERP_BACKUP_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
            if let Ok(mut st) = erp_live_state().lock() {
                st.running = false;
            }
        }
    }
    let _guard = RunGuard;

    let started_ms = now_ms();
    if let Ok(mut st) = erp_live_state().lock() {
        st.running = true;
        st.last_attempt_at = started_ms;
        st.last_error.clear();
        st.stage = "جاري الاتصال بموقع الشركة وتسجيل الدخول...".into();
    }

    let outcome = (|| -> Result<serde_json::Value, String> {
        let cfg = read_config();
        let base_url = cfg.erp_backup_url.trim().trim_end_matches('/').to_string();
        let username = cfg.erp_backup_username.trim().to_string();
        let password = cfg.erp_backup_password.clone();
        if base_url.is_empty() || username.is_empty() || password.is_empty() {
            return Err("يرجى حفظ اسم المستخدم وكلمة مرور أدمن الموقع أولاً في إعدادات النسخ الاحتياطي".into());
        }

        let mut sess = ErpHttpSession::new(&base_url, &cfg.erp_backup_did_cookie);

        // 1. Fetch login page & submit admin credentials
        let (_login_url, login_html) = sess.get_html("/accounts/login/")?;
        let csrf = extract_csrf_token_from_html(&login_html)
            .or_else(|| sess.cookies.get("elkhawaga_csrftoken").cloned())
            .or_else(|| sess.cookies.get("csrftoken").cloned())
            .unwrap_or_default();
        let dev_info = r#"{"screen_resolution":"1920x1080","timezone":"Africa/Cairo","language":"ar","platform":"Win32","color_depth":24,"pixel_ratio":1,"has_touch":false,"cpu_cores":8}"#;
        let login_fields = vec![
            ("csrfmiddlewaretoken".to_string(), csrf),
            ("username".to_string(), username),
            ("password".to_string(), password),
            ("device_token".to_string(), cfg.erp_backup_device_token.trim().to_string()),
            ("device_info".to_string(), dev_info.to_string()),
        ];
        let (_st_code, post_login_url, post_login_html) = sess.post_form("/accounts/login/", "/accounts/login/", &login_fields)?;
        let has_session = sess.cookies.contains_key("elkhawaga_sessionid")
            || sess.cookies.contains_key("sessionid")
            || post_login_html.contains("/accounts/logout/")
            || post_login_html.contains("data-user-authenticated=\"true\"");
        if !has_session && post_login_url.contains("/accounts/login") {
            return Err("فشل تسجيل الدخول في موقع elkhawaga.uk — تأكد من اسم مستخدم وكلمة مرور الأدمن (أو قيود الجهاز/OTP)".into());
        }

        // 2. Snapshot pre-existing backup links so we never re-download old 1-year-old backups
        set_erp_stage("تم تسجيل الدخول ✓ — جاري فحص قائمة النسخ الحالية...");
        let mut pre_downloads: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pre_details: std::collections::HashSet<String> = std::collections::HashSet::new();
        for list_path in ["/backup-system/", "/backup-system/backups/"] {
            if let Ok((_, h)) = sess.get_html(list_path) {
                let (dls, dets) = extract_erp_backup_links(&h);
                pre_downloads.extend(dls);
                pre_details.extend(dets);
            }
        }

        // 3. Open /backup-system/backups/create/ and trigger new full backup
        let stamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let marker_title = format!("ITK_Auto_{}", stamp);
        set_erp_stage(&format!("جاري إنشاء نسخة احتياطية كاملة جديدة ({})...", marker_title));

        let (create_url, create_html) = sess.get_html("/backup-system/backups/create/")?;
        if create_url.contains("/accounts/login") {
            return Err("انتهت جلسة الموقع أو لا يملك هذا الحساب صلاحية دخول لوحة النسخ الاحتياطي".into());
        }
        let (form_action, form_fields) = extract_create_backup_form(&create_html, "/backup-system/backups/create/", &marker_title);
        let (create_status, after_create_url, after_create_body) =
            sess.post_form(&form_action, &create_url, &form_fields)?;
        if create_status >= 400 {
            return Err(format!("رفض الموقع طلب إنشاء النسخة الاحتياطية (HTTP {})", create_status));
        }

        // Check if JSON response directly returned download_url or detail url
        let mut direct_download_url: Option<String> = None;
        let mut candidate_detail_urls: Vec<String> = Vec::new();
        if let Ok(jv) = serde_json::from_str::<serde_json::Value>(after_create_body.trim()) {
            if let Some(dl) = jv["download_url"].as_str().or_else(|| jv["file_url"].as_str()) {
                if !dl.is_empty() {
                    direct_download_url = Some(dl.to_string());
                }
            }
            if let Some(id_val) = jv.get("id").or_else(|| jv.get("backup_id")) {
                let id_str = id_val.as_str().map(String::from).unwrap_or_else(|| id_val.to_string());
                let id_clean = id_str.trim_matches('"');
                if !id_clean.is_empty() && id_clean != "null" {
                    candidate_detail_urls.push(format!("/backup-system/backups/{}/", id_clean));
                    candidate_detail_urls.push(format!("/backup-system/backups/{}/download/", id_clean));
                }
            }
        }
        if after_create_url.contains("/backup-system/backups/") && !after_create_url.contains("/create") {
            candidate_detail_urls.push(after_create_url.clone());
        }
        let (imm_dls, imm_dets) = extract_erp_backup_links(&after_create_body);
        for d in imm_dls {
            if !pre_downloads.contains(&d) {
                direct_download_url = Some(d);
                break;
            }
        }
        for det in imm_dets {
            if !pre_details.contains(&det) && !candidate_detail_urls.contains(&det) {
                candidate_detail_urls.push(det);
            }
        }

        // 4. Poll up to 60 * 3s (3 minutes) until the new backup finishes compressing and exposes its download link
        let mut resolved_download = direct_download_url;
        for attempt in 0..60 {
            if resolved_download.is_some() {
                break;
            }
            if attempt > 0 {
                set_erp_stage(&format!("جاري ضغط النسخة على الموقع... ({} ثانية)", attempt * 3));
                std::thread::sleep(Duration::from_secs(3));
            }
            // Check any discovered detail page first
            for det_url in candidate_detail_urls.clone() {
                if det_url.contains("download") {
                    continue;
                }
                if let Ok((_, det_html)) = sess.get_html(&det_url) {
                    let (dls, _) = extract_erp_backup_links(&det_html);
                    if let Some(dl) = dls.into_iter().find(|u| !pre_downloads.contains(u)) {
                        resolved_download = Some(dl);
                        break;
                    }
                }
            }
            if resolved_download.is_some() {
                break;
            }
            // Check backup list & dashboard pages
            for list_path in ["/backup-system/backups/", "/backup-system/"] {
                if let Ok((_, list_html)) = sess.get_html(list_path) {
                    let (near_dl, near_det) = find_link_near_marker(&list_html, &marker_title);
                    if let Some(dl) = near_dl {
                        resolved_download = Some(dl);
                        break;
                    }
                    if let Some(det) = near_det {
                        if !candidate_detail_urls.contains(&det) {
                            candidate_detail_urls.push(det.clone());
                        }
                        if let Ok((_, det_html)) = sess.get_html(&det) {
                            let (dls, _) = extract_erp_backup_links(&det_html);
                            if let Some(dl) = dls.into_iter().next() {
                                resolved_download = Some(dl);
                                break;
                            }
                            // Try standard Django convention <detail>/download/ if detail shows completed
                            if det_html.contains("مكتمل") || det_html.to_ascii_lowercase().contains("completed") {
                                let guessed = format!("{}/download/", det.trim_end_matches('/'));
                                resolved_download = Some(guessed);
                                break;
                            }
                        }
                    }
                    let (all_dls, all_dets) = extract_erp_backup_links(&list_html);
                    if let Some(new_dl) = all_dls.into_iter().find(|u| !pre_downloads.contains(u)) {
                        resolved_download = Some(new_dl);
                        break;
                    }
                    for new_det in all_dets {
                        if !pre_details.contains(&new_det) && !candidate_detail_urls.contains(&new_det) {
                            candidate_detail_urls.push(new_det);
                        }
                    }
                }
            }
        }

        let download_url = resolved_download.ok_or_else(|| {
            "تم إرسال طلب إنشاء النسخة للموقع ولكن لم يظهر رابط التحميل خلال المهلة المحددة — راجع لوحة النسخ على الموقع".to_string()
        })?;

        // 5. Stream download & verify archive integrity
        set_erp_stage("جاري تحميل النسخة الاحتياطية وفحص سلامة الأرشيف (SHA-256)...");
        let (bytes, ct, disp) = sess.download_bytes(&download_url, "/backup-system/")?;
        let (format_label, ext) = verify_backup_payload(&bytes, &ct, &disp)?;

        let sha256_hex: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let root = erp_backups_root_dir();
        let _ = std::fs::create_dir_all(&root);
        harden_archive_acl(&root);

        let file_name = format!("ERP_Backup_{}{}", stamp, ext);
        let final_path = root.join(&file_name);
        let tmp_path = root.join(format!("{}.tmp", file_name));
        std::fs::write(&tmp_path, &bytes)
            .map_err(|e| format!("تعذر حفظ النسخة الاحتياطية على قرص السيرفر: {}", e))?;
        std::fs::rename(&tmp_path, &final_path)
            .or_else(|_| std::fs::copy(&tmp_path, &final_path).map(|_| { let _ = std::fs::remove_file(&tmp_path); }))
            .map_err(|e| format!("تعذر تثبيت ملف النسخة الاحتياطية النهائي: {}", e))?;

        let finished_ms = now_ms();
        let duration_ms = finished_ms.saturating_sub(started_ms);
        let entry = json!({
            "id": file_name,
            "file_name": file_name,
            "remote_title": marker_title,
            "size_bytes": bytes.len(),
            "format": format_label,
            "verified": true,
            "sha256": sha256_hex,
            "reason": reason,
            "duration_ms": duration_ms,
            "created_at": finished_ms,
        });
        {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(erp_backups_log_path(&root))
            {
                let _ = writeln!(f, "{}", entry);
            }
        }
        apply_erp_backup_retention(&root);

        Ok(json!({
            "ok": true,
            "success": true,
            "backup": entry,
            "erp_backups_dir": root.to_string_lossy().to_string(),
        }))
    })();

    match &outcome {
        Ok(val) => {
            if let Ok(mut st) = erp_live_state().lock() {
                st.last_ok_at = now_ms();
                st.last_error.clear();
                let sz = format_file_size(val["backup"]["size_bytes"].as_u64().unwrap_or(0));
                st.stage = format!("✓ اكتمل السحب وفحص السلامة بنجاح ({})", sz);
            }
            notify_wa_bot_erp_event(
                true,
                val["backup"]["file_name"].as_str().unwrap_or("").to_string(),
                val["backup"]["size_bytes"].as_u64().unwrap_or(0),
                val["backup"]["format_label"].as_str().unwrap_or("").to_string(),
                String::new(),
                reason.to_string(),
            );
        }
        Err(err_msg) => {
            if let Ok(mut st) = erp_live_state().lock() {
                st.last_error = err_msg.clone();
                st.stage = format!("فشل السحب: {}", err_msg);
            }
            notify_wa_bot_erp_event(
                false,
                String::new(),
                0,
                String::new(),
                err_msg.clone(),
                reason.to_string(),
            );
            if reason.starts_with("auto") {
                if let Some(reg_arc) = registry {
                    let mut alert = Alert {
                        id: format!("al_erpbk_{}", random_hex(6)),
                        device_id: "server_erp_backup".into(),
                        device_name: "ERP-Backup-Scheduler".into(),
                        alert_type: "tamper".into(),
                        severity: "high".into(),
                        message: format!("تعذر سحب النسخة الاحتياطية التلقائية لموقع الشركة: {}", err_msg),
                        meta: json!({ "source": "erp_backup", "reason": reason }).to_string(),
                        acked: false,
                        acked_at: None,
                        acked_by: None,
                        created_at: now_ms(),
                    };
                    mirror_lan_alert_to_relay(&alert);
                    alert.meta = extract_and_save_lan_alert_media(&alert.id, &alert.meta);
                    if let Ok(mut reg) = reg_arc.lock() {
                        reg.alerts.push(alert);
                        if reg.alerts.len() > 200 {
                            let drop_n = reg.alerts.len() - 200;
                            reg.alerts.drain(0..drop_n);
                        }
                        save_lan_alerts(&reg);
                    }
                }
            }
        }
    }
    outcome
}

pub fn trigger_erp_site_backup(
    reason: &str,
    registry: Option<Arc<Mutex<Registry>>>,
) -> Result<serde_json::Value, String> {
    if ERP_BACKUP_RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(json!({
            "ok": true,
            "success": true,
            "already_running": true,
            "message": "جاري تنفيذ عملية السحب بالفعل في الخلفية",
        }));
    }
    let cfg = read_config();
    if cfg.erp_backup_username.trim().is_empty() || cfg.erp_backup_password.is_empty() {
        return Err("يرجى إدخال وحفظ اسم المستخدم وكلمة مرور أدمن الموقع أولاً".into());
    }
    let reason_owned = reason.to_string();
    std::thread::spawn(move || {
        let _ = run_erp_site_backup_blocking(&reason_owned, registry.as_ref());
    });
    Ok(json!({
        "ok": true,
        "success": true,
        "started": true,
    }))
}

/// Binds the first free port starting at `preferred` and serves clients on a background thread.
pub fn start(token: String, preferred: u16) -> Result<ServerHandle, String> {
    ensure_server_archive_dirs();
    // Background automatic daily backup scheduler (checks shortly after startup, then hourly).
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(12));
        loop {
            let list = list_server_backups();
            let latest_ts = list["backups"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|v| v["created_at"].as_u64())
                .unwrap_or(0);
            if now_ms().saturating_sub(latest_ts) >= 24 * 3600 * 1000 {
                let _ = create_server_backup("auto_daily");
            }
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });
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
                    let raw_len = raw.len();
                    if let Ok(mut list) = serde_json::from_str::<Vec<Alert>>(raw.trim_start_matches('\u{feff}')) {
                        drop(raw);
                        let mut migrated_media = false;
                        for a in &mut list {
                            if a.meta.len() > 1024 {
                                let slim = extract_and_save_lan_alert_media(&a.id, &a.meta);
                                if slim.len() != a.meta.len() {
                                    a.meta = slim;
                                    migrated_media = true;
                                }
                            }
                        }
                        if list.len() > 200 {
                            let drop_n = list.len() - 200;
                            list.drain(0..drop_n);
                            migrated_media = true;
                        }
                        // Background sync of only the latest 10 alerts (sequentially, 1 HTTP client, zero RAM spike)
                        let recent_sync: Vec<Alert> = list.iter().rev().take(10).cloned().collect();
                        reg_init.alerts = list;
                        if migrated_media || raw_len > 512 * 1024 {
                            save_lan_alerts(&reg_init);
                            prune_lan_alert_media_files(400);
                        }
                        if !recent_sync.is_empty() {
                            std::thread::spawn(move || {
                                std::thread::sleep(std::time::Duration::from_secs(3));
                                let cfg = read_config();
                                if cfg.admin_key.trim().is_empty() {
                                    return;
                                }
                                let mut bases: Vec<String> = vec!["http://127.0.0.1:8790".to_string()];
                                let configured = cfg.relay_url.trim().trim_end_matches('/').to_string();
                                if !configured.is_empty() && !bases.iter().any(|b| b == &configured) {
                                    bases.push(configured);
                                }
                                let http = tls_agent(15);
                                for a in recent_sync {
                                    let mut meta_to_send = a.meta.clone();
                                    if let Some((sc, cam)) = read_lan_alert_media(&a.id, None) {
                                        if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&meta_to_send) {
                                            if let Some(obj) = v.as_object_mut() {
                                                if !sc.is_empty() {
                                                    obj.insert("screenshot".to_string(), json!(sc));
                                                }
                                                if !cam.is_empty() {
                                                    obj.insert("camera_photo".to_string(), json!(cam));
                                                }
                                            }
                                            meta_to_send = v.to_string();
                                        }
                                    }
                                    let payload = json!({
                                        "id": a.id,
                                        "device_id": a.device_id,
                                        "device_name": a.device_name,
                                        "type": a.alert_type,
                                        "severity": a.severity,
                                        "message": a.message,
                                        "meta": meta_to_send,
                                        "created_at": a.created_at,
                                    });
                                    for base in &bases {
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
                                }
                            });
                        }
                    }
                }
                let registry = Arc::new(Mutex::new(reg_init));
                // Background automatic ERP website backup scheduler (checks every 60s; default interval = 60 mins).
                let sched_reg = registry.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(20));
                    loop {
                        let cfg = read_config();
                        if cfg.erp_backup_enabled
                            && !cfg.erp_backup_username.trim().is_empty()
                            && !cfg.erp_backup_password.is_empty()
                            && !ERP_BACKUP_RUNNING.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            let interval_ms = cfg.erp_backup_interval_mins.max(15) * 60_000;
                            let root = erp_backups_root_dir();
                            let latest_ok_ts = read_erp_backup_entries(&root)
                                .first()
                                .and_then(|v| v["created_at"].as_u64())
                                .unwrap_or(0);
                            let last_attempt_ts = erp_live_state()
                                .lock()
                                .map(|g| g.last_attempt_at)
                                .unwrap_or(0);
                            let now_t = now_ms();
                            // Enforce at least 10-minute retry cooldown if the previous attempt failed
                            let retry_cooldown_ok = now_t.saturating_sub(last_attempt_ts) >= 10 * 60_000;
                            if now_t.saturating_sub(latest_ok_ts) >= interval_ms && retry_cooldown_ok {
                                let _ = run_erp_site_backup_blocking("auto_hourly", Some(&sched_reg));
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                });
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
    let nosniff = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap();
    let refpol = Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap();
    Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(header)
        .with_header(nosniff)
        .with_header(refpol)
}

fn bytes_response(bytes: Vec<u8>, content_type: &[u8], status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(&b"Content-Type"[..], content_type).unwrap();
    let nosniff = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap();
    let frame = Header::from_bytes(&b"X-Frame-Options"[..], &b"SAMEORIGIN"[..]).unwrap();
    let refpol = Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap();
    let cc = Header::from_bytes(&b"Cache-Control"[..], &b"no-cache, must-revalidate"[..]).unwrap();
    Response::from_data(bytes)
        .with_status_code(status)
        .with_header(header)
        .with_header(nosniff)
        .with_header(frame)
        .with_header(refpol)
        .with_header(cc)
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
        let mut req_builder = http.get(&url);
        if !cfg.admin_key.trim().is_empty() {
            req_builder = req_builder.set("Authorization", &format!("Bearer {}", cfg.admin_key.trim()));
        }
        let Ok(resp) = req_builder.call() else { continue };
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
        "/" | "/index.html" | "/admin" | "/admin/" => {
            let html = include_str!("../../web/index.html")
                .replace(
                    "<script src=\"tauri-shim.js\"></script>",
                    "<script>window.__ITK_WEB_ADMIN__=true;</script><script src=\"tauri-shim.js?v=117\"></script>",
                )
                .replace(
                    "<script src=\"index.inline.js\"></script>",
                    "<script src=\"index.inline.js?v=117\"></script>",
                );
            Some((html.into_bytes(), b"text/html; charset=utf-8", 200))
        }
        "/manifest.webmanifest" => Some((include_bytes!("../../web/manifest.webmanifest").to_vec(), b"application/manifest+json; charset=utf-8", 200)),
        "/sw.js" => Some((include_bytes!("../../web/sw.js").to_vec(), b"application/javascript; charset=utf-8", 200)),
        "/theme.js" => Some((include_bytes!("../../web/theme.js").to_vec(), b"application/javascript; charset=utf-8", 200)),
        "/tauri-shim.js" => Some((include_bytes!("../../web/tauri-shim.js").to_vec(), b"application/javascript; charset=utf-8", 200)),
        "/index.inline.js" => Some((include_bytes!("../../web/index.inline.js").to_vec(), b"application/javascript; charset=utf-8", 200)),
        "/styles/theme.css" => Some((include_bytes!("../../web/styles/theme.css").to_vec(), b"text/css; charset=utf-8", 200)),
        "/styles/redesign.css" => Some((include_bytes!("../../web/styles/redesign.css").to_vec(), b"text/css; charset=utf-8", 200)),
        "/styles/dark.css" => Some((include_bytes!("../../web/styles/dark.css").to_vec(), b"text/css; charset=utf-8", 200)),
        "/assets/company-logo-tight.png" => Some((include_bytes!("../../web/assets/company-logo-tight.png").to_vec(), b"image/png", 200)),
        "/assets/company-logo.jpg" => Some((include_bytes!("../../web/assets/company-logo.jpg").to_vec(), b"image/jpeg", 200)),
        "/assets/apple-touch-icon.png" => Some((include_bytes!("../../web/assets/apple-touch-icon.png").to_vec(), b"image/png", 200)),
        "/assets/ipad-icon-167.png" => Some((include_bytes!("../../web/assets/ipad-icon-167.png").to_vec(), b"image/png", 200)),
        "/assets/pwa-icon-512.png" => Some((include_bytes!("../../web/assets/pwa-icon-512.png").to_vec(), b"image/png", 200)),
        "/favicon.ico" => Some((include_bytes!("../../web/assets/apple-touch-icon.png").to_vec(), b"image/png", 200)),
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
        "erp_domains": cfg.erp_domains,
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

fn find_admin_installer_path() -> Option<std::path::PathBuf> {
    let name = "IT ELKHAWGA Admin_1.0.0_x64-setup.exe";
    let candidates = [
        std::path::PathBuf::from(r"C:\Users\IT APP\Desktop\blockwebsite\final-release").join(name),
        std::path::PathBuf::from(r"C:\Users\IT APP\Desktop\tools").join(name),
        resource_dir().join(name),
        data_dir().join(name),
    ];
    for p in candidates {
        if let Ok(m) = std::fs::metadata(&p) {
            if m.is_file() && m.len() > 500_000 {
                return Some(p);
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
                .with_header(Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type, X-ITK-Client"[..]).unwrap())
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
            let has_csrf_hdr = req
                .headers()
                .iter()
                .any(|h| h.field.equiv("X-ITK-Client") && h.value.as_str().trim() == "1");
            if !has_csrf_hdr {
                let _ = req.respond(cors(json_response(json!({"success": false, "error": "missing X-ITK-Client header"}), 403)));
                return;
            }
            let mut body = String::new();
            let _ = req.as_reader().take(16_384).read_to_string(&mut body);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));
            let rd_id = parsed["rustdeskId"].as_str().unwrap_or("").to_string();
            let pw = parsed["password"].as_str().map(|s| s.to_string());
            let mode = parsed["mode"].as_str().map(|s| s.to_string());
            let dev_ip = parsed["deviceIp"].as_str().map(|s| s.to_string());
            let payload = match crate::commands::open_support_session_inner(rd_id, pw, mode, dev_ip) {
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

    // Serve authenticated Admin NSIS installer & update metadata over LAN server as fallback.
    if method == Method::Get && (path == "/api/v1/admin/update-info" || path == "/api/v1/admin/admin-setup.exe") {
        let cfg = read_config();
        let expected_auth = format!("Bearer {}", cfg.admin_key);
        let ok_auth = !cfg.admin_key.trim().is_empty()
            && req
                .headers()
                .iter()
                .any(|h| h.field.equiv("Authorization") && h.value.as_str() == expected_auth);
        if !ok_auth {
            let _ = req.respond(json_response(json!({"ok": false, "error": "unauthorized"}), 401));
            return;
        }
        let Some(installer_path) = find_admin_installer_path() else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "admin installer not found"}), 404));
            return;
        };
        let Ok(bytes) = std::fs::read(&installer_path) else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "read error"}), 500));
            return;
        };
        if path == "/api/v1/admin/update-info" {
            let mtime_ms = std::fs::metadata(&installer_path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let sha256_hex: String = Sha256::digest(&bytes).iter().map(|b| format!("{:02x}", b)).collect();
            let _ = req.respond(json_response(
                json!({
                    "ok": true,
                    "available": true,
                    "size": bytes.len(),
                    "mtime_ms": mtime_ms,
                    "sha256": sha256_hex,
                    "version": APP_VERSION,
                }),
                200,
            ));
        } else {
            let _ = req.respond(bytes_response(bytes, b"application/octet-stream", 200));
        }
        return;
    }

    // Serve archived uploaded DLP files — strictly authenticated with Admin JWT or Server Admin Key.
    if method == Method::Get && (path.starts_with("/api/uploads/") || path.starts_with("/api/v1/uploads/")) {
        let auth_result = authorize_upload_request(&req, &url, token);
        if let Err((code, msg)) = auth_result {
            let _ = req.respond(json_response(json!({"ok": false, "error": msg}), code));
            return;
        }
        let fid = path
            .strip_prefix("/api/v1/uploads/")
            .or_else(|| path.strip_prefix("/api/uploads/"))
            .unwrap_or("");
        let inline_mode = url.contains("inline=1");
        if let Some((orig_name, bytes)) = fetch_uploaded_file_bytes(fid) {
            let safe_ascii: String = orig_name
                .chars()
                .map(|c| if c.is_ascii() && c != '"' && c != '\r' && c != '\n' && c != '\\' && c != '/' { c } else { '_' })
                .collect();
            let utf8_enc = encode_rfc5987_component(&orig_name);
            let disp_kind = if inline_mode { "inline" } else { "attachment" };
            let disp = format!(
                "{}; filename=\"{}\"; filename*=UTF-8''{}",
                disp_kind,
                if safe_ascii.is_empty() { "file.bin" } else { &safe_ascii },
                utf8_enc
            );
            let ct = Header::from_bytes(&b"Content-Type"[..], mime_for_filename(&orig_name)).unwrap();
            let cd = Header::from_bytes(&b"Content-Disposition"[..], disp.as_bytes()).unwrap();
            let cors = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
            let nosniff = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap();
            let refpol = Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap();
            let mut resp_out = Response::from_data(bytes)
                .with_status_code(200)
                .with_header(ct)
                .with_header(cd)
                .with_header(cors)
                .with_header(nosniff)
                .with_header(refpol);
            if inline_mode {
                if let Ok(cc) = Header::from_bytes(&b"Cache-Control"[..], &b"private, max-age=86400"[..]) {
                    resp_out = resp_out.with_header(cc);
                }
            }
            let _ = req.respond(resp_out);
        } else {
            let _ = req.respond(json_response(json!({"error": "uploaded file not found"}), 404));
        }
        return;
    }

    // Serve pulled ERP website backup archives — strictly authenticated for Super Admin / Server Key.
    if method == Method::Get
        && (path.starts_with("/api/erp-backups/download/") || path.starts_with("/api/v1/erp-backups/download/"))
    {
        if let Err((code, msg)) = authorize_upload_request(&req, &url, token) {
            let _ = req.respond(json_response(json!({"ok": false, "error": msg}), code));
            return;
        }
        let fname = path
            .strip_prefix("/api/v1/erp-backups/download/")
            .or_else(|| path.strip_prefix("/api/erp-backups/download/"))
            .unwrap_or("");
        if let Some((clean_name, bytes)) = fetch_erp_backup_file_bytes(fname) {
            let disp = format!("attachment; filename=\"{}\"", clean_name);
            let ct = Header::from_bytes(&b"Content-Type"[..], b"application/octet-stream").unwrap();
            let cd = Header::from_bytes(&b"Content-Disposition"[..], disp.as_bytes()).unwrap();
            let cors = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
            let nosniff = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap();
            let _ = req.respond(
                Response::from_data(bytes)
                    .with_status_code(200)
                    .with_header(ct)
                    .with_header(cd)
                    .with_header(cors)
                    .with_header(nosniff),
            );
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "ملف النسخة الاحتياطية غير موجود"}), 404));
        }
        return;
    }

    // Proxy Dahua CCTV binary JPEG stream & incident clip download to local/remote Relay so Web/Desktop Admin on :8787 works natively.
    if method == Method::Get
        && (path == "/api/cctv/frame"
            || path == "/api/v1/cctv/frame"
            || path == "/api/cctv/clip"
            || path == "/api/v1/cctv/clip")
    {
        let is_clip = path.ends_with("/clip");
        let hdr_tok = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| {
                let v = h.value.as_str().trim();
                if v.get(..7).map_or(false, |p| p.eq_ignore_ascii_case("bearer ")) {
                    Some(v.get(7..).unwrap_or("").trim().to_string())
                } else {
                    None
                }
            });
        let q_tok = extract_query_param(&url, "token");
        let supplied = hdr_tok.or(q_tok).unwrap_or_default();
        let cfg = read_config();
        let admin_ok = !cfg.admin_key.trim().is_empty() && supplied == cfg.admin_key.trim();
        if !admin_ok && crate::auth::verify_jwt(&supplied).is_err() {
            let _ = req.respond(json_response(json!({"ok": false, "error": "unauthorized"}), 401));
            return;
        }
        let query_str = url.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut bases = vec!["http://127.0.0.1:8790".to_string()];
        let conf_relay = if cfg.relay_url.trim().is_empty() {
            DEFAULT_RELAY_URL.to_string()
        } else {
            cfg.relay_url.trim().trim_end_matches('/').to_string()
        };
        if !conf_relay.is_empty() && !bases.iter().any(|b| b == &conf_relay) {
            bases.push(conf_relay);
        }
        let http = tls_agent(if is_clip { 45 } else { 14 });
        let upstream_path = if is_clip { "/api/cctv/clip" } else { "/api/cctv/frame" };
        for base in bases {
            let target = if query_str.is_empty() {
                format!("{}{}", base, upstream_path)
            } else {
                format!("{}{}?{}", base, upstream_path, query_str)
            };
            let mut b = http.get(&target);
            if !cfg.admin_key.trim().is_empty() {
                b = b.set("Authorization", &format!("Bearer {}", cfg.admin_key.trim()));
            } else if !supplied.is_empty() {
                b = b.set("Authorization", &format!("Bearer {}", supplied));
            }
            match b.call() {
                Ok(resp) if resp.status() == 200 => {
                    let mime = resp.header("Content-Type").unwrap_or("application/octet-stream").to_string();
                    let cd_opt = resp.header("Content-Disposition").map(str::to_string);
                    let mut buf = Vec::new();
                    if resp.into_reader().take(12 * 1024 * 1024).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                        let ct = Header::from_bytes(&b"Content-Type"[..], mime.as_bytes()).unwrap();
                        let cc = Header::from_bytes(&b"Cache-Control"[..], &b"no-store, no-cache, must-revalidate"[..]).unwrap();
                        let cors = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
                        let mut r_out = Response::from_data(buf)
                            .with_status_code(200)
                            .with_header(ct)
                            .with_header(cc)
                            .with_header(cors);
                        if let Some(cd_str) = cd_opt {
                            if let Ok(cd_hdr) = Header::from_bytes(&b"Content-Disposition"[..], cd_str.as_bytes()) {
                                r_out = r_out.with_header(cd_hdr);
                            }
                        }
                        let _ = req.respond(r_out);
                        return;
                    }
                }
                Err(ureq::Error::Status(403, _)) => {
                    let _ = req.respond(json_response(
                        json!({"ok": false, "error": "تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط"}),
                        403,
                    ));
                    return;
                }
                _ => {}
            }
        }
        let _ = req.respond(json_response(json!({"ok": false, "error": "تعذر جلب البيانات من الكاميرا"}), 502));
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
        let client_ip = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Forwarded-For"))
            .and_then(|h| h.value.as_str().split(',').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| req.remote_addr().map(|a| a.ip().to_string()));
        let mut body = String::new();
        let _ = req.as_reader().take(262_144).read_to_string(&mut body);
        let handle = ServerHandle {
            registry: registry.clone(),
            port,
            token: token.to_string(),
        };
        let (status, payload) =
            crate::commands::dispatch_web_rpc(&handle, &body, auth_hdr.as_deref(), client_ip.as_deref());
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
            let mut alert = Alert {
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
            alert.meta = extract_and_save_lan_alert_media(&alert.id, &alert.meta);
            reg.alerts.push(alert);
            if reg.alerts.len() > 200 {
                let drop_n = reg.alerts.len() - 200;
                reg.alerts.drain(0..drop_n);
            }
            save_lan_alerts(&reg);
            prune_lan_alert_media_files(400);
        }

        reg.devices.insert(
            poll.device_id.clone(),
            Device {
                device_id: poll.device_id.clone(),
                hostname: poll.hostname.clone(),
                ip,
                blocked: poll.blocked,
                usb_blocked: poll.usb_blocked,
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
                    || prev.usb_blocked != cur.usb_blocked
                    || prev.mode != cur.mode
                    || prev.app_version != cur.app_version
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
                p["usb_block"] = json!(gp.usb_block || cfg.usb_block);
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

    let raw_sub = url.strip_prefix("/api/admin/").unwrap_or("");
    let path = raw_sub.split('?').next().unwrap_or(raw_sub);

    // Backups & Storage management over LAN / Relay proxy
    if method == &Method::Get && path == "drives" {
        let _ = req.respond(json_response(json!({"ok": true, "drives": list_server_drives()}), 200));
        return;
    }
    if method == &Method::Post && path == "archive/dir" {
        let np = body_val["new_path"].as_str().unwrap_or("");
        let mv = body_val["move_existing"].as_bool().unwrap_or(true);
        match change_server_archive_dir(np, mv) {
            Ok(v) => { let _ = req.respond(json_response(v, 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "success": false, "error": e}), 400)); }
        }
        return;
    }
    if method == &Method::Post && path == "backups/dir" {
        let np = body_val["new_path"].as_str().unwrap_or("");
        let mv = body_val["move_existing"].as_bool().unwrap_or(true);
        match change_server_backup_dir(np, mv) {
            Ok(v) => { let _ = req.respond(json_response(v, 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "success": false, "error": e}), 400)); }
        }
        return;
    }
    if method == &Method::Get && path == "backups" {
        let _ = req.respond(json_response(list_server_backups(), 200));
        return;
    }
    if method == &Method::Post && path == "backups/create" {
        let reason = body_val["reason"].as_str().unwrap_or("manual");
        match create_server_backup(reason) {
            Ok(v) => { let _ = req.respond(json_response(v, 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "success": false, "error": e}), 500)); }
        }
        return;
    }
    if method == &Method::Post && path == "backups/restore" {
        let bid = body_val["backup_id"].as_str().unwrap_or("");
        match restore_server_backup(bid, Some(registry)) {
            Ok(v) => { let _ = req.respond(json_response(v, 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "success": false, "error": e}), 400)); }
        }
        return;
    }
    if method == &Method::Get && path == "erp-backups" {
        let _ = req.respond(json_response(list_erp_backups(), 200));
        return;
    }
    if method == &Method::Post && path == "erp-backups/config" {
        match save_erp_backup_settings(&body_val) {
            Ok(v) => { let _ = req.respond(json_response(v, 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "success": false, "error": e}), 400)); }
        }
        return;
    }
    if method == &Method::Post && path == "erp-backups/run" {
        let reason = body_val["reason"].as_str().unwrap_or("manual");
        match trigger_erp_site_backup(reason, Some(registry.clone())) {
            Ok(v) => { let _ = req.respond(json_response(v, 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "success": false, "error": e}), 400)); }
        }
        return;
    }
    if method == &Method::Post && path == "erp-backups/dir" {
        let np = body_val["new_path"].as_str().unwrap_or("");
        let mv = body_val["move_existing"].as_bool().unwrap_or(true);
        match change_erp_backup_dir(np, mv) {
            Ok(v) => { let _ = req.respond(json_response(v, 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "success": false, "error": e}), 400)); }
        }
        return;
    }
    if method == &Method::Post && path.starts_with("groups/") && path.ends_with("/command") {
        let group_id = path.strip_prefix("groups/").unwrap().strip_suffix("/command").unwrap();
        let command = body_val["command"].as_str().unwrap_or("").to_string();
        let actor = body_val["actor"].as_str().unwrap_or("admin");
        let role = body_val["actor_role"].as_str().unwrap_or("admin");
        let handle = ServerHandle {
            registry: registry.clone(),
            port: 8787,
            token: String::new(),
        };
        match handle.send_group_command(group_id.to_string(), command, actor, role) {
            Ok(n) => { let _ = req.respond(json_response(json!({"ok": true, "queued": n}), 200)); }
            Err(e) => { let _ = req.respond(json_response(json!({"ok": false, "error": e}), 404)); }
        }
        return;
    }

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
    if method == &Method::Get && path.starts_with("alerts/") && !path.ends_with("/ack") {
        let alert_id = path.strip_prefix("alerts/").unwrap_or("").trim();
        let fallback_meta = {
            let reg = registry.lock().unwrap();
            reg.alerts
                .iter()
                .find(|a| a.id == alert_id)
                .map(|a| a.meta.clone())
        };
        if let Some((sc, cam)) = read_lan_alert_media(alert_id, fallback_meta.as_deref()) {
            let _ = req.respond(json_response(
                json!({
                    "ok": true,
                    "id": alert_id,
                    "screenshot": sc,
                    "camera_photo": cam,
                }),
                200,
            ));
        } else {
            let _ = req.respond(json_response(json!({"ok": false, "error": "not found"}), 404));
        }
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
                "usb_blocked": d.usb_blocked,
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
            "usb_block" => "usb_block",
            "usb_unblock" => "usb_unblock",
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
            if let Some(d) = reg.devices.get_mut(&id) {
                if command_type == "block" { d.blocked = true; }
                else if command_type == "unblock" { d.blocked = false; }
                else if command_type == "usb_block" { d.usb_blocked = true; }
                else if command_type == "usb_unblock" { d.usb_blocked = false; }
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
                    "usb_block": policy.as_ref().map(|p| p.usb_block).unwrap_or(false),
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
                usb_block: body_val["usb_block"].as_bool().unwrap_or(false),
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
                || body_val["usb_block"].is_boolean()
            {
                let mut policy = reg.group_policies.get(gid).cloned().unwrap_or(GroupPolicy {
                    version: rid("gv_"),
                    mode: "whitelist".into(),
                    allowed: vec![],
                    blocked: vec![],
                    ephemeral_browser: false,
                    usb_block: false,
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
                if let Some(ub) = body_val["usb_block"].as_bool() {
                    policy.usb_block = ub;
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
            "usb_block" => "usb_block",
            "usb_unblock" => "usb_unblock",
            "update_client" => "update_client",
            _ => { let _ = req.respond(json_response(json!({"ok": false, "error": "invalid command"}), 400)); return; }
        };
        let targets: Vec<_> = reg.devices.values().filter(|d| d.group_id == gid).map(|d| d.device_id.clone()).collect();
        let mut count = 0;
        for id in targets {
            reg.pending.insert(id.clone(), command_type.to_string());
            if let Some(d) = reg.devices.get_mut(&id) {
                if command_type == "block" { d.blocked = true; }
                else if command_type == "unblock" { d.blocked = false; }
                else if command_type == "usb_block" { d.usb_blocked = true; }
                else if command_type == "usb_unblock" { d.usb_blocked = false; }
            }
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
        let valid = command == "block" || command == "unblock"
            || command == "usb_block" || command == "usb_unblock"
            || command.starts_with("throttle:")
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
                    else if command == "usb_block" { d.usb_blocked = true; }
                    else if command == "usb_unblock" { d.usb_blocked = false; }
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
                else if command == "usb_block" { d.usb_blocked = true; }
                else if command == "usb_unblock" { d.usb_blocked = false; }
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
                "usb_block": policy.as_ref().map(|p| p.usb_block).unwrap_or(false),
            })
        }).collect()
    }

    pub fn create_group(&self, name: String, mode: String, allowed: Vec<String>, blocked: Vec<String>, ephemeral_browser: bool, usb_block: bool) -> Result<serde_json::Value, String> {
        let mut reg = self.registry.lock().unwrap();
        let gid = rid("grp_");
        let group = Group { id: gid.clone(), name: name.clone(), created_at: now() };
        let policy = GroupPolicy {
            version: rid("gv_"),
            mode: if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() },
            allowed,
            blocked,
            ephemeral_browser,
            usb_block,
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
            "usb_block": policy.usb_block,
        }))
    }

    pub fn update_group(&self, group_id: String, name: String, mode: String, allowed: Vec<String>, blocked: Vec<String>, ephemeral_browser: bool, usb_block: bool) -> Result<serde_json::Value, String> {
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
            usb_block: false,
            updated_at: now(),
        });
        policy.mode = if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() };
        policy.allowed = allowed;
        policy.blocked = blocked;
        policy.ephemeral_browser = ephemeral_browser;
        policy.usb_block = usb_block;
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
            "usb_block": policy.usb_block,
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
        let fallback_meta = {
            let reg = self.registry.lock().unwrap();
            reg.alerts
                .iter()
                .find(|a| a.id == alert_id)
                .map(|a| a.meta.clone())
        };
        let (sc, cam) = read_lan_alert_media(alert_id, fallback_meta.as_deref())?;
        Some(json!({
            "ok": true,
            "id": alert_id,
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
            save_lan_alerts(&reg);
            Ok(())
        } else {
            Err("alert not found".into())
        }
    }

    pub fn ack_all_alerts(&self, alert_type: Option<String>) -> usize {
        let mut reg = self.registry.lock().unwrap();
        let tf = alert_type.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let ts = now();
        let mut count = 0usize;
        for a in reg.alerts.iter_mut() {
            if a.acked_at.is_some() {
                continue;
            }
            if let Some(ref t) = tf {
                if &a.alert_type != t {
                    continue;
                }
            }
            a.acked_at = Some(ts);
            a.acked_by = Some("admin".into());
            a.acked = true;
            count += 1;
        }
        if count > 0 {
            save_lan_alerts(&reg);
        }
        count
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
            "usb_block" => "usb_block",
            "usb_unblock" => "usb_unblock",
            "update_client" => "update_client",
            _ => return Err("invalid command".into()),
        };
        let audit_act = match cmd_type {
            "block" => "group_block",
            "unblock" => "group_unblock",
            "usb_block" => "group_usb_block",
            "usb_unblock" => "group_usb_unblock",
            "update_client" => "group_update_client",
            _ => "group_command",
        };
        let targets: Vec<_> = reg.devices.values().filter(|d| d.group_id == group_id).map(|d| d.device_id.clone()).collect();
        let mut count = 0;
        for id in targets {
            reg.pending.insert(id.clone(), cmd_type.to_string());
            if let Some(d) = reg.devices.get_mut(&id) {
                if cmd_type == "block" { d.blocked = true; }
                else if cmd_type == "unblock" { d.blocked = false; }
                else if cmd_type == "usb_block" { d.usb_blocked = true; }
                else if cmd_type == "usb_unblock" { d.usb_blocked = false; }
            }
            count += 1;
            record_audit(&mut reg, actor, audit_act, Some(&id), "queued", actor_role);
        }
        save_lan_devices(&reg);
        Ok(count)
    }
}

/// Audit-log action name for a device command.
fn command_audit_action(command: &str) -> &'static str {
    match command {
        "block" => "device_block",
        "unblock" => "device_unblock",
        "usb_block" => "device_usb_block",
        "usb_unblock" => "device_usb_unblock",
        "restart" => "device_restart",
        "shutdown" => "device_shutdown",
        "cancel_power" => "device_cancel_power",
        "update_client" => "device_update_client",
        _ => "device_throttle",
    }
}

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            let dec = percent_decode_utf8(v);
            if !dec.trim().is_empty() {
                return Some(dec.trim().to_string());
            }
        }
    }
    None
}

pub(crate) fn verify_upload_token(supplied_tok: &str, server_token: &str) -> Result<(), (u16, &'static str)> {
    let tok = supplied_tok.trim();
    if tok.is_empty() {
        return Err((401, "يرجى تسجيل الدخول بحساب المدير لتحميل الملفات المؤرشفة"));
    }
    let cfg = read_config();
    if (!cfg.admin_key.trim().is_empty() && tok == cfg.admin_key.trim())
        || (!server_token.trim().is_empty() && tok == server_token.trim())
    {
        return Ok(());
    }
    if let Ok(claims) = crate::auth::verify_jwt(tok) {
        let role = normalize_admin_role(&claims.role);
        if cfg.dlp_super_only && role != "super" {
            return Err((403, "تم حصر تحميل ملفات الأرشيف الحساسة بحساب السوبر أدمن فقط"));
        }
        return Ok(());
    }
    Err((401, "انتهت الجلسة أو التوكين غير صالح — يرجى تسجيل الدخول مجدداً"))
}

fn authorize_upload_request(req: &Request, url: &str, server_token: &str) -> Result<(), (u16, &'static str)> {
    let hdr_tok = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| {
            let v = h.value.as_str().trim();
            if v.get(..7).map_or(false, |p| p.eq_ignore_ascii_case("bearer ")) {
                Some(v.get(7..).unwrap_or("").trim().to_string())
            } else {
                None
            }
        });
    let tok = hdr_tok.or_else(|| extract_query_param(url, "token")).unwrap_or_default();
    verify_upload_token(&tok, server_token)
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
        assert_eq!(serve_web_asset("/favicon.ico").map(|x| x.2), Some(200));
        assert!(serve_web_asset("/manifest.webmanifest").is_some());
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
            None,
        );
        assert_eq!(st, 401);
        assert!(info["result"].is_null());

        let (st_unauth, _) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_devices","args":{}}"#,
            None,
            None,
        );
        assert_eq!(st_unauth, 401);

        let admin_jwt = crate::auth::make_jwt("eng1", "admin").expect("admin jwt");
        let admin_hdr = format!("Bearer {}", admin_jwt);
        let (st_admin, info_admin) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_server_info","args":{}}"#,
            Some(&admin_hdr),
            None,
        );
        assert_eq!(st_admin, 200);
        assert_eq!(info_admin["result"]["token"], "secret-lan-token");

        let jwt = crate::auth::make_jwt("tester", "viewer").expect("jwt");
        let hdr = format!("Bearer {}", jwt);

        let (st_auth, info_auth) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_server_info","args":{}}"#,
            Some(&hdr),
            None,
        );
        assert_eq!(st_auth, 200);
        assert_eq!(info_auth["result"]["token"], "");

        let (st_dev, _) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"get_devices","args":{}}"#,
            Some(&hdr),
            None,
        );
        assert_eq!(st_dev, 200);

        let (st_viewer_mut, viewer_res) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"add_site","args":{"site":"example.com"}}"#,
            Some(&hdr),
            None,
        );
        assert_eq!(st_viewer_mut, 200);
        assert_eq!(viewer_res["result"]["success"], false);

        let (_, viewer_ack) = crate::commands::dispatch_web_rpc(
            &handle,
            r#"{"cmd":"ack_all_alerts","args":{}}"#,
            Some(&hdr),
            None,
        );
        assert_eq!(viewer_ack["result"]["success"], false);
    }

    #[test]
    fn security_pbkdf2_upload_auth_and_login_rate_limit() {
        let h = crate::common::hash_admin_password("StrongP@ss2026!");
        assert!(h.starts_with("pbkdf2$100000$"));
        assert!(crate::common::verify_password_hash("StrongP@ss2026!", &h));
        assert!(!crate::common::verify_password_hash("WrongPass", &h));

        let legacy = crate::common::hash_password("Legacy123");
        assert!(crate::common::verify_password_hash("Legacy123", &legacy));
        assert!(!crate::common::verify_password_hash("Other", &legacy));

        assert_eq!(verify_upload_token("", "lan-tok").unwrap_err().0, 401);
        assert_eq!(verify_upload_token("forged.jwt.tok", "lan-tok").unwrap_err().0, 401);
        let valid_jwt = crate::auth::make_jwt("superadmin", "super").expect("jwt");
        assert!(verify_upload_token(&valid_jwt, "lan-tok").is_ok());

        let test_key = "198.51.100.77|brutetest";
        for i in 0..5 {
            let locked = crate::commands::record_login_result(test_key, "brutetest", "198.51.100.77", false);
            assert_eq!(locked, i == 4);
        }
        assert!(crate::commands::check_login_lockout(test_key).is_some());
        crate::commands::record_login_result(test_key, "brutetest", "198.51.100.77", true);
        assert!(crate::commands::check_login_lockout(test_key).is_none());
    }

    #[test]
    fn archive_dir_normalization_and_disk_space() {
        assert_eq!(
            normalize_archive_dir_path(r"D:\").unwrap(),
            std::path::PathBuf::from(r"D:\IT-ELKHAWGA-Archive")
        );
        assert_eq!(
            normalize_archive_dir_path("E:/MyArchive/").unwrap(),
            std::path::PathBuf::from(r"E:\MyArchive")
        );
        assert!(normalize_archive_dir_path(r"C:\Windows").is_err());
        let (free_b, total_b) = disk_space_for_path(std::path::Path::new(r"C:\"));
        assert!(total_b > 0 && free_b > 0);
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

    #[test]
    fn rustdesk_custom_server_toml_sets_and_clears_options() {
        let initial = "id = '123456789'\n\n[options]\naccess-mode = 'full'\n";
        let set_oss = crate::common::sync_rustdesk_custom_server_toml(
            initial,
            "192.168.20.164:21116",
            "PUBKEY123=",
        );
        assert!(set_oss.contains("id = '123456789'"));
        assert!(set_oss.contains("access-mode = 'full'"));
        assert!(set_oss.contains("custom-rendezvous-server = '192.168.20.164'"));
        assert!(set_oss.contains("relay-server = '192.168.20.164'"));
        assert!(set_oss.contains("key = 'PUBKEY123='"));

        let cleared = crate::common::sync_rustdesk_custom_server_toml(&set_oss, "", "");
        assert!(cleared.contains("id = '123456789'"));
        assert!(cleared.contains("access-mode = 'full'"));
        assert!(!cleared.contains("custom-rendezvous-server"));
        assert!(!cleared.contains("relay-server"));
        assert!(!cleared.contains("PUBKEY123="));
    }

    #[test]
    fn erp_form_extraction_and_archive_integrity_verifier() {
        let sample_create_html = r#"
            <html><body>
              <form action="/accounts/logout/" method="post"><input type="hidden" name="csrfmiddlewaretoken" value="wrong"></form>
              <form method="post">
                <input type="hidden" name="csrfmiddlewaretoken" value="csrf_tok_12345">
                <input type="text" name="name" value="نسخة احتياطية كاملة 2026-11-22_07-02">
                <textarea name="description"></textarea>
                <select name="backup_type">
                  <option value="partial">نسخة جزئية</option>
                  <option value="full" selected>نسخة كاملة</option>
                </select>
                <button type="submit">إنشاء النسخة الاحتياطية</button>
              </form>
            </body></html>
        "#;
        let (act, fields) = extract_create_backup_form(
            sample_create_html,
            "/backup-system/backups/create/",
            "ITK_Auto_2026-11-22_07-00-00",
        );
        assert_eq!(act, "/backup-system/backups/create/");
        assert!(fields.contains(&("csrfmiddlewaretoken".into(), "csrf_tok_12345".into())));
        assert!(fields.contains(&("name".into(), "ITK_Auto_2026-11-22_07-00-00".into())));
        assert!(fields.contains(&("backup_type".into(), "full".into())));

        // Reject HTML login page masquerading as backup download
        let html_fake = vec![b'<'; 128];
        assert!(verify_backup_payload(&html_fake, "text/html; charset=utf-8", "").is_err());

        // Reject truncated ZIP (missing EOCD PK\x05\x06)
        let mut bad_zip = b"PK\x03\x04".to_vec();
        bad_zip.extend_from_slice(&[0u8; 100]);
        assert!(verify_backup_payload(&bad_zip, "application/zip", "filename=\"bk.zip\"").is_err());

        // Accept valid ZIP with EOCD
        let mut good_zip = b"PK\x03\x04".to_vec();
        good_zip.extend_from_slice(&[0u8; 80]);
        good_zip.extend_from_slice(b"PK\x05\x06");
        good_zip.extend_from_slice(&[0u8; 18]);
        let (fmt, ext) = verify_backup_payload(&good_zip, "application/zip", "attachment; filename=\"bk.zip\"").unwrap();
        assert_eq!(ext, ".zip");
        assert!(fmt.contains("ZIP"));

        // Verify ErpHttpSession configures SChannel TLS backend (never fails with "no TLS backend")
        let mut sess = ErpHttpSession::new("https://127.0.0.1:1", "test_did");
        let err_msg = sess.get_html("/accounts/login/").unwrap_err();
        assert!(
            !err_msg.contains("no TLS backend"),
            "ErpHttpSession missing TLS backend: {}",
            err_msg
        );

        // Verify extract_erp_backup_links never panics when start + 512 lands inside multi-byte Arabic UTF-8
        let arabic_pad = "نسخة احتياطية كاملة لشركة الخواجة ".repeat(30);
        let tricky_html = format!(
            r#"<a href="/backup-system/backups/42/download/">تحميل</a><div>{}</div>"#,
            arabic_pad
        );
        let (dls, _) = extract_erp_backup_links(&tricky_html);
        assert_eq!(dls, vec!["/backup-system/backups/42/download/".to_string()]);
    }
}
