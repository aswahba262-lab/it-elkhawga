//! Tauri commands exposed to the web UI (see web/tauri-shim.js for the exact call surface).
//! Admin commands talk to the in-process LAN server (server.rs) or the managed relay;
//! client commands apply changes through the SYSTEM agent's local API when possible.

use crate::common::*;
use crate::server::{ServerHandle, DeviceView};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

#[derive(Clone, Serialize)]
pub struct Status {
    blocked: bool,
    mode: String,
    connected: bool,
    hostname: String,
    ip: String,
}

pub struct AppState {
    pub server: Mutex<Option<ServerHandle>>,
}

/// The web UI checks `r.success` on every mutating command, so results are wrapped
/// here instead of relying on a rejected promise (which the UI reports as an error toast).
fn ok() -> Value {
    json!({"success": true})
}
fn fail(e: impl ToString) -> Value {
    json!({"success": false, "error": e.to_string()})
}
fn result(r: Result<(), String>) -> Value {
    match r {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

fn with_server<F, T>(state: &AppState, f: F) -> Result<T, String>
where
    F: FnOnce(&ServerHandle) -> Result<T, String>,
{
    let guard = state.server.lock().unwrap();
    match guard.as_ref() {
        Some(s) => f(s),
        None => Err("السيرفر المحلي غير متاح".into()),
    }
}

// ---------- Status / mode ----------

/// The UI treats this as a plain boolean (`isBlocked = await api.getStatus()`).
#[tauri::command]
pub fn get_status() -> bool {
    is_blocked()
}

#[tauri::command]
pub fn get_status_detail() -> Status {
    Status {
        blocked: is_blocked(),
        mode: read_config().mode,
        connected: true,
        hostname: hostname(),
        ip: local_ip(),
    }
}

#[tauri::command]
pub fn get_mode() -> String {
    app_mode()
}

// ---------- Blocking ----------

#[tauri::command]
pub fn block_internet(actor_username: Option<String>, actor_role: Option<String>) -> Value {
    let actor = actor_username.unwrap_or_default();
    let role = actor_role.unwrap_or_default();
    let r = block_internet_inner(&actor, &role);
    match r {
        Ok(_) => json!({"success": true}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn block_internet_inner(actor: &str, role: &str) -> Result<(), String> {
    let cfg = read_config();
    // Always try the SYSTEM agent first: it is the only context that can apply the
    // block unattended and it owns the local proxy.
    let agent = tls_agent(20);
    match agent
        .post(&format!("http://{}/local/block", LOCAL_API_ADDR))
        .send_json(json!({}))
    {
        Ok(r) => {
            let v: Value = r.into_json().map_err(|e| e.to_string())?;
            if v["success"].as_bool().unwrap_or(false) {
                log_action(&format!("BLOCK (local) - success by {} ({})", actor.trim(), role.trim()));
                return Ok(());
            }
            return Err(v["error"].as_str().unwrap_or("فشل الحجب").to_string());
        }
        Err(_) => { /* agent not reachable - fall back to direct elevation */ }
    }
    // No agent running (dev machine or agent task missing).
    if cfg.password_hash.is_empty() {
        run_script_elevated("block-internet.ps1", None)?;
        set_block_state(true);
        log_action(&format!("BLOCK (local) - success by {} ({})", actor.trim(), role.trim()));
        return Ok(());
    }
    Err("الوكيل غير متاح. تأكد من تثبيت نسخة العميل/الوكيل على الجهاز أو أعد تشغيله".into())
}

#[tauri::command]
pub fn unblock_internet(password: Option<String>, actor_username: Option<String>, actor_role: Option<String>) -> Value {
    let actor = actor_username.unwrap_or_default();
    let role = actor_role.unwrap_or_default();
    match unblock_internet_inner(password.unwrap_or_default(), &actor, &role) {
        Ok(_) => json!({"success": true}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn unblock_internet_inner(supplied: String, actor: &str, role: &str) -> Result<(), String> {
    let cfg = read_config();
    if !cfg.password_hash.is_empty() && !password_ok(&cfg, &supplied) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        log_action("UNBLOCK refused - wrong password");
        return Err("كلمة السر غير صحيحة".into());
    }
    let agent = tls_agent(20);
    match agent
        .post(&format!("http://{}/local/unblock", LOCAL_API_ADDR))
        .send_json(json!({ "password": supplied }))
    {
        Ok(r) => {
            let v: Value = r.into_json().map_err(|e| e.to_string())?;
            if v["success"].as_bool().unwrap_or(false) {
                log_action(&format!("UNBLOCK (local) - success by {} ({})", actor.trim(), role.trim()));
                return Ok(());
            }
            return Err(v["error"].as_str().unwrap_or("فشل الفتح").to_string());
        }
        Err(_) => { /* agent not reachable - fall back to direct elevation */ }
    }
    if cfg.password_hash.is_empty() {
        run_script_elevated("allow-internet.ps1", None)?;
        set_block_state(false);
        log_action(&format!("UNBLOCK (local) - success by {} ({})", actor.trim(), role.trim()));
        return Ok(());
    }
    Err("الوكيل غير متاح. تأكد من تثبيت نسخة العميل/الوكيل على الجهاز أو أعد تشغيله".into())
}

// ---------- Site lists ----------

#[tauri::command]
pub fn get_allowed_sites() -> Vec<String> {
    read_list(&allowed_path())
}

#[tauri::command]
pub fn get_blocked_sites() -> Vec<String> {
    read_list(&blocked_path())
}

#[tauri::command]
pub fn add_site(site: String) -> Value {
    result((|| {
        let domain = clean_domain(&site).ok_or_else(|| "اسم موقع غير صالح".to_string())?;
        let mut items = read_list(&allowed_path());
        if !items.contains(&domain) {
            items.push(domain);
        }
        write_list(&allowed_path(), "Allowed sites", &items)
    })())
}

#[tauri::command]
pub fn remove_site(site: String) -> Value {
    let items: Vec<String> = read_list(&allowed_path()).into_iter().filter(|s| *s != site).collect();
    result(write_list(&allowed_path(), "Allowed sites", &items))
}

#[tauri::command]
pub fn add_blocked_site(site: String) -> Value {
    result((|| {
        let domain = clean_domain(&site).ok_or_else(|| "اسم موقع غير صالح".to_string())?;
        let mut items = read_list(&blocked_path());
        if !items.contains(&domain) {
            items.push(domain);
        }
        write_list(&blocked_path(), "Blocked sites", &items)
    })())
}

#[tauri::command]
pub fn remove_blocked_site(site: String) -> Value {
    let items: Vec<String> = read_list(&blocked_path()).into_iter().filter(|s| *s != site).collect();
    result(write_list(&blocked_path(), "Blocked sites", &items))
}

// ---------- Config / settings ----------

#[tauri::command]
pub fn get_config() -> Value {
    let cfg = read_config();
    json!({
        "mode": cfg.mode,
        "auto_start": cfg.auto_start,
        "has_password": !cfg.password_hash.is_empty(),
        "server_port": cfg.server_port,
        "relay_url": cfg.relay_url,
        "usb_block": cfg.usb_block,
        "exfil_threshold_mb": cfg.exfil_threshold_mb,
        "exfil_window_secs": cfg.exfil_window_secs,
        "exfil_suspicious": cfg.exfil_suspicious,
        "rustdesk_server": cfg.rustdesk_server,
        "rustdesk_key": cfg.rustdesk_key,
        "api_token": cfg.api_token,
    })
}

#[tauri::command]
pub fn set_list_mode(mode: String) -> Value {
    let mut cfg = read_config();
    cfg.mode = if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() };
    result(write_config(&cfg))
}

#[tauri::command]
pub fn toggle_autostart(enable: bool) -> Value {
    let script = if enable { "enable-autostart.ps1" } else { "disable-autostart.ps1" };
    let mut cfg = read_config();
    cfg.auto_start = enable;
    if let Err(e) = write_config(&cfg) {
        return fail(e);
    }
    result(if is_admin_mode() {
        run_script_elevated(script, None)
    } else {
        run_script(script, &[])
    })
}

#[tauri::command]
pub fn set_password(current_password: Option<String>, new_password: Option<String>) -> Value {
    let mut cfg = read_config();
    if !cfg.password_hash.is_empty() {
        let cur = current_password.unwrap_or_default();
        if !password_ok(&cfg, &cur) {
            std::thread::sleep(std::time::Duration::from_secs(1));
            return fail("كلمة السر الحالية غير صحيحة");
        }
    }
    let new = new_password.unwrap_or_default();
    if new.trim().is_empty() {
        cfg.password_hash = String::new();
    } else {
        cfg.password_hash = hash_password(&new);
    }
    result(write_config(&cfg))
}

#[tauri::command]
pub fn get_admin_users() -> Vec<Value> {
    let cfg = read_config();
    if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
        if let Ok(v) = relay_request("/api/v1/admin/users", "GET", None) {
            if let Some(users) = v["users"].as_array() {
                if !users.is_empty() {
                    return users.clone();
                }
            }
        }
    }
    cfg.admins
        .into_iter()
        .map(|u| json!({ "username": u.username, "role": normalize_admin_role(&u.role) }))
        .collect()
}

#[tauri::command]
pub fn upsert_admin_user(username: String, password: String, role: Option<String>, actor_username: Option<String>, actor_role: Option<String>) -> Value {
    let username = username.trim();
    if username.is_empty() {
        return fail("اسم المدير مطلوب");
    }

    let cfg = read_config();
    let actor = actor_username.unwrap_or_default();
    let actor_role_name = actor_role.unwrap_or_default();
    if !cfg.admins.is_empty() && !can_manage_admin_users(&cfg, &actor, &actor_role_name) {
        return fail("فقط السوبر أدمن يمكنه إدارة حسابات المديرين");
    }

    let mut cfg = cfg;
    let mut normalized_role = normalize_admin_role(role.as_deref().unwrap_or("admin"));
    if normalized_role.is_empty() {
        normalized_role = "admin".to_string();
    }

    if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
        let relay_result = relay_request(
            "/api/v1/admin/users",
            "POST",
            Some(&json!({
                "username": username,
                "password": password,
                "role": normalized_role,
                "actor_username": actor,
                "actor_role": actor_role_name,
            })),
        );
        if relay_result.is_ok() {
            // Keep the local config in sync for offline access and for the old single-machine flow.
        } else if !cfg.admins.is_empty() || cfg.password_hash.is_empty() {
            // Relay sync failure is ignored to keep the local manager path working.
        }
    }

    if let Some(existing) = cfg.admins.iter_mut().find(|u| u.username.eq_ignore_ascii_case(username)) {
        if !password.trim().is_empty() {
            existing.password_hash = hash_password(password.trim());
        }
        existing.role = normalized_role;
    } else {
        cfg.admins.push(AdminUser {
            username: username.to_string(),
            password_hash: if password.trim().is_empty() { String::new() } else { hash_password(password.trim()) },
            role: normalized_role,
        });
    }

    match write_config(&cfg) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub fn remove_admin_user(username: String, actor_username: Option<String>, actor_role: Option<String>) -> Value {
    let username = username.trim();
    if username.is_empty() {
        return fail("اسم المدير مطلوب");
    }

    let cfg = read_config();
    let actor = actor_username.unwrap_or_default();
    let actor_role_name = actor_role.unwrap_or_default();
    if !cfg.admins.is_empty() && !can_manage_admin_users(&cfg, &actor, &actor_role_name) {
        return fail("فقط السوبر أدمن يمكنه إدارة حسابات المديرين");
    }

    if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
        let encoded = username.replace(' ', "%20").replace('/', "%2F");
        let _ = relay_delete(&format!("/api/v1/admin/users/{}", encoded));
    }

    let mut cfg = cfg;
    let before = cfg.admins.len();
    cfg.admins.retain(|u| !u.username.eq_ignore_ascii_case(username));

    if cfg.admins.len() == before {
        return fail("المستخدم غير موجود");
    }

    match write_config(&cfg) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub fn admin_login(username: String, password: String) -> Value {
    let username = username.trim();
    if username.is_empty() {
        return fail("اسم المستخدم مطلوب");
    }

    let cfg = read_config();
    match admin_login_ok(&cfg, username, &password) {
        Some(role) => json!({
            "success": true,
            "username": username,
            "role": normalize_admin_role(&role),
            "is_super_admin": normalize_admin_role(&role) == "super",
        }),
        None => {
            let relay_cfg = read_config();
            if !relay_cfg.relay_url.trim().is_empty() && !relay_cfg.admin_key.trim().is_empty() {
                match relay_request(
                    "/api/v1/admin/login",
                    "POST",
                    Some(&json!({ "username": username, "password": password })),
                ) {
                    Ok(v) => {
                        if v["success"].as_bool().unwrap_or(false) {
                            let role = v["role"].as_str().unwrap_or("admin");
                            return json!({
                                "success": true,
                                "username": username,
                                "role": normalize_admin_role(role),
                                "is_super_admin": normalize_admin_role(role) == "super",
                            });
                        }
                    }
                    Err(_) => {}
                }
            }
            fail("اسم المستخدم أو كلمة المرور غير صحيحة")
        }
    }
}

// ---------- Logs ----------

#[tauri::command]
pub fn get_logs() -> String {
    read_log()
}

// ---------- LAN server (admin machine) ----------

#[tauri::command]
pub fn get_server_info(state: tauri::State<AppState>) -> Value {
    let guard = state.server.lock().unwrap();
    match guard.as_ref() {
        Some(s) => json!({
            "port": s.port,
            "token": s.token,
            "ip": local_ip(),
        }),
        None => json!({ "port": 0, "token": "", "ip": local_ip() }),
    }
}

/// Same field set the relay returns, so the admin UI can render one table for both transports.
fn device_to_json(d: &DeviceView) -> Value {
    json!({
        "device_id": d.device.device_id,
        "hostname": d.device.hostname,
        "ip": d.device.ip,
        "blocked": d.device.blocked,
        "mode": d.device.mode,
        "app_version": d.device.app_version,
        "last_seen": d.device.last_seen,
        "online": d.online,
        "rustdesk_id": d.device.rustdesk_id,
        "rustdesk_password": d.device.rustdesk_password,
        "throttle_kbps": d.device.throttle_kbps,
        "sites": d.device.sites,
        "denied": d.device.denied,
        "group_id": d.device.group_id,
        "label": d.device.label,
        "last_event": d.device.last_event,
        "last_event_at": d.device.last_event_at,
        "screen_requested": d.device.screen_requested,
        "transport": "lan",
    })
}

#[tauri::command]
pub fn get_devices(state: tauri::State<AppState>) -> Vec<Value> {
    let guard = state.server.lock().unwrap();
    match guard.as_ref() {
        Some(s) => s.devices().iter().map(device_to_json).collect(),
        None => Vec::new(),
    }
}

#[tauri::command]
pub fn send_device_command(
    state: tauri::State<AppState>,
    device_id: String,
    command: String,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let actor = actor_username.unwrap_or_default();
    let role = actor_role.unwrap_or_default();
    result(with_server(&state, |s| s.send_command(&device_id, &command, &actor, &role)))
}

/// True when the device is currently registered on the local LAN server.
fn is_lan_device(state: &AppState, device_id: &str) -> bool {
    let guard = state.server.lock().unwrap();
    guard
        .as_ref()
        .map(|s| s.devices().iter().any(|d| d.device.device_id == device_id))
        .unwrap_or(false)
}

// ---------- Relay (managed cloud link) ----------

#[tauri::command]
pub fn get_relay_config() -> Value {
    let cfg = read_config();
    json!({
        "relay_url": cfg.relay_url,
        "admin_key": cfg.admin_key,
        "has_admin_key": !cfg.admin_key.trim().is_empty(),
        "has_password": !cfg.password_hash.is_empty(),
        "rustdesk_server": cfg.rustdesk_server,
        "rustdesk_key": cfg.rustdesk_key,
        "has_rustdesk_password": !cfg.rustdesk_password.trim().is_empty(),
    })
}

#[tauri::command]
pub fn set_relay_config(
    relay_url: String,
    admin_key: Option<String>,
    current_password: Option<String>,
    rustdesk_server: Option<String>,
    rustdesk_key: Option<String>,
    rustdesk_password: Option<String>,
) -> Value {
    let mut cfg = read_config();
    if !cfg.password_hash.is_empty() && !password_ok(&cfg, &current_password.unwrap_or_default()) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        return fail("كلمة السر غير صحيحة");
    }
    cfg.relay_url = relay_url.trim().trim_end_matches('/').to_string();
    if let Some(k) = admin_key {
        if !k.trim().is_empty() {
            cfg.admin_key = k.trim().to_string();
        }
    }
    if let Some(s) = rustdesk_server {
        cfg.rustdesk_server = s.trim().to_string();
    }
    if let Some(k) = rustdesk_key {
        cfg.rustdesk_key = k.trim().to_string();
    }
    if let Some(p) = rustdesk_password {
        if !p.trim().is_empty() {
            cfg.rustdesk_password = p.trim().to_string();
        }
    }
    if let Err(e) = write_config(&cfg) {
        return fail(e);
    }
    // Push the RustDesk settings to every device on the next policy sync.
    let _ = relay_request("/api/v1/admin/policy", "PUT", Some(&json!({
        "rustdesk_server": cfg.rustdesk_server,
        "rustdesk_key": cfg.rustdesk_key,
        "rustdesk_password": cfg.rustdesk_password,
    })));
    ok()
}

fn relay_request(path: &str, method: &str, body: Option<&Value>) -> Result<Value, String> {
    let cfg = read_config();
    let url = format!("{}{}", cfg.relay_url.trim_end_matches('/'), path);
    let http = tls_agent(20);
    let mut req = match method {
        "GET" => http.get(&url),
        "POST" => http.post(&url),
        "PUT" => http.put(&url),
        _ => return Err("طريقة غير مدعومة".into()),
    };
    req = req.set("Authorization", &format!("Bearer {}", cfg.admin_key));
    req = req.set("Content-Type", "application/json");
    let resp = if method == "GET" {
        req.call()
    } else {
        req.send_json(body.cloned().unwrap_or_else(|| json!({})))
    }
    .map_err(|e| format!("تعذر الاتصال بالـ Relay: {}", e))?;
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
    if v["ok"].as_bool().unwrap_or(false) {
        Ok(v)
    } else {
        Err(v["error"].as_str().unwrap_or("طلب فاشل").to_string())
    }
}

#[tauri::command]
pub fn create_pairing_token(label: Option<String>) -> Value {
    match relay_request(
        "/api/v1/admin/pairing-tokens",
        "POST",
        Some(&json!({ "label": label.unwrap_or_default(), "expires_minutes": 0 })),
    ) {
        Ok(v) => json!({"success": true, "token": v["token"].clone(), "expires_at": v["expires_at"].clone()}),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub fn get_relay_devices() -> Vec<Value> {
    match relay_request("/api/v1/admin/devices", "GET", None) {
        Ok(v) => v["devices"].as_array().cloned().unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

#[tauri::command]
pub fn send_relay_command(device_id: String, command: String, actor_username: Option<String>, actor_role: Option<String>) -> Value {
    let actor = actor_username.unwrap_or_default();
    let role = actor_role.unwrap_or_default();
    let res = relay_request(
        &format!("/api/v1/admin/devices/{}/command", device_id),
        "POST",
        Some(&json!({ "command": command, "actor": actor, "actor_role": role })),
    );
    result(res.map(|_| ()))
}

#[tauri::command]
pub fn sync_policy_now() -> Value {
    let cfg = read_config();
    let policy = json!({
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
        "rustdesk_password": cfg.rustdesk_password,
    });
    result(relay_request("/api/v1/admin/policy", "PUT", Some(&policy)).map(|_| ()))
}

#[tauri::command]
pub fn get_dashboard_stats() -> Value {
    relay_request("/api/v1/admin/stats", "GET", None)
        .map(|v| v["stats"].clone())
        .unwrap_or(Value::Null)
}

#[tauri::command]
pub fn get_relay_alerts(alert_type: Option<String>, acked: Option<String>) -> Value {
    let mut path = "/api/v1/admin/alerts?".to_string();
    if let Some(t) = alert_type.filter(|t| !t.is_empty()) {
        path.push_str(&format!("type={}&", t));
    }
    if let Some(a) = acked.filter(|a| !a.is_empty()) {
        path.push_str(&format!("acked={}&", a));
    }
    relay_request(path.trim_end_matches('&'), "GET", None)
        .unwrap_or_else(|_| json!({"ok": false, "alerts": [], "unacked": 0}))
}

#[tauri::command]
pub fn ack_alert(alert_id: String) -> Value {
    result(relay_request(&format!("/api/v1/admin/alerts/{}/ack", alert_id), "POST", None).map(|_| ()))
}

#[tauri::command]
pub fn get_audit_log() -> Value {
    relay_request("/api/v1/admin/audit", "GET", None)
        .unwrap_or_else(|_| json!({"ok": false, "entries": []}))
}

#[tauri::command]
pub fn get_relay_groups() -> Value {
    relay_request("/api/v1/admin/groups", "GET", None)
        .unwrap_or_else(|_| json!({"ok": false, "groups": []}))
}

#[tauri::command]
pub fn create_relay_group(name: String, mode: String) -> Value {
    match relay_request(
        "/api/v1/admin/groups",
        "POST",
        Some(&json!({ "name": name, "mode": mode, "allowed": [], "blocked": [] })),
    ) {
        Ok(v) => json!({"success": true, "group": v["group"].clone()}),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub fn update_relay_group(
    group_id: String,
    name: String,
    mode: String,
    allowed: Vec<String>,
    blocked: Vec<String>,
) -> Value {
    match relay_request(
        &format!("/api/v1/admin/groups/{}", group_id),
        "PUT",
        Some(&json!({ "name": name, "mode": mode, "allowed": allowed, "blocked": blocked })),
    ) {
        Ok(v) => json!({"success": true, "group": v["group"].clone()}),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub fn delete_relay_group(group_id: String) -> Value {
    result(relay_delete(&format!("/api/v1/admin/groups/{}", group_id)))
}

/// DELETE against the relay (ureq has no `send_json` for DELETE).
fn relay_delete(path: &str) -> Result<(), String> {
    let cfg = read_config();
    let url = format!("{}{}", cfg.relay_url.trim_end_matches('/'), path);
    let http = tls_agent(20);
    let resp = http
        .delete(&url)
        .set("Authorization", &format!("Bearer {}", cfg.admin_key))
        .call()
        .map_err(|e| format!("تعذر الاتصال بالـ Relay: {}", e))?;
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
    if v["ok"].as_bool().unwrap_or(false) {
        Ok(())
    } else {
        Err(v["error"].as_str().unwrap_or("فشل الحذف").to_string())
    }
}

#[tauri::command]
pub fn assign_device_group(state: tauri::State<AppState>, device_id: String, group_id: Option<String>) -> Value {
    let gid = group_id.clone().unwrap_or_default();
    if is_lan_device(&state, &device_id) {
        return result(with_server(&state, |s| s.assign_device_group(device_id.clone(), gid.clone())));
    }
    result(
        relay_request(
            &format!("/api/v1/admin/devices/{}/group", device_id),
            "POST",
            Some(&json!({ "group_id": gid })),
        )
        .map(|_| ()),
    )
}

#[tauri::command]
pub fn send_group_command(group_id: String, command: String, actor_username: Option<String>, actor_role: Option<String>) -> Value {
    let actor = actor_username.unwrap_or_default();
    let role = actor_role.unwrap_or_default();
    result(
        relay_request(
            &format!("/api/v1/admin/groups/{}/command", group_id),
            "POST",
            Some(&json!({ "command": command, "actor": actor, "actor_role": role })),
        )
        .map(|_| ()),
    )
}

#[tauri::command]
pub fn rename_relay_device(state: tauri::State<AppState>, device_id: String, label: String) -> Value {
    if is_lan_device(&state, &device_id) {
        return result(with_server(&state, |s| s.rename_device(device_id.clone(), label.clone())));
    }
    result(
        relay_request(
            &format!("/api/v1/admin/devices/{}/label", device_id),
            "POST",
            Some(&json!({ "label": label })),
        )
        .map(|_| ()),
    )
}

#[tauri::command]
pub fn delete_relay_device(state: tauri::State<AppState>, device_id: String) -> Value {
    if is_lan_device(&state, &device_id) {
        return result(with_server(&state, |s| s.delete_device(device_id.clone()).map(|_| ())));
    }
    result(relay_delete(&format!("/api/v1/admin/devices/{}", device_id)))
}

// ---------- RustDesk support ----------

#[tauri::command]
pub fn open_support_session(rustdesk_id: String) -> Value {
    match open_support_session_inner(rustdesk_id) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

fn open_support_session_inner(rustdesk_id: String) -> Result<(), String> {
    if rustdesk_id.trim().is_empty() {
        return Err("لا يوجد RustDesk ID لهذا الجهاز".into());
    }
    let candidates = rustdesk_candidates();
    for exe in candidates {
        if exe.exists() {
            std::process::Command::new(&exe)
                .args(["--connect", rustdesk_id.trim()])
                .spawn()
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
    Err("RustDesk غير مثبت على هذا الجهاز".into())
}

#[tauri::command]
pub fn set_device_rustdesk_password(
    state: tauri::State<AppState>,
    device_id: String,
    password: String,
) -> Value {
    if is_lan_device(&state, &device_id) {
        return result(with_server(&state, |s| {
            s.set_rustdesk_password(device_id.clone(), password.clone())
        }));
    }
    result(
        relay_request(
            &format!("/api/v1/admin/devices/{}/rustdesk_password", device_id),
            "POST",
            Some(&json!({ "password": password })),
        )
        .map(|_| ()),
    )
}

#[tauri::command]
pub fn request_screenshot(state: tauri::State<AppState>, device_id: String) -> Value {
    if is_lan_device(&state, &device_id) {
        return result(with_server(&state, |s| s.request_screenshot(device_id.clone())));
    }
    result(
        relay_request(
            &format!("/api/v1/admin/devices/{}/screen/request", device_id),
            "POST",
            None,
        )
        .map(|_| ()),
    )
}

#[tauri::command]
pub fn get_screenshot(state: tauri::State<AppState>, device_id: String) -> Value {
    // LAN devices are served locally; everything else comes from the relay.
    if is_lan_device(&state, &device_id) {
        let v = {
            let guard = state.server.lock().unwrap();
            match guard.as_ref() {
                Some(s) => s.get_screenshot(device_id.clone()),
                None => json!({"ok": false, "image": "", "at": 0, "requested": false}),
            }
        };
        return v;
    }
    match relay_request(
        &format!("/api/v1/admin/devices/{}/screen", device_id),
        "GET",
        None,
    ) {
        Ok(v) => v,
        Err(_) => json!({"ok": false, "image": "", "at": 0, "requested": false}),
    }
}

// ---------- Client-side link settings ----------

#[tauri::command]
pub fn get_client_config() -> Value {
    let link = read_client();
    // Probe the SYSTEM agent's local API so the UI can show the real state:
    // - agent_running: the --agent process owns 127.0.0.1:8788
    // - connected: the agent has an accepted poll (relay or LAN) right now
    let status = tls_agent(3)
        .get(&format!("http://{}/local/status", LOCAL_API_ADDR))
        .call()
        .ok()
        .and_then(|r| r.into_json::<Value>().ok());
    let agent_running = status.is_some();
    let connected = status
        .as_ref()
        .and_then(|v| v["connected"].as_bool())
        .unwrap_or(false);
    let blocked = status
        .as_ref()
        .and_then(|v| v["blocked"].as_bool())
        .unwrap_or_else(is_blocked);
    let enrolled = !link.device_token.is_empty();
    json!({
        "server_url": link.server_url,
        "token": link.token,
        "device_id": link.device_id,
        "relay_url": link.relay_url,
        "transport": link.transport,
        "has_relay": enrolled,
        "enrolled": enrolled,
        "agent_running": agent_running,
        "connected": connected,
        "blocked": blocked,
        "rustdesk_id": link.rustdesk_id,
    })
}

#[tauri::command]
pub fn set_client_config(server_url: String, token: String, password: Option<String>) -> Value {
    match set_client_config_inner(server_url, token, password) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

fn set_client_config_inner(server_url: String, token: String, password: Option<String>) -> Result<(), String> {
    let cfg = read_config();
    let supplied = password.unwrap_or_default();
    if !cfg.password_hash.is_empty() && !password_ok(&cfg, &supplied) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        return Err("كلمة السر غير صحيحة".into());
    }
    let agent = tls_agent(10);
    let resp = agent
        .post(&format!("http://{}/local/link", LOCAL_API_ADDR))
        .send_json(json!({ "server_url": server_url, "token": token, "password": supplied }));
    match resp {
        Ok(r) => {
            let v: Value = r.into_json().map_err(|e| e.to_string())?;
            if v["success"].as_bool().unwrap_or(false) {
                Ok(())
            } else {
                Err(v["error"].as_str().unwrap_or("فشل الحفظ").to_string())
            }
        }
        Err(e) => Err(format!("تعذر الاتصال بالوكيل: {}", e)),
    }
}

#[tauri::command]
pub fn enroll_relay(relay_url: String, pairing_token: String, password: Option<String>) -> Value {
    match enroll_relay_inner(relay_url, pairing_token, password) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

fn enroll_relay_inner(relay_url: String, pairing_token: String, password: Option<String>) -> Result<(), String> {
    let cfg = read_config();
    let supplied = password.unwrap_or_default();
    if !cfg.password_hash.is_empty() && !password_ok(&cfg, &supplied) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        return Err("كلمة السر غير صحيحة".into());
    }
    let agent = tls_agent(10);
    let resp = agent
        .post(&format!("http://{}/local/relay", LOCAL_API_ADDR))
        .send_json(json!({
            "relay_url": relay_url.trim().trim_end_matches('/'),
            "pairing_token": pairing_token.trim(),
            "password": supplied,
        }));
    match resp {
        Ok(r) => {
            let v: Value = r.into_json().map_err(|e| e.to_string())?;
            if v["success"].as_bool().unwrap_or(false) {
                Ok(())
            } else {
                Err(v["error"].as_str().unwrap_or("فشل الربط").to_string())
            }
        }
        Err(e) => Err(format!("تعذر الاتصال بالوكيل: {}", e)),
    }
}

#[tauri::command]
pub fn disconnect_relay(password: Option<String>) -> Value {
    match disconnect_relay_inner(password) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

fn disconnect_relay_inner(password: Option<String>) -> Result<(), String> {
    let cfg = read_config();
    let supplied = password.unwrap_or_default();
    if !cfg.password_hash.is_empty() && !password_ok(&cfg, &supplied) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        return Err("كلمة السر غير صحيحة".into());
    }
    let agent = tls_agent(10);
    let resp = agent
        .post(&format!("http://{}/local/relay/off", LOCAL_API_ADDR))
        .send_json(json!({ "password": supplied }));
    match resp {
        Ok(r) => {
            let v: Value = r.into_json().map_err(|e| e.to_string())?;
            if v["success"].as_bool().unwrap_or(false) {
                Ok(())
            } else {
                Err(v["error"].as_str().unwrap_or("فشل فك الربط").to_string())
            }
        }
        Err(e) => Err(format!("تعذر الاتصال بالوكيل: {}", e)),
    }
}

// Unused helpers kept for signature parity with the previous implementation.
#[allow(dead_code)]
fn hash_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}
