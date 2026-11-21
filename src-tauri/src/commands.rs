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

fn server_opt(state: &AppState) -> Option<ServerHandle> {
    state.server.lock().unwrap().clone()
}

async fn run_bg<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())
}

fn with_server_opt<F, T>(server: Option<&ServerHandle>, f: F) -> Result<T, String>
where
    F: FnOnce(&ServerHandle) -> Result<T, String>,
{
    match server {
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

// ---------- Blocking & Auth Helper ----------

fn resolve_actor(
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<(String, String), String> {
    if let Some(t) = token.filter(|s| !s.trim().is_empty()) {
        let claims = crate::auth::verify_jwt(&t)?;
        return Ok((claims.sub, normalize_admin_role(&claims.role)));
    }
    if !is_admin_mode() {
        return Ok(("employee".to_string(), "client".to_string()));
    }
    let cfg = read_config();
    let supplied_user = actor_username.unwrap_or_default();
    let supplied_user = supplied_user.trim();
    if cfg.admins.is_empty() {
        let fallback_user = if supplied_user.is_empty() { "admin" } else { supplied_user };
        return Ok((fallback_user.to_string(), "super".to_string()));
    }
    if !supplied_user.is_empty() {
        if let Some(found) = cfg.admins.iter().find(|u| u.username.eq_ignore_ascii_case(supplied_user)) {
            return Ok((found.username.clone(), normalize_admin_role(&found.role)));
        }
    }
    let _ = actor_role;
    Err("يرجى تسجيل الدخول بحساب المدير أولاً".to_string())
}

fn can_control_devices(role: &str) -> bool {
    matches!(role, "super" | "admin" | "support" | "client")
}

fn block_internet_sync(
    password: Option<String>,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let (actor, role) = match resolve_actor(token, actor_username, actor_role) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    if !can_control_devices(&role) {
        return fail("صلاحية المشاهدة فقط لا تسمح بقفل الإنترنت");
    }
    match block_internet_inner(password.unwrap_or_default(), &actor, &role) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn block_internet(
    password: Option<String>,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<Value, String> {
    run_bg(move || block_internet_sync(password, token, actor_username, actor_role)).await
}

fn block_internet_inner(supplied: String, actor: &str, role: &str) -> Result<(), String> {
    if !is_admin_mode() {
        let cfg = read_config();
        if supplied.trim().is_empty() || !password_ok(&cfg, &supplied) {
            std::thread::sleep(std::time::Duration::from_secs(1));
            log_action("BLOCK refused - wrong password");
            return Err("كلمة السر غير صحيحة".into());
        }
    }
    // Always try the SYSTEM agent first: it is the only context that can apply the
    // block unattended and it owns the local proxy.
    let agent = tls_agent(20);
    match agent
        .post(&format!("http://{}/local/block", LOCAL_API_ADDR))
        .send_json(json!({ "password": supplied }))
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
    // No agent running (dev machine or agent task missing): run elevated via UAC.
    run_script_elevated("block-internet.ps1", None)?;
    set_block_state(true);
    log_action(&format!("BLOCK (local elevated) - success by {} ({})", actor.trim(), role.trim()));
    Ok(())
}

fn unblock_internet_sync(
    password: Option<String>,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let (actor, role) = match resolve_actor(token, actor_username, actor_role) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    if !can_control_devices(&role) {
        return fail("صلاحية المشاهدة فقط لا تسمح بفتح الإنترنت");
    }
    match unblock_internet_inner(password.unwrap_or_default(), &actor, &role) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn unblock_internet(
    password: Option<String>,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<Value, String> {
    run_bg(move || unblock_internet_sync(password, token, actor_username, actor_role)).await
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
    let pw_arg = if supplied.is_empty() { None } else { Some(supplied.as_str()) };
    run_script_elevated("allow-internet.ps1", pw_arg)?;
    set_block_state(false);
    log_action(&format!("UNBLOCK (local elevated) - success by {} ({})", actor.trim(), role.trim()));
    Ok(())
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

fn toggle_autostart_sync(enable: bool) -> Value {
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
pub async fn toggle_autostart(enable: bool) -> Result<Value, String> {
    run_bg(move || toggle_autostart_sync(enable)).await
}

fn set_password_sync(current_password: Option<String>, new_password: Option<String>) -> Value {
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
pub async fn set_password(
    current_password: Option<String>,
    new_password: Option<String>,
) -> Result<Value, String> {
    run_bg(move || set_password_sync(current_password, new_password)).await
}

fn get_admin_users_sync() -> Vec<Value> {
    let mut cfg = read_config();

    if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
        if let Ok(v) = relay_request("/api/v1/admin/users", "GET", None) {
            let relay_users = v["users"].as_array().cloned().unwrap_or_default();
            let relay_names: std::collections::HashSet<String> = relay_users
                .iter()
                .filter_map(|u| u["username"].as_str().map(|s| s.trim().to_ascii_lowercase()))
                .collect();
            for local_u in &cfg.admins {
                if !relay_names.contains(&local_u.username.trim().to_ascii_lowercase()) {
                    let _ = relay_request(
                        "/api/v1/admin/users",
                        "POST",
                        Some(&json!({
                            "username": local_u.username,
                            "password_hash": local_u.password_hash,
                            "role": normalize_admin_role(&local_u.role),
                            "actor_username": "system_sync",
                        })),
                    );
                }
            }
            let mut cfg_changed = false;
            for ru in relay_users {
                let rname = ru["username"].as_str().unwrap_or("").trim();
                if rname.is_empty() {
                    continue;
                }
                let rrole = normalize_admin_role(ru["role"].as_str().unwrap_or("admin"));
                let rhash = ru["password_hash"].as_str().unwrap_or("").trim().to_string();
                if !cfg.admins.iter().any(|lu| lu.username.eq_ignore_ascii_case(rname)) {
                    cfg.admins.push(AdminUser {
                        username: rname.to_string(),
                        password_hash: rhash,
                        role: rrole,
                    });
                    cfg_changed = true;
                }
            }
            if cfg_changed {
                let _ = write_config(&cfg);
            }
        }
    }

    cfg.admins
        .iter()
        .map(|u| json!({ "username": u.username, "role": normalize_admin_role(&u.role) }))
        .collect()
}

#[tauri::command]
pub async fn get_admin_users() -> Result<Vec<Value>, String> {
    run_bg(get_admin_users_sync).await
}

fn upsert_admin_user_sync(
    username: String,
    password: String,
    role: Option<String>,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let username = username.trim();
    if username.is_empty() {
        return fail("اسم المدير مطلوب");
    }

    let cfg = read_config();
    let (actor, actor_role_name) = match resolve_actor(token, actor_username, actor_role) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    if !cfg.admins.is_empty() && !can_manage_admin_users(&cfg, &actor, &actor_role_name) && actor_role_name != "super" {
        return fail("فقط السوبر أدمن يمكنه إدارة حسابات المديرين");
    }

    let mut cfg = cfg;
    let mut normalized_role = normalize_admin_role(role.as_deref().unwrap_or("admin"));
    if normalized_role.is_empty() {
        normalized_role = "admin".to_string();
    }

    let final_hash = if let Some(existing) = cfg.admins.iter_mut().find(|u| u.username.eq_ignore_ascii_case(username)) {
        if !password.trim().is_empty() {
            existing.password_hash = hash_password(password.trim());
        }
        existing.role = normalized_role.clone();
        existing.password_hash.clone()
    } else {
        let h = if password.trim().is_empty() { String::new() } else { hash_password(password.trim()) };
        cfg.admins.push(AdminUser {
            username: username.to_string(),
            password_hash: h.clone(),
            role: normalized_role.clone(),
        });
        h
    };

    if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
        let _ = relay_request(
            "/api/v1/admin/users",
            "POST",
            Some(&json!({
                "username": username,
                "password": password.trim(),
                "password_hash": final_hash,
                "role": normalized_role,
                "actor_username": actor,
                "actor_role": actor_role_name,
            })),
        );
    }

    match write_config(&cfg) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn upsert_admin_user(
    username: String,
    password: String,
    role: Option<String>,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<Value, String> {
    run_bg(move || upsert_admin_user_sync(username, password, role, token, actor_username, actor_role)).await
}

fn remove_admin_user_sync(
    username: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let username = username.trim();
    if username.is_empty() {
        return fail("اسم المدير مطلوب");
    }

    let cfg = read_config();
    let (actor, actor_role_name) = match resolve_actor(token, actor_username, actor_role) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    if !cfg.admins.is_empty() && !can_manage_admin_users(&cfg, &actor, &actor_role_name) && actor_role_name != "super" {
        return fail("فقط السوبر أدمن يمكنه إدارة حسابات المديرين");
    }
    if username.eq_ignore_ascii_case(&actor)
        && cfg.admins.iter().filter(|u| normalize_admin_role(&u.role) == "super").count() <= 1
    {
        return fail("لا يمكن حذف آخر حساب سوبر أدمن");
    }

    let mut relay_deleted = false;
    if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
        let encoded = username.replace(' ', "%20").replace('/', "%2F");
        if let Ok(v) = relay_request(&format!("/api/v1/admin/users/{}", encoded), "DELETE", None) {
            relay_deleted = v["deleted"].as_bool().unwrap_or(false);
        }
    }

    let mut cfg = cfg;
    let before = cfg.admins.len();
    cfg.admins.retain(|u| !u.username.eq_ignore_ascii_case(username));
    let local_deleted = cfg.admins.len() != before;

    if !local_deleted && !relay_deleted {
        return fail("المستخدم غير موجود");
    }

    if local_deleted {
        if let Err(e) = write_config(&cfg) {
            return fail(e);
        }
    }
    ok()
}

#[tauri::command]
pub async fn remove_admin_user(
    username: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<Value, String> {
    run_bg(move || remove_admin_user_sync(username, token, actor_username, actor_role)).await
}

fn admin_login_sync(username: String, password: String) -> Value {
    let username = username.trim();
    if username.is_empty() {
        return fail("اسم المستخدم مطلوب");
    }

    let cfg = read_config();
    match admin_login_ok(&cfg, username, &password) {
        Some(role) => {
            let normalized = normalize_admin_role(&role);
            let token = crate::auth::make_jwt(username, &normalized).unwrap_or_default();
            json!({
                "success": true,
                "token": token,
                "username": username,
                "role": normalized,
                "is_super_admin": normalized == "super",
            })
        },
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
                            let normalized = normalize_admin_role(role);
                            let token = crate::auth::make_jwt(username, &normalized).unwrap_or_default();
                            return json!({
                                "success": true,
                                "token": token,
                                "username": username,
                                "role": normalized,
                                "is_super_admin": normalized == "super",
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

#[tauri::command]
pub async fn admin_login(username: String, password: String) -> Result<Value, String> {
    run_bg(move || admin_login_sync(username, password)).await
}

// ---------- Logs ----------

#[tauri::command]
pub async fn get_logs() -> Result<String, String> {
    run_bg(read_log).await
}

// ---------- LAN server (admin machine) ----------

fn get_server_info_inner(server: Option<&ServerHandle>, include_token: bool) -> Value {
    match server {
        Some(s) => json!({
            "port": s.port,
            "token": if include_token { s.token.as_str() } else { "" },
            "ip": local_ip(),
        }),
        None => json!({ "port": 0, "token": "", "ip": local_ip() }),
    }
}

#[tauri::command]
pub async fn get_server_info(state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || get_server_info_inner(srv.as_ref(), true)).await
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

fn get_devices_inner(server: Option<&ServerHandle>) -> Vec<Value> {
    match server {
        Some(s) => s.devices().iter().map(device_to_json).collect(),
        None => Vec::new(),
    }
}

#[tauri::command]
pub async fn get_devices(state: tauri::State<'_, AppState>) -> Result<Vec<Value>, String> {
    let srv = server_opt(&state);
    run_bg(move || get_devices_inner(srv.as_ref())).await
}

fn send_device_command_inner(
    server: Option<&ServerHandle>,
    device_id: String,
    command: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let (actor, role) = match resolve_actor(token, actor_username, actor_role) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    if !can_control_devices(&role) {
        return fail("صلاحية المشاهدة فقط لا تسمح بإرسال أوامر للأجهزة");
    }
    result(with_server_opt(server, |s| s.send_command(&device_id, &command, &actor, &role)))
}

#[tauri::command]
pub async fn send_device_command(
    state: tauri::State<'_, AppState>,
    device_id: String,
    command: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || send_device_command_inner(srv.as_ref(), device_id, command, token, actor_username, actor_role)).await
}

/// True when the device is currently registered on the local LAN server.
fn is_lan_device(server: Option<&ServerHandle>, device_id: &str) -> bool {
    server
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

fn set_relay_config_sync(
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

#[tauri::command]
pub async fn set_relay_config(
    relay_url: String,
    admin_key: Option<String>,
    current_password: Option<String>,
    rustdesk_server: Option<String>,
    rustdesk_key: Option<String>,
    rustdesk_password: Option<String>,
) -> Result<Value, String> {
    run_bg(move || {
        set_relay_config_sync(
            relay_url,
            admin_key,
            current_password,
            rustdesk_server,
            rustdesk_key,
            rustdesk_password,
        )
    })
    .await
}

static LOCAL_RELAY_PROBE: Mutex<(u64, bool)> = Mutex::new((0, false));
static RELAY_HTTP_AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();

fn is_local_relay_listening() -> bool {
    let now = now_ms();
    if let Ok(g) = LOCAL_RELAY_PROBE.lock() {
        if g.0 > 0 && now.saturating_sub(g.0) < 15_000 {
            return g.1;
        }
    }
    let alive = "127.0.0.1:8790"
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|addr| std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(60)).is_ok())
        .unwrap_or(false);
    if let Ok(mut g) = LOCAL_RELAY_PROBE.lock() {
        *g = (now, alive);
    }
    alive
}

fn relay_http_agent() -> &'static ureq::Agent {
    RELAY_HTTP_AGENT.get_or_init(|| tls_agent(15))
}

fn relay_base_urls(cfg: &Config) -> Vec<String> {
    let mut bases = Vec::new();
    if is_local_relay_listening() {
        bases.push("http://127.0.0.1:8790".to_string());
    }
    let configured = cfg.relay_url.trim().trim_end_matches('/').to_string();
    if !configured.is_empty() && !bases.iter().any(|b| b == &configured) {
        bases.push(configured);
    }
    bases
}

fn relay_request(path: &str, method: &str, body: Option<&Value>) -> Result<Value, String> {
    let cfg = read_config();
    let bases = relay_base_urls(&cfg);
    if bases.is_empty() {
        return Err("لم يتم ضبط عنوان الـ Relay".into());
    }
    let http = relay_http_agent();
    let mut last_err = String::from("تعذر الاتصال بالـ Relay");
    for base in bases {
        let url = format!("{}{}", base, path);
        let mut req = match method {
            "GET" => http.get(&url),
            "POST" => http.post(&url),
            "PUT" => http.put(&url),
            "DELETE" => http.delete(&url),
            _ => return Err("طريقة غير مدعومة".into()),
        };
        req = req.set("Authorization", &format!("Bearer {}", cfg.admin_key));
        if method != "GET" && method != "DELETE" {
            req = req.set("Content-Type", "application/json");
        }
        let resp = if method == "GET" || method == "DELETE" {
            req.call()
        } else {
            req.send_json(body.cloned().unwrap_or_else(|| json!({})))
        };
        match resp {
            Ok(r) => match r.into_json::<Value>() {
                Ok(v) if v["ok"].as_bool().unwrap_or(false) => return Ok(v),
                Ok(v) => last_err = v["error"].as_str().unwrap_or("طلب فاشل").to_string(),
                Err(e) => last_err = e.to_string(),
            },
            Err(e) => last_err = format!("تعذر الاتصال بالـ Relay: {}", e),
        }
    }
    Err(last_err)
}

fn create_pairing_token_sync(label: Option<String>) -> Value {
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
pub async fn create_pairing_token(label: Option<String>) -> Result<Value, String> {
    run_bg(move || create_pairing_token_sync(label)).await
}

fn get_relay_devices_inner(server: Option<&ServerHandle>) -> Vec<Value> {
    let mut devices = match relay_request("/api/v1/admin/devices", "GET", None) {
        Ok(v) => v["devices"].as_array().cloned().unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    if let Some(s) = server {
        let lan = s.devices();
        if !lan.is_empty() {
            let lan_ids: std::collections::HashSet<String> = lan
                .iter()
                .map(|d| d.device.device_id.clone())
                .filter(|x| !x.is_empty())
                .collect();
            let lan_hosts: std::collections::HashSet<String> = lan
                .iter()
                .map(|d| d.device.hostname.trim().to_ascii_lowercase())
                .filter(|x| !x.is_empty())
                .collect();
            let lan_rd: std::collections::HashSet<String> = lan
                .iter()
                .map(|d| d.device.rustdesk_id.chars().filter(|c| !c.is_whitespace()).collect::<String>())
                .filter(|x| !x.is_empty())
                .collect();
            devices.retain(|v| {
                let did = v["device_id"].as_str().unwrap_or("").trim();
                let host = v["hostname"].as_str().unwrap_or("").trim().to_ascii_lowercase();
                let rd: String = v["rustdesk_id"].as_str().unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect();
                !lan_ids.contains(did)
                    && (host.is_empty() || !lan_hosts.contains(&host))
                    && (rd.is_empty() || !lan_rd.contains(&rd))
            });
        }
    }
    devices
}

#[tauri::command]
pub async fn get_relay_devices(state: tauri::State<'_, AppState>) -> Result<Vec<Value>, String> {
    let srv = server_opt(&state);
    run_bg(move || get_relay_devices_inner(srv.as_ref())).await
}

fn send_relay_command_sync(
    device_id: String,
    command: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let (actor, role) = match resolve_actor(token, actor_username, actor_role) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    if !can_control_devices(&role) {
        return fail("صلاحية المشاهدة فقط لا تسمح بإرسال أوامر للأجهزة");
    }
    let res = relay_request(
        &format!("/api/v1/admin/devices/{}/command", device_id),
        "POST",
        Some(&json!({ "command": command, "actor": actor, "actor_role": role })),
    );
    result(res.map(|_| ()))
}

#[tauri::command]
pub async fn send_relay_command(
    device_id: String,
    command: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<Value, String> {
    run_bg(move || send_relay_command_sync(device_id, command, token, actor_username, actor_role)).await
}

fn sync_policy_now_sync() -> Value {
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
pub async fn sync_policy_now() -> Result<Value, String> {
    run_bg(sync_policy_now_sync).await
}

fn get_dashboard_stats_sync() -> Value {
    relay_request("/api/v1/admin/stats", "GET", None)
        .map(|v| v["stats"].clone())
        .unwrap_or(Value::Null)
}

#[tauri::command]
pub async fn get_dashboard_stats() -> Result<Value, String> {
    run_bg(get_dashboard_stats_sync).await
}

fn get_relay_alerts_inner(
    server: Option<&ServerHandle>,
    alert_type: Option<String>,
    acked: Option<String>,
) -> Value {
    let lan_val = with_server_opt(server, |s| Ok(s.get_alerts(alert_type.clone(), acked.clone())))
        .unwrap_or_else(|_| json!({"ok": false, "alerts": [], "unacked": 0}));
    let mut path = "/api/v1/admin/alerts?".to_string();
    if let Some(t) = alert_type.filter(|t| !t.is_empty()) {
        path.push_str(&format!("type={}&", t));
    }
    if let Some(a) = acked.filter(|a| !a.is_empty()) {
        path.push_str(&format!("acked={}&", a));
    }
    let relay_val = relay_request(path.trim_end_matches('&'), "GET", None)
        .unwrap_or_else(|_| json!({"ok": false, "alerts": [], "unacked": 0}));

    let mut merged: Vec<Value> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for src in [&relay_val, &lan_val] {
        if let Some(arr) = src["alerts"].as_array() {
            for item in arr {
                let id = item["id"].as_str().unwrap_or("").trim().to_string();
                if !id.is_empty() && !seen_ids.insert(id) {
                    continue;
                }
                merged.push(item.clone());
            }
        }
    }
    merged.sort_by(|a, b| {
        b["created_at"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["created_at"].as_u64().unwrap_or(0))
    });
    merged.truncate(200);
    let relay_unacked = relay_val["unacked"].as_u64().unwrap_or(0);
    let lan_only_unacked = if let Some(arr) = lan_val["alerts"].as_array() {
        let relay_ids: std::collections::HashSet<&str> = relay_val["alerts"]
            .as_array()
            .map(|ra| ra.iter().filter_map(|x| x["id"].as_str()).collect())
            .unwrap_or_default();
        arr.iter()
            .filter(|x| {
                let id = x["id"].as_str().unwrap_or("");
                let is_acked = x["acked"].as_bool().unwrap_or(false) || !x["acked_at"].is_null();
                !is_acked && !relay_ids.contains(id)
            })
            .count() as u64
    } else {
        0
    };
    let total_unacked = relay_unacked + lan_only_unacked;
    json!({"ok": true, "alerts": merged, "unacked": total_unacked})
}

#[tauri::command]
pub async fn get_relay_alerts(
    state: tauri::State<'_, AppState>,
    alert_type: Option<String>,
    acked: Option<String>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || get_relay_alerts_inner(srv.as_ref(), alert_type, acked)).await
}

fn get_alert_media_inner(server: Option<&ServerHandle>, alert_id: String) -> Value {
    let id = alert_id.trim();
    if id.is_empty() {
        return json!({"ok": false, "error": "معرّف التنبيه مفقود"});
    }
    if let Some(local_hit) = server.and_then(|s| s.get_alert_media(id)) {
        return local_hit;
    }
    let cfg = read_config();
    let bases = relay_base_urls(&cfg);
    let safe_id: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if safe_id.is_empty() {
        return json!({"ok": false, "error": "معرّف التنبيه غير صالح"});
    }
    let http = tls_agent(30);
    for base in bases {
        let url = format!("{}/api/v1/admin/alerts/{}", base, safe_id);
        let Ok(resp) = http
            .get(&url)
            .set("Authorization", &format!("Bearer {}", cfg.admin_key))
            .call()
        else {
            continue;
        };
        if let Ok(v) = resp.into_json::<Value>() {
            if v["ok"].as_bool().unwrap_or(false) {
                return v;
            }
        }
    }
    json!({"ok": false, "screenshot": "", "camera_photo": ""})
}

#[tauri::command]
pub async fn get_alert_media(
    state: tauri::State<'_, AppState>,
    alert_id: String,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || get_alert_media_inner(srv.as_ref(), alert_id)).await
}

fn ack_alert_inner(server: Option<&ServerHandle>, alert_id: String) -> Value {
    let lan_res = with_server_opt(server, |s| s.ack_alert(alert_id.clone()));
    let relay_res = relay_request(&format!("/api/v1/admin/alerts/{}/ack", alert_id), "POST", None);
    if relay_res.is_ok() || lan_res.is_ok() {
        ok()
    } else {
        fail(relay_res.err().or(lan_res.err()).unwrap_or_else(|| "فشل إقرار التنبيه".into()))
    }
}

#[tauri::command]
pub async fn ack_alert(
    state: tauri::State<'_, AppState>,
    alert_id: String,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || ack_alert_inner(srv.as_ref(), alert_id)).await
}

fn get_uploaded_files_inner(channel: Option<String>) -> Value {
    let ch_filter = channel.unwrap_or_default().trim().to_ascii_lowercase();
    let mut by_id: std::collections::HashMap<String, Value> = std::collections::HashMap::new();

    // 1. Local archive-log.jsonl (captures both LAN uploads and co-hosted Relay entries).
    for mut item in crate::server::read_local_archive_entries() {
        let fid = item["file_id"].as_str().unwrap_or("").trim().to_string();
        if fid.is_empty() {
            continue;
        }
        let sp = item["stored_path"].as_str().unwrap_or("");
        item["exists_on_disk"] = json!(!sp.is_empty() && std::path::Path::new(sp).is_file());
        by_id.insert(fid, item);
    }

    // 2. Cloud Relay archive DB (picks up remote Relay devices and merged metadata).
    let q_path = if ch_filter.is_empty() {
        "/api/v1/admin/uploads".to_string()
    } else {
        format!("/api/v1/admin/uploads?channel={}", ch_filter)
    };
    if let Ok(v) = relay_request(&q_path, "GET", None) {
        if let Some(arr) = v["files"].as_array() {
            for item in arr {
                let fid = item["file_id"].as_str().unwrap_or("").trim().to_string();
                if fid.is_empty() {
                    continue;
                }
                if let Some(prev) = by_id.get_mut(&fid) {
                    for k in [
                        "device_name",
                        "windows_user",
                        "channel",
                        "recipient_name",
                        "recipient_phone",
                        "page_url",
                        "sha256",
                        "stored_path",
                    ] {
                        let cur_empty = prev[k].as_str().unwrap_or("").trim().is_empty();
                        let inc = item[k].as_str().unwrap_or("").trim();
                        if cur_empty && !inc.is_empty() {
                            prev[k] = json!(inc);
                        }
                    }
                    if !prev["exists_on_disk"].as_bool().unwrap_or(false)
                        && item["exists_on_disk"].as_bool().unwrap_or(false)
                    {
                        prev["exists_on_disk"] = json!(true);
                    }
                } else {
                    by_id.insert(fid, item.clone());
                }
            }
        }
    }

    let mut files: Vec<Value> = by_id.into_values().collect();
    if !ch_filter.is_empty() {
        files.retain(|f| {
            let ch = f["channel"].as_str().unwrap_or("whatsapp_web").to_ascii_lowercase();
            if ch_filter == "whatsapp_web" {
                ch.contains("whatsapp")
            } else {
                ch == ch_filter
            }
        });
    }
    files.sort_by(|a, b| {
        b["created_at"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["created_at"].as_u64().unwrap_or(0))
    });
    files.truncate(400);

    json!({
        "ok": true,
        "archive_root": crate::server::server_archive_root().to_string_lossy().to_string(),
        "files": files,
    })
}

#[tauri::command]
pub async fn get_uploaded_files(channel: Option<String>) -> Result<Value, String> {
    run_bg(move || get_uploaded_files_inner(channel)).await
}

fn save_uploaded_file_sync(file_id: String, file_name: Option<String>) -> Value {
    let fid = file_id.trim();
    if fid.is_empty() {
        return fail("معرّف الملف مفقود");
    }
    let Some((resolved_name, bytes)) = crate::server::fetch_uploaded_file_bytes(fid) else {
        return fail("تعذر العثور على الملف الأصلي على السيرفر");
    };
    if bytes.is_empty() {
        return fail("الملف فارغ أو غير مكتمل");
    }
    let preferred = file_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "file" && s != "file.bin")
        .unwrap_or(resolved_name);
    let mut clean: String = preferred
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0'..='\x1f' => '_',
            _ => c,
        })
        .collect::<String>()
        .trim()
        .trim_end_matches('.')
        .to_string();
    if clean.is_empty() {
        clean = format!("{}.bin", fid);
    }
    if !clean.contains('.') {
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            clean.push_str(".jpg");
        } else if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
            clean.push_str(".png");
        } else if bytes.starts_with(b"%PDF-") {
            clean.push_str(".pdf");
        }
    }

    let dl_dir = std::env::var("USERPROFILE")
        .ok()
        .map(|u| std::path::PathBuf::from(u).join("Downloads"))
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dl_dir);

    let (stem, ext) = match clean.rfind('.') {
        Some(idx) if idx > 0 => (&clean[..idx], &clean[idx..]),
        _ => (clean.as_str(), ""),
    };
    let mut dest = dl_dir.join(&clean);
    let mut n = 1u32;
    while dest.exists() && n < 500 {
        dest = dl_dir.join(format!("{} ({}){}", stem, n, ext));
        n += 1;
    }

    if let Err(e) = std::fs::write(&dest, &bytes) {
        return fail(format!("فشل حفظ الملف: {}", e));
    }
    let mut cmd = std::process::Command::new("explorer.exe");
    cmd.arg(format!("/select,{}", dest.to_string_lossy()));
    let _ = cmd.spawn();

    json!({
        "success": true,
        "path": dest.to_string_lossy().to_string(),
        "size": bytes.len(),
    })
}

#[tauri::command]
pub async fn save_uploaded_file(
    file_id: String,
    file_name: Option<String>,
) -> Result<Value, String> {
    run_bg(move || save_uploaded_file_sync(file_id, file_name)).await
}

fn save_base64_image_sync(base64_data: String, file_name: Option<String>) -> Value {
    let raw_trimmed = base64_data.trim();
    let payload = match raw_trimmed.find(";base64,") {
        Some(idx) => &raw_trimmed[idx + 8..],
        None => raw_trimmed,
    };
    let Some(bytes) = base64_decode(payload) else {
        return fail("بيانات الصورة غير صالحة");
    };
    if bytes.is_empty() {
        return fail("الصورة فارغة");
    }
    let ext_default = if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        ".jpg"
    } else {
        ".png"
    };
    let base_name = file_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("alert_evidence_{}{}", now_ms(), ext_default));
    let mut clean: String = base_name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0'..='\x1f' => '_',
            _ => c,
        })
        .collect::<String>()
        .trim()
        .trim_end_matches('.')
        .to_string();
    if !clean.contains('.') {
        clean.push_str(ext_default);
    }

    let dl_dir = std::env::var("USERPROFILE")
        .ok()
        .map(|u| std::path::PathBuf::from(u).join("Downloads"))
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dl_dir);

    let (stem, ext) = match clean.rfind('.') {
        Some(idx) if idx > 0 => (&clean[..idx], &clean[idx..]),
        _ => (clean.as_str(), ""),
    };
    let mut dest = dl_dir.join(&clean);
    let mut n = 1u32;
    while dest.exists() && n < 500 {
        dest = dl_dir.join(format!("{} ({}){}", stem, n, ext));
        n += 1;
    }

    if let Err(e) = std::fs::write(&dest, &bytes) {
        return fail(format!("فشل حفظ الصورة: {}", e));
    }
    let mut cmd = std::process::Command::new("explorer.exe");
    cmd.arg(format!("/select,{}", dest.to_string_lossy()));
    let _ = cmd.spawn();

    json!({
        "success": true,
        "path": dest.to_string_lossy().to_string(),
        "size": bytes.len(),
    })
}

#[tauri::command]
pub async fn save_base64_image(
    base64_data: String,
    file_name: Option<String>,
) -> Result<Value, String> {
    run_bg(move || save_base64_image_sync(base64_data, file_name)).await
}

fn open_archive_folder_sync(target_path: Option<String>) -> Value {
    if !is_admin_mode() {
        return fail("متاح فقط على جهاز المدير");
    }
    let root = crate::server::server_archive_root();
    let _ = std::fs::create_dir_all(&root);
    let root_canon = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());

    if let Some(raw) = target_path.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        let cand = std::path::PathBuf::from(&raw);
        if let Ok(canon) = std::fs::canonicalize(&cand) {
            if canon.starts_with(&root_canon) && canon.is_file() {
                let mut cmd = std::process::Command::new("explorer.exe");
                cmd.arg(format!("/select,{}", canon.to_string_lossy()));
                let _ = cmd.spawn();
                return ok();
            }
        }
    }

    let mut cmd = std::process::Command::new("explorer.exe");
    cmd.arg(&root_canon);
    match cmd.spawn() {
        Ok(_) => ok(),
        Err(e) => fail(format!("تعذر فتح المجلد: {}", e)),
    }
}

#[tauri::command]
pub async fn open_archive_folder(target_path: Option<String>) -> Result<Value, String> {
    run_bg(move || open_archive_folder_sync(target_path)).await
}

fn get_audit_log_inner(server: Option<&ServerHandle>) -> Value {
    let lan_val = with_server_opt(server, |s| Ok(s.get_audit_log()))
        .unwrap_or_else(|_| json!({"ok": false, "entries": []}));
    let relay_val = relay_request("/api/v1/admin/audit", "GET", None)
        .unwrap_or_else(|_| json!({"ok": false, "entries": []}));
    let mut merged: Vec<Value> = Vec::new();
    for src in [&lan_val, &relay_val] {
        if let Some(arr) = src["entries"].as_array() {
            merged.extend(arr.iter().cloned());
        }
    }
    merged.sort_by(|a, b| {
        b["created_at"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["created_at"].as_u64().unwrap_or(0))
    });
    merged.truncate(200);
    json!({"ok": true, "entries": merged})
}

#[tauri::command]
pub async fn get_audit_log(state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || get_audit_log_inner(srv.as_ref())).await
}

fn get_relay_groups_inner(server: Option<&ServerHandle>) -> Value {
    match relay_request("/api/v1/admin/groups", "GET", None) {
        Ok(mut v) => {
            if let Some(arr) = v["groups"].as_array().cloned() {
                let counts = with_server_opt(server, |s| {
                    s.sync_groups(&arr);
                    Ok(s.group_device_counts())
                })
                .unwrap_or_default();
                if let Some(out_arr) = v["groups"].as_array_mut() {
                    for g in out_arr.iter_mut() {
                        if let Some(id) = g["id"].as_str() {
                            if let Some(&lan_n) = counts.get(id) {
                                let relay_n = g["devices"].as_u64().unwrap_or(0);
                                g["devices"] = json!(relay_n + lan_n as u64);
                            }
                        }
                    }
                }
            }
            v
        }
        Err(_) => {
            let local = with_server_opt(server, |s| Ok(s.get_groups())).unwrap_or_default();
            json!({"ok": true, "groups": local})
        }
    }
}

#[tauri::command]
pub async fn get_relay_groups(state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || get_relay_groups_inner(srv.as_ref())).await
}

fn create_relay_group_inner(
    server: Option<&ServerHandle>,
    name: String,
    mode: String,
    ephemeral_browser: Option<bool>,
) -> Value {
    let ephem = ephemeral_browser.unwrap_or(false);
    match relay_request(
        "/api/v1/admin/groups",
        "POST",
        Some(&json!({ "name": name, "mode": mode, "allowed": [], "blocked": [], "ephemeral_browser": ephem })),
    ) {
        Ok(v) => {
            let grp = v["group"].clone();
            let _ = with_server_opt(server, |s| {
                s.sync_groups(&[grp.clone()]);
                Ok(())
            });
            json!({"success": true, "group": grp})
        }
        Err(e) => match with_server_opt(server, |s| s.create_group(name, mode, vec![], vec![], ephem)) {
            Ok(grp) => json!({"success": true, "group": grp}),
            Err(_) => fail(e),
        },
    }
}

#[tauri::command]
pub async fn create_relay_group(
    state: tauri::State<'_, AppState>,
    name: String,
    mode: String,
    ephemeral_browser: Option<bool>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || create_relay_group_inner(srv.as_ref(), name, mode, ephemeral_browser)).await
}

fn update_relay_group_inner(
    server: Option<&ServerHandle>,
    group_id: String,
    name: String,
    mode: String,
    allowed: Vec<String>,
    blocked: Vec<String>,
    ephemeral_browser: Option<bool>,
) -> Value {
    let ephem = ephemeral_browser.unwrap_or(false);
    let lan_res = with_server_opt(server, |s| {
        s.update_group(
            group_id.clone(),
            name.clone(),
            mode.clone(),
            allowed.clone(),
            blocked.clone(),
            ephem,
        )
    });
    match relay_request(
        &format!("/api/v1/admin/groups/{}", group_id),
        "PUT",
        Some(&json!({ "name": name, "mode": mode, "allowed": allowed, "blocked": blocked, "ephemeral_browser": ephem })),
    ) {
        Ok(v) => {
            let grp = v["group"].clone();
            let _ = with_server_opt(server, |s| {
                s.sync_groups(&[grp.clone()]);
                Ok(())
            });
            json!({"success": true, "group": grp})
        }
        Err(e) => match lan_res {
            Ok(grp) => json!({"success": true, "group": grp}),
            Err(_) => fail(e),
        },
    }
}

#[tauri::command]
pub async fn update_relay_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
    name: String,
    mode: String,
    allowed: Vec<String>,
    blocked: Vec<String>,
    ephemeral_browser: Option<bool>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || update_relay_group_inner(srv.as_ref(), group_id, name, mode, allowed, blocked, ephemeral_browser)).await
}

fn delete_relay_group_inner(server: Option<&ServerHandle>, group_id: String) -> Value {
    let lan_res = with_server_opt(server, |s| s.delete_group(group_id.clone()));
    let relay_res = relay_delete(&format!("/api/v1/admin/groups/{}", group_id));
    if relay_res.is_ok() || lan_res.is_ok() {
        ok()
    } else {
        fail(relay_res.err().or(lan_res.err()).unwrap_or_else(|| "فشل الحذف".into()))
    }
}

#[tauri::command]
pub async fn delete_relay_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || delete_relay_group_inner(srv.as_ref(), group_id)).await
}

/// DELETE against the relay using the same candidate URL resolution as `relay_request`.
fn relay_delete(path: &str) -> Result<(), String> {
    relay_request(path, "DELETE", None).map(|_| ())
}

fn assign_device_group_inner(server: Option<&ServerHandle>, device_id: String, group_id: Option<String>) -> Value {
    let gid = group_id.clone().unwrap_or_default();
    if is_lan_device(server, &device_id) {
        if !gid.is_empty() {
            let known = with_server_opt(server, |s| Ok(s.has_group(&gid))).unwrap_or(false);
            if !known {
                if let Ok(v) = relay_request("/api/v1/admin/groups", "GET", None) {
                    if let Some(arr) = v["groups"].as_array() {
                        let _ = with_server_opt(server, |s| {
                            s.sync_groups(arr);
                            Ok(())
                        });
                    }
                }
            }
        }
        return result(with_server_opt(server, |s| s.assign_device_group(device_id.clone(), gid.clone())));
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
pub async fn assign_device_group(
    state: tauri::State<'_, AppState>,
    device_id: String,
    group_id: Option<String>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || assign_device_group_inner(srv.as_ref(), device_id, group_id)).await
}

fn send_group_command_inner(
    server: Option<&ServerHandle>,
    group_id: String,
    command: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Value {
    let (actor, role) = match resolve_actor(token, actor_username, actor_role) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    if !can_control_devices(&role) {
        return fail("صلاحية المشاهدة فقط لا تسمح بإرسال أوامر للمجموعات");
    }
    let lan_res = with_server_opt(server, |s| {
        s.send_group_command(group_id.clone(), command.clone(), &actor, &role)
    });
    let relay_res = relay_request(
        &format!("/api/v1/admin/groups/{}/command", group_id),
        "POST",
        Some(&json!({ "command": command, "actor": actor, "actor_role": role })),
    );
    if relay_res.is_ok() || lan_res.is_ok() {
        ok()
    } else {
        fail(relay_res.err().or(lan_res.err()).unwrap_or_else(|| "فشل إرسال الأمر".into()))
    }
}

#[tauri::command]
pub async fn send_group_command(
    state: tauri::State<'_, AppState>,
    group_id: String,
    command: String,
    token: Option<String>,
    actor_username: Option<String>,
    actor_role: Option<String>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || send_group_command_inner(srv.as_ref(), group_id, command, token, actor_username, actor_role)).await
}

fn rename_relay_device_inner(server: Option<&ServerHandle>, device_id: String, label: String) -> Value {
    if is_lan_device(server, &device_id) {
        return result(with_server_opt(server, |s| s.rename_device(device_id.clone(), label.clone())));
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
pub async fn rename_relay_device(
    state: tauri::State<'_, AppState>,
    device_id: String,
    label: String,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || rename_relay_device_inner(srv.as_ref(), device_id, label)).await
}

fn delete_relay_device_inner(server: Option<&ServerHandle>, device_id: String) -> Value {
    if is_lan_device(server, &device_id) {
        return result(with_server_opt(server, |s| s.delete_device(device_id.clone()).map(|_| ())));
    }
    result(relay_delete(&format!("/api/v1/admin/devices/{}", device_id)))
}

#[tauri::command]
pub async fn delete_relay_device(
    state: tauri::State<'_, AppState>,
    device_id: String,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || delete_relay_device_inner(srv.as_ref(), device_id)).await
}

// ---------- RustDesk support ----------

fn open_support_session_sync(
    rustdesk_id: String,
    password: Option<String>,
    mode: Option<String>,
) -> Value {
    match open_support_session_inner(rustdesk_id, password, mode) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn open_support_session(
    rustdesk_id: String,
    password: Option<String>,
    mode: Option<String>,
) -> Result<Value, String> {
    run_bg(move || open_support_session_sync(rustdesk_id, password, mode)).await
}

pub(crate) fn open_support_session_inner(
    rustdesk_id: String,
    password: Option<String>,
    mode: Option<String>,
) -> Result<(), String> {
    let id: String = rustdesk_id.chars().filter(|c| !c.is_whitespace()).collect();
    if id.is_empty() {
        return Err("لا يوجد RustDesk ID لهذا الجهاز".into());
    }
    // The ID goes into a URI/command line, so accept only plain RustDesk IDs.
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err("RustDesk ID غير صالح".into());
    }
    // Device-specific password (set from the admin key button) wins; otherwise use the
    // fleet-wide permanent password (defaults to DEFAULT_RUSTDESK_PASSWORD).
    let pw = password
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| {
            let cfg_pw = read_config().rustdesk_password.trim().to_string();
            if cfg_pw.is_empty() { DEFAULT_RUSTDESK_PASSWORD.to_string() } else { cfg_pw }
        });

    let session_mode = mode.as_deref().unwrap_or("support").trim().to_ascii_lowercase();
    let is_view_only = session_mode == "watch" || session_mode == "camera";
    crate::common::configure_admin_rustdesk_peer(&id, is_view_only);

    for exe in rustdesk_candidates() {
        if exe.is_file() {
            let mut cmd = std::process::Command::new(&exe);
            if session_mode == "camera" {
                cmd.args(["--view-camera", &id, "--password", &pw]);
            } else {
                cmd.args(["--connect", &id, "--password", &pw]);
            }
            cmd.spawn().map_err(|e| e.to_string())?;
            let mode_label = match session_mode.as_str() {
                "camera" => "CAMERA (view-only)",
                "watch" => "WATCH (view-only)",
                _ => "SUPPORT",
            };
            log_action(&format!("{} session opened to RustDesk {}", mode_label, id));
            return Ok(());
        }
    }
    Err("RustDesk غير مثبت على هذا الجهاز".into())
}

fn set_device_rustdesk_password_inner(
    server: Option<&ServerHandle>,
    device_id: String,
    password: String,
) -> Value {
    if is_lan_device(server, &device_id) {
        return result(with_server_opt(server, |s| {
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
pub async fn set_device_rustdesk_password(
    state: tauri::State<'_, AppState>,
    device_id: String,
    password: String,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || set_device_rustdesk_password_inner(srv.as_ref(), device_id, password)).await
}

fn request_screenshot_inner(
    server: Option<&ServerHandle>,
    device_id: String,
    transport: Option<String>,
    mode: Option<String>,
) -> Value {
    let use_lan = match transport.as_deref() {
        Some("lan") => true,
        Some("relay") => false,
        _ => is_lan_device(server, &device_id),
    };
    if use_lan {
        return result(with_server_opt(server, |s| s.request_screenshot(device_id.clone(), mode.clone())));
    }
    let body = json!({ "mode": mode.as_deref().unwrap_or("once") });
    result(
        relay_request(
            &format!("/api/v1/admin/devices/{}/screen/request", device_id),
            "POST",
            Some(&body),
        )
        .map(|_| ()),
    )
}

#[tauri::command]
pub async fn request_screenshot(
    state: tauri::State<'_, AppState>,
    device_id: String,
    transport: Option<String>,
    mode: Option<String>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || request_screenshot_inner(srv.as_ref(), device_id, transport, mode)).await
}

fn get_screenshot_inner(
    server: Option<&ServerHandle>,
    device_id: String,
    transport: Option<String>,
) -> Value {
    let use_lan = match transport.as_deref() {
        Some("lan") => true,
        Some("relay") => false,
        _ => is_lan_device(server, &device_id),
    };
    if use_lan {
        return match server {
            Some(s) => s.get_screenshot(device_id.clone()),
            None => json!({"ok": false, "image": "", "at": 0, "requested": false}),
        };
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

#[tauri::command]
pub async fn get_screenshot(
    state: tauri::State<'_, AppState>,
    device_id: String,
    transport: Option<String>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || get_screenshot_inner(srv.as_ref(), device_id, transport)).await
}

// ---------- Client-side link settings ----------

fn get_client_config_sync() -> Value {
    let link = read_client();
    // Probe the SYSTEM agent's local API so the UI can show the real state:
    // - agent_running: the --agent process owns 127.0.0.1:8788
    // - connected: the agent has an accepted poll (relay or LAN) right now
    let status = tls_agent(2)
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
pub async fn get_client_config() -> Result<Value, String> {
    run_bg(get_client_config_sync).await
}

#[tauri::command]
pub async fn set_client_config(
    server_url: String,
    token: String,
    password: Option<String>,
) -> Result<Value, String> {
    run_bg(move || match set_client_config_inner(server_url, token, password) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    })
    .await
}

fn is_private_ip_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower.starts_with("192.168.")
        || lower.starts_with("10.")
        || lower.starts_with("172.")
        || lower.starts_with("127.")
}

fn normalize_endpoint_url(raw: &str, default_port: u16, lan_only_port: bool) -> String {
    let mut u = raw.trim().trim_end_matches('/').to_string();
    if u.is_empty() {
        return u;
    }
    let lower = u.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        let scheme = if !lan_only_port || is_private_ip_host(&lower) { "http://" } else { "https://" };
        u = format!("{}{}", scheme, u);
    }
    let after_scheme = u.split_once("://").map(|(_, rest)| rest).unwrap_or(&u);
    let host_part = after_scheme.split('/').next().unwrap_or("");
    let needs_port = !host_part.is_empty() && !host_part.contains(':') && (!lan_only_port || is_private_ip_host(host_part));
    if needs_port {
        u.push_str(&format!(":{}", default_port));
    }
    u
}

fn normalize_lan_server_url(raw: &str) -> String {
    normalize_endpoint_url(raw, 8787, false)
}

fn normalize_relay_url(raw: &str) -> String {
    normalize_endpoint_url(raw, 8790, true)
}

fn set_client_config_inner(server_url: String, token: String, password: Option<String>) -> Result<(), String> {
    let cfg = read_config();
    let supplied = password.unwrap_or_default();
    if !cfg.password_hash.is_empty() && !password_ok(&cfg, &supplied) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        return Err("كلمة السر غير صحيحة".into());
    }
    let clean_url = normalize_lan_server_url(&server_url);
    let clean_token = token.trim().to_string();
    if clean_url.is_empty() || clean_token.is_empty() {
        return Err("أدخل عنوان السيرفر ومفتاح الربط".into());
    }

    let agent = tls_agent(10);
    let resp = agent
        .post(&format!("http://{}/local/link", LOCAL_API_ADDR))
        .send_json(json!({ "server_url": clean_url, "token": clean_token, "password": supplied }));
    match resp {
        Ok(r) => {
            let v: Value = r.into_json().map_err(|e| e.to_string())?;
            if v["success"].as_bool().unwrap_or(false) {
                Ok(())
            } else {
                Err(v["error"].as_str().unwrap_or("فشل الحفظ").to_string())
            }
        }
        Err(_) => {
            // Fallback when running standalone client EXE without the SYSTEM agent task active.
            let mut link = read_client();
            link.server_url = clean_url;
            link.token = clean_token;
            link.transport = "lan".to_string();
            link.relay_url = String::new();
            link.device_token = String::new();
            link.pairing_token = String::new();
            link.policy_version = String::new();
            write_client(&link)?;
            log_action("Server link updated (direct fallback)");
            if let Ok(exe) = std::env::current_exe() {
                let mut cmd = std::process::Command::new(exe);
                cmd.arg("--agent");
                let _ = hidden(&mut cmd).spawn();
            }
            let quick_http = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(4))
                .build();
            if crate::transport::lan_poll(&quick_http, &link, None).is_some() {
                Ok(())
            } else {
                Err("تم حفظ بيانات الربط، لكن تعذر الوصول لسيرفر المدير الآن (تأكد من العنوان والمفتاح وأن لوحة المدير مفتوحة)".into())
            }
        }
    }
}

#[tauri::command]
pub async fn enroll_relay(
    relay_url: String,
    pairing_token: String,
    password: Option<String>,
) -> Result<Value, String> {
    run_bg(move || match enroll_relay_inner(relay_url, pairing_token, password) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    })
    .await
}

fn enroll_relay_inner(relay_url: String, pairing_token: String, password: Option<String>) -> Result<(), String> {
    let cfg = read_config();
    let supplied = password.unwrap_or_default();
    if !cfg.password_hash.is_empty() && !password_ok(&cfg, &supplied) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        return Err("كلمة السر غير صحيحة".into());
    }
    let clean_url = normalize_relay_url(&relay_url);
    let clean_pt = pairing_token.trim().to_string();
    if clean_url.is_empty() {
        return Err("عنوان الـ Relay مطلوب".into());
    }
    let agent = tls_agent(35);
    let resp = agent
        .post(&format!("http://{}/local/relay", LOCAL_API_ADDR))
        .send_json(json!({
            "relay_url": clean_url,
            "pairing_token": clean_pt,
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
        Err(_) => {
            // Fallback when running standalone client EXE without the SYSTEM agent task active.
            let mut link = read_client();
            link.relay_url = clean_url;
            link.device_token = String::new();
            link.last_command_id = String::new();
            link.policy_version = String::new();
            link.transport = "relay".to_string();
            link.pairing_token = clean_pt;
            write_client(&link)?;
            log_action("Relay link updated (direct fallback)");
            if !link.pairing_token.is_empty() {
                if let Some((device_id, device_token)) =
                    crate::transport::RelayClient::new().enroll(&link.relay_url, &link.pairing_token)
                {
                    link.device_id = device_id;
                    link.device_token = device_token;
                    let _ = write_client(&link);
                    log_action("Relay enrollment succeeded (direct fallback)");
                }
            }
            if let Ok(exe) = std::env::current_exe() {
                let mut cmd = std::process::Command::new(exe);
                cmd.arg("--agent");
                let _ = hidden(&mut cmd).spawn();
            }
            Ok(())
        }
    }
}

#[tauri::command]
pub async fn disconnect_relay(password: Option<String>) -> Result<Value, String> {
    run_bg(move || match disconnect_relay_inner(password) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    })
    .await
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
        Err(_) => {
            let mut link = read_client();
            link.relay_url = String::new();
            link.device_token = String::new();
            link.pairing_token = String::new();
            link.last_command_id = String::new();
            link.transport = "lan".to_string();
            write_client(&link)?;
            log_action("Relay link removed (direct fallback)");
            Ok(())
        }
    }
}

// ---------- Web Admin RPC bridge (over LAN HTTP server) ----------

fn str_arg(args: &Value, key: &str) -> String {
    args[key].as_str().unwrap_or("").to_string()
}

fn opt_str_arg(args: &Value, key: &str) -> Option<String> {
    args[key].as_str().map(str::to_string)
}

fn str_vec_arg(args: &Value, key: &str) -> Vec<String> {
    args[key]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn extract_bearer_token<'a>(auth_header: Option<&'a str>, args: &'a Value) -> Option<&'a str> {
    if let Some(hdr) = auth_header {
        let trimmed = hdr.trim();
        if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
            let t = trimmed[7..].trim();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    args["token"].as_str().map(str::trim).filter(|s| !s.is_empty())
}

pub fn dispatch_web_rpc(server: &ServerHandle, raw_body: &str, auth_header: Option<&str>) -> (u16, Value) {
    let req: Value = match serde_json::from_str(raw_body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "طلب غير صالح"})),
    };
    let cmd = req["cmd"].as_str().unwrap_or("").trim();
    if cmd.is_empty() {
        return (400, json!({"ok": false, "error": "اسم الأمر مفقود"}));
    }
    let args = &req["args"];

    let raw_tok = extract_bearer_token(auth_header, args);
    let claims = raw_tok.and_then(|t| crate::auth::verify_jwt(t).ok());

    match cmd {
        "admin_login" => {
            let res = admin_login_sync(str_arg(args, "username"), str_arg(args, "password"));
            return (200, json!({"ok": true, "result": res}));
        }
        "get_server_info" => {
            let res = get_server_info_inner(Some(server), claims.is_some());
            return (200, json!({"ok": true, "result": res}));
        }
        "get_mode" => {
            return (200, json!({"ok": true, "result": get_mode()}));
        }
        _ => {}
    }

    let claims = match claims {
        Some(c) => c,
        None => return (401, json!({"ok": false, "error": "يرجى تسجيل الدخول بحساب المدير أولاً"})),
    };
    let verified_tok = raw_tok.map(str::to_string);
    let actor = claims.sub;
    let role = normalize_admin_role(&claims.role);

    if role == "viewer"
        && matches!(
            cmd,
            "add_site"
                | "remove_site"
                | "add_blocked_site"
                | "remove_blocked_site"
                | "set_list_mode"
                | "toggle_autostart"
                | "set_password"
                | "set_relay_config"
                | "create_pairing_token"
                | "sync_policy_now"
                | "create_relay_group"
                | "update_relay_group"
                | "delete_relay_group"
                | "assign_device_group"
                | "rename_relay_device"
                | "delete_relay_device"
                | "set_device_rustdesk_password"
        )
    {
        return (200, json!({"ok": true, "result": fail("صلاحية المشاهدة فقط لا تسمح بالتعديل")}));
    }

    let result_val = match cmd {
        "get_status" => json!(get_status()),
        "get_status_detail" => json!(get_status_detail()),
        "block_internet" => block_internet_sync(opt_str_arg(args, "password"), verified_tok, Some(actor), Some(role)),
        "unblock_internet" => unblock_internet_sync(opt_str_arg(args, "password"), verified_tok, Some(actor), Some(role)),
        "get_allowed_sites" => json!(get_allowed_sites()),
        "get_blocked_sites" => json!(get_blocked_sites()),
        "add_site" => add_site(str_arg(args, "site")),
        "remove_site" => remove_site(str_arg(args, "site")),
        "add_blocked_site" => add_blocked_site(str_arg(args, "site")),
        "remove_blocked_site" => remove_blocked_site(str_arg(args, "site")),
        "get_logs" => json!(read_log()),
        "get_config" => get_config(),
        "set_list_mode" => set_list_mode(str_arg(args, "mode")),
        "toggle_autostart" => toggle_autostart_sync(args["enable"].as_bool().unwrap_or(false)),
        "set_password" => set_password_sync(opt_str_arg(args, "currentPassword"), opt_str_arg(args, "newPassword")),
        "get_admin_users" => json!(get_admin_users_sync()),
        "upsert_admin_user" => upsert_admin_user_sync(
            str_arg(args, "username"),
            str_arg(args, "password"),
            opt_str_arg(args, "role"),
            verified_tok,
            Some(actor),
            Some(role),
        ),
        "remove_admin_user" => remove_admin_user_sync(
            str_arg(args, "username"),
            verified_tok,
            Some(actor),
            Some(role),
        ),
        "get_devices" => json!(get_devices_inner(Some(server))),
        "send_device_command" => send_device_command_inner(
            Some(server),
            str_arg(args, "deviceId"),
            str_arg(args, "command"),
            verified_tok,
            Some(actor),
            Some(role),
        ),
        "get_relay_config" => get_relay_config(),
        "set_relay_config" => set_relay_config_sync(
            str_arg(args, "relayUrl"),
            opt_str_arg(args, "adminKey"),
            opt_str_arg(args, "currentPassword"),
            opt_str_arg(args, "rustdeskServer"),
            opt_str_arg(args, "rustdeskKey"),
            opt_str_arg(args, "rustdeskPassword"),
        ),
        "create_pairing_token" => create_pairing_token_sync(opt_str_arg(args, "label")),
        "get_relay_devices" => json!(get_relay_devices_inner(Some(server))),
        "send_relay_command" => send_relay_command_sync(
            str_arg(args, "deviceId"),
            str_arg(args, "command"),
            verified_tok,
            Some(actor),
            Some(role),
        ),
        "sync_policy_now" => sync_policy_now_sync(),
        "get_relay_groups" => get_relay_groups_inner(Some(server)),
        "get_dashboard_stats" => get_dashboard_stats_sync(),
        "get_relay_alerts" => get_relay_alerts_inner(
            Some(server),
            opt_str_arg(args, "alertType"),
            opt_str_arg(args, "acked"),
        ),
        "get_alert_media" => get_alert_media_inner(Some(server), str_arg(args, "alertId")),
        "ack_alert" => ack_alert_inner(Some(server), str_arg(args, "alertId")),
        "get_uploaded_files" => get_uploaded_files_inner(opt_str_arg(args, "channel")),
        "open_archive_folder" => open_archive_folder_sync(opt_str_arg(args, "targetPath")),
        "get_audit_log" => get_audit_log_inner(Some(server)),
        "create_relay_group" => create_relay_group_inner(
            Some(server),
            str_arg(args, "name"),
            str_arg(args, "mode"),
            args["ephemeralBrowser"].as_bool(),
        ),
        "update_relay_group" => update_relay_group_inner(
            Some(server),
            str_arg(args, "groupId"),
            str_arg(args, "name"),
            str_arg(args, "mode"),
            str_vec_arg(args, "allowed"),
            str_vec_arg(args, "blocked"),
            args["ephemeralBrowser"].as_bool(),
        ),
        "delete_relay_group" => delete_relay_group_inner(Some(server), str_arg(args, "groupId")),
        "assign_device_group" => assign_device_group_inner(
            Some(server),
            str_arg(args, "deviceId"),
            opt_str_arg(args, "groupId"),
        ),
        "send_group_command" => send_group_command_inner(
            Some(server),
            str_arg(args, "groupId"),
            str_arg(args, "command"),
            verified_tok,
            Some(actor),
            Some(role),
        ),
        "rename_relay_device" => rename_relay_device_inner(
            Some(server),
            str_arg(args, "deviceId"),
            str_arg(args, "label"),
        ),
        "delete_relay_device" => delete_relay_device_inner(Some(server), str_arg(args, "deviceId")),
        "open_support_session" => open_support_session_sync(
            str_arg(args, "rustdeskId"),
            opt_str_arg(args, "password"),
            opt_str_arg(args, "mode"),
        ),
        "set_device_rustdesk_password" => set_device_rustdesk_password_inner(
            Some(server),
            str_arg(args, "deviceId"),
            str_arg(args, "password"),
        ),
        "request_screenshot" => request_screenshot_inner(
            Some(server),
            str_arg(args, "deviceId"),
            opt_str_arg(args, "transport"),
            opt_str_arg(args, "mode"),
        ),
        "get_screenshot" => get_screenshot_inner(
            Some(server),
            str_arg(args, "deviceId"),
            opt_str_arg(args, "transport"),
        ),
        _ => return (404, json!({"ok": false, "error": "أمر غير معروف"})),
    };
    (200, json!({"ok": true, "result": result_val}))
}

// Unused helpers kept for signature parity with the previous implementation.
#[allow(dead_code)]
fn hash_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}
