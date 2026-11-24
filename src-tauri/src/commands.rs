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

fn add_sites_bulk_sync(sites: Vec<String>, kind: String) -> Value {
    let is_blocked_list = kind.trim().eq_ignore_ascii_case("blocked");
    let target_path = if is_blocked_list { blocked_path() } else { allowed_path() };
    let header = if is_blocked_list { "Blocked sites" } else { "Allowed sites" };
    let mut items = read_list(&target_path);
    let mut added = 0usize;
    for raw in sites {
        for token in raw.split(|c: char| c == '\n' || c == '\r' || c == ',' || c == ';' || c.is_whitespace()) {
            let t = token.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(dom) = clean_domain(t) {
                if !items.contains(&dom) {
                    items.push(dom);
                    added += 1;
                }
            }
        }
    }
    match write_list(&target_path, header, &items) {
        Ok(_) => {
            let _ = sync_policy_now_sync();
            json!({ "success": true, "added": added, "total": items.len() })
        }
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn add_sites_bulk(sites: Vec<String>, kind: String) -> Result<Value, String> {
    run_bg(move || add_sites_bulk_sync(sites, kind)).await
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
        "dlp_super_only": cfg.dlp_super_only,
        "exfil_threshold_mb": cfg.exfil_threshold_mb,
        "exfil_window_secs": cfg.exfil_window_secs,
        "exfil_suspicious": cfg.exfil_suspicious,
        "erp_domains": cfg.erp_domains,
        "erp_master_token": if is_admin_mode() { cfg.erp_master_token } else { String::new() },
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

fn set_dlp_config_sync(
    usb_block: bool,
    exfil_threshold_mb: u64,
    exfil_window_secs: u64,
    exfil_suspicious: Vec<String>,
    dlp_super_only: Option<bool>,
    erp_domains: Option<Vec<String>>,
    erp_master_token: Option<String>,
) -> Value {
    let mut cfg = read_config();
    cfg.usb_block = usb_block;
    if let Some(super_only) = dlp_super_only {
        cfg.dlp_super_only = super_only;
    }
    cfg.exfil_threshold_mb = exfil_threshold_mb.clamp(1, 10_240);
    cfg.exfil_window_secs = exfil_window_secs.clamp(30, 86_400);
    let mut clean_hosts: Vec<String> = Vec::new();
    for raw in exfil_suspicious {
        for tok in raw.split(|c: char| c == '\n' || c == '\r' || c == ',' || c == ';' || c.is_whitespace()) {
            if let Some(d) = clean_domain(tok) {
                if !clean_hosts.contains(&d) {
                    clean_hosts.push(d);
                }
            }
        }
    }
    cfg.exfil_suspicious = clean_hosts;
    if let Some(raw_erp) = erp_domains {
        let mut clean_erp: Vec<String> = Vec::new();
        for raw in raw_erp {
            for tok in raw.split(|c: char| c == '\n' || c == '\r' || c == ',' || c == ';' || c.is_whitespace()) {
                if let Some(d) = clean_domain(tok) {
                    if !clean_erp.iter().any(|x| x.eq_ignore_ascii_case(&d)) {
                        clean_erp.push(d);
                    }
                }
            }
        }
        if !clean_erp.iter().any(|x| x.eq_ignore_ascii_case(DEFAULT_ERP_DOMAIN)) {
            clean_erp.insert(0, DEFAULT_ERP_DOMAIN.to_string());
        }
        cfg.erp_domains = clean_erp;
    }
    if let Some(tok) = erp_master_token {
        let trimmed = tok.trim();
        if !trimmed.is_empty() {
            cfg.erp_master_token = trimmed.to_string();
        }
    }
    if let Err(e) = write_config(&cfg) {
        return fail(e);
    }
    let _ = sync_policy_now_sync();
    ok()
}

#[tauri::command]
pub async fn set_dlp_config(
    usb_block: bool,
    exfil_threshold_mb: u64,
    exfil_window_secs: u64,
    exfil_suspicious: Vec<String>,
    dlp_super_only: Option<bool>,
    erp_domains: Option<Vec<String>>,
    erp_master_token: Option<String>,
) -> Result<Value, String> {
    run_bg(move || {
        set_dlp_config_sync(
            usb_block,
            exfil_threshold_mb,
            exfil_window_secs,
            exfil_suspicious,
            dlp_super_only,
            erp_domains,
            erp_master_token,
        )
    })
    .await
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
            existing.password_hash = hash_admin_password(password.trim());
        }
        existing.role = normalized_role.clone();
        existing.password_hash.clone()
    } else {
        let h = if password.trim().is_empty() { String::new() } else { hash_admin_password(password.trim()) };
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

struct LoginAttemptBucket {
    fails: u32,
    first_fail_ms: u64,
    locked_until_ms: u64,
}

static LOGIN_RATE_LIMIT: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, LoginAttemptBucket>>> =
    std::sync::OnceLock::new();

fn login_rate_map() -> &'static std::sync::Mutex<std::collections::HashMap<String, LoginAttemptBucket>> {
    LOGIN_RATE_LIMIT.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

pub(crate) fn check_login_lockout(rate_key: &str) -> Option<u64> {
    let mut map = login_rate_map().lock().unwrap_or_else(|e| e.into_inner());
    let now = now_ms();
    if let Some(b) = map.get_mut(rate_key) {
        if b.locked_until_ms > now {
            return Some((b.locked_until_ms - now + 999) / 1000);
        }
        if now.saturating_sub(b.first_fail_ms) > 600_000 {
            map.remove(rate_key);
        }
    }
    None
}

pub(crate) fn record_login_result(rate_key: &str, username: &str, client_ip: &str, success: bool) -> bool {
    let mut map = login_rate_map().lock().unwrap_or_else(|e| e.into_inner());
    if success {
        map.remove(rate_key);
        return false;
    }
    let now = now_ms();
    let entry = map.entry(rate_key.to_string()).or_insert(LoginAttemptBucket {
        fails: 0,
        first_fail_ms: now,
        locked_until_ms: 0,
    });
    if now.saturating_sub(entry.first_fail_ms) > 600_000 {
        entry.fails = 0;
        entry.first_fail_ms = now;
        entry.locked_until_ms = 0;
    }
    entry.fails += 1;
    if entry.fails >= 5 {
        entry.locked_until_ms = now + 600_000;
        let msg = format!(
            "تحذير أمني: حظر مؤقت بعد 5 محاولات دخول فاشلة لحساب المدير ({}) من العنوان {}",
            username,
            if client_ip.is_empty() { "محلي" } else { client_ip }
        );
        let _ = relay_request(
            "/api/v1/admin/alerts",
            "POST",
            Some(&json!({
                "device_id": "admin_portal",
                "device_name": "بوابة دخول المدير",
                "type": "auth_fail",
                "severity": "high",
                "message": msg,
                "meta": { "ip": client_ip, "username": username }
            })),
        );
        return true;
    }
    false
}

fn upgrade_legacy_admin_hash_if_needed(username: &str, plaintext_pw: &str) {
    if plaintext_pw.trim().is_empty() {
        return;
    }
    let mut cfg = read_config();
    let mut upgraded_hash: Option<(String, String)> = None;
    if let Some(u) = cfg.admins.iter_mut().find(|u| u.username.eq_ignore_ascii_case(username)) {
        if !u.password_hash.is_empty() && !u.password_hash.starts_with("pbkdf2$") {
            let new_h = hash_admin_password(plaintext_pw);
            u.password_hash = new_h.clone();
            upgraded_hash = Some((new_h, normalize_admin_role(&u.role)));
        }
    }
    if let Some((new_h, role)) = upgraded_hash {
        let _ = write_config(&cfg);
        if !cfg.relay_url.trim().is_empty() && !cfg.admin_key.trim().is_empty() {
            let _ = relay_request(
                "/api/v1/admin/users",
                "POST",
                Some(&json!({
                    "username": username,
                    "password_hash": new_h,
                    "role": role,
                    "actor_username": "security_auto_upgrade",
                })),
            );
        }
    }
}

pub(crate) fn admin_login_sync_with_ip(username: String, password: String, client_ip: Option<&str>) -> Value {
    let username = username.trim();
    if username.is_empty() {
        return fail("اسم المستخدم مطلوب");
    }
    let ip_str = client_ip.unwrap_or("local").trim();
    let rate_key = format!("{}|{}", ip_str, username.to_ascii_lowercase());
    if let Some(wait_secs) = check_login_lockout(&rate_key) {
        let mins = (wait_secs + 59) / 60;
        return fail(format!(
            "تم إيقاف المحاولات مؤقتاً لحماية الحساب بعد تكرار كلمة المرور الخاطئة. حاول مجدداً بعد {} دقيقة",
            mins.max(1)
        ));
    }

    let cfg = read_config();
    match admin_login_ok(&cfg, username, &password) {
        Some(role) => {
            record_login_result(&rate_key, username, ip_str, true);
            upgrade_legacy_admin_hash_if_needed(username, &password);
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
                    Some(&json!({ "username": username, "password": password, "client_ip": ip_str })),
                ) {
                    Ok(v) => {
                        if v["success"].as_bool().unwrap_or(false) {
                            record_login_result(&rate_key, username, ip_str, true);
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
            let locked = record_login_result(&rate_key, username, ip_str, false);
            if locked {
                fail("تم حظر الدخول مؤقتاً لمدة 10 دقائق بسبب 5 محاولات خاطئة متتالية، وتم تسجيل تنبيه أمني")
            } else {
                fail("اسم المستخدم أو كلمة المرور غير صحيحة")
            }
        }
    }
}

fn admin_login_sync(username: String, password: String) -> Value {
    admin_login_sync_with_ip(username, password, None)
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

fn check_server_connection_inner(server: Option<&ServerHandle>) -> Value {
    let lan_port = server.map(|s| s.port).unwrap_or(0);
    let is_host = is_local_relay_server();
    let cfg = read_config();
    let relay_url = cfg.relay_url.trim().trim_end_matches('/').to_string();
    let mut relay_connected = false;
    let mut relay_auth_ok = false;
    let mut relay_latency_ms = 0u64;
    let mut error_msg = String::new();

    if !relay_url.is_empty() {
        let target_base = if is_host {
            "http://127.0.0.1:8790".to_string()
        } else {
            relay_url.clone()
        };
        let started = std::time::Instant::now();
        let http = tls_agent(4);
        let check_url = format!("{}/api/v1/admin/rustdesk-oss", target_base);
        let mut req = http.get(&check_url);
        if !cfg.admin_key.trim().is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", cfg.admin_key.trim()));
        }
        match req.call() {
            Ok(resp) => {
                relay_latency_ms = started.elapsed().as_millis() as u64;
                relay_connected = resp.status() == 200;
                relay_auth_ok = resp.status() == 200;
            }
            Err(ureq::Error::Status(code, _)) => {
                relay_latency_ms = started.elapsed().as_millis() as u64;
                if code == 401 || code == 403 {
                    relay_connected = true;
                    relay_auth_ok = false;
                    error_msg = "مفتاح الربط بالسيرفر (ADMIN_KEY) غير مطابق".to_string();
                } else {
                    error_msg = format!("HTTP {}", code);
                }
            }
            Err(_) => {
                error_msg = "تعذر الوصول إلى السيرفر السحابي".to_string();
            }
        }
    }

    json!({
        "ok": relay_connected || (is_host && lan_port > 0),
        "relay_connected": relay_connected,
        "relay_auth_ok": relay_auth_ok,
        "relay_latency_ms": relay_latency_ms,
        "is_host_server": is_host,
        "lan_port": lan_port,
        "relay_url": relay_url,
        "error": error_msg,
        "checked_at": now_ms(),
    })
}

#[tauri::command]
pub async fn check_server_connection(state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || check_server_connection_inner(srv.as_ref())).await
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
        "usb_blocked": d.device.usb_blocked,
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
    let mut by_id: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    if let Some(s) = server {
        for d in s.devices() {
            let j = device_to_json(&d);
            if let Some(id) = j["device_id"].as_str() {
                by_id.insert(id.to_string(), j);
            }
        }
    }
    // When an IT Engineer runs Admin from outside the company (not on the Main Host Server),
    // also fetch the company's LAN devices via the authenticated Relay -> LAN bridge!
    if !is_local_relay_server() {
        if let Ok(v) = relay_request("/api/v1/admin/lan-proxy/devices", "GET", None) {
            if let Some(arr) = v["devices"].as_array() {
                for item in arr {
                    let mut c = item.clone();
                    c["transport"] = json!("lan");
                    if let Some(id) = c["device_id"].as_str().filter(|s| !s.is_empty()) {
                        by_id.entry(id.to_string()).or_insert(c);
                    }
                }
            }
        }
    }
    let mut out: Vec<Value> = by_id.into_values().collect();
    out.sort_by(|a, b| b["last_seen"].as_u64().unwrap_or(0).cmp(&a["last_seen"].as_u64().unwrap_or(0)));
    out
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
    let local_known = device_id != "*" && is_lan_device(server, &device_id);
    if local_known || is_local_relay_server() {
        return result(with_server_opt(server, |s| s.send_command(&device_id, &command, &actor, &role)));
    }
    let local_res = if device_id == "*" {
        with_server_opt(server, |s| s.send_command(&device_id, &command, &actor, &role)).ok()
    } else {
        None
    };
    let remote_lan = relay_request(
        &format!("/api/v1/admin/lan-proxy/devices/{}/command", device_id),
        "POST",
        Some(&json!({ "command": command, "actor": actor })),
    );
    if remote_lan.is_ok() || local_res.is_some() {
        ok()
    } else {
        fail(remote_lan.err().unwrap_or_else(|| "فشل إرسال الأمر للجهاز المحلي".into()))
    }
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
    crate::common::configure_admin_rustdesk_server();
    // Push the Full policy + RustDesk settings to every device on the next policy sync.
    let _ = sync_policy_now_sync();
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
    let def_cloud = DEFAULT_RELAY_URL.trim().trim_end_matches('/').to_string();
    if !def_cloud.is_empty() && !bases.iter().any(|b| b == &def_cloud) {
        bases.push(def_cloud);
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
                Ok(v) => {
                    return Err(v["error"].as_str().unwrap_or("طلب فاشل").to_string());
                }
                Err(e) => last_err = e.to_string(),
            },
            Err(ureq::Error::Status(code, r)) => {
                if let Ok(v) = r.into_json::<Value>() {
                    if let Some(msg) = v["error"].as_str().filter(|s| !s.trim().is_empty()) {
                        return Err(msg.to_string());
                    }
                }
                last_err = format!("رفض السيرفر الطلب (HTTP {})", code);
            }
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

fn get_wa_bot_status_sync() -> Value {
    match relay_request("/api/v1/admin/wa-bot/status", "GET", None) {
        Ok(mut v) => {
            v["success"] = json!(true);
            v
        }
        Err(e) => fail(e),
    }
}

fn save_wa_bot_config_sync(config: Value) -> Value {
    match relay_request("/api/v1/admin/wa-bot/config", "POST", Some(&config)) {
        Ok(mut v) => {
            v["success"] = json!(true);
            v
        }
        Err(e) => fail(e),
    }
}

fn connect_wa_bot_sync() -> Value {
    match relay_request("/api/v1/admin/wa-bot/connect", "POST", Some(&json!({}))) {
        Ok(mut v) => {
            v["success"] = json!(true);
            v
        }
        Err(e) => fail(e),
    }
}

fn disconnect_wa_bot_sync(logout: bool) -> Value {
    match relay_request("/api/v1/admin/wa-bot/disconnect", "POST", Some(&json!({ "logout": logout }))) {
        Ok(mut v) => {
            v["success"] = json!(true);
            v
        }
        Err(e) => fail(e),
    }
}

fn send_wa_bot_test_sync() -> Value {
    match relay_request("/api/v1/admin/wa-bot/test", "POST", Some(&json!({}))) {
        Ok(mut v) => {
            v["success"] = json!(true);
            v
        }
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn get_wa_bot_status() -> Result<Value, String> {
    run_bg(get_wa_bot_status_sync).await
}

#[tauri::command]
pub async fn save_wa_bot_config(config: Value) -> Result<Value, String> {
    run_bg(move || save_wa_bot_config_sync(config)).await
}

#[tauri::command]
pub async fn connect_wa_bot() -> Result<Value, String> {
    run_bg(connect_wa_bot_sync).await
}

#[tauri::command]
pub async fn disconnect_wa_bot(logout: Option<bool>) -> Result<Value, String> {
    run_bg(move || disconnect_wa_bot_sync(logout.unwrap_or(false))).await
}

#[tauri::command]
pub async fn send_wa_bot_test() -> Result<Value, String> {
    run_bg(send_wa_bot_test_sync).await
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
        "erp_domains": cfg.erp_domains,
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

fn ack_all_alerts_inner(server: Option<&ServerHandle>, alert_type: Option<String>) -> Value {
    let lan_n = server.map(|s| s.ack_all_alerts(alert_type.clone())).unwrap_or(0);
    let body = json!({ "type": alert_type.unwrap_or_default() });
    let relay_res = relay_request("/api/v1/admin/alerts/ack-all", "POST", Some(&body));
    let relay_n = relay_res
        .as_ref()
        .ok()
        .and_then(|v| v["count"].as_u64())
        .unwrap_or(0) as usize;
    if relay_res.is_ok() || server.is_some() {
        json!({ "success": true, "count": lan_n + relay_n })
    } else {
        fail("تعذر إقرار التنبيهات")
    }
}

#[tauri::command]
pub async fn ack_all_alerts(
    state: tauri::State<'_, AppState>,
    alert_type: Option<String>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || ack_all_alerts_inner(srv.as_ref(), alert_type)).await
}

fn get_rustdesk_oss_status_sync() -> Value {
    let mut cfg = read_config();
    let rd_dir = std::path::PathBuf::from(r"C:\ProgramData\IT-ELKHAWGA-RustDeskServer");
    let local_installed = rd_dir.join("hbbs.exe").is_file() && rd_dir.join("hbbr.exe").is_file();
    let mut pub_key = std::fs::read_to_string(rd_dir.join("id_ed25519.pub"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let local_running = ["127.0.0.1:21116", "127.0.0.1:21117"].iter().all(|addr| {
        addr.parse::<std::net::SocketAddr>()
            .ok()
            .map(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(80)).is_ok())
            .unwrap_or(false)
    });
    let mut installed = local_installed;
    let mut server_lan_ip = if local_installed { local_ip() } else { String::new() };
    let mut active_server = cfg.rustdesk_server.clone();
    let mut active_key = cfg.rustdesk_key.clone();

    if let Ok(v) = relay_request("/api/v1/admin/rustdesk-oss", "GET", None) {
        if v["installed"].as_bool().unwrap_or(false) {
            installed = true;
        }
        if let Some(pk) = v["public_key"].as_str().filter(|s| !s.trim().is_empty()) {
            if pub_key.is_empty() {
                pub_key = pk.trim().to_string();
            }
        }
        if let Some(rip) = v["lan_ip"].as_str().filter(|s| !s.trim().is_empty()) {
            server_lan_ip = rip.trim().to_string();
        }
        if v.get("active_server").is_some() {
            let r_srv = v["active_server"].as_str().unwrap_or("").trim().to_string();
            let r_key = v["active_key"].as_str().unwrap_or("").trim().to_string();
            if r_srv != cfg.rustdesk_server || r_key != cfg.rustdesk_key {
                cfg.rustdesk_server = r_srv.clone();
                cfg.rustdesk_key = r_key.clone();
                let _ = write_config(&cfg);
                crate::common::configure_admin_rustdesk_server();
            }
            active_server = r_srv;
            active_key = r_key;
        }
    }
    if server_lan_ip.is_empty() {
        server_lan_ip = local_ip();
    }
    json!({
        "ok": true,
        "installed": installed,
        "running": local_running || installed,
        "lan_host": format!("{}:21116", server_lan_ip),
        "lan_ip": server_lan_ip,
        "public_key": pub_key,
        "active_server": active_server,
        "active_key": active_key,
    })
}

#[tauri::command]
pub async fn get_rustdesk_oss_status() -> Result<Value, String> {
    run_bg(get_rustdesk_oss_status_sync).await
}

fn admin_update_state_path() -> std::path::PathBuf {
    data_dir().join("admin-update-state.json")
}

fn read_installed_admin_sha256() -> String {
    let Ok(raw) = std::fs::read_to_string(admin_update_state_path()) else {
        return String::new();
    };
    serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| v["installed_sha256"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn is_running_on_build_server() -> bool {
    if !is_local_relay_listening() {
        return false;
    }
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy().to_ascii_lowercase();
        if s.contains("final-release") || s.contains("target\\release") {
            return true;
        }
    }
    false
}

fn check_admin_update_sync() -> Value {
    if !is_admin_mode() {
        return json!({"ok": false, "available": false, "update_available": false});
    }
    let host_server = is_running_on_build_server();
    let local_mtime_ms = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let Ok(v) = relay_request("/api/v1/admin/update-info", "GET", None) else {
        return json!({
            "ok": false,
            "available": false,
            "update_available": false,
            "is_host_server": host_server,
            "local_mtime_ms": local_mtime_ms,
        });
    };
    let remote_sha = v["sha256"].as_str().unwrap_or("").trim().to_string();
    let remote_mtime = v["mtime_ms"].as_u64().unwrap_or(0);
    let remote_size = v["size"].as_u64().unwrap_or(0);
    let installed_sha = read_installed_admin_sha256();

    let update_available = if host_server || local_mtime_ms.saturating_add(90_000) >= remote_mtime {
        false
    } else if !installed_sha.is_empty() && !remote_sha.is_empty() {
        installed_sha != remote_sha
    } else {
        true
    };

    json!({
        "ok": true,
        "available": true,
        "update_available": update_available,
        "is_host_server": host_server,
        "remote_sha256": remote_sha,
        "installed_sha256": installed_sha,
        "remote_mtime_ms": remote_mtime,
        "local_mtime_ms": local_mtime_ms,
        "size": remote_size,
    })
}

#[tauri::command]
pub async fn check_admin_update() -> Result<Value, String> {
    run_bg(check_admin_update_sync).await
}

fn apply_admin_update_sync() -> Value {
    use std::io::Read;
    if !is_admin_mode() {
        return fail("متاح فقط لنسخة المهندس Admin");
    }
    if is_running_on_build_server() {
        return fail("أنت تعمل حالياً على السيرفر الرئيسي المحدّث بالفعل");
    }
    let cfg = read_config();
    let bases = relay_base_urls(&cfg);
    if bases.is_empty() || cfg.admin_key.trim().is_empty() {
        return fail("لم يتم ضبط اتصال الـ Relay لتحميل التحديث");
    }

    let http = tls_agent(120);
    let mut downloaded: Option<Vec<u8>> = None;
    let mut last_err = String::from("تعذر تحميل ملف تحديث الأدمن من السيرفر");
    for base in bases {
        let url = format!("{}/api/v1/admin/admin-setup.exe", base);
        match http
            .get(&url)
            .set("Authorization", &format!("Bearer {}", cfg.admin_key))
            .call()
        {
            Ok(resp) if resp.status() == 200 => {
                let mut buf = Vec::new();
                if resp.into_reader().take(60 * 1024 * 1024).read_to_end(&mut buf).is_ok()
                    && buf.len() > 500_000
                    && buf.starts_with(b"MZ")
                {
                    downloaded = Some(buf);
                    break;
                } else {
                    last_err = "حجم ملف التحديث غير مكتمل".into();
                }
            }
            Ok(resp) => {
                last_err = format!("رفض السيرفر التحميل (HTTP {})", resp.status());
            }
            Err(e) => {
                last_err = format!("خطأ اتصال أثناء التحميل: {}", e);
            }
        }
    }

    let Some(bytes) = downloaded else {
        return fail(last_err);
    };
    let sha_hex: String = Sha256::digest(&bytes).iter().map(|b| format!("{:02x}", b)).collect();
    let temp_setup = std::env::temp_dir().join("IT-ELKHAWGA-Admin-OnlineUpdate.exe");
    if let Err(e) = std::fs::write(&temp_setup, &bytes) {
        return fail(format!("تعذر حفظ ملف التحديث المؤقت: {}", e));
    }

    let _ = std::fs::write(
        admin_update_state_path(),
        serde_json::to_string_pretty(&json!({
            "installed_sha256": sha_hex,
            "updated_at": now_ms(),
        }))
        .unwrap_or_default(),
    );

    let current_exe_path = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| r"C:\Program Files\IT ELKHAWGA Admin\it-elkhawga.exe".to_string());
    let ps_path = std::env::temp_dir().join("itk-run-admin-update.ps1");
    let ps_script = format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
Start-Sleep -Milliseconds 900
$setup = '{setup}'
$relaunch = '{relaunch}'
$defaultInstalled = 'C:\Program Files\IT ELKHAWGA Admin\it-elkhawga.exe'
$p = Start-Process -FilePath $setup -ArgumentList '/S' -Verb RunAs -PassThru -Wait
Start-Sleep -Seconds 1
if (Test-Path -LiteralPath $defaultInstalled) {{
  Start-Process -FilePath $defaultInstalled
}} elseif (Test-Path -LiteralPath $relaunch) {{
  Start-Process -FilePath $relaunch
}}
"#,
        setup = temp_setup.to_string_lossy().replace('\'', "''"),
        relaunch = current_exe_path.replace('\'', "''"),
    );
    if let Err(e) = std::fs::write(&ps_path, ps_script) {
        return fail(format!("تعذر تجهيز سكربت التحديث: {}", e));
    }

    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        &ps_path.to_string_lossy(),
    ]);
    if let Err(e) = hidden(&mut cmd).spawn() {
        return fail(format!("تعذر بدء مثبت التحديث: {}", e));
    }
    log_action(&format!("Admin online self-update started ({} bytes, sha256={})", bytes.len(), &sha_hex[..12]));
    json!({
        "success": true,
        "size": bytes.len(),
        "sha256": sha_hex,
    })
}

#[tauri::command]
pub async fn apply_admin_update() -> Result<Value, String> {
    run_bg(apply_admin_update_sync).await
}

fn save_text_file_sync(content: String, file_name: String) -> Value {
    let mut clean: String = file_name
        .trim()
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
        clean = format!("IT-ELKHAWGA-Report-{}.csv", now_ms());
    }
    let dl_dir = std::env::var("USERPROFILE")
        .ok()
        .map(|u| std::path::PathBuf::from(u).join("Downloads"))
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dl_dir);
    let (stem, ext) = match clean.rfind('.') {
        Some(idx) if idx > 0 => (&clean[..idx], &clean[idx..]),
        _ => (clean.as_str(), ".csv"),
    };
    let mut dest = dl_dir.join(format!("{}{}", stem, ext));
    let mut n = 1u32;
    while dest.exists() && n < 500 {
        dest = dl_dir.join(format!("{} ({}){}", stem, n, ext));
        n += 1;
    }
    let mut bytes = Vec::new();
    if ext.eq_ignore_ascii_case(".csv") && !content.starts_with('\u{feff}') {
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    }
    bytes.extend_from_slice(content.as_bytes());
    if let Err(e) = std::fs::write(&dest, &bytes) {
        return fail(format!("فشل حفظ التقرير: {}", e));
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
pub async fn save_text_file(content: String, file_name: String) -> Result<Value, String> {
    run_bg(move || save_text_file_sync(content, file_name)).await
}

fn classify_archive_ext_kind(file_name: &str) -> &'static str {
    let lower = file_name.trim().to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "xls" | "xlsx" | "csv" | "doc" | "docx" | "pdf" | "ppt" | "pptx" | "txt" | "rtf"
        | "sql" | "db" | "sqlite" | "accdb" | "mdb" | "json" | "xml" => "docs",
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "svg" | "heic" => "images",
        "zip" | "rar" | "7z" | "tar" | "gz" | "iso" => "archives",
        _ => "other",
    }
}

#[derive(Default, Clone)]
struct ArchiveFilterParams {
    channel: Option<String>,
    from_ms: Option<u64>,
    to_ms: Option<u64>,
    file_type: Option<String>,
    device: Option<String>,
    search: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
    tz_offset_mins: Option<i64>,
}

fn url_encode_qp(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn get_uploaded_files_inner(params: ArchiveFilterParams) -> Value {
    let ch_filter = params.channel.unwrap_or_default().trim().to_ascii_lowercase();
    let from_ms = params.from_ms.unwrap_or(0);
    let to_ms = params.to_ms.unwrap_or(0);
    let ft_filter = params.file_type.unwrap_or_default().trim().to_ascii_lowercase();
    let dev_filter = params.device.unwrap_or_default().trim().to_string();
    let q_filter = params.search.unwrap_or_default().trim().to_lowercase();
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(60).clamp(10, 5000);
    let tz_offset_mins = params.tz_offset_mins.unwrap_or(-120);

    let mut qp = vec![
        format!("page={}", page),
        format!("page_size={}", page_size),
        format!("tz_offset={}", tz_offset_mins),
    ];
    if !ch_filter.is_empty() {
        qp.push(format!("channel={}", url_encode_qp(&ch_filter)));
    }
    if from_ms > 0 {
        qp.push(format!("from_ms={}", from_ms));
    }
    if to_ms > 0 {
        qp.push(format!("to_ms={}", to_ms));
    }
    if !ft_filter.is_empty() {
        qp.push(format!("file_type={}", url_encode_qp(&ft_filter)));
    }
    if !dev_filter.is_empty() {
        qp.push(format!("device={}", url_encode_qp(&dev_filter)));
    }
    if !q_filter.is_empty() {
        qp.push(format!("q={}", url_encode_qp(&q_filter)));
    }
    let q_path = format!("/api/v1/admin/uploads?{}", qp.join("&"));

    // Fast path: if Relay answered with scalable summary + daily_index, enrich & return directly!
    let mut relay_resp: Option<Value> = relay_request(&q_path, "GET", None).ok();
    if let Some(ref mut v) = relay_resp {
        if v["summary"].is_object() && v["daily_index"].is_array() {
            let local_root = crate::server::server_archive_root();
            let (local_free, local_total) = crate::server::disk_space_for_path(&local_root);
            if is_local_relay_server() && local_total > 0 {
                v["disk_free_bytes"] = json!(local_free);
                v["disk_total_bytes"] = json!(local_total);
                v["archive_root"] = json!(local_root.to_string_lossy().to_string());
                v["drives"] = json!(crate::server::list_server_drives());
            } else {
                let drives = relay_request("/api/v1/admin/lan-proxy/drives", "GET", None)
                    .ok()
                    .and_then(|d| d["drives"].as_array().cloned())
                    .unwrap_or_default();
                v["drives"] = json!(drives);
            }
            return v.clone();
        }
    }

    // Fallback (pure offline LAN mode without Relay): compute summary, daily_index, filter & paginate locally.
    let mut by_id: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for item in crate::server::read_local_archive_entries() {
        let fid = item["file_id"].as_str().unwrap_or("").trim().to_string();
        if !fid.is_empty() {
            by_id.insert(fid, item);
        }
    }
    if let Some(ref v) = relay_resp {
        if let Some(arr) = v["files"].as_array() {
            for item in arr {
                let fid = item["file_id"].as_str().unwrap_or("").trim().to_string();
                if !fid.is_empty() && !by_id.contains_key(&fid) {
                    by_id.insert(fid, item.clone());
                }
            }
        }
    }

    let mut all_files: Vec<Value> = by_id.into_values().collect();
    all_files.sort_by(|a, b| {
        b["created_at"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["created_at"].as_u64().unwrap_or(0))
    });

    let mut total_bytes = 0u64;
    let mut wa_count = 0usize;
    let mut sensitive_count = 0usize;
    let mut images_count = 0usize;
    let mut today_count = 0usize;
    let day_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        .saturating_sub(86_400_000);
    let mut per_dev: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut daily_map: std::collections::BTreeMap<String, (usize, usize, usize, usize, u64)> =
        std::collections::BTreeMap::new();

    for f in &all_files {
        let sz = f["file_size"].as_u64().unwrap_or(0);
        total_bytes = total_bytes.saturating_add(sz);
        let ch = f["channel"].as_str().unwrap_or("whatsapp_web").to_ascii_lowercase();
        if ch.contains("whatsapp") {
            wa_count += 1;
        }
        let fname = f["file_name"].as_str().unwrap_or("");
        let cat = classify_archive_ext_kind(fname);
        if cat == "docs" || cat == "archives" {
            sensitive_count += 1;
        }
        if cat == "images" {
            images_count += 1;
        }
        let ts = f["created_at"].as_u64().unwrap_or(0);
        if ts >= day_ago {
            today_count += 1;
        }
        let dn = f["device_name"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| f["device_id"].as_str())
            .unwrap_or("غير معروف")
            .to_string();
        *per_dev.entry(dn).or_insert(0) += 1;

        if ts > 0 {
            let shifted_ms = (ts as i64) - tz_offset_mins * 60_000;
            if let Some(dt) = chrono::DateTime::from_timestamp_millis(shifted_ms) {
                let day_key = dt.format("%Y-%m-%d").to_string();
                let entry = daily_map.entry(day_key).or_insert((0, 0, 0, 0, 0));
                entry.0 += 1;
                if cat == "images" {
                    entry.1 += 1;
                } else if cat == "docs" {
                    entry.2 += 1;
                } else if cat == "archives" {
                    entry.3 += 1;
                }
                entry.4 = entry.4.saturating_add(sz);
            }
        }
    }

    let mut top_device = "—".to_string();
    let mut top_device_count = 0usize;
    let mut devices_list: Vec<Value> = Vec::new();
    let mut dev_vec: Vec<(String, usize)> = per_dev.into_iter().collect();
    dev_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (name, cnt) in dev_vec {
        if cnt > top_device_count {
            top_device_count = cnt;
            top_device = name.clone();
        }
        devices_list.push(json!({"name": name, "count": cnt}));
    }

    let daily_index: Vec<Value> = daily_map
        .into_iter()
        .rev()
        .take(366)
        .map(|(day, (tot, imgs, docs, archs, b))| {
            json!({
                "day": day,
                "total": tot,
                "images": imgs,
                "docs": docs,
                "archives": archs,
                "bytes": b,
            })
        })
        .collect();

    let matched: Vec<Value> = all_files
        .iter()
        .filter(|f| {
            let ch = f["channel"].as_str().unwrap_or("whatsapp_web").to_ascii_lowercase();
            if ch_filter == "whatsapp_web" && !ch.contains("whatsapp") {
                return false;
            }
            if ch_filter == "web_upload" && ch.contains("whatsapp") {
                return false;
            }
            let ts = f["created_at"].as_u64().unwrap_or(0);
            if from_ms > 0 && ts < from_ms {
                return false;
            }
            if to_ms > 0 && ts > to_ms {
                return false;
            }
            let fname = f["file_name"].as_str().unwrap_or("");
            if !ft_filter.is_empty() && classify_archive_ext_kind(fname) != ft_filter {
                return false;
            }
            let dn = f["device_name"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| f["device_id"].as_str())
                .unwrap_or("");
            if !dev_filter.is_empty()
                && dn != dev_filter
                && f["device_id"].as_str().unwrap_or("") != dev_filter
            {
                return false;
            }
            if !q_filter.is_empty() {
                let hay = format!(
                    "{} {} {} {} {} {} {} {}",
                    fname,
                    dn,
                    f["device_id"].as_str().unwrap_or(""),
                    f["windows_user"].as_str().unwrap_or(""),
                    f["recipient_name"].as_str().unwrap_or(""),
                    f["recipient_phone"].as_str().unwrap_or(""),
                    f["page_url"].as_str().unwrap_or(""),
                    f["sha256"].as_str().unwrap_or("")
                )
                .to_lowercase();
                if !hay.contains(&q_filter) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let total_matching = matched.len();
    let total_pages = ((total_matching + page_size - 1) / page_size).max(1);
    let safe_page = page.min(total_pages);
    let offset = (safe_page - 1) * page_size;
    let files: Vec<Value> = matched
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|mut item| {
            let sp = item["stored_path"].as_str().unwrap_or("");
            item["exists_on_disk"] = json!(!sp.is_empty() && std::path::Path::new(sp).is_file());
            item
        })
        .collect();

    let local_root = crate::server::server_archive_root();
    let (local_free, local_total) = crate::server::disk_space_for_path(&local_root);

    json!({
        "ok": true,
        "archive_root": local_root.to_string_lossy().to_string(),
        "disk_free_bytes": local_free,
        "disk_total_bytes": local_total,
        "drives": crate::server::list_server_drives(),
        "summary": {
            "total_files": all_files.len(),
            "total_bytes": total_bytes,
            "whatsapp_count": wa_count,
            "sensitive_count": sensitive_count,
            "images_count": images_count,
            "today_count": today_count,
            "top_device": top_device,
            "top_device_count": top_device_count,
        },
        "devices": devices_list,
        "daily_index": daily_index,
        "total_matching": total_matching,
        "page": safe_page,
        "page_size": page_size,
        "total_pages": total_pages,
        "files": files,
    })
}

fn is_local_relay_server() -> bool {
    "127.0.0.1:8790"
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(40)).is_ok())
        .unwrap_or(false)
}

fn browse_folder_dialog_sync(current_dir: String, title: &str, default_subfolder: &str) -> Value {
    let ps_script = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         Add-Type -AssemblyName System.Windows.Forms; \
         $dlg = New-Object System.Windows.Forms.FolderBrowserDialog; \
         $dlg.Description = '{1}'; \
         $dlg.ShowNewFolderButton = $true; \
         if (Test-Path -LiteralPath '{0}') {{ $dlg.SelectedPath = '{0}' }}; \
         if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{ Write-Output $dlg.SelectedPath }}",
        current_dir.replace('\'', "''"),
        title.replace('\'', "''")
    );
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-Sta", "-ExecutionPolicy", "Bypass", "-Command", &ps_script]);
    match hidden(&mut cmd).output() {
        Ok(out) => {
            let chosen = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if chosen.is_empty() {
                json!({ "success": false, "cancelled": true })
            } else {
                let normalized = crate::server::normalize_custom_storage_dir(&chosen, default_subfolder)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or(chosen);
                json!({ "success": true, "path": normalized })
            }
        }
        Err(e) => fail(format!("تعذر فتح نافذة اختيار المجلد: {}", e)),
    }
}

#[tauri::command]
pub async fn browse_archive_folder() -> Result<Value, String> {
    run_bg(|| {
        let cur = crate::server::server_archive_root().to_string_lossy().to_string();
        browse_folder_dialog_sync(cur, "اختر مجلد تخزين أرشيف الملفات المرفوعة (DLP Archive)", "IT-ELKHAWGA-Archive")
    })
    .await
}

#[tauri::command]
pub async fn browse_backup_folder() -> Result<Value, String> {
    run_bg(|| {
        let cur = crate::server::backups_root_dir().to_string_lossy().to_string();
        browse_folder_dialog_sync(cur, "اختر مجلد حفظ النسخ الاحتياطية (System Backups)", "IT-ELKHAWGA-Backups")
    })
    .await
}

fn set_archive_dir_sync(new_path: String, move_existing: bool) -> Value {
    let res_val = if is_local_relay_server() {
        match crate::server::change_server_archive_dir(&new_path, move_existing) {
            Ok(v) => v,
            Err(e) => return fail(e),
        }
    } else {
        match relay_request(
            "/api/v1/admin/lan-proxy/archive/dir",
            "POST",
            Some(&json!({ "new_path": new_path, "move_existing": move_existing })),
        ) {
            Ok(v) => v,
            Err(e) => return fail(e),
        }
    };

    let old_r = res_val["old_root"].as_str().unwrap_or("");
    let new_r = res_val["archive_root"].as_str().unwrap_or("");
    if !new_r.is_empty() {
        let _ = relay_request(
            "/api/v1/admin/archive-migrate",
            "POST",
            Some(&json!({
                "old_root": old_r,
                "new_root": new_r,
                "moved": move_existing,
            })),
        );
    }
    res_val
}

#[tauri::command]
pub async fn set_archive_dir(new_path: String, move_existing: Option<bool>) -> Result<Value, String> {
    run_bg(move || set_archive_dir_sync(new_path, move_existing.unwrap_or(true))).await
}

fn set_backup_dir_sync(new_path: String, move_existing: bool) -> Value {
    if is_local_relay_server() {
        return match crate::server::change_server_backup_dir(&new_path, move_existing) {
            Ok(v) => v,
            Err(e) => fail(e),
        };
    }
    match relay_request(
        "/api/v1/admin/lan-proxy/backups/dir",
        "POST",
        Some(&json!({ "new_path": new_path, "move_existing": move_existing })),
    ) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn set_backup_dir(new_path: String, move_existing: Option<bool>) -> Result<Value, String> {
    run_bg(move || set_backup_dir_sync(new_path, move_existing.unwrap_or(true))).await
}

#[tauri::command]
pub async fn browse_erp_backup_folder() -> Result<Value, String> {
    run_bg(|| {
        let cur = crate::server::erp_backups_root_dir().to_string_lossy().to_string();
        browse_folder_dialog_sync(cur, "اختر مجلد حفظ النسخ الاحتياطية لموقع الشركة (elkhawaga.uk)", "Elkhawaga-ERP-Backups")
    })
    .await
}

fn set_erp_backup_dir_sync(new_path: String, move_existing: bool) -> Value {
    if is_local_relay_server() {
        return match crate::server::change_erp_backup_dir(&new_path, move_existing) {
            Ok(v) => v,
            Err(e) => fail(e),
        };
    }
    match relay_request(
        "/api/v1/admin/lan-proxy/erp-backups/dir",
        "POST",
        Some(&json!({ "new_path": new_path, "move_existing": move_existing })),
    ) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn set_erp_backup_dir(new_path: String, move_existing: Option<bool>) -> Result<Value, String> {
    run_bg(move || set_erp_backup_dir_sync(new_path, move_existing.unwrap_or(true))).await
}

#[tauri::command]
pub async fn get_uploaded_files(
    channel: Option<String>,
    from_ms: Option<u64>,
    to_ms: Option<u64>,
    file_type: Option<String>,
    device: Option<String>,
    search: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
    tz_offset_mins: Option<i64>,
) -> Result<Value, String> {
    let params = ArchiveFilterParams {
        channel,
        from_ms,
        to_ms,
        file_type,
        device,
        search,
        page,
        page_size,
        tz_offset_mins,
    };
    run_bg(move || get_uploaded_files_inner(params)).await
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
    usb_block: Option<bool>,
) -> Value {
    let ephem = ephemeral_browser.unwrap_or(false);
    let ublk = usb_block.unwrap_or(false);
    match relay_request(
        "/api/v1/admin/groups",
        "POST",
        Some(&json!({ "name": name, "mode": mode, "allowed": [], "blocked": [], "ephemeral_browser": ephem, "usb_block": ublk })),
    ) {
        Ok(v) => {
            let grp = v["group"].clone();
            let _ = with_server_opt(server, |s| {
                s.sync_groups(&[grp.clone()]);
                Ok(())
            });
            json!({"success": true, "group": grp})
        }
        Err(e) => match with_server_opt(server, |s| s.create_group(name, mode, vec![], vec![], ephem, ublk)) {
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
    usb_block: Option<bool>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || create_relay_group_inner(srv.as_ref(), name, mode, ephemeral_browser, usb_block)).await
}

fn update_relay_group_inner(
    server: Option<&ServerHandle>,
    group_id: String,
    name: String,
    mode: String,
    allowed: Vec<String>,
    blocked: Vec<String>,
    ephemeral_browser: Option<bool>,
    usb_block: Option<bool>,
) -> Value {
    let ephem = ephemeral_browser.unwrap_or(false);
    let ublk = usb_block.unwrap_or(false);
    let lan_res = with_server_opt(server, |s| {
        s.update_group(
            group_id.clone(),
            name.clone(),
            mode.clone(),
            allowed.clone(),
            blocked.clone(),
            ephem,
            ublk,
        )
    });
    match relay_request(
        &format!("/api/v1/admin/groups/{}", group_id),
        "PUT",
        Some(&json!({ "name": name, "mode": mode, "allowed": allowed, "blocked": blocked, "ephemeral_browser": ephem, "usb_block": ublk })),
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
    usb_block: Option<bool>,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || update_relay_group_inner(srv.as_ref(), group_id, name, mode, allowed, blocked, ephemeral_browser, usb_block)).await
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
    let r1 = relay_request(
        &format!("/api/v1/admin/devices/{}/group", device_id),
        "POST",
        Some(&json!({ "group_id": gid })),
    );
    if r1.is_ok() {
        return ok();
    }
    if !is_local_relay_server() {
        let r2 = relay_request(
            &format!("/api/v1/admin/lan-proxy/devices/{}/group", device_id),
            "POST",
            Some(&json!({ "group_id": gid })),
        );
        if r2.is_ok() {
            return ok();
        }
    }
    result(r1.map(|_| ()))
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
    let remote_lan_res = if !is_local_relay_server() {
        relay_request(
            &format!("/api/v1/admin/lan-proxy/groups/{}/command", group_id),
            "POST",
            Some(&json!({ "command": command, "actor": actor, "actor_role": role })),
        )
        .ok()
    } else {
        None
    };
    let relay_res = relay_request(
        &format!("/api/v1/admin/groups/{}/command", group_id),
        "POST",
        Some(&json!({ "command": command, "actor": actor, "actor_role": role })),
    );
    if relay_res.is_ok() || lan_res.is_ok() || remote_lan_res.is_some() {
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
    let r1 = relay_request(
        &format!("/api/v1/admin/devices/{}/label", device_id),
        "POST",
        Some(&json!({ "label": label })),
    );
    if r1.is_ok() {
        return ok();
    }
    if !is_local_relay_server() {
        if relay_request(
            &format!("/api/v1/admin/lan-proxy/devices/{}/label", device_id),
            "POST",
            Some(&json!({ "label": label })),
        )
        .is_ok()
        {
            return ok();
        }
    }
    result(r1.map(|_| ()))
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
    let r1 = relay_delete(&format!("/api/v1/admin/devices/{}", device_id));
    if !is_local_relay_server() {
        let r2 = relay_delete(&format!("/api/v1/admin/lan-proxy/devices/{}", device_id));
        if r1.is_ok() || r2.is_ok() {
            return ok();
        }
    }
    result(r1)
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
    device_ip: Option<String>,
) -> Value {
    match open_support_session_inner(rustdesk_id, password, mode, device_ip) {
        Ok(_) => ok(),
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn open_support_session(
    rustdesk_id: String,
    password: Option<String>,
    mode: Option<String>,
    device_ip: Option<String>,
) -> Result<Value, String> {
    run_bg(move || open_support_session_sync(rustdesk_id, password, mode, device_ip)).await
}

fn try_fast_lan_direct_target(device_ip: Option<&str>) -> Option<String> {
    let raw = device_ip?.trim().trim_start_matches("::ffff:");
    if raw.is_empty() || raw.starts_with("127.") {
        return None;
    }
    if !is_private_ip_host(raw) {
        return None;
    }
    let sock: std::net::SocketAddr = format!("{}:21118", raw).parse().ok()?;
    if std::net::TcpStream::connect_timeout(&sock, std::time::Duration::from_millis(85)).is_ok() {
        Some(raw.to_string())
    } else {
        None
    }
}

pub(crate) fn open_support_session_inner(
    rustdesk_id: String,
    password: Option<String>,
    mode: Option<String>,
    device_ip: Option<String>,
) -> Result<(), String> {
    let id: String = rustdesk_id.chars().filter(|c| !c.is_whitespace()).collect();
    let direct_ip = try_fast_lan_direct_target(device_ip.as_deref());
    if id.is_empty() && direct_ip.is_none() {
        return Err("لا يوجد RustDesk ID لهذا الجهاز".into());
    }
    // The ID goes into a URI/command line, so accept only plain RustDesk IDs.
    if !id.is_empty() && !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
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
    if !id.is_empty() {
        crate::common::configure_admin_rustdesk_peer(&id, is_view_only);
    }
    if let Some(ref lip) = direct_ip {
        crate::common::configure_admin_rustdesk_peer(lip, is_view_only);
    }
    let connect_target = direct_ip.as_deref().unwrap_or(id.as_str());

    for exe in rustdesk_candidates() {
        if exe.is_file() {
            let mut cmd = std::process::Command::new(&exe);
            if session_mode == "camera" {
                cmd.args(["--view-camera", connect_target, "--password", &pw]);
            } else {
                cmd.args(["--connect", connect_target, "--password", &pw]);
            }
            cmd.spawn().map_err(|e| e.to_string())?;
            let mode_label = match session_mode.as_str() {
                "camera" => "CAMERA (view-only)",
                "watch" => "WATCH (view-only)",
                _ => "SUPPORT",
            };
            log_action(&format!("{} session opened to RustDesk {}", mode_label, connect_target));
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
    let r1 = relay_request(
        &format!("/api/v1/admin/devices/{}/rustdesk_password", device_id),
        "POST",
        Some(&json!({ "password": password })),
    );
    if r1.is_ok() {
        return ok();
    }
    if !is_local_relay_server() {
        if relay_request(
            &format!("/api/v1/admin/lan-proxy/devices/{}/rustdesk_password", device_id),
            "POST",
            Some(&json!({ "password": password })),
        )
        .is_ok()
        {
            return ok();
        }
    }
    result(r1.map(|_| ()))
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
    let body = json!({ "mode": mode.as_deref().unwrap_or("once") });
    let use_lan = match transport.as_deref() {
        Some("lan") => true,
        Some("relay") => false,
        _ => is_lan_device(server, &device_id),
    };
    if use_lan {
        if is_lan_device(server, &device_id) || is_local_relay_server() {
            return result(with_server_opt(server, |s| s.request_screenshot(device_id.clone(), mode.clone())));
        }
        return result(
            relay_request(
                &format!("/api/v1/admin/lan-proxy/devices/{}/screen/request", device_id),
                "POST",
                Some(&body),
            )
            .map(|_| ()),
        );
    }
    let r1 = relay_request(
        &format!("/api/v1/admin/devices/{}/screen/request", device_id),
        "POST",
        Some(&body),
    );
    if r1.is_ok() {
        return ok();
    }
    if !is_local_relay_server() {
        if relay_request(
            &format!("/api/v1/admin/lan-proxy/devices/{}/screen/request", device_id),
            "POST",
            Some(&body),
        )
        .is_ok()
        {
            return ok();
        }
    }
    result(r1.map(|_| ()))
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
        if is_lan_device(server, &device_id) || is_local_relay_server() {
            return match server {
                Some(s) => s.get_screenshot(device_id.clone()),
                None => json!({"ok": false, "image": "", "at": 0, "requested": false}),
            };
        }
        return relay_request(
            &format!("/api/v1/admin/lan-proxy/devices/{}/screen", device_id),
            "GET",
            None,
        )
        .unwrap_or_else(|_| json!({"ok": false, "image": "", "at": 0, "requested": false}));
    }
    match relay_request(
        &format!("/api/v1/admin/devices/{}/screen", device_id),
        "GET",
        None,
    ) {
        Ok(v) if !v["image"].as_str().unwrap_or("").is_empty() || v["requested"].as_bool().unwrap_or(false) => v,
        Ok(v) => {
            if !is_local_relay_server() {
                if let Ok(lv) = relay_request(
                    &format!("/api/v1/admin/lan-proxy/devices/{}/screen", device_id),
                    "GET",
                    None,
                ) {
                    if !lv["image"].as_str().unwrap_or("").is_empty() || lv["requested"].as_bool().unwrap_or(false) {
                        return lv;
                    }
                }
            }
            v
        }
        Err(_) => json!({"ok": false, "image": "", "at": 0, "requested": false}),
    }
}

fn get_backups_list_inner() -> Value {
    if is_local_relay_server() {
        return crate::server::list_server_backups();
    }
    relay_request("/api/v1/admin/lan-proxy/backups", "GET", None)
        .unwrap_or_else(|_| crate::server::list_server_backups())
}

#[tauri::command]
pub async fn get_backups_list() -> Result<Value, String> {
    run_bg(get_backups_list_inner).await
}

fn create_system_backup_inner() -> Value {
    if is_local_relay_server() {
        return match crate::server::create_server_backup("manual") {
            Ok(v) => v,
            Err(e) => fail(e),
        };
    }
    match relay_request(
        "/api/v1/admin/lan-proxy/backups/create",
        "POST",
        Some(&json!({ "reason": "manual_remote" })),
    ) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn create_system_backup() -> Result<Value, String> {
    run_bg(create_system_backup_inner).await
}

fn restore_system_backup_inner(server: Option<&ServerHandle>, backup_id: String) -> Value {
    if is_local_relay_server() {
        let reg = server.map(|s| &s.registry);
        return match crate::server::restore_server_backup(&backup_id, reg) {
            Ok(v) => {
                let _ = sync_policy_now_sync();
                v
            }
            Err(e) => fail(e),
        };
    }
    match relay_request(
        "/api/v1/admin/lan-proxy/backups/restore",
        "POST",
        Some(&json!({ "backup_id": backup_id })),
    ) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn restore_system_backup(
    state: tauri::State<'_, AppState>,
    backup_id: String,
) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || restore_system_backup_inner(srv.as_ref(), backup_id)).await
}

#[tauri::command]
pub async fn open_backups_folder() -> Result<Value, String> {
    run_bg(|| {
        let dir = crate::server::backups_root_dir();
        let _ = std::fs::create_dir_all(&dir);
        let mut cmd = std::process::Command::new("explorer.exe");
        cmd.arg(&dir);
        match cmd.spawn() {
            Ok(_) => ok(),
            Err(e) => fail(format!("تعذر فتح مجلد النسخ الاحتياطية: {}", e)),
        }
    })
    .await
}

fn get_erp_backups_status_inner() -> Value {
    if is_local_relay_server() {
        return crate::server::list_erp_backups();
    }
    relay_request("/api/v1/admin/lan-proxy/erp-backups", "GET", None)
        .unwrap_or_else(|_| crate::server::list_erp_backups())
}

#[tauri::command]
pub async fn get_erp_backups_status() -> Result<Value, String> {
    run_bg(get_erp_backups_status_inner).await
}

fn save_erp_backup_config_inner(
    enabled: bool,
    interval_mins: u64,
    url: String,
    username: String,
    password: Option<String>,
    did_cookie: Option<String>,
    device_token: Option<String>,
) -> Value {
    let payload = json!({
        "enabled": enabled,
        "interval_mins": interval_mins,
        "url": url,
        "username": username,
        "password": password.unwrap_or_default(),
        "did_cookie": did_cookie,
        "device_token": device_token,
    });
    if is_local_relay_server() {
        return match crate::server::save_erp_backup_settings(&payload) {
            Ok(v) => v,
            Err(e) => fail(e),
        };
    }
    match relay_request("/api/v1/admin/lan-proxy/erp-backups/config", "POST", Some(&payload)) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn save_erp_backup_config(
    enabled: bool,
    interval_mins: u64,
    url: String,
    username: String,
    password: Option<String>,
    did_cookie: Option<String>,
    device_token: Option<String>,
) -> Result<Value, String> {
    run_bg(move || {
        save_erp_backup_config_inner(enabled, interval_mins, url, username, password, did_cookie, device_token)
    })
    .await
}

fn run_erp_backup_now_inner(server: Option<&ServerHandle>) -> Value {
    if is_local_relay_server() {
        let reg = server.map(|s| s.registry.clone());
        return match crate::server::trigger_erp_site_backup("manual", reg) {
            Ok(v) => v,
            Err(e) => fail(e),
        };
    }
    match relay_request(
        "/api/v1/admin/lan-proxy/erp-backups/run",
        "POST",
        Some(&json!({ "reason": "manual_remote" })),
    ) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn run_erp_backup_now(state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let srv = server_opt(&state);
    run_bg(move || run_erp_backup_now_inner(srv.as_ref())).await
}

#[tauri::command]
pub async fn open_erp_backups_folder() -> Result<Value, String> {
    run_bg(|| {
        let dir = crate::server::erp_backups_root_dir();
        let _ = std::fs::create_dir_all(&dir);
        let mut cmd = std::process::Command::new("explorer.exe");
        cmd.arg(&dir);
        match cmd.spawn() {
            Ok(_) => ok(),
            Err(e) => fail(format!("تعذر فتح مجلد نسخ الموقع: {}", e)),
        }
    })
    .await
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
            let quick_http = tls_agent(4);
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

pub fn dispatch_web_rpc(
    server: &ServerHandle,
    raw_body: &str,
    auth_header: Option<&str>,
    client_ip: Option<&str>,
) -> (u16, Value) {
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
            let res = admin_login_sync_with_ip(str_arg(args, "username"), str_arg(args, "password"), client_ip);
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

    if cmd == "get_server_info" {
        let include_tok = role != "viewer";
        let res = get_server_info_inner(Some(server), include_tok);
        return (200, json!({"ok": true, "result": res}));
    }

    if role == "viewer"
        && matches!(
            cmd,
            "add_site"
                | "remove_site"
                | "add_blocked_site"
                | "remove_blocked_site"
                | "add_sites_bulk"
                | "set_list_mode"
                | "set_dlp_config"
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
                | "ack_alert"
                | "ack_all_alerts"
                | "open_archive_folder"
        )
    {
        return (200, json!({"ok": true, "result": fail("صلاحية المشاهدة فقط لا تسمح بالتعديل")}));
    }

    if role == "viewer" && cmd == "open_support_session" {
        let req_mode = args["mode"].as_str().unwrap_or("support").trim().to_ascii_lowercase();
        if req_mode != "watch" {
            return (200, json!({"ok": true, "result": fail("صلاحية المشاهدة فقط تسمح بوضع المشاهدة دون التحكم الكامل")}));
        }
    }

    if matches!(cmd, "get_uploaded_files" | "open_archive_folder") {
        let cur_cfg = read_config();
        if cur_cfg.dlp_super_only && role != "super" {
            return (200, json!({
                "ok": true,
                "result": {
                    "ok": false,
                    "success": false,
                    "files": [],
                    "error": "تم حصر الاطلاع على أرشيف الملفات الحساسة بحساب السوبر أدمن فقط"
                }
            }));
        }
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
        "add_sites_bulk" => add_sites_bulk_sync(str_vec_arg(args, "sites"), str_arg(args, "kind")),
        "get_logs" => json!(read_log()),
        "get_config" => {
            let mut v = get_config();
            if role != "super" {
                v["api_token"] = json!("");
            }
            if role == "viewer" {
                v["erp_master_token"] = json!("");
            }
            v
        }
        "set_list_mode" => set_list_mode(str_arg(args, "mode")),
        "set_dlp_config" => set_dlp_config_sync(
            args["usbBlock"].as_bool().unwrap_or(false),
            args["exfilThresholdMb"].as_u64().unwrap_or(50),
            args["exfilWindowSecs"].as_u64().unwrap_or(600),
            str_vec_arg(args, "exfilSuspicious"),
            if role == "super" { args["dlpSuperOnly"].as_bool() } else { None },
            if args["erpDomains"].is_array() { Some(str_vec_arg(args, "erpDomains")) } else { None },
            opt_str_arg(args, "erpMasterToken"),
        ),
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
        "check_server_connection" => check_server_connection_inner(Some(server)),
        "send_device_command" => send_device_command_inner(
            Some(server),
            str_arg(args, "deviceId"),
            str_arg(args, "command"),
            verified_tok,
            Some(actor),
            Some(role),
        ),
        "get_relay_config" => {
            let mut v = get_relay_config();
            if role != "super" {
                v["admin_key"] = json!("");
            }
            v
        }
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
        "ack_all_alerts" => ack_all_alerts_inner(Some(server), opt_str_arg(args, "alertType")),
        "get_rustdesk_oss_status" => get_rustdesk_oss_status_sync(),
        "check_admin_update" => check_admin_update_sync(),
        "get_uploaded_files" => get_uploaded_files_inner(ArchiveFilterParams {
            channel: opt_str_arg(args, "channel"),
            from_ms: args.get("fromMs").and_then(|v| v.as_u64()),
            to_ms: args.get("toMs").and_then(|v| v.as_u64()),
            file_type: opt_str_arg(args, "fileType"),
            device: opt_str_arg(args, "device"),
            search: opt_str_arg(args, "search"),
            page: args.get("page").and_then(|v| v.as_u64()).map(|n| n as usize),
            page_size: args.get("pageSize").and_then(|v| v.as_u64()).map(|n| n as usize),
            tz_offset_mins: args.get("tzOffsetMins").and_then(|v| v.as_i64()),
        }),
        "get_backups_list" => get_backups_list_inner(),
        "create_system_backup" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه إنشاء أو استعادة النسخ الاحتياطية")
            } else {
                create_system_backup_inner()
            }
        }
        "restore_system_backup" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه استعادة النسخ الاحتياطية")
            } else {
                restore_system_backup_inner(Some(server), str_arg(args, "backupId"))
            }
        }
        "set_archive_dir" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه تغيير مسار تخزين الأرشيف على السيرفر")
            } else {
                set_archive_dir_sync(
                    str_arg(args, "newPath"),
                    args["moveExisting"].as_bool().unwrap_or(true),
                )
            }
        }
        "set_backup_dir" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه تغيير مسار حفظ النسخ الاحتياطية على السيرفر")
            } else {
                set_backup_dir_sync(
                    str_arg(args, "newPath"),
                    args["moveExisting"].as_bool().unwrap_or(true),
                )
            }
        }
        "get_erp_backups_status" => get_erp_backups_status_inner(),
        "save_erp_backup_config" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه تعديل إعدادات النسخ الاحتياطي لموقع الشركة")
            } else {
                save_erp_backup_config_inner(
                    args["enabled"].as_bool().unwrap_or(false),
                    args["intervalMins"].as_u64().unwrap_or(60),
                    str_arg(args, "url"),
                    str_arg(args, "username"),
                    opt_str_arg(args, "password"),
                    opt_str_arg(args, "didCookie"),
                    opt_str_arg(args, "deviceToken"),
                )
            }
        }
        "run_erp_backup_now" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه سحب نسخة احتياطية من موقع الشركة")
            } else {
                run_erp_backup_now_inner(Some(server))
            }
        }
        "set_erp_backup_dir" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه تغيير مسار حفظ نسخ موقع الشركة على السيرفر")
            } else {
                set_erp_backup_dir_sync(
                    str_arg(args, "newPath"),
                    args["moveExisting"].as_bool().unwrap_or(true),
                )
            }
        }
        "open_archive_folder" => open_archive_folder_sync(opt_str_arg(args, "targetPath")),
        "get_audit_log" => get_audit_log_inner(Some(server)),
        "create_relay_group" => create_relay_group_inner(
            Some(server),
            str_arg(args, "name"),
            str_arg(args, "mode"),
            args["ephemeralBrowser"].as_bool(),
            args["usbBlock"].as_bool(),
        ),
        "update_relay_group" => update_relay_group_inner(
            Some(server),
            str_arg(args, "groupId"),
            str_arg(args, "name"),
            str_arg(args, "mode"),
            str_vec_arg(args, "allowed"),
            str_vec_arg(args, "blocked"),
            args["ephemeralBrowser"].as_bool(),
            args["usbBlock"].as_bool(),
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
            opt_str_arg(args, "deviceIp"),
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
        "get_wa_bot_status" => get_wa_bot_status_sync(),
        "save_wa_bot_config" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه تعديل إعدادات بوت واتساب")
            } else {
                save_wa_bot_config_sync(args.get("config").cloned().unwrap_or_else(|| json!({})))
            }
        }
        "connect_wa_bot" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه ربط بوت واتساب")
            } else {
                connect_wa_bot_sync()
            }
        }
        "disconnect_wa_bot" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه فصل بوت واتساب")
            } else {
                disconnect_wa_bot_sync(args["logout"].as_bool().unwrap_or(false))
            }
        }
        "send_wa_bot_test" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه إرسال رسالة اختبار")
            } else {
                send_wa_bot_test_sync()
            }
        }
        "cctv_list_dvrs" => {
            let mut v = cctv_list_dvrs_sync_for_actor(Some(&actor), Some(&role));
            let super_only = v["settings"]["super_only"].as_bool().unwrap_or(false);
            if super_only && role != "super" {
                v["dvrs"] = json!([]);
                v["restricted"] = json!(true);
            }
            v
        }
        "cctv_action" => {
            let act = str_arg(args, "action");
            let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
            if role != "super" {
                let list_chk = cctv_list_dvrs_sync();
                if list_chk["settings"]["super_only"].as_bool().unwrap_or(false) {
                    return (200, json!({"ok": true, "result": fail("تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط")}));
                }
            }
            if role == "viewer" && matches!(act.as_str(), "ptz" | "save_channel_meta" | "pull_names" | "save_settings") {
                fail("صلاحية المشاهدة فقط لا تسمح بالتعديل أو تحريك الكاميرات")
            } else {
                cctv_action_sync(act, payload, Some(actor), Some(role))
            }
        }
        "cctv_save_dvr" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه إضافة أو تعديل أجهزة الـ DVR")
            } else {
                cctv_save_dvr_sync(args.get("dvr").cloned().unwrap_or_else(|| args.clone()))
            }
        }
        "cctv_delete_dvr" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه حذف أجهزة الـ DVR")
            } else {
                cctv_delete_dvr_sync(str_arg(args, "id"))
            }
        }
        "cctv_test_dvr" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه فحص اتصال الـ DVR")
            } else {
                cctv_test_dvr_sync(args.get("dvr").cloned().unwrap_or_else(|| args.clone()))
            }
        }
        "cctv_scan_lan" => {
            if role != "super" && role != "admin" {
                fail("فقط المدير أو السوبر أدمن يمكنه البحث التلقائي عن أجهزة الـ DVR")
            } else {
                cctv_scan_lan_sync(opt_str_arg(args, "bridgeDeviceId"))
            }
        }
        "cctv_set_settings" => {
            if role != "super" {
                fail("فقط السوبر أدمن يمكنه تعديل صلاحية خصوصية الكاميرات")
            } else {
                cctv_set_settings_sync(args["superOnly"].as_bool().unwrap_or(false))
            }
        }
        "cctv_get_frame_b64" => {
            let list_chk = cctv_list_dvrs_sync();
            if list_chk["settings"]["super_only"].as_bool().unwrap_or(false) && role != "super" {
                fail("تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط")
            } else {
                cctv_get_frame_b64_sync(
                    str_arg(args, "dvrId"),
                    args["channel"].as_u64().unwrap_or(1) as u32,
                    args["hd"].as_bool().unwrap_or(false),
                )
            }
        }
        _ => return (404, json!({"ok": false, "error": "أمر غير معروف"})),
    };
    (200, json!({"ok": true, "result": result_val}))
}

// ---------- Dahua CCTV Live Center Commands ----------

fn cctv_list_dvrs_sync() -> Value {
    cctv_list_dvrs_sync_for_actor(None, None)
}

fn cctv_list_dvrs_sync_for_actor(actor: Option<&str>, role: Option<&str>) -> Value {
    let mut qs = String::new();
    if let Some(a) = actor.filter(|s| !s.trim().is_empty()) {
        qs.push_str(&format!("?actor={}&role={}", a, role.unwrap_or("super")));
    }
    match relay_request(&format!("/api/v1/admin/cctv/list{}", qs), "GET", None) {
        Ok(v) => v,
        Err(e) => json!({ "ok": false, "dvrs": [], "settings": { "super_only": false }, "error": e }),
    }
}

fn cctv_action_sync(action: String, payload: Value, actor: Option<String>, role: Option<String>) -> Value {
    if action == "download_clip_local" {
        return cctv_download_clip_local_sync(&payload);
    }
    let body = json!({
        "action": action,
        "payload": payload,
        "actor": actor.unwrap_or_default(),
        "role": role.unwrap_or_else(|| "super".to_string()),
    });
    match relay_request("/api/v1/admin/cctv/action", "POST", Some(&body)) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

fn cctv_download_clip_local_sync(payload: &Value) -> Value {
    use std::io::Read;
    let dvr_id = payload["dvr_id"].as_str().unwrap_or("").trim();
    let ch = payload["channel"].as_u64().unwrap_or(1);
    let st = payload["start_time"].as_str().unwrap_or("").trim();
    let et = payload["end_time"].as_str().unwrap_or("").trim();
    if dvr_id.is_empty() || st.is_empty() || et.is_empty() {
        return fail("بيانات المقطع غير مكتملة");
    }
    let cfg = read_config();
    let bases = relay_base_urls(&cfg);
    let http = tls_agent(50);
    let enc = |s: &str| s.replace(' ', "%20").replace(':', "%3A");
    for base in bases {
        let url = format!(
            "{}/api/cctv/clip?dvr_id={}&channel={}&start_time={}&end_time={}",
            base,
            dvr_id,
            ch,
            enc(st),
            enc(et)
        );
        match http
            .get(&url)
            .set("Authorization", &format!("Bearer {}", cfg.admin_key))
            .call()
        {
            Ok(resp) if resp.status() == 200 => {
                let mut buf = Vec::new();
                if resp.into_reader().take(12 * 1024 * 1024).read_to_end(&mut buf).is_ok() && buf.len() > 1024 {
                    let is_mp4 = buf.len() > 8 && &buf[4..8] == b"ftyp";
                    let ext = if is_mp4 { "mp4" } else { "dav" };
                    let dl_dir = std::env::var("USERPROFILE")
                        .ok()
                        .map(|u| std::path::PathBuf::from(u).join("Downloads"))
                        .unwrap_or_else(std::env::temp_dir);
                    let _ = std::fs::create_dir_all(&dl_dir);
                    let dest = dl_dir.join(format!("Dahua_Clip_CH{}_{}.{}", ch, now_ms(), ext));
                    if let Err(e) = std::fs::write(&dest, &buf) {
                        return fail(format!("تعذر حفظ المقطع: {}", e));
                    }
                    let mut cmd = std::process::Command::new("explorer.exe");
                    cmd.arg(format!("/select,{}", dest.to_string_lossy()));
                    let _ = cmd.spawn();
                    return json!({
                        "ok": true,
                        "success": true,
                        "path": dest.to_string_lossy().to_string(),
                        "size": buf.len(),
                    });
                }
            }
            Err(ureq::Error::Status(_, r)) => {
                if let Ok(v) = r.into_json::<Value>() {
                    if let Some(m) = v["error"].as_str() {
                        return fail(m);
                    }
                }
            }
            _ => {}
        }
    }
    fail("تعذر سحب المقطع المسجل من السيرفر")
}

#[tauri::command]
pub async fn cctv_action(action: String, payload: Option<Value>) -> Result<Value, String> {
    run_bg(move || cctv_action_sync(action, payload.unwrap_or_else(|| json!({})), None, Some("super".into()))).await
}

#[tauri::command]
pub async fn cctv_list_dvrs() -> Result<Value, String> {
    run_bg(cctv_list_dvrs_sync).await
}

fn cctv_save_dvr_sync(dvr: Value) -> Value {
    match relay_request("/api/v1/admin/cctv/save", "POST", Some(&dvr)) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn cctv_save_dvr(dvr: Value) -> Result<Value, String> {
    run_bg(move || cctv_save_dvr_sync(dvr)).await
}

fn cctv_delete_dvr_sync(id: String) -> Value {
    match relay_request("/api/v1/admin/cctv/delete", "POST", Some(&json!({ "id": id }))) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn cctv_delete_dvr(id: String) -> Result<Value, String> {
    run_bg(move || cctv_delete_dvr_sync(id)).await
}

fn cctv_test_dvr_sync(dvr: Value) -> Value {
    match relay_request("/api/v1/admin/cctv/test", "POST", Some(&dvr)) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn cctv_test_dvr(dvr: Value) -> Result<Value, String> {
    run_bg(move || cctv_test_dvr_sync(dvr)).await
}

fn cctv_scan_lan_sync(bridge_device_id: Option<String>) -> Value {
    let bid = bridge_device_id.unwrap_or_default();
    match relay_request("/api/v1/admin/cctv/scan", "POST", Some(&json!({ "bridge_device_id": bid }))) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn cctv_scan_lan(bridge_device_id: Option<String>) -> Result<Value, String> {
    run_bg(move || cctv_scan_lan_sync(bridge_device_id)).await
}

fn cctv_set_settings_sync(super_only: bool) -> Value {
    match relay_request("/api/v1/admin/cctv/settings", "POST", Some(&json!({ "super_only": super_only }))) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn cctv_set_settings(super_only: bool) -> Result<Value, String> {
    run_bg(move || cctv_set_settings_sync(super_only)).await
}

fn cctv_get_frame_b64_sync(dvr_id: String, channel: u32, hd: bool) -> Value {
    match relay_request(
        "/api/v1/admin/cctv/frame-b64",
        "POST",
        Some(&json!({ "dvr_id": dvr_id, "channel": channel, "hd": hd })),
    ) {
        Ok(v) => v,
        Err(e) => fail(e),
    }
}

#[tauri::command]
pub async fn cctv_get_frame_b64(dvr_id: String, channel: u32, hd: Option<bool>) -> Result<Value, String> {
    run_bg(move || cctv_get_frame_b64_sync(dvr_id, channel, hd.unwrap_or(false))).await
}

// Unused helpers kept for signature parity with the previous implementation.
#[allow(dead_code)]
fn hash_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}
