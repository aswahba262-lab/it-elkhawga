use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const APP_VERSION: &str = "1.1.1";
pub const APP_NAME: &str = "IT ELKHAWGA";
pub const DEFAULT_SUPER_ADMIN_USERNAME: &str = "admin";
pub const DEFAULT_SUPER_ADMIN_PASSWORD: &str = "Admin@123";
/// Default RustDesk unattended password baked into the build.
pub const DEFAULT_RUSTDESK_PASSWORD: &str = "KH2027kh";
/// Default protection password hash enforced on Client machines before initial policy sync.
pub const DEFAULT_CLIENT_PASSWORD_HASH: &str =
    "5bedd317328c9ed79ecd3aecee74d37f97813cb4ce61ef3402eb388fb369fa86";
/// Relay endpoint baked into the build so installs work with zero configuration.
pub const DEFAULT_RELAY_URL: &str = "https://desktop-04jeumk.tail0632e0.ts.net";
/// Admin key baked into the admin build only. Employees never need it.
pub const DEFAULT_ADMIN_KEY: &str =
    "2a0fa2811eb5acdba9847da8ece72ac29e59352a051e093664ba5fd413da2f8e";
/// Permanent pairing token kept only for reference (clients no longer auto-enroll with it).
#[allow(dead_code)]
pub const DEFAULT_PAIRING_TOKEN: &str = "pair_it_elkhawga_forever";
pub const APP_AUTHOR: &str = "Ahmed Wahba";
pub const LOCAL_API_ADDR: &str = "127.0.0.1:8788";
/// Primary company ERP domain whose browser Cookies, LocalStorage, and IndexedDB device tokens are always preserved.
pub const DEFAULT_ERP_DOMAIN: &str = "elkhawaga.uk";
/// Master QR enrollment code used by IT engineers when registering a new company PC on the ERP system.
pub const DEFAULT_ERP_MASTER_TOKEN: &str = "QRM-v1-sNv4DGnLKrO01NKYCQi2RQ";

// ---------- Paths ----------

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Folder holding the PowerShell scripts. Installed: next to the exe. Dev: the project root.
pub fn resource_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
    } else {
        exe_dir()
    }
}

fn defaults_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        resource_dir()
    } else {
        exe_dir().join("defaults")
    }
}

/// Mutable state (config, site lists, logs). Machine-wide so the SYSTEM agent and the UI share it.
pub fn data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("IBP_DATA_DIR") {
        return PathBuf::from(p);
    }
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(base).join("InternetBlocker")
}

pub fn app_mode() -> String {
    if cfg!(debug_assertions) {
        return match std::env::var("IBP_MODE").as_deref() {
            Ok("client") => "client".into(),
            _ => "admin".into(),
        };
    }
    let raw = fs::read_to_string(exe_dir().join("build-mode.json")).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    if v["mode"] == "client" {
        "client".into()
    } else {
        "admin".into()
    }
}

pub fn is_admin_mode() -> bool {
    app_mode() == "admin"
}

// ---------- Config ----------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AdminUser {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(default = "default_admin_role")]
    pub role: String,
}

fn default_admin_role() -> String {
    "super".to_string()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(default)]
    pub auto_start: bool,
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub admins: Vec<AdminUser>,
    #[serde(default = "default_port")]
    pub server_port: u16,
    /// Managed relay URL (https://...) used by the admin to control remote devices.
    #[serde(default)]
    pub relay_url: String,
    /// Admin key used to authenticate against the managed relay.
    #[serde(default)]
    pub admin_key: String,
    /// Exfiltration alert threshold in MB.
    #[serde(default = "default_exfil_threshold")]
    pub exfil_threshold_mb: u64,
    /// Rolling window in seconds for the threshold.
    #[serde(default = "default_exfil_window")]
    pub exfil_window_secs: u64,
    /// Suspicious hosts (immediate alert).
    #[serde(default)]
    pub exfil_suspicious: Vec<String>,
    /// Block USB mass storage.
    #[serde(default)]
    pub usb_block: bool,
    /// Self-hosted RustDesk server (host:port).
    #[serde(default)]
    pub rustdesk_server: String,
    /// Public key of the self-hosted RustDesk server.
    #[serde(default)]
    pub rustdesk_key: String,
    /// Permanent password for unattended RustDesk access (no approval prompt).
    #[serde(default)]
    pub rustdesk_password: String,
    /// Open Chrome & Edge with ephemeral profiles and zero history/cache/password persistence.
    #[serde(default)]
    pub ephemeral_browser: bool,
    /// Restrict viewing and downloading archived sensitive DLP files to Super Admin accounts only.
    #[serde(default)]
    pub dlp_super_only: bool,
    /// Custom server directory where exact-copy DLP uploaded files are archived (empty = C:\IT-ELKHAWGA-Archive).
    #[serde(default)]
    pub archive_dir: String,
    /// Custom server directory where automated and manual system backups are stored (empty = <archive_dir>\Backups).
    #[serde(default)]
    pub backup_dir: String,
    /// Company ERP/internal domains whose browser device tokens (Cookies, LocalStorage, IndexedDB) must never be wiped.
    #[serde(default)]
    pub erp_domains: Vec<String>,
    /// Company ERP Master enrollment token stored for IT convenience in Settings.
    #[serde(default)]
    pub erp_master_token: String,
    /// Enable automatic scheduled backups pulled from the company ERP website (elkhawaga.uk).
    #[serde(default)]
    pub erp_backup_enabled: bool,
    /// Interval in minutes between automatic ERP website backups (default 60 = every hour).
    #[serde(default = "default_erp_backup_interval_mins")]
    pub erp_backup_interval_mins: u64,
    /// Base URL of the company ERP website for automated backups.
    #[serde(default = "default_erp_backup_url")]
    pub erp_backup_url: String,
    /// Admin username on the company ERP website used to create & download backups.
    #[serde(default)]
    pub erp_backup_username: String,
    /// Admin password on the company ERP website (never exposed in plaintext to Web UI).
    #[serde(default)]
    pub erp_backup_password: String,
    /// Optional registered device cookie (`elkhawaga_did`) passed during ERP login.
    #[serde(default = "default_erp_backup_did")]
    pub erp_backup_did_cookie: String,
    /// Optional registered device UUID (`device_token`) passed during ERP login.
    #[serde(default = "default_erp_backup_dev_token")]
    pub erp_backup_device_token: String,
    /// Custom server directory where pulled ERP website backups are saved (empty = <archive_dir>\ERP-Backups).
    #[serde(default)]
    pub erp_backup_dir: String,
}

fn default_erp_backup_interval_mins() -> u64 {
    60
}
fn default_erp_backup_url() -> String {
    "https://elkhawaga.uk".to_string()
}
fn default_erp_backup_did() -> String {
    "lncbD_iTXRf1".to_string()
}
fn default_erp_backup_dev_token() -> String {
    "4ef685ca-2e40-49f9-8c48-9b5ec5b7143c".to_string()
}

fn default_mode() -> String {
    "whitelist".into()
}
fn default_port() -> u16 {
    8787
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: default_mode(),
            password_hash: String::new(),
            auto_start: false,
            api_token: String::new(),
            admins: Vec::new(),
            server_port: default_port(),
            relay_url: String::new(),
            admin_key: String::new(),
            exfil_threshold_mb: 50,
            exfil_window_secs: 600,
            exfil_suspicious: Vec::new(),
            usb_block: false,
            rustdesk_server: String::new(),
            rustdesk_key: String::new(),
            rustdesk_password: String::new(),
            ephemeral_browser: false,
            dlp_super_only: false,
            archive_dir: String::new(),
            backup_dir: String::new(),
            erp_domains: vec![DEFAULT_ERP_DOMAIN.to_string()],
            erp_master_token: DEFAULT_ERP_MASTER_TOKEN.to_string(),
            erp_backup_enabled: false,
            erp_backup_interval_mins: default_erp_backup_interval_mins(),
            erp_backup_url: default_erp_backup_url(),
            erp_backup_username: String::new(),
            erp_backup_password: String::new(),
            erp_backup_did_cookie: default_erp_backup_did(),
            erp_backup_device_token: default_erp_backup_dev_token(),
            erp_backup_dir: String::new(),
        }
    }
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

pub fn read_config() -> Config {
    let mut c: Config = fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_default();
    // Default Admin installs to the company Cloud Relay URL out-of-the-box so remote IT
    // engineers outside the LAN connect immediately without manual setup, while Client
    // installs leave config.relay_url untouched unless explicitly configured.
    if c.relay_url.contains("wahba.taild9bb1e.ts.net")
        || (is_admin_mode() && c.relay_url.trim().is_empty())
    {
        c.relay_url = DEFAULT_RELAY_URL.to_string();
    }
    if is_admin_mode() && c.admin_key.trim().is_empty() {
        c.admin_key = DEFAULT_ADMIN_KEY.to_string();
    }
    if c.rustdesk_password.trim().is_empty() {
        c.rustdesk_password = DEFAULT_RUSTDESK_PASSWORD.to_string();
    }
    if !is_admin_mode() && c.password_hash.trim().is_empty() {
        c.password_hash = DEFAULT_CLIENT_PASSWORD_HASH.to_string();
    }
    if c.erp_domains.is_empty() {
        c.erp_domains = vec![DEFAULT_ERP_DOMAIN.to_string()];
    }
    if c.erp_master_token.trim().is_empty() {
        c.erp_master_token = DEFAULT_ERP_MASTER_TOKEN.to_string();
    }
    if c.erp_backup_url.trim().is_empty() {
        c.erp_backup_url = default_erp_backup_url();
    }
    if c.erp_backup_interval_mins == 0 {
        c.erp_backup_interval_mins = 60;
    }
    if c.erp_backup_did_cookie.trim().is_empty() {
        c.erp_backup_did_cookie = default_erp_backup_did();
    }
    if c.erp_backup_device_token.trim().is_empty() {
        c.erp_backup_device_token = default_erp_backup_dev_token();
    }
    c
}

static FILE_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn atomic_write(path: &Path, content: &str) -> Result<(), String> {
    let _guard = FILE_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
        let tmp = dir.join(format!("{}.tmp.{}.{}", name, std::process::id(), random_hex(4)));
        if fs::write(&tmp, content).is_ok() {
            if fs::rename(&tmp, path).is_ok() {
                return Ok(());
            }
            let _ = fs::remove_file(&tmp);
        }
    }
    fs::write(path, content).map_err(|e| e.to_string())
}

pub fn write_config(c: &Config) -> Result<(), String> {
    let s = serde_json::to_string_pretty(c).map_err(|e| e.to_string())?;
    let res = atomic_write(&config_path(), &s);
    invalidate_policy_cache();
    res
}

// ---------- In-Memory Proxy Policy & Config Cache ----------

#[derive(Clone, Debug)]
pub struct ProxyPolicySnapshot {
    pub mode: String,
    pub exfil_threshold_mb: u64,
    pub exfil_window_secs: u64,
    pub always_allowed_hosts: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
}

static POLICY_CACHE_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static POLICY_CACHE_STATE: std::sync::Mutex<
    Option<(u64, PathBuf, std::time::Instant, std::sync::Arc<ProxyPolicySnapshot>)>,
> = std::sync::Mutex::new(None);

pub fn invalidate_policy_cache() {
    POLICY_CACHE_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

fn extract_policy_url_host(s: &str) -> String {
    s.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_start_matches("www.")
        .to_lowercase()
}

pub fn cached_policy_snapshot() -> std::sync::Arc<ProxyPolicySnapshot> {
    let cur_gen = POLICY_CACHE_GEN.load(std::sync::atomic::Ordering::Acquire);
    let cur_dir = data_dir();
    let ttl = if cfg!(test) {
        std::time::Duration::from_millis(0)
    } else {
        std::time::Duration::from_secs(2)
    };

    if ttl > std::time::Duration::ZERO {
        if let Ok(guard) = POLICY_CACHE_STATE.lock() {
            if let Some((gen_id, ref dir, fetched_at, ref snap)) = *guard {
                if gen_id == cur_gen && dir == &cur_dir && fetched_at.elapsed() < ttl {
                    return std::sync::Arc::clone(snap);
                }
            }
        }
    }

    let cfg = read_config();
    let link = read_client();
    let mut always_allowed_hosts = vec!["rustdesk.com".to_string(), "rustdesk.net".to_string()];
    for candidate in [&link.server_url, &cfg.relay_url, &link.relay_url] {
        let h = extract_policy_url_host(candidate);
        if !h.is_empty() && !always_allowed_hosts.contains(&h) {
            always_allowed_hosts.push(h);
        }
    }
    if !cfg.rustdesk_server.trim().is_empty() {
        let rs_host = extract_policy_url_host(&cfg.rustdesk_server);
        if !rs_host.is_empty() && !always_allowed_hosts.contains(&rs_host) {
            always_allowed_hosts.push(rs_host);
        }
        let rs_raw = cfg.rustdesk_server.trim().to_lowercase();
        if !rs_raw.is_empty() && !always_allowed_hosts.contains(&rs_raw) {
            always_allowed_hosts.push(rs_raw);
        }
    }

    let mut allowed_domains = Vec::new();
    for entry in cfg.erp_domains.iter().chain(read_list(&allowed_path()).iter()) {
        if let Some(clean) = clean_domain(entry) {
            let d = clean.trim_start_matches("www.").to_lowercase();
            if !d.is_empty() && !allowed_domains.contains(&d) {
                allowed_domains.push(d);
            }
        }
    }

    let mut blocked_domains = Vec::new();
    for entry in read_list(&blocked_path()) {
        if let Some(clean) = clean_domain(&entry) {
            let d = clean.trim_start_matches("www.").to_lowercase();
            if !d.is_empty() && !blocked_domains.contains(&d) {
                blocked_domains.push(d);
            }
        }
    }

    let snap = std::sync::Arc::new(ProxyPolicySnapshot {
        mode: cfg.mode,
        exfil_threshold_mb: cfg.exfil_threshold_mb.max(1),
        exfil_window_secs: cfg.exfil_window_secs.max(60),
        always_allowed_hosts,
        allowed_domains,
        blocked_domains,
    });

    if let Ok(mut guard) = POLICY_CACHE_STATE.lock() {
        *guard = Some((cur_gen, cur_dir, std::time::Instant::now(), std::sync::Arc::clone(&snap)));
    }
    snap
}

pub fn random_hex(bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..bytes).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

/// Creates the data folder and seeds it from the bundled defaults on first run.
/// Builds a ureq agent that can speak HTTPS.
///
/// ureq only auto-installs a TLS backend when its rustls feature ("tls") is on.
/// We build with native-tls, so the SChannel connector must be supplied here or
/// every https:// request fails with "no TLS backend is configured".
/// Returns a `ureq::AgentBuilder` pre-configured with the Windows SChannel TLS connector.
pub fn tls_agent_builder() -> ureq::AgentBuilder {
    let connector = ureq::native_tls::TlsConnector::new()
        .expect("Failed to initialize native TLS backend (Schannel). Check MinGW toolchain and Windows trust store.");
    ureq::AgentBuilder::new().tls_connector(std::sync::Arc::new(connector))
}

pub fn tls_agent(timeout_secs: u64) -> ureq::Agent {
    tls_agent_builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
}

/// Grants BUILTIN\Users modify rights on the data directory so the local agent,
/// client UI, and screen helper can read/write client state reliably even in
/// user-session fallback mode.
pub fn grant_users_data_access() {
    let dir = data_dir();
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(&dir)
        .arg("/grant:r")
        .arg("*S-1-5-32-545:(OI)(CI)M")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let _ = hidden(&mut cmd).status();
}

fn default_exfil_threshold() -> u64 { 50 }
fn default_exfil_window() -> u64 { 600 }

pub fn ensure_data() {
    let dir = data_dir();
    let _ = fs::create_dir_all(&dir);
    for f in ["config.json", "allowed-sites.txt", "blocked-sites.txt"] {
        let target = dir.join(f);
        if !target.exists() {
            let _ = fs::copy(defaults_dir().join(f), &target);
        }
    }
    let mut cfg = read_config();
    if is_admin_mode() {
        seed_default_super_admin_if_needed(&mut cfg);
        if cfg.api_token.is_empty() {
            cfg.api_token = random_hex(16);
        }
        let _ = write_config(&cfg);
    }
}

pub fn seed_default_super_admin_if_needed(cfg: &mut Config) {
    if cfg.admins.iter().any(|u| u.username.eq_ignore_ascii_case(DEFAULT_SUPER_ADMIN_USERNAME)) {
        if let Some(user) = cfg.admins.iter_mut().find(|u| u.username.eq_ignore_ascii_case(DEFAULT_SUPER_ADMIN_USERNAME)) {
            user.role = normalize_admin_role(&user.role);
            if user.role != "super" {
                user.role = "super".to_string();
            }
            if user.password_hash.is_empty() {
                user.password_hash = hash_password(DEFAULT_SUPER_ADMIN_PASSWORD);
            }
        }
        return;
    }

    if !cfg.admins.iter().any(|u| normalize_admin_role(&u.role) == "super") {
        cfg.admins.insert(
            0,
            AdminUser {
                username: DEFAULT_SUPER_ADMIN_USERNAME.to_string(),
                password_hash: hash_password(DEFAULT_SUPER_ADMIN_PASSWORD),
                role: "super".to_string(),
            },
        );
    }
}

pub fn hash_password(p: &str) -> String {
    let digest = Sha256::digest(p.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = Sha256::digest(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_res = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_res);
    let out_res = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&out_res);
    out
}

fn pbkdf2_hmac_sha256_32(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &salt_block);
    let mut t = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for j in 0..32 {
            t[j] ^= u[j];
        }
    }
    t
}

fn decode_hex_bytes(hex_str: &str) -> Option<Vec<u8>> {
    let b = hex_str.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)? as u8;
        let lo = (b[i + 1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn hash_admin_password(p: &str) -> String {
    let salt_hex = random_hex(16);
    let salt_bytes = decode_hex_bytes(&salt_hex).unwrap_or_default();
    let dk = pbkdf2_hmac_sha256_32(p.as_bytes(), &salt_bytes, 100_000);
    let dk_hex: String = dk.iter().map(|b| format!("{:02x}", b)).collect();
    format!("pbkdf2$100000${}${}", salt_hex, dk_hex)
}

pub fn verify_password_hash(supplied: &str, stored: &str) -> bool {
    let stored = stored.trim();
    if stored.is_empty() {
        return true;
    }
    if let Some(rest) = stored.strip_prefix("pbkdf2$") {
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 3 {
            return false;
        }
        let Ok(iters) = parts[0].parse::<u32>() else { return false };
        if !(10_000..=1_000_000).contains(&iters) {
            return false;
        }
        let Some(salt_bytes) = decode_hex_bytes(parts[1]) else { return false };
        let Some(expected_dk) = decode_hex_bytes(parts[2]) else { return false };
        let actual_dk = pbkdf2_hmac_sha256_32(supplied.as_bytes(), &salt_bytes, iters);
        return constant_time_eq(&actual_dk, &expected_dk);
    }
    let sha_hex = hash_password(supplied);
    constant_time_eq(sha_hex.as_bytes(), stored.as_bytes())
}

pub fn password_ok(cfg: &Config, supplied: &str) -> bool {
    verify_password_hash(supplied, &cfg.password_hash)
}

pub fn admin_password_ok(cfg: &Config, username: &str, supplied: &str) -> bool {
    if cfg.admins.is_empty() {
        return password_ok(cfg, supplied);
    }
    cfg.admins
        .iter()
        .find(|u| u.username.eq_ignore_ascii_case(username))
        .map(|u| verify_password_hash(supplied, &u.password_hash))
        .unwrap_or(false)
}

pub fn normalize_admin_role(role: &str) -> String {
    match role.trim().to_ascii_lowercase().as_str() {
        "super" => "super".to_string(),
        "admin" => "admin".to_string(),
        "support" => "support".to_string(),
        "viewer" => "viewer".to_string(),
        _ => "admin".to_string(),
    }
}

pub fn admin_login_ok(cfg: &Config, username: &str, supplied: &str) -> Option<String> {
    let username = username.trim();
    if username.is_empty() {
        return None;
    }

    if cfg.admins.is_empty() {
        if verify_password_hash(supplied, &cfg.password_hash) {
            return Some("super".to_string());
        }
        return None;
    }

    cfg.admins
        .iter()
        .find(|u| u.username.eq_ignore_ascii_case(username))
        .and_then(|u| {
            if verify_password_hash(supplied, &u.password_hash) {
                Some(normalize_admin_role(&u.role))
            } else {
                None
            }
        })
}

pub fn admin_has_role(cfg: &Config, username: &str, required_role: &str) -> bool {
    if cfg.admins.is_empty() {
        return true;
    }
    let required = required_role.trim().to_ascii_lowercase();
    cfg.admins
        .iter()
        .find(|u| u.username.eq_ignore_ascii_case(username))
        .map(|u| {
            let role = u.role.trim().to_ascii_lowercase();
            role == "super" || role == required || (required == "super" && role == "super")
        })
        .unwrap_or(false)
}

pub fn can_manage_admin_users(cfg: &Config, actor_username: &str, actor_role: &str) -> bool {
    let actor = actor_username.trim();
    if actor.is_empty() {
        return false;
    }
    if cfg.admins.is_empty() {
        return true;
    }
    let role = normalize_admin_role(actor_role);
    if role == "super" {
        return cfg.admins.iter().any(|u| u.username.eq_ignore_ascii_case(actor) && normalize_admin_role(&u.role) == "super");
    }
    cfg.admins
        .iter()
        .find(|u| u.username.eq_ignore_ascii_case(actor))
        .map(|u| normalize_admin_role(&u.role) == "super")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_password_still_works() {
        let cfg = Config {
            password_hash: hash_password("secret"),
            ..Default::default()
        };
        assert!(password_ok(&cfg, "secret"));
        assert!(!password_ok(&cfg, "wrong"));
    }

    #[test]
    fn multi_admin_roles_are_checked() {
        let cfg = Config {
            admins: vec![
                AdminUser {
                    username: "superadmin".to_string(),
                    password_hash: hash_password("super-pass"),
                    role: "super".to_string(),
                },
                AdminUser {
                    username: "support".to_string(),
                    password_hash: hash_password("support-pass"),
                    role: "support".to_string(),
                },
            ],
            ..Default::default()
        };

        assert!(admin_password_ok(&cfg, "superadmin", "super-pass"));
        assert!(admin_password_ok(&cfg, "support", "support-pass"));
        assert!(!admin_password_ok(&cfg, "support", "wrong"));
        assert!(admin_has_role(&cfg, "superadmin", "support"));
        assert!(admin_has_role(&cfg, "support", "support"));
        assert!(!admin_has_role(&cfg, "support", "super"));
    }

    #[test]
    fn admin_login_helper_accepts_legacy_and_multi_admin_credentials() {
        let legacy_cfg = Config {
            password_hash: hash_password("legacy-secret"),
            ..Default::default()
        };
        let multi_cfg = Config {
            admins: vec![
                AdminUser {
                    username: "manager".to_string(),
                    password_hash: hash_password("manager-pass"),
                    role: "admin".to_string(),
                },
                AdminUser {
                    username: "ops".to_string(),
                    password_hash: hash_password("ops-pass"),
                    role: "support".to_string(),
                },
            ],
            ..Default::default()
        };

        assert_eq!(admin_login_ok(&legacy_cfg, "admin", "legacy-secret"), Some("super".to_string()));
        assert_eq!(admin_login_ok(&multi_cfg, "manager", "manager-pass"), Some("admin".to_string()));
        assert_eq!(admin_login_ok(&multi_cfg, "ops", "ops-pass"), Some("support".to_string()));
        assert_eq!(admin_login_ok(&multi_cfg, "manager", "wrong"), None);
    }

    #[test]
    fn only_super_admin_can_manage_other_admins() {
        let cfg = Config {
            admins: vec![
                AdminUser {
                    username: "superadmin".to_string(),
                    password_hash: hash_password("super-pass"),
                    role: "super".to_string(),
                },
                AdminUser {
                    username: "manager".to_string(),
                    password_hash: hash_password("manager-pass"),
                    role: "admin".to_string(),
                },
            ],
            ..Default::default()
        };

        assert!(can_manage_admin_users(&cfg, "superadmin", "super"));
        assert!(!can_manage_admin_users(&cfg, "manager", "admin"));
        assert!(!can_manage_admin_users(&cfg, "manager", "super"));
        assert!(!can_manage_admin_users(&cfg, "unknown", "admin"));
    }

    #[test]
    fn empty_admin_list_is_seeded_with_default_super_admin() {
        let mut cfg = Config::default();
        seed_default_super_admin_if_needed(&mut cfg);

        assert_eq!(cfg.admins.len(), 1);
        assert_eq!(cfg.admins[0].username, "admin");
        assert_eq!(cfg.admins[0].role, "super");
        assert!(admin_login_ok(&cfg, "admin", "Admin@123").is_some());
    }

    #[test]
    fn client_defaults_to_fixed_relay_and_rustdesk_password() {
        let mut c = ClientLink::default();
        c.device_id.clear();
        c.relay_url.clear();
        c.rustdesk_password.clear();
        c.pairing_token.clear();
        c.transport.clear();

        let fixed = read_client();
        assert_eq!(fixed.relay_url, DEFAULT_RELAY_URL);
        assert_eq!(fixed.rustdesk_password, DEFAULT_RUSTDESK_PASSWORD);
        assert!(!fixed.device_id.is_empty());
    }

    #[test]
    fn rustdesk_uri_prefills_password() {
        assert_eq!(
            rustdesk_connect_uri("123456789", DEFAULT_RUSTDESK_PASSWORD),
            "rustdesk://connection/new/123456789?password=KH2027kh"
        );
        assert_eq!(
            rustdesk_connect_uri("1", "a b&c"),
            "rustdesk://connection/new/1?password=a%20b%26c"
        );
        assert_eq!(rustdesk_connect_uri("1", ""), "rustdesk://connection/new/1");
    }

    #[test]
    fn capture_screen_returns_valid_png_base64() {
        let sample = vec![120u8; 64 * 36 * 4];
        let b64 = encode_bgra_png_base64(&sample, 64, 36).expect("PNG encoding should succeed");
        assert!(b64.starts_with("iVBORw0KGgo"), "unexpected header: {}", &b64[..16.min(b64.len())]);
        assert!(b64.len() > 80);

        if let Some(live) = capture_screen_base64() {
            assert!(live.starts_with("iVBORw0KGgo"));
        }
    }

    #[test]
    fn admin_rustdesk_peer_toml_toggles_view_only() {
        let sample = "password = [\n    48,\n    49,\n]\nview_style = 'original'\nview_only = false\n\n[options]\ncustom-fps = '30'\n\n[ui_flutter]\nwm_ViewCamera = '{}'\n";
        let watch_toml = upsert_peer_view_only_toml(sample, true);
        assert!(watch_toml.contains("password = [\n    48,\n    49,\n]"));
        assert!(watch_toml.contains("view_only = true"));
        assert!(watch_toml.contains("disable_clipboard = true"));
        assert!(watch_toml.contains("enable-file-copy-paste = false"));
        assert!(watch_toml.contains("[options]\ncustom-fps = '30'"));
        assert!(watch_toml.contains("[ui_flutter]\nwm_ViewCamera = '{}'"));

        let support_toml = upsert_peer_view_only_toml(&watch_toml, false);
        assert_eq!(support_toml.contains("view_only = false"), true);
        assert!(support_toml.contains("disable_clipboard = false"));
        assert!(support_toml.contains("enable-file-copy-paste = true"));
    }

    #[test]
    fn whatsapp_phone_lookup_extracts_jid_near_utf8_and_utf16_contact_ignoring_lid() {
        let mut blob_utf8 = Vec::new();
        blob_utf8.extend_from_slice(br#"{"id":"998877665544@lid","name":"Other"}"#);
        blob_utf8.extend_from_slice(
            r#"{"id":"201001234567@c.us","name":"أحمد المبيعات","pushname":"Ahmed"}"#.as_bytes(),
        );
        assert_eq!(
            extract_phone_near_contact_bytes(&blob_utf8, "أحمد المبيعات").as_deref(),
            Some("+201001234567")
        );

        let mut blob_utf16 = Vec::new();
        for u in "محمد فرع القاهرة".encode_utf16() {
            blob_utf16.extend_from_slice(&u.to_le_bytes());
        }
        blob_utf16.extend_from_slice(b"\0\011223344556677@lid\0\0201112223334@s.whatsapp.net\0");
        assert_eq!(
            extract_phone_near_contact_bytes(&blob_utf16, "محمد فرع القاهرة").as_deref(),
            Some("+201112223334")
        );
    }

    #[test]
    fn webcam_media_foundation_smoke_does_not_panic() {
        let _ = capture_webcam_base64();
    }

    #[test]
    fn rfc1321_md5_and_dahua_digest_auth_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        let hdr = r#"Digest realm="Login to DVR", qop="auth", nonce="1234567890abcdef", opaque="xyz987""#;
        let parsed = parse_digest_header(hdr).expect("digest header");
        assert_eq!(parsed.get("realm").map(String::as_str), Some("Login to DVR"));
        assert_eq!(parsed.get("nonce").map(String::as_str), Some("1234567890abcdef"));
        let auth = build_digest_authorization(
            "GET",
            "/cgi-bin/snapshot.cgi?channel=1&subtype=1",
            "admin",
            "Pass123",
            &parsed,
            1,
        );
        assert!(auth.starts_with("Digest username=\"admin\""));
        assert!(auth.contains("qop=auth"));
        assert!(auth.contains("nc=00000001"));
    }
}

// ---------- Site lists ----------

pub fn allowed_path() -> PathBuf {
    data_dir().join("allowed-sites.txt")
}
pub fn blocked_path() -> PathBuf {
    data_dir().join("blocked-sites.txt")
}

pub fn read_list(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().trim_start_matches('\u{feff}').to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

pub fn write_list(path: &Path, header: &str, items: &[String]) -> Result<(), String> {
    let body = format!("# {}\n\n{}\n", header, items.join("\n"));
    let res = fs::write(path, body).map_err(|e| e.to_string());
    invalidate_policy_cache();
    res
}

/// Accepts "https://Example.com/path" and returns "example.com"; rejects anything that is
/// not a plain hostname, since these names are written into the hosts file.
pub fn clean_domain(input: &str) -> Option<String> {
    let mut s = input.trim().to_lowercase();
    for p in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest.to_string();
        }
    }
    let end = s.find(|c| c == '/' || c == '?' || c == '#').unwrap_or(s.len());
    s.truncate(end);
    if let Some((host_only, _port)) = s.split_once(':') {
        s = host_only.to_string();
    }
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return None;
    }
    if s.starts_with(['.', '-']) || s.ends_with(['.', '-']) || s.contains("..") {
        return None;
    }
    Some(s)
}

// ---------- Client link settings ----------

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ClientLink {
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub policy_version: String,
    /// When set, the agent talks to the managed relay instead of the LAN server.
    #[serde(default)]
    pub relay_url: String,
    /// Per-device token issued by the relay after enrollment.
    #[serde(default)]
    pub device_token: String,
    /// "lan" or "relay"; derived from relay_url when empty.
    #[serde(default)]
    pub transport: String,
    /// One-time pairing token used to obtain a device token (consumed on success).
    #[serde(default)]
    pub pairing_token: String,
    /// ID of the last relay command applied locally, so a restart never re-applies it.
    #[serde(default)]
    pub last_command_id: String,
    /// Event to report to the relay on the next poll (e.g. local password unblock).
    #[serde(default)]
    pub pending_event: String,
    /// RustDesk ID of this device (if RustDesk is installed), reported to the admin.
    #[serde(default)]
    pub rustdesk_id: String,
    /// Self-hosted RustDesk server (host:port) to use instead of the public one.
    #[serde(default)]
    pub rustdesk_server: String,
    /// Public key of the self-hosted RustDesk server.
    #[serde(default)]
    pub rustdesk_key: String,
    /// Permanent password for unattended RustDesk access.
    #[serde(default)]
    pub rustdesk_password: String,
    /// Pending alert (JSON) to report to the relay on the next poll.
    #[serde(default)]
    pub pending_alert: String,
    /// Ephemeral/clean browser mode pushed by the device's group policy.
    #[serde(default)]
    pub ephemeral_browser: bool,
    /// Per-device USB mass storage override: "" = inherit group/global policy, "block" = forced locked, "unblock" = forced open.
    #[serde(default)]
    pub usb_override: String,
}

pub fn is_usb_effectively_blocked(cfg: &Config, link: &ClientLink) -> bool {
    match link.usb_override.trim() {
        "block" => true,
        "unblock" => false,
        _ => cfg.usb_block,
    }
}

/// Immediately locks or unlocks USB mass storage drives & WPD mobile phone file transfer
/// via Windows Registry policies without affecting USB mice, keyboards, printers, or webcams.
pub fn apply_usb_storage_policy(block: bool) {
    let start_val = if block { "4" } else { "3" };
    let mut reg_svc = Command::new("reg");
    reg_svc.args([
        "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
        "/v",
        "Start",
        "/t",
        "REG_DWORD",
        "/d",
        start_val,
        "/f",
    ]);
    let _ = hidden(&mut reg_svc).output();

    let base_pol = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";
    if block {
        let mut r_all = Command::new("reg");
        r_all.args(["add", base_pol, "/v", "Deny_All", "/t", "REG_DWORD", "/d", "1", "/f"]);
        let _ = hidden(&mut r_all).output();

        for guid in [
            "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}", // Removable Disks / Flash Drives
            "{6ac27878-a6fa-4155-ba85-f98f491d4f33}", // WPD / MTP Mobile Phone Storage
            "{eec5ad98-8080-425f-922a-dabf3de3f69a}", // Portable Devices
        ] {
            let sub_key = format!(r"{}\{}", base_pol, guid);
            for val_name in ["Deny_Read", "Deny_Write", "Deny_Execute"] {
                let mut r_sub = Command::new("reg");
                r_sub.args(["add", &sub_key, "/v", val_name, "/t", "REG_DWORD", "/d", "1", "/f"]);
                let _ = hidden(&mut r_sub).output();
            }
        }
    } else {
        let mut r_del = Command::new("reg");
        r_del.args(["delete", base_pol, "/f"]);
        let _ = hidden(&mut r_del).output();
    }
}

fn client_path() -> PathBuf {
    data_dir().join("client.json")
}

pub fn read_client() -> ClientLink {
    // Strip a UTF-8 BOM: editors and installers on Windows write one, and serde_json
    // rejects it, which would silently wipe the link settings on every start.
    // Retry briefly in case a concurrent writer is replacing client.json.
    let path = client_path();
    let existed = path.exists();
    let mut parsed: Option<ClientLink> = None;
    let attempts = if existed { 3 } else { 1 };
    for i in 0..attempts {
        if let Ok(s) = fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<ClientLink>(s.trim_start_matches('\u{feff}')) {
                parsed = Some(v);
                break;
            }
        }
        if i + 1 < attempts {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
    let mut c = parsed.unwrap_or_default();
    if c.device_id.is_empty() {
        c.device_id = random_hex(12);
        if !existed {
            let _ = write_client(&c);
        }
    }
    if c.relay_url.trim().is_empty() || c.relay_url.contains("wahba.taild9bb1e.ts.net") {
        c.relay_url = DEFAULT_RELAY_URL.to_string();
    }
    if c.rustdesk_password.trim().is_empty() {
        c.rustdesk_password = DEFAULT_RUSTDESK_PASSWORD.to_string();
    }
    if c.transport.trim().is_empty() {
        c.transport = if !c.server_url.trim().is_empty() {
            "lan".to_string()
        } else if !c.device_token.is_empty() || !c.pairing_token.is_empty() {
            "relay".to_string()
        } else {
            "lan".to_string()
        };
    }
    c
}

pub fn write_client(c: &ClientLink) -> Result<(), String> {
    // Written atomically without a BOM so concurrent readers never see a truncated 0-byte file.
    let s = serde_json::to_string_pretty(c).map_err(|e| e.to_string())?;
    let res = atomic_write(&client_path(), &s);
    invalidate_policy_cache();
    res
}

// ---------- Logging ----------

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn timestamp() -> String {
    let secs = (now_ms() / 1000) as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, m, d, t / 3600, (t % 3600) / 60, t % 60)
}

pub fn log_action(msg: &str) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(data_dir().join("activity.log")) {
        let _ = writeln!(f, "[{}] {}", timestamp(), msg);
    }
}

pub fn read_log() -> String {
    fs::read_to_string(data_dir().join("activity.log")).unwrap_or_default()
}

// ---------- Machine info ----------

pub fn hostname() -> String {
    static CACHED_HOST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CACHED_HOST
        .get_or_init(|| {
            if let Ok(h) = std::env::var("COMPUTERNAME") {
                if !h.is_empty() {
                    return h;
                }
            }
            let mut cmd = Command::new("hostname");
            hidden(&mut cmd)
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "unknown".into())
        })
        .clone()
}

pub fn local_ip() -> String {
    for target in ["192.168.1.1:80", "10.0.0.1:80", "8.8.8.8:80"] {
        if let Ok(ip) = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect(target).map(|_| s))
            .and_then(|s| s.local_addr())
            .map(|a| a.ip().to_string())
        {
            if !ip.starts_with("127.") && !ip.starts_with("100.") {
                return ip;
            }
        }
    }
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

// ---------- Dahua DVR / XVR Bridge & HTTP Digest Auth ----------

/// Pure-Rust RFC 1321 MD5 hex digest (used for Dahua DVR HTTP Digest Authentication).
pub fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_digest_header(www_auth: &str) -> Option<std::collections::HashMap<String, String>> {
    let s = www_auth.trim();
    if s.len() < 7 || !s.get(..6).map_or(false, |p| p.eq_ignore_ascii_case("digest")) {
        return None;
    }
    let rest = s.get(6..)?.trim_start();
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    let mut map = std::collections::HashMap::new();
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-') {
            i += 1;
        }
        if i == key_start {
            i += 1;
            continue;
        }
        let key = String::from_utf8_lossy(&bytes[key_start..i]).to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let val = if bytes[i] == b'"' {
            i += 1;
            let val_start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let v = String::from_utf8_lossy(&bytes[val_start..i]).to_string();
            if i < bytes.len() && bytes[i] == b'"' {
                i += 1;
            }
            v
        } else {
            let val_start = i;
            while i < bytes.len() && bytes[i] != b',' && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            String::from_utf8_lossy(&bytes[val_start..i]).to_string()
        };
        map.insert(key, val);
    }
    if map.contains_key("nonce") {
        Some(map)
    } else {
        None
    }
}

fn build_digest_authorization(
    method: &str,
    uri: &str,
    username: &str,
    password: &str,
    challenge: &std::collections::HashMap<String, String>,
    nc_num: u32,
) -> String {
    let alg_raw = challenge
        .get("algorithm")
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_else(|| "MD5".to_string());
    let is_sha256 = alg_raw.starts_with("SHA-256");
    let hash_fn = |input: &str| -> String {
        if is_sha256 {
            hash_password(input)
        } else {
            md5_hex(input.as_bytes())
        }
    };
    let realm = challenge.get("realm").map(String::as_str).unwrap_or("");
    let nonce = challenge.get("nonce").map(String::as_str).unwrap_or("");
    let qop_raw = challenge.get("qop").map(String::as_str).unwrap_or("");
    let use_auth_qop = qop_raw
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("auth"));
    let cnonce = random_hex(8);
    let nc_hex = format!("{:08x}", nc_num.max(1));

    let mut ha1 = hash_fn(&format!("{}:{}:{}", username, realm, password));
    if alg_raw.ends_with("-SESS") {
        ha1 = hash_fn(&format!("{}:{}:{}", ha1, nonce, cnonce));
    }
    let ha2 = hash_fn(&format!("{}:{}", method, uri));
    let response = if use_auth_qop {
        hash_fn(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc_hex, cnonce, ha2))
    } else {
        hash_fn(&format!("{}:{}:{}", ha1, nonce, ha2))
    };

    let mut parts = vec![
        format!("username=\"{}\"", username),
        format!("realm=\"{}\"", realm),
        format!("nonce=\"{}\"", nonce),
        format!("uri=\"{}\"", uri),
        format!("response=\"{}\"", response),
    ];
    if let Some(alg) = challenge.get("algorithm") {
        parts.push(format!("algorithm={}", alg));
    }
    if let Some(opaque) = challenge.get("opaque") {
        parts.push(format!("opaque=\"{}\"", opaque));
    }
    if use_auth_qop {
        parts.push("qop=auth".to_string());
        parts.push(format!("nc={}", nc_hex));
        parts.push(format!("cnonce=\"{}\"", cnonce));
    }
    format!("Digest {}", parts.join(", "))
}

type DahuaDigestCacheMap = std::collections::HashMap<String, (std::collections::HashMap<String, String>, u32)>;

fn dahua_digest_cache() -> &'static std::sync::Mutex<DahuaDigestCacheMap> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<DahuaDigestCacheMap>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn dahua_raw_get(agent: &ureq::Agent, url: &str, auth_hdr: Option<&str>) -> Result<(u16, Option<String>, Vec<u8>), String> {
    let mut req = agent.get(url).set("User-Agent", "IT-ELKHAWGA-CCTV/1.0");
    if let Some(h) = auth_hdr {
        req = req.set("Authorization", h);
    }
    match req.call() {
        Ok(resp) => {
            let code = resp.status();
            let www = resp.header("WWW-Authenticate").map(str::to_string);
            let mut buf = Vec::new();
            use std::io::Read;
            let _ = resp.into_reader().take(8 * 1024 * 1024).read_to_end(&mut buf);
            Ok((code, www, buf))
        }
        Err(ureq::Error::Status(code, resp)) => {
            let www = resp.header("WWW-Authenticate").map(str::to_string);
            let mut buf = Vec::new();
            use std::io::Read;
            let _ = resp.into_reader().take(256 * 1024).read_to_end(&mut buf);
            Ok((code, www, buf))
        }
        Err(e) => Err(format!("تعذر الاتصال بجهاز الـ DVR على الشبكة المحلية: {}", e)),
    }
}

fn dahua_authed_get(
    host: &str,
    port: u16,
    path_with_query: &str,
    username: &str,
    password: &str,
) -> Result<(u16, Vec<u8>), String> {
    static DVR_AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    let agent = DVR_AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_millis(1400))
            .timeout(std::time::Duration::from_millis(2400))
            .build()
    });
    let url = format!("http://{}:{}{}", host, port, path_with_query);
    let cache_key = format!("{}:{}:{}", host, port, username);

    let cached_opt = dahua_digest_cache()
        .lock()
        .ok()
        .and_then(|mut map| {
            map.get_mut(&cache_key).map(|entry| {
                entry.1 = entry.1.wrapping_add(1).max(1);
                (entry.0.clone(), entry.1)
            })
        });

    if let Some((challenge, nc)) = cached_opt {
        let hdr = build_digest_authorization("GET", path_with_query, username, password, &challenge, nc);
        let (code, _, body) = dahua_raw_get(agent, &url, Some(&hdr))?;
        if code != 401 {
            return Ok((code, body));
        }
        if let Ok(mut map) = dahua_digest_cache().lock() {
            map.remove(&cache_key);
        }
    }

    let (probe_code, www_opt, probe_body) = dahua_raw_get(agent, &url, None)?;
    if probe_code != 401 {
        return Ok((probe_code, probe_body));
    }
    if let Some(ref www) = www_opt {
        if let Some(challenge) = parse_digest_header(www) {
            if let Ok(mut map) = dahua_digest_cache().lock() {
                if map.len() > 64 {
                    map.clear();
                }
                map.insert(cache_key, (challenge.clone(), 1));
            }
            let hdr = build_digest_authorization("GET", path_with_query, username, password, &challenge, 1);
            let (code, _, body) = dahua_raw_get(agent, &url, Some(&hdr))?;
            return Ok((code, body));
        }
    }

    let basic = base64_encode(format!("{}:{}", username, password).as_bytes());
    let (code, _, body) = dahua_raw_get(agent, &url, Some(&format!("Basic {}", basic)))?;
    Ok((code, body))
}

fn is_valid_dvr_image(buf: &[u8]) -> bool {
    buf.len() >= 256
        && ((buf[0] == 0xff && buf[1] == 0xd8) || (buf[0] == 0x89 && buf[1] == 0x50))
}

fn is_private_lan_dvr_host(host: &str) -> bool {
    let h = host.trim();
    if h.starts_with("10.") || h.starts_with("192.168.") {
        return true;
    }
    if let Some(rest) = h.strip_prefix("172.") {
        if let Some(oct_str) = rest.split('.').next() {
            if let Ok(oct) = oct_str.parse::<u8>() {
                return (16..=31).contains(&oct);
            }
        }
    }
    false
}

/// Executes an authenticated on-demand Dahua CGI HTTP GET (`ChannelTitle`, `storageDevice`, `mediaFileFind`, `loadfile`, `ptz`)
/// strictly against a private LAN IPv4 Dahua DVR/NVR.
pub fn execute_dahua_cgi(
    host: &str,
    port: u16,
    path_with_query: &str,
    username: &str,
    password: &str,
    max_bytes: u64,
    timeout_ms: u64,
) -> Result<(u16, String, Vec<u8>), String> {
    let clean_host = host.trim();
    if !is_private_lan_dvr_host(clean_host) {
        return Err("يُسمح فقط بعناوين الشبكة الداخلية للـ DVR".into());
    }
    let pq = path_with_query.trim();
    if !pq.starts_with("/cgi-bin/") && !pq.starts_with("/RPC2") {
        return Err("مسار CGI غير صالح".into());
    }
    let safe_max = max_bytes.clamp(4096, 10 * 1024 * 1024);
    let safe_timeout = timeout_ms.clamp(1500, 35_000);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_millis(2000))
        .timeout(std::time::Duration::from_millis(safe_timeout))
        .build();
    let url = format!("http://{}:{}{}", clean_host, port.max(1), pq);
    let cache_key = format!("{}:{}:{}", clean_host, port.max(1), username);

    let do_req = |auth_hdr: Option<&str>| -> Result<(u16, Option<String>, String, Vec<u8>), String> {
        let mut r = agent.get(&url).set("User-Agent", "IT-ELKHAWGA-CCTV/1.1");
        if let Some(h) = auth_hdr {
            r = r.set("Authorization", h);
        }
        match r.call() {
            Ok(resp) => {
                let code = resp.status();
                let www = resp.header("WWW-Authenticate").map(str::to_string);
                let ct = resp.header("Content-Type").unwrap_or("text/plain").to_string();
                let mut buf = Vec::new();
                use std::io::Read;
                let _ = resp.into_reader().take(safe_max).read_to_end(&mut buf);
                Ok((code, www, ct, buf))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let www = resp.header("WWW-Authenticate").map(str::to_string);
                let ct = resp.header("Content-Type").unwrap_or("text/plain").to_string();
                let mut buf = Vec::new();
                use std::io::Read;
                let _ = resp.into_reader().take(256 * 1024).read_to_end(&mut buf);
                Ok((code, www, ct, buf))
            }
            Err(e) => Err(format!("تعذر الاتصال بجهاز الـ DVR: {}", e)),
        }
    };

    let cached_opt = dahua_digest_cache().lock().ok().and_then(|mut map| {
        map.get_mut(&cache_key).map(|entry| {
            entry.1 = entry.1.wrapping_add(1).max(1);
            (entry.0.clone(), entry.1)
        })
    });

    if let Some((challenge, nc)) = cached_opt {
        let hdr = build_digest_authorization("GET", pq, username, password, &challenge, nc);
        let (code, _, ct, body) = do_req(Some(&hdr))?;
        if code != 401 {
            return Ok((code, ct, body));
        }
        if let Ok(mut map) = dahua_digest_cache().lock() {
            map.remove(&cache_key);
        }
    }

    let (probe_code, www_opt, probe_ct, probe_body) = do_req(None)?;
    if probe_code != 401 {
        return Ok((probe_code, probe_ct, probe_body));
    }
    if let Some(ref www) = www_opt {
        if let Some(challenge) = parse_digest_header(www) {
            if let Ok(mut map) = dahua_digest_cache().lock() {
                if map.len() > 64 {
                    map.clear();
                }
                map.insert(cache_key, (challenge.clone(), 1));
            }
            let hdr = build_digest_authorization("GET", pq, username, password, &challenge, 1);
            let (code, _, ct, body) = do_req(Some(&hdr))?;
            return Ok((code, ct, body));
        }
    }
    let basic = base64_encode(format!("{}:{}", username, password).as_bytes());
    let (code, _, ct, body) = do_req(Some(&format!("Basic {}", basic)))?;
    Ok((code, ct, body))
}

/// Opens a single on-demand live HTTP audio stream (`/cgi-bin/audio.cgi?action=getAudio&httptype=singlepart&channel=<ch>`)
/// from a private-LAN Dahua DVR/XVR while an admin has unmuted that camera (`~3 KB/s` AAC or `~8 KB/s` G.711, `0% CPU`),
/// and closes the TCP socket immediately as soon as `keep_going()` or `on_chunk(...)` returns `false`.
pub fn stream_dahua_audio_live<FKeep, FChunk>(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    channel: u32,
    mut keep_going: FKeep,
    mut on_chunk: FChunk,
) -> Result<(), String>
where
    FKeep: FnMut() -> bool,
    FChunk: FnMut(&str, &[u8]) -> bool,
{
    let clean_host = host.trim();
    if !is_private_lan_dvr_host(clean_host) {
        return Err("يُسمح فقط بعناوين الشبكة الداخلية للـ DVR".into());
    }
    let ch = channel.clamp(1, 64);
    let pq = format!(
        "/cgi-bin/audio.cgi?action=getAudio&httptype=singlepart&channel={}",
        ch
    );
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_millis(2000))
        .timeout_read(std::time::Duration::from_millis(3500))
        .build();
    let url = format!("http://{}:{}{}", clean_host, port.max(1), pq);
    let cache_key = format!("{}:{}:{}", clean_host, port.max(1), username);

    let open_req = |auth_hdr: Option<&str>| -> Result<Result<ureq::Response, (u16, Option<String>)>, String> {
        let mut r = agent.get(&url).set("User-Agent", "IT-ELKHAWGA-CCTV/1.1");
        if let Some(h) = auth_hdr {
            r = r.set("Authorization", h);
        }
        match r.call() {
            Ok(resp) => Ok(Ok(resp)),
            Err(ureq::Error::Status(code, resp)) => {
                let www = resp.header("WWW-Authenticate").map(str::to_string);
                Ok(Err((code, www)))
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("Unexpected EOF") {
                    Err("هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت غير مفعّل لها في إعدادات الـ DVR".into())
                } else {
                    Err(format!("تعذر فتح بث الصوت من الـ DVR: {}", msg))
                }
            }
        }
    };

    let cached_opt = dahua_digest_cache().lock().ok().and_then(|mut map| {
        map.get_mut(&cache_key).map(|entry| {
            entry.1 = entry.1.wrapping_add(1).max(1);
            (entry.0.clone(), entry.1)
        })
    });

    let mut live_resp: Option<ureq::Response> = None;
    if let Some((challenge, nc)) = cached_opt {
        let hdr = build_digest_authorization("GET", &pq, username, password, &challenge, nc);
        match open_req(Some(&hdr))? {
            Ok(resp) => live_resp = Some(resp),
            Err((401, _)) => {
                if let Ok(mut map) = dahua_digest_cache().lock() {
                    map.remove(&cache_key);
                }
            }
            Err((code, _)) => {
                return Err(format!(
                    "هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت مغلق في الـ DVR (HTTP {})",
                    code
                ));
            }
        }
    }

    if live_resp.is_none() {
        match open_req(None)? {
            Ok(resp) => live_resp = Some(resp),
            Err((401, www_opt)) => {
                if let Some(ref www) = www_opt {
                    if let Some(challenge) = parse_digest_header(www) {
                        if let Ok(mut map) = dahua_digest_cache().lock() {
                            if map.len() > 64 {
                                map.clear();
                            }
                            map.insert(cache_key, (challenge.clone(), 1));
                        }
                        let hdr = build_digest_authorization("GET", &pq, username, password, &challenge, 1);
                        match open_req(Some(&hdr))? {
                            Ok(resp) => live_resp = Some(resp),
                            Err((401, _)) => return Err("بيانات دخول الـ DVR غير صحيحة (HTTP 401)".into()),
                            Err((code, _)) => {
                                return Err(format!(
                                    "هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت مغلق في الـ DVR (HTTP {})",
                                    code
                                ))
                            }
                        }
                    }
                }
                if live_resp.is_none() {
                    let basic = base64_encode(format!("{}:{}", username, password).as_bytes());
                    match open_req(Some(&format!("Basic {}", basic)))? {
                        Ok(resp) => live_resp = Some(resp),
                        Err((code, _)) => {
                            return Err(format!("تعذر فتح بث الصوت من الـ DVR (HTTP {})", code));
                        }
                    }
                }
            }
            Err((code, _)) => {
                return Err(format!(
                    "هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت مغلق في الـ DVR (HTTP {})",
                    code
                ));
            }
        }
    }

    let Some(resp) = live_resp else {
        return Err("تعذر فتح قناة الصوت المباشر".into());
    };
    let ct = resp.header("Content-Type").unwrap_or("Audio/AAC").to_string();
    let mut reader = resp.into_reader();
    let mut read_buf = [0u8; 2048];
    let mut batch: Vec<u8> = Vec::with_capacity(3072);
    let mut batch_started = std::time::Instant::now();
    let mut any_bytes = false;

    use std::io::Read;
    while keep_going() {
        match reader.read(&mut read_buf) {
            Ok(0) => {
                if !batch.is_empty() {
                    let _ = on_chunk(&ct, &batch);
                }
                if !any_bytes {
                    return Err("هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت غير مفعّل لها في الـ DVR".into());
                }
                break;
            }
            Ok(n) => {
                if batch.is_empty() {
                    batch_started = std::time::Instant::now();
                }
                any_bytes = true;
                batch.extend_from_slice(&read_buf[..n]);
                if batch.len() >= 1024 || batch_started.elapsed() >= std::time::Duration::from_millis(220) {
                    if !on_chunk(&ct, &batch) {
                        break;
                    }
                    batch.clear();
                }
            }
            Err(e) => {
                if !keep_going() {
                    break;
                }
                if !any_bytes {
                    return Err(format!("انقطع اتصال صوت الكاميرا: {}", e));
                }
                break;
            }
        }
    }
    Ok(())
}

/// Fetches a live JPEG/PNG snapshot from a Dahua DVR/XVR on the local LAN using HTTP Digest/Basic Auth.
pub fn fetch_dahua_snapshot(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    channel: u32,
    hd: bool,
) -> Result<Vec<u8>, String> {
    let clean_host = host.trim();
    if clean_host.is_empty() {
        return Err("عنوان IP للـ DVR فارغ".into());
    }
    let ch = channel.clamp(1, 64);
    let sub = if hd { 0 } else { 1 };
    let primary = format!("/cgi-bin/snapshot.cgi?channel={}&subtype={}", ch, sub);
    let (mut code, mut body) = dahua_authed_get(clean_host, port.max(1), &primary, username, password)?;
    if code == 401 {
        return Err("اسم المستخدم أو كلمة مرور جهاز الـ DVR غير صحيحة (HTTP 401)".into());
    }
    if (code == 400 || code == 404) && !hd {
        let fallback = format!("/cgi-bin/snapshot.cgi?channel={}", ch);
        let (c2, b2) = dahua_authed_get(clean_host, port.max(1), &fallback, username, password)?;
        code = c2;
        body = b2;
    }
    if code != 200 || !is_valid_dvr_image(&body) {
        return Err(format!("القناة رقم {} غير متصلة أو لا توجد كاميرا عليها (HTTP {})", ch, code));
    }
    Ok(body)
}

/// Scans the local `/24` IPv4 subnet for Dahua DVRs/XVRs/NVRs (TCP signature port `37777` + HTTP `80`/`8080`).
pub fn scan_local_subnet_for_dahua() -> Vec<serde_json::Value> {
    let my_ip = local_ip();
    let parts: Vec<&str> = my_ip.split('.').collect();
    if parts.len() != 4 || my_ip.starts_with("127.") {
        return Vec::new();
    }
    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    let next_host = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(1));
    let found = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut handles = Vec::with_capacity(32);

    for _ in 0..32 {
        let pref = prefix.clone();
        let idx_counter = std::sync::Arc::clone(&next_host);
        let out_arc = std::sync::Arc::clone(&found);
        handles.push(std::thread::spawn(move || {
            loop {
                let host_num = idx_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if host_num > 254 {
                    break;
                }
                let ip = format!("{}.{}", pref, host_num);
                let Ok(addr_37777) = format!("{}:37777", ip).parse::<std::net::SocketAddr>() else {
                    continue;
                };
                if std::net::TcpStream::connect_timeout(&addr_37777, std::time::Duration::from_millis(480)).is_err() {
                    continue;
                }
                let has_80 = format!("{}:80", ip)
                    .parse::<std::net::SocketAddr>()
                    .ok()
                    .map(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(400)).is_ok())
                    .unwrap_or(false);
                let has_8080 = if !has_80 {
                    format!("{}:8080", ip)
                        .parse::<std::net::SocketAddr>()
                        .ok()
                        .map(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(400)).is_ok())
                        .unwrap_or(false)
                } else {
                    false
                };
                let http_port = if has_80 { 80 } else if has_8080 { 8080 } else { 80 };
                if let Ok(mut g) = out_arc.lock() {
                    g.push((
                        host_num,
                        serde_json::json!({
                            "host": ip,
                            "http_port": http_port,
                            "rtsp_port": 554,
                            "vendor": "Dahua DVR / XVR (منفذ 37777 مكتشف)"
                        }),
                    ));
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut vec_out = found.lock().map(|g| g.clone()).unwrap_or_default();
    vec_out.sort_by_key(|x| x.0);
    vec_out.into_iter().map(|x| x.1).collect()
}

// ---------- Blocking state and script execution ----------

pub fn hidden(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(windows)]
fn split_reg_root(key: &str) -> Option<(*mut std::ffi::c_void, String)> {
    const HKLM: *mut std::ffi::c_void = 0x8000_0002usize as *mut std::ffi::c_void;
    const HKCU: *mut std::ffi::c_void = 0x8000_0001usize as *mut std::ffi::c_void;
    if let Some(sub) = key.strip_prefix(r"HKLM\").or_else(|| key.strip_prefix(r"HKEY_LOCAL_MACHINE\")) {
        return Some((HKLM, sub.to_string()));
    }
    if let Some(sub) = key.strip_prefix(r"HKCU\").or_else(|| key.strip_prefix(r"HKEY_CURRENT_USER\")) {
        return Some((HKCU, sub.to_string()));
    }
    None
}

#[cfg(windows)]
pub fn reg_query_dword(key: &str, value: &str) -> Option<u32> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: *mut std::ffi::c_void,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: *mut std::ffi::c_void,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: *mut std::ffi::c_void) -> i32;
    }
    const KEY_READ: u32 = 0x20019;
    const REG_DWORD: u32 = 4;
    let (root, sub) = split_reg_root(key)?;
    let wsub: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
    let wval: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut hkey: *mut std::ffi::c_void = std::ptr::null_mut();
        if RegOpenKeyExW(root, wsub.as_ptr(), 0, KEY_READ, &mut hkey) != 0 || hkey.is_null() {
            return None;
        }
        let mut data: u32 = 0;
        let mut cb: u32 = 4;
        let mut vtype: u32 = 0;
        let rc = RegQueryValueExW(
            hkey,
            wval.as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            (&mut data as *mut u32) as *mut u8,
            &mut cb,
        );
        RegCloseKey(hkey);
        if rc == 0 && vtype == REG_DWORD {
            Some(data)
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
pub fn reg_query_dword(_key: &str, _value: &str) -> Option<u32> {
    None
}

pub fn reg_value_exists(key: &str, value: &str) -> bool {
    reg_query_dword(key, value).is_some() || reg_query_string(key, value).is_some()
}

#[cfg(windows)]
pub fn reg_query_string(key: &str, value: &str) -> Option<String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: *mut std::ffi::c_void,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: *mut std::ffi::c_void,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: *mut std::ffi::c_void) -> i32;
    }
    const KEY_READ: u32 = 0x20019;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    let (root, sub) = split_reg_root(key)?;
    let wsub: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
    let wval: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut hkey: *mut std::ffi::c_void = std::ptr::null_mut();
        if RegOpenKeyExW(root, wsub.as_ptr(), 0, KEY_READ, &mut hkey) != 0 || hkey.is_null() {
            return None;
        }
        let mut cb: u32 = 0;
        let mut vtype: u32 = 0;
        if RegQueryValueExW(
            hkey,
            wval.as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            std::ptr::null_mut(),
            &mut cb,
        ) != 0
            || cb < 2
            || cb > 16384
            || (vtype != REG_SZ && vtype != REG_EXPAND_SZ)
        {
            RegCloseKey(hkey);
            return None;
        }
        let mut buf = vec![0u16; (cb as usize + 1) / 2];
        let rc = RegQueryValueExW(
            hkey,
            wval.as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            buf.as_mut_ptr() as *mut u8,
            &mut cb,
        );
        RegCloseKey(hkey);
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let s = String::from_utf16_lossy(&buf[..end]).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }
}

#[cfg(not(windows))]
pub fn reg_query_string(_key: &str, _value: &str) -> Option<String> {
    None
}

pub fn hosts_block_active() -> bool {
    let hosts = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32").join("drivers").join("etc").join("hosts"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"));
    fs::read_to_string(hosts)
        .map(|t| t.contains("# === BLOCKED SITES START ==="))
        .unwrap_or(false)
}

/// Detect the effective block state across all mechanisms used by block-internet.ps1
/// (HKLM/HKCU proxy, browser policies, hosts markers). This avoids a stuck UI when one
/// layer is applied but another is missing.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Decodes standard or URL-safe base64 (stripping optional `data:...;base64,` prefix).
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let raw = match input.trim().split_once(";base64,") {
        Some((_, b64)) => b64,
        None => input.trim(),
    };
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in raw.bytes() {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Captures the primary screen as a JPEG (base64) from the CURRENT user session.
/// Must run inside the interactive session; SYSTEM/Session-0 returns a black image.
/// Reads the RustDesk ID from the user's RustDesk config, if installed.
/// Writes the self-hosted RustDesk server settings to RustDesk2.toml so the
/// client never contacts the public relay server. No-op if not configured.
pub fn sync_rustdesk_custom_server_toml(existing: &str, server_raw: &str, key_raw: &str) -> String {
    let srv_trim = server_raw.trim();
    let host_only = srv_trim
        .strip_suffix(":21116")
        .or_else(|| srv_trim.strip_suffix(":21117"))
        .unwrap_or(srv_trim)
        .trim();
    let key_trim = key_raw.trim();

    let mut top_lines: Vec<String> = Vec::new();
    let mut opt_order: Vec<String> = Vec::new();
    let mut opt_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut other_sections: Vec<String> = Vec::new();
    let mut current_section = String::new();

    for raw in existing.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            if current_section != "options" {
                other_sections.push(raw.to_string());
            }
            continue;
        }
        if current_section.is_empty() {
            if let Some((k, _)) = trimmed.split_once('=') {
                let kn = k.trim();
                if kn == "rendezvous_server" || kn == "key" {
                    continue;
                }
            }
            top_lines.push(raw.to_string());
        } else if current_section == "options" {
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim().to_string();
                if !key.is_empty() {
                    if !opt_map.contains_key(&key) {
                        opt_order.push(key.clone());
                    }
                    opt_map.insert(key, v.trim().to_string());
                }
            }
        } else {
            other_sections.push(raw.to_string());
        }
    }

    if host_only.is_empty() {
        for k in ["custom-rendezvous-server", "relay-server", "key"] {
            opt_map.remove(k);
            opt_order.retain(|x| x != k);
        }
    } else {
        let relay_host = host_only.split(':').next().unwrap_or(host_only).trim();
        for (k, val) in [
            ("custom-rendezvous-server", format!("'{}'", host_only)),
            ("relay-server", format!("'{}'", relay_host)),
        ] {
            let ks = k.to_string();
            if !opt_map.contains_key(&ks) {
                opt_order.push(ks.clone());
            }
            opt_map.insert(ks, val);
        }
        if !key_trim.is_empty() {
            let ks = "key".to_string();
            if !opt_map.contains_key(&ks) {
                opt_order.push(ks.clone());
            }
            opt_map.insert(ks, format!("'{}'", key_trim));
        } else {
            opt_map.remove("key");
            opt_order.retain(|x| x != "key");
        }
    }

    while top_lines.last().map_or(false, |l| l.trim().is_empty()) {
        top_lines.pop();
    }

    let mut out = String::new();
    for line in &top_lines {
        out.push_str(line);
        out.push('\n');
    }
    if !top_lines.is_empty() {
        out.push('\n');
    }
    out.push_str("[options]\n");
    for k in &opt_order {
        if let Some(v) = opt_map.get(k) {
            out.push_str(&format!("{} = {}\n", k, v));
        }
    }
    for line in &other_sections {
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn rustdesk2_toml_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        if !appdata.trim().is_empty() {
            paths.push(PathBuf::from(appdata).join("RustDesk").join("config").join("RustDesk2.toml"));
        }
    }
    paths.push(PathBuf::from(
        r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml",
    ));
    paths.push(PathBuf::from(
        r"C:\Windows\System32\config\systemprofile\AppData\Roaming\RustDesk\config\RustDesk2.toml",
    ));
    paths
}

/// Writes (or clears) the self-hosted RustDesk server settings in `RustDesk2.toml` `[options]`
/// across user and service profiles while preserving all existing options and IDs.
pub fn configure_rustdesk_server() {
    ensure_rustdesk_stealth_config();
    let link = read_client();
    for path in rustdesk2_toml_paths() {
        let existing = fs::read_to_string(&path).unwrap_or_default();
        if existing.is_empty() && link.rustdesk_server.trim().is_empty() {
            continue;
        }
        let updated = sync_rustdesk_custom_server_toml(&existing, &link.rustdesk_server, &link.rustdesk_key);
        if updated != existing {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&path, updated);
        }
    }
    ensure_rustdesk_stealth_config();
}

/// Syncs the Admin machine's own `RustDesk2.toml` `[options]` with `cfg.rustdesk_server` and `cfg.rustdesk_key`.
pub fn configure_admin_rustdesk_server() {
    let cfg = read_config();
    for path in rustdesk2_toml_paths() {
        let existing = fs::read_to_string(&path).unwrap_or_default();
        if existing.is_empty() && cfg.rustdesk_server.trim().is_empty() {
            continue;
        }
        let updated = sync_rustdesk_custom_server_toml(&existing, &cfg.rustdesk_server, &cfg.rustdesk_key);
        if updated != existing {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&path, updated);
        }
    }
}

fn upsert_rustdesk2_options(existing: &str) -> String {
    const STEALTH_OPTS: [(&str, &str); 11] = [
        ("approve-mode", "'password'"),
        ("verification-method", "'use-permanent-password'"),
        ("access-mode", "'full'"),
        ("enable-camera", "'Y'"),
        ("allow-remove-wallpaper", "'N'"),
        ("enable-lan-discovery", "'Y'"),
        ("direct-server", "'Y'"),
        ("hide-cm", "'Y'"),
        ("allow-hide-cm", "'Y'"),
        ("hide-tray", "'Y'"),
        ("stop-service", "'N'"),
    ];

    let mut top_lines: Vec<String> = Vec::new();
    let mut opt_order: Vec<String> = Vec::new();
    let mut opt_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut other_sections: Vec<String> = Vec::new();
    let mut current_section = String::new();

    for raw in existing.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            if current_section != "options" {
                other_sections.push(raw.to_string());
            }
            continue;
        }
        if current_section.is_empty() {
            top_lines.push(raw.to_string());
        } else if current_section == "options" {
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim().to_string();
                if !key.is_empty() {
                    if !opt_map.contains_key(&key) {
                        opt_order.push(key.clone());
                    }
                    opt_map.insert(key, v.trim().to_string());
                }
            }
        } else {
            other_sections.push(raw.to_string());
        }
    }

    for (k, v) in STEALTH_OPTS {
        let ks = k.to_string();
        if !opt_map.contains_key(&ks) {
            opt_order.push(ks.clone());
        }
        opt_map.insert(ks, v.to_string());
    }

    while top_lines.last().map_or(false, |l| l.trim().is_empty()) {
        top_lines.pop();
    }

    let mut out = String::new();
    for line in &top_lines {
        out.push_str(line);
        out.push('\n');
    }
    if !top_lines.is_empty() {
        out.push('\n');
    }
    out.push_str("[options]\n");
    for k in &opt_order {
        if let Some(v) = opt_map.get(k) {
            out.push_str(&format!("{} = {}\n", k, v));
        }
    }
    for line in &other_sections {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Ensures RustDesk is configured for silent password-only unattended connections
/// on client devices without altering the Admin machine's RustDesk settings.
pub fn ensure_rustdesk_stealth_config() {
    if is_admin_mode() {
        return;
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        if !appdata.trim().is_empty() {
            paths.push(PathBuf::from(appdata).join("RustDesk").join("config").join("RustDesk2.toml"));
        }
    }
    paths.push(PathBuf::from(
        r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml",
    ));
    paths.push(PathBuf::from(
        r"C:\Windows\System32\config\systemprofile\AppData\Roaming\RustDesk\config\RustDesk2.toml",
    ));
    if let Ok(users_dir) = fs::read_dir(r"C:\Users") {
        for entry in users_dir.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let cfg_dir = p.join("AppData").join("Roaming").join("RustDesk").join("config");
                if cfg_dir.exists() || p.join("Desktop").exists() {
                    paths.push(cfg_dir.join("RustDesk2.toml"));
                }
                // Remove employee Desktop & Start Menu shortcuts so employees cannot open RustDesk GUI
                let _ = fs::remove_file(p.join("Desktop").join("RustDesk.lnk"));
                let _ = fs::remove_dir_all(
                    p.join("AppData")
                        .join("Roaming")
                        .join("Microsoft")
                        .join("Windows")
                        .join("Start Menu")
                        .join("Programs")
                        .join("RustDesk"),
                );
            }
        }
    }
    let _ = fs::remove_file(r"C:\Users\Public\Desktop\RustDesk.lnk");
    let _ = fs::remove_dir_all(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\RustDesk");

    for path in paths {
        let existing = fs::read_to_string(&path).unwrap_or_default();
        let updated = upsert_rustdesk2_options(&existing);
        if updated != existing {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&path, updated);
        }
    }
}

/// Elevated SYSTEM watchdog for Client PCs: keeps the RustDesk Windows service running,
/// heals the unattended permanent password if tampered with, and locks NTFS ACLs on
/// RustDesk config directories so regular employees have Read-Only access (cannot alter
/// password, ID server, or stealth options).
pub fn enforce_rustdesk_employee_lockdown(expected_password: &str) {
    if is_admin_mode() {
        return;
    }
    let has_rd = rustdesk_candidates().into_iter().any(|p| p.is_file());
    if !has_rd {
        return;
    }

    ensure_rustdesk_stealth_config();
    configure_rustdesk_server();

    // Ensure RustDesk service is set to auto-start and running
    let mut sc_cfg = Command::new("sc.exe");
    sc_cfg.args(["config", "RustDesk", "start=", "auto"]);
    let _ = hidden(&mut sc_cfg)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let mut sc_start = Command::new("sc.exe");
    sc_start.args(["start", "RustDesk"]);
    let _ = hidden(&mut sc_start)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // Verify LocalService RustDesk.toml still holds a non-empty permanent password hash; re-apply if cleared
    let svc_toml = PathBuf::from(
        r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk.toml",
    );
    let pw = expected_password.trim();
    if !pw.is_empty() {
        let raw = fs::read_to_string(&svc_toml).unwrap_or_default();
        let has_pw = raw.lines().any(|l| {
            let t = l.trim();
            if let Some(rest) = t.strip_prefix("password") {
                let val = rest
                    .trim_start_matches(|c: char| c == ' ' || c == '=' || c == '\t')
                    .trim_matches(|c: char| c == '\'' || c == '"');
                !val.is_empty()
            } else {
                false
            }
        });
        if !has_pw {
            let _ = apply_rustdesk_permanent_password(pw);
        }
    }

    // Lock NTFS write permissions on RustDesk config directories so SYSTEM, LOCAL SERVICE,
    // and Administrators have Full Control while standard Users only have Read & Execute (RX).
    let mut cfg_dirs: Vec<PathBuf> = vec![
        PathBuf::from(r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config"),
        PathBuf::from(r"C:\Windows\System32\config\systemprofile\AppData\Roaming\RustDesk\config"),
    ];
    if let Ok(users_dir) = fs::read_dir(r"C:\Users") {
        for entry in users_dir.flatten() {
            let d = entry
                .path()
                .join("AppData")
                .join("Roaming")
                .join("RustDesk")
                .join("config");
            if d.is_dir() {
                cfg_dirs.push(d);
            }
        }
    }
    for dir in cfg_dirs {
        if dir.is_dir() {
            let mut ic = Command::new("icacls");
            ic.arg(&dir)
                .args([
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-19:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                    "*S-1-5-32-545:(OI)(CI)RX",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let _ = hidden(&mut ic).status();
        }
    }
}

/// Sets or clears view-only restrictions inside a RustDesk peer TOML file while preserving
/// saved passwords, multi-line arrays, and all `[sections]`.
pub fn upsert_peer_view_only_toml(existing: &str, view_only: bool) -> String {
    let desired: [(&str, String); 5] = [
        ("view_only", if view_only { "true" } else { "false" }.to_string()),
        ("show_remote_cursor", if view_only { "true" } else { "false" }.to_string()),
        ("show_my_cursor", "false".to_string()),
        ("disable_clipboard", if view_only { "true" } else { "false" }.to_string()),
        ("enable-file-copy-paste", if view_only { "false" } else { "true" }.to_string()),
    ];
    let mut top_lines: Vec<String> = Vec::new();
    let mut rest_lines: Vec<String> = Vec::new();
    let mut in_sections = false;
    let mut seen = [false; 5];

    for raw in existing.lines() {
        let trimmed = raw.trim();
        if !in_sections && trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_sections = true;
        }
        if in_sections {
            rest_lines.push(raw.to_string());
            continue;
        }
        let mut replaced = false;
        if let Some((k, _)) = trimmed.split_once('=') {
            let key = k.trim();
            for (idx, (target_k, target_v)) in desired.iter().enumerate() {
                if key == *target_k {
                    top_lines.push(format!("{} = {}", target_k, target_v));
                    seen[idx] = true;
                    replaced = true;
                    break;
                }
            }
        }
        if !replaced {
            top_lines.push(raw.to_string());
        }
    }

    while top_lines.last().map_or(false, |l| l.trim().is_empty()) {
        top_lines.pop();
    }
    for (idx, (k, v)) in desired.iter().enumerate() {
        if !seen[idx] {
            top_lines.push(format!("{} = {}", k, v));
        }
    }

    let mut out = String::new();
    for line in &top_lines {
        out.push_str(line);
        out.push('\n');
    }
    if !rest_lines.is_empty() {
        out.push('\n');
        for line in &rest_lines {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Configures the local Admin RustDesk peer profile (`%APPDATA%\RustDesk\config\peers\<id>.toml`)
/// before launching a session so View-Only screen/camera watch modes never send input events.
pub fn configure_admin_rustdesk_peer(peer_id: &str, view_only: bool) {
    configure_admin_rustdesk_server();
    let clean: String = peer_id
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect();
    if clean.is_empty() {
        return;
    }
    let Ok(appdata) = std::env::var("APPDATA") else { return };
    if appdata.trim().is_empty() {
        return;
    }
    let peer_path = PathBuf::from(appdata)
        .join("RustDesk")
        .join("config")
        .join("peers")
        .join(format!("{}.toml", clean));
    let existing = fs::read_to_string(&peer_path).unwrap_or_default();
    let updated = upsert_peer_view_only_toml(&existing, view_only);
    if updated != existing || !peer_path.exists() {
        if let Some(parent) = peer_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&peer_path, updated);
    }
}

static STEALTH_GUARD_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Continuously hides and disables all RustDesk GUI/floating `--cm` windows on employee
/// devices so remote support sessions stay invisible and cannot be closed by the user.
#[cfg(windows)]
pub fn start_rustdesk_stealth_guard() {
    if is_admin_mode() {
        return;
    }
    if STEALTH_GUARD_STARTED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_err()
    {
        return;
    }

    #[link(name = "user32")]
    extern "system" {
        fn EnumWindows(
            lpEnumFunc: unsafe extern "system" fn(*mut std::ffi::c_void, isize) -> i32,
            lParam: isize,
        ) -> i32;
        fn GetWindowThreadProcessId(hWnd: *mut std::ffi::c_void, lpdwProcessId: *mut u32) -> u32;
        fn GetWindowLongPtrW(hWnd: *mut std::ffi::c_void, nIndex: i32) -> isize;
        fn SetWindowLongPtrW(
            hWnd: *mut std::ffi::c_void,
            nIndex: i32,
            dwNewLong: isize,
        ) -> isize;
        fn SetLayeredWindowAttributes(
            hwnd: *mut std::ffi::c_void,
            crKey: u32,
            bAlpha: u8,
            dwFlags: u32,
        ) -> i32;
        fn SetWindowPos(
            hWnd: *mut std::ffi::c_void,
            hWndInsertAfter: *mut std::ffi::c_void,
            X: i32,
            Y: i32,
            cx: i32,
            cy: i32,
            uFlags: u32,
        ) -> i32;
        fn EnableWindow(hWnd: *mut std::ffi::c_void, bEnable: i32) -> i32;
        fn ShowWindow(hWnd: *mut std::ffi::c_void, nCmdShow: i32) -> i32;
        fn IsWindowVisible(hWnd: *mut std::ffi::c_void) -> i32;
        fn IsWindowEnabled(hWnd: *mut std::ffi::c_void) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> *mut std::ffi::c_void;
        fn QueryFullProcessImageNameW(
            hProcess: *mut std::ffi::c_void,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    static NON_RUSTDESK_PIDS: std::sync::Mutex<Option<Vec<u32>>> = std::sync::Mutex::new(None);
    static RUSTDESK_PIDS: std::sync::Mutex<Option<Vec<u32>>> = std::sync::Mutex::new(None);

    unsafe extern "system" fn hide_rustdesk_window(
        hwnd: *mut std::ffi::c_void,
        _lparam: isize,
    ) -> i32 {
        const GWL_EXSTYLE: i32 = -20;
        const WS_EX_TRANSPARENT: isize = 0x0000_0020;
        const WS_EX_TOOLWINDOW: isize = 0x0000_0080;
        const WS_EX_APPWINDOW: isize = 0x0004_0000;
        const WS_EX_LAYERED: isize = 0x0008_0000;
        const WS_EX_NOACTIVATE: isize = 0x0800_0000;
        const LWA_ALPHA: u32 = 0x0000_0002;
        const SWP_NOZORDER: u32 = 0x0004;
        const SWP_NOACTIVATE: u32 = 0x0010;
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

        // Skip already-hidden / invisible background windows before opening process handles.
        if IsWindowVisible(hwnd) == 0 {
            return 1;
        }

        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == 0 {
            return 1;
        }
        if let Ok(g) = NON_RUSTDESK_PIDS.lock() {
            if g.as_ref().map_or(false, |v| v.contains(&pid)) {
                return 1;
            }
        }
        let known_rd = RUSTDESK_PIDS
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|v| v.contains(&pid)))
            .unwrap_or(false);

        let is_rustdesk = if known_rd {
            true
        } else {
            let hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if hproc.is_null() {
                return 1;
            }
            let mut buf = [0u16; 260];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(hproc, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(hproc);
            if ok == 0 || len == 0 {
                return 1;
            }
            let exe = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();
            let rd = Path::new(&exe)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == "rustdesk.exe")
                .unwrap_or(false);
            if rd {
                if let Ok(mut g) = RUSTDESK_PIDS.lock() {
                    let v = g.get_or_insert_with(Vec::new);
                    if v.len() >= 16 {
                        v.remove(0);
                    }
                    v.push(pid);
                }
            } else if let Ok(mut g) = NON_RUSTDESK_PIDS.lock() {
                let v = g.get_or_insert_with(Vec::new);
                if v.len() >= 256 {
                    v.drain(0..64);
                }
                v.push(pid);
            }
            rd
        };

        if !is_rustdesk {
            return 1;
        }

        let ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        let new_ex = (ex & !WS_EX_APPWINDOW)
            | WS_EX_LAYERED
            | WS_EX_TRANSPARENT
            | WS_EX_TOOLWINDOW
            | WS_EX_NOACTIVATE;
        if ex != new_ex || IsWindowVisible(hwnd) != 0 || IsWindowEnabled(hwnd) != 0 {
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_ex);
            SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                -32000,
                -32000,
                1,
                1,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            EnableWindow(hwnd, 0);
            ShowWindow(hwnd, 0);
        }
        1
    }

    std::thread::spawn(move || {
        let mut ticks: u32 = 0;
        loop {
            unsafe {
                EnumWindows(hide_rustdesk_window, 0);
            }
            ticks = ticks.wrapping_add(1);
            // Periodically flush PID caches every ~5 minutes in case Windows recycles a PID
            if ticks % 340 == 0 {
                if let Ok(mut g) = NON_RUSTDESK_PIDS.lock() {
                    if let Some(v) = g.as_mut() {
                        v.clear();
                    }
                }
                if let Ok(mut g) = RUSTDESK_PIDS.lock() {
                    if let Some(v) = g.as_mut() {
                        v.clear();
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(850));
        }
    });
}

/// Enumerates currently connected USB mass-storage device IDs directly from
/// `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Enum` without spawning PowerShell.
#[cfg(windows)]
pub fn list_usbstor_device_ids() -> Vec<String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: *mut std::ffi::c_void,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: *mut std::ffi::c_void,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: *mut std::ffi::c_void) -> i32;
    }
    const HKEY_LOCAL_MACHINE: *mut std::ffi::c_void = 0x8000_0002usize as *mut std::ffi::c_void;
    const KEY_READ: u32 = 0x20019;
    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;

    let mut sub: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Enum\0"
        .encode_utf16()
        .collect();
    let mut hkey: *mut std::ffi::c_void = std::ptr::null_mut();
    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_mut_ptr(), 0, KEY_READ, &mut hkey) != 0
            || hkey.is_null()
        {
            return Vec::new();
        }
        let count_name: Vec<u16> = "Count\0".encode_utf16().collect();
        let mut count_val: u32 = 0;
        let mut cb: u32 = 4;
        let mut vtype: u32 = 0;
        if RegQueryValueExW(
            hkey,
            count_name.as_ptr(),
            std::ptr::null_mut(),
            &mut vtype,
            (&mut count_val as *mut u32) as *mut u8,
            &mut cb,
        ) != 0
            || vtype != REG_DWORD
        {
            RegCloseKey(hkey);
            return Vec::new();
        }
        let mut out = Vec::new();
        for idx in 0..count_val.min(64) {
            let vname: Vec<u16> = format!("{}\0", idx).encode_utf16().collect();
            let mut buf = [0u16; 260];
            let mut bcb: u32 = (buf.len() * 2) as u32;
            let mut stype: u32 = 0;
            if RegQueryValueExW(
                hkey,
                vname.as_ptr(),
                std::ptr::null_mut(),
                &mut stype,
                buf.as_mut_ptr() as *mut u8,
                &mut bcb,
            ) == 0
                && stype == REG_SZ
                && bcb >= 2
            {
                let ulen = (bcb as usize / 2).min(buf.len());
                let end = buf[..ulen].iter().position(|&c| c == 0).unwrap_or(ulen);
                let s = String::from_utf16_lossy(&buf[..end]).trim().to_string();
                if !s.is_empty() {
                    out.push(s);
                }
            }
        }
        RegCloseKey(hkey);
        out
    }
}

#[cfg(not(windows))]
pub fn list_usbstor_device_ids() -> Vec<String> {
    Vec::new()
}

#[cfg(not(windows))]
pub fn start_rustdesk_stealth_guard() {}

pub fn read_rustdesk_id() -> String {
    // 1) Ask RustDesk itself (works for all versions).
    for exe in rustdesk_candidates() {
        if !exe.is_file() {
            continue;
        }
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("--get-id");
        if let Ok(out) = hidden(&mut cmd).output() {
            if out.status.success() {
                let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !id.is_empty() && id.chars().all(|c| c.is_ascii_digit() || c == ' ') {
                    return id.replace(' ', "");
                }
            }
        }
    }
    // 2) Fall back to config files (older versions store id = "..." in TOML).
    let base = std::env::var("APPDATA").ok().unwrap_or_default();
    if !base.is_empty() {
        let candidates = [
            std::path::PathBuf::from(&base).join("RustDesk").join("config").join("RustDesk.toml"),
            std::path::PathBuf::from(&base).join("RustDesk").join("config").join("RustDesk2.toml"),
        ];
        for path in candidates {
            if let Ok(text) = fs::read_to_string(&path) {
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("id") {
                        let rest = rest.trim_start_matches(|c: char| c == ' ' || c == '=' || c == '\t');
                        if let Some(stripped) = rest.strip_prefix('"') {
                            if let Some(end) = stripped.find('"') {
                                let id = &stripped[..end];
                                if !id.is_empty() {
                                    return id.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    String::new()
}

/// Sets RustDesk's permanent (unattended) password on this machine so the admin can
/// connect without the employee clicking Accept. Must run elevated (the agent runs as
/// SYSTEM). Returns true only if an installed rustdesk.exe accepted the password.
pub fn apply_rustdesk_permanent_password(password: &str) -> bool {
    ensure_rustdesk_stealth_config();
    let password = password.trim();
    if password.is_empty() {
        return false;
    }
    for exe in rustdesk_candidates() {
        if !exe.is_file() {
            continue;
        }
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("--password").arg(password);
        let ok = hidden(&mut cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            ensure_rustdesk_stealth_config();
            return true;
        }
    }
    false
}

/// Builds the RustDesk URI that opens a session with the password pre-filled,
/// e.g. `rustdesk://connection/new/123456789?password=...`.
pub fn rustdesk_connect_uri(rustdesk_id: &str, password: &str) -> String {
    let mut enc = String::new();
    for b in password.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            enc.push(b as char);
        } else {
            enc.push_str(&format!("%{:02X}", b));
        }
    }
    if enc.is_empty() {
        format!("rustdesk://connection/new/{}", rustdesk_id)
    } else {
        format!("rustdesk://connection/new/{}?password={}", rustdesk_id, enc)
    }
}

pub fn rustdesk_candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(';') {
            out.push(std::path::PathBuf::from(dir).join("rustdesk.exe"));
        }
    }
    for env_var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Ok(base) = std::env::var(env_var) {
            out.push(std::path::PathBuf::from(&base).join("RustDesk").join("rustdesk.exe"));
        }
    }
    out.push(std::path::PathBuf::from(r"C:\Program Files\RustDesk\rustdesk.exe"));
    out.push(std::path::PathBuf::from(r"C:\Program Files (x86)\RustDesk\rustdesk.exe"));
    out
}

/// Captures the primary screen directly via Win32 GDI scaled to at most `max_w` width
/// (no PowerShell, so Windows Defender AMSI never blocks it) and encodes a compact PNG as base64.
#[cfg(windows)]
pub fn capture_screen_scaled_base64(max_w: i32) -> Option<String> {
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, SetStretchBltMode, StretchBlt, BITMAPINFO,
        BITMAPINFOHEADER, BI_RGB, COLORONCOLOR, DIB_RGB_COLORS, SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SetProcessDPIAware, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
        SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

    unsafe {
        let _ = SetProcessDPIAware();
        let src_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let src_y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let src_w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let src_h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if src_w <= 0 || src_h <= 0 {
            return None;
        }

        let cap_w = max_w.max(320);
        let (dst_w, dst_h) = if src_w > cap_w {
            let h = ((src_h as i64 * cap_w as i64) / src_w as i64).max(1) as i32;
            (cap_w, h)
        } else {
            (src_w, src_h)
        };

        let screen_dc = GetDC(std::ptr::null_mut());
        if screen_dc.is_null() {
            return None;
        }
        let mem_dc = CreateCompatibleDC(screen_dc);
        if mem_dc.is_null() {
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }
        let bmp = CreateCompatibleBitmap(screen_dc, dst_w, dst_h);
        if bmp.is_null() {
            DeleteDC(mem_dc);
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }

        let old = SelectObject(mem_dc, bmp);
        let blt_ok = if dst_w == src_w && dst_h == src_h {
            BitBlt(mem_dc, 0, 0, dst_w, dst_h, screen_dc, src_x, src_y, SRCCOPY)
        } else {
            SetStretchBltMode(mem_dc, COLORONCOLOR as i32);
            StretchBlt(
                mem_dc, 0, 0, dst_w, dst_h, screen_dc, src_x, src_y, src_w, src_h, SRCCOPY,
            )
        };
        // IMPORTANT: Win32 requires deselecting `bmp` from `mem_dc` BEFORE calling GetDIBits!
        SelectObject(mem_dc, old);

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: dst_w,
                biHeight: -dst_h, // top-down scanlines
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [std::mem::zeroed()],
        };

        let mut bgra = vec![0u8; (dst_w as usize) * (dst_h as usize) * 4];
        let lines = if blt_ok != 0 {
            GetDIBits(
                screen_dc,
                bmp,
                0,
                dst_h as u32,
                bgra.as_mut_ptr() as *mut _,
                &mut bmi,
                DIB_RGB_COLORS,
            )
        } else {
            0
        };

        DeleteObject(bmp);
        DeleteDC(mem_dc);
        ReleaseDC(std::ptr::null_mut(), screen_dc);

        if lines == 0 {
            return None;
        }

        encode_bgra_png_base64(&bgra, dst_w as u32, dst_h as u32)
    }
}

#[cfg(windows)]
pub fn capture_screen_base64() -> Option<String> {
    capture_screen_scaled_base64(1280)
}

/// Captures a specific top-level window directly via Win32 `PrintWindow(PW_RENDERFULLCONTENT)`
/// so Chromium/WhatsApp windows are captured cleanly even when dialogs or Explorer overlap them.
#[cfg(windows)]
pub fn capture_window_base64(hwnd_raw: isize, max_w: i32) -> Option<String> {
    use windows_sys::Win32::Graphics::Gdi::{
        CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, GetDIBits,
        ReleaseDC, SelectObject, SetStretchBltMode, StretchBlt, BITMAPINFO, BITMAPINFOHEADER,
        BI_RGB, DIB_RGB_COLORS, SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SetProcessDPIAware;

    #[repr(C)]
    struct WinRect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn IsWindowVisible(hWnd: *mut std::ffi::c_void) -> i32;
        fn IsIconic(hWnd: *mut std::ffi::c_void) -> i32;
        fn GetWindowRect(hWnd: *mut std::ffi::c_void, lpRect: *mut WinRect) -> i32;
        fn PrintWindow(
            hwnd: *mut std::ffi::c_void,
            hdcBlt: *mut std::ffi::c_void,
            nFlags: u32,
        ) -> i32;
    }

    if hwnd_raw == 0 {
        return None;
    }
    let hwnd = hwnd_raw as *mut std::ffi::c_void;
    unsafe {
        let _ = SetProcessDPIAware();
        if IsWindowVisible(hwnd) == 0 || IsIconic(hwnd) != 0 {
            return None;
        }
        let mut rc = WinRect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        if GetWindowRect(hwnd, &mut rc) == 0 {
            return None;
        }
        let src_w = rc.right - rc.left;
        let src_h = rc.bottom - rc.top;
        if src_w < 320 || src_h < 220 {
            return None;
        }

        let screen_dc = GetDC(std::ptr::null_mut());
        if screen_dc.is_null() {
            return None;
        }
        let src_dc = CreateCompatibleDC(screen_dc);
        if src_dc.is_null() {
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }
        let src_bmp = CreateCompatibleBitmap(screen_dc, src_w, src_h);
        if src_bmp.is_null() {
            DeleteDC(src_dc);
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }
        let old_src = SelectObject(src_dc, src_bmp);
        const PW_RENDERFULLCONTENT: u32 = 2;
        let pw_ok = PrintWindow(hwnd, src_dc, PW_RENDERFULLCONTENT);
        if pw_ok == 0 {
            SelectObject(src_dc, old_src);
            DeleteObject(src_bmp);
            DeleteDC(src_dc);
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }

        let cap_w = max_w.max(320);
        let (dst_w, dst_h) = if src_w > cap_w {
            let h = ((src_h as i64 * cap_w as i64) / src_w as i64).max(1) as i32;
            (cap_w, h)
        } else {
            (src_w, src_h)
        };

        let dst_dc = CreateCompatibleDC(screen_dc);
        if dst_dc.is_null() {
            SelectObject(src_dc, old_src);
            DeleteObject(src_bmp);
            DeleteDC(src_dc);
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }
        let dst_bmp = CreateCompatibleBitmap(screen_dc, dst_w, dst_h);
        if dst_bmp.is_null() {
            DeleteDC(dst_dc);
            SelectObject(src_dc, old_src);
            DeleteObject(src_bmp);
            DeleteDC(src_dc);
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }
        let old_dst = SelectObject(dst_dc, dst_bmp);
        const HALFTONE_MODE: i32 = 4;
        SetStretchBltMode(dst_dc, HALFTONE_MODE);
        let blt_ok = StretchBlt(
            dst_dc, 0, 0, dst_w, dst_h, src_dc, 0, 0, src_w, src_h, SRCCOPY,
        );
        // Deselect bitmaps before reading pixels with GetDIBits.
        SelectObject(dst_dc, old_dst);
        SelectObject(src_dc, old_src);

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: dst_w,
                biHeight: -dst_h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [std::mem::zeroed()],
        };
        let mut bgra = vec![0u8; (dst_w as usize) * (dst_h as usize) * 4];
        let lines = if blt_ok != 0 {
            GetDIBits(
                screen_dc,
                dst_bmp,
                0,
                dst_h as u32,
                bgra.as_mut_ptr() as *mut _,
                &mut bmi,
                DIB_RGB_COLORS,
            )
        } else {
            0
        };

        DeleteObject(dst_bmp);
        DeleteDC(dst_dc);
        DeleteObject(src_bmp);
        DeleteDC(src_dc);
        ReleaseDC(std::ptr::null_mut(), screen_dc);

        if lines == 0 {
            return None;
        }
        // Reject blank / all-black PrintWindow captures so caller falls back cleanly.
        let total_px = (dst_w as usize) * (dst_h as usize);
        let stride_px = (total_px / 300).max(1);
        let mut non_black = 0usize;
        let mut first_rgb: Option<(u8, u8, u8)> = None;
        let mut has_contrast = false;
        for px_idx in (0..total_px).step_by(stride_px) {
            let o = px_idx * 4;
            let rgb = (bgra[o + 2], bgra[o + 1], bgra[o]);
            if (rgb.0 as u16 + rgb.1 as u16 + rgb.2 as u16) > 24 {
                non_black += 1;
            }
            match first_rgb {
                None => first_rgb = Some(rgb),
                Some(f) if f != rgb => has_contrast = true,
                _ => {}
            }
        }
        if non_black < 3 || !has_contrast {
            return None;
        }
        encode_bgra_png_base64(&bgra, dst_w as u32, dst_h as u32)
    }
}

#[cfg(not(windows))]
pub fn capture_window_base64(_hwnd_raw: isize, _max_w: i32) -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn capture_screen_scaled_base64(_max_w: i32) -> Option<String> {
    None
}

/// Converts BGRA pixel buffer to a base64-encoded RGB PNG.
pub fn encode_bgra_png_base64(bgra: &[u8], width: u32, height: u32) -> Option<String> {
    if width == 0 || height == 0 || bgra.len() < (width as usize) * (height as usize) * 4 {
        return None;
    }
    let mut rgb = Vec::with_capacity((width as usize) * (height as usize) * 3);
    for px in bgra.chunks_exact(4) {
        rgb.push(px[2]);
        rgb.push(px[1]);
        rgb.push(px[0]);
    }
    let mut png_bytes = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut png_bytes, width, height);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Fast);
        let mut writer = enc.write_header().ok()?;
        writer.write_image_data(&rgb).ok()?;
    }
    if png_bytes.is_empty() {
        return None;
    }
    Some(base64_encode(&png_bytes))
}

#[cfg(not(windows))]
pub fn capture_screen_base64() -> Option<String> {
    None
}

pub fn block_state_path() -> std::path::PathBuf {
    data_dir().join("blocked.state")
}

/// Records the authoritative block state. The registry is ambiguous because a
/// speed limit also enables our proxy, so we persist the real policy state.
pub fn set_block_state(blocked: bool) {
    let _ = fs::write(block_state_path(), if blocked { "1" } else { "0" });
}

pub fn is_blocked() -> bool {
    if let Ok(state) = fs::read_to_string(block_state_path()) {
        return state.trim() == "1";
    }
    detect_blocked_legacy()
}

/// Best-effort detection used only when no marker exists yet (old installs).
pub fn detect_blocked_legacy() -> bool {
    if reg_query_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyEnable",
    ) == Some(1)
    {
        return true;
    }
    if reg_query_dword(
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyEnable",
    ) == Some(1)
    {
        return true;
    }
    for key in [
        r"HKLM\SOFTWARE\Policies\Google\Chrome",
        r"HKLM\SOFTWARE\Policies\Microsoft\Edge",
    ] {
        if reg_value_exists(key, "ProxyMode") || reg_value_exists(key, "ProxyServer") {
            return true;
        }
    }
    hosts_block_active()
}

fn script_args(script: &str) -> Vec<String> {
    vec![
        "-NoProfile".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-File".into(),
        resource_dir().join(script).to_string_lossy().to_string(),
        "-DataDir".into(),
        data_dir().to_string_lossy().to_string(),
    ]
}

/// Runs a script directly. Only valid when the current process is already elevated (the SYSTEM agent).
pub fn run_script(script: &str, extra: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("powershell");
    cmd.args(script_args(script)).args(extra);
    let out = hidden(&mut cmd).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(exit_reason(out.status.code()))
    }
}

fn exit_reason(code: Option<i32>) -> String {
    match code {
        Some(2) => "كلمة السر مطلوبة".into(),
        Some(3) => "كلمة السر غير صحيحة".into(),
        Some(c) => format!("فشل التنفيذ (كود {})", c),
        None => "تم إلغاء العملية".into(),
    }
}

/// Runs a script elevated through a UAC prompt, for the interactive admin machine.
pub fn run_script_elevated(script: &str, password: Option<&str>) -> Result<(), String> {
    let mut args = script_args(script);
    let mut pw_file: Option<PathBuf> = None;

    if let Some(pw) = password.filter(|p| !p.is_empty()) {
        let path = std::env::temp_dir().join(format!("ibp-{}.tmp", random_hex(8)));
        fs::write(&path, pw).map_err(|e| e.to_string())?;
        args.push("-PasswordFile".into());
        args.push(path.to_string_lossy().to_string());
        pw_file = Some(path);
    }
    if script == "allow-internet.ps1" {
        args.push("-NoPrompt".into());
    }

    // Paths are quoted for the elevated PowerShell; the whole thing is passed encoded so no
    // quoting layer can break or be injected into.
    let arg_string: String = args
        .iter()
        .map(|a| if a.starts_with('-') && !a.contains(' ') { a.clone() } else { format!("\"{}\"", a) })
        .collect::<Vec<_>>()
        .join(" ");
    let inner = format!(
        "$p = Start-Process -FilePath 'powershell.exe' -ArgumentList '{}' -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop; exit $p.ExitCode",
        arg_string.replace('\'', "''")
    );
    let encoded = encode_utf16_base64(&inner);

    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-EncodedCommand", &encoded]);
    let result = hidden(&mut cmd).output();

    if let Some(p) = pw_file {
        let _ = fs::remove_file(p);
    }

    let out = result.map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(exit_reason(out.status.code()))
    }
}

fn encode_utf16_base64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn preserved_company_cookie_patterns() -> Vec<String> {
    const EXCLUDED_CHAT_SOCIAL: [&str; 12] = [
        "whatsapp.com",
        "web.whatsapp.com",
        "whatsapp.net",
        "facebook.com",
        "fb.com",
        "youtube.com",
        "youtu.be",
        "instagram.com",
        "tiktok.com",
        "twitter.com",
        "x.com",
        "telegram.org",
    ];
    let mut raw_entries = read_list(&allowed_path());
    // Always preserve the company's primary ERP system domains even in Blacklist mode
    // or before the first group policy sync completes.
    raw_entries.push(DEFAULT_ERP_DOMAIN.to_string());
    for d in read_config().erp_domains {
        raw_entries.push(d);
    }

    let mut patterns = Vec::new();
    for entry in raw_entries {
        let Some(cleaned) = clean_domain(&entry) else { continue };
        let (host_only, port_opt) = match cleaned.split_once(':') {
            Some((h, p)) => (h.trim_start_matches("www.").to_lowercase(), Some(p)),
            None => (cleaned.trim_start_matches("www.").to_lowercase(), None),
        };
        if host_only.is_empty()
            || EXCLUDED_CHAT_SOCIAL
                .iter()
                .any(|ex| host_only == *ex || host_only.ends_with(&format!(".{}", ex)))
        {
            continue;
        }
        let is_ip = host_only == "localhost"
            || (host_only.split('.').count() == 4
                && host_only.split('.').all(|seg| seg.parse::<u8>().is_ok()));
        let suffix = port_opt.map(|p| format!(":{}", p)).unwrap_or_default();
        if is_ip {
            patterns.push(format!("https://{}{}", host_only, suffix));
            patterns.push(format!("http://{}{}", host_only, suffix));
        } else {
            patterns.push(format!("[*.]{}{}", host_only, suffix));
            patterns.push(format!("https://[*.]{}{}", host_only, suffix));
            patterns.push(format!("http://[*.]{}{}", host_only, suffix));
        }
    }
    patterns.sort();
    patterns.dedup();
    patterns
}

fn list_loaded_hku_policy_roots() -> Vec<String> {
    let mut roots = vec![
        r"HKLM\SOFTWARE\Policies\Google\Chrome".to_string(),
        r"HKLM\SOFTWARE\Policies\Microsoft\Edge".to_string(),
        r"HKCU\SOFTWARE\Policies\Google\Chrome".to_string(),
        r"HKCU\SOFTWARE\Policies\Microsoft\Edge".to_string(),
    ];
    let mut q = Command::new("reg");
    q.args(["query", "HKU"]);
    if let Ok(out) = hidden(&mut q).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let t = line.trim();
            if t.starts_with(r"HKEY_USERS\S-1-5-21-") && !t.ends_with("_Classes") {
                let sid_root = t.replacen("HKEY_USERS\\", "HKU\\", 1);
                roots.push(format!(r"{}\SOFTWARE\Policies\Google\Chrome", sid_root));
                roots.push(format!(r"{}\SOFTWARE\Policies\Microsoft\Edge", sid_root));
            }
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Applies or removes Chrome and Edge clean-browser policies that wipe browsing history,
/// saved passwords, autofill, bookmarks, caches, and open tabs on exit (plus disabling F12 DevTools),
/// while NEVER setting `DefaultCookiesSetting = 4` so company ERP device-binding tokens
/// (`elkhawaga_did` HttpOnly cookie, `elkhawaga_device_token` LocalStorage, `ElkhawagaDeviceDB`)
/// survive permanently across browser restarts.
pub fn apply_ephemeral_browser_policy(enable: bool) {
    if is_admin_mode() {
        return;
    }
    const MACHINE_ROOTS: [&str; 2] = [
        r"HKLM\SOFTWARE\Policies\Google\Chrome",
        r"HKLM\SOFTWARE\Policies\Microsoft\Edge",
    ];
    const COMMON_DWORDS: [(&str, &str); 21] = [
        ("SavingBrowserHistoryDisabled", "1"),
        ("SearchSuggestEnabled", "0"),
        ("UrlKeyedAnonymizedDataCollectionEnabled", "0"),
        ("BrowserSignin", "0"),
        ("SyncDisabled", "1"),
        ("PasswordManagerEnabled", "0"),
        ("AutofillAddressEnabled", "0"),
        ("AutofillCreditCardEnabled", "0"),
        ("HomepageIsNewTabPage", "0"),
        ("ShowHomeButton", "0"),
        ("BackgroundModeEnabled", "0"),
        ("StartupBoostEnabled", "0"),
        ("EditBookmarksEnabled", "0"),
        ("BookmarkBarEnabled", "0"),
        ("DeveloperToolsAvailability", "2"),
        ("NTPCardsVisible", "0"),
        ("NTPMiddleSlotAnnouncementVisible", "0"),
        ("PromotionalTabsEnabled", "0"),
        ("AIModeSettings", "1"),
        ("GenAILocalFoundationalModelSettings", "1"),
        ("HistorySearchSettings", "2"),
    ];
    const EDGE_NTP_DWORDS: [(&str, &str); 7] = [
        ("NewTabPageQuickLinksEnabled", "0"),
        ("NewTabPageHideDefaultTopSites", "1"),
        ("NewTabPageContentEnabled", "0"),
        ("NewTabPageFeedsEnabled", "0"),
        ("SpotlightExperiencesAndRecommendationsEnabled", "0"),
        ("EdgeCollectionsEnabled", "0"),
        ("HubsSidebarEnabled", "0"),
    ];
    const EDGE_STRING_SETTINGS: [(&str, &str); 2] = [
        ("NewTabPageLocation", "about:blank"),
        ("HomepageLocation", "about:blank"),
    ];
    const CLEAR_ON_EXIT_ITEMS: [&str; 5] = [
        "browsing_history",
        "download_history",
        "cached_images_and_files",
        "password_signin",
        "autofill",
    ];
    const SESSION_ONLY_SOCIAL_URLS: [&str; 12] = [
        "https://[*.]whatsapp.com",
        "https://[*.]whatsapp.net",
        "https://[*.]facebook.com",
        "https://[*.]messenger.com",
        "https://[*.]instagram.com",
        "https://[*.]tiktok.com",
        "https://[*.]youtube.com",
        "https://[*.]google.com",
        "https://[*.]live.com",
        "https://[*.]telegram.org",
        "https://[*.]x.com",
        "https://[*.]twitter.com",
    ];

    let cookie_patterns = if enable {
        preserved_company_cookie_patterns()
    } else {
        Vec::new()
    };

    // Clean any stale or conflicting keys across HKLM, HKCU, and all loaded user SIDs in HKU
    for root in list_loaded_hku_policy_roots() {
        for legacy_val in [
            "ForceEphemeralProfiles",
            "ClearBrowsingDataOnExit",
            "DefaultCookiesSetting",
            "RestoreOnStartup",
            "NewTabPageLocation",
            "HomepageLocation",
        ] {
            let mut del_legacy = Command::new("reg");
            del_legacy.args(["delete", &root, "/v", legacy_val, "/f"]);
            let _ = hidden(&mut del_legacy).output();
        }
        for sub in [
            "ClearBrowsingDataOnExitList",
            "CookiesAllowedForUrls",
            "SaveCookiesOnExit",
            "CookiesSessionOnlyForUrls",
            "RestoreOnStartupURLs",
        ] {
            let subkey = format!(r"{}\{}", root, sub);
            let mut del_sub = Command::new("reg");
            del_sub.args(["delete", &subkey, "/f"]);
            let _ = hidden(&mut del_sub).output();
        }
        if !enable || !root.starts_with(r"HKLM\") {
            for (name, _) in COMMON_DWORDS.iter().chain(EDGE_NTP_DWORDS.iter()).chain(EDGE_STRING_SETTINGS.iter()) {
                let mut cmd = Command::new("reg");
                cmd.args(["delete", &root, "/v", name, "/f"]);
                let _ = hidden(&mut cmd).output();
            }
        }
    }

    if !enable {
        return;
    }

    for root in MACHINE_ROOTS {
        let is_edge = root.contains("Microsoft\\Edge");
        let list_key = format!(r"{}\ClearBrowsingDataOnExitList", root);
        let cookies_key = format!(r"{}\CookiesAllowedForUrls", root);
        let save_cookies_key = format!(r"{}\SaveCookiesOnExit", root);
        let session_only_key = format!(r"{}\CookiesSessionOnlyForUrls", root);
        let startup_urls_key = format!(r"{}\RestoreOnStartupURLs", root);

        for (name, val) in COMMON_DWORDS {
            let mut cmd = Command::new("reg");
            cmd.args(["add", root, "/v", name, "/t", "REG_DWORD", "/d", val, "/f"]);
            let _ = hidden(&mut cmd).output();
        }
        // Chrome on non-domain Windows honors RestoreOnStartup=5 (New Tab) and ignores 4,
        // while Edge honors RestoreOnStartup=4 + about:blank on all Windows editions.
        {
            let mut cmd = Command::new("reg");
            cmd.args([
                "add",
                root,
                "/v",
                "RestoreOnStartup",
                "/t",
                "REG_DWORD",
                "/d",
                if is_edge { "4" } else { "5" },
                "/f",
            ]);
            let _ = hidden(&mut cmd).output();
        }
        if is_edge {
            for (name, val) in EDGE_STRING_SETTINGS {
                let mut cmd = Command::new("reg");
                cmd.args(["add", root, "/v", name, "/t", "REG_SZ", "/d", val, "/f"]);
                let _ = hidden(&mut cmd).output();
            }
            {
                let mut cmd = Command::new("reg");
                cmd.args(["add", &startup_urls_key, "/v", "1", "/t", "REG_SZ", "/d", "about:blank", "/f"]);
                let _ = hidden(&mut cmd).output();
            }
            for (name, val) in EDGE_NTP_DWORDS {
                let mut cmd = Command::new("reg");
                cmd.args(["add", root, "/v", name, "/t", "REG_DWORD", "/d", val, "/f"]);
                let _ = hidden(&mut cmd).output();
            }
        }
        for (idx, item) in CLEAR_ON_EXIT_ITEMS.iter().enumerate() {
            let name = (idx + 1).to_string();
            let mut cmd = Command::new("reg");
            cmd.args(["add", &list_key, "/v", &name, "/t", "REG_SZ", "/d", item, "/f"]);
            let _ = hidden(&mut cmd).output();
        }
        for (idx, pat) in SESSION_ONLY_SOCIAL_URLS.iter().enumerate() {
            let name = (idx + 1).to_string();
            let mut cmd = Command::new("reg");
            cmd.args(["add", &session_only_key, "/v", &name, "/t", "REG_SZ", "/d", pat, "/f"]);
            let _ = hidden(&mut cmd).output();
        }
        for (idx, pat) in cookie_patterns.iter().enumerate() {
            let name = (idx + 1).to_string();
            let mut cmd = Command::new("reg");
            cmd.args(["add", &cookies_key, "/v", &name, "/t", "REG_SZ", "/d", pat, "/f"]);
            let _ = hidden(&mut cmd).output();
            if is_edge {
                let mut edge_cmd = Command::new("reg");
                edge_cmd.args(["add", &save_cookies_key, "/v", &name, "/t", "REG_SZ", "/d", pat, "/f"]);
                let _ = hidden(&mut edge_cmd).output();
            }
        }
    }
}

#[cfg(windows)]
pub fn is_process_running(exe_name: &str) -> bool {
    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut std::ffi::c_void;
        fn Process32FirstW(hSnapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(hSnapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    let invalid = (-1isize) as *mut std::ffi::c_void;
    let target = exe_name.trim().to_ascii_lowercase();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap == invalid {
            return false;
        }
        let mut entry = ProcessEntry32W {
            dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0u16; 260],
        };
        let mut found = false;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let end = entry
                    .sz_exe_file
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.sz_exe_file.len());
                let name = String::from_utf16_lossy(&entry.sz_exe_file[..end]);
                if name.eq_ignore_ascii_case(&target) {
                    found = true;
                    break;
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

#[cfg(not(windows))]
pub fn is_process_running(_exe_name: &str) -> bool {
    false
}

fn write_empty_chromium_bookmarks(profile_path: &Path) {
    const EMPTY_BOOKMARKS_JSON: &str = r#"{"checksum":"","roots":{"bookmark_bar":{"children":[],"name":"Bookmarks bar","type":"folder"},"other":{"children":[],"name":"Other bookmarks","type":"folder"},"synced":{"children":[],"name":"Mobile bookmarks","type":"folder"}},"version":1}"#;
    for bak in [
        "Bookmarks.bak",
        "AccountBookmarks.bak",
        "BookmarkMergedSurfaceOrdering",
        "EncryptedAccountBookmarks2",
    ] {
        let _ = fs::remove_file(profile_path.join(bak));
    }
    for bm in ["Bookmarks", "AccountBookmarks"] {
        let p = profile_path.join(bm);
        let _ = fs::write(p, EMPTY_BOOKMARKS_JSON);
    }
}

fn scrub_profile_ntp_preferences(profile_path: &Path) {
    let _ = fs::remove_file(profile_path.join("Secure Preferences"));
    let pref_path = profile_path.join("Preferences");
    let Ok(raw) = fs::read_to_string(&pref_path) else { return };
    let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&raw) else { return };
    let mut changed = false;
    if let Some(obj) = val.as_object_mut() {
        let desired_ntp = serde_json::json!({
            "custom_links_initialized": true,
            "custom_links_list": [],
            "num_personal_suggestions": 0,
            "shortcuts_visible": false,
            "use_most_visited": false
        });
        if obj.get("ntp") != Some(&desired_ntp) {
            obj.insert("ntp".to_string(), desired_ntp);
            changed = true;
        }
        for k in [
            "NewTabPage",
            "pinned_tabs",
            "zero_suggest_list_data",
            "zerosuggest",
            "omnibox",
            "saved_tab_groups",
            "bookmark",
            "account_info",
            "account_values",
            "sync",
        ] {
            if obj.remove(k).is_some() {
                changed = true;
            }
        }
        if let Some(edge_ntp) = obj.get_mut("edge").and_then(|v| v.as_object_mut()) {
            let empty_arr = serde_json::json!([]);
            if edge_ntp.get("ntp_quick_links") != Some(&empty_arr) {
                edge_ntp.insert("ntp_quick_links".to_string(), empty_arr);
                changed = true;
            }
        }
    }
    if changed {
        if let Ok(out) = serde_json::to_string(&val) {
            let _ = fs::write(&pref_path, out);
        }
    }
}

fn all_user_local_appdata_dirs() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let users_root = PathBuf::from(format!(r"{}\Users", sys_drive));
    if let Ok(entries) = fs::read_dir(&users_root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let uname = entry.file_name().to_string_lossy().to_string();
            let lower = uname.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "public" | "default" | "default user" | "all users" | "wdagutilityaccount"
            ) {
                continue;
            }
            let local_dir = p.join("AppData").join("Local");
            if local_dir.is_dir() {
                out.push((uname, local_dir));
            }
        }
    }
    if let Ok(v) = std::env::var("LOCALAPPDATA") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            let pb = PathBuf::from(trimmed);
            if pb.is_dir() && !out.iter().any(|(_, existing)| existing == &pb) {
                out.push(("current".to_string(), pb));
            }
        }
    }
    out
}

fn dir_has_leveldb_payload(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else { return false };
    let mut has_data = false;
    for entry in entries.flatten() {
        let p = entry.path();
        if let Ok(meta) = p.metadata() {
            if meta.is_file() && meta.len() > 0 {
                let fname = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if fname.ends_with(".ldb") || fname.ends_with(".log") || fname.starts_with("manifest-") {
                    has_data = true;
                    break;
                }
            }
        }
    }
    has_data
}

fn copy_dir_flat(src: &Path, dst: &Path) -> bool {
    let Ok(entries) = fs::read_dir(src) else { return false };
    if fs::create_dir_all(dst).is_err() {
        return false;
    }
    let mut copied_any = false;
    for entry in entries.flatten() {
        let sp = entry.path();
        let dp = dst.join(entry.file_name());
        if sp.is_file() {
            let fname = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if fname == "lock" {
                continue;
            }
            if fs::copy(&sp, &dp).is_ok() {
                copied_any = true;
            }
        }
    }
    copied_any
}

fn sync_erp_indexeddb_for_profile(profile_path: &Path, user_tag: &str, browser_tag: &str, erp_hosts: &[String]) {
    let idb_root = profile_path.join("IndexedDB");
    let profile_name = profile_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "Default".to_string());
    let safe_slot: String = format!("{}__{}__{}", user_tag, browser_tag, profile_name)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let vault_root = data_dir().join("erp-vault").join(safe_slot);

    for host in erp_hosts {
        let clean_h = host.trim().trim_start_matches("www.").to_ascii_lowercase();
        if clean_h.is_empty() || clean_h.contains(':') || clean_h.contains('/') {
            continue;
        }
        let folder_name = format!("https_{}_0.indexeddb.leveldb", clean_h);
        let live_dir = idb_root.join(&folder_name);
        let backup_dir = vault_root.join(&folder_name);

        if dir_has_leveldb_payload(&live_dir) {
            let tmp_dir = vault_root.join(format!("{}.tmp", folder_name));
            let _ = fs::remove_dir_all(&tmp_dir);
            if copy_dir_flat(&live_dir, &tmp_dir) {
                let _ = fs::remove_dir_all(&backup_dir);
                let _ = fs::rename(&tmp_dir, &backup_dir);
            }
        } else if dir_has_leveldb_payload(&backup_dir) {
            let _ = copy_dir_flat(&backup_dir, &live_dir);
        }
    }
}

/// Snapshots and self-heals the company ERP IndexedDB (`ElkhawagaDeviceDB`) across all
/// local user profiles whenever Chrome or Edge is closed so accidental browser clears recover.
pub fn protect_erp_browser_vault_if_closed() {
    if is_admin_mode() {
        return;
    }
    let mut erp_hosts = read_config().erp_domains;
    if !erp_hosts.iter().any(|d| d.eq_ignore_ascii_case(DEFAULT_ERP_DOMAIN)) {
        erp_hosts.push(DEFAULT_ERP_DOMAIN.to_string());
    }
    const BROWSERS: [(&str, &str, &str); 2] = [
        ("chrome.exe", "chrome", r"Google\Chrome\User Data"),
        ("msedge.exe", "edge", r"Microsoft\Edge\User Data"),
    ];
    let user_dirs = all_user_local_appdata_dirs();
    for (exe, tag, rel_dir) in BROWSERS {
        if is_process_running(exe) {
            continue;
        }
        for (uname, local_app_data) in &user_dirs {
            let user_data = local_app_data.join(rel_dir);
            let Ok(entries) = fs::read_dir(&user_data) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name_str = entry.file_name().to_string_lossy().to_string();
                if name_str != "Default" && !name_str.starts_with("Profile ") {
                    continue;
                }
                sync_erp_indexeddb_for_profile(&path, uname, tag, &erp_hosts);
            }
        }
    }
}

/// Removes local Chrome/Edge browsing history, Omnibox predictors, bookmarks, caches,
/// open sessions/tabs, and saved passwords once the browser process has closed naturally,
/// while preserving persistent cookies, LocalStorage, and IndexedDB device tokens
/// (`elkhawaga_did`, `elkhawaga_device_token`, `ElkhawagaDeviceDB`) for company systems.
pub fn wipe_browser_data_if_closed(_force_close_once: bool) {
    if is_admin_mode() {
        return;
    }
    let user_dirs = all_user_local_appdata_dirs();
    if user_dirs.is_empty() {
        return;
    }
    let mut erp_hosts = read_config().erp_domains;
    if !erp_hosts.iter().any(|d| d.eq_ignore_ascii_case(DEFAULT_ERP_DOMAIN)) {
        erp_hosts.push(DEFAULT_ERP_DOMAIN.to_string());
    }
    const BROWSERS: [(&str, &str, &str); 2] = [
        ("chrome.exe", "chrome", r"Google\Chrome\User Data"),
        ("msedge.exe", "edge", r"Microsoft\Edge\User Data"),
    ];
    const TRACE_FILES: &[&str] = &[
        "History",
        "History-journal",
        "History-wal",
        "History-shm",
        "History Provider Cache",
        "HistoryEmbeddings",
        "HistoryEmbeddings-journal",
        "HistoryClustersCache",
        "Visited Links",
        "Top Sites",
        "Top Sites-journal",
        "Top Sites-wal",
        "Shortcuts",
        "Shortcuts-journal",
        "Shortcuts-wal",
        "Network Action Predictor",
        "Network Action Predictor-journal",
        "Network Action Predictor-wal",
        "WebAssistDatabase",
        "WebAssistDatabase-journal",
        "Favicons",
        "Favicons-journal",
        "Favicons-wal",
        "Bookmarks",
        "Bookmarks.bak",
        "AccountBookmarks",
        "AccountBookmarks.bak",
        "EncryptedAccountBookmarks2",
        "BookmarkMergedSurfaceOrdering",
        "Login Data",
        "Login Data-journal",
        "Login Data-wal",
        "Login Data For Account",
        "Login Data For Account-journal",
        "Login Data For Account-wal",
        "Web Data",
        "Web Data-journal",
        "Web Data-wal",
        "Account Web Data",
        "Account Web Data-journal",
        "Account Web Data-wal",
        "Current Session",
        "Current Tabs",
        "Last Session",
        "Last Tabs",
        "Media History",
        "Media History-journal",
        "DownloadMetadata",
        "DIPS",
        "DIPS-wal",
    ];
    const TRACE_DIRS: &[&str] = &[
        "Sync Data",
        "Accounts",
        "shared_proto_db",
        "Segmentation Platform",
        "Collaboration",
        "DataSharing",
        "chrome_cart_db",
        "commerce_subscription_db",
        "discounts_db",
        "discount_infos_db",
        "parcel_tracking_db",
        "optimization_guide_hint_cache_store",
        "Sessions",
        "Sessions_Encrypted",
        "Session Storage",
        "EdgeSessions",
        "EdgeJourneys",
        "Collections",
        "Workspaces",
        "JumpListIcons",
        "JumpListIconsOld",
        "JumpListIconsMostVisited",
        "JumpListIconsRecentClosed",
        "Cache",
        "Code Cache",
        "GPUCache",
    ];

    for (exe, tag, rel_dir) in BROWSERS {
        let running = is_process_running(exe);
        for (uname, local_app_data) in &user_dirs {
            let user_data = local_app_data.join(rel_dir);
            let Ok(entries) = fs::read_dir(&user_data) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let is_profile = name_str == "Default"
                    || name_str.starts_with("Profile ")
                    || (name_str != "System Profile"
                        && (path.join("Preferences").is_file() || path.join("Bookmarks").is_file()));
                if !is_profile {
                    continue;
                }
                // Even if browser is currently open on update, empty out Bookmarks JSON files
                // so they cannot survive on disk; full SQLite/LevelDB wipe runs as soon as it closes.
                if running {
                    write_empty_chromium_bookmarks(&path);
                    continue;
                }
                sync_erp_indexeddb_for_profile(&path, uname, tag, &erp_hosts);
                scrub_profile_ntp_preferences(&path);
                for f in TRACE_FILES {
                    let _ = fs::remove_file(path.join(f));
                }
                let _ = fs::remove_file(path.join("DIPS-wal"));
                for d in TRACE_DIRS {
                    let _ = fs::remove_dir_all(path.join(d));
                }
                write_empty_chromium_bookmarks(&path);
                if let Ok(idb_entries) = fs::read_dir(path.join("IndexedDB")) {
                    for idb in idb_entries.flatten() {
                        let iname = idb.file_name().to_string_lossy().to_ascii_lowercase();
                        if iname.contains("whatsapp") {
                            let _ = fs::remove_dir_all(idb.path());
                        }
                    }
                }
            }
        }
    }
}

/// Disabled: blocked-site notifications are rendered directly inside the browser tab
/// by the proxy (HTTP & HTTPS) instead of popping a Win32 taskbar message box.
#[allow(dead_code)]
pub fn show_blocked_site_notification(_host: &str) {}

pub fn format_file_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", (bytes as f64) / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", (bytes as f64) / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

pub fn classify_dlp_file(name: &str, _size_bytes: u64) -> (&'static str, &'static str, String) {
    let ext = Path::new(name.trim())
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let cat_sev = match ext.as_str() {
        "xlsx" | "xls" | "csv" | "docx" | "doc" | "pdf" | "pptx" | "ppt" | "txt" | "rtf"
        | "sql" | "db" | "mdb" | "accdb" | "json" | "xml" => ("مستند/بيانات عمل", "critical"),
        "zip" | "rar" | "7z" | "tar" | "gz" | "iso" => ("ملف مضغوط/أرشيف", "critical"),
        "jpg" | "jpeg" | "png" | "webp" | "gif" | "bmp" => ("صورة", "medium"),
        "mp4" | "mov" | "avi" | "mkv" | "mp3" | "wav" | "ogg" => ("ملف وسائط (فيديو/صوت)", "high"),
        _ => ("ملف مرفق", "high"),
    };
    (cat_sev.0, cat_sev.1, ext)
}

/// Scans all extension subkeys under Windows File Dialog `ComDlg32\OpenSavePidlMRU`
/// returning `(subkey_name, last_write_filetime, resolved_file_path)`.
#[cfg(windows)]
pub fn scan_comdlg_mru_entries() -> Vec<(String, u64, PathBuf)> {
    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: *mut std::ffi::c_void,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn RegEnumKeyExW(
            hKey: *mut std::ffi::c_void,
            dwIndex: u32,
            lpName: *mut u16,
            lpcchName: *mut u32,
            lpReserved: *mut u32,
            lpClass: *mut u16,
            lpcchClass: *mut u32,
            lpftLastWriteTime: *mut FileTime,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: *mut std::ffi::c_void,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: *mut std::ffi::c_void) -> i32;
    }
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetPathFromIDListW(pidl: *const std::ffi::c_void, pszPath: *mut u16) -> i32;
    }

    const HKEY_CURRENT_USER: *mut std::ffi::c_void = (-2147483647i32 as isize) as *mut _;
    const KEY_READ: u32 = 0x20019;

    unsafe fn reg_query_bytes(hkey: *mut std::ffi::c_void, val_name: &str) -> Option<Vec<u8>> {
        let wname: Vec<u16> = val_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut size: u32 = 0;
        if RegQueryValueExW(
            hkey,
            wname.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        ) != 0
            || size == 0
            || size > 64 * 1024
        {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if RegQueryValueExW(
            hkey,
            wname.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut size,
        ) != 0
        {
            return None;
        }
        buf.truncate(size as usize);
        Some(buf)
    }

    let root_subkey: Vec<u16> =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

    let mut out_entries = Vec::new();
    unsafe {
        let mut root_key: *mut std::ffi::c_void = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, root_subkey.as_ptr(), 0, KEY_READ, &mut root_key) != 0
            || root_key.is_null()
        {
            return out_entries;
        }
        for dw_index in 0..128u32 {
            let mut name_buf = [0u16; 128];
            let mut name_len = name_buf.len() as u32;
            let mut ft = FileTime::default();
            if RegEnumKeyExW(
                root_key,
                dw_index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut ft,
            ) != 0
            {
                break;
            }
            let sub_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            if sub_name.is_empty() {
                continue;
            }
            let write_ts = ((ft.dw_high_date_time as u64) << 32) | (ft.dw_low_date_time as u64);
            let sub_w: Vec<u16> = sub_name.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sub_key: *mut std::ffi::c_void = std::ptr::null_mut();
            if RegOpenKeyExW(root_key, sub_w.as_ptr(), 0, KEY_READ, &mut sub_key) != 0
                || sub_key.is_null()
            {
                continue;
            }
            let resolved = reg_query_bytes(sub_key, "MRUListEx").and_then(|bytes| {
                if bytes.len() < 4 {
                    return None;
                }
                let idx = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if idx == u32::MAX {
                    return None;
                }
                let pidl = reg_query_bytes(sub_key, &idx.to_string())?;
                if pidl.len() < 4 {
                    return None;
                }
                let mut path_buf = [0u16; 1024];
                if SHGetPathFromIDListW(pidl.as_ptr() as *const _, path_buf.as_mut_ptr()) == 0 {
                    return None;
                }
                let end = path_buf.iter().position(|&c| c == 0).unwrap_or(path_buf.len());
                let s = String::from_utf16_lossy(&path_buf[..end]).trim().to_string();
                let pb = PathBuf::from(&s);
                if !s.is_empty() && pb.is_file() {
                    Some(pb)
                } else {
                    None
                }
            });
            let _ = RegCloseKey(sub_key);
            if let Some(pb) = resolved {
                out_entries.push((sub_name, write_ts, pb));
            }
        }
        let _ = RegCloseKey(root_key);
    }
    out_entries
}

#[cfg(not(windows))]
pub fn scan_comdlg_mru_entries() -> Vec<(String, u64, PathBuf)> {
    Vec::new()
}

/// Reads the most recently selected file path across all ComDlg32 MRU extension buckets.
#[cfg(windows)]
pub fn read_latest_comdlg_mru_file() -> Option<PathBuf> {
    scan_comdlg_mru_entries()
        .into_iter()
        .max_by_key(|(_, wt, _)| *wt)
        .map(|(_, _, p)| p)
}

#[cfg(not(windows))]
pub fn read_latest_comdlg_mru_file() -> Option<PathBuf> {
    None
}

/// Reads file paths currently stored in the Windows clipboard (CF_HDROP).
#[cfg(windows)]
pub fn read_clipboard_files() -> Vec<PathBuf> {
    #[link(name = "user32")]
    extern "system" {
        fn IsClipboardFormatAvailable(format: u32) -> i32;
        fn OpenClipboard(hWndNewOwner: *mut std::ffi::c_void) -> i32;
        fn GetClipboardData(uFormat: u32) -> *mut std::ffi::c_void;
        fn CloseClipboard() -> i32;
    }
    #[link(name = "shell32")]
    extern "system" {
        fn DragQueryFileW(
            hDrop: *mut std::ffi::c_void,
            iFile: u32,
            lpszFile: *mut u16,
            cch: u32,
        ) -> u32;
    }

    const CF_HDROP: u32 = 15;
    unsafe {
        if IsClipboardFormatAvailable(CF_HDROP) == 0 {
            return Vec::new();
        }
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return Vec::new();
        }
        struct ClipGuard;
        impl Drop for ClipGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseClipboard();
                }
            }
        }
        let _guard = ClipGuard;

        let hdrop = GetClipboardData(CF_HDROP);
        if hdrop.is_null() {
            return Vec::new();
        }
        let count = DragQueryFileW(hdrop, u32::MAX, std::ptr::null_mut(), 0).min(15);
        let mut out = Vec::new();
        for i in 0..count {
            let mut buf = [0u16; 1024];
            let n = DragQueryFileW(hdrop, i, buf.as_mut_ptr(), buf.len() as u32);
            if n > 0 {
                let pb = PathBuf::from(String::from_utf16_lossy(&buf[..n as usize]));
                if pb.is_file() {
                    out.push(pb);
                }
            }
        }
        out
    }
}

#[cfg(not(windows))]
pub fn read_clipboard_files() -> Vec<PathBuf> {
    Vec::new()
}

/// Returns the Windows clipboard sequence counter so changes (including Ctrl+C screenshots)
/// can be detected without polling clipboard contents aggressively.
#[cfg(windows)]
pub fn clipboard_sequence_number() -> u32 {
    #[link(name = "user32")]
    extern "system" {
        fn GetClipboardSequenceNumber() -> u32;
    }
    unsafe { GetClipboardSequenceNumber() }
}

#[cfg(not(windows))]
pub fn clipboard_sequence_number() -> u32 {
    0
}

/// Copies any bitmap currently on the Windows clipboard (`CF_DIB`, excluding `CF_HDROP` files)
/// as a lossless PNG into `dest_dir` so Ctrl+V / Win+Shift+S pasted screenshots are archived.
#[cfg(windows)]
pub fn stage_clipboard_dib_png(dest_dir: &Path) -> Option<PathBuf> {
    #[link(name = "user32")]
    extern "system" {
        fn IsClipboardFormatAvailable(format: u32) -> i32;
        fn OpenClipboard(hWndNewOwner: *mut std::ffi::c_void) -> i32;
        fn GetClipboardData(uFormat: u32) -> *mut std::ffi::c_void;
        fn CloseClipboard() -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalLock(hMem: *mut std::ffi::c_void) -> *const u8;
        fn GlobalUnlock(hMem: *mut std::ffi::c_void) -> i32;
        fn GlobalSize(hMem: *mut std::ffi::c_void) -> usize;
    }

    const CF_DIB: u32 = 8;
    const CF_HDROP: u32 = 15;
    const MAX_DIB_BYTES: usize = 48 * 1024 * 1024;

    let dib: Vec<u8> = unsafe {
        if IsClipboardFormatAvailable(CF_HDROP) != 0 || IsClipboardFormatAvailable(CF_DIB) == 0 {
            return None;
        }
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        struct ClipGuard;
        impl Drop for ClipGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseClipboard();
                }
            }
        }
        let _guard = ClipGuard;

        let hmem = GetClipboardData(CF_DIB);
        if hmem.is_null() {
            return None;
        }
        let sz = GlobalSize(hmem);
        if sz < 40 || sz > MAX_DIB_BYTES {
            return None;
        }
        let ptr = GlobalLock(hmem);
        if ptr.is_null() {
            return None;
        }
        let copied = std::slice::from_raw_parts(ptr, sz).to_vec();
        let _ = GlobalUnlock(hmem);
        copied
    };

    if dib.len() < 40 {
        return None;
    }
    let header_sz = u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]) as usize;
    let width = i32::from_le_bytes([dib[4], dib[5], dib[6], dib[7]]);
    let height_signed = i32::from_le_bytes([dib[8], dib[9], dib[10], dib[11]]);
    let bpp = u16::from_le_bytes([dib[14], dib[15]]);
    let compression = u32::from_le_bytes([dib[16], dib[17], dib[18], dib[19]]);
    let clr_used = u32::from_le_bytes([dib[32], dib[33], dib[34], dib[35]]) as usize;
    if header_sz < 40
        || header_sz > 256
        || width <= 0
        || height_signed == 0
        || (compression != 0 && compression != 3)
        || (bpp != 24 && bpp != 32)
    {
        return None;
    }
    let mask_extra = if header_sz == 40 && compression == 3 { 12usize } else { 0usize };
    let px_offset = header_sz + mask_extra + clr_used.saturating_mul(4);
    let src_w = width as usize;
    let src_h = height_signed.unsigned_abs() as usize;
    let top_down = height_signed < 0;
    let row_stride = ((src_w * (bpp as usize) + 31) / 32) * 4;
    if px_offset + row_stride.saturating_mul(src_h) > dib.len() {
        return None;
    }

    let max_w = 2560usize;
    let (dst_w, dst_h) = if src_w > max_w {
        (max_w, ((src_h * max_w) / src_w).max(1))
    } else {
        (src_w, src_h)
    };
    let mut bgra = vec![0u8; dst_w * dst_h * 4];
    for dy in 0..dst_h {
        let sy = (dy * src_h) / dst_h;
        let bmp_row = if top_down { sy } else { src_h - 1 - sy };
        let row_start = px_offset + bmp_row * row_stride;
        for dx in 0..dst_w {
            let sx = (dx * src_w) / dst_w;
            let p = row_start + sx * ((bpp as usize) / 8);
            let o = (dy * dst_w + dx) * 4;
            bgra[o] = dib[p];
            bgra[o + 1] = dib[p + 1];
            bgra[o + 2] = dib[p + 2];
            bgra[o + 3] = 255;
        }
    }
    let b64 = encode_bgra_png_base64(&bgra, dst_w as u32, dst_h as u32)?;
    let png_bytes = base64_decode(&b64)?;
    let _ = fs::create_dir_all(dest_dir);
    let out_path = dest_dir.join(format!("لقطة_حافظة_{}.png", now_ms()));
    fs::write(&out_path, &png_bytes).ok()?;
    Some(out_path)
}

#[cfg(not(windows))]
pub fn stage_clipboard_dib_png(_dest_dir: &Path) -> Option<PathBuf> {
    None
}

#[derive(Clone, Debug, Default)]
pub struct UploadWindowState {
    pub browser_open: bool,
    pub wa_open: bool,
    pub fg_is_browser: bool,
    pub fg_is_wa: bool,
    pub browser_open_dialog: bool,
    pub any_open_dialog: bool,
    pub save_dialog: bool,
    pub best_title: String,
    pub wa_hwnd: isize,
    pub browser_hwnd: isize,
}

#[cfg(windows)]
fn is_browser_process_exe(exe_name: &str) -> bool {
    matches!(
        exe_name,
        "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "opera.exe"
            | "vivaldi.exe"
            | "whatsapp.exe"
            | "whatsapp.root.exe"
            | "telegram.exe"
    )
}

#[cfg(windows)]
fn hwnd_process_basename(hwnd: *mut std::ffi::c_void) -> String {
    #[link(name = "user32")]
    extern "system" {
        fn GetWindowThreadProcessId(hWnd: *mut std::ffi::c_void, lpdwProcessId: *mut u32) -> u32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> *mut std::ffi::c_void;
        fn QueryFullProcessImageNameW(
            hProcess: *mut std::ffi::c_void,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    if hwnd.is_null() {
        return String::new();
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    unsafe {
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == 0 {
            return String::new();
        }
        let hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if hproc.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 260];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(hproc, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(hproc);
        if ok == 0 || len == 0 {
            return String::new();
        }
        let full = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();
        Path::new(&full)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    }
}

/// Inspects visible top-level windows to detect browsers, WhatsApp Web/Desktop,
/// browser-owned File Open upload dialogs (excluding Save As download dialogs and
/// unrelated local apps like Excel/Word), foreground state, and window handles.
#[cfg(windows)]
pub fn inspect_upload_windows_ext() -> UploadWindowState {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetClassNameW, GetWindowTextW};

    #[link(name = "user32")]
    extern "system" {
        fn EnumWindows(
            lpEnumFunc: unsafe extern "system" fn(*mut std::ffi::c_void, isize) -> i32,
            lParam: isize,
        ) -> i32;
        fn IsWindowVisible(hWnd: *mut std::ffi::c_void) -> i32;
        fn IsIconic(hWnd: *mut std::ffi::c_void) -> i32;
        fn GetForegroundWindow() -> *mut std::ffi::c_void;
        fn GetWindow(hWnd: *mut std::ffi::c_void, uCmd: u32) -> *mut std::ffi::c_void;
    }

    struct WinState {
        fg_hwnd: *mut std::ffi::c_void,
        out: UploadWindowState,
        fg_browser_title: String,
        wa_title: String,
        any_browser_title: String,
    }

    unsafe extern "system" fn enum_cb(hwnd: *mut std::ffi::c_void, lparam: isize) -> i32 {
        if IsWindowVisible(hwnd) == 0 {
            return 1;
        }
        let st = &mut *(lparam as *mut WinState);
        let mut cls_buf = [0u16; 128];
        let cls_len = GetClassNameW(hwnd as _, cls_buf.as_mut_ptr(), cls_buf.len() as i32);
        let cls = if cls_len > 0 {
            String::from_utf16_lossy(&cls_buf[..cls_len as usize])
        } else {
            String::new()
        };
        let mut title_buf = [0u16; 256];
        let t_len = GetWindowTextW(hwnd as _, title_buf.as_mut_ptr(), title_buf.len() as i32);
        if t_len <= 0 {
            return 1;
        }
        let title = String::from_utf16_lossy(&title_buf[..t_len as usize]);
        let title_lc = title.to_lowercase();
        let proc_name = hwnd_process_basename(hwnd);
        let proc_is_browser = is_browser_process_exe(&proc_name);
        let is_wa = (title_lc.contains("whatsapp") || title.contains("واتساب") || proc_name.starts_with("whatsapp"))
            && !title_lc.contains("it elkhawga");
        let is_browser = (proc_is_browser && !title_lc.contains("it elkhawga"))
            || (cls == "Chrome_WidgetWin_1" && !title_lc.contains("it elkhawga"))
            || cls == "MozillaWindowClass"
            || is_wa
            || ["chrome", "edge", "firefox", "brave", "opera", "telegram"]
                .iter()
                .any(|b| title_lc.contains(b));

        let not_minimized = IsIconic(hwnd) == 0;
        if is_wa {
            st.out.wa_open = true;
            if hwnd == st.fg_hwnd {
                st.out.fg_is_wa = true;
                st.out.wa_hwnd = hwnd as isize;
            } else if st.out.wa_hwnd == 0 && not_minimized {
                st.out.wa_hwnd = hwnd as isize;
            }
            if st.wa_title.is_empty() {
                st.wa_title = title.clone();
            }
        }
        if is_browser {
            st.out.browser_open = true;
            if hwnd == st.fg_hwnd {
                st.out.fg_is_browser = true;
                st.out.browser_hwnd = hwnd as isize;
                if st.fg_browser_title.is_empty() {
                    st.fg_browser_title = title.clone();
                }
            } else if st.out.browser_hwnd == 0 && not_minimized {
                st.out.browser_hwnd = hwnd as isize;
            }
            if st.any_browser_title.is_empty() {
                st.any_browser_title = title.clone();
            }
        }
        if cls == "#32770" {
            let is_save = ["save", "حفظ", "download", "تنزيل", "export", "تصدير", "print", "طباعة"]
                .iter()
                .any(|w| title_lc.contains(w) || title.contains(w));
            if is_save {
                st.out.save_dialog = true;
            } else if title_lc == "open"
                || title == "فتح"
                || ["open", "choose", "select", "upload", "attach"]
                    .iter()
                    .any(|w| title_lc.contains(w))
                || ["فتح", "اختيار", "اختر", "إرفاق", "تحميل"]
                    .iter()
                    .any(|w| title.contains(w))
            {
                st.out.any_open_dialog = true;
                const GW_OWNER: u32 = 4;
                let owner = GetWindow(hwnd, GW_OWNER);
                let owner_proc = hwnd_process_basename(owner);
                let owner_is_browser = if !owner.is_null() {
                    is_browser_process_exe(&owner_proc)
                } else {
                    false
                };
                if proc_is_browser || owner_is_browser {
                    st.out.browser_open_dialog = true;
                }
            }
        }
        1
    }

    let fg = unsafe { GetForegroundWindow() };
    let mut st = WinState {
        fg_hwnd: fg,
        out: UploadWindowState::default(),
        fg_browser_title: String::new(),
        wa_title: String::new(),
        any_browser_title: String::new(),
    };
    unsafe {
        let _ = EnumWindows(enum_cb, (&mut st as *mut WinState) as isize);
    }
    if st.out.browser_hwnd == 0 && st.out.wa_hwnd != 0 {
        st.out.browser_hwnd = st.out.wa_hwnd;
    }
    st.out.best_title = if !st.fg_browser_title.is_empty() {
        st.fg_browser_title
    } else if !st.wa_title.is_empty() {
        st.wa_title
    } else {
        st.any_browser_title
    };
    st.out
}

#[cfg(not(windows))]
pub fn inspect_upload_windows_ext() -> UploadWindowState {
    UploadWindowState::default()
}

pub fn inspect_upload_windows() -> (bool, bool, bool, bool, String) {
    let s = inspect_upload_windows_ext();
    (s.browser_open, s.wa_open, s.browser_open_dialog, s.save_dialog, s.best_title)
}

#[allow(dead_code)]
pub fn inspect_whatsapp_window_state() -> (bool, bool, String) {
    let s = inspect_upload_windows_ext();
    (s.wa_open, s.browser_open_dialog, s.best_title)
}

fn ensure_upload_context_script() -> PathBuf {
    let p = data_dir().join("upload-context.ps1");
    let script = r#"param([int]$NeedOcr = 0)
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$res = @{
  recipient = ''
  phone = ''
  title = ''
  site = ''
  in_preview = $false
  explorer = @()
}

try {
  $sh = New-Object -ComObject Shell.Application
  foreach ($w in $sh.Windows()) {
    try {
      $sel = $w.Document.SelectedItems()
      foreach ($item in $sel) {
        $fp = [string]$item.Path
        if ($fp -and (Test-Path -LiteralPath $fp -PathType Leaf)) {
          if ($res.explorer.Count -lt 10) { $res.explorer += $fp }
        }
      }
    } catch {}
  }
} catch {}

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
public static class WinProbe {
  public struct RECT { public int Left, Top, Right, Bottom; }
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr hWnd, StringBuilder sb, int max);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hParent, EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
  [DllImport("oleacc.dll")] public static extern int AccessibleObjectFromWindow(IntPtr hwnd, uint dwId, ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ppv);

  public static void WakeChromium(IntPtr topHwnd) {
    if (topHwnd == IntPtr.Zero) return;
    Guid iid = new Guid("618736e0-3c3d-11cf-810c-00aa00389b71");
    object obj = null;
    try { AccessibleObjectFromWindow(topHwnd, 0xFFFFFFFCu, ref iid, out obj); } catch {}
    EnumChildWindows(topHwnd, (ch, lp) => {
      var cb = new StringBuilder(128);
      GetClassName(ch, cb, cb.Capacity);
      if (cb.ToString().Contains("Chrome_RenderWidgetHostHWND")) {
        object o2 = null;
        try { AccessibleObjectFromWindow(ch, 0xFFFFFFFCu, ref iid, out o2); } catch {}
      }
      return true;
    }, IntPtr.Zero);
  }

  public static Bitmap CaptureWindowBitmap(IntPtr hwnd) {
    RECT rc;
    if (!GetWindowRect(hwnd, out rc)) return null;
    int w = rc.Right - rc.Left;
    int h = rc.Bottom - rc.Top;
    if (w < 320 || h < 220) return null;
    var bmp = new Bitmap(w, h);
    using (var g = Graphics.FromImage(bmp)) {
      IntPtr hdc = g.GetHdc();
      bool ok = PrintWindow(hwnd, hdc, 2);
      g.ReleaseHdc(hdc);
      if (!ok) {
        try { g.CopyFromScreen(rc.Left, rc.Top, 0, 0, bmp.Size); } catch {}
      }
    }
    return bmp;
  }

  public static List<Tuple<IntPtr,string,string>> ListVisible() {
    SetProcessDPIAware();
    var list = new List<Tuple<IntPtr,string,string>>();
    EnumWindows((h, lp) => {
      if (!IsWindowVisible(h) || IsIconic(h)) return true;
      var sb = new StringBuilder(512);
      GetWindowText(h, sb, sb.Capacity);
      var t = sb.ToString();
      if (string.IsNullOrWhiteSpace(t)) return true;
      var cb = new StringBuilder(128);
      GetClassName(h, cb, cb.Capacity);
      list.Add(Tuple.Create(h, cb.ToString(), t));
      return true;
    }, IntPtr.Zero);
    return list;
  }
}
"@ -ReferencedAssemblies System.Drawing -ErrorAction SilentlyContinue

function Extract-PhoneFromText([string]$txt) {
  if ([string]::IsNullOrWhiteSpace($txt)) { return '' }
  $m = [regex]::Match($txt, '(\+\d[\d\s\-\(\)]{7,16}\d)')
  if (-not $m.Success) {
    $m = [regex]::Match($txt, '(?:\b|^)(01[0125]\d{8}|201[0125]\d{8}|9665\d{8}|9715\d{8})(?:\b|$)')
  }
  if (-not $m.Success) { return '' }
  $d = ($m.Value -replace '[^\d+]', '')
  $digits = ($d -replace '\+', '')
  if ($digits.Length -lt 9 -or $digits.Length -gt 15) { return '' }
  if ($digits -match '^(010|011|012|015)\d{8}$') { return ('+2' + $digits) }
  if ($d.StartsWith('+')) { return $d }
  return ('+' + $digits)
}

$noiseRx = '^(HTML5|Web Area|RootWebArea|WhatsApp|WhatsApp Web|واتساب|web\.whatsapp\.com|New tab|New Tab|تبويب جديد|علامة تبويب جديدة|Google Chrome|Microsoft Edge|Brave|Open|فتح|Choose File|اختر ملف|بحث|Search|Search or start new chat|البحث أو بدء دردشة جديدة|Chats|دردشات|الكل|All|غير مقروءة|Unread|المفضلة|Favorites|المجموعات|Groups|Status|الحالة|Channels|القنوات|Communities|المجتمعات|Settings|الإعدادات|Profile|الملف الشخصي|Attach|إرفاق|Menu|القائمة|online|متصل|متصل الآن|typing.*|يكتب.*|recording.*|يسجل.*|last seen.*|آخر ظهور.*|click here.*|اضغط هنا.*|انقر هنا.*|Get WhatsApp.*|تنزيل واتساب.*|End-to-end encrypted|تشفير تام.*|Select chats|تحديد الدردشات|Meta AI|Archive|الأرشيف|Locked chats|Archived|Send|إرسال|Close|إغلاق|Cancel|إلغاء|Type a message.*|اكتب رسالة.*|Add a caption.*|إضافة شرح.*|اكتب تعليق.*|موقع محظور.*)$'
$previewHintRx = '^(Add a caption.*|إضافة شرح.*|اكتب تعليق.*|معاينة.*| Crop | اقتصاص )$'

$fg = [WinProbe]::GetForegroundWindow()
$wins = [WinProbe]::ListVisible()
$targetHwnd = [IntPtr]::Zero
$targetTitle = ''
$isWa = $false

foreach ($w in $wins) {
  $t = $w.Item3; $tl = $t.ToLowerInvariant()
  if ($w.Item1 -eq $fg -and ($tl -match 'whatsapp|واتساب') -and $tl -notmatch 'it elkhawga') {
    $targetHwnd = $w.Item1; $targetTitle = $t; $isWa = $true; break
  }
}
if ($targetHwnd -eq [IntPtr]::Zero) {
  foreach ($w in $wins) {
    $t = $w.Item3; $tl = $t.ToLowerInvariant()
    if (($tl -match 'whatsapp|واتساب') -and $tl -notmatch 'it elkhawga') {
      $targetHwnd = $w.Item1; $targetTitle = $t; $isWa = $true; break
    }
  }
}
if ($targetHwnd -eq [IntPtr]::Zero) {
  foreach ($w in $wins) {
    $t = $w.Item3; $tl = $t.ToLowerInvariant()
    if ($w.Item1 -eq $fg -and (($w.Item2 -eq 'Chrome_WidgetWin_1' -or $w.Item2 -eq 'MozillaWindowClass' -or $tl -match 'chrome|edge|firefox|brave|opera|telegram') -and $tl -notmatch 'it elkhawga')) {
      $targetHwnd = $w.Item1; $targetTitle = $t; break
    }
  }
}
if ($targetHwnd -eq [IntPtr]::Zero) {
  foreach ($w in $wins) {
    $c = $w.Item2; $t = $w.Item3; $tl = $t.ToLowerInvariant()
    if (($c -eq 'Chrome_WidgetWin_1' -or $c -eq 'MozillaWindowClass' -or $tl -match 'chrome|edge|firefox|brave|opera|telegram') -and $tl -notmatch 'it elkhawga') {
      $targetHwnd = $w.Item1; $targetTitle = $t; break
    }
  }
}
$res.title = $targetTitle

$winRc = New-Object WinProbe+RECT
$hasRect = $false
if ($targetHwnd -ne [IntPtr]::Zero) {
  $hasRect = [WinProbe]::GetWindowRect($targetHwnd, [ref]$winRc)
  try {
    Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($targetHwnd)
    if ($root) {
      $edits = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)))
      for ($i = 0; $i -lt [Math]::Min($edits.Count, 10); $i++) {
        $vp = $null
        if ($edits[$i].TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
          $val = ([string]$vp.Current.Value).Trim()
          if ($val -match '^[a-z0-9.-]+\.[a-z]{2,}(/|$)' -or $val -match '^https?://') {
            $res.site = $val.Split('?')[0]
            if ($val -match 'web\.whatsapp\.com') { $isWa = $true }
            break
          }
        }
      }
      if ($isWa) {
        $docCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Document)
        $docs = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $docCond)
        if ($docs.Count -eq 0) {
          [WinProbe]::WakeChromium($targetHwnd)
          Start-Sleep -Milliseconds 120
          $docs = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $docCond)
        }
        $selCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.SelectionItemPattern]::IsSelectedProperty, $true)
        $selItems = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $selCond)
        foreach ($si in $selItems) {
          $nm = ([string]$si.Current.Name).Trim()
          if ($nm -and $nm.Length -le 120 -and $nm -notmatch $noiseRx) {
            $firstLine = ($nm -split "[\r\n]")[0].Trim()
            if ($firstLine -and $firstLine -notmatch $noiseRx) {
              $res.recipient = $firstLine
            }
            $ep = Extract-PhoneFromText $nm
            if ($ep) { $res.phone = $ep }
            break
          }
        }
        if ($docs.Count -gt 0 -and $hasRect) {
          $doc = $docs[0]
          $winW = [Math]::Max(1, ($winRc.Right - $winRc.Left))
          $cText = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
          $cBtn  = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
          $cHead = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Heading)
          $cLink = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Hyperlink)
          $cEdit = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
          $orCond = New-Object System.Windows.Automation.OrCondition($cText, $cBtn, $cHead, $cLink, $cEdit)
          $nodes = $doc.FindAll([System.Windows.Automation.TreeScope]::Descendants, $orCond)
          $limit = [Math]::Min($nodes.Count, 260)
          $headerCandidate = ''
          for ($i = 0; $i -lt $limit; $i++) {
            $el = $nodes[$i]
            $nm = ([string]$el.Current.Name).Trim()
            if (-not $nm -or $nm.Length -gt 120) { continue }
            if ($nm -match $previewHintRx) {
              $res.in_preview = $true
              continue
            }
            $rect = $el.Current.BoundingRectangle
            if ($rect.Width -gt ($winW * 0.85)) { continue }
            $inTopBand = ($rect.Top -ge ($winRc.Top + 62)) -and ($rect.Top -le ($winRc.Top + 195))
            $inPreviewBottom = ($rect.Top -ge ($winRc.Top + [int](($winRc.Bottom - $winRc.Top) * 0.72)))
            $ep = Extract-PhoneFromText $nm
            if ($ep -and (-not $res.phone) -and ($inTopBand -or $inPreviewBottom)) {
              $res.phone = $ep
            }
            if ($inTopBand -and (-not $headerCandidate) -and $nm.Length -ge 2 -and $nm -notmatch $noiseRx) {
              if ($nm -notmatch '^\d{1,2}:\d{2}(\s*(AM|PM|ص|م))?$' -and $nm -notmatch '^\d{1,4}$') {
                $headerCandidate = $nm
              }
            }
          }
          if ($headerCandidate) {
            $res.recipient = $headerCandidate
          }
        }
      }
    }
  } catch {}
}

if ($NeedOcr -eq 1 -and $isWa -and ([string]::IsNullOrWhiteSpace($res.recipient) -or [string]::IsNullOrWhiteSpace($res.phone)) -and $targetHwnd -ne [IntPtr]::Zero -and $hasRect) {
  try {
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    [Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
    [Windows.Globalization.Language,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
    [Windows.Graphics.Imaging.BitmapDecoder,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
    [Windows.Graphics.Imaging.SoftwareBitmap,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
    [Windows.Media.Ocr.OcrResult,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
    [Windows.Storage.Streams.IRandomAccessStream,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    $fullBmp = [WinProbe]::CaptureWindowBitmap($targetHwnd)
    if (-not $fullBmp) {
      $ww0 = $winRc.Right - $winRc.Left; $wh0 = $winRc.Bottom - $winRc.Top
      if ($ww0 -gt 350 -and $wh0 -gt 240) {
        $fullBmp = New-Object System.Drawing.Bitmap($ww0, $wh0)
        $g0 = [System.Drawing.Graphics]::FromImage($fullBmp)
        $g0.CopyFromScreen($winRc.Left, $winRc.Top, 0, 0, $fullBmp.Size)
        $g0.Dispose()
      }
    }
    if ($fullBmp) {
      $ww = $fullBmp.Width; $wh = $fullBmp.Height
      $regions = @(
        @([int]($ww * 0.08), 68, [Math]::Max(240, [int]($ww * 0.72)), 138),
        @([int]($ww * 0.08), [int]($wh * 0.72), [Math]::Max(240, [int]($ww * 0.78)), [Math]::Max(90, [int]($wh * 0.24)))
      )
      foreach ($reg in $regions) {
        $rx = [Math]::Max(0, [Math]::Min($ww - 20, $reg[0]))
        $ry = [Math]::Max(0, [Math]::Min($wh - 20, $reg[1]))
        $rw = [Math]::Min($ww - $rx, $reg[2])
        $rh = [Math]::Min($wh - $ry, $reg[3])
        if ($rw -lt 120 -or $rh -lt 40) { continue }
        $crop = $fullBmp.Clone((New-Object System.Drawing.Rectangle($rx, $ry, $rw, $rh)), $fullBmp.PixelFormat)
        $ms = New-Object System.IO.MemoryStream
        $crop.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $crop.Dispose()
        $ms.Position = 0
        $ras = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($ms)
        $dec = $asTask.MakeGenericMethod([Windows.Graphics.Imaging.BitmapDecoder]).Invoke($null, @([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($ras))).GetAwaiter().GetResult()
        $sb = $asTask.MakeGenericMethod([Windows.Graphics.Imaging.SoftwareBitmap]).Invoke($null, @($dec.GetSoftwareBitmapAsync())).GetAwaiter().GetResult()
        foreach ($langTag in @('ar-SA', 'en-US')) {
          $eng = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new($langTag))
          if ($eng) {
            $ocrRes = $asTask.MakeGenericMethod([Windows.Media.Ocr.OcrResult]).Invoke($null, @($eng.RecognizeAsync($sb))).GetAwaiter().GetResult()
            if ($ocrRes -and $ocrRes.Lines.Count -gt 0) {
              foreach ($ln in $ocrRes.Lines) {
                $tx = ([string]$ln.Text).Trim()
                if (-not $tx -or $tx.Length -lt 2 -or $tx -match $noiseRx) { continue }
                if ($tx -match '^\d{1,2}:\d{2}(\s*(AM|PM|ص|م))?$') { continue }
                $ep = Extract-PhoneFromText $tx
                if ($ep -and (-not $res.phone)) { $res.phone = $ep }
                if (-not $res.recipient) { $res.recipient = $tx }
              }
            }
          }
          if ($res.recipient -and $res.phone) { break }
        }
        $ras.Dispose()
        $ms.Dispose()
        if ($res.recipient) { break }
      }
      $fullBmp.Dispose()
    }
  } catch {}
}

$res | ConvertTo-Json -Compress
"#;
    if fs::read_to_string(&p).ok().as_deref() != Some(script) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(&p, script);
    }
    p
}

#[cfg(windows)]
pub fn query_active_upload_context_ext(need_ocr: bool) -> (String, String, String, Vec<PathBuf>, bool) {
    let script_path = ensure_upload_context_script();
    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        &script_path.to_string_lossy(),
        "-NeedOcr",
        if need_ocr { "1" } else { "0" },
    ]);
    let Ok(out) = hidden(&mut cmd).output() else {
        return (String::new(), String::new(), String::new(), Vec::new(), false);
    };
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (String::new(), String::new(), String::new(), Vec::new(), false);
    };
    let recip = v["recipient"].as_str().unwrap_or("").trim().to_string();
    let mut phone = v["phone"].as_str().unwrap_or("").trim().to_string();
    if phone.is_empty() && !recip.is_empty() {
        phone = normalize_extracted_phone(&recip);
    }
    let site = v["site"].as_str().unwrap_or("").trim().to_string();
    let title = v["title"].as_str().unwrap_or("").trim().to_string();
    let site_or_title = if !site.is_empty() { site } else { title };
    let in_preview = v["in_preview"].as_bool().unwrap_or(false);
    let explorer = v["explorer"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(PathBuf::from)
                .filter(|p| p.is_file())
                .collect()
        })
        .unwrap_or_default();
    (recip, phone, site_or_title, explorer, in_preview)
}

/// Extracts active recipient name, phone number, site/title, and selected File Explorer items.
#[cfg(windows)]
pub fn query_active_upload_context(need_ocr: bool) -> (String, String, String, Vec<PathBuf>) {
    let (r, p, s, e, _) = query_active_upload_context_ext(need_ocr);
    (r, p, s, e)
}

#[cfg(not(windows))]
pub fn query_active_upload_context_ext(_need_ocr: bool) -> (String, String, String, Vec<PathBuf>, bool) {
    (String::new(), String::new(), String::new(), Vec::new(), false)
}

#[cfg(not(windows))]
pub fn query_active_upload_context(_need_ocr: bool) -> (String, String, String, Vec<PathBuf>) {
    (String::new(), String::new(), String::new(), Vec::new())
}

/// Fast Win32 check: returns true if the user's foreground window is File Explorer or Desktop
/// (used to stage selected files right before Drag & Drop into a browser/WhatsApp).
#[cfg(windows)]
pub fn is_explorer_foreground() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::GetClassNameW;
    #[link(name = "user32")]
    extern "system" {
        fn GetForegroundWindow() -> *mut std::ffi::c_void;
    }
    unsafe {
        let fg = GetForegroundWindow();
        if fg.is_null() {
            return false;
        }
        let mut cls_buf = [0u16; 64];
        let len = GetClassNameW(fg as _, cls_buf.as_mut_ptr(), cls_buf.len() as i32);
        if len <= 0 {
            return false;
        }
        let cls = String::from_utf16_lossy(&cls_buf[..len as usize]);
        matches!(
            cls.as_str(),
            "CabinetWClass" | "ExploreWClass" | "Progman" | "WorkerW"
        )
    }
}

#[cfg(not(windows))]
pub fn is_explorer_foreground() -> bool {
    false
}

/// Queries currently selected file paths across open File Explorer windows (`Shell.Application`).
#[cfg(windows)]
pub fn query_selected_explorer_files() -> Vec<PathBuf> {
    let ps = r#"$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $out=@(); $sh=New-Object -ComObject Shell.Application; foreach($w in $sh.Windows()){ try { foreach($it in $w.Document.SelectedItems()){ $p=[string]$it.Path; if($p -and (Test-Path -LiteralPath $p -PathType Leaf)){ $out+=$p } } } catch {} }; $out | Select-Object -First 5 | ConvertTo-Json -Compress"#;
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps]);
    let Ok(out) = hidden(&mut cmd).output() else {
        return Vec::new();
    };
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return Vec::new();
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
        if let Some(arr) = v.as_array() {
            return arr
                .iter()
                .filter_map(|x| x.as_str())
                .map(PathBuf::from)
                .filter(|p| p.is_file())
                .collect();
        }
        if let Some(single) = v.as_str() {
            let p = PathBuf::from(single);
            if p.is_file() {
                return vec![p];
            }
        }
    }
    Vec::new()
}

#[cfg(not(windows))]
pub fn query_selected_explorer_files() -> Vec<PathBuf> {
    Vec::new()
}

/// Fallback safety net: scans common user folders (`Downloads`, `Desktop`, `Pictures\Screenshots`,
/// `Documents`) for the most recently written non-temp file within `within_secs` seconds.
pub fn find_recent_user_file(within_secs: u64) -> Option<PathBuf> {
    let profile = std::env::var("USERPROFILE").ok()?;
    let base = PathBuf::from(profile);
    let dirs = [
        base.join("Downloads"),
        base.join("Desktop"),
        base.join("Pictures").join("Screenshots"),
        base.join("Documents"),
    ];
    let max_age = std::time::Duration::from_secs(within_secs);
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for dir in &dirs {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for ent in rd.flatten() {
            let p = ent.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
            let lc = name.to_ascii_lowercase();
            if lc.starts_with('.')
                || lc.starts_with("~$")
                || lc.ends_with(".tmp")
                || lc.ends_with(".crdownload")
                || lc.ends_with(".part")
                || lc.ends_with(".lnk")
                || lc.ends_with(".ini")
            {
                continue;
            }
            let Ok(meta) = ent.metadata() else { continue };
            if !meta.is_file() || meta.len() == 0 || meta.len() > 64 * 1024 * 1024 {
                continue;
            }
            let mtime = meta.modified().or_else(|_| meta.created()).ok()?;
            let Ok(age) = mtime.elapsed() else { continue };
            if age <= max_age {
                if best.as_ref().map_or(true, |(bt, _)| mtime > *bt) {
                    best = Some((mtime, p));
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Normalizes a candidate phone string to `+<digits>` (rejecting short/long non-phone runs).
pub fn normalize_extracted_phone(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let has_plus = trimmed.starts_with('+');
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 9 || digits.len() > 15 {
        return String::new();
    }
    if let Some(first) = digits.chars().next() {
        if digits.chars().all(|c| c == first) {
            return String::new();
        }
    }
    if digits.len() == 11
        && (digits.starts_with("010")
            || digits.starts_with("011")
            || digits.starts_with("012")
            || digits.starts_with("015"))
    {
        return format!("+2{}", digits);
    }
    if has_plus || !digits.starts_with('0') {
        format!("+{}", digits)
    } else {
        digits
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start + needle.len() > haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|off| start + off)
}

fn scan_ascii_jid_phone(ascii: &str) -> Option<String> {
    for marker in ["@c.us", "@s.whatsapp.net"] {
        let mut idx = 0usize;
        while let Some(rel) = ascii[idx..].find(marker) {
            let at = idx + rel;
            let bytes = ascii.as_bytes();
            let mut start = at;
            while start > 0 && bytes[start - 1].is_ascii_digit() {
                start -= 1;
            }
            let norm = normalize_extracted_phone(&ascii[start..at]);
            if !norm.is_empty() {
                return Some(norm);
            }
            idx = at + marker.len();
        }
    }
    if let Some(pn_pos) = ascii.find("phoneNumber") {
        let tail = &ascii[pn_pos + "phoneNumber".len()..];
        let mut run = String::new();
        let mut started = false;
        for ch in tail.chars().take(28) {
            if ch == '+' && !started {
                run.push(ch);
                started = true;
            } else if ch.is_ascii_digit() {
                run.push(ch);
                started = true;
            } else if started {
                break;
            }
        }
        let norm = normalize_extracted_phone(&run);
        if !norm.is_empty() {
            return Some(norm);
        }
    }
    None
}

/// Searches raw Chromium LevelDB/IndexedDB bytes around UTF-8 or UTF-16LE occurrences of
/// `contact_name` for real WhatsApp user JIDs (`@c.us`, `@s.whatsapp.net`, or `phoneNumber`),
/// ignoring opaque `@lid` identifiers.
pub fn extract_phone_near_contact_bytes(buf: &[u8], contact_name: &str) -> Option<String> {
    let name = contact_name.trim();
    if name.chars().count() < 2 || buf.is_empty() {
        return None;
    }
    let direct = normalize_extracted_phone(name);
    if !direct.is_empty() {
        return Some(direct);
    }
    let utf8_needle = name.as_bytes().to_vec();
    let utf16_needle: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

    for needle in [&utf16_needle, &utf8_needle] {
        let mut pos = 0usize;
        let mut hits = 0usize;
        while let Some(idx) = find_bytes(buf, needle, pos) {
            let win_start = idx.saturating_sub(700);
            let win_end = (idx + needle.len() + 700).min(buf.len());
            let slice = &buf[win_start..win_end];

            let ascii_raw: String = slice
                .iter()
                .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { ' ' })
                .collect();
            if let Some(p) = scan_ascii_jid_phone(&ascii_raw) {
                return Some(p);
            }

            for offset in [0usize, 1usize] {
                let mut ascii_u16 = String::with_capacity(slice.len() / 2);
                let mut j = offset;
                while j + 1 < slice.len() {
                    if slice[j + 1] == 0 && (0x20..=0x7E).contains(&slice[j]) {
                        ascii_u16.push(slice[j] as char);
                    } else {
                        ascii_u16.push(' ');
                    }
                    j += 2;
                }
                if let Some(p) = scan_ascii_jid_phone(&ascii_u16) {
                    return Some(p);
                }
            }

            pos = idx + needle.len();
            hits += 1;
            if hits >= 8 {
                break;
            }
        }
    }
    None
}

static WA_PHONE_CACHE: std::sync::Mutex<
    Option<std::collections::HashMap<String, (Option<String>, std::time::Instant)>>,
> = std::sync::Mutex::new(None);

/// Resolves a WhatsApp saved contact name (e.g. from `#main header`) to the contact's
/// real phone number (`+2010...`) by reading Chrome/Edge/Brave/Opera IndexedDB LevelDB files
/// (`https_web.whatsapp.com_0.indexeddb.leveldb`) with Windows shared-read locking.
#[cfg(windows)]
pub fn lookup_whatsapp_phone_by_name(contact_name: &str) -> Option<String> {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;

    let clean = contact_name.trim();
    if clean.chars().count() < 2 {
        return None;
    }
    let direct = normalize_extracted_phone(clean);
    if !direct.is_empty() {
        return Some(direct);
    }
    if let Ok(guard) = WA_PHONE_CACHE.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some((cached, ts)) = map.get(clean) {
                if ts.elapsed() < std::time::Duration::from_secs(300) {
                    return cached.clone();
                }
            }
        }
    }

    let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
    if local_app_data.trim().is_empty() {
        return None;
    }
    let roots = [
        PathBuf::from(&local_app_data).join(r"Google\Chrome\User Data"),
        PathBuf::from(&local_app_data).join(r"Microsoft\Edge\User Data"),
        PathBuf::from(&local_app_data).join(r"BraveSoftware\Brave-Browser\User Data"),
        PathBuf::from(&local_app_data).join(r"Opera Software\Opera Stable"),
    ];
    let mut idb_files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for root in roots {
        let Ok(profiles) = fs::read_dir(&root) else { continue };
        for prof in profiles.flatten() {
            let ppath = prof.path();
            if !ppath.is_dir() {
                continue;
            }
            let leveldb_dir = ppath
                .join("IndexedDB")
                .join("https_web.whatsapp.com_0.indexeddb.leveldb");
            let Ok(entries) = fs::read_dir(&leveldb_dir) else { continue };
            for f in entries.flatten() {
                let fp = f.path();
                if !fp.is_file() {
                    continue;
                }
                let ext = fp
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if ext == "ldb" || ext == "log" {
                    let meta = f.metadata().ok();
                    let sz = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    if sz > 0 && sz <= 32 * 1024 * 1024 {
                        let mtime = meta
                            .and_then(|m| m.modified().ok())
                            .unwrap_or(std::time::UNIX_EPOCH);
                        idb_files.push((mtime, fp));
                    }
                }
            }
        }
    }
    idb_files.sort_by(|a, b| b.0.cmp(&a.0));

    let mut found: Option<String> = None;
    for (_, fp) in idb_files.into_iter().take(24) {
        const FILE_SHARE_ALL: u32 = 7;
        let Ok(mut f) = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_ALL)
            .open(&fp)
        else {
            continue;
        };
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() {
            if let Some(phone) = extract_phone_near_contact_bytes(&buf, clean) {
                found = Some(phone);
                break;
            }
        }
    }

    if let Ok(mut guard) = WA_PHONE_CACHE.lock() {
        let map = guard.get_or_insert_with(std::collections::HashMap::new);
        if map.len() > 256 {
            map.retain(|_, (_, t)| t.elapsed() < std::time::Duration::from_secs(300));
        }
        map.insert(clean.to_string(), (found.clone(), std::time::Instant::now()));
    }
    found
}

#[cfg(not(windows))]
pub fn lookup_whatsapp_phone_by_name(contact_name: &str) -> Option<String> {
    let norm = normalize_extracted_phone(contact_name);
    if !norm.is_empty() { Some(norm) } else { None }
}

fn decode_bmp_to_png_base64(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let _ = fs::remove_file(path);
    if data.len() < 54 || &data[0..2] != b"BM" {
        return None;
    }
    let px_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
    let width = i32::from_le_bytes([data[18], data[19], data[20], data[21]]);
    let height_signed = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
    let bpp = u16::from_le_bytes([data[28], data[29]]);
    let compression = u32::from_le_bytes([data[30], data[31], data[32], data[33]]);
    if width <= 0 || height_signed == 0 || (compression != 0 && compression != 3) || (bpp != 24 && bpp != 32) {
        return None;
    }
    let src_w = width as usize;
    let src_h = height_signed.unsigned_abs() as usize;
    let top_down = height_signed < 0;
    let row_stride = ((src_w * (bpp as usize) + 31) / 32) * 4;
    if px_offset + row_stride.saturating_mul(src_h) > data.len() {
        return None;
    }
    let max_w = 480usize;
    let (dst_w, dst_h) = if src_w > max_w {
        let dh = ((src_h * max_w) / src_w).max(1);
        (max_w, dh)
    } else {
        (src_w, src_h)
    };
    let mut bgra = vec![0u8; dst_w * dst_h * 4];
    for dy in 0..dst_h {
        let sy = (dy * src_h) / dst_h;
        let bmp_row = if top_down { sy } else { src_h - 1 - sy };
        let row_start = px_offset + bmp_row * row_stride;
        for dx in 0..dst_w {
            let sx = (dx * src_w) / dst_w;
            let p = row_start + sx * ((bpp as usize) / 8);
            let o = (dy * dst_w + dx) * 4;
            bgra[o] = data[p];
            bgra[o + 1] = data[p + 1];
            bgra[o + 2] = data[p + 2];
            bgra[o + 3] = 255;
        }
    }
    encode_bgra_png_base64(&bgra, dst_w as u32, dst_h as u32)
}

/// 64-bit Windows Media Foundation (`mfplat.dll`, `mf.dll`, `mfreadwrite.dll`) webcam
/// capture & streaming engine. Works reliably on modern Windows 10/11 USB/integrated
/// UVC cameras where legacy 32-bit Video for Windows (`avicap32.dll`) returns no device.
#[cfg(windows)]
fn mf_webcam_session_loop<F, C>(
    single_frame: bool,
    mut should_continue: F,
    mut on_frame: C,
) -> Result<(), &'static str>
where
    F: FnMut() -> bool,
    C: FnMut(String),
{
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid {
        Guid { data1: d1, data2: d2, data3: d3, data4: d4 }
    }

    const MF_SDK_VERSION: u32 = 0x0002;
    const MF_API_VERSION: u32 = 0x0070;
    const MF_VERSION_V2: u32 = (MF_SDK_VERSION << 16) | MF_API_VERSION;
    const MF_VERSION_V1: u32 = (1 << 16) | MF_API_VERSION;
    const MF_SOURCE_READER_FIRST_VIDEO_STREAM: u32 = 0xFFFF_FFFC;

    const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE: Guid =
        guid(0xc60a_c5fe, 0x252a, 0x478f, [0xa0, 0xef, 0xbc, 0x8f, 0xa5, 0xf7, 0xca, 0xd3]);
    const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID: Guid =
        guid(0x8ac3_587a, 0x4ae7, 0x42d8, [0x99, 0xe0, 0x0a, 0x60, 0x13, 0xee, 0xf9, 0x0f]);
    const MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING: Guid =
        guid(0xfb39_4f3d, 0xccf1, 0x42ee, [0xbb, 0xb3, 0xf9, 0xb8, 0x45, 0xd5, 0x68, 0x1d]);
    const IID_IMF_MEDIA_SOURCE: Guid =
        guid(0x279a_808d, 0xaec7, 0x40c8, [0x9c, 0x6b, 0xa6, 0xb4, 0x92, 0xc7, 0x8a, 0x66]);
    const IID_IMF_2D_BUFFER: Guid =
        guid(0x7dc9_d5f9, 0x9ed9, 0x44ec, [0x9b, 0xbf, 0x06, 0x00, 0xbb, 0x58, 0x9f, 0xbb]);
    const MF_MT_MAJOR_TYPE: Guid =
        guid(0x48eb_a18e, 0xf8c9, 0x4687, [0xbf, 0x11, 0x0a, 0x74, 0xc9, 0xf9, 0x6a, 0x8f]);
    const MF_MT_SUBTYPE: Guid =
        guid(0xf7e3_4c9a, 0x42e8, 0x4714, [0xb7, 0x4b, 0xcb, 0x29, 0xd7, 0x2c, 0x35, 0xe5]);
    const MF_MT_FRAME_SIZE: Guid =
        guid(0x1652_c33d, 0xd6b2, 0x4012, [0xb8, 0x34, 0x72, 0x03, 0x08, 0x49, 0xa3, 0x7d]);
    const MF_MT_DEFAULT_STRIDE: Guid =
        guid(0x644b_4e48, 0x1e02, 0x4516, [0xb0, 0xeb, 0xc0, 0x1c, 0xa9, 0xd4, 0x9a, 0xc6]);
    const MF_MEDIA_TYPE_VIDEO: Guid =
        guid(0x7364_6976, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
    const MF_VIDEO_FORMAT_RGB32: Guid =
        guid(0x0000_0016, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(lpLibFileName: *const u8) -> *mut c_void;
        fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *const c_void;
    }

    type CoInitExFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    type CoUninitFn = unsafe extern "system" fn();
    type CoTaskMemFreeFn = unsafe extern "system" fn(*mut c_void);
    type MfStartupFn = unsafe extern "system" fn(u32, u32) -> i32;
    type MfShutdownFn = unsafe extern "system" fn() -> i32;
    type MfCreateAttrsFn = unsafe extern "system" fn(*mut *mut c_void, u32) -> i32;
    type MfCreateMediaTypeFn = unsafe extern "system" fn(*mut *mut c_void) -> i32;
    type MfEnumDeviceSourcesFn =
        unsafe extern "system" fn(*mut c_void, *mut *mut *mut c_void, *mut u32) -> i32;
    type MfCreateSourceReaderFn =
        unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32;

    type FnQueryInterface = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
    type FnRelease = unsafe extern "system" fn(*mut c_void) -> u32;
    type FnGetU32 = unsafe extern "system" fn(*mut c_void, *const Guid, *mut u32) -> i32;
    type FnGetU64 = unsafe extern "system" fn(*mut c_void, *const Guid, *mut u64) -> i32;
    type FnSetU32 = unsafe extern "system" fn(*mut c_void, *const Guid, u32) -> i32;
    type FnSetU64 = unsafe extern "system" fn(*mut c_void, *const Guid, u64) -> i32;
    type FnSetGuid = unsafe extern "system" fn(*mut c_void, *const Guid, *const Guid) -> i32;
    type FnActivateObj = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
    type FnShutdownObj = unsafe extern "system" fn(*mut c_void) -> i32;
    type FnMediaSourceShutdown = unsafe extern "system" fn(*mut c_void) -> i32;
    type FnGetNativeMediaType =
        unsafe extern "system" fn(*mut c_void, u32, u32, *mut *mut c_void) -> i32;
    type FnGetCurrentMediaType =
        unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type FnSetCurrentMediaType =
        unsafe extern "system" fn(*mut c_void, u32, *mut u32, *mut c_void) -> i32;
    type FnReadSample = unsafe extern "system" fn(
        *mut c_void,
        u32,
        u32,
        *mut u32,
        *mut u32,
        *mut i64,
        *mut *mut c_void,
    ) -> i32;
    type FnConvertContig = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
    type FnBufLock = unsafe extern "system" fn(*mut c_void, *mut *mut u8, *mut u32, *mut u32) -> i32;
    type FnBufUnlock = unsafe extern "system" fn(*mut c_void) -> i32;
    type Fn2DLock = unsafe extern "system" fn(*mut c_void, *mut *mut u8, *mut i32) -> i32;
    type Fn2DUnlock = unsafe extern "system" fn(*mut c_void) -> i32;

    #[inline]
    unsafe fn vtbl<T>(obj: *mut c_void, slot: usize) -> T {
        let table = *(obj as *const *const *const c_void);
        std::mem::transmute_copy(&*table.add(slot))
    }

    #[inline]
    unsafe fn com_release(obj: *mut c_void) {
        if !obj.is_null() {
            let f: FnRelease = vtbl(obj, 2);
            let _ = f(obj);
        }
    }

    unsafe {
        let h_ole = LoadLibraryA(b"ole32.dll\0".as_ptr());
        let h_plat = LoadLibraryA(b"mfplat.dll\0".as_ptr());
        let h_mf = LoadLibraryA(b"mf.dll\0".as_ptr());
        let h_rw = LoadLibraryA(b"mfreadwrite.dll\0".as_ptr());
        if h_ole.is_null() || h_plat.is_null() || h_mf.is_null() || h_rw.is_null() {
            return Err("mf_unavailable");
        }

        let p_co_init = GetProcAddress(h_ole, b"CoInitializeEx\0".as_ptr());
        let p_co_uninit = GetProcAddress(h_ole, b"CoUninitialize\0".as_ptr());
        let p_co_free = GetProcAddress(h_ole, b"CoTaskMemFree\0".as_ptr());
        let p_mf_start = GetProcAddress(h_plat, b"MFStartup\0".as_ptr());
        let p_mf_stop = GetProcAddress(h_plat, b"MFShutdown\0".as_ptr());
        let p_mf_attrs = GetProcAddress(h_plat, b"MFCreateAttributes\0".as_ptr());
        let p_mf_type = GetProcAddress(h_plat, b"MFCreateMediaType\0".as_ptr());
        let p_mf_enum = GetProcAddress(h_mf, b"MFEnumDeviceSources\0".as_ptr());
        let p_mf_reader = GetProcAddress(h_rw, b"MFCreateSourceReaderFromMediaSource\0".as_ptr());
        if p_co_init.is_null()
            || p_co_free.is_null()
            || p_mf_start.is_null()
            || p_mf_stop.is_null()
            || p_mf_attrs.is_null()
            || p_mf_type.is_null()
            || p_mf_enum.is_null()
            || p_mf_reader.is_null()
        {
            return Err("mf_unavailable");
        }

        let co_init: CoInitExFn = std::mem::transmute(p_co_init);
        let co_free: CoTaskMemFreeFn = std::mem::transmute(p_co_free);
        let mf_start: MfStartupFn = std::mem::transmute(p_mf_start);
        let mf_stop: MfShutdownFn = std::mem::transmute(p_mf_stop);
        let mf_attrs: MfCreateAttrsFn = std::mem::transmute(p_mf_attrs);
        let mf_type: MfCreateMediaTypeFn = std::mem::transmute(p_mf_type);
        let mf_enum: MfEnumDeviceSourcesFn = std::mem::transmute(p_mf_enum);
        let mf_reader: MfCreateSourceReaderFn = std::mem::transmute(p_mf_reader);

        let hr_co = co_init(std::ptr::null_mut(), 0);
        let did_co_init = hr_co == 0 || hr_co == 1;
        struct CoGuard(bool, Option<CoUninitFn>);
        impl Drop for CoGuard {
            fn drop(&mut self) {
                if self.0 {
                    if let Some(f) = self.1 {
                        unsafe { f(); }
                    }
                }
            }
        }
        let co_uninit_opt = if p_co_uninit.is_null() {
            None
        } else {
            Some(std::mem::transmute::<_, CoUninitFn>(p_co_uninit))
        };
        let _co_guard = CoGuard(did_co_init, co_uninit_opt);

        if mf_start(MF_VERSION_V2, 0) < 0 && mf_start(MF_VERSION_V1, 0) < 0 {
            return Err("mf_unavailable");
        }
        struct MfGuard(MfShutdownFn);
        impl Drop for MfGuard {
            fn drop(&mut self) {
                unsafe { let _ = (self.0)(); }
            }
        }
        let _mf_guard = MfGuard(mf_stop);

        let mut enum_attrs: *mut c_void = std::ptr::null_mut();
        if mf_attrs(&mut enum_attrs, 1) < 0 || enum_attrs.is_null() {
            return Err("mf_unavailable");
        }
        let set_guid: FnSetGuid = vtbl(enum_attrs, 24);
        let hr_sg = set_guid(
            enum_attrs,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        );
        let mut devices: *mut *mut c_void = std::ptr::null_mut();
        let mut count: u32 = 0;
        let hr_enum = if hr_sg >= 0 {
            mf_enum(enum_attrs, &mut devices, &mut count)
        } else {
            -1
        };
        com_release(enum_attrs);
        if hr_enum < 0 || count == 0 || devices.is_null() {
            if !devices.is_null() {
                co_free(devices as *mut c_void);
            }
            return Err("no_camera");
        }

        let mut active_source: *mut c_void = std::ptr::null_mut();
        let mut reader: *mut c_void = std::ptr::null_mut();
        for idx in 0..count as usize {
            let act = *devices.add(idx);
            if act.is_null() {
                continue;
            }
            let act_obj: FnActivateObj = vtbl(act, 33);
            let mut src: *mut c_void = std::ptr::null_mut();
            if act_obj(act, &IID_IMF_MEDIA_SOURCE, &mut src) < 0 || src.is_null() {
                continue;
            }
            let mut rd_attrs: *mut c_void = std::ptr::null_mut();
            let mut rdr: *mut c_void = std::ptr::null_mut();
            let hr_rd = if mf_attrs(&mut rd_attrs, 1) >= 0 && !rd_attrs.is_null() {
                let set_u32: FnSetU32 = vtbl(rd_attrs, 21);
                let _ = set_u32(rd_attrs, &MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, 1);
                let hr = mf_reader(src, rd_attrs, &mut rdr);
                com_release(rd_attrs);
                hr
            } else {
                mf_reader(src, std::ptr::null_mut(), &mut rdr)
            };
            if hr_rd >= 0 && !rdr.is_null() {
                active_source = src;
                reader = rdr;
                break;
            }
            let shut: FnMediaSourceShutdown = vtbl(src, 12);
            let _ = shut(src);
            com_release(src);
        }

        if reader.is_null() || active_source.is_null() {
            for idx in 0..count as usize {
                let act = *devices.add(idx);
                if !act.is_null() {
                    let shut_act: FnShutdownObj = vtbl(act, 34);
                    let _ = shut_act(act);
                    com_release(act);
                }
            }
            co_free(devices as *mut c_void);
            return Err("no_camera");
        }

        // Configure RGB32 output with MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING.
        let mut out_type: *mut c_void = std::ptr::null_mut();
        if mf_type(&mut out_type) >= 0 && !out_type.is_null() {
            let mt_set_guid: FnSetGuid = vtbl(out_type, 24);
            let _ = mt_set_guid(out_type, &MF_MT_MAJOR_TYPE, &MF_MEDIA_TYPE_VIDEO);
            let _ = mt_set_guid(out_type, &MF_MT_SUBTYPE, &MF_VIDEO_FORMAT_RGB32);
            let set_cur_mt: FnSetCurrentMediaType = vtbl(reader, 7);
            if set_cur_mt(reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, std::ptr::null_mut(), out_type) < 0 {
                // Retry copying native frame size if the driver rejects an unspecified size.
                let get_nat: FnGetNativeMediaType = vtbl(reader, 5);
                let mut nat_mt: *mut c_void = std::ptr::null_mut();
                if get_nat(reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, &mut nat_mt) >= 0
                    && !nat_mt.is_null()
                {
                    let get_u64: FnGetU64 = vtbl(nat_mt, 8);
                    let mut packed_sz: u64 = 0;
                    if get_u64(nat_mt, &MF_MT_FRAME_SIZE, &mut packed_sz) >= 0 && packed_sz != 0 {
                        let set_u64: FnSetU64 = vtbl(out_type, 22);
                        let _ = set_u64(out_type, &MF_MT_FRAME_SIZE, packed_sz);
                        let _ = set_cur_mt(
                            reader,
                            MF_SOURCE_READER_FIRST_VIDEO_STREAM,
                            std::ptr::null_mut(),
                            out_type,
                        );
                    }
                    com_release(nat_mt);
                }
            }
            com_release(out_type);
        }

        let mut src_w: usize = 0;
        let mut src_h: usize = 0;
        let mut default_stride: i32 = 0;
        let get_cur_mt: FnGetCurrentMediaType = vtbl(reader, 6);
        let mut cur_mt: *mut c_void = std::ptr::null_mut();
        if get_cur_mt(reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, &mut cur_mt) >= 0
            && !cur_mt.is_null()
        {
            let get_u64: FnGetU64 = vtbl(cur_mt, 8);
            let mut packed_sz: u64 = 0;
            if get_u64(cur_mt, &MF_MT_FRAME_SIZE, &mut packed_sz) >= 0 {
                src_w = (packed_sz >> 32) as u32 as usize;
                src_h = (packed_sz & 0xFFFF_FFFF) as u32 as usize;
            }
            let get_u32: FnGetU32 = vtbl(cur_mt, 7);
            let mut raw_stride: u32 = 0;
            if get_u32(cur_mt, &MF_MT_DEFAULT_STRIDE, &mut raw_stride) >= 0 {
                default_stride = raw_stride as i32;
            }
            com_release(cur_mt);
        }

        if src_w == 0 || src_h == 0 || src_w > 4096 || src_h > 4096 {
            com_release(reader);
            let shut: FnMediaSourceShutdown = vtbl(active_source, 12);
            let _ = shut(active_source);
            com_release(active_source);
            for idx in 0..count as usize {
                let act = *devices.add(idx);
                if !act.is_null() {
                    let shut_act: FnShutdownObj = vtbl(act, 34);
                    let _ = shut_act(act);
                    com_release(act);
                }
            }
            co_free(devices as *mut c_void);
            return Err("camera_format_error");
        }
        if default_stride == 0 {
            default_stride = (src_w * 4) as i32;
        }

        let read_sample: FnReadSample = vtbl(reader, 9);
        let mut valid_frames = 0usize;
        let mut empty_ticks = 0usize;
        let max_w = 560usize;
        let (dst_w, dst_h) = if src_w > max_w {
            (max_w, ((src_h * max_w) / src_w).max(1))
        } else {
            (src_w, src_h)
        };
        let mut bgra = vec![0u8; dst_w * dst_h * 4];

        while should_continue() {
            let mut actual_idx: u32 = 0;
            let mut stream_flags: u32 = 0;
            let mut ts: i64 = 0;
            let mut sample: *mut c_void = std::ptr::null_mut();
            let hr = read_sample(
                reader,
                MF_SOURCE_READER_FIRST_VIDEO_STREAM,
                0,
                &mut actual_idx,
                &mut stream_flags,
                &mut ts,
                &mut sample,
            );
            if hr < 0 {
                break;
            }
            if sample.is_null() {
                empty_ticks += 1;
                if empty_ticks > 40 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            empty_ticks = 0;
            valid_frames += 1;
            // Skip first 2 frames while auto-exposure settles.
            if valid_frames <= 2 {
                com_release(sample);
                std::thread::sleep(std::time::Duration::from_millis(60));
                continue;
            }

            let conv: FnConvertContig = vtbl(sample, 41);
            let mut media_buf: *mut c_void = std::ptr::null_mut();
            if conv(sample, &mut media_buf) >= 0 && !media_buf.is_null() {
                let qi: FnQueryInterface = vtbl(media_buf, 0);
                let mut buf2d: *mut c_void = std::ptr::null_mut();
                let mut encoded: Option<String> = None;
                if qi(media_buf, &IID_IMF_2D_BUFFER, &mut buf2d) >= 0 && !buf2d.is_null() {
                    let lock2d: Fn2DLock = vtbl(buf2d, 3);
                    let unlock2d: Fn2DUnlock = vtbl(buf2d, 4);
                    let mut scan0: *mut u8 = std::ptr::null_mut();
                    let mut pitch: i32 = 0;
                    if lock2d(buf2d, &mut scan0, &mut pitch) >= 0
                        && !scan0.is_null()
                        && pitch.unsigned_abs() as usize >= src_w * 4
                    {
                        for dy in 0..dst_h {
                            let sy = (dy * src_h) / dst_h;
                            let row = scan0.offset((sy as isize) * (pitch as isize));
                            for dx in 0..dst_w {
                                let sx = (dx * src_w) / dst_w;
                                let px = row.add(sx * 4);
                                let o = (dy * dst_w + dx) * 4;
                                bgra[o] = *px;
                                bgra[o + 1] = *px.add(1);
                                bgra[o + 2] = *px.add(2);
                                bgra[o + 3] = 255;
                            }
                        }
                        let _ = unlock2d(buf2d);
                        encoded = encode_bgra_png_base64(&bgra, dst_w as u32, dst_h as u32);
                    }
                    com_release(buf2d);
                } else {
                    let lock1d: FnBufLock = vtbl(media_buf, 3);
                    let unlock1d: FnBufUnlock = vtbl(media_buf, 4);
                    let mut ptr: *mut u8 = std::ptr::null_mut();
                    let mut max_len: u32 = 0;
                    let mut cur_len: u32 = 0;
                    let abs_stride = default_stride.unsigned_abs() as usize;
                    if lock1d(media_buf, &mut ptr, &mut max_len, &mut cur_len) >= 0
                        && !ptr.is_null()
                        && abs_stride >= src_w * 4
                        && (cur_len as usize) >= abs_stride.saturating_mul(src_h)
                    {
                        for dy in 0..dst_h {
                            let sy = (dy * src_h) / dst_h;
                            let row_idx = if default_stride >= 0 { sy } else { src_h - 1 - sy };
                            let row = ptr.add(row_idx * abs_stride);
                            for dx in 0..dst_w {
                                let sx = (dx * src_w) / dst_w;
                                let px = row.add(sx * 4);
                                let o = (dy * dst_w + dx) * 4;
                                bgra[o] = *px;
                                bgra[o + 1] = *px.add(1);
                                bgra[o + 2] = *px.add(2);
                                bgra[o + 3] = 255;
                            }
                        }
                        let _ = unlock1d(media_buf);
                        encoded = encode_bgra_png_base64(&bgra, dst_w as u32, dst_h as u32);
                    }
                }
                com_release(media_buf);
                com_release(sample);
                if let Some(b64) = encoded {
                    on_frame(b64);
                    if single_frame {
                        break;
                    }
                }
            } else {
                com_release(sample);
            }
            if !single_frame {
                std::thread::sleep(std::time::Duration::from_millis(140));
            }
        }

        com_release(reader);
        let shut: FnMediaSourceShutdown = vtbl(active_source, 12);
        let _ = shut(active_source);
        com_release(active_source);
        for idx in 0..count as usize {
            let act = *devices.add(idx);
            if !act.is_null() {
                let shut_act: FnShutdownObj = vtbl(act, 34);
                let _ = shut_act(act);
                com_release(act);
            }
        }
        co_free(devices as *mut c_void);
    }
    Ok(())
}

/// Captures a single frame from an attached webcam via 64-bit Windows Media Foundation
/// (falling back to Win32 `avicap32.dll` only if Media Foundation is unavailable).
/// Returns `None` immediately when no webcam is attached.
#[cfg(windows)]
pub fn capture_webcam_base64() -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let mut captured: Option<String> = None;
        let started = std::time::Instant::now();
        let mf_res = mf_webcam_session_loop(
            true,
            || started.elapsed() < std::time::Duration::from_millis(3800),
            |img| captured = Some(img),
        );
        if captured.is_none() && mf_res == Err("mf_unavailable") {
            captured = capture_webcam_avicap32_fallback();
        }
        let _ = tx.send(captured);
    });
    rx.recv_timeout(std::time::Duration::from_secs(5)).ok().flatten()
}

#[cfg(windows)]
fn capture_webcam_avicap32_fallback() -> Option<String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
        fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *const std::ffi::c_void;
    }
    #[link(name = "user32")]
    extern "system" {
        fn SendMessageW(hWnd: *mut std::ffi::c_void, Msg: u32, wParam: usize, lParam: isize) -> isize;
        fn DestroyWindow(hWnd: *mut std::ffi::c_void) -> i32;
    }

    type CapGetDriverDescW = unsafe extern "system" fn(u32, *mut u16, i32, *mut u16, i32) -> i32;
    type CapCreateCaptureWindowW = unsafe extern "system" fn(
        *const u16,
        u32,
        i32,
        i32,
        i32,
        i32,
        *mut std::ffi::c_void,
        i32,
    ) -> *mut std::ffi::c_void;

    let mut captured: Option<String> = None;
    unsafe {
        let hmod = LoadLibraryA(b"avicap32.dll\0".as_ptr());
        if !hmod.is_null() {
            let desc_ptr = GetProcAddress(hmod, b"capGetDriverDescriptionW\0".as_ptr());
            let create_ptr = GetProcAddress(hmod, b"capCreateCaptureWindowW\0".as_ptr());
            if !desc_ptr.is_null() && !create_ptr.is_null() {
                let cap_desc: CapGetDriverDescW = std::mem::transmute(desc_ptr);
                let cap_create: CapCreateCaptureWindowW = std::mem::transmute(create_ptr);
                let mut found_idx: Option<usize> = None;
                for idx in 0..4u32 {
                    let mut nbuf = [0u16; 128];
                    let mut vbuf = [0u16; 128];
                    if cap_desc(idx, nbuf.as_mut_ptr(), 128, vbuf.as_mut_ptr(), 128) != 0 {
                        found_idx = Some(idx as usize);
                        break;
                    }
                }
                if let Some(drv_idx) = found_idx {
                    const WS_POPUP: u32 = 0x8000_0000;
                    const WM_CAP_DRIVER_CONNECT: u32 = 0x0400 + 10;
                    const WM_CAP_DRIVER_DISCONNECT: u32 = 0x0400 + 11;
                    const WM_CAP_FILE_SAVEDIBW: u32 = 0x0400 + 25;
                    const WM_CAP_GRAB_FRAME_NOSTOP: u32 = 0x0400 + 61;
                    const WM_CAP_SET_CALLBACK_ERRORW: u32 = 0x0400 + 102;
                    const WM_CAP_SET_CALLBACK_STATUSW: u32 = 0x0400 + 103;

                    let wname: Vec<u16> = "itk_cam\0".encode_utf16().collect();
                    let hwnd = cap_create(wname.as_ptr(), WS_POPUP, -200, -200, 1, 1, std::ptr::null_mut(), 0);
                    if !hwnd.is_null() {
                        let _ = SendMessageW(hwnd, WM_CAP_SET_CALLBACK_ERRORW, 0, 0);
                        let _ = SendMessageW(hwnd, WM_CAP_SET_CALLBACK_STATUSW, 0, 0);
                        if SendMessageW(hwnd, WM_CAP_DRIVER_CONNECT, drv_idx, 0) != 0 {
                            std::thread::sleep(std::time::Duration::from_millis(320));
                            let _ = SendMessageW(hwnd, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0);
                            std::thread::sleep(std::time::Duration::from_millis(160));
                            let _ = SendMessageW(hwnd, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0);
                            let bmp_path = std::env::temp_dir().join(format!("itk-cam-{}.bmp", random_hex(6)));
                            let wpath: Vec<u16> = bmp_path
                                .to_string_lossy()
                                .encode_utf16()
                                .chain(std::iter::once(0))
                                .collect();
                            if SendMessageW(hwnd, WM_CAP_FILE_SAVEDIBW, 0, wpath.as_ptr() as isize) != 0 {
                                captured = decode_bmp_to_png_base64(&bmp_path);
                            } else {
                                let _ = fs::remove_file(&bmp_path);
                            }
                            let _ = SendMessageW(hwnd, WM_CAP_DRIVER_DISCONNECT, drv_idx, 0);
                        }
                        let _ = DestroyWindow(hwnd);
                    }
                }
            }
        }
    }
    captured
}

#[cfg(not(windows))]
pub fn capture_webcam_base64() -> Option<String> {
    None
}

/// Continuously streams frames from an attached webcam via 64-bit Windows Media Foundation
/// until `should_continue()` returns `false`. Calls `on_frame(Err("no_camera"))` if no camera is present.
#[cfg(windows)]
pub fn run_webcam_stream_loop<F, C>(mut should_continue: F, mut on_frame: C)
where
    F: FnMut() -> bool,
    C: FnMut(Result<String, &'static str>),
{
    let mut sent_any = false;
    let res = mf_webcam_session_loop(
        false,
        || should_continue(),
        |img| {
            sent_any = true;
            on_frame(Ok(img));
        },
    );
    match res {
        Ok(()) => {
            if !sent_any && should_continue() {
                on_frame(Err("no_camera"));
            }
        }
        Err("mf_unavailable") => run_avicap32_stream_fallback(should_continue, on_frame),
        Err(code) => on_frame(Err(code)),
    }
}

#[cfg(windows)]
fn run_avicap32_stream_fallback<F, C>(mut should_continue: F, mut on_frame: C)
where
    F: FnMut() -> bool,
    C: FnMut(Result<String, &'static str>),
{
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
        fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *const std::ffi::c_void;
    }
    #[link(name = "user32")]
    extern "system" {
        fn SendMessageW(hWnd: *mut std::ffi::c_void, Msg: u32, wParam: usize, lParam: isize) -> isize;
        fn DestroyWindow(hWnd: *mut std::ffi::c_void) -> i32;
    }

    type CapGetDriverDescW = unsafe extern "system" fn(u32, *mut u16, i32, *mut u16, i32) -> i32;
    type CapCreateCaptureWindowW = unsafe extern "system" fn(
        *const u16,
        u32,
        i32,
        i32,
        i32,
        i32,
        *mut std::ffi::c_void,
        i32,
    ) -> *mut std::ffi::c_void;

    unsafe {
        let hmod = LoadLibraryA(b"avicap32.dll\0".as_ptr());
        if hmod.is_null() {
            on_frame(Err("no_camera"));
            return;
        }
        let desc_ptr = GetProcAddress(hmod, b"capGetDriverDescriptionW\0".as_ptr());
        let create_ptr = GetProcAddress(hmod, b"capCreateCaptureWindowW\0".as_ptr());
        if desc_ptr.is_null() || create_ptr.is_null() {
            on_frame(Err("no_camera"));
            return;
        }
        let cap_desc: CapGetDriverDescW = std::mem::transmute(desc_ptr);
        let cap_create: CapCreateCaptureWindowW = std::mem::transmute(create_ptr);
        let mut found_idx: Option<usize> = None;
        for idx in 0..4u32 {
            let mut nbuf = [0u16; 128];
            let mut vbuf = [0u16; 128];
            if cap_desc(idx, nbuf.as_mut_ptr(), 128, vbuf.as_mut_ptr(), 128) != 0 {
                found_idx = Some(idx as usize);
                break;
            }
        }
        let Some(drv_idx) = found_idx else {
            on_frame(Err("no_camera"));
            return;
        };

        const WS_POPUP: u32 = 0x8000_0000;
        const WM_CAP_DRIVER_CONNECT: u32 = 0x0400 + 10;
        const WM_CAP_DRIVER_DISCONNECT: u32 = 0x0400 + 11;
        const WM_CAP_FILE_SAVEDIBW: u32 = 0x0400 + 25;
        const WM_CAP_GRAB_FRAME_NOSTOP: u32 = 0x0400 + 61;
        const WM_CAP_SET_CALLBACK_ERRORW: u32 = 0x0400 + 102;
        const WM_CAP_SET_CALLBACK_STATUSW: u32 = 0x0400 + 103;

        let wname: Vec<u16> = "itk_cam_stream\0".encode_utf16().collect();
        let hwnd = cap_create(wname.as_ptr(), WS_POPUP, -200, -200, 1, 1, std::ptr::null_mut(), 0);
        if hwnd.is_null() {
            on_frame(Err("no_camera"));
            return;
        }
        let _ = SendMessageW(hwnd, WM_CAP_SET_CALLBACK_ERRORW, 0, 0);
        let _ = SendMessageW(hwnd, WM_CAP_SET_CALLBACK_STATUSW, 0, 0);
        if SendMessageW(hwnd, WM_CAP_DRIVER_CONNECT, drv_idx, 0) == 0 {
            let _ = DestroyWindow(hwnd);
            on_frame(Err("no_camera"));
            return;
        }

        std::thread::sleep(std::time::Duration::from_millis(260));
        let _ = SendMessageW(hwnd, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0);
        let bmp_path = std::env::temp_dir().join(format!("itk-cam-s-{}.bmp", random_hex(6)));
        let wpath: Vec<u16> = bmp_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        while should_continue() {
            let _ = SendMessageW(hwnd, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0);
            if SendMessageW(hwnd, WM_CAP_FILE_SAVEDIBW, 0, wpath.as_ptr() as isize) != 0 {
                if let Some(b64) = decode_bmp_to_png_base64(&bmp_path) {
                    on_frame(Ok(b64));
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(180));
        }

        let _ = fs::remove_file(&bmp_path);
        let _ = SendMessageW(hwnd, WM_CAP_DRIVER_DISCONNECT, drv_idx, 0);
        let _ = DestroyWindow(hwnd);
    }
}

#[cfg(not(windows))]
pub fn run_webcam_stream_loop<F, C>(_should_continue: F, mut on_frame: C)
where
    F: Fn() -> bool,
    C: FnMut(Result<String, &'static str>),
{
    on_frame(Err("no_camera"));
}

fn patch_browser_shortcuts_for_extension(ext_dir: &Path) {
    let ext_flag = format!("--load-extension=\"{}\"", ext_dir.to_string_lossy());
    let ps_script = format!(
        r#"$ErrorActionPreference='SilentlyContinue'
$extFlag = '{ext_flag}'
$accFlag = '--force-renderer-accessibility'
$ws = New-Object -ComObject WScript.Shell
$roots = @(
  "$env:PUBLIC\Desktop",
  "$env:USERPROFILE\Desktop",
  "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
)
foreach ($r in $roots) {{
  if (-not (Test-Path $r)) {{ continue }}
  Get-ChildItem -Path $r -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    $sc = $ws.CreateShortcut($_.FullName)
    $tp = [string]$sc.TargetPath
    if ($tp -match '\\(chrome|msedge|brave)\.exe$') {{
      $args = [string]$sc.Arguments
      $changed = $false
      if ($args -notmatch 'wa-monitor') {{
        $args = ($args.Trim() + ' ' + $extFlag).Trim()
        $changed = $true
      }}
      if ($args -notmatch '--force-renderer-accessibility') {{
        $args = ($args.Trim() + ' ' + $accFlag).Trim()
        $changed = $true
      }}
      if ($changed) {{
        $sc.Arguments = $args
        $sc.Save()
      }}
    }}
  }}
}}"#,
        ext_flag = ext_flag.replace('\'', "''")
    );
    std::thread::spawn(move || {
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_script]);
        let _ = hidden(&mut cmd).output();
    });
}

/// Writes an unpacked MV3 DLP browser monitor extension into `data_dir()/wa-monitor`
/// for Chrome/Edge to capture uploaded file copies (`<= 20 MB`), destination/recipient
/// metadata across WhatsApp Web & all internet sites, and drag/drop/paste events.
pub fn ensure_whatsapp_web_extension() {
    if is_admin_mode() {
        return;
    }
    let dir = data_dir().join("wa-monitor");
    let _ = fs::create_dir_all(&dir);

    let manifest = r#"{
  "manifest_version": 3,
  "name": "IT ELKHAWGA DLP Monitor",
  "version": "1.3.0",
  "permissions": [],
  "host_permissions": ["http://127.0.0.1:8788/*"],
  "background": { "service_worker": "background.js" },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start",
      "all_frames": true
    }
  ]
}"#;

    let background_js = r#"chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || !msg.kind) return;
  const endpoint = msg.kind === 'wa_context'
    ? 'http://127.0.0.1:8788/local/whatsapp-context'
    : msg.kind === 'wa_upload'
    ? 'http://127.0.0.1:8788/local/whatsapp-upload'
    : '';
  if (!endpoint) return;
  fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(msg.payload || {})
  }).catch(() => {});
});"#;

    let content_js = r#"(() => {
  const seen = new Map();
  const phoneByName = new Map();
  const phoneByLid = new Map();
  let lastCtxSig = '';
  let lastValidCtx = { recipient_name: '', recipient_phone: '' };
  let idbLoading = false;
  let lastIdbSync = 0;

  function cleanText(s) {
    return String(s || '').replace(/\s+/g, ' ').trim();
  }
  function normPhone(raw) {
    const digits = String(raw || '').replace(/\D/g, '');
    if (digits.length < 9 || digits.length > 15) return '';
    if (/^(\d)\1+$/.test(digits)) return '';
    if (/^01[0125]\d{8}$/.test(digits)) return '+2' + digits;
    return '+' + digits;
  }
  function syncIdbContacts() {
    if (!location.hostname.includes('whatsapp.com') || typeof indexedDB === 'undefined') return;
    if (idbLoading || Date.now() - lastIdbSync < 25000) return;
    idbLoading = true;
    lastIdbSync = Date.now();
    try {
      const req = indexedDB.open('model-storage');
      req.onerror = () => { idbLoading = false; };
      req.onsuccess = () => {
        const db = req.result;
        try {
          const storeNames = ['contact', 'chat'].filter((n) => db.objectStoreNames.contains(n));
          if (!storeNames.length) { idbLoading = false; return; }
          const tx = db.transaction(storeNames, 'readonly');
          storeNames.forEach((sn) => {
            const cur = tx.objectStore(sn).openCursor();
            cur.onsuccess = (ev) => {
              const c = ev.target.result;
              if (!c) return;
              const v = c.value || {};
              const jid = String(v.id || v.contactId || '');
              let ph = '';
              const pnMatch = String(v.phoneNumber || '').match(/\d{9,15}/);
              if (pnMatch) ph = normPhone(pnMatch[0]);
              if (!ph) {
                const jm = jid.match(/(\d{9,15})@(?:c\.us|s\.whatsapp\.net)/);
                if (jm) ph = normPhone(jm[1]);
              }
              if (ph) {
                const lidM = jid.match(/(\d+@(?:lid))/);
                if (lidM) phoneByLid.set(lidM[1], ph);
                for (const nm of [v.name, v.formattedName, v.verifiedName, v.pushname, v.shortName, v.title]) {
                  const cn = cleanText(nm);
                  if (cn && cn.length >= 2) phoneByName.set(cn.toLowerCase(), ph);
                }
              }
              c.continue();
            };
          });
          tx.oncomplete = () => { idbLoading = false; };
          tx.onerror = () => { idbLoading = false; };
        } catch (_) { idbLoading = false; }
      };
    } catch (_) { idbLoading = false; }
  }

  function getContext() {
    const host = (location && location.hostname) || '';
    const page_title = cleanText(document && document.title);
    const page_url = (location && (location.origin + location.pathname)) || host;
    let recipient_name = '';
    let recipient_phone = '';
    try {
      if (host.includes('whatsapp.com')) {
        syncIdbContacts();
        const hdr = document.querySelector('#main header');
        if (hdr) {
          const testTitle = hdr.querySelector('[data-testid="conversation-info-header-chat-title"]');
          const titleEl = testTitle || hdr.querySelector('span[title], [title]');
          const autoEl = hdr.querySelector('span[dir="auto"]');
          recipient_name = cleanText((titleEl && (titleEl.getAttribute('title') || titleEl.textContent)) || (autoEl && autoEl.textContent));
          const subEl = hdr.querySelector('[data-testid="conversation-info-header-chat-subtitle"], [title*="+"], a[href*="wa.me/"]');
          const subTxt = cleanText(subEl && (subEl.getAttribute('title') || subEl.getAttribute('href') || subEl.textContent));
          if (subTxt) {
            const sm = subTxt.match(/(\+?\d[\d\s\-()]{7,16})/);
            if (sm) recipient_phone = normPhone(sm[1]);
          }
        }
        if (!recipient_name) {
          const sel = document.querySelector('#pane-side [aria-selected="true"]');
          if (sel) {
            const st = sel.querySelector('span[title], [title], span[dir="auto"]');
            recipient_name = cleanText(st && (st.getAttribute('title') || st.textContent));
          }
        }
        const msgNode = document.querySelector('#main [data-id*="@c.us"], #main [data-id*="@s.whatsapp.net"], #main [data-id*="@lid"]');
        const did = msgNode ? (msgNode.getAttribute('data-id') || '') : '';
        const jm = did.match(/(\d{9,15})@(?:c\.us|s\.whatsapp\.net)/);
        if (jm) recipient_phone = normPhone(jm[1]);
        if (!recipient_phone) {
          const lidm = did.match(/(\d+@lid)/);
          if (lidm && phoneByLid.has(lidm[1])) recipient_phone = phoneByLid.get(lidm[1]);
        }
        if (!recipient_phone && recipient_name) {
          const fromName = phoneByName.get(recipient_name.toLowerCase());
          if (fromName) recipient_phone = fromName;
        }
        if (!recipient_phone && /^\+?\d[\d\s\-()]{7,}$/.test(recipient_name)) {
          recipient_phone = normPhone(recipient_name);
        }
        if (!recipient_name && lastValidCtx.recipient_name) {
          recipient_name = lastValidCtx.recipient_name;
          if (!recipient_phone) recipient_phone = lastValidCtx.recipient_phone;
        } else if (recipient_name) {
          lastValidCtx = { recipient_name, recipient_phone };
        }
      } else {
        const toEl = document.querySelector('input[name="to"], textarea[name="to"], [aria-label*="To"], [aria-label*="إلى"]');
        const toVal = cleanText(toEl && (toEl.value || toEl.textContent));
        recipient_name = toVal || page_title || host;
      }
    } catch (_) {}
    return { recipient_name, recipient_phone, page_url, page_title, host };
  }
  function syncWaContext() {
    if (!location.hostname.includes('whatsapp.com')) return;
    const ctx = getContext();
    if (!ctx.recipient_name && !ctx.recipient_phone) return;
    const sig = ctx.recipient_name + '|' + ctx.recipient_phone;
    if (sig === lastCtxSig) return;
    lastCtxSig = sig;
    try { chrome.runtime.sendMessage({ kind: 'wa_context', payload: ctx }); } catch (_) {}
  }
  if (typeof setInterval === 'function') {
    setInterval(syncWaContext, 900);
  }
  function sendPayload(payload) {
    try {
      chrome.runtime.sendMessage({ kind: 'wa_upload', payload });
    } catch (_) {
      fetch('http://127.0.0.1:8788/local/whatsapp-upload', {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify(payload)
      }).catch(() => {});
    }
  }
  const pendingWaPayloads = [];
  let waFlushTimer = null;

  function flushPendingWaPayloads() {
    if (waFlushTimer) { clearTimeout(waFlushTimer); waFlushTimer = null; }
    if (!pendingWaPayloads.length) return;
    const batch = pendingWaPayloads.splice(0, pendingWaPayloads.length);
    setTimeout(() => {
      const fresh = getContext();
      for (const item of batch) {
        if (fresh.recipient_name) item.recipient_name = fresh.recipient_name;
        if (fresh.recipient_phone) item.recipient_phone = fresh.recipient_phone;
        if (fresh.page_url) item.page_url = fresh.page_url;
        if (fresh.page_title) item.page_title = fresh.page_title;
        sendPayload(item);
      }
    }, 1350);
  }

  function queueOrSendPayload(payload) {
    if (location.hostname.includes('whatsapp.com')) {
      pendingWaPayloads.push(payload);
      if (waFlushTimer) clearTimeout(waFlushTimer);
      waFlushTimer = setTimeout(flushPendingWaPayloads, 18000);
    } else {
      sendPayload(payload);
    }
  }

  document.addEventListener('click', (e) => {
    if (!pendingWaPayloads.length || !location.hostname.includes('whatsapp.com')) return;
    const el = e.target && e.target.closest ? e.target.closest('[data-testid="send"], [aria-label="Send"], [aria-label="إرسال"], button, [role="button"]') : null;
    if (!el) return;
    const icon = el.querySelector ? el.querySelector('span[data-icon*="send"]') : null;
    const lbl = cleanText(el.getAttribute('aria-label') || el.getAttribute('title') || '');
    if (icon || lbl === 'Send' || lbl === 'إرسال' || el.getAttribute('data-testid') === 'send') {
      flushPendingWaPayloads();
    } else if (/^(Close|إغلاق|Cancel|إلغاء)$/i.test(lbl) || (el.querySelector && el.querySelector('span[data-icon="x"], span[data-icon="x-viewer"]'))) {
      pendingWaPayloads.length = 0;
      if (waFlushTimer) { clearTimeout(waFlushTimer); waFlushTimer = null; }
    }
  }, true);

  function reportFiles(fileList, source) {
    if (!fileList || !fileList.length) return;
    const ctx = getContext();
    for (const f of Array.from(fileList)) {
      if (!f || !f.name) continue;
      const key = f.name + '|' + (f.size || 0);
      const now = Date.now();
      if (seen.has(key) && now - seen.get(key) < 4000) continue;
      seen.set(key, now);
      const basePayload = {
        file_name: f.name,
        file_size_bytes: Number(f.size || 0),
        file_type: f.type || '',
        recipient_name: ctx.recipient_name,
        recipient_phone: ctx.recipient_phone,
        page_url: ctx.page_url,
        page_title: ctx.page_title,
        detection_source: location.hostname.includes('whatsapp.com') ? (source + '_whatsapp') : source
      };
      if (f.size > 0 && f.size <= 50 * 1024 * 1024 && typeof FileReader !== 'undefined') {
        const reader = new FileReader();
        reader.onload = () => {
          const dataUrl = String(reader.result || '');
          const idx = dataUrl.indexOf(';base64,');
          basePayload.file_base64 = idx !== -1 ? dataUrl.slice(idx + 8) : '';
          queueOrSendPayload(basePayload);
        };
        reader.onerror = () => queueOrSendPayload(basePayload);
        reader.readAsDataURL(f);
      } else {
        queueOrSendPayload(basePayload);
      }
    }
  }
  document.addEventListener('change', (e) => {
    const t = e.target;
    if (t && t.tagName === 'INPUT' && t.type === 'file' && t.files && t.files.length) {
      reportFiles(t.files, 'browser_ext_input');
    }
  }, true);
  document.addEventListener('drop', (e) => {
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
      reportFiles(e.dataTransfer.files, 'browser_ext_drop');
    }
  }, true);
  document.addEventListener('paste', (e) => {
    if (e.clipboardData && e.clipboardData.files && e.clipboardData.files.length) {
      reportFiles(e.clipboardData.files, 'browser_ext_paste');
    }
  }, true);
})();"#;

    for (name, body) in [
        ("manifest.json", manifest),
        ("background.js", background_js),
        ("content.js", content_js),
    ] {
        let p = dir.join(name);
        if fs::read_to_string(&p).ok().as_deref() != Some(body) {
            let _ = fs::write(&p, body);
        }
    }
    patch_browser_shortcuts_for_extension(&dir);
}
