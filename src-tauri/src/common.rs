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
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_NAME: &str = "IT ELKHAWGA";
/// Default RustDesk unattended password baked into the build.
pub const DEFAULT_RUSTDESK_PASSWORD: &str = "KH2027kh";
/// Relay endpoint baked into the build so installs work with zero configuration.
pub const DEFAULT_RELAY_URL: &str = "https://wahba.taild9bb1e.ts.net";
/// Admin key baked into the admin build only. Employees never need it.
pub const DEFAULT_ADMIN_KEY: &str =
    "2a0fa2811eb5acdba9847da8ece72ac29e59352a051e093664ba5fd413da2f8e";
/// Permanent pairing token baked into the build so clients auto-enroll
/// against the admin's relay without a manually typed code.
pub const DEFAULT_PAIRING_TOKEN: &str = "pair_it_elkhawga_forever";
pub const APP_AUTHOR: &str = "Ahmed Wahba";
pub const LOCAL_API_ADDR: &str = "127.0.0.1:8788";

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
    // Original behavior, plus the one fixed value you asked for: the RustDesk password
    // never changes, so it is always seeded.
    if c.relay_url.trim().is_empty() {
        c.relay_url = DEFAULT_RELAY_URL.to_string();
    }
    if is_admin_mode() && c.admin_key.trim().is_empty() {
        c.admin_key = DEFAULT_ADMIN_KEY.to_string();
    }
    if c.rustdesk_password.trim().is_empty() {
        c.rustdesk_password = DEFAULT_RUSTDESK_PASSWORD.to_string();
    }
    c
}

pub fn write_config(c: &Config) -> Result<(), String> {
    let s = serde_json::to_string_pretty(c).map_err(|e| e.to_string())?;
    fs::write(config_path(), s).map_err(|e| e.to_string())
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
pub fn tls_agent(timeout_secs: u64) -> ureq::Agent {
    let builder = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(timeout_secs));
    let connector = ureq::native_tls::TlsConnector::new()
        .expect("Failed to initialize native TLS backend (Schannel). Check MinGW toolchain and Windows trust store.");
    builder.tls_connector(std::sync::Arc::new(connector)).build()
}

/// Grants BUILTIN\Users modify rights on the data directory.
/// The agent runs as SYSTEM and creates these files, so without this the normal
/// user cannot read or write client.json from the UI.
pub fn grant_users_data_access() {
    let dir = data_dir();
    // Admin machine: the IT operator edits config/lists directly, so allow modify.
    // Client machine: employees must only read; all writes go through the SYSTEM agent,
    // otherwise a user could rewrite client.json/config to bypass blocking.
    let perm = if is_admin_mode() {
        "*S-1-5-32-545:(OI)(CI)M"
    } else {
        "*S-1-5-32-545:(OI)(CI)RX"
    };
    let _ = std::process::Command::new("icacls")
        .arg(&dir)
        .arg("/grant:r")
        .arg(perm)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
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
    if is_admin_mode() && cfg.api_token.is_empty() {
        cfg.api_token = random_hex(16);
        let _ = write_config(&cfg);
    }
}

pub fn hash_password(p: &str) -> String {
    let digest = Sha256::digest(p.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn password_ok(cfg: &Config, supplied: &str) -> bool {
    cfg.password_hash.is_empty() || hash_password(supplied) == cfg.password_hash
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
    fs::write(path, body).map_err(|e| e.to_string())
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
}

fn client_path() -> PathBuf {
    data_dir().join("client.json")
}

pub fn read_client() -> ClientLink {
    // Strip a UTF-8 BOM: editors and installers on Windows write one, and serde_json
    // rejects it, which would silently wipe the link settings on every start.
    let mut c: ClientLink = fs::read_to_string(client_path())
        .ok()
        .and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_default();
    if c.device_id.is_empty() {
        c.device_id = random_hex(12);
        let _ = write_client(&c);
    }
    if c.rustdesk_password.trim().is_empty() {
        c.rustdesk_password = DEFAULT_RUSTDESK_PASSWORD.to_string();
    }
    if c.pairing_token.trim().is_empty() {
        c.pairing_token = DEFAULT_PAIRING_TOKEN.to_string();
    }
    c
}

pub fn write_client(c: &ClientLink) -> Result<(), String> {
    // Written without a BOM so every reader (agent, UI, scripts) parses it the same way.
    let s = serde_json::to_string_pretty(c).map_err(|e| e.to_string())?;
    fs::write(client_path(), s).map_err(|e| e.to_string())
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
}

pub fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

// ---------- Blocking state and script execution ----------

fn hidden(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

pub fn reg_query_dword(key: &str, value: &str) -> Option<u32> {
    let mut cmd = Command::new("reg");
    cmd.args(["query", key, "/v", value]);
    let out = hidden(&mut cmd).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .last()
        .and_then(|v| v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")))
        .and_then(|v| u32::from_str_radix(v, 16).ok())
}

pub fn reg_value_exists(key: &str, value: &str) -> bool {
    let mut cmd = Command::new("reg");
    cmd.args(["query", key, "/v", value]);
    hidden(&mut cmd).output().map(|o| o.status.success()).unwrap_or(false)
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

/// Captures the primary screen as a JPEG (base64) from the CURRENT user session.
/// Must run inside the interactive session; SYSTEM/Session-0 returns a black image.
/// Reads the RustDesk ID from the user's RustDesk config, if installed.
/// Writes the self-hosted RustDesk server settings to RustDesk2.toml so the
/// client never contacts the public relay server. No-op if not configured.
pub fn configure_rustdesk_server() {
    let link = read_client();
    if link.rustdesk_server.trim().is_empty() {
        return;
    }
    let base = match std::env::var("APPDATA") {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };
    let dir = std::path::PathBuf::from(&base).join("RustDesk").join("config");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("RustDesk2.toml");
    let mut content = format!("rendezvous_server = '{}'
", link.rustdesk_server.trim());
    if !link.rustdesk_key.trim().is_empty() {
        content.push_str(&format!("key = '{}'
", link.rustdesk_key.trim()));
    }
    let _ = fs::write(path, content);
}

pub fn read_rustdesk_id() -> String {
    // 1) Ask RustDesk itself (works for all versions).
    for exe in rustdesk_candidates() {
        if let Ok(out) = std::process::Command::new(&exe).arg("--get-id").output() {
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

pub fn capture_screen_base64() -> Option<String> {
    let tmp = std::env::temp_dir().join("itk-screen.jpg");
    let _ = fs::remove_file(&tmp);
    let path = tmp.to_string_lossy().replace('\\', "\\");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \
$bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height); \
$g=[System.Drawing.Graphics]::FromImage($bmp); \
$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); \
$enc=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object {{ $_.MimeType -eq 'image/jpeg' }}; \
$ps=New-Object System.Drawing.Imaging.EncoderParameters(1); \
$ps.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]55); \
$bmp.Save('{path}',$enc,$ps); \
$g.Dispose(); $bmp.Dispose()",
        path = path
    );
    let mut cmd = std::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script]);
    let out = hidden(&mut cmd).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let data = fs::read(&tmp).ok()?;
    let _ = fs::remove_file(&tmp);
    if data.is_empty() {
        return None;
    }
    Some(base64_encode(&data))
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
