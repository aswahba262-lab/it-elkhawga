use crate::common::*;
use crate::transport::{RelayClient, RelayPollOutcome, Transport, lan_poll, lan_upload_file, lan_upload_screen_frame};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server};

const POLL_SECONDS: u64 = 4;

static SCREEN_WANTED: AtomicBool = AtomicBool::new(false);
static STREAM_MODE: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
static STREAM_UNTIL_MS: AtomicU64 = AtomicU64::new(0);
static CAPTURE_STREAM_MODE: AtomicU8 = AtomicU8::new(0);
static CAPTURE_STREAM_UNTIL_MS: AtomicU64 = AtomicU64::new(0);
static UPDATE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static EVIDENCE_WANTED: AtomicBool = AtomicBool::new(false);
static LAST_CAPTURE_POLL_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LAST_TAMPER_CHECK_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LAST_TAMPER_ALERT_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ALERT_QUEUE: std::sync::Mutex<std::collections::VecDeque<Value>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());
static EVIDENCE_STORE: std::sync::Mutex<Option<(Option<String>, Option<String>, String, String, String, Instant)>> =
    std::sync::Mutex::new(None);
static LAST_WA_CONTEXT: std::sync::Mutex<Option<(String, String, String, Instant)>> =
    std::sync::Mutex::new(None);
static RECENT_EXT_UPLOADS: std::sync::Mutex<Vec<(String, Instant)>> =
    std::sync::Mutex::new(Vec::new());
static CCTV_TASKS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
static CCTV_CGI_QUEUE: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
static CCTV_SCAN_WANTED: AtomicBool = AtomicBool::new(false);
static CCTV_SCAN_BUSY: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, Default)]
struct CctvAudioBridgeSpec {
    dvr_id: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    channel: u32,
    until_ms: u64,
}

static CCTV_AUDIO_SPEC: std::sync::Mutex<Option<CctvAudioBridgeSpec>> = std::sync::Mutex::new(None);

fn sync_cctv_tasks_from_value(val: Option<&Value>) {
    let now_t = epoch_ms();
    let mut g = CCTV_TASKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(arr) = val.and_then(|v| v.as_array()) {
        // Normalize server timestamps into client-local deadlines (`ttl_ms`) so clock skew between
        // Server and Branch PCs never causes premature expiry or stuck leases!
        let mut normalized: Vec<Value> = Vec::with_capacity(arr.len());
        for raw_t in arr {
            let mut item = raw_t.clone();
            let ttl = item["ttl_ms"].as_u64().unwrap_or(12_000).clamp(1500, 30_000);
            item["local_until"] = json!(now_t + ttl);
            let a_ttl = item["audio_ttl_ms"].as_u64().unwrap_or(0);
            if a_ttl > 0 {
                item["local_audio_until"] = json!(now_t + a_ttl.clamp(1500, 20_000));
            } else {
                item["local_audio_until"] = json!(0);
            }
            normalized.push(item);
        }
        *g = normalized;
    } else {
        g.clear();
    }
    let mut next_audio: Option<CctvAudioBridgeSpec> = None;
    for t in g.iter() {
        let ch = t["audio_channel"].as_u64().unwrap_or(0) as u32;
        let a_until = t["local_audio_until"]
            .as_u64()
            .filter(|&u| u > 0)
            .or_else(|| t["audio_until"].as_u64())
            .unwrap_or(0);
        if ch > 0 && a_until > now_t {
            let dvr_id = t["dvr_id"].as_str().unwrap_or("").trim().to_string();
            let host = t["host"].as_str().unwrap_or("").trim().to_string();
            if !dvr_id.is_empty() && !host.is_empty() {
                next_audio = Some(CctvAudioBridgeSpec {
                    dvr_id,
                    host,
                    port: t["http_port"].as_u64().unwrap_or(80) as u16,
                    username: t["username"].as_str().unwrap_or("admin").to_string(),
                    password: t["password"].as_str().unwrap_or("").to_string(),
                    channel: ch,
                    until_ms: a_until,
                });
                break;
            }
        }
    }
    drop(g);
    let mut ag = CCTV_AUDIO_SPEC.lock().unwrap_or_else(|e| e.into_inner());
    *ag = next_audio;
}

fn enqueue_cctv_cgi_jobs(val: Option<&Value>) {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return;
    };
    if arr.is_empty() {
        return;
    }
    let mut q = CCTV_CGI_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    for job in arr {
        let jid = job["job_id"].as_str().unwrap_or("");
        if !jid.is_empty() && !q.iter().any(|x| x["job_id"].as_str() == Some(jid)) {
            if q.len() < 24 {
                q.push(job.clone());
            }
        }
    }
}

pub fn enqueue_client_alert(alert: Value) {
    if alert.is_null() {
        return;
    }
    let mut q = ALERT_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    if q.len() >= 30 {
        q.pop_front();
    }
    q.push_back(alert);
}

fn spawn_security_alert(alert_type: &'static str, severity: &'static str, message: String) {
    std::thread::spawn(move || {
        let win_user = std::env::var("USERNAME").unwrap_or_default();
        let mut meta = json!({ "windows_user": win_user });
        if let Some((sc, cam, _rn, _rp, pu)) = request_agent_evidence(2200) {
            if let Some(s) = sc {
                meta["screenshot"] = json!(s);
            }
            if let Some(c) = cam {
                meta["camera_photo"] = json!(c);
            }
            if !pu.is_empty() {
                meta["page_url"] = json!(pu);
            }
        }
        enqueue_client_alert(json!({
            "type": alert_type,
            "severity": severity,
            "message": message,
            "meta": meta,
        }));
    });
}

fn clean_wa_title_recipient(title: &str) -> String {
    let mut t: String = title
        .chars()
        .filter(|&c| c != '\u{200b}' && c != '\u{200e}' && c != '\u{200f}' && c != '\u{feff}')
        .collect::<String>()
        .trim()
        .to_string();
    for suffix in [
        " - Google Chrome",
        " - Microsoft Edge",
        " — Mozilla Firefox",
        " - Brave",
        " - Opera",
    ] {
        if let Some(stripped) = t.strip_suffix(suffix) {
            t = stripped.trim().to_string();
        }
    }
    // Strip Edge profile tags like " - Profile 1" or " - Personal" or " - Work"
    for prof in [" - Personal", " - Work", " - العمل", " - شخصي"] {
        if let Some(stripped) = t.strip_suffix(prof) {
            t = stripped.trim().to_string();
        }
    }
    if let Some(idx) = t.rfind(" - Profile ") {
        if t[idx + 11..].chars().all(|c| c.is_ascii_digit()) {
            t = t[..idx].trim().to_string();
        }
    }
    // Strip Edge multi-tab suffix " and N more page(s)"
    if let Some(idx) = t.rfind(" and ") {
        let rest = &t[idx + 5..];
        if rest.ends_with(" more page") || rest.ends_with(" more pages") {
            t = t[..idx].trim().to_string();
        }
    }
    if t.starts_with('(') {
        if let Some(pos) = t.find(") ") {
            t = t[pos + 2..].trim().to_string();
        }
    }
    let lower = t.to_ascii_lowercase();
    if lower == "whatsapp"
        || lower == "whatsapp web"
        || lower == "html5"
        || lower == "web area"
        || lower == "new tab"
        || lower == "open"
        || lower == "save as"
        || lower == "choose file"
        || lower == "file upload"
        || lower.contains("it elkhawga")
        || t == "واتساب"
        || t == "تبويب جديد"
        || t == "علامة تبويب جديدة"
        || t == "فتح"
        || t == "حفظ باسم"
        || t.starts_with("موقع محظور")
    {
        String::new()
    } else {
        t
    }
}

fn is_title_whatsapp(title: &str) -> bool {
    let lc = title.to_ascii_lowercase();
    (lc.contains("whatsapp") || title.contains("واتساب")) && !lc.contains("it elkhawga")
}

fn is_company_erp_url_or_title(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lc = trimmed.to_ascii_lowercase();
    if lc.contains("elkhawaga.uk")
        || lc.contains("10.10.1.1")
        || trimmed.contains("نظام الخواجه")
        || trimmed.contains("طابور الاعتماد")
        || trimmed.contains("الخواجه")
    {
        return true;
    }
    let cfg = read_config();
    cfg.erp_domains.iter().any(|d| {
        let clean = d.trim().to_ascii_lowercase();
        !clean.is_empty() && lc.contains(&clean)
    })
}

fn is_noise_recipient_label(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    let lc = t.to_ascii_lowercase();
    matches!(
        lc.as_str(),
        "html5"
            | "web area"
            | "rootwebarea"
            | "whatsapp"
            | "whatsapp web"
            | "new tab"
            | "open"
            | "choose file"
            | "save as"
            | "google chrome"
            | "microsoft edge"
            | "brave"
    ) || matches!(
        t,
        "واتساب" | "فتح" | "تبويب جديد" | "علامة تبويب جديدة" | "إرسال" | "إغلاق"
    ) || t.starts_with("موقع محظور")
}

fn capture_upload_target_screen(
    win: &crate::common::UploadWindowState,
    is_wa: bool,
    last_clean_wa_shot: &Option<(String, Instant)>,
) -> Option<String> {
    if is_wa && win.wa_hwnd != 0 {
        if let Some(img) = crate::common::capture_window_base64(win.wa_hwnd, 1366) {
            return Some(img);
        }
    }
    if win.browser_hwnd != 0 && (win.fg_is_browser || !is_wa) {
        if let Some(img) = crate::common::capture_window_base64(win.browser_hwnd, 1366) {
            return Some(img);
        }
    }
    if is_wa && !win.fg_is_wa {
        if let Some((img, ts)) = last_clean_wa_shot {
            if ts.elapsed() <= Duration::from_secs(60) {
                return Some(img.clone());
            }
        }
    }
    crate::common::capture_screen_scaled_base64(1366).or_else(capture_screen_base64)
}

fn request_agent_evidence(timeout_ms: u64) -> Option<(Option<String>, Option<String>, String, String, String)> {
    if is_admin_mode() {
        return None;
    }
    let last_poll = LAST_CAPTURE_POLL_SECS.load(Ordering::Relaxed);
    if epoch_secs().saturating_sub(last_poll) > 6 {
        return None;
    }
    {
        let mut g = EVIDENCE_STORE.lock().unwrap_or_else(|e| e.into_inner());
        *g = None;
    }
    EVIDENCE_WANTED.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let max_wait = Duration::from_millis(timeout_ms);
    while started.elapsed() < max_wait {
        std::thread::sleep(Duration::from_millis(90));
        let found = {
            let mut g = EVIDENCE_STORE.lock().unwrap_or_else(|e| e.into_inner());
            g.take()
        };
        if let Some((sc, cam, rn, rp, pu, _)) = found {
            EVIDENCE_WANTED.store(false, Ordering::SeqCst);
            return Some((sc, cam, rn, rp, pu));
        }
    }
    EVIDENCE_WANTED.store(false, Ordering::SeqCst);
    None
}

fn send_whatsapp_upload_report(
    file_name: &str,
    file_size_bytes: u64,
    file_path: &str,
    staged_path: Option<&str>,
    recipient_hint: &str,
    recipient_phone: &str,
    page_url: &str,
    detection_source: &str,
    screenshot: Option<&str>,
    camera_photo: Option<&str>,
    file_base64: Option<&str>,
) {
    let win_user = std::env::var("USERNAME").unwrap_or_default();
    let size_text = if file_size_bytes > 0 {
        format_file_size(file_size_bytes)
    } else {
        "غير محدد".to_string()
    };
    let mut payload = json!({
        "file_name": file_name,
        "file_size_bytes": file_size_bytes,
        "file_size": size_text,
        "file_path": file_path,
        "staged_path": staged_path.unwrap_or(""),
        "recipient_name": recipient_hint,
        "recipient_phone": recipient_phone,
        "page_url": page_url,
        "windows_user": win_user,
        "detection_source": detection_source,
    });
    if let Some(img) = screenshot {
        payload["screenshot"] = json!(img);
    }
    if let Some(cam) = camera_photo {
        payload["camera_photo"] = json!(cam);
    }
    if let Some(b64) = file_base64 {
        payload["file_base64"] = json!(b64);
    }
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(60)).build();
    let _ = agent
        .post(&format!("http://{}/local/whatsapp-upload", LOCAL_API_ADDR))
        .send_json(payload);
}

fn read_exact_file_bytes(path_str: &str, max_bytes: u64) -> Option<Vec<u8>> {
    let p = std::path::Path::new(path_str.trim());
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > max_bytes {
        return None;
    }
    std::fs::read(p).ok()
}

fn save_and_upload_dlp_file(
    file_name: &str,
    file_path: &str,
    staged_path: &str,
    file_base64_opt: Option<&str>,
    channel: &str,
    recipient_name: &str,
    recipient_phone: &str,
    page_url: &str,
    windows_user: &str,
) -> Option<(String, String)> {
    use sha2::{Digest, Sha256};
    const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
    let raw_bytes: Vec<u8> = if let Some(b64) = file_base64_opt.filter(|s| !s.trim().is_empty()) {
        base64_decode(b64)?
    } else if !staged_path.trim().is_empty() {
        read_exact_file_bytes(staged_path, MAX_FILE_BYTES as u64)
            .or_else(|| read_exact_file_bytes(file_path, MAX_FILE_BYTES as u64))?
    } else if !file_path.trim().is_empty() {
        read_exact_file_bytes(file_path, MAX_FILE_BYTES as u64)?
    } else if let Some(recent_p) = crate::common::find_recent_user_file(25) {
        read_exact_file_bytes(&recent_p.to_string_lossy(), MAX_FILE_BYTES as u64)?
    } else {
        return None;
    };
    if raw_bytes.is_empty() || raw_bytes.len() > MAX_FILE_BYTES {
        return None;
    }

    let sha256_hex: String = Sha256::digest(&raw_bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let file_id = format!("upl_{}", random_hex(12));
    let safe_name: String = file_name
        .trim()
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0'..='\x1f' => '_',
            _ => c,
        })
        .take(120)
        .collect();
    let final_name = if safe_name.is_empty() { "file.bin".to_string() } else { safe_name };
    let dir = data_dir().join("uploaded-files");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join(format!("{}__{}", file_id, final_name)), &raw_bytes);

    let b64 = base64_encode(&raw_bytes);
    let link = read_client();
    let payload = json!({
        "file_id": file_id,
        "device_id": link.device_id,
        "hostname": hostname(),
        "windows_user": windows_user,
        "channel": channel,
        "file_name": file_name,
        "file_size_bytes": raw_bytes.len(),
        "sha256": sha256_hex,
        "recipient_name": recipient_name,
        "recipient_phone": recipient_phone,
        "page_url": page_url,
        "file_base64": b64,
    });
    std::thread::spawn(move || {
        let transport = Transport::from_link(&link);
        if matches!(transport, Transport::Lan) && !link.server_url.trim().is_empty() {
            let http = tls_agent(180);
            let _ = lan_upload_file(&http, &link, &payload);
        }
        if !link.relay_url.trim().is_empty() && !link.device_token.trim().is_empty() {
            let relay = RelayClient::new();
            let _ = relay.upload_file(&link.relay_url, &link.device_token, &payload);
        } else if !matches!(transport, Transport::Lan) && !link.server_url.trim().is_empty() {
            let http = tls_agent(180);
            let _ = lan_upload_file(&http, &link, &payload);
        }
    });
    Some((file_id, sha256_hex))
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn staging_dir() -> std::path::PathBuf {
    data_dir().join("uploaded-files-staging")
}

/// Copies a candidate file in the user's own session before it can be moved, deleted,
/// or locked (or when it lives on USB/network/OneDrive paths inaccessible to SYSTEM).
fn stage_user_session_file(src: &std::path::Path) -> Option<std::path::PathBuf> {
    const MAX_STAGE_BYTES: u64 = 64 * 1024 * 1024;
    let meta = std::fs::metadata(src).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_STAGE_BYTES {
        return None;
    }
    let dir = staging_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut count = 0usize;
        for ent in entries.flatten() {
            count += 1;
            let p = ent.path();
            let expired = ent
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map_or(false, |age| age > Duration::from_secs(900));
            if expired || count > 24 {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    let orig_name = src.file_name().and_then(|n| n.to_str()).unwrap_or("file.bin");
    let safe_name: String = orig_name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0'..='\x1f' => '_',
            _ => c,
        })
        .take(100)
        .collect();
    let dst = dir.join(format!("stg_{}__{}", epoch_ms(), safe_name));
    std::fs::copy(src, &dst).ok()?;
    Some(dst)
}

/// Entry point of `it-elkhawga.exe --capture-agent`. Runs inside the logged-in employee's
/// interactive desktop session so GDI captures the real desktop (SYSTEM/Session-0 cannot).
pub fn run_capture_agent() {
    // Single-instance guard: if another capture-agent is already running in this session, exit.
    let _single_instance = match std::net::TcpListener::bind("127.0.0.1:8789") {
        Ok(l) => l,
        Err(_) => return,
    };

    // Apply self-hosted RustDesk server settings (if configured) so clients
    // never touch the public relay server.
    configure_rustdesk_server();
    crate::common::ensure_rustdesk_stealth_config();
    crate::common::start_rustdesk_stealth_guard();
    crate::common::ensure_whatsapp_web_extension();

    // Dedicated continuous stream pusher (~4-5 FPS screen or live webcam) so DLP monitoring
    // and UI polling never stall live frame delivery.
    std::thread::spawn(|| {
        let post_agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build();
        loop {
            let now_t = epoch_ms();
            let mode = CAPTURE_STREAM_MODE.load(Ordering::Relaxed);
            let until = CAPTURE_STREAM_UNTIL_MS.load(Ordering::Relaxed);
            if mode == 0 || now_t >= until {
                CAPTURE_STREAM_MODE.store(0, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(120));
                continue;
            }
            if mode == 1 {
                if let Some(img) = crate::common::capture_screen_scaled_base64(960) {
                    let _ = post_agent
                        .post(&format!("http://{}/local/screenshot", LOCAL_API_ADDR))
                        .send_json(json!({"image": img, "kind": "screen", "error": ""}));
                }
                std::thread::sleep(Duration::from_millis(160));
            } else if mode == 2 {
                let mut had_err = false;
                crate::common::run_webcam_stream_loop(
                    || {
                        CAPTURE_STREAM_MODE.load(Ordering::Relaxed) == 2
                            && epoch_ms() < CAPTURE_STREAM_UNTIL_MS.load(Ordering::Relaxed)
                    },
                    |res| match res {
                        Ok(img) => {
                            let _ = post_agent
                                .post(&format!("http://{}/local/screenshot", LOCAL_API_ADDR))
                                .send_json(json!({"image": img, "kind": "camera", "error": ""}));
                        }
                        Err(err_code) => {
                            had_err = true;
                            let _ = post_agent
                                .post(&format!("http://{}/local/screenshot", LOCAL_API_ADDR))
                                .send_json(json!({"image": "", "kind": "camera", "error": err_code}));
                        }
                    },
                );
                if had_err {
                    std::thread::sleep(Duration::from_millis(1200));
                }
            }
        }
    });
    // Set a permanent password for unattended access (no approval prompt).
    // Re-applied when it changes, retried every minute until it succeeds (e.g. RustDesk
    // installed after the agent started), and re-enforced every 10 minutes in case it
    // was changed locally on the device.
    let mut last_pw = String::new();
    let mut last_rd_srv = read_client().rustdesk_server;
    let mut last_rd_key = read_client().rustdesk_key;
    let mut last_try: Option<std::time::Instant> = None;
    let mut last_ok: Option<std::time::Instant> = None;
    let mut cached_rd_id = String::new();
    let mut last_rd_check: Option<std::time::Instant> = None;
    let mut last_rd_report: Option<std::time::Instant> = None;
    let mut last_agent_wake: Option<std::time::Instant> = None;
    let mut last_mru_map: HashMap<String, (u64, std::path::PathBuf)> =
        crate::common::scan_comdlg_mru_entries()
            .into_iter()
            .map(|(k, ts, p)| (k, (ts, p)))
            .collect();
    let mut last_clip_seq = crate::common::clipboard_sequence_number();
    let mut last_explorer_path: Option<std::path::PathBuf> = None;
    let mut recent_candidate_file: Option<(std::path::PathBuf, Option<std::path::PathBuf>, u64, String, Instant)> = None;
    let mut was_browser_dialog_open = false;
    let mut last_dialog_open_at: Option<Instant> = None;
    let mut last_wa_alert: Option<(String, Instant)> = None;
    let mut last_ctx_poll: Option<Instant> = None;
    let mut last_clean_wa_shot: Option<(String, Instant)> = None;
    let mut cached_ctx: (String, String, String, Instant) =
        (String::new(), String::new(), String::new(), Instant::now());
    let mut cached_wa_ctx: (String, String, Instant) =
        (String::new(), String::new(), Instant::now());
    let mut last_explorer_poll: Option<Instant> = None;
    // Pending WhatsApp File-Dialog attachment waiting for the employee to press Send:
    // (orig_path, staged_path, file_size, pre_recipient, pre_phone, attached_at, saw_preview, last_uia_poll, send_ready_at)
    let mut pending_wa_dialog: Option<(
        std::path::PathBuf,
        Option<std::path::PathBuf>,
        u64,
        String,
        String,
        Instant,
        bool,
        Instant,
        Option<Instant>,
    )> = None;
    let local_http = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
    let mut prev_dialog_seen = false;
    let mut cached_link = read_client();
    let mut last_link_read = Instant::now();
    loop {
        if last_link_read.elapsed() >= Duration::from_secs(5) {
            cached_link = read_client();
            last_link_read = Instant::now();
        }
        let link = &cached_link;
        if link.rustdesk_server != last_rd_srv || link.rustdesk_key != last_rd_key {
            last_rd_srv = link.rustdesk_server.clone();
            last_rd_key = link.rustdesk_key.clone();
            configure_rustdesk_server();
            cached_rd_id.clear();
            last_rd_check = None;
        }
        let pw = link.rustdesk_password.trim().to_string();
        if !pw.is_empty() {
            let changed = pw != last_pw;
            let retry_due = last_ok.is_none() && last_try.map_or(true, |t| t.elapsed() >= Duration::from_secs(60));
            let enforce_due = last_ok.map_or(false, |t| t.elapsed() >= Duration::from_secs(600));
            if changed || retry_due || enforce_due {
                last_try = Some(std::time::Instant::now());
                let ok = crate::common::apply_rustdesk_permanent_password(&pw);
                if ok && (changed || last_ok.is_none()) {
                    log_action("RustDesk permanent password applied (unattended access)");
                }
                // Remember it either way: a failure is retried by `retry_due` once a minute.
                last_pw = pw;
                last_ok = if ok { Some(std::time::Instant::now()) } else { None };
            }
        }
        // Report the RustDesk ID (cached, re-checked at most once every 60s when missing)
        // so we do not spawn external binaries every second.
        if cached_rd_id.is_empty() && last_rd_check.map_or(true, |t| t.elapsed() >= Duration::from_secs(60)) {
            last_rd_check = Some(std::time::Instant::now());
            let rd_id = read_rustdesk_id();
            if !rd_id.is_empty() {
                cached_rd_id = rd_id;
                last_rd_report = None;
            }
        }
        if !cached_rd_id.is_empty() && last_rd_report.map_or(true, |t| t.elapsed() >= Duration::from_secs(30)) {
            if local_http
                .post(&format!("http://{}/local/rustdesk", LOCAL_API_ADDR))
                .send_json(json!({"rustdesk_id": cached_rd_id}))
                .is_ok()
            {
                last_rd_report = Some(std::time::Instant::now());
            }
        }

        let probe_wins = crate::common::inspect_upload_windows_ext();
        let (requested, stream_mode, evidence_wanted, wa_active, wa_proxy_upload, recent_ext_file) = match local_http
            .get(&format!(
                "http://{}/local/screenshot?cw={}&ew={}",
                LOCAL_API_ADDR,
                if probe_wins.chrome_win_open { 1 } else { 0 },
                if probe_wins.edge_win_open { 1 } else { 0 }
            ))
            .call()
        {
            Ok(r) => match r.into_json::<Value>() {
                Ok(v) => {
                    let req_flag = v["requested"].as_bool().unwrap_or(false);
                    let st_mode = v["stream_mode"].as_str().unwrap_or("").trim().to_ascii_lowercase();
                    let ev_flag = v["evidence_wanted"].as_bool().unwrap_or(false);
                    let wa_act = v["wa_active"].as_bool().unwrap_or(false);
                    let proxy_up = v.get("wa_proxy_upload").filter(|p| p.is_object()).map(|p| {
                        (
                            p["host"].as_str().unwrap_or("mmg.whatsapp.net").to_string(),
                            p["bytes"].as_u64().unwrap_or(0),
                        )
                    });
                    let ext_recent = v["recent_ext_file"].as_str().unwrap_or("").to_string();
                    (req_flag, st_mode, ev_flag, wa_act, proxy_up, ext_recent)
                }
                Err(_) => (false, String::new(), false, false, None, String::new()),
            },
            Err(_) => {
                // Watchdog: if --agent (127.0.0.1:8788) is not running after reboot, wake it up.
                if last_agent_wake.map_or(true, |t| t.elapsed() >= Duration::from_secs(10)) {
                    last_agent_wake = Some(std::time::Instant::now());
                    let mut sc = std::process::Command::new("schtasks");
                    sc.args(["/Run", "/TN", "IT ELKHAWGA Agent"]);
                    let _ = crate::common::hidden(&mut sc).output();
                    if let Ok(exe) = std::env::current_exe() {
                        let mut c = std::process::Command::new(&exe);
                        c.arg("--agent");
                        let _ = crate::common::hidden(&mut c).spawn();
                    }
                }
                (false, String::new(), false, false, None, String::new())
            }
        };

        let mode_code: u8 = match stream_mode.as_str() {
            "screen" => 1,
            "camera" => 2,
            _ => 0,
        };
        if mode_code != 0 {
            CAPTURE_STREAM_UNTIL_MS.store(epoch_ms() + 12_000, Ordering::Relaxed);
        } else {
            CAPTURE_STREAM_UNTIL_MS.store(0, Ordering::Relaxed);
        }
        CAPTURE_STREAM_MODE.store(mode_code, Ordering::Relaxed);

        let mut captured_now: Option<String> = None;
        if requested && mode_code == 0 {
            if let Some(img) = crate::common::capture_screen_scaled_base64(1280).or_else(capture_screen_base64) {
                captured_now = Some(img.clone());
                let upload_agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
                let _ = upload_agent
                    .post(&format!("http://{}/local/screenshot", LOCAL_API_ADDR))
                    .send_json(json!({"image": img}));
            }
        }
        if evidence_wanted {
            // Wait briefly if a File Open dialog is still closing, then settle so the
            // actual WhatsApp/browser window renders instead of File Explorer.
            let wait_start = Instant::now();
            while wait_start.elapsed() < Duration::from_millis(600) {
                let w = crate::common::inspect_upload_windows_ext();
                if !w.browser_open_dialog && !w.any_open_dialog {
                    break;
                }
                std::thread::sleep(Duration::from_millis(120));
            }
            std::thread::sleep(Duration::from_millis(250));
            let win_ev = crate::common::inspect_upload_windows_ext();
            let is_wa_ev = win_ev.wa_open || wa_active || win_ev.fg_is_wa;
            let shot = capture_upload_target_screen(&win_ev, is_wa_ev, &last_clean_wa_shot)
                .or_else(|| captured_now.clone());
            // Never grab the physical USB webcam during background DLP/tamper evidence capture
            // so the employee's browser camera is always free for ERP QR-Code login (elkhawaga.uk).
            let cam: Option<String> = None;
            let (mut recip_q, mut phone_q, mut site_q, _) =
                crate::common::query_active_upload_context(false);
            if recip_q.is_empty() && cached_ctx.3.elapsed() <= Duration::from_secs(120) {
                recip_q = cached_ctx.0.clone();
                if phone_q.is_empty() {
                    phone_q = cached_ctx.1.clone();
                }
            }
            if recip_q.is_empty() {
                recip_q = clean_wa_title_recipient(&win_ev.best_title);
            }
            if site_q.is_empty() {
                site_q = if !cached_ctx.2.is_empty() {
                    cached_ctx.2.clone()
                } else {
                    win_ev.best_title.clone()
                };
            }
            if phone_q.is_empty() && !recip_q.is_empty() && is_wa_ev {
                if let Some(p) = crate::common::lookup_whatsapp_phone_by_name(&recip_q) {
                    phone_q = p;
                }
            }
            let ev_agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build();
            let _ = ev_agent
                .post(&format!("http://{}/local/evidence", LOCAL_API_ADDR))
                .send_json(json!({
                    "screenshot": shot.unwrap_or_default(),
                    "camera_photo": cam.unwrap_or_default(),
                    "recipient_name": recip_q,
                    "recipient_phone": phone_q,
                    "page_url": site_q,
                }));
        }

        let mut fast_dialog_poll = false;
        if !is_admin_mode() {
            let win = probe_wins;
            fast_dialog_poll = win.browser_open_dialog || win.any_open_dialog;
            let dialog_just_opened = !prev_dialog_seen && win.browser_open_dialog;
            prev_dialog_seen = win.browser_open_dialog;

            let prev_browser_dialog = was_browser_dialog_open && !win.browser_open_dialog;
            if win.save_dialog {
                was_browser_dialog_open = false;
            } else if win.browser_open_dialog {
                was_browser_dialog_open = true;
                last_dialog_open_at = Some(Instant::now());
            } else if last_dialog_open_at.map_or(true, |t| t.elapsed() >= Duration::from_secs(16)) {
                was_browser_dialog_open = false;
            }

            let _ = &mut last_explorer_poll;
            // Lightweight zero-PowerShell, zero-GDI, zero-disk context tracking during normal browsing:
            if (win.browser_open || win.wa_open)
                && last_ctx_poll.map_or(true, |t| t.elapsed() >= Duration::from_millis(3500))
            {
                last_ctx_poll = Some(Instant::now());
                let rc = clean_wa_title_recipient(&win.best_title);
                let ph = normalize_extracted_phone(&rc);
                let title_is_wa = is_title_whatsapp(&win.best_title);
                if (win.fg_is_wa || title_is_wa) && !is_noise_recipient_label(&rc) {
                    let keep_ph = if !ph.is_empty() {
                        ph.clone()
                    } else if cached_wa_ctx.0 == rc {
                        cached_wa_ctx.1.clone()
                    } else {
                        String::new()
                    };
                    cached_wa_ctx = (rc.clone(), keep_ph, Instant::now());
                }
                let st = win.best_title.trim().to_string();
                if (!is_noise_recipient_label(&rc) || !ph.is_empty() || !st.is_empty())
                    && st != "Open"
                    && st != "فتح"
                {
                    cached_ctx = (
                        if !is_noise_recipient_label(&rc) { rc } else { cached_ctx.0.clone() },
                        if !ph.is_empty() { ph } else { cached_ctx.1.clone() },
                        if !st.is_empty() { st } else { cached_ctx.2.clone() },
                        Instant::now(),
                    );
                }
            }

            if dialog_just_opened {
                let (rc, mut ph, st, exp_files, _) = crate::common::query_active_upload_context_ext(false);
                let dialog_for_wa = win.wa_open && (win.fg_is_wa || is_title_whatsapp(&st) || st.to_ascii_lowercase().contains("whatsapp"));
                if dialog_for_wa && win.wa_hwnd != 0 {
                    if let Some(clean_img) = crate::common::capture_window_base64(win.wa_hwnd, 1366) {
                        last_clean_wa_shot = Some((clean_img, Instant::now()));
                    }
                }
                if ph.is_empty() && !rc.is_empty() && dialog_for_wa {
                    if let Some(p) = crate::common::lookup_whatsapp_phone_by_name(&rc) {
                        ph = p;
                    }
                }
                if dialog_for_wa && !is_noise_recipient_label(&rc) {
                    cached_wa_ctx = (
                        rc.clone(),
                        if !ph.is_empty() { ph.clone() } else { cached_wa_ctx.1.clone() },
                        Instant::now(),
                    );
                }
                if let Some(p) = exp_files.into_iter().next() {
                    if last_explorer_path.as_ref() != Some(&p) {
                        let fsize = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                        let staged = stage_user_session_file(&p);
                        recent_candidate_file =
                            Some((p.clone(), staged, fsize, "explorer_selection".into(), Instant::now()));
                        last_explorer_path = Some(p);
                    }
                }
                if (!is_noise_recipient_label(&rc) || !ph.is_empty() || !st.is_empty())
                    && st != "Open"
                    && st != "فتح"
                {
                    cached_ctx = (
                        if !is_noise_recipient_label(&rc) { rc } else { cached_ctx.0.clone() },
                        if !ph.is_empty() { ph } else { cached_ctx.1.clone() },
                        if !st.is_empty() { st } else { cached_ctx.2.clone() },
                        Instant::now(),
                    );
                }
            }

            let mut updated_mru: Option<(String, u64, std::path::PathBuf)> = None;
            if win.browser_open_dialog || win.any_open_dialog || prev_browser_dialog || was_browser_dialog_open {
                let mru_entries = crate::common::scan_comdlg_mru_entries();
                for (subk, wt, pb) in mru_entries {
                    let changed = match last_mru_map.get(&subk) {
                        Some((prev_wt, prev_pb)) => wt > *prev_wt || *prev_pb != pb,
                        None => true,
                    };
                    if changed {
                        last_mru_map.insert(subk.clone(), (wt, pb.clone()));
                        if updated_mru.as_ref().map_or(true, |(_, best_wt, _)| wt >= *best_wt) {
                            updated_mru = Some((subk, wt, pb));
                        }
                    }
                }
            }

            let is_browser_trigger = was_browser_dialog_open
                || prev_browser_dialog
                || win.browser_open_dialog
                || win.fg_is_browser
                || win.fg_is_wa;
            let trigger_path: Option<std::path::PathBuf> = if !is_browser_trigger {
                None
            } else if let Some((_, _, ref pb)) = updated_mru {
                Some(pb.clone())
            } else if prev_browser_dialog && !win.save_dialog {
                crate::common::read_latest_comdlg_mru_file()
            } else {
                None
            };

            if let Some(ref p) = trigger_path {
                let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("ملف").to_string();
                let flc = fname.to_ascii_lowercase();
                let is_temp = flc.ends_with(".tmp")
                    || flc.ends_with(".crdownload")
                    || flc.ends_with(".part")
                    || flc.starts_with("it-elkhawga")
                    || flc.starts_with("itk-");
                if !is_temp && !win.save_dialog {
                    let fsize = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                    let staged = stage_user_session_file(p);
                    recent_candidate_file =
                        Some((p.clone(), staged.clone(), fsize, "capture_file_dialog".into(), Instant::now()));
                    let dup = last_wa_alert
                        .as_ref()
                        .map_or(false, |(prev, t)| prev == &flc && t.elapsed() < Duration::from_secs(9))
                        || (!recent_ext_file.is_empty() && recent_ext_file.eq_ignore_ascii_case(&fname));
                    if !dup {
                        let wait_start = Instant::now();
                        while wait_start.elapsed() < Duration::from_millis(2200) {
                            let w = crate::common::inspect_upload_windows_ext();
                            if !w.browser_open_dialog && !w.any_open_dialog {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(150));
                        }
                        std::thread::sleep(Duration::from_millis(650));

                        let win_now = crate::common::inspect_upload_windows_ext();
                        let (mut r_name, mut r_phone, mut page_site, _, in_wa_prev) =
                            crate::common::query_active_upload_context_ext(false);
                        let is_wa_target = win_now.wa_open
                            && (win_now.fg_is_wa
                                || is_title_whatsapp(&win_now.best_title)
                                || is_title_whatsapp(&page_site)
                                || page_site.to_ascii_lowercase().contains("whatsapp"));

                        if is_wa_target {
                            // Stage & defer screenshot until the employee actually presses Send
                            // and WhatsApp closes the attachment preview back into the chat view!
                            if is_noise_recipient_label(&r_name) && cached_wa_ctx.2.elapsed() <= Duration::from_secs(180) {
                                r_name = cached_wa_ctx.0.clone();
                            }
                            if r_phone.is_empty() && cached_wa_ctx.2.elapsed() <= Duration::from_secs(180) {
                                r_phone = cached_wa_ctx.1.clone();
                            }
                            pending_wa_dialog = Some((
                                p.clone(),
                                staged.clone(),
                                fsize,
                                r_name,
                                r_phone,
                                Instant::now(),
                                in_wa_prev,
                                Instant::now(),
                                None,
                            ));
                        } else if !is_company_erp_url_or_title(&win_now.best_title)
                            && !is_company_erp_url_or_title(&page_site)
                            && !is_company_erp_url_or_title(&cached_ctx.2)
                        {
                            if is_noise_recipient_label(&r_name) && cached_ctx.3.elapsed() <= Duration::from_secs(120) {
                                r_name = cached_ctx.0.clone();
                            }
                            if page_site.is_empty() || page_site == "Open" || page_site == "فتح" {
                                page_site = if !cached_ctx.2.is_empty() && cached_ctx.2 != "Open" && cached_ctx.2 != "فتح" {
                                    cached_ctx.2.clone()
                                } else {
                                    win_now.best_title.clone()
                                };
                            }
                            if !is_company_erp_url_or_title(&page_site) {
                                std::thread::sleep(Duration::from_millis(300));
                                let win_web = crate::common::inspect_upload_windows_ext();
                                let shot = capture_upload_target_screen(&win_web, false, &last_clean_wa_shot)
                                    .or_else(|| captured_now.clone());
                                let cam: Option<String> = None;
                                let fpath_str = p.to_string_lossy().to_string();
                                let staged_str = staged.as_ref().map(|s| s.to_string_lossy().to_string());
                                send_whatsapp_upload_report(
                                    &fname,
                                    fsize,
                                    &fpath_str,
                                    staged_str.as_deref(),
                                    &r_name,
                                    &r_phone,
                                    &page_site,
                                    "capture_web_dialog",
                                    shot.as_deref(),
                                    cam.as_deref(),
                                    None,
                                );
                                last_wa_alert = Some((flc, Instant::now()));
                            }
                        }
                    }
                }
            }

            let cur_clip_seq = crate::common::clipboard_sequence_number();
            if cur_clip_seq != last_clip_seq {
                let cur_clip = crate::common::read_clipboard_files().into_iter().next();
                if let Some(ref p) = cur_clip {
                    let fsize = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                    let staged = stage_user_session_file(p);
                    recent_candidate_file =
                        Some((p.clone(), staged, fsize, "clipboard".into(), Instant::now()));
                }
                last_clip_seq = cur_clip_seq;
            }

            // Advance pending WhatsApp File-Dialog send watcher so screenshot happens
            // right AFTER Send closes the attachment preview and returns to the chat thread!
            let mut wa_proxy_consumed = false;
            if let Some(ref mut pend) = pending_wa_dialog {
                fast_dialog_poll = true;
                if wa_proxy_upload.is_some() && pend.8.is_none() {
                    pend.8 = Some(Instant::now());
                    wa_proxy_consumed = true;
                } else if pend.8.is_none() && pend.7.elapsed() >= Duration::from_millis(900) {
                    pend.7 = Instant::now();
                    let (rc_chk, ph_chk, _, _, now_preview) =
                        crate::common::query_active_upload_context_ext(false);
                    if !is_noise_recipient_label(&rc_chk) {
                        pend.3 = rc_chk;
                    }
                    if !ph_chk.is_empty() {
                        pend.4 = ph_chk;
                    }
                    if now_preview {
                        pend.6 = true;
                    } else if pend.6 || pend.5.elapsed() >= Duration::from_secs(8) {
                        pend.8 = Some(Instant::now());
                    }
                }
                if pend.5.elapsed() >= Duration::from_secs(35) && pend.8.is_none() {
                    pend.8 = Some(Instant::now());
                }
            }
            if pending_wa_dialog
                .as_ref()
                .and_then(|p| p.8)
                .map_or(false, |t| t.elapsed() >= Duration::from_millis(1150))
            {
                if let Some((p_path, stg_opt, p_sz, pre_rc, pre_ph, _, _, _, _)) = pending_wa_dialog.take() {
                    let fname = p_path.file_name().and_then(|n| n.to_str()).unwrap_or("ملف").to_string();
                    let flc = fname.to_ascii_lowercase();
                    let dup = (!recent_ext_file.is_empty() && recent_ext_file.eq_ignore_ascii_case(&fname))
                        || last_wa_alert.as_ref().map_or(false, |(prev, t)| prev == &flc && t.elapsed() < Duration::from_secs(8));
                    if !dup {
                        let win_now = crate::common::inspect_upload_windows_ext();
                        let (mut r_name, mut r_phone, mut page_site, _, _) =
                            crate::common::query_active_upload_context_ext(true);
                        if is_noise_recipient_label(&r_name) {
                            r_name = if !is_noise_recipient_label(&pre_rc) {
                                pre_rc
                            } else if cached_wa_ctx.2.elapsed() <= Duration::from_secs(180) {
                                cached_wa_ctx.0.clone()
                            } else {
                                clean_wa_title_recipient(&win_now.best_title)
                            };
                        }
                        if r_phone.is_empty() {
                            r_phone = if !pre_ph.is_empty() {
                                pre_ph
                            } else if !r_name.is_empty() {
                                crate::common::lookup_whatsapp_phone_by_name(&r_name).unwrap_or_default()
                            } else {
                                String::new()
                            };
                        }
                        if page_site.is_empty() || page_site == "Open" || page_site == "فتح" {
                            page_site = "https://web.whatsapp.com".to_string();
                        }
                        let shot = capture_upload_target_screen(&win_now, true, &last_clean_wa_shot)
                            .or_else(|| captured_now.clone());
                        let cam: Option<String> = None;
                        let fpath_str = p_path.to_string_lossy().to_string();
                        let staged_str = stg_opt.as_ref().map(|s| s.to_string_lossy().to_string());
                        send_whatsapp_upload_report(
                            &fname,
                            p_sz,
                            &fpath_str,
                            staged_str.as_deref(),
                            &r_name,
                            &r_phone,
                            &page_site,
                            "capture_whatsapp_dialog_sent",
                            shot.as_deref(),
                            cam.as_deref(),
                            None,
                        );
                        last_wa_alert = Some((flc, Instant::now()));
                    }
                }
            }

            if !wa_proxy_consumed {
                if let Some((_proxy_host, proxy_bytes)) = wa_proxy_upload {
                    if win.wa_open || win.fg_is_wa {
                        let candidate = recent_candidate_file
                            .as_ref()
                            .filter(|(_, _, _, _, t)| t.elapsed() <= Duration::from_secs(120))
                            .cloned()
                            .or_else(|| {
                                crate::common::find_recent_user_file(25).map(|rp| {
                                    let sz = std::fs::metadata(&rp).map(|m| m.len()).unwrap_or(proxy_bytes);
                                    let stg = stage_user_session_file(&rp);
                                    (rp, stg, sz, "recent_folder".to_string(), Instant::now())
                                })
                            });
                        // Require either a real staged file OR active foreground WhatsApp upload >= 32 KB
                        if candidate.is_some() || (win.fg_is_wa && proxy_bytes >= 32 * 1024) {
                            let (fname, fsize, fpath, staged_str, src) = match candidate {
                                Some((p, stg, sz, src_tag, _)) => (
                                    p.file_name().and_then(|n| n.to_str()).unwrap_or("ملف").to_string(),
                                    if sz > 0 { sz } else { proxy_bytes },
                                    p.to_string_lossy().to_string(),
                                    stg.map(|s| s.to_string_lossy().to_string()),
                                    format!("capture_whatsapp_{}", src_tag),
                                ),
                                None => (
                                    "رسالة وسائط مباشرة عبر واتساب".to_string(),
                                    proxy_bytes,
                                    String::new(),
                                    None,
                                    "capture_whatsapp_direct_media".to_string(),
                                ),
                            };
                            let flc = fname.to_ascii_lowercase();
                            let dup = last_wa_alert
                                .as_ref()
                                .map_or(false, |(prev, t)| prev == &flc && t.elapsed() < Duration::from_secs(9))
                                || (!recent_ext_file.is_empty() && recent_ext_file.eq_ignore_ascii_case(&fname));
                            if !dup {
                                // Settle 1.15s after mmg.whatsapp.net upload finishes so preview closes back to chat
                                std::thread::sleep(Duration::from_millis(1150));
                                let win_now = crate::common::inspect_upload_windows_ext();
                                let (mut r_name, mut r_phone, mut page_site, _, _) =
                                    crate::common::query_active_upload_context_ext(true);
                                if is_noise_recipient_label(&r_name) && cached_wa_ctx.2.elapsed() <= Duration::from_secs(180) {
                                    r_name = cached_wa_ctx.0.clone();
                                }
                                if is_noise_recipient_label(&r_name) {
                                    r_name = clean_wa_title_recipient(&win_now.best_title);
                                }
                                if r_phone.is_empty() && !r_name.is_empty() {
                                    if let Some(ph) = crate::common::lookup_whatsapp_phone_by_name(&r_name) {
                                        r_phone = ph;
                                    }
                                }
                                if r_phone.is_empty() && cached_wa_ctx.2.elapsed() <= Duration::from_secs(180) {
                                    r_phone = cached_wa_ctx.1.clone();
                                }
                                if page_site.is_empty() || page_site == "Open" || page_site == "فتح" {
                                    page_site = "https://web.whatsapp.com".to_string();
                                }
                                let shot = capture_upload_target_screen(&win_now, true, &last_clean_wa_shot)
                                    .or(captured_now);
                                let cam: Option<String> = None;
                                send_whatsapp_upload_report(
                                    &fname,
                                    fsize,
                                    &fpath,
                                    staged_str.as_deref(),
                                    &r_name,
                                    &r_phone,
                                    &page_site,
                                    &src,
                                    shot.as_deref(),
                                    cam.as_deref(),
                                    None,
                                );
                                last_wa_alert = Some((flc, Instant::now()));
                            }
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(if fast_dialog_poll || mode_code != 0 {
            350
        } else {
            3500
        }));
    }
}

fn start_usb_monitor() {
    std::thread::spawn(|| {
        let known_path = data_dir().join("usb-known.txt");
        let mut known: std::collections::HashSet<String> = std::fs::read_to_string(&known_path)
            .ok()
            .map(|s| s.lines().map(String::from).collect())
            .unwrap_or_default();

        loop {
            let current: std::collections::HashSet<String> =
                crate::common::list_usbstor_device_ids().into_iter().collect();

            let mut changed = false;
            for id in &current {
                if !known.contains(id) {
                    known.insert(id.clone());
                    changed = true;
                    let alert = json!({
                        "type": "usb",
                        "severity": "medium",
                        "message": format!("تم توصيل وحدة تخزين USB جديدة: {}", id)
                    });
                    enqueue_client_alert(alert);

                    let cur_cfg = read_config();
                    let cur_link = read_client();
                    if crate::common::is_usb_effectively_blocked(&cur_cfg, &cur_link) {
                        crate::common::apply_usb_storage_policy(true);
                    }
                }
            }

            if changed {
                let _ = std::fs::write(&known_path, known.iter().cloned().collect::<Vec<_>>().join("\n"));
            }

            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    });
}

pub fn run() {
    ensure_data();
    grant_users_data_access();
    crate::common::ensure_rustdesk_stealth_config();
    crate::proxy::ensure_root_ca_trusted();
    crate::proxy::start_default();
    start_usb_monitor();
    if !block_state_path().exists() {
        set_block_state(detect_blocked_legacy());
    }

    let local = match Server::http(LOCAL_API_ADDR) {
        Ok(s) => s,
        Err(_) => return, // another agent already owns the port
    };

    let linked = Arc::new(AtomicBool::new(false));
    {
        let linked = linked.clone();
        std::thread::spawn(move || {
            for req in local.incoming_requests() {
                if *req.method() == Method::Get {
                    handle_local(req, &linked);
                } else {
                    let l = linked.clone();
                    std::thread::spawn(move || handle_local(req, &l));
                }
            }
        });
    }

    log_action("Agent started");
    if is_blocked() || read_config().auto_start {
        let _ = apply_block("startup sync");
    }

    // Run Clean Browser HKLM policy enforcement & post-close trace cleanup inside the
    // elevated SYSTEM `--agent` process so Registry updates never hit Access Denied.
    if !is_admin_mode() {
        std::thread::spawn(|| {
            let init_ephem = read_client().ephemeral_browser || read_config().ephemeral_browser;
            crate::common::apply_ephemeral_browser_policy(init_ephem);
            crate::common::enforce_rustdesk_employee_lockdown(&read_client().rustdesk_password);
            if init_ephem {
                crate::common::wipe_browser_data_if_closed(true);
            } else {
                crate::common::protect_erp_browser_vault_if_closed();
            }
            let mut last_ephem = init_ephem;
            let (mut was_chrome_open, mut was_edge_open) = crate::common::are_browsers_running();
            let mut last_rd_lock_tick = Instant::now();
            loop {
                std::thread::sleep(Duration::from_secs(6));
                let link_now = read_client();
                let ephem = link_now.ephemeral_browser || read_config().ephemeral_browser;
                if ephem != last_ephem {
                    crate::common::apply_ephemeral_browser_policy(ephem);
                    if ephem {
                        crate::common::wipe_browser_data_if_closed(true);
                    }
                    last_ephem = ephem;
                }
                let (chrome_open, edge_open) = crate::common::are_browsers_running();
                let browser_just_closed = (was_chrome_open && !chrome_open) || (was_edge_open && !edge_open);
                was_chrome_open = chrome_open;
                was_edge_open = edge_open;

                if browser_just_closed {
                    // Wait 1.2s so Chrome/Edge finishes flushing persistent ERP cookies/storage on exit
                    std::thread::sleep(Duration::from_millis(1200));
                    if ephem {
                        crate::common::wipe_browser_data_if_closed(false);
                    } else {
                        crate::common::protect_erp_browser_vault_if_closed();
                    }
                }
                if last_rd_lock_tick.elapsed() >= Duration::from_secs(600) {
                    last_rd_lock_tick = Instant::now();
                    crate::common::enforce_rustdesk_employee_lockdown(&link_now.rustdesk_password);
                }
            }
        });

        // On-demand Dahua DVR Branch Bridge worker: strictly 0% CPU and 0 B/s when idle;
        // streams lightweight JPEG snapshots to the Relay only while an admin has an active lease.
        std::thread::spawn(|| {
            let bridge_relay = RelayClient::new();
            loop {
                if CCTV_SCAN_WANTED.swap(false, Ordering::SeqCst)
                    && !CCTV_SCAN_BUSY.swap(true, Ordering::SeqCst)
                {
                    std::thread::spawn(|| {
                        let found = crate::common::scan_local_subnet_for_dahua();
                        let link = read_client();
                        if !link.relay_url.trim().is_empty() && !link.device_token.trim().is_empty() {
                            let _ = RelayClient::new().upload_cctv_scan(&link.relay_url, &link.device_token, &found);
                        }
                        CCTV_SCAN_BUSY.store(false, Ordering::SeqCst);
                    });
                }

                let pending_cgi: Vec<Value> = {
                    let mut q = CCTV_CGI_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
                    std::mem::take(&mut *q)
                };
                if !pending_cgi.is_empty() {
                    for job in pending_cgi {
                        std::thread::spawn(move || {
                            let jid = job["job_id"].as_str().unwrap_or("").to_string();
                            let host = job["host"].as_str().unwrap_or("").to_string();
                            let port = job["http_port"].as_u64().unwrap_or(80) as u16;
                            let user = job["username"].as_str().unwrap_or("admin").to_string();
                            let pass = job["password"].as_str().unwrap_or("").to_string();
                            let path = job["path"].as_str().unwrap_or("").to_string();
                            let max_b = job["max_bytes"].as_u64().unwrap_or(262_144);
                            let t_ms = job["timeout_ms"].as_u64().unwrap_or(8_000);
                            if jid.is_empty() {
                                return;
                            }
                            let payload = match crate::common::execute_dahua_cgi(&host, port, &path, &user, &pass, max_b, t_ms) {
                                Ok((code, ct, bytes)) => json!({
                                    "job_id": jid,
                                    "status": code,
                                    "content_type": ct,
                                    "body_b64": crate::common::base64_encode(&bytes),
                                    "error": "",
                                }),
                                Err(e) => json!({
                                    "job_id": jid,
                                    "status": 0,
                                    "content_type": "",
                                    "body_b64": "",
                                    "error": e,
                                }),
                            };
                            let link = read_client();
                            if !link.relay_url.trim().is_empty() && !link.device_token.trim().is_empty() {
                                let _ = RelayClient::new().upload_cctv_cgi(&link.relay_url, &link.device_token, &payload);
                            }
                        });
                    }
                }

                let now_t = epoch_ms();
                let active_tasks: Vec<Value> = {
                    let mut g = CCTV_TASKS.lock().unwrap_or_else(|e| e.into_inner());
                    g.retain(|t| {
                        t["local_until"]
                            .as_u64()
                            .or_else(|| t["until"].as_u64())
                            .unwrap_or(0)
                            > now_t
                    });
                    g.clone()
                };

                if active_tasks.is_empty() {
                    std::thread::sleep(Duration::from_millis(600));
                    continue;
                }

                let link = read_client();
                if link.relay_url.trim().is_empty() || link.device_token.trim().is_empty() {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }

                let mut total_channels = 0usize;
                for task in &active_tasks {
                    let dvr_id = task["dvr_id"].as_str().unwrap_or("").trim().to_string();
                    let host = task["host"].as_str().unwrap_or("").trim().to_string();
                    let port = task["http_port"].as_u64().unwrap_or(80) as u16;
                    let username = task["username"].as_str().unwrap_or("admin").to_string();
                    let password = task["password"].as_str().unwrap_or("").to_string();
                    let hd = task["hd"].as_bool().unwrap_or(false);
                    let max_conc = (task["concurrency"].as_u64().unwrap_or(4) as usize).clamp(1, 4);
                    let channels: Vec<u32> = task["channels"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect())
                        .unwrap_or_else(|| vec![1]);
                    if dvr_id.is_empty() || host.is_empty() || channels.is_empty() {
                        continue;
                    }
                    total_channels += channels.len();
                    for chunk in channels.chunks(max_conc) {
                        std::thread::scope(|s| {
                            for &ch in chunk {
                                let dvr_id_ref = &dvr_id;
                                let host_ref = &host;
                                let user_ref = &username;
                                let pass_ref = &password;
                                let relay_ref = &bridge_relay;
                                let r_url = &link.relay_url;
                                let d_tok = &link.device_token;
                                s.spawn(move || {
                                    let payload = match crate::common::fetch_dahua_snapshot(host_ref, port, user_ref, pass_ref, ch, hd) {
                                        Ok(bytes) => json!({
                                            "dvr_id": dvr_id_ref,
                                            "channel": ch,
                                            "hd": hd,
                                            "image": crate::common::base64_encode(&bytes),
                                            "error": "",
                                        }),
                                        Err(err) => json!({
                                            "dvr_id": dvr_id_ref,
                                            "channel": ch,
                                            "hd": hd,
                                            "image": "",
                                            "error": err,
                                        }),
                                    };
                                    if let Some(resp) = relay_ref.upload_cctv_frame(r_url, d_tok, &payload) {
                                        if let Some(updated) = resp.get("cctv_tasks") {
                                            sync_cctv_tasks_from_value(if updated.is_null() { None } else { Some(updated) });
                                        }
                                    }
                                });
                            }
                        });
                    }
                }

                let pace_ms = if total_channels <= 1 { 180 } else { 240 };
                std::thread::sleep(Duration::from_millis(pace_ms));
            }
        });

        // Dedicated zero-CPU on-demand Dahua Live Audio reader: sleeps 100% idle when muted,
        // opens a single ~3 KB/s local socket when an admin clicks `🔊`, and closes immediately on mute.
        std::thread::spawn(move || {
            let audio_relay = RelayClient::new();
            loop {
                let spec_opt = {
                    let g = CCTV_AUDIO_SPEC.lock().unwrap_or_else(|e| e.into_inner());
                    g.clone()
                };
                let now_t = epoch_ms();
                let Some(spec) = spec_opt.filter(|s| s.channel > 0 && s.until_ms > now_t) else {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                };
                let link = read_client();
                if link.relay_url.trim().is_empty() || link.device_token.trim().is_empty() {
                    std::thread::sleep(Duration::from_millis(400));
                    continue;
                }
                let target_dvr = spec.dvr_id.clone();
                let target_ch = spec.channel;
                let r_url = link.relay_url.clone();
                let d_tok = link.device_token.clone();

                let res = crate::common::stream_dahua_audio_live(
                    &spec.host,
                    spec.port,
                    &spec.username,
                    &spec.password,
                    spec.channel,
                    || {
                        let g = CCTV_AUDIO_SPEC.lock().unwrap_or_else(|e| e.into_inner());
                        match g.as_ref() {
                            Some(cur) => {
                                cur.dvr_id == target_dvr
                                    && cur.channel == target_ch
                                    && cur.until_ms > epoch_ms()
                            }
                            None => false,
                        }
                    },
                    |ct, bytes| {
                        let payload = json!({
                            "dvr_id": target_dvr,
                            "channel": target_ch,
                            "content_type": ct,
                            "data_b64": crate::common::base64_encode(bytes),
                            "error": "",
                        });
                        match audio_relay.upload_cctv_audio(&r_url, &d_tok, &payload) {
                            Some(resp) => {
                                if let Some(updated) = resp.get("cctv_tasks") {
                                    sync_cctv_tasks_from_value(if updated.is_null() { None } else { Some(updated) });
                                }
                                resp["active"].as_bool().unwrap_or(true)
                            }
                            None => false,
                        }
                    },
                );

                if let Err(err_msg) = res {
                    let payload = json!({
                        "dvr_id": spec.dvr_id,
                        "channel": spec.channel,
                        "content_type": "",
                        "data_b64": "",
                        "error": err_msg,
                    });
                    if let Some(resp) = audio_relay.upload_cctv_audio(&r_url, &d_tok, &payload) {
                        if let Some(updated) = resp.get("cctv_tasks") {
                            sync_cctv_tasks_from_value(if updated.is_null() { None } else { Some(updated) });
                        }
                    }
                    // Prevent rapid reconnect spin if channel has no microphone
                    {
                        let mut g = CCTV_AUDIO_SPEC.lock().unwrap_or_else(|e| e.into_inner());
                        if g.as_ref().map_or(false, |c| c.dvr_id == spec.dvr_id && c.channel == spec.channel) {
                            *g = None;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(800));
                }
            }
        });
    }

    let http = tls_agent(6);
    let relay_client = RelayClient::new();
    let mut last_screen_wake: u64 = 0;
    loop {
        poll_once(&http, &relay_client, &linked);
        // Keep the user-session capture/DLP helper alive proactively and wake it
        // immediately whenever live screen/camera streaming is active.
        if !is_admin_mode() {
            let now_s = epoch_secs();
            let last_poll = LAST_CAPTURE_POLL_SECS.load(Ordering::Relaxed);
            let stale_limit = if SCREEN_WANTED.load(Ordering::Relaxed) { 5 } else { 25 };
            let wake_cooldown = if SCREEN_WANTED.load(Ordering::Relaxed) { 15 } else { 30 };
            if now_s.saturating_sub(last_poll) > stale_limit
                && now_s.saturating_sub(last_screen_wake) >= wake_cooldown
            {
                last_screen_wake = now_s;
                let mut cmd = std::process::Command::new("schtasks");
                cmd.args(["/Run", "/TN", "IT ELKHAWGA Screen"]);
                let _ = crate::common::hidden(&mut cmd).output();
            }
        }
        std::thread::sleep(Duration::from_secs(POLL_SECONDS));
    }
}

/// Downloads the latest Client NSIS installer from LAN server or Cloud Relay and applies it silently.
fn apply_client_self_update(cmd_id: &str) -> Result<(), String> {
    if is_admin_mode() {
        log_action("Client self-update ignored on admin machine");
        return Ok(());
    }
    if UPDATE_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        log_action("Client self-update already in progress");
        return Ok(());
    }
    let link = read_client();
    let is_relay = matches!(Transport::from_link(&link), Transport::Relay);
    let mut urls: Vec<String> = Vec::new();
    let lan_url = link.server_url.trim().trim_end_matches('/');
    let relay_url = link.relay_url.trim().trim_end_matches('/');
    let def_relay = DEFAULT_RELAY_URL.trim_end_matches('/');
    if is_relay {
        if !relay_url.is_empty() {
            urls.push(format!("{}/api/v1/client-setup.exe", relay_url));
        }
        if !def_relay.is_empty() && def_relay != relay_url {
            urls.push(format!("{}/api/v1/client-setup.exe", def_relay));
        }
        if !lan_url.is_empty() {
            urls.push(format!("{}/api/client-setup.exe", lan_url));
        }
    } else {
        if !lan_url.is_empty() {
            urls.push(format!("{}/api/client-setup.exe", lan_url));
        }
        if !relay_url.is_empty() {
            urls.push(format!("{}/api/v1/client-setup.exe", relay_url));
        }
        if !def_relay.is_empty() && def_relay != relay_url {
            urls.push(format!("{}/api/v1/client-setup.exe", def_relay));
        }
    }
    if urls.is_empty() {
        UPDATE_IN_PROGRESS.store(false, Ordering::SeqCst);
        return Err("no server or relay url configured for self-update".into());
    }

    let ack_id = cmd_id.to_string();
    log_action(&format!("Client self-update queued ({} source URLs)", urls.len()));
    std::thread::spawn(move || {
        let http = tls_agent(120);
        let mut downloaded: Option<(Vec<u8>, String)> = None;
        for url in &urls {
            match http.get(url).call() {
                Ok(resp) => {
                    let mut buf: Vec<u8> = Vec::new();
                    if resp.into_reader().read_to_end(&mut buf).is_ok()
                        && buf.len() > 500_000
                        && buf.starts_with(b"MZ")
                    {
                        downloaded = Some((buf, url.clone()));
                        break;
                    } else {
                        log_action(&format!("Client self-update received invalid installer from {}", url));
                    }
                }
                Err(e) => {
                    log_action(&format!("Client self-update download error from {}: {}", url, e));
                }
            }
        }
        let Some((bytes, src_url)) = downloaded else {
            log_action("Client self-update failed: unable to fetch installer from any endpoint (will retry)");
            UPDATE_IN_PROGRESS.store(false, Ordering::SeqCst);
            return;
        };

        let temp_exe = std::env::temp_dir().join("it-elkhawga-client-update.exe");
        if let Err(e) = std::fs::write(&temp_exe, &bytes) {
            log_action(&format!("Client self-update write failed: {}", e));
            UPDATE_IN_PROGRESS.store(false, Ordering::SeqCst);
            return;
        }
        // Only record last_command_id AFTER the valid installer binary is verified on disk
        if !ack_id.is_empty() {
            let mut l = read_client();
            l.last_command_id = ack_id;
            let _ = write_client(&l);
        }
        log_action(&format!(
            "Client self-update downloaded {} bytes from {}; waiting 5s for command ACK",
            bytes.len(),
            src_url
        ));
        // Let the main poll loop send ack_command_id before NSIS_HOOK_PREINSTALL stops the agent.
        std::thread::sleep(Duration::from_secs(5));

        // Launch silent installer detached from the current Task Scheduler job object so killing
        // it-elkhawga.exe during NSIS preinstall never terminates the running updater itself.
        let temp_str = temp_exe.to_string_lossy().to_string();
        let mut launched = false;
        let mut sch_create = std::process::Command::new("schtasks");
        sch_create.args([
            "/Create",
            "/TN",
            "IT ELKHAWGA SelfUpdate",
            "/TR",
            &format!("\"{}\" /S", temp_str),
            "/SC",
            "ONCE",
            "/ST",
            "00:00",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
        ]);
        if crate::common::hidden(&mut sch_create).output().map_or(false, |o| o.status.success()) {
            let mut sch_run = std::process::Command::new("schtasks");
            sch_run.args(["/Run", "/TN", "IT ELKHAWGA SelfUpdate"]);
            if crate::common::hidden(&mut sch_run).output().map_or(false, |o| o.status.success()) {
                launched = true;
                log_action("Client self-update launched via independent Scheduled Task (IT ELKHAWGA SelfUpdate)");
            }
        }
        if !launched {
            let mut cmd = std::process::Command::new(&temp_exe);
            cmd.arg("/S");
            match crate::common::hidden(&mut cmd).spawn() {
                Ok(_) => log_action("Client self-update launched silent installer (/S)"),
                Err(e) => log_action(&format!("Client self-update spawn failed: {}", e)),
            }
        }
        std::thread::sleep(Duration::from_secs(60));
        UPDATE_IN_PROGRESS.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// Seconds the employee gets (with an on-screen warning) before a remote restart/shutdown.
/// Also guarantees the next poll acknowledges the command before Windows goes down, so
/// the relay never re-delivers it after boot (which would cause a reboot loop).
const POWER_DELAY_SECS: u32 = 60;

/// Remote restart / shutdown / cancel, issued by the admin. Runs as SYSTEM.
fn apply_power_command(cmd: &str) -> Result<(), String> {
    let delay = POWER_DELAY_SECS.to_string();
    let (args, label): (Vec<&str>, &str) = match cmd {
        "restart" => (
            vec!["/r", "/t", &delay, "/d", "p:0:0", "/c",
                 "سيتم إعادة تشغيل الجهاز خلال دقيقة بواسطة قسم IT - احفظ عملك الآن"],
            "RESTART",
        ),
        "shutdown" => (
            vec!["/s", "/t", &delay, "/d", "p:0:0", "/c",
                 "سيتم إيقاف تشغيل الجهاز خلال دقيقة بواسطة قسم IT - احفظ عملك الآن"],
            "SHUTDOWN",
        ),
        _ => (vec!["/a"], "CANCEL POWER"),
    };
    let mut sh = std::process::Command::new("shutdown.exe");
    sh.args(&args);
    let out = crate::common::hidden(&mut sh).output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            log_action(&format!("{} (remote command) - failed to start shutdown.exe: {}", label, e));
            return Ok(());
        }
    };
    // `shutdown /a` exits non-zero when nothing is pending; that is not a failure.
    if out.status.success() || cmd == "cancel_power" {
        log_action(&format!("{} (remote command) - scheduled", label));
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        log_action(&format!("{} (remote command) - failed: {}", label, err));
    }
    // Always report success so the command id is acknowledged: a retried power command
    // could survive the reboot and be re-delivered on every boot (reboot loop).
    Ok(())
}

/// Sets the RustDesk unattended password on this machine (used by the admin key button).
fn apply_rustdesk_password(password: &str) {
    if crate::common::apply_rustdesk_permanent_password(password) {
        log_action("RustDesk password updated");
    }
}

fn apply_block(reason: &str) -> Result<(), String> {
    crate::proxy::ensure_root_ca_trusted();
    let r = run_script("block-internet.ps1", &[]);
    if r.is_ok() {
        set_block_state(true);
    }
    log_action(&match &r {
        Ok(_) => format!("BLOCK ({}) - success", reason),
        Err(e) => format!("BLOCK ({}) - failed: {}", reason, e),
    });
    r
}

fn apply_unblock(reason: &str) -> Result<(), String> {
    let r = run_script("allow-internet.ps1", &["-Force"]);
    if r.is_ok() {
        set_block_state(false);
    }
    log_action(&match &r {
        Ok(_) => format!("UNBLOCK ({}) - success", reason),
        Err(e) => format!("UNBLOCK ({}) - failed: {}", reason, e),
    });
    r
}

fn parse_pending_alert(raw: &str) -> Value {
    if raw.trim().is_empty() {
        return Value::Null;
    }
    serde_json::from_str(raw).unwrap_or(Value::Null)
}

/// Detects tampering with the protection layer (proxy settings, browser policies,
/// or scheduled tasks). Both whitelist and blacklist modes enforce filtering via `127.0.0.1:8080`.
fn check_tamper() -> Option<(&'static str, &'static str, String)> {
    let cfg = read_config();
    match std::fs::read_to_string(block_state_path()).ok() {
        Some(s) if s.trim() == "1" => {}
        Some(_) => return None, // Explicitly unblocked by admin/password ("0").
        None => {
            if cfg.auto_start {
                return Some(("tamper", "high", "تم حذف ملف حالة الحماية (blocked.state)".to_string()));
            }
            return None;
        }
    }

    let hklm_inet = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
    let hklm_on = crate::common::reg_query_dword(hklm_inet, "ProxyEnable") == Some(1)
        && crate::common::reg_query_string(hklm_inet, "ProxyServer")
            .map_or(false, |s| s.contains("127.0.0.1:8080"));
    if !hklm_on {
        return Some(("tamper", "high", "تم تعطيل أو تغيير بروكسي النظام (127.0.0.1:8080) أثناء الحجب".to_string()));
    }

    let chrome_pol = r"HKLM\SOFTWARE\Policies\Google\Chrome";
    let edge_pol = r"HKLM\SOFTWARE\Policies\Microsoft\Edge";
    let chrome_ok = reg_query_string(chrome_pol, "ProxyServer")
        .map_or(false, |s| s.contains("127.0.0.1:8080"));
    let edge_ok = reg_query_string(edge_pol, "ProxyServer")
        .map_or(false, |s| s.contains("127.0.0.1:8080"));
    if !chrome_ok || !edge_ok {
        return Some(("tamper", "high", "تم تعديل أو حذف سياسات البروكسي للمتصفح أثناء الحجب".to_string()));
    }
    let edge_bypass_ok = reg_query_string(edge_pol, "ProxyBypassList")
        .map_or(false, |s| {
            let lc = s.to_ascii_lowercase();
            lc.contains("10.*") && lc.contains("192.168.*") && lc.contains("elkhawaga.uk")
        });
    if !edge_bypass_ok {
        let _ = apply_block("lan bypass upgrade");
    }

    let sys_tasks = std::path::Path::new(r"C:\Windows\System32\Tasks");
    for (task_name, err_msg) in [
        ("IT ELKHAWGA Agent", "تم حذف مهمة الـ Agent (IT ELKHAWGA Agent)"),
        ("IT ELKHAWGA Screen", "تم حذف مهمة المراقبة والحماية (IT ELKHAWGA Screen)"),
    ] {
        // Zero-process fast path: scheduled tasks live as files under System32\Tasks (readable by SYSTEM)
        if sys_tasks.join(task_name).is_file() {
            continue;
        }
        let mut sc = std::process::Command::new("schtasks");
        sc.args(["/Query", "/TN", task_name]);
        let task_ok = crate::common::hidden(&mut sc)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !task_ok {
            return Some(("tamper", "high", err_msg.to_string()));
        }
    }
    None
}

fn poll_once(http: &ureq::Agent, relay: &RelayClient, linked: &AtomicBool) {
    if is_admin_mode() {
        return;
    }
    let cfg = read_config();
    // Tamper check (strictly once every 90s using zero-process Win32 Registry & file checks)
    let now_s = epoch_secs();
    let last_chk = LAST_TAMPER_CHECK_SECS.load(Ordering::Relaxed);
    if now_s.saturating_sub(last_chk) >= 90 {
        LAST_TAMPER_CHECK_SECS.store(now_s, Ordering::Relaxed);
        let last_tamper = LAST_TAMPER_ALERT_SECS.load(Ordering::Relaxed);
        if now_s >= last_tamper {
            if let Some((t, sev, msg)) = check_tamper() {
                LAST_TAMPER_ALERT_SECS.store(now_s + 120, Ordering::Relaxed);
            let win_user = std::env::var("USERNAME").unwrap_or_default();
            let mut meta = json!({ "windows_user": win_user });
            if let Some((sc, cam, _rn, _rp, pu)) = request_agent_evidence(2200) {
                if let Some(s) = sc {
                    meta["screenshot"] = json!(s);
                }
                if let Some(c) = cam {
                    meta["camera_photo"] = json!(c);
                }
                if !pu.is_empty() {
                    meta["page_url"] = json!(pu);
                }
            }
            let alert = json!({"type": t, "severity": sev, "message": msg, "meta": meta});
            enqueue_client_alert(alert);
            let _ = apply_block("tamper auto-heal");
            }
        }
    }
    // Suspicious upload/exfiltration attempts captured by the local proxy
    let exfil_hosts = crate::proxy::drain_exfil();
    if !exfil_hosts.is_empty() {
        let joined = exfil_hosts.join("، ");
        let win_user = std::env::var("USERNAME").unwrap_or_default();
        let mut meta = json!({ "hosts": exfil_hosts, "windows_user": win_user });
        if let Some((sc, cam, _rn, _rp, pu)) = request_agent_evidence(2200) {
            if let Some(s) = sc {
                meta["screenshot"] = json!(s);
            }
            if let Some(c) = cam {
                meta["camera_photo"] = json!(c);
            }
            if !pu.is_empty() {
                meta["page_url"] = json!(pu);
            }
        }
        let alert = json!({
            "type": "exfil",
            "severity": "high",
            "message": format!("محاولة فتح موقع رفع ملفات أو تسريب بيانات مشبوه: {}", joined),
            "meta": meta
        });
        enqueue_client_alert(alert);
    }

    if read_client().pending_alert.trim().is_empty() {
        let next = ALERT_QUEUE.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
        if let Some(a) = next {
            let mut l = read_client();
            l.pending_alert = a.to_string();
            let _ = write_client(&l);
        }
    }

    let link = read_client();
    let transport = Transport::from_link(&link);
    let pending_event = link.pending_event.clone();
    let pending_alert = link.pending_alert.clone();
    // Only include `alert` inside poll `state` for LAN polling (`server.rs` reads `poll.alert`);
    // Relay devices report alerts via dedicated `/api/v1/device/alert` BEFORE long-polling so
    // base64 screenshots/camera photos never stall or time out the 20s `/api/v1/device/poll` request.
    let state = json!({
        "device_id": link.device_id,
        "hostname": hostname(),
        "blocked": is_blocked(),
        "usb_blocked": crate::common::is_usb_effectively_blocked(&cfg, &link),
        "mode": cfg.mode,
        "policy_version": link.policy_version,
        "app_version": APP_VERSION,
        "event": pending_event.clone(),
        "sites": crate::proxy::recent_sites(),
        "rustdesk_id": link.rustdesk_id.clone(),
        "denied": crate::proxy::recent_denied(),
        "alert": if matches!(transport, Transport::Lan) {
            parse_pending_alert(&link.pending_alert)
        } else {
            Value::Null
        },
    });

    let ack: Option<String> = if link.last_command_id.is_empty() { None } else { Some(link.last_command_id.clone()) };
    let mut alert_delivered = true;
    let reply: Value = match transport {
        Transport::Relay => {
            // Pairing token is reusable: one token links this client to the admin
            // forever and re-enrollment is always possible (survives reinstalls /
            // stale tokens). We never consume (clear) the pairing token.
            let mut link = link;
            if link.device_token.is_empty() && !link.pairing_token.is_empty() {
                if let Some((device_id, device_token)) =
                    relay.enroll(&link.relay_url, &link.pairing_token)
                {
                    link.device_id = device_id;
                    link.device_token = device_token;
                    let _ = write_client(&link);
                    log_action("Relay enrollment succeeded");
                }
            }
            if link.device_token.is_empty() {
                linked.store(false, Ordering::Relaxed);
                log_action("Relay: no device token - enrollment required");
                return;
            }
            if !pending_alert.is_empty() {
                let parsed = parse_pending_alert(&pending_alert);
                alert_delivered = relay
                    .report_alert(&link.relay_url, &link.device_token, &parsed)
                    .is_some();
                if alert_delivered {
                    let mut l = read_client();
                    l.pending_alert = String::new();
                    let _ = write_client(&l);
                }
            }
            match relay.poll_status(&link.relay_url, &link.device_token, &state, ack.as_deref()) {
                RelayPollOutcome::Ok(command, policy, screen, stream_mode, cctv_tasks, cctv_scan, cctv_cgi) => {
                    SCREEN_WANTED.store(screen, Ordering::Relaxed);
                    sync_cctv_tasks_from_value(cctv_tasks.as_ref());
                    enqueue_cctv_cgi_jobs(cctv_cgi.as_ref());
                    if cctv_scan {
                        CCTV_SCAN_WANTED.store(true, Ordering::SeqCst);
                    }
                    json!({"command": command, "policy": policy, "screen": screen, "stream_mode": stream_mode})
                }
                RelayPollOutcome::Unauthorized => {
                    // Explicitly rejected token: drop it so the next cycle re-enrolls.
                    if !link.pairing_token.is_empty() {
                        let mut l = read_client();
                        l.device_token = String::new();
                        let _ = write_client(&l);
                    }
                    linked.store(false, Ordering::Relaxed);
                    log_action("Relay token rejected - re-enrolling");
                    return;
                }
                RelayPollOutcome::NetworkError => {
                    // Transient network timeout/offline: keep device_token intact.
                    linked.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
        Transport::Lan => {
            if link.server_url.is_empty() || link.token.is_empty() {
                linked.store(false, Ordering::Relaxed);
                return;
            }
            if !pending_alert.is_empty()
                && !link.relay_url.trim().is_empty()
                && !link.device_token.trim().is_empty()
            {
                let parsed = parse_pending_alert(&pending_alert);
                let rl_url = link.relay_url.clone();
                let rl_tok = link.device_token.clone();
                std::thread::spawn(move || {
                    let _ = RelayClient::new().report_alert(&rl_url, &rl_tok, &parsed);
                });
            }
            match lan_poll(http, &link, ack.as_deref()) {
                Some(v) => v,
                None => {
                    linked.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
    };
    linked.store(true, Ordering::Relaxed);

    // The relay accepted our state (which carried the event), so clear it.
    if !pending_event.is_empty() {
        let mut l = read_client();
        l.pending_event = String::new();
        let _ = write_client(&l);
    }
    if !pending_alert.is_empty() && alert_delivered {
        let mut l = read_client();
        l.pending_alert = String::new();
        let _ = write_client(&l);
    }

    let st_mode = reply
        .get("stream_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if st_mode == "screen" || st_mode == "camera" {
        if let Ok(mut g) = STREAM_MODE.lock() {
            *g = st_mode;
        }
        STREAM_UNTIL_MS.store(epoch_ms() + 12_000, Ordering::Relaxed);
        SCREEN_WANTED.store(true, Ordering::Relaxed);
    } else if st_mode == "once" || reply.get("screen").and_then(|v| v.as_bool()) == Some(true) {
        if let Ok(mut g) = STREAM_MODE.lock() {
            g.clear();
        }
        STREAM_UNTIL_MS.store(0, Ordering::Relaxed);
        SCREEN_WANTED.store(true, Ordering::Relaxed);
    } else {
        if let Ok(mut g) = STREAM_MODE.lock() {
            g.clear();
        }
        STREAM_UNTIL_MS.store(0, Ordering::Relaxed);
        SCREEN_WANTED.store(false, Ordering::Relaxed);
    }
    if let Some(pw) = reply.get("rustdesk_password").and_then(|v| v.as_str()) {
        if !pw.is_empty() {
            let cur = read_client();
            // Apply to RustDesk only when it actually changed, so we don't spawn
            // rustdesk.exe on every poll.
            if cur.rustdesk_password != pw {
                apply_rustdesk_password(pw);
            }
            let mut l = read_client();
            l.rustdesk_password = pw.to_string();
            let _ = write_client(&l);
        }
    }

    if let Some(policy) = reply.get("policy").filter(|p| p.is_object()) {
        apply_policy(policy);
    }

    // Support both relay shape (command: {type,id}) and LAN shape (command: "block").
    let cmd_opt: Option<String> = match reply.get("command") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(_)) => reply.get("command").and_then(|c| c.get("type")).and_then(|t| t.as_str()).map(String::from),
        _ => None,
    };
    if let Some(cmd) = cmd_opt.as_deref() {
        let id = match reply.get("command") {
            Some(Value::Object(_)) => reply["command"].get("id").and_then(|i| i.as_str()).unwrap_or(""),
            _ => "",
        };
        let already = match ack {
            Some(a) => !a.is_empty() && *id == *a,
            None => false,
        };
        if already {
            // already applied
        } else {
            let outcome = if cmd == "block" {
                apply_block("remote command")
            } else if cmd == "unblock" {
                apply_unblock("remote command")
            } else if let Some(kbps) = cmd.strip_prefix("throttle:") {
                let n: i64 = kbps.trim().parse().unwrap_or(0);
                crate::proxy::set_throttle(n.max(0) as u32);
                // Force traffic through the local proxy while shaping; release it
                // again when the limit is cleared and the device is not blocked.
                let blocked_now = is_blocked() && read_config().mode == "whitelist";
                let enable_proxy = if n > 0 {
                    1
                } else if !blocked_now {
                    -1
                } else {
                    0
                };
                let r = run_script(
                    "throttle.ps1",
                    &["-Kbps", &n.to_string(), "-EnableProxy", &enable_proxy.to_string()],
                );
                log_action(&match &r {
                    Ok(_) => format!("THROTTLE set to {}Kbps", n),
                    Err(e) => format!("THROTTLE failed: {}", e),
                });
                r
            } else if cmd == "restart" || cmd == "shutdown" || cmd == "cancel_power" {
                apply_power_command(cmd)
            } else if cmd == "update_client" {
                apply_client_self_update(id)
            } else if cmd == "usb_block" {
                let mut l = read_client();
                l.usb_override = "block".to_string();
                let _ = write_client(&l);
                crate::common::apply_usb_storage_policy(true);
                log_action("USB mass storage blocked (remote command)");
                Ok(())
            } else if cmd == "usb_unblock" {
                let mut l = read_client();
                l.usb_override = "unblock".to_string();
                let _ = write_client(&l);
                crate::common::apply_usb_storage_policy(false);
                log_action("USB mass storage unblocked (remote command)");
                Ok(())
            } else if cmd == "usb_inherit" {
                let mut l = read_client();
                l.usb_override.clear();
                let _ = write_client(&l);
                let c = read_config();
                crate::common::apply_usb_storage_policy(c.usb_block);
                log_action("USB mass storage reset to group/global policy");
                Ok(())
            } else {
                Ok(())
            };
            match outcome {
                Ok(_) => {
                    if !id.is_empty() && cmd != "update_client" {
                        let mut l = read_client();
                        l.last_command_id = id.to_string();
                        let _ = write_client(&l);
                    }
                }
                Err(e) => {
                    // Do not record the id; the relay keeps returning it and we retry.
                    log_action(&format!("Command '{}' failed, will retry: {}", cmd, e));
                }
            }
        }
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).filter_map(clean_domain).collect())
        .unwrap_or_default()
}

fn apply_policy(policy: &Value) {
    let mut cfg = read_config();
    if let Some(mode) = policy["mode"].as_str() {
        cfg.mode = if mode == "blacklist" { "blacklist".into() } else { "whitelist".into() };
    }
    // Never clear the local protection password just because a transport omitted it.
    if let Some(hash) = policy["password_hash"].as_str() {
        if !hash.is_empty() {
            cfg.password_hash = hash.to_string();
        }
    }
    if let Some(auto) = policy["auto_start"].as_bool() {
        cfg.auto_start = auto;
    }
    if let Some(t) = policy["exfil_threshold_mb"].as_u64() {
        cfg.exfil_threshold_mb = t;
    }
    if let Some(w) = policy["exfil_window_secs"].as_u64() {
        cfg.exfil_window_secs = w;
    }
    if let Some(arr) = policy["exfil_suspicious"].as_array() {
        cfg.exfil_suspicious = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
    }
    let prev_usb = cfg.usb_block;
    if let Some(b) = policy["usb_block"].as_bool() {
        cfg.usb_block = b;
    }
    if let Some(arr) = policy["erp_domains"].as_array() {
        let mut doms: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().and_then(clean_domain))
            .collect();
        if !doms.iter().any(|d| d.eq_ignore_ascii_case(DEFAULT_ERP_DOMAIN)) {
            doms.insert(0, DEFAULT_ERP_DOMAIN.to_string());
        }
        doms.dedup();
        cfg.erp_domains = doms;
    }
    let prev_ephem = cfg.ephemeral_browser || read_client().ephemeral_browser;
    let ephem = policy["ephemeral_browser"].as_bool().unwrap_or(false);
    cfg.ephemeral_browser = ephem;
    let mut rd_changed = false;
    if let Some(s) = policy["rustdesk_server"].as_str() {
        let mut l = read_client();
        if l.rustdesk_server != s {
            l.rustdesk_server = s.to_string();
            let _ = write_client(&l);
            rd_changed = true;
        }
    }
    if let Some(k) = policy["rustdesk_key"].as_str() {
        let mut l = read_client();
        if l.rustdesk_key != k {
            l.rustdesk_key = k.to_string();
            let _ = write_client(&l);
            rd_changed = true;
        }
    }
    if let Some(pw) = policy["rustdesk_password"].as_str() {
        let mut l = read_client();
        l.rustdesk_password = pw.to_string();
        let _ = write_client(&l);
    }
    if rd_changed {
        configure_rustdesk_server();
    }
    let allowed_entries = strings(&policy["allowed"]);
    let blocked_entries = strings(&policy["blocked"]);
    let wa_allowed = if cfg.mode == "blacklist" {
        !blocked_entries.iter().any(|s| s.to_ascii_lowercase().contains("whatsapp"))
    } else {
        allowed_entries.iter().any(|s| s.to_ascii_lowercase().contains("whatsapp"))
    };
    let _ = write_config(&cfg);
    let _ = write_list(&allowed_path(), "Allowed sites (synced from admin)", &allowed_entries);
    let _ = write_list(&blocked_path(), "Blocked sites (synced from admin)", &blocked_entries);
    if ephem != prev_ephem {
        crate::common::apply_ephemeral_browser_policy(ephem);
    }

    let mut link = read_client();
    let prev_eff_usb = prev_usb && link.usb_override != "allow" || link.usb_override == "block";
    if prev_usb != cfg.usb_block {
        // Group or global USB policy explicitly flipped by admin: adopt the new policy across the group.
        link.usb_override.clear();
    }
    let new_eff_usb = crate::common::is_usb_effectively_blocked(&cfg, &link);
    if prev_eff_usb != new_eff_usb || prev_usb != cfg.usb_block {
        crate::common::apply_usb_storage_policy(new_eff_usb);
    }
    link.ephemeral_browser = ephem;
    link.policy_version = policy["version"].as_str().unwrap_or("").to_string();
    let _ = write_client(&link);
    log_action("Policy synced from admin");

    if is_blocked() {
        let cur_bypass = crate::common::reg_query_string(
            r"HKLM\SOFTWARE\Policies\Google\Chrome",
            "ProxyBypassList",
        )
        .unwrap_or_default()
        .to_ascii_lowercase();
        let has_wa_bypass = cur_bypass.contains("whatsapp.com");
        let has_erp_bypass = cur_bypass.contains("elkhawaga.uk");
        let has_lan_bypass = cur_bypass.contains("10.*") && cur_bypass.contains("192.168.*");
        if check_tamper().is_some() || (has_wa_bypass != wa_allowed) || !has_erp_bypass || !has_lan_bypass {
            let _ = apply_block("policy changed");
        } else {
            crate::common::invalidate_policy_cache();
        }
    }
}

fn reply(body: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(body.to_string()).with_header(header)
}

fn handle_local(mut req: Request, linked: &AtomicBool) {
    // Screenshot uploads and DLP file payloads may carry base64 blobs up to ~28 MB.
    let max_body: u64 = if *req.method() == Method::Post && req.url() == "/local/whatsapp-upload" {
        38 * 1024 * 1024
    } else if *req.method() == Method::Post
        && (req.url() == "/local/screenshot" || req.url() == "/local/evidence")
    {
        12 * 1024 * 1024
    } else {
        65_536
    };
    let mut raw = String::new();
    let _ = req.as_reader().take(max_body).read_to_string(&mut raw);
    let body: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let cfg = read_config();

    let raw_url = req.url().to_string();
    let url_path = raw_url.split('?').next().unwrap_or(&raw_url);
    let out = match (req.method().clone(), url_path) {
        (Method::Get, "/local/status") => json!({
            "connected": linked.load(Ordering::Relaxed),
            "blocked": is_blocked(),
            "version": APP_VERSION,
        }),
        (Method::Post, "/local/block") => {
            if !is_admin_mode() {
                let pw = body["password"].as_str().unwrap_or("");
                if pw.trim().is_empty() || !password_ok(&cfg, pw) {
                    std::thread::sleep(Duration::from_secs(1));
                    log_action("BLOCK refused - wrong password");
                    json!({"success": false, "error": "كلمة السر غير صحيحة"})
                } else {
                    match apply_block("local user") {
                        Ok(_) => {
                            let mut l = read_client();
                            l.pending_event = "block_password".to_string();
                            let _ = write_client(&l);
                            json!({"success": true})
                        }
                        Err(e) => json!({"success": false, "error": e}),
                    }
                }
            } else {
                match apply_block("local user") {
                    Ok(_) => json!({"success": true}),
                    Err(e) => json!({"success": false, "error": e}),
                }
            }
        }
        (Method::Post, "/local/unblock") => {
            if !password_ok(&cfg, body["password"].as_str().unwrap_or("")) {
                std::thread::sleep(Duration::from_secs(1));
                log_action("UNBLOCK refused - wrong password");
                spawn_security_alert(
                    "auth_fail",
                    "high",
                    "⚠️ محاولة فاشلة لفتح الإنترنت بكلمة سر خاطئة على جهاز الموظف".to_string(),
                );
                json!({"success": false, "error": "كلمة السر غير صحيحة"})
            } else {
                match apply_unblock("local user") {
                    Ok(_) => {
                        let mut l = read_client();
                        l.pending_event = "unblock_password".to_string();
                        let _ = write_client(&l);
                        spawn_security_alert(
                            "bypass",
                            "medium",
                            "🔓 تم فتح قفل الإنترنت محلياً باستخدام كلمة السر على جهاز الموظف".to_string(),
                        );
                        json!({"success": true})
                    }
                    Err(e) => json!({"success": false, "error": e}),
                }
            }
        }
        (Method::Get, "/local/screenshot") => {
            LAST_CAPTURE_POLL_SECS.store(epoch_secs(), Ordering::Relaxed);
            if let Some(q) = raw_url.split('?').nth(1) {
                let mut cw: Option<bool> = None;
                let mut ew: Option<bool> = None;
                for pair in q.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k == "cw" {
                            cw = Some(v == "1");
                        } else if k == "ew" {
                            ew = Some(v == "1");
                        }
                    }
                }
                if let (Some(c), Some(e)) = (cw, ew) {
                    crate::common::report_user_browser_windows(c, e);
                }
            }
            let recent_ext = {
                let mut g = RECENT_EXT_UPLOADS.lock().unwrap_or_else(|e| e.into_inner());
                g.retain(|(_, t)| t.elapsed() < Duration::from_secs(12));
                g.last().map(|(n, _)| n.clone()).unwrap_or_default()
            };
            let active_stream = if epoch_ms() < STREAM_UNTIL_MS.load(Ordering::Relaxed) {
                STREAM_MODE.lock().map(|g| g.clone()).unwrap_or_default()
            } else {
                String::new()
            };
            json!({
                "requested": SCREEN_WANTED.load(Ordering::Relaxed),
                "stream_mode": active_stream,
                "evidence_wanted": EVIDENCE_WANTED.load(Ordering::Relaxed),
                "blocked_host": crate::proxy::take_denied_notification().unwrap_or_default(),
                "wa_active": crate::proxy::was_whatsapp_recently_active(180),
                "wa_proxy_upload": crate::proxy::take_whatsapp_proxy_upload()
                    .map(|(h, b)| json!({"host": h, "bytes": b}))
                    .unwrap_or(Value::Null),
                "recent_ext_file": recent_ext,
            })
        }
        (Method::Post, "/local/whatsapp-context") => {
            let rn = body["recipient_name"].as_str().unwrap_or("").trim().to_string();
            let rp = body["recipient_phone"].as_str().unwrap_or("").trim().to_string();
            let pu = body["page_url"].as_str().unwrap_or("").trim().to_string();
            if !rn.is_empty() || !rp.is_empty() || !pu.is_empty() {
                let mut g = LAST_WA_CONTEXT.lock().unwrap_or_else(|e| e.into_inner());
                *g = Some((rn, rp, pu, Instant::now()));
            }
            json!({"success": true})
        }
        (Method::Post, "/local/evidence") => {
            let sc = body["screenshot"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
            let cam = body["camera_photo"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
            let rn = body["recipient_name"].as_str().unwrap_or("").trim().to_string();
            let rp = body["recipient_phone"].as_str().unwrap_or("").trim().to_string();
            let pu = body["page_url"].as_str().unwrap_or("").trim().to_string();
            {
                let mut g = EVIDENCE_STORE.lock().unwrap_or_else(|e| e.into_inner());
                *g = Some((sc, cam, rn, rp, pu, Instant::now()));
            }
            EVIDENCE_WANTED.store(false, Ordering::SeqCst);
            json!({"success": true})
        }
        (Method::Post, "/local/whatsapp-upload") => {
            let raw_name = body["file_name"].as_str().unwrap_or("").trim();
            let file_name = if raw_name.is_empty() {
                "ملف مرفوع عبر الإنترنت".to_string()
            } else {
                raw_name.to_string()
            };
            let size_bytes = body["file_size_bytes"].as_u64().unwrap_or(0);
            let file_size = body["file_size"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .unwrap_or_else(|| {
                    if size_bytes > 0 {
                        format_file_size(size_bytes)
                    } else {
                        "غير محدد".to_string()
                    }
                });
            let file_path = body["file_path"].as_str().unwrap_or("").trim().to_string();
            let staged_path = body["staged_path"].as_str().unwrap_or("").trim().to_string();
            let mut recipient_name = body["recipient_name"].as_str().unwrap_or("").trim().to_string();
            let mut recipient_phone = body["recipient_phone"].as_str().unwrap_or("").trim().to_string();
            let mut page_url = body["page_url"].as_str().unwrap_or("").trim().to_string();
            let page_title = body["page_title"].as_str().unwrap_or("").trim().to_string();
            if page_url.is_empty() && !page_title.is_empty() {
                page_url = page_title.clone();
            }
            if is_company_erp_url_or_title(&page_url)
                || is_company_erp_url_or_title(&page_title)
                || is_company_erp_url_or_title(&recipient_name)
            {
                let _ = req.respond(reply(json!({"success": true, "skipped": "company_erp"})));
                return;
            }
            let win_user = body["windows_user"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .unwrap_or_else(|| std::env::var("USERNAME").unwrap_or_default());
            let detection_source = body["detection_source"]
                .as_str()
                .unwrap_or("whatsapp_web")
                .trim()
                .to_string();
            let mut screenshot = body["screenshot"].as_str().unwrap_or("").trim().to_string();
            let mut camera_photo = body["camera_photo"].as_str().unwrap_or("").trim().to_string();

            if !detection_source.starts_with("capture_") {
                {
                    let mut g = RECENT_EXT_UPLOADS.lock().unwrap_or_else(|e| e.into_inner());
                    g.retain(|(_, t)| t.elapsed() < Duration::from_secs(12));
                    g.push((file_name.clone(), Instant::now()));
                }
                if screenshot.is_empty() && camera_photo.is_empty() {
                    {
                        let mut g = EVIDENCE_STORE.lock().unwrap_or_else(|e| e.into_inner());
                        *g = None;
                    }
                    EVIDENCE_WANTED.store(true, Ordering::SeqCst);
                    let wait_start = Instant::now();
                    while wait_start.elapsed() < Duration::from_millis(1600) {
                        std::thread::sleep(Duration::from_millis(100));
                        let found = {
                            let mut g = EVIDENCE_STORE.lock().unwrap_or_else(|e| e.into_inner());
                            g.take()
                        };
                        if let Some((sc, cam, rn, rp, pu, _)) = found {
                            if screenshot.is_empty() { screenshot = sc.unwrap_or_default(); }
                            if camera_photo.is_empty() { camera_photo = cam.unwrap_or_default(); }
                            if recipient_name.is_empty() && !rn.is_empty() { recipient_name = rn; }
                            if recipient_phone.is_empty() && !rp.is_empty() { recipient_phone = rp; }
                            if page_url.is_empty() && !pu.is_empty() { page_url = pu; }
                            break;
                        }
                    }
                    EVIDENCE_WANTED.store(false, Ordering::SeqCst);
                }
            }

            if recipient_name.is_empty() || recipient_phone.is_empty() {
                let ctx_opt = {
                    let g = LAST_WA_CONTEXT.lock().unwrap_or_else(|e| e.into_inner());
                    g.clone()
                };
                if let Some((rn, rp, pu, ts)) = ctx_opt {
                    if ts.elapsed() <= Duration::from_secs(180) {
                        if recipient_name.is_empty() && !rn.is_empty() {
                            recipient_name = rn;
                        }
                        if recipient_phone.is_empty() && !rp.is_empty() {
                            recipient_phone = rp;
                        }
                        if page_url.is_empty() && !pu.is_empty() {
                            page_url = pu;
                        }
                    }
                }
            }

            if is_noise_recipient_label(&recipient_name) {
                recipient_name.clear();
            }
            if page_url == "Open" || page_url == "فتح" {
                page_url.clear();
            }
            let is_whatsapp = detection_source.contains("whatsapp")
                || page_url.to_ascii_lowercase().contains("whatsapp")
                || page_url.contains("واتساب")
                || page_title.to_ascii_lowercase().contains("whatsapp")
                || page_title.contains("واتساب");
            if recipient_phone.is_empty() && !recipient_name.is_empty() && is_whatsapp {
                if let Some(ph) = crate::common::lookup_whatsapp_phone_by_name(&recipient_name) {
                    recipient_phone = ph;
                }
            }
            let channel = if is_whatsapp { "whatsapp_web" } else { "web_upload" };

            let uploaded_file = save_and_upload_dlp_file(
                &file_name,
                &file_path,
                &staged_path,
                body["file_base64"].as_str(),
                channel,
                &recipient_name,
                &recipient_phone,
                &page_url,
                &win_user,
            );
            let uploaded_file_id = uploaded_file.as_ref().map(|(id, _)| id.clone());
            let file_sha256 = uploaded_file.as_ref().map(|(_, h)| h.clone());

            let (category_ar, severity, ext) = classify_dlp_file(&file_name, size_bytes);
            let final_ext = if ext.is_empty() {
                body["file_type"].as_str().unwrap_or("").trim().to_string()
            } else {
                ext
            };
            let target_str = match (recipient_name.is_empty(), recipient_phone.is_empty()) {
                (false, false) => format!(" إلى {} ({})", recipient_name, recipient_phone),
                (false, true) => format!(" إلى {}", recipient_name),
                (true, false) => format!(" إلى {}", recipient_phone),
                (true, true) => if !page_url.is_empty() { format!(" (عبر {})", page_url) } else { String::new() },
            };
            let channel_label = if is_whatsapp { "واتساب ويب" } else { "الإنترنت" };
            let message = format!(
                "📤 رفع ملف على {}: {} ({} · {}){}",
                channel_label, file_name, category_ar, file_size, target_str
            );
            let mut meta = json!({
                "channel": channel,
                "file_name": file_name,
                "file_ext": final_ext,
                "file_category": category_ar,
                "file_size": file_size,
                "file_path": file_path,
                "recipient_name": recipient_name,
                "recipient_phone": recipient_phone,
                "page_url": page_url,
                "windows_user": win_user,
                "detection_source": detection_source,
            });
            if let Some(ref fid) = uploaded_file_id {
                meta["uploaded_file_id"] = json!(fid);
            }
            if let Some(ref h) = file_sha256 {
                meta["sha256"] = json!(h);
            }
            if !screenshot.is_empty() {
                meta["screenshot"] = json!(screenshot);
            }
            if !camera_photo.is_empty() {
                meta["camera_photo"] = json!(camera_photo);
            }
            enqueue_client_alert(json!({
                "type": "exfil",
                "severity": severity,
                "message": message,
                "meta": meta,
            }));
            SCREEN_WANTED.store(true, Ordering::Relaxed);
            log_action(&format!("Upload DLP alert: {} ({}, archived={})", file_name, category_ar, uploaded_file_id.is_some()));
            json!({"success": true, "uploaded_file_id": uploaded_file_id})
        }
        (Method::Post, "/local/screenshot") => {
            let img = body["image"].as_str().unwrap_or("");
            let kind = body["kind"].as_str().unwrap_or("screen");
            let err_str = body["error"].as_str().unwrap_or("");
            if img.is_empty() && err_str.is_empty() {
                json!({"success": false, "error": "no image"})
            } else {
                let link = read_client();
                let transport = Transport::from_link(&link);
                let result = match transport {
                    Transport::Relay => {
                        let relay = RelayClient::new();
                        relay
                            .upload_screen_frame(&link.relay_url, &link.device_token, img, kind, err_str)
                            .is_some()
                    }
                    Transport::Lan => {
                        let http = tls_agent(30);
                        lan_upload_screen_frame(&http, &link, img, kind, err_str).is_some()
                    }
                };
                if result {
                    if epoch_ms() >= STREAM_UNTIL_MS.load(Ordering::Relaxed) {
                        SCREEN_WANTED.store(false, Ordering::Relaxed);
                        log_action("Screenshot uploaded");
                    }
                    json!({"success": true})
                } else {
                    json!({"success": false, "error": "upload failed"})
                }
            }
        }
        (Method::Post, "/local/rustdesk") => {
            let mut link = read_client();
            if let Some(id) = body["rustdesk_id"].as_str() {
                if !id.trim().is_empty() {
                    link.rustdesk_id = id.trim().to_string();
                    let _ = write_client(&link);
                }
            }
            json!({"success": true})
        }
        (Method::Post, "/local/relay") => {
            if !password_ok(&cfg, body["password"].as_str().unwrap_or("")) {
                std::thread::sleep(Duration::from_secs(1));
                log_action("Relay link refused - wrong password");
                json!({"success": false, "error": "كلمة السر غير صحيحة"})
            } else {
                let url = body["relay_url"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
                let pt = body["pairing_token"].as_str().unwrap_or("").trim().to_string();
                let mut link = read_client();
                if url.is_empty() {
                    json!({"success": false, "error": "عنوان الـ Relay مطلوب"})
                } else {
                    link.relay_url = url;
                    link.device_token = String::new();
                    link.last_command_id = String::new();
                    link.policy_version = String::new();
                    link.transport = "relay".to_string();
                    if pt.is_empty() {
                        link.pairing_token = String::new();
                    } else {
                        link.pairing_token = pt;
                    }
                    match write_client(&link) {
                        Ok(_) => {
                            log_action("Relay link saved by agent");
                            if !link.pairing_token.is_empty() {
                                if let Some((device_id, device_token)) =
                                    RelayClient::new().enroll(&link.relay_url, &link.pairing_token)
                                {
                                    link.device_id = device_id;
                                    link.device_token = device_token;
                                    let _ = write_client(&link);
                                    linked.store(true, Ordering::Relaxed);
                                    log_action("Relay enrollment succeeded (immediate)");
                                }
                            }
                            json!({"success": true})
                        }
                        Err(e) => json!({"success": false, "error": e}),
                    }
                }
            }
        }
        (Method::Post, "/local/relay/off") => {
            if !password_ok(&cfg, body["password"].as_str().unwrap_or("")) {
                std::thread::sleep(Duration::from_secs(1));
                log_action("Relay disconnect refused - wrong password");
                spawn_security_alert(
                    "tamper",
                    "high",
                    "⚠️ محاولة فاشلة لفك ربط الجهاز بالـ Relay بكلمة سر خاطئة".to_string(),
                );
                json!({"success": false, "error": "كلمة السر غير صحيحة"})
            } else {
                let mut link = read_client();
                link.relay_url = String::new();
                link.device_token = String::new();
                link.pairing_token = String::new();
                link.last_command_id = String::new();
                link.transport = "lan".to_string();
                match write_client(&link) {
                    Ok(_) => {
                        linked.store(false, Ordering::Relaxed);
                        log_action("Relay link removed by agent");
                        json!({"success": true})
                    }
                    Err(e) => json!({"success": false, "error": e}),
                }
            }
        }
        (Method::Post, "/local/link") => {
            if !password_ok(&cfg, body["password"].as_str().unwrap_or("")) {
                std::thread::sleep(Duration::from_secs(1));
                spawn_security_alert(
                    "tamper",
                    "high",
                    "⚠️ محاولة فاشلة لتغيير إعدادات ربط السيرفر بكلمة سر خاطئة".to_string(),
                );
                json!({"success": false, "error": "كلمة السر مطلوبة لتعديل الربط"})
            } else {
                let mut link = read_client();
                link.server_url = body["server_url"]
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('/')
                    .to_string();
                link.token = body["token"].as_str().unwrap_or("").trim().to_string();
                link.transport = "lan".to_string();
                link.relay_url = String::new();
                link.device_token = String::new();
                link.pairing_token = String::new();
                link.policy_version = String::new();
                match write_client(&link) {
                    Ok(_) => {
                        log_action("Server link updated");
                        let quick_http = tls_agent(4);
                        if lan_poll(&quick_http, &link, None).is_some() {
                            linked.store(true, Ordering::Relaxed);
                            log_action("LAN poll succeeded");
                            json!({"success": true, "connected": true})
                        } else {
                            linked.store(false, Ordering::Relaxed);
                            log_action("LAN poll failed after saving link");
                            json!({
                                "success": false,
                                "error": "تم حفظ بيانات الربط، لكن تعذر الوصول لسيرفر المدير الآن (تأكد من العنوان والمفتاح وأن لوحة المدير مفتوحة)"
                            })
                        }
                    }
                    Err(e) => json!({"success": false, "error": e}),
                }
            }
        }
        _ => json!({"success": false, "error": "not found"}),
    };
    let _ = req.respond(reply(out));
}