//! Local HTTP proxy used by the agent.
//!
//! Runs on 127.0.0.1:8080 (the address the block script already points the
//! system proxy at). It:
//!   * logs every host the device tries to reach (whitelist/blacklist aware),
//!   * denies hosts that are not allowed while the device is blocked,
//!   * shapes traffic to the per-device limit when one is configured.
//!
//! The proxy never decrypts allowed TLS traffic: HTTPS is tunnelled with
//! raw TCP CONNECT for permitted hosts, and uses a local IT ELKHAWGA Root CA
//! solely to return the browser block page for explicitly denied hosts.

use crate::common::*;
use chrono::Datelike;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const PROXY_ADDR: &str = "127.0.0.1:8080";
const MAX_HEAD: usize = 16 * 1024;
const LOG_LIMIT: usize = 40;

#[derive(Default)]
pub struct SiteLog {
    pub hosts: VecDeque<(String, u64)>,
    pub denied: VecDeque<String>,
    pub exfil: VecDeque<String>,
    pub pending_notify: Option<String>,
    pub last_notify_by_host: std::collections::HashMap<String, Instant>,
}

pub struct ProxyState {
    pub sites: Mutex<SiteLog>,
    /// Current throttle in kilobits per second (0 = unlimited).
    pub throttle_kbps: AtomicU32,
}

impl ProxyState {
    pub fn new() -> Self {
        ProxyState {
            sites: Mutex::new(SiteLog::default()),
            throttle_kbps: AtomicU32::new(0),
        }
    }

    pub fn record(&self, host: &str) {
        if host.is_empty() || is_background_noise_host(host) {
            return;
        }
        let mut log = self.sites.lock().unwrap();
        let now = now_secs();
        if let Some(pos) = log.hosts.iter().position(|(h, _)| h == host) {
            log.hosts.remove(pos);
        }
        log.hosts.push_front((host.to_string(), now));
        while log.hosts.len() > LOG_LIMIT {
            log.hosts.pop_back();
        }
    }

    pub fn recent(&self) -> Vec<String> {
        let log = self.sites.lock().unwrap();
        log.hosts.iter().take(15).map(|(h, _)| h.clone()).collect()
    }

    pub fn record_denied(&self, host: &str) {
        if host.is_empty() || is_background_noise_host(host) {
            return;
        }
        let mut log = self.sites.lock().unwrap();
        if let Some(pos) = log.denied.iter().position(|h| h == host) {
            log.denied.remove(pos);
        }
        log.denied.push_front(host.to_string());
        while log.denied.len() > 15 {
            log.denied.pop_back();
        }
    }

    pub fn recent_denied(&self) -> Vec<String> {
        let log = self.sites.lock().unwrap();
        log.denied.iter().take(12).cloned().collect()
    }

    pub fn record_exfil(&self, host: &str) {
        if host.is_empty() {
            return;
        }
        let mut log = self.sites.lock().unwrap();
        if let Some(pos) = log.exfil.iter().position(|h| h == host) {
            log.exfil.remove(pos);
        }
        log.exfil.push_front(host.to_string());
        while log.exfil.len() > 15 {
            log.exfil.pop_back();
        }
    }

    pub fn drain_exfil(&self) -> Vec<String> {
        let mut log = self.sites.lock().unwrap();
        let out: Vec<String> = log.exfil.drain(..).collect();
        out
    }

    pub fn queue_notification(&self, host: &str) {
        if is_background_noise_host(host) {
            return;
        }
        let disp = display_root_domain(host);
        if disp.is_empty() || is_background_noise_host(&disp) {
            return;
        }
        let mut log = self.sites.lock().unwrap();
        let now = Instant::now();
        if let Some(prev) = log.last_notify_by_host.get(&disp) {
            if now.duration_since(*prev) < Duration::from_secs(2) {
                return;
            }
        }
        if log.last_notify_by_host.len() > 128 {
            log.last_notify_by_host
                .retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
        }
        log.last_notify_by_host.insert(disp.clone(), now);
        log.pending_notify = Some(disp);
    }

    pub fn take_notification(&self) -> Option<String> {
        let mut log = self.sites.lock().unwrap();
        log.pending_notify.take()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

static STATE: std::sync::OnceLock<Arc<ProxyState>> = std::sync::OnceLock::new();

pub fn global() -> Arc<ProxyState> {
    STATE
        .get_or_init(|| Arc::new(ProxyState::new()))
        .clone()
}

/// Starts the proxy once on a background thread.
pub fn start_default() {
    start(global());
}

pub fn set_throttle(kbps: u32) {
    global().throttle_kbps.store(kbps, Ordering::Relaxed);
}

pub fn recent_sites() -> Vec<String> {
    global().recent()
}

pub fn recent_denied() -> Vec<String> {
    global().recent_denied()
}

pub fn record_exfil(host: &str) {
    global().record_exfil(host);
}

pub fn drain_exfil() -> Vec<String> {
    global().drain_exfil()
}

pub fn take_denied_notification() -> Option<String> {
    global().take_notification()
}

/// Starts the proxy on a background thread. Safe to call once.
pub fn start(state: Arc<ProxyState>) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(PROXY_ADDR) {
            Ok(l) => l,
            Err(_) => return,
        };
        for stream in listener.incoming().flatten() {
            let st = state.clone();
            std::thread::spawn(move || {
                let _ = handle(stream, &st);
            });
        }
    });
}

fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut b = [0u8; 512];
    loop {
        let n = stream.read(&mut b).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&b[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
    }
    String::from_utf8(buf).ok()
}

fn header_value(head: &str, name: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn request_line(head: &str) -> Option<(String, String, String)> {
    let first = head.lines().next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    Some((method, target, version))
}

/// host[:port] for a request target.
fn target_host_port(method: &str, target: &str) -> Option<(String, u16)> {
    if method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = target.split_once(':').unwrap_or((target, "443"));
        return Some((h.to_string(), p.parse().unwrap_or(443)));
    }
    // absolute-URI form: http://host[:port]/path
    let rest = target.split("://").nth(1)?;
    let hostport = rest.split('/').next()?;
    let (h, p) = hostport.split_once(':').unwrap_or((hostport, "80"));
    Some((h.to_string(), p.parse().unwrap_or(80)))
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').trim_start_matches("www.").to_lowercase()
}

fn display_root_domain(host: &str) -> String {
    let mut h = host.trim().trim_end_matches('.').to_lowercase();
    for prefix in ["www.", "m.", "mobile.", "web."] {
        if let Some(rest) = h.strip_prefix(prefix) {
            h = rest.to_string();
        }
    }
    h
}

fn host_matches_domain(h: &str, domain: &str) -> bool {
    !domain.is_empty() && (h == domain || h.ends_with(&format!(".{}", domain)))
}

fn is_background_noise_host(host: &str) -> bool {
    let h = normalize_host(host);
    if h.is_empty() {
        return true;
    }
    if h.starts_with("ocsp.")
        || h.starts_with("crl.")
        || h.starts_with("telemetry.")
        || h.starts_with("metrics.")
        || (1..=6).any(|i| h.starts_with(&format!("clients{}.", i)))
    {
        return true;
    }
    const NOISE_DOMAINS: &[&str] = &[
        "windowsupdate.com",
        "update.microsoft.com",
        "events.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "delivery.mp.microsoft.com",
        "do.dsp.mp.microsoft.com",
        "telecommandsvc.microsoft.com",
        "officeclient.microsoft.com",
        "microsoft.com",
        "windows.com",
        "windows.net",
        "bing.com",
        "msn.com",
        "live.com",
        "officeapps.live.com",
        "skype.com",
        "office.com",
        "office.net",
        "ecs.office.com",
        "c2r.ts.cdn.office.net",
        "msftconnecttest.com",
        "msftncsi.com",
        "sfx.ms",
        "gfx.ms",
        "onestore.ms",
        "azureedge.net",
        "azure.com",
        "trafficmanager.net",
        "msedge.net",
        "b-msedge.net",
        "a-msedge.net",
        "spo-msedge.net",
        "l-msedge.net",
        "s-msedge.net",
        "t-msedge.net",
        "edge.microsoft.com",
        "microsoftedgeservices.com",
        "nelreports.net",
        "smartscreen.microsoft.com",
        "smartscreen-prod.microsoft.com",
        "footprintdns.com",
        "msidentity.com",
        "msauth.net",
        "msftauth.net",
        "passport.net",
        "microsoftonline.com",
        "virtualearth.net",
        "googleapis.com",
        "accounts.google.com",
        "clients1.google.com",
        "clients2.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "clients5.google.com",
        "clients6.google.com",
        "update.googleapis.com",
        "safebrowsing.googleapis.com",
        "optimizationguide-pa.googleapis.com",
        "content-autofill.googleapis.com",
        "clientservices.googleapis.com",
        "fonts.googleapis.com",
        "ajax.googleapis.com",
        "gstatic.com",
        "gvt1.com",
        "gvt2.com",
        "1e100.net",
        "digicert.com",
        "sectigo.com",
        "verisign.com",
        "identrust.com",
        "letsencrypt.org",
        "lencr.org",
        "pki.goog",
        "googletagmanager.com",
        "google-analytics.com",
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "scorecardresearch.com",
        "criteo.com",
        "taboola.com",
        "outbrain.com",
        "adsrvr.org",
        "adnxs.com",
        "rubiconproject.com",
        "pubmatic.com",
        "casalemedia.com",
        "openx.net",
        "moatads.com",
        "amazon-adsystem.com",
        "facebook.net",
        "fbcdn.net",
        "fbsbx.com",
        "cdninstagram.com",
        "ytimg.com",
        "googlevideo.com",
        "ggpht.com",
        "twimg.com",
        "tiktokcdn.com",
        "cloudflareinsights.com",
        "cloudfront.net",
        "akamaized.net",
        "akamaihd.net",
        "akamai.net",
        "fastly.net",
        "jsdelivr.net",
        "unpkg.com",
        "cdnjs.com",
        "fontawesome.com",
        "clarity.ms",
        "hotjar.com",
        "sentry.io",
        "whatsapp.net",
        "anydesk.com",
        "mozilla.com",
        "mozilla.net",
        "firefox.com",
        "opera.com",
        "brave.com",
    ];
    if NOISE_DOMAINS.iter().any(|d| host_matches_domain(&h, d)) {
        return true;
    }
    ["rustdesk.com", "rustdesk.net", "tailscale.com", "ts.net"]
        .iter()
        .any(|d| host_matches_domain(&h, d))
}

fn extract_url_host(raw: &str) -> String {
    raw.trim()
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

fn is_local_or_private_lan_host(h: &str) -> bool {
    if h == "localhost" || h == "127.0.0.1" || h == "::1" || h.ends_with(".local") {
        return true;
    }
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|s| s.parse::<u8>().is_ok()) {
        let a: u8 = parts[0].parse().unwrap_or(0);
        let b: u8 = parts[1].parse().unwrap_or(0);
        if a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && (16..=31).contains(&b)) {
            return true;
        }
    }
    false
}

fn host_always_allowed_with(h: &str, snap: &ProxyPolicySnapshot) -> bool {
    // Always allow the local machine, private LAN IPs (branch routers 192.168.x.x / 10.x.x.x, DVRs, printers),
    // and the relay/control plane, otherwise a blocked device could never access local LAN routers or poll.
    if is_local_or_private_lan_host(h) {
        return true;
    }
    snap.always_allowed_hosts
        .iter()
        .any(|d| host_matches_domain(h, d))
}

fn host_always_allowed(host: &str) -> bool {
    let h = normalize_host(host);
    let snap = cached_policy_snapshot();
    host_always_allowed_with(&h, &snap)
}

fn host_in_cleaned_list(h: &str, cleaned_entries: &[String]) -> bool {
    for d in cleaned_entries {
        if host_matches_domain(h, d) {
            return true;
        }
        if (d == "web.whatsapp.com" || d == "whatsapp.com")
            && (host_matches_domain(h, "whatsapp.com") || host_matches_domain(h, "whatsapp.net"))
        {
            return true;
        }
    }
    false
}

fn host_explicitly_allowed_with(h: &str, snap: &ProxyPolicySnapshot) -> bool {
    host_always_allowed_with(h, snap) || host_in_cleaned_list(h, &snap.allowed_domains)
}

fn host_explicitly_allowed(host: &str) -> bool {
    let h = normalize_host(host);
    let snap = cached_policy_snapshot();
    host_explicitly_allowed_with(&h, &snap)
}

fn host_in_blocked_list_with(
    h: &str,
    snap: &ProxyPolicySnapshot,
    include_default_blacklist: bool,
) -> bool {
    if host_in_cleaned_list(h, &snap.blocked_domains) {
        return true;
    }
    if include_default_blacklist {
        const DEFAULT_DISTRACTIONS: [&str; 13] = [
            "youtube.com",
            "facebook.com",
            "m.facebook.com",
            "twitter.com",
            "x.com",
            "instagram.com",
            "tiktok.com",
            "reddit.com",
            "netflix.com",
            "twitch.tv",
            "snapchat.com",
            "pinterest.com",
            "linkedin.com",
        ];
        if DEFAULT_DISTRACTIONS
            .iter()
            .any(|d| host_matches_domain(h, d))
        {
            return true;
        }
    }
    false
}

fn host_in_blocked_list(host: &str, include_default_blacklist: bool) -> bool {
    let h = normalize_host(host);
    let snap = cached_policy_snapshot();
    host_in_blocked_list_with(&h, &snap, include_default_blacklist)
}

fn host_denied_by_policy(host: &str) -> bool {
    if !is_blocked() {
        return false;
    }
    let h = normalize_host(host);
    let snap = cached_policy_snapshot();
    if host_always_allowed_with(&h, &snap) {
        return false;
    }
    if snap.mode == "blacklist" {
        !host_explicitly_allowed_with(&h, &snap) && host_in_blocked_list_with(&h, &snap, true)
    } else {
        !host_explicitly_allowed_with(&h, &snap)
    }
}

/// Token-bucket style paced copy. `kbps` = 0 means no limit.
fn is_suspicious_host(host: &str) -> bool {
    let suspicious = [
        "mega.nz", "dropbox.com", "drive.google.com", "wetransfer.com",
        "sendspace.com", "mediafire.com", "4shared.com", "rapidshare.com",
        "anonfiles.com", "gofile.io", "transfer.sh", "file.io",
    ];
    suspicious.iter().any(|s| host == *s || host.ends_with(&format!(".{}", s)))
}

static LAST_WHATSAPP_SECS: AtomicU64 = AtomicU64::new(0);
static WA_UPLOAD_ACCUM: Mutex<
    Option<std::collections::HashMap<String, (u64, Instant, Instant, Option<Instant>)>>,
> = Mutex::new(None);

use std::sync::atomic::AtomicU64;

pub fn was_whatsapp_recently_active(within_secs: u64) -> bool {
    let last = LAST_WHATSAPP_SECS.load(Ordering::Relaxed);
    last > 0 && now_secs().saturating_sub(last) <= within_secs
}

pub fn take_whatsapp_proxy_upload() -> Option<(String, u64)> {
    let mut guard = WA_UPLOAD_ACCUM.lock().unwrap();
    let map = guard.as_mut()?;
    let now = Instant::now();
    for (host, entry) in map.iter_mut() {
        let (bytes, first_at, last_at, last_emit) = entry;
        if *bytes > 0 && now.duration_since(*last_at) > Duration::from_secs(25) {
            *bytes = 0;
            continue;
        }
        let settled = now.duration_since(*last_at) >= Duration::from_millis(550)
            || now.duration_since(*first_at) >= Duration::from_secs(6);
        let cooldown_ok = last_emit.map_or(true, |prev| now.duration_since(prev) >= Duration::from_secs(5));
        if *bytes >= 10 * 1024 && settled && cooldown_ok {
            let total = *bytes;
            *bytes = 0;
            *first_at = now;
            *last_at = now;
            *last_emit = Some(now);
            return Some((host.clone(), total));
        }
    }
    None
}

fn is_whatsapp_media_upload_host(host: &str) -> bool {
    let h = normalize_host(host);
    // Strictly match WhatsApp's Multimedia Upload Gateway (`mmg.whatsapp.net`).
    // `media-*.cdn.whatsapp.net` and `media.*.fna.whatsapp.net` are download CDNs whose
    // TLS/HTTP GET handshakes (~4.2 KB) would otherwise cause false fileless alerts.
    h == "mmg.whatsapp.net" || h.ends_with(".mmg.whatsapp.net")
}

fn record_whatsapp_upload_bytes(host: &str, bytes: u64) {
    let h = normalize_host(host);
    if !is_whatsapp_media_upload_host(&h) {
        return;
    }
    let mut guard = WA_UPLOAD_ACCUM.lock().unwrap();
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let now = Instant::now();
    let entry = map.entry(h).or_insert((0, now, now, None));
    if entry.0 == 0 || now.duration_since(entry.2) > Duration::from_secs(20) {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 = entry.0.saturating_add(bytes);
    entry.2 = now;
}

// Per-host upload tracking with a 10-minute window.
static UPLOADS: std::sync::Mutex<Option<std::collections::HashMap<String, (u64, std::time::Instant)>>> =
    std::sync::Mutex::new(None);

fn track_upload_dir(host: &str, bytes: u64, is_upload: bool) {
    if !is_upload || bytes == 0 || host.is_empty() {
        return;
    }
    record_whatsapp_upload_bytes(host, bytes);
    let snap = cached_policy_snapshot();
    let threshold_mb: u64 = snap.exfil_threshold_mb;
    let window_secs: u64 = snap.exfil_window_secs;
    let mut guard = UPLOADS.lock().unwrap();
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let now = std::time::Instant::now();
    let entry = map.entry(host.to_string()).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() > window_secs {
        entry.0 = 0;
        entry.1 = now;
    }
    entry.0 = entry.0.saturating_add(bytes);
    if entry.0 > threshold_mb * 1024 * 1024 {
        crate::proxy::record_exfil(host);
        // reset window so we don't spam
        entry.0 = 0;
        entry.1 = now;
    }
}

fn copy_paced(mut src: TcpStream, mut dst: TcpStream, kbps: u32, host: &str, is_upload: bool) {
    let mut buf = vec![0u8; 16 * 1024];
    let bytes_per_sec = (kbps as f64) * 1000.0 / 8.0;
    let started = Instant::now();
    let mut sent: f64 = 0.0;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if dst.write_all(&buf[..n]).is_err() {
            break;
        }
        sent += n as f64;
        track_upload_dir(host, n as u64, is_upload);
        if bytes_per_sec > 0.0 {
            let target = Duration::from_secs_f64(sent / bytes_per_sec);
            let elapsed = started.elapsed();
            if target > elapsed {
                std::thread::sleep(target - elapsed);
            }
        }
    }
    let _ = dst.shutdown(std::net::Shutdown::Write);
}

fn respond(stream: &mut TcpStream, code: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        body.len(),
        body
    );
    let _ = stream.write_all(msg.as_bytes());
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn blocked_page_html(host: &str) -> String {
    let safe_host = escape_html(host);
    format!(
        r#"<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>موقع محظور - IT ELKHAWGA</title>
<style>
  body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;font-family:'Segoe UI',Tahoma,sans-serif;color:#f8fafc;padding:20px}}
  .card{{max-width:480px;width:100%;background:#1e293b;border:1px solid #334155;border-top:5px solid #ef4444;border-radius:16px;padding:32px 28px;text-align:center;box-shadow:0 20px 50px rgba(0,0,0,.45)}}
  .icon{{font-size:48px;margin-bottom:12px}}
  h1{{margin:0 0 10px;font-size:22px;color:#fca5a5}}
  .host{{display:inline-block;margin:12px 0;padding:8px 16px;border-radius:10px;background:#0f172a;border:1px solid #334155;font-family:Consolas,monospace;font-size:15px;color:#38bdf8;direction:ltr}}
  p{{margin:8px 0 0;color:#cbd5e1;font-size:14.5px;line-height:1.7}}
  .foot{{margin-top:20px;font-size:12px;color:#64748b}}
</style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>هذا الموقع مقفول بواسطة IT ELKHAWGA</h1>
    <div class="host">{}</div>
    <p>تم حظر الوصول إلى هذا الموقع طبقاً لسياسة الشركة.<br>إذا كنت بحاجة إلى فتحه للعمل، يرجى التواصل مع قسم الـ IT.</p>
    <div class="foot">IT ELKHAWGA Security System</div>
  </div>
</body>
</html>"#,
        safe_host
    )
}

fn build_root_ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "IT ELKHAWGA Security Root CA");
    dn.push(DnType::OrganizationName, "IT ELKHAWGA");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 12, 31);
    params
}

struct RootCaState {
    ca_cert: Certificate,
    #[cfg_attr(not(test), allow(dead_code))]
    ca_cert_der: CertificateDer<'static>,
    ca_key: KeyPair,
    shared_leaf_key: KeyPair,
    shared_leaf_key_der: Vec<u8>,
    leaf_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl RootCaState {
    fn load_or_create(ca_dir: &Path) -> Result<Self, String> {
        let key_path = ca_dir.join("ca-key.pem");
        let cer_path = ca_dir.join("ca-cert.cer");
        let pem_path = ca_dir.join("ca-cert.pem");

        let shared_leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("generate shared leaf key: {}", e))?;
        let shared_leaf_key_der = shared_leaf_key.serialize_der();

        if key_path.exists() && cer_path.exists() {
            if let (Ok(key_pem), Ok(cer_bytes)) =
                (fs::read_to_string(&key_path), fs::read(&cer_path))
            {
                if !cer_bytes.is_empty() {
                    if let Ok(ca_key) = KeyPair::from_pem(&key_pem) {
                        if let Ok(ca_cert) = build_root_ca_params().self_signed(&ca_key) {
                            return Ok(Self {
                                ca_cert,
                                ca_cert_der: CertificateDer::from(cer_bytes),
                                ca_key,
                                shared_leaf_key,
                                shared_leaf_key_der,
                                leaf_cache: Mutex::new(HashMap::new()),
                            });
                        }
                    }
                }
            }
        }

        fs::create_dir_all(ca_dir).map_err(|e| format!("create ca dir: {}", e))?;
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("generate ca key: {}", e))?;
        let ca_cert = build_root_ca_params()
            .self_signed(&ca_key)
            .map_err(|e| format!("self sign ca: {}", e))?;

        let ca_cert_der = ca_cert.der().clone();
        fs::write(&key_path, ca_key.serialize_pem()).map_err(|e| format!("write ca key: {}", e))?;
        fs::write(&cer_path, ca_cert_der.as_ref()).map_err(|e| format!("write ca cer: {}", e))?;
        let _ = fs::write(&pem_path, ca_cert.pem());

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_key,
            shared_leaf_key,
            shared_leaf_key_der,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    fn server_config_for_host(&self, raw_host: &str, norm_host: &str) -> Result<Arc<ServerConfig>, String> {
        let clean_raw = clean_san_host(raw_host);
        let clean_norm = clean_san_host(norm_host);
        let cache_key = if !clean_raw.is_empty() {
            clean_raw.clone()
        } else {
            clean_norm.clone()
        };
        if cache_key.is_empty() {
            return Err("empty host".into());
        }

        if let Ok(cache) = self.leaf_cache.lock() {
            if let Some(cfg) = cache.get(&cache_key) {
                return Ok(Arc::clone(cfg));
            }
        }

        let sans = build_leaf_sans(&clean_raw, &clean_norm);
        let mut params = CertificateParams::new(sans).map_err(|e| format!("leaf params: {}", e))?;
        let now = chrono::Utc::now();
        let nb = now - chrono::Duration::days(7);
        let na = now + chrono::Duration::days(300);
        params.not_before = rcgen::date_time_ymd(nb.year(), nb.month() as u8, nb.day() as u8);
        params.not_after = rcgen::date_time_ymd(na.year(), na.month() as u8, na.day() as u8);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cache_key.clone());
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let mut hasher = Sha256::new();
        hasher.update(cache_key.as_bytes());
        hasher.update(now_ms().to_le_bytes());
        let digest = hasher.finalize();
        let mut serial = digest[..16].to_vec();
        serial[0] = (serial[0] & 0x7F) | 0x01;
        params.serial_number = Some(SerialNumber::from_slice(&serial));

        let leaf_cert = params
            .signed_by(&self.shared_leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("sign leaf: {}", e))?;

        let cert_chain = vec![leaf_cert.der().clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.shared_leaf_key_der.clone()));
        let mut cfg =
            ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("tls versions: {}", e))?
                .with_no_client_auth()
                .with_single_cert(cert_chain, key_der)
                .map_err(|e| format!("tls cert: {}", e))?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);

        if let Ok(mut cache) = self.leaf_cache.lock() {
            if cache.len() >= 512 {
                cache.clear();
            }
            cache.insert(cache_key, Arc::clone(&cfg));
        }
        Ok(cfg)
    }
}

fn clean_san_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed.to_ascii_lowercase()
}

fn build_leaf_sans(clean_raw: &str, clean_norm: &str) -> Vec<String> {
    let mut sans = Vec::new();
    for candidate in [clean_raw, clean_norm] {
        if !candidate.is_empty() && !sans.iter().any(|x| x == candidate) {
            sans.push(candidate.to_string());
        }
    }
    for base in [clean_norm, clean_raw] {
        if !base.is_empty() && base.parse::<std::net::IpAddr>().is_err() {
            let wc = format!("*.{}", base);
            if !sans.iter().any(|x| x == &wc) {
                sans.push(wc);
            }
        }
    }
    sans
}

fn root_ca_dir() -> std::path::PathBuf {
    data_dir().join("ca")
}

static ROOT_CA: OnceLock<Result<RootCaState, String>> = OnceLock::new();

fn get_root_ca() -> Option<&'static RootCaState> {
    ROOT_CA
        .get_or_init(|| RootCaState::load_or_create(&root_ca_dir()))
        .as_ref()
        .ok()
}

/// Ensures the local IT ELKHAWGA Root CA exists on disk and is trusted in the
/// Windows certificate store (and Firefox enterprise roots) so denied HTTPS
/// destinations render our browser block page cleanly.
pub fn ensure_root_ca_trusted() {
    if get_root_ca().is_none() {
        return;
    }
    let cer_path = root_ca_dir().join("ca-cert.cer");
    if !cer_path.exists() {
        return;
    }
    let mut cmd = Command::new("certutil");
    hidden(&mut cmd).args(["-addstore", "-f", "Root"]).arg(&cer_path);
    match cmd.output() {
        Ok(out) if out.status.success() => {
            log_action("PROXY Root CA trusted in Windows certificate store");
        }
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            log_action(&format!(
                "PROXY certutil Root CA warning ({:?}): {} {}",
                out.status.code(),
                stdout.trim(),
                stderr.trim()
            ));
        }
        Err(e) => log_action(&format!("PROXY certutil failed: {}", e)),
    }

    let mut reg = Command::new("reg");
    hidden(&mut reg).args([
        "add",
        r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\Certificates",
        "/v",
        "ImportEnterpriseRoots",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ]);
    let _ = reg.output();
}

fn wants_full_block_html(req_bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(req_bytes);
    for line in head.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("sec-fetch-dest") {
                let v = val.trim().to_ascii_lowercase();
                return v.is_empty()
                    || matches!(v.as_str(), "document" | "iframe" | "frame" | "empty");
            }
        }
    }
    true
}

fn serve_blocked_https_with_ca(
    mut client: TcpStream,
    ca: &RootCaState,
    raw_host: &str,
    norm_host: &str,
) {
    let Ok(server_cfg) = ca.server_config_for_host(raw_host, norm_host) else {
        respond(&mut client, "403 Forbidden", "blocked by IT ELKHAWGA");
        return;
    };

    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let _ = client.flush();

    let Ok(conn) = ServerConnection::new(server_cfg) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, client);
    let _ = tls.get_mut().set_read_timeout(Some(Duration::from_millis(350)));
    let _ = tls.get_mut().set_write_timeout(Some(Duration::from_millis(350)));

    let mut req_buf = [0u8; 8192];
    let mut total = 0usize;
    while total < req_buf.len() {
        match tls.read(&mut req_buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if req_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                break;
            }
            Err(_) => return,
        }
    }
    if total == 0 {
        return;
    }

    let resp = if wants_full_block_html(&req_buf[..total]) {
        let html = blocked_page_html(norm_host);
        format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        )
    } else {
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 7\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nBlocked"
            .to_string()
    };

    let _ = tls.write_all(resp.as_bytes());
    let _ = tls.flush();
    tls.conn.send_close_notify();
    let (mut conn, mut sock) = tls.into_parts();
    while conn.wants_write() {
        match conn.write_tls(&mut sock) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = sock.flush();
    let _ = sock.shutdown(Shutdown::Both);
}

fn respond_blocked(mut stream: TcpStream, method: &str, raw_host: &str, norm_host: &str) {
    if method.eq_ignore_ascii_case("CONNECT") {
        if !is_background_noise_host(raw_host) {
            if let Some(ca) = get_root_ca() {
                serve_blocked_https_with_ca(stream, ca, raw_host, norm_host);
                return;
            }
        }
        respond(&mut stream, "403 Forbidden", "blocked by IT ELKHAWGA");
        return;
    }
    let html = blocked_page_html(norm_host);
    let msg = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    let _ = stream.write_all(msg.as_bytes());
    let _ = stream.flush();
}

fn connect_upstream(host: &str, port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addrs = (host, port).to_socket_addrs()?;
    let mut last_err = None;
    for addr in addrs.take(3) {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "upstream resolve failed")
    }))
}

fn handle(mut client: TcpStream, state: &Arc<ProxyState>) -> std::io::Result<()> {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_millis(2500)));
    let head = match read_head(&mut client) {
        Some(h) => h,
        None => return Ok(()),
    };
    let (method, target, _version) = match request_line(&head) {
        Some(v) => v,
        None => {
            respond(&mut client, "400 Bad Request", "bad request");
            return Ok(());
        }
    };
    let (host, port) = match target_host_port(&method, &target) {
        Some(v) => v,
        None => {
            respond(&mut client, "400 Bad Request", "bad target");
            return Ok(());
        }
    };

    let norm_host = normalize_host(&host);
    state.record(&norm_host);
    if norm_host == "whatsapp.com"
        || norm_host.ends_with(".whatsapp.com")
        || norm_host == "whatsapp.net"
        || norm_host.ends_with(".whatsapp.net")
    {
        LAST_WHATSAPP_SECS.store(now_secs(), Ordering::Relaxed);
    }

    // Suspicious destination => immediate exfil alert.
    if is_suspicious_host(&norm_host) {
        state.record_exfil(&norm_host);
    }

    if host_denied_by_policy(&host) {
        state.record_denied(&norm_host);
        state.queue_notification(&norm_host);
        respond_blocked(client, &method, &host, &norm_host);
        return Ok(());
    }

    let upstream = match connect_upstream(&host, port, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(_) => {
            respond(&mut client, "502 Bad Gateway", "upstream unreachable");
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(true);
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(300)));

    let kbps = state.throttle_kbps.load(Ordering::Relaxed);

    if method.eq_ignore_ascii_case("CONNECT") {
        let _ = client.set_read_timeout(Some(Duration::from_secs(300)));
        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        tunnel(client, upstream, kbps, &host);
        return Ok(());
    }

    // Plain HTTP: rewrite the absolute URI to origin form and forward.
    let mut rebuilt = String::new();
    let mut lines = head.lines();
    if let Some(_first) = lines.next() {
        let path = target
            .split("://")
            .nth(1)
            .and_then(|r| r.find('/').map(|i| &r[i..]))
            .unwrap_or("/");
        rebuilt.push_str(&format!("{} {} HTTP/1.1\r\n", method, path));
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("proxy-connection:") {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    rebuilt.push_str("\r\n");

    let mut up = upstream;
    if up.write_all(rebuilt.as_bytes()).is_err() {
        return Ok(());
    }
    if rebuilt.len() > 25 * 1024 {
        track_upload_dir(&host, rebuilt.len() as u64, true);
    }
    let up_read = up.try_clone()?;
    let client_write = client.try_clone()?;
    if kbps > 0 {
        copy_paced(up_read, client_write, kbps, &host, false);
    } else {
        let mut r = up_read;
        let mut w = client_write;
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if w.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    }
    Ok(())
}

fn tunnel(client: TcpStream, upstream: TcpStream, kbps: u32, host: &str) {
    let c_read = match client.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let u_write = match upstream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let host_c = host.to_string();
    let up = std::thread::spawn(move || {
        if kbps > 0 {
            copy_paced(c_read, u_write, kbps, &host_c, true);
        } else {
            let mut r = c_read;
            let mut w = u_write;
            let mut buf = vec![0u8; 32 * 1024];
            let mut pending_up: u64 = 0;
            let mut last_flush = Instant::now();
            loop {
                let n = match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
                pending_up = pending_up.saturating_add(n as u64);
                if pending_up >= 65_536 || last_flush.elapsed() >= Duration::from_millis(350) {
                    track_upload_dir(&host_c, pending_up, true);
                    pending_up = 0;
                    last_flush = Instant::now();
                }
            }
            if pending_up > 0 {
                track_upload_dir(&host_c, pending_up, true);
            }
        }
    });
    if kbps > 0 {
        copy_paced(upstream, client, kbps, &host, false);
    } else {
        let mut r = upstream;
        let mut w = client;
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if w.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    }
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_http_head_for_test(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 8192 {
                        break;
                    }
                }
            }
        }
        buf
    }

    #[test]
    fn https_blocked_page_tls_roundtrip_serves_it_elkhawga_html() {
        let temp_dir = std::env::temp_dir().join(format!(
            "it_elkhawga_ca_test_{}_{}",
            std::process::id(),
            now_ms()
        ));
        let ca = Arc::new(RootCaState::load_or_create(&temp_dir).expect("ca init"));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_cert_der.clone()).expect("add root ca");
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .expect("client tls versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let ca_srv = Arc::clone(&ca);
        let srv_handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().expect("accept");
                let _ = read_http_head_for_test(&mut s);
                serve_blocked_https_with_ca(s, &ca_srv, "www.facebook.com", "facebook.com");
            }
        });

        // Case A: top-level browser document navigation receives full Arabic HTML block page
        let mut c1 = TcpStream::connect(addr).expect("connect case A");
        c1.write_all(
            b"CONNECT www.facebook.com:443 HTTP/1.1\r\nHost: www.facebook.com:443\r\n\r\n",
        )
        .expect("write CONNECT A");
        c1.flush().expect("flush CONNECT A");
        let connect_resp_1 =
            String::from_utf8_lossy(&read_http_head_for_test(&mut c1)).into_owned();
        assert!(
            connect_resp_1.starts_with("HTTP/1.1 200 Connection Established"),
            "unexpected CONNECT A response: {}",
            connect_resp_1
        );
        let server_name: rustls::pki_types::ServerName<'static> =
            "www.facebook.com".try_into().expect("server name");
        let conn1 = rustls::ClientConnection::new(Arc::clone(&client_cfg), server_name.clone())
            .expect("client conn 1");
        let mut tls1 = StreamOwned::new(conn1, c1);
        tls1.write_all(
            b"GET / HTTP/1.1\r\nHost: www.facebook.com\r\nSec-Fetch-Dest: document\r\nConnection: close\r\n\r\n",
        )
        .expect("write GET A");
        tls1.flush().expect("flush GET A");
        let mut body1 = String::new();
        tls1.read_to_string(&mut body1).expect("read TLS A");
        assert!(
            body1.contains("403 Forbidden"),
            "missing 403 in case A: {}",
            body1
        );
        assert!(
            body1.contains("هذا الموقع مقفول بواسطة IT ELKHAWGA"),
            "missing Arabic block title in case A: {}",
            body1
        );
        assert!(
            body1.contains("facebook.com"),
            "missing domain in case A: {}",
            body1
        );

        // Case B: embedded image/script subresource receives short plain 403 without HTML
        let mut c2 = TcpStream::connect(addr).expect("connect case B");
        c2.write_all(
            b"CONNECT www.facebook.com:443 HTTP/1.1\r\nHost: www.facebook.com:443\r\n\r\n",
        )
        .expect("write CONNECT B");
        c2.flush().expect("flush CONNECT B");
        let connect_resp_2 =
            String::from_utf8_lossy(&read_http_head_for_test(&mut c2)).into_owned();
        assert!(connect_resp_2.starts_with("HTTP/1.1 200 Connection Established"));
        let conn2 =
            rustls::ClientConnection::new(Arc::clone(&client_cfg), server_name).expect("client conn 2");
        let mut tls2 = StreamOwned::new(conn2, c2);
        tls2.write_all(
            b"GET /logo.png HTTP/1.1\r\nHost: www.facebook.com\r\nSec-Fetch-Dest: image\r\nConnection: close\r\n\r\n",
        )
        .expect("write GET B");
        tls2.flush().expect("flush GET B");
        let mut body2 = String::new();
        tls2.read_to_string(&mut body2).expect("read TLS B");
        assert!(
            body2.contains("403 Forbidden"),
            "missing 403 in case B: {}",
            body2
        );
        assert!(
            body2.ends_with("\r\n\r\nBlocked"),
            "unexpected case B body: {}",
            body2
        );
        assert!(
            !body2.contains("<!DOCTYPE html>"),
            "unexpected HTML in case B: {}",
            body2
        );

        srv_handle.join().expect("server thread join");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn whatsapp_upload_host_filter_ignores_download_cdns() {
        assert!(is_whatsapp_media_upload_host("mmg.whatsapp.net"));
        assert!(is_whatsapp_media_upload_host("mmg-fna.mmg.whatsapp.net"));
        assert!(!is_whatsapp_media_upload_host("media-hbe1-2.cdn.whatsapp.net"));
        assert!(!is_whatsapp_media_upload_host("media.fcai19-3.fna.whatsapp.net"));
        assert!(!is_whatsapp_media_upload_host("web.whatsapp.com"));
    }
}
