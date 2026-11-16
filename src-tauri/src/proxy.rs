//! Local HTTP proxy used by the agent.
//!
//! Runs on 127.0.0.1:8080 (the address the block script already points the
//! system proxy at). It:
//!   * logs every host the device tries to reach (whitelist/blacklist aware),
//!   * denies hosts that are not allowed while the device is blocked,
//!   * shapes traffic to the per-device limit when one is configured.
//!
//! The proxy never decrypts TLS: HTTPS is tunnelled with CONNECT and only the
//! destination host name is recorded.

use crate::common::*;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const PROXY_ADDR: &str = "127.0.0.1:8080";
const MAX_HEAD: usize = 16 * 1024;
const LOG_LIMIT: usize = 40;

#[derive(Default)]
pub struct SiteLog {
    pub hosts: VecDeque<(String, u64)>,
    pub denied: VecDeque<String>,
    pub exfil: VecDeque<String>,
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
        if host.is_empty() {
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
        if host.is_empty() {
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
    host.trim().trim_start_matches("www.").to_lowercase()
}

fn host_allowed(host: &str) -> bool {
    let h = normalize_host(host);
    // Always allow the local machine and the relay/control plane, otherwise a
    // blocked device could never poll for an unblock command (deadlock) and
    // the admin could not manage it.
    if h == "localhost" || h == "127.0.0.1" || h == "::1" {
        return true;
    }
    let cfg = read_config();
    // LAN admin server must stay reachable while blocked.
    let link = read_client();
    if !link.server_url.trim().is_empty() {
        let sh = link
            .server_url
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .trim_start_matches("www.")
            .to_lowercase();
        if !sh.is_empty() && (h == sh || h.ends_with(&format!(".{}", sh))) {
            return true;
        }
    }
    if !cfg.relay_url.trim().is_empty() {
        let rh = cfg
            .relay_url
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .trim_start_matches("www.")
            .to_lowercase();
        if !rh.is_empty() && (h == rh || h.ends_with(&format!(".{}", rh))) {
            return true;
        }
    }
    // Always allow RustDesk endpoints so remote support keeps working while blocked.
    for rd in ["rustdesk.com", "rustdesk.net"] {
        if h == *rd || h.ends_with(&format!(".{}", rd)) {
            return true;
        }
    }
    if !cfg.rustdesk_server.trim().is_empty() {
        let rs = cfg.rustdesk_server.trim().to_lowercase();
        if h == rs || h.ends_with(&format!(".{}", rs)) {
            return true;
        }
    }
    let allowed = read_list(&allowed_path());
    for entry in allowed {
        let d = clean_domain(&entry).unwrap_or_default();
        let d = d.trim_start_matches("www.").to_lowercase();
        if d.is_empty() {
            continue;
        }
        if h == d || h.ends_with(&format!(".{}", d)) {
            return true;
        }
    }
    let _ = cfg;
    false
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

// Per-host upload tracking with a 10-minute window.
static UPLOADS: std::sync::Mutex<Option<std::collections::HashMap<String, (u64, std::time::Instant)>>> =
    std::sync::Mutex::new(None);

fn track_upload(host: &str, bytes: u64) {
    if host.is_empty() {
        return;
    }
    let threshold_mb: u64 = read_config().exfil_threshold_mb.max(1);
    let window_secs: u64 = read_config().exfil_window_secs.max(60);
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

fn copy_paced(mut src: TcpStream, mut dst: TcpStream, kbps: u32, host: &str) {
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
        track_upload(host, n as u64);
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

fn handle(mut client: TcpStream, state: &Arc<ProxyState>) -> std::io::Result<()> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(20)));
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

    // Suspicious destination => immediate exfil alert.
    if is_suspicious_host(&norm_host) {
        state.record_exfil(&norm_host);
    }

    // While blocked in whitelist mode only allowed hosts may pass.
    let blocked = is_blocked();
    if blocked && read_config().mode == "whitelist" && !host_allowed(&host) {
        state.record_denied(&normalize_host(&host));
        log_action(&format!("PROXY denied {}", host));
        respond(&mut client, "403 Forbidden", "blocked by IT ELKHAWGA");
        return Ok(());
    }

    let upstream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            respond(&mut client, "502 Bad Gateway", "upstream unreachable");
            return Ok(());
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(300)));

    let kbps = state.throttle_kbps.load(Ordering::Relaxed);

    if method.eq_ignore_ascii_case("CONNECT") {
        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        tunnel(client, upstream, kbps, &host);
        return Ok(());
    }

    // Plain HTTP: rewrite the absolute URI to origin form and forward.
    let mut rebuilt = String::new();
    let mut lines = head.lines();
    if let Some(first) = lines.next() {
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
    let up_read = up.try_clone()?;
    let client_write = client.try_clone()?;
    if kbps > 0 {
        copy_paced(up_read, client_write, kbps, &host);
    } else {
        // still track uploads even without throttling
        let mut r = up_read;
        let mut w = client_write;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if w.write_all(&buf[..n]).is_err() {
                break;
            }
            track_upload(&host, n as u64);
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
            copy_paced(c_read, u_write, kbps, &host_c);
        } else {
            let mut r = c_read;
            let mut w = u_write;
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
                track_upload(&host_c, n as u64);
            }
        }
    });
    if kbps > 0 {
        copy_paced(upstream, client, kbps, &host);
    } else {
        let mut r = upstream;
        let mut w = client;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if w.write_all(&buf[..n]).is_err() {
                break;
            }
            track_upload(&host, n as u64);
        }
    }
    let _ = up.join();
}
