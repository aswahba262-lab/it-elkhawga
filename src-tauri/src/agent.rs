use crate::common::*;
use crate::transport::{RelayClient, Transport, lan_poll, lan_upload_screen};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

const POLL_SECONDS: u64 = 1;

static SCREEN_WANTED: AtomicBool = AtomicBool::new(false);

/// Entry point of `internet-blocker.exe --agent`. Runs as SYSTEM from a scheduled task, so it can
/// change machine settings without a UAC prompt. The UI talks to it over 127.0.0.1.
pub fn run_capture_agent() {
    // Apply self-hosted RustDesk server settings (if configured) so clients
    // never touch the public relay server.
    configure_rustdesk_server();
    // Set a permanent password for unattended access (no approval prompt).
    let mut last_pw = String::new();
    {
        let link = read_client();
        if !link.rustdesk_password.trim().is_empty() {
            for exe in crate::common::rustdesk_candidates() {
                let _ = std::process::Command::new(&exe)
                    .arg("--password")
                    .arg(&link.rustdesk_password)
                    .output();
                last_pw = link.rustdesk_password.clone();
                break;
            }
        }
    }
    loop {
        // Re-apply the RustDesk password whenever it changes (e.g. after a
        // policy sync from the admin) so unattended access keeps working.
        let link = read_client();
        if !link.rustdesk_password.trim().is_empty() && link.rustdesk_password != last_pw {
            for exe in crate::common::rustdesk_candidates() {
                let _ = std::process::Command::new(&exe)
                    .arg("--password")
                    .arg(&link.rustdesk_password)
                    .output();
                last_pw = link.rustdesk_password.clone();
                break;
            }
        }
        // Report the RustDesk ID (if installed) so the admin can open a support session.
        let rd_id = read_rustdesk_id();
        if !rd_id.is_empty() {
            let a = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
            let _ = a
                .post(&format!("http://{}/local/rustdesk", LOCAL_API_ADDR))
                .send_json(json!({"rustdesk_id": rd_id}));
        }

        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
        let requested = agent
            .get(&format!("http://{}/local/screenshot", LOCAL_API_ADDR))
            .call()
            .ok()
            .and_then(|r| r.into_json::<Value>().ok())
            .and_then(|v| v["requested"].as_bool())
            .unwrap_or(false);

        if requested {
            if let Some(img) = capture_screen_base64() {
                let _ = agent
                    .post(&format!("http://{}/local/screenshot", LOCAL_API_ADDR))
                    .send_json(json!({"image": img}));
            }
        }
        std::thread::sleep(Duration::from_secs(2));
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
            // enumerate USB mass storage devices
            let out = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    "Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | Select-Object -ExpandProperty PNPDeviceID",
                ])
                .output();

            let mut current = std::collections::HashSet::new();
            if let Ok(o) = out {
                let text = String::from_utf8_lossy(&o.stdout);
                for line in text.lines() {
                    let id = line.trim();
                    if !id.is_empty() {
                        current.insert(id.to_string());
                    }
                }
            }

            // new devices?
            for id in &current {
                if !known.contains(id) {
                    known.insert(id.clone());
                    // report alert
                    let mut link = read_client();
                    let alert = json!({"type": "usb", "severity": "medium", "message": format!("USB device inserted: {}", id)});
                    link.pending_alert = alert.to_string();
                    let _ = write_client(&link);

                    // optional block
                    if read_config().usb_block {
                        let _ = std::process::Command::new("reg")
                            .args(["add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"])
                            .output();
                    }
                }
            }

            // persist known
            let _ = std::fs::write(&known_path, known.iter().cloned().collect::<Vec<_>>().join("\n"));

            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    });
}

pub fn run() {
    ensure_data();
    grant_users_data_access();
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
                handle_local(req, &linked);
            }
        });
    }

    log_action("Agent started");
    if read_config().auto_start && !is_blocked() {
        let _ = apply_block("startup");
    }

    let http = ureq::AgentBuilder::new().timeout(Duration::from_secs(6)).build();
    loop {
        poll_once(&http, &linked);
        std::thread::sleep(Duration::from_secs(POLL_SECONDS));
    }
}

/// Sets the RustDesk unattended password on this machine (used by the admin's ðŸ”‘ button).
fn apply_rustdesk_password(password: &str) {
    if password.trim().is_empty() {
        return;
    }
    for exe in crate::common::rustdesk_candidates() {
        let ok = std::process::Command::new(&exe)
            .arg("--password")
            .arg(password)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            log_action("RustDesk password updated");
            return;
        }
    }
}

fn apply_block(reason: &str) -> Result<(), String> {
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

/// Detects tampering with the protection layer.
fn check_tamper() -> Option<(&'static str, &'static str, String)> {
    let blocked_marker = block_state_path().exists()
        && std::fs::read_to_string(block_state_path()).ok().map(|x| x.trim() == "1").unwrap_or(false);
    if !blocked_marker {
        return None;
    }
    // proxy disabled while blocked?
    let proxy_on = crate::common::reg_query_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyEnable",
    ) == Some(1)
        || reg_query_dword(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyEnable",
        ) == Some(1);
    let chrome_policy = crate::common::reg_value_exists(r"HKLM\SOFTWARE\Policies\Google\Chrome", "ProxyMode")
        || reg_value_exists(r"HKLM\SOFTWARE\Policies\Google\Chrome", "ProxyServer");
    if !proxy_on && !chrome_policy {
        return Some(("tamper", "high", "ØªÙ… ØªØ¹Ø·ÙŠÙ„ Ø§Ù„Ø¨Ø±ÙˆÙƒØ³ÙŠ/Ø§Ù„Ø³ÙŠØ§Ø³Ø§Øª Ø£Ø«Ù†Ø§Ø¡ Ø§Ù„Ø­Ø¬Ø¨".to_string()));
    }
    // agent task missing?
    let task_ok = std::process::Command::new("schtasks")
        .args(["/Query", "/TN", "IT ELKHAWGA Agent"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !task_ok {
        return Some(("tamper", "high", "ØªÙ… Ø­Ø°Ù Ù…Ù‡Ù…Ø© Ø§Ù„Ù€ Agent".to_string()));
    }
    None
}

fn poll_once(http: &ureq::Agent, linked: &AtomicBool) {
    let cfg = read_config();
    let link = read_client();
    let transport = Transport::from_link(&link);
    // Tamper check
    if let Some((t, sev, msg)) = check_tamper() {
        let alert = json!({"type": t, "severity": sev, "message": msg});
        let mut l = read_client();
        l.pending_alert = alert.to_string();
        let _ = write_client(&l);
    }

    let pending_event = link.pending_event.clone();
    let pending_alert = link.pending_alert.clone();
    let state = json!({
        "device_id": link.device_id,
        "hostname": hostname(),
        "blocked": is_blocked(),
        "mode": cfg.mode,
        "policy_version": link.policy_version,
        "app_version": APP_VERSION,
        "event": pending_event.clone(),
        "sites": crate::proxy::recent_sites(),
        "rustdesk_id": link.rustdesk_id.clone(),
        "denied": crate::proxy::recent_denied(),
        "alert": parse_pending_alert(&link.pending_alert),
    });

    let ack: Option<String> = if link.last_command_id.is_empty() { None } else { Some(link.last_command_id.clone()) };
    let mut reply: Option<Value> = None;

    match transport {
        Transport::Relay => {
            let relay = RelayClient::new();
            // Original flow: the admin generates a pairing token and the operator types it
            // into the client; the agent exchanges it once for a per-device token.
            let mut link = link;
            if link.device_token.is_empty() && !link.pairing_token.is_empty() {
                if let Some((device_id, device_token)) =
                    relay.enroll(&link.relay_url, &link.pairing_token)
                {
                    link.device_id = device_id;
                    link.device_token = device_token;
                    link.pairing_token = String::new();
                    let _ = write_client(&link);
                    log_action("Relay enrollment succeeded");
                }
            }
            if link.device_token.is_empty() {
                linked.store(false, Ordering::Relaxed);
                log_action("Relay: no device token - enrollment required");
                return;
            }
            match relay.poll(&link.relay_url, &link.device_token, &state, ack.as_deref()) {
                Some((command, policy, screen)) => {
                    SCREEN_WANTED.store(screen, Ordering::Relaxed);
                    reply = Some(json!({"command": command, "policy": policy, "screen": screen}));
                }
                None => {
                    linked.store(false, Ordering::Relaxed);
                    log_action("Relay poll failed");
                    return;
                }
            }
        }
        Transport::Lan => {
            if link.server_url.is_empty() || link.token.is_empty() {
                linked.store(false, Ordering::Relaxed);
                return;
            }
            match lan_poll(http, &link, ack.as_deref()) {
                Some(v) => reply = Some(v),
                None => {
                    linked.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
    }

    let reply = match reply {
        Some(v) => v,
        None => return,
    };
    linked.store(true, Ordering::Relaxed);

    // The relay accepted our state (which carried the event), so clear it.
    if !pending_event.is_empty() {
        let mut l = read_client();
        l.pending_event = String::new();
        let _ = write_client(&l);
    }
    if !pending_alert.is_empty() {
        let mut l = read_client();
        l.pending_alert = String::new();
        let _ = write_client(&l);
    }

    if let Some(want) = reply.get("screen").and_then(|v| v.as_bool()) {
        SCREEN_WANTED.store(want, Ordering::Relaxed);
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

    if let Some(cmd) = reply.get("command").and_then(|c| c.get("type")).and_then(|t| t.as_str()) {
        let id = reply["command"].get("id").and_then(|i| i.as_str()).unwrap_or("");
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
            } else {
                Ok(())
            };
            match outcome {
                Ok(_) => {
                    if !id.is_empty() {
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
    if let Some(b) = policy["usb_block"].as_bool() {
        cfg.usb_block = b;
    }
    if let Some(s) = policy["rustdesk_server"].as_str() {
        let mut l = read_client();
        l.rustdesk_server = s.to_string();
        let _ = write_client(&l);
    }
    if let Some(k) = policy["rustdesk_key"].as_str() {
        let mut l = read_client();
        l.rustdesk_key = k.to_string();
        let _ = write_client(&l);
    }
    if let Some(pw) = policy["rustdesk_password"].as_str() {
        let mut l = read_client();
        l.rustdesk_password = pw.to_string();
        let _ = write_client(&l);
    }
    let _ = write_config(&cfg);

    let _ = write_list(&allowed_path(), "Allowed sites (synced from admin)", &strings(&policy["allowed"]));
    let _ = write_list(&blocked_path(), "Blocked sites (synced from admin)", &strings(&policy["blocked"]));

    let mut link = read_client();
    link.policy_version = policy["version"].as_str().unwrap_or("").to_string();
    let _ = write_client(&link);
    log_action("Policy synced from admin");

    if is_blocked() {
        let _ = apply_block("policy changed");
    }
}

fn reply(body: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(body.to_string()).with_header(header)
}

fn handle_local(mut req: Request, linked: &AtomicBool) {
    let mut raw = String::new();
    let _ = req.as_reader().take(16_384).read_to_string(&mut raw);
    let body: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let cfg = read_config();

    let out = match (req.method().clone(), req.url()) {
        (Method::Get, "/local/status") => json!({
            "connected": linked.load(Ordering::Relaxed),
            "blocked": is_blocked(),
        }),
        (Method::Post, "/local/block") => match apply_block("local user") {
            Ok(_) => json!({"success": true}),
            Err(e) => json!({"success": false, "error": e}),
        },
        (Method::Post, "/local/unblock") => {
            if !password_ok(&cfg, body["password"].as_str().unwrap_or("")) {
                std::thread::sleep(Duration::from_secs(1));
                log_action("UNBLOCK refused - wrong password");
                json!({"success": false, "error": "ÙƒÙ„Ù…Ø© Ø§Ù„Ø³Ø± ØºÙŠØ± ØµØ­ÙŠØ­Ø©"})
            } else {
                match apply_unblock("local user") {
                    Ok(_) => {
                        let mut l = read_client();
                        l.pending_event = "unblock_password".to_string();
                        let _ = write_client(&l);
                        json!({"success": true})
                    }
                    Err(e) => json!({"success": false, "error": e}),
                }
            }
        }
        (Method::Get, "/local/screenshot") => {
            json!({"requested": SCREEN_WANTED.load(Ordering::Relaxed)})
        }
        (Method::Post, "/local/screenshot") => {
            let img = body["image"].as_str().unwrap_or("");
            if img.is_empty() {
                json!({"success": false, "error": "no image"})
            } else {
                let link = read_client();
                let transport = Transport::from_link(&link);
                let result = match transport {
                    Transport::Relay => {
                        let relay = RelayClient::new();
                        relay.upload_screen(&link.relay_url, &link.device_token, img).is_some()
                    }
                    Transport::Lan => {
                        let http = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
                        lan_upload_screen(&http, &link, img).is_some()
                    }
                };
                if result {
                    SCREEN_WANTED.store(false, Ordering::Relaxed);
                    log_action("Screenshot uploaded");
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
            let had_link = {
                let cur = read_client();
                !cur.relay_url.is_empty() || !cur.device_token.is_empty()
            };
            if had_link && cfg.password_hash.is_empty() {
                json!({"success": false, "error": "ÙƒÙ„Ù…Ø© Ø§Ù„Ø³Ø± ØºÙŠØ± Ù…ÙØ¹Ù‘Ù„Ø© â€” Ø¹ÙŠÙ‘Ù†Ù‡Ø§ Ù…Ù† Ø§Ù„Ù…Ø¯ÙŠØ± Ø£ÙˆÙ„Ø§Ù‹"})
            } else if !password_ok(&cfg, body["password"].as_str().unwrap_or("")) {
                std::thread::sleep(Duration::from_secs(1));
                log_action("Relay link refused - wrong password");
                json!({"success": false, "error": "ÙƒÙ„Ù…Ø© Ø§Ù„Ø³Ø± ØºÙŠØ± ØµØ­ÙŠØ­Ø©"})
            } else {
                let url = body["relay_url"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
                let pt = body["pairing_token"].as_str().unwrap_or("").trim().to_string();
                let mut link = read_client();
                if url.is_empty() {
                    json!({"success": false, "error": "Ø¹Ù†ÙˆØ§Ù† Ø§Ù„Ù€ Relay Ù…Ø·Ù„ÙˆØ¨"})
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
                            json!({"success": true})
                        }
                        Err(e) => json!({"success": false, "error": e}),
                    }
                }
            }
        }
        (Method::Post, "/local/relay/off") => {
            if cfg.password_hash.is_empty() {
                json!({"success": false, "error": "ÙƒÙ„Ù…Ø© Ø§Ù„Ø³Ø± ØºÙŠØ± Ù…ÙØ¹Ù‘Ù„Ø© â€” Ø¹ÙŠÙ‘Ù†Ù‡Ø§ Ù…Ù† Ø§Ù„Ù…Ø¯ÙŠØ± Ø£ÙˆÙ„Ø§Ù‹"})
            } else if !password_ok(&cfg, body["password"].as_str().unwrap_or("")) {
                std::thread::sleep(Duration::from_secs(1));
                log_action("Relay disconnect refused - wrong password");
                json!({"success": false, "error": "ÙƒÙ„Ù…Ø© Ø§Ù„Ø³Ø± ØºÙŠØ± ØµØ­ÙŠØ­Ø©"})
            } else {
                let mut link = read_client();
                link.relay_url = String::new();
                link.device_token = String::new();
                link.pairing_token = String::new();
                link.last_command_id = String::new();
                link.transport = "lan".to_string();
                match write_client(&link) {
                    Ok(_) => {
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
                json!({"success": false, "error": "ÙƒÙ„Ù…Ø© Ø§Ù„Ø³Ø± Ù…Ø·Ù„ÙˆØ¨Ø© Ù„ØªØ¹Ø¯ÙŠÙ„ Ø§Ù„Ø±Ø¨Ø·"})
            } else {
                let mut link = read_client();
                link.server_url = body["server_url"].as_str().unwrap_or("").trim().to_string();
                link.token = body["token"].as_str().unwrap_or("").trim().to_string();
                link.transport = "lan".to_string();
                link.relay_url = String::new();
                link.device_token = String::new();
                link.pairing_token = String::new();
                link.policy_version = String::new();
                match write_client(&link) {
                    Ok(_) => {
                        log_action("Server link updated");
                        json!({"success": true})
                    }
                    Err(e) => json!({"success": false, "error": e}),
                }
            }
        }
        _ => json!({"success": false, "error": "not found"}),
    };
    let _ = req.respond(reply(out));
}
