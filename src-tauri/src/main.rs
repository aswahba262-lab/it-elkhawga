#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent;
mod commands;
mod common;
mod proxy;
mod server;
mod transport;
mod auth;

use std::sync::Mutex;
use tauri::Manager;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--capture-agent") {
        agent::run_capture_agent();
        return;
    }
    if args.iter().any(|a| a == "--agent") {
        agent::run();
        return;
    }
    if args.iter().any(|a| a == "--server") {
        common::ensure_data();
        if common::is_admin_mode() {
            let cfg = common::read_config();
            if let Ok(_srv) = server::start(cfg.api_token, cfg.server_port) {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
        }
        return;
    }

    common::ensure_data();

    // The admin build hosts the server that employee machines connect to;
    // only client installs run the local blocking proxy / background agents.
    let server = if common::is_admin_mode() {
        let cfg = common::read_config();
        server::start(cfg.api_token, cfg.server_port).ok()
    } else {
        proxy::start_default();
        // Ensure both the background agent and user-session screenshot helper are running
        // immediately without waiting for reboot or re-login. Each exits cleanly if already active.
        if let Ok(exe) = std::env::current_exe() {
            for flag in ["--agent", "--capture-agent"] {
                let mut cmd = std::process::Command::new(&exe);
                cmd.arg(flag);
                let _ = common::hidden(&mut cmd).spawn();
            }
        }
        None
    };

    let admin_redirect_port = if common::is_admin_mode() && server.is_none() {
        Some(common::read_config().server_port)
    } else {
        None
    };

    tauri::Builder::default()
        .manage(commands::AppState { server: Mutex::new(server) })
        .setup(move |app| {
            if let Some(port) = admin_redirect_port {
                if let Some(w) = app.get_webview_window("main") {
                    let js = format!(
                        "if (!window.location.href.startsWith('http://127.0.0.1:{}')) {{ window.location.replace('http://127.0.0.1:{}/'); }}",
                        port, port
                    );
                    let _ = w.eval(&js);
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let st = window.state::<commands::AppState>();
                let owns_server = st.server.lock().map(|g| g.is_some()).unwrap_or(false);
                if common::is_admin_mode() && owns_server {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_mode,
            commands::get_allowed_sites,
            commands::block_internet,
            commands::unblock_internet,
            commands::get_client_config,
            commands::set_client_config,
            commands::get_blocked_sites,
            commands::add_site,
            commands::remove_site,
            commands::add_blocked_site,
            commands::remove_blocked_site,
            commands::add_sites_bulk,
            commands::get_logs,
            commands::get_config,
            commands::set_list_mode,
            commands::set_dlp_config,
            commands::toggle_autostart,
            commands::set_password,
            commands::get_admin_users,
            commands::upsert_admin_user,
            commands::remove_admin_user,
            commands::admin_login,
            commands::get_server_info,
            commands::check_server_connection,
            commands::get_devices,
            commands::send_device_command,
            commands::get_relay_config,
            commands::set_relay_config,
            commands::create_pairing_token,
            commands::get_relay_devices,
            commands::send_relay_command,
            commands::sync_policy_now,
            commands::get_dashboard_stats,
            commands::get_relay_alerts,
            commands::get_alert_media,
            commands::get_uploaded_files,
            commands::get_backups_list,
            commands::create_system_backup,
            commands::restore_system_backup,
            commands::open_backups_folder,
            commands::browse_backup_folder,
            commands::set_backup_dir,
            commands::get_erp_backups_status,
            commands::save_erp_backup_config,
            commands::run_erp_backup_now,
            commands::open_erp_backups_folder,
            commands::browse_erp_backup_folder,
            commands::set_erp_backup_dir,
            commands::browse_archive_folder,
            commands::set_archive_dir,
            commands::save_uploaded_file,
            commands::save_base64_image,
            commands::save_text_file,
            commands::open_archive_folder,
            commands::get_audit_log,
            commands::ack_alert,
            commands::ack_all_alerts,
            commands::get_rustdesk_oss_status,
            commands::check_admin_update,
            commands::apply_admin_update,
            commands::get_relay_groups,
            commands::create_relay_group,
            commands::update_relay_group,
            commands::delete_relay_group,
            commands::assign_device_group,
            commands::send_group_command,
            commands::rename_relay_device,
            commands::delete_relay_device,
            commands::open_support_session,
            commands::set_device_rustdesk_password,
            commands::request_screenshot,
            commands::get_screenshot,
            commands::get_wa_bot_status,
            commands::save_wa_bot_config,
            commands::connect_wa_bot,
            commands::disconnect_wa_bot,
            commands::send_wa_bot_test,
            commands::cctv_list_dvrs,
            commands::cctv_save_dvr,
            commands::cctv_delete_dvr,
            commands::cctv_test_dvr,
            commands::cctv_scan_lan,
            commands::cctv_set_settings,
            commands::cctv_get_frame_b64,
            commands::cctv_action,
            commands::enroll_relay,
            commands::disconnect_relay,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the application");
}
