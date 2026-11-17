#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent;
mod commands;
mod common;
mod proxy;
mod server;
mod transport;

use std::sync::Mutex;

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

    common::ensure_data();

    // The admin build hosts the server that employee machines connect to.
    let server = if common::is_admin_mode() {
        let cfg = common::read_config();
        server::start(cfg.api_token, cfg.server_port).ok()
    } else {
        None
    };

    tauri::Builder::default()
        .manage(commands::AppState { server: Mutex::new(server) })
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
            commands::get_logs,
            commands::get_config,
            commands::set_list_mode,
            commands::toggle_autostart,
            commands::set_password,
            commands::get_admin_users,
            commands::upsert_admin_user,
            commands::remove_admin_user,
            commands::admin_login,
            commands::get_server_info,
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
            commands::get_audit_log,
            commands::ack_alert,
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
            commands::enroll_relay,
            commands::disconnect_relay,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the application");
}
