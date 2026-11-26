// Maps window.electronAPI (the API the pages were written against) onto Tauri commands,
// or provides a fallback mock in regular browser dev/preview mode.
(function () {
  if (window.electronAPI) return;

  let authToken = '';
  try {
    authToken = sessionStorage.getItem('ibp_auth_token') || localStorage.getItem('ibp_auth_token') || '';
  } catch (e) { }

  function setAuthToken(tok, remember) {
    authToken = tok || '';
    try {
      if (authToken) {
        sessionStorage.setItem('ibp_auth_token', authToken);
        if (remember !== false) {
          localStorage.setItem('ibp_auth_token', authToken);
        } else {
          localStorage.removeItem('ibp_auth_token');
        }
      } else {
        sessionStorage.removeItem('ibp_auth_token');
        localStorage.removeItem('ibp_auth_token');
      }
    } catch (e) { }
  }

  const isTauri = Boolean(window.__TAURI__ && window.__TAURI__.core);
  const isWebAdmin = Boolean(window.__ITK_WEB_ADMIN__);
  if (isTauri || isWebAdmin) {
    const invoke = isTauri
      ? window.__TAURI__.core.invoke
      : async (cmd, args) => {
        const headers = { 'Content-Type': 'application/json' };
        if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
        const resp = await fetch('/api/rpc', {
          method: 'POST',
          headers,
          body: JSON.stringify({ cmd, args: args || {} }),
        });
        const data = await resp.json().catch(() => ({}));
        if (resp.status === 401) {
          setAuthToken('');
          const modal = document.getElementById('loginModal');
          if (modal) {
            modal.classList.add('show');
            document.body.classList.add('auth-locked');
          }
          throw new Error(data.error || 'انتهت الجلسة، يرجى تسجيل الدخول');
        }
        if (!resp.ok) {
          throw new Error(data.error || ('HTTP ' + resp.status));
        }
        return data.result;
      };
    const listen = isTauri ? window.__TAURI__.event.listen : () => { };

    window.electronAPI = {
      setAuthToken,
      getAuthToken: () => authToken,
      getStatus: () => invoke('get_status'),
      getMode: () => invoke('get_mode'),
      blockInternet: (actorUsername, actorRole, password) => invoke('block_internet', {
        password: password || null,
        token: authToken || null,
        actorUsername: actorUsername || '',
        actorRole: actorRole || ''
      }),
      unblockInternet: (password, actorUsername, actorRole) => invoke('unblock_internet', {
        password: password || null,
        token: authToken || null,
        actorUsername: actorUsername || '',
        actorRole: actorRole || ''
      }),
      getAllowedSites: () => invoke('get_allowed_sites'),
      getBlockedSites: () => invoke('get_blocked_sites'),
      addSite: (site) => invoke('add_site', { site }),
      removeSite: (site) => invoke('remove_site', { site }),
      addBlockedSite: (site) => invoke('add_blocked_site', { site }),
      removeBlockedSite: (site) => invoke('remove_blocked_site', { site }),
      addSitesBulk: (sites, kind) => invoke('add_sites_bulk', { sites: Array.isArray(sites) ? sites : [String(sites || '')], kind: kind || 'allowed' }),
      getLogs: () => invoke('get_logs'),
      getConfig: () => invoke('get_config'),
      setListMode: (mode) => invoke('set_list_mode', { mode }),
      setDlpConfig: (usbBlock, exfilThresholdMb, exfilWindowSecs, exfilSuspicious, dlpSuperOnly, erpDomains, erpMasterToken) =>
        invoke('set_dlp_config', {
          usbBlock: Boolean(usbBlock),
          exfilThresholdMb: Number(exfilThresholdMb || 50),
          exfilWindowSecs: Number(exfilWindowSecs || 600),
          exfilSuspicious: Array.isArray(exfilSuspicious) ? exfilSuspicious : [],
          dlpSuperOnly: Boolean(dlpSuperOnly),
          erpDomains: Array.isArray(erpDomains) ? erpDomains : null,
          erpMasterToken: typeof erpMasterToken === 'string' ? erpMasterToken : null,
        }),
      toggleAutostart: (enable) => invoke('toggle_autostart', { enable }),
      setPassword: (currentPassword, newPassword) => invoke('set_password', { currentPassword, newPassword }),
      getAdminUsers: () => invoke('get_admin_users'),
      upsertAdminUser: (username, password, role, actorUsername, actorRole) => invoke('upsert_admin_user', {
        username,
        password,
        role: role || null,
        token: authToken || null,
        actorUsername: actorUsername || '',
        actorRole: actorRole || ''
      }),
      removeAdminUser: (username, actorUsername, actorRole) => invoke('remove_admin_user', {
        username,
        token: authToken || null,
        actorUsername: actorUsername || '',
        actorRole: actorRole || ''
      }),
      adminLogin: async (username, password, remember) => {
        const res = await invoke('admin_login', { username, password });
        if (res && res.success && res.token) {
          setAuthToken(res.token, remember);
        }
        return res;
      },
      getServerInfo: () => invoke('get_server_info'),
      checkServerConnection: () => invoke('check_server_connection'),
      getDevices: () => invoke('get_devices'),
      sendDeviceCommand: (deviceId, command, actorUsername, actorRole) => invoke('send_device_command', {
        deviceId,
        command,
        token: authToken || null,
        actorUsername: actorUsername || '',
        actorRole: actorRole || ''
      }),
      getRelayConfig: () => invoke('get_relay_config'),
      setRelayConfig: (relayUrl, adminKey, currentPassword, rustdeskServer, rustdeskKey, rustdeskPassword) =>
        invoke('set_relay_config', {
          relayUrl,
          adminKey: adminKey || null,
          currentPassword: currentPassword || null,
          rustdeskServer: typeof rustdeskServer === 'string' ? rustdeskServer : null,
          rustdeskKey: typeof rustdeskKey === 'string' ? rustdeskKey : null,
          rustdeskPassword: rustdeskPassword || null,
        }),
      createPairingToken: (label) => invoke('create_pairing_token', { label: label || null }),
      getRelayDevices: () => invoke('get_relay_devices'),
      sendRelayCommand: (deviceId, command, actorUsername, actorRole) => invoke('send_relay_command', {
        deviceId,
        command,
        token: authToken || null,
        actorUsername: actorUsername || '',
        actorRole: actorRole || ''
      }),
      syncPolicy: () => invoke('sync_policy_now'),
      getRelayGroups: () => invoke('get_relay_groups'),
      getDashboardStats: () => invoke('get_dashboard_stats'),
      getRelayAlerts: (type, acked) => invoke('get_relay_alerts', { alertType: type || null, acked: acked || null }),
      getAlertMedia: (alertId) => invoke('get_alert_media', { alertId }),
      ackAlert: (id) => invoke('ack_alert', { alertId: id }),
      ackAllAlerts: (type) => invoke('ack_all_alerts', { alertType: type || null }),
      getRustdeskOssStatus: () => invoke('get_rustdesk_oss_status'),
      checkAdminUpdate: () => invoke('check_admin_update'),
      applyAdminUpdate: isTauri ? () => invoke('apply_admin_update') : null,
      getUploadedFiles: (opts) => {
        if (!opts || typeof opts === 'string') {
          return invoke('get_uploaded_files', { channel: opts || null, tzOffsetMins: new Date().getTimezoneOffset() });
        }
        return invoke('get_uploaded_files', {
          channel: opts.channel || null,
          fromMs: opts.fromMs || null,
          toMs: opts.toMs || null,
          fileType: opts.fileType || null,
          device: opts.device || null,
          search: opts.search || null,
          page: opts.page || 1,
          pageSize: opts.pageSize || 60,
          tzOffsetMins: typeof opts.tzOffsetMins === 'number' ? opts.tzOffsetMins : new Date().getTimezoneOffset(),
        });
      },
      getBackupsList: () => invoke('get_backups_list'),
      createSystemBackup: () => invoke('create_system_backup'),
      restoreSystemBackup: (backupId) => invoke('restore_system_backup', { backupId }),
      openBackupsFolder: isTauri ? () => invoke('open_backups_folder') : null,
      browseBackupFolder: isTauri ? () => invoke('browse_backup_folder') : null,
      setBackupDir: (newPath, moveExisting) => invoke('set_backup_dir', {
        newPath: String(newPath || '').trim(),
        moveExisting: moveExisting !== false,
      }),
      getErpBackupsStatus: () => invoke('get_erp_backups_status'),
      saveErpBackupConfig: (enabled, intervalMins, url, username, password, didCookie, deviceToken) =>
        invoke('save_erp_backup_config', {
          enabled: Boolean(enabled),
          intervalMins: Number(intervalMins || 60),
          url: String(url || 'https://elkhawaga.uk').trim(),
          username: String(username || '').trim(),
          password: password ? String(password) : null,
          didCookie: typeof didCookie === 'string' ? didCookie.trim() : null,
          deviceToken: typeof deviceToken === 'string' ? deviceToken.trim() : null,
        }),
      runErpBackupNow: () => invoke('run_erp_backup_now'),
      openErpBackupsFolder: isTauri ? () => invoke('open_erp_backups_folder') : null,
      browseErpBackupFolder: isTauri ? () => invoke('browse_erp_backup_folder') : null,
      setErpBackupDir: (newPath, moveExisting) => invoke('set_erp_backup_dir', {
        newPath: String(newPath || '').trim(),
        moveExisting: moveExisting !== false,
      }),
      browseArchiveFolder: isTauri ? () => invoke('browse_archive_folder') : null,
      setArchiveDir: (newPath, moveExisting) => invoke('set_archive_dir', {
        newPath: String(newPath || '').trim(),
        moveExisting: moveExisting !== false,
      }),
      saveUploadedFile: isTauri
        ? (fileId, fileName) => invoke('save_uploaded_file', { fileId, fileName: fileName || null })
        : null,
      saveBase64Image: isTauri
        ? (base64Data, fileName) => invoke('save_base64_image', { base64Data, fileName: fileName || null })
        : null,
      saveTextFile: isTauri
        ? (content, fileName) => invoke('save_text_file', { content, fileName })
        : null,
      openArchiveFolder: async (targetPath) => {
        const isLocal = isTauri || location.hostname === '127.0.0.1' || location.hostname === 'localhost';
        if (!isLocal) {
          return {
            success: false,
            remote: true,
            error: 'أنت تتصفح من جهاز بعيد — استخدم زر "تحميل النسخة الأصلية" لتنزيل الملف مباشرة على جهازك'
          };
        }
        return invoke('open_archive_folder', { targetPath: targetPath || null });
      },
      getAuditLog: () => invoke('get_audit_log'),
      createRelayGroup: (name, mode, ephemeralBrowser, usbBlock) => invoke('create_relay_group', { name, mode, ephemeralBrowser: Boolean(ephemeralBrowser), usbBlock: Boolean(usbBlock) }),
      updateRelayGroup: (groupId, name, mode, allowed, blocked, ephemeralBrowser, usbBlock) => invoke('update_relay_group', { groupId, name, mode, allowed, blocked, ephemeralBrowser: Boolean(ephemeralBrowser), usbBlock: Boolean(usbBlock) }),
      deleteRelayGroup: (groupId) => invoke('delete_relay_group', { groupId }),
      assignDeviceGroup: (deviceId, groupId) => invoke('assign_device_group', { deviceId, groupId: groupId || null }),
      sendGroupCommand: (groupId, command, actorUsername, actorRole) => invoke('send_group_command', {
        groupId,
        command,
        token: authToken || null,
        actorUsername: actorUsername || '',
        actorRole: actorRole || ''
      }),
      renameRelayDevice: (deviceId, label) => invoke('rename_relay_device', { deviceId, label }),
      deleteRelayDevice: (deviceId) => invoke('delete_relay_device', { deviceId }),
      openSupportSession: async (rustdeskId, password, mode, deviceIp) => {
        const sessionMode = String(mode || 'support').trim().toLowerCase();
        const isLocalServerHost =
          location.hostname === '127.0.0.1' || location.hostname === 'localhost';
        if (isTauri || isLocalServerHost) {
          try {
            const res = await invoke('open_support_session', {
              rustdeskId,
              password: password || null,
              mode: sessionMode,
              deviceIp: deviceIp || null,
            });
            if (res && res.success !== false) return res;
            if (isTauri) return res;
          } catch (e) {
            if (isTauri) throw e;
          }
        }
        const id = String(rustdeskId || '').replace(/\s+/g, '');
        if (!id) return { success: false, error: 'لا يوجد RustDesk ID لهذا الجهاز' };
        if (!/^[a-zA-Z0-9._-]+$/.test(id)) return { success: false, error: 'RustDesk ID غير صالح' };
        const pw = String(password || '').trim() || 'KH2027kh';

        // Try local IT ELKHAWGA Admin helper on this laptop (127.0.0.1:8787) so view_only
        // in %APPDATA%\RustDesk\config\peers\<id>.toml is configured automatically.
        // First send only Content-Type (compatible with v1.1.x CORS preflight), then retry
        // with X-ITK-Client if v1.2.0 responds with 403.
        const payloadStr = JSON.stringify({ rustdeskId: id, password: pw, mode: sessionMode, deviceIp: deviceIp || '' });
        for (const hdrs of [
          { 'Content-Type': 'application/json' },
          { 'Content-Type': 'application/json', 'X-ITK-Client': '1' },
        ]) {
          try {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 900);
            const localRes = await fetch('http://127.0.0.1:8787/api/local/rustdesk-session', {
              method: 'POST',
              headers: hdrs,
              body: payloadStr,
              signal: ctrl.signal,
            });
            clearTimeout(timer);
            if (localRes && localRes.ok) {
              const jr = await localRes.json();
              if (jr && jr.success) return jr;
            }
            if (localRes && localRes.status !== 403) break;
          } catch (_) {
            break;
          }
        }

        if (sessionMode === 'camera') {
          window.location.href = 'rustdesk://view-camera/' + encodeURIComponent(id) + '?password=' + encodeURIComponent(pw);
          return { success: true };
        }
        window.location.href = 'rustdesk://connect/' + encodeURIComponent(id) + '?password=' + encodeURIComponent(pw);
        return { success: true };
      },
      setDeviceRustdeskPassword: (deviceId, password) => invoke('set_device_rustdesk_password', { deviceId, password }),
      requestScreenshot: (deviceId, transport, mode) => invoke('request_screenshot', {
        deviceId,
        transport: transport || null,
        mode: mode || null,
      }),
      getScreenshot: (deviceId, transport) => invoke('get_screenshot', { deviceId, transport: transport || null }),
      getWaBotStatus: () => invoke('get_wa_bot_status'),
      saveWaBotConfig: (config) => invoke('save_wa_bot_config', { config: config || {} }),
      connectWaBot: () => invoke('connect_wa_bot'),
      disconnectWaBot: (logout) => invoke('disconnect_wa_bot', { logout: Boolean(logout) }),
      sendWaBotTest: () => invoke('send_wa_bot_test'),
      cctvListDvrs: () => invoke('cctv_list_dvrs'),
      cctvSaveDvr: (dvr) => invoke('cctv_save_dvr', { dvr: dvr || {} }),
      cctvDeleteDvr: (id) => invoke('cctv_delete_dvr', { id }),
      cctvTestDvr: (dvr) => invoke('cctv_test_dvr', { dvr: dvr || {} }),
      cctvScanLan: (bridgeDeviceId) => invoke('cctv_scan_lan', { bridgeDeviceId: bridgeDeviceId || null }),
      cctvSetSettings: (superOnly) => invoke('cctv_set_settings', { superOnly: Boolean(superOnly) }),
      cctvGetFrameB64: (dvrId, channel, hd) => invoke('cctv_get_frame_b64', {
        dvrId,
        channel: Number(channel || 1),
        hd: Boolean(hd),
      }),
      cctvAction: (action, payload) => invoke('cctv_action', { action, payload: payload || {} }),
      getClientConfig: () => invoke('get_client_config'),
      setClientConfig: (serverUrl, token, password) => invoke('set_client_config', { serverUrl, token, password: password || null }),
      enrollRelay: (relayUrl, pairingToken, password) => invoke('enroll_relay', { relayUrl, pairingToken, password: password || null }),
      disconnectRelay: (password) => invoke('disconnect_relay', { password: password || null }),
      onStatusUpdate: (cb) => { listen('status-update', (e) => cb(e.payload)); },
    };
    return;
  }

  // --- Browser Preview Mode Fallback ---
  const now = Date.now();
  let mockDevices = [
    {
      device_id: 'dev_sales_01',
      hostname: 'SALES-LAPTOP-01',
      os: 'windows',
      app_version: '1.0.0',
      ip: '192.168.1.105',
      online: true,
      blocked: false,
      group_id: 'sales',
      label: 'جهاز المبيعات - أحمد وهبة',
      last_seen: now - 45000,
      last_event: 'unblock_password',
      last_event_at: now - 1800000,
      throttle_kbps: 0,
      sites: ['crm.salesforce.com', 'mail.company.com', 'portal.office.com', 'drive.google.com', 'slack.com', 'hubspot.com', 'erp.internal.local'],
      denied: ['facebook.com', 'youtube.com', 'tiktok.com', 'netflix.com'],
      rustdesk_id: '891 234 567',
      rustdesk_password: 'pass',
    },
    {
      device_id: 'dev_finance_02',
      hostname: 'FINANCE-DESK-02',
      os: 'windows',
      app_version: '1.0.0',
      ip: '192.168.1.114',
      online: true,
      blocked: true,
      group_id: 'finance',
      label: 'جهاز الحسابات - مريم',
      last_seen: now - 120000,
      last_event: 'block_password',
      last_event_at: now - 3600000,
      throttle_kbps: 1024,
      sites: ['accounting.local', 'tax.gov.eg', 'banks.com.eg', 'payroll.internal'],
      denied: ['gaming.com', 'steam.com', 'torrent.org'],
      rustdesk_id: '',
      rustdesk_password: '',
    },
    {
      device_id: 'dev_hr_03',
      hostname: 'HR-PC-DESKTOP',
      os: 'windows',
      app_version: '1.0.0',
      ip: '192.168.1.189',
      online: false,
      blocked: false,
      group_id: '',
      label: 'جهاز الموارد البشرية',
      last_seen: now - 86400000 * 2,
      last_event: '',
      last_event_at: 0,
      throttle_kbps: 0,
      sites: ['hr.portal.company', 'linkedin.com', 'internal-docs.net'],
      denied: [],
      rustdesk_id: '674 123 908',
      rustdesk_password: 'hr-secret-pass',
    }
  ];

  let mockGroups = [
    { id: 'sales', name: 'المبيعات', mode: 'whitelist', allowed: [], blocked: [] },
    { id: 'finance', name: 'الحسابات', mode: 'whitelist', allowed: [], blocked: [] },
    { id: 'hr', name: 'الموارد البشرية', mode: 'whitelist', allowed: [], blocked: [] }
  ];

  let mockAdmins = [
    { username: 'admin', role: 'super', created_at: now }
  ];

  function makeMockToken(username, role) {
    const hdr = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=+$/, '');
    const pld = btoa(unescape(encodeURIComponent(JSON.stringify({
      sub: username,
      role: role || 'super',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 43200
    })))).replace(/=+$/, '');
    return hdr + '.' + pld + '.mock_sig';
  }

  window.electronAPI = {
    setAuthToken,
    getAuthToken: () => authToken,
    getStatus: async () => false,
    getMode: async () => 'whitelist',
    blockInternet: async () => ({ success: true }),
    unblockInternet: async () => ({ success: true }),
    getAllowedSites: async () => ['example.com', 'google.com', 'microsoft.com'],
    getBlockedSites: async () => ['facebook.com', 'youtube.com'],
    addSite: async () => ({ success: true }),
    removeSite: async () => ({ success: true }),
    addBlockedSite: async () => ({ success: true }),
    removeBlockedSite: async () => ({ success: true }),
    getLogs: async () => '[2026-11-17 19:00:00 UTC] Agent started\n[2026-11-17 19:05:12 UTC] BLOCK (local) - success by admin (super)',
    getConfig: async () => ({ mode: 'whitelist', has_password: false, auto_start: false }),
    setListMode: async () => ({ success: true }),
    toggleAutostart: async () => ({ success: true }),
    setPassword: async () => ({ success: true }),
    getAdminUsers: async () => mockAdmins,
    upsertAdminUser: async (username, password, role) => {
      const ex = mockAdmins.find(u => u.username.toLowerCase() === username.toLowerCase());
      if (ex) ex.role = role || 'admin';
      else mockAdmins.push({ username, role: role || 'admin', created_at: Date.now() });
      return { success: true };
    },
    removeAdminUser: async (username) => {
      mockAdmins = mockAdmins.filter(u => u.username.toLowerCase() !== username.toLowerCase());
      return { success: true };
    },
    adminLogin: async (username, password) => {
      const found = mockAdmins.find(u => u.username.toLowerCase() === (username || '').toLowerCase());
      const role = found ? found.role : (username === 'admin' ? 'super' : '');
      if (!role || !password) return { success: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' };
      const token = makeMockToken(username, role);
      setAuthToken(token);
      return { success: true, token, username, role, is_super_admin: role === 'super' };
    },
    getServerInfo: async () => ({ port: 8787, ip: '192.168.1.100', token: 'mock-lan-token-12345' }),
    getDevices: async () => mockDevices,
    sendDeviceCommand: async (deviceId, command) => {
      mockDevices.forEach(d => {
        if (deviceId === '*' || d.device_id === deviceId) {
          if (command === 'block') d.blocked = true;
          if (command === 'unblock') d.blocked = false;
        }
      });
      return { success: true };
    },
    getRelayConfig: async () => ({
      relay_url: 'https://relay.company.com',
      has_admin_key: true,
      rustdesk_server: 'relay.company.com:21116',
      rustdesk_key: 'id_ed25519_mock_key',
      has_rustdesk_password: true,
      relay_version: '3'
    }),
    setRelayConfig: async () => ({ success: true }),
    createPairingToken: async (label) => ({ success: true, token: 'PAIR-' + Math.floor(100000 + Math.random() * 900000) }),
    getRelayDevices: async () => mockDevices,
    sendRelayCommand: async (deviceId, command) => {
      mockDevices.forEach(d => {
        if (deviceId === '*' || d.device_id === deviceId) {
          if (command === 'block') d.blocked = true;
          if (command === 'unblock') d.blocked = false;
          if (command.startsWith('throttle:')) {
            d.throttle_kbps = Number(command.split(':')[1]) || 0;
          }
        }
      });
      return { success: true };
    },
    syncPolicy: async () => ({ success: true }),
    getRelayGroups: async () => ({ groups: mockGroups }),
    getDashboardStats: async () => ({
      devices_count: mockDevices.length,
      online_count: mockDevices.filter(d => d.online).length,
      blocked_count: mockDevices.filter(d => d.blocked).length,
      alerts_count: 0,
      groups_count: mockGroups.length,
      kpis: {
        users: { value: 3, growth: 0 },
        orders: { value: 12, growth: 5 },
        engagement: { value: 94, growth: 2 },
        allowed: { value: 7, growth: 0 },
        blocked: { value: 4, growth: 0 }
      }
    }),
    getRelayAlerts: async () => [],
    ackAlert: async () => ({ success: true }),
    getAuditLog: async () => [],
    createRelayGroup: async (name, mode) => {
      const id = 'grp_' + Date.now();
      mockGroups.push({ id, name, mode, allowed: [], blocked: [] });
      return { success: true, id };
    },
    updateRelayGroup: async () => ({ success: true }),
    deleteRelayGroup: async (id) => {
      mockGroups = mockGroups.filter(g => g.id !== id);
      return { success: true };
    },
    assignDeviceGroup: async (deviceId, groupId) => {
      const d = mockDevices.find(x => x.device_id === deviceId);
      if (d) d.group_id = groupId || '';
      return { success: true };
    },
    sendGroupCommand: async () => ({ success: true }),
    renameRelayDevice: async (deviceId, label) => {
      const d = mockDevices.find(x => x.device_id === deviceId);
      if (d) d.label = label;
      return { success: true };
    },
    deleteRelayDevice: async (deviceId) => {
      mockDevices = mockDevices.filter(x => x.device_id !== deviceId);
      return { success: true };
    },
    openSupportSession: async () => ({ success: true }),
    setDeviceRustdeskPassword: async (deviceId, password) => {
      const d = mockDevices.find(x => x.device_id === deviceId);
      if (d) d.rustdesk_password = password;
      return { success: true };
    },
    requestScreenshot: async () => ({ success: true }),
    getScreenshot: async () => null,
    getWaBotStatus: async () => ({ success: true, ok: true, state: 'disconnected', connected: false, config: { enabled: false, recipients: '', max_file_mb: 25, features: {} }, logs: [] }),
    saveWaBotConfig: async (cfg) => ({ success: true, ok: true, config: cfg }),
    connectWaBot: async () => ({ success: true, ok: true, state: 'qr_ready' }),
    disconnectWaBot: async () => ({ success: true, ok: true, state: 'disconnected' }),
    sendWaBotTest: async () => ({ success: true, ok: true }),
    cctvListDvrs: async () => ({ ok: true, settings: { super_only: false }, dvrs: [] }),
    cctvSaveDvr: async () => ({ ok: true, settings: { super_only: false }, dvrs: [] }),
    cctvDeleteDvr: async () => ({ ok: true, settings: { super_only: false }, dvrs: [] }),
    cctvTestDvr: async () => ({ ok: true, message: 'Mock OK' }),
    cctvScanLan: async () => ({ ok: true, found: [] }),
    cctvSetSettings: async (superOnly) => ({ ok: true, settings: { super_only: Boolean(superOnly) } }),
    cctvGetFrameB64: async () => ({ ok: false }),
    cctvAction: async () => ({ ok: true }),
    getClientConfig: async () => ({}),
    setClientConfig: async () => ({ success: true }),
    enrollRelay: async () => ({ success: true }),
    disconnectRelay: async () => ({ success: true }),
    onStatusUpdate: (cb) => { /* no-op in browser */ },
  };
})();
