

    const api = window.electronAPI;
    const $ = (id) => document.getElementById(id);
    let isBlocked = false;
    let selectedMode = 'whitelist';
    let devicesTimer = null;
    let currentAdminUser = '';
    let currentAdminRole = '';

    function hasSuperAdminAccess() {
      return String(currentAdminRole || '').toLowerCase() === 'super';
    }

    function canManageAdminUsers() {
      return hasSuperAdminAccess() && currentAdminUser.trim();
    }

    const esc = (s) => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };
    const TRASH = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 002 2h6a2 2 0 002-2l1-12M9 7V4h6v3"/></svg>';

    function toast(msg, type = 'success') {
      const t = $('toast');
      t.textContent = msg;
      t.className = 'toast ' + type + ' show';
      clearTimeout(toast._t);
      toast._t = setTimeout(() => { t.className = 'toast'; }, 3000);
    }

    /* ---------- Navigation ---------- */
    document.querySelectorAll('.nav-item').forEach((item) => {
      item.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));
        document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
        item.classList.add('active');
        $('view-' + item.dataset.view).classList.add('active');
        $('pageTitle').textContent = item.dataset.title;
        $('pageSub').textContent = item.dataset.sub;
        if (item.dataset.view === 'logs') loadLogs();
        if (item.dataset.view === 'devices') loadServerInfo();
        if (item.dataset.view === 'relay') { loadRelayConfig(); loadRelayDevices(); startRelayTimer(); }
        if (item.dataset.view === 'alerts') { loadAlerts(); loadAudit(); startRelayTimer(); }
        else if (item.dataset.view === 'dashboard') { startRelayTimer(); loadKpis(); }
        else { stopRelayTimer(); }
        if (item.dataset.view === 'groups') { loadGroups(); }
      });
    });

    /* ---------- Status ---------- */
    function renderStatus() {
      $('hero').classList.toggle('blocked', isBlocked);
      $('ringIcon').textContent = isBlocked ? '🔒' : '🌐';
      $('heroTitle').textContent = isBlocked ? 'الإنترنت مقفول' : 'الإنترنت مفتوح';
      $('heroTitle').className = 'hero-title ' + (isBlocked ? 'blocked' : 'ok');
      $('heroDesc').textContent = isBlocked ? 'المواقع المسموحة فقط متاحة على هذا الجهاز' : 'جميع المواقع متاحة على هذا الجهاز';
      $('sideDot').className = 'dot' + (isBlocked ? ' blocked' : '');
      $('sideStatus').textContent = isBlocked ? 'الإنترنت مقفول' : 'الإنترنت مفتوح';
      $('blockBtn').disabled = isBlocked;
      $('unblockBtn').disabled = !isBlocked;
    }

    async function loadStatus() {
      isBlocked = await api.getStatus();
      renderStatus();
    }

    api.onStatusUpdate((s) => { isBlocked = s; renderStatus(); });

    async function runAction(btn, busyText, fn, okMsg, failMsg) {
      const original = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> ' + busyText;
      try {
        const r = await fn();
        if (r && r.success) toast(okMsg); else toast((r && r.error) || failMsg, 'error');
      } catch (e) {
        toast('حدث خطأ: ' + e.message, 'error');
      }
      btn.innerHTML = original;
      await loadStatus();
    }

    $('blockBtn').addEventListener('click', () => runAction($('blockBtn'), 'جاري القفل...', () => api.blockInternet(currentAdminUser, currentAdminRole), 'تم قفل الإنترنت', 'فشل القفل'));

    function doUnblock(pw) {
      runAction($('unblockBtn'), 'جاري الفتح...', () => api.unblockInternet(pw, currentAdminUser, currentAdminRole), 'تم فتح الإنترنت', 'فشل الفتح');
    }

    $('unblockBtn').addEventListener('click', async () => {
      const c = await api.getConfig();
      if (!c.has_password) { doUnblock(''); return; }
      $('passInput').value = '';
      $('passModal').classList.add('show');
      $('passInput').focus();
    });
    $('passCancel').addEventListener('click', () => $('passModal').classList.remove('show'));
    $('passOk').addEventListener('click', () => {
      const pw = $('passInput').value;
      $('passModal').classList.remove('show');
      doUnblock(pw);
    });
    $('passInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('passOk').click(); });

    /* ---------- Sites ---------- */
    function renderList(el, sites, removable, emptyText) {
      if (!sites.length) { el.innerHTML = '<div class="empty">' + emptyText + '</div>'; return; }
      el.innerHTML = sites.map((s) =>
        '<div class="list-item"><span>' + esc(s) + '</span>' +
        (removable ? '<button class="icon-btn" data-remove="' + esc(s) + '" data-kind="' + removable + '" title="حذف">' + TRASH + '</button>' : '') +
        '</div>').join('');
    }

    async function loadSites() {
      const allowed = await api.getAllowedSites();
      const blocked = await api.getBlockedSites();
      renderList($('allowedList'), allowed, 'allowed', 'لا توجد مواقع مسموحة');
      renderList($('blockedList'), blocked, 'blocked', 'لا توجد مواقع مقفولة');
      $('kpiAllowed').textContent = allowed.length;
      $('kpiBlocked').textContent = blocked.length;
    }

    document.addEventListener('click', async (e) => {
      const rm = e.target.closest('[data-remove]');
      if (rm) {
        try {
          if (rm.dataset.kind === 'allowed') await api.removeSite(rm.dataset.remove);
          else await api.removeBlockedSite(rm.dataset.remove);
          await loadSites();
          toast('تم الحذف');
        } catch (err) { toast('حدث خطأ: ' + err.message, 'error'); }
      }
      const cp = e.target.closest('[data-copy]');
      if (cp) {
        navigator.clipboard.writeText($(cp.dataset.copy).textContent);
        toast('تم النسخ');
      }

      const adminEdit = e.target.closest('[data-admin-edit]');
      if (adminEdit) {
        if (!canManageAdminUsers()) {
          toast('فقط السوبر أدمن يمكنه تعديل حسابات المديرين', 'error');
          return;
        }
        const user = adminEdit.dataset.adminEdit;
        $('adminUserName').value = user;
        $('adminUserPass').value = '';
        $('adminUserPass').placeholder = 'اتركها فارغة إذا لم ترد تغييرها';
        $('adminUserRole').value = adminEdit.dataset.adminRole || 'admin';
        $('adminUserName').focus();
        toast('تم تحميل بيانات المدير');
        return;
      }

      const adminDel = e.target.closest('[data-admin-remove]');
      if (adminDel) {
        if (!canManageAdminUsers()) {
          toast('فقط السوبر أدمن يمكنه حذف المديرين', 'error');
          return;
        }
        const username = adminDel.dataset.adminRemove;
        if (!confirm('حذف المدير "' + username + '"؟')) return;
        try {
          const r = await api.removeAdminUser(username, currentAdminUser, currentAdminRole);
          if (r.success) {
            toast('تم حذف المدير');
            await loadAdminUsers();
          } else {
            toast(r.error || 'فشل الحذف', 'error');
          }
        } catch (err) { toast('حدث خطأ: ' + err.message, 'error'); }
      }
    });

    function cleanDomain(v) {
      return v.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    }

    async function addTo(inputId, fn) {
      const v = cleanDomain($(inputId).value);
      if (!v) { toast('اكتب اسم الموقع', 'error'); return; }
      try {
        await fn(v);
        $(inputId).value = '';
        await loadSites();
        toast('تمت الإضافة');
      } catch (err) { toast('حدث خطأ: ' + err.message, 'error'); }
    }

    $('addSiteBtn').addEventListener('click', () => addTo('newSiteInput', (v) => api.addSite(v)));
    $('addBlockedBtn').addEventListener('click', () => addTo('newBlockedInput', (v) => api.addBlockedSite(v)));
    $('newSiteInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('addSiteBtn').click(); });
    $('newBlockedInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('addBlockedBtn').click(); });

    /* ---------- Settings ---------- */
    function renderMode() {
      $('modeWhitelist').classList.toggle('selected', selectedMode === 'whitelist');
      $('modeBlacklist').classList.toggle('selected', selectedMode === 'blacklist');
      $('dashMode').textContent = selectedMode === 'whitelist' ? 'Whitelist - اقفل الكل واسمح بالمحدد' : 'Blacklist - افتح الكل واقفل المحدد';
    }

    async function loadConfig() {
      const c = await api.getConfig();
      selectedMode = c.mode || 'whitelist';
      $('autostartToggle').checked = !!c.auto_start;
      renderMode();
    }

    $('modeWhitelist').addEventListener('click', () => { selectedMode = 'whitelist'; renderMode(); });
    $('modeBlacklist').addEventListener('click', () => { selectedMode = 'blacklist'; renderMode(); });

    $('saveModeBtn').addEventListener('click', async () => {
      const r = await api.setListMode(selectedMode);
      if (r.success) toast('تم حفظ الوضع. اضغط "قفل الإنترنت" ليسري'); else toast(r.error || 'فشل الحفظ', 'error');
    });

    $('autostartToggle').addEventListener('change', async (e) => {
      const want = e.target.checked;
      const r = await api.toggleAutostart(want);
      if (r.success) toast(want ? 'تم تفعيل التشغيل التلقائي' : 'تم إيقاف التشغيل التلقائي');
      else { toast(r.error || 'فشلت العملية', 'error'); e.target.checked = !want; }
    });

    $('savePassBtn').addEventListener('click', async () => {
      const cur = $('curPass').value, nw = $('newPass').value, cf = $('confPass').value;
      if (nw.length < 4) { toast('كلمة السر 4 أحرف على الأقل', 'error'); return; }
      if (nw !== cf) { toast('كلمتا السر غير متطابقتين', 'error'); return; }
      const r = await api.setPassword(cur, nw);
      if (r.success) { $('curPass').value = $('newPass').value = $('confPass').value = ''; toast('تم حفظ كلمة السر'); }
      else toast(r.error || 'فشل الحفظ', 'error');
    });

    /* ---------- Admin users ---------- */
    async function loadAdminUsers() {
      if (!api.getAdminUsers) return;
      const users = await api.getAdminUsers();
      const tbody = $('adminsTableBody');
      const total = users.length || 0;
      const superCount = users.filter(u => String(u.role || 'admin') === 'super').length;
      const adminCount = users.filter(u => String(u.role || 'admin') === 'admin').length;
      $('adminTotalStat').textContent = total;
      $('adminSuperStat').textContent = superCount;
      $('adminNormalStat').textContent = adminCount;
      const canManage = canManageAdminUsers();
      const actionButtons = canManage ? '' : '<div class="hint" style="margin:0;">فقط السوبر أدمن يمكنه إنشاء أو تعديل أو حذف حسابات المديرين.</div>';
      if (!total) {
        tbody.innerHTML = '<tr><td colspan="4"><div class="empty">لا يوجد مديرين مسجلين بعد.</div></td></tr>';
        return;
      }
      tbody.innerHTML = users.map((u) => {
        const role = String(u.role || 'admin');
        const state = role === 'super' ? '<span class="badge violet">Super</span>' : role === 'support' ? '<span class="badge gold">Support</span>' : role === 'viewer' ? '<span class="badge gray">Viewer</span>' : '<span class="badge green">Admin</span>';
        const actions = canManage
          ? '<button class="btn btn-ghost btn-sm" data-admin-edit="' + esc(u.username || '') + '" data-admin-role="' + esc(role) + '">تعديل</button> ' +
            '<button class="btn btn-danger btn-sm" data-admin-remove="' + esc(u.username || '') + '">حذف</button>'
          : '<span class="badge gray">للقراءة فقط</span>';
        return '<tr>' +
          '<td><b>' + esc(u.username || '') + '</b></td>' +
          '<td>' + esc(role) + '</td>' +
          '<td>' + state + '</td>' +
          '<td>' + actions + '</td>' +
        '</tr>';
      }).join('');
      if (!canManage) {
        $('adminsTableBody').insertAdjacentHTML('beforeend', '<tr><td colspan="4">' + actionButtons + '</td></tr>');
      }
    }

    function clearAdminForm() {
      $('adminUserName').value = '';
      $('adminUserPass').value = '';
      $('adminUserRole').value = 'admin';
      $('adminUserPass').placeholder = 'اتركها فارغة إذا لم ترد تغييرها';
      $('adminUserName').focus();
    }

    $('saveAdminBtn').addEventListener('click', async () => {
      if (!canManageAdminUsers()) {
        toast('فقط السوبر أدمن يمكنه إنشاء أو تعديل المديرين', 'error');
        return;
      }
      const username = $('adminUserName').value.trim();
      const password = $('adminUserPass').value.trim();
      const role = $('adminUserRole').value;
      if (!username) { toast('اكتب اسم المستخدم أولاً', 'error'); return; }
      try {
        const r = await api.upsertAdminUser(username, password, role, currentAdminUser, currentAdminRole);
        if (r.success) {
          toast('تم حفظ بيانات المدير');
          clearAdminForm();
          await loadAdminUsers();
        } else {
          toast(r.error || 'فشل حفظ المدير', 'error');
        }
      } catch (err) { toast('حدث خطأ: ' + err.message, 'error'); }
    });

    $('clearAdminFormBtn').addEventListener('click', clearAdminForm);
    $('refreshAdminsBtn').addEventListener('click', loadAdminUsers);

    $('adminLoginBtn').addEventListener('click', async () => {
      const username = $('adminLoginName').value.trim();
      const password = $('adminLoginPass').value;
      if (!username) { toast('اكتب اسم المستخدم', 'error'); return; }
      try {
        const r = await api.adminLogin(username, password);
        if (r.success) {
          currentAdminUser = username;
          currentAdminRole = String(r.role || 'admin');
          $('adminLoginResult').innerHTML = '<span class="badge green">تم الدخول</span> المستخدم: <b>' + esc(username) + '</b> · الدور: <b>' + esc(currentAdminRole) + '</b>';
          toast('تم تسجيل الدخول بنجاح');
          await loadAdminUsers();
        } else {
          currentAdminUser = '';
          currentAdminRole = '';
          $('adminLoginResult').innerHTML = '<span class="badge red">فشل</span> ' + esc(r.error || 'اسم المستخدم أو كلمة المرور غير صحيحة');
          toast(r.error || 'فشل الدخول', 'error');
        }
      } catch (err) {
        currentAdminUser = '';
        currentAdminRole = '';
        $('adminLoginResult').textContent = 'حدث خطأ في تسجيل الدخول';
        toast('حدث خطأ: ' + err.message, 'error');
      }
    });

    /* ---------- Logs ---------- */
    async function loadLogs() {
      $('logsBox').textContent = '...';
      const logs = await api.getLogs();
      $('logsBox').textContent = logs && logs.trim() ? logs : 'لا توجد عمليات مسجلة بعد.';
    }
    $('refreshLogsBtn').addEventListener('click', loadLogs);

    /* ---------- Devices ---------- */
    function ago(ts) {
      const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
      if (s < 5) return 'الآن';
      if (s < 60) return 'منذ ' + s + ' ثانية';
      if (s < 3600) return 'منذ ' + Math.round(s / 60) + ' دقيقة';
      return 'منذ ' + Math.round(s / 3600) + ' ساعة';
    }

    async function loadServerInfo() {
      if (!api.getServerInfo) return;
      const info = await api.getServerInfo();
      $('serverUrl').textContent = 'http://' + info.ip + ':' + info.port;
      $('serverToken').textContent = info.token;
    }

    /* ---------- Device table (shared by LAN and Relay) ---------- */
    async function ensureGroupsCache() {
      if (groupsCache.length) return;
      try { const gr = await api.getRelayGroups(); groupsCache = (gr && gr.groups) || []; } catch (e) {}
    }

    /** Builds one row with the full feature set, for both transports.
     *  prefix: 'lan' (local server) or 'relay' (cloud). */
    function deviceRow(d, prefix) {
      const online = d.online;
      const state = !online ? '<span class="badge gray">غير متصل</span>'
        : d.blocked ? '<span class="badge red">مقفول</span>' : '<span class="badge green">مفتوح</span>';
      let evBadge = '';
      if (d.last_event === 'unblock_password' && d.last_event_at) {
        evBadge = '<div class="badge gold" style="margin-top:6px;">فتح بكلمة سر · ' + ago(d.last_event_at) + '</div>';
      } else if (d.last_event === 'block_password' && d.last_event_at) {
        evBadge = '<div class="badge violet" style="margin-top:6px;">قفل يدوي · ' + ago(d.last_event_at) + '</div>';
      }
      const shown = d.label || d.hostname || d.device_id;
      const sub = d.label && d.hostname ? '<div class="mono" style="font-size:11px;color:#94a3b8">' + esc(d.hostname) + '</div>' : '';
      const rd = d.rustdesk_id ? '<div class="mono" style="font-size:11px;color:#6d28d9;margin-top:2px;">RustDesk: ' + esc(d.rustdesk_id) + '</div>' : '';
      const opts = ['<option value="">— افتراضي —</option>'].concat(
        groupsCache.map(function (g) {
          return '<option value="' + esc(g.id) + '"' + (d.group_id === g.id ? ' selected' : '') + '>' + esc(g.name) + '</option>';
        })
      ).join('');
      const groupSel = '<select class="input" style="padding:7px 10px;font-size:12.5px;" data-dev-group="' + esc(d.device_id) + '" data-transport="' + prefix + '">' + opts + '</select>';
      const controls =
        (online ? '<button class="btn btn-danger btn-sm" data-dev-cmd="block" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '">قفل</button> ' +
                  '<button class="btn btn-success btn-sm" data-dev-cmd="unblock" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '">فتح</button> ' : '') +
        '<button class="btn btn-ghost btn-sm" data-screen-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">🖥 شاشة</button> ' +
        (d.rustdesk_id
          ? '<button class="btn btn-ghost btn-sm" data-support-device="' + esc(d.rustdesk_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">🛠 دعم</button> ' +
            '<button class="btn btn-ghost btn-sm" data-rdpass-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-current-rdpass="' + esc(d.rustdesk_password || '') + '">🔑 كلمة</button> '
          : '<a class="btn btn-ghost btn-sm" href="https://rustdesk.com" target="_blank" rel="noopener" style="text-decoration:none;">⬇ RustDesk</a> ') +
        '<button class="btn btn-ghost btn-sm" data-rename-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-current-name="' + esc(d.label || '') + '">✎ اسم</button> ' +
        '<button class="btn btn-ghost btn-sm" data-delete-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" style="color:#b91c1c;">🗑 حذف</button>';
      return '<tr><td><b>' + esc(shown) + '</b>' + sub + rd + '</td><td class="mono">' + esc(d.ip || '') + '</td><td>' + state + evBadge +
        '</td><td>' + groupSel + '</td><td>' + (d.last_seen ? ago(d.last_seen) : '-') + '</td><td>' + sitesCell(d.sites, d.denied) + '</td><td>' +
        '<div style="display:flex;gap:6px;align-items:center;">' +
          '<select class="input" data-throttle-input="' + esc(d.device_id) + '" data-transport="' + prefix + '" style="width:120px;padding:6px 8px;font-size:12px;">' +
            speedOptions(d.throttle_kbps) +
          '</select>' +
          '<button class="btn btn-ghost btn-sm" data-throttle-apply="' + esc(d.device_id) + '" data-transport="' + prefix + '">تعيين</button>' +
        '</div>' +
        '</td><td>' + controls + '</td></tr>';
    }

    async function loadDevices() {
      if (!api.getDevices) return;
      // Don't rebuild rows while a dropdown is open on this table.
      const ae = document.activeElement;
      if (ae && ae.tagName === 'SELECT' && ae.closest('#view-devices')) return;
      if (lanTableHover) return;
      await ensureGroupsCache();
      let devices = [];
      try { devices = (await api.getDevices()) || []; } catch (e) { devices = []; }
      const online = devices.filter((d) => d.online).length;
      if ($('navDeviceCount')) $('navDeviceCount').textContent = devices.length;
      if ($('kpiLan')) $('kpiLan').textContent = online;
      $('devicesEmpty').style.display = devices.length ? 'none' : 'block';
      $('devicesBody').innerHTML = devices.map((d) => deviceRow(d, 'lan')).join('');
    }

    document.addEventListener('click', async (e) => {
      const b = e.target.closest('[data-dev-cmd]');
      if (!b) return;
      try {
        const isRelay = b.dataset.transport === 'relay';
        const r = isRelay
          ? await api.sendRelayCommand(b.dataset.id, b.dataset.devCmd, currentAdminUser, currentAdminRole)
          : await api.sendDeviceCommand(b.dataset.id, b.dataset.devCmd, currentAdminUser, currentAdminRole);
        if (r && r.success === false) { toast(r.error || 'فشل إرسال الأمر', 'error'); return; }
        toast('تم إرسال الأمر' + (isRelay ? ' للـ Relay' : '، يصل خلال ثوانٍ'));
      } catch (err) { toast(err.message || 'فشل إرسال الأمر', 'error'); }
    });

    if ($('refreshLanBtn')) $('refreshLanBtn').addEventListener('click', loadDevices);

    let lanTableHover = false;
    document.addEventListener('mouseover', (e) => {
      if (e.target.closest && e.target.closest('#view-devices .table-wrap')) lanTableHover = true;
    });
    document.addEventListener('mouseout', (e) => {
      if (e.target.closest && e.target.closest('#view-devices .table-wrap')) lanTableHover = false;
    });

    $('blockAllBtn').addEventListener('click', async () => { await api.sendDeviceCommand('*', 'block', currentAdminUser, currentAdminRole); toast('تم إرسال أمر القفل لكل الأجهزة'); });
    $('unblockAllBtn').addEventListener('click', async () => { await api.sendDeviceCommand('*', 'unblock', currentAdminUser, currentAdminRole); toast('تم إرسال أمر الفتح لكل الأجهزة'); });

    /* ---------- Relay ---------- */
    async function loadRelayConfig() {
      if (!api.getRelayConfig) return;
      try {
        const c = await api.getRelayConfig();
        $('relayUrlInput').value = c.relay_url || '';
        $('relayKeyInput').value = '';
        $('relayKeyInput').placeholder = c.has_admin_key ? 'مفتاح محفوظ (اتركه فارغاً للإبقاء عليه)' : 'مفتاح المدير للـ Relay';
        const su = $('relayStatusUrl');
        if (su) su.textContent = c.relay_url || '—';
        $('rdServerInput').value = c.rustdesk_server || '';
        $('rdKeyInput').value = c.rustdesk_key || '';
        $('rdPassInput').value = '';
        $('rdPassInput').placeholder = c.has_rustdesk_password ? 'كلمة سر محفوظة (اتركه فارغًا للإبقاء)' : 'اتركه فارغًا لتعطيل';
        $('relayKeySaved').style.display = c.has_admin_key ? 'inline-flex' : 'none';
        if (c.relay_version && c.relay_version !== '3') {
          toast('نسخة الـ Relay قديمة (' + c.relay_version + ') — أعِد تشغيل أحدث relay/server.js', 'error');
        }
      } catch (e) { /* ignore */ }
    }

    $('saveRelayBtn').addEventListener('click', async () => {
      const url = $('relayUrlInput').value.trim();
      const key = $('relayKeyInput').value.trim();
      if (!url) { toast('اكتب عنوان الـ Relay', 'error'); return; }
      const c = await api.getConfig();
      let pw = '';
      if (c.has_password) {
        pw = prompt('كلمة سر المدير لتأكيد تغيير إعدادات الـ Relay') || '';
        if (!pw) return;
      }
      const rdServer = $('rdServerInput').value.trim();
      const rdKey = $('rdKeyInput').value.trim();
      const rdPass = $('rdPassInput').value.trim();
      const r = await api.setRelayConfig(url, key || null, pw || null, rdServer || null, rdKey || null, rdPass || null);
      if (r.success) { toast('تم حفظ إعدادات الـ Relay'); await loadRelayDevices(); }
      else toast(r.error || 'فشل الحفظ', 'error');
    });

    $('genPairBtn').addEventListener('click', async () => {
      const label = $('pairLabelInput').value.trim();
      try {
        const r = await api.createPairingToken(label || null);
        $('pairToken').textContent = r.token || '';
        $('pairResultWrap').style.display = 'block';
        toast('تم إنشاء رمز الربط');
      } catch (e) { toast(e.message || 'فشل إنشاء الرمز', 'error'); }
    });

    let relayTableHover = false;

    async function loadRelayDevices() {
      if (!api.getRelayDevices) return;
      // Never rebuild the rows while a dropdown is open or the pointer is over
      // the table, otherwise the select closes before a choice is made.
      const ae = document.activeElement;
      if (ae && ae.tagName === 'SELECT' && ae.closest('#view-relay')) return;
      if (relayTableHover) return;
      if (!groupsCache.length) {
        try { const gr = await api.getRelayGroups(); groupsCache = (gr && gr.groups) || []; } catch (e) {}
      }
      let devices = [];
      try {
        const r = await api.getRelayDevices();
        devices = Array.isArray(r) ? r : ((r && r.devices) || []);
      } catch (e) { devices = []; }
      $('relayDevicesEmpty').style.display = devices.length ? 'none' : 'block';
      const rc = $('navRelayCount');
      if (rc) rc.textContent = devices.length;
      const rs = $('kpiRelay');
      if (rs) rs.textContent = devices.filter(function (x) { return x.online; }).length;
      $('relayDevicesBody').innerHTML = devices.map((d) => deviceRow(d, 'relay')).join('');
    }

    document.addEventListener('change', async (e) => {
      const sel = e.target.closest('[data-dev-group]');
      if (!sel) return;
      // Groups are stored on the relay; LAN devices are synced to it too when linked.
      try {
        const r = await api.assignDeviceGroup(sel.dataset.devGroup, sel.value || null);
        if (r && r.success) {
          toast('تم تعيين المجموعة');
          loadGroups();
          if (sel.dataset.transport === 'lan') loadDevices(); else loadRelayDevices();
        } else toast((r && r.error) || 'فشل التعيين', 'error');
      } catch (err) { toast(err.message || 'فشل التعيين', 'error'); }
    });

    document.addEventListener('click', async (e) => {
      const b = e.target.closest('[data-relay-cmd]');
      if (!b) return;
      const r = await api.sendRelayCommand(b.dataset.id, b.dataset.relayCmd, currentAdminUser, currentAdminRole);
      if (r && r.success) toast('تم إرسال الأمر للـ Relay');
      else toast((r && r.error) || 'فشل إرسال الأمر', 'error');
    });

    $('refreshRelayBtn').addEventListener('click', loadRelayDevices);

    const SEV_COLOR = { low: '#64748b', medium: '#a16207', high: '#b91c1c', critical: '#7f1d1d' };
    const SEV_BG = { low: 'rgba(100,116,139,.12)', medium: 'rgba(199,154,43,.14)', high: 'rgba(220,38,38,.12)', critical: 'rgba(127,29,29,.18)' };
    const TYPE_LABEL = { tamper: 'تلاعب', exfil: 'سرقة بيانات', usb: 'USB', auth_fail: 'فشل مصادقة', bypass: 'تجاوز' };

    async function loadAlerts() {
      if (!api.getRelayAlerts) return;
      const type = $('alertFilter').value;
      const acked = $('alertAckFilter').value;
      let alerts = [];
      try {
        const r = await api.getRelayAlerts(type || null, acked);
        alerts = (r && r.alerts) || [];
        const n = (r && r.unacked) || 0;
        const badge = $('navAlertCount');
        if (badge) badge.textContent = n;
      } catch (e) { alerts = []; }
      if (!alerts.length) {
        $('alertsList').innerHTML = '<div class="empty">لا توجد تنبيهات.</div>';
        return;
      }
      $('alertsList').innerHTML = alerts.map(function (a) {
        const sev = a.severity || 'medium';
        const color = SEV_COLOR[sev] || '#64748b';
        const bg = SEV_BG[sev] || 'rgba(100,116,139,.12)';
        const acked = a.acked;
        return '<div class="card" style="margin-bottom:12px;border-inline-start:4px solid ' + color + ';background:' + bg + ';">' +
          '<div style="display:flex;justify-content:space-between;align-items:start;gap:12px;">' +
            '<div>' +
              '<div style="font-weight:800;font-size:14px;color:' + color + ';">' + esc(TYPE_LABEL[a.type] || a.type) + ' · ' + esc(sev.toUpperCase()) + '</div>' +
              '<div style="font-size:12.5px;color:var(--text);margin-top:4px;">' + esc(a.message) + '</div>' +
              '<div class="mono" style="font-size:11px;color:#94a3b8;margin-top:6px;">' + esc(a.device_name || a.device_id) + ' · ' + ago(a.created_at) + (acked ? ' · مُقرَّة' : '') + '</div>' +
            '</div>' +
            (acked ? '' : '<button class="btn btn-ghost btn-sm" data-ack-alert="' + esc(a.id) + '">إقرار</button>') +
          '</div>' +
        '</div>';
      }).join('');
    }

    document.addEventListener('click', async (e) => {
      const b = e.target.closest('[data-ack-alert]');
      if (!b) return;
      try {
        await api.ackAlert(b.dataset.ackAlert);
        toast('تم إقرار التنبيه');
        loadAlerts();
      loadAudit();
      } catch (err) { toast(err.message || 'فشل', 'error'); }
    });

    $('refreshAlertsBtn').addEventListener('click', loadAlerts);
    $('alertFilter').addEventListener('change', loadAlerts);
    $('alertAckFilter').addEventListener('change', loadAlerts);

    async function loadAudit() {
      if (!api.getAuditLog) return;
      let entries = [];
      try { const r = await api.getAuditLog(); entries = (r && r.entries) || []; } catch (e) { entries = []; }
      if (!entries.length) { $('auditList').innerHTML = '<div class="empty">لا توجد سجلات.</div>'; return; }
      $('auditList').innerHTML = entries.map(function (e) {
        const res = e.result === 'ok' ? '<span class="badge green">OK</span>' : '<span class="badge red">' + esc(e.result || '') + '</span>';
        return '<div class="list-item">' +
          '<span><b>' + esc(e.action) + '</b>' + (e.target ? ' · ' + esc(e.target) : '') + '</span>' +
          '<span style="display:flex;gap:8px;align-items:center;">' + res +
          '<span class="mono" style="font-size:11px;color:#94a3b8;">' + esc(e.actor) + ' · ' + ago(e.created_at) + '</span></span></div>';
      }).join('');
    }
    $('refreshAuditBtn').addEventListener('click', loadAudit);

    let screenTimer = null;
    let currentScreenDevice = null;
    function stopScreenTimer() { if (screenTimer) { clearInterval(screenTimer); screenTimer = null; } }
    async function requestAndLoadScreen(deviceId) {
      try { await api.requestScreenshot(deviceId); } catch (e) {}
      await pollScreen(deviceId);
    }
    async function pollScreen(deviceId) {
      try {
        const r = await api.getScreenshot(deviceId);
        if (r && r.image) {
          $('screenImg').src = 'data:image/jpeg;base64,' + r.image;
          $('screenImg').style.display = 'block';
          $('screenEmpty').style.display = 'none';
          const t = r.at ? new Date(r.at).toLocaleTimeString() : '';
          $('screenStatus').textContent = 'آخر لقطة: ' + t + (r.requested ? ' (بانتظار تحديث)' : '');
        } else {
          $('screenImg').style.display = 'none';
          $('screenEmpty').style.display = 'block';
          $('screenStatus').textContent = r && r.requested ? 'بانتظار لقطة من الجهاز...' : 'لا توجد لقطة yet';
        }
      } catch (e) { $('screenStatus').textContent = 'تعذر جلب اللقطة'; }
    }
    function openScreen(deviceId, name) {
      currentScreenDevice = deviceId;
      $('screenTitle').textContent = 'شاشة ' + name;
      $('screenImg').style.display = 'none';
      $('screenEmpty').style.display = 'block';
      $('screenStatus').textContent = 'جارٍ طلب لقطة شاشة...';
      $('screenModal').classList.add('show');
      requestAndLoadScreen(deviceId);
      stopScreenTimer();
      screenTimer = setInterval(() => pollScreen(deviceId), 4000);
    }
    $('screenCloseBtn').addEventListener('click', () => { $('screenModal').classList.remove('show'); stopScreenTimer(); currentScreenDevice = null; });
    $('screenModal').addEventListener('click', (e) => { if (e.target.id === 'screenModal') { $('screenModal').classList.remove('show'); stopScreenTimer(); currentScreenDevice = null; } });
    $('screenRefreshBtn').addEventListener('click', () => { if (currentScreenDevice) requestAndLoadScreen(currentScreenDevice); });

    document.addEventListener('mouseover', (e) => {
      if (e.target.closest && e.target.closest('#view-relay .table-wrap')) relayTableHover = true;
    });
    document.addEventListener('mouseout', (e) => {
      if (e.target.closest && e.target.closest('#view-relay .table-wrap')) relayTableHover = false;
    });

    let relayTimer = null;
    function startRelayTimer() {
      stopRelayTimer();
      relayTimer = setInterval(loadRelayDevices, 3000);
    }
    function stopRelayTimer() {
      if (relayTimer) { clearInterval(relayTimer); relayTimer = null; }
    }

    /* ---------- Dashboard KPI details ---------- */
    const KPI_TITLES = {
      users: 'المستخدمون (أجهزة Relay)',
      orders: 'الطلبات النشطة',
      engagement: 'معدل التفاعل',
      allowed: 'المواقع المسموحة',
      blocked: 'المواقع المقفولة',
      lan: 'أجهزة الشبكة المحلية',
      relay: 'أجهزة متصلة عبر Relay'
    };

    async function openKpi(key) {
      $('kpiModalTitle').textContent = KPI_TITLES[key] || 'التفاصيل';
      const body = $('kpiModalBody');
      body.innerHTML = '<div class="empty">جارٍ التحميل...</div>';
      $('kpiModal').classList.add('show');

      let html = '';
      try {
        if (key === 'users' || key === 'relay' || key === 'engagement') {
          const r = await api.getRelayDevices();
          const list = Array.isArray(r) ? r : ((r && r.devices) || []);
          const online = list.filter((d) => d.online);
          if (key === 'engagement') {
            const pct = list.length ? Math.round((online.length / list.length) * 100) : 0;
            html = '<div class="list-item"><span>المتصلون الآن</span><b>' + online.length + '</b></div>' +
                   '<div class="list-item"><span>إجمالي الأجهزة</span><b>' + list.length + '</b></div>' +
                   '<div class="list-item"><span>النسبة</span><b>' + pct + '%</b></div>';
          } else if (!list.length) {
            html = '<div class="empty">لا توجد أجهزة مربوطة</div>';
          } else {
            html = list.map((d) =>
              '<div class="list-item"><span>' + esc(d.label || d.hostname || d.device_id) + '</span>' +
              '<span class="badge ' + (d.online ? 'green' : 'gray') + '">' + (d.online ? 'متصل' : 'غير متصل') + '</span></div>'
            ).join('');
          }
        } else if (key === 'orders') {
          const r = await api.getDashboardStats();
          const n = (r && r.stats && r.stats.orders) ? r.stats.orders.value : 0;
          html = '<div class="list-item"><span>أوامر معلّقة غير مؤكَّدة</span><b>' + n + '</b></div>' +
                 '<div class="hint">أوامر القفل/الفتح التي لم يؤكّدها الجهاز بعد.</div>';
        } else if (key === 'allowed' || key === 'blocked') {
          const sites = key === 'allowed' ? await api.getAllowedSites() : await api.getBlockedSites();
          html = sites.length
            ? sites.map((x) => '<div class="list-item"><span class="mono">' + esc(x) + '</span></div>').join('')
            : '<div class="empty">القائمة فارغة</div>';
        } else if (key === 'lan') {
          const devices = (await api.getDevices()) || [];
          html = devices.length
            ? devices.map((d) =>
                '<div class="list-item"><span>' + esc(d.hostname || d.device_id) + '</span>' +
                '<span class="badge ' + (d.online ? 'green' : 'gray') + '">' + (d.online ? 'متصل' : 'غير متصل') + '</span></div>'
              ).join('')
            : '<div class="empty">لا توجد أجهزة محلية</div>';
        }
      } catch (e) {
        html = '<div class="empty">تعذر جلب التفاصيل</div>';
      }
      body.innerHTML = html || '<div class="empty">لا توجد تفاصيل</div>';
    }

    document.addEventListener('click', (e) => {
      const c = e.target.closest('[data-kpi]');
      if (c) { openKpi(c.dataset.kpi); }
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target && e.target.dataset && e.target.dataset.kpi) {
        openKpi(e.target.dataset.kpi);
      }
    });
    $('kpiModalClose').addEventListener('click', () => $('kpiModal').classList.remove('show'));
    $('kpiModal').addEventListener('click', (e) => {
      if (e.target.id === 'kpiModal') $('kpiModal').classList.remove('show');
    });

    /* ---------- Dashboard KPIs ---------- */
    function kpiNumber(n) {
      const v = Number(n || 0);
      return v.toLocaleString('en-US', { maximumFractionDigits: 1 });
    }
    function setBadge(id, growth) {
      const el = $(id);
      if (!el) return;
      const g = Number(growth || 0);
      el.textContent = (g >= 0 ? '+' : '') + g.toFixed(1) + '%';
      el.classList.remove('up', 'down');
      el.classList.add(g >= 0 ? 'up' : 'down');
    }
    async function loadKpis() {
      if (!api.getDashboardStats) return;
      let stats = null;
      try {
        const r = await api.getDashboardStats();
        stats = r && r.stats;
      } catch (e) { stats = null; }
      if (!stats) return;
      if (stats.users) { $('kpiUsers').textContent = kpiNumber(stats.users.value); setBadge('kpiUsersBadge', stats.users.growth); }
      if (stats.profit) { $('kpiProfit').textContent = kpiNumber(stats.profit.value); setBadge('kpiProfitBadge', stats.profit.growth); }
      if (stats.orders) { $('kpiOrders').textContent = kpiNumber(stats.orders.value); setBadge('kpiOrdersBadge', stats.orders.growth); }
      if (stats.engagement) { $('kpiEngagement').textContent = kpiNumber(stats.engagement.value) + '%'; setBadge('kpiEngagementBadge', stats.engagement.growth); }
    }

    /* ---------- Groups ---------- */
    let groupsCache = [];

    const SPEED_PRESETS = [
      [0, 'بدون حد'],
      [512, '512 Kbps'],
      [1024, '1 Mbps'],
      [2048, '2 Mbps'],
      [4096, '4 Mbps'],
      [8192, '8 Mbps'],
      [16384, '16 Mbps'],
      [32768, '32 Mbps'],
      [51200, '50 Mbps']
    ];
    function sitesCell(sites, denied) {
      const list = Array.isArray(sites) ? sites.filter(Boolean) : [];
      const blocked = Array.isArray(denied) ? denied.filter(Boolean) : [];
      let html = '';
      if (!list.length) {
        html = '<span style="color:#94a3b8;font-size:12px;">—</span>';
      } else {
        const shown = list.slice(0, 2).join(', ');
        const more = list.length > 2 ? ' +' + (list.length - 2) : '';
        html = '<span class="mono" style="font-size:11.5px;" title="' + esc(list.join('\n')) + '">' + esc(shown + more) + '</span>';
      }
      if (blocked.length) {
        html += '<div class="mono" style="color:#b91c1c;font-size:11px;margin-top:4px;" title="' +
          esc('نطاقات ممنوعة تحتاج السماح:\n' + blocked.join('\n')) + '">' +
          esc('ممنوع: ' + blocked.slice(0, 2).join(', ') + (blocked.length > 2 ? ' +' + (blocked.length - 2) : '')) +
          '</div>';
      }
      return html;
    }

    function speedOptions(current) {
      const cur = Number(current || 0);
      return SPEED_PRESETS.map(function (p) {
        return '<option value="' + p[0] + '"' + (p[0] === cur ? ' selected' : '') + '>' + p[1] + '</option>';
      }).join('');
    }

    function linesToArr(v) {
      return v.split('\n').map((x) => x.trim()).filter(Boolean);
    }

    function groupCard(g) {
      const allowed = (g.allowed || []).join('\n');
      const blocked = (g.blocked || []).join('\n');
      return '<div class="card" style="margin-bottom:16px;">' +
        '<div class="row" style="margin-bottom:12px;">' +
          '<input class="input" data-g-name="' + esc(g.id) + '" value="' + esc(g.name) + '">' +
          '<select class="input" data-g-mode="' + esc(g.id) + '" style="max-width:190px;">' +
            '<option value="whitelist"' + (g.mode === 'whitelist' ? ' selected' : '') + '>Whitelist</option>' +
            '<option value="blacklist"' + (g.mode === 'blacklist' ? ' selected' : '') + '>Blacklist</option>' +
          '</select>' +
          '<span class="badge violet">' + (g.devices || 0) + ' جهاز</span>' +
        '</div>' +
        '<div class="grid cols-2">' +
          '<div class="field"><span class="label">المواقع المسموحة (سطر لكل موقع)</span>' +
            '<textarea class="input mono" rows="7" dir="ltr" data-g-allowed="' + esc(g.id) + '">' + esc(allowed) + '</textarea></div>' +
          '<div class="field"><span class="label">المواقع المقفولة (سطر لكل موقع)</span>' +
            '<textarea class="input mono" rows="7" dir="ltr" data-g-blocked="' + esc(g.id) + '">' + esc(blocked) + '</textarea></div>' +
        '</div>' +
        '<div class="hero-actions" style="margin-top:4px;">' +
          '<button class="btn btn-primary btn-sm" data-save-group="' + esc(g.id) + '">حفظ</button>' +
          '<button class="btn btn-danger btn-sm" data-grp-cmd="block" data-id="' + esc(g.id) + '">قفل كل المجموعة</button>' +
          '<button class="btn btn-success btn-sm" data-grp-cmd="unblock" data-id="' + esc(g.id) + '">فتح كل المجموعة</button>' +
          '<button class="btn btn-ghost btn-sm" data-del-group="' + esc(g.id) + '">حذف</button>' +
        '</div>' +
      '</div>';
    }

    async function loadGroups() {
      if (!api.getRelayGroups) return;
      try {
        const r = await api.getRelayGroups();
        groupsCache = (r && r.groups) || [];
      } catch (e) { groupsCache = []; }
      $('groupsList').innerHTML = groupsCache.length
        ? groupsCache.map(groupCard).join('')
        : '<div class="empty">لا توجد مجموعات بعد. أنشئ مجموعة وابدأ بتعيين الأجهزة إليها.</div>';
    }

    $('createGroupBtn').addEventListener('click', async () => {
      const name = $('newGroupName').value.trim();
      if (!name) { toast('اكتب اسم المجموعة', 'error'); return; }
      try {
        await api.createRelayGroup(name, $('newGroupMode').value);
        $('newGroupName').value = '';
        await loadGroups();
        toast('تم إنشاء المجموعة');
      } catch (e) { toast(e.message || 'فشل الإنشاء', 'error'); }
    });

    document.addEventListener('click', async (e) => {
      const save = e.target.closest('[data-save-group]');
      if (save) {
        const id = save.dataset.saveGroup;
        const name = document.querySelector('[data-g-name="' + id + '"]').value.trim();
        const mode = document.querySelector('[data-g-mode="' + id + '"]').value;
        const allowed = linesToArr(document.querySelector('[data-g-allowed="' + id + '"]').value);
        const blocked = linesToArr(document.querySelector('[data-g-blocked="' + id + '"]').value);
        try {
          await api.updateRelayGroup(id, name, mode, allowed, blocked);
          loadGroups(); toast('تم حفظ المجموعة');
        } catch (err) { toast(err.message || 'فشل الحفظ', 'error'); }
        return;
      }
      const del = e.target.closest('[data-del-group]');
      if (del) {
        if (!confirm('حذف المجموعة؟ الأجهزة داخلها ستعود للمجموعة الافتراضية.')) return;
        try { await api.deleteRelayGroup(del.dataset.delGroup); await loadGroups(); await loadRelayDevices(); toast('تم الحذف'); }
        catch (err) { toast(err.message || 'فشل الحذف', 'error'); }
        return;
      }
      const thr = e.target.closest('[data-throttle-apply]');
      if (thr) {
        const id = thr.dataset.throttleApply;
        const isLan = thr.dataset.transport === 'lan';
        const input = document.querySelector('[data-throttle-input="' + id + '"]');
        const raw = input ? input.value : '0';
        const kbps = parseInt(raw, 10);
        if (isNaN(kbps) || kbps < 0) { toast('قيمة غير صالحة', 'error'); return; }
        try {
          const r = isLan
            ? await api.sendDeviceCommand(id, 'throttle:' + kbps, currentAdminUser, currentAdminRole)
            : await api.sendRelayCommand(id, 'throttle:' + kbps, currentAdminUser, currentAdminRole);
          if (r && r.success !== false) {
            toast(kbps > 0 ? ('تم إرسال حد ' + kbps + 'Kbps') : 'تم إلغاء الحد');
            if (thr.blur) thr.blur();
            setTimeout(isLan ? loadDevices : loadRelayDevices, 800);
          } else {
            toast((r && r.error) || 'فشل إرسال الأمر', 'error');
          }
        } catch (err) { toast(err.message || 'فشل', 'error'); }
        return;
      }
      const rdp = e.target.closest('[data-rdpass-device]');
      if (rdp) {
        const pw = prompt('كلمة السر (Unattended) لهذا الجهاز (اتركه فارغًا للإبقاء على الافتراضي):', rdp.dataset.currentRdpass || '');
        if (pw === null) return;
        try {
          const r = await api.setDeviceRustdeskPassword(rdp.dataset.rdpassDevice, pw);
          if (r && r.success !== false) toast('تم تعيين كلمة السر');
          else toast((r && r.error) || 'فشل التعيين', 'error');
        } catch (err) { toast(err.message || 'فشل', 'error'); }
        setTimeout(rdp.dataset.transport === 'lan' ? loadDevices : loadRelayDevices, 800);
        return;
      }
      const sup = e.target.closest('[data-support-device]');
      if (sup) {
        try {
          const r = await api.openSupportSession(sup.dataset.supportDevice);
          if (r && r.success !== false) toast('تم فتح جلسة RustDesk');
          else toast((r && r.error) || 'فشل فتح الجلسة', 'error');
        } catch (err) { toast(err.message || 'فشل فتح الجلسة', 'error'); }
        return;
      }
      const scr = e.target.closest('[data-screen-device]');
      if (scr) {
        openScreen(scr.dataset.screenDevice, scr.dataset.deviceName || '');
        return;
      }
      const delDev = e.target.closest('[data-delete-device]');
      if (delDev) {
        const isLan = delDev.dataset.transport === 'lan';
        if (!confirm('حذف الجهاز "' + (delDev.dataset.deviceName || '') + '" من القائمة؟' + (isLan ? ' سيختفي حتى يتصل من جديد.' : ' لن يستطيع الاتصال بعد ذلك بدون رمز ربط جديد.'))) return;
        try {
          const r = await api.deleteRelayDevice(delDev.dataset.deleteDevice);
          if (r && r.success !== false) { toast('تم حذف الجهاز'); if (isLan) loadDevices(); else { loadRelayDevices(); loadGroups(); } }
          else toast((r && r.error) || 'فشل الحذف', 'error');
        } catch (err) { toast(err.message || 'فشل الحذف', 'error'); }
        return;
      }
      const rn = e.target.closest('[data-rename-device]');
      if (rn) {
        const name = prompt('اسم الجهاز (الموظف):', rn.dataset.currentName || '');
        if (name === null) return;
        try {
          const r = await api.renameRelayDevice(rn.dataset.renameDevice, name.trim());
          if (r && r.success !== false) { toast('تم تعديل الاسم'); setTimeout(rn.dataset.transport === 'lan' ? loadDevices : loadRelayDevices, 800); }
          else toast((r && r.error) || 'فشل تعديل الاسم', 'error');
        } catch (err) { toast(err.message || 'فشل تعديل الاسم', 'error'); }
        return;
      }
      const gc = e.target.closest('[data-grp-cmd]');
      if (gc) {
        try {
          const r = await api.sendGroupCommand(gc.dataset.id, gc.dataset.grpCmd, currentAdminUser, currentAdminRole);
          if (r && r.success) toast('تم إرسال أمر المجموعة'); else toast((r && r.error) || 'فشل', 'error');
        } catch (err) { toast(err.message || 'فشل', 'error'); }
        return;
      }
    });

    $('syncPolicyBtn').addEventListener('click', async () => {
      try {
        const r = await api.syncPolicy();
        if (r && r.success) toast('تمت مزامنة القوائم مع الـ Relay');
        else toast((r && r.error) || 'فشلت المزامنة', 'error');
      } catch (e) { toast(e.message || 'فشلت المزامنة', 'error'); }
    });

    /* ---------- Init ---------- */
    (async () => {
      await loadStatus();
      await loadSites();
      await loadConfig();
      await loadServerInfo();
      await loadDevices();
      devicesTimer = setInterval(loadDevices, 4000);
      await loadRelayConfig();
      loadRelayDevices();
      loadAlerts();
      loadKpis();
      loadAdminUsers();
    })();
  