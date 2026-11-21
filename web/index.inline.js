(function () {
  const api = window.electronAPI;
  const $ = (id) => document.getElementById(id);

  let isBlocked = false;
  let selectedMode = 'whitelist';
  let devicesTimer = null;
  let relayTimer = null;
  let authToken = (api && api.getAuthToken && api.getAuthToken()) || '';
  let currentAdminUser = '';
  let currentAdminRole = '';
  window.currentAdminUser = '';
  window.currentAdminRole = '';

  const esc = (s) => {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  };
  const TRASH = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 002 2h6a2 2 0 002-2l1-12M9 7V4h6v3"/></svg>';

  function toast(msg, type = 'success') {
    const t = $('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = 'toast ' + type + ' show';
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { t.className = 'toast'; }, 3000);
  }

  /* ---------- Auth & Session ---------- */
  function getTokenPayload(tok = authToken) {
    if (!tok) return null;
    try {
      const parts = tok.split('.');
      if (parts.length < 2) return null;
      const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
      const json = decodeURIComponent(escape(atob(padded)));
      return JSON.parse(json);
    } catch (e) {
      return null;
    }
  }

  function isTokenValid(tok = authToken) {
    const p = getTokenPayload(tok);
    if (!p || !p.sub) return false;
    const now = Math.floor(Date.now() / 1000);
    return !p.exp || p.exp > now;
  }

  function hasSuperAdminAccess() {
    return String(currentAdminRole || '').toLowerCase() === 'super';
  }

  function canManageAdminUsers() {
    return hasSuperAdminAccess() && Boolean((currentAdminUser || '').trim());
  }

  function updateAdminUi() {
    const isSuper = hasSuperAdminAccess();
    const isViewer = String(currentAdminRole || '').toLowerCase() === 'viewer';
    document.querySelectorAll('[data-admin-edit],[data-admin-remove]').forEach((el) => {
      el.style.display = isSuper ? '' : 'none';
    });
    const saveAdminBtn = $('saveAdminBtn');
    if (saveAdminBtn) saveAdminBtn.disabled = !isSuper;

    const badge = $('currentAdminBadge');
    if (badge) {
      if (currentAdminUser) {
        badge.textContent = currentAdminUser + ' · ' + String(currentAdminRole || 'admin').toUpperCase();
      } else {
        badge.textContent = 'ADMIN';
      }
    }
    const logoutBtn = $('logoutBtn');
    if (logoutBtn) {
      logoutBtn.style.display = currentAdminUser ? '' : 'none';
    }
    if (isViewer) {
      $('blockBtn').disabled = true;
      $('unblockBtn').disabled = true;
    }
  }

  function syncSessionIdentity(username, role, token) {
    authToken = token || '';
    currentAdminUser = username || '';
    currentAdminRole = role || '';
    window.currentAdminUser = currentAdminUser;
    window.currentAdminRole = currentAdminRole;
    if (api && api.setAuthToken) api.setAuthToken(authToken);
    updateAdminUi();
  }

  function showLoginModal(errMsg = '') {
    const modal = $('loginModal');
    if (!modal) return;
    const errEl = $('loginError');
    if (errEl) {
      errEl.textContent = errMsg;
      errEl.style.display = errMsg ? 'block' : 'none';
    }
    modal.classList.add('show');
    document.body.classList.add('auth-locked');
    setTimeout(() => {
      const u = $('loginUser');
      if (u) u.focus();
    }, 60);
  }

  function hideLoginModal() {
    const modal = $('loginModal');
    if (modal) modal.classList.remove('show');
    document.body.classList.remove('auth-locked');
    const errEl = $('loginError');
    if (errEl) {
      errEl.textContent = '';
      errEl.style.display = 'none';
    }
  }

  async function submitModalLogin() {
    const username = ($('loginUser') && $('loginUser').value || '').trim();
    const password = ($('loginPass') && $('loginPass').value) || '';
    if (!username || !password) {
      showLoginModal('أدخل اسم المستخدم وكلمة المرور');
      return;
    }
    const btn = $('loginBtn');
    const orig = btn ? btn.innerHTML : 'دخول';
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> جاري التحقق...';
    }
    try {
      const res = await api.adminLogin(username, password);
      if (res && res.success) {
        syncSessionIdentity(res.username || username, res.role || 'admin', res.token || '');
        if ($('loginPass')) $('loginPass').value = '';
        hideLoginModal();
        toast('مرحباً ' + (res.username || username));
        await bootDashboardData();
      } else {
        showLoginModal((res && res.error) || 'اسم المستخدم أو كلمة المرور غير صحيحة');
      }
    } catch (e) {
      showLoginModal('حدث خطأ أثناء تسجيل الدخول: ' + (e.message || e));
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = orig;
      }
    }
  }

  // الفورم يستقبل Enter وزر "دخول" معاً عبر submit (بدون إرسال مزدوج).
  if ($('loginForm')) {
    $('loginForm').addEventListener('submit', (e) => {
      e.preventDefault();
      if (!$('loginBtn').disabled) submitModalLogin();
    });
  }
  if ($('loginPassToggle')) {
    $('loginPassToggle').addEventListener('click', () => {
      const p = $('loginPass');
      const show = p.type === 'password';
      p.type = show ? 'text' : 'password';
      $('loginPassToggle').classList.toggle('on', show);
      $('loginPassToggle').title = show ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور';
      p.focus();
    });
  }

  async function updateAuthServerStatus() {
    const el = $('authServerStatus');
    if (!el) return;
    let ok = false;
    let text = 'السيرفر المحلي غير متاح';
    try {
      const info = api.getServerInfo ? await api.getServerInfo() : null;
      if (info && Number(info.port) > 0) {
        ok = true;
        text = 'السيرفر المحلي يعمل · ' + (info.ip || '') + ':' + info.port;
      }
    } catch (e) {}
    el.classList.toggle('ok', ok);
    el.lastElementChild.textContent = text;
  }
  updateAuthServerStatus();

  if ($('logoutBtn')) {
    $('logoutBtn').addEventListener('click', () => {
      syncSessionIdentity('', '', '');
      if (devicesTimer) { clearInterval(devicesTimer); devicesTimer = null; }
      stopRelayTimer();
      stopBlockedAttempts();
      showLoginModal();
      toast('تم تسجيل الخروج');
    });
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
      if (item.dataset.view === 'devices') { loadServerInfo(); loadDevices(); }
      if (item.dataset.view === 'admins') loadAdminUsers();
      if (item.dataset.view === 'relay') { loadRelayConfig(); loadRelayDevices(); startRelayTimer(); }
      if (item.dataset.view === 'alerts') { loadAlerts(); loadAudit(); startRelayTimer(); }
      else if (item.dataset.view === 'archive') { loadArchiveFiles(); startRelayTimer(); }
      else if (item.dataset.view === 'dashboard') { startRelayTimer(); loadKpis(); }
      else if (item.dataset.view !== 'relay') { stopRelayTimer(); }
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
    const isViewer = String(currentAdminRole || '').toLowerCase() === 'viewer';
    $('blockBtn').disabled = isViewer || isBlocked;
    $('unblockBtn').disabled = isViewer || !isBlocked;
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
      if (r && r.success) toast(okMsg);
      else toast((r && r.error) || failMsg, 'error');
    } catch (e) {
      toast('حدث خطأ: ' + (e && e.message ? e.message : e), 'error');
    }
    btn.innerHTML = original;
    await loadStatus();
  }

  $('blockBtn').addEventListener('click', () =>
    runAction($('blockBtn'), 'جاري القفل...', () => api.blockInternet(currentAdminUser, currentAdminRole), 'تم قفل الإنترنت', 'فشل القفل')
  );

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
    renderPolicyBar(allowed.length, blocked.length);
  }

  /* ---------- مؤشرات الرئيسية (SVG بدون مكتبات) ---------- */
  const RING_LEN = 2 * Math.PI * 50;
  let policyCounts = { allowed: 0, blocked: 0 };

  function setRing(barId, pct) {
    const bar = $(barId);
    if (!bar) return;
    bar.style.strokeDasharray = RING_LEN.toFixed(1);
    bar.style.strokeDashoffset = (RING_LEN * (1 - Math.max(0, Math.min(1, pct)))).toFixed(1);
  }

  function renderDashRings(total, online, blocked) {
    if (!$('ringOnlineBar')) return;
    const onPct = total ? online / total : 0;
    const blPct = total ? blocked / total : 0;
    setRing('ringOnlineBar', onPct);
    setRing('ringBlockedBar', blPct);
    $('ringOnlinePct').textContent = Math.round(onPct * 100) + '%';
    $('ringBlockedPct').textContent = Math.round(blPct * 100) + '%';
    $('ringOnlineCount').textContent = online;
    $('ringOnlineTotal').textContent = total;
    $('ringBlockedCount').textContent = blocked;
    $('ringOpenCount').textContent = Math.max(0, total - blocked);
  }

  function renderPolicyBar(allowed, blocked) {
    if (allowed != null) policyCounts = { allowed, blocked };
    if (!$('policyAllowedBar')) return;
    const a = policyCounts.allowed;
    const b = policyCounts.blocked;
    const sum = a + b;
    $('policyAllowedBar').style.width = (sum ? (a / sum) * 100 : 50) + '%';
    $('policyBlockedBar').style.width = (sum ? (b / sum) * 100 : 50) + '%';
    $('policyAllowed').textContent = a;
    $('policyBlocked').textContent = b;
    $('policyModeLabel').textContent = 'الوضع النشط: ' + (selectedMode === 'whitelist' ? 'Whitelist (قائمة بيضاء)' : 'Blacklist (قائمة سوداء)');
  }
  renderDashRings(0, 0, 0);

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
      const r = await fn(v);
      if (r && r.success === false) {
        toast(r.error || 'فشلت الإضافة', 'error');
        return;
      }
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
    if ($('dashModeCard')) $('dashModeCard').textContent = $('dashMode').textContent;
    renderPolicyBar();
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
    const users = (await api.getAdminUsers()) || [];
    const tbody = $('adminsTableBody');
    if (!tbody) return;
    const total = users.length || 0;
    const superCount = users.filter((u) => String(u.role || 'admin') === 'super').length;
    const adminCount = users.filter((u) => String(u.role || 'admin') === 'admin').length;
    $('adminTotalStat').textContent = total;
    $('adminSuperStat').textContent = superCount;
    $('adminNormalStat').textContent = adminCount;
    const canManage = canManageAdminUsers();
    if (!total) {
      tbody.innerHTML = '<tr><td colspan="4"><div class="empty">لا يوجد مديرين مسجلين بعد.</div></td></tr>';
      return;
    }
    tbody.innerHTML = users.map((u) => {
      const role = String(u.role || 'admin');
      const state = role === 'super' ? '<span class="badge violet">Super</span>'
        : role === 'support' ? '<span class="badge gold">Support</span>'
        : role === 'viewer' ? '<span class="badge gray">Viewer</span>'
        : '<span class="badge green">Admin</span>';
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
      tbody.insertAdjacentHTML('beforeend', '<tr><td colspan="4"><div class="hint" style="margin:0;">فقط السوبر أدمن يمكنه إنشاء أو تعديل أو حذف حسابات المديرين.</div></td></tr>');
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
        syncSessionIdentity(r.username || username, String(r.role || 'admin'), r.token || '');
        $('adminLoginResult').innerHTML = '<span class="badge green">تم الدخول</span> المستخدم: <b>' + esc(currentAdminUser) + '</b> · الدور: <b>' + esc(currentAdminRole) + '</b>';
        toast('تم التبديل إلى حساب ' + currentAdminUser);
        await loadAdminUsers();
        await loadStatus();
      } else {
        $('adminLoginResult').innerHTML = '<span class="badge red">فشل</span> ' + esc(r.error || 'اسم المستخدم أو كلمة المرور غير صحيحة');
        toast(r.error || 'فشل الدخول', 'error');
      }
    } catch (err) {
      $('adminLoginResult').textContent = 'حدث خطأ في تسجيل الدخول';
      toast('حدث خطأ: ' + err.message, 'error');
    }
  });

  /* ---------- Logs ---------- */
  async function loadLogs() {
    $('logsBox').textContent = '...';
    const raw = await api.getLogs();
    const logs = typeof raw === 'string' ? raw : (Array.isArray(raw) ? raw.join('\n') : '');
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

  const isTauriRuntime = Boolean(window.__TAURI__) || location.hostname === 'tauri.localhost' || (location.protocol !== 'http:' && location.protocol !== 'https:');
  let serverHttpBase = isTauriRuntime ? 'http://127.0.0.1:8787' : '';

  async function loadServerInfo() {
    if (!api.getServerInfo) return;
    const info = await api.getServerInfo();
    if (info && info.port && isTauriRuntime) {
      serverHttpBase = 'http://127.0.0.1:' + info.port;
    }
    $('serverUrl').textContent = 'http://' + info.ip + ':' + info.port;
    $('serverToken').textContent = info.token;
  }

  /* ---------- Groups & Speed Helpers ---------- */
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
    if (!list.length && !blocked.length) {
      return '<span style="color:#94a3b8;font-size:12px;">—</span>';
    }
    if (list.length) {
      const shown = list.slice(0, 2).join(' · ');
      const more = list.length > 2 ? ' +' + (list.length - 2) : '';
      html += '<span class="badge" style="background:rgba(15,76,129,0.08);color:var(--primary);font-family:ui-monospace,monospace;font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(list.join('\n')) + '">' + esc(shown + more) + '</span>';
    }
    if (blocked.length) {
      const shownB = blocked.slice(0, 2).join(' · ');
      const moreB = blocked.length > 2 ? ' +' + (blocked.length - 2) : '';
      html += '<span class="badge red" style="font-family:ui-monospace,monospace;font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px;margin-inline-start:6px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc('نطاقات ممنوعة تحتاج السماح:\n' + blocked.join('\n')) + '">' + esc('ممنوع: ' + shownB + moreB) + '</span>';
    }
    return html;
  }

  function speedOptions(current) {
    const cur = Number(current || 0);
    return SPEED_PRESETS.map(function (p) {
      return '<option value="' + p[0] + '"' + (p[0] === cur ? ' selected' : '') + '>' + p[1] + '</option>';
    }).join('');
  }

  async function ensureGroupsCache() {
    if (groupsCache.length) return;
    try { const gr = await api.getRelayGroups(); groupsCache = (gr && gr.groups) || []; } catch (e) {}
  }

  function deviceRow(d, prefix) {
    const online = d.online;
    const state = !online ? '<span class="badge gray">غير متصل</span>'
      : d.blocked ? '<span class="badge red">مقفول</span>' : '<span class="badge green">مفتوح</span>';
    let evBadge = '';
    if (d.last_event === 'unblock_password' && d.last_event_at) {
      evBadge = '<span class="badge gold">فتح بكلمة سر · ' + ago(d.last_event_at) + '</span>';
    } else if (d.last_event === 'block_password' && d.last_event_at) {
      evBadge = '<span class="badge violet">قفل يدوي · ' + ago(d.last_event_at) + '</span>';
    }
    const shown = d.label || d.hostname || d.device_id;
    const sub = d.label && d.hostname ? esc(d.hostname) : '';
    const rd = d.rustdesk_id ? esc(d.rustdesk_id) : '';
    const opts = ['<option value="">— افتراضي —</option>'].concat(
      groupsCache.map(function (g) {
        return '<option value="' + esc(g.id) + '"' + (d.group_id === g.id ? ' selected' : '') + '>' + esc(g.name) + '</option>';
      })
    ).join('');
    const groupSel = '<select class="input" style="padding:6px 10px;font-size:12.5px;min-width:130px;" data-dev-group="' + esc(d.device_id) + '" data-transport="' + prefix + '">' + opts + '</select>';
    const controls =
      (online ? '<button class="btn btn-danger btn-sm" data-dev-cmd="block" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '">قفل</button> ' +
                '<button class="btn btn-success btn-sm" data-dev-cmd="unblock" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '">فتح</button> ' +
                '<details class="power-menu"><summary class="btn btn-ghost btn-sm">⏻ الطاقة</summary><div class="power-list">' +
                  '<button type="button" data-dev-cmd="restart" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">⟳ إعادة تشغيل</button>' +
                  '<button type="button" class="danger" data-dev-cmd="shutdown" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">⏻ إيقاف التشغيل</button>' +
                  '<button type="button" data-dev-cmd="cancel_power" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">✕ إلغاء الإيقاف/الريستارت</button>' +
                '</div></details> ' +
                '<button class="btn btn-ghost btn-sm" data-dev-cmd="update_client" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="إرسال وتثبيت أحدث إصدار من الكلاينت عن بُعد بصمت">⬆ تحديث</button> ' : '') +
      '<button class="btn btn-ghost btn-sm" data-rename-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-current-name="' + esc(d.label || '') + '">✎ اسم</button> ' +
      '<button class="btn btn-ghost btn-sm" data-screen-device="' + esc(d.device_id) + '" data-rd-id="' + esc(d.rustdesk_id || '') + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="التقاط صورة للشاشة">🖥 شاشة</button> ' +
      '<button class="btn btn-ghost btn-sm" data-watch-device="' + esc(d.device_id) + '" data-rd-id="' + esc(d.rustdesk_id || '') + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="مشاهدة سريعة للشاشة في بث حي (مشاهدة فقط بدون تحكم)">👁 مشاهدة</button> ' +
      '<button class="btn btn-ghost btn-sm" data-camera-device="' + esc(d.device_id) + '" data-rd-id="' + esc(d.rustdesk_id || '') + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="مشاهدة بث الكاميرا الحي من جهاز الموظف (مشاهدة فقط بدون تحكم)">📷 كاميرا</button> ' +
      (d.rustdesk_id
        ? '<button class="btn btn-ghost btn-sm" data-support-device="' + esc(d.rustdesk_id) + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="دعم فني كامل مع التحكم بالماوس والكيبورد">🛠 دعم</button> ' +
          '<button class="btn btn-ghost btn-sm" data-rdpass-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-current-rdpass="' + esc(d.rustdesk_password || '') + '">🔑 كلمة</button> '
        : '<a class="btn btn-ghost btn-sm" href="https://rustdesk.com" target="_blank" rel="noopener" style="text-decoration:none;">⬇ RustDesk</a> ') +
      '<button class="btn btn-ghost btn-sm btn-delete" data-delete-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">🗑 حذف</button>';

    const searchText = [shown, d.hostname, d.ip, d.rustdesk_id, d.device_id].filter(Boolean).join(' ').toLowerCase();
    return '<div class="device-card' + (online ? (d.blocked ? ' is-blocked' : ' is-open') : ' is-offline') + '" data-device-id="' + esc(d.device_id) + '"' +
      ' data-online="' + (online ? '1' : '0') + '" data-blocked="' + (d.blocked ? '1' : '0') + '"' +
      ' data-group="' + esc(d.group_id || '') + '" data-q="' + esc(searchText) + '">' +
      '<div class="device-card-header">' +
        '<div class="device-info-main">' +
          '<div class="device-avatar ' + (online ? 'online' : 'offline') + '">' +
            '<svg class="icon" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>' +
          '</div>' +
          '<div class="device-titles">' +
            '<div class="device-name-row">' +
              '<span class="device-name">' + esc(shown) + '</span>' +
              '<span class="device-status-badge">' + state + '</span>' +
              evBadge +
            '</div>' +
            '<div class="device-meta-row">' +
              '<span class="device-meta-pill" style="background:' + (prefix === 'lan' ? 'rgba(14,165,233,0.12);color:#0284c7;' : 'rgba(139,92,246,0.12);color:#7c3aed;') + 'font-weight:700;">' + (prefix === 'lan' ? 'LAN محلي' : 'Relay سحابي') + '</span>' +
              (sub ? '<span class="device-hostname-text">' + sub + '</span>' : '') +
              '<span class="device-meta-pill ip">' + esc(d.ip || '—') + '</span>' +
              '<span class="device-meta-pill time">' + (d.last_seen ? ago(d.last_seen) : '-') + '</span>' +
              (rd ? '<span class="device-meta-pill rd">RustDesk: ' + rd + '</span>' : '') +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="device-actions-toolbar">' +
          controls +
        '</div>' +
      '</div>' +
      '<div class="device-card-body">' +
        '<div class="device-config-item">' +
          '<span class="device-config-label">المجموعة:</span>' +
          groupSel +
        '</div>' +
        '<div class="device-config-item">' +
          '<span class="device-config-label">السرعة:</span>' +
          '<div class="device-throttle-wrap">' +
            '<select class="input" data-throttle-input="' + esc(d.device_id) + '" data-transport="' + prefix + '" style="min-width:115px;padding:6px 10px;font-size:12.5px;">' +
              speedOptions(d.throttle_kbps) +
            '</select>' +
            '<button class="btn btn-primary btn-sm" data-throttle-apply="' + esc(d.device_id) + '" data-transport="' + prefix + '">تعيين</button>' +
          '</div>' +
        '</div>' +
        '<div class="device-config-item device-sites-item">' +
          '<span class="device-config-label">المواقع:</span>' +
          '<div class="device-sites-content">' +
            sitesCell(d.sites, d.denied) +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  let lanTableHover = false;
  document.addEventListener('mouseover', (e) => {
    if (e.target.closest && e.target.closest('#view-devices .devices-card-container')) lanTableHover = true;
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.closest && e.target.closest('#view-devices .devices-card-container')) lanTableHover = false;
  });

  async function loadDevices() {
    if (!api.getDevices) return;
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
    applyDeviceFilter('devicesBody');
  }

  /* ---------- بحث وفلترة الأجهزة (LAN و Relay) ---------- */
  const deviceFilters = {};
  const FILTER_PILLS = [
    ['all', 'الكل'], ['online', 'متصل'], ['offline', 'غير متصل'], ['blocked', 'مقفول'], ['open', 'مفتوح'],
  ];

  function mountDeviceToolbar(containerId) {
    const box = $(containerId);
    if (!box || $(containerId + 'Toolbar')) return;
    deviceFilters[containerId] = { q: '', status: 'all', group: '' };
    const bar = document.createElement('div');
    bar.className = 'dev-toolbar';
    bar.id = containerId + 'Toolbar';
    bar.innerHTML =
      '<div class="dev-search">' +
        '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>' +
        '<input type="search" placeholder="بحث بالاسم أو IP أو رقم RustDesk..." data-dev-search>' +
      '</div>' +
      '<div class="dev-pills">' +
        FILTER_PILLS.map((p) => '<button type="button" class="dev-pill' + (p[0] === 'all' ? ' active' : '') + '" data-dev-filter="' + p[0] + '">' + p[1] + ' <b>0</b></button>').join('') +
      '</div>' +
      '<select class="input dev-group-filter" data-dev-group-filter><option value="">كل المجموعات</option></select>';
    box.parentNode.insertBefore(bar, box);

    const nomatch = document.createElement('div');
    nomatch.className = 'empty dev-nomatch';
    nomatch.id = containerId + 'NoMatch';
    nomatch.style.display = 'none';
    nomatch.textContent = 'لا توجد أجهزة مطابقة للبحث أو الفلتر الحالي';
    box.parentNode.insertBefore(nomatch, box.nextSibling);

    let t = null;
    bar.querySelector('[data-dev-search]').addEventListener('input', (e) => {
      clearTimeout(t);
      t = setTimeout(() => { deviceFilters[containerId].q = e.target.value.trim().toLowerCase(); applyDeviceFilter(containerId); }, 150);
    });
    bar.querySelectorAll('[data-dev-filter]').forEach((b) => b.addEventListener('click', () => {
      bar.querySelectorAll('[data-dev-filter]').forEach((x) => x.classList.toggle('active', x === b));
      deviceFilters[containerId].status = b.dataset.devFilter;
      applyDeviceFilter(containerId);
    }));
    bar.querySelector('[data-dev-group-filter]').addEventListener('change', (e) => {
      deviceFilters[containerId].group = e.target.value;
      applyDeviceFilter(containerId);
    });
  }

  function applyDeviceFilter(containerId) {
    const box = $(containerId);
    const f = deviceFilters[containerId];
    if (!box || !f) return;
    const cards = Array.from(box.querySelectorAll('.device-card'));
    const counts = { all: 0, online: 0, offline: 0, blocked: 0, open: 0 };
    let visible = 0;
    cards.forEach((c) => {
      const on = c.dataset.online === '1';
      const bl = c.dataset.blocked === '1';
      const inGroup = !f.group || c.dataset.group === f.group;
      const inSearch = !f.q || (c.dataset.q || '').includes(f.q);
      if (inGroup && inSearch) {
        counts.all++;
        counts[on ? 'online' : 'offline']++;
        if (on) counts[bl ? 'blocked' : 'open']++;
      }
      const statusOk = f.status === 'all' || (f.status === 'online' && on) || (f.status === 'offline' && !on) ||
        (f.status === 'blocked' && on && bl) || (f.status === 'open' && on && !bl);
      const show = inGroup && inSearch && statusOk;
      c.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    const bar = $(containerId + 'Toolbar');
    if (bar) {
      bar.querySelectorAll('[data-dev-filter]').forEach((b) => { b.querySelector('b').textContent = counts[b.dataset.devFilter]; });
      const sel = bar.querySelector('[data-dev-group-filter]');
      if (sel && document.activeElement !== sel) {
        const cur = f.group;
        sel.innerHTML = '<option value="">كل المجموعات</option>' + groupsCache.map((g) =>
          '<option value="' + esc(g.id) + '"' + (g.id === cur ? ' selected' : '') + '>' + esc(g.name) + '</option>').join('');
        sel.style.display = groupsCache.length ? '' : 'none';
      }
    }
    const nm = $(containerId + 'NoMatch');
    if (nm) nm.style.display = cards.length && !visible ? 'block' : 'none';
  }

  mountDeviceToolbar('devicesBody');
  mountDeviceToolbar('relayDevicesBody');

  document.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-dev-cmd]');
    if (!b) return;
    const cmd = b.dataset.devCmd;
    const name = b.dataset.deviceName || 'الجهاز';
    const POWER_MSG = {
      restart: 'إعادة تشغيل "' + name + '"؟\nسيظهر للموظف تحذير، ويُعاد التشغيل بعد 60 ثانية (يمكنك الإلغاء خلالها).',
      shutdown: 'إيقاف تشغيل "' + name + '"؟\nسيظهر للموظف تحذير، ويُطفأ الجهاز بعد 60 ثانية (يمكنك الإلغاء خلالها).\nتنبيه: لن تستطيع تشغيله مرة أخرى عن بُعد.',
      update_client: 'إرسال تحديث الكلاينت الصامت إلى "' + name + '"؟\nسيتم تحميل أحدث إصدار وتثبيته في الخلفية تلقائياً بدون ظهور أي نافذة للموظف.',
    };
    if (POWER_MSG[cmd] && !confirm(POWER_MSG[cmd])) return;
    const menu = b.closest('details.power-menu');
    if (menu) menu.open = false;
    try {
      const isRelay = b.dataset.transport === 'relay';
      const r = isRelay
        ? await api.sendRelayCommand(b.dataset.id, cmd, currentAdminUser, currentAdminRole)
        : await api.sendDeviceCommand(b.dataset.id, cmd, currentAdminUser, currentAdminRole);
      if (r && r.success === false) { toast(r.error || 'فشل إرسال الأمر', 'error'); return; }
      const DONE = {
        restart: 'تم إرسال أمر إعادة التشغيل — يُنفَّذ بعد 60 ثانية',
        shutdown: 'تم إرسال أمر إيقاف التشغيل — يُنفَّذ بعد 60 ثانية',
        cancel_power: 'تم إرسال أمر الإلغاء',
        update_client: 'تم إرسال أمر التحديث الصامت — يُثبَّت ويعود للاتصال خلال دقيقة',
      };
      toast(DONE[cmd] || ('تم إرسال الأمر' + (isRelay ? ' للـ Relay' : '، يصل خلال ثوانٍ')));
      if ($('view-groups') && $('view-groups').classList.contains('active')) {
        setTimeout(loadGroups, 800);
      }
    } catch (err) { toast(err.message || 'فشل إرسال الأمر', 'error'); }
  });

  // إغلاق قائمة الطاقة عند الضغط خارجها
  document.addEventListener('click', (e) => {
    document.querySelectorAll('details.power-menu[open]').forEach((m) => { if (!m.contains(e.target)) m.open = false; });
  });

  if ($('refreshLanBtn')) $('refreshLanBtn').addEventListener('click', loadDevices);

  $('blockAllBtn').addEventListener('click', async () => {
    const r = await api.sendDeviceCommand('*', 'block', currentAdminUser, currentAdminRole);
    if (r && r.success === false) toast(r.error || 'فشل إرسال الأمر', 'error');
    else toast('تم إرسال أمر القفل لكل الأجهزة');
  });
  $('unblockAllBtn').addEventListener('click', async () => {
    const r = await api.sendDeviceCommand('*', 'unblock', currentAdminUser, currentAdminRole);
    if (r && r.success === false) toast(r.error || 'فشل إرسال الأمر', 'error');
    else toast('تم إرسال أمر الفتح لكل الأجهزة');
  });
  if ($('updateAllLanBtn')) {
    $('updateAllLanBtn').addEventListener('click', async () => {
      if (!confirm('إرسال وتثبيت أحدث نسخة من الكلاينت عن بُعد بصمت لكل الأجهزة المتصلة على الشبكة المحلية؟')) return;
      const r = await api.sendDeviceCommand('*', 'update_client', currentAdminUser, currentAdminRole);
      if (r && r.success === false) toast(r.error || 'فشل إرسال الأمر', 'error');
      else toast('تم إرسال أمر التحديث الصامت لكل الأجهزة المتصلة');
    });
  }

  // نفس الإجراءات الجماعية لأجهزة الـ Relay (خارج الشبكة المحلية)
  [['relayBlockAllBtn', 'block', 'قفل كل أجهزة الـ Relay؟', 'تم إرسال أمر القفل لكل أجهزة الـ Relay'],
   ['relayUnblockAllBtn', 'unblock', 'فتح الإنترنت لكل أجهزة الـ Relay؟', 'تم إرسال أمر الفتح لكل أجهزة الـ Relay'],
   ['relayUpdateAllBtn', 'update_client', 'إرسال وتثبيت أحدث نسخة من الكلاينت بصمت لكل أجهزة الـ Relay؟', 'تم إرسال أمر التحديث الصامت لكل أجهزة الـ Relay']]
    .forEach(([id, cmd, ask, done]) => {
      if (!$(id)) return;
      $(id).addEventListener('click', async () => {
        if (!confirm(ask)) return;
        try {
          const r = await api.sendRelayCommand('*', cmd, currentAdminUser, currentAdminRole);
          if (r && r.success === false) toast(r.error || 'فشل إرسال الأمر', 'error');
          else { toast(done); setTimeout(loadRelayDevices, 800); }
        } catch (err) { toast(err.message || 'فشل إرسال الأمر', 'error'); }
      });
    });

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
      if (r && r.success === false) { toast(r.error || 'فشل إنشاء الرمز', 'error'); return; }
      $('pairToken').textContent = r.token || '';
      $('pairResultWrap').style.display = 'block';
      toast('تم إنشاء رمز الربط');
    } catch (e) { toast(e.message || 'فشل إنشاء الرمز', 'error'); }
  });

  let relayTableHover = false;
  document.addEventListener('mouseover', (e) => {
    if (e.target.closest && e.target.closest('#view-relay .devices-card-container')) relayTableHover = true;
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.closest && e.target.closest('#view-relay .devices-card-container')) relayTableHover = false;
  });

  let relayDevicesBusy = false;
  let lastRelayDevicesSnapshot = [];
  async function loadRelayDevices() {
    if (!api.getRelayDevices || relayDevicesBusy) return;
    const ae = document.activeElement;
    if (ae && ae.tagName === 'SELECT' && ae.closest('#view-relay')) return;
    if (relayTableHover) return;
    relayDevicesBusy = true;
    try {
      if (!groupsCache.length) {
        try { const gr = await api.getRelayGroups(); groupsCache = (gr && gr.groups) || []; } catch (e) {}
      }
      let devices = [];
      try {
        const r = await api.getRelayDevices();
        devices = Array.isArray(r) ? r : ((r && r.devices) || []);
      } catch (e) { devices = []; }
      lastRelayDevicesSnapshot = devices;
      $('relayDevicesEmpty').style.display = devices.length ? 'none' : 'block';
      const rc = $('navRelayCount');
      if (rc) rc.textContent = devices.length;
      const rs = $('kpiRelay');
      if (rs) rs.textContent = devices.filter(function (x) { return x.online; }).length;
      $('relayDevicesBody').innerHTML = devices.map((d) => deviceRow(d, 'relay')).join('');
      applyDeviceFilter('relayDevicesBody');
    } finally {
      relayDevicesBusy = false;
    }
  }

  document.addEventListener('change', async (e) => {
    const sel = e.target.closest('[data-dev-group]');
    if (!sel) return;
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

  const SEV_COLOR = { low: '#64748b', medium: '#a16207', high: '#b91c1c', critical: '#7f1d1d' };
  const SEV_BG = { low: 'rgba(100,116,139,.12)', medium: 'rgba(199,154,43,.14)', high: 'rgba(220,38,38,.12)', critical: 'rgba(127,29,29,.18)' };
  const TYPE_LABEL = { tamper: 'تلاعب', exfil: 'سرقة بيانات / رفع ملفات', usb: 'USB', auth_fail: 'فشل مصادقة', bypass: 'تجاوز' };
  const alertShotCache = {};
  const alertCamCache = {};

  function parseAlertMeta(raw) {
    if (!raw) return null;
    if (typeof raw === 'object') return raw;
    if (typeof raw === 'string' && raw.trim().startsWith('{')) {
      try { return JSON.parse(raw); } catch (e) {}
    }
    return null;
  }

  async function loadAlerts() {
    if (!api.getRelayAlerts) return;
    const type = $('alertFilter').value;
    const acked = $('alertAckFilter').value;
    let alerts = [];
    try {
      const r = await api.getRelayAlerts(type || null, acked);
      alerts = Array.isArray(r) ? r : ((r && r.alerts) || []);
      const n = (r && r.unacked) || 0;
      const badge = $('navAlertCount');
      if (badge) badge.textContent = n;
    } catch (e) { alerts = []; }
    const shotKeys = Object.keys(alertShotCache);
    if (shotKeys.length > 40) shotKeys.slice(0, shotKeys.length - 40).forEach((k) => { delete alertShotCache[k]; });
    const camKeys = Object.keys(alertCamCache);
    if (camKeys.length > 40) camKeys.slice(0, camKeys.length - 40).forEach((k) => { delete alertCamCache[k]; });
    if (!alerts.length) {
      $('alertsList').innerHTML = '<div class="empty">لا توجد تنبيهات.</div>';
      return;
    }
    $('alertsList').innerHTML = alerts.map(function (a) {
      const sev = a.severity || 'medium';
      const color = SEV_COLOR[sev] || '#64748b';
      const bg = SEV_BG[sev] || 'rgba(100,116,139,.12)';
      const ackedFlag = a.acked;
      const devLabel = a.device_name || a.device_id || '';
      const meta = parseAlertMeta(a.meta);
      if (meta && meta.screenshot && a.id) {
        alertShotCache[a.id] = meta.screenshot;
      }
      if (meta && meta.camera_photo && a.id) {
        alertCamCache[a.id] = meta.camera_photo;
      }
      const cachedShot = a.id ? (alertShotCache[a.id] || '') : '';
      const cachedCam = a.id ? (alertCamCache[a.id] || '') : '';
      const hasShot = Boolean((meta && (meta.screenshot || meta.has_screenshot)) || cachedShot);
      const hasCam = Boolean((meta && (meta.camera_photo || meta.has_camera_photo)) || cachedCam);
      const camMime = (cachedCam && !String(cachedCam).startsWith('iVBOR')) ? 'image/jpeg' : 'image/png';
      const thumbsHtml = (cachedShot || cachedCam)
        ? '<div style="grid-column:1 / -1;display:flex;gap:10px;flex-wrap:wrap;margin-top:4px;">' +
            (cachedCam ? '<div style="display:flex;flex-direction:column;gap:4px;"><span style="font-size:11px;font-weight:700;color:#fca5a5;">📷 كاميرا الموظف</span><img data-alert-cam="' + esc(a.id) + '" data-device-name="' + esc(devLabel) + '" data-shot-time="' + esc(ago(a.created_at)) + '" src="data:' + camMime + ';base64,' + esc(cachedCam) + '" alt="cam" style="height:88px;width:auto;border-radius:8px;border:2px solid rgba(239,68,68,.55);cursor:pointer;object-fit:cover;"></div>' : '') +
            (cachedShot ? '<div style="display:flex;flex-direction:column;gap:4px;"><span style="font-size:11px;font-weight:700;color:#93c5fd;">📸 لقطة الشاشة</span><img data-alert-shot="' + esc(a.id) + '" data-device-name="' + esc(devLabel) + '" data-shot-time="' + esc(ago(a.created_at)) + '" src="data:' + (String(cachedShot).startsWith('iVBOR') ? 'image/png' : 'image/jpeg') + ';base64,' + esc(cachedShot) + '" alt="screen" style="height:88px;width:auto;border-radius:8px;border:1px solid rgba(148,163,184,.35);cursor:pointer;object-fit:cover;"></div>' : '') +
          '</div>'
        : '';
      const isUploadAlert = !!(meta && (meta.channel === 'whatsapp_web' || meta.channel === 'web_upload' || meta.file_name));
      let detailsHtml = '';
      if (isUploadAlert) {
        const typeStr = [meta.file_category, meta.file_ext ? ('(' + meta.file_ext.toUpperCase() + ')') : ''].filter(Boolean).join(' ') || '—';
        const recipName = meta.recipient_name || meta.page_url || 'انظر لقطة الشاشة';
        const recipPhone = meta.recipient_phone || 'غير ظاهر (مسجل باسم جهة اتصال)';
        detailsHtml = '<div style="margin-top:8px;padding:8px 12px;border-radius:10px;background:rgba(15,23,42,0.06);border:1px solid rgba(148,163,184,0.22);display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:6px 12px;font-size:12px;">' +
          '<div>📄 <b>اسم الملف:</b> <span class="mono">' + esc(meta.file_name || '—') + '</span></div>' +
          '<div>🏷 <b>النوع:</b> ' + esc(typeStr) + '</div>' +
          '<div>📦 <b>الحجم:</b> <span class="mono">' + esc(meta.file_size || '—') + '</span></div>' +
          '<div>👤 <b>المرسل إليه / الوجهة:</b> <span style="font-weight:700;">' + esc(recipName) + '</span></div>' +
          '<div>📞 <b>رقم المرسل له:</b> <span class="mono" dir="ltr" style="font-weight:700;color:' + (meta.recipient_phone ? '#2563eb' : '#94a3b8') + ';">' + esc(recipPhone) + '</span></div>' +
          (meta.page_url ? ('<div>🌐 <b>الموقع/النافذة:</b> <span class="mono">' + esc(meta.page_url) + '</span></div>') : '') +
          '<div>💻 <b>مستخدم الجهاز:</b> <span class="mono">' + esc(meta.windows_user || '—') + '</span></div>' +
          (meta.file_path ? ('<div style="grid-column:1 / -1;word-break:break-all;">📂 <b>المسار:</b> <span class="mono">' + esc(meta.file_path) + '</span></div>') : '') +
          thumbsHtml +
        '</div>';
      } else if (meta && (hasShot || hasCam || meta.windows_user || meta.page_url)) {
        detailsHtml = '<div style="margin-top:8px;padding:8px 12px;border-radius:10px;background:rgba(15,23,42,0.06);border:1px solid rgba(148,163,184,0.22);display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:6px 12px;font-size:12px;">' +
          (meta.windows_user ? ('<div>💻 <b>مستخدم الجهاز:</b> <span class="mono">' + esc(meta.windows_user) + '</span></div>') : '') +
          (meta.page_url ? ('<div>🌐 <b>النافذة/الموقع:</b> <span class="mono">' + esc(meta.page_url) + '</span></div>') : '') +
          thumbsHtml +
        '</div>';
      }
      const dlBtn = (meta && meta.uploaded_file_id)
        ? '<a class="btn btn-success btn-sm" data-download-upload="' + esc(meta.uploaded_file_id) + '" data-file-name="' + esc((meta && meta.file_name) || 'file') + '" href="' + esc(serverHttpBase + '/api/uploads/' + encodeURIComponent(meta.uploaded_file_id)) + '" target="_blank" download="' + esc((meta && meta.file_name) || 'file') + '" style="text-decoration:none;">⬇ تحميل النسخة طبق الأصل</a>'
        : '';
      const camBtn = hasCam
        ? '<button class="btn btn-danger btn-sm" data-alert-cam="' + esc(a.id) + '" data-device-name="' + esc(devLabel) + '" data-shot-time="' + esc(ago(a.created_at)) + '">📷 صورة الكاميرا</button>'
        : '';
      const shotBtn = hasShot
        ? '<button class="btn btn-primary btn-sm" data-alert-shot="' + esc(a.id) + '" data-device-name="' + esc(devLabel) + '" data-shot-time="' + esc(ago(a.created_at)) + '">' + (isUploadAlert ? '📸 لقطة الرفع' : '📸 لقطة الشاشة') + '</button>'
        : '';
      const liveBtn = a.device_id
        ? '<button class="btn btn-ghost btn-sm" data-screen-device="' + esc(a.device_id) + '" data-device-name="' + esc(devLabel) + '">🖥 الشاشة الحية</button>'
        : '';
      const ackBtn = ackedFlag ? '' : '<button class="btn btn-ghost btn-sm" data-ack-alert="' + esc(a.id) + '">إقرار</button>';
      return '<div class="card" style="margin-bottom:12px;border-inline-start:4px solid ' + color + ';background:' + bg + ';">' +
        '<div style="display:flex;justify-content:space-between;align-items:start;gap:12px;flex-wrap:wrap;">' +
          '<div style="flex:1 1 320px;min-width:0;">' +
            '<div style="font-weight:800;font-size:14px;color:' + color + ';">' + esc(TYPE_LABEL[a.type] || a.type) + ' · ' + esc(sev.toUpperCase()) + '</div>' +
            '<div style="font-size:12.5px;color:var(--text);margin-top:4px;">' + esc(a.message) + '</div>' +
            detailsHtml +
            '<div class="mono" style="font-size:11px;color:#94a3b8;margin-top:6px;">' + esc(devLabel) + ' · ' + ago(a.created_at) + (ackedFlag ? ' · مُقرَّة' : '') + '</div>' +
          '</div>' +
          '<div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;">' + dlBtn + camBtn + shotBtn + liveBtn + ackBtn + '</div>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  document.addEventListener('click', async (e) => {
    const cam = e.target.closest('[data-alert-cam]');
    if (cam) {
      const aid = cam.dataset.alertCam;
      stopScreenTimer();
      currentScreenDevice = null;
      currentScreenTransport = null;
      currentScreenRdId = '';
      currentScreenRdPass = '';
      $('screenTitle').textContent = 'صورة كاميرا الموظف وقت التنبيه — ' + (cam.dataset.deviceName || '');
      updateLiveToggleUi();
      let b64 = alertCamCache[aid] || '';
      if (!b64 && api.getAlertMedia) {
        $('screenImg').style.display = 'none';
        $('screenEmpty').textContent = '⏳ جارٍ تحميل صورة الكاميرا من السيرفر...';
        $('screenEmpty').style.display = 'block';
        $('screenStatus').textContent = 'جارٍ التحميل...';
        $('screenModal').classList.add('show');
        try {
          const media = await api.getAlertMedia(aid);
          if (media && media.screenshot) alertShotCache[aid] = media.screenshot;
          if (media && media.camera_photo) alertCamCache[aid] = media.camera_photo;
          b64 = alertCamCache[aid] || '';
        } catch (_) {}
      }
      if (!b64) {
        $('screenModal').classList.remove('show');
        toast('لا توجد صورة كاميرا محفوظة لهذا التنبيه', 'error');
        return;
      }
      const mime = String(b64).startsWith('iVBOR') ? 'image/png' : 'image/jpeg';
      $('screenImg').src = 'data:' + mime + ';base64,' + b64;
      $('screenImg').dataset.hasFrame = '1';
      $('screenImg').style.display = 'block';
      $('screenEmpty').style.display = 'none';
      $('screenStatus').textContent = cam.dataset.shotTime ? ('وقت الالتقاط: ' + cam.dataset.shotTime) : 'صورة الكاميرا وقت التنبيه';
      $('screenModal').classList.add('show');
      return;
    }
    const shot = e.target.closest('[data-alert-shot]');
    if (shot) {
      const aid = shot.dataset.alertShot;
      stopScreenTimer();
      currentScreenDevice = null;
      currentScreenTransport = null;
      currentScreenRdId = '';
      currentScreenRdPass = '';
      $('screenTitle').textContent = 'لقطة الشاشة وقت التنبيه — ' + (shot.dataset.deviceName || '');
      updateLiveToggleUi();
      let b64 = alertShotCache[aid] || '';
      if (!b64 && api.getAlertMedia) {
        $('screenImg').style.display = 'none';
        $('screenEmpty').textContent = '⏳ جارٍ تحميل لقطة الشاشة من السيرفر...';
        $('screenEmpty').style.display = 'block';
        $('screenStatus').textContent = 'جارٍ التحميل...';
        $('screenModal').classList.add('show');
        try {
          const media = await api.getAlertMedia(aid);
          if (media && media.screenshot) alertShotCache[aid] = media.screenshot;
          if (media && media.camera_photo) alertCamCache[aid] = media.camera_photo;
          b64 = alertShotCache[aid] || '';
        } catch (_) {}
      }
      if (!b64) {
        $('screenModal').classList.remove('show');
        toast('لا توجد لقطة محفوظة لهذا التنبيه', 'error');
        return;
      }
      const mime = String(b64).startsWith('iVBOR') ? 'image/png' : 'image/jpeg';
      $('screenImg').src = 'data:' + mime + ';base64,' + b64;
      $('screenImg').dataset.hasFrame = '1';
      $('screenImg').style.display = 'block';
      $('screenEmpty').style.display = 'none';
      $('screenStatus').textContent = shot.dataset.shotTime ? ('وقت الالتقاط: ' + shot.dataset.shotTime) : 'لقطة محفوظة مع التنبيه';
      $('screenModal').classList.add('show');
      return;
    }
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
    try {
      const r = await api.getAuditLog();
      entries = Array.isArray(r) ? r : ((r && r.entries) || []);
    } catch (e) { entries = []; }
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
  let streamRenewTimer = null;
  let currentScreenDevice = null;
  let currentScreenTransport = null;
  let currentScreenMode = 'once';
  let currentScreenRdId = '';
  let currentScreenRdPass = '';
  let liveWatchMode = false;
  let lastScreenAt = 0;
  let screenPolling = false;
  function updateLiveToggleUi() {
    const btn = $('screenLiveToggleBtn');
    if (btn) {
      btn.style.display = currentScreenDevice ? '' : 'none';
      if (liveWatchMode) {
        btn.textContent = '⏸ إيقاف البث المباشر';
        btn.classList.remove('btn-ghost');
        btn.classList.add('btn-danger');
      } else {
        btn.textContent = '👁 بث مباشر صامت';
        btn.classList.remove('btn-danger');
        btn.classList.add('btn-ghost');
      }
    }
  }
  function stopScreenTimer() {
    if (screenTimer) { clearInterval(screenTimer); screenTimer = null; }
    if (streamRenewTimer) { clearInterval(streamRenewTimer); streamRenewTimer = null; }
    if (currentScreenDevice && (currentScreenMode === 'screen' || currentScreenMode === 'camera')) {
      api.requestScreenshot(currentScreenDevice, currentScreenTransport, 'stop').catch(() => {});
    }
    screenPolling = false;
    liveWatchMode = false;
    currentScreenMode = 'once';
    updateLiveToggleUi();
  }
  async function requestAndLoadScreen(deviceId, transport, mode) {
    const reqMode = mode || currentScreenMode || 'once';
    try { await api.requestScreenshot(deviceId, transport, reqMode); } catch (e) {}
    await pollScreen(deviceId, transport);
  }
  async function pollScreen(deviceId, transport) {
    if (screenPolling) return;
    screenPolling = true;
    try {
      const r = await api.getScreenshot(deviceId, transport);
      if (currentScreenDevice !== deviceId) return;
      if (r && r.error === 'no_camera' && currentScreenMode === 'camera') {
        if (streamRenewTimer) { clearInterval(streamRenewTimer); streamRenewTimer = null; }
        $('screenImg').style.display = 'none';
        $('screenEmpty').textContent = '📷 لا توجد كاميرا متصلة بجهاز هذا الموظف';
        $('screenEmpty').style.display = 'block';
        $('screenStatus').textContent = '📷 تعذر البث — لا توجد كاميرا متصلة بهذا الجهاز';
        return;
      }
      if (r && r.image) {
        if (r.at !== lastScreenAt) {
          lastScreenAt = r.at || Date.now();
          const mime = String(r.image).startsWith('iVBOR') ? 'image/png' : 'image/jpeg';
          $('screenImg').src = 'data:' + mime + ';base64,' + r.image;
        }
        $('screenImg').dataset.hasFrame = '1';
        $('screenImg').style.display = 'block';
        $('screenEmpty').style.display = 'none';
        const t = r.at ? new Date(r.at).toLocaleTimeString() : '';
        if (currentScreenMode === 'camera') {
          $('screenStatus').textContent = '📷 بث حي لكاميرا الموظف (مشاهدة فقط) — آخر إطار: ' + t;
        } else if (liveWatchMode) {
          $('screenStatus').textContent = '👁 بث حي سريع للشاشة (مشاهدة فقط بدون تحكم) — آخر إطار: ' + t;
        } else {
          $('screenStatus').textContent = 'آخر لقطة: ' + t + (r.requested ? ' (بانتظار تحديث)' : '');
        }
      } else if (liveWatchMode && $('screenImg').dataset.hasFrame === '1') {
        $('screenImg').style.display = 'block';
        $('screenEmpty').style.display = 'none';
        $('screenStatus').textContent = currentScreenMode === 'camera'
          ? '📷 بث حي لكاميرا الموظف — جارٍ استلام الإطارات...'
          : '👁 بث حي سريع للشاشة — جارٍ استلام الإطارات...';
      } else {
        $('screenImg').style.display = 'none';
        $('screenEmpty').textContent = currentScreenMode === 'camera'
          ? '📷 جارٍ تشغيل كاميرا الموظف واستلام الصورة...'
          : 'في انتظار لقطة الشاشة من الجهاز...';
        $('screenEmpty').style.display = 'block';
        $('screenStatus').textContent = r && r.requested
          ? (currentScreenMode === 'camera' ? '📷 جارٍ الاتصال بكاميرا الموظف...' : liveWatchMode ? '👁 جارٍ بدء البث المباشر السريع...' : 'بانتظار لقطة من الجهاز...')
          : 'لا توجد لقطة بعد';
      }
    } catch (e) {
      if (currentScreenDevice === deviceId) $('screenStatus').textContent = 'تعذر جلب اللقطة';
    } finally {
      screenPolling = false;
    }
  }
  function openScreen(deviceId, name, transport, mode, rdId, rdPass) {
    stopScreenTimer();
    const normMode = mode === 'camera' ? 'camera' : (mode === 'screen' || mode === true) ? 'screen' : 'once';
    currentScreenDevice = deviceId;
    currentScreenTransport = transport || null;
    currentScreenMode = normMode;
    currentScreenRdId = rdId || '';
    currentScreenRdPass = rdPass || '';
    liveWatchMode = normMode === 'screen' || normMode === 'camera';
    lastScreenAt = 0;
    updateLiveToggleUi();
    $('screenImg').dataset.hasFrame = '0';
    $('screenImg').style.display = 'none';
    $('screenEmpty').textContent = normMode === 'camera'
      ? '📷 جارٍ الاتصال بكاميرا الموظف...'
      : 'في انتظار لقطة الشاشة من الجهاز...';
    $('screenEmpty').style.display = 'block';
    $('screenTitle').textContent = normMode === 'camera'
      ? ('📷 كاميرا الموظف (مشاهدة فقط) — ' + name)
      : normMode === 'screen'
      ? ('👁 مشاهدة الشاشة بث حي (بدون تحكم) — ' + name)
      : ('شاشة ' + name);
    $('screenStatus').textContent = normMode === 'camera'
      ? '📷 جارٍ فتح البث الحي للكاميرا...'
      : normMode === 'screen'
      ? '👁 جارٍ فتح البث الحي السريع...'
      : 'جارٍ طلب لقطة شاشة...';
    $('screenModal').classList.add('show');
    requestAndLoadScreen(deviceId, currentScreenTransport, currentScreenMode);
    if (liveWatchMode) {
      streamRenewTimer = setInterval(() => {
        if (currentScreenDevice === deviceId && liveWatchMode) {
          api.requestScreenshot(deviceId, currentScreenTransport, currentScreenMode).catch(() => {});
        }
      }, 4000);
      screenTimer = setInterval(() => pollScreen(deviceId, currentScreenTransport), 250);
    } else {
      screenTimer = setInterval(() => pollScreen(deviceId, currentScreenTransport), 1000);
    }
  }
  function closeScreenModal() {
    $('screenModal').classList.remove('show');
    stopScreenTimer();
    currentScreenDevice = null;
    currentScreenTransport = null;
    currentScreenRdId = '';
    currentScreenRdPass = '';
  }
  $('screenCloseBtn').addEventListener('click', closeScreenModal);
  $('screenModal').addEventListener('click', (e) => { if (e.target.id === 'screenModal') closeScreenModal(); });
  $('screenRefreshBtn').addEventListener('click', () => { if (currentScreenDevice) requestAndLoadScreen(currentScreenDevice, currentScreenTransport, currentScreenMode); });
  if ($('screenDownloadBtn')) {
    $('screenDownloadBtn').style.display = '';
    $('screenDownloadBtn').addEventListener('click', async () => {
      const imgEl = $('screenImg');
      const src = (imgEl && imgEl.style.display !== 'none' && imgEl.src) ? imgEl.src : '';
      if (!src || !src.startsWith('data:image/')) {
        toast('لا توجد صورة معروضة حالياً للحفظ', 'error');
        return;
      }
      const isJpg = src.startsWith('data:image/jpeg');
      const ext = isJpg ? '.jpg' : '.png';
      const titleClean = ($('screenTitle').textContent || 'evidence').replace(/[<>:"/\\|?*]+/g, '_').trim();
      const fname = (titleClean || 'evidence') + ext;
      if (api.saveBase64Image) {
        try {
          const r = await api.saveBase64Image(src, fname);
          if (r && r.success) toast('✓ تم حفظ الصورة بنجاح في مجلد التنزيلات (Downloads)');
          else toast((r && r.error) || 'فشل حفظ الصورة', 'error');
        } catch (err) {
          toast(err.message || 'فشل حفظ الصورة', 'error');
        }
        return;
      }
      try {
        const b64 = src.split(';base64,')[1] || '';
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const blob = new Blob([bytes], { type: isJpg ? 'image/jpeg' : 'image/png' });
        const objUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = objUrl;
        a.download = fname;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
        toast('✓ جارٍ تنزيل الصورة');
      } catch (err) {
        toast('تعذر حفظ الصورة', 'error');
      }
    });
  }
  if ($('screenLiveToggleBtn')) {
    $('screenLiveToggleBtn').addEventListener('click', () => {
      if (!currentScreenDevice) return;
      if (liveWatchMode) {
        api.requestScreenshot(currentScreenDevice, currentScreenTransport, 'stop').catch(() => {});
        if (streamRenewTimer) { clearInterval(streamRenewTimer); streamRenewTimer = null; }
        if (screenTimer) { clearInterval(screenTimer); screenTimer = null; }
        liveWatchMode = false;
        currentScreenMode = 'once';
        updateLiveToggleUi();
      } else {
        openScreen(currentScreenDevice, $('screenTitle').textContent.replace(/^.*?—\s*/, ''), currentScreenTransport, 'screen', currentScreenRdId, currentScreenRdPass);
      }
    });
  }

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
        const statsObj = (r && (r.stats || r.kpis)) || {};
        const n = statsObj.orders ? statsObj.orders.value : 0;
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
      stats = r && (r.stats || r.kpis || r);
    } catch (e) { stats = null; }
    if (!stats) return;
    if (stats.users && $('kpiUsers')) { $('kpiUsers').textContent = kpiNumber(stats.users.value); setBadge('kpiUsersBadge', stats.users.growth); }
    if (stats.profit && $('kpiProfit')) { $('kpiProfit').textContent = kpiNumber(stats.profit.value); setBadge('kpiProfitBadge', stats.profit.growth); }
    if (stats.orders && $('kpiOrders')) { $('kpiOrders').textContent = kpiNumber(stats.orders.value); setBadge('kpiOrdersBadge', stats.orders.growth); }
    if (stats.engagement && $('kpiEngagement')) { $('kpiEngagement').textContent = kpiNumber(stats.engagement.value) + '%'; setBadge('kpiEngagementBadge', stats.engagement.growth); }
  }

  /* ---------- Groups ---------- */
  const collapsedGroups = new Set();

  function linesToArr(v) {
    return v.split('\n').map((x) => x.trim()).filter(Boolean);
  }

  function mergeGroupDevices(lanList, relayList) {
    const byId = new Map();
    (Array.isArray(lanList) ? lanList : []).forEach((d) => {
      if (!d || !d.device_id) return;
      byId.set(d.device_id, Object.assign({}, d, { _transport: 'lan' }));
    });
    (Array.isArray(relayList) ? relayList : []).forEach((d) => {
      if (!d || !d.device_id) return;
      const existing = byId.get(d.device_id);
      if (existing) {
        if (!existing.group_id && d.group_id) existing.group_id = d.group_id;
        if (!existing.label && d.label) existing.label = d.label;
      } else {
        byId.set(d.device_id, Object.assign({}, d, { _transport: 'relay' }));
      }
    });
    return Array.from(byId.values());
  }

  function groupCard(g, groupDevices, otherDevices) {
    const allowed = (g.allowed || []).join('\n');
    const blocked = (g.blocked || []).join('\n');
    const ephem = Boolean(g.ephemeral_browser);
    const list = Array.isArray(groupDevices) ? groupDevices : [];
    const others = Array.isArray(otherDevices) ? otherDevices : [];
    const isOpen = !collapsedGroups.has(g.id);
    const onlineCount = list.filter((d) => d.online).length;
    const blockedCount = list.filter((d) => d.online && d.blocked).length;
    const addOpts = ['<option value="">' + (others.length ? '— اختر جهازاً لضمه لهذه المجموعة —' : '— لا توجد أجهزة أخرى خارج المجموعة —') + '</option>'].concat(
      others.map((d) => {
        const dName = d.label || d.hostname || d.device_id;
        const tLabel = d._transport === 'lan' ? 'LAN' : 'Relay';
        const gObj = groupsCache.find((x) => x.id === d.group_id);
        const curG = gObj ? (' · حالياً: ' + gObj.name) : '';
        return '<option value="' + esc(d.device_id) + '">' + esc(dName) + ' (' + tLabel + curG + ')</option>';
      })
    ).join('');
    const allowedCount = (g.allowed || []).length;
    const blockedCountSites = (g.blocked || []).length;
    const devicesHtml = list.length
      ? list.map((d) => deviceRow(d, d._transport || 'relay')).join('')
      : '<div class="empty" style="padding:18px 12px;font-size:13px;">لا توجد أجهزة مضافة في هذه المجموعة بعد. يمكنك ضم جهاز من القائمة أعلاه أو من صفحة الأجهزة.</div>';
    return '<div class="card group-card">' +
      '<div class="group-card-top" data-group-header-toggle="' + esc(g.id) + '" style="cursor:pointer;" title="اضغط لعرض أو إخفاء أجهزة المجموعة">' +
        '<input class="input g-name-input" data-g-name="' + esc(g.id) + '" value="' + esc(g.name) + '">' +
        '<select class="input g-mode-select" data-g-mode="' + esc(g.id) + '">' +
          '<option value="whitelist"' + (g.mode === 'whitelist' ? ' selected' : '') + '>Whitelist</option>' +
          '<option value="blacklist"' + (g.mode === 'blacklist' ? ' selected' : '') + '>Blacklist</option>' +
        '</select>' +
        '<span class="badge violet" data-toggle-group-devices="' + esc(g.id) + '" style="cursor:pointer;">🖥 ' + list.length + ' جهاز ' + (isOpen ? '▴' : '▾') + '</span>' +
        '<span class="badge ' + (ephem ? 'green' : 'gray') + '">' + (ephem ? '🧹 تصفح نظيف مفعّل' : 'تصفح عادي') + '</span>' +
        '<div class="group-card-actions">' +
          '<button class="btn btn-primary btn-sm" data-save-group="' + esc(g.id) + '">حفظ</button>' +
          '<button class="btn ' + (ephem ? 'btn-success' : 'btn-ghost') + ' btn-sm" data-toggle-ephemeral="' + esc(g.id) + '" data-ephem="' + (ephem ? '1' : '0') + '">' + (ephem ? '🧹 التصفح النظيف: مفعّل (إيقاف)' : '🧹 تفعيل التصفح النظيف') + '</button>' +
          '<button class="btn btn-danger btn-sm" data-grp-cmd="block" data-id="' + esc(g.id) + '">قفل المجموعة</button>' +
          '<button class="btn btn-success btn-sm" data-grp-cmd="unblock" data-id="' + esc(g.id) + '">فتح المجموعة</button>' +
          '<button class="btn btn-ghost btn-sm" data-grp-cmd="update_client" data-id="' + esc(g.id) + '" title="إرسال وتثبيت أحدث نسخة من الكلاينت بصمت لكل أجهزة المجموعة">⬆ تحديث الكلاينت</button>' +
          '<button class="btn btn-ghost btn-sm" data-del-group="' + esc(g.id) + '">حذف</button>' +
        '</div>' +
      '</div>' +
      '<label class="group-ephem-row">' +
        '<input type="checkbox" data-g-ephemeral="' + esc(g.id) + '"' + (ephem ? ' checked' : '') + ' style="width:15px;height:15px;accent-color:var(--primary);">' +
        '<span>🧹 <b>وضع التصفح النظيف (Chrome &amp; Edge):</b> فتح كأول مرة ومسح السجل والكاش وكلمات السر والجلسات تلقائياً عند كل إغلاق</span>' +
      '</label>' +
      '<div class="group-sites-grid">' +
        '<div class="field"><span class="label"><span>المواقع المسموحة (سطر لكل موقع)</span><span class="badge green" style="padding:2px 8px;font-size:11px;">' + allowedCount + '</span></span>' +
          '<textarea class="input mono" rows="3" dir="ltr" data-g-allowed="' + esc(g.id) + '">' + esc(allowed) + '</textarea></div>' +
        '<div class="field"><span class="label"><span>المواقع المقفولة (سطر لكل موقع)</span><span class="badge red" style="padding:2px 8px;font-size:11px;">' + blockedCountSites + '</span></span>' +
          '<textarea class="input mono" rows="3" dir="ltr" data-g-blocked="' + esc(g.id) + '">' + esc(blocked) + '</textarea></div>' +
      '</div>' +
      '<div class="group-devices-sec">' +
        '<div class="group-devices-bar">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;cursor:pointer;" data-toggle-group-devices="' + esc(g.id) + '">' +
            '<b style="font-size:13px;">🖥 الأجهزة داخل مجموعة «' + esc(g.name) + '» (' + list.length + ')</b>' +
            '<span class="badge green" style="padding:3px 9px;font-size:11px;">' + onlineCount + ' متصل</span>' +
            '<span class="badge ' + (blockedCount ? 'red' : 'gray') + '" style="padding:3px 9px;font-size:11px;">' + blockedCount + ' مقفول</span>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">' +
            '<select class="input" data-add-group-device-select="' + esc(g.id) + '">' + addOpts + '</select>' +
            '<button type="button" class="btn btn-primary btn-sm" data-add-group-device-btn="' + esc(g.id) + '"' + (others.length ? '' : ' disabled') + '>+ ضم للمجموعة</button>' +
          '</div>' +
        '</div>' +
        '<div class="devices-card-container" data-group-devices-panel="' + esc(g.id) + '" style="display:' + (isOpen ? '' : 'none') + ';">' +
          devicesHtml +
        '</div>' +
      '</div>' +
    '</div>';
  }

  async function loadGroups() {
    if (!api.getRelayGroups) return;
    let lan = [];
    let relay = [];
    try {
      const [gr, lr, rr] = await Promise.all([
        api.getRelayGroups(),
        api.getDevices ? api.getDevices().catch(() => []) : Promise.resolve([]),
        api.getRelayDevices ? api.getRelayDevices().catch(() => []) : Promise.resolve([]),
      ]);
      groupsCache = (gr && gr.groups) || [];
      lan = Array.isArray(lr) ? lr : [];
      relay = Array.isArray(rr) ? rr : ((rr && rr.devices) || []);
    } catch (e) { groupsCache = []; }
    const allDevices = mergeGroupDevices(lan, relay);
    $('groupsList').innerHTML = groupsCache.length
      ? groupsCache.map((g) => {
          const groupDevices = allDevices.filter((d) => d.group_id === g.id);
          const otherDevices = allDevices.filter((d) => d.group_id !== g.id);
          g.devices = groupDevices.length;
          return groupCard(g, groupDevices, otherDevices);
        }).join('')
      : '<div class="empty">لا توجد مجموعات بعد. أنشئ مجموعة وابدأ بتعيين الأجهزة إليها.</div>';
  }

  $('createGroupBtn').addEventListener('click', async () => {
    const name = $('newGroupName').value.trim();
    if (!name) { toast('اكتب اسم المجموعة', 'error'); return; }
    const ephem = Boolean($('newGroupEphemeral') && $('newGroupEphemeral').checked);
    try {
      const r = await api.createRelayGroup(name, $('newGroupMode').value, ephem);
      if (r && r.success === false) { toast(r.error || 'فشل الإنشاء', 'error'); return; }
      $('newGroupName').value = '';
      if ($('newGroupEphemeral')) $('newGroupEphemeral').checked = false;
      await loadGroups();
      toast('تم إنشاء المجموعة');
    } catch (e) { toast(e.message || 'فشل الإنشاء', 'error'); }
  });

  document.addEventListener('click', async (e) => {
    const togGrpDev = e.target.closest('[data-toggle-group-devices]');
    const grpHdr = !togGrpDev && !e.target.closest('input, select, button, label, a')
      ? e.target.closest('[data-group-header-toggle]')
      : null;
    if (togGrpDev || grpHdr) {
      const id = togGrpDev ? togGrpDev.dataset.toggleGroupDevices : grpHdr.dataset.groupHeaderToggle;
      if (collapsedGroups.has(id)) collapsedGroups.delete(id);
      else collapsedGroups.add(id);
      const isOpen = !collapsedGroups.has(id);
      const panel = document.querySelector('[data-group-devices-panel="' + id + '"]');
      if (panel) panel.style.display = isOpen ? '' : 'none';
      const badge = document.querySelector('[data-toggle-group-devices="' + id + '"]');
      if (badge) badge.textContent = badge.textContent.replace(/[▴▾]/, isOpen ? '▴' : '▾');
      return;
    }
    const addGrpDev = e.target.closest('[data-add-group-device-btn]');
    if (addGrpDev) {
      const id = addGrpDev.dataset.addGroupDeviceBtn;
      const sel = document.querySelector('[data-add-group-device-select="' + id + '"]');
      const deviceId = sel ? sel.value : '';
      if (!deviceId) { toast('اختر جهازاً أولاً', 'error'); return; }
      try {
        const r = await api.assignDeviceGroup(deviceId, id);
        if (r && r.success !== false) {
          collapsedGroups.delete(id);
          toast('تم ضم الجهاز إلى المجموعة');
          await Promise.all([loadGroups(), loadDevices(), loadRelayDevices()]);
        } else {
          toast((r && r.error) || 'فشل ضم الجهاز', 'error');
        }
      } catch (err) { toast(err.message || 'فشل ضم الجهاز', 'error'); }
      return;
    }
    const save = e.target.closest('[data-save-group]');
    if (save) {
      const id = save.dataset.saveGroup;
      const name = document.querySelector('[data-g-name="' + id + '"]').value.trim();
      const mode = document.querySelector('[data-g-mode="' + id + '"]').value;
      const allowed = linesToArr(document.querySelector('[data-g-allowed="' + id + '"]').value);
      const blocked = linesToArr(document.querySelector('[data-g-blocked="' + id + '"]').value);
      const ephemEl = document.querySelector('[data-g-ephemeral="' + id + '"]');
      const ephem = Boolean(ephemEl && ephemEl.checked);
      try {
        const r = await api.updateRelayGroup(id, name, mode, allowed, blocked, ephem);
        if (r && r.success === false) { toast(r.error || 'فشل الحفظ', 'error'); return; }
        loadGroups(); toast('تم حفظ المجموعة');
      } catch (err) { toast(err.message || 'فشل الحفظ', 'error'); }
      return;
    }
    const togEphem = e.target.closest('[data-toggle-ephemeral]');
    if (togEphem) {
      const id = togEphem.dataset.toggleEphemeral;
      const curEphem = togEphem.dataset.ephem === '1';
      const nextEphem = !curEphem;
      const ephemEl = document.querySelector('[data-g-ephemeral="' + id + '"]');
      if (ephemEl) ephemEl.checked = nextEphem;
      const name = document.querySelector('[data-g-name="' + id + '"]').value.trim();
      const mode = document.querySelector('[data-g-mode="' + id + '"]').value;
      const allowed = linesToArr(document.querySelector('[data-g-allowed="' + id + '"]').value);
      const blocked = linesToArr(document.querySelector('[data-g-blocked="' + id + '"]').value);
      try {
        const r = await api.updateRelayGroup(id, name, mode, allowed, blocked, nextEphem);
        if (r && r.success === false) { toast(r.error || 'فشل التحديث', 'error'); return; }
        loadGroups();
        toast(nextEphem ? 'تم تفعيل التصفح النظيف لهذه المجموعة فقط' : 'تم إيقاف التصفح النظيف عن هذه المجموعة');
      } catch (err) { toast(err.message || 'فشل التحديث', 'error'); }
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
      const card = thr.closest('.device-card');
      const input = (card && card.querySelector('[data-throttle-input="' + id + '"]')) || document.querySelector('[data-throttle-input="' + id + '"]');
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
          if ($('view-groups') && $('view-groups').classList.contains('active')) setTimeout(loadGroups, 800);
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
      if ($('view-groups') && $('view-groups').classList.contains('active')) setTimeout(loadGroups, 800);
      return;
    }
    const sup = e.target.closest('[data-support-device]');
    if (sup) {
      try {
        const r = await api.openSupportSession(sup.dataset.supportDevice, sup.dataset.rdPass || null, 'support');
        if (r && r.success !== false) toast('🛠 تم فتح جلسة الدعم الكامل عبر RustDesk (تحكم بالماوس والكيبورد)');
        else if (!(r && r.cancelled)) toast((r && r.error) || 'فشل فتح الجلسة', 'error');
      } catch (err) { toast(err.message || 'فشل فتح الجلسة', 'error'); }
      return;
    }
    const camBtn = e.target.closest('[data-camera-device]');
    if (camBtn) {
      const rdId = (camBtn.dataset.rdId || '').trim();
      if (!rdId) {
        toast('لا يوجد RustDesk ID مسجل لهذا الجهاز بعد — تأكد من تثبيت وتشغيل RustDesk على جهاز الموظف', 'error');
        return;
      }
      try {
        const r = await api.openSupportSession(rdId, camBtn.dataset.rdPass || null, 'camera');
        if (r && r.success !== false) toast('📷 تم فتح كاميرا الموظف مباشرة عبر RustDesk (بدون تحكم في الجهاز)');
        else if (!(r && r.cancelled)) toast((r && r.error) || 'فشل فتح الكاميرا عبر RustDesk', 'error');
      } catch (err) { toast(err.message || 'فشل فتح الكاميرا عبر RustDesk', 'error'); }
      return;
    }
    const scr = e.target.closest('[data-screen-device]');
    if (scr) {
      openScreen(
        scr.dataset.screenDevice,
        scr.dataset.deviceName || '',
        scr.dataset.transport || '',
        'once',
        scr.dataset.rdId || '',
        scr.dataset.rdPass || ''
      );
      return;
    }
    const watch = e.target.closest('[data-watch-device]');
    if (watch) {
      const rdId = (watch.dataset.rdId || '').trim();
      if (!rdId) {
        toast('لا يوجد RustDesk ID مسجل لهذا الجهاز بعد — تأكد من تثبيت وتشغيل RustDesk على جهاز الموظف', 'error');
        return;
      }
      try {
        const r = await api.openSupportSession(rdId, watch.dataset.rdPass || null, 'watch');
        if (r && r.success !== false) toast('👁 تم فتح وضع المشاهدة فقط عبر RustDesk (بدون تحكم بالماوس أو الكيبورد)');
        else if (!(r && r.cancelled)) toast((r && r.error) || 'فشل فتح وضع المشاهدة عبر RustDesk', 'error');
      } catch (err) { toast(err.message || 'فشل فتح وضع المشاهدة عبر RustDesk', 'error'); }
      return;
    }
    const delDev = e.target.closest('[data-delete-device]');
    if (delDev) {
      const isLan = delDev.dataset.transport === 'lan';
      if (!confirm('حذف الجهاز "' + (delDev.dataset.deviceName || '') + '" من القائمة؟' + (isLan ? ' سيختفي حتى يتصل من جديد.' : ' لن يستطيع الاتصال بعد ذلك بدون رمز ربط جديد.'))) return;
      try {
        const r = await api.deleteRelayDevice(delDev.dataset.deleteDevice);
        if (r && r.success !== false) { toast('تم حذف الجهاز'); if (isLan) loadDevices(); else loadRelayDevices(); loadGroups(); }
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
        if (r && r.success !== false) {
          toast('تم تعديل الاسم');
          setTimeout(rn.dataset.transport === 'lan' ? loadDevices : loadRelayDevices, 800);
          if ($('view-groups') && $('view-groups').classList.contains('active')) setTimeout(loadGroups, 800);
        }
        else toast((r && r.error) || 'فشل تعديل الاسم', 'error');
      } catch (err) { toast(err.message || 'فشل تعديل الاسم', 'error'); }
      return;
    }
    const gc = e.target.closest('[data-grp-cmd]');
    if (gc) {
      if (gc.dataset.grpCmd === 'update_client' && !confirm('إرسال وتثبيت أحدث نسخة من الكلاينت عن بُعد بصمت لكل أجهزة هذه المجموعة؟')) return;
      try {
        const r = await api.sendGroupCommand(gc.dataset.id, gc.dataset.grpCmd, currentAdminUser, currentAdminRole);
        if (r && r.success) {
          toast('تم إرسال أمر المجموعة');
          setTimeout(() => {
            loadDevices();
            loadRelayDevices();
            if ($('view-groups') && $('view-groups').classList.contains('active')) loadGroups();
          }, 800);
        } else toast((r && r.error) || 'فشل', 'error');
      } catch (err) { toast(err.message || 'فشل', 'error'); }
      return;
    }
  });

  document.querySelectorAll('#syncPolicyBtn, #syncPolicyBtn2').forEach((b) => {
    b.addEventListener('click', async () => {
      try {
        const r = await api.syncPolicy();
        if (r && r.success) toast('تمت مزامنة القوائم مع الـ Relay');
        else toast((r && r.error) || 'فشلت المزامنة', 'error');
      } catch (e) { toast(e.message || 'فشلت المزامنة', 'error'); }
    });
  });

  document.querySelectorAll('#refreshRelayBtn, #refreshRelayBtn2').forEach((b) => {
    b.addEventListener('click', loadRelayDevices);
  });

  function selectView(viewName) {
    const item = document.querySelector('.nav-item[data-view="' + viewName + '"]');
    if (item) item.click();
  }
  window.addEventListener('hashchange', () => {
    const h = location.hash.replace('#', '');
    if (h) selectView(h);
  });
  if (location.hash) {
    const h = location.hash.replace('#', '');
    setTimeout(() => selectView(h), 150);
  }

  /* ---------- محاولات فتح مواقع محظورة ----------
   * كل جهاز (LAN أو Relay) يرسل مع كل poll قائمة `denied` بالمواقع التي رفضها البروكسي.
   * هنا نجمعها من كل الأجهزة، ونحفظ وقت أول رصد لكل (جهاز + موقع) في localStorage. */
  const BA_STORE_KEY = 'itk_blocked_attempts_v2';
  const BA_READ_KEY = 'itk_blocked_attempts_read_v1';
  const BA_MAX = 300;
  let baTimer = null;
  let baItems = {};
  try { baItems = JSON.parse(localStorage.getItem(BA_STORE_KEY) || '{}') || {}; } catch (e) { baItems = {}; }

  function baReadTs() { return Number(localStorage.getItem(BA_READ_KEY) || 0); }
  function baSave() {
    const keys = Object.keys(baItems);
    if (keys.length > BA_MAX) {
      keys.sort((a, b) => baItems[b].first - baItems[a].first).slice(BA_MAX).forEach((k) => delete baItems[k]);
    }
    try { localStorage.setItem(BA_STORE_KEY, JSON.stringify(baItems)); } catch (e) {}
  }
  function baTime(ts) {
    const d = new Date(ts);
    const today = new Date().toDateString() === d.toDateString();
    return today ? d.toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' })
                 : d.toLocaleString('ar-EG', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  function renderBlockedAttempts() {
    const unread = Object.values(baItems).filter((a) => a.first > baReadTs()).length;
    const badge = $('blockedAttemptsBadge');
    if (badge) {
      badge.textContent = unread > 99 ? '99+' : String(unread);
      badge.style.display = unread ? '' : 'none';
    }
    const panel = $('blockedAttemptsPanel');
    if (!panel || panel.style.display === 'none') return;
    const q = (($('blockedAttemptsSearch') || {}).value || '').trim().toLowerCase();
    const rows = Object.values(baItems)
      .filter((a) => !q || (a.device + ' ' + a.ip + ' ' + a.host).toLowerCase().includes(q))
      .sort((a, b) => b.first - a.first);
    const readTs = baReadTs();
    $('blockedAttemptsBody').innerHTML = rows.map((a) =>
      '<tr class="' + (a.first > readTs ? 'ba-new' : '') + '">' +
        '<td><strong>' + esc(a.device) + '</strong>' + (a.source === 'relay' ? ' <span class="ba-src">Relay</span>' : '') + '</td>' +
        '<td class="ba-mono">' + esc(a.ip || '—') + '</td>' +
        '<td class="ba-host">' + esc(a.host) + '</td>' +
        '<td class="ba-time">' + esc(baTime(a.first)) + '</td>' +
      '</tr>').join('');
    $('blockedAttemptsEmpty').style.display = rows.length ? 'none' : 'block';
  }

  function baIngest(devices, source) {
    const now = Date.now();
    let changed = false;
    (devices || []).forEach((d) => {
      const denied = Array.isArray(d.denied) ? d.denied.filter(Boolean) : [];
      const id = d.device_id || d.hostname || d.ip || '?';
      const name = d.label || d.hostname || d.device_id || 'جهاز غير معروف';
      denied.forEach((host) => {
        // المفتاح بدون نوع الاتصال: نفس الجهاز لو ظهر عبر LAN و Relay يتسجل مرة واحدة.
        const key = id + '|' + host;
        const cur = baItems[key];
        if (!cur) {
          baItems[key] = { device: name, ip: d.ip || '', host: String(host), source, first: now };
          changed = true;
        } else if (cur.device !== name || (d.ip && cur.ip !== d.ip) || (source === 'lan' && cur.source !== 'lan')) {
          cur.device = name;
          if (d.ip) cur.ip = d.ip;
          if (source === 'lan') cur.source = 'lan';
          changed = true;
        }
      });
    });
    return changed;
  }

  // آخر قائمة أجهزة مدمجة (LAN + Relay) — يستخدمها الشريط العلوي ومؤشرات الرئيسية.
  let liveDevices = [];

  function renderLiveStats() {
    // نفس الجهاز قد يظهر عبر LAN و Relay؛ نعدّه مرة واحدة.
    const seen = {};
    liveDevices.forEach((d) => {
      const id = d.device_id || d.hostname || d.ip;
      if (!id) return;
      const prev = seen[id];
      seen[id] = { online: !!d.online || (prev && prev.online), blocked: !!d.blocked || (prev && prev.blocked) };
    });
    const list = Object.values(seen);
    const online = list.filter((x) => x.online).length;
    const blocked = list.filter((x) => x.blocked).length;
    if ($('tbOnline')) $('tbOnline').textContent = online;
    if ($('tbBlocked')) $('tbBlocked').textContent = blocked;
    if (typeof renderDashRings === 'function') renderDashRings(list.length, online, blocked);
  }

  let baBusy = false;
  let baTickCount = 0;
  async function pollBlockedAttempts() {
    if (baBusy) return;
    baBusy = true;
    baTickCount++;
    try {
      let changed = false;
      let lan = [];
      let relay = lastRelayDevicesSnapshot;
      if (api.getDevices) {
        try { lan = (await api.getDevices()) || []; } catch (e) {}
        changed = baIngest(lan, 'lan') || changed;
      }
      if (api.getRelayDevices && !relayDevicesBusy) {
        try {
          const r = await api.getRelayDevices();
          relay = Array.isArray(r) ? r : ((r && r.devices) || []);
          lastRelayDevicesSnapshot = relay;
        } catch (e) {}
      }
      changed = baIngest(relay, 'relay') || changed;
      liveDevices = lan.concat(relay);
      renderLiveStats();
      if (changed) baSave();
      renderBlockedAttempts();
      await loadAlerts();
      const archiveOpen = $('view-archive') && $('view-archive').classList.contains('active');
      if (archiveOpen || baTickCount % 3 === 1) {
        await loadArchiveFiles();
      }
    } finally {
      baBusy = false;
    }
  }

  // زر التنبيهات في الشريط العلوي يعكس عدّاد التنبيهات في القائمة الجانبية.
  (function initTopbarAlerts() {
    const src = $('navAlertCount');
    const dst = $('tbAlerts');
    const btn = $('tbAlertsBtn');
    if (!src || !dst || !btn) return;
    const sync = () => {
      const n = parseInt(src.textContent, 10) || 0;
      dst.textContent = n > 99 ? '99+' : String(n);
      btn.classList.toggle('has-alerts', n > 0);
    };
    new MutationObserver(sync).observe(src, { childList: true, characterData: true, subtree: true });
    sync();
    btn.addEventListener('click', () => {
      const nav = document.querySelector('.nav-item[data-view="alerts"]');
      if (nav) nav.click();
    });
  })();

  function startBlockedAttempts() {
    stopBlockedAttempts();
    pollBlockedAttempts();
    baTimer = setInterval(pollBlockedAttempts, 8000);
  }
  function stopBlockedAttempts() {
    if (baTimer) { clearInterval(baTimer); baTimer = null; }
  }

  (function initBlockedAttemptsUi() {
    const btn = $('blockedAttemptsBtn');
    const panel = $('blockedAttemptsPanel');
    if (!btn || !panel) return;
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
      renderBlockedAttempts();
    });
    panel.addEventListener('click', (e) => e.stopPropagation());
    document.addEventListener('click', () => { panel.style.display = 'none'; });
    $('blockedAttemptsSearch').addEventListener('input', renderBlockedAttempts);
    $('blockedAttemptsRead').addEventListener('click', () => {
      localStorage.setItem(BA_READ_KEY, String(Date.now()));
      renderBlockedAttempts();
    });
    $('blockedAttemptsClear').addEventListener('click', () => {
      if (!confirm('مسح سجل المحاولات المحظورة؟')) return;
      baItems = {};
      baSave();
      localStorage.setItem(BA_READ_KEY, String(Date.now()));
      renderBlockedAttempts();
    });
    renderBlockedAttempts();
  })();

  /* ---------- Server File Archive ---------- */
  let archiveFilesCache = [];

  function formatArchiveBytes(n) {
    const b = Number(n || 0);
    if (!b) return '—';
    if (b >= 1024 * 1024) return (b / (1024 * 1024)).toFixed(2) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  function renderArchiveFiles() {
    const body = $('archiveTableBody');
    const empty = $('archiveEmpty');
    if (!body || !empty) return;
    const chFilter = ($('archiveChannelFilter') && $('archiveChannelFilter').value) || '';
    const q = (($('archiveSearchInput') && $('archiveSearchInput').value) || '').trim().toLowerCase();
    const isLocalHost = Boolean(window.__TAURI__ && window.__TAURI__.core)
      || location.hostname === '127.0.0.1'
      || location.hostname === 'localhost';

    const filtered = archiveFilesCache.filter((f) => {
      const ch = String(f.channel || 'whatsapp_web').toLowerCase();
      if (chFilter === 'whatsapp_web' && !ch.includes('whatsapp')) return false;
      if (q) {
        const hay = [
          f.file_name,
          f.device_name,
          f.device_id,
          f.windows_user,
          f.recipient_name,
          f.recipient_phone,
          f.stored_path,
          f.sha256,
        ].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    let totalBytes = 0;
    let waCount = 0;
    archiveFilesCache.forEach((f) => {
      totalBytes += Number(f.file_size || 0);
      if (String(f.channel || 'whatsapp_web').toLowerCase().includes('whatsapp')) waCount++;
    });
    if ($('navArchiveCount')) $('navArchiveCount').textContent = archiveFilesCache.length;
    if ($('archiveStatsText')) {
      $('archiveStatsText').textContent =
        archiveFilesCache.length + ' ملف (' + waCount + ' واتساب · ' + formatArchiveBytes(totalBytes) + ')';
    }

    if (!filtered.length) {
      body.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    body.innerHTML = filtered.map((f) => {
      const ch = String(f.channel || 'whatsapp_web').toLowerCase();
      const chBadge = ch.includes('whatsapp')
        ? '<span class="badge green">واتساب</span>'
        : '<span class="badge">ويب</span>';
      const recipLine = esc(f.recipient_name || f.page_url || '—');
      const phoneLine = f.recipient_phone
        ? '<div class="mono" dir="ltr" style="font-size:11.5px;color:#2563eb;font-weight:700;">' + esc(f.recipient_phone) + '</div>'
        : '<div style="font-size:11px;color:#94a3b8;">بدون رقم ظاهر</div>';
      const shaShort = f.sha256 ? String(f.sha256).slice(0, 12) + '…' : '';
      const dlUrl = serverHttpBase + '/api/uploads/' + encodeURIComponent(f.file_id || '');
      const localBtn = (isLocalHost && f.stored_path)
        ? '<button class="btn btn-ghost btn-sm" type="button" data-open-archive-path="' + esc(f.stored_path) + '">📂 المجلد</button>'
        : '';
      return '<tr>' +
        '<td class="mono" style="font-size:11.5px;white-space:nowrap;">' + esc(ago(f.created_at)) + '</td>' +
        '<td><div style="font-weight:700;">' + esc(f.file_name || 'file.bin') + '</div>' +
          '<div style="font-size:11px;color:#94a3b8;margin-top:2px;">' +
            '<span class="mono">' + esc(formatArchiveBytes(f.file_size)) + '</span>' +
            (shaShort ? (' · <span class="badge green" style="font-size:10px;padding:1px 6px;" title="SHA-256: ' + esc(f.sha256) + '">✓ طبق الأصل ' + esc(shaShort) + '</span>') : '') +
          '</div></td>' +
        '<td>' + chBadge + '</td>' +
        '<td><div><b>' + esc(f.device_name || f.device_id || '—') + '</b></div>' +
          (f.windows_user ? ('<div class="mono" style="font-size:11px;color:#94a3b8;">' + esc(f.windows_user) + '</div>') : '') +
        '</td>' +
        '<td><div><b>' + recipLine + '</b></div>' + phoneLine + '</td>' +
        '<td><div style="display:flex;gap:6px;flex-wrap:wrap;">' +
          '<a class="btn btn-success btn-sm" data-download-upload="' + esc(f.file_id || '') + '" data-file-name="' + esc(f.file_name || 'file') + '" href="' + esc(dlUrl) + '" target="_blank" download="' + esc(f.file_name || 'file') + '" style="text-decoration:none;">⬇ تحميل النسخة الأصلية</a>' +
          localBtn +
        '</div></td>' +
      '</tr>';
    }).join('');
  }

  let archiveBusy = false;
  async function loadArchiveFiles() {
    if (!api.getUploadedFiles || archiveBusy) return;
    archiveBusy = true;
    try {
      const r = await api.getUploadedFiles(null);
      archiveFilesCache = (r && Array.isArray(r.files)) ? r.files : [];
      if ($('archiveRootPath') && r && r.archive_root) {
        $('archiveRootPath').textContent = r.archive_root;
      }
    } catch (e) {
      archiveFilesCache = [];
    } finally {
      archiveBusy = false;
    }
    renderArchiveFiles();
  }

  if ($('refreshArchiveBtn')) $('refreshArchiveBtn').addEventListener('click', loadArchiveFiles);
  if ($('archiveChannelFilter')) $('archiveChannelFilter').addEventListener('change', renderArchiveFiles);
  if ($('archiveSearchInput')) $('archiveSearchInput').addEventListener('input', renderArchiveFiles);
  if ($('openArchiveFolderBtn')) {
    $('openArchiveFolderBtn').addEventListener('click', async () => {
      try {
        const r = await api.openArchiveFolder(null);
        if (!r || r.success === false) {
          toast((r && r.error) || 'تعذر فتح مجلد الأرشيف', r && r.remote ? 'success' : 'error');
        }
      } catch (e) {
        toast(e.message || 'تعذر فتح مجلد الأرشيف', 'error');
      }
    });
  }
  document.addEventListener('click', async (e) => {
    const dlLink = e.target.closest('[data-download-upload]');
    if (dlLink && api.saveUploadedFile) {
      e.preventDefault();
      const fid = dlLink.dataset.downloadUpload || '';
      const fname = dlLink.dataset.fileName || '';
      toast('⬇ جارٍ تنزيل الملف الأصلي إلى مجلد Downloads...');
      try {
        const r = await api.saveUploadedFile(fid, fname);
        if (r && r.success) {
          toast('✓ تم حفظ الملف بنجاح في مجلد التنزيلات (Downloads)');
        } else {
          toast((r && r.error) || 'تعذر تحميل الملف الأصلي', 'error');
        }
      } catch (err) {
        toast(err.message || 'تعذر تحميل الملف الأصلي', 'error');
      }
      return;
    }
    const b = e.target.closest('[data-open-archive-path]');
    if (!b || !api.openArchiveFolder) return;
    try {
      const r = await api.openArchiveFolder(b.dataset.openArchivePath);
      if (!r || r.success === false) toast((r && r.error) || 'تعذر فتح موقع الملف', 'error');
    } catch (err) { toast(err.message || 'تعذر فتح موقع الملف', 'error'); }
  });

  /* ---------- Init ---------- */
  async function bootDashboardData() {
    await loadStatus();
    await loadSites();
    await loadConfig();
    await loadServerInfo();
    await loadDevices();
    if (devicesTimer) clearInterval(devicesTimer);
    devicesTimer = setInterval(loadDevices, 4000);
    await loadRelayConfig();
    loadRelayDevices();
    loadKpis();
    loadAdminUsers();
    startBlockedAttempts();
  }

  (async () => {
    if (isTokenValid(authToken)) {
      const payload = getTokenPayload(authToken);
      syncSessionIdentity(payload.sub, payload.role || 'admin', authToken);
      hideLoginModal();
      await bootDashboardData();
    } else {
      syncSessionIdentity('', '', '');
      showLoginModal();
    }
  })();
})();
