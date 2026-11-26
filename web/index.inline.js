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

  let latestClientVersion = '1.2.5';
  const SAVED_LOGIN_KEY = 'ibp_saved_admin_creds_v1';

  function compareSemver(a, b) {
    const pa = String(a || '0.0.0').trim().replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
    const pb = String(b || '0.0.0').trim().replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
    for (let i = 0; i < 3; i++) {
      const da = pa[i] || 0;
      const db = pb[i] || 0;
      if (da !== db) return da - db;
    }
    return 0;
  }

  function loadRememberedLogin() {
    try {
      const raw = localStorage.getItem(SAVED_LOGIN_KEY);
      if (!raw) return null;
      const obj = JSON.parse(decodeURIComponent(escape(atob(raw))));
      if (obj && typeof obj.u === 'string') return obj;
    } catch (e) {}
    return null;
  }

  function persistRememberedLogin(username, password, remember) {
    try {
      if (remember && username) {
        const enc = btoa(unescape(encodeURIComponent(JSON.stringify({ u: username, p: password || '' }))));
        localStorage.setItem(SAVED_LOGIN_KEY, enc);
      } else {
        localStorage.removeItem(SAVED_LOGIN_KEY);
      }
    } catch (e) {}
  }

  function applyRememberedLoginFields() {
    const saved = loadRememberedLogin();
    const uEl = $('loginUser');
    const pEl = $('loginPass');
    const rEl = $('loginRemember');
    if (saved) {
      if (uEl && !uEl.value) uEl.value = saved.u || '';
      if (pEl && !pEl.value) pEl.value = saved.p || '';
      if (rEl) rEl.checked = true;
    }
  }

  function syncSessionIdentity(username, role, token, remember) {
    authToken = token || '';
    currentAdminUser = username || '';
    currentAdminRole = role || '';
    window.currentAdminUser = currentAdminUser;
    window.currentAdminRole = currentAdminRole;
    if (api && api.setAuthToken) api.setAuthToken(authToken, remember);
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
    applyRememberedLoginFields();
    modal.classList.add('show');
    document.body.classList.add('auth-locked');
    setTimeout(() => {
      const u = $('loginUser');
      const p = $('loginPass');
      if (u && !u.value) u.focus();
      else if (p && !p.value) p.focus();
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
    const remember = $('loginRemember') ? Boolean($('loginRemember').checked) : true;
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
      const res = await api.adminLogin(username, password, remember);
      if (res && res.success) {
        persistRememberedLogin(username, password, remember);
        syncSessionIdentity(res.username || username, res.role || 'admin', res.token || '', remember);
        if (!remember && $('loginPass')) $('loginPass').value = '';
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

  if ($('loginRemember')) {
    $('loginRemember').addEventListener('change', (e) => {
      if (!e.target.checked) {
        persistRememberedLogin('', '', false);
      }
    });
  }

  // لا نعرض عنوان IP الداخلي للسيرفر في شاشة الدخول قبل المصادقة حفاظاً على سرية الشبكة الداخلية.
  function updateAuthServerStatus() {
    const el = $('authServerStatus');
    if (!el) return;
    el.classList.add('ok');
    if (el.lastElementChild) {
      el.lastElementChild.textContent = '🔒 اتصال مشفّر وآمن — بوابة الإدارة المعتمدة';
    }
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
      if (item.dataset.view === 'wabot') { loadWaBotStatus(false); startWaBotPoll(); }
      else { stopWaBotPoll(); }
      if (item.dataset.view === 'cameras') { openCamerasView(); }
      else { stopCctvWall(); }
      if (item.dataset.view === 'biometrics') { openBiometricsView(); }
      else { stopBiometricsPoll(); }
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

  const SITE_PRESETS = {
    allow_ms365: { kind: 'allowed', list: ['office.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'sharepoint.com', 'teams.microsoft.com', 'microsoft.com'] },
    allow_google: { kind: 'allowed', list: ['google.com', 'mail.google.com', 'drive.google.com', 'docs.google.com', 'gstatic.com', 'googleapis.com', 'accounts.google.com'] },
    allow_whatsapp: { kind: 'allowed', list: ['web.whatsapp.com', 'whatsapp.com', 'whatsapp.net'] },
    block_social: { kind: 'blocked', list: ['facebook.com', 'instagram.com', 'tiktok.com', 'twitter.com', 'x.com', 'snapchat.com', 'reddit.com'] },
    block_video: { kind: 'blocked', list: ['youtube.com', 'youtu.be', 'netflix.com', 'shahid.mbc.net', 'twitch.tv', 'dailymotion.com'] },
    block_fileshare: { kind: 'blocked', list: ['wetransfer.com', 'mega.nz', 'mediafire.com', '4shared.com', 'sendspace.com', 'gofile.io'] },
    block_ai: { kind: 'blocked', list: ['chatgpt.com', 'openai.com', 'claude.ai', 'gemini.google.com', 'deepseek.com', 'perplexity.ai'] },
  };

  async function saveDownloadText(content, fileName, mimeType) {
    if (api.saveTextFile) {
      const r = await api.saveTextFile(content, fileName);
      if (r && r.success) {
        toast('✓ تم حفظ التقرير في مجلد التنزيلات (Downloads)');
        return true;
      }
      toast((r && r.error) || 'تعذر حفظ التقرير', 'error');
      return false;
    }
    const prefix = fileName.toLowerCase().endsWith('.csv') ? '\uFEFF' : '';
    const blob = new Blob([prefix + content], { type: mimeType || 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast('✓ جارٍ تنزيل التقرير');
    return true;
  }

  function csvCell(val) {
    const s = String(val == null ? '' : val).replace(/"/g, '""');
    return '"' + s + '"';
  }

  async function addTo(inputId, fn, kind) {
    const rawVal = $(inputId).value.trim();
    if (!rawVal) { toast('اكتب اسم الموقع', 'error'); return; }
    const parts = rawVal.split(/[\s,;]+/).map(cleanDomain).filter(Boolean);
    if (!parts.length) { toast('اسم موقع غير صالح', 'error'); return; }
    try {
      if (parts.length > 1 && api.addSitesBulk) {
        const r = await api.addSitesBulk(parts, kind || 'allowed');
        if (r && r.success === false) {
          toast(r.error || 'فشلت الإضافة', 'error');
          return;
        }
        $(inputId).value = '';
        await loadSites();
        toast('تمت إضافة ' + (r.added || parts.length) + ' موقع ومزامنتها');
        return;
      }
      const r = await fn(parts[0]);
      if (r && r.success === false) {
        toast(r.error || 'فشلت الإضافة', 'error');
        return;
      }
      $(inputId).value = '';
      await loadSites();
      toast('تمت الإضافة');
    } catch (err) { toast('حدث خطأ: ' + err.message, 'error'); }
  }

  $('addSiteBtn').addEventListener('click', () => addTo('newSiteInput', (v) => api.addSite(v), 'allowed'));
  $('addBlockedBtn').addEventListener('click', () => addTo('newBlockedInput', (v) => api.addBlockedSite(v), 'blocked'));
  if ($('syncSitesNowBtn')) {
    $('syncSitesNowBtn').addEventListener('click', async () => {
      try {
        const r = await api.syncPolicy();
        if (r && r.success !== false) toast('✓ تمت مزامنة قوائم المواقع مع كل الأجهزة');
        else toast((r && r.error) || 'تعذرت المزامنة', 'error');
      } catch (e) { toast(e.message || 'تعذرت المزامنة', 'error'); }
    });
  }
  document.addEventListener('click', async (e) => {
    const presetBtn = e.target.closest('[data-site-preset]');
    if (!presetBtn) return;
    const preset = SITE_PRESETS[presetBtn.dataset.sitePreset];
    if (!preset) return;
    try {
      if (api.addSitesBulk) {
        const r = await api.addSitesBulk(preset.list, preset.kind);
        if (r && r.success !== false) {
          await loadSites();
          toast('✓ تمت إضافة القائمة الجاهزة (' + (r.added || 0) + ' نطاق جديد) ومزامنتها');
        } else toast((r && r.error) || 'فشلت الإضافة', 'error');
      } else {
        for (const dom of preset.list) {
          if (preset.kind === 'blocked') await api.addBlockedSite(dom);
          else await api.addSite(dom);
        }
        await loadSites();
        toast('✓ تمت إضافة القائمة الجاهزة');
      }
    } catch (err) { toast(err.message || 'فشلت الإضافة', 'error'); }
  });
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
    if ($('usbBlockToggle')) $('usbBlockToggle').checked = !!c.usb_block;
    if ($('dlpSuperOnlyToggle')) {
      $('dlpSuperOnlyToggle').checked = !!c.dlp_super_only;
      $('dlpSuperOnlyToggle').disabled = !hasSuperAdminAccess();
    }
    const archNav = document.querySelector('.nav-item[data-view="archive"]');
    if (archNav) {
      archNav.style.display = (c.dlp_super_only && !hasSuperAdminAccess()) ? 'none' : '';
    }
    if ($('exfilThresholdInput')) $('exfilThresholdInput').value = c.exfil_threshold_mb || 50;
    if ($('exfilWindowInput')) $('exfilWindowInput').value = c.exfil_window_secs || 600;
    if ($('exfilSuspiciousInput')) $('exfilSuspiciousInput').value = Array.isArray(c.exfil_suspicious) ? c.exfil_suspicious.join('\n') : '';
    if ($('erpDomainsInput')) {
      const erpList = Array.isArray(c.erp_domains) && c.erp_domains.length ? c.erp_domains : ['elkhawaga.uk'];
      $('erpDomainsInput').value = erpList.join('\n');
    }
    if ($('erpMasterTokenInput') && typeof c.erp_master_token === 'string' && c.erp_master_token) {
      $('erpMasterTokenInput').value = c.erp_master_token;
    }
    renderMode();
    loadBackupsList();
    loadErpBackupsStatus();
  }

  function renderServerDriveButtons(containerId, targetInputId, subfolderName, drives) {
    const bar = $(containerId);
    if (!bar) return;
    if (!Array.isArray(drives) || !drives.length) {
      bar.innerHTML = '<span style="font-size:12px;color:var(--muted);">اكتب مسار الهارد الجديد بالأسفل (مثال: D:\\' + subfolderName + ')</span>';
      return;
    }
    bar.innerHTML = drives.map((d) => {
      const freeGb = ((Number(d.free_bytes || 0)) / (1024 * 1024 * 1024)).toFixed(1);
      const totGb = ((Number(d.total_bytes || 0)) / (1024 * 1024 * 1024)).toFixed(0);
      const suggested = String(d.letter || 'D:') + '\\' + subfolderName;
      return '<button type="button" class="btn btn-ghost btn-sm" data-pick-drive-input="' + esc(targetInputId) + '" data-pick-drive-path="' + esc(suggested) + '">' +
        '💿 القرص <b class="mono" dir="ltr">' + esc(d.letter) + '</b> (متاح ' + freeGb + ' GB من ' + totGb + ' GB)</button>';
    }).join('');
  }

  async function loadBackupsList() {
    if (!api.getBackupsList || !$('backupsListBox')) return;
    const isLocalHost = Boolean(window.__TAURI__ && window.__TAURI__.core && location.hostname === 'localhost')
      && false;
    if ($('openBackupsDirBtn')) {
      $('openBackupsDirBtn').style.display = (api.openBackupsFolder && $('adminUpdateStatusBadge') && $('adminUpdateStatusBadge').textContent.includes('الرئيسي')) ? '' : 'none';
    }
    if ($('browseBackupDirBtn')) {
      $('browseBackupDirBtn').style.display = (api.browseBackupFolder && $('adminUpdateStatusBadge') && $('adminUpdateStatusBadge').textContent.includes('الرئيسي')) ? '' : 'none';
    }
    if ($('toggleBackupPathBtn')) {
      $('toggleBackupPathBtn').style.display = hasSuperAdminAccess() ? '' : 'none';
    }
    try {
      const r = await api.getBackupsList();
      if (r && r.backups_dir) {
        if ($('backupsDirPathText')) $('backupsDirPathText').textContent = r.backups_dir;
        if ($('backupDirInput') && document.activeElement !== $('backupDirInput')) {
          $('backupDirInput').value = r.backups_dir;
        }
      }
      if (r && r.disk_total_bytes) {
        const bBadge = $('backupDiskSpaceBadge');
        if (bBadge) {
          const fGb = (Number(r.disk_free_bytes || 0) / (1024 * 1024 * 1024)).toFixed(1);
          const tGb = (Number(r.disk_total_bytes || 0) / (1024 * 1024 * 1024)).toFixed(0);
          bBadge.style.display = 'inline-flex';
          bBadge.textContent = '💾 متاح بالقرص: ' + fGb + ' GB من ' + tGb + ' GB';
          bBadge.className = Number(r.disk_free_bytes || 0) < 5 * 1073741824 ? 'badge red'
            : Number(r.disk_free_bytes || 0) < 15 * 1073741824 ? 'badge gold' : 'badge green';
        }
      }
      if (r && Array.isArray(r.drives)) {
        renderServerDriveButtons('backupServerDrivesBar', 'backupDirInput', 'IT-ELKHAWGA-Backups', r.drives);
      }
      const list = (r && Array.isArray(r.backups)) ? r.backups : [];
      if (!list.length) {
        $('backupsListBox').innerHTML = '<div class="empty">جاري تجهيز أول نسخة احتياطية تلقائية... يمكنك أيضاً الضغط على «إنشاء نسخة احتياطية الآن»</div>';
        return;
      }
      const isSuper = hasSuperAdminAccess();
      $('backupsListBox').innerHTML = list.slice(0, 10).map((b) => {
        const dtStr = b.created_at ? new Date(b.created_at).toLocaleString('ar-EG') : b.id;
        const reasonLabel = b.reason === 'auto_daily' ? 'تلقائية يومية'
          : b.reason === 'pre_restore' ? 'قبل الاستعادة'
          : 'يدوية فورية';
        const badgeCls = b.reason === 'auto_daily' ? 'green' : 'violet';
        const sizeStr = formatArchiveBytes(b.total_bytes || 0);
        const restoreBtn = isSuper
          ? '<button class="btn btn-ghost btn-sm" type="button" data-restore-backup="' + esc(b.id) + '">♻ استعادة هذه النسخة</button>'
          : '';
        return '<div class="list-item" style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">' +
          '<div>' +
          '<b class="mono" dir="ltr">' + esc(b.id) + '</b> ' +
          '<span class="badge ' + badgeCls + '" style="margin-inline-start:6px;">' + reasonLabel + '</span>' +
          '<div style="font-size:11.5px;color:var(--muted);margin-top:2px;">التاريخ: ' + esc(dtStr) + ' · الملفات: ' + Number(b.files_count || 0) + ' · الحجم: <span class="mono">' + esc(sizeStr) + '</span></div>' +
          '</div>' +
          '<div>' + restoreBtn + '</div>' +
          '</div>';
      }).join('');
    } catch (_) {}
  }

  if ($('toggleBackupPathBtn')) {
    $('toggleBackupPathBtn').addEventListener('click', () => {
      const box = $('backupStorageCard');
      if (!box) return;
      box.style.display = box.style.display === 'none' ? 'block' : 'none';
      if (box.style.display === 'block') loadBackupsList();
    });
  }
  if ($('browseBackupDirBtn')) {
    $('browseBackupDirBtn').addEventListener('click', async () => {
      if (!api.browseBackupFolder) return;
      try {
        const r = await api.browseBackupFolder();
        if (r && r.success && r.path && $('backupDirInput')) $('backupDirInput').value = r.path;
      } catch (e) { toast(e.message || 'تعذر فتح مستعرض المجلدات', 'error'); }
    });
  }
  async function applyBackupDirChange(pathStr) {
    if (!api.setBackupDir) return;
    const moveExisting = Boolean($('moveExistingBackupsChk') && $('moveExistingBackupsChk').checked);
    const btn = $('saveBackupDirBtn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = '⏳ جارٍ التطبيق...'; }
    try {
      const r = await api.setBackupDir(pathStr, moveExisting);
      if (r && r.success) {
        const movedMsg = r.moved_files ? (' (تم نقل ' + r.moved_files + ' ملف تلقائياً)') : '';
        toast('✓ تم تحديث مسار حفظ النسخ الاحتياطية على السيرفر' + movedMsg);
        if ($('backupStorageCard')) $('backupStorageCard').style.display = 'none';
        await loadBackupsList();
      } else {
        toast((r && r.error) || 'تعذر تغيير مسار النسخ الاحتياطية', 'error');
      }
    } catch (e) {
      toast(e.message || 'تعذر تغيير مسار النسخ الاحتياطية', 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
  }
  if ($('saveBackupDirBtn')) {
    $('saveBackupDirBtn').addEventListener('click', () => {
      const target = (($('backupDirInput') && $('backupDirInput').value) || '').trim();
      if (!target) { toast('اختر القرص الجديد أو اكتب المسار أولاً', 'error'); return; }
      applyBackupDirChange(target);
    });
  }
  if ($('resetBackupDirBtn')) {
    $('resetBackupDirBtn').addEventListener('click', () => {
      if (!confirm('إعادة مسار النسخ الاحتياطية ليتبع مجلد الأرشيف تلقائياً؟')) return;
      applyBackupDirChange('');
    });
  }
  document.addEventListener('click', (e) => {
    const dp = e.target.closest('[data-pick-drive-input]');
    if (!dp) return;
    const inp = $(dp.dataset.pickDriveInput || '');
    if (inp) {
      inp.value = dp.dataset.pickDrivePath || '';
      inp.focus();
      toast('تم اختيار المسار: ' + inp.value + ' — اضغط «حفظ وتطبيق المسار» للتنفيذ');
    }
  });

  if ($('createBackupBtn')) {
    $('createBackupBtn').addEventListener('click', async () => {
      if (!api.createSystemBackup) return;
      const btn = $('createBackupBtn');
      const orig = btn.textContent;
      btn.disabled = true;
      btn.textContent = '⏳ جارٍ الحفظ...';
      try {
        const r = await api.createSystemBackup();
        if (r && r.success) {
          toast('✓ تم إنشاء النسخة الاحتياطية بنجاح (' + (r.id || '') + ')');
          await loadBackupsList();
        } else {
          toast((r && r.error) || 'فشل إنشاء النسخة الاحتياطية', 'error');
        }
      } catch (e) {
        toast(e.message || 'فشل إنشاء النسخة الاحتياطية', 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  }
  if ($('refreshBackupsBtn')) $('refreshBackupsBtn').addEventListener('click', loadBackupsList);
  if ($('openBackupsDirBtn')) {
    $('openBackupsDirBtn').addEventListener('click', async () => {
      if (!api.openBackupsFolder) return;
      const r = await api.openBackupsFolder();
      if (!r || r.success === false) toast((r && r.error) || 'تعذر فتح المجلد', 'error');
    });
  }

  /* ---------- Automated Hourly ERP Website Backups (elkhawaga.uk) ---------- */
  let erpBackupPollTimer = null;
  let lastErpBackupRunning = false;

  async function loadErpBackupsStatus() {
    if (!api.getErpBackupsStatus || !$('erpBackupsListBox')) return;
    const isSuper = hasSuperAdminAccess();
    if ($('openErpBackupsDirBtn')) {
      $('openErpBackupsDirBtn').style.display = (api.openErpBackupsFolder && $('adminUpdateStatusBadge') && $('adminUpdateStatusBadge').textContent.includes('الرئيسي')) ? '' : 'none';
    }
    if ($('browseErpBackupDirBtn')) {
      $('browseErpBackupDirBtn').style.display = (api.browseErpBackupFolder && $('adminUpdateStatusBadge') && $('adminUpdateStatusBadge').textContent.includes('الرئيسي')) ? '' : 'none';
    }
    if ($('toggleErpBackupPathBtn')) $('toggleErpBackupPathBtn').style.display = isSuper ? '' : 'none';
    if ($('runErpBackupNowBtn')) $('runErpBackupNowBtn').style.display = isSuper ? '' : 'none';
    if ($('saveErpBackupConfigBtn')) $('saveErpBackupConfigBtn').style.display = isSuper ? '' : 'none';
    if ($('erpBackupEnabledToggle')) $('erpBackupEnabledToggle').disabled = !isSuper;

    try {
      const r = await api.getErpBackupsStatus();
      if (!r) return;
      if (r.erp_backups_dir) {
        if ($('erpBackupsDirPathText')) $('erpBackupsDirPathText').textContent = r.erp_backups_dir;
        if ($('erpBackupDirInput') && document.activeElement !== $('erpBackupDirInput')) {
          $('erpBackupDirInput').value = r.erp_backups_dir;
        }
      }
      if (r.disk_total_bytes && $('erpBackupDiskSpaceBadge')) {
        const bBadge = $('erpBackupDiskSpaceBadge');
        const fGb = (Number(r.disk_free_bytes || 0) / (1024 * 1024 * 1024)).toFixed(1);
        const tGb = (Number(r.disk_total_bytes || 0) / (1024 * 1024 * 1024)).toFixed(0);
        bBadge.style.display = 'inline-flex';
        bBadge.textContent = '💾 متاح بالقرص: ' + fGb + ' GB من ' + tGb + ' GB';
        bBadge.className = Number(r.disk_free_bytes || 0) < 5 * 1073741824 ? 'badge red'
          : Number(r.disk_free_bytes || 0) < 15 * 1073741824 ? 'badge gold' : 'badge green';
      }
      if (Array.isArray(r.drives)) {
        renderServerDriveButtons('erpBackupServerDrivesBar', 'erpBackupDirInput', 'Elkhawaga-ERP-Backups', r.drives);
      }

      const cfg = r.config || {};
      if ($('erpBackupEnabledToggle') && document.activeElement !== $('erpBackupEnabledToggle')) {
        $('erpBackupEnabledToggle').checked = Boolean(cfg.enabled);
      }
      if ($('erpBackupIntervalSelect') && document.activeElement !== $('erpBackupIntervalSelect')) {
        $('erpBackupIntervalSelect').value = String(cfg.interval_mins || 60);
      }
      if ($('erpBackupUrlInput') && document.activeElement !== $('erpBackupUrlInput') && cfg.url) {
        $('erpBackupUrlInput').value = cfg.url;
      }
      if ($('erpBackupUserInput') && document.activeElement !== $('erpBackupUserInput') && typeof cfg.username === 'string' && !$('erpBackupUserInput').dataset.dirty) {
        $('erpBackupUserInput').value = cfg.username;
      }
      if ($('erpBackupPassSavedBadge')) {
        $('erpBackupPassSavedBadge').style.display = cfg.has_password ? 'inline-flex' : 'none';
      }

      const st = r.status || {};
      const schedBadge = $('erpBackupScheduleBadge');
      if (schedBadge) {
        if (st.running) {
          schedBadge.className = 'badge violet';
          schedBadge.textContent = '⏳ جاري السحب والفحص الآن...';
        } else if (cfg.enabled) {
          const hrs = Math.round((Number(cfg.interval_mins || 60) / 60) * 10) / 10;
          schedBadge.className = 'badge green';
          schedBadge.textContent = hrs === 1 ? '✓ يعمل تلقائياً كل ساعة' : ('✓ يعمل تلقائياً كل ' + hrs + ' ساعات');
        } else {
          schedBadge.className = 'badge gold';
          schedBadge.textContent = 'متوقف (يدوي فقط)';
        }
      }

      const banner = $('erpBackupLiveBanner');
      if (banner) {
        if (st.running) {
          banner.style.display = 'block';
          banner.style.background = 'rgba(37,99,235,0.10)';
          banner.style.border = '1px solid rgba(37,99,235,0.30)';
          banner.style.color = '#1d4ed8';
          banner.textContent = '⏳ ' + (st.stage || 'جاري الاتصال بموقع elkhawaga.uk وسحب النسخة الاحتياطية...');
        } else if (st.last_error) {
          banner.style.display = 'block';
          banner.style.background = 'rgba(220,38,38,0.10)';
          banner.style.border = '1px solid rgba(220,38,38,0.32)';
          banner.style.color = '#dc2626';
          banner.textContent = '⚠ آخر محاولة سحب: ' + st.last_error;
        } else if (st.stage) {
          banner.style.display = 'block';
          banner.style.background = 'rgba(16,185,129,0.10)';
          banner.style.border = '1px solid rgba(16,185,129,0.30)';
          banner.style.color = '#059669';
          banner.textContent = st.stage;
        } else {
          banner.style.display = 'none';
        }
      }

      if (st.running) {
        lastErpBackupRunning = true;
        if (!erpBackupPollTimer) {
          erpBackupPollTimer = setInterval(loadErpBackupsStatus, 2500);
        }
      } else {
        if (lastErpBackupRunning) {
          lastErpBackupRunning = false;
          if (!st.last_error) toast('✓ اكتمل سحب وفحص النسخة الاحتياطية لموقع الشركة بنجاح!');
          else toast(st.last_error, 'error');
        }
        if (erpBackupPollTimer) {
          clearInterval(erpBackupPollTimer);
          erpBackupPollTimer = null;
        }
      }

      const list = Array.isArray(r.backups) ? r.backups : [];
      if (!list.length) {
        $('erpBackupsListBox').innerHTML = '<div class="empty">لم يتم سحب أي نسخة من الموقع بعد — أدخل اسم المستخدم وكلمة مرور أدمن الموقع بالأعلى ثم اضغط «⚡ سحب وفحص نسخة من الموقع الآن»</div>';
        return;
      }
      const authTok = (api.getAuthToken && api.getAuthToken()) || '';
      $('erpBackupsListBox').innerHTML = list.slice(0, 15).map((b) => {
        const dtStr = b.created_at ? new Date(b.created_at).toLocaleString('ar-EG') : b.file_name;
        const sizeStr = formatArchiveBytes(b.size_bytes || 0);
        const durSec = b.duration_ms ? ((Number(b.duration_ms) / 1000).toFixed(1) + ' ث') : '—';
        const shaShort = b.sha256 ? (String(b.sha256).slice(0, 12) + '…') : '';
        const isAuto = String(b.reason || '').startsWith('auto');
        const reasonText = isAuto ? 'تلقائية مجدولة' : 'سحب فوري';
        const dlUrl = serverHttpBase + '/api/erp-backups/download/' + encodeURIComponent(b.file_name || '') + (authTok ? ('?token=' + encodeURIComponent(authTok)) : '');
        const dlBtn = isSuper
          ? '<a class="btn btn-success btn-sm" href="' + esc(dlUrl) + '" target="_blank" rel="noreferrer" download="' + esc(b.file_name || 'backup.zip') + '" style="text-decoration:none;">⬇ تحميل النسخة</a>'
          : '';
        return '<div class="list-item" style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">' +
          '<div>' +
          '<b class="mono" dir="ltr">' + esc(b.file_name) + '</b> ' +
          '<span class="badge green" style="margin-inline-start:6px;">' + esc(b.format || '✓ مفحوص') + '</span> ' +
          '<span class="badge ' + (isAuto ? 'violet' : 'gold') + '" style="margin-inline-start:4px;">' + reasonText + '</span>' +
          '<div style="font-size:11.5px;color:var(--muted);margin-top:3px;">التاريخ: ' + esc(dtStr) + ' · الحجم: <b class="mono">' + esc(sizeStr) + '</b> · زمن السحب: ' + esc(durSec) + (shaShort ? (' · SHA-256: <span class="mono" dir="ltr">' + esc(shaShort) + '</span>') : '') + '</div>' +
          '</div>' +
          '<div>' + dlBtn + '</div>' +
          '</div>';
      }).join('');
    } catch (_) {}
  }

  if ($('erpBackupUserInput')) {
    $('erpBackupUserInput').addEventListener('input', () => {
      $('erpBackupUserInput').dataset.dirty = '1';
    });
  }
  if ($('saveErpBackupConfigBtn')) {
    $('saveErpBackupConfigBtn').addEventListener('click', async () => {
      if (!api.saveErpBackupConfig) return;
      const enabled = Boolean($('erpBackupEnabledToggle') && $('erpBackupEnabledToggle').checked);
      const mins = parseInt(($('erpBackupIntervalSelect') && $('erpBackupIntervalSelect').value) || '60', 10) || 60;
      const url = (($('erpBackupUrlInput') && $('erpBackupUrlInput').value) || 'https://elkhawaga.uk').trim();
      const user = (($('erpBackupUserInput') && $('erpBackupUserInput').value) || '').trim();
      const pass = ($('erpBackupPassInput') && $('erpBackupPassInput').value) || '';
      if (!user) {
        toast('يرجى إدخال اسم مستخدم أدمن الموقع أولاً', 'error');
        return;
      }
      try {
        const r = await api.saveErpBackupConfig(enabled, mins, url, user, pass || null, null, null);
        if (r && r.success !== false) {
          if ($('erpBackupPassInput')) $('erpBackupPassInput').value = '';
          if ($('erpBackupUserInput')) delete $('erpBackupUserInput').dataset.dirty;
          toast(enabled ? '✓ تم حفظ الإعدادات وتفعيل السحب التلقائي الدوري للموقع!' : '✓ تم حفظ بيانات الربط بموقع الشركة بنجاح');
          await loadErpBackupsStatus();
        } else {
          toast((r && r.error) || 'تعذر حفظ إعدادات النسخ الاحتياطي للموقع', 'error');
        }
      } catch (e) {
        toast(e.message || 'تعذر حفظ الإعدادات', 'error');
      }
    });
  }

  if ($('runErpBackupNowBtn')) {
    $('runErpBackupNowBtn').addEventListener('click', async () => {
      if (!api.runErpBackupNow) return;
      // Auto-save username/password first if user typed them and clicked Run Now directly!
      const user = (($('erpBackupUserInput') && $('erpBackupUserInput').value) || '').trim();
      const pass = ($('erpBackupPassInput') && $('erpBackupPassInput').value) || '';
      if (user && (pass || ($('erpBackupUserInput') && $('erpBackupUserInput').dataset.dirty))) {
        const enabled = Boolean($('erpBackupEnabledToggle') && $('erpBackupEnabledToggle').checked);
        const mins = parseInt(($('erpBackupIntervalSelect') && $('erpBackupIntervalSelect').value) || '60', 10) || 60;
        const url = (($('erpBackupUrlInput') && $('erpBackupUrlInput').value) || 'https://elkhawaga.uk').trim();
        await api.saveErpBackupConfig(enabled, mins, url, user, pass || null, null, null).catch(() => {});
        if ($('erpBackupPassInput')) $('erpBackupPassInput').value = '';
        if ($('erpBackupUserInput')) delete $('erpBackupUserInput').dataset.dirty;
      }
      try {
        const r = await api.runErpBackupNow();
        if (r && r.success !== false) {
          toast('⏳ بدأ الاتصال بموقع elkhawaga.uk لإنشاء وسحب النسخة الاحتياطية...');
          await loadErpBackupsStatus();
        } else {
          toast((r && r.error) || 'تعذر بدء سحب النسخة الاحتياطية', 'error');
        }
      } catch (e) {
        toast(e.message || 'تعذر بدء سحب النسخة الاحتياطية', 'error');
      }
    });
  }

  if ($('refreshErpBackupsBtn')) $('refreshErpBackupsBtn').addEventListener('click', loadErpBackupsStatus);
  if ($('openErpBackupsDirBtn')) {
    $('openErpBackupsDirBtn').addEventListener('click', async () => {
      if (!api.openErpBackupsFolder) return;
      const r = await api.openErpBackupsFolder();
      if (!r || r.success === false) toast((r && r.error) || 'تعذر فتح المجلد', 'error');
    });
  }
  if ($('toggleErpBackupPathBtn')) {
    $('toggleErpBackupPathBtn').addEventListener('click', () => {
      const box = $('erpBackupStorageCard');
      if (!box) return;
      box.style.display = box.style.display === 'none' ? 'block' : 'none';
      if (box.style.display === 'block') loadErpBackupsStatus();
    });
  }
  if ($('browseErpBackupDirBtn')) {
    $('browseErpBackupDirBtn').addEventListener('click', async () => {
      if (!api.browseErpBackupFolder) return;
      try {
        const r = await api.browseErpBackupFolder();
        if (r && r.success && r.path && $('erpBackupDirInput')) $('erpBackupDirInput').value = r.path;
      } catch (e) { toast(e.message || 'تعذر فتح مستعرض المجلدات', 'error'); }
    });
  }
  async function applyErpBackupDirChange(pathStr) {
    if (!api.setErpBackupDir) return;
    const moveExisting = Boolean($('moveExistingErpBackupsChk') && $('moveExistingErpBackupsChk').checked);
    const btn = $('saveErpBackupDirBtn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = '⏳ جارٍ التطبيق...'; }
    try {
      const r = await api.setErpBackupDir(pathStr, moveExisting);
      if (r && r.success) {
        const movedMsg = r.moved_files ? (' (تم نقل ' + r.moved_files + ' ملف تلقائياً)') : '';
        toast('✓ تم تحديث مسار حفظ نسخ موقع الشركة على السيرفر' + movedMsg);
        if ($('erpBackupStorageCard')) $('erpBackupStorageCard').style.display = 'none';
        await loadErpBackupsStatus();
      } else {
        toast((r && r.error) || 'تعذر تغيير مسار نسخ الموقع', 'error');
      }
    } catch (e) {
      toast(e.message || 'تعذر تغيير مسار نسخ الموقع', 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
  }
  if ($('saveErpBackupDirBtn')) {
    $('saveErpBackupDirBtn').addEventListener('click', () => {
      const target = (($('erpBackupDirInput') && $('erpBackupDirInput').value) || '').trim();
      if (!target) { toast('اختر القرص الجديد أو اكتب المسار أولاً', 'error'); return; }
      applyErpBackupDirChange(target);
    });
  }
  if ($('resetErpBackupDirBtn')) {
    $('resetErpBackupDirBtn').addEventListener('click', () => {
      if (!confirm('إعادة مسار حفظ نسخ الموقع إلى المسار التلقائي؟')) return;
      applyErpBackupDirChange('');
    });
  }
  document.addEventListener('click', async (e) => {
    const rb = e.target.closest('[data-restore-backup]');
    if (!rb || !api.restoreSystemBackup) return;
    const bid = rb.dataset.restoreBackup || '';
    if (!bid) return;
    if (!confirm('استعادة النسخة الاحتياطية (' + bid + ')؟\n\nسيقوم النظام أولاً بأخذ نسخة أمان احتياطية للحالة الحالية، ثم يستعيد إعدادات وقوائم المواقع والمجموعات والأجهزة من النسخة المختارة.')) return;
    try {
      const r = await api.restoreSystemBackup(bid);
      if (r && r.success) {
        toast('✓ تمت استعادة النسخة الاحتياطية بنجاح ومزامنة الإعدادات');
        await loadSites();
        await loadConfig();
        await loadDevices();
        await loadRelayDevices();
      } else {
        toast((r && r.error) || 'تعذرت الاستعادة', 'error');
      }
    } catch (err) {
      toast(err.message || 'تعذرت الاستعادة', 'error');
    }
  });

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

  if ($('fillSuspiciousBtn')) {
    $('fillSuspiciousBtn').addEventListener('click', () => {
      const defaults = ['wetransfer.com', 'mega.nz', 'mediafire.com', 'gofile.io', 'sendspace.com', '4shared.com', 'dropbox.com'];
      const cur = ($('exfilSuspiciousInput').value || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      defaults.forEach((d) => { if (!cur.includes(d)) cur.push(d); });
      $('exfilSuspiciousInput').value = cur.join('\n');
      toast('تم إدراج أشهر مواقع رفع الملفات — اضغط حفظ لتطبيقها');
    });
  }
  if ($('copyErpMasterTokenBtn')) {
    $('copyErpMasterTokenBtn').addEventListener('click', async () => {
      const v = ($('erpMasterTokenInput') && $('erpMasterTokenInput').value || '').trim();
      if (!v) return;
      try {
        await navigator.clipboard.writeText(v);
        toast('✓ تم نسخ كود ربط السيستم: ' + v);
      } catch (_) {
        toast('تعذر النسخ التلقائي — انسخ الكود يدوياً', 'error');
      }
    });
  }
  if ($('saveDlpConfigBtn')) {
    $('saveDlpConfigBtn').addEventListener('click', async () => {
      if (!api.setDlpConfig) return;
      const usbBlock = Boolean($('usbBlockToggle') && $('usbBlockToggle').checked);
      const dlpSuperOnly = Boolean($('dlpSuperOnlyToggle') && $('dlpSuperOnlyToggle').checked);
      const thresh = parseInt(($('exfilThresholdInput') && $('exfilThresholdInput').value) || '50', 10) || 50;
      const winSecs = parseInt(($('exfilWindowInput') && $('exfilWindowInput').value) || '600', 10) || 600;
      const susp = (($('exfilSuspiciousInput') && $('exfilSuspiciousInput').value) || '')
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      const erpDomains = (($('erpDomainsInput') && $('erpDomainsInput').value) || 'elkhawaga.uk')
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      const erpMasterToken = (($('erpMasterTokenInput') && $('erpMasterTokenInput').value) || '').trim();
      try {
        const r = await api.setDlpConfig(usbBlock, thresh, winSecs, susp, dlpSuperOnly, erpDomains, erpMasterToken);
        if (r && r.success !== false) {
          toast('✓ تم حفظ سياسات الحماية وربط سيستم الشركة ومزامنتها لكل الأجهزة');
          await loadConfig();
        } else toast((r && r.error) || 'فشل الحفظ', 'error');
      } catch (e) { toast(e.message || 'فشل الحفظ', 'error'); }
    });
  }

  let adminUpdateBusy = false;
  async function refreshAdminUpdateUi(manualToast) {
    if (!api.checkAdminUpdate) return;
    try {
      const info = await api.checkAdminUpdate();
      const topBtn = $('adminUpdateTopBtn');
      const badge = $('adminUpdateStatusBadge');
      const details = $('adminUpdateDetailsText');
      const runBtn = $('runAdminUpdateBtn');
      if (!api.applyAdminUpdate) {
        if (topBtn) topBtn.style.display = 'none';
        if (badge) { badge.className = 'badge green'; badge.textContent = 'وضع المتصفح (محدّث تلقائياً)'; }
        if (runBtn) runBtn.textContent = '↻ تحديث واجهة المتصفح';
        return;
      }
      if (info && info.is_host_server) {
        if (topBtn) topBtn.style.display = 'none';
        if (badge) { badge.className = 'badge green'; badge.textContent = '✓ السيرفر الرئيسي (أحدث نسخة)'; }
        if (details && info.remote_mtime_ms) {
          details.innerHTML = 'أنت تعمل على السيرفر الرئيسي مباشرة. آخر حزمة تحديث للأدمن جاهزة للمهندسين بتاريخ: <b>' + esc(new Date(info.remote_mtime_ms).toLocaleString('ar-EG')) + '</b>.';
        }
        if (manualToast) toast('✓ هذا هو السيرفر الرئيسي ويعمل بأحدث إصدار');
        return;
      }
      if (info && info.available) {
        const dtStr = info.remote_mtime_ms ? new Date(info.remote_mtime_ms).toLocaleString('ar-EG') : '';
        if (info.update_available) {
          if (topBtn) topBtn.style.display = '';
          if (badge) { badge.className = 'badge gold'; badge.textContent = '⬆ يتوفر تحديث جديد على السيرفر'; }
          if (details) details.innerHTML = 'يتوفر إصدار أحدث من برنامج الأدمن على السيرفر بتاريخ <b>' + esc(dtStr) + '</b> — اضغط «تحديث برنامج الأدمن أونلاين الآن» للتنزيل والتثبيت التلقائي.';
          if (manualToast) toast('⬆ يتوفر تحديث جديد لبرنامج الأدمن على السيرفر!');
        } else {
          if (topBtn) topBtn.style.display = 'none';
          if (badge) { badge.className = 'badge green'; badge.textContent = '✓ محدّث لآخر إصدار'; }
          if (details && dtStr) details.innerHTML = 'برنامج الأدمن لديك محدّث لآخر نسخة على السيرفر (<b>' + esc(dtStr) + '</b>). يمكنك أيضاً إعادة التحديث يدوياً في أي وقت.';
          if (manualToast) toast('✓ برنامج الأدمن محدّث بالفعل لآخر إصدار');
        }
      } else if (manualToast) {
        toast('تعذر الوصول لمعلومات التحديث على السيرفر حالياً', 'error');
      }
    } catch (_) {}
  }

  async function triggerAdminSelfUpdate() {
    if (!api.applyAdminUpdate) {
      location.reload();
      return;
    }
    if (adminUpdateBusy) return;
    if (!confirm('تحديث برنامج IT ELKHAWGA Admin أونلاين من السيرفر الآن؟\n\nسيتم تنزيل أحدث نسخة وتثبيتها ثم إعادة فتح البرنامج تلقائياً خلال ثوانٍ (اضغط "نعم / Yes" عند ظهور نافذة صلاحية التثبيت في Windows).')) return;
    adminUpdateBusy = true;
    toast('⬇ جارٍ تنزيل أحدث نسخة من برنامج الأدمن من السيرفر...');
    try {
      const r = await api.applyAdminUpdate();
      if (r && r.success) {
        toast('✓ اكتمل التنزيل — جارٍ تثبيت التحديث وإعادة تشغيل البرنامج...');
      } else {
        toast((r && r.error) || 'تعذر تحديث برنامج الأدمن', 'error');
        adminUpdateBusy = false;
      }
    } catch (e) {
      toast(e.message || 'تعذر تحديث برنامج الأدمن', 'error');
      adminUpdateBusy = false;
    }
  }

  if ($('checkAdminUpdateBtn')) $('checkAdminUpdateBtn').addEventListener('click', () => refreshAdminUpdateUi(true));
  if ($('runAdminUpdateBtn')) $('runAdminUpdateBtn').addEventListener('click', triggerAdminSelfUpdate);
  if ($('adminUpdateTopBtn')) $('adminUpdateTopBtn').addEventListener('click', triggerAdminSelfUpdate);

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
  const isAppleTouch = /iPad|iPhone|iPod/i.test(navigator.userAgent || '')
    || (navigator.platform === 'MacIntel' && Number(navigator.maxTouchPoints || 0) > 1);
  const isStandalonePwa = Boolean(
    (window.navigator && window.navigator.standalone === true) ||
    (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches)
  );
  if (isAppleTouch && !isStandalonePwa && !isTauriRuntime && $('iosInstallBanner')) {
    try {
      if (localStorage.getItem('itk_hide_ios_banner') !== '1') {
        $('iosInstallBanner').style.display = 'flex';
      }
    } catch (_) {
      $('iosInstallBanner').style.display = 'flex';
    }
    if ($('dismissIosBannerBtn')) {
      $('dismissIosBannerBtn').addEventListener('click', () => {
        $('iosInstallBanner').style.display = 'none';
        try { localStorage.setItem('itk_hide_ios_banner', '1'); } catch (_) {}
      });
    }
  }
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
    try { const gr = await api.getRelayGroups(); groupsCache = (gr && gr.groups) || []; } catch (e) { }
  }

  function deviceRow(d, prefix) {
    const online = d.online;
    const usbBlocked = Boolean(d.usb_blocked);
    const state = !online ? '<span class="badge gray">غير متصل</span>'
      : d.blocked ? '<span class="badge red">مقفول</span>' : '<span class="badge green">مفتوح</span>';
    const usbStateBadge = usbBlocked
      ? '<span class="badge amber" title="منافذ تخزين USB والفلاشات مقفولة على هذا الجهاز">🔌 USB مقفول</span>'
      : '';
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
    const usbBtn = usbBlocked
      ? '<button class="btn btn-success btn-sm" data-dev-cmd="usb_unblock" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="فتح منافذ الفلاشات ووحدات التخزين USB لهذا الجهاز فقط">🔓 فتح USB</button> '
      : '<button class="btn btn-ghost btn-sm" style="border-color:rgba(245,158,11,0.45);color:#d97706;" data-dev-cmd="usb_block" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="قفل منافذ الفلاشات ووحدات التخزين USB لهذا الجهاز فقط (دون المساس بالماوس أو الكيبورد)">🔌 قفل USB</button> ';
    const controls =
      (online ? '<button class="btn btn-danger btn-sm" data-dev-cmd="block" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '">قفل</button> ' +
        '<button class="btn btn-success btn-sm" data-dev-cmd="unblock" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '">فتح</button> ' +
        usbBtn +
        '<details class="power-menu"><summary class="btn btn-ghost btn-sm">⏻ الطاقة</summary><div class="power-list">' +
        '<button type="button" data-dev-cmd="restart" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">⟳ إعادة تشغيل</button>' +
        '<button type="button" class="danger" data-dev-cmd="shutdown" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">⏻ إيقاف التشغيل</button>' +
        '<button type="button" data-dev-cmd="cancel_power" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">✕ إلغاء الإيقاف/الريستارت</button>' +
        '</div></details> ' +
        '<button class="btn btn-ghost btn-sm" data-dev-cmd="update_client" data-id="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="إرسال وتثبيت أحدث إصدار من الكلاينت عن بُعد بصمت">⬆ تحديث</button> ' : '') +
      '<button class="btn btn-ghost btn-sm" data-rename-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-current-name="' + esc(d.label || '') + '">✎ اسم</button> ' +
      '<button class="btn btn-ghost btn-sm" data-screen-device="' + esc(d.device_id) + '" data-rd-id="' + esc(d.rustdesk_id || '') + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-dev-ip="' + esc(d.ip || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="التقاط صورة للشاشة">🖥 شاشة</button> ' +
      '<button class="btn btn-ghost btn-sm" data-watch-device="' + esc(d.device_id) + '" data-rd-id="' + esc(d.rustdesk_id || '') + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-dev-ip="' + esc(d.ip || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="مشاهدة سريعة للشاشة في بث حي (مشاهدة فقط بدون تحكم)">👁 مشاهدة</button> ' +
      '<button class="btn btn-ghost btn-sm" data-camera-device="' + esc(d.device_id) + '" data-rd-id="' + esc(d.rustdesk_id || '') + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-dev-ip="' + esc(d.ip || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="مشاهدة بث الكاميرا الحي من جهاز الموظف (مشاهدة فقط بدون تحكم)">📷 كاميرا</button> ' +
      (d.rustdesk_id
        ? '<button class="btn btn-ghost btn-sm" data-support-device="' + esc(d.rustdesk_id) + '" data-rd-pass="' + esc(d.rustdesk_password || '') + '" data-dev-ip="' + esc(d.ip || '') + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '" title="دعم فني كامل مع التحكم بالماوس والكيبورد">🛠 دعم</button> ' +
        '<button class="btn btn-ghost btn-sm" data-rdpass-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-current-rdpass="' + esc(d.rustdesk_password || '') + '">🔑 كلمة</button> '
        : '<a class="btn btn-ghost btn-sm" href="https://rustdesk.com" target="_blank" rel="noopener" style="text-decoration:none;">⬇ RustDesk</a> ') +
      '<button class="btn btn-ghost btn-sm btn-delete" data-delete-device="' + esc(d.device_id) + '" data-transport="' + prefix + '" data-device-name="' + esc(shown) + '">🗑 حذف</button>';

    const verStr = String(d.app_version || '1.0.0').replace(/^v/i, '');
    const targetVer = String(d.latest_client_version || latestClientVersion || '1.2.3').replace(/^v/i, '');
    if (compareSemver(targetVer, latestClientVersion) > 0) latestClientVersion = targetVer;
    const isLatestVer = compareSemver(verStr, targetVer) >= 0;
    const searchText = [shown, d.hostname, d.ip, d.rustdesk_id, d.device_id, 'v' + verStr].filter(Boolean).join(' ').toLowerCase();
    return '<div class="device-card' + (online ? (d.blocked ? ' is-blocked' : ' is-open') : ' is-offline') + '" data-device-id="' + esc(d.device_id) + '"' +
      ' data-online="' + (online ? '1' : '0') + '" data-blocked="' + (d.blocked ? '1' : '0') + '"' +
      ' data-usb-blocked="' + (usbBlocked ? '1' : '0') + '"' +
      ' data-outdated="' + (isLatestVer ? '0' : '1') + '"' +
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
      usbStateBadge +
      evBadge +
      '</div>' +
      '<div class="device-meta-row">' +
      '<span class="device-meta-pill" style="background:' + (prefix === 'lan' ? 'rgba(14,165,233,0.12);color:#0284c7;' : 'rgba(139,92,246,0.12);color:#7c3aed;') + 'font-weight:700;">' + (prefix === 'lan' ? 'LAN محلي' : 'Relay سحابي') + '</span>' +
      '<span class="device-meta-pill mono" dir="ltr" style="background:' + (isLatestVer ? 'rgba(16,185,129,0.15);color:#059669;' : 'rgba(245,158,11,0.16);color:#d97706;') + 'font-weight:800;" title="' + (isLatestVer ? 'محدّث على آخر إصدار (v' + esc(targetVer) + ')' : 'إصدار قديم (v' + esc(verStr) + ') — اضغط ⬆ تحديث للترقية إلى v' + esc(targetVer)) + '">' + (isLatestVer ? '✓ v' : '⚠ v') + esc(verStr) + '</span>' +
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

  function buildDevicesRenderKey(devices, prefix) {
    const grpKey = (groupsCache || []).map((g) => g.id + ':' + g.name).join(',');
    return prefix + '|' + grpKey + '|' + (devices || []).map((d) => [
      d.device_id || '',
      d.online ? '1' : '0',
      d.blocked ? '1' : '0',
      d.usb_blocked ? '1' : '0',
      d.app_version || '',
      d.label || '',
      d.hostname || '',
      d.ip || '',
      d.group_id || '',
      d.throttle_kbps || 0,
      d.rustdesk_id || '',
      d.rustdesk_password || '',
      d.last_event || '',
      d.last_event_at || 0,
      (d.sites || []).join(','),
      (d.denied || []).join(','),
    ].join('\x1f')).join('\n');
  }

  function refreshDeviceTimePills(containerId, devices) {
    const box = $(containerId);
    if (!box) return;
    const byId = {};
    (devices || []).forEach((d) => { if (d && d.device_id) byId[d.device_id] = d; });
    box.querySelectorAll('.device-card').forEach((card) => {
      const d = byId[card.dataset.deviceId];
      if (!d) return;
      const tEl = card.querySelector('.device-meta-pill.time');
      if (tEl) {
        const nextText = d.last_seen ? ago(d.last_seen) : '-';
        if (tEl.textContent !== nextText) tEl.textContent = nextText;
      }
    });
  }

  let lanDevicesBusy = false;
  let lastLanRenderKey = '';
  async function loadDevices() {
    if (!api.getDevices || lanDevicesBusy) return;
    const ae = document.activeElement;
    if (ae && ae.tagName === 'SELECT' && ae.closest('#view-devices')) return;
    if (document.querySelector('#view-devices details.power-menu[open]')) return;
    if (lanTableHover) return;
    lanDevicesBusy = true;
    try {
      await ensureGroupsCache();
      let devices = [];
      try { devices = (await api.getDevices()) || []; } catch (e) { devices = []; }
      const online = devices.filter((d) => d.online).length;
      if ($('navDeviceCount')) $('navDeviceCount').textContent = devices.length;
      if ($('kpiLan')) $('kpiLan').textContent = online;
      $('devicesEmpty').style.display = devices.length ? 'none' : 'block';
      const bodyEl = $('devicesBody');
      const nextKey = buildDevicesRenderKey(devices, 'lan');
      if (nextKey !== lastLanRenderKey || bodyEl.querySelectorAll('.device-card').length !== devices.length) {
        lastLanRenderKey = nextKey;
        bodyEl.innerHTML = devices.map((d) => deviceRow(d, 'lan')).join('');
        applyDeviceFilter('devicesBody');
      } else {
        refreshDeviceTimePills('devicesBody', devices);
      }
    } finally {
      lanDevicesBusy = false;
    }
  }

  /* ---------- بحث وفلترة الأجهزة (LAN و Relay) ---------- */
  const deviceFilters = {};
  const FILTER_PILLS = [
    ['all', 'الكل'], ['online', 'متصل'], ['offline', 'غير متصل'], ['blocked', 'مقفول'], ['open', 'مفتوح'], ['usb_locked', 'USB مقفول'], ['outdated', 'يحتاج تحديث'],
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
    const counts = { all: 0, online: 0, offline: 0, blocked: 0, open: 0, usb_locked: 0, outdated: 0 };
    let visible = 0;
    cards.forEach((c) => {
      const on = c.dataset.online === '1';
      const bl = c.dataset.blocked === '1';
      const ubl = c.dataset.usbBlocked === '1';
      const out = c.dataset.outdated === '1';
      const inGroup = !f.group || c.dataset.group === f.group;
      const inSearch = !f.q || (c.dataset.q || '').includes(f.q);
      if (inGroup && inSearch) {
        counts.all++;
        counts[on ? 'online' : 'offline']++;
        if (on) counts[bl ? 'blocked' : 'open']++;
        if (ubl) counts.usb_locked++;
        if (out) counts.outdated++;
      }
      const statusOk = f.status === 'all' || (f.status === 'online' && on) || (f.status === 'offline' && !on) ||
        (f.status === 'blocked' && on && bl) || (f.status === 'open' && on && !bl) || (f.status === 'usb_locked' && ubl) || (f.status === 'outdated' && out);
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
        usb_block: '🔌 تم إرسال أمر قفل منافذ تخزين USB للجهاز',
        usb_unblock: '🔓 تم إرسال أمر فتح منافذ تخزين USB للجهاز',
        restart: 'تم إرسال أمر إعادة التشغيل — يُنفَّذ بعد 60 ثانية',
        shutdown: 'تم إرسال أمر إيقاف التشغيل — يُنفَّذ بعد 60 ثانية',
        cancel_power: 'تم إرسال أمر الإلغاء',
        update_client: 'تم إرسال أمر التحديث الصامت — يُثبَّت ويعود للاتصال خلال دقيقة',
      };
      toast(DONE[cmd] || ('تم إرسال الأمر' + (isRelay ? ' للـ Relay' : '، يصل خلال ثوانٍ')));
      setTimeout(isRelay ? loadRelayDevices : loadDevices, 400);
      if ($('view-groups') && $('view-groups').classList.contains('active')) {
        setTimeout(loadGroups, 500);
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
  let cachedOssInfo = null;
  async function loadRustdeskOssStatus() {
    if (!api.getRustdeskOssStatus) return;
    try {
      const st = await api.getRustdeskOssStatus();
      cachedOssInfo = st;
      if ($('rdOssLanHost') && st && st.lan_host) $('rdOssLanHost').textContent = st.lan_host;
      if ($('rdOssPubKey')) $('rdOssPubKey').textContent = (st && st.public_key) || '—';
      const badge = $('rdOssStatusBadge');
      const usingOss = Boolean(st && st.active_server);
      const localBtn = $('applyLocalRdOssBtn');
      const hybridBtn = $('clearRdOssBtn');
      if (localBtn && hybridBtn) {
        if (usingOss) {
          localBtn.className = 'btn btn-success btn-sm';
          localBtn.textContent = '✓ السيرفر المحلي مفعّل (' + st.active_server + ')';
          hybridBtn.className = 'btn btn-ghost btn-sm';
          hybridBtn.textContent = '🌐 التبديل إلى الوضع الهجين (موصى به من خارج الشركة)';
        } else {
          localBtn.className = 'btn btn-ghost btn-sm';
          localBtn.textContent = '⚡ تفعيل السيرفر المحلي للشبكة الداخلية فقط';
          hybridBtn.className = 'btn btn-success btn-sm';
          hybridBtn.textContent = '✓ الوضع الهجين نشط (سحابي للخارج + LAN مباشر بالداخل)';
        }
      }
      if (badge) {
        if (st && st.running) {
          badge.className = usingOss ? 'badge gold' : 'badge green';
          badge.textContent = usingOss
            ? ('⚡ وضع السيرفر المحلي فقط (' + st.active_server + ')')
            : '✓ الوضع الهجين مفعّل (يعمل داخل وخارج الشركة)';
        } else {
          badge.className = 'badge gray';
          badge.textContent = 'الوضع الهجين السحابي نشط';
        }
      }
    } catch (_) { }
  }

  async function loadRelayConfig() {
    if (!api.getRelayConfig) return;
    try {
      const c = await api.getRelayConfig();
      $('relayUrlInput').value = c.relay_url || '';
      $('relayKeyInput').value = '';
      $('relayKeyInput').placeholder = c.has_admin_key ? 'مفتاح محفوظ (اتركه فارغاً للإبقاء عليه)' : 'مفتاح المدير للـ Relay';
      const su = $('relayStatusUrl');
      if (su) su.textContent = c.relay_url || '—';
      if ($('ipadAppUrlText') && c.relay_url) $('ipadAppUrlText').textContent = c.relay_url;
      $('rdServerInput').value = c.rustdesk_server || '';
      $('rdKeyInput').value = c.rustdesk_key || '';
      $('rdPassInput').value = '';
      $('rdPassInput').placeholder = c.has_rustdesk_password ? 'كلمة سر محفوظة (اتركه فارغًا للإبقاء)' : 'اتركه فارغًا لتعطيل';
      $('relayKeySaved').style.display = c.has_admin_key ? 'inline-flex' : 'none';
      if (c.relay_version && c.relay_version !== '3') {
        toast('نسخة الـ Relay قديمة (' + c.relay_version + ') — أعِد تشغيل أحدث relay/server.js', 'error');
      }
    } catch (e) { /* ignore */ }
    await loadRustdeskOssStatus();
  }

  if ($('applyLocalRdOssBtn')) {
    $('applyLocalRdOssBtn').addEventListener('click', async () => {
      if (!cachedOssInfo || !cachedOssInfo.public_key) await loadRustdeskOssStatus();
      const host = (cachedOssInfo && cachedOssInfo.lan_host) || ($('rdOssLanHost') && $('rdOssLanHost').textContent) || '';
      const pub = (cachedOssInfo && cachedOssInfo.public_key) || '';
      if (!host || !pub) {
        toast('لم يتم العثور على مفتاح خادم RustDesk OSS المحلي', 'error');
        return;
      }
      if (!confirm('تفعيل خادم RustDesk OSS المحلي (' + host + ') لجميع الأجهزة؟\n\nملاحظة: للأجهزة داخل الشركة أو المتصلة عبر Tailscale يعمل بسرعة فائقة فوراً. للمهندسين خارج الشركة بدون VPN يلزم فتح المنافذ 21115–21119 على الراوتر.')) return;
      $('rdServerInput').value = host;
      $('rdKeyInput').value = pub;
      const url = $('relayUrlInput').value.trim();
      const c = await api.getConfig();
      let pw = '';
      if (c.has_password) {
        pw = prompt('كلمة سر الحماية لتأكيد حفظ إعدادات السيرفر') || '';
        if (!pw) return;
      }
      const r = await api.setRelayConfig(url, null, pw || null, host, pub, null);
      if (r && r.success) {
        toast('⚡ تم تفعيل خادم RustDesk OSS المحلي ومزامنته مع كل الأجهزة');
        await loadRelayConfig();
      } else {
        toast((r && r.error) || 'فشل الحفظ', 'error');
      }
    });
  }

  if ($('clearRdOssBtn')) {
    $('clearRdOssBtn').addEventListener('click', async () => {
      $('rdServerInput').value = '';
      $('rdKeyInput').value = '';
      const url = $('relayUrlInput').value.trim();
      const c = await api.getConfig();
      let pw = '';
      if (c.has_password) {
        pw = prompt('كلمة سر الحماية لتأكيد تفعيل الوضع الهجين') || '';
        if (!pw) return;
      }
      const r = await api.setRelayConfig(url, null, pw || null, '', '', null);
      if (r && r.success) {
        toast('🌐 تم تفعيل الوضع الهجين (اتصال LAN مباشر بالداخل + سحابي للمهندسين بالخارج)');
        await loadRelayConfig();
      } else {
        toast((r && r.error) || 'فشل الحفظ', 'error');
      }
    });
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
    const r = await api.setRelayConfig(url, key || null, pw || null, rdServer, rdKey, rdPass || null);
    if (r.success) { toast('تم حفظ إعدادات الـ Relay ومزامنتها'); await loadRelayConfig(); await loadRelayDevices(); }
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
  const isCoarseTouch = Boolean(window.matchMedia && window.matchMedia('(hover: none), (pointer: coarse)').matches);
  document.addEventListener('mouseover', (e) => {
    if (isCoarseTouch) return;
    if (e.target.closest && e.target.closest('#view-relay .devices-card-container')) relayTableHover = true;
  });
  document.addEventListener('mouseout', (e) => {
    if (isCoarseTouch) return;
    if (e.target.closest && e.target.closest('#view-relay .devices-card-container')) relayTableHover = false;
  });

  let relayDevicesBusy = false;
  let lastRelayDevicesSnapshot = [];
  let lastRelayRenderKey = '';
  async function loadRelayDevices() {
    if (!api.getRelayDevices || relayDevicesBusy) return;
    const ae = document.activeElement;
    if (ae && ae.tagName === 'SELECT' && ae.closest('#view-relay')) return;
    if (document.querySelector('#view-relay details.power-menu[open]')) return;
    if (relayTableHover) return;
    relayDevicesBusy = true;
    try {
      if (!groupsCache.length) {
        try { const gr = await api.getRelayGroups(); groupsCache = (gr && gr.groups) || []; } catch (e) { }
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
      const bodyEl = $('relayDevicesBody');
      const nextKey = buildDevicesRenderKey(devices, 'relay');
      if (nextKey !== lastRelayRenderKey || bodyEl.querySelectorAll('.device-card').length !== devices.length) {
        lastRelayRenderKey = nextKey;
        bodyEl.innerHTML = devices.map((d) => deviceRow(d, 'relay')).join('');
        applyDeviceFilter('relayDevicesBody');
      } else {
        refreshDeviceTimePills('relayDevicesBody', devices);
      }
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
      try { return JSON.parse(raw); } catch (e) { }
    }
    return null;
  }

  let lastLoadedAlerts = [];

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
    lastLoadedAlerts = alerts;
    renderFilteredAlerts();
  }

  function renderFilteredAlerts() {
    const q = (($('alertSearchInput') && $('alertSearchInput').value) || '').trim().toLowerCase();
    const sevFilter = ($('alertSeverityFilter') && $('alertSeverityFilter').value) || '';
    const unackedTotal = lastLoadedAlerts.filter((a) => !a.acked).length;
    const exfilCount = lastLoadedAlerts.filter((a) => a.type === 'exfil').length;
    const tamperCount = lastLoadedAlerts.filter((a) => a.type === 'tamper' || a.type === 'auth_fail' || a.type === 'bypass').length;
    if ($('alertsStatUnacked')) $('alertsStatUnacked').textContent = unackedTotal + ' غير مقرّة';
    if ($('alertsStatExfil')) $('alertsStatExfil').textContent = exfilCount + ' رفع ملفات';
    if ($('alertsStatTamper')) $('alertsStatTamper').textContent = tamperCount + ' تلاعب / مصادقة';

    const alerts = lastLoadedAlerts.filter((a) => {
      if (sevFilter && (a.severity || 'medium') !== sevFilter) return false;
      if (q) {
        const m = parseAlertMeta(a.meta) || {};
        const hay = [
          a.device_name,
          a.device_id,
          a.message,
          a.type,
          m.file_name,
          m.recipient_name,
          m.recipient_phone,
          m.windows_user,
          m.page_url,
        ].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    if (!alerts.length) {
      $('alertsList').innerHTML = '<div class="empty">لا توجد تنبيهات مطابقة.</div>';
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
      const dlHref = (meta && meta.uploaded_file_id)
        ? (serverHttpBase + '/api/uploads/' + encodeURIComponent(meta.uploaded_file_id) + (authToken ? ('?token=' + encodeURIComponent(authToken)) : ''))
        : '';
      const hideDlpForNonSuper = Boolean($('dlpSuperOnlyToggle') && $('dlpSuperOnlyToggle').checked && !hasSuperAdminAccess());
      const dlBtn = (meta && meta.uploaded_file_id && !hideDlpForNonSuper)
        ? '<a class="btn btn-success btn-sm" data-download-upload="' + esc(meta.uploaded_file_id) + '" data-file-name="' + esc((meta && meta.file_name) || 'file') + '" href="' + esc(dlHref) + '" target="_blank" rel="noreferrer" download="' + esc((meta && meta.file_name) || 'file') + '" style="text-decoration:none;">⬇ تحميل النسخة طبق الأصل</a>'
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
        } catch (_) { }
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
        } catch (_) { }
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
  if ($('alertSeverityFilter')) $('alertSeverityFilter').addEventListener('change', renderFilteredAlerts);
  if ($('alertSearchInput')) $('alertSearchInput').addEventListener('input', renderFilteredAlerts);
  if ($('ackAllAlertsBtn')) {
    $('ackAllAlertsBtn').addEventListener('click', async () => {
      if (!api.ackAllAlerts) return;
      const curType = $('alertFilter').value || null;
      if (!confirm(curType ? 'إقرار جميع التنبيهات غير المقرّة من هذا النوع؟' : 'إقرار جميع التنبيهات غير المقرّة؟')) return;
      try {
        const r = await api.ackAllAlerts(curType);
        if (r && r.success !== false) {
          toast('✓ تم إقرار التنبيهات بنجاح');
          await loadAlerts();
          await loadAudit();
        } else toast((r && r.error) || 'فشل إقرار التنبيهات', 'error');
      } catch (e) { toast(e.message || 'فشل إقرار التنبيهات', 'error'); }
    });
  }
  if ($('exportAlertsCsvBtn')) {
    $('exportAlertsCsvBtn').addEventListener('click', async () => {
      if (!lastLoadedAlerts.length) {
        toast('لا توجد تنبيهات لتصديرها حالياً', 'error');
        return;
      }
      const header = ['التاريخ والوقت', 'الجهاز', 'النوع', 'الخطورة', 'التفاصيل', 'الملف', 'المرسل إليه', 'رقم الهاتف', 'مستخدم الويندوز', 'الحالة'].map(csvCell).join(',');
      const rows = lastLoadedAlerts.map((a) => {
        const m = parseAlertMeta(a.meta) || {};
        const dt = a.created_at ? new Date(a.created_at).toLocaleString('ar-EG') : '';
        return [
          dt,
          a.device_name || a.device_id || '',
          TYPE_LABEL[a.type] || a.type || '',
          (a.severity || '').toUpperCase(),
          a.message || '',
          m.file_name || '',
          m.recipient_name || '',
          m.recipient_phone || '',
          m.windows_user || '',
          a.acked ? 'مقرّة' : 'غير مقرّة',
        ].map(csvCell).join(',');
      });
      const d = new Date().toISOString().slice(0, 10);
      await saveDownloadText([header].concat(rows).join('\r\n'), 'IT-ELKHAWGA-Alerts-' + d + '.csv', 'text/csv;charset=utf-8');
    });
  }

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
  function openIpadRustdeskSheet(rdId, rdPass, deviceName) {
    const cleanId = String(rdId || '').replace(/\s+/g, '');
    if (!cleanId) {
      toast('لا يوجد RustDesk ID مسجل لهذا الجهاز بعد', 'error');
      return;
    }
    const pw = String(rdPass || '').trim() || 'KH2027kh';
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(pw).catch(() => {});
      }
    } catch (_) {}
    if ($('ipadRdTitle')) $('ipadRdTitle').textContent = '🚀 الاتصال عبر RustDesk — ' + (deviceName || cleanId);
    if ($('ipadRdIdText')) $('ipadRdIdText').textContent = cleanId;
    if ($('ipadRdPassText')) $('ipadRdPassText').textContent = pw;
    if ($('ipadRdLaunchLink')) {
      $('ipadRdLaunchLink').href = 'rustdesk://connection/new/' + encodeURIComponent(cleanId) + '?password=' + encodeURIComponent(pw);
    }
    if ($('ipadRustdeskModal')) $('ipadRustdeskModal').classList.add('show');
  }
  if ($('ipadRdCloseBtn')) {
    $('ipadRdCloseBtn').addEventListener('click', () => $('ipadRustdeskModal').classList.remove('show'));
  }
  if ($('ipadRustdeskModal')) {
    $('ipadRustdeskModal').addEventListener('click', (e) => {
      if (e.target.id === 'ipadRustdeskModal') $('ipadRustdeskModal').classList.remove('show');
    });
  }

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
    const rdAppBtn = $('screenOpenRdAppBtn');
    if (rdAppBtn) {
      rdAppBtn.style.display = (isAppleTouch && currentScreenRdId) ? '' : 'none';
    }
  }
  if ($('screenOpenRdAppBtn')) {
    $('screenOpenRdAppBtn').addEventListener('click', () => {
      if (currentScreenRdId) {
        openIpadRustdeskSheet(currentScreenRdId, currentScreenRdPass, ($('screenTitle').textContent || '').replace(/^.*?—\s*/, ''));
      }
    });
  }
  function stopScreenTimer() {
    if (screenTimer) { clearInterval(screenTimer); screenTimer = null; }
    if (streamRenewTimer) { clearInterval(streamRenewTimer); streamRenewTimer = null; }
    if (currentScreenDevice && (currentScreenMode === 'screen' || currentScreenMode === 'camera')) {
      api.requestScreenshot(currentScreenDevice, currentScreenTransport, 'stop').catch(() => { });
    }
    screenPolling = false;
    liveWatchMode = false;
    currentScreenMode = 'once';
    updateLiveToggleUi();
  }
  async function requestAndLoadScreen(deviceId, transport, mode) {
    const reqMode = mode || currentScreenMode || 'once';
    try { await api.requestScreenshot(deviceId, transport, reqMode); } catch (e) { }
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
          api.requestScreenshot(deviceId, currentScreenTransport, currentScreenMode).catch(() => { });
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
        api.requestScreenshot(currentScreenDevice, currentScreenTransport, 'stop').catch(() => { });
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
    relayTimer = setInterval(() => {
      if (!document.hidden) loadRelayDevices();
    }, 3000);
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
    const usbGrp = Boolean(g.usb_block);
    const list = Array.isArray(groupDevices) ? groupDevices : [];
    const others = Array.isArray(otherDevices) ? otherDevices : [];
    const isOpen = !collapsedGroups.has(g.id);
    const onlineCount = list.filter((d) => d.online).length;
    const blockedCount = list.filter((d) => d.online && d.blocked).length;
    const usbBlockedCount = list.filter((d) => d.usb_blocked).length;
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
      '<span class="badge ' + (usbGrp ? 'amber' : 'gray') + '">' + (usbGrp ? '🔌 USB مقفول للمجموعة' : 'USB مفتوح') + '</span>' +
      '<div class="group-card-actions">' +
      '<button class="btn btn-primary btn-sm" data-save-group="' + esc(g.id) + '">حفظ</button>' +
      '<button class="btn btn-ghost btn-sm" type="button" data-copy-default-sites="' + esc(g.id) + '" title="نسخ المواقع المسموحة والمقفولة من القائمة الافتراضية لهذه المجموعة">📋 نسخ من الافتراضي</button>' +
      '<button class="btn ' + (ephem ? 'btn-success' : 'btn-ghost') + ' btn-sm" data-toggle-ephemeral="' + esc(g.id) + '" data-ephem="' + (ephem ? '1' : '0') + '">' + (ephem ? '🧹 التصفح النظيف: مفعّل' : '🧹 تفعيل التصفح النظيف') + '</button>' +
      '<button class="btn ' + (usbGrp ? 'btn-danger' : 'btn-ghost') + ' btn-sm" data-toggle-usb-group="' + esc(g.id) + '" data-usb="' + (usbGrp ? '1' : '0') + '">' + (usbGrp ? '🔌 سياسة USB: مقفول' : '🔌 قفل USB بالسياسة') + '</button>' +
      '<button class="btn btn-danger btn-sm" data-grp-cmd="block" data-id="' + esc(g.id) + '">قفل الإنترنت</button>' +
      '<button class="btn btn-success btn-sm" data-grp-cmd="unblock" data-id="' + esc(g.id) + '">فتح الإنترنت</button>' +
      '<button class="btn btn-ghost btn-sm" style="border-color:rgba(245,158,11,0.45);color:#d97706;" data-grp-cmd="usb_block" data-id="' + esc(g.id) + '">🔌 قفل USB للكل</button>' +
      '<button class="btn btn-ghost btn-sm" data-grp-cmd="usb_unblock" data-id="' + esc(g.id) + '">🔓 فتح USB للكل</button>' +
      '<button class="btn btn-ghost btn-sm" data-grp-cmd="update_client" data-id="' + esc(g.id) + '" title="إرسال وتثبيت أحدث نسخة من الكلاينت بصمت لكل أجهزة المجموعة">⬆ تحديث الكلاينت</button>' +
      '<button class="btn btn-ghost btn-sm" data-del-group="' + esc(g.id) + '">حذف</button>' +
      '</div>' +
      '</div>' +
      '<label class="group-ephem-row">' +
      '<input type="checkbox" data-g-ephemeral="' + esc(g.id) + '"' + (ephem ? ' checked' : '') + ' style="width:15px;height:15px;accent-color:var(--primary);">' +
      '<span>🧹 <b>وضع التصفح النظيف (Chrome &amp; Edge):</b> فتح كأول مرة ومسح السجل والكاش وكلمات السر والجلسات تلقائياً عند كل إغلاق</span>' +
      '</label>' +
      '<label class="group-ephem-row" style="margin-top:4px;">' +
      '<input type="checkbox" data-g-usb-block="' + esc(g.id) + '"' + (usbGrp ? ' checked' : '') + ' style="width:15px;height:15px;accent-color:#d97706;">' +
      '<span>🔌 <b>قفل منافذ الفلاشات ووحدات التخزين (USB Storage):</b> منع الفلاشات والهاردات الخارجية ونقل ملفات الموبايل لأجهزة هذه المجموعة</span>' +
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
      '<span class="badge ' + (blockedCount ? 'red' : 'gray') + '" style="padding:3px 9px;font-size:11px;">' + blockedCount + ' مقفول إنترنت</span>' +
      '<span class="badge ' + (usbBlockedCount ? 'amber' : 'gray') + '" style="padding:3px 9px;font-size:11px;">' + usbBlockedCount + ' مقفول USB</span>' +
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
    const assignedCount = allDevices.filter((d) => d.group_id && groupsCache.some((g) => g.id === d.group_id)).length;
    if ($('groupsSummaryBadge')) {
      $('groupsSummaryBadge').textContent = groupsCache.length + ' مجموعة · ' + assignedCount + ' جهاز موزع · ' + Math.max(0, allDevices.length - assignedCount) + ' افتراضي';
    }
    const gq = (($('groupsSearchInput') && $('groupsSearchInput').value) || '').trim().toLowerCase();
    const visibleGroups = groupsCache.filter((g) => {
      if (!gq) return true;
      if (String(g.name || '').toLowerCase().includes(gq)) return true;
      return allDevices.some((d) => d.group_id === g.id && [d.label, d.hostname, d.ip].join(' ').toLowerCase().includes(gq));
    });
    $('groupsList').innerHTML = visibleGroups.length
      ? visibleGroups.map((g) => {
        const groupDevices = allDevices.filter((d) => d.group_id === g.id);
        const otherDevices = allDevices.filter((d) => d.group_id !== g.id);
        g.devices = groupDevices.length;
        return groupCard(g, groupDevices, otherDevices);
      }).join('')
      : '<div class="empty">' + (groupsCache.length ? 'لا توجد مجموعات مطابقة للبحث.' : 'لا توجد مجموعات بعد. أنشئ مجموعة وابدأ بتعيين الأجهزة إليها.') + '</div>';
  }
  if ($('groupsSearchInput')) $('groupsSearchInput').addEventListener('input', loadGroups);

  $('createGroupBtn').addEventListener('click', async () => {
    const name = $('newGroupName').value.trim();
    if (!name) { toast('اكتب اسم المجموعة', 'error'); return; }
    const ephem = Boolean($('newGroupEphemeral') && $('newGroupEphemeral').checked);
    const usbGrp = Boolean($('newGroupUsbBlock') && $('newGroupUsbBlock').checked);
    try {
      const r = await api.createRelayGroup(name, $('newGroupMode').value, ephem, usbGrp);
      if (r && r.success === false) { toast(r.error || 'فشل الإنشاء', 'error'); return; }
      $('newGroupName').value = '';
      if ($('newGroupEphemeral')) $('newGroupEphemeral').checked = false;
      if ($('newGroupUsbBlock')) $('newGroupUsbBlock').checked = false;
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
    const copyDef = e.target.closest('[data-copy-default-sites]');
    if (copyDef) {
      const id = copyDef.dataset.copyDefaultSites;
      try {
        const [al, bl] = await Promise.all([api.getAllowedSites(), api.getBlockedSites()]);
        const alBox = document.querySelector('[data-g-allowed="' + id + '"]');
        const blBox = document.querySelector('[data-g-blocked="' + id + '"]');
        if (alBox) alBox.value = (al || []).join('\n');
        if (blBox) blBox.value = (bl || []).join('\n');
        toast('تم نسخ المواقع الافتراضية للمجموعة — اضغط "حفظ" لتطبيقها');
      } catch (err) { toast('تعذر نسخ القوائم', 'error'); }
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
      const usbEl = document.querySelector('[data-g-usb-block="' + id + '"]');
      const ephem = Boolean(ephemEl && ephemEl.checked);
      const usbGrp = Boolean(usbEl && usbEl.checked);
      try {
        const r = await api.updateRelayGroup(id, name, mode, allowed, blocked, ephem, usbGrp);
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
      const usbEl = document.querySelector('[data-g-usb-block="' + id + '"]');
      if (ephemEl) ephemEl.checked = nextEphem;
      const name = document.querySelector('[data-g-name="' + id + '"]').value.trim();
      const mode = document.querySelector('[data-g-mode="' + id + '"]').value;
      const allowed = linesToArr(document.querySelector('[data-g-allowed="' + id + '"]').value);
      const blocked = linesToArr(document.querySelector('[data-g-blocked="' + id + '"]').value);
      const usbGrp = Boolean(usbEl && usbEl.checked);
      try {
        const r = await api.updateRelayGroup(id, name, mode, allowed, blocked, nextEphem, usbGrp);
        if (r && r.success === false) { toast(r.error || 'فشل التحديث', 'error'); return; }
        loadGroups();
        toast(nextEphem ? 'تم تفعيل التصفح النظيف لهذه المجموعة فقط' : 'تم إيقاف التصفح النظيف عن هذه المجموعة');
      } catch (err) { toast(err.message || 'فشل التحديث', 'error'); }
      return;
    }
    const togUsbGrp = e.target.closest('[data-toggle-usb-group]');
    if (togUsbGrp) {
      const id = togUsbGrp.dataset.toggleUsbGroup;
      const curUsb = togUsbGrp.dataset.usb === '1';
      const nextUsb = !curUsb;
      const usbEl = document.querySelector('[data-g-usb-block="' + id + '"]');
      const ephemEl = document.querySelector('[data-g-ephemeral="' + id + '"]');
      if (usbEl) usbEl.checked = nextUsb;
      const name = document.querySelector('[data-g-name="' + id + '"]').value.trim();
      const mode = document.querySelector('[data-g-mode="' + id + '"]').value;
      const allowed = linesToArr(document.querySelector('[data-g-allowed="' + id + '"]').value);
      const blocked = linesToArr(document.querySelector('[data-g-blocked="' + id + '"]').value);
      const ephem = Boolean(ephemEl && ephemEl.checked);
      try {
        const r = await api.updateRelayGroup(id, name, mode, allowed, blocked, ephem, nextUsb);
        if (r && r.success === false) { toast(r.error || 'فشل التحديث', 'error'); return; }
        await api.sendGroupCommand(id, nextUsb ? 'usb_block' : 'usb_unblock', currentAdminUser, currentAdminRole).catch(() => {});
        loadGroups();
        loadDevices();
        loadRelayDevices();
        toast(nextUsb ? '🔌 تم قفل منافذ تخزين USB لأجهزة هذه المجموعة' : '🔓 تم فتح منافذ تخزين USB لأجهزة هذه المجموعة');
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
      if (isAppleTouch) {
        openIpadRustdeskSheet(sup.dataset.supportDevice, sup.dataset.rdPass || null, sup.dataset.deviceName || '');
        return;
      }
      try {
        const r = await api.openSupportSession(sup.dataset.supportDevice, sup.dataset.rdPass || null, 'support', sup.dataset.devIp || null);
        if (r && r.success !== false) toast('🛠 تم فتح جلسة الدعم الكامل عبر RustDesk (تحكم بالماوس والكيبورد)');
        else if (!(r && r.cancelled)) toast((r && r.error) || 'فشل فتح الجلسة', 'error');
      } catch (err) { toast(err.message || 'فشل فتح الجلسة', 'error'); }
      return;
    }
    const camBtn = e.target.closest('[data-camera-device]');
    if (camBtn) {
      if (isAppleTouch) {
        openScreen(
          camBtn.dataset.cameraDevice,
          camBtn.dataset.deviceName || '',
          camBtn.dataset.transport || '',
          'camera',
          camBtn.dataset.rdId || '',
          camBtn.dataset.rdPass || ''
        );
        return;
      }
      const rdId = (camBtn.dataset.rdId || '').trim();
      const devIp = (camBtn.dataset.devIp || '').trim();
      if (!rdId && !devIp) {
        toast('لا يوجد RustDesk ID مسجل لهذا الجهاز بعد — تأكد من تثبيت وتشغيل RustDesk على جهاز الموظف', 'error');
        return;
      }
      try {
        const r = await api.openSupportSession(rdId, camBtn.dataset.rdPass || null, 'camera', devIp || null);
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
      if (isAppleTouch) {
        openScreen(
          watch.dataset.watchDevice,
          watch.dataset.deviceName || '',
          watch.dataset.transport || '',
          'screen',
          watch.dataset.rdId || '',
          watch.dataset.rdPass || ''
        );
        return;
      }
      const rdId = (watch.dataset.rdId || '').trim();
      const devIp = (watch.dataset.devIp || '').trim();
      if (!rdId && !devIp) {
        toast('لا يوجد RustDesk ID مسجل لهذا الجهاز بعد — تأكد من تثبيت وتشغيل RustDesk على جهاز الموظف', 'error');
        return;
      }
      try {
        const r = await api.openSupportSession(rdId, watch.dataset.rdPass || null, 'watch', devIp || null);
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
    try { localStorage.setItem(BA_STORE_KEY, JSON.stringify(baItems)); } catch (e) { }
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
      '<td><button type="button" class="btn btn-success btn-sm" style="padding:2px 8px;font-size:11px;" data-ba-allow="' + esc(a.host) + '">✓ سماح</button></td>' +
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
        try { lan = (await api.getDevices()) || []; } catch (e) { }
        changed = baIngest(lan, 'lan') || changed;
      }
      if (api.getRelayDevices && !relayDevicesBusy) {
        try {
          const r = await api.getRelayDevices();
          relay = Array.isArray(r) ? r : ((r && r.devices) || []);
          lastRelayDevicesSnapshot = relay;
        } catch (e) { }
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
    baTimer = setInterval(() => {
      if (!document.hidden) pollBlockedAttempts();
    }, 8000);
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
    panel.addEventListener('click', async (e) => {
      e.stopPropagation();
      const allowBtn = e.target.closest('[data-ba-allow]');
      if (allowBtn) {
        const host = cleanDomain(allowBtn.dataset.baAllow || '');
        if (!host) return;
        try {
          if (api.addSitesBulk) await api.addSitesBulk([host], 'allowed');
          else { await api.addSite(host); await api.syncPolicy(); }
          await loadSites();
          toast('✓ تم السماح للموقع (' + host + ') ومزامنة الصلاحيات');
        } catch (err) { toast(err.message || 'تعذر إضافة الموقع', 'error'); }
      }
    });
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

  /* ---------- Server File Archive (Scalable Calendar, Gallery & Lightbox) ---------- */
  let archiveFilesCache = [];
  let archiveDailyIndex = [];
  let archiveSummary = null;
  let archiveDevicesList = [];
  let archiveCurPage = 1;
  let archiveTotalPages = 1;
  let archiveTotalMatching = 0;
  let archiveViewMode = localStorage.getItem('ibp_archive_view_mode') || 'gallery';
  let archLbIndex = -1;
  let archLbZoomed = false;
  let archSearchTimer = null;

  function formatArchiveBytes(n) {
    const b = Number(n || 0);
    if (!b) return '—';
    if (b >= 1024 * 1024) return (b / (1024 * 1024)).toFixed(2) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  function classifyArchiveExt(fileName) {
    const lower = String(fileName || '').toLowerCase();
    const dot = lower.lastIndexOf('.');
    const ext = dot >= 0 ? lower.slice(dot + 1) : '';
    if (['xls', 'xlsx', 'csv', 'doc', 'docx', 'pdf', 'ppt', 'pptx', 'txt', 'rtf', 'sql', 'db', 'sqlite', 'accdb', 'mdb', 'json', 'xml'].includes(ext)) return 'docs';
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'heic'].includes(ext)) return 'images';
    if (['zip', 'rar', '7z', 'tar', 'gz', 'iso'].includes(ext)) return 'archives';
    return 'other';
  }

  function getFileExtUpper(fileName) {
    const s = String(fileName || '').trim();
    const dot = s.lastIndexOf('.');
    return dot >= 0 ? s.slice(dot + 1).toUpperCase().slice(0, 6) : 'FILE';
  }

  function formatArchiveExactDate(ts) {
    if (!ts) return { date: '—', time: '' };
    const d = new Date(Number(ts));
    if (isNaN(d.getTime())) return { date: '—', time: '' };
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    const time = d.toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' });
    return { date: yyyy + '/' + mm + '/' + dd, time };
  }

  function toLocalYmd(d) {
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }

  function formatDayTitleAr(ymd) {
    const parts = String(ymd || '').split('-').map(Number);
    if (parts.length !== 3 || !parts[0]) return ymd;
    const d = new Date(parts[0], parts[1] - 1, parts[2], 12, 0, 0);
    return d.toLocaleDateString('ar-EG', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  }

  function formatMonthTitleAr(ym) {
    const parts = String(ym || '').split('-').map(Number);
    if (parts.length < 2 || !parts[0]) return ym;
    const d = new Date(parts[0], parts[1] - 1, 1, 12, 0, 0);
    return d.toLocaleDateString('ar-EG', { month: 'long', year: 'numeric' });
  }

  function buildArchiveFileUrl(fileId, inline) {
    const base = serverHttpBase + '/api/uploads/' + encodeURIComponent(fileId || '');
    const params = [];
    if (inline) params.push('inline=1');
    if (authToken) params.push('token=' + encodeURIComponent(authToken));
    return params.length ? (base + '?' + params.join('&')) : base;
  }

  function computeArchiveTimeBounds() {
    const preset = ($('archiveDateFilter') && $('archiveDateFilter').value) || '';
    const dFrom = (($('archiveDateFrom') && $('archiveDateFrom').value) || '').trim();
    const dTo = (($('archiveDateTo') && $('archiveDateTo').value) || '').trim();

    if (dFrom || dTo) {
      const startYmd = dFrom || dTo;
      const endYmd = dTo || dFrom;
      const sp = startYmd.split('-').map(Number);
      const ep = endYmd.split('-').map(Number);
      const fromMs = sp.length === 3 ? new Date(sp[0], sp[1] - 1, sp[2], 0, 0, 0, 0).getTime() : 0;
      const toMs = ep.length === 3 ? new Date(ep[0], ep[1] - 1, ep[2], 23, 59, 59, 999).getTime() : 0;
      return { fromMs, toMs, singleDay: startYmd === endYmd ? startYmd : '' };
    }

    const now = new Date();
    if (preset === 'today' || preset === '1') {
      const s = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0).getTime();
      const e = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999).getTime();
      return { fromMs: s, toMs: e, singleDay: toLocalYmd(now) };
    }
    if (preset === 'yesterday') {
      const y = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1, 12, 0, 0);
      const s = new Date(y.getFullYear(), y.getMonth(), y.getDate(), 0, 0, 0, 0).getTime();
      const e = new Date(y.getFullYear(), y.getMonth(), y.getDate(), 23, 59, 59, 999).getTime();
      return { fromMs: s, toMs: e, singleDay: toLocalYmd(y) };
    }
    const daysNum = parseInt(preset, 10) || 0;
    if (daysNum > 0) {
      return { fromMs: Date.now() - daysNum * 86400 * 1000, toMs: 0, singleDay: '' };
    }
    return { fromMs: 0, toMs: 0, singleDay: '' };
  }

  function buildArchiveQueryObject(overridePageSize) {
    const bounds = computeArchiveTimeBounds();
    const pageSize = overridePageSize || (parseInt(($('archPageSizeSelect') && $('archPageSizeSelect').value) || '60', 10) || 60);
    return {
      channel: ($('archiveChannelFilter') && $('archiveChannelFilter').value) || '',
      fromMs: bounds.fromMs || null,
      toMs: bounds.toMs || null,
      fileType: ($('archiveTypeFilter') && $('archiveTypeFilter').value) || '',
      device: ($('archiveDeviceFilter') && $('archiveDeviceFilter').value) || '',
      search: (($('archiveSearchInput') && $('archiveSearchInput').value) || '').trim(),
      page: overridePageSize ? 1 : archiveCurPage,
      pageSize,
      tzOffsetMins: new Date().getTimezoneOffset(),
    };
  }

  function hasActiveArchiveFilters() {
    return Boolean(
      (($('archiveDateFilter') && $('archiveDateFilter').value) || '') ||
      (($('archiveDateFrom') && $('archiveDateFrom').value) || '') ||
      (($('archiveDateTo') && $('archiveDateTo').value) || '') ||
      (($('archiveTypeFilter') && $('archiveTypeFilter').value) || '') ||
      (($('archiveDeviceFilter') && $('archiveDeviceFilter').value) || '') ||
      (($('archiveChannelFilter') && $('archiveChannelFilter').value) || '') ||
      ((($('archiveSearchInput') && $('archiveSearchInput').value) || '').trim())
    );
  }

  function syncArchiveViewTabsUi() {
    const tabsWrap = $('archiveViewTabs');
    if (tabsWrap) {
      tabsWrap.querySelectorAll('[data-archive-view]').forEach((btn) => {
        const active = btn.dataset.archiveView === archiveViewMode;
        btn.classList.toggle('btn-primary', active);
        btn.classList.toggle('btn-ghost', !active);
      });
    }
    if ($('archiveDaysPane')) $('archiveDaysPane').style.display = archiveViewMode === 'days' ? 'block' : 'none';
    if ($('archiveGalleryPane')) $('archiveGalleryPane').style.display = archiveViewMode === 'gallery' ? 'grid' : 'none';
    if ($('archiveTablePane')) $('archiveTablePane').style.display = archiveViewMode === 'table' ? 'block' : 'none';
  }

  function renderArchiveDaysPane() {
    const pane = $('archiveDaysPane');
    if (!pane) return;
    if (!archiveDailyIndex.length) {
      pane.innerHTML = '<div class="empty">لا توجد أيام مسجّلة في الأرشيف حتى الآن.</div>';
      return;
    }
    const byMonth = {};
    const monthOrder = [];
    archiveDailyIndex.forEach((d) => {
      const ym = String(d.day || '').slice(0, 7);
      if (!byMonth[ym]) { byMonth[ym] = []; monthOrder.push(ym); }
      byMonth[ym].push(d);
    });

    pane.innerHTML = monthOrder.map((ym) => {
      const days = byMonth[ym];
      const mTotal = days.reduce((s, x) => s + Number(x.total || 0), 0);
      const mImages = days.reduce((s, x) => s + Number(x.images || 0), 0);
      return '<div style="margin-bottom:18px;">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;padding:0 4px;">' +
        '<div style="font-weight:800;font-size:14.5px;color:var(--primary-2);">🗓 ' + esc(formatMonthTitleAr(ym)) + '</div>' +
        '<div style="font-size:12px;color:var(--muted);font-weight:700;">' + mTotal + ' ملف · ' + mImages + ' صورة</div>' +
        '</div>' +
        '<div class="arch-day-grid">' +
        days.map((d) =>
          '<div class="arch-day-card">' +
          '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;">' +
          '<div>' +
          '<div style="font-weight:800;font-size:13.5px;">' + esc(formatDayTitleAr(d.day)) + '</div>' +
          '<div class="mono" style="font-size:11px;color:var(--muted);margin-top:2px;">' + esc(d.day) + ' · ' + esc(formatArchiveBytes(d.bytes)) + '</div>' +
          '</div>' +
          '<span class="badge blue" style="font-weight:800;">' + Number(d.total || 0) + ' ملف</span>' +
          '</div>' +
          '<div style="display:flex;gap:6px;flex-wrap:wrap;font-size:11.5px;">' +
          '<span class="badge green">🖼 ' + Number(d.images || 0) + ' صورة</span>' +
          (d.docs ? ('<span class="badge red">📄 ' + Number(d.docs) + ' مستند</span>') : '') +
          (d.archives ? ('<span class="badge gold">📦 ' + Number(d.archives) + ' مضغوط</span>') : '') +
          '</div>' +
          '<div style="display:flex;gap:6px;margin-top:2px;">' +
          '<button type="button" class="btn btn-primary btn-sm" style="flex:1;justify-content:center;" data-jump-archive-day="' + esc(d.day) + '" data-jump-type="images">🖼 صور اليوم</button>' +
          '<button type="button" class="btn btn-ghost btn-sm" style="flex:1;justify-content:center;" data-jump-archive-day="' + esc(d.day) + '" data-jump-type="">📂 كل الملفات</button>' +
          '</div>' +
          '</div>'
        ).join('') +
        '</div></div>';
    }).join('');
  }

  function renderArchiveFiles() {
    const body = $('archiveTableBody');
    const gallery = $('archiveGalleryPane');
    const empty = $('archiveEmpty');
    if (!body || !empty || !gallery) return;

    syncArchiveViewTabsUi();

    const isLocalHost = Boolean(window.__TAURI__ && window.__TAURI__.core)
      || location.hostname === '127.0.0.1'
      || location.hostname === 'localhost';

    const sum = archiveSummary || {
      total_files: archiveFilesCache.length,
      total_bytes: 0,
      whatsapp_count: 0,
      sensitive_count: 0,
      images_count: 0,
      today_count: 0,
      top_device: '—',
      top_device_count: 0,
    };

    if ($('dlpKpiTotal')) $('dlpKpiTotal').textContent = Number(sum.total_files || 0).toLocaleString('en-US');
    if ($('dlpKpiSize')) $('dlpKpiSize').textContent = formatArchiveBytes(sum.total_bytes);
    if ($('dlpKpiSensitive')) $('dlpKpiSensitive').textContent = Number(sum.sensitive_count || 0).toLocaleString('en-US');
    if ($('dlpKpiToday')) $('dlpKpiToday').textContent = Number(sum.today_count || 0).toLocaleString('en-US');
    if ($('dlpKpiTopDevice')) $('dlpKpiTopDevice').textContent = sum.top_device || '—';
    if ($('dlpKpiTopCount')) $('dlpKpiTopCount').textContent = (sum.top_device_count || 0) + ' ملف';
    if ($('navArchiveCount')) $('navArchiveCount').textContent = sum.total_files || 0;
    if ($('archiveStatsText')) {
      $('archiveStatsText').textContent =
        (sum.total_files || 0) + ' ملف (' + (sum.images_count || 0) + ' صورة · ' + (sum.whatsapp_count || 0) + ' واتساب · ' + formatArchiveBytes(sum.total_bytes) + ')';
    }

    if ($('archiveDeviceFilter') && document.activeElement !== $('archiveDeviceFilter')) {
      const curDev = $('archiveDeviceFilter').value || '';
      $('archiveDeviceFilter').innerHTML = '<option value="">كل الأجهزة (' + archiveDevicesList.length + ')</option>' +
        archiveDevicesList.map((d) => '<option value="' + esc(d.name) + '"' + (d.name === curDev ? ' selected' : '') + '>' + esc(d.name) + ' (' + d.count + ')</option>').join('');
    }

    if ($('archiveResetFiltersBtn')) {
      $('archiveResetFiltersBtn').style.display = hasActiveArchiveFilters() ? '' : 'none';
    }

    const bounds = computeArchiveTimeBounds();
    const dayBanner = $('archiveActiveDayBanner');
    if (dayBanner) {
      if (bounds.singleDay) {
        dayBanner.style.display = 'flex';
        if ($('archiveActiveDayText')) {
          $('archiveActiveDayText').textContent = '📅 تتصفح الآن أرشيف يوم: ' + formatDayTitleAr(bounds.singleDay) + ' (' + archiveTotalMatching + ' ملف مطابق)';
        }
      } else {
        dayBanner.style.display = 'none';
      }
    }

    renderArchiveDaysPane();

    const pageSize = parseInt(($('archPageSizeSelect') && $('archPageSizeSelect').value) || '60', 10) || 60;
    const fromIdx = archiveTotalMatching ? ((archiveCurPage - 1) * pageSize + 1) : 0;
    const toIdx = Math.min(archiveTotalMatching, fromIdx + archiveFilesCache.length - 1);
    if ($('archiveMatchCounter')) {
      $('archiveMatchCounter').textContent = archiveViewMode === 'days'
        ? ('إجمالي الأيام النشطة: ' + archiveDailyIndex.length + ' يوم · إجمالي الملفات: ' + (sum.total_files || 0))
        : (archiveTotalMatching
          ? ('عرض ' + fromIdx + '–' + toIdx + ' من أصل ' + archiveTotalMatching.toLocaleString('en-US') + ' ملف مطابق')
          : '0 ملف مطابق');
    }

    const pagBar = $('archivePaginationBar');
    if (pagBar) {
      const showPag = archiveViewMode !== 'days' && archiveTotalMatching > 0;
      pagBar.style.display = showPag ? 'flex' : 'none';
      if ($('archPageInfo')) $('archPageInfo').textContent = 'صفحة ' + archiveCurPage + ' من ' + archiveTotalPages;
      if ($('archPageFirst')) $('archPageFirst').disabled = archiveCurPage <= 1;
      if ($('archPagePrev')) $('archPagePrev').disabled = archiveCurPage <= 1;
      if ($('archPageNext')) $('archPageNext').disabled = archiveCurPage >= archiveTotalPages;
      if ($('archPageLast')) $('archPageLast').disabled = archiveCurPage >= archiveTotalPages;
    }

    if (archiveViewMode === 'days') {
      empty.style.display = 'none';
      return;
    }

    if (!archiveFilesCache.length) {
      body.innerHTML = '';
      gallery.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';

    // Render Photo Gallery Grid
    gallery.innerHTML = archiveFilesCache.map((f, idx) => {
      const cat = classifyArchiveExt(f.file_name);
      const isImg = cat === 'images';
      const inlineUrl = buildArchiveFileUrl(f.file_id, true);
      const dlUrl = buildArchiveFileUrl(f.file_id, false);
      const dt = formatArchiveExactDate(f.created_at);
      const ch = String(f.channel || 'whatsapp_web').toLowerCase();
      const chTag = ch.includes('whatsapp')
        ? '<span class="badge green" style="background:rgba(16,185,129,0.9);color:#fff;font-size:10.5px;">واتساب</span>'
        : '<span class="badge blue" style="background:rgba(37,99,235,0.9);color:#fff;font-size:10.5px;">ويب</span>';
      const extLabel = getFileExtUpper(f.file_name);
      const thumbInner = isImg
        ? '<img src="' + esc(inlineUrl) + '" alt="' + esc(f.file_name || '') + '" loading="lazy" decoding="async">'
        : '<div class="arch-doc-placeholder">' +
          '<div style="font-size:30px;">' + (cat === 'archives' ? '📦' : (extLabel === 'PDF' ? '📕' : '📄')) + '</div>' +
          '<span class="mono" style="background:rgba(255,255,255,0.14);padding:2px 8px;border-radius:6px;">' + esc(extLabel) + '</span>' +
          '</div>';
      const recip = f.recipient_name || f.page_url || '—';
      return '<div class="arch-photo-card">' +
        '<div class="arch-photo-thumb" data-arch-preview-idx="' + idx + '" title="اضغط للمعاينة المكبّرة">' +
        thumbInner +
        '<div class="arch-photo-overlay-top">' +
        chTag +
        '<span class="mono" style="background:rgba(15,23,42,0.78);color:#fff;padding:2px 7px;border-radius:6px;font-size:10.5px;font-weight:700;">' + esc(formatArchiveBytes(f.file_size)) + '</span>' +
        '</div>' +
        '</div>' +
        '<div class="arch-photo-body">' +
        '<div style="font-weight:800;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="' + esc(f.file_name || '') + '">' + esc(f.file_name || 'file.bin') + '</div>' +
        '<div class="mono" style="font-size:11px;color:var(--muted);">🗓 ' + esc(dt.date) + ' · ' + esc(dt.time) + '</div>' +
        '<div style="font-size:11.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">💻 <b>' + esc(f.device_name || f.device_id || '—') + '</b>' + (f.windows_user ? (' <span style="color:var(--muted);">(' + esc(f.windows_user) + ')</span>') : '') + '</div>' +
        '<div style="font-size:11.5px;color:var(--primary-2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="' + esc(recip + (f.recipient_phone ? (' ' + f.recipient_phone) : '')) + '">👤 ' + esc(recip) + (f.recipient_phone ? (' · <span class="mono" dir="ltr">' + esc(f.recipient_phone) + '</span>') : '') + '</div>' +
        '<div style="display:flex;gap:6px;margin-top:auto;padding-top:6px;">' +
        '<button type="button" class="btn btn-ghost btn-sm" style="flex:1;justify-content:center;padding:5px 8px;font-size:11.5px;" data-arch-preview-idx="' + idx + '">👁 معاينة</button>' +
        '<a class="btn btn-success btn-sm" style="flex:1;justify-content:center;padding:5px 8px;font-size:11.5px;text-decoration:none;" data-download-upload="' + esc(f.file_id || '') + '" data-file-name="' + esc(f.file_name || 'file') + '" href="' + esc(dlUrl) + '" target="_blank" rel="noreferrer" download="' + esc(f.file_name || 'file') + '">⬇ تحميل</a>' +
        '</div>' +
        '</div>' +
        '</div>';
    }).join('');

    // Render Detailed Table
    body.innerHTML = archiveFilesCache.map((f, idx) => {
      const cat = classifyArchiveExt(f.file_name);
      const isImg = cat === 'images';
      const inlineUrl = buildArchiveFileUrl(f.file_id, true);
      const dlUrl = buildArchiveFileUrl(f.file_id, false);
      const dt = formatArchiveExactDate(f.created_at);
      const ch = String(f.channel || 'whatsapp_web').toLowerCase();
      const chBadge = ch.includes('whatsapp')
        ? '<span class="badge green">واتساب</span>'
        : '<span class="badge">ويب</span>';
      const recipLine = esc(f.recipient_name || f.page_url || '—');
      const phoneLine = f.recipient_phone
        ? '<div class="mono" dir="ltr" style="font-size:11.5px;color:#2563eb;font-weight:700;">' + esc(f.recipient_phone) + '</div>'
        : '<div style="font-size:11px;color:#94a3b8;">بدون رقم ظاهر</div>';
      const shaShort = f.sha256 ? String(f.sha256).slice(0, 10) + '…' : '';
      const localBtn = (isLocalHost && f.stored_path)
        ? '<button class="btn btn-ghost btn-sm" type="button" data-open-archive-path="' + esc(f.stored_path) + '">📂</button>'
        : '';
      const miniThumb = isImg
        ? '<img class="arch-mini-thumb" src="' + esc(inlineUrl) + '" alt="" loading="lazy" decoding="async" data-arch-preview-idx="' + idx + '" title="اضغط لتكبير الصورة">'
        : '<div class="arch-mini-thumb" data-arch-preview-idx="' + idx + '" style="display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px;font-weight:800;">' + esc(getFileExtUpper(f.file_name)) + '</div>';
      return '<tr>' +
        '<td style="white-space:nowrap;">' +
        '<div class="mono" style="font-weight:800;font-size:12px;">' + esc(dt.date) + '</div>' +
        '<div style="font-size:11px;color:var(--muted);">' + esc(dt.time) + ' · ' + esc(ago(f.created_at)) + '</div>' +
        '</td>' +
        '<td><div style="display:flex;align-items:center;gap:10px;">' +
        miniThumb +
        '<div style="min-width:0;">' +
        '<div style="font-weight:700;word-break:break-word;">' + esc(f.file_name || 'file.bin') + '</div>' +
        '<div style="font-size:11px;color:#94a3b8;margin-top:2px;">' +
        '<span class="mono">' + esc(formatArchiveBytes(f.file_size)) + '</span>' +
        (shaShort ? (' · <span class="badge green" style="font-size:10px;padding:1px 6px;" title="SHA-256: ' + esc(f.sha256) + '">✓ ' + esc(shaShort) + '</span>') : '') +
        '</div></div></div></td>' +
        '<td>' + chBadge + '</td>' +
        '<td><div><b>' + esc(f.device_name || f.device_id || '—') + '</b></div>' +
        (f.windows_user ? ('<div class="mono" style="font-size:11px;color:#94a3b8;">' + esc(f.windows_user) + '</div>') : '') +
        '</td>' +
        '<td><div><b>' + recipLine + '</b></div>' + phoneLine + '</td>' +
        '<td><div style="display:flex;gap:6px;flex-wrap:wrap;">' +
        '<button type="button" class="btn btn-ghost btn-sm" data-arch-preview-idx="' + idx + '">👁 معاينة</button>' +
        '<a class="btn btn-success btn-sm" data-download-upload="' + esc(f.file_id || '') + '" data-file-name="' + esc(f.file_name || 'file') + '" href="' + esc(dlUrl) + '" target="_blank" rel="noreferrer" download="' + esc(f.file_name || 'file') + '" style="text-decoration:none;">⬇ تحميل</a>' +
        localBtn +
        '</div></td>' +
        '</tr>';
    }).join('');
  }

  function openArchiveLightbox(idx) {
    if (idx < 0 || idx >= archiveFilesCache.length) return;
    archLbIndex = idx;
    archLbZoomed = false;
    const modal = $('archiveLightboxModal');
    if (!modal) return;
    const f = archiveFilesCache[idx];
    const dt = formatArchiveExactDate(f.created_at);
    const cat = classifyArchiveExt(f.file_name);
    const ext = getFileExtUpper(f.file_name);
    const inlineUrl = buildArchiveFileUrl(f.file_id, true);
    const dlUrl = buildArchiveFileUrl(f.file_id, false);

    if ($('archLbTitle')) $('archLbTitle').textContent = f.file_name || 'ملف مؤرشف';
    if ($('archLbMeta')) {
      const parts = [
        '🗓 ' + dt.date + ' ' + dt.time,
        '📦 ' + formatArchiveBytes(f.file_size),
        '💻 ' + (f.device_name || f.device_id || '—') + (f.windows_user ? (' (' + f.windows_user + ')') : ''),
        '👤 ' + (f.recipient_name || f.page_url || '—') + (f.recipient_phone ? (' · ' + f.recipient_phone) : ''),
      ];
      $('archLbMeta').textContent = parts.join('   |   ');
    }
    if ($('archLbCounter')) $('archLbCounter').textContent = (idx + 1) + ' / ' + archiveFilesCache.length;
    if ($('archLbPrev')) $('archLbPrev').disabled = idx <= 0;
    if ($('archLbNext')) $('archLbNext').disabled = idx >= archiveFilesCache.length - 1;
    if ($('archLbZoomBtn')) {
      $('archLbZoomBtn').style.display = cat === 'images' ? '' : 'none';
      $('archLbZoomBtn').textContent = '🔍 تكبير';
    }
    const dlBtn = $('archLbDownloadBtn');
    if (dlBtn) {
      dlBtn.href = dlUrl;
      dlBtn.setAttribute('download', f.file_name || 'file');
      dlBtn.dataset.downloadUpload = f.file_id || '';
      dlBtn.dataset.fileName = f.file_name || 'file';
    }

    const stage = $('archLbStage');
    if (stage) {
      if (cat === 'images') {
        stage.innerHTML = '<img id="archLbImg" src="' + esc(inlineUrl) + '" alt="' + esc(f.file_name || '') + '" style="max-width:100%;max-height:68vh;object-fit:contain;border-radius:8px;cursor:zoom-in;">';
      } else if (ext === 'PDF') {
        stage.innerHTML = '<iframe src="' + esc(inlineUrl) + '" style="width:100%;height:68vh;border:0;border-radius:8px;background:#fff;"></iframe>';
      } else {
        stage.innerHTML = '<div style="text-align:center;color:#e2e8f0;padding:40px 20px;">' +
          '<div style="font-size:52px;margin-bottom:12px;">' + (cat === 'archives' ? '📦' : '📄') + '</div>' +
          '<div style="font-weight:800;font-size:17px;margin-bottom:6px;">' + esc(f.file_name || '') + '</div>' +
          '<div style="font-size:13px;color:#94a3b8;margin-bottom:18px;">صيغة الملف (' + esc(ext) + ') · الحجم: ' + esc(formatArchiveBytes(f.file_size)) + '</div>' +
          (f.sha256 ? ('<div class="mono" style="font-size:11px;color:#64748b;margin-bottom:16px;">SHA-256: ' + esc(f.sha256) + '</div>') : '') +
          '<p style="font-size:13px;color:#cbd5e1;">اضغط «⬇ تحميل الأصل» بالأعلى لفتح النسخة الكاملة على جهازك.</p>' +
          '</div>';
      }
    }
    modal.style.display = 'flex';
    modal.classList.add('show');
  }

  function closeArchiveLightbox() {
    const modal = $('archiveLightboxModal');
    if (!modal) return;
    modal.classList.remove('show');
    modal.style.display = 'none';
    if ($('archLbStage')) $('archLbStage').innerHTML = '';
    archLbIndex = -1;
  }

  function toggleArchiveLightboxZoom() {
    const img = $('archLbImg');
    if (!img) return;
    archLbZoomed = !archLbZoomed;
    if (archLbZoomed) {
      img.style.maxWidth = 'none';
      img.style.maxHeight = 'none';
      img.style.width = '155%';
      img.style.cursor = 'zoom-out';
      if ($('archLbZoomBtn')) $('archLbZoomBtn').textContent = '🔍 تصغير';
    } else {
      img.style.maxWidth = '100%';
      img.style.maxHeight = '68vh';
      img.style.width = '';
      img.style.cursor = 'zoom-in';
      if ($('archLbZoomBtn')) $('archLbZoomBtn').textContent = '🔍 تكبير';
    }
  }

  function updateArchiveDiskBadge(freeBytes, totalBytes) {
    const badge = $('archiveDiskSpaceBadge');
    if (!badge) return;
    const free = Number(freeBytes || 0);
    const total = Number(totalBytes || 0);
    if (!total) {
      badge.style.display = 'none';
      return;
    }
    const freeGb = (free / (1024 * 1024 * 1024)).toFixed(1);
    const totalGb = (total / (1024 * 1024 * 1024)).toFixed(0);
    badge.style.display = 'inline-flex';
    badge.textContent = '💾 متاح بالقرص: ' + freeGb + ' GB من ' + totalGb + ' GB';
    if (free < 5 * 1024 * 1024 * 1024) badge.className = 'badge red';
    else if (free < 15 * 1024 * 1024 * 1024) badge.className = 'badge gold';
    else badge.className = 'badge green';
  }

  let archiveBusy = false;
  async function loadArchiveFiles(resetPage) {
    if (!api.getUploadedFiles || archiveBusy) return;
    if (resetPage === true) archiveCurPage = 1;
    archiveBusy = true;
    try {
      const r = await api.getUploadedFiles(buildArchiveQueryObject());
      archiveFilesCache = (r && Array.isArray(r.files)) ? r.files : [];
      archiveSummary = (r && r.summary) ? r.summary : null;
      archiveDevicesList = (r && Array.isArray(r.devices)) ? r.devices : [];
      archiveDailyIndex = (r && Array.isArray(r.daily_index)) ? r.daily_index : [];
      archiveTotalMatching = (r && typeof r.total_matching === 'number') ? r.total_matching : archiveFilesCache.length;
      archiveTotalPages = (r && r.total_pages) ? r.total_pages : 1;
      archiveCurPage = (r && r.page) ? r.page : archiveCurPage;

      if (r && r.archive_root) {
        if ($('archiveRootPath')) $('archiveRootPath').textContent = r.archive_root;
        if ($('archiveDirInput') && document.activeElement !== $('archiveDirInput')) {
          $('archiveDirInput').value = r.archive_root;
        }
      }
      if (r) updateArchiveDiskBadge(r.disk_free_bytes, r.disk_total_bytes);
      if (r && Array.isArray(r.drives)) {
        renderServerDriveButtons('archiveServerDrivesBar', 'archiveDirInput', 'IT-ELKHAWGA-Archive', r.drives);
      }
      if ($('toggleArchivePathBtn')) {
        $('toggleArchivePathBtn').style.display = hasSuperAdminAccess() ? '' : 'none';
      }
      if ($('browseArchiveDirBtn')) {
        $('browseArchiveDirBtn').style.display = (api.browseArchiveFolder && $('adminUpdateStatusBadge') && $('adminUpdateStatusBadge').textContent.includes('الرئيسي')) ? '' : 'none';
      }
    } catch (e) {
      archiveFilesCache = [];
    } finally {
      archiveBusy = false;
    }
    renderArchiveFiles();
  }

  async function fetchFilteredArchiveForExport() {
    try {
      const r = await api.getUploadedFiles(buildArchiveQueryObject(5000));
      return (r && Array.isArray(r.files)) ? r.files : archiveFilesCache;
    } catch (e) {
      return archiveFilesCache;
    }
  }

  if ($('toggleArchivePathBtn')) {
    $('toggleArchivePathBtn').addEventListener('click', () => {
      const card = $('archiveStorageCard');
      if (!card) return;
      const nextShow = card.style.display === 'none';
      card.style.display = nextShow ? 'block' : 'none';
      if (nextShow && $('archiveDirInput')) {
        if (!$('archiveDirInput').value && $('archiveRootPath')) {
          $('archiveDirInput').value = $('archiveRootPath').textContent || '';
        }
        $('archiveDirInput').focus();
      }
    });
  }
  if ($('browseArchiveDirBtn')) {
    $('browseArchiveDirBtn').addEventListener('click', async () => {
      if (!api.browseArchiveFolder) return;
      try {
        const r = await api.browseArchiveFolder();
        if (r && r.success && r.path && $('archiveDirInput')) {
          $('archiveDirInput').value = r.path;
        }
      } catch (e) {
        toast(e.message || 'تعذر فتح مستعرض المجلدات', 'error');
      }
    });
  }
  async function applyArchiveDirChange(pathStr) {
    if (!api.setArchiveDir) return;
    const moveExisting = Boolean($('moveExistingArchiveChk') && $('moveExistingArchiveChk').checked);
    const btn = $('saveArchiveDirBtn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = '⏳ جارٍ التطبيق...'; }
    try {
      const r = await api.setArchiveDir(pathStr, moveExisting);
      if (r && r.success) {
        const movedMsg = r.moved_files ? (' (تم نقل ' + r.moved_files + ' ملف تلقائياً)') : '';
        toast('✓ تم تحديث مسار تخزين الأرشيف بنجاح' + movedMsg);
        if ($('archiveStorageCard')) $('archiveStorageCard').style.display = 'none';
        await loadArchiveFiles(false);
      } else {
        toast((r && r.error) || 'تعذر تغيير مسار التخزين', 'error');
      }
    } catch (e) {
      toast(e.message || 'تعذر تغيير مسار التخزين', 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
  }
  if ($('saveArchiveDirBtn')) {
    $('saveArchiveDirBtn').addEventListener('click', () => {
      const target = (($('archiveDirInput') && $('archiveDirInput').value) || '').trim();
      if (!target) { toast('اكتب المسار الجديد أو اختره بالماوس أولاً', 'error'); return; }
      applyArchiveDirChange(target);
    });
  }
  if ($('resetArchiveDirBtn')) {
    $('resetArchiveDirBtn').addEventListener('click', () => {
      if (!confirm('إعادة مسار تخزين الأرشيف إلى المجلد الافتراضي (C:\\IT-ELKHAWGA-Archive)؟')) return;
      applyArchiveDirChange('');
    });
  }

  if ($('archiveViewTabs')) {
    $('archiveViewTabs').addEventListener('click', (e) => {
      const b = e.target.closest('[data-archive-view]');
      if (!b) return;
      archiveViewMode = b.dataset.archiveView;
      try { localStorage.setItem('ibp_archive_view_mode', archiveViewMode); } catch (_) {}
      renderArchiveFiles();
    });
  }

  if ($('refreshArchiveBtn')) $('refreshArchiveBtn').addEventListener('click', () => loadArchiveFiles(false));
  if ($('archiveChannelFilter')) $('archiveChannelFilter').addEventListener('change', () => loadArchiveFiles(true));
  if ($('archiveDateFilter')) {
    $('archiveDateFilter').addEventListener('change', () => {
      const val = $('archiveDateFilter').value;
      if (val !== 'custom') {
        if ($('archiveDateFrom')) $('archiveDateFrom').value = '';
        if ($('archiveDateTo')) $('archiveDateTo').value = '';
      }
      loadArchiveFiles(true);
    });
  }
  if ($('archiveDateFrom')) {
    $('archiveDateFrom').addEventListener('change', () => {
      if ($('archiveDateFilter')) $('archiveDateFilter').value = ($('archiveDateFrom').value || ($('archiveDateTo') && $('archiveDateTo').value)) ? 'custom' : '';
      loadArchiveFiles(true);
    });
  }
  if ($('archiveDateTo')) {
    $('archiveDateTo').addEventListener('change', () => {
      if ($('archiveDateFilter')) $('archiveDateFilter').value = ($('archiveDateTo').value || ($('archiveDateFrom') && $('archiveDateFrom').value)) ? 'custom' : '';
      loadArchiveFiles(true);
    });
  }
  if ($('archiveSameDayBtn')) {
    $('archiveSameDayBtn').addEventListener('click', () => {
      const fromEl = $('archiveDateFrom');
      const toEl = $('archiveDateTo');
      const chosen = (fromEl && fromEl.value) || (toEl && toEl.value) || toLocalYmd(new Date());
      if (fromEl) fromEl.value = chosen;
      if (toEl) toEl.value = chosen;
      if ($('archiveDateFilter')) $('archiveDateFilter').value = 'custom';
      loadArchiveFiles(true);
    });
  }
  if ($('archiveClearDayBtn')) {
    $('archiveClearDayBtn').addEventListener('click', () => {
      if ($('archiveDateFrom')) $('archiveDateFrom').value = '';
      if ($('archiveDateTo')) $('archiveDateTo').value = '';
      if ($('archiveDateFilter')) $('archiveDateFilter').value = '';
      loadArchiveFiles(true);
    });
  }
  if ($('archiveResetFiltersBtn')) {
    $('archiveResetFiltersBtn').addEventListener('click', () => {
      if ($('archiveDateFilter')) $('archiveDateFilter').value = '';
      if ($('archiveDateFrom')) $('archiveDateFrom').value = '';
      if ($('archiveDateTo')) $('archiveDateTo').value = '';
      if ($('archiveTypeFilter')) $('archiveTypeFilter').value = '';
      if ($('archiveDeviceFilter')) $('archiveDeviceFilter').value = '';
      if ($('archiveChannelFilter')) $('archiveChannelFilter').value = '';
      if ($('archiveSearchInput')) $('archiveSearchInput').value = '';
      loadArchiveFiles(true);
    });
  }
  if ($('archiveTypeFilter')) $('archiveTypeFilter').addEventListener('change', () => loadArchiveFiles(true));
  if ($('archiveDeviceFilter')) $('archiveDeviceFilter').addEventListener('change', () => loadArchiveFiles(true));
  if ($('archiveSearchInput')) {
    $('archiveSearchInput').addEventListener('input', () => {
      clearTimeout(archSearchTimer);
      archSearchTimer = setTimeout(() => loadArchiveFiles(true), 260);
    });
  }
  if ($('archPageSizeSelect')) $('archPageSizeSelect').addEventListener('change', () => loadArchiveFiles(true));
  if ($('archPageFirst')) $('archPageFirst').addEventListener('click', () => { if (archiveCurPage > 1) { archiveCurPage = 1; loadArchiveFiles(false); } });
  if ($('archPagePrev')) $('archPagePrev').addEventListener('click', () => { if (archiveCurPage > 1) { archiveCurPage--; loadArchiveFiles(false); } });
  if ($('archPageNext')) $('archPageNext').addEventListener('click', () => { if (archiveCurPage < archiveTotalPages) { archiveCurPage++; loadArchiveFiles(false); } });
  if ($('archPageLast')) $('archPageLast').addEventListener('click', () => { if (archiveCurPage < archiveTotalPages) { archiveCurPage = archiveTotalPages; loadArchiveFiles(false); } });

  if ($('archLbClose')) $('archLbClose').addEventListener('click', closeArchiveLightbox);
  if ($('archLbPrev')) $('archLbPrev').addEventListener('click', () => { if (archLbIndex > 0) openArchiveLightbox(archLbIndex - 1); });
  if ($('archLbNext')) $('archLbNext').addEventListener('click', () => { if (archLbIndex < archiveFilesCache.length - 1) openArchiveLightbox(archLbIndex + 1); });
  if ($('archLbZoomBtn')) $('archLbZoomBtn').addEventListener('click', toggleArchiveLightboxZoom);
  if ($('archiveLightboxModal')) {
    $('archiveLightboxModal').addEventListener('click', (e) => {
      if (e.target === $('archiveLightboxModal')) closeArchiveLightbox();
      else if (e.target && e.target.id === 'archLbImg') toggleArchiveLightboxZoom();
    });
  }
  document.addEventListener('keydown', (e) => {
    const modal = $('archiveLightboxModal');
    if (!modal || modal.style.display === 'none') return;
    if (e.key === 'Escape') closeArchiveLightbox();
    else if (e.key === 'ArrowLeft' && archLbIndex < archiveFilesCache.length - 1) openArchiveLightbox(archLbIndex + 1);
    else if (e.key === 'ArrowRight' && archLbIndex > 0) openArchiveLightbox(archLbIndex - 1);
  });

  document.addEventListener('click', (e) => {
    const dayBtn = e.target.closest('[data-jump-archive-day]');
    if (dayBtn) {
      const day = dayBtn.dataset.jumpArchiveDay || '';
      const jType = dayBtn.dataset.jumpType || '';
      if ($('archiveDateFrom')) $('archiveDateFrom').value = day;
      if ($('archiveDateTo')) $('archiveDateTo').value = day;
      if ($('archiveDateFilter')) $('archiveDateFilter').value = 'custom';
      if ($('archiveTypeFilter')) $('archiveTypeFilter').value = jType;
      archiveViewMode = jType === 'images' ? 'gallery' : 'table';
      try { localStorage.setItem('ibp_archive_view_mode', archiveViewMode); } catch (_) {}
      loadArchiveFiles(true);
      return;
    }
    const prevEl = e.target.closest('[data-arch-preview-idx]');
    if (prevEl) {
      const idx = parseInt(prevEl.dataset.archPreviewIdx, 10);
      if (!isNaN(idx)) openArchiveLightbox(idx);
    }
  });

  if ($('exportDlpCsvBtn')) {
    $('exportDlpCsvBtn').addEventListener('click', async () => {
      const list = await fetchFilteredArchiveForExport();
      if (!list.length) { toast('لا توجد ملفات مطابقة لتصديرها', 'error'); return; }
      const header = ['التاريخ والوقت', 'اسم الملف', 'الحجم', 'القناة', 'الجهاز', 'مستخدم الويندوز', 'المرسل إليه / الوجهة', 'رقم الهاتف', 'SHA-256', 'المسار على السيرفر'].map(csvCell).join(',');
      const rows = list.map((f) => [
        f.created_at ? new Date(f.created_at).toLocaleString('ar-EG') : '',
        f.file_name || '',
        formatArchiveBytes(f.file_size),
        String(f.channel || '').includes('whatsapp') ? 'واتساب ويب' : 'ويب',
        f.device_name || f.device_id || '',
        f.windows_user || '',
        f.recipient_name || f.page_url || '',
        f.recipient_phone || '',
        f.sha256 || '',
        f.stored_path || '',
      ].map(csvCell).join(','));
      const d = new Date().toISOString().slice(0, 10);
      await saveDownloadText([header].concat(rows).join('\r\n'), 'IT-ELKHAWGA-DLP-Report-' + d + '.csv', 'text/csv;charset=utf-8');
    });
  }
  if ($('exportDlpPrintBtn')) {
    $('exportDlpPrintBtn').addEventListener('click', async () => {
      const list = await fetchFilteredArchiveForExport();
      if (!list.length) { toast('لا توجد ملفات مطابقة لإنشاء التقرير', 'error'); return; }
      const nowStr = new Date().toLocaleString('ar-EG');
      const rowsHtml = list.map((f, idx) =>
        '<tr>' +
        '<td>' + (idx + 1) + '</td>' +
        '<td>' + esc(f.created_at ? new Date(f.created_at).toLocaleString('ar-EG') : '—') + '</td>' +
        '<td><b>' + esc(f.device_name || f.device_id || '—') + '</b><br><small>' + esc(f.windows_user || '') + '</small></td>' +
        '<td><b>' + esc(f.file_name || '') + '</b><br><small>' + esc(formatArchiveBytes(f.file_size)) + '</small></td>' +
        '<td>' + (String(f.channel || '').includes('whatsapp') ? 'واتساب ويب' : 'ويب') + '</td>' +
        '<td>' + esc(f.recipient_name || f.page_url || '—') + (f.recipient_phone ? ('<br><span dir="ltr">' + esc(f.recipient_phone) + '</span>') : '') + '</td>' +
        '<td style="font-family:monospace;font-size:10px;">' + esc((f.sha256 || '').slice(0, 16)) + '</td>' +
        '</tr>'
      ).join('');
      const reportHtml = '<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>تقرير حماية الملفات DLP - IT ELKHAWGA</title>' +
        '<style>body{font-family:Segoe UI,Tahoma,sans-serif;margin:28px;color:#0f172a}h1{margin:0 0 6px;font-size:22px;color:#0f4c81}.meta{color:#475569;font-size:13px;margin-bottom:18px}table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{border:1px solid #cbd5e1;padding:8px 10px;text-align:right;vertical-align:top}th{background:#f1f5f9;font-weight:800}@media print{.no-print{display:none}}</style></head><body>' +
        '<div class="no-print" style="margin-bottom:16px;"><button onclick="window.print()" style="padding:8px 18px;font-weight:700;cursor:pointer;">🖨 طباعة / حفظ كملف PDF</button></div>' +
        '<h1>IT ELKHAWGA — تقرير حماية الملفات والبيانات (DLP)</h1>' +
        '<div class="meta">تاريخ إصدار التقرير: ' + esc(nowStr) + ' · إجمالي السجلات بالتقرير: <b>' + list.length + '</b></div>' +
        '<table><thead><tr><th>#</th><th>التاريخ والوقت</th><th>الجهاز / المستخدم</th><th>الملف والحجم</th><th>القناة</th><th>المرسل إليه / الرقم</th><th>بصمة SHA-256</th></tr></thead><tbody>' + rowsHtml + '</tbody></table>' +
        '</body></html>';
      const d = new Date().toISOString().slice(0, 10);
      await saveDownloadText(reportHtml, 'IT-ELKHAWGA-DLP-Printable-' + d + '.html', 'text/html;charset=utf-8');
    });
  }
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
    if (dlLink && isAppleTouch) {
      e.preventDefault();
      const fid = dlLink.dataset.downloadUpload || '';
      if (fid) {
        const tokPart = authToken ? ('&token=' + encodeURIComponent(authToken)) : '';
        window.open(serverHttpBase + '/api/uploads/' + encodeURIComponent(fid) + '?inline=1' + tokPart, '_blank', 'noopener,noreferrer');
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

  let connTimer = null;
  let connBusy = false;
  async function refreshServerConnectionPill(manualClick) {
    const pill = $('adminServerConnPill');
    const txt = $('adminServerConnText');
    if (!pill || !txt || connBusy) return;
    connBusy = true;
    const t0 = performance.now();
    try {
      const info = api.checkServerConnection
        ? await api.checkServerConnection()
        : await api.getServerInfo();
      const rtt = Math.max(1, Math.round(performance.now() - t0));
      const relayOk = info && info.relay_connected !== undefined ? Boolean(info.relay_connected) : true;
      const isHost = Boolean(info && info.is_host_server);
      const lanOk = Boolean(info && Number(info.lan_port || info.port || 0) > 0);
      const pingMs = Number(info && info.relay_latency_ms) || rtt;

      if (relayOk) {
        pill.className = 'live-pill srv-conn ok';
        txt.textContent = isHost ? 'السيرفر الرئيسي متصل' : ('متصل بالسيرفر · ' + pingMs + 'ms');
        pill.title = isHost
          ? ('أنت تعمل على السيرفر الرئيسي مباشرة (LAN :' + (info.lan_port || 8787) + ' + Relay متاح)')
          : ('متصل بسيرفر الشركة بنجاح — زمن الاستجابة: ' + pingMs + 'ms');
        if (manualClick) toast('✓ متصل بالسيرفر بنجاح (' + pingMs + 'ms)');
      } else if (lanOk && isTauriRuntime) {
        pill.className = 'live-pill srv-conn warn';
        txt.textContent = 'متصل محلياً فقط (السحابي غير متاح)';
        pill.title = (info && info.error) || 'تعذر الوصول للسيرفر السحابي حالياً';
        if (manualClick) toast('⚠ البرنامج يعمل محلياً لكن تعذر الوصول للسيرفر السحابي: ' + ((info && info.error) || ''), 'error');
      } else {
        pill.className = 'live-pill srv-conn offline';
        txt.textContent = 'غير متصل بالسيرفر!';
        pill.title = (info && info.error) || 'انقطع الاتصال بالسيرفر';
        if (manualClick) toast('🔴 غير متصل بالسيرفر: ' + ((info && info.error) || 'تحقق من الإنترنت أو تشغيل السيرفر'), 'error');
      }
    } catch (err) {
      pill.className = 'live-pill srv-conn offline';
      txt.textContent = 'غير متصل بالسيرفر!';
      pill.title = 'انقطع الاتصال بالسيرفر — جاري إعادة المحاولة تلقائياً';
      if (manualClick) toast('🔴 تعذر الاتصال بالسيرفر حالياً — تأكد من الإنترنت أو حالة السيرفر الرئيسي', 'error');
    } finally {
      connBusy = false;
    }
  }
  if ($('adminServerConnPill')) {
    $('adminServerConnPill').addEventListener('click', () => refreshServerConnectionPill(true));
  }

  /* ---------- WhatsApp Bot Center ---------- */
  let waBotPollTimer = null;
  let waBotDirty = false;
  let waBotLoadedOnce = false;
  let waBotLastState = 'disconnected';

  async function callWaBotApi(shimName, rpcCmd, rpcArgs) {
    if (api && typeof api[shimName] === 'function') {
      if (shimName === 'saveWaBotConfig') return api.saveWaBotConfig(rpcArgs && rpcArgs.config);
      if (shimName === 'disconnectWaBot') return api.disconnectWaBot(Boolean(rpcArgs && rpcArgs.logout));
      return api[shimName]();
    }
    if (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function') {
      return window.__TAURI__.core.invoke(rpcCmd, rpcArgs || {});
    }
    const headers = { 'Content-Type': 'application/json' };
    const tok = (api && api.getAuthToken && api.getAuthToken()) || authToken || '';
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    const resp = await fetch('/api/rpc', {
      method: 'POST',
      headers,
      body: JSON.stringify({ cmd: rpcCmd, args: rpcArgs || {} }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    return data.result;
  }

  function updateWaBotFeatureCountBadge() {
    const boxes = Array.from(document.querySelectorAll('input[data-wa-feat]'));
    const active = boxes.filter((b) => b.checked).length;
    const badge = $('waBotActiveFeatCount');
    if (badge) {
      badge.textContent = 'الخصائص المفعّلة: ' + active + ' من ' + (boxes.length || 13);
      badge.className = 'badge ' + (active > 0 ? 'green' : 'gray');
    }
  }

  function collectWaBotConfigFromUi() {
    const features = {};
    document.querySelectorAll('input[data-wa-feat]').forEach((el) => {
      const k = el.getAttribute('data-wa-feat');
      if (k) features[k] = Boolean(el.checked);
    });
    return {
      enabled: Boolean($('waBotEnabledToggle') && $('waBotEnabledToggle').checked),
      recipients: (($('waBotRecipientsInput') && $('waBotRecipientsInput').value) || '').trim(),
      max_file_mb: Math.max(1, Math.min(64, Number(($('waBotMaxMbInput') && $('waBotMaxMbInput').value) || 25) || 25)),
      custom_aliases: (($('waBotCustomAliasesInput') && $('waBotCustomAliasesInput').value) || '').trim(),
      features,
    };
  }

  function renderWaBotStatus(st, forceSyncForm) {
    if (!st || (!st.ok && !st.success)) return;
    const state = st.state || 'disconnected';
    waBotLastState = state;
    const badge = $('waBotStateBadge');
    const desc = $('waBotStateDesc');
    const navBadge = $('navWaBotBadge');
    const qrBox = $('waBotQrBox');
    const qrImg = $('waBotQrImg');
    const errBanner = $('waBotErrorBanner');
    const connectBtn = $('waBotConnectBtn');
    const testBtn = $('waBotTestBtn');
    const pauseBtn = $('waBotPauseBtn');
    const logoutBtn = $('waBotLogoutBtn');

    if (navBadge) {
      if (state === 'connected') {
        navBadge.style.display = '';
        navBadge.textContent = st.config && st.config.enabled ? 'نشط' : 'متصل';
        navBadge.style.background = st.config && st.config.enabled ? 'rgba(16,185,129,0.18)' : 'rgba(59,130,246,0.16)';
        navBadge.style.color = st.config && st.config.enabled ? '#10b981' : '#3b82f6';
      } else if (state === 'qr_ready') {
        navBadge.style.display = '';
        navBadge.textContent = 'QR';
        navBadge.style.background = 'rgba(245,158,11,0.18)';
        navBadge.style.color = '#f59e0b';
      } else {
        navBadge.style.display = 'none';
      }
    }

    if (badge) {
      if (state === 'connected') {
        badge.className = 'badge green';
        badge.textContent = '🟢 متصل' + (st.bot_phone ? (' (+' + st.bot_phone + ')') : '');
      } else if (state === 'qr_ready') {
        badge.className = 'badge amber';
        badge.textContent = '🟡 بانتظار مسح رمز QR';
      } else if (state === 'connecting') {
        badge.className = 'badge blue';
        badge.textContent = '🔄 جاري الاتصال بواتساب...';
      } else {
        badge.className = 'badge gray';
        badge.textContent = st.has_saved_session ? '⏸ متوقف مؤقتاً (الجلسة محفوظة)' : '⚪ غير مرتبط';
      }
    }

    if (desc) {
      if (state === 'connected') {
        desc.innerHTML = '✅ تم ربط هاتف البوت بنجاح' +
          (st.bot_name ? (' (<b>' + esc(st.bot_name) + '</b>)') : '') +
          '. اختر الخصائص التي تريد تفعيلها بالأسفل أو أرسل رسالة اختبار للتأكد من وصول التنبيهات لهاتفك.';
      } else if (state === 'qr_ready') {
        desc.innerHTML = '📱 امسح رمز <b>QR</b> الظاهر على اليسار من تطبيق واتساب على شريحة البوت (الأجهزة المرتبطة ⬅ ربط جهاز). يتم التحديث تلقائياً فور المسح.';
      } else if (state === 'connecting') {
        desc.innerHTML = '⏳ جاري تهيئة الاتصال المشفّر مع خوادم واتساب وتجهيز الجلسة...';
      } else {
        desc.innerHTML = 'اربط رقم شريحة البوت بمسح رمز <b>QR</b> مرة واحدة فقط، ثم شغّل أو أوقف كل خاصية على حدة بحرية كاملة.';
      }
    }

    if (qrBox && qrImg) {
      if (state === 'qr_ready' && st.qr_data_url) {
        qrImg.src = st.qr_data_url;
        qrBox.style.display = 'flex';
      } else {
        qrBox.style.display = 'none';
      }
    }

    if (errBanner) {
      if (st.last_error) {
        errBanner.textContent = '⚠ ' + st.last_error;
        errBanner.style.display = 'block';
      } else {
        errBanner.style.display = 'none';
      }
    }

    if (connectBtn) {
      connectBtn.style.display = state === 'connected' ? 'none' : '';
      connectBtn.textContent = st.has_saved_session && state === 'disconnected'
        ? '▶ استئناف اتصال البوت'
        : (state === 'qr_ready' ? '↻ توليد رمز QR جديد' : '🔗 ربط / توليد رمز QR');
    }
    if (testBtn) testBtn.style.display = state === 'connected' ? '' : 'none';
    if (pauseBtn) pauseBtn.style.display = (state === 'connected' || state === 'connecting' || state === 'qr_ready') ? '' : 'none';
    if (logoutBtn) logoutBtn.style.display = (state === 'connected' || st.has_saved_session) ? '' : 'none';

    if ((forceSyncForm || !waBotLoadedOnce || !waBotDirty) && st.config) {
      waBotLoadedOnce = true;
      const cfg = st.config;
      if ($('waBotEnabledToggle')) $('waBotEnabledToggle').checked = Boolean(cfg.enabled);
      if ($('waBotRecipientsInput')) $('waBotRecipientsInput').value = cfg.recipients || '';
      if ($('waBotMaxMbInput')) $('waBotMaxMbInput').value = cfg.max_file_mb || 25;
      if ($('waBotCustomAliasesInput')) $('waBotCustomAliasesInput').value = cfg.custom_aliases || '';
      const feats = cfg.features || {};
      document.querySelectorAll('input[data-wa-feat]').forEach((el) => {
        const k = el.getAttribute('data-wa-feat');
        el.checked = Boolean(k && feats[k]);
      });
      if (forceSyncForm) waBotDirty = false;
      updateWaBotFeatureCountBadge();
    }

    const logsEl = $('waBotLogsBox');
    if (logsEl && Array.isArray(st.logs)) {
      logsEl.textContent = st.logs.length
        ? st.logs.map((l) => '[' + (l.time || '') + '] ' + (l.text || '')).join('\n')
        : 'لا توجد أحداث مسجلة بعد.';
    }
  }

  async function loadWaBotStatus(forceSyncForm) {
    try {
      const st = await callWaBotApi('getWaBotStatus', 'get_wa_bot_status', {});
      renderWaBotStatus(st, Boolean(forceSyncForm));
    } catch (_) {}
  }

  function startWaBotPoll() {
    stopWaBotPoll();
    waBotPollTimer = setInterval(() => {
      if (document.hidden) return;
      const open = $('view-wabot') && $('view-wabot').classList.contains('active');
      if (!open) return;
      loadWaBotStatus(false);
    }, 2500);
  }

  function stopWaBotPoll() {
    if (waBotPollTimer) {
      clearInterval(waBotPollTimer);
      waBotPollTimer = null;
    }
  }

  async function saveWaBotSettings(showToastMsg = true) {
    const cfg = collectWaBotConfigFromUi();
    const res = await callWaBotApi('saveWaBotConfig', 'save_wa_bot_config', { config: cfg });
    if (res && (res.ok || res.success)) {
      waBotDirty = false;
      renderWaBotStatus(res, true);
      if (showToastMsg) toast('✓ تم حفظ إعدادات وخصائص بوت واتساب بنجاح');
      return true;
    }
    if (showToastMsg) toast((res && res.error) || 'تعذر حفظ إعدادات البوت', 'error');
    return false;
  }

  (function initWaBotUi() {
    document.querySelectorAll('input[data-wa-feat], #waBotEnabledToggle, #waBotRecipientsInput, #waBotMaxMbInput, #waBotCustomAliasesInput').forEach((el) => {
      el.addEventListener('change', () => {
        waBotDirty = true;
        updateWaBotFeatureCountBadge();
      });
      if ((el.tagName === 'INPUT' && el.type !== 'checkbox') || el.tagName === 'TEXTAREA') {
        el.addEventListener('input', () => { waBotDirty = true; });
      }
    });

    if ($('waBotSelectAllBtn')) {
      $('waBotSelectAllBtn').addEventListener('click', () => {
        document.querySelectorAll('input[data-wa-feat]').forEach((el) => { el.checked = true; });
        if ($('waBotEnabledToggle')) $('waBotEnabledToggle').checked = true;
        waBotDirty = true;
        updateWaBotFeatureCountBadge();
      });
    }

    if ($('waBotClearAllBtn')) {
      $('waBotClearAllBtn').addEventListener('click', () => {
        document.querySelectorAll('input[data-wa-feat]').forEach((el) => { el.checked = false; });
        waBotDirty = true;
        updateWaBotFeatureCountBadge();
      });
    }

    ['waBotSaveBtn', 'waBotSaveBtnBottom'].forEach((id) => {
      if ($(id)) {
        $(id).addEventListener('click', async () => {
          const btn = $(id);
          const orig = btn.innerHTML;
          btn.disabled = true;
          btn.innerHTML = '<span class="spinner"></span> جاري الحفظ...';
          try { await saveWaBotSettings(true); } finally { btn.disabled = false; btn.innerHTML = orig; }
        });
      }
    });

    if ($('waBotConnectBtn')) {
      $('waBotConnectBtn').addEventListener('click', async () => {
        const btn = $('waBotConnectBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري تجهيز QR...';
        try {
          if (waBotDirty) await saveWaBotSettings(false);
          const res = await callWaBotApi('connectWaBot', 'connect_wa_bot', {});
          if (res && (res.ok || res.success)) {
            renderWaBotStatus(res, false);
            startWaBotPoll();
            if (res.state === 'qr_ready') {
              toast('📱 تم توليد رمز QR — امسحه الآن من هاتف البوت');
            }
          } else {
            toast((res && res.error) || 'تعذر بدء ربط البوت', 'error');
          }
        } catch (e) {
          toast('خطأ: ' + (e.message || e), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('waBotPauseBtn')) {
      $('waBotPauseBtn').addEventListener('click', async () => {
        const res = await callWaBotApi('disconnectWaBot', 'disconnect_wa_bot', { logout: false });
        if (res && (res.ok || res.success)) {
          renderWaBotStatus(res, false);
          toast('تم إيقاف اتصال البوت مؤقتاً مع الاحتفاظ بالجلسة');
        } else {
          toast((res && res.error) || 'تعذر الإيقاف', 'error');
        }
      });
    }

    if ($('waBotLogoutBtn')) {
      $('waBotLogoutBtn').addEventListener('click', async () => {
        if (!window.confirm('هل تريد فك ربط رقم الهاتف الحالي نهائياً ومسح الجلسة لربط رقم جديد؟')) return;
        const res = await callWaBotApi('disconnectWaBot', 'disconnect_wa_bot', { logout: true });
        if (res && (res.ok || res.success)) {
          renderWaBotStatus(res, false);
          toast('تم فك ربط الرقم بنجاح — يمكنك مسح QR لرقم جديد');
        } else {
          toast((res && res.error) || 'تعذر فك الربط', 'error');
        }
      });
    }

    if ($('waBotTestBtn')) {
      $('waBotTestBtn').addEventListener('click', async () => {
        const btn = $('waBotTestBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الإرسال...';
        try {
          if (waBotDirty) await saveWaBotSettings(false);
          const res = await callWaBotApi('sendWaBotTest', 'send_wa_bot_test', {});
          if (res && (res.ok || res.success)) {
            toast('✅ تم إرسال رسالة الاختبار إلى واتساب بنجاح!');
            loadWaBotStatus(false);
          } else {
            toast((res && res.error) || 'تعذر إرسال رسالة الاختبار', 'error');
          }
        } catch (e) {
          toast('تعذر الإرسال: ' + (e.message || e), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('waBotRefreshBtn')) {
      $('waBotRefreshBtn').addEventListener('click', () => loadWaBotStatus(true));
    }
  })();

  /* ---------- Dahua Next-Generation Enterprise Video Player (MediaMTX WebRTC + fMP4/MSE Zero-Transcode + HLS Fallback) ---------- */
  let cctvDvrs = [];
  let cctvSettings = { super_only: false, auto_hide_empty: true, favorites: [] };
  let cctvGridCols = Number(localStorage.getItem('ibp_cctv_grid_cols') || 2) || 2; // 1 (1), 2 (4), 3 (9), 4 (16), 5 (25), 6 (36)
  let cctvSelectedBranch = localStorage.getItem('ibp_cctv_selected_branch') || 'all';
  let cctvChannelPage = 0;
  let cctvLivePlaying = true;
  let cctvAutoTourTimer = null;
  let cctvStreamEpoch = 0;
  let cctvDetectedChannelNames = null;
  let cctvBridgeDevicesCache = [];
  let cctvEngineMode = localStorage.getItem('ibp_cctv_engine_mode') || 'nextgen'; // 'nextgen' | 'webrtc' | 'mse' | 'hls' | 'legacy'
  let cctvStreamQualityMode = localStorage.getItem('ibp_cctv_quality_mode') || 'auto'; // 'auto' | 'main' | 'sub'
  let cctvBufferMode = localStorage.getItem('ibp_cctv_buffer_mode') || 'realtime'; // 'realtime' (<0.4s) | 'smooth3s' (3s buffer)
  let cctvAspectFitMode = localStorage.getItem('ibp_cctv_aspect_fit') || 'fill'; // 'fill' (Fill Screen 100%) | 'contain' (Fit to Screen 16:9)
  let cctvFocusedTileKey = ''; // dvrId:channel promoted to Main Stream HD when clicked in multi-cam grids
  const cctvTileStreamOverride = new Map(); // tileKey -> 'hd' | 'sd' per-camera manual override
  const cctvTileZoomState = new Map(); // tileKey -> { scale, x, y } for in-place mouse-wheel zoom on any tile
  const cctvTileFpsTracker = new Map(); // tileKey -> { count, lastSec, fps, kbps, bytesSec }
  const cctvActiveRecorders = new Map(); // tileKey -> { canvas, ctx, recorder, chunks, timer, startedAt, fileName }
  const cctvFrameVault = new Map(); // tileKey -> { src, at, transport, hd, fps } for 0ms instant first-frame paint
  const cctvActiveTilePlayers = new Map(); // tileKey -> { stop: () => void, kind: string, hd: boolean, videoEl: HTMLVideoElement }
  let cctvHdActivePlayer = null; // { stop: () => void, kind: string, hd: boolean }
  let cctvCustomLayoutOrder = []; // Array of tileKey ('dvrId:channel') saved by Drag & Drop / Save Layout
  try {
    const savedLayout = JSON.parse(localStorage.getItem('ibp_cctv_custom_layout') || 'null');
    if (savedLayout && Array.isArray(savedLayout.order)) {
      cctvCustomLayoutOrder = savedLayout.order;
    }
  } catch (_) {}
  let cctvDragSourceKey = '';
  let cctvHdTarget = null; // { dvrId, channel, tilesList, index, item, hdOverride }
  let cctvHdEpoch = 0;
  let cctvHdLastDataUrl = '';
  let cctvZoomScale = 1;
  let cctvPanX = 0;
  let cctvPanY = 0;
  let cctvDragging = false;
  let cctvDragStart = { x: 0, y: 0 };
  let cctvHudIdleTimer = null;
  let cctvHudVisible = true;
  let cctvWallFsIdleTimer = null;

  function resolveCctvRelayOrigin() {
    if (location.port === '8790') return '';
    if (location.hostname === '127.0.0.1' || location.hostname === 'localhost' || isNativeTauriOrigin) {
      return 'http://127.0.0.1:8790';
    }
    return '';
  }

  function destroyAllActiveTilePlayers() {
    for (const p of cctvActiveTilePlayers.values()) {
      try { if (p && typeof p.stop === 'function') p.stop(); } catch (_) {}
    }
    cctvActiveTilePlayers.clear();
  }

  function destroyHdActivePlayer() {
    if (cctvHdActivePlayer) {
      try { if (typeof cctvHdActivePlayer.stop === 'function') cctvHdActivePlayer.stop(); } catch (_) {}
      cctvHdActivePlayer = null;
    }
    const vid = $('cctvHdVideo');
    if (vid) {
      try { vid.pause(); } catch (_) {}
      try { vid.srcObject = null; } catch (_) {}
      try { vid.removeAttribute('src'); vid.load(); } catch (_) {}
      vid.style.display = 'none';
    }
  }

  function captureVideoElementDataUrl(videoEl, imgFallbackEl) {
    if (videoEl && videoEl.style.display !== 'none' && videoEl.readyState >= 2 && videoEl.videoWidth > 0) {
      try {
        const c = document.createElement('canvas');
        const rawW = videoEl.videoWidth;
        const rawH = videoEl.videoHeight;
        // Correct Dahua anamorphic 1080N (960x1080) to true 1920x1080 16:9 in screenshots!
        c.width = (rawW === 960 && rawH === 1080) ? 1920 : rawW;
        c.height = rawH;
        const ctx = c.getContext('2d');
        ctx.drawImage(videoEl, 0, 0, c.width, c.height);
        return c.toDataURL('image/jpeg', 0.94);
      } catch (_) {}
    }
    if (imgFallbackEl && imgFallbackEl.dataset && imgFallbackEl.dataset.lastSrc) {
      return imgFallbackEl.dataset.lastSrc;
    }
    return '';
  }

  function setCctvHdHudVisible(visible) {
    cctvHudVisible = Boolean(visible);
    const topHud = $('cctvHdTopHud');
    const botHud = $('cctvHdBottomHud');
    const ptzPad = $('cctvPtzPad');
    const vp = $('cctvHdViewport');
    if (topHud) {
      topHud.style.opacity = cctvHudVisible ? '1' : '0';
      topHud.style.transform = cctvHudVisible ? 'translateY(0)' : 'translateY(-16px)';
      topHud.style.pointerEvents = cctvHudVisible ? 'auto' : 'none';
    }
    if (botHud) {
      botHud.style.opacity = cctvHudVisible ? '1' : '0';
      botHud.style.transform = cctvHudVisible ? 'translateY(0)' : 'translateY(16px)';
      botHud.style.pointerEvents = cctvHudVisible ? 'auto' : 'none';
    }
    if (ptzPad && ptzPad.style.display !== 'none') {
      ptzPad.style.transition = 'opacity 0.32s ease';
      ptzPad.style.opacity = cctvHudVisible ? '1' : '0';
      ptzPad.style.pointerEvents = cctvHudVisible ? 'auto' : 'none';
    }
    if (vp) {
      vp.style.cursor = cctvHudVisible
        ? (cctvZoomScale > 1 ? (cctvDragging ? 'grabbing' : 'grab') : 'default')
        : 'none';
    }
  }

  function wakeCctvHdHud() {
    const modal = $('cctvHdModal');
    if (!modal || !modal.classList.contains('show')) return;
    if (!cctvHudVisible) {
      setCctvHdHudVisible(true);
    }
    if (cctvHudIdleTimer) clearTimeout(cctvHudIdleTimer);
    cctvHudIdleTimer = setTimeout(() => {
      const m = $('cctvHdModal');
      if (!m || !m.classList.contains('show')) return;
      setCctvHdHudVisible(false);
    }, 2500);
  }

  function setCctvWallFsHudVisible(visible) {
    const isFs = Boolean(document.fullscreenElement && document.fullscreenElement.id === 'cctvTheaterStage');
    const topCard = $('cctvTopControlCard');
    const wall = $('cctvWallGrid');
    if (!isFs) {
      if (topCard) topCard.style.display = '';
      document.querySelectorAll('.cctv-tile-hud').forEach((el) => {
        el.style.opacity = '1';
        el.style.pointerEvents = el.dataset.hudInteractive === '1' ? 'auto' : 'none';
      });
      if (wall) wall.style.cursor = '';
      return;
    }
    if (topCard) {
      topCard.style.display = visible ? '' : 'none';
    }
    if (wall) {
      wall.style.height = visible ? 'calc(100vh - 64px)' : '100vh';
      wall.style.minHeight = visible ? 'calc(100vh - 64px)' : '100vh';
      wall.style.cursor = visible ? 'pointer' : 'none';
    }
    document.querySelectorAll('.cctv-tile-hud').forEach((el) => {
      el.style.transition = 'opacity 0.32s ease';
      el.style.opacity = visible ? '1' : '0';
      if (el.dataset.hudInteractive === '1') {
        el.style.pointerEvents = visible ? 'auto' : 'none';
      }
    });
  }

  function wakeCctvWallFsHud() {
    const isFs = Boolean(document.fullscreenElement && document.fullscreenElement.id === 'cctvTheaterStage');
    if (!isFs) return;
    setCctvWallFsHudVisible(true);
    if (cctvWallFsIdleTimer) clearTimeout(cctvWallFsIdleTimer);
    cctvWallFsIdleTimer = setTimeout(() => {
      const stillFs = Boolean(document.fullscreenElement && document.fullscreenElement.id === 'cctvTheaterStage');
      if (stillFs) setCctvWallFsHudVisible(false);
    }, 2500);
  }

  // Live Camera Audio state (`0% CPU` & `0 B/s` when muted)
  let cctvAudioTarget = null; // { dvrId, channel, label }
  let cctvAudioEpoch = 0;
  let cctvAudioCtx = null;
  let cctvAudioGain = null;
  let cctvAudioVolume = 1.35;
  let cctvAudioNextTime = 0;
  let cctvAudioLastAdtsTail = null; // { bytes: Uint8Array, count: number }
  const cctvAudioScanAttempted = new Set();

  // True whenever running inside the installed Tauri Desktop Admin app (`http://tauri.localhost` or `tauri://`)
  // so camera frames & clip downloads route through Rust -> Cloud Relay HTTPS instead of relative `/api/cctv/...`!
  const isNativeTauriOrigin = Boolean(
    window.__TAURI__ &&
    window.__TAURI__.core &&
    (location.hostname === 'tauri.localhost' || (location.protocol !== 'http:' && location.protocol !== 'https:'))
  );

  async function callCctvApi(shimName, rpcCmd, rpcArgs) {
    if (api && typeof api[shimName] === 'function') {
      if (shimName === 'cctvSaveDvr') return api.cctvSaveDvr(rpcArgs && rpcArgs.dvr);
      if (shimName === 'cctvDeleteDvr') return api.cctvDeleteDvr(rpcArgs && rpcArgs.id);
      if (shimName === 'cctvTestDvr') return api.cctvTestDvr(rpcArgs && rpcArgs.dvr);
      if (shimName === 'cctvScanLan') return api.cctvScanLan(rpcArgs && rpcArgs.bridgeDeviceId);
      if (shimName === 'cctvSetSettings') return api.cctvSetSettings(Boolean(rpcArgs && rpcArgs.superOnly));
      if (shimName === 'cctvGetFrameB64') return api.cctvGetFrameB64(rpcArgs.dvrId, rpcArgs.channel, rpcArgs.hd);
      if (shimName === 'cctvAction') return api.cctvAction(rpcArgs.action, rpcArgs.payload);
      return api[shimName]();
    }
    if (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function') {
      return window.__TAURI__.core.invoke(rpcCmd, rpcArgs || {});
    }
    const headers = { 'Content-Type': 'application/json' };
    const tok = (api && api.getAuthToken && api.getAuthToken()) || authToken || '';
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    const resp = await fetch('/api/rpc', {
      method: 'POST',
      headers,
      body: JSON.stringify({ cmd: rpcCmd, args: rpcArgs || {} }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    return data.result;
  }

  function isChannelFav(dvrId, channel) {
    const favs = Array.isArray(cctvSettings.favorites) ? cctvSettings.favorites : [];
    return favs.some((f) => f.dvr_id === dvrId && Number(f.channel) === Number(channel));
  }

  async function toggleChannelFav(dvrId, channel) {
    const cur = Array.isArray(cctvSettings.favorites) ? cctvSettings.favorites.slice() : [];
    const idx = cur.findIndex((f) => f.dvr_id === dvrId && Number(f.channel) === Number(channel));
    const added = idx === -1;
    if (added) {
      cur.push({ dvr_id: dvrId, channel: Number(channel) });
    } else {
      cur.splice(idx, 1);
    }
    const res = await callCctvApi('cctvAction', 'cctv_action', {
      action: 'save_favorites',
      payload: { favorites: cur },
    });
    if (res && res.ok && res.settings) {
      cctvSettings = res.settings;
      syncCctvBranchAndPageSelectors();
      toast(added ? '⭐ تمت إضافة الكاميرا إلى شاشة الإدارة المفضّلة (VIP)' : 'تمت إزالة الكاميرا من المفضّلة');
      renderCctvWall();
    }
  }

  function applyCctvRoleVisibility() {
    const isSuper = hasSuperAdminAccess();
    const isViewer = String(currentAdminRole || '').toLowerCase() === 'viewer';
    const navItem = $('navCamerasItem');
    if (navItem) {
      navItem.style.display = (cctvSettings.super_only && !isSuper) ? 'none' : '';
    }
    const superWrap = $('cctvSuperOnlyWrap');
    if (superWrap) {
      superWrap.style.display = isSuper ? 'inline-flex' : 'none';
    }
    const superSw = $('cctvSuperOnlySwitch');
    if (superSw) {
      superSw.checked = Boolean(cctvSettings.super_only);
    }
    const autoHideSw = $('cctvAutoHideSwitch');
    if (autoHideSw) {
      autoHideSw.checked = cctvSettings.auto_hide_empty !== false;
    }
    const manageBtn = $('cctvManageToggleBtn');
    if (manageBtn) {
      manageBtn.style.display = isViewer ? 'none' : '';
    }
  }

  function buildCctvFrameUrl(dvrId, channel, hd) {
    const tok = (api && api.getAuthToken && api.getAuthToken()) || authToken || '';
    const qs = new URLSearchParams({
      dvr_id: String(dvrId || ''),
      channel: String(channel || 1),
      hd: hd ? '1' : '0',
      _t: String(Date.now()) + '_' + Math.random().toString(36).slice(2, 6),
    });
    if (tok) qs.set('token', tok);
    return '/api/cctv/frame?' + qs.toString();
  }

  function isChannelSkipped(dvr, ch) {
    const manualHidden = Array.isArray(dvr.hidden_channels) && dvr.hidden_channels.includes(Number(ch));
    if (manualHidden) return true;
    if (cctvSettings.auto_hide_empty !== false) {
      const deadArr = Array.isArray(dvr.dead_channels) ? dvr.dead_channels : [];
      if (deadArr.includes(Number(ch))) return true;
    }
    return false;
  }

  function getVisibleCctvTiles() {
    const enabledDvrs = cctvDvrs.filter((d) => d.enabled !== false);
    if (!enabledDvrs.length) return { allTiles: [], pageTiles: [], totalPages: 1 };
    const perPage = cctvGridCols * cctvGridCols;

    if (cctvSelectedBranch === 'vip') {
      const favs = Array.isArray(cctvSettings.favorites) ? cctvSettings.favorites : [];
      const tiles = [];
      for (const f of favs) {
        const d = enabledDvrs.find((x) => x.id === f.dvr_id);
        if (!d) continue;
        const ch = Number(f.channel || 1);
        const customTitle = (d.channel_names && d.channel_names[String(ch)]) || '';
        tiles.push({
          dvr: d,
          dvrId: d.id,
          channel: ch,
          branchName: d.name,
          camLabel: customTitle ? ('ك' + ch + ' · ' + customTitle) : ('كاميرا ' + ch),
        });
      }
      const totalPages = Math.max(1, Math.ceil(tiles.length / perPage));
      if (cctvChannelPage >= totalPages) cctvChannelPage = 0;
      const start = cctvChannelPage * perPage;
      return { allTiles: tiles, pageTiles: tiles.slice(start, start + perPage), totalPages };
    }

    if (cctvSelectedBranch === 'all') {
      const tiles = [];
      let maxCh = 1;
      enabledDvrs.forEach((d) => { if ((d.channels_count || 1) > maxCh) maxCh = d.channels_count || 1; });
      for (let ch = 1; ch <= maxCh && tiles.length < 64; ch++) {
        for (const d of enabledDvrs) {
          if (ch <= (d.channels_count || 8) && !isChannelSkipped(d, ch)) {
            const customTitle = (d.channel_names && d.channel_names[String(ch)]) || '';
            tiles.push({
              dvr: d,
              dvrId: d.id,
              channel: ch,
              branchName: d.name,
              camLabel: customTitle ? ('ك' + ch + ' · ' + customTitle) : ('كاميرا ' + ch),
            });
          }
        }
      }
      if (cctvCustomLayoutOrder.length > 0) {
        const orderMap = new Map(cctvCustomLayoutOrder.map((k, i) => [k, i]));
        tiles.sort((a, b) => {
          const ka = a.dvrId + ':' + a.channel;
          const kb = b.dvrId + ':' + b.channel;
          const ia = orderMap.has(ka) ? orderMap.get(ka) : 9999;
          const ib = orderMap.has(kb) ? orderMap.get(kb) : 9999;
          return ia - ib;
        });
      }
      const totalPages = Math.max(1, Math.ceil(tiles.length / perPage));
      if (cctvChannelPage >= totalPages) cctvChannelPage = 0;
      const start = cctvChannelPage * perPage;
      return { allTiles: tiles, pageTiles: tiles.slice(start, start + perPage), totalPages };
    }

    const dvr = enabledDvrs.find((d) => d.id === cctvSelectedBranch) || enabledDvrs[0];
    if (!dvr) return { allTiles: [], pageTiles: [], totalPages: 1 };
    const totalCh = Math.max(1, Number(dvr.channels_count || 8));
    const tiles = [];
    for (let ch = 1; ch <= totalCh; ch++) {
      if (isChannelSkipped(dvr, ch)) continue;
      const customTitle = (dvr.channel_names && dvr.channel_names[String(ch)]) || '';
      tiles.push({
        dvr,
        dvrId: dvr.id,
        channel: ch,
        branchName: dvr.name,
        camLabel: customTitle ? ('كاميرا ' + ch + ' · ' + customTitle) : ('كاميرا ' + ch),
      });
    }
    if (cctvCustomLayoutOrder.length > 0) {
      const orderMap = new Map(cctvCustomLayoutOrder.map((k, i) => [k, i]));
      tiles.sort((a, b) => {
        const ka = a.dvrId + ':' + a.channel;
        const kb = b.dvrId + ':' + b.channel;
        const ia = orderMap.has(ka) ? orderMap.get(ka) : 9999;
        const ib = orderMap.has(kb) ? orderMap.get(kb) : 9999;
        return ia - ib;
      });
    }
    const totalPages = Math.max(1, Math.ceil(tiles.length / perPage));
    if (cctvChannelPage >= totalPages) cctvChannelPage = 0;
    const start = cctvChannelPage * perPage;
    return { allTiles: tiles, pageTiles: tiles.slice(start, start + perPage), totalPages };
  }

  function stopCctvAutoTour() {
    if (cctvAutoTourTimer) {
      clearInterval(cctvAutoTourTimer);
      cctvAutoTourTimer = null;
    }
    const btn = $('cctvAutoTourBtn');
    if (btn) {
      btn.className = 'btn btn-ghost btn-sm';
      btn.textContent = '🔄 دوران';
    }
  }

  function toggleCctvAutoTour() {
    if (cctvAutoTourTimer) {
      stopCctvAutoTour();
      toast('تم إيقاف الدوران التلقائي');
      return;
    }
    const btn = $('cctvAutoTourBtn');
    if (btn) {
      btn.className = 'btn btn-primary btn-sm';
      btn.textContent = '🔄 يدور الآن (12ث)';
    }
    toast('🔄 تم تشغيل وضع الدوران التلقائي لغرفة العمليات (يقلب كل 12 ثانية)');
    cctvAutoTourTimer = setInterval(() => {
      if (document.hidden) return;
      const open = $('view-cameras') && $('view-cameras').classList.contains('active');
      if (!open) { stopCctvAutoTour(); return; }
      const computed = getVisibleCctvTiles();
      const totalPages = computed.totalPages || 1;
      if (totalPages > 1) {
        cctvChannelPage = (cctvChannelPage + 1) % totalPages;
        renderCctvWall();
      } else if (cctvDvrs.length > 1) {
        const ids = ['all'].concat(cctvDvrs.map((d) => d.id));
        const curIdx = ids.indexOf(cctvSelectedBranch);
        cctvSelectedBranch = ids[(curIdx + 1) % ids.length];
        cctvChannelPage = 0;
        if ($('cctvBranchSelect')) $('cctvBranchSelect').value = cctvSelectedBranch;
        renderCctvWall();
      }
    }, 12000);
  }

  function stopCctvWall() {
    cctvStreamEpoch += 1;
    destroyAllActiveTilePlayers();
    destroyHdActivePlayer();
    stopCctvAutoTour();
    stopCctvAudio(true);
    closeCctvHdModal();
  }

  function hasChannelAudio(dvr, channel) {
    if (!dvr || !Array.isArray(dvr.audio_channels)) return false;
    return dvr.audio_channels.includes(Number(channel));
  }

  function isAudioPlayingFor(dvrId, channel) {
    return Boolean(
      cctvAudioTarget &&
      cctvAudioTarget.dvrId === dvrId &&
      Number(cctvAudioTarget.channel) === Number(channel)
    );
  }

  function ensureCctvAudioContext() {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) {
      throw new Error('متصفحك الحالي لا يدعم تشغيل الصوت المباشر (Web Audio API)');
    }
    if (!cctvAudioCtx || cctvAudioCtx.state === 'closed') {
      cctvAudioCtx = new AudioCtx();
      cctvAudioGain = cctvAudioCtx.createGain();
      cctvAudioGain.gain.value = cctvAudioVolume;
      cctvAudioGain.connect(cctvAudioCtx.destination);
    }
    if (cctvAudioCtx.state === 'suspended') {
      cctvAudioCtx.resume().catch(() => {});
    }
    // Unlock iPadOS / iOS Safari audio output inside user gesture
    try {
      const silent = cctvAudioCtx.createBuffer(1, 1, 22050);
      const sNode = cctvAudioCtx.createBufferSource();
      sNode.buffer = silent;
      sNode.connect(cctvAudioGain);
      sNode.start(0);
    } catch (_) {}
    return cctvAudioCtx;
  }

  function setCctvAudioVolumePercent(pct) {
    const clamped = Math.max(20, Math.min(250, Number(pct || 135) || 135));
    cctvAudioVolume = clamped / 100;
    if (cctvAudioGain && cctvAudioCtx) {
      try { cctvAudioGain.gain.setValueAtTime(cctvAudioVolume, cctvAudioCtx.currentTime); } catch (_) {
        cctvAudioGain.gain.value = cctvAudioVolume;
      }
    }
    if ($('cctvWallVolumeSlider') && Number($('cctvWallVolumeSlider').value) !== clamped) {
      $('cctvWallVolumeSlider').value = String(clamped);
    }
    if ($('cctvHdVolumeSlider') && Number($('cctvHdVolumeSlider').value) !== clamped) {
      $('cctvHdVolumeSlider').value = String(clamped);
    }
  }

  function sliceTailAdtsFrames(u8, maxFrames) {
    const slices = [];
    let pos = 0;
    while (pos + 7 <= u8.length) {
      if (u8[pos] === 0xff && (u8[pos + 1] & 0xf0) === 0xf0 && (u8[pos + 1] & 0x06) === 0x00) {
        const len = ((u8[pos + 3] & 0x03) << 11) | (u8[pos + 4] << 3) | ((u8[pos + 5] & 0xe0) >> 5);
        if (len >= 7 && len <= 2048 && pos + len <= u8.length) {
          slices.push(u8.subarray(pos, pos + len));
          pos += len;
          continue;
        }
      }
      pos += 1;
    }
    if (!slices.length) return null;
    const picked = slices.slice(-maxFrames);
    let total = 0;
    picked.forEach((s) => { total += s.length; });
    const out = new Uint8Array(total);
    let off = 0;
    picked.forEach((s) => { out.set(s, off); off += s.length; });
    return { bytes: out, count: picked.length };
  }

  async function scheduleCctvAudioChunk(chunk, boundEpoch) {
    if (!chunk || !chunk.data_b64 || !cctvAudioCtx || !cctvAudioGain) return;
    if (boundEpoch !== cctvAudioEpoch || !cctvAudioTarget) return;
    const bin = atob(chunk.data_b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    if (!u8.length) return;

    if (chunk.format === 'aac') {
      const prevTail = cctvAudioLastAdtsTail;
      cctvAudioLastAdtsTail = sliceTailAdtsFrames(u8, 2);
      let decodeU8 = u8;
      let warmupFrames = 0;
      if (prevTail && prevTail.bytes && prevTail.bytes.length) {
        decodeU8 = new Uint8Array(prevTail.bytes.length + u8.length);
        decodeU8.set(prevTail.bytes, 0);
        decodeU8.set(u8, prevTail.bytes.length);
        warmupFrames = prevTail.count;
      }
      try {
        const audioBuf = await cctvAudioCtx.decodeAudioData(decodeU8.buffer.slice(0));
        if (boundEpoch !== cctvAudioEpoch || !cctvAudioTarget) return;
        const sr = Math.max(8000, Number(chunk.sample_rate || 16000) || 16000);
        const fc = Math.max(1, Number(chunk.frame_count || 1) || 1);
        const expectedDur = (fc * 1024) / sr;
        const warmupOffset = warmupFrames > 0
          ? Math.max(0, Math.min(Math.max(0, audioBuf.duration - expectedDur), (warmupFrames * 1024) / sr))
          : 0;
        const playDur = Math.max(0.01, Math.min(expectedDur, audioBuf.duration - warmupOffset));
        const nowCtx = cctvAudioCtx.currentTime;
        if (cctvAudioNextTime < nowCtx + 0.04) {
          cctvAudioNextTime = nowCtx + 0.28;
        } else if (cctvAudioNextTime > nowCtx + 1.5) {
          cctvAudioNextTime = nowCtx + 0.30;
        }
        const src = cctvAudioCtx.createBufferSource();
        src.buffer = audioBuf;
        src.connect(cctvAudioGain);
        src.start(cctvAudioNextTime, warmupOffset, playDur);
        cctvAudioNextTime += playDur;
      } catch (_) {}
      return;
    }

    // 16-bit Little-Endian PCM (`pcm16`, e.g. decoded G.711A / G.711Mu @ 8000 Hz)
    const sampleCount = Math.floor(u8.length / 2);
    if (sampleCount <= 0) return;
    const sr = Math.max(8000, Number(chunk.sample_rate || 8000) || 8000);
    const audioBuf = cctvAudioCtx.createBuffer(1, sampleCount, sr);
    const chData = audioBuf.getChannelData(0);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    for (let i = 0; i < sampleCount; i++) {
      chData[i] = dv.getInt16(i * 2, true) / 32768;
    }
    const nowCtx = cctvAudioCtx.currentTime;
    if (cctvAudioNextTime < nowCtx + 0.04) {
      cctvAudioNextTime = nowCtx + 0.26;
    } else if (cctvAudioNextTime > nowCtx + 1.5) {
      cctvAudioNextTime = nowCtx + 0.28;
    }
    const src = cctvAudioCtx.createBufferSource();
    src.buffer = audioBuf;
    src.connect(cctvAudioGain);
    src.start(cctvAudioNextTime);
    cctvAudioNextTime += audioBuf.duration;
  }

  function syncCctvAudioButtonsUi() {
    const topBar = $('cctvActiveAudioBar');
    const topLbl = $('cctvActiveAudioLabel');
    if (topBar) {
      topBar.style.display = cctvAudioTarget ? 'inline-flex' : 'none';
      if (topLbl && cctvAudioTarget) {
        topLbl.textContent = '🎙️ ' + (cctvAudioTarget.label || ('كاميرا ' + cctvAudioTarget.channel));
      }
    }

    const computed = getVisibleCctvTiles();
    const pageTiles = computed.pageTiles || [];
    document.querySelectorAll('[data-cctv-audio]').forEach((btn) => {
      const idx = Number(btn.getAttribute('data-cctv-audio') || 0);
      const t = pageTiles[idx];
      if (!t) return;
      const playing = isAudioPlayingFor(t.dvrId, t.channel);
      const hasMic = hasChannelAudio(t.dvr, t.channel);
      const scannedNoMic = Boolean(t.dvr && t.dvr.audio_scanned && !hasMic);
      if (playing) {
        btn.textContent = '🔊 شغّال';
        btn.style.background = 'rgba(16,185,129,0.92)';
        btn.style.color = '#ffffff';
        btn.style.borderColor = '#34d399';
        btn.style.opacity = '1';
      } else if (hasMic) {
        btn.textContent = '🔇 صوت';
        btn.style.background = 'rgba(15,23,42,0.84)';
        btn.style.color = '#34d399';
        btn.style.borderColor = 'rgba(52,211,153,0.55)';
        btn.style.opacity = '1';
      } else {
        btn.textContent = '🔇';
        btn.style.background = 'rgba(15,23,42,0.75)';
        btn.style.color = '#94a3b8';
        btn.style.borderColor = 'rgba(148,163,184,0.28)';
        btn.style.opacity = scannedNoMic ? '0.52' : '0.88';
      }
    });

    const hdBtn = $('cctvHdAudioBtn');
    const hdVol = $('cctvHdVolumeSlider');
    if (hdBtn && cctvHdTarget && cctvHdTarget.item) {
      const it = cctvHdTarget.item;
      const playing = isAudioPlayingFor(it.dvrId, it.channel);
      const hasMic = hasChannelAudio(it.dvr, it.channel);
      if (playing) {
        hdBtn.className = 'btn btn-success btn-sm';
        hdBtn.style.color = '#fff';
        hdBtn.textContent = '🔊 الصوت يعمل (كتم)';
        if (hdVol) hdVol.style.display = '';
      } else {
        hdBtn.className = 'btn btn-ghost btn-sm';
        hdBtn.style.color = hasMic ? '#34d399' : '#94a3b8';
        hdBtn.style.borderColor = hasMic ? 'rgba(52,211,153,0.5)' : 'rgba(148,163,184,0.3)';
        hdBtn.textContent = (it.dvr && it.dvr.audio_scanned && !hasMic)
          ? '🔇 بدون مايك'
          : (hasMic ? '🔇 تشغيل الصوت 🎙️' : '🔇 تشغيل الصوت');
        if (hdVol) hdVol.style.display = 'none';
      }
    }
  }

  function stopCctvAudio(notifyBackend) {
    const prev = cctvAudioTarget;
    cctvAudioEpoch += 1;
    cctvAudioTarget = null;
    cctvAudioNextTime = 0;
    cctvAudioLastAdtsTail = null;
    if (cctvAudioCtx && cctvAudioCtx.state === 'running') {
      // Reset scheduled nodes cleanly by recreating gain node
      try {
        if (cctvAudioGain) cctvAudioGain.disconnect();
        cctvAudioGain = cctvAudioCtx.createGain();
        cctvAudioGain.gain.value = cctvAudioVolume;
        cctvAudioGain.connect(cctvAudioCtx.destination);
      } catch (_) {}
    }
    syncCctvAudioButtonsUi();
    if (notifyBackend && prev) {
      callCctvApi('cctvAction', 'cctv_action', {
        action: 'stop_audio',
        payload: { dvr_id: prev.dvrId },
      }).catch(() => {});
    }
  }

  async function toggleCctvAudio(dvr, channel, label) {
    if (!dvr) return;
    const ch = Number(channel || 1) || 1;
    if (isAudioPlayingFor(dvr.id, ch)) {
      stopCctvAudio(true);
      toast('🔇 تم كتم صوت الكاميرا');
      return;
    }

    try {
      ensureCctvAudioContext();
    } catch (e) {
      toast(e.message || 'تعذر تهيئة الصوت', 'error');
      return;
    }

    if (cctvAudioTarget && cctvAudioTarget.dvrId !== dvr.id) {
      callCctvApi('cctvAction', 'cctv_action', {
        action: 'stop_audio',
        payload: { dvr_id: cctvAudioTarget.dvrId },
      }).catch(() => {});
    }

    cctvAudioEpoch += 1;
    const myAudioEpoch = cctvAudioEpoch;
    cctvAudioTarget = {
      dvrId: dvr.id,
      channel: ch,
      label: label || (dvr.name + ' · كاميرا ' + ch),
    };
    cctvAudioNextTime = 0;
    cctvAudioLastAdtsTail = null;
    syncCctvAudioButtonsUi();
    toast('🔊 جاري تشغيل الصوت المباشر: ' + cctvAudioTarget.label);

    let lastSeq = 0;
    const pollLoop = async () => {
      if (myAudioEpoch !== cctvAudioEpoch || !cctvAudioTarget) return;
      const camOpen = ($('view-cameras') && $('view-cameras').classList.contains('active')) ||
        ($('cctvHdModal') && $('cctvHdModal').classList.contains('show'));
      if (!camOpen || document.hidden) {
        if (!camOpen) {
          stopCctvAudio(true);
          return;
        }
        setTimeout(pollLoop, 500);
        return;
      }
      try {
        const res = await callCctvApi('cctvAction', 'cctv_action', {
          action: 'poll_audio',
          payload: {
            dvr_id: dvr.id,
            channel: ch,
            since_seq: lastSeq,
          },
        });
        if (myAudioEpoch !== cctvAudioEpoch || !cctvAudioTarget) return;
        if (!res || !res.ok) {
          const errMsg = (res && res.error) || 'هذه الكاميرا غير مزوّدة بمايكروفون';
          if (res && Array.isArray(res.audio_channels)) {
            dvr.audio_channels = res.audio_channels;
            dvr.audio_scanned = true;
          }
          stopCctvAudio(false);
          toast(errMsg, 'error');
          return;
        }
        if (typeof res.seq === 'number' && res.seq > lastSeq) {
          lastSeq = res.seq;
        }
        if (Array.isArray(res.chunks) && res.chunks.length) {
          for (const c of res.chunks) {
            await scheduleCctvAudioChunk(c, myAudioEpoch);
          }
        }
        setTimeout(pollLoop, 260);
      } catch (e) {
        if (myAudioEpoch !== cctvAudioEpoch) return;
        setTimeout(pollLoop, 900);
      }
    };
    pollLoop();
  }

  function renderCctvHealthBar() {
    const bar = $('cctvHealthSummaryBar');
    if (!bar) return;
    if (!cctvDvrs.length) {
      bar.style.display = 'none';
      return;
    }
    const badges = cctvDvrs.map((d) => {
      const h = d.health || {};
      if (!h.checked_at) {
        return '<span class="badge gray" title="اضغط «🛡️ فحص الهاردات» لفحص حالة التسجيل">🏢 ' + esc(d.name) + ': لم يُفحص الهارد بعد</span>';
      }
      if (h.hdd_status === 'ok') {
        const space = h.total_gb > 0 ? (' · متاح ' + h.free_gb + 'GB من ' + h.total_gb + 'GB') : '';
        return '<span class="badge green">🟢 ' + esc(d.name) + ': هارد سليم' + esc(space) + '</span>';
      }
      if (h.hdd_status === 'error') {
        return '<span class="badge red">🚨 ' + esc(d.name) + ': عطل في هارد التسجيل!</span>';
      }
      if (h.hdd_status === 'missing') {
        return '<span class="badge amber">⚠️ ' + esc(d.name) + ': لا يوجد هارد مكتشف</span>';
      }
      return '<span class="badge blue">🏢 ' + esc(d.name) + (h.device_model ? (' · ' + esc(h.device_model)) : '') + '</span>';
    });
    bar.innerHTML = badges.join('');
    bar.style.display = 'flex';
  }

  function syncCctvBranchAndPageSelectors() {
    const sel = $('cctvBranchSelect');
    if (sel) {
      const prev = cctvSelectedBranch;
      const favCount = Array.isArray(cctvSettings.favorites) ? cctvSettings.favorites.length : 0;
      const opts = [
        '<option value="all">🌐 غرفة العمليات الموحدة (كل الفروع — ' + cctvDvrs.length + ')</option>',
      ];
      if (favCount > 0 || prev === 'vip') {
        opts.unshift('<option value="vip">⭐ شاشة الإدارة المفضّلة VIP (' + favCount + ' كاميرات)</option>');
      }
      cctvDvrs.forEach((d) => {
        const modeTag = d.connection_mode === 'router' ? '🌐 راوتر مباشر 100%' : (d.connection_mode === 'bridge' ? '🌉 جسر فرع' : '🖧 مباشر');
        opts.push(
          '<option value="' + esc(d.id) + '">🏢 ' + esc(d.name) + ' (' + (d.channels_count || 8) + ' كاميرات · ' + modeTag + ')</option>'
        );
      });
      sel.innerHTML = opts.join('');
      if ((prev === 'vip' && favCount > 0) || (prev !== 'all' && cctvDvrs.some((d) => d.id === prev))) {
        sel.value = prev;
      } else {
        cctvSelectedBranch = 'all';
        sel.value = 'all';
      }
    }

    const navCnt = $('navCctvCount');
    if (navCnt) navCnt.textContent = String(cctvDvrs.length || 0);
    renderCctvHealthBar();
  }

  function renderCctvSavedList() {
    const box = $('cctvSavedList');
    if (!box) return;
    if (!cctvDvrs.length) {
      box.innerHTML = '<div class="empty" style="padding:16px;">لم يتم إضافة أي جهاز Dahua DVR بعد. أضف أول فرع أو مخزن بالأعلى.</div>';
      return;
    }
    box.innerHTML = '<div style="display:grid;gap:8px;">' + cctvDvrs.map((d) => {
      const modeBadge = d.connection_mode === 'router'
        ? '<span class="badge green">🌐 راوتر الفرع مباشر 100%: ' + esc((d.router_host || d.host) + ':' + (d.router_http_port || 8085)) + '</span>'
        : (d.connection_mode === 'bridge'
          ? '<span class="badge blue">🌉 جسر الفرع: ' + esc(d.bridge_device_name || d.bridge_device_id || 'غير محدد') + '</span>'
          : '<span class="badge green">🖧 مباشر على شبكة السيرفر</span>');
      const hiddenCnt = Array.isArray(d.hidden_channels) ? d.hidden_channels.length : 0;
      return (
        '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;padding:10px 13px;border-radius:10px;background:var(--surface-2);border:1px solid var(--border);">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">' +
            '<strong style="font-size:13.5px;">🏢 ' + esc(d.name) + '</strong>' +
            modeBadge +
            '<span class="mono" dir="ltr" style="font-size:12px;color:var(--muted);">' + esc(d.host) + ':' + (d.http_port || 80) + '</span>' +
            '<span class="badge gray">' + (d.channels_count || 8) + ' كاميرات' + (hiddenCnt ? (' · ' + hiddenCnt + ' مخفية') : '') + '</span>' +
            (d.allowed_admins ? '<span class="badge amber">👥 مخصّص لـ: ' + esc(d.allowed_admins) + '</span>' : '') +
          '</div>' +
          '<div style="display:flex;gap:6px;flex-wrap:wrap;">' +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-watch="' + esc(d.id) + '">👁 عرض</button>' +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-pullnames="' + esc(d.id) + '" title="سحب أسماء الكاميرات من داخل الـ DVR">🏷️ سحب الأسماء</button>' +
            (hiddenCnt ? '<button type="button" class="btn btn-ghost btn-sm" data-cctv-unhideall="' + esc(d.id) + '">👁 إظهار المخفي</button>' : '') +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-edit="' + esc(d.id) + '">✏ تعديل</button>' +
            '<button type="button" class="btn btn-danger btn-sm" data-cctv-del="' + esc(d.id) + '">🗑 حذف</button>' +
          '</div>' +
        '</div>'
      );
    }).join('') + '</div>';
  }

  // ==========================================================================
  // Dahua Next-Generation Enterprise Video Stream Session Manager
  // (WebRTC WHEP + Direct Zero-Transcode fMP4/MSE + Low-Latency HLS + Legacy Fallback)
  // ==========================================================================
  function startNextGenVideoStreamSession({
    dvrId,
    channel,
    hd,
    videoEl,
    imgFallbackEl,
    statusOverlayEl,
    statusDotEl,
    fpsBadgeEl,
    timeBadgeEl,
    codecBadgeEl,
    onReady,
    onOffline,
  }) {
    let cancelled = false;
    let pc = null;
    let abortCtrl = null;
    let mediaSource = null;
    let sourceBuffer = null;
    let msUrl = '';
    let retryTimer = null;
    let telemetryTimer = null;
    let retryAttempt = 0;
    let bytesCounter = 0;
    let lastMeasureAt = Date.now();
    let streamProtocolLabel = '';
    let streamCodecLabel = '';
    let firstFrameElapsedMs = 0;
    const sessionStartAt = Date.now();

    const setStatusOverlay = (mode, text, subText) => {
      if (cancelled) return;
      if (statusDotEl) {
        statusDotEl.style.background = mode === 'live' ? '#10b981' : (mode === 'offline' ? '#ef4444' : '#f59e0b');
        statusDotEl.style.boxShadow = '0 0 8px ' + (mode === 'live' ? '#10b981' : (mode === 'offline' ? '#ef4444' : '#f59e0b'));
      }
      if (!statusOverlayEl) return;
      if (mode === 'live') {
        statusOverlayEl.style.display = 'none';
        return;
      }
      statusOverlayEl.style.display = 'flex';
      statusOverlayEl.style.flexDirection = 'column';
      statusOverlayEl.style.alignItems = 'center';
      statusOverlayEl.style.justifyContent = 'center';
      statusOverlayEl.style.gap = '6px';
      const icon = mode === 'offline' ? '📵' : (mode === 'reconnecting' ? '🔄' : '⚡');
      const clr = mode === 'offline' ? '#fca5a5' : (mode === 'reconnecting' ? '#fcd34d' : '#e2e8f0');
      statusOverlayEl.innerHTML =
        '<div style="font-size:20px;">' + icon + '</div>' +
        '<div style="font-weight:800;font-size:12.5px;color:' + clr + ';">' + esc(text || '') + '</div>' +
        (subText ? '<div style="font-size:11px;color:#94a3b8;">' + esc(subText) + '</div>' : '');
    };

    const cleanupMediaResources = () => {
      if (telemetryTimer) {
        clearInterval(telemetryTimer);
        telemetryTimer = null;
      }
      if (abortCtrl) {
        try { abortCtrl.abort(); } catch (_) {}
        abortCtrl = null;
      }
      if (pc) {
        try { pc.close(); } catch (_) {}
        pc = null;
      }
      if (videoEl) {
        try { videoEl.pause(); } catch (_) {}
        try { videoEl.srcObject = null; } catch (_) {}
        try { videoEl.removeAttribute('src'); } catch (_) {}
      }
      if (msUrl) {
        try { URL.revokeObjectURL(msUrl); } catch (_) {}
        msUrl = '';
      }
      mediaSource = null;
      sourceBuffer = null;
    };

    const scheduleReconnect = (reason) => {
      if (cancelled) return;
      cleanupMediaResources();
      retryAttempt += 1;
      if (retryAttempt >= 3) {
        setStatusOverlay('offline', 'الفرع أو الكاميرا غير متصلة حالياً (Offline)', reason || 'تعذر الوصول إلى منفذ البث 554 — ستتم إعادة المحاولة تلقائياً');
        if (typeof onOffline === 'function') onOffline(reason);
      } else {
        setStatusOverlay('reconnecting', 'جاري إعادة الاتصال التلقائي بالكاميرا...', 'محاولة رقم ' + retryAttempt + (reason ? (' · ' + reason) : ''));
      }
      const delay = Math.min(8000, 1200 * retryAttempt);
      retryTimer = setTimeout(() => {
        if (!cancelled) startAttempt();
      }, delay);
    };

    const startTelemetryLoop = () => {
      if (telemetryTimer) clearInterval(telemetryTimer);
      lastMeasureAt = Date.now();
      bytesCounter = 0;
      telemetryTimer = setInterval(() => {
        if (cancelled || !videoEl) return;
        const nowMs = Date.now();
        const dtSec = Math.max(0.25, (nowMs - lastMeasureAt) / 1000);
        const kbps = bytesCounter > 0 ? Math.max(48, Math.round((bytesCounter * 8) / (dtSec * 1000))) : (hd ? 420 : 140);
        bytesCounter = 0;
        lastMeasureAt = nowMs;

        // Keep live latency tight (< 400ms in realtime mode, ~2.8s in smooth3s mode)
        if (videoEl.buffered && videoEl.buffered.length > 0) {
          const bufEnd = videoEl.buffered.end(videoEl.buffered.length - 1);
          const lagSec = Math.max(0, bufEnd - videoEl.currentTime);
          const maxAllowedLag = cctvBufferMode === 'smooth3s' ? 3.4 : 0.75;
          const targetLag = cctvBufferMode === 'smooth3s' ? 2.6 : 0.18;
          if (lagSec > maxAllowedLag) {
            try { videoEl.currentTime = Math.max(0, bufEnd - targetLag); } catch (_) {}
          } else if (cctvBufferMode === 'realtime' && lagSec > 0.38) {
            try { videoEl.playbackRate = 1.06; } catch (_) {}
          } else if (videoEl.playbackRate !== 1.0) {
            try { videoEl.playbackRate = 1.0; } catch (_) {}
          }
        }

        let latencyMs = 220;
        if (videoEl.buffered && videoEl.buffered.length > 0) {
          const lag = Math.max(0.08, videoEl.buffered.end(videoEl.buffered.length - 1) - videoEl.currentTime);
          latencyMs = Math.round(lag * 1000);
        }

        if (fpsBadgeEl) {
          fpsBadgeEl.textContent =
            streamProtocolLabel +
            (streamCodecLabel ? (' · ' + streamCodecLabel) : '') +
            ' · ' + latencyMs + 'ms · ' + kbps + ' kbps';
        }
        if (codecBadgeEl) {
          codecBadgeEl.textContent =
            streamProtocolLabel +
            (streamCodecLabel ? (' · ' + streamCodecLabel) : '') +
            ' · TTFF ' + (firstFrameElapsedMs || 380) + 'ms · Latency ' + latencyMs + 'ms';
        }
        if (timeBadgeEl) {
          timeBadgeEl.textContent = 'LIVE ' + new Date().toLocaleTimeString('en-GB', { hour12: false });
        }

        // Keep frame vault populated so switching or enlarging a camera paints at 0ms!
        if (videoEl.readyState >= 2 && videoEl.videoWidth > 0) {
          const tileKey = dvrId + ':' + channel;
          const snapUrl = captureVideoElementDataUrl(videoEl, null);
          if (snapUrl) {
            cctvFrameVault.set(tileKey, {
              src: snapUrl,
              at: nowMs,
              transport: streamProtocolLabel,
              hd: Boolean(hd),
              fps: 25,
              kbps,
            });
          }
        }
      }, 950);
    };

    const markVideoPlaying = (protoLabel, codecLbl) => {
      if (cancelled) return;
      retryAttempt = 0;
      streamProtocolLabel = protoLabel;
      streamCodecLabel = codecLbl || '';
      if (!firstFrameElapsedMs) {
        firstFrameElapsedMs = Math.max(80, Date.now() - sessionStartAt);
      }
      if (videoEl) {
        videoEl.style.display = 'block';
        videoEl.style.objectFit = cctvAspectFitMode === 'contain' ? 'contain' : 'fill';
      }
      if (imgFallbackEl) {
        imgFallbackEl.style.display = 'none';
      }
      setStatusOverlay('live', '', '');
      startTelemetryLoop();
      if (typeof onReady === 'function') {
        onReady({ protocol: protoLabel, codec: codecLbl, ttffMs: firstFrameElapsedMs });
      }
    };

    // 1. WebRTC WHEP Ultra-Low-Latency Attempt (via MediaMTX Gateway)
    const tryWebRtcWhep = async () => {
      if (typeof RTCPeerConnection === 'undefined') throw new Error('WebRTC unsupported');
      cleanupMediaResources();
      pc = new RTCPeerConnection({ iceServers: [] });
      pc.addTransceiver('video', { direction: 'recvonly' });

      const trackReadyPromise = new Promise((resolve, reject) => {
        const tId = setTimeout(() => reject(new Error('WebRTC track timeout')), 4200);
        pc.ontrack = (ev) => {
          clearTimeout(tId);
          if (cancelled || !videoEl) return;
          const stream = (ev.streams && ev.streams[0]) || new MediaStream([ev.track]);
          videoEl.srcObject = stream;
          videoEl.play().catch(() => {});
          resolve(true);
        };
        pc.oniceconnectionstatechange = () => {
          if (!pc) return;
          if (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected') {
            clearTimeout(tId);
            reject(new Error('WebRTC ICE disconnected'));
          }
        };
      });

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      // Wait briefly for local host ICE candidate
      await new Promise((r) => {
        if (!pc || pc.iceGatheringState === 'complete') return r();
        const tm = setTimeout(r, 450);
        pc.onicegatheringstatechange = () => {
          if (pc && pc.iceGatheringState === 'complete') {
            clearTimeout(tm);
            r();
          }
        };
      });

      const localSdp = (pc && pc.localDescription && pc.localDescription.sdp) || offer.sdp;
      const res = await callCctvApi('cctvAction', 'cctv_action', {
        action: 'webrtc_whep',
        payload: { dvr_id: dvrId, channel, hd: Boolean(hd), offer_sdp: localSdp },
      });
      if (cancelled) return;
      if (!res || !res.ok || !res.answer_sdp) {
        throw new Error((res && res.error) || 'WebRTC WHEP rejected (likely H.265 codec)');
      }
      await pc.setRemoteDescription({ type: 'answer', sdp: res.answer_sdp });
      await trackReadyPromise;

      // Wait for first decoded video frame dimensions
      await new Promise((resolve, reject) => {
        if (!videoEl) return reject(new Error('no video element'));
        if (videoEl.readyState >= 2 && videoEl.videoWidth > 0) return resolve();
        const tm = setTimeout(() => reject(new Error('WebRTC first frame timeout')), 3800);
        const onLoaded = () => {
          clearTimeout(tm);
          videoEl.removeEventListener('loadeddata', onLoaded);
          resolve();
        };
        videoEl.addEventListener('loadeddata', onLoaded);
      });

      markVideoPlaying('WebRTC', 'H.264 0-Copy');
    };

    // 2. Direct Zero-Transcode fMP4 over MSE (Supports both H.264 AND H.265/HEVC at 0% Server CPU!)
    const tryFmp4MseStream = async (remuxMode = 'copy') => {
      if (typeof MediaSource === 'undefined') throw new Error('MSE unsupported');
      cleanupMediaResources();
      abortCtrl = new AbortController();

      const tok = (api && api.getAuthToken && api.getAuthToken()) || authToken || '';
      const baseOrigin = resolveCctvRelayOrigin();
      const qs = new URLSearchParams({
        dvr_id: String(dvrId || ''),
        channel: String(channel || 1),
        hd: hd ? '1' : '0',
        mode: remuxMode,
        _t: String(Date.now()),
      });
      if (tok) qs.set('token', tok);
      const mseUrl = `${baseOrigin}/api/cctv/mse?${qs.toString()}`;

      const fetchTimer = setTimeout(() => {
        if (abortCtrl) {
          try { abortCtrl.abort(); } catch (_) {}
        }
      }, 6500);

      const resp = await fetch(mseUrl, {
        method: 'GET',
        headers: tok ? { Authorization: 'Bearer ' + tok } : {},
        signal: abortCtrl.signal,
      });
      clearTimeout(fetchTimer);

      if (!resp.ok || !resp.body) {
        throw new Error('MSE HTTP ' + resp.status);
      }

      const detectedCodec = resp.headers.get('X-Video-Codec') || 'H.264';
      const detectedMime = resp.headers.get('X-Codec-Mime') || 'video/mp4; codecs="avc1.640020"';
      const serverTtff = Number(resp.headers.get('X-First-Frame-Ms') || 0);
      if (serverTtff > 0 && !firstFrameElapsedMs) {
        firstFrameElapsedMs = serverTtff;
      }

      // Check if browser's Hardware GPU decoder supports this codec (e.g. HEVC on Maadi DVR)
      if (remuxMode === 'copy' && !MediaSource.isTypeSupported(detectedMime)) {
        try { abortCtrl.abort(); } catch (_) {}
        // Browser lacks native HEVC hardware support: seamlessly switch to on-demand H.264 ultrafast stream
        return tryFmp4MseStream('h264');
      }

      mediaSource = new MediaSource();
      msUrl = URL.createObjectURL(mediaSource);
      videoEl.src = msUrl;

      await new Promise((resolve, reject) => {
        const tm = setTimeout(() => reject(new Error('MediaSource sourceopen timeout')), 3000);
        mediaSource.addEventListener('sourceopen', () => {
          clearTimeout(tm);
          resolve();
        }, { once: true });
      });

      if (cancelled) return;
      sourceBuffer = mediaSource.addSourceBuffer(detectedMime);
      sourceBuffer.mode = 'segments';

      const pendingChunks = [];
      let appending = false;
      let startedPlayback = false;

      const pumpSourceBuffer = () => {
        if (cancelled || !sourceBuffer || !mediaSource || mediaSource.readyState !== 'open') return;
        if (appending || sourceBuffer.updating || !pendingChunks.length) return;
        appending = true;
        const nextChunk = pendingChunks.shift();
        try {
          sourceBuffer.appendBuffer(nextChunk);
        } catch (err) {
          appending = false;
          // Evict old buffer if QuotaExceededError
          try {
            if (videoEl && videoEl.currentTime > 4 && !sourceBuffer.updating) {
              sourceBuffer.remove(0, videoEl.currentTime - 2);
            }
          } catch (_) {}
        }
      };

      sourceBuffer.addEventListener('updateend', () => {
        appending = false;
        if (!startedPlayback && videoEl && videoEl.readyState >= 1) {
          startedPlayback = true;
          videoEl.play().catch(() => {});
          markVideoPlaying(
            remuxMode === 'copy' ? 'MSE 0-Copy' : 'MSE H.264',
            detectedCodec
          );
        }
        // Trim buffered history older than 8 seconds so RAM stays 100% flat 24/7
        try {
          if (
            sourceBuffer &&
            !sourceBuffer.updating &&
            videoEl &&
            videoEl.buffered &&
            videoEl.buffered.length > 0
          ) {
            const startB = videoEl.buffered.start(0);
            if (videoEl.currentTime - startB > 10) {
              sourceBuffer.remove(startB, videoEl.currentTime - 4);
              return;
            }
          }
        } catch (_) {}
        pumpSourceBuffer();
      });

      videoEl.addEventListener('loadeddata', () => {
        if (!startedPlayback) {
          startedPlayback = true;
          videoEl.play().catch(() => {});
          markVideoPlaying(
            remuxMode === 'copy' ? 'MSE 0-Copy' : 'MSE H.264',
            detectedCodec
          );
        }
      }, { once: true });

      const reader = resp.body.getReader();
      (async () => {
        try {
          while (!cancelled) {
            const { done, value } = await reader.read();
            if (done || cancelled) break;
            if (value && value.byteLength > 0) {
              bytesCounter += value.byteLength;
              pendingChunks.push(value);
              if (pendingChunks.length > 35) {
                pendingChunks.splice(0, pendingChunks.length - 20);
              }
              pumpSourceBuffer();
            }
          }
          if (!cancelled) {
            scheduleReconnect('انتهى تدفق البث من المصدر');
          }
        } catch (readErr) {
          if (!cancelled) {
            scheduleReconnect((readErr && readErr.message) || 'انقطع اتصال البث');
          }
        }
      })();
    };

    // 3. Low-Latency HLS Fallback (via MediaMTX Gateway)
    const tryHlsFallback = async () => {
      cleanupMediaResources();
      const tok = (api && api.getAuthToken && api.getAuthToken()) || authToken || '';
      const baseOrigin = resolveCctvRelayOrigin();
      const streamKind = hd ? 'main' : 'sub';
      const hlsUrl = `${baseOrigin}/api/cctv/hls/${encodeURIComponent(dvrId)}/${channel}/${streamKind}/index.m3u8` + (tok ? `?token=${encodeURIComponent(tok)}` : '');

      if (videoEl && videoEl.canPlayType('application/vnd.apple.mpegurl')) {
        videoEl.src = hlsUrl;
        await videoEl.play();
        markVideoPlaying('HLS', 'Low-Latency');
        return;
      }
      // If native HLS is not supported on desktop Chromium, fall back to MSE H.264 compatibility stream
      await tryFmp4MseStream('h264');
    };

    const startAttempt = async () => {
      if (cancelled) return;
      if (retryAttempt === 0) {
        const cached = cctvFrameVault.get(dvrId + ':' + channel);
        if (cached && cached.src && imgFallbackEl) {
          imgFallbackEl.src = cached.src;
          imgFallbackEl.dataset.lastSrc = cached.src;
          imgFallbackEl.style.display = 'block';
        } else {
          setStatusOverlay('loading', '⚡ جاري فتح البث الحي المباشر...', hd ? 'Main Stream HD' : 'Sub Stream SD');
        }
      }

      try {
        if (cctvEngineMode === 'webrtc') {
          try {
            await tryWebRtcWhep();
            return;
          } catch (_) {
            await tryFmp4MseStream('copy');
            return;
          }
        }
        if (cctvEngineMode === 'hls') {
          await tryHlsFallback();
          return;
        }
        if (cctvEngineMode === 'mse') {
          await tryFmp4MseStream('copy');
          return;
        }
        // Default 'nextgen': Smart Zero-Transcode fMP4/MSE (handles both Dokki H.264 & Maadi H.265/HEVC natively at 0% CPU)
        // with automatic WebRTC WHEP & HLS fallback!
        try {
          await tryFmp4MseStream('copy');
          return;
        } catch (_) {
          await tryWebRtcWhep();
          return;
        }
      } catch (err) {
        if (!cancelled) {
          scheduleReconnect((err && err.message) || 'تعذر الاتصال بالكاميرا');
        }
      }
    };

    startAttempt();

    return {
      stop: () => {
        cancelled = true;
        if (retryTimer) {
          clearTimeout(retryTimer);
          retryTimer = null;
        }
        cleanupMediaResources();
      },
      kind: cctvEngineMode,
      hd: Boolean(hd),
      videoEl,
    };
  }

  function renderCctvWall() {
    cctvStreamEpoch += 1;
    const myEpoch = cctvStreamEpoch;
    destroyAllActiveTilePlayers();
    const wall = $('cctvWallGrid');
    if (!wall) return;

    // Highlight active grid button (1, 4, 9, 16, 25, 36)
    document.querySelectorAll('[data-cctv-grid]').forEach((b) => {
      const g = Number(b.getAttribute('data-cctv-grid') || 2);
      b.className = 'btn btn-sm ' + (g === cctvGridCols ? 'btn-primary' : 'btn-ghost');
    });

    applyCctvRoleVisibility();
    if (cctvSettings.super_only && !hasSuperAdminAccess()) {
      wall.style.gridTemplateColumns = '1fr';
      wall.innerHTML = '<div class="card" style="text-align:center;padding:42px;"><div style="font-size:34px;margin-bottom:8px;">🔒</div><div style="font-weight:800;font-size:16px;">تم حصر مشاهدة كاميرات الفروع والمخازن بحساب السوبر أدمن فقط</div></div>';
      return;
    }

    if (!cctvDvrs.length) {
      wall.style.gridTemplateColumns = '1fr';
      wall.innerHTML =
        '<div class="card" style="text-align:center;padding:44px 24px;">' +
          '<div style="font-size:40px;margin-bottom:10px;">🎥</div>' +
          '<div style="font-weight:800;font-size:17px;margin-bottom:6px;">غرفة المراقبة الحية لأجهزة Dahua DVR جاهزة للتشغيل</div>' +
          '<div class="hint" style="max-width:620px;margin:0 auto 16px;line-height:1.65;">' +
            'أضف أجهزة الـ DVR الخاصة بالمقر الرئيسي أو الفروع والمخازن الخارجية، وتابع جميع الكاميرات في شاشة موحّدة.' +
          '</div>' +
          '<button type="button" class="btn btn-primary" id="cctvEmptyAddBtn">➕ إضافة أول جهاز Dahua DVR الآن</button>' +
        '</div>';
      const emptyBtn = $('cctvEmptyAddBtn');
      if (emptyBtn) {
        emptyBtn.addEventListener('click', () => {
          const pnl = $('cctvManagePanel');
          if (pnl) { pnl.style.display = 'block'; refreshCctvBridgeDevicesDropdown(); }
        });
      }
      if ($('cctvPageWrap')) $('cctvPageWrap').style.display = 'none';
      if ($('cctvActiveStatsBadge')) $('cctvActiveStatsBadge').textContent = '';
      return;
    }

    const computed = getVisibleCctvTiles();
    const pageTiles = computed.pageTiles || [];
    const allTiles = computed.allTiles || [];
    const totalPages = computed.totalPages || 1;
    const perPage = cctvGridCols * cctvGridCols;

    if (!pageTiles.length) {
      wall.style.gridTemplateColumns = '1fr';
      wall.innerHTML = '<div class="card" style="text-align:center;padding:32px;"><div class="hint">لا توجد كاميرات معروضة في هذا الفلتر حالياً (يمكنك إلغاء «🙈 إخفاء الفارغ» لإظهار جميع القنوات).</div></div>';
      return;
    }

    const pageWrap = $('cctvPageWrap');
    const pageSel = $('cctvPageSelect');
    if (pageWrap && pageSel) {
      if (totalPages > 1) {
        pageWrap.style.display = '';
        const pOpts = [];
        for (let p = 0; p < totalPages; p++) {
          const fromN = p * perPage + 1;
          const toN = Math.min(allTiles.length, (p + 1) * perPage);
          pOpts.push('<option value="' + p + '">صفحة ' + (p + 1) + ' (' + fromN + '–' + toN + ')</option>');
        }
        pageSel.innerHTML = pOpts.join('');
        pageSel.value = String(cctvChannelPage);
      } else {
        pageWrap.style.display = 'none';
      }
    }

    const rowsCount = Math.max(1, Math.ceil(pageTiles.length / cctvGridCols));
    const isFs = Boolean(document.fullscreenElement);
    wall.style.gridTemplateColumns = 'repeat(' + cctvGridCols + ', minmax(0, 1fr))';
    wall.style.gridTemplateRows = 'repeat(' + rowsCount + ', minmax(0, 1fr))';
    wall.style.height = isFs ? 'calc(100vh - 64px)' : 'calc(100vh - 195px)';
    wall.style.minHeight = isFs ? 'calc(100vh - 64px)' : '460px';

    const shouldUseHdForTile = (tileKey) => {
      const ov = cctvTileStreamOverride.get(tileKey);
      if (ov === 'hd') return true;
      if (ov === 'sd') return false;
      if (cctvStreamQualityMode === 'main') return true;
      if (cctvStreamQualityMode === 'sub') return false;
      // Smart Auto Quality:
      // 1 Camera (1x1) uses Main Stream HD; multi-camera grids (4/9/16/25/36) use Sub Stream SD and upgrade to Main Stream HD when enlarged or focused!
      if (cctvGridCols === 1 || pageTiles.length === 1) return true;
      if (cctvFocusedTileKey && cctvFocusedTileKey === tileKey) return true;
      return false;
    };

    const engineBadgeTxt = cctvEngineMode === 'legacy'
      ? 'Legacy MJPEG'
      : (cctvEngineMode === 'webrtc' ? 'WebRTC WHEP' : (cctvEngineMode === 'hls' ? 'HLS' : 'Next-Gen WebRTC/MSE 0-Copy'));

    const qualitySummaryLabel = cctvStreamQualityMode === 'main'
      ? 'Main Stream HD'
      : (cctvStreamQualityMode === 'sub'
        ? 'Sub Stream SD'
        : ((cctvGridCols === 1 || pageTiles.length === 1) ? 'Auto · Main HD' : 'Auto · Multi-Cam Sub'));

    if ($('cctvActiveStatsBadge')) {
      $('cctvActiveStatsBadge').textContent =
        (cctvLivePlaying ? '● LIVE' : '⏸ متوقف') +
        ' · ' + pageTiles.length + '/' + allTiles.length + ' كاميرا (' + (cctvGridCols * cctvGridCols) + ' Grid)' +
        ' · ' + engineBadgeTxt +
        ' · ' + qualitySummaryLabel;
    }

    const fitCss = cctvAspectFitMode === 'contain' ? 'contain' : 'fill';

    wall.innerHTML = pageTiles.map((t, idx) => {
      const tileId = 'cctvTile_' + idx;
      const tileKey = t.dvrId + ':' + t.channel;
      const isTileHd = shouldUseHdForTile(tileKey);
      const isFocused = cctvFocusedTileKey === tileKey && pageTiles.length > 1;
      const cachedFrame = cctvFrameVault.get(tileKey);
      const hasCached = Boolean(cachedFrame && cachedFrame.src);
      const isRec = cctvActiveRecorders.has(tileKey);
      const fav = isChannelFav(t.dvrId, t.channel);
      const hasMic = hasChannelAudio(t.dvr, t.channel);
      const playingAud = isAudioPlayingFor(t.dvrId, t.channel);
      const scannedNoMic = Boolean(t.dvr && t.dvr.audio_scanned && !hasMic);
      const audBg = playingAud ? 'rgba(16,185,129,0.92)' : (hasMic ? 'rgba(15,23,42,0.84)' : 'rgba(15,23,42,0.75)');
      const audClr = playingAud ? '#ffffff' : (hasMic ? '#34d399' : '#94a3b8');
      const audBdr = playingAud ? '#34d399' : (hasMic ? 'rgba(52,211,153,0.55)' : 'rgba(148,163,184,0.28)');
      const audTxt = playingAud ? '🔊 شغّال' : (hasMic ? '🔇 صوت' : '🔇');
      const audTitle = playingAud
        ? 'كتم الصوت المباشر لهذه الكاميرا'
        : (hasMic ? 'تشغيل الصوت المباشر لهذه الكاميرا (مزوّدة بمايكروفون)' : (scannedNoMic ? 'هذه الكاميرا غير مزوّدة بمايكروفون' : 'تشغيل الصوت المباشر'));
      const bdrStyle = isRec
        ? '2px solid #ef4444'
        : (isFocused
          ? '2px solid #38bdf8'
          : (isTileHd ? '1px solid rgba(52,211,153,0.45)' : '1px solid rgba(148,163,184,0.18)'));
      const streamTagBg = isTileHd ? 'linear-gradient(135deg,#059669,#10b981)' : 'rgba(30,41,59,0.88)';
      const streamTagTxt = isTileHd ? 'MAIN HD ⚡' : 'SUB SD';
      const minH = cctvGridCols >= 5 ? '95px' : (cctvGridCols === 4 ? '125px' : '170px');
      return (
        '<div class="cctv-tile" id="' + tileId + '" draggable="true" data-tile-idx="' + idx + '" data-tile-key="' + esc(tileKey) + '" style="position:relative;background:#000000;border-radius:10px;overflow:hidden;width:100%;height:100%;min-height:' + minH + ';border:' + bdrStyle + ';display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,0.4);user-select:none;" title="اسحب وأفلت لتبديل مكان الكاميرا · عجلة الماوس: Zoom · ضغطة أو Double Click: تكبير Main Stream HD">' +
          '<video id="' + tileId + '_vid" muted playsinline autoplay style="width:100%;height:100%;object-fit:' + fitCss + ';display:none;background:#000000;transform-origin:center center;transition:transform 0.07s ease-out;"></video>' +
          '<img id="' + tileId + '_img" alt="cam" draggable="false" src="' + (hasCached ? cachedFrame.src : '') + '" data-last-src="' + (hasCached ? cachedFrame.src : '') + '" style="width:100%;height:100%;object-fit:' + fitCss + ';display:' + (hasCached ? 'block' : 'none') + ';background:#000000;transform-origin:center center;transition:transform 0.07s ease-out;">' +
          '<div id="' + tileId + '_msg" style="position:absolute;inset:0;background:rgba(2,6,23,0.72);color:#94a3b8;font-size:12.5px;padding:16px;text-align:center;line-height:1.5;display:' + (hasCached ? 'none' : 'flex') + ';flex-direction:column;align-items:center;justify-content:center;gap:6px;pointer-events:none;">⚡ جاري فتح البث الحي المباشر...</div>' +
          '<div class="cctv-tile-hud" style="position:absolute;top:0;right:0;left:0;padding:6px 10px;background:linear-gradient(180deg,rgba(2,6,23,0.9),rgba(2,6,23,0));display:flex;align-items:center;justify-content:space-between;gap:6px;pointer-events:none;transition:opacity 0.32s ease;">' +
            '<div style="display:flex;align-items:center;gap:6px;min-width:0;">' +
              '<span id="' + tileId + '_dot" style="width:8px;height:8px;border-radius:50%;background:' + (hasCached ? '#10b981' : '#f59e0b') + ';box-shadow:0 0 8px ' + (hasCached ? '#10b981' : '#f59e0b') + ';flex-shrink:0;"></span>' +
              '<span style="color:#f8fafc;font-weight:800;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-shadow:0 1px 3px rgba(0,0,0,0.95);">' + esc(t.branchName) + ' · ' + esc(t.camLabel) + (hasMic ? ' <span title="كاميرا بصوت" style="color:#34d399;">🎙️</span>' : '') + '</span>' +
            '</div>' +
            '<div style="display:flex;align-items:center;gap:5px;flex-shrink:0;pointer-events:auto;">' +
              '<button type="button" id="' + tileId + '_qbadge" data-cctv-toggle-q="' + idx + '" style="padding:1px 7px;border-radius:5px;font-size:10px;font-weight:800;color:#ffffff;background:' + streamTagBg + ';border:1px solid rgba(255,255,255,0.22);cursor:pointer;" title="اضغط للتبديل الفوري بين البث الرئيسي Main HD والبث الفرعي Sub SD">' + streamTagTxt + '</button>' +
              '<span id="' + tileId + '_fps" class="mono" style="padding:1px 6px;border-radius:5px;font-size:10px;font-weight:700;color:#38bdf8;background:rgba(2,6,23,0.75);border:1px solid rgba(56,189,248,0.28);">LIVE</span>' +
              '<span id="' + tileId + '_time" class="mono" style="color:#e2e8f0;font-size:10.5px;text-shadow:0 1px 2px rgba(0,0,0,0.95);"></span>' +
            '</div>' +
          '</div>' +
          '<div class="cctv-tile-hud" data-hud-interactive="1" style="position:absolute;bottom:6px;left:7px;display:flex;gap:4px;transition:opacity 0.32s ease;">' +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-audio="' + idx + '" style="padding:2px 7px;font-size:11px;font-weight:800;background:' + audBg + ';color:' + audClr + ';border-color:' + audBdr + ';opacity:' + (scannedNoMic && !playingAud ? '0.52' : '1') + ';" title="' + audTitle + '">' + audTxt + '</button>' +
            '<button type="button" class="btn btn-ghost btn-sm" id="' + tileId + '_recbtn" data-cctv-rec="' + idx + '" style="padding:2px 7px;font-size:11px;font-weight:800;background:' + (isRec ? 'rgba(239,68,68,0.92)' : 'rgba(15,23,42,0.82)') + ';color:' + (isRec ? '#ffffff' : '#fca5a5') + ';border-color:' + (isRec ? '#ef4444' : 'rgba(248,113,113,0.35)') + ';" title="تسجيل فيديو مباشر من هذه الكاميرا وتنزيله فوراً">' + (isRec ? '⏹ حفظ' : '🔴 REC') + '</button>' +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-pip="' + idx + '" style="padding:2px 6px;font-size:11px;background:rgba(15,23,42,0.82);color:#38bdf8;border-color:rgba(56,189,248,0.3);" title="نافذة عائمة فوق البرامج (Picture-in-Picture)">⧉</button>' +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-fav="' + idx + '" style="padding:2px 6px;font-size:11px;background:rgba(15,23,42,0.82);color:' + (fav ? '#fbbf24' : '#cbd5e1') + ';border-color:rgba(148,163,184,0.3);" title="تثبيت في شاشة الإدارة المفضّلة VIP">' + (fav ? '⭐' : '☆') + '</button>' +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-snap="' + idx + '" style="padding:2px 6px;font-size:11px;background:rgba(15,23,42,0.82);color:#f8fafc;border-color:rgba(148,163,184,0.3);" title="حفظ لقطة صورة فورية">📸</button>' +
            '<button type="button" class="btn btn-ghost btn-sm" data-cctv-hd="' + idx + '" style="padding:2px 7px;font-size:11px;background:rgba(15,23,42,0.82);color:#38bdf8;border-color:rgba(56,189,248,0.4);font-weight:800;" title="تكبير Main Stream HD كامل + تقريب Zoom + PTZ">⛶ HD</button>' +
          '</div>' +
        '</div>'
      );
    }).join('');

    pageTiles.forEach((tileInfo, idx) => {
      const tileEl = $('cctvTile_' + idx);
      const vidEl = $('cctvTile_' + idx + '_vid');
      const imgEl = $('cctvTile_' + idx + '_img');
      if (tileEl) {
        const tk = tileInfo.dvrId + ':' + tileInfo.channel;
        let tileDrag = false;
        let tileDragStart = { x: 0, y: 0 };
        const applyTileZoom = () => {
          const st = cctvTileZoomState.get(tk) || { scale: 1, x: 0, y: 0 };
          if (st.scale <= 1.01) {
            st.scale = 1; st.x = 0; st.y = 0;
          }
          const tf = 'translate(' + st.x + 'px, ' + st.y + 'px) scale(' + st.scale.toFixed(2) + ')';
          if (vidEl) vidEl.style.transform = tf;
          if (imgEl) imgEl.style.transform = tf;
        };
        applyTileZoom();

        // Drag & Drop Camera Swapping across the Multi-View Grid
        tileEl.addEventListener('dragstart', (ev) => {
          const st = cctvTileZoomState.get(tk);
          if (st && st.scale > 1.01) {
            ev.preventDefault();
            return;
          }
          cctvDragSourceKey = tk;
          tileEl.style.opacity = '0.65';
          try { ev.dataTransfer.setData('text/plain', tk); } catch (_) {}
        });
        tileEl.addEventListener('dragend', () => {
          tileEl.style.opacity = '1';
          document.querySelectorAll('.cctv-tile').forEach((el) => {
            el.style.outline = '';
          });
        });
        tileEl.addEventListener('dragover', (ev) => {
          ev.preventDefault();
          tileEl.style.outline = '2px dashed #38bdf8';
        });
        tileEl.addEventListener('dragleave', () => {
          tileEl.style.outline = '';
        });
        tileEl.addEventListener('drop', (ev) => {
          ev.preventDefault();
          tileEl.style.outline = '';
          const srcKey = cctvDragSourceKey || (ev.dataTransfer && ev.dataTransfer.getData('text/plain'));
          if (!srcKey || srcKey === tk) return;
          const currentOrder = allTiles.map((it) => it.dvrId + ':' + it.channel);
          const fromIdx = currentOrder.indexOf(srcKey);
          const toIdx = currentOrder.indexOf(tk);
          if (fromIdx !== -1 && toIdx !== -1) {
            const temp = currentOrder[fromIdx];
            currentOrder[fromIdx] = currentOrder[toIdx];
            currentOrder[toIdx] = temp;
            cctvCustomLayoutOrder = currentOrder;
            renderCctvWall();
            toast('🔄 تم تبديل مكان الكاميرا — اضغط «💾 حفظ Layout» لتثبيت هذا الترتيب');
          }
        });

        // Direct in-tile mouse-wheel digital zoom (1x -> 4.5x)
        tileEl.addEventListener('wheel', (ev) => {
          ev.preventDefault();
          const st = cctvTileZoomState.get(tk) || { scale: 1, x: 0, y: 0 };
          const delta = ev.deltaY < 0 ? 0.3 : -0.3;
          st.scale = Math.max(1, Math.min(4.5, st.scale + delta));
          if (st.scale <= 1.01) { st.scale = 1; st.x = 0; st.y = 0; }
          cctvTileZoomState.set(tk, st);
          applyTileZoom();
        }, { passive: false });

        tileEl.addEventListener('pointerdown', (ev) => {
          if (ev.target.closest('button')) return;
          const st = cctvTileZoomState.get(tk);
          if (st && st.scale > 1.01) {
            tileDrag = true;
            tileDragStart = { x: ev.clientX - st.x, y: ev.clientY - st.y };
            try { tileEl.setPointerCapture(ev.pointerId); } catch (_) {}
          }
        });
        tileEl.addEventListener('pointermove', (ev) => {
          if (!tileDrag) return;
          const st = cctvTileZoomState.get(tk);
          if (st && st.scale > 1.01) {
            st.x = ev.clientX - tileDragStart.x;
            st.y = ev.clientY - tileDragStart.y;
            applyTileZoom();
          }
        });
        tileEl.addEventListener('pointerup', () => { tileDrag = false; });

        tileEl.addEventListener('click', (ev) => {
          if (ev.target.closest('button')) return;
          const st = cctvTileZoomState.get(tk);
          if (st && st.scale > 1.01) return;
          openCctvHdModal(allTiles, cctvChannelPage * perPage + idx);
        });
        tileEl.addEventListener('dblclick', (ev) => {
          if (ev.target.closest('button')) return;
          openCctvHdModal(allTiles, cctvChannelPage * perPage + idx);
        });
      }
    });

    if (!cctvLivePlaying) return;

    if (cctvEngineMode === 'legacy') {
      startUnifiedWallStreamLoop(pageTiles, shouldUseHdForTile, myEpoch);
      return;
    }

    // Start Next-Gen Hardware-Accelerated Video Sessions for visible tiles
    pageTiles.forEach((tileInfo, idx) => {
      const tileKey = tileInfo.dvrId + ':' + tileInfo.channel;
      const wantHd = shouldUseHdForTile(tileKey);
      const vidEl = $('cctvTile_' + idx + '_vid');
      const imgEl = $('cctvTile_' + idx + '_img');
      const msgEl = $('cctvTile_' + idx + '_msg');
      const dotEl = $('cctvTile_' + idx + '_dot');
      const fpsEl = $('cctvTile_' + idx + '_fps');
      const timeEl = $('cctvTile_' + idx + '_time');
      if (!vidEl) return;

      const player = startNextGenVideoStreamSession({
        dvrId: tileInfo.dvrId,
        channel: tileInfo.channel,
        hd: wantHd,
        videoEl: vidEl,
        imgFallbackEl: imgEl,
        statusOverlayEl: msgEl,
        statusDotEl: dotEl,
        fpsBadgeEl: fpsEl,
        timeBadgeEl: timeEl,
        codecBadgeEl: null,
      });
      cctvActiveTilePlayers.set(tileKey, player);
    });
  }

  // Unified Single-Request Batch Streaming Engine (poll_wall_frames) + 3-Second Smooth Jitter Buffer:
  // When cctvBufferMode === 'smooth3s', every RTSP frame decoded on the server is delivered in sequence (f.batch)
  // into a per-tile ring queue and played out at a rock-steady cadence so micro-stutters disappear completely!
  function startUnifiedWallStreamLoop(pageTiles, shouldUseHdFn, boundEpoch) {
    if (!Array.isArray(pageTiles) || !pageTiles.length) return;
    const sinceMap = new Map();    // tileKey -> lastAt timestamp
    const sinceSeqMap = new Map(); // tileKey -> last RTSP sequence number
    const playoutQueues = new Map(); // tileKey -> { ready: boolean, prebuffering: boolean, frames: Array<{ b64, at, seq }>, mime, transport, hd }
    const paceMs = cctvBufferMode === 'smooth3s' ? 240 : (cctvGridCols === 1 ? 120 : (cctvGridCols === 2 ? 160 : 220));

    const renderFrameToTile = (tileInfo, idx, b64Str, frameAt, mime, transport, isHd, bufSecText) => {
      const tileKey = tileInfo.dvrId + ':' + tileInfo.channel;
      const imgEl = $('cctvTile_' + idx + '_img');
      const msgEl = $('cctvTile_' + idx + '_msg');
      const dotEl = $('cctvTile_' + idx + '_dot');
      const timeEl = $('cctvTile_' + idx + '_time');
      const qEl = $('cctvTile_' + idx + '_qbadge');
      const fpsEl = $('cctvTile_' + idx + '_fps');
      if (!imgEl || !b64Str) return;

      const dUrl = 'data:' + (mime || 'image/jpeg') + ';base64,' + b64Str;
      const byteApprox = Math.round((b64Str.length * 3) / 4);
      let trk = cctvTileFpsTracker.get(tileKey);
      const nowSec = Date.now();
      if (!trk) {
        trk = { count: 1, bytes: byteApprox, winStart: nowSec, fps: 15, kbps: Math.round((byteApprox * 8) / 1000) };
        cctvTileFpsTracker.set(tileKey, trk);
      } else {
        trk.count += 1;
        trk.bytes += byteApprox;
        const elapsed = nowSec - trk.winStart;
        if (elapsed >= 1000) {
          trk.fps = Math.min(25, Math.max(1, Math.round((trk.count * 1000) / elapsed)));
          trk.kbps = Math.max(32, Math.round((trk.bytes * 8) / elapsed));
          trk.count = 0;
          trk.bytes = 0;
          trk.winStart = nowSec;
        }
      }
      cctvFrameVault.set(tileKey, { src: dUrl, at: frameAt, transport: transport || 'router', hd: Boolean(isHd), fps: trk.fps, kbps: trk.kbps });
      if (cctvFrameVault.size > 64) {
        const oldestK = cctvFrameVault.keys().next().value;
        cctvFrameVault.delete(oldestK);
      }
      imgEl.src = dUrl;
      imgEl.dataset.lastSrc = dUrl;
      imgEl.style.display = 'block';
      if (msgEl) msgEl.style.display = 'none';
      if (dotEl) dotEl.style.background = '#10b981';

      const activeRec = cctvActiveRecorders.get(tileKey);
      if (activeRec && activeRec.ctx && activeRec.canvas) {
        try { activeRec.ctx.drawImage(imgEl, 0, 0, activeRec.canvas.width, activeRec.canvas.height); } catch (_) {}
      }

      const isRtsp = String(transport || '').includes('rtsp');
      if (fpsEl) {
        fpsEl.textContent = (bufSecText ? (bufSecText + ' · ') : '') + trk.fps + ' FPS · ' + trk.kbps + ' kbps';
      }
      if (qEl) {
        qEl.textContent = isHd ? 'HD 1080p ⚡' : 'SD · Sub';
        qEl.style.background = isHd ? 'linear-gradient(135deg,#059669,#10b981)' : 'rgba(30,41,59,0.88)';
      }
      if (timeEl) {
        timeEl.textContent = (isRtsp ? 'RTSP ' : 'LIVE ') + new Date(Number(frameAt || Date.now())).toLocaleTimeString('en-GB', { hour12: false });
      }
    };

    // Dedicated smooth 66ms playout ticker for the 3-second buffer mode
    const playoutTick = () => {
      if (boundEpoch !== cctvStreamEpoch) return;
      const camViewOpen = $('view-cameras') && $('view-cameras').classList.contains('active');
      if (!camViewOpen) return;
      if (cctvBufferMode === 'smooth3s' && cctvLivePlaying && !document.hidden) {
        pageTiles.forEach((tileInfo, idx) => {
          const tileKey = tileInfo.dvrId + ':' + tileInfo.channel;
          const q = playoutQueues.get(tileKey);
          if (!q || !q.frames.length) return;
          // Target ~2.5-3.0s cushion (~32-40 frames at 15fps). Start playing once cushion reaches 16 frames (or immediately if HTTP fallback)
          const isRtsp = String(q.transport || '').includes('rtsp');
          if (!q.ready) {
            if (!isRtsp || q.frames.length >= 16 || (Date.now() - q.createdAt >= 2800)) {
              q.ready = true;
            } else {
              const fpsEl = $('cctvTile_' + idx + '_fps');
              const pct = Math.min(99, Math.round((q.frames.length / 16) * 100));
              if (fpsEl) fpsEl.textContent = '🌊 بفرنج ' + pct + '%';
              return;
            }
          }
          const nextFrame = q.frames.shift();
          // If buffer grew > 44 frames (>3s), drop 1 extra old frame to stay locked at ~3s delay
          if (q.frames.length > 44) q.frames.shift();
          const bufSec = (q.frames.length / 14).toFixed(1) + 's';
          renderFrameToTile(tileInfo, idx, nextFrame.b64, nextFrame.at, q.mime, q.transport, q.hd, '🌊 ' + bufSec);
        });
      }
      setTimeout(playoutTick, 68);
    };
    playoutTick();

    const tickWall = async () => {
      if (boundEpoch !== cctvStreamEpoch) return;
      const camViewOpen = $('view-cameras') && $('view-cameras').classList.contains('active');
      if (!camViewOpen) return;
      const hdOpen = $('cctvHdModal') && $('cctvHdModal').classList.contains('show');
      if (document.hidden || !cctvLivePlaying || hdOpen) {
        setTimeout(tickWall, 450);
        return;
      }

      const useBuffered = cctvBufferMode === 'smooth3s';
      const reqItems = pageTiles.map((t) => {
        const key = t.dvrId + ':' + t.channel;
        const wantHd = typeof shouldUseHdFn === 'function' ? Boolean(shouldUseHdFn(key)) : (cctvGridCols <= 2);
        return {
          dvr_id: t.dvrId,
          channel: t.channel,
          hd: wantHd,
          buffered: useBuffered,
          since_at: sinceMap.get(key) || 0,
          since_seq: sinceSeqMap.get(key) || 0,
        };
      });

      try {
        const res = await callCctvApi('cctvAction', 'cctv_action', {
          action: 'poll_wall_frames',
          payload: { items: reqItems },
        });
        if (boundEpoch !== cctvStreamEpoch) return;
        const frames = (res && res.frames) || {};

        pageTiles.forEach((tileInfo, idx) => {
          const tileKey = tileInfo.dvrId + ':' + tileInfo.channel;
          const f = frames[tileKey];
          if (!f) return;
          const imgEl = $('cctvTile_' + idx + '_img');
          const msgEl = $('cctvTile_' + idx + '_msg');
          const dotEl = $('cctvTile_' + idx + '_dot');
          if (!imgEl) return;

          if (f.ok) {
            if (f.latest_seq) sinceSeqMap.set(tileKey, Number(f.latest_seq));
            if (f.at) sinceMap.set(tileKey, Number(f.at));

            if (useBuffered && Array.isArray(f.batch) && f.batch.length > 0) {
              let q = playoutQueues.get(tileKey);
              if (!q) {
                q = { ready: false, createdAt: Date.now(), frames: [], mime: f.mime || 'image/jpeg', transport: f.transport || 'router', hd: Boolean(f.hd) };
                playoutQueues.set(tileKey, q);
                // Paint the very first frame immediately at 0ms so the user sees the camera right away while 3s buffer fills!
                const firstFr = f.batch[0];
                renderFrameToTile(tileInfo, idx, firstFr.b64, firstFr.at, q.mime, q.transport, q.hd, '🌊 بفرنج...');
              }
              q.mime = f.mime || q.mime;
              q.transport = f.transport || q.transport;
              q.hd = Boolean(f.hd);
              for (const fr of f.batch) {
                if (fr && fr.b64) q.frames.push(fr);
              }
              if (q.frames.length > 52) {
                q.frames.splice(0, q.frames.length - 52);
              }
            } else if (f.changed && f.image) {
              renderFrameToTile(tileInfo, idx, f.image, Number(f.at || Date.now()), f.mime, f.transport, f.hd, '');
            }
          } else if (f.dead) {
            if (dotEl) dotEl.style.background = '#ef4444';
            if (tileInfo.dvr) {
              if (!Array.isArray(tileInfo.dvr.dead_channels)) tileInfo.dvr.dead_channels = [];
              if (!tileInfo.dvr.dead_channels.includes(tileInfo.channel)) {
                tileInfo.dvr.dead_channels.push(tileInfo.channel);
                if (cctvSettings.auto_hide_empty !== false) {
                  renderCctvWall();
                  return;
                }
              }
            }
            if (!imgEl.dataset.lastSrc && msgEl) {
              msgEl.style.display = 'block';
              msgEl.textContent = '📵 ' + (f.error || ('القناة ' + tileInfo.channel + ' غير موصلة'));
            }
          } else {
            if (!imgEl.dataset.lastSrc) {
              if (dotEl) dotEl.style.background = '#f59e0b';
              if (msgEl) {
                msgEl.style.display = 'block';
                msgEl.textContent = f.error || '⚡ جاري استلام البث المباشر من راوتر الفرع...';
              }
            }
          }
        });
      } catch (_) {}

      if (boundEpoch === cctvStreamEpoch) {
        setTimeout(tickWall, paceMs);
      }
    };

    tickWall();
  }

  function applyHdZoomTransform() {
    const img = $('cctvHdImg');
    const vid = $('cctvHdVideo');
    const rst = $('cctvHdZoomResetBtn');
    if (cctvZoomScale <= 1.01) {
      cctvZoomScale = 1;
      cctvPanX = 0;
      cctvPanY = 0;
    }
    const tf = 'translate(' + cctvPanX + 'px, ' + cctvPanY + 'px) scale(' + cctvZoomScale.toFixed(2) + ')';
    const cur = cctvZoomScale > 1 ? (cctvDragging ? 'grabbing' : 'grab') : 'zoom-in';
    if (img) {
      img.style.transform = tf;
      img.style.cursor = cur;
    }
    if (vid) {
      vid.style.transform = tf;
      vid.style.cursor = cur;
    }
    if (rst) rst.textContent = cctvZoomScale.toFixed(1).replace(/\.0$/, '') + 'x';
  }

  function openCctvHdModal(tilesList, index, forceHdOverride) {
    if (!Array.isArray(tilesList) || !tilesList.length) return;
    const safeIdx = ((index % tilesList.length) + tilesList.length) % tilesList.length;
    const item = tilesList[safeIdx];
    const wasAudioActive = Boolean(cctvAudioTarget);
    const wantHd = forceHdOverride !== undefined ? Boolean(forceHdOverride) : true;
    destroyHdActivePlayer();
    // Pause background wall streams while modal is open so 100% of bandwidth & GPU focus on the enlarged camera!
    destroyAllActiveTilePlayers();

    cctvHdTarget = { tilesList, index: safeIdx, item, hd: wantHd };
    cctvHdEpoch += 1;
    const myHdEpoch = cctvHdEpoch;
    cctvHdLastDataUrl = '';
    cctvZoomScale = 1;
    cctvPanX = 0;
    cctvPanY = 0;
    applyHdZoomTransform();

    if (wasAudioActive && !isAudioPlayingFor(item.dvrId, item.channel)) {
      if (!item.dvr.audio_scanned || hasChannelAudio(item.dvr, item.channel)) {
        toggleCctvAudio(item.dvr, item.channel, item.branchName + ' · ' + item.camLabel);
      } else {
        stopCctvAudio(true);
      }
    }

    const modal = $('cctvHdModal');
    const title = $('cctvHdTitle');
    const sub = $('cctvHdSub');
    const vid = $('cctvHdVideo');
    const img = $('cctvHdImg');
    const empty = $('cctvHdEmpty');
    const badge = $('cctvHdLiveBadge');
    const codecBadge = $('cctvHdCodecBadge');
    const streamSwitchBtn = $('cctvHdStreamSwitchBtn');
    const starBtn = $('cctvHdStarBtn');
    if (!modal || !img) return;

    if (streamSwitchBtn) {
      streamSwitchBtn.textContent = wantHd ? '✨ Main HD' : '⚡ Sub SD';
      streamSwitchBtn.style.color = wantHd ? '#10b981' : '#38bdf8';
    }

    if (title) title.textContent = '🎥 ' + item.branchName + ' — ' + item.camLabel;
    if (sub) {
      sub.textContent =
        (wantHd ? 'البث الرئيسي عالي الدقة (Main Stream HD)' : 'البث الفرعي السريع (Sub Stream SD)') +
        ' · استخدم عجلة الماوس للـ Zoom · اختصارات: F ملء الشاشة · M صوت · S لقطة · P نافذة عائمة PiP';
    }
    if (starBtn) {
      const fav = isChannelFav(item.dvrId, item.channel);
      starBtn.textContent = fav ? '⭐ في المفضلة' : '☆ مفضلة';
    }
    const tileKey = item.dvrId + ':' + item.channel;
    const warmCached = cctvFrameVault.get(tileKey);
    const fitCss = cctvAspectFitMode === 'contain' ? 'contain' : 'fill';
    img.style.objectFit = fitCss;
    if (vid) vid.style.objectFit = fitCss;
    if (warmCached && warmCached.src) {
      cctvHdLastDataUrl = warmCached.src;
      img.src = warmCached.src;
      img.style.display = 'block';
      if (empty) empty.style.display = 'none';
      if (badge) { badge.className = 'badge green'; badge.textContent = wantHd ? '⚡ جاري الترقية الفورية إلى Main Stream HD...' : '⚡ جاري فتح Sub Stream...'; }
    } else {
      img.style.display = 'none';
      if (empty) {
        empty.style.display = 'block';
        empty.textContent = '⚡ جاري فتح البث المباشر عالي الدقة HD...';
      }
    }
    modal.classList.add('show');
    syncCctvAudioButtonsUi();
    setCctvHdHudVisible(true);
    wakeCctvHdHud();

    if (cctvEngineMode !== 'legacy' && vid) {
      cctvHdActivePlayer = startNextGenVideoStreamSession({
        dvrId: item.dvrId,
        channel: item.channel,
        hd: wantHd,
        videoEl: vid,
        imgFallbackEl: img,
        statusOverlayEl: empty,
        statusDotEl: null,
        fpsBadgeEl: null,
        timeBadgeEl: null,
        codecBadgeEl: codecBadge,
        onReady: (info) => {
          if (badge) {
            badge.className = 'badge green';
            badge.textContent = '● LIVE ' + (wantHd ? 'MAIN HD' : 'SUB SD') + ' · ' + (info.protocol || 'MSE');
          }
        },
        onOffline: (reason) => {
          if (badge) {
            badge.className = 'badge red';
            badge.textContent = '📵 OFFLINE';
          }
        },
      });
      return;
    }

    let hdSinceAt = 0;
    let hdSinceSeq = 0;
    const hdPlayQueue = [];
    let hdBufferReady = false;
    const hdCreatedAt = Date.now();
    let hdMime = 'image/jpeg';
    let hdTransport = 'rtsp_router';

    const paintHdFrame = (b64Str, frameAt, bufLabel) => {
      if (!b64Str) return;
      const dUrl = 'data:' + hdMime + ';base64,' + b64Str;
      cctvHdLastDataUrl = dUrl;
      img.src = dUrl;
      img.style.display = 'block';
      if (empty) empty.style.display = 'none';
      if (badge) {
        const isRtsp = String(hdTransport || '').includes('rtsp');
        badge.className = 'badge green';
        badge.textContent = (bufLabel ? (bufLabel + ' · ') : '') + (isRtsp ? '● LIVE HD RTSP ⚡ · ' : '● LIVE HD · ') + new Date(Number(frameAt || Date.now())).toLocaleTimeString('en-GB', { hour12: false });
      }
    };

    const tickHdPlayout = () => {
      if (myHdEpoch !== cctvHdEpoch) return;
      if (!modal.classList.contains('show')) return;
      if (cctvBufferMode === 'smooth3s' && !document.hidden && hdPlayQueue.length > 0) {
        const isRtsp = String(hdTransport || '').includes('rtsp');
        if (!hdBufferReady) {
          if (!isRtsp || hdPlayQueue.length >= 16 || (Date.now() - hdCreatedAt >= 2800)) {
            hdBufferReady = true;
          } else {
            const pct = Math.min(99, Math.round((hdPlayQueue.length / 16) * 100));
            if (badge) badge.textContent = '🌊 جاري ملء بفرنج السلاسة (' + pct + '%)...';
            setTimeout(tickHdPlayout, 68);
            return;
          }
        }
        const nextFr = hdPlayQueue.shift();
        if (hdPlayQueue.length > 44) hdPlayQueue.shift();
        const bufSec = (hdPlayQueue.length / 14).toFixed(1) + 's';
        paintHdFrame(nextFr.b64, nextFr.at, '🌊 Buffer ' + bufSec);
      }
      setTimeout(tickHdPlayout, 68);
    };
    tickHdPlayout();

    const loopHd = async () => {
      if (myHdEpoch !== cctvHdEpoch) return;
      if (!modal.classList.contains('show')) return;
      if (document.hidden) {
        setTimeout(loopHd, 400);
        return;
      }
      const useBuffered = cctvBufferMode === 'smooth3s';
      try {
        const res = await callCctvApi('cctvAction', 'cctv_action', {
          action: 'poll_wall_frames',
          payload: {
            items: [{ dvr_id: item.dvrId, channel: item.channel, hd: wantHd, buffered: useBuffered, since_at: hdSinceAt, since_seq: hdSinceSeq }],
          },
        });
        if (myHdEpoch !== cctvHdEpoch) return;
        const f = res && res.frames && res.frames[tileKey];
        if (f && f.ok) {
          hdMime = f.mime || hdMime;
          hdTransport = f.transport || hdTransport;
          if (f.latest_seq) hdSinceSeq = Number(f.latest_seq);
          if (f.at) hdSinceAt = Number(f.at);

          if (useBuffered && Array.isArray(f.batch) && f.batch.length > 0) {
            if (!cctvHdLastDataUrl) {
              paintHdFrame(f.batch[0].b64, f.batch[0].at, '🌊 بفرنج...');
            }
            for (const fr of f.batch) {
              if (fr && fr.b64) hdPlayQueue.push(fr);
            }
            if (hdPlayQueue.length > 52) {
              hdPlayQueue.splice(0, hdPlayQueue.length - 52);
            }
          } else if (f.changed && f.image) {
            paintHdFrame(f.image, f.at, '');
          }
        } else if (!cctvHdLastDataUrl && empty) {
          empty.textContent = (f && f.error) || '⏳ جاري جلب البث المباشر عالي الدقة HD...';
        }
        setTimeout(loopHd, useBuffered ? 220 : 125);
      } catch (e) {
        if (myHdEpoch !== cctvHdEpoch) return;
        if (badge) { badge.className = 'badge amber'; badge.textContent = '⏳ إعادة المحاولة...'; }
        setTimeout(loopHd, 900);
      }
    };
    loopHd();
  }

  function closeCctvHdModal() {
    const wasOpen = Boolean($('cctvHdModal') && $('cctvHdModal').classList.contains('show'));
    cctvHdEpoch += 1;
    cctvHdTarget = null;
    destroyHdActivePlayer();
    if (cctvHudIdleTimer) {
      clearTimeout(cctvHudIdleTimer);
      cctvHudIdleTimer = null;
    }
    setCctvHdHudVisible(true);
    if ($('cctvPtzPad')) $('cctvPtzPad').style.display = 'none';
    const modal = $('cctvHdModal');
    const card = $('cctvHdModalCard');
    if (document.fullscreenElement && (document.fullscreenElement === modal || document.fullscreenElement === card)) {
      document.exitFullscreen().catch(() => {});
    }
    if (modal) modal.classList.remove('show');
    syncCctvAudioButtonsUi();
    // Resume multi-camera wall streams when closing the enlarged camera modal
    if (wasOpen && $('view-cameras') && $('view-cameras').classList.contains('active')) {
      renderCctvWall();
    }
  }

  function toLocalDatetimeInputVal(dt) {
    const pad = (n) => String(n).padStart(2, '0');
    return dt.getFullYear() + '-' + pad(dt.getMonth() + 1) + '-' + pad(dt.getDate()) + 'T' + pad(dt.getHours()) + ':' + pad(dt.getMinutes());
  }

  function toDahuaDateTimeStr(inputVal) {
    const s = String(inputVal || '').trim().replace('T', ' ');
    if (!s) return '';
    return s.length === 16 ? (s + ':00') : s;
  }

  function openCctvPlaybackModal(prefDvrId, prefChannel) {
    if (!cctvDvrs.length) {
      toast('أضف جهاز DVR أولاً لاسترجاع التسجيلات', 'error');
      return;
    }
    const modal = $('cctvPlaybackModal');
    const bSel = $('cctvPbBranchSelect');
    const cSel = $('cctvPbChannelSelect');
    if (!modal || !bSel || !cSel) return;

    bSel.innerHTML = cctvDvrs.map((d) => '<option value="' + esc(d.id) + '">🏢 ' + esc(d.name) + '</option>').join('');
    const chosenDvr = cctvDvrs.find((d) => d.id === prefDvrId) || cctvDvrs[0];
    bSel.value = chosenDvr.id;

    const fillChannels = (dvrObj, selCh) => {
      const cnt = Math.max(1, Number((dvrObj && dvrObj.channels_count) || 8));
      const cOpts = [];
      for (let i = 1; i <= cnt; i++) {
        const nm = (dvrObj && dvrObj.channel_names && dvrObj.channel_names[String(i)]) || '';
        cOpts.push('<option value="' + i + '">كاميرا ' + i + (nm ? (' · ' + esc(nm)) : '') + '</option>');
      }
      cSel.innerHTML = cOpts.join('');
      if (selCh) cSel.value = String(selCh);
    };
    fillChannels(chosenDvr, prefChannel || 1);
    bSel.onchange = () => {
      const d = cctvDvrs.find((x) => x.id === bSel.value);
      fillChannels(d, 1);
    };

    const nowDt = new Date();
    const hourAgo = new Date(nowDt.getTime() - 60 * 60 * 1000);
    if ($('cctvPbStartInput')) $('cctvPbStartInput').value = toLocalDatetimeInputVal(hourAgo);
    if ($('cctvPbEndInput')) $('cctvPbEndInput').value = toLocalDatetimeInputVal(nowDt);
    modal.classList.add('show');
  }

  function buildCctvClipUrl(dvrId, channel, startTime, endTime) {
    const tok = (api && api.getAuthToken && api.getAuthToken()) || authToken || '';
    const qs = new URLSearchParams({
      dvr_id: String(dvrId || ''),
      channel: String(channel || 1),
      start_time: startTime,
      end_time: endTime,
    });
    if (tok) qs.set('token', tok);
    return '/api/cctv/clip?' + qs.toString();
  }

  async function downloadCctvSnapshotUrl(srcUrl, fileName) {
    if (!srcUrl) {
      toast('انتظر ظهور صورة الكاميرا أولاً', 'error');
      return;
    }
    try {
      if (srcUrl.startsWith('data:') && api && typeof api.saveBase64Image === 'function') {
        const res = await api.saveBase64Image(srcUrl, fileName);
        if (res && res.success) toast('✓ تم حفظ لقطة الكاميرا في التنزيلات');
        return;
      }
      const resp = await fetch(srcUrl);
      const blob = await resp.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        URL.revokeObjectURL(a.href);
        a.remove();
      }, 1500);
      toast('📸 تم تنزيل لقطة الكاميرا');
    } catch (e) {
      toast('تعذر حفظ اللقطة: ' + (e.message || e), 'error');
    }
  }

  async function refreshCctvBridgeDevicesDropdown(selectedId) {
    const sel = $('cctvBridgeDeviceSelect');
    if (!sel) return;
    try {
      const rDevs = await api.getRelayDevices();
      cctvBridgeDevicesCache = Array.isArray(rDevs) ? rDevs : ((rDevs && rDevs.devices) || []);
    } catch (_) {}
    const curVal = selectedId !== undefined ? selectedId : sel.value;
    const opts = ['<option value="">— اختر جهاز الكمبيوتر الموجود في نفس الفرع / المخزن —</option>'];
    cctvBridgeDevicesCache.forEach((d) => {
      const online = Boolean(d.online);
      const name = d.label || d.hostname || d.device_id;
      const ver = d.app_version || '1.0.0';
      const dot = online ? '🟢 متصل' : '⚪ غير متصل';
      opts.push(
        '<option value="' + esc(d.device_id) + '">' +
          dot + ' — ' + esc(name) + ' (v' + esc(ver) + (d.ip ? ' · ' + esc(d.ip) : '') + ')' +
        '</option>'
      );
    });
    sel.innerHTML = opts.join('');
    if (curVal) sel.value = curVal;
    checkSelectedBridgeDeviceVersion();
  }

  function isClientVerReadyForCctv(verStr) {
    const p = String(verStr || '0.0.0').trim().replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
    if ((p[0] || 0) !== 1) return (p[0] || 0) > 1;
    if ((p[1] || 0) !== 1) return (p[1] || 0) > 1;
    return (p[2] || 0) >= 0;
  }

  function checkSelectedBridgeDeviceVersion() {
    const box = $('cctvBridgeUpgradeBox');
    const txt = $('cctvBridgeUpgradeText');
    const sel = $('cctvBridgeDeviceSelect');
    const mode = ($('cctvModeSelect') && $('cctvModeSelect').value) || 'bridge';
    if (!box || !sel || mode !== 'bridge' || !sel.value) {
      if (box) box.style.display = 'none';
      return;
    }
    const dev = cctvBridgeDevicesCache.find((d) => d.device_id === sel.value);
    if (!dev || isClientVerReadyForCctv(dev.app_version)) {
      box.style.display = 'none';
      return;
    }
    const name = dev.label || dev.hostname || dev.device_id;
    if (txt) {
      txt.textContent =
        '⚠ جهاز «' + name + '» يعمل بالإصدار v' + (dev.app_version || '1.0.0') +
        ' — اضغط الزر لترقيته صامتاً بالخلفية إلى v1.1.0 لتفعيل فحص الهارد واسترجاع التسجيلات.';
    }
    box.style.display = 'flex';
  }

  function resetCctvForm() {
    cctvDetectedChannelNames = null;
    if ($('cctvEditIdInput')) $('cctvEditIdInput').value = '';
    if ($('cctvFormTitle')) $('cctvFormTitle').textContent = '➕ إضافة جهاز Dahua DVR / XVR جديد (فرع أو مخزن)';
    if ($('cctvNameInput')) $('cctvNameInput').value = '';
    if ($('cctvModeSelect')) $('cctvModeSelect').value = 'router';
    if ($('cctvRouterRow')) $('cctvRouterRow').style.display = '';
    if ($('cctvRouterHostInput')) $('cctvRouterHostInput').value = '';
    if ($('cctvRouterHttpPortInput')) $('cctvRouterHttpPortInput').value = '8085';
    if ($('cctvRouterRtspPortInput')) $('cctvRouterRtspPortInput').value = '554';
    if ($('cctvBridgeDeviceRow')) $('cctvBridgeDeviceRow').style.display = 'none';
    if ($('cctvBridgeDeviceSelect')) $('cctvBridgeDeviceSelect').value = '';
    if ($('cctvHostInput')) $('cctvHostInput').value = '10.10.1.108';
    if ($('cctvHttpPortInput')) $('cctvHttpPortInput').value = '80';
    if ($('cctvChannelsInput')) $('cctvChannelsInput').value = '8';
    if ($('cctvUserInput')) $('cctvUserInput').value = 'admin';
    if ($('cctvPassInput')) {
      $('cctvPassInput').value = '';
      $('cctvPassInput').placeholder = 'أدخل كلمة مرور جهاز Dahua DVR';
    }
    if ($('cctvAllowedAdminsInput')) $('cctvAllowedAdminsInput').value = '';
    if ($('cctvTestResultBanner')) $('cctvTestResultBanner').style.display = 'none';
    if ($('cctvScanResultsBox')) $('cctvScanResultsBox').style.display = 'none';
  }

  function collectCctvFormPayload() {
    const rawMode = ($('cctvModeSelect') && $('cctvModeSelect').value) || 'router';
    const mode = rawMode === 'router' ? 'router' : (rawMode === 'direct' ? 'direct' : 'bridge');
    const out = {
      id: (($('cctvEditIdInput') && $('cctvEditIdInput').value) || '').trim(),
      name: (($('cctvNameInput') && $('cctvNameInput').value) || '').trim(),
      connection_mode: mode,
      router_host: mode === 'router' ? (($('cctvRouterHostInput') && $('cctvRouterHostInput').value) || '').trim() : '',
      router_http_port: Number(($('cctvRouterHttpPortInput') && $('cctvRouterHttpPortInput').value) || 8085) || 8085,
      router_rtsp_port: Number(($('cctvRouterRtspPortInput') && $('cctvRouterRtspPortInput').value) || 554) || 554,
      bridge_device_id: mode === 'bridge' ? (($('cctvBridgeDeviceSelect') && $('cctvBridgeDeviceSelect').value) || '').trim() : '',
      backup_bridge_device_id: '',
      host: (($('cctvHostInput') && $('cctvHostInput').value) || '10.10.1.108').trim(),
      http_port: Number(($('cctvHttpPortInput') && $('cctvHttpPortInput').value) || 80) || 80,
      channels_count: Number(($('cctvChannelsInput') && $('cctvChannelsInput').value) || 8) || 8,
      username: (($('cctvUserInput') && $('cctvUserInput').value) || 'admin').trim() || 'admin',
      password: ($('cctvPassInput') && $('cctvPassInput').value) || '',
      allowed_admins: (($('cctvAllowedAdminsInput') && $('cctvAllowedAdminsInput').value) || '').trim(),
    };
    if (cctvDetectedChannelNames && Object.keys(cctvDetectedChannelNames).length) {
      out.channel_names = cctvDetectedChannelNames;
    }
    return out;
  }

  async function loadCctvDvrs(reRenderWall) {
    try {
      const res = await callCctvApi('cctvListDvrs', 'cctv_list_dvrs', {});
      if (res && res.settings) {
        cctvSettings = res.settings;
      }
      if (res && Array.isArray(res.dvrs)) {
        cctvDvrs = res.dvrs;
      }
      applyCctvRoleVisibility();
      syncCctvBranchAndPageSelectors();
      renderCctvSavedList();
      if (reRenderWall && $('view-cameras') && $('view-cameras').classList.contains('active')) {
        renderCctvWall();
      }
    } catch (_) {}
  }

  async function openCamerasView() {
    await loadCctvDvrs(false);
    renderCctvWall();
    // Auto-discover microphone-enabled channels once in the background so `🎙️` badges appear automatically
    for (const d of cctvDvrs) {
      if (d && d.enabled !== false && !d.audio_scanned && !cctvAudioScanAttempted.has(d.id)) {
        cctvAudioScanAttempted.add(d.id);
        callCctvApi('cctvAction', 'cctv_action', {
          action: 'detect_audio',
          payload: { dvr_id: d.id },
        })
          .then((r) => {
            if (r && r.ok && Array.isArray(r.dvrs)) {
              cctvDvrs = r.dvrs;
              if ($('view-cameras') && $('view-cameras').classList.contains('active')) {
                renderCctvWall();
              }
            }
          })
          .catch(() => {});
      }
    }
  }

  (function initCctvUi() {
    if ($('cctvBranchSelect')) {
      $('cctvBranchSelect').addEventListener('change', (e) => {
        cctvSelectedBranch = e.target.value || 'all';
        localStorage.setItem('ibp_cctv_selected_branch', cctvSelectedBranch);
        cctvChannelPage = 0;
        renderCctvWall();
      });
    }
    if ($('cctvPageSelect')) {
      $('cctvPageSelect').addEventListener('change', (e) => {
        cctvChannelPage = Number(e.target.value || 0) || 0;
        renderCctvWall();
      });
    }
    document.querySelectorAll('[data-cctv-grid]').forEach((btn) => {
      btn.addEventListener('click', () => {
        cctvGridCols = Number(btn.getAttribute('data-cctv-grid') || 2) || 2;
        localStorage.setItem('ibp_cctv_grid_cols', String(cctvGridCols));
        cctvChannelPage = 0;
        cctvFocusedTileKey = '';
        document.querySelectorAll('[data-cctv-grid]').forEach((b) => {
          b.className = 'btn btn-sm ' + (b === btn ? 'btn-primary' : 'btn-ghost');
        });
        renderCctvWall();
      });
    });

    if ($('cctvEngineModeSelect')) {
      $('cctvEngineModeSelect').value = cctvEngineMode;
      $('cctvEngineModeSelect').addEventListener('change', (e) => {
        cctvEngineMode = e.target.value || 'nextgen';
        localStorage.setItem('ibp_cctv_engine_mode', cctvEngineMode);
        renderCctvWall();
        const lbls = {
          nextgen: '🚀 تم تفعيل مشغل الجيل الجديد (WebRTC + Direct fMP4/MSE Zero-Transcode)',
          webrtc: '⚡ تم تفعيل وضع WebRTC WHEP منخفض التأخير',
          mse: '🎬 تم تفعيل البث المباشر fMP4/MSE بدون إعادة ترميز (H.264 / H.265)',
          hls: '📡 تم تفعيل وضع HLS Low-Latency',
          legacy: '🛡️ تم تفعيل المشغل الاحتياطي (Legacy MJPEG Buffer)',
        };
        toast(lbls[cctvEngineMode] || lbls.nextgen);
      });
    }

    if ($('cctvSaveLayoutBtn')) {
      $('cctvSaveLayoutBtn').addEventListener('click', () => {
        const computed = getVisibleCctvTiles();
        const order = (computed.allTiles || []).map((t) => t.dvrId + ':' + t.channel);
        cctvCustomLayoutOrder = order;
        localStorage.setItem('ibp_cctv_custom_layout', JSON.stringify({
          gridCols: cctvGridCols,
          branch: cctvSelectedBranch,
          order,
          savedAt: Date.now(),
        }));
        localStorage.setItem('ibp_cctv_grid_cols', String(cctvGridCols));
        localStorage.setItem('ibp_cctv_selected_branch', cctvSelectedBranch);
        toast('💾 تم حفظ تخطيط وترتيب الكاميرات بنجاح (Layout Saved)');
      });
    }

    if ($('cctvResetLayoutBtn')) {
      $('cctvResetLayoutBtn').addEventListener('click', () => {
        cctvCustomLayoutOrder = [];
        localStorage.removeItem('ibp_cctv_custom_layout');
        renderCctvWall();
        toast('↺ تمت استعادة الترتيب الافتراضي للكاميرات');
      });
    }

    if ($('cctvStreamQualitySelect')) {
      $('cctvStreamQualitySelect').value = cctvStreamQualityMode;
      $('cctvStreamQualitySelect').addEventListener('change', (e) => {
        cctvStreamQualityMode = e.target.value || 'auto';
        localStorage.setItem('ibp_cctv_quality_mode', cctvStreamQualityMode);
        renderCctvWall();
        const msg = cctvStreamQualityMode === 'main'
          ? '✨ تم تفعيل البث الرئيسي عالي الدقة (Main Stream HD) لجميع الكاميرات'
          : (cctvStreamQualityMode === 'sub'
            ? '⚡ تم تفعيل البث الفرعي فائق السرعة (Sub Stream SD)'
            : '🧠 تم تفعيل التبديل الذكي (Auto Main/Sub حسب عدد الكاميرات والتركيز)');
        toast(msg);
      });
    }

    if ($('cctvBufferModeSelect')) {
      $('cctvBufferModeSelect').value = cctvBufferMode;
      $('cctvBufferModeSelect').addEventListener('change', (e) => {
        cctvBufferMode = e.target.value || 'realtime';
        localStorage.setItem('ibp_cctv_buffer_mode', cctvBufferMode);
        renderCctvWall();
        toast(cctvBufferMode === 'smooth3s'
          ? '🌊 تم تفعيل وضع السلاسة الفائقة (بفرنج 3 ثوانٍ)'
          : '⚡ تم تفعيل وضع البث اللحظي منخفض التأخير (<0.4s)');
      });
    }

    const syncAspectFitButtons = () => {
      const fitCss = cctvAspectFitMode === 'contain' ? 'contain' : 'fill';
      const lbl = cctvAspectFitMode === 'contain' ? '📐 Fit to Screen' : '🖼️ Fill Screen';
      if ($('cctvAspectFitBtn')) $('cctvAspectFitBtn').textContent = lbl;
      if ($('cctvHdFitToggleBtn')) $('cctvHdFitToggleBtn').textContent = lbl;
      document.querySelectorAll('#cctvWallGrid img, #cctvWallGrid video').forEach((el) => {
        el.style.objectFit = fitCss;
      });
      if ($('cctvHdImg')) $('cctvHdImg').style.objectFit = fitCss;
      if ($('cctvHdVideo')) $('cctvHdVideo').style.objectFit = fitCss;
    };
    syncAspectFitButtons();

    const toggleAspectFitMode = () => {
      cctvAspectFitMode = cctvAspectFitMode === 'contain' ? 'fill' : 'contain';
      localStorage.setItem('ibp_cctv_aspect_fit', cctvAspectFitMode);
      syncAspectFitButtons();
      toast(cctvAspectFitMode === 'contain'
        ? '📐 تم تفعيل Fit to Screen (المحافظة على الأبعاد الأصلية بدون تمدد)'
        : '🖼️ تم تفعيل Fill Screen (ملء شاشة المشغل بالكامل 100% بدون حواف)');
    };

    if ($('cctvHdStreamSwitchBtn')) {
      $('cctvHdStreamSwitchBtn').addEventListener('click', () => {
        if (!cctvHdTarget) return;
        const nextHd = !cctvHdTarget.hd;
        openCctvHdModal(cctvHdTarget.tilesList, cctvHdTarget.index, nextHd);
        toast(nextHd ? '✨ تم التحويل إلى البث الرئيسي Main Stream HD' : '⚡ تم التحويل إلى البث الفرعي Sub Stream SD');
      });
    }

    if ($('cctvHdPipBtn')) {
      $('cctvHdPipBtn').addEventListener('click', async () => {
        const vid = $('cctvHdVideo');
        if (!vid || vid.style.display === 'none' || vid.readyState < 2) {
          toast('نافذة PiP تتطلب تشغيل البث عبر محرك الفيديو المباشر أولاً', 'error');
          return;
        }
        try {
          if (document.pictureInPictureElement) {
            await document.exitPictureInPicture();
          } else if (typeof vid.requestPictureInPicture === 'function') {
            await vid.requestPictureInPicture();
            toast('⧉ تم فتح الكاميرا في نافذة عائمة (Picture-in-Picture)');
          } else {
            toast('متصفحك الحالي لا يدعم Picture-in-Picture', 'error');
          }
        } catch (err) {
          toast('تعذر فتح نافذة PiP: ' + (err.message || err), 'error');
        }
      });
    }

    if ($('cctvHdCloseBtnTop')) {
      $('cctvHdCloseBtnTop').addEventListener('click', closeCctvHdModal);
    }

    const toggleHdTrueFullscreen = async () => {
      const card = $('cctvHdModalCard') || $('cctvHdModal');
      if (!card) return;
      try {
        if (!document.fullscreenElement) {
          await card.requestFullscreen();
        } else {
          await document.exitFullscreen();
        }
      } catch (err) {
        toast('تعذر تفعيل ملء الشاشة: ' + (err.message || err), 'error');
      }
    };

    if ($('cctvHdTrueFullscreenBtn')) {
      $('cctvHdTrueFullscreenBtn').addEventListener('click', toggleHdTrueFullscreen);
    }
    if ($('cctvHdViewport')) {
      $('cctvHdViewport').addEventListener('dblclick', (ev) => {
        if (ev.target.closest('button') || ev.target.closest('#cctvPtzPad')) return;
        toggleHdTrueFullscreen();
      });
    }

    // Auto-hide HUD controls after 2.5s of mouse/touch inactivity in Enlarged Camera & Fullscreen Wall,
    // and immediately restore them on any mouse movement, wheel scroll, key press, or touch!
    const hdModalEl = $('cctvHdModal');
    if (hdModalEl) {
      ['mousemove', 'pointermove', 'mousedown', 'pointerdown', 'wheel', 'touchstart', 'touchmove'].forEach((evtName) => {
        hdModalEl.addEventListener(evtName, () => {
          wakeCctvHdHud();
        }, { passive: true });
      });
    }
    const theaterStageEl = $('cctvTheaterStage');
    if (theaterStageEl) {
      ['mousemove', 'pointermove', 'mousedown', 'pointerdown', 'wheel', 'touchstart', 'touchmove'].forEach((evtName) => {
        theaterStageEl.addEventListener(evtName, () => {
          wakeCctvWallFsHud();
        }, { passive: true });
      });
    }
    window.addEventListener('keydown', () => {
      wakeCctvHdHud();
      wakeCctvWallFsHud();
    }, { passive: true });

    if ($('cctvAspectFitBtn')) {
      $('cctvAspectFitBtn').addEventListener('click', toggleAspectFitMode);
    }
    if ($('cctvHdFitToggleBtn')) {
      $('cctvHdFitToggleBtn').addEventListener('click', toggleAspectFitMode);
    }

    if ($('cctvFullscreenWallBtn')) {
      $('cctvFullscreenWallBtn').addEventListener('click', async () => {
        const stage = $('cctvTheaterStage') || $('view-cameras');
        if (!stage) return;
        try {
          if (!document.fullscreenElement) {
            await stage.requestFullscreen();
          } else {
            await document.exitFullscreen();
          }
        } catch (err) {
          toast('تعذر تفعيل وضع ملء الشاشة: ' + (err.message || err), 'error');
        }
      });
    }

    document.addEventListener('fullscreenchange', () => {
      const isFs = Boolean(document.fullscreenElement);
      const stage = $('cctvTheaterStage');
      if (stage) {
        stage.style.background = isFs ? '#020617' : '';
        stage.style.padding = isFs ? '6px' : '';
      }
      if ($('cctvFullscreenWallBtn')) {
        $('cctvFullscreenWallBtn').textContent = isFs ? '🗗 إنهاء ملء الشاشة' : '⛶ ملء الشاشة';
      }
      if ($('cctvStreamStatusHint')) {
        $('cctvStreamStatusHint').style.display = isFs ? 'none' : 'flex';
      }
      if (!isFs) {
        if (cctvWallFsIdleTimer) {
          clearTimeout(cctvWallFsIdleTimer);
          cctvWallFsIdleTimer = null;
        }
        setCctvWallFsHudVisible(true);
      } else {
        wakeCctvWallFsHud();
      }
      wakeCctvHdHud();
      if ($('view-cameras') && $('view-cameras').classList.contains('active')) {
        renderCctvWall();
      }
    });

    if ($('cctvAutoHideSwitch')) {
      $('cctvAutoHideSwitch').addEventListener('change', async (e) => {
        const val = Boolean(e.target.checked);
        cctvSettings.auto_hide_empty = val;
        cctvChannelPage = 0;
        renderCctvWall();
        await callCctvApi('cctvAction', 'cctv_action', {
          action: 'save_settings',
          payload: { auto_hide_empty: val },
        }).catch(() => {});
      });
    }

    if ($('cctvAutoTourBtn')) {
      $('cctvAutoTourBtn').addEventListener('click', toggleCctvAutoTour);
    }

    if ($('cctvOpenPlaybackBtn')) {
      $('cctvOpenPlaybackBtn').addEventListener('click', () => {
        const prefId = (cctvSelectedBranch !== 'all' && cctvSelectedBranch !== 'vip') ? cctvSelectedBranch : '';
        openCctvPlaybackModal(prefId, 1);
      });
    }

    if ($('cctvCheckHealthBtn')) {
      $('cctvCheckHealthBtn').addEventListener('click', async () => {
        const btn = $('cctvCheckHealthBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الفحص...';
        try {
          const res = await callCctvApi('cctvAction', 'cctv_action', { action: 'check_all_health', payload: {} });
          if (res && res.ok) {
            if (Array.isArray(res.dvrs)) cctvDvrs = res.dvrs;
            renderCctvHealthBar();
            toast('🛡️ اكتمل فحص صحة هاردات التسجيل وأجهزة الـ DVR بنجاح');
          } else {
            toast((res && res.error) || 'تعذر الفحص', 'error');
          }
        } catch (e) {
          toast('خطأ: ' + (e.message || e), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('cctvPlayPauseBtn')) {
      $('cctvPlayPauseBtn').addEventListener('click', () => {
        cctvLivePlaying = !cctvLivePlaying;
        if (!cctvLivePlaying) stopCctvAudio(true);
        const btn = $('cctvPlayPauseBtn');
        btn.textContent = cctvLivePlaying ? '⏸ إيقاف' : '▶ تشغيل';
        btn.className = 'btn btn-sm ' + (cctvLivePlaying ? 'btn-success' : 'btn-primary');
        renderCctvWall();
      });
    }

    if ($('cctvMuteTopBtn')) {
      $('cctvMuteTopBtn').addEventListener('click', () => {
        stopCctvAudio(true);
        toast('🔇 تم كتم الصوت المباشر');
      });
    }
    if ($('cctvWallVolumeSlider')) {
      $('cctvWallVolumeSlider').addEventListener('input', (e) => setCctvAudioVolumePercent(e.target.value));
    }
    if ($('cctvHdVolumeSlider')) {
      $('cctvHdVolumeSlider').addEventListener('input', (e) => setCctvAudioVolumePercent(e.target.value));
    }
    if ($('cctvHdAudioBtn')) {
      $('cctvHdAudioBtn').addEventListener('click', () => {
        if (!cctvHdTarget || !cctvHdTarget.item) return;
        const it = cctvHdTarget.item;
        toggleCctvAudio(it.dvr, it.channel, it.branchName + ' · ' + it.camLabel);
      });
    }

    if ($('cctvOpenLogsBtn')) {
      $('cctvOpenLogsBtn').addEventListener('click', async () => {
        try {
          const res = await callCctvApi('cctvAction', 'cctv_action', {
            action: 'get_cctv_logs',
            payload: { limit: 200 },
          });
          const modal = $('kpiModal');
          const title = $('kpiModalTitle');
          const body = $('kpiModalBody');
          if (!modal || !title || !body) return;
          title.textContent = '📋 سجل تشخيص الكاميرات (cctv-cameras.log)';
          const lines = (res && Array.isArray(res.lines)) ? res.lines : [];
          const logPath = (res && res.log_path) || 'C:\\Users\\IT APP\\Desktop\\blockwebsite\\cctv-cameras.log';
          body.innerHTML =
            '<div style="margin-bottom:8px;font-size:12px;color:var(--muted);">مسار ملف اللوج والنسخة الاحتياطية على السيرفر: <code class="mono" dir="ltr">' + esc(logPath) + '</code></div>' +
            '<pre class="mono" dir="ltr" style="background:#090d16;color:#e2e8f0;padding:12px;border-radius:10px;border:1px solid var(--border);font-size:11.5px;max-height:46vh;overflow:auto;white-space:pre-wrap;line-height:1.55;">' +
            (lines.length ? esc(lines.slice().reverse().join('\n')) : 'لا توجد أحداث مسجلة بعد.') +
            '</pre>';
          modal.classList.add('show');
        } catch (err) {
          toast('تعذر قراءة سجل الكاميرات: ' + (err.message || err), 'error');
        }
      });
    }

    if ($('cctvRefreshNowBtn')) {
      $('cctvRefreshNowBtn').addEventListener('click', () => {
        cctvLivePlaying = true;
        if ($('cctvPlayPauseBtn')) {
          $('cctvPlayPauseBtn').textContent = '⏸ إيقاف';
          $('cctvPlayPauseBtn').className = 'btn btn-success btn-sm';
        }
        loadCctvDvrs(true);
      });
    }

    if ($('cctvSuperOnlySwitch')) {
      $('cctvSuperOnlySwitch').addEventListener('change', async (e) => {
        const val = Boolean(e.target.checked);
        const res = await callCctvApi('cctvSetSettings', 'cctv_set_settings', { superOnly: val });
        if (res && res.ok) {
          cctvSettings = res.settings || { ...cctvSettings, super_only: val };
          toast(val ? '🔒 تم حصر الكاميرات بحساب السوبر أدمن فقط' : '🔓 تم السماح للمديرين بمشاهدة الكاميرات');
        } else {
          e.target.checked = !val;
          toast((res && res.error) || 'تعذر تحديث الإعداد', 'error');
        }
      });
    }

    if ($('cctvManageToggleBtn')) {
      $('cctvManageToggleBtn').addEventListener('click', () => {
        const pnl = $('cctvManagePanel');
        if (!pnl) return;
        const show = pnl.style.display === 'none';
        pnl.style.display = show ? 'block' : 'none';
        if (show) refreshCctvBridgeDevicesDropdown();
      });
    }
    if ($('cctvCloseManageBtn')) {
      $('cctvCloseManageBtn').addEventListener('click', () => {
        if ($('cctvManagePanel')) $('cctvManagePanel').style.display = 'none';
      });
    }
    if ($('cctvModeSelect')) {
      $('cctvModeSelect').addEventListener('change', (e) => {
        const val = e.target.value;
        if ($('cctvRouterRow')) $('cctvRouterRow').style.display = val === 'router' ? '' : 'none';
        if ($('cctvBridgeDeviceRow')) $('cctvBridgeDeviceRow').style.display = val === 'bridge' ? '' : 'none';
        if (val === 'bridge') refreshCctvBridgeDevicesDropdown();
      });
    }
    if ($('cctvReloadDevicesBtn')) {
      $('cctvReloadDevicesBtn').addEventListener('click', () => refreshCctvBridgeDevicesDropdown());
    }
    if ($('cctvBridgeDeviceSelect')) {
      $('cctvBridgeDeviceSelect').addEventListener('change', () => checkSelectedBridgeDeviceVersion());
    }
    if ($('cctvUpgradeBridgeBtn')) {
      $('cctvUpgradeBridgeBtn').addEventListener('click', async () => {
        const sel = $('cctvBridgeDeviceSelect');
        const devId = sel && sel.value;
        if (!devId) return;
        const btn = $('cctvUpgradeBridgeBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الترقية الصامتة بالخلفية...';
        try {
          const r = await api.sendRelayCommand(devId, 'update_client', currentAdminUser, currentAdminRole);
          if (r && (r.success || r.ok)) {
            toast('⬆️ تم إرسال الترقية الصامتة لجهاز الفرع — جاري الانتظار حتى يتصل بـ v1.1.0...');
            const started = Date.now();
            while (Date.now() - started < 55000) {
              await new Promise((res) => setTimeout(res, 3500));
              await refreshCctvBridgeDevicesDropdown(devId);
              const updated = cctvBridgeDevicesCache.find((d) => d.device_id === devId);
              if (updated && isClientVerReadyForCctv(updated.app_version)) {
                toast('✅ اكتملت ترقية جهاز الفرع إلى v' + updated.app_version + ' بنجاح!');
                break;
              }
            }
          } else {
            toast((r && r.error) || 'تعذر إرسال أمر الترقية', 'error');
          }
        } catch (e) {
          toast('خطأ: ' + (e.message || e), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
          checkSelectedBridgeDeviceVersion();
        }
      });
    }
    if ($('cctvResetFormBtn')) {
      $('cctvResetFormBtn').addEventListener('click', resetCctvForm);
    }

    if ($('cctvAutoScanBtn')) {
      $('cctvAutoScanBtn').addEventListener('click', async () => {
        const btn = $('cctvAutoScanBtn');
        const box = $('cctvScanResultsBox');
        const mode = ($('cctvModeSelect') && $('cctvModeSelect').value) === 'direct' ? 'direct' : 'bridge';
        const bridgeId = mode === 'bridge' ? (($('cctvBridgeDeviceSelect') && $('cctvBridgeDeviceSelect').value) || '').trim() : '';
        if (mode === 'bridge' && !bridgeId) {
          toast('اختر كمبيوتر الفرع أولاً ليقوم بفحص شبكته الداخلية عن أجهزة Dahua', 'error');
          return;
        }
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الفحص...';
        if (box) {
          box.style.display = 'block';
          box.innerHTML = '⏳ جاري مسح الشبكة المحلية بحثاً عن أجهزة Dahua DVR (منفذ 37777)... قد يستغرق 5–10 ثوانٍ.';
        }
        try {
          const res = await callCctvApi('cctvScanLan', 'cctv_scan_lan', { bridgeDeviceId: bridgeId || null });
          if (res && res.ok && Array.isArray(res.found)) {
            if (!res.found.length) {
              box.innerHTML = '⚠ لم يتم العثور تلقائياً على منفذ Dahua 37777 على نفس الشبكة — يمكنك كتابة الـ IP يدوياً.';
            } else {
              box.innerHTML =
                '<div style="font-weight:700;margin-bottom:5px;color:#10b981;">✓ تم اكتشاف ' + res.found.length + ' جهاز Dahua (اضغط للاختيار):</div>' +
                '<div style="display:flex;gap:6px;flex-wrap:wrap;">' +
                res.found.map((f) =>
                  '<button type="button" class="btn btn-ghost btn-sm" data-pick-dvr-ip="' + esc(f.host) + '" data-pick-dvr-port="' + (f.http_port || 80) + '">' +
                    '📹 <span class="mono" dir="ltr">' + esc(f.host) + ':' + (f.http_port || 80) + '</span>' +
                  '</button>'
                ).join('') +
                '</div>';
            }
          } else {
            box.innerHTML = '<span style="color:var(--danger);">⚠ ' + esc((res && res.error) || 'تعذر الفحص') + '</span>';
          }
        } catch (e) {
          if (box) box.innerHTML = '<span style="color:var(--danger);">⚠ ' + esc(e.message || e) + '</span>';
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('cctvTestBtn')) {
      $('cctvTestBtn').addEventListener('click', async () => {
        const btn = $('cctvTestBtn');
        const banner = $('cctvTestResultBanner');
        const payload = collectCctvFormPayload();
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الفحص...';
        try {
          const res = await callCctvApi('cctvTestDvr', 'cctv_test_dvr', { dvr: payload });
          if (res && res.ok) {
            if (res.detected_channels && $('cctvChannelsInput')) {
              const std = [4, 8, 16, 24, 32, 64].find((n) => n >= res.detected_channels) || 16;
              $('cctvChannelsInput').value = String(std);
            }
            if (res.channel_names) {
              cctvDetectedChannelNames = res.channel_names;
            }
            if (banner) {
              banner.style.display = 'block';
              banner.style.background = 'rgba(16,185,129,0.12)';
              banner.style.color = '#10b981';
              banner.style.border = '1px solid rgba(16,185,129,0.3)';
              banner.textContent = res.message || '✓ نجح الاتصال بجهاز الـ DVR';
            }
            toast('✓ نجح فحص الاتصال بجهاز الـ DVR');
          } else {
            if (banner) {
              banner.style.display = 'block';
              banner.style.background = 'rgba(239,68,68,0.12)';
              banner.style.color = '#ef4444';
              banner.style.border = '1px solid rgba(239,68,68,0.3)';
              banner.textContent = '⚠ ' + ((res && res.error) || 'فشل الاتصال بجهاز الـ DVR');
            }
          }
        } catch (e) {
          if (banner) {
            banner.style.display = 'block';
            banner.style.background = 'rgba(239,68,68,0.12)';
            banner.style.color = '#ef4444';
            banner.textContent = '⚠ ' + (e.message || e);
          }
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('cctvSaveBtn')) {
      $('cctvSaveBtn').addEventListener('click', async () => {
        const btn = $('cctvSaveBtn');
        const payload = collectCctvFormPayload();
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الحفظ...';
        try {
          const res = await callCctvApi('cctvSaveDvr', 'cctv_save_dvr', { dvr: payload });
          if (res && res.ok) {
            cctvDvrs = res.dvrs || [];
            if (res.settings) cctvSettings = res.settings;
            syncCctvBranchAndPageSelectors();
            renderCctvSavedList();
            resetCctvForm();
            renderCctvWall();
            toast('✓ تم حفظ جهاز الـ DVR وتشغيل البث المباشر');
          } else {
            toast((res && res.error) || 'تعذر حفظ بيانات الـ DVR', 'error');
          }
        } catch (e) {
          toast('خطأ: ' + (e.message || e), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    document.addEventListener('click', async (e) => {
      const pickBtn = e.target.closest('[data-pick-dvr-ip]');
      if (pickBtn) {
        if ($('cctvHostInput')) $('cctvHostInput').value = pickBtn.getAttribute('data-pick-dvr-ip') || '';
        if ($('cctvHttpPortInput')) $('cctvHttpPortInput').value = pickBtn.getAttribute('data-pick-dvr-port') || '80';
        toast('✓ تم تعبئة عنوان IP والمنفذ تلقائياً');
        return;
      }

      const watchBtn = e.target.closest('[data-cctv-watch]');
      if (watchBtn) {
        cctvSelectedBranch = watchBtn.getAttribute('data-cctv-watch') || 'all';
        cctvChannelPage = 0;
        if ($('cctvBranchSelect')) $('cctvBranchSelect').value = cctvSelectedBranch;
        if ($('cctvManagePanel')) $('cctvManagePanel').style.display = 'none';
        renderCctvWall();
        return;
      }

      const pullBtn = e.target.closest('[data-cctv-pullnames]');
      if (pullBtn) {
        const id = pullBtn.getAttribute('data-cctv-pullnames');
        const orig = pullBtn.innerHTML;
        pullBtn.disabled = true;
        pullBtn.innerHTML = '⏳...';
        try {
          const res = await callCctvApi('cctvAction', 'cctv_action', { action: 'pull_names', payload: { dvr_id: id } });
          if (res && res.ok) {
            if (Array.isArray(res.dvrs)) cctvDvrs = res.dvrs;
            renderCctvSavedList();
            renderCctvWall();
            toast(res.message || '✓ تم سحب أسماء الكاميرات');
          } else {
            toast((res && res.error) || 'تعذر سحب الأسماء', 'error');
          }
        } catch (err) {
          toast('خطأ: ' + (err.message || err), 'error');
        } finally {
          pullBtn.disabled = false;
          pullBtn.innerHTML = orig;
        }
        return;
      }

      const unhideBtn = e.target.closest('[data-cctv-unhideall]');
      if (unhideBtn) {
        const id = unhideBtn.getAttribute('data-cctv-unhideall');
        const dvr = cctvDvrs.find((x) => x.id === id);
        if (!dvr) return;
        const res = await callCctvApi('cctvSaveDvr', 'cctv_save_dvr', {
          dvr: { ...dvr, hidden_channels: [] },
        });
        if (res && res.ok) {
          cctvDvrs = res.dvrs || [];
          renderCctvSavedList();
          renderCctvWall();
          toast('✓ تمت استعادة إظهار جميع القنوات المخفية');
        }
        return;
      }

      const editBtn = e.target.closest('[data-cctv-edit]');
      if (editBtn) {
        const id = editBtn.getAttribute('data-cctv-edit');
        const dvr = cctvDvrs.find((x) => x.id === id);
        if (!dvr) return;
        if ($('cctvManagePanel')) $('cctvManagePanel').style.display = 'block';
        await refreshCctvBridgeDevicesDropdown(dvr.bridge_device_id || '');
        if ($('cctvEditIdInput')) $('cctvEditIdInput').value = dvr.id;
        if ($('cctvFormTitle')) $('cctvFormTitle').textContent = '✏ تعديل بيانات جهاز DVR: ' + dvr.name;
        if ($('cctvNameInput')) $('cctvNameInput').value = dvr.name || '';
        const modeVal = dvr.connection_mode || 'router';
        if ($('cctvModeSelect')) $('cctvModeSelect').value = modeVal;
        if ($('cctvRouterRow')) $('cctvRouterRow').style.display = modeVal === 'router' ? '' : 'none';
        if ($('cctvRouterHostInput')) $('cctvRouterHostInput').value = dvr.router_host || '';
        if ($('cctvRouterHttpPortInput')) $('cctvRouterHttpPortInput').value = String(dvr.router_http_port || 8085);
        if ($('cctvRouterRtspPortInput')) $('cctvRouterRtspPortInput').value = String(dvr.router_rtsp_port || 554);
        if ($('cctvBridgeDeviceRow')) $('cctvBridgeDeviceRow').style.display = modeVal === 'bridge' ? '' : 'none';
        if ($('cctvBridgeDeviceSelect')) $('cctvBridgeDeviceSelect').value = dvr.bridge_device_id || '';
        if ($('cctvHostInput')) $('cctvHostInput').value = dvr.host || '';
        if ($('cctvHttpPortInput')) $('cctvHttpPortInput').value = String(dvr.http_port || 80);
        if ($('cctvChannelsInput')) $('cctvChannelsInput').value = String(dvr.channels_count || 8);
        if ($('cctvUserInput')) $('cctvUserInput').value = dvr.username || 'admin';
        if ($('cctvAllowedAdminsInput')) $('cctvAllowedAdminsInput').value = dvr.allowed_admins || '';
        if ($('cctvPassInput')) {
          $('cctvPassInput').value = '';
          $('cctvPassInput').placeholder = dvr.has_password ? 'محفوظة مسبقاً (اتركها فارغة لعدم التغيير)' : 'أدخل كلمة مرور الـ DVR';
        }
        cctvDetectedChannelNames = dvr.channel_names || null;
        checkSelectedBridgeDeviceVersion();
        return;
      }

      const delBtn = e.target.closest('[data-cctv-del]');
      if (delBtn) {
        const id = delBtn.getAttribute('data-cctv-del');
        const dvr = cctvDvrs.find((x) => x.id === id);
        if (!dvr) return;
        if (!window.confirm('هل تريد حذف جهاز الـ DVR الخاص بـ «' + dvr.name + '»؟')) return;
        const res = await callCctvApi('cctvDeleteDvr', 'cctv_delete_dvr', { id });
        if (res && res.ok) {
          cctvDvrs = res.dvrs || [];
          syncCctvBranchAndPageSelectors();
          renderCctvSavedList();
          renderCctvWall();
          toast('تم حذف جهاز الـ DVR');
        }
        return;
      }

      const toggleQBtn = e.target.closest('[data-cctv-toggle-q]');
      if (toggleQBtn) {
        e.stopPropagation();
        const tileIdx = Number(toggleQBtn.getAttribute('data-cctv-toggle-q') || 0);
        const computed = getVisibleCctvTiles();
        const tile = (computed.pageTiles || [])[tileIdx];
        if (tile) {
          const tk = tile.dvrId + ':' + tile.channel;
          const curTxt = toggleQBtn.textContent || '';
          const nextMode = curTxt.includes('HD') ? 'sd' : 'hd';
          cctvTileStreamOverride.set(tk, nextMode);
          toast(nextMode === 'hd'
            ? ('✨ تم تحويل «' + tile.branchName + ' · ' + tile.camLabel + '» إلى البث الرئيسي عالي الدقة Main Stream HD')
            : ('⚡ تم تحويل «' + tile.branchName + ' · ' + tile.camLabel + '» إلى البث الفرعي السريع Sub Stream SD'));
          renderCctvWall();
        }
        return;
      }

      const recBtn = e.target.closest('[data-cctv-rec]');
      if (recBtn) {
        e.stopPropagation();
        const tileIdx = Number(recBtn.getAttribute('data-cctv-rec') || 0);
        const computed = getVisibleCctvTiles();
        const tile = (computed.pageTiles || [])[tileIdx];
        const vidEl = $('cctvTile_' + tileIdx + '_vid');
        const imgEl = $('cctvTile_' + tileIdx + '_img');
        if (!tile) return;
        const tk = tile.dvrId + ':' + tile.channel;
        if (cctvActiveRecorders.has(tk)) {
          const recState = cctvActiveRecorders.get(tk);
          cctvActiveRecorders.delete(tk);
          try { if (recState.timer) clearInterval(recState.timer); } catch (_) {}
          try { if (recState.recorder && recState.recorder.state !== 'inactive') recState.recorder.stop(); } catch (_) {}
          recBtn.textContent = '🔴 REC';
          recBtn.style.background = 'rgba(15,23,42,0.82)';
          recBtn.style.color = '#fca5a5';
          return;
        }
        const hasVid = Boolean(vidEl && vidEl.style.display !== 'none' && vidEl.readyState >= 2 && vidEl.videoWidth > 0);
        const hasImg = Boolean(imgEl && imgEl.dataset.lastSrc);
        if (!hasVid && !hasImg) {
          toast('انتظر ظهور البث المباشر للكاميرا أولاً ثم اضغط تسجيل', 'error');
          return;
        }
        try {
          const canvas = document.createElement('canvas');
          canvas.width = 1280;
          canvas.height = 720;
          const ctx = canvas.getContext('2d');
          if (hasVid) ctx.drawImage(vidEl, 0, 0, canvas.width, canvas.height);
          else if (imgEl) ctx.drawImage(imgEl, 0, 0, canvas.width, canvas.height);
          const stream = canvas.captureStream(15);
          const mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp9')
            ? 'video/webm;codecs=vp9'
            : (MediaRecorder.isTypeSupported('video/webm;codecs=vp8') ? 'video/webm;codecs=vp8' : 'video/webm');
          const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 2500000 });
          const chunks = [];
          const fileName = 'Dahua_LiveRec_' + (tile.branchName || 'Branch') + '_CH' + tile.channel + '_' + Date.now() + '.webm';
          recorder.ondataavailable = (ev) => { if (ev.data && ev.data.size > 0) chunks.push(ev.data); };
          recorder.onstop = () => {
            if (!chunks.length) return;
            const blob = new Blob(chunks, { type: mimeType });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
            toast('✅ تم حفظ وتنزيل التسجيل المباشر: ' + fileName);
          };
          const timer = setInterval(() => {
            try {
              if (vidEl && vidEl.style.display !== 'none' && vidEl.readyState >= 2) {
                ctx.drawImage(vidEl, 0, 0, canvas.width, canvas.height);
              } else if (imgEl && imgEl.complete && imgEl.naturalWidth > 0) {
                ctx.drawImage(imgEl, 0, 0, canvas.width, canvas.height);
              }
            } catch (_) {}
          }, 66);
          recorder.start(250);
          cctvActiveRecorders.set(tk, { canvas, ctx, recorder, chunks, timer, startedAt: Date.now(), fileName });
          recBtn.textContent = '⏹ حفظ';
          recBtn.style.background = 'rgba(239,68,68,0.92)';
          recBtn.style.color = '#ffffff';
          toast('🔴 بدأ تسجيل البث الحي للكاميرا — اضغط «⏹ حفظ» في أي وقت لتنزيل الفيديو');
        } catch (err) {
          toast('تعذر بدء تسجيل الفيديو: ' + (err.message || err), 'error');
        }
        return;
      }

      const pipBtn = e.target.closest('[data-cctv-pip]');
      if (pipBtn) {
        e.stopPropagation();
        const tileIdx = Number(pipBtn.getAttribute('data-cctv-pip') || 0);
        const vidEl = $('cctvTile_' + tileIdx + '_vid');
        if (!vidEl || vidEl.style.display === 'none' || vidEl.readyState < 2) {
          toast('انتظر اتصال البث المباشر للكاميرا لتفعيل نافذة PiP العائمة', 'error');
          return;
        }
        try {
          if (document.pictureInPictureElement === vidEl) {
            await document.exitPictureInPicture();
          } else if (typeof vidEl.requestPictureInPicture === 'function') {
            await vidEl.requestPictureInPicture();
            toast('⧉ تم فتح الكاميرا في نافذة عائمة (Picture-in-Picture)');
          }
        } catch (err) {
          toast('تعذر فتح نافذة PiP: ' + (err.message || err), 'error');
        }
        return;
      }

      const audBtn = e.target.closest('[data-cctv-audio]');
      if (audBtn) {
        e.stopPropagation();
        const tileIdx = Number(audBtn.getAttribute('data-cctv-audio') || 0);
        const computed = getVisibleCctvTiles();
        const tile = (computed.pageTiles || [])[tileIdx];
        if (tile) {
          await toggleCctvAudio(tile.dvr, tile.channel, tile.branchName + ' · ' + tile.camLabel);
        }
        return;
      }

      const favBtn = e.target.closest('[data-cctv-fav]');
      if (favBtn) {
        e.stopPropagation();
        const tileIdx = Number(favBtn.getAttribute('data-cctv-fav') || 0);
        const computed = getVisibleCctvTiles();
        const tile = (computed.pageTiles || [])[tileIdx];
        if (tile) await toggleChannelFav(tile.dvrId, tile.channel);
        return;
      }

      const hdBtn = e.target.closest('[data-cctv-hd]');
      if (hdBtn) {
        e.stopPropagation();
        const tileIdx = Number(hdBtn.getAttribute('data-cctv-hd') || 0);
        const computed = getVisibleCctvTiles();
        const perPage = cctvGridCols * cctvGridCols;
        openCctvHdModal(computed.allTiles || [], cctvChannelPage * perPage + tileIdx);
        return;
      }

      const snapBtn = e.target.closest('[data-cctv-snap]');
      if (snapBtn) {
        e.stopPropagation();
        const tileIdx = Number(snapBtn.getAttribute('data-cctv-snap') || 0);
        const vidEl = $('cctvTile_' + tileIdx + '_vid');
        const imgEl = $('cctvTile_' + tileIdx + '_img');
        const computed = getVisibleCctvTiles();
        const tile = (computed.pageTiles || [])[tileIdx];
        const fname = 'Dahua_' + ((tile && tile.branchName) || 'Cam') + '_CH' + ((tile && tile.channel) || 1) + '_' + Date.now() + '.jpg';
        const snapUrl = captureVideoElementDataUrl(vidEl, imgEl);
        await downloadCctvSnapshotUrl(snapUrl, fname);
        return;
      }

      const ptzBtn = e.target.closest('[data-ptz-code]');
      if (ptzBtn && cctvHdTarget && cctvHdTarget.item) {
        const code = ptzBtn.getAttribute('data-ptz-code');
        const res = await callCctvApi('cctvAction', 'cctv_action', {
          action: 'ptz',
          payload: { dvr_id: cctvHdTarget.item.dvrId, channel: cctvHdTarget.item.channel, code, speed: 4 },
        }).catch((err) => ({ ok: false, error: err.message }));
        if (!res || !res.ok) {
          toast((res && res.error) || 'هذه الكاميرا ثابتة أو لا تدعم تحريك PTZ', 'error');
        }
        return;
      }

      const clipDlBtn = e.target.closest('[data-pb-clip]');
      if (clipDlBtn) {
        const dvrId = clipDlBtn.getAttribute('data-pb-dvr');
        const ch = clipDlBtn.getAttribute('data-pb-ch');
        const st = clipDlBtn.getAttribute('data-pb-st');
        const et = clipDlBtn.getAttribute('data-pb-et');
        // Cap clip window to 60 seconds from start so download finishes in seconds with zero branch lag
        const stDate = new Date(st.replace(' ', 'T'));
        const etDate = new Date(et.replace(' ', 'T'));
        let safeEt = et;
        if (!isNaN(stDate.getTime()) && (isNaN(etDate.getTime()) || (etDate.getTime() - stDate.getTime()) > 60000)) {
          const capped = new Date(stDate.getTime() + 60000);
          safeEt = toDahuaDateTimeStr(toLocalDatetimeInputVal(capped));
        }
        toast('⏳ جاري سحب مقطع الفيديو (60 ثانية) من هارد الـ DVR...');
        if (isNativeTauriOrigin) {
          const dlRes = await callCctvApi('cctvAction', 'cctv_action', {
            action: 'download_clip_local',
            payload: { dvr_id: dvrId, channel: Number(ch || 1), start_time: st, end_time: safeEt },
          });
          if (dlRes && (dlRes.ok || dlRes.success)) {
            toast('✅ تم حفظ مقطع الفيديو في التنزيلات وفتح المجلد');
          } else {
            toast((dlRes && dlRes.error) || 'تعذر سحب المقطع', 'error');
          }
        } else {
          window.open(buildCctvClipUrl(dvrId, ch, st, safeEt), '_blank');
        }
        return;
      }
    });

    // HD Digital Zoom & Pan bindings
    if ($('cctvHdZoomInBtn')) {
      $('cctvHdZoomInBtn').addEventListener('click', () => {
        cctvZoomScale = Math.min(5, cctvZoomScale + 0.5);
        applyHdZoomTransform();
      });
    }
    if ($('cctvHdZoomOutBtn')) {
      $('cctvHdZoomOutBtn').addEventListener('click', () => {
        cctvZoomScale = Math.max(1, cctvZoomScale - 0.5);
        applyHdZoomTransform();
      });
    }
    if ($('cctvHdZoomResetBtn')) {
      $('cctvHdZoomResetBtn').addEventListener('click', () => {
        cctvZoomScale = 1; cctvPanX = 0; cctvPanY = 0;
        applyHdZoomTransform();
      });
    }
    const vp = $('cctvHdViewport');
    if (vp) {
      vp.addEventListener('wheel', (e) => {
        e.preventDefault();
        const delta = e.deltaY < 0 ? 0.35 : -0.35;
        cctvZoomScale = Math.max(1, Math.min(5, cctvZoomScale + delta));
        applyHdZoomTransform();
      }, { passive: false });
      vp.addEventListener('pointerdown', (e) => {
        if (e.target.closest('button') || cctvZoomScale <= 1) return;
        cctvDragging = true;
        cctvDragStart = { x: e.clientX - cctvPanX, y: e.clientY - cctvPanY };
        applyHdZoomTransform();
      });
      window.addEventListener('pointermove', (e) => {
        if (!cctvDragging) return;
        cctvPanX = e.clientX - cctvDragStart.x;
        cctvPanY = e.clientY - cctvDragStart.y;
        applyHdZoomTransform();
      });
      window.addEventListener('pointerup', () => {
        if (cctvDragging) {
          cctvDragging = false;
          applyHdZoomTransform();
        }
      });
    }

    if ($('cctvHdStarBtn')) {
      $('cctvHdStarBtn').addEventListener('click', async () => {
        if (!cctvHdTarget || !cctvHdTarget.item) return;
        await toggleChannelFav(cctvHdTarget.item.dvrId, cctvHdTarget.item.channel);
        const fav = isChannelFav(cctvHdTarget.item.dvrId, cctvHdTarget.item.channel);
        $('cctvHdStarBtn').textContent = fav ? '⭐ في المفضلة' : '☆ مفضلة';
      });
    }
    if ($('cctvHdRenameBtn')) {
      $('cctvHdRenameBtn').addEventListener('click', async () => {
        if (!cctvHdTarget || !cctvHdTarget.item) return;
        const it = cctvHdTarget.item;
        const curName = (it.dvr.channel_names && it.dvr.channel_names[String(it.channel)]) || '';
        const newName = window.prompt('أدخل اسماً واضحاً لهذه الكاميرا (مثال: كاشير أكتوبر · بوابة المخزن):', curName);
        if (newName === null) return;
        const res = await callCctvApi('cctvAction', 'cctv_action', {
          action: 'save_channel_meta',
          payload: { dvr_id: it.dvrId, channel: it.channel, title: newName },
        });
        if (res && res.ok) {
          cctvDvrs = res.dvrs || cctvDvrs;
          const labelTxt = newName.trim() ? ('كاميرا ' + it.channel + ' · ' + newName.trim()) : ('كاميرا ' + it.channel);
          if ($('cctvHdTitle')) $('cctvHdTitle').textContent = '🎥 ' + it.branchName + ' — ' + labelTxt;
          renderCctvWall();
          toast('✓ تم حفظ اسم الكاميرا بنجاح');
        }
      });
    }
    if ($('cctvHdHideChanBtn')) {
      $('cctvHdHideChanBtn').addEventListener('click', async () => {
        if (!cctvHdTarget || !cctvHdTarget.item) return;
        const it = cctvHdTarget.item;
        if (!window.confirm('هل تريد إخفاء «' + it.camLabel + '» من شاشة العرض؟ (يمكنك استعادتها في أي وقت من إعدادات الـ DVR)')) return;
        const res = await callCctvApi('cctvAction', 'cctv_action', {
          action: 'save_channel_meta',
          payload: { dvr_id: it.dvrId, channel: it.channel, hidden: true },
        });
        if (res && res.ok) {
          cctvDvrs = res.dvrs || cctvDvrs;
          closeCctvHdModal();
          renderCctvSavedList();
          renderCctvWall();
          toast('🙈 تم إخفاء القناة من شاشة العرض');
        }
      });
    }
    if ($('cctvHdPtzToggleBtn')) {
      $('cctvHdPtzToggleBtn').addEventListener('click', () => {
        const pad = $('cctvPtzPad');
        if (pad) pad.style.display = pad.style.display === 'none' ? 'block' : 'none';
      });
    }
    if ($('cctvHdPlaybackJumpBtn')) {
      $('cctvHdPlaybackJumpBtn').addEventListener('click', () => {
        const it = cctvHdTarget && cctvHdTarget.item;
        closeCctvHdModal();
        if (it) openCctvPlaybackModal(it.dvrId, it.channel);
      });
    }

    if ($('cctvHdCloseBtn')) $('cctvHdCloseBtn').addEventListener('click', closeCctvHdModal);
    if ($('cctvHdModal')) {
      $('cctvHdModal').addEventListener('click', (e) => {
        if (e.target === $('cctvHdModal')) closeCctvHdModal();
      });
    }
    if ($('cctvHdPrevBtn')) {
      $('cctvHdPrevBtn').addEventListener('click', () => {
        if (cctvHdTarget) openCctvHdModal(cctvHdTarget.tilesList, cctvHdTarget.index - 1);
      });
    }
    if ($('cctvHdNextBtn')) {
      $('cctvHdNextBtn').addEventListener('click', () => {
        if (cctvHdTarget) openCctvHdModal(cctvHdTarget.tilesList, cctvHdTarget.index + 1);
      });
    }
    if ($('cctvHdDownloadBtn')) {
      $('cctvHdDownloadBtn').addEventListener('click', () => {
        const it = cctvHdTarget && cctvHdTarget.item;
        const fname = 'Dahua_HD_' + ((it && it.branchName) || 'Cam') + '_CH' + ((it && it.channel) || 1) + '_' + Date.now() + '.jpg';
        const snapUrl = captureVideoElementDataUrl($('cctvHdVideo'), $('cctvHdImg')) || cctvHdLastDataUrl;
        downloadCctvSnapshotUrl(snapUrl, fname);
      });
    }

    // Keyboard shortcuts for Enterprise CCTV Player:
    // F = Fullscreen, M = Mute/Unmute, S = Screenshot, P = Picture-in-Picture, ArrowLeft/Right = Prev/Next Camera, Escape = Close
    window.addEventListener('keydown', (ev) => {
      const tag = (ev.target && ev.target.tagName) ? ev.target.tagName.toUpperCase() : '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (ev.target && ev.target.isContentEditable)) return;
      const hdOpen = Boolean($('cctvHdModal') && $('cctvHdModal').classList.contains('show'));
      const camViewOpen = Boolean($('view-cameras') && $('view-cameras').classList.contains('active'));
      if (!hdOpen && !camViewOpen) return;

      const key = String(ev.key || '').toLowerCase();
      if (ev.key === 'Escape' && hdOpen) {
        ev.preventDefault();
        closeCctvHdModal();
        return;
      }
      if (ev.key === 'ArrowLeft' && hdOpen && cctvHdTarget) {
        ev.preventDefault();
        openCctvHdModal(cctvHdTarget.tilesList, cctvHdTarget.index + 1);
        return;
      }
      if (ev.key === 'ArrowRight' && hdOpen && cctvHdTarget) {
        ev.preventDefault();
        openCctvHdModal(cctvHdTarget.tilesList, cctvHdTarget.index - 1);
        return;
      }
      if (key === 'f') {
        ev.preventDefault();
        if (hdOpen && $('cctvHdTrueFullscreenBtn')) $('cctvHdTrueFullscreenBtn').click();
        else if ($('cctvFullscreenWallBtn')) $('cctvFullscreenWallBtn').click();
        return;
      }
      if (key === 'm') {
        ev.preventDefault();
        if (hdOpen && $('cctvHdAudioBtn')) $('cctvHdAudioBtn').click();
        else if (cctvAudioTarget) stopCctvAudio(true);
        return;
      }
      if (key === 's') {
        ev.preventDefault();
        if (hdOpen && $('cctvHdDownloadBtn')) $('cctvHdDownloadBtn').click();
        else {
          const firstSnap = document.querySelector('[data-cctv-snap="0"]');
          if (firstSnap) firstSnap.click();
        }
        return;
      }
      if (key === 'p') {
        ev.preventDefault();
        if (hdOpen && $('cctvHdPipBtn')) $('cctvHdPipBtn').click();
        else {
          const firstPip = document.querySelector('[data-cctv-pip="0"]');
          if (firstPip) firstPip.click();
        }
      }
    });

    // Playback modal bindings
    ['cctvPlaybackCloseBtn', 'cctvPlaybackCloseTop'].forEach((id) => {
      if ($(id)) $(id).addEventListener('click', () => $('cctvPlaybackModal').classList.remove('show'));
    });
    if ($('cctvPbSearchBtn')) {
      $('cctvPbSearchBtn').addEventListener('click', async () => {
        const btn = $('cctvPbSearchBtn');
        const box = $('cctvPbResultsBox');
        const dvrId = $('cctvPbBranchSelect') && $('cctvPbBranchSelect').value;
        const ch = Number(($('cctvPbChannelSelect') && $('cctvPbChannelSelect').value) || 1);
        const st = toDahuaDateTimeStr($('cctvPbStartInput') && $('cctvPbStartInput').value);
        const et = toDahuaDateTimeStr($('cctvPbEndInput') && $('cctvPbEndInput').value);
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري البحث...';
        if (box) box.innerHTML = '⏳ جاري الاستعلام من هارد الـ DVR في الفرع...';
        try {
          const res = await callCctvApi('cctvAction', 'cctv_action', {
            action: 'search_recordings',
            payload: { dvr_id: dvrId, channel: ch, start_time: st, end_time: et },
          });
          if (res && res.ok && Array.isArray(res.items)) {
            if (!res.items.length) {
              box.innerHTML = '⚠ لم يتم العثور على ملفات تسجيل في هذه الفترة الزمنية على هارد الـ DVR.';
            } else {
              box.innerHTML =
                '<div style="font-weight:800;margin-bottom:8px;color:#10b981;">✓ تم العثور على ' + res.items.length + ' مقطع مسجل:</div>' +
                '<div style="display:grid;gap:6px;">' +
                res.items.map((it) => {
                  const mb = it.size_bytes > 0 ? ((it.size_bytes / (1024 * 1024)).toFixed(1) + ' MB') : 'تسجيل مستمر';
                  return (
                    '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;padding:8px 10px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">' +
                      '<div><span class="mono" dir="ltr">' + esc(it.start_time) + ' ⬅ ' + esc(it.end_time) + '</span> <span class="badge gray">' + esc(mb) + '</span></div>' +
                      '<button type="button" class="btn btn-success btn-sm" data-pb-clip="1" data-pb-dvr="' + esc(dvrId) + '" data-pb-ch="' + ch + '" data-pb-st="' + esc(it.start_time) + '" data-pb-et="' + esc(it.end_time) + '">⬇ سحب أول 60 ثانية</button>' +
                    '</div>'
                  );
                }).join('') +
                '</div>';
            }
          } else {
            box.innerHTML = '<span style="color:var(--danger);">⚠ ' + esc((res && res.error) || 'تعذر البحث') + '</span>';
          }
        } catch (err) {
          if (box) box.innerHTML = '<span style="color:var(--danger);">⚠ ' + esc(err.message || err) + '</span>';
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }
    if ($('cctvPbQuickClipBtn')) {
      $('cctvPbQuickClipBtn').addEventListener('click', async () => {
        const dvrId = $('cctvPbBranchSelect') && $('cctvPbBranchSelect').value;
        const ch = Number(($('cctvPbChannelSelect') && $('cctvPbChannelSelect').value) || 1);
        const stRaw = $('cctvPbStartInput') && $('cctvPbStartInput').value;
        if (!dvrId || !stRaw) return;
        const stDate = new Date(stRaw);
        const etDate = new Date(stDate.getTime() + 60000);
        const st = toDahuaDateTimeStr(stRaw);
        const et = toDahuaDateTimeStr(toLocalDatetimeInputVal(etDate));
        toast('⏳ جاري سحب مقطع 60 ثانية مباشرة من هارد الـ DVR...');
        if (isNativeTauriOrigin) {
          const dlRes = await callCctvApi('cctvAction', 'cctv_action', {
            action: 'download_clip_local',
            payload: { dvr_id: dvrId, channel: ch, start_time: st, end_time: et },
          });
          if (dlRes && (dlRes.ok || dlRes.success)) {
            toast('✅ تم حفظ مقطع الفيديو في التنزيلات وفتح المجلد');
          } else {
            toast((dlRes && dlRes.error) || 'تعذر سحب المقطع', 'error');
          }
        } else {
          window.open(buildCctvClipUrl(dvrId, ch, st, et), '_blank');
        }
      });
    }
  })();

  /* ==========================================================================
     Biometrics & Attendance Center (ZKTeco Port 4370 + Hikvision ISAPI)
     ========================================================================== */
  let bioDevices = [];
  let bioLogs = [];
  let bioSummary = { total_devices: 0, online_devices: 0, offline_devices: 0, total_logs: 0, today_logs: 0 };
  let bioPollTimer = null;

  async function callBiometricsApi(action, payload) {
    const tok = (api && api.getAuthToken && api.getAuthToken()) || authToken || '';
    const baseOrigin = resolveCctvRelayOrigin();
    const directUrl = (baseOrigin || '') + '/api/biometrics/action';
    if (tok && (location.port === '8790' || location.hostname === '127.0.0.1' || location.hostname === 'localhost' || !isNativeTauriOrigin)) {
      try {
        const resp = await fetch(directUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + tok,
          },
          body: JSON.stringify({ action, payload: payload || {} }),
        });
        if (resp && resp.ok) {
          return await resp.json();
        }
      } catch (_) {}
    }
    if (api && typeof api.biometricsAction === 'function') {
      return api.biometricsAction(action, payload || {});
    }
    const headers = { 'Content-Type': 'application/json' };
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    const resp = await fetch('/api/rpc', {
      method: 'POST',
      headers,
      body: JSON.stringify({ cmd: 'biometrics_action', args: { action, payload: payload || {} } }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    return data.result;
  }

  function showBioBanner(msg, isError) {
    const el = $('bioActionStatusBanner');
    if (!el) return;
    if (!msg) {
      el.style.display = 'none';
      return;
    }
    el.style.display = 'block';
    el.style.background = isError ? 'rgba(239,68,68,0.12)' : 'rgba(16,185,129,0.12)';
    el.style.border = isError ? '1px solid rgba(239,68,68,0.35)' : '1px solid rgba(16,185,129,0.35)';
    el.style.color = isError ? '#ef4444' : '#10b981';
    el.textContent = msg;
  }

  function updateBiometricsKpis() {
    const total = Number(bioSummary.total_devices || bioDevices.length || 0);
    const online = Number(bioSummary.online_devices != null ? bioSummary.online_devices : bioDevices.filter((d) => d.online).length);
    const offline = Math.max(0, total - online);
    const totalLogs = Number(bioSummary.total_logs != null ? bioSummary.total_logs : bioLogs.length);
    const todayLogs = Number(bioSummary.today_logs || 0);

    if ($('bioKpiTotalDevices')) $('bioKpiTotalDevices').textContent = String(total);
    if ($('bioKpiOnlineDevices')) $('bioKpiOnlineDevices').textContent = String(online);
    if ($('bioKpiOfflineDevices')) $('bioKpiOfflineDevices').textContent = String(offline);
    if ($('bioKpiTotalLogs')) $('bioKpiTotalLogs').textContent = String(totalLogs);
    if ($('bioKpiTodayLogsBadge')) $('bioKpiTodayLogsBadge').textContent = 'اليوم: ' + todayLogs;
    if ($('navBiometricsCount')) {
      $('navBiometricsCount').textContent = total > 0 ? (online + '/' + total) : '0';
      $('navBiometricsCount').style.background = offline > 0 ? 'rgba(239,68,68,0.18)' : '';
      $('navBiometricsCount').style.color = offline > 0 ? '#ef4444' : '';
    }
  }

  function syncBioLogDeviceFilter() {
    const sel = $('bioLogDeviceFilter');
    if (!sel) return;
    const prev = sel.value;
    sel.innerHTML = '<option value="">كل ماكينات البصمة (' + bioDevices.length + ')</option>' +
      bioDevices.map((d) => '<option value="' + esc(d.id) + '">' + esc(d.name) + (d.branch ? (' — ' + esc(d.branch)) : '') + '</option>').join('');
    if (prev && bioDevices.some((d) => d.id === prev)) {
      sel.value = prev;
    }
  }

  function renderBiometricsDevices() {
    const grid = $('bioDevicesGrid');
    if (!grid) return;
    if (!bioDevices.length) {
      grid.innerHTML = '<div class="empty" style="grid-column:1/-1;">لا توجد ماكينات بصمة مضافة بعد — اضغط «➕ إضافة ماكينة بصمة (ZK / Hikvision)» أو «🔎 كشف تلقائي لأجهزة البصمة على الشبكة»</div>';
      return;
    }
    const isViewer = String(currentAdminRole || '').toLowerCase() === 'viewer';
    grid.innerHTML = bioDevices.map((d) => {
      const isOnline = Boolean(d.online);
      const vBadge = d.vendor === 'hikvision'
        ? '<span class="badge blue mono">Hikvision ISAPI</span>'
        : '<span class="badge violet mono">ZKTeco 4370</span>';
      const statusBadge = isOnline
        ? '<span class="badge green">🟢 متصل (' + Number(d.latency_ms || 1) + 'ms)</span>'
        : '<span class="badge red">🔴 غير متصل / مفصول</span>';
      const lastSeenStr = d.last_seen
        ? new Date(d.last_seen).toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        : 'لم يتصل بعد';
      const lastPullStr = d.last_pull_at
        ? new Date(d.last_pull_at).toLocaleString('ar-EG', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
        : 'لم يُسحب بعد';
      const borderCol = isOnline ? 'rgba(16,185,129,0.38)' : 'rgba(239,68,68,0.45)';
      return (
        '<div class="card" style="margin-bottom:0;padding:14px;border:1.5px solid ' + borderCol + ';display:flex;flex-direction:column;justify-content:space-between;gap:10px;">' +
          '<div>' +
            '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:8px;">' +
              '<div>' +
                '<div style="font-weight:900;font-size:15px;">👆 ' + esc(d.name) + '</div>' +
                '<div class="hint" style="margin-top:2px;">🏢 ' + esc(d.branch || 'المقر الرئيسي') + '</div>' +
              '</div>' +
              '<div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center;">' +
                statusBadge +
                vBadge +
              '</div>' +
            '</div>' +
            '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:6px;padding:9px 11px;border-radius:10px;background:var(--surface-2);border:1px solid var(--border);font-size:12px;">' +
              '<div><span style="color:var(--muted);">عنوان الـ IP:</span> <b class="mono" dir="ltr">' + esc(d.ip) + ':' + Number(d.port || 4370) + '</b></div>' +
              '<div><span style="color:var(--muted);">الرقم التسلسلي:</span> <b class="mono" dir="ltr">' + esc(d.serial_number || '—') + '</b></div>' +
              '<div><span style="color:var(--muted);">الطراز:</span> <b class="mono" dir="ltr">' + esc(d.device_model || (d.vendor === 'hikvision' ? 'Hikvision' : 'ZKTeco')) + '</b></div>' +
              '<div><span style="color:var(--muted);">آخر ظهور:</span> <b>' + esc(lastSeenStr) + '</b></div>' +
              '<div><span style="color:var(--muted);">البصمات المسحوبة:</span> <b class="mono" style="color:#8b5cf6;">' + Number(d.last_pull_count || 0) + '</b></div>' +
              '<div><span style="color:var(--muted);">آخر سحب:</span> <b>' + esc(lastPullStr) + '</b></div>' +
            '</div>' +
            (!isOnline && d.last_error
              ? '<div style="margin-top:7px;padding:6px 9px;border-radius:8px;background:rgba(239,68,68,0.1);color:#ef4444;font-size:11.5px;font-weight:700;">⚠️ السبب: ' + esc(d.last_error) + '</div>'
              : '') +
          '</div>' +
          '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;padding-top:8px;border-top:1px solid var(--border);">' +
            '<div style="display:flex;gap:6px;flex-wrap:wrap;">' +
              '<button type="button" class="btn btn-primary btn-sm" data-bio-pull="' + esc(d.id) + '" style="background:linear-gradient(135deg,#059669,#10b981);border:none;">📥 سحب البصمات</button>' +
              '<button type="button" class="btn btn-ghost btn-sm" data-bio-probe="' + esc(d.id) + '">🔌 فحص</button>' +
            '</div>' +
            (!isViewer
              ? '<div style="display:flex;gap:5px;">' +
                  '<button type="button" class="btn btn-ghost btn-sm" data-bio-edit="' + esc(d.id) + '" title="تعديل بيانات الماكينة">✏️</button>' +
                  '<button type="button" class="btn btn-ghost btn-sm" data-bio-del="' + esc(d.id) + '" style="color:var(--danger);" title="حذف الماكينة">🗑</button>' +
                '</div>'
              : '') +
          '</div>' +
        '</div>'
      );
    }).join('');
  }

  function formatBioPunchType(t) {
    const s = String(t || '');
    if (s === 'check_in') return '<span class="badge green">🟢 حضور</span>';
    if (s === 'check_out') return '<span class="badge gold">🟡 انصراف</span>';
    if (s === 'break_out') return '<span class="badge gray">خروج راحة</span>';
    if (s === 'break_in') return '<span class="badge blue">عودة راحة</span>';
    if (s === 'overtime_in') return '<span class="badge violet">إضافي حضور</span>';
    if (s === 'overtime_out') return '<span class="badge violet">إضافي انصراف</span>';
    return '<span class="badge blue">' + esc(s || 'بصمة') + '</span>';
  }

  function formatBioVerifyMode(m) {
    const s = String(m || '');
    if (s === 'fingerprint') return '👆 بصمة إصبع';
    if (s === 'face') return '😊 بصمة وجه';
    if (s === 'card') return '💳 كارت ذكي';
    if (s === 'password') return '🔢 كود سري';
    return esc(s || '👆 بصمة');
  }

  function renderBiometricsLogs() {
    const tbody = $('bioLogsTableBody');
    if (!tbody) return;
    const devFilter = ($('bioLogDeviceFilter') && $('bioLogDeviceFilter').value) || '';
    const q = (($('bioLogSearchInput') && $('bioLogSearchInput').value) || '').trim().toLowerCase();

    const filtered = bioLogs.filter((r) => {
      if (devFilter && r.device_id !== devFilter) return false;
      if (q) {
        const hay = `${r.employee_id || ''} ${r.employee_name || ''} ${r.branch || ''} ${r.device_name || ''} ${r.punch_time || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty">لا توجد حركات بصمة مطابقة للبحث الحالي</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.slice(0, 350).map((r) => {
      const vBadge = r.vendor === 'hikvision'
        ? '<span class="badge blue mono">Hikvision</span>'
        : '<span class="badge violet mono">ZKTeco</span>';
      return (
        '<tr>' +
          '<td class="mono" style="font-weight:800;">' + esc(r.employee_id) + '</td>' +
          '<td style="font-weight:700;">' + esc(r.employee_name || ('موظف #' + r.employee_id)) + '</td>' +
          '<td>' + esc(r.branch || '—') + '</td>' +
          '<td>' + esc(r.device_name || '—') + '</td>' +
          '<td>' + vBadge + '</td>' +
          '<td class="mono" dir="ltr" style="font-weight:700;">' + esc(r.punch_time) + '</td>' +
          '<td>' + formatBioPunchType(r.punch_type) + '</td>' +
          '<td>' + formatBioVerifyMode(r.verify_mode) + '</td>' +
        '</tr>'
      );
    }).join('');
  }

  async function loadBiometricsOverview(silent) {
    try {
      const devId = ($('bioLogDeviceFilter') && $('bioLogDeviceFilter').value) || '';
      const q = (($('bioLogSearchInput') && $('bioLogSearchInput').value) || '').trim();
      const res = await callBiometricsApi('overview', { device_id: devId, search: q, limit: 350 });
      if (res && res.ok) {
        bioDevices = Array.isArray(res.devices) ? res.devices : [];
        bioLogs = Array.isArray(res.logs) ? res.logs : [];
        if (res.summary) bioSummary = res.summary;
        updateBiometricsKpis();
        syncBioLogDeviceFilter();
        renderBiometricsDevices();
        renderBiometricsLogs();
      }
    } catch (e) {
      if (!silent) toast('تعذر تحميل بيانات أجهزة البصمة: ' + (e.message || e), 'error');
    }
  }

  function openBiometricsView() {
    loadBiometricsOverview(false);
    if (bioPollTimer) clearInterval(bioPollTimer);
    bioPollTimer = setInterval(() => {
      if (!document.hidden && $('view-biometrics') && $('view-biometrics').classList.contains('active')) {
        loadBiometricsOverview(true);
      }
    }, 15000);
  }

  function stopBiometricsPoll() {
    if (bioPollTimer) {
      clearInterval(bioPollTimer);
      bioPollTimer = null;
    }
  }

  function syncBioVendorFormFields() {
    const vendor = ($('bioVendorSelect') && $('bioVendorSelect').value) || 'zk';
    const isHik = vendor === 'hikvision';
    if ($('bioHikvisionAuthRow')) {
      $('bioHikvisionAuthRow').style.display = isHik ? 'grid' : 'none';
    }
    if ($('bioZkCommKeyWrap')) {
      $('bioZkCommKeyWrap').style.display = isHik ? 'none' : '';
    }
    if ($('bioPortInput')) {
      const curPort = Number($('bioPortInput').value || 0);
      if (isHik && (curPort === 4370 || !curPort)) $('bioPortInput').value = '80';
      if (!isHik && (curPort === 80 || !curPort)) $('bioPortInput').value = '4370';
    }
  }

  function resetBioForm() {
    if ($('bioEditIdInput')) $('bioEditIdInput').value = '';
    if ($('bioNameInput')) $('bioNameInput').value = '';
    if ($('bioBranchInput')) $('bioBranchInput').value = '';
    if ($('bioVendorSelect')) $('bioVendorSelect').value = 'zk';
    if ($('bioIpInput')) $('bioIpInput').value = '';
    if ($('bioPortInput')) $('bioPortInput').value = '4370';
    if ($('bioCommKeyInput')) $('bioCommKeyInput').value = '0';
    if ($('bioUserInput')) $('bioUserInput').value = 'admin';
    if ($('bioPassInput')) $('bioPassInput').value = '';
    if ($('bioFormTitle')) $('bioFormTitle').textContent = '➕ إضافة ماكينة بصمة جديدة على الشبكة المحلية (ZKTeco / Hikvision)';
    if ($('bioTestResultBanner')) $('bioTestResultBanner').style.display = 'none';
    syncBioVendorFormFields();
  }

  (function bindBiometricsEvents() {
    if ($('bioVendorSelect')) {
      $('bioVendorSelect').addEventListener('change', syncBioVendorFormFields);
    }
    if ($('bioManageToggleBtn')) {
      $('bioManageToggleBtn').addEventListener('click', () => {
        const panel = $('bioManagePanel');
        if (!panel) return;
        const open = panel.style.display === 'none';
        panel.style.display = open ? 'block' : 'none';
        if (open) {
          resetBioForm();
          if ($('bioNameInput')) $('bioNameInput').focus();
        }
      });
    }
    if ($('bioCloseManageBtn')) {
      $('bioCloseManageBtn').addEventListener('click', () => {
        if ($('bioManagePanel')) $('bioManagePanel').style.display = 'none';
      });
    }
    if ($('bioResetFormBtn')) {
      $('bioResetFormBtn').addEventListener('click', resetBioForm);
    }

    if ($('bioTestConnBtn')) {
      $('bioTestConnBtn').addEventListener('click', async () => {
        const btn = $('bioTestConnBtn');
        const banner = $('bioTestResultBanner');
        const payload = {
          id: ($('bioEditIdInput') && $('bioEditIdInput').value) || '',
          name: ($('bioNameInput') && $('bioNameInput').value.trim()) || 'ماكينة بصمة',
          branch: ($('bioBranchInput') && $('bioBranchInput').value.trim()) || '',
          vendor: ($('bioVendorSelect') && $('bioVendorSelect').value) || 'zk',
          ip: ($('bioIpInput') && $('bioIpInput').value.trim()) || '',
          port: Number(($('bioPortInput') && $('bioPortInput').value) || 4370),
          comm_key: ($('bioCommKeyInput') && $('bioCommKeyInput').value.trim()) || '0',
          username: ($('bioUserInput') && $('bioUserInput').value.trim()) || 'admin',
          password: ($('bioPassInput') && $('bioPassInput').value) || '',
        };
        if (!payload.ip) {
          toast('يرجى إدخال عنوان الـ IP الداخلي لماكينة البصمة', 'error');
          return;
        }
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري فحص الاتصال...';
        if (banner) {
          banner.style.display = 'block';
          banner.style.background = 'rgba(59,130,246,0.12)';
          banner.style.border = '1px solid rgba(59,130,246,0.35)';
          banner.style.color = '#38bdf8';
          banner.textContent = '⏳ جاري الاتصال بالماكينة على ' + payload.ip + ':' + payload.port + ' ...';
        }
        try {
          const res = await callBiometricsApi('test_device', payload);
          if (res && res.ok) {
            if (banner) {
              banner.style.background = 'rgba(16,185,129,0.14)';
              banner.style.border = '1px solid rgba(16,185,129,0.4)';
              banner.style.color = '#10b981';
              banner.textContent = '✅ متصلة بنجاح (' + Number(res.latency_ms || 1) + 'ms) · الطراز: ' + (res.device_model || payload.vendor.toUpperCase()) + (res.serial_number ? (' · S/N: ' + res.serial_number) : '');
            }
            toast('✅ ماكينة البصمة متصلة وتستجيب بنجاح');
          } else {
            if (banner) {
              banner.style.background = 'rgba(239,68,68,0.14)';
              banner.style.border = '1px solid rgba(239,68,68,0.4)';
              banner.style.color = '#ef4444';
              banner.textContent = '❌ تعذر الاتصال: ' + ((res && res.error) || 'تأكد من عنوان الـ IP والبورت وأن الماكينة تعمل على الشبكة');
            }
            toast((res && res.error) || 'تعذر الاتصال بماكينة البصمة', 'error');
          }
        } catch (err) {
          if (banner) {
            banner.style.background = 'rgba(239,68,68,0.14)';
            banner.style.color = '#ef4444';
            banner.textContent = '❌ خطأ: ' + (err.message || err);
          }
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('bioSaveDeviceBtn')) {
      $('bioSaveDeviceBtn').addEventListener('click', async () => {
        const btn = $('bioSaveDeviceBtn');
        const payload = {
          id: ($('bioEditIdInput') && $('bioEditIdInput').value) || '',
          name: ($('bioNameInput') && $('bioNameInput').value.trim()) || '',
          branch: ($('bioBranchInput') && $('bioBranchInput').value.trim()) || '',
          vendor: ($('bioVendorSelect') && $('bioVendorSelect').value) || 'zk',
          ip: ($('bioIpInput') && $('bioIpInput').value.trim()) || '',
          port: Number(($('bioPortInput') && $('bioPortInput').value) || 4370),
          comm_key: ($('bioCommKeyInput') && $('bioCommKeyInput').value.trim()) || '0',
          username: ($('bioUserInput') && $('bioUserInput').value.trim()) || 'admin',
          password: ($('bioPassInput') && $('bioPassInput').value) || '',
          enabled: true,
        };
        if (!payload.ip) {
          toast('يرجى إدخال عنوان الـ IP لماكينة البصمة', 'error');
          return;
        }
        if (!payload.name) {
          payload.name = (payload.vendor === 'hikvision' ? 'بصمة Hikvision ' : 'بصمة ZKTeco ') + payload.ip;
        }
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الحفظ والفحص...';
        try {
          const res = await callBiometricsApi('save_device', payload);
          if (res && res.ok) {
            bioDevices = Array.isArray(res.devices) ? res.devices : bioDevices;
            if (res.summary) bioSummary = res.summary;
            updateBiometricsKpis();
            syncBioLogDeviceFilter();
            renderBiometricsDevices();
            if ($('bioManagePanel')) $('bioManagePanel').style.display = 'none';
            resetBioForm();
            toast('✓ تم حفظ ماكينة البصمة وفحص اتصالها على الشبكة');
          } else {
            toast((res && res.error) || 'فشل حفظ ماكينة البصمة', 'error');
          }
        } catch (err) {
          toast('خطأ: ' + (err.message || err), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('bioProbeAllBtn')) {
      $('bioProbeAllBtn').addEventListener('click', async () => {
        const btn = $('bioProbeAllBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري الفحص...';
        showBioBanner('⏳ جاري فحص حالة اتصال جميع ماكينات البصمة على الشبكة المحلية...', false);
        try {
          const res = await callBiometricsApi('probe_all', {});
          if (res && res.ok) {
            bioDevices = Array.isArray(res.devices) ? res.devices : bioDevices;
            if (res.summary) bioSummary = res.summary;
            updateBiometricsKpis();
            renderBiometricsDevices();
            const onCount = bioDevices.filter((d) => d.online).length;
            showBioBanner('✅ اكتمل الفحص اللحظي: ' + onCount + ' متصل من إجمالي ' + bioDevices.length + ' ماكينة بصمة', false);
            toast('✓ تم تحديث حالة اتصال ماكينات البصمة');
          } else {
            showBioBanner((res && res.error) || 'تعذر فحص الأجهزة', true);
          }
        } catch (err) {
          showBioBanner('خطأ: ' + (err.message || err), true);
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('bioPullAllBtn')) {
      $('bioPullAllBtn').addEventListener('click', async () => {
        const btn = $('bioPullAllBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري سحب البصمات...';
        showBioBanner('⏳ جاري الاتصال بماكينات البصمة وسحب سجلات الحضور والانصراف...', false);
        try {
          const res = await callBiometricsApi('pull_logs', {});
          if (res && res.ok) {
            if (Array.isArray(res.devices)) bioDevices = res.devices;
            if (Array.isArray(res.logs)) bioLogs = res.logs;
            if (res.summary) bioSummary = res.summary;
            updateBiometricsKpis();
            renderBiometricsDevices();
            renderBiometricsLogs();
            const msg = '✅ اكتمل سحب البصمات: إجمالي الحركات المقروءة (' + Number(res.total_pulled || 0) + ') · حركات جديدة تمت إضافتها للسيرفر (' + Number(res.total_inserted || 0) + ')';
            showBioBanner(msg, false);
            toast(msg);
          } else {
            showBioBanner((res && res.error) || 'تعذر سحب البصمات', true);
            toast((res && res.error) || 'تعذر سحب البصمات', 'error');
          }
        } catch (err) {
          showBioBanner('خطأ أثناء سحب البصمات: ' + (err.message || err), true);
          toast('خطأ: ' + (err.message || err), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('bioAutoScanLanBtn')) {
      $('bioAutoScanLanBtn').addEventListener('click', async () => {
        const btn = $('bioAutoScanLanBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> جاري مسح الشبكة...';
        showBioBanner('🔎 جاري البحث التلقائي في الشبكة المحلية عن ماكينات بصمة ZKTeco (منفذ 4370)...', false);
        try {
          const res = await callBiometricsApi('scan_lan', {});
          if (res && res.ok && Array.isArray(res.found)) {
            if (!res.found.length) {
              showBioBanner('ℹ️ لم يتم العثور تلقائياً على ماكينات ZKTeco على المنفذ 4370 في نفس النطاق — يمكنك إضافة الـ IP يدوياً (سواء ZK أو Hikvision).', false);
            } else {
              const ips = res.found.map((x) => x.ip + ':' + x.port).join(' ، ');
              showBioBanner('✅ تم اكتشاف (' + res.found.length + ') ماكينة بصمة على الشبكة: ' + ips + ' — تم ملء أول جهاز في نموذج الإضافة.', false);
              if ($('bioManagePanel')) $('bioManagePanel').style.display = 'block';
              resetBioForm();
              if ($('bioIpInput')) $('bioIpInput').value = res.found[0].ip;
              if ($('bioPortInput')) $('bioPortInput').value = String(res.found[0].port || 4370);
              if ($('bioNameInput')) $('bioNameInput').value = 'ماكينة بصمة ' + res.found[0].ip;
            }
          } else {
            showBioBanner((res && res.error) || 'تعذر فحص الشبكة', true);
          }
        } catch (err) {
          showBioBanner('خطأ: ' + (err.message || err), true);
        } finally {
          btn.disabled = false;
          btn.innerHTML = orig;
        }
      });
    }

    if ($('bioExportCsvBtn')) {
      $('bioExportCsvBtn').addEventListener('click', async () => {
        const devId = ($('bioLogDeviceFilter') && $('bioLogDeviceFilter').value) || '';
        const q = (($('bioLogSearchInput') && $('bioLogSearchInput').value) || '').trim();
        const filtered = bioLogs.filter((r) => {
          if (devId && r.device_id !== devId) return false;
          if (q) {
            const hay = `${r.employee_id || ''} ${r.employee_name || ''} ${r.branch || ''} ${r.device_name || ''} ${r.punch_time || ''}`.toLowerCase();
            if (!hay.includes(q)) return false;
          }
          return true;
        });
        if (!filtered.length) {
          toast('لا توجد حركات بصمة حالياً لتصديرها', 'error');
          return;
        }
        const rows = [
          ['كود الموظف', 'اسم الموظف', 'الفرع / القسم', 'ماكينة البصمة', 'النوع', 'وقت البصمة', 'نوع الحركة', 'طريقة التحقق'].map(csvCell).join(','),
        ];
        filtered.forEach((r) => {
          rows.push([
            r.employee_id,
            r.employee_name || ('موظف #' + r.employee_id),
            r.branch || '—',
            r.device_name || '—',
            r.vendor === 'hikvision' ? 'Hikvision' : 'ZKTeco',
            r.punch_time,
            r.punch_type === 'check_out' ? 'انصراف' : 'حضور',
            r.verify_mode || 'fingerprint',
          ].map(csvCell).join(','));
        });
        await saveDownloadText(rows.join('\r\n'), 'Biometrics_Attendance_' + new Date().toISOString().slice(0, 10) + '.csv', 'text/csv;charset=utf-8');
      });
    }

    if ($('bioLogDeviceFilter')) {
      $('bioLogDeviceFilter').addEventListener('change', () => loadBiometricsOverview(true));
    }
    if ($('bioLogSearchInput')) {
      $('bioLogSearchInput').addEventListener('input', () => renderBiometricsLogs());
    }
    if ($('bioRefreshLogsBtn')) {
      $('bioRefreshLogsBtn').addEventListener('click', () => loadBiometricsOverview(false));
    }

    document.addEventListener('click', async (e) => {
      const pullBtn = e.target.closest('[data-bio-pull]');
      if (pullBtn) {
        const id = pullBtn.getAttribute('data-bio-pull');
        const dev = bioDevices.find((x) => x.id === id);
        const orig = pullBtn.innerHTML;
        pullBtn.disabled = true;
        pullBtn.innerHTML = '<span class="spinner"></span> جاري السحب...';
        showBioBanner('⏳ جاري سحب حركات البصمة من «' + ((dev && dev.name) || id) + '»...', false);
        try {
          const res = await callBiometricsApi('pull_logs', { id });
          if (res && res.ok) {
            if (Array.isArray(res.devices)) bioDevices = res.devices;
            if (Array.isArray(res.logs)) bioLogs = res.logs;
            if (res.summary) bioSummary = res.summary;
            updateBiometricsKpis();
            renderBiometricsDevices();
            renderBiometricsLogs();
            const firstRes = (Array.isArray(res.results) && res.results[0]) || {};
            if (firstRes.ok === false) {
              showBioBanner('⚠️ تعذر سحب البصمات من «' + ((dev && dev.name) || id) + '»: ' + (firstRes.error || 'غير متصل'), true);
              toast(firstRes.error || 'تعذر السحب من الماكينة', 'error');
            } else {
              const msg = '✅ تم سحب (' + Number(res.total_pulled || 0) + ') حركة بصمة من «' + ((dev && dev.name) || id) + '» (منها ' + Number(res.total_inserted || 0) + ' جديدة)';
              showBioBanner(msg, false);
              toast(msg);
            }
          } else {
            showBioBanner((res && res.error) || 'تعذر سحب البصمات', true);
          }
        } catch (err) {
          showBioBanner('خطأ: ' + (err.message || err), true);
        } finally {
          pullBtn.disabled = false;
          pullBtn.innerHTML = orig;
        }
        return;
      }

      const probeBtn = e.target.closest('[data-bio-probe]');
      if (probeBtn) {
        const id = probeBtn.getAttribute('data-bio-probe');
        const orig = probeBtn.innerHTML;
        probeBtn.disabled = true;
        probeBtn.innerHTML = '...';
        try {
          const res = await callBiometricsApi('probe_one', { id });
          if (res && res.ok) {
            if (Array.isArray(res.devices)) bioDevices = res.devices;
            if (res.summary) bioSummary = res.summary;
            updateBiometricsKpis();
            renderBiometricsDevices();
            const d = res.device;
            if (d && d.online) {
              toast('🟢 «' + d.name + '» متصل (' + d.latency_ms + 'ms)');
            } else {
              toast('🔴 «' + ((d && d.name) || 'الجهاز') + '» غير متصل حالياً', 'error');
            }
          }
        } catch (err) {
          toast('خطأ: ' + (err.message || err), 'error');
        } finally {
          probeBtn.disabled = false;
          probeBtn.innerHTML = orig;
        }
        return;
      }

      const editBtn = e.target.closest('[data-bio-edit]');
      if (editBtn) {
        const id = editBtn.getAttribute('data-bio-edit');
        const d = bioDevices.find((x) => x.id === id);
        if (!d) return;
        if ($('bioManagePanel')) $('bioManagePanel').style.display = 'block';
        if ($('bioEditIdInput')) $('bioEditIdInput').value = d.id;
        if ($('bioNameInput')) $('bioNameInput').value = d.name || '';
        if ($('bioBranchInput')) $('bioBranchInput').value = d.branch || '';
        if ($('bioVendorSelect')) $('bioVendorSelect').value = d.vendor || 'zk';
        if ($('bioIpInput')) $('bioIpInput').value = d.ip || '';
        if ($('bioPortInput')) $('bioPortInput').value = String(d.port || (d.vendor === 'hikvision' ? 80 : 4370));
        if ($('bioCommKeyInput')) $('bioCommKeyInput').value = d.comm_key || '0';
        if ($('bioUserInput')) $('bioUserInput').value = d.username || 'admin';
        if ($('bioPassInput')) {
          $('bioPassInput').value = '';
          $('bioPassInput').placeholder = d.has_password ? 'محفوظة (اتركها فارغة للإبقاء عليها)' : 'أدخل كلمة المرور';
        }
        if ($('bioFormTitle')) $('bioFormTitle').textContent = '✏️ تعديل بيانات ماكينة البصمة: ' + d.name;
        syncBioVendorFormFields();
        if ($('bioNameInput')) $('bioNameInput').focus();
        return;
      }

      const delBtn = e.target.closest('[data-bio-del]');
      if (delBtn) {
        const id = delBtn.getAttribute('data-bio-del');
        const d = bioDevices.find((x) => x.id === id);
        if (!window.confirm('هل أنت متأكد من حذف ماكينة البصمة «' + ((d && d.name) || id) + '»؟')) return;
        try {
          const res = await callBiometricsApi('delete_device', { id });
          if (res && res.ok) {
            bioDevices = Array.isArray(res.devices) ? res.devices : [];
            if (res.summary) bioSummary = res.summary;
            updateBiometricsKpis();
            syncBioLogDeviceFilter();
            renderBiometricsDevices();
            toast('🗑 تم حذف ماكينة البصمة');
          } else {
            toast((res && res.error) || 'فشل الحذف', 'error');
          }
        } catch (err) {
          toast('خطأ: ' + (err.message || err), 'error');
        }
      }
    });
  })();

  /* ---------- Init ---------- */
  let visibilityHookBound = false;
  async function bootDashboardData() {
    refreshServerConnectionPill(false);
    if (connTimer) clearInterval(connTimer);
    connTimer = setInterval(() => {
      if (!document.hidden) refreshServerConnectionPill(false);
    }, 8000);

    await Promise.all([
      loadStatus(),
      loadSites(),
      loadConfig(),
      loadServerInfo(),
      loadDevices(),
      loadRelayConfig(),
    ]);

    if (devicesTimer) clearInterval(devicesTimer);
    devicesTimer = setInterval(() => {
      if (!document.hidden) loadDevices();
    }, 4000);

    Promise.all([
      loadRelayDevices(),
      loadKpis(),
      loadAdminUsers(),
      loadWaBotStatus(true),
      loadCctvDvrs(false),
      loadBiometricsOverview(true),
    ]).catch(() => {});

    startBlockedAttempts();
    refreshAdminUpdateUi(false);
    setInterval(() => {
      if (!document.hidden) refreshAdminUpdateUi(false);
    }, 60000);

    if (!visibilityHookBound) {
      visibilityHookBound = true;
      document.addEventListener('visibilitychange', () => {
        if (!document.hidden && isTokenValid(authToken)) {
          refreshServerConnectionPill(false);
          loadDevices();
          if (relayTimer) loadRelayDevices();
        }
      });
    }
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
