import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import makeWASocket, {
  DisconnectReason,
  fetchLatestBaileysVersion,
  useMultiFileAuthState,
} from '@whiskeysockets/baileys';
import QRCode from 'qrcode';
import pino from 'pino';

const DEFAULT_FEATURES = {
  // الإشعارات الفورية التلقائية (جميعها متوقفة افتراضياً ليختار المدير ما يشاء)
  notify_wa_files: false,
  notify_web_files: false,
  send_screenshot: false,
  send_original_file: false,
  notify_security_tamper: false,
  notify_blocked_sites: false,
  notify_erp_backup_ok: false,
  notify_erp_backup_fail: false,
  notify_device_offline: false,
  notify_server_health: false,
  notify_cctv_health: false,
  notify_cctv_schedule: false,
  notify_biometrics_offline: true,
  notify_morning_brief: true,
  // الأوامر التفاعلية من واتساب المدير (جميعها متوقفة افتراضياً ليختار المدير ما يشاء)
  cmd_status: false,
  cmd_screenshot: false,
  cmd_camera: false,
  cmd_cctv: false,
  cmd_biometrics: true,
  cmd_block_unblock: false,
  cmd_usb: false,
  cmd_group_control: false,
  cmd_sites: false,
  cmd_daily_report: false,
  cmd_recent_files: false,
  cmd_rustdesk: false,
  cmd_update_client: false,
  cmd_power: false,
  cmd_erp_backup: false,
};

const DEFAULT_CONFIG = {
  enabled: false,
  auto_connect: true,
  recipients: '',
  max_file_mb: 25,
  custom_aliases: '',
  features: { ...DEFAULT_FEATURES },
};

const MIME_BY_EXT = {
  '.pdf': 'application/pdf',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.xls': 'application/vnd.ms-excel',
  '.csv': 'text/csv',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.doc': 'application/msword',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.zip': 'application/zip',
  '.rar': 'application/vnd.rar',
  '.7z': 'application/x-7z-compressed',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.txt': 'text/plain',
  '.json': 'application/json',
};

function guessMime(fileName) {
  const ext = path.extname(String(fileName || '')).toLowerCase();
  return MIME_BY_EXT[ext] || 'application/octet-stream';
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function formatCairoTime(tsMs) {
  try {
    return new Date(tsMs || Date.now()).toLocaleString('ar-EG', {
      timeZone: 'Africa/Cairo',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch (_) {
    return new Date(tsMs || Date.now()).toISOString();
  }
}

export function normalizeRecipientEntry(raw) {
  const s = String(raw || '').trim();
  if (!s) return '';
  if (s.endsWith('@g.us') || s.endsWith('@s.whatsapp.net')) return s;
  let digits = s.replace(/[^\d]/g, '');
  if (!digits) return '';
  if (digits.startsWith('00')) digits = digits.slice(2);
  // Egyptian mobile shorthand (e.g. 01012345678 -> 201012345678)
  if (digits.length === 11 && /^01[0125]\d{8}$/.test(digits)) {
    digits = '2' + digits;
  }
  if (digits.length < 8 || digits.length > 16) return '';
  return `${digits}@s.whatsapp.net`;
}

function parseRecipientJids(recipientsStr) {
  const parts = String(recipientsStr || '')
    .split(/[\n,;،]+/)
    .map((p) => normalizeRecipientEntry(p))
    .filter(Boolean);
  return Array.from(new Set(parts));
}

function extractDigitsFromJid(jid) {
  const s = String(jid || '').trim();
  if (!s || s.endsWith('@g.us') || s.endsWith('@lid')) return '';
  const left = s.split('@')[0] || '';
  const base = left.split(':')[0] || '';
  return base.replace(/[^\d]/g, '');
}

function readLanServerCreds() {
  try {
    const cfgPath = 'C:/ProgramData/InternetBlocker/config.json';
    if (fs.existsSync(cfgPath)) {
      const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8').replace(/^\uFEFF/, '')) || {};
      return {
        port: Number(cfg.server_port || 8787),
        token: String(cfg.api_token || '').trim(),
      };
    }
  } catch (_) {}
  return { port: 8787, token: '' };
}

function lanAdminRequest(method, subPath, bodyObj = null) {
  return new Promise((resolve) => {
    const { port, token } = readLanServerCreds();
    if (!token) return resolve(null);
    const payload = bodyObj ? Buffer.from(JSON.stringify(bodyObj), 'utf8') : null;
    const headers = { Authorization: `Bearer ${token}` };
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = payload.length;
    }
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: `/api/admin/${subPath.replace(/^\/+/, '')}`,
        method,
        headers,
        timeout: 8000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve(parsed);
          } catch (_) {
            resolve(null);
          }
        });
      }
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    if (payload) req.write(payload);
    req.end();
  });
}

export function createWhatsAppBot({ db, dataDir, getArchiveRoot, cctv = null, biometrics = null }) {
  let bioManager = biometrics;
  function setBiometricsManager(mgr) {
    bioManager = mgr;
  }
  const authDir = path.join(dataDir, 'wa-bot-auth');
  const configPath = path.join(dataDir, 'wa-bot-config.json');
  const heartbeatPath = path.join(dataDir, 'wa-bot-heartbeat.json');
  const logger = pino({ level: 'silent' });

  let previousShutdownGapMs = 0;
  let bootGapNotified = false;
  try {
    if (fs.existsSync(heartbeatPath)) {
      const hb = JSON.parse(fs.readFileSync(heartbeatPath, 'utf8'));
      const lastTs = Number(hb && hb.ts) || 0;
      if (lastTs > 0 && Date.now() - lastTs >= 120_000) {
        previousShutdownGapMs = Date.now() - lastTs;
      }
    }
    fs.writeFileSync(heartbeatPath, JSON.stringify({ ts: Date.now() }), 'utf8');
  } catch (_) {}
  setInterval(() => {
    try { fs.writeFileSync(heartbeatPath, JSON.stringify({ ts: Date.now() }), 'utf8'); } catch (_) {}
  }, 30_000);

  let config = loadConfig();
  let sock = null;
  let state = 'disconnected'; // disconnected | connecting | qr_ready | connected
  let qrDataUrl = '';
  let qrUpdatedAt = 0;
  let botPhone = '';
  let botName = '';
  let lastError = '';
  let manualStop = false;
  let reconnectTimer = null;
  let connectingPromise = null;
  const activityLog = [];

  // Runtime trackers for device offline & blocked-site notifications
  const deviceOnlineTracker = new Map(); // device_id -> { online, offlineSince, alertedOffline, name }
  const seenBlockedPairs = new Map(); // "deviceId|host" -> timestampMs
  const sentByBotIds = new Set();
  const processedIncomingIds = new Set();
  let lastListedFiles = [];
  let baselineSeeded = false;

  function rememberSentMsg(sentObj) {
    const id = sentObj && sentObj.key && sentObj.key.id;
    if (id) {
      sentByBotIds.add(id);
      if (sentByBotIds.size > 500) {
        const first = sentByBotIds.values().next().value;
        sentByBotIds.delete(first);
      }
    }
  }

  function pushLog(text, level = 'info') {
    activityLog.unshift({
      at: Date.now(),
      time: formatCairoTime(Date.now()),
      level,
      text: String(text || '').slice(0, 300),
    });
    if (activityLog.length > 50) activityLog.length = 50;
  }

  function loadConfig() {
    try {
      if (fs.existsSync(configPath)) {
        const raw = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        return sanitizeConfig(raw);
      }
    } catch (_) {}
    return sanitizeConfig(DEFAULT_CONFIG);
  }

  function sanitizeConfig(raw) {
    const src = raw && typeof raw === 'object' ? raw : {};
    const fSrc = src.features && typeof src.features === 'object' ? src.features : {};
    const features = {};
    for (const k of Object.keys(DEFAULT_FEATURES)) {
      features[k] = fSrc[k] !== undefined ? Boolean(fSrc[k]) : Boolean(DEFAULT_FEATURES[k]);
    }
    const maxMb = Math.max(1, Math.min(64, Number(src.max_file_mb) || 25));
    return {
      enabled: Boolean(src.enabled),
      auto_connect: src.auto_connect !== false,
      recipients: String(src.recipients || '').trim().slice(0, 1000),
      max_file_mb: maxMb,
      custom_aliases: String(src.custom_aliases || '').trim().slice(0, 4000),
      features,
    };
  }

  function saveConfig(nextRaw) {
    const merged = sanitizeConfig({
      ...config,
      ...(nextRaw || {}),
      features: {
        ...(config.features || {}),
        ...((nextRaw && nextRaw.features) || {}),
      },
    });
    config = merged;
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
    pushLog('تم حفظ إعدادات وخصائص بوت واتساب بنجاح');
    return getStatus();
  }

  function hasSavedSession() {
    try {
      return fs.existsSync(path.join(authDir, 'creds.json'));
    } catch (_) {
      return false;
    }
  }

  function getStatus() {
    const parsedRecipients = parseRecipientJids(config.recipients);
    return {
      ok: true,
      state,
      connected: state === 'connected',
      has_saved_session: hasSavedSession(),
      qr_data_url: state === 'qr_ready' ? qrDataUrl : '',
      qr_updated_at: qrUpdatedAt,
      bot_phone: botPhone,
      bot_name: botName,
      last_error: lastError,
      recipients_count: parsedRecipients.length,
      parsed_recipients: parsedRecipients,
      config,
      logs: activityLog.slice(0, 25),
    };
  }

  function clearReconnectTimer() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  async function startSocket() {
    if (connectingPromise) return connectingPromise;
    connectingPromise = (async () => {
      try {
        clearReconnectTimer();
        manualStop = false;
        lastError = '';
        if (sock) {
          try { sock.ev.removeAllListeners(); sock.end(undefined); } catch (_) {}
          sock = null;
        }
        state = 'connecting';
        fs.mkdirSync(authDir, { recursive: true });
        const { state: authState, saveCreds } = await useMultiFileAuthState(authDir);
        let version = undefined;
        try {
          const vInfo = await Promise.race([
            fetchLatestBaileysVersion(),
            new Promise((r) => setTimeout(() => r(null), 5000)),
          ]);
          if (vInfo && vInfo.version) version = vInfo.version;
        } catch (_) {}

        const ws = makeWASocket({
           ...(version ? { version } : {}),
          auth: authState,
          logger,
          printQRInTerminal: false,
          browser: ['IT ELKHAWGA Server', 'Chrome', '131.0.0'],
          markOnlineOnConnect: false,
          syncFullHistory: false,
          generateHighQualityLinkPreview: false,
        });
        sock = ws;

        ws.ev.on('creds.update', saveCreds);

        ws.ev.on('connection.update', async (update) => {
          if (sock !== ws) return;
          const { connection, lastDisconnect, qr } = update;
          if (qr) {
            try {
              qrDataUrl = await QRCode.toDataURL(qr, {
                width: 300,
                margin: 2,
                color: { dark: '#0a1f3d', light: '#ffffff' },
              });
              qrUpdatedAt = Date.now();
              state = 'qr_ready';
              lastError = '';
              pushLog('تم توليد رمز QR جديد — امسحه من تطبيق واتساب على هاتف البوت');
            } catch (e) {
              lastError = 'تعذر توليد صورة QR';
            }
          }
          if (connection === 'open') {
            qrDataUrl = '';
            state = 'connected';
            lastError = '';
            const me = ws.user || {};
            botPhone = extractDigitsFromJid(me.id || '') || String(me.id || '').split('@')[0] || '';
            botName = String(me.name || me.verifiedName || 'IT ELKHAWGA Bot');
            pushLog(`✓ متصل الآن برقم البوت: +${botPhone}`);
            if (!bootGapNotified && previousShutdownGapMs >= 120_000) {
              bootGapNotified = true;
              const mins = Math.max(2, Math.round(previousShutdownGapMs / 60_000));
              setTimeout(() => {
                onServerHealthEvent({ kind: 'host_recovered', downMinutes: mins }).catch(() => {});
              }, 2000);
            }
          } else if (connection === 'close') {
            qrDataUrl = '';
            const statusCode =
              lastDisconnect?.error?.output?.statusCode ||
              lastDisconnect?.error?.statusCode ||
              0;
            const loggedOut = statusCode === DisconnectReason.loggedOut || statusCode === 401;
            if (loggedOut) {
              state = 'disconnected';
              botPhone = '';
              botName = '';
              lastError = 'تم تسجيل الخروج من الهاتف — يرجى مسح رمز QR من جديد';
              pushLog(lastError, 'warn');
              try { fs.rmSync(authDir, { recursive: true, force: true }); } catch (_) {}
            } else if (manualStop) {
              state = 'disconnected';
            } else {
              state = 'connecting';
              const errMsg = lastDisconnect?.error?.message || `انقطع الاتصال (${statusCode || 'شبكة'})`;
              lastError = `جاري إعادة الاتصال تلقائياً... (${errMsg})`;
              clearReconnectTimer();
              reconnectTimer = setTimeout(() => {
                if (!manualStop) startSocket().catch(() => {});
              }, 5000);
            }
          }
        });

        ws.ev.on('messages.upsert', async ({ messages, type }) => {
          if ((type !== 'notify' && type !== 'append') || !Array.isArray(messages)) return;
          for (const msg of messages) {
            if (type === 'append') {
              const tsSec = Number(msg?.messageTimestamp || 0);
              if (!tsSec || Math.abs(Date.now() / 1000 - tsSec) > 35) continue;
            }
            handleIncomingMessage(msg).catch((e) => {
              pushLog(`خطأ أثناء معالجة رسالة واردة: ${e && e.message}`, 'warn');
            });
          }
        });
      } catch (err) {
        state = 'disconnected';
        lastError = (err && err.message) || 'فشل بدء جلسة واتساب';
        pushLog(`تعذر تشغيل البوت: ${lastError}`, 'error');
      } finally {
        connectingPromise = null;
      }
    })();
    return connectingPromise;
  }

  async function connect() {
    config.auto_connect = true;
    try { fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8'); } catch (_) {}
    await startSocket();
    // Wait up to 8.5s so the generated QR image (or immediate connection) is returned on the first click
    const t0 = Date.now();
    while (state === 'connecting' && Date.now() - t0 < 8500) {
      await new Promise((r) => setTimeout(r, 200));
    }
    return getStatus();
  }

  async function disconnect({ logout = false } = {}) {
    manualStop = true;
    clearReconnectTimer();
    if (!logout) {
      config.auto_connect = false;
      try { fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8'); } catch (_) {}
    }
    const cur = sock;
    sock = null;
    if (cur) {
      try {
        if (logout && state === 'connected') {
          await Promise.race([cur.logout(), new Promise((r) => setTimeout(r, 3000))]);
        }
      } catch (_) {}
      try { cur.ev.removeAllListeners(); cur.end(undefined); } catch (_) {}
    }
    if (logout) {
      try { fs.rmSync(authDir, { recursive: true, force: true }); } catch (_) {}
      botPhone = '';
      botName = '';
      pushLog('تم فك ربط هاتف البوت ومسح الجلسة المحفوظة');
    } else {
      pushLog('تم إيقاف اتصال البوت مؤقتاً (الجلسة محفوظة)');
    }
    qrDataUrl = '';
    state = 'disconnected';
    lastError = '';
    return getStatus();
  }

  async function sendToRecipients(content, logSummary = '') {
    if (!sock || state !== 'connected') {
      throw new Error('البوت غير متصل حالياً بواتساب — افتح تبويب بوت واتساب وتأكد من الربط');
    }
    const jids = parseRecipientJids(config.recipients);
    if (!jids.length) {
      throw new Error('لم يتم إدخال رقم هاتف المدير المستقبِل في إعدادات البوت');
    }
    let sent = 0;
    let lastSendErr = '';
    for (const jid of jids) {
      try {
        const resMsg = await sock.sendMessage(jid, content);
        rememberSentMsg(resMsg);
        sent++;
      } catch (e) {
        lastSendErr = (e && e.message) || 'فشل الإرسال';
      }
    }
    if (sent === 0 && lastSendErr) {
      throw new Error(lastSendErr);
    }
    if (logSummary) pushLog(logSummary);
    return sent;
  }

  async function sendTestMessage() {
    const activeFeaturesCount = Object.values(config.features || {}).filter(Boolean).length;
    const text =
      `✅ *اختبار بوت واتساب — IT ELKHAWGA*\n` +
      `━━━━━━━━━━━━━━\n` +
      `• حالة الربط: متصل بنجاح\n` +
      `• المفتاح العام للبوت: ${config.enabled ? 'مُفعّل 🟢' : 'مُعطّل مؤقتاً ⚪'}\n` +
      `• عدد الخصائص المفعلة حالياً: *${activeFeaturesCount}* من *${Object.keys(DEFAULT_FEATURES).length}*\n` +
      `• التوقيت: ${formatCairoTime(Date.now())}\n\n` +
      `💡 يمكنك إرسال كلمة *مساعدة* لعرض الأوامر المفعلة حالياً.`;
    const sent = await sendToRecipients({ text }, 'تم إرسال رسالة اختبار بنجاح إلى أرقام الإدارة');
    return { ok: true, sent };
  }

  function decodeBase64Buffer(b64Str) {
    if (!b64Str || typeof b64Str !== 'string') return null;
    let clean = b64Str.trim();
    const idx = clean.indexOf(';base64,');
    if (idx !== -1) clean = clean.slice(idx + 8);
    if (clean.length < 64) return null;
    try {
      return Buffer.from(clean, 'base64');
    } catch (_) {
      return null;
    }
  }

  async function resolveArchivedFile({ uploadedFileId, deviceId, fileName }) {
    for (let attempt = 0; attempt < 8; attempt++) {
      if (uploadedFileId) {
        try {
          const row = db
            .prepare('SELECT file_name, stored_path, file_size FROM uploaded_files WHERE file_id=?')
            .get(String(uploadedFileId));
          if (row && row.stored_path && fs.existsSync(row.stored_path)) {
            return { storedPath: row.stored_path, fileName: row.file_name || fileName || 'file.bin', size: Number(row.file_size || 0) };
          }
        } catch (_) {}
      }
      // Fallback: check LAN archive-index.jsonl for LAN-connected devices
      try {
        const idxPath = path.join(getArchiveRoot(), 'archive-index.jsonl');
        if (fs.existsSync(idxPath)) {
          const stat = fs.statSync(idxPath);
          const readLen = Math.min(stat.size, 64 * 1024);
          const fd = fs.openSync(idxPath, 'r');
          const buf = Buffer.alloc(readLen);
          fs.readSync(fd, buf, 0, readLen, Math.max(0, stat.size - readLen));
          fs.closeSync(fd);
          const lines = buf.toString('utf8').trim().split('\n').reverse();
          for (const line of lines) {
            if (!line.trim().startsWith('{')) continue;
            try {
              const rec = JSON.parse(line);
              const matchId = uploadedFileId && rec.file_id === uploadedFileId;
              const matchRecent =
                !uploadedFileId &&
                fileName &&
                rec.file_name === fileName &&
                (!deviceId || rec.device_id === deviceId) &&
                Date.now() - Number(rec.created_at || 0) < 30_000;
              if ((matchId || matchRecent) && rec.stored_path && fs.existsSync(rec.stored_path)) {
                return {
                  storedPath: rec.stored_path,
                  fileName: rec.file_name || fileName || 'file.bin',
                  size: Number(rec.file_size || 0),
                };
              }
            } catch (_) {}
          }
        }
      } catch (_) {}

      if (attempt < 7) {
        await new Promise((r) => setTimeout(r, 450));
      }
    }
    return null;
  }

  function lookupDeviceDisplayName(deviceId, metaObj) {
    if (metaObj && metaObj.device_name) return String(metaObj.device_name);
    try {
      const row = db.prepare('SELECT label, hostname FROM devices WHERE device_id=?').get(deviceId);
      if (row) return row.label || row.hostname || deviceId;
    } catch (_) {}
    return deviceId || 'جهاز غير معروف';
  }

  async function onAlert({ id, deviceId, type, severity, message, metaObj, screenshotB64 }) {
    try {
      if (!config.enabled || state !== 'connected') return;
      const jids = parseRecipientJids(config.recipients);
      if (!jids.length) return;

      const meta = metaObj && typeof metaObj === 'object' ? metaObj : {};
      // ERP backup events are handled by onErpBackupEvent with dedicated OK/Fail switches
      if (deviceId === 'server_erp_backup' || meta.source === 'erp_backup') return;

      const f = config.features || {};
      const isUploadAlert =
        type === 'dlp_upload' ||
        Boolean(meta.file_name || meta.uploaded_file_id || meta.channel);

      if (isUploadAlert) {
        const ch = String(meta.channel || 'whatsapp_web').toLowerCase();
        const isWa = ch.includes('whatsapp');
        if (isWa && !f.notify_wa_files) return;
        if (!isWa && !f.notify_web_files) return;

        const devName = lookupDeviceDisplayName(deviceId, meta);
        const lines = [
          isWa ? `📤 *تنبيه إرسال ملف عبر واتساب*` : `🌐 *تنبيه رفع ملف لموقع خارجي*`,
          `━━━━━━━━━━━━━━`,
          `💻 *الجهاز:* ${devName}`,
        ];
        if (meta.windows_user) lines.push(`👤 *مستخدم الويندوز:* ${meta.windows_user}`);
        if (meta.file_name) {
          const szTxt = meta.file_size ? ` (${formatBytes(meta.file_size)})` : '';
          lines.push(`📄 *الملف:* ${meta.file_name}${szTxt}`);
        }
        if (meta.recipient_name || meta.recipient_phone) {
          const recStr = [meta.recipient_name, meta.recipient_phone ? `(+${String(meta.recipient_phone).replace(/^\+/, '')})` : '']
            .filter(Boolean)
            .join(' ');
          lines.push(`🎯 *المستلم:* ${recStr}`);
        }
        if (!isWa && meta.page_url) {
          lines.push(`🔗 *الموقع:* ${String(meta.page_url).slice(0, 120)}`);
        }
        lines.push(`🕒 *الوقت:* ${formatCairoTime(Date.now())}`);
        const caption = lines.join('\n');

        const imgBuf = f.send_screenshot ? decodeBase64Buffer(screenshotB64) : null;
        if (imgBuf) {
          await sendToRecipients({ image: imgBuf, caption }, `إرسال تنبيه ملف + صورة شاشة (${devName})`);
        } else {
          await sendToRecipients({ text: caption }, `إرسال تنبيه ملف نصي (${devName})`);
        }

        if (f.send_original_file) {
          const found = await resolveArchivedFile({
            uploadedFileId: meta.uploaded_file_id,
            deviceId,
            fileName: meta.file_name,
          });
          if (found && found.storedPath) {
            const stat = fs.statSync(found.storedPath);
            const maxBytes = (Number(config.max_file_mb) || 25) * 1024 * 1024;
            if (stat.size > 0 && stat.size <= maxBytes) {
              const fileBuf = fs.readFileSync(found.storedPath);
              await sendToRecipients(
                {
                  document: fileBuf,
                  fileName: found.fileName,
                  mimetype: guessMime(found.fileName),
                  caption: `📎 نسخة الأصل المحفوظة: ${found.fileName} (${formatBytes(stat.size)})`,
                },
                `إرفاق نسخة الملف الأصلي (${found.fileName})`
              );
            } else if (stat.size > maxBytes) {
              await sendToRecipients({
                text: `ℹ️ حجم الملف الأصلي (${formatBytes(stat.size)}) يتجاوز الحد المسموح للإرفاق في البوت (${config.max_file_mb} MB) — الملف محفوظ بالكامل في أرشيف السيرفر.`,
              });
            }
          }
        }
        return;
      }

      // Security / Tamper / Auth Fail / Bypass alerts
      if (!f.notify_security_tamper) return;
      const devName = lookupDeviceDisplayName(deviceId, meta);
      const sevEmoji = severity === 'critical' || severity === 'high' ? '🚨' : '⚠️';
      const text =
        `${sevEmoji} *تنبيه أمان وتلاعب — IT ELKHAWGA*\n` +
        `━━━━━━━━━━━━━━\n` +
        `💻 *الجهاز:* ${devName}\n` +
        `📌 *الحدث:* ${message || type}\n` +
        `🕒 *الوقت:* ${formatCairoTime(Date.now())}`;
      const imgBuf = f.send_screenshot ? decodeBase64Buffer(screenshotB64) : null;
      if (imgBuf) {
        await sendToRecipients({ image: imgBuf, caption: text }, `إرسال تنبيه أمان مصوّر (${devName})`);
      } else {
        await sendToRecipients({ text }, `إرسال تنبيه أمان (${devName})`);
      }
    } catch (e) {
      pushLog(`تعذر إرسال إشعار واتساب: ${e && e.message}`, 'warn');
    }
  }

  async function onErpBackupEvent({ ok, fileName, sizeBytes, formatLabel, error, reason }) {
    try {
      if (!config.enabled || state !== 'connected') return;
      const f = config.features || {};
      if (ok) {
        if (!f.notify_erp_backup_ok) return;
        const text =
          `✅ *نجاح النسخة الاحتياطية لموقع الشركة*\n` +
          `━━━━━━━━━━━━━━\n` +
          `📦 *الملف:* ${fileName || 'ERP_Backup'}\n` +
          `💾 *الحجم:* ${formatBytes(sizeBytes || 0)}\n` +
          `🔍 *الفحص:* ${formatLabel || 'سليمة ✓'}\n` +
          `⚙️ *النوع:* ${String(reason || '').startsWith('auto') ? 'تلقائية دورية' : 'يدوية'}\n` +
          `🕒 *الوقت:* ${formatCairoTime(Date.now())}`;
        await sendToRecipients({ text }, 'إرسال إشعار نجاح النسخة الاحتياطية لموقع الشركة');
      } else {
        if (!f.notify_erp_backup_fail) return;
        const text =
          `🚨 *تنبيه: تعذر سحب النسخة الاحتياطية لموقع الشركة*\n` +
          `━━━━━━━━━━━━━━\n` +
          `❌ *السبب:* ${error || 'خطأ غير معروف'}\n` +
          `🕒 *الوقت:* ${formatCairoTime(Date.now())}`;
        await sendToRecipients({ text }, 'إرسال تنبيه فشل النسخة الاحتياطية لموقع الشركة', 'warn');
      }
    } catch (e) {
      pushLog(`خطأ في إشعار النسخ الاحتياطي: ${e && e.message}`, 'warn');
    }
  }

  async function onServerHealthEvent({ kind, downMinutes }) {
    try {
      if (!config.enabled || state !== 'connected') return;
      const f = config.features || {};
      if (!f.notify_server_health) return;
      if (kind === 'admin_down') {
        const text =
          `🚨 *تنبيه السيرفر الرئيسي — IT ELKHAWGA*\n` +
          `━━━━━━━━━━━━━━\n` +
          `⚠️ توقّف منفذ لوحة الإدارة المحلي (8787) عن الاستجابة.\n` +
          `🔄 يقوم المراقب الذاتي الآن بإعادة تشغيله تلقائياً...\n` +
          `🕒 ${formatCairoTime(Date.now())}`;
        await sendToRecipients({ text }, 'إرسال تنبيه توقف منفذ السيرفر (8787)', 'warn');
      } else if (kind === 'admin_recovered') {
        const text =
          `✅ *عاد السيرفر الرئيسي للعمل — IT ELKHAWGA*\n` +
          `━━━━━━━━━━━━━━\n` +
          `🟢 تمت إعادة تشغيل منفذ لوحة الإدارة (8787) تلقائياً بنجاح وعادت جميع الخدمات للعمل.\n` +
          `🕒 ${formatCairoTime(Date.now())}`;
        await sendToRecipients({ text }, 'إرسال إشعار عودة منفذ السيرفر (8787) للعمل');
      } else if (kind === 'host_recovered') {
        const text =
          `🔄 *إشعار عودة جهاز السيرفر بعد انقطاع*\n` +
          `━━━━━━━━━━━━━━\n` +
          `⚡ عاد جهاز السيرفر الرئيسي والإنترنت للعمل الآن بعد توقف دام حوالي *${downMinutes || 2} دقيقة*.\n` +
          `🕒 ${formatCairoTime(Date.now())}`;
        await sendToRecipients({ text }, 'إرسال إشعار عودة جهاز السيرفر بعد انقطاع الكهرباء/الإنترنت');
      }
    } catch (_) {}
  }

  async function onBiometricStatusEvent({ kind, device }) {
    try {
      if (!config.enabled || state !== 'connected' || !device) return;
      const f = config.features || {};
      if (f.notify_biometrics_offline === false) return;
      const vendorLabel = String(device.vendor || '').toLowerCase() === 'hikvision' ? 'Hikvision' : 'ZKTeco';
      const branchTxt = device.branch_name ? ` (${device.branch_name})` : '';
      if (kind === 'offline') {
        const text =
          `🔴 *تنبيه فصل جهاز بصمة — IT ELKHAWGA*\n` +
          `━━━━━━━━━━━━━━\n` +
          `👆 *جهاز البصمة:* ${device.name}${branchTxt}\n` +
          `🏷️ *النوع:* ${vendorLabel}\n` +
          `🌐 *العنوان:* \`${device.host}:${device.port}\`\n` +
          `⚠️ *الحالة:* غير متصل بالشبكة المحلية الآن!\n` +
          `🕒 *الوقت:* ${formatCairoTime(Date.now())}`;
        await sendToRecipients({ text }, `تنبيه انقطاع جهاز البصمة (${device.name})`, 'warn');
      } else if (kind === 'online') {
        const text =
          `🟢 *عودة اتصال جهاز بصمة — IT ELKHAWGA*\n` +
          `━━━━━━━━━━━━━━\n` +
          `👆 *جهاز البصمة:* ${device.name}${branchTxt}\n` +
          `🏷️ *النوع:* ${vendorLabel}\n` +
          `🌐 *العنوان:* \`${device.host}:${device.port}\`\n` +
          `⚡ *زمن الاستجابة:* ${device.latency_ms || 5} ms\n` +
          `🕒 *الوقت:* ${formatCairoTime(Date.now())}`;
        await sendToRecipients({ text }, `إشعار عودة اتصال جهاز البصمة (${device.name})`);
      }
    } catch (_) {}
  }

  async function getMergedDevices() {
    const byId = new Map();
    const nowMs = Date.now();
    try {
      const relayRows = db
        .prepare(
          'SELECT device_id, hostname, label, ip, blocked, last_seen, app_version, denied, rustdesk_id, rustdesk_password, group_id FROM devices ORDER BY last_seen DESC'
        )
        .all();
      for (const r of relayRows) {
        let denied = [];
        try { denied = JSON.parse(r.denied || '[]'); } catch (_) {}
        const online = Boolean(r.last_seen && nowMs - Number(r.last_seen) < 60_000);
        byId.set(r.device_id, {
          device_id: r.device_id,
          name: r.label || r.hostname || r.device_id,
          hostname: r.hostname || '',
          label: r.label || '',
          ip: r.ip || '',
          blocked: Boolean(r.blocked),
          online,
          last_seen: Number(r.last_seen || 0),
          rustdesk_id: r.rustdesk_id || '',
          rustdesk_password: r.rustdesk_password || '',
          group_id: r.group_id || '',
          transport: 'relay',
          has_relay: true,
          has_lan: false,
          denied: Array.isArray(denied) ? denied : [],
        });
      }
    } catch (_) {}

    const lanResp = await lanAdminRequest('GET', 'devices');
    if (lanResp && Array.isArray(lanResp.devices)) {
      for (const d of lanResp.devices) {
        if (!d || !d.device_id) continue;
        const prev = byId.get(d.device_id);
        const lanOnline = Boolean(d.online);
        const denied = Array.isArray(d.denied) ? d.denied : [];
        if (prev) {
          prev.has_lan = true;
          if (lanOnline) {
            prev.online = true;
            prev.transport = 'lan';
          }
          if (d.label && !prev.label) {
            prev.label = d.label;
            prev.name = d.label;
          }
          if (d.ip && (!prev.ip || lanOnline)) prev.ip = d.ip;
          if (d.rustdesk_id && !prev.rustdesk_id) prev.rustdesk_id = d.rustdesk_id;
          if (d.rustdesk_password && !prev.rustdesk_password) prev.rustdesk_password = d.rustdesk_password;
          if (d.group_id && !prev.group_id) prev.group_id = d.group_id;
          prev.blocked = Boolean(d.blocked || prev.blocked);
          prev.denied = Array.from(new Set([...(prev.denied || []), ...denied]));
        } else {
          byId.set(d.device_id, {
            device_id: d.device_id,
            name: d.label || d.hostname || d.device_id,
            hostname: d.hostname || '',
            label: d.label || '',
            ip: d.ip || '',
            blocked: Boolean(d.blocked),
            online: lanOnline,
            last_seen: Number(d.last_seen || 0),
            rustdesk_id: d.rustdesk_id || '',
            rustdesk_password: d.rustdesk_password || '',
            group_id: d.group_id || '',
            transport: 'lan',
            has_relay: false,
            has_lan: true,
            denied,
          });
        }
      }
    }
    return Array.from(byId.values());
  }

  async function buildExecutiveMorningBriefText({ pullFreshBiometrics = false } = {}) {
    const nowMs = Date.now();
    // 1. Devices status
    const devices = await getMergedDevices();
    const onlineDevs = devices.filter((d) => d.online);
    const blockedDevs = devices.filter((d) => d.blocked);
    const openDevs = Math.max(0, devices.length - blockedDevs.length);

    // 2. ERP Backup status (elkhawaga.uk)
    const erpSt = await lanAdminRequest('GET', 'erp-backups').catch(() => null);
    const lastErp = erpSt && Array.isArray(erpSt.backups) && erpSt.backups[0] ? erpSt.backups[0] : null;
    const erpLine = lastErp
      ? `🟢 محدثة — \`${lastErp.file_name}\` (${formatBytes(lastErp.size_bytes)})`
      : `⚪ لم يتم سحب نسخة بعد`;

    // 3. Dahua CCTV DVRs & HDD Health
    let cctvLines = ['⚪ لا توجد أجهزة DVR مضافة'];
    if (cctv) {
      const dvrs = (cctv.listDvrs().dvrs || []).filter((d) => d.enabled);
      if (dvrs.length) {
        const hAll = await cctv.checkAllDvrsHealth().catch(() => null);
        const hMap = new Map();
        if (hAll && Array.isArray(hAll.results)) {
          for (const r of hAll.results) hMap.set(r.dvr_id, r.health || {});
        }
        cctvLines = dvrs.map((d) => {
          const h = hMap.get(d.id) || {};
          const reachable = h.reachable !== false;
          const hddSt = h.hdd_status || 'ok';
          const hddLabel = hddSt === 'ok'
            ? `هارد سليم ✅${h.total_gb ? ` (${h.total_gb}GB)` : ''}`
            : (hddSt === 'error' ? '⚠️ عطل هارد!' : (hddSt === 'missing' ? '⚠️ بدون هارد!' : 'متصل'));
          return `   • ${reachable ? '🟢' : '🔴'} *${d.name}* (${d.channels_count || 8} كاميرا): ${reachable ? hddLabel : 'غير متصل'}`;
        });
      }
    }

    // 4. Biometrics devices & Today's Attendance
    let bioHeader = '⚪ لا توجد ماكينات بصمة مضافة';
    const bioDevLines = [];
    let bioAttendanceLines = [];
    if (bioManager) {
      if (pullFreshBiometrics) {
        await bioManager.pullAttendanceLogs({}).catch(() => {});
      }
      const bioSt = await bioManager.checkAllDevicesHealth(false).catch(() => bioManager.listDevices());
      const bioDevs = (bioSt && bioSt.devices) || [];
      const bioSum = (bioSt && bioSt.summary) || {};
      const attBrief = bioManager.getTodayAttendanceBrief ? bioManager.getTodayAttendanceBrief() : null;

      bioHeader = `🟢 متصل: *${bioSum.online_devices || 0}* من *${bioDevs.length}* ماكينة`;
      for (const bd of bioDevs) {
        const icon = bd.online ? '🟢' : '🔴';
        const vTag = bd.vendor === 'hikvision' ? 'Hikvision' : 'ZKTeco';
        bioDevLines.push(`   • ${icon} *${bd.name}* [${vTag}]: ${bd.online ? `متصل (${bd.latency_ms}ms)` : 'مفصول'}`);
      }
      if (attBrief) {
        bioAttendanceLines = [
          `   👥 *الحاضرون (${attBrief.active_day_label}):* *${attBrief.present_employees_count}* موظف (من إجمالي ${attBrief.total_registered_employees || '—'} مسجلين · ${attBrief.total_punches} حركة)`,
        ];
        if (attBrief.first_punch) {
          bioAttendanceLines.push(`   🌅 *أول حضور:* ${attBrief.first_punch.name} (#${attBrief.first_punch.id}) الساعة \`${attBrief.first_punch.time}\``);
        }
        if (attBrief.last_punch) {
          bioAttendanceLines.push(`   🕒 *آخر بصمة:* ${attBrief.last_punch.name} (#${attBrief.last_punch.id}) الساعة \`${attBrief.last_punch.time}\``);
        }
      }
    }

    // 5. DLP Archive & Security Alerts Today
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    let todayFiles = 0;
    let todayWaFiles = 0;
    let unackedAlerts = 0;
    try {
      todayFiles = db.prepare('SELECT COUNT(*) AS n FROM uploaded_files WHERE created_at >= ?').get(startOfDay.getTime()).n || 0;
      todayWaFiles = db.prepare("SELECT COUNT(*) AS n FROM uploaded_files WHERE created_at >= ? AND channel LIKE '%whatsapp%'").get(startOfDay.getTime()).n || 0;
      unackedAlerts = db.prepare('SELECT COUNT(*) AS n FROM alerts WHERE acked_at IS NULL').get().n || 0;
    } catch (_) {}

    const lines = [
      `☀️ *التقرير الصباحي الموحّد للإدارة العليا — IT ELKHAWGA*`,
      `━━━━━━━━━━━━━━━━━━━━`,
      `🖥️ *1. السيرفر الرئيسي وموقع الشركة (elkhawaga.uk):*`,
      `   • حالة السيرفر السحابي: 🟢 يعمل بكفاءة 100%`,
      `   • آخر نسخة احتياطية للموقع: ${erpLine}`,
      `━━━━━━━━━━━━━━━━━━━━`,
      `💻 *2. أجهزة الفروع والموظفين (${devices.length} جهاز):*`,
      `   • 🟢 متصل الآن: *${onlineDevs.length}* جهاز | ⚪ مغلق: *${devices.length - onlineDevs.length}*`,
      `   • 🔒 مقفول الإنترنت (Whitelist): *${blockedDevs.length}* | 🌐 مفتوح: *${openDevs}*`,
      `━━━━━━━━━━━━━━━━━━━━`,
      `🎥 *3. كاميرات الفروع (Dahua DVR) وهاردات التسجيل:*`,
      ...cctvLines,
      `━━━━━━━━━━━━━━━━━━━━`,
      `👆 *4. ماكينات البصمة والحضور والانصراف:*`,
      `   • حالة الماكينات: ${bioHeader}`,
      ...bioDevLines,
      ...bioAttendanceLines,
      `━━━━━━━━━━━━━━━━━━━━`,
      `🛡️ *5. أرشيف الملفات والتنبيهات الأمنية اليوم:*`,
      `   • 📂 ملفات مؤرشفة اليوم: *${todayFiles}* (منها *${todayWaFiles}* واتساب)`,
      `   • 🔔 تنبيهات غير مقروءة: *${unackedAlerts}*`,
      `━━━━━━━━━━━━━━━━━━━━`,
      `🕒 *التوقيت:* ${formatCairoTime(nowMs)}`,
      `💡 للاستعلام عن دوام أي موظف أرسل: *حضور <اسم الموظف>*`,
    ];
    return lines.join('\n');
  }

  function findMatchingDevice(devices, query) {
    const q = String(query || '').trim().toLowerCase();
    if (!q) return null;
    return (
      devices.find((d) => d.name.toLowerCase() === q || d.hostname.toLowerCase() === q || d.device_id.toLowerCase() === q || d.ip === q) ||
      devices.find((d) => d.name.toLowerCase().includes(q) || d.hostname.toLowerCase().includes(q))
    );
  }

  async function resolveJidPhoneDigits(jid) {
    const s = String(jid || '').trim();
    if (!s || s.endsWith('@g.us')) return '';
    const direct = extractDigitsFromJid(s);
    if (direct) return direct;
    if (!s.endsWith('@lid')) return '';
    const lidBase = ((s.split('@')[0] || '').split(':')[0] || '').replace(/[^\d]/g, '');
    if (!lidBase) return '';

    // 1. Check Baileys v7 lidMapping repository in memory if available
    try {
      const mapped = await sock?.signalRepository?.lidMapping?.getPNForLID?.(s);
      const d = extractDigitsFromJid(mapped || '');
      if (d) return d;
    } catch (_) {}

    // 2. Check persisted lid-mapping-<lid>_reverse.json in wa-bot-auth
    try {
      const revPath = path.join(authDir, `lid-mapping-${lidBase}_reverse.json`);
      if (fs.existsSync(revPath)) {
        const val = JSON.parse(fs.readFileSync(revPath, 'utf8'));
        const d = String(val || '').replace(/[^\d]/g, '');
        if (d) return d;
      }
    } catch (_) {}

    // 3. Check forward lid-mapping-<phone>.json for each configured recipient phone
    try {
      const allowedPhones = parseRecipientJids(config.recipients).map(extractDigitsFromJid).filter(Boolean);
      for (const ph of allowedPhones) {
        const fwdPath = path.join(authDir, `lid-mapping-${ph}.json`);
        if (fs.existsSync(fwdPath)) {
          const val = JSON.parse(fs.readFileSync(fwdPath, 'utf8'));
          if (String(val || '').replace(/[^\d]/g, '') === lidBase) {
            return ph;
          }
        }
      }
    } catch (_) {}

    return '';
  }

  async function isAuthorizedSender(msg) {
    const msgId = String(msg?.key?.id || '');
    if (msgId && sentByBotIds.has(msgId)) return false;

    const allowedJids = parseRecipientJids(config.recipients);
    if (!allowedJids.length) return false;
    const remoteJid = String(msg.key?.remoteJid || '');
    if (allowedJids.includes(remoteJid) && !msg.key?.fromMe) return true;

    const allowedPhones = new Set(allowedJids.map(extractDigitsFromJid).filter(Boolean));
    if (botPhone) allowedPhones.add(botPhone);

    const rawCandidates = [
      msg.key?.remoteJid,
      msg.key?.remoteJidAlt,
      msg.key?.participant,
      msg.key?.participantAlt,
      msg.key?.senderPn,
    ].filter(Boolean);

    for (const cand of rawCandidates) {
      const digits = await resolveJidPhoneDigits(cand);
      if (digits && allowedPhones.has(digits)) {
        // If fromMe, only allow if user typed a command to self or to an allowed recipient chat
        return true;
      }
    }
    return false;
  }

  function unwrapInnerMessage(m) {
    let cur = m;
    for (let depth = 0; depth < 5 && cur && typeof cur === 'object'; depth++) {
      if (cur.ephemeralMessage?.message) cur = cur.ephemeralMessage.message;
      else if (cur.viewOnceMessage?.message) cur = cur.viewOnceMessage.message;
      else if (cur.viewOnceMessageV2?.message) cur = cur.viewOnceMessageV2.message;
      else if (cur.documentWithCaptionMessage?.message) cur = cur.documentWithCaptionMessage.message;
      else if (cur.deviceSentMessage?.message) cur = cur.deviceSentMessage.message;
      else break;
    }
    return cur;
  }

  function extractMessageText(msg) {
    const m = unwrapInnerMessage(msg.message);
    if (!m) return '';
    return String(
      m.conversation ||
        m.extendedTextMessage?.text ||
        m.imageMessage?.caption ||
        m.documentMessage?.caption ||
        ''
    ).trim();
  }

  async function handleIncomingMessage(msg) {
    const msgId = String(msg?.key?.id || '');
    if (msgId) {
      if (sentByBotIds.has(msgId) || processedIncomingIds.has(msgId)) return;
      processedIncomingIds.add(msgId);
      if (processedIncomingIds.size > 500) {
        const oldest = processedIncomingIds.values().next().value;
        processedIncomingIds.delete(oldest);
      }
    }

    const text = extractMessageText(msg);
    if (!text || !config.enabled || state !== 'connected') return;

    const remoteJid = String(msg.key?.remoteJid || '');
    // Helper so admin can discover a WhatsApp Group ID easily when adding the bot to a group
    if (remoteJid.endsWith('@g.us') && (text === 'معرف الجروب' || text.toLowerCase() === 'groupid')) {
      pushLog(`معرف الجروب المستلم منه الطلب: ${remoteJid}`);
    }

    const authorized = await isAuthorizedSender(msg);
    if (!authorized) return;

    const f = config.features || {};
    const anyCmdEnabled =
      f.cmd_status ||
      f.cmd_screenshot ||
      f.cmd_camera ||
      f.cmd_cctv ||
      f.cmd_biometrics !== false ||
      f.cmd_block_unblock ||
      f.cmd_usb ||
      f.cmd_group_control ||
      f.cmd_sites ||
      f.cmd_daily_report ||
      f.cmd_recent_files ||
      f.cmd_rustdesk ||
      f.cmd_update_client ||
      f.cmd_power ||
      f.cmd_erp_backup;
    if (!anyCmdEnabled) return;

    // Expand custom admin shortcut aliases (e.g. "1 = حالة" or "كام اكتوبر = كاميرا October Sales-1")
    let rawCmd = text.replace(/\s+/g, ' ').trim();
    if (config.custom_aliases) {
      const aliasLines = String(config.custom_aliases).split(/\r?\n/);
      for (const ln of aliasLines) {
        const eqIdx = ln.indexOf('=');
        if (eqIdx > 0) {
          const k = ln.slice(0, eqIdx).trim();
          const v = ln.slice(eqIdx + 1).trim();
          if (k && v && rawCmd.toLowerCase() === k.toLowerCase()) {
            rawCmd = v.replace(/\s+/g, ' ').trim();
            break;
          }
        }
      }
    }

    const normalized = rawCmd;
    const lower = normalized.toLowerCase();

    const resolvedPhone = await resolveJidPhoneDigits(remoteJid);
    const reply = async (content) => {
      if (!sock || state !== 'connected') return;
      try {
        const sent = await sock.sendMessage(remoteJid, content);
        rememberSentMsg(sent);
      } catch (_) {
        if (resolvedPhone) {
          const sent2 = await sock.sendMessage(`${resolvedPhone}@s.whatsapp.net`, content);
          rememberSentMsg(sent2);
        }
      }
    };

    // 1. Help / Menu
    if (['مساعدة', 'المساعدة', 'اوامر', 'الأوامر', 'الاوامر', 'help', 'menu'].includes(lower)) {
      const cmds = ['🤖 *أوامر بوت IT ELKHAWGA المفعّلة حالياً:*', '━━━━━━━━━━━━━━'];
      if (f.cmd_status) cmds.push('• *حالة* أو *اجهزة* ⬅ عرض الفروع المتصلة والمنقطعة');
      if (f.cmd_daily_report) cmds.push('• *تقرير* أو *موجز* ⬅ التقرير الموحّد للإدارة (السيرفر + الأجهزة + الكاميرات + البصمات)');
      if (f.cmd_screenshot) cmds.push('• *صورة <اسم الجهاز>* ⬅ التقاط صورة شاشة فورية');
      if (f.cmd_camera) cmds.push('• *كاميرا <اسم الجهاز>* ⬅ التقاط صورة فورية من الكاميرا');
      if (f.cmd_cctv) {
        cmds.push('• *داهوا* ⬅ عرض قائمة الفروع والمخازن المربوطة');
        cmds.push('• *داهوا <اسم الفرع> <رقم الكاميرا>* ⬅ لقطة HD فورية من الـ DVR');
      }
      if (f.cmd_biometrics !== false) {
        cmds.push('• *بصمات* أو *حالة البصمات* ⬅ حالة اتصال أجهزة البصمة (ZK & Hikvision)');
        cmds.push('• *سحب البصمات* ⬅ سحب حركات الحضور والانصراف من جميع أجهزة البصمة فوراً');
        cmds.push('• *حضور <اسم الموظف أو الكود>* ⬅ مواعيد حضور وانصراف الموظف خلال الأسبوع');
      }
      if (f.cmd_block_unblock) {
        cmds.push('• *قفل <اسم الجهاز>* ⬅ حجب الإنترنت عن الجهاز');
        cmds.push('• *فتح <اسم الجهاز>* ⬅ فتح الإنترنت للجهاز');
      }
      if (f.cmd_usb) {
        cmds.push('• *قفل usb <اسم الجهاز>* / *فتح usb <اسم الجهاز>* ⬅ قفل/فتح الفلاشات');
      }
      if (f.cmd_group_control) {
        cmds.push('• *قفل مجموعة <الاسم>* / *فتح مجموعة <الاسم>*');
      }
      if (f.cmd_sites) {
        cmds.push('• *سماح <موقع>* / *حجب <موقع>* ⬅ تعديل المواقع فوراً');
      }
      if (f.cmd_recent_files) {
        cmds.push('• *ملفات* أو *ملفات <اسم الجهاز>* ⬅ آخر الملفات المسحوبة (+ *هات 1* لتحميله)');
      }
      if (f.cmd_rustdesk) cmds.push('• *راست <اسم الجهاز>* ⬅ إرسال كود وباسورد RustDesk');
      if (f.cmd_update_client) cmds.push('• *تحديث <اسم الجهاز>* أو *تحديث الكل*');
      if (f.cmd_power) cmds.push('• *ريستارت <اسم الجهاز>* / *ايقاف <اسم الجهاز>*');
      if (f.cmd_erp_backup) cmds.push('• *نسخة* أو *باكاب* ⬅ بدء سحب نسخة احتياطية لموقع الشركة');
      await reply({ text: cmds.join('\n') });
      return;
    }

    // 2. Status / Devices list
    if (['حالة', 'الحالة', 'اجهزة', 'أجهزة', 'الاجهزة', 'الأجهزة', 'status', 'devices'].includes(lower)) {
      if (!f.cmd_status) {
        await reply({ text: '⚠️ أمر استعلام الحالة متوقف حالياً من إعدادات بوت واتساب في لوحة التحكم.' });
        return;
      }
      const devices = await getMergedDevices();
      const online = devices.filter((d) => d.online);
      const offline = devices.filter((d) => !d.online);
      const lines = [
        `📊 *حالة أجهزة الفروع (${devices.length} جهاز)*`,
        `🟢 متصل الآن: *${online.length}* | ⚪ غير متصل: *${offline.length}*`,
        `━━━━━━━━━━━━━━`,
      ];
      for (const d of online.slice(0, 25)) {
        lines.push(`🟢 *${d.name}* ${d.blocked ? '🔒(مقفول)' : '🌐'}`);
      }
      for (const d of offline.slice(0, 15)) {
        lines.push(`⚪ ${d.name}`);
      }
      await reply({ text: lines.join('\n') });
      pushLog('تم الرد على أمر استعلام حالة الأجهزة عبر واتساب');
      return;
    }

    // 2b. Unified Executive Morning Brief / Daily Summary Report: "تقرير" / "ملخص" / "موجز" / "التقرير الصباحي"
    if (['تقرير', 'التقرير', 'تقرير اليوم', 'ملخص', 'ملخص اليوم', 'موجز', 'الموجز', 'التقرير الصباحي', 'تقرير الصباح', 'موجز الصباح', 'report', 'summary', 'brief', 'morning'].includes(lower)) {
      if (!f.cmd_daily_report && f.notify_morning_brief === false) {
        await reply({ text: '⚠️ أمر التقرير اليومي متوقف حالياً من إعدادات بوت واتساب في لوحة التحكم.' });
        return;
      }
      const briefText = await buildExecutiveMorningBriefText({ pullFreshBiometrics: false });
      await reply({ text: briefText });
      pushLog('تم إرسال التقرير الموحّد للإدارة العليا عبر واتساب');
      return;
    }

    // 3. Screenshot command: "صورة <device>" or "screen <device>"
    const scrMatch = normalized.match(/^(?:صورة|صوره|شاشة|لقطة|screen|shot)\s+(.+)$/i);
    if (scrMatch) {
      if (!f.cmd_screenshot) {
        await reply({ text: '⚠️ أمر طلب لقطة الشاشة متوقف حالياً من إعدادات بوت واتساب في لوحة التحكم.' });
        return;
      }
      const targetQuery = scrMatch[1].trim();
      const devices = await getMergedDevices();
      const target = findMatchingDevice(devices, targetQuery);
      if (!target) {
        await reply({ text: `❌ لم يتم العثور على جهاز يطابق: "${targetQuery}"` });
        return;
      }
      if (!target.online) {
        await reply({ text: `⚠️ الجهاز *${target.name}* غير متصل حالياً.` });
        return;
      }
      await reply({ text: `📸 جاري طلب لقطة شاشة حية من *${target.name}*...` });
      const reqStart = Date.now();
      if (target.has_relay) {
        try {
          db.prepare("UPDATE devices SET screen_requested=1, stream_mode='', stream_until=0 WHERE device_id=?").run(target.device_id);
          db.prepare("INSERT INTO screens(device_id,image,at,kind,error) VALUES(?, '', 0, 'screen', '') ON CONFLICT(device_id) DO UPDATE SET image='', at=0, kind='screen', error=''").run(target.device_id);
        } catch (_) {}
      }
      if (target.has_lan) {
        await lanAdminRequest('POST', `devices/${encodeURIComponent(target.device_id)}/screen/request`, { mode: 'once' });
      }

      let gotImage = '';
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 700));
        if (target.has_relay) {
          try {
            const row = db.prepare('SELECT image, at FROM screens WHERE device_id=?').get(target.device_id);
            if (row && row.image && Number(row.at || 0) >= reqStart - 2000) {
              gotImage = row.image;
              break;
            }
          } catch (_) {}
        }
        if (target.has_lan) {
          const lanSc = await lanAdminRequest('GET', `devices/${encodeURIComponent(target.device_id)}/screen`);
          if (lanSc && lanSc.image && Number(lanSc.at || 0) >= reqStart - 2000) {
            gotImage = lanSc.image;
            break;
          }
        }
      }

      const buf = decodeBase64Buffer(gotImage);
      if (buf) {
        await reply({
          image: buf,
          caption: `🖥 لقطة شاشة فورية — *${target.name}*\n🕒 ${formatCairoTime(Date.now())}`,
        });
        pushLog(`تم إرسال لقطة شاشة فورية للجهاز (${target.name}) بأمر واتساب`);
      } else {
        await reply({ text: `⚠️ لم يرد الجهاز *${target.name}* بلقطة الشاشة في الوقت المحدد (قد تكون الشاشة مغلقة أو في وضع السكون).` });
      }
      return;
    }

    // 3b. Webcam Photo command: "كاميرا <device>" or "camera <device>"
    const camMatch = normalized.match(/^(?:كاميرا|كاميرا ويب|كام|camera|webcam|cam)\s+(.+)$/i);
    if (camMatch) {
      if (!f.cmd_camera) {
        await reply({ text: '⚠️ أمر التقاط صورة الكاميرا متوقف حالياً من إعدادات بوت واتساب في لوحة التحكم — قم بتفعيل مفتاح «أمر التقاط صورة من كاميرا الويب» أولاً.' });
        return;
      }
      const targetQuery = camMatch[1].trim();
      const devices = await getMergedDevices();
      const target = findMatchingDevice(devices, targetQuery);
      if (!target) {
        await reply({ text: `❌ لم يتم العثور على جهاز يطابق: "${targetQuery}"` });
        return;
      }
      if (!target.online) {
        await reply({ text: `⚠️ الجهاز *${target.name}* غير متصل حالياً.` });
        return;
      }
      await reply({ text: `📷 جاري التقاط صورة فورية من كاميرا الويب للجهاز *${target.name}*...` });
      const reqStart = Date.now();
      const untilMs = Date.now() + 14_000;
      if (target.has_relay) {
        try {
          db.prepare("INSERT INTO screens(device_id,image,at,kind,error) VALUES(?, '', 0, 'camera', '') ON CONFLICT(device_id) DO UPDATE SET image='', at=0, kind='camera', error=''").run(target.device_id);
          db.prepare("UPDATE devices SET screen_requested=1, stream_mode='camera', stream_until=? WHERE device_id=?").run(untilMs, target.device_id);
        } catch (_) {}
      }
      if (target.has_lan) {
        await lanAdminRequest('POST', `devices/${encodeURIComponent(target.device_id)}/screen/request`, { mode: 'camera' });
      }

      let gotCamImg = '';
      let gotCamErr = '';
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 700));
        if (target.has_relay) {
          try {
            const row = db.prepare('SELECT image, at, kind, error FROM screens WHERE device_id=?').get(target.device_id);
            if (row && row.kind === 'camera') {
              if (row.image && Number(row.at || 0) >= reqStart - 2000) {
                gotCamImg = row.image;
                break;
              }
              if (row.error && Number(row.at || 0) >= reqStart - 2000) {
                gotCamErr = row.error;
                break;
              }
            }
          } catch (_) {}
        }
        if (target.has_lan) {
          const lanSc = await lanAdminRequest('GET', `devices/${encodeURIComponent(target.device_id)}/screen`);
          if (lanSc && lanSc.kind === 'camera') {
            if (lanSc.image && Number(lanSc.at || 0) >= reqStart - 2000) {
              gotCamImg = lanSc.image;
              break;
            }
            if (lanSc.error && Number(lanSc.at || 0) >= reqStart - 2000) {
              gotCamErr = lanSc.error;
              break;
            }
          }
        }
      }

      // Stop camera stream lease immediately after grabbing the single photo
      if (target.has_relay) {
        try { db.prepare("UPDATE devices SET screen_requested=0, stream_mode='', stream_until=0 WHERE device_id=?").run(target.device_id); } catch (_) {}
      }
      if (target.has_lan) {
        lanAdminRequest('POST', `devices/${encodeURIComponent(target.device_id)}/screen/request`, { mode: 'stop' }).catch(() => {});
      }

      const camBuf = decodeBase64Buffer(gotCamImg);
      if (camBuf) {
        await reply({
          image: camBuf,
          caption: `📷 لقطة كاميرا ويب فورية — *${target.name}*\n🕒 ${formatCairoTime(Date.now())}`,
        });
        pushLog(`تم إرسال صورة كاميرا للجهاز (${target.name}) بأمر واتساب`);
      } else if (gotCamErr) {
        await reply({ text: `📷 لا توجد كاميرا ويب متصلة حالياً بالجهاز *${target.name}* (أو الكاميرا مشغولة من برنامج آخر).` });
      } else {
        await reply({ text: `⚠️ لم يرد الجهاز *${target.name}* بصورة كاميرا (تأكد أن الجهاز يحتوي على كاميرا ويب متصلة).` });
      }
      return;
    }

    // 3b2. Dahua CCTV DVR Snapshot / Tour / Health commands
    const cctvTourMatch = ['جولة', 'جوله', 'جولة كاميرات', 'جولة مخازن', 'جولة فروع', 'tour'].includes(lower);
    const cctvHealthMatch = ['صحة الكاميرات', 'فحص الكاميرات', 'هاردات', 'هاردات الكاميرات', 'cctv health'].includes(lower);
    const cctvListMatch = ['داهوا', 'كاميرات', 'الكاميرات', 'مخازن', 'المخازن', 'dvr', 'cctv'].includes(lower);
    const cctvSnapMatch = (!cctvListMatch && !cctvTourMatch && !cctvHealthMatch)
      ? normalized.match(/^(?:داهوا|مخزن|فرع|dvr|cctv)\s+(.+?)(?:\s+(\d{1,2}))?$/i)
      : null;
    if (cctvListMatch || cctvSnapMatch || cctvTourMatch || cctvHealthMatch) {
      if (!f.cmd_cctv) {
        await reply({ text: '⚠️ أوامر كاميرات المراقبة (Dahua DVR) عبر واتساب متوقفة حالياً من إعدادات البوت.' });
        return;
      }
      if (!cctv) {
        await reply({ text: '⚠️ خدمة الكاميرات غير مهيأة حالياً.' });
        return;
      }
      const allDvrs = (cctv.listDvrs().dvrs || []).filter((d) => d.enabled);
      if (!allDvrs.length) {
        await reply({ text: '🎥 لم تتم إضافة أي جهاز Dahua DVR بعد — افتح تبويب «🎥 كاميرات الفروع» لإضافة الفروع والمخازن.' });
        return;
      }
      if (cctvHealthMatch) {
        await reply({ text: `🛡️ جاري فحص صحة أجهزة الـ DVR وهاردات التسجيل في *${allDvrs.length}* فرع...` });
        const hRes = await cctv.checkAllDvrsHealth();
        const lines = ['🛡️ *تقرير صحة أجهزة الـ DVR وهاردات التسجيل:*', '━━━━━━━━━━━━━━'];
        for (const item of hRes.results || []) {
          if (!item.ok) {
            lines.push(`🔴 *${item.name}:* ${item.error}`);
          } else {
            const h = item.health || {};
            const hddIcon = h.hdd_status === 'ok' ? '🟢 هارد سليم' : (h.hdd_status === 'error' ? '🚨 عطل بالهارد!' : '⚠️ لا يوجد هارد مكتشف');
            const capTxt = h.total_gb > 0 ? ` (${h.free_gb} GB متاح من ${h.total_gb} GB)` : '';
            const offTxt = h.offline_channels && h.offline_channels.length ? ` · قنوات مفصولة: [${h.offline_channels.join(', ')}]` : '';
            lines.push(`• *${item.name}:* ${hddIcon}${capTxt}${offTxt}`);
          }
        }
        await reply({ text: lines.join('\n') });
        return;
      }
      if (cctvTourMatch) {
        await reply({ text: `🌐 بدء جولة مصوّرة سريعة على *${allDvrs.length}* فرع ومخزن...` });
        const favs = (cctv.getSettings().favorites || []);
        for (const d of allDvrs) {
          const favForDvr = favs.find((x) => x.dvr_id === d.id);
          const ch = favForDvr ? Number(favForDvr.channel || 1) : 1;
          try {
            const frame = await cctv.getFrame({ dvrId: d.id, channel: ch, hd: true, waitMs: 8500 });
            const chTitle = (d.channel_names && d.channel_names[String(ch)]) || `كاميرا ${ch}`;
            await reply({
              image: frame.buf,
              caption: `🏢 *${d.name}* — ${chTitle}\n🕒 ${formatCairoTime(frame.at)}`,
            });
          } catch (e) {
            await reply({ text: `⚠️ *${d.name}:* تعذر سحب اللقطة (${(e && e.message) || 'غير متصل'})` });
          }
        }
        pushLog('إتمام جولة كاميرات الفروع عبر واتساب');
        return;
      }
      if (cctvListMatch) {
        const lines = ['🎥 *فروع ومخازن كاميرات Dahua المسجلة:*', '━━━━━━━━━━━━━━'];
        allDvrs.forEach((d, idx) => {
          lines.push(`*${idx + 1}.* ${d.name} (${d.channels_count} كاميرا — ${d.connection_mode === 'bridge' ? 'جسر الفرع' : 'ربط مباشر'})`);
        });
        lines.push('━━━━━━━━━━━━━━');
        lines.push('💡 الأوامر المتاحة:\n• *داهوا ' + allDvrs[0].name + ' 1* ⬅ لقطة HD فورية\n• *جولة* ⬅ لقطات حية لكل الفروع\n• *هاردات* ⬅ فحص صحة هاردات التسجيل');
        await reply({ text: lines.join('\n') });
        return;
      }
      const qBranch = cctvSnapMatch[1].trim().toLowerCase();
      const chNum = Math.max(1, Math.min(64, parseInt(cctvSnapMatch[2] || '1', 10) || 1));
      const matchedDvr =
        allDvrs.find((d) => d.name.toLowerCase() === qBranch) ||
        allDvrs.find((d) => d.name.toLowerCase().includes(qBranch));
      if (!matchedDvr) {
        await reply({ text: `❌ لم يتم العثور على فرع أو مخزن يطابق: "${cctvSnapMatch[1].trim()}" — أرسل كلمة *داهوا* لعرض القائمة.` });
        return;
      }
      await reply({ text: `🎥 جاري سحب لقطة HD حية من *${matchedDvr.name}* — كاميرا *${chNum}*...` });
      try {
        const frame = await cctv.getFrame({ dvrId: matchedDvr.id, channel: chNum, hd: true, waitMs: 7500 });
        const chTitle = (matchedDvr.channel_names && matchedDvr.channel_names[String(chNum)]) || `كاميرا ${chNum}`;
        await reply({
          image: frame.buf,
          caption: `🎥 *${matchedDvr.name}* — ${chTitle}\n🕒 ${formatCairoTime(frame.at)}`,
        });
        pushLog(`إرسال لقطة كاميرا Dahua (${matchedDvr.name} - كاميرا ${chNum}) عبر واتساب`);
      } catch (e) {
        await reply({ text: `⚠️ تعذر سحب صورة الكاميرا: ${(e && e.message) || 'تأكد من اتصال الفرع والـ DVR'}` });
      }
      return;
    }

    // 3b3. Biometrics Attendance Devices Status & Pull Logs commands ("بصمات" / "حالة البصمات" / "سحب البصمات")
    const bioStatusMatch = ['بصمات', 'البصمات', 'بصمة', 'البصمة', 'حالة البصمات', 'حاله البصمات', 'اجهزة البصمة', 'أجهزة البصمة', 'biometrics'].includes(lower);
    const bioPullMatch = ['سحب البصمات', 'سحب بصمات', 'سحب الحضور', 'تحديث البصمات', 'pull biometrics'].includes(lower)
      ? { all: true, query: '' }
      : (normalized.match(/^(?:سحب بصمة|سحب بصمات)\s+(.+)$/i)
        ? { all: false, query: normalized.replace(/^(?:سحب بصمة|سحب بصمات)\s+/i, '').trim() }
        : null);

    if (bioStatusMatch || bioPullMatch) {
      if (f.cmd_biometrics === false) {
        await reply({ text: '⚠️ أوامر أجهزة البصمة عبر واتساب متوقفة حالياً من إعدادات البوت.' });
        return;
      }
      if (!bioManager) {
        await reply({ text: '⚠️ خدمة أجهزة البصمة غير مهيأة حالياً.' });
        return;
      }
      if (bioStatusMatch) {
        const st = await bioManager.checkAllDevicesHealth(false);
        const devs = st.devices || [];
        if (!devs.length) {
          await reply({ text: '👆 لم تتم إضافة أي جهاز بصمة بعد — افتح تبويب «👆 أجهزة البصمة» في لوحة الإدارة لإضافة أجهزة ZKTeco و Hikvision.' });
          return;
        }
        const sum = st.summary || {};
        const lines = [
          `👆 *حالة أجهزة البصمة والحضور (${devs.length} جهاز)*`,
          `🟢 متصل: *${sum.online_devices || 0}* | 🔴 غير متصل: *${sum.offline_devices || 0}*`,
          `📊 إجمالي الحركات المسحوبة: *${sum.total_logs || 0}* (اليوم: *${sum.today_logs || 0}*)`,
          `━━━━━━━━━━━━━━`,
        ];
        for (const d of devs) {
          const icon = d.online ? '🟢' : '🔴';
          const vTag = d.vendor === 'hikvision' ? 'Hikvision' : 'ZKTeco';
          const brTxt = d.branch_name ? ` (${d.branch_name})` : '';
          const stateTxt = d.online ? `متصل (${d.latency_ms}ms)` : `مفصول (${d.last_error || 'غير متصل'})`;
          lines.push(`${icon} *${d.name}*${brTxt} [${vTag}]\n   🌐 \`${d.host}:${d.port}\` — ${stateTxt}`);
        }
        lines.push(`━━━━━━━━━━━━━━`);
        lines.push(`💡 لسحب حركات البصمة الآن أرسل: *سحب البصمات*`);
        await reply({ text: lines.join('\n') });
        pushLog('تم الرد على استعلام حالة أجهزة البصمة عبر واتساب');
        return;
      }

      if (bioPullMatch) {
        const list = (bioManager.listDevices().devices || []);
        if (!list.length) {
          await reply({ text: '👆 لا توجد أجهزة بصمة مضافة بعد.' });
          return;
        }
        let targetId = '';
        if (!bioPullMatch.all && bioPullMatch.query) {
          const q = bioPullMatch.query.toLowerCase();
          const matched = list.find((d) => d.name.toLowerCase().includes(q) || (d.branch_name || '').toLowerCase().includes(q) || d.host === q);
          if (!matched) {
            await reply({ text: `❌ لم يتم العثور على جهاز بصمة يطابق: "${bioPullMatch.query}"` });
            return;
          }
          targetId = matched.id;
        }
        await reply({ text: `⏳ جاري الاتصال بأجهزة البصمة على الشبكة المحلية وسحب سجلات الحضور والانصراف...` });
        try {
          const pullRes = await bioManager.pullAttendanceLogs({ deviceId: targetId });
          const lines = [
            `✅ *اكتمل سحب سجلات البصمة بنجاح*`,
            `📥 إجمالي الحركات المقروءة: *${pullRes.total_pulled || 0}*`,
            `🆕 حركات جديدة حُفظت بالسيرفر: *${pullRes.new_inserted || 0}*`,
            `━━━━━━━━━━━━━━`,
          ];
          for (const r of pullRes.results || []) {
            if (r.ok) {
              lines.push(`🟢 *${r.name}:* تم سحب ${r.pulled_count} حركة (${r.new_count} جديدة · إجمالي مخزن ${r.total_stored})`);
            } else {
              lines.push(`🔴 *${r.name}:* تعذر السحب (${r.error})`);
            }
          }
          await reply({ text: lines.join('\n') });
          pushLog('تم سحب سجلات البصمات بأمر واتساب');
        } catch (err) {
          await reply({ text: `⚠️ تعذر سحب البصمات: ${(err && err.message) || err}` });
        }
        return;
      }
    }

    // 3b4. Employee Attendance Lookup by Name or Code ("حضور <اسم الموظف>" / "بصمة <اسم الموظف>" / "دوام <اسم الموظف>")
    const empAttMatch = normalized.match(/^(?:حضور|انصراف|دوام|مواعيد|بصمة موظف|بصمه موظف|بصمة|بصمه)\s+(.+)$/i);
    if (empAttMatch) {
      if (f.cmd_biometrics === false) {
        await reply({ text: '⚠️ أوامر أجهزة البصمة عبر واتساب متوقفة حالياً من إعدادات البوت.' });
        return;
      }
      if (!bioManager || typeof bioManager.searchEmployeeWeeklyAttendance !== 'function') {
        await reply({ text: '⚠️ خدمة البحث في سجلات البصمة غير مهيأة حالياً.' });
        return;
      }
      const empQuery = empAttMatch[1].trim();
      const res = bioManager.searchEmployeeWeeklyAttendance(empQuery, 7);
      if (!res || !res.ok) {
        await reply({ text: `⚠️ ${(res && res.error) || 'تعذر البحث عن الموظف'}` });
        return;
      }
      if (!res.found || !Array.isArray(res.employees) || !res.employees.length) {
        await reply({
          text:
            `❌ لم يتم العثور على موظف يطابق: *"${empQuery}"*\n` +
            `💡 يمكنك البحث بالاسم بالعربية أو الإنجليزية أو بكود البصمة (مثال: *حضور كرم* أو *حضور ميلاد* أو *حضور 22*).\n` +
            `ولسحب أحدث البصمات من الماكينات أرسل: *سحب البصمات*`,
        });
        return;
      }

      const dayNameAr = (ymd) => {
        try {
          const dt = new Date(`${ymd}T12:00:00`);
          return dt.toLocaleDateString('ar-EG', { weekday: 'long' });
        } catch (_) {
          return '';
        }
      };

      const lines = [
        `👆 *تقرير حضور وانصراف الموظف (آخر 7 أيام عمل)*`,
        `🔎 البحث: *"${empQuery}"*${res.total_matched > 1 ? ` (مطابق لـ ${res.total_matched} موظفين)` : ''}`,
      ];

      for (const emp of res.employees) {
        lines.push(`━━━━━━━━━━━━━━━━━━━━`);
        lines.push(`👤 *${emp.employee_name || `موظف #${emp.employee_id}`}* (كود: \`${emp.employee_id}\`)`);
        lines.push(`🏢 ${emp.branch_name || 'المقر الرئيسي'} — ${emp.device_name || 'ماكينة البصمة'}`);
        if (!emp.days || !emp.days.length) {
          lines.push(`⚪ لا توجد حركات بصمة مسجلة لهذا الموظف في السجل المسحوب حالياً.`);
          continue;
        }
        lines.push(`📅 *أيام الحضور المسجلة (${emp.days.length} أيام · إجمالي ${emp.total_punches} بصمة):*`);
        for (const d of emp.days) {
          const wDay = dayNameAr(d.day);
          const dayLabel = wDay ? `${wDay} ${d.day}` : d.day;
          if (d.check_out) {
            lines.push(`   • *${dayLabel}:*\n     🟢 حضور: \`${d.check_in}\` ⬅ 🔴 انصراف: \`${d.check_out}\` (⏱ ${d.duration_text})`);
          } else {
            lines.push(`   • *${dayLabel}:* 🕒 بصمة الساعة \`${d.check_in}\`${d.punches_count > 1 ? ` (${d.punches_count} حركات: ${d.all_times.join(' ، ')})` : ''}`);
          }
        }
      }
      await reply({ text: lines.join('\n') });
      pushLog(`تم الرد على استعلام حضور الموظف (${empQuery}) عبر واتساب`);
      return;
    }

    // 3c. USB Storage Lock / Unlock command (single device or group): "قفل usb <device>" / "فتح usb <device>" / "قفل فلاشة <device>"
    const usbMatch = normalized.match(/^(قفل|حظر|فتح|فك)\s+(?:usb|يو اس بي|فلاشة|فلاشه|فلاشات)\s+(.+)$/i);
    if (usbMatch) {
      if (!f.cmd_usb) {
        await reply({ text: '⚠️ أوامر قفل وفتح منافذ USB عبر واتساب متوقفة حالياً من إعدادات البوت.' });
        return;
      }
      const verb = usbMatch[1].toLowerCase();
      const cmdType = ['قفل', 'حظر'].includes(verb) ? 'usb_block' : 'usb_unblock';
      const rest = usbMatch[2].trim();
      const grpSub = rest.match(/^(?:مجموعة|مجموعه|جروب|فرع)\s+(.+)$/i);
      if (grpSub) {
        const gq = grpSub[1].trim().toLowerCase();
        let matchedGrp = null;
        try {
          const rows = db.prepare('SELECT id, name FROM groups').all();
          matchedGrp = rows.find((g) => String(g.name || '').toLowerCase() === gq) ||
            rows.find((g) => String(g.name || '').toLowerCase().includes(gq));
        } catch (_) {}
        if (!matchedGrp) {
          await reply({ text: `❌ لم يتم العثور على مجموعة تطابق: "${grpSub[1].trim()}"` });
          return;
        }
        let count = 0;
        try {
          const targets = db.prepare('SELECT device_id FROM devices WHERE group_id=?').all(matchedGrp.id);
          const ins = db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)');
          const clr = db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL');
          const upd = db.prepare('UPDATE devices SET usb_blocked=? WHERE device_id=?');
          for (const t of targets) {
            clr.run(t.device_id);
            ins.run('cmd_' + Date.now() + '_' + count, t.device_id, cmdType, Date.now());
            upd.run(cmdType === 'usb_block' ? 1 : 0, t.device_id);
            count++;
          }
        } catch (_) {}
        await lanAdminRequest('POST', `groups/${encodeURIComponent(matchedGrp.id)}/command`, {
          command: cmdType,
          actor: 'whatsapp_bot',
          actor_role: 'super',
        });
        await reply({
          text: cmdType === 'usb_block'
            ? `🔌 تم إرسال أمر *قفل منافذ تخزين USB* لمجموعة *${matchedGrp.name}* (${count} جهاز)`
            : `🔓 تم إرسال أمر *فتح منافذ تخزين USB* لمجموعة *${matchedGrp.name}* (${count} جهاز)`,
        });
        pushLog(`تنفيذ أمر (${cmdType}) للمجموعة (${matchedGrp.name}) عبر واتساب`);
        return;
      }

      const devices = await getMergedDevices();
      const target = findMatchingDevice(devices, rest);
      if (!target) {
        await reply({ text: `❌ لم يتم العثور على جهاز يطابق: "${rest}"` });
        return;
      }
      if (target.has_relay) {
        try {
          db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL').run(target.device_id);
          db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)').run(
            'cmd_' + Date.now(),
            target.device_id,
            cmdType,
            Date.now()
          );
          db.prepare('UPDATE devices SET usb_blocked=? WHERE device_id=?').run(cmdType === 'usb_block' ? 1 : 0, target.device_id);
        } catch (_) {}
      }
      if (target.has_lan) {
        await lanAdminRequest('POST', `devices/${encodeURIComponent(target.device_id)}/command`, {
          command: cmdType,
          actor: 'whatsapp_bot',
        });
      }
      await reply({
        text: cmdType === 'usb_block'
          ? `🔌 تم إرسال أمر *قفل منافذ تخزين USB والفلاشات* للجهاز: *${target.name}*`
          : `🔓 تم إرسال أمر *فتح منافذ تخزين USB والفلاشات* للجهاز: *${target.name}*`,
      });
      pushLog(`تنفيذ أمر (${cmdType}) للجهاز (${target.name}) عبر واتساب`);
      return;
    }

    // 4a. Group Block / Unblock: "قفل مجموعة <name>" / "فتح مجموعة <name>"
    const grpMatch = normalized.match(/^(قفل|حظر|فتح|فك)\s+(?:مجموعة|مجموعه|جروب|فرع)\s+(.+)$/i);
    if (grpMatch) {
      if (!f.cmd_group_control) {
        await reply({ text: '⚠️ أوامر التحكم في المجموعات متوقفة حالياً من إعدادات بوت واتساب.' });
        return;
      }
      const verb = grpMatch[1].toLowerCase();
      const cmdType = ['قفل', 'حظر'].includes(verb) ? 'block' : 'unblock';
      const grpQuery = grpMatch[2].trim().toLowerCase();
      let matchedGrp = null;
      try {
        const rows = db.prepare('SELECT id, name FROM groups').all();
        matchedGrp = rows.find((g) => String(g.name || '').toLowerCase() === grpQuery) ||
          rows.find((g) => String(g.name || '').toLowerCase().includes(grpQuery));
      } catch (_) {}
      if (!matchedGrp) {
        await reply({ text: `❌ لم يتم العثور على مجموعة تطابق: "${grpMatch[2].trim()}"` });
        return;
      }
      let count = 0;
      try {
        const targets = db.prepare('SELECT device_id FROM devices WHERE group_id=?').all(matchedGrp.id);
        const ins = db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)');
        const clr = db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL');
        const upd = db.prepare('UPDATE devices SET blocked=? WHERE device_id=?');
        for (const t of targets) {
          clr.run(t.device_id);
          ins.run('cmd_' + Date.now() + '_' + count, t.device_id, cmdType, Date.now());
          upd.run(cmdType === 'block' ? 1 : 0, t.device_id);
          count++;
        }
      } catch (_) {}
      await lanAdminRequest('POST', `groups/${encodeURIComponent(matchedGrp.id)}/command`, {
        command: cmdType,
        actor: 'whatsapp_bot',
        actor_role: 'super',
      });
      await reply({
        text:
          cmdType === 'block'
            ? `🔒 تم إرسال أمر *قفل الإنترنت* لمجموعة *${matchedGrp.name}* (${count} جهاز مرتبط)`
            : `🌐 تم إرسال أمر *فتح الإنترنت* لمجموعة *${matchedGrp.name}* (${count} جهاز مرتبط)`,
      });
      pushLog(`تنفيذ أمر (${cmdType}) للمجموعة (${matchedGrp.name}) عبر واتساب`);
      return;
    }

    // 4b. Site Allow / Block command: "سماح <domain>" / "حجب <domain>"
    const siteMatch = normalized.match(/^(سماح|حجب|منع|allow)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\/.*)?$/i);
    if (siteMatch) {
      if (!f.cmd_sites) {
        await reply({ text: '⚠️ أوامر إضافة وحجب المواقع عبر واتساب متوقفة حالياً من إعدادات البوت.' });
        return;
      }
      const isAllow = ['سماح', 'allow'].includes(siteMatch[1].toLowerCase());
      const domain = siteMatch[2].trim().toLowerCase().replace(/^www\./, '');
      try {
        const dataRoot = 'C:/ProgramData/InternetBlocker';
        const targetFile = path.join(dataRoot, isAllow ? 'allowed.txt' : 'blocked.txt');
        const otherFile = path.join(dataRoot, isAllow ? 'blocked.txt' : 'allowed.txt');
        const readLines = (p) =>
          fs.existsSync(p)
            ? fs.readFileSync(p, 'utf8').split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean)
            : [];
        const listA = Array.from(new Set([...readLines(targetFile), domain]));
        const listB = readLines(otherFile).filter((d) => d !== domain);
        fs.writeFileSync(targetFile, listA.join('\n') + '\n', 'utf8');
        fs.writeFileSync(otherFile, listB.join('\n') + (listB.length ? '\n' : ''), 'utf8');

        // Sync Relay global policy version immediately so remote branches apply within 3 seconds
        const polRow = db.prepare('SELECT data FROM policy WHERE id=1').get();
        if (polRow && polRow.data) {
          const pData = JSON.parse(polRow.data);
          pData.allowed = isAllow ? listA : listB;
          pData.blocked = isAllow ? listB : listA;
          db.prepare('UPDATE policy SET version=?, data=?, updated_at=? WHERE id=1').run(
            'pv_' + Date.now(),
            JSON.stringify(pData),
            Date.now()
          );
        }
        await reply({
          text: isAllow
            ? `✅ تمت إضافة الموقع *${domain}* إلى قائمة المواقع المسموحة ومزامنته مع الفروع.`
            : `🚫 تمت إضافة الموقع *${domain}* إلى قائمة المواقع المحجوبة ومزامنته مع الفروع.`,
        });
        pushLog(`${isAllow ? 'سماح' : 'حجب'} موقع (${domain}) بأمر واتساب`);
      } catch (e) {
        await reply({ text: `⚠️ تعذر تحديث قائمة المواقع: ${e && e.message}` });
      }
      return;
    }

    // 4c. Recent Archived Files & Fetch by index: "ملفات [device]" + "هات <1..5>"
    const fetchFileMatch = normalized.match(/^(?:هات|ارسل|أرسل|ملف|تحميل)\s+(\d{1,2})$/i);
    if (fetchFileMatch) {
      if (!f.cmd_recent_files) {
        await reply({ text: '⚠️ أمر استعراض وسحب ملفات الأرشيف متوقف حالياً من إعدادات البوت.' });
        return;
      }
      const idx = parseInt(fetchFileMatch[1], 10) - 1;
      const item = lastListedFiles[idx];
      if (!item || !item.stored_path || !fs.existsSync(item.stored_path)) {
        await reply({ text: '⚠️ رقم الملف غير موجود — أرسل كلمة *ملفات* أولاً لعرض أحدث الملفات المرقّمة.' });
        return;
      }
      const stat = fs.statSync(item.stored_path);
      const maxBytes = (Number(config.max_file_mb) || 25) * 1024 * 1024;
      if (stat.size > maxBytes) {
        await reply({ text: `⚠️ حجم الملف (${formatBytes(stat.size)}) أكبر من الحد المسموح (${config.max_file_mb} MB).` });
        return;
      }
      await reply({
        document: fs.readFileSync(item.stored_path),
        fileName: item.file_name || 'file.bin',
        mimetype: guessMime(item.file_name),
        caption: `📎 *${item.file_name}*\n💻 الجهاز: ${item.device_name || '—'}\n🕒 ${formatCairoTime(item.created_at)}`,
      });
      pushLog(`إرسال ملف من الأرشيف (${item.file_name}) بأمر واتساب`);
      return;
    }

    const recentFilesMatch = normalized.match(/^(?:ملفات|اخر ملفات|آخر ملفات|الارشيف|الأرشيف|files)(?:\s+(.+))?$/i);
    if (recentFilesMatch) {
      if (!f.cmd_recent_files) {
        await reply({ text: '⚠️ أمر استعراض ملفات الأرشيف متوقف حالياً من إعدادات البوت.' });
        return;
      }
      const devQ = (recentFilesMatch[1] || '').trim().toLowerCase();
      let rows = [];
      try {
        rows = db
          .prepare('SELECT file_name, file_size, stored_path, device_name, recipient_name, created_at FROM uploaded_files ORDER BY created_at DESC LIMIT 60')
          .all();
      } catch (_) {}
      if (devQ) {
        rows = rows.filter((r) => String(r.device_name || '').toLowerCase().includes(devQ));
      }
      const top5 = rows.filter((r) => r.stored_path && fs.existsSync(r.stored_path)).slice(0, 5);
      lastListedFiles = top5;
      if (!top5.length) {
        await reply({ text: '📂 لا توجد ملفات مطابقة في الأرشيف حالياً.' });
        return;
      }
      const lines = ['📂 *أحدث الملفات المحفوظة في الأرشيف:*', '━━━━━━━━━━━━━━'];
      top5.forEach((fItem, i) => {
        lines.push(`*${i + 1}.* ${fItem.file_name} (${formatBytes(fItem.file_size)})\n   💻 ${fItem.device_name || '—'}${fItem.recipient_name ? ' ⬅ ' + fItem.recipient_name : ''}`);
      });
      lines.push('━━━━━━━━━━━━━━');
      lines.push('💡 لتحميل أي ملف في المحادثة أرسل: *هات 1* أو *هات 2*');
      await reply({ text: lines.join('\n') });
      pushLog('عرض أحدث ملفات الأرشيف بأمر واتساب');
      return;
    }

    // 4d. RustDesk Info command: "راست <device>" / "دعم <device>"
    const rdMatch = normalized.match(/^(?:راست|دعم|rustdesk|rd)\s+(.+)$/i);
    if (rdMatch) {
      if (!f.cmd_rustdesk) {
        await reply({ text: '⚠️ أمر استعلام بيانات RustDesk متوقف حالياً من إعدادات البوت.' });
        return;
      }
      const devices = await getMergedDevices();
      const target = findMatchingDevice(devices, rdMatch[1].trim());
      if (!target) {
        await reply({ text: `❌ لم يتم العثور على جهاز يطابق: "${rdMatch[1].trim()}"` });
        return;
      }
      const rdId = target.rustdesk_id || 'غير مسجل بعد';
      const rdPass = target.rustdesk_password || 'KH2027kh';
      await reply({
        text:
          `🖥️ *بيانات اتصال RustDesk — ${target.name}*\n` +
          `━━━━━━━━━━━━━━\n` +
          `• *الحالة:* ${target.online ? '🟢 متصل الآن' : '⚪ غير متصل'}\n` +
          `• *RustDesk ID:* \`${rdId}\`\n` +
          `• *كلمة المرور:* \`${rdPass}\`\n` +
          (target.ip ? `• *IP:* \`${target.ip}\`` : ''),
      });
      pushLog(`إرسال بيانات RustDesk للجهاز (${target.name}) عبر واتساب`);
      return;
    }

    // 4e. Client Remote Update command: "تحديث <device | الكل>"
    const updMatch = normalized.match(/^(?:تحديث|ترقية|update)\s+(.+)$/i);
    if (updMatch) {
      if (!f.cmd_update_client) {
        await reply({ text: '⚠️ أمر تحديث الأجهزة عن بُعد متوقف حالياً من إعدادات البوت.' });
        return;
      }
      const q = updMatch[1].trim();
      const isAll = ['الكل', 'جميع الاجهزة', 'جميع الأجهزة', 'all'].includes(q.toLowerCase());
      if (isAll) {
        let count = 0;
        try {
          const allDevs = db.prepare('SELECT device_id FROM devices').all();
          const ins = db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)');
          for (const d of allDevs) {
            ins.run('cmd_' + Date.now() + '_' + count, d.device_id, 'update_client', Date.now());
            count++;
          }
        } catch (_) {}
        await lanAdminRequest('POST', 'devices/*/command', { command: 'update_client', actor: 'whatsapp_bot' });
        await reply({ text: `⬆️ تم إرسال أمر التحديث الصامت لجميع الأجهزة المسجلة (${count} جهاز).` });
        pushLog('إرسال أمر تحديث جماعي للأجهزة عبر واتساب');
        return;
      }
      const devices = await getMergedDevices();
      const target = findMatchingDevice(devices, q);
      if (!target) {
        await reply({ text: `❌ لم يتم العثور على جهاز يطابق: "${q}"` });
        return;
      }
      if (target.has_relay) {
        try {
          db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)').run(
            'cmd_' + Date.now(),
            target.device_id,
            'update_client',
            Date.now()
          );
        } catch (_) {}
      }
      if (target.has_lan) {
        await lanAdminRequest('POST', `devices/${encodeURIComponent(target.device_id)}/command`, {
          command: 'update_client',
          actor: 'whatsapp_bot',
        });
      }
      await reply({ text: `⬆️ تم إرسال أمر التحديث الصامت للجهاز: *${target.name}*` });
      pushLog(`إرسال أمر تحديث للجهاز (${target.name}) عبر واتساب`);
      return;
    }

    // 4f. Power Control command: "ريستارت <device>" / "ايقاف <device>" / "الغاء ايقاف <device>"
    const pwrMatch = normalized.match(/^(ريستارت|اعادة تشغيل|إعادة تشغيل|ايقاف تشغيل|إيقاف تشغيل|ايقاف|إيقاف|الغاء ايقاف|إلغاء إيقاف|restart|shutdown)\s+(.+)$/i);
    if (pwrMatch) {
      if (!f.cmd_power) {
        await reply({ text: '⚠️ أوامر إعادة التشغيل وإيقاف التشغيل عن بُعد متوقفة حالياً من إعدادات البوت.' });
        return;
      }
      const v = pwrMatch[1].toLowerCase();
      const cmdType = v.includes('الغاء') || v.includes('إلغاء')
        ? 'cancel_power'
        : v.includes('ريستارت') || v.includes('تشغيل') && v.includes('عاد') || v === 'restart'
        ? 'restart'
        : 'shutdown';
      const devices = await getMergedDevices();
      const target = findMatchingDevice(devices, pwrMatch[2].trim());
      if (!target) {
        await reply({ text: `❌ لم يتم العثور على جهاز يطابق: "${pwrMatch[2].trim()}"` });
        return;
      }
      if (target.has_relay) {
        try {
          db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL').run(target.device_id);
          db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)').run(
            'cmd_' + Date.now(),
            target.device_id,
            cmdType,
            Date.now()
          );
        } catch (_) {}
      }
      if (target.has_lan) {
        await lanAdminRequest('POST', `devices/${encodeURIComponent(target.device_id)}/command`, {
          command: cmdType,
          actor: 'whatsapp_bot',
        });
      }
      const labelAr = cmdType === 'restart' ? 'إعادة التشغيل' : cmdType === 'cancel_power' ? 'إلغاء الإيقاف' : 'إيقاف التشغيل';
      await reply({ text: `⚡ تم إرسال أمر *${labelAr}* للجهاز: *${target.name}*` });
      pushLog(`تنفيذ أمر الطاقة (${cmdType}) للجهاز (${target.name}) عبر واتساب`);
      return;
    }

    // 4g. Single Device Block / Unblock: "قفل <device>" / "فتح <device>"
    const blkMatch = normalized.match(/^(قفل|حظر|فتح|فك|block|unblock)\s+(.+)$/i);
    if (blkMatch) {
      if (!f.cmd_block_unblock) {
        await reply({ text: '⚠️ أوامر قفل وفتح الإنترنت عن بُعد متوقفة حالياً من إعدادات بوت واتساب.' });
        return;
      }
      const verb = blkMatch[1].toLowerCase();
      const cmdType = ['قفل', 'حظر', 'block'].includes(verb) ? 'block' : 'unblock';
      const targetQuery = blkMatch[2].trim();
      const devices = await getMergedDevices();
      const target = findMatchingDevice(devices, targetQuery);
      if (!target) {
        await reply({ text: `❌ لم يتم العثور على جهاز يطابق: "${targetQuery}"` });
        return;
      }
      if (target.has_relay) {
        try {
          db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL').run(target.device_id);
          db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)').run(
            'cmd_' + Date.now(),
            target.device_id,
            cmdType,
            Date.now()
          );
          db.prepare('UPDATE devices SET blocked=? WHERE device_id=?').run(cmdType === 'block' ? 1 : 0, target.device_id);
        } catch (_) {}
      }
      if (target.has_lan) {
        await lanAdminRequest('POST', `devices/${encodeURIComponent(target.device_id)}/command`, {
          command: cmdType,
          actor: 'whatsapp_bot',
        });
      }
      await reply({
        text:
          cmdType === 'block'
            ? `🔒 تم إرسال أمر *قفل الإنترنت* للجهاز: *${target.name}*`
            : `🌐 تم إرسال أمر *فتح الإنترنت* للجهاز: *${target.name}*`,
      });
      pushLog(`تنفيذ أمر (${cmdType}) للجهاز (${target.name}) عبر واتساب`);
      return;
    }

    // 5. ERP Backup command
    if (['نسخة', 'نسخه', 'باكاب', 'نسخة احتياطية', 'backup'].includes(lower)) {
      if (!f.cmd_erp_backup) {
        await reply({ text: '⚠️ أمر سحب النسخة الاحتياطية عبر واتساب متوقف حالياً من إعدادات البوت.' });
        return;
      }
      const res = await lanAdminRequest('POST', 'erp-backups/run', { reason: 'whatsapp_bot' });
      if (res && (res.ok || res.success)) {
        await reply({ text: '⏳ بدأ السيرفر الآن سحب وفحص نسخة احتياطية جديدة من موقع الشركة `elkhawaga.uk`...' });
        pushLog('تم بدء سحب نسخة احتياطية لموقع الشركة بأمر واتساب');
      } else {
        await reply({ text: `⚠️ تعذر بدء النسخة الاحتياطية: ${(res && res.error) || 'تأكد من إعدادات النسخ الاحتياطي'}` });
      }
      return;
    }

    // Polite feedback in direct chat when an authorized admin sends an unrecognized command
    if (!remoteJid.endsWith('@g.us') && normalized.length <= 60) {
      await reply({
        text: `ℹ️ لم أتعرف على الأمر: *"${normalized}"*\nأرسل كلمة *مساعدة* لعرض جميع الأوامر المتاحة والمفعّلة حالياً.`,
      });
    }
  }

  // Periodic background watcher for Device Offline/Online & Blocked Site Attempts (runs only when enabled)
  async function periodicMonitorTick() {
    try {
      const devices = await getMergedDevices();
      const nowMs = Date.now();
      const f = config.features || {};

      // Seed initial state on first run so restarting the server never floods historic events
      if (!baselineSeeded) {
        baselineSeeded = true;
        for (const d of devices) {
          deviceOnlineTracker.set(d.device_id, {
            online: d.online,
            offlineSince: d.online ? 0 : nowMs,
            alertedOffline: !d.online,
            name: d.name,
          });
          for (const host of d.denied || []) {
            seenBlockedPairs.set(`${d.device_id}|${host}`, nowMs);
          }
        }
        return;
      }

      const canSend = config.enabled && state === 'connected' && parseRecipientJids(config.recipients).length > 0;

      // 1. Device Offline / Online notifications
      for (const d of devices) {
        const prev = deviceOnlineTracker.get(d.device_id);
        if (!prev) {
          deviceOnlineTracker.set(d.device_id, {
            online: d.online,
            offlineSince: d.online ? 0 : nowMs,
            alertedOffline: false,
            name: d.name,
          });
          continue;
        }
        prev.name = d.name;
        if (d.online) {
          if (prev.alertedOffline && canSend && f.notify_device_offline) {
            await sendToRecipients(
              { text: `🟢 *عاد للاتصال:* الجهاز *${d.name}* متصل الآن بالسيرفر.\n🕒 ${formatCairoTime(nowMs)}` },
              `إشعار عودة اتصال (${d.name})`
            );
          }
          prev.online = true;
          prev.offlineSince = 0;
          prev.alertedOffline = false;
        } else {
          if (prev.online) {
            prev.online = false;
            prev.offlineSince = nowMs;
          } else if (!prev.alertedOffline && prev.offlineSince > 0 && nowMs - prev.offlineSince >= 180_000) {
            prev.alertedOffline = true;
            if (canSend && f.notify_device_offline) {
              await sendToRecipients(
                { text: `🔴 *انقطاع اتصال جهاز:* الجهاز *${d.name}* غير متصل منذ أكثر من 3 دقائق.\n🕒 ${formatCairoTime(nowMs)}` },
                `إشعار انقطاع اتصال (${d.name})`
              );
            }
          }
        }
      }

      // 2. Blocked site attempt notifications
      for (const d of devices) {
        for (const host of d.denied || []) {
          const key = `${d.device_id}|${host}`;
          if (!seenBlockedPairs.has(key)) {
            seenBlockedPairs.set(key, nowMs);
            if (canSend && f.notify_blocked_sites) {
              await sendToRecipients(
                {
                  text:
                    `🚫 *محاولة فتح موقع محظور*\n` +
                    `━━━━━━━━━━━━━━\n` +
                    `💻 *الجهاز:* ${d.name}\n` +
                    `🌐 *الموقع:* ${host}\n` +
                    `🕒 *الوقت:* ${formatCairoTime(nowMs)}`,
                },
                `إشعار موقع محظور (${d.name} -> ${host})`
              );
            }
          }
        }
      }
      if (seenBlockedPairs.size > 2000) {
        const entries = Array.from(seenBlockedPairs.entries()).sort((a, b) => b[1] - a[1]).slice(0, 1000);
        seenBlockedPairs.clear();
        for (const [k, v] of entries) seenBlockedPairs.set(k, v);
      }

      // 3. Scheduled CCTV Opening/Closing Visual Tour & 30-min DVR HDD Health Alert
      if (canSend && cctv) {
        if (f.notify_cctv_schedule) {
          const cairoNow = new Date(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
          const hhmm = `${String(cairoNow.getHours()).padStart(2, '0')}:${String(cairoNow.getMinutes()).padStart(2, '0')}`;
          const dayKey = `${cairoNow.getFullYear()}-${cairoNow.getMonth() + 1}-${cairoNow.getDate()}|${hhmm}`;
          const cSet = cctv.getSettings();
          if ((hhmm === cSet.schedule_morning || hhmm === cSet.schedule_evening) && globalThis.__lastCctvSchedSlot !== dayKey) {
            globalThis.__lastCctvSchedSlot = dayKey;
            const slotLabel = hhmm === cSet.schedule_morning ? 'تقرير فتح الفروع والمخازن الصباحي' : 'تقرير إغلاق وتأمين الفروع المسائي';
            const dvrs = (cctv.listDvrs().dvrs || []).filter((d) => d.enabled);
            if (dvrs.length) {
              await sendToRecipients({ text: `🕘 *${slotLabel}* (${hhmm}) — جاري إرسال لقطات الفروع...` });
              for (const d of dvrs) {
                try {
                  const frame = await cctv.getFrame({ dvrId: d.id, channel: 1, hd: true, waitMs: 8500 });
                  await sendToRecipients({
                    image: frame.buf,
                    caption: `🏢 *${d.name}* — ${slotLabel}\n🕒 ${formatCairoTime(frame.at)}`,
                  });
                } catch (_) {}
              }
            }
          }
        }

        if (f.notify_cctv_health && (!globalThis.__lastCctvHealthTick || nowMs - globalThis.__lastCctvHealthTick >= 30 * 60_000)) {
          globalThis.__lastCctvHealthTick = nowMs;
          const hAll = await cctv.checkAllDvrsHealth().catch(() => null);
          if (hAll && Array.isArray(hAll.results)) {
            for (const item of hAll.results) {
              const st = item.health && item.health.hdd_status;
              const alertKey = `${item.dvr_id}|${st}`;
              if ((st === 'error' || st === 'missing') && globalThis.__lastHddAlertKey !== alertKey) {
                globalThis.__lastHddAlertKey = alertKey;
                await sendToRecipients({
                  text:
                    `🚨 *تحذير هارد كاميرات المراقبة — ${item.name}*\n` +
                    `━━━━━━━━━━━━━━\n` +
                    `⚠️ ${st === 'error' ? 'تم رصد عطل في هارد التسجيل داخل جهاز الـ DVR!' : 'لا يوجد هارد تسجيل نشط داخل جهاز الـ DVR!'}\n` +
                    `🕒 ${formatCairoTime(nowMs)}`,
                }, `تنبيه عطل هارد DVR (${item.name})`, 'warn');
              }
            }
          }
        }
      }

      // 4. Scheduled Executive Morning Brief (10:30 AM Cairo Time daily)
      if (canSend && f.notify_morning_brief !== false) {
        const cairoNow = new Date(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
        const hhmm = `${String(cairoNow.getHours()).padStart(2, '0')}:${String(cairoNow.getMinutes()).padStart(2, '0')}`;
        const briefDayKey = `${cairoNow.getFullYear()}-${cairoNow.getMonth() + 1}-${cairoNow.getDate()}`;
        if (hhmm === '10:30' && globalThis.__lastExecutiveMorningBriefDay !== briefDayKey) {
          globalThis.__lastExecutiveMorningBriefDay = briefDayKey;
          const briefText = await buildExecutiveMorningBriefText({ pullFreshBiometrics: true });
          await sendToRecipients({ text: briefText }, 'إرسال التقرير الصباحي الموحّد للإدارة العليا (10:30 ص)');
        }
      }
    } catch (_) {}
  }

  setInterval(() => {
    periodicMonitorTick().catch(() => {});
  }, 25_000);
  setTimeout(() => {
    periodicMonitorTick().catch(() => {});
  }, 5000);

  // Auto-resume saved WhatsApp session on server boot if paired previously
  if (hasSavedSession() && config.auto_connect !== false) {
    setTimeout(() => {
      startSocket().catch(() => {});
    }, 1500);
  }

  return {
    getStatus,
    saveConfig,
    connect,
    disconnect,
    sendTestMessage,
    onAlert,
    onErpBackupEvent,
    onServerHealthEvent,
    onBiometricStatusEvent,
    setBiometricsManager,
  };
}
