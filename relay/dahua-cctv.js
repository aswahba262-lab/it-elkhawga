import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';

const dvrHttpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 48,
  keepAliveMsecs: 15000,
});

function rid(prefix = '') {
  return prefix + crypto.randomUUID().replace(/-/g, '');
}

function md5Hex(str) {
  return crypto.createHash('md5').update(str, 'utf8').digest('hex');
}

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function parseDigestHeader(wwwAuth) {
  const s = String(wwwAuth || '').trim();
  if (!/^digest\s+/i.test(s)) return null;
  const body = s.replace(/^digest\s+/i, '');
  const out = {};
  const re = /([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    out[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : m[3];
  }
  return out.nonce ? out : null;
}

function buildDigestAuthorization({ method, uri, username, password, challenge, ncNum }) {
  const algRaw = String(challenge.algorithm || 'MD5').toUpperCase();
  const isSha256 = algRaw.startsWith('SHA-256');
  const H = isSha256 ? sha256Hex : md5Hex;
  const realm = challenge.realm || '';
  const nonce = challenge.nonce || '';
  const opaque = challenge.opaque;
  const qopRaw = String(challenge.qop || '');
  const qopTokens = qopRaw.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const useAuthQop = qopTokens.includes('auth');
  const cnonce = crypto.randomBytes(8).toString('hex');
  const ncHex = String(ncNum || 1).padStart(8, '0');

  let ha1 = H(`${username}:${realm}:${password}`);
  if (algRaw.endsWith('-SESS')) {
    ha1 = H(`${ha1}:${nonce}:${cnonce}`);
  }
  const ha2 = H(`${method}:${uri}`);
  const response = useAuthQop
    ? H(`${ha1}:${nonce}:${ncHex}:${cnonce}:auth:${ha2}`)
    : H(`${ha1}:${nonce}:${ha2}`);

  const parts = [
    `username="${username}"`,
    `realm="${realm}"`,
    `nonce="${nonce}"`,
    `uri="${uri}"`,
    `response="${response}"`,
  ];
  if (challenge.algorithm) parts.push(`algorithm=${challenge.algorithm}`);
  if (opaque !== undefined) parts.push(`opaque="${opaque}"`);
  if (useAuthQop) {
    parts.push('qop=auth');
    parts.push(`nc=${ncHex}`);
    parts.push(`cnonce="${cnonce}"`);
  }
  return `Digest ${parts.join(', ')}`;
}

function rawHttpGet({ host, port, pathWithQuery, headers = {}, timeoutMs = 6000 }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: host,
        port: Number(port || 80),
        path: pathWithQuery,
        method: 'GET',
        headers: {
          Connection: 'keep-alive',
          Accept: '*/*',
          'User-Agent': 'IT-ELKHAWGA-CCTV/1.0',
          ...headers,
        },
        agent: dvrHttpAgent,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        let total = 0;
        res.on('data', (c) => {
          total += c.length;
          if (total <= 12 * 1024 * 1024) chunks.push(c);
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers || {},
            body: Buffer.concat(chunks),
          });
        });
      }
    );
    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy(new Error('انتهت مهلة الاتصال بالـ DVR'));
    });
    req.end();
  });
}

export function createDahuaCctvManager({ db }) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS cctv_dvrs (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      connection_mode TEXT NOT NULL DEFAULT 'direct',
      bridge_device_id TEXT DEFAULT '',
      host TEXT NOT NULL,
      http_port INTEGER NOT NULL DEFAULT 80,
      rtsp_port INTEGER NOT NULL DEFAULT 554,
      username TEXT NOT NULL DEFAULT 'admin',
      password TEXT NOT NULL DEFAULT '',
      channels_count INTEGER NOT NULL DEFAULT 8,
      channel_names TEXT DEFAULT '{}',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cctv_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      super_only INTEGER NOT NULL DEFAULT 0
    );
    INSERT OR IGNORE INTO cctv_settings(id, super_only) VALUES (1, 0);
  `);

  // Safe schema migrations for v1.1.0+ enterprise CCTV & Live Audio features
  for (const sql of [
    "ALTER TABLE cctv_dvrs ADD COLUMN hidden_channels TEXT DEFAULT '[]'",
    "ALTER TABLE cctv_dvrs ADD COLUMN allowed_admins TEXT DEFAULT ''",
    "ALTER TABLE cctv_dvrs ADD COLUMN health_json TEXT DEFAULT '{}'",
    "ALTER TABLE cctv_dvrs ADD COLUMN audio_channels TEXT DEFAULT ''",
    "ALTER TABLE cctv_settings ADD COLUMN favorites_json TEXT DEFAULT '[]'",
    "ALTER TABLE cctv_settings ADD COLUMN auto_hide_empty INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE cctv_settings ADD COLUMN schedule_morning TEXT DEFAULT '10:00'",
    "ALTER TABLE cctv_settings ADD COLUMN schedule_evening TEXT DEFAULT '22:00'",
  ]) {
    try { db.exec(sql); } catch (_) {}
  }

  // Precomputed ITU-T G.711 A-law & Mu-law -> 16-bit PCM lookup tables (for coaxial/analog Dahua mics)
  const ALAW_TO_PCM16 = new Int16Array(256);
  const ULAW_TO_PCM16 = new Int16Array(256);
  for (let i = 0; i < 256; i++) {
    let a = i ^ 0x55;
    let t = (a & 0x0f) << 4;
    const seg = (a & 0x70) >> 4;
    if (seg === 0) t += 8;
    else if (seg === 1) t += 0x108;
    else { t += 0x108; t <<= (seg - 1); }
    ALAW_TO_PCM16[i] = (a & 0x80) ? t : -t;

    let u = ~i & 0xff;
    const uExp = (u & 0x70) >> 4;
    let uMan = ((u & 0x0f) << 3) + 0x84;
    uMan <<= uExp;
    ULAW_TO_PCM16[i] = (u & 0x80) ? (0x84 - uMan) : (uMan - 0x84);
  }
  const ADTS_SAMPLE_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350];

  // Digest challenge cache per "host:port:username" -> { challenge, nc }
  const digestCache = new Map();

  // Active bridge leases per bridge_device_id -> Map<leaseKey, { dvrId, channel, hd, until }>
  const bridgeLeases = new Map();
  // Active live audio lease per dvrId -> { dvrId, bridgeDeviceId, channel, until }
  const audioLeases = new Map();
  // Live audio ring-buffers per `${dvrId}:${channel}` -> { seq, adtsCarry, chunks, error, errorAt, fallbackInflight }
  const audioStreams = new Map();
  // Direct-mode persistent audio HTTP requests per `${dvrId}:${channel}` -> ClientRequest
  const directAudioReqs = new Map();
  // Remote branch Dahua LAN scan requests: device_id -> { requestedAt, until, result }
  const branchScanJobs = new Map();
  // Remote branch on-demand Dahua CGI jobs: jobId -> { deviceId, jobPayload, until, resolve, reject }
  const branchCgiJobs = new Map();

  // Latest frames cached in memory: key = `${dvrId}:${channel}:${hd ? 1 : 0}` -> { buf, mime, at, error }
  const frameCache = new Map();
  // Temporary cooldown for unplugged/offline channels so bridge PCs never stall on empty BNC/IP slots
  const deadChannelUntil = new Map();
  // Deduplicate concurrent identical direct & bridge fetches
  const inflightDirect = new Map();
  const inflightBridge = new Map();

  function getSettings() {
    const row = db.prepare('SELECT * FROM cctv_settings WHERE id=1').get() || {};
    let favorites = [];
    try { favorites = JSON.parse(row.favorites_json || '[]') || []; } catch (_) {}
    if (!Array.isArray(favorites)) favorites = [];
    return {
      super_only: Boolean(row.super_only),
      auto_hide_empty: row.auto_hide_empty === undefined ? true : Boolean(row.auto_hide_empty),
      schedule_morning: String(row.schedule_morning || '10:00'),
      schedule_evening: String(row.schedule_evening || '22:00'),
      favorites,
    };
  }

  function setSettings(patch = {}) {
    const cur = getSettings();
    const superOnly = patch.super_only !== undefined ? Boolean(patch.super_only) : cur.super_only;
    const autoHide = patch.auto_hide_empty !== undefined ? Boolean(patch.auto_hide_empty) : cur.auto_hide_empty;
    const morn = typeof patch.schedule_morning === 'string' && /^\d{2}:\d{2}$/.test(patch.schedule_morning.trim())
      ? patch.schedule_morning.trim()
      : cur.schedule_morning;
    const eve = typeof patch.schedule_evening === 'string' && /^\d{2}:\d{2}$/.test(patch.schedule_evening.trim())
      ? patch.schedule_evening.trim()
      : cur.schedule_evening;
    const favs = Array.isArray(patch.favorites) ? patch.favorites.slice(0, 32) : cur.favorites;
    db.prepare(`UPDATE cctv_settings
      SET super_only=?, auto_hide_empty=?, schedule_morning=?, schedule_evening=?, favorites_json=?
      WHERE id=1`).run(
      superOnly ? 1 : 0,
      autoHide ? 1 : 0,
      morn,
      eve,
      JSON.stringify(favs)
    );
    return getSettings();
  }

  function getAutoDeadChannelsList(dvrId) {
    const out = [];
    const prefix = `${dvrId}:`;
    const nowMs = Date.now();
    for (const [k, info] of deadChannelUntil.entries()) {
      if (k.startsWith(prefix) && info && info.until > nowMs) {
        const ch = parseInt(k.slice(prefix.length), 10);
        if (ch > 0) out.push(ch);
      }
    }
    return out;
  }

  function sanitizeDvrForClient(row, bridgeDevicesMap) {
    let channelNames = {};
    let hiddenChannels = [];
    let audioChannels = [];
    const audioScanned = typeof row.audio_channels === 'string' && row.audio_channels.trim().startsWith('[');
    let health = {};
    try { channelNames = JSON.parse(row.channel_names || '{}') || {}; } catch (_) {}
    try { hiddenChannels = JSON.parse(row.hidden_channels || '[]') || []; } catch (_) {}
    try { if (audioScanned) audioChannels = JSON.parse(row.audio_channels) || []; } catch (_) {}
    try { health = JSON.parse(row.health_json || '{}') || {}; } catch (_) {}
    if (!Array.isArray(hiddenChannels)) hiddenChannels = [];
    if (!Array.isArray(audioChannels)) audioChannels = [];
    const bName = row.bridge_device_id && bridgeDevicesMap ? (bridgeDevicesMap.get(row.bridge_device_id) || '') : '';
    return {
      id: row.id,
      name: row.name,
      connection_mode: row.connection_mode || 'direct',
      bridge_device_id: row.bridge_device_id || '',
      bridge_device_name: bName,
      host: row.host,
      http_port: Number(row.http_port || 80),
      rtsp_port: Number(row.rtsp_port || 554),
      username: row.username || 'admin',
      has_password: Boolean(row.password && row.password.length > 0),
      channels_count: Math.max(1, Math.min(64, Number(row.channels_count || 8))),
      channel_names: channelNames,
      hidden_channels: hiddenChannels,
      audio_channels: audioChannels,
      audio_scanned: audioScanned,
      dead_channels: getAutoDeadChannelsList(row.id),
      allowed_admins: String(row.allowed_admins || ''),
      health,
      enabled: Boolean(row.enabled),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  function canAdminAccessDvr(row, actor, role) {
    const r = String(role || 'super').toLowerCase();
    if (!actor || r === 'super') return true;
    const rawAllowed = String(row.allowed_admins || '').trim();
    if (!rawAllowed) return true;
    const allowedSet = rawAllowed
      .split(/[\s,;،]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (!allowedSet.length) return true;
    return allowedSet.includes(String(actor).trim().toLowerCase());
  }

  function listDvrs(opts = {}) {
    const actor = opts && opts.actor ? String(opts.actor) : '';
    const role = opts && opts.role ? String(opts.role) : 'super';
    const devRows = db.prepare('SELECT device_id, label, hostname FROM devices').all();
    const bridgeMap = new Map(devRows.map((d) => [d.device_id, d.label || d.hostname || d.device_id]));
    const rows = db.prepare('SELECT * FROM cctv_dvrs ORDER BY created_at ASC').all();
    const visible = rows.filter((r) => canAdminAccessDvr(r, actor, role));
    return {
      ok: true,
      settings: getSettings(),
      dvrs: visible.map((r) => sanitizeDvrForClient(r, bridgeMap)),
    };
  }

  function getRawDvr(id) {
    if (!id) return null;
    return db.prepare('SELECT * FROM cctv_dvrs WHERE id=?').get(String(id)) || null;
  }

  function saveDvr(payload) {
    const id = String(payload.id || '').trim() || rid('dvr_');
    const existing = getRawDvr(id);
    const name = String(payload.name || '').trim().slice(0, 100);
    if (!name) throw new Error('يرجى إدخال اسم الفرع أو المخزن');
    const mode = payload.connection_mode === 'bridge' ? 'bridge' : 'direct';
    const bridgeDeviceId = mode === 'bridge' ? String(payload.bridge_device_id || '').trim() : '';
    if (mode === 'bridge' && !bridgeDeviceId) {
      throw new Error('يرجى اختيار جهاز الكمبيوتر الوسيط في الفرع عند استخدام وضع الربط عبر جسر الفرع');
    }
    let host = String(payload.host || '').trim().replace(/^https?:\/\//i, '').split('/')[0] || '';
    if (host.includes(':')) {
      host = host.split(':')[0];
    }
    if (!host) throw new Error('يرجى إدخال عنوان IP الخاص بجهاز Dahua DVR (مثل 192.168.1.108)');
    const httpPort = Math.max(1, Math.min(65535, Number(payload.http_port || 80) || 80));
    const rtspPort = Math.max(1, Math.min(65535, Number(payload.rtsp_port || 554) || 554));
    const username = String(payload.username || 'admin').trim().slice(0, 64) || 'admin';
    const suppliedPass = typeof payload.password === 'string' ? payload.password : '';
    const password = suppliedPass !== '' ? suppliedPass : (existing ? existing.password : '');
    const channelsCount = Math.max(1, Math.min(64, Number(payload.channels_count || 8) || 8));
    let channelNamesObj = {};
    if (payload.channel_names && typeof payload.channel_names === 'object') {
      channelNamesObj = payload.channel_names;
    } else if (existing && existing.channel_names) {
      try { channelNamesObj = JSON.parse(existing.channel_names) || {}; } catch (_) {}
    }
    let hiddenArr = [];
    if (Array.isArray(payload.hidden_channels)) {
      hiddenArr = payload.hidden_channels.map((n) => parseInt(n, 10)).filter((n) => n > 0 && n <= 64);
    } else if (existing && existing.hidden_channels) {
      try { hiddenArr = JSON.parse(existing.hidden_channels) || []; } catch (_) {}
    }
    const allowedAdmins = payload.allowed_admins !== undefined
      ? String(payload.allowed_admins || '').trim().slice(0, 300)
      : (existing ? String(existing.allowed_admins || '') : '');
    const enabled = payload.enabled === undefined ? 1 : (payload.enabled ? 1 : 0);
    const ts = Date.now();

    if (existing) {
      db.prepare(`UPDATE cctv_dvrs SET
        name=?, connection_mode=?, bridge_device_id=?, host=?, http_port=?, rtsp_port=?,
        username=?, password=?, channels_count=?, channel_names=?, hidden_channels=?, allowed_admins=?, enabled=?, updated_at=?
        WHERE id=?`).run(
        name, mode, bridgeDeviceId, host, httpPort, rtspPort,
        username, password, channelsCount, JSON.stringify(channelNamesObj), JSON.stringify(hiddenArr), allowedAdmins, enabled, ts, id
      );
    } else {
      db.prepare(`INSERT INTO cctv_dvrs
        (id, name, connection_mode, bridge_device_id, host, http_port, rtsp_port, username, password, channels_count, channel_names, hidden_channels, allowed_admins, enabled, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        id, name, mode, bridgeDeviceId, host, httpPort, rtspPort,
        username, password, channelsCount, JSON.stringify(channelNamesObj), JSON.stringify(hiddenArr), allowedAdmins, enabled, ts, ts
      );
    }
    return listDvrs();
  }

  function deleteDvr(id) {
    db.prepare('DELETE FROM cctv_dvrs WHERE id=?').run(String(id || ''));
    return listDvrs();
  }

  async function dahuaAuthedGet({ host, port, pathWithQuery, username, password, timeoutMs = 5500 }) {
    const cacheKey = `${host}:${port}:${username}`;
    const cached = digestCache.get(cacheKey);
    if (cached && cached.challenge) {
      cached.nc = (cached.nc || 1) + 1;
      const authHdr = buildDigestAuthorization({
        method: 'GET',
        uri: pathWithQuery,
        username,
        password,
        challenge: cached.challenge,
        ncNum: cached.nc,
      });
      const r1 = await rawHttpGet({
        host,
        port,
        pathWithQuery,
        headers: { Authorization: authHdr },
        timeoutMs,
      });
      if (r1.statusCode !== 401) {
        return r1;
      }
      digestCache.delete(cacheKey);
    }

    // Initial request to obtain WWW-Authenticate challenge
    const probe = await rawHttpGet({ host, port, pathWithQuery, timeoutMs });
    if (probe.statusCode !== 401) {
      return probe;
    }
    const rawWww = probe.headers['www-authenticate'];
    const wwwStr = Array.isArray(rawWww) ? rawWww.join(', ') : String(rawWww || '');
    const challenge = parseDigestHeader(wwwStr);
    if (challenge) {
      digestCache.set(cacheKey, { challenge, nc: 1 });
      const authHdr = buildDigestAuthorization({
        method: 'GET',
        uri: pathWithQuery,
        username,
        password,
        challenge,
        ncNum: 1,
      });
      return rawHttpGet({
        host,
        port,
        pathWithQuery,
        headers: { Authorization: authHdr },
        timeoutMs,
      });
    }
    // Fallback to HTTP Basic Auth
    const basic = Buffer.from(`${username}:${password}`, 'utf8').toString('base64');
    return rawHttpGet({
      host,
      port,
      pathWithQuery,
      headers: { Authorization: `Basic ${basic}` },
      timeoutMs,
    });
  }

  function isLikelyImage(buf) {
    if (!buf || buf.length < 256) return false;
    // JPEG SOI FF D8 or PNG 89 50 4E 47
    return (buf[0] === 0xff && buf[1] === 0xd8) || (buf[0] === 0x89 && buf[1] === 0x50);
  }

  async function fetchDirectSnapshot(dvr, channel, hd = false) {
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const sub = hd ? 0 : 1;
    const primaryPath = `/cgi-bin/snapshot.cgi?channel=${ch}&subtype=${sub}`;
    let resp = await dahuaAuthedGet({
      host: dvr.host,
      port: dvr.http_port,
      pathWithQuery: primaryPath,
      username: dvr.username,
      password: dvr.password,
      timeoutMs: 5500,
    });

    if (resp.statusCode === 401) {
      throw new Error('اسم المستخدم أو كلمة مرور جهاز الـ DVR غير صحيحة (HTTP 401)');
    }

    if ((resp.statusCode !== 200 || !isLikelyImage(resp.body)) && !hd) {
      // Older Dahua firmware fallback without &subtype=1
      resp = await dahuaAuthedGet({
        host: dvr.host,
        port: dvr.http_port,
        pathWithQuery: `/cgi-bin/snapshot.cgi?channel=${ch}`,
        username: dvr.username,
        password: dvr.password,
        timeoutMs: 5500,
      });
    }

    if (resp.statusCode !== 200 || !isLikelyImage(resp.body)) {
      throw new Error(`تعذر جلب صورة الكاميرا رقم ${ch} (HTTP ${resp.statusCode || 0})`);
    }

    const mime = resp.body[0] === 0x89 ? 'image/png' : 'image/jpeg';
    return { buf: resp.body, mime, at: Date.now() };
  }

  function isVersionAtLeast(verStr, minMajor, minMinor, minPatch) {
    const parts = String(verStr || '0.0.0').trim().replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
    const [maj = 0, min = 0, pat = 0] = parts;
    if (maj !== minMajor) return maj > minMajor;
    if (min !== minMinor) return min > minMinor;
    return pat >= minPatch;
  }

  async function testDvrConnection(payload) {
    const existing = payload.id ? getRawDvr(payload.id) : null;
    const mode = payload.connection_mode === 'bridge' ? 'bridge' : 'direct';
    let host = String(payload.host || (existing && existing.host) || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (host.includes(':')) host = host.split(':')[0];
    const httpPort = Number(payload.http_port || (existing && existing.http_port) || 80) || 80;
    const username = String(payload.username || (existing && existing.username) || 'admin').trim();
    const password = payload.password ? String(payload.password) : (existing ? existing.password : '');

    if (!host) throw new Error('يرجى كتابة عنوان IP للـ DVR أولاً (مثل 192.168.1.108 أو 10.10.1.108)');

    if (mode === 'bridge') {
      const bridgeId = String(payload.bridge_device_id || (existing && existing.bridge_device_id) || '').trim();
      if (!bridgeId) throw new Error('اختر جهاز الكمبيوتر الوسيط في الفرع أولاً');
      const dev = db.prepare('SELECT last_seen, label, hostname, app_version FROM devices WHERE device_id=?').get(bridgeId);
      const devLabel = (dev && (dev.label || dev.hostname)) || bridgeId;
      const isOnline = Boolean(dev && dev.last_seen && Date.now() - Number(dev.last_seen) < 60_000);
      if (!isOnline) {
        throw new Error(`جهاز الفرع المختار (${devLabel}) غير متصل حالياً — تأكد من أن الجهاز يعمل ومتصل بالإنترنت`);
      }
      if (!isVersionAtLeast(dev.app_version, 1, 0, 9)) {
        throw new Error(`جهاز الفرع (${devLabel}) يعمل حالياً بالإصدار القديم v${dev.app_version || '1.0.0'} — اضغط زر «⬆️ ترقية جهاز الفرع لـ v1.0.9» بالأسفل وانتظر 30 ثانية ثم أعد الفحص`);
      }
      const probeId = existing ? existing.id : ('test_' + rid());
      const frame = await getFrame({
        dvrId: probeId,
        channel: 1,
        hd: false,
        waitMs: 7500,
        overrideDvr: {
          id: probeId,
          connection_mode: 'bridge',
          bridge_device_id: bridgeId,
          host,
          http_port: httpPort,
          username,
          password,
          enabled: 1,
        },
      });
      if (frame && frame.buf) {
        return {
          ok: true,
          sample_bytes: frame.buf.length,
          message: `✓ نجح الاتصال بجهاز Dahua DVR (${host}) عبر كمبيوتر الفرع (${devLabel}) وتم استلام بث الكاميرا 1 بنجاح!`,
        };
      }
      return {
        ok: true,
        message: `✓ جهاز الفرع (${devLabel}) متصل وجاهز — احفظ بيانات الـ DVR لبدء البث المباشر`,
      };
    }

    // Direct mode: probe ChannelTitle + SystemInfo + Channel 1 snapshot
    const tempDvr = { host, http_port: httpPort, username, password };
    let detectedChannels = 0;
    const channelNames = {};
    let deviceModel = '';

    try {
      const titleResp = await dahuaAuthedGet({
        host,
        port: httpPort,
        pathWithQuery: '/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle',
        username,
        password,
        timeoutMs: 4500,
      });
      if (titleResp.statusCode === 401) {
        throw new Error('اسم المستخدم أو كلمة مرور الـ DVR غير صحيحة');
      }
      if (titleResp.statusCode === 200) {
        const txt = titleResp.body.toString('utf8');
        const lines = txt.split(/\r?\n/);
        for (const ln of lines) {
          const m = ln.match(/table\.ChannelTitle\[(\d+)\]\.Name=(.+)$/);
          if (m) {
            const idx1 = parseInt(m[1], 10) + 1;
            const title = m[2].trim();
            if (idx1 > detectedChannels) detectedChannels = idx1;
            if (title) channelNames[String(idx1)] = title;
          }
        }
      }
    } catch (e) {
      if (String(e.message || '').includes('401') || String(e.message || '').includes('غير صحيحة')) {
        throw e;
      }
    }

    try {
      const sysResp = await dahuaAuthedGet({
        host,
        port: httpPort,
        pathWithQuery: '/cgi-bin/magicBox.cgi?action=getDeviceType',
        username,
        password,
        timeoutMs: 3500,
      });
      if (sysResp.statusCode === 200) {
        const txt = sysResp.body.toString('utf8').trim();
        const m = txt.match(/type=(.+)$/i);
        deviceModel = (m ? m[1] : txt).trim().slice(0, 60);
      }
    } catch (_) {}

    const snap = await fetchDirectSnapshot(tempDvr, 1, false);
    return {
      ok: true,
      detected_channels: detectedChannels || undefined,
      channel_names: Object.keys(channelNames).length ? channelNames : undefined,
      device_model: deviceModel,
      sample_bytes: snap.buf.length,
      message: `✓ متصل بنجاح بجهاز Dahua${deviceModel ? ' (' + deviceModel + ')' : ''}${detectedChannels ? ' — تم اكتشاف ' + detectedChannels + ' قناة تلقائياً' : ''}`,
    };
  }

  function registerBridgeLease(dvr, channel, hd, durationMs = 12_000, overrideDvr = null) {
    const devId = dvr.bridge_device_id;
    if (!devId) return;
    let map = bridgeLeases.get(devId);
    if (!map) {
      map = new Map();
      bridgeLeases.set(devId, map);
    }
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const key = `${dvr.id}:${ch}`;
    map.set(key, {
      dvr_id: dvr.id,
      channel: ch,
      hd: Boolean(hd),
      until: Date.now() + durationMs,
      override: overrideDvr || null,
    });
  }

  // Called inside /api/v1/device/poll for employee bridge PCs
  function getActiveTaskForDevice(deviceId) {
    if (!deviceId) return null;
    const nowMs = Date.now();
    const byDvr = new Map();
    const map = bridgeLeases.get(deviceId);
    if (map && map.size > 0) {
      for (const [k, item] of map.entries()) {
        if (item.until <= nowMs) {
          map.delete(k);
          continue;
        }
        const dvr = item.override || getRawDvr(item.dvr_id);
        if (!dvr || !dvr.enabled) {
          map.delete(k);
          continue;
        }
        const deadInfo = deadChannelUntil.get(`${dvr.id}:${item.channel}`);
        if (deadInfo && deadInfo.until > nowMs) {
          continue;
        }
        let entry = byDvr.get(dvr.id);
        if (!entry) {
          entry = {
            dvr_id: dvr.id,
            host: dvr.host,
            http_port: Number(dvr.http_port || 80),
            username: dvr.username || 'admin',
            password: dvr.password || '',
            channels: [],
            hd: false,
            until: item.until,
            audio_channel: 0,
            audio_until: 0,
          };
          byDvr.set(dvr.id, entry);
        }
        if (!entry.channels.includes(item.channel)) entry.channels.push(item.channel);
        if (item.hd) entry.hd = true;
        if (item.until > entry.until) entry.until = item.until;
      }
      if (map.size === 0) bridgeLeases.delete(deviceId);
    }

    // Attach on-demand Live Audio lease (if an admin has unmuted a camera on this branch PC)
    for (const [aDvrId, aLease] of audioLeases.entries()) {
      if (aLease.until <= nowMs) {
        audioLeases.delete(aDvrId);
        continue;
      }
      if (aLease.bridgeDeviceId !== deviceId) continue;
      const dvr = getRawDvr(aDvrId);
      if (!dvr || !dvr.enabled) {
        audioLeases.delete(aDvrId);
        continue;
      }
      let entry = byDvr.get(dvr.id);
      if (!entry) {
        entry = {
          dvr_id: dvr.id,
          host: dvr.host,
          http_port: Number(dvr.http_port || 80),
          username: dvr.username || 'admin',
          password: dvr.password || '',
          channels: [],
          hd: false,
          until: aLease.until,
          audio_channel: aLease.channel,
          audio_until: aLease.until,
        };
        byDvr.set(dvr.id, entry);
      } else {
        entry.audio_channel = aLease.channel;
        entry.audio_until = aLease.until;
        if (aLease.until > entry.until) entry.until = aLease.until;
      }
    }

    const tasks = Array.from(byDvr.values());
    return tasks.length ? tasks : null;
  }

  function ingestBridgeFrame({ deviceId, dvrId, channel, hd, imageB64, error }) {
    const isTestProbe = String(dvrId || '').startsWith('test_');
    const dvr = isTestProbe ? { id: String(dvrId), bridge_device_id: deviceId } : getRawDvr(dvrId);
    if (!dvr || dvr.bridge_device_id !== deviceId) return false;
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const key = `${dvr.id}:${ch}:${hd ? 1 : 0}`;
    const fallbackKey = `${dvr.id}:${ch}:0`;
    if (error) {
      const errMsg = String(error).slice(0, 200);
      frameCache.set(key, { buf: null, mime: 'image/jpeg', at: Date.now(), error: errMsg });
      deadChannelUntil.set(`${dvr.id}:${ch}`, { until: Date.now() + 20_000, error: errMsg });
      return true;
    }
    deadChannelUntil.delete(`${dvr.id}:${ch}`);
    let clean = String(imageB64 || '').trim();
    const idx = clean.indexOf(';base64,');
    if (idx !== -1) clean = clean.slice(idx + 8);
    if (!clean) return false;
    const buf = Buffer.from(clean, 'base64');
    if (!isLikelyImage(buf)) return false;
    const mime = buf[0] === 0x89 ? 'image/png' : 'image/jpeg';
    const record = { buf, mime, at: Date.now(), error: '' };
    frameCache.set(key, record);
    if (hd) frameCache.set(fallbackKey, record);
    if (frameCache.size > 160) {
      const oldestKey = frameCache.keys().next().value;
      frameCache.delete(oldestKey);
    }
    return true;
  }

  async function getFrame({ dvrId, channel = 1, hd = false, waitMs = 3500, overrideDvr = null }) {
    const dvr = overrideDvr || getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const cacheKey = `${dvr.id}:${ch}:${hd ? 1 : 0}`;

    if (dvr.connection_mode === 'bridge') {
      const dev = db.prepare('SELECT last_seen, label, hostname, app_version FROM devices WHERE device_id=?').get(dvr.bridge_device_id);
      const devLabel = (dev && (dev.label || dev.hostname)) || dvr.bridge_device_id;
      if (!dev || !dev.last_seen || Date.now() - Number(dev.last_seen) > 60_000) {
        throw new Error(`كمبيوتر الفرع (${devLabel}) غير متصل حالياً`);
      }
      if (!isVersionAtLeast(dev.app_version, 1, 0, 9)) {
        throw new Error(`كمبيوتر الفرع (${devLabel}) يعمل بالإصدار v${dev.app_version || '1.0.0'} ويحتاج التحديث إلى v1.0.10`);
      }
      const deadInfo = deadChannelUntil.get(`${dvr.id}:${ch}`);
      if (deadInfo && deadInfo.until > Date.now()) {
        throw new Error(deadInfo.error || `القناة ${ch} غير متصلة`);
      }
      const existing = frameCache.get(cacheKey) || (!hd ? frameCache.get(`${dvr.id}:${ch}:1`) : frameCache.get(`${dvr.id}:${ch}:0`));
      if (existing && existing.buf && Date.now() - existing.at < 1800) {
        registerBridgeLease(dvr, ch, hd, 12_000, overrideDvr);
        return existing;
      }
      if (inflightBridge.has(cacheKey)) {
        return inflightBridge.get(cacheKey);
      }
      const bp = (async () => {
        try {
          registerBridgeLease(dvr, ch, hd, 14_000, overrideDvr);
          const started = Date.now();
          const prevAt = existing ? existing.at : 0;
          while (Date.now() - started < waitMs) {
            await new Promise((r) => setTimeout(r, 150));
            const deadNow = deadChannelUntil.get(`${dvr.id}:${ch}`);
            if (deadNow && deadNow.until > Date.now()) {
              throw new Error(deadNow.error || `القناة ${ch} غير متصلة`);
            }
            const cur = frameCache.get(cacheKey) || (!hd ? frameCache.get(`${dvr.id}:${ch}:1`) : null);
            if (cur && cur.at > prevAt) {
              if (cur.error) throw new Error(cur.error);
              if (cur.buf) return cur;
            }
          }
          if (existing && existing.buf && Date.now() - existing.at < 25_000) {
            return existing;
          }
          if (existing && existing.error) {
            throw new Error(existing.error);
          }
          throw new Error('في انتظار بث الكاميرا من جهاز الفرع...');
        } finally {
          inflightBridge.delete(cacheKey);
        }
      })();
      inflightBridge.set(cacheKey, bp);
      return bp;
    }

    // Direct mode (with 120ms micro-coalescing if multiple admins view the exact same camera simultaneously)
    const cached = frameCache.get(cacheKey);
    if (cached && cached.buf && Date.now() - cached.at < 120) {
      return cached;
    }
    if (inflightDirect.has(cacheKey)) {
      return inflightDirect.get(cacheKey);
    }
    const p = (async () => {
      try {
        const res = await fetchDirectSnapshot(dvr, ch, hd);
        const rec = { buf: res.buf, mime: res.mime, at: res.at, error: '' };
        frameCache.set(cacheKey, rec);
        return rec;
      } finally {
        inflightDirect.delete(cacheKey);
      }
    })();
    inflightDirect.set(cacheKey, p);
    return p;
  }

  function probeTcpPort(host, port, timeoutMs = 650) {
    return new Promise((resolve) => {
      const sock = new net.Socket();
      let done = false;
      const finish = (ok) => {
        if (done) return;
        done = true;
        try { sock.destroy(); } catch (_) {}
        resolve(ok);
      };
      sock.setTimeout(timeoutMs);
      sock.once('connect', () => finish(true));
      sock.once('timeout', () => finish(false));
      sock.once('error', () => finish(false));
      sock.connect(port, host);
    });
  }

  async function scanLocalLanForDahua() {
    const nets = os.networkInterfaces();
    const prefixes = new Set();
    for (const list of Object.values(nets)) {
      for (const iface of list || []) {
        if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('100.')) {
          const parts = iface.address.split('.');
          if (parts.length === 4) prefixes.add(`${parts[0]}.${parts[1]}.${parts[2]}`);
        }
      }
    }
    const found = [];
    for (const prefix of Array.from(prefixes).slice(0, 2)) {
      const ips = [];
      for (let i = 1; i <= 254; i++) ips.push(`${prefix}.${i}`);
      const batchSize = 48;
      for (let b = 0; b < ips.length; b += batchSize) {
        const slice = ips.slice(b, b + batchSize);
        const results = await Promise.all(
          slice.map(async (ip) => {
            // Port 37777 is Dahua's signature TCP command port across all Dahua DVRs/NVRs/IPCams!
            const has37777 = await probeTcpPort(ip, 37777, 550);
            if (!has37777) return null;
            const has80 = await probeTcpPort(ip, 80, 450);
            const has8080 = !has80 ? await probeTcpPort(ip, 8080, 450) : false;
            return {
              host: ip,
              http_port: has80 ? 80 : (has8080 ? 8080 : 80),
              rtsp_port: 554,
              vendor: 'Dahua DVR / XVR (منفذ 37777 مكتشف)',
            };
          })
        );
        for (const item of results) {
          if (item) found.push(item);
        }
      }
    }
    return { ok: true, found };
  }

  async function scanBranchForDahua(bridgeDeviceId) {
    const devId = String(bridgeDeviceId || '').trim();
    if (!devId) return scanLocalLanForDahua();
    const dev = db.prepare('SELECT last_seen, label, hostname, app_version FROM devices WHERE device_id=?').get(devId);
    const devLabel = (dev && (dev.label || dev.hostname)) || devId;
    if (!dev || !dev.last_seen || Date.now() - Number(dev.last_seen) > 60_000) {
      throw new Error(`كمبيوتر الفرع (${devLabel}) غير متصل حالياً`);
    }
    if (!isVersionAtLeast(dev.app_version, 1, 0, 9)) {
      throw new Error(`كمبيوتر الفرع (${devLabel}) يعمل بالإصدار القديم v${dev.app_version || '1.0.0'} — اضغط زر «⬆️ ترقية جهاز الفرع لـ v1.0.9» أولاً`);
    }
    const started = Date.now();
    branchScanJobs.set(devId, { requestedAt: started, until: started + 15_000, result: null });
    while (Date.now() - started < 12_000) {
      await new Promise((r) => setTimeout(r, 250));
      const job = branchScanJobs.get(devId);
      if (job && Array.isArray(job.result)) {
        branchScanJobs.delete(devId);
        return { ok: true, found: job.result };
      }
    }
    branchScanJobs.delete(devId);
    throw new Error('لم يرد جهاز الفرع بنتيجة البحث (تأكد أن الجهاز متصل الآن ومحدّث للإصدار v1.0.9)');
  }

  function popPendingScanForDevice(deviceId) {
    const job = branchScanJobs.get(deviceId);
    if (!job) return false;
    if (job.until <= Date.now() || job.result !== null) return false;
    // Mark dispatched by extending until slightly while waiting for result
    job.dispatched = true;
    return !job.sentOnce && (job.sentOnce = true);
  }

  function ingestBranchScanResult(deviceId, foundList) {
    const job = branchScanJobs.get(deviceId);
    if (!job) return false;
    job.result = Array.isArray(foundList) ? foundList.slice(0, 20) : [];
    return true;
  }

  function popPendingCgiForDevice(deviceId) {
    if (!deviceId) return null;
    const nowMs = Date.now();
    const out = [];
    for (const [jid, job] of branchCgiJobs.entries()) {
      if (job.until <= nowMs) {
        branchCgiJobs.delete(jid);
        job.reject(new Error('انتهت مهلة انتظار استجابة جسر الفرع'));
        continue;
      }
      if (job.deviceId === deviceId && !job.dispatched) {
        job.dispatched = true;
        out.push(job.payload);
      }
    }
    return out.length ? out : null;
  }

  function ingestBranchCgiResult(deviceId, body) {
    const jid = String((body && body.job_id) || '');
    const job = branchCgiJobs.get(jid);
    if (!job || job.deviceId !== deviceId) return false;
    branchCgiJobs.delete(jid);
    if (body && body.error) {
      job.reject(new Error(String(body.error)));
      return true;
    }
    const buf = body && body.body_b64 ? Buffer.from(String(body.body_b64), 'base64') : Buffer.alloc(0);
    job.resolve({
      statusCode: Number(body.status || 200),
      contentType: String(body.content_type || 'text/plain'),
      body: buf,
    });
    return true;
  }

  async function executeDvrCgi(dvr, pathWithQuery, { timeoutMs = 9000, maxBytes = 262144 } = {}) {
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    if (dvr.connection_mode !== 'bridge') {
      const resp = await dahuaAuthedGet({
        host: dvr.host,
        port: dvr.http_port,
        pathWithQuery,
        username: dvr.username,
        password: dvr.password,
        timeoutMs,
      });
      return {
        statusCode: resp.statusCode,
        contentType: String((resp.headers && resp.headers['content-type']) || 'text/plain'),
        body: resp.body.length > maxBytes ? resp.body.subarray(0, maxBytes) : resp.body,
      };
    }

    const devId = String(dvr.bridge_device_id || '').trim();
    const dev = db.prepare('SELECT last_seen, label, hostname, app_version FROM devices WHERE device_id=?').get(devId);
    const devLabel = (dev && (dev.label || dev.hostname)) || devId;
    if (!dev || !dev.last_seen || Date.now() - Number(dev.last_seen) > 60_000) {
      throw new Error(`كمبيوتر الفرع (${devLabel}) غير متصل حالياً`);
    }
    if (!isVersionAtLeast(dev.app_version, 1, 1, 0)) {
      throw new Error(`هذه الميزة المتقدمة تتطلب ترقية كمبيوتر الفرع (${devLabel}) إلى الإصدار v1.1.0 — افتح إعدادات الـ DVR واضغط زر الترقية الصامتة`);
    }

    const jobId = rid('cgi_');
    return new Promise((resolve, reject) => {
      const waitLimit = Math.max(timeoutMs + 5000, 12_000);
      const timer = setTimeout(() => {
        if (branchCgiJobs.has(jobId)) {
          branchCgiJobs.delete(jobId);
          reject(new Error(`تأخر رد جهاز الـ DVR في فرع ${dvr.name}`));
        }
      }, waitLimit);
      branchCgiJobs.set(jobId, {
        deviceId: devId,
        dispatched: false,
        until: Date.now() + waitLimit,
        payload: {
          job_id: jobId,
          host: dvr.host,
          http_port: Number(dvr.http_port || 80),
          username: dvr.username || 'admin',
          password: dvr.password || '',
          path: pathWithQuery,
          max_bytes: maxBytes,
          timeout_ms: timeoutMs,
        },
        resolve: (val) => { clearTimeout(timer); resolve(val); },
        reject: (err) => { clearTimeout(timer); reject(err); },
      });
    });
  }

  function parseDahuaKvLines(text) {
    const map = {};
    for (const rawLine of String(text || '').split(/\r?\n/)) {
      const idx = rawLine.indexOf('=');
      if (idx > 0) {
        const k = rawLine.slice(0, idx).trim();
        const v = rawLine.slice(idx + 1).trim();
        map[k] = v;
      }
    }
    return map;
  }

  // Phase 1: Pull Camera Names from DVR (works for both Direct & Remote Bridge!)
  async function pullChannelNames(dvrId) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const resp = await executeDvrCgi(dvr, '/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle', { timeoutMs: 7500 });
    if (resp.statusCode === 401) throw new Error('اسم المستخدم أو كلمة مرور الـ DVR غير صحيحة');
    if (resp.statusCode !== 200) throw new Error(`رفض الـ DVR طلب أسماء القنوات (HTTP ${resp.statusCode})`);
    const txt = resp.body.toString('utf8');
    let existingNames = {};
    try { existingNames = JSON.parse(dvr.channel_names || '{}') || {}; } catch (_) {}
    let count = 0;
    for (const ln of txt.split(/\r?\n/)) {
      const m = ln.match(/table\.ChannelTitle\[(\d+)\]\.Name=(.+)$/);
      if (m) {
        const ch = String(parseInt(m[1], 10) + 1);
        const title = m[2].trim();
        if (title) {
          existingNames[ch] = title;
          count++;
        }
      }
    }
    db.prepare('UPDATE cctv_dvrs SET channel_names=?, updated_at=? WHERE id=?').run(
      JSON.stringify(existingNames),
      Date.now(),
      dvr.id
    );
    try { await detectAudioChannels(dvr.id); } catch (_) {}
    return {
      ok: true,
      pulled_count: count,
      channel_names: existingNames,
      dvrs: listDvrs().dvrs,
      message: count > 0 ? `✓ تم سحب أسماء ${count} كاميرا وكشف الكاميرات المزوّدة بصوت بنجاح` : 'تم الاتصال ولكن لم تُسجّل أسماء مخصّصة داخل الـ DVR',
    };
  }

  // Phase 1: Rename a single camera in Arabic or hide/unhide a channel
  function saveChannelMeta({ dvrId, channel, title, hidden }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    let names = {};
    let hiddenArr = [];
    try { names = JSON.parse(dvr.channel_names || '{}') || {}; } catch (_) {}
    try { hiddenArr = JSON.parse(dvr.hidden_channels || '[]') || []; } catch (_) {}
    if (!Array.isArray(hiddenArr)) hiddenArr = [];
    if (typeof title === 'string') {
      const clean = title.trim().slice(0, 60);
      if (clean) names[String(ch)] = clean;
      else delete names[String(ch)];
    }
    if (hidden !== undefined) {
      hiddenArr = hiddenArr.filter((x) => Number(x) !== ch);
      if (hidden) hiddenArr.push(ch);
    }
    db.prepare('UPDATE cctv_dvrs SET channel_names=?, hidden_channels=?, updated_at=? WHERE id=?').run(
      JSON.stringify(names),
      JSON.stringify(hiddenArr),
      Date.now(),
      dvr.id
    );
    return listDvrs();
  }

  // Phase 2: DVR & HDD Storage Health Check
  async function checkDvrHealth(dvrId) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    let hddStatus = 'unknown'; // 'ok' | 'missing' | 'error' | 'unknown'
    let totalBytes = 0;
    let usedBytes = 0;
    let hddStateRaw = '';
    let deviceModel = '';
    let serialNo = '';

    try {
      const stResp = await executeDvrCgi(dvr, '/cgi-bin/storageDevice.cgi?action=getDeviceAllInfo', { timeoutMs: 8000 });
      if (stResp.statusCode === 401) throw new Error('بيانات دخول الـ DVR غير صحيحة (401)');
      if (stResp.statusCode === 200) {
        const txt = stResp.body.toString('utf8');
        const kv = parseDahuaKvLines(txt);
        let hasAnyDiskEntry = false;
        let hasErr = false;
        for (const [k, v] of Object.entries(kv)) {
          if (/\.(Name|Path)$/i.test(k) && v) hasAnyDiskEntry = true;
          if (/TotalBytes$/i.test(k)) {
            const n = parseFloat(v);
            if (Number.isFinite(n) && n > 0) {
              totalBytes += n;
              hasAnyDiskEntry = true;
            }
          }
          if (/UsedBytes$/i.test(k)) {
            const u = parseFloat(v);
            if (Number.isFinite(u) && u >= 0) usedBytes += u;
          }
          if (/IsError$/i.test(k) && String(v).toLowerCase() === 'true') hasErr = true;
          if (/\.State$/i.test(k) && v) {
            hddStateRaw = v;
            if (/error|damage|bad|abnormal|unformatted/i.test(v)) hasErr = true;
          }
        }
        if (!hasAnyDiskEntry) {
          hddStatus = 'missing';
        } else {
          hddStatus = hasErr ? 'error' : (totalBytes > 0 ? 'ok' : 'missing');
        }
      }
    } catch (e) {
      if (String(e.message || '').includes('401') || String(e.message || '').includes('v1.1.0') || String(e.message || '').includes('غير متصل')) {
        throw e;
      }
    }

    try {
      const mResp = await executeDvrCgi(dvr, '/cgi-bin/magicBox.cgi?action=getDeviceType', { timeoutMs: 5000 });
      if (mResp.statusCode === 200) {
        const kv = parseDahuaKvLines(mResp.body.toString('utf8'));
        deviceModel = (kv.type || mResp.body.toString('utf8').trim()).slice(0, 60);
      }
    } catch (_) {}

    try {
      const sResp = await executeDvrCgi(dvr, '/cgi-bin/magicBox.cgi?action=getSerialNo', { timeoutMs: 5000 });
      if (sResp.statusCode === 200) {
        const kv = parseDahuaKvLines(sResp.body.toString('utf8'));
        serialNo = (kv.sn || '').slice(0, 60);
      }
    } catch (_) {}

    const totalGb = totalBytes > 0 ? Math.round((totalBytes / (1024 ** 3)) * 10) / 10 : 0;
    const freeGb = totalBytes > usedBytes ? Math.round(((totalBytes - usedBytes) / (1024 ** 3)) * 10) / 10 : 0;
    const offlineChannels = getAutoDeadChannelsList(dvr.id);
    const health = {
      ok: true,
      hdd_status: hddStatus,
      hdd_state: hddStateRaw,
      total_gb: totalGb,
      free_gb: freeGb,
      device_model: deviceModel,
      serial_no: serialNo,
      offline_channels: offlineChannels,
      checked_at: Date.now(),
    };
    db.prepare('UPDATE cctv_dvrs SET health_json=? WHERE id=?').run(JSON.stringify(health), dvr.id);
    if (!dvr.audio_channels || !String(dvr.audio_channels).trim().startsWith('[')) {
      try { await detectAudioChannels(dvr.id); } catch (_) {}
    }
    return { ok: true, dvr_id: dvr.id, name: dvr.name, health, dvrs: listDvrs().dvrs };
  }

  async function checkAllDvrsHealth() {
    const rows = db.prepare('SELECT * FROM cctv_dvrs WHERE enabled=1 ORDER BY created_at ASC').all();
    const results = [];
    for (const r of rows) {
      try {
        const h = await checkDvrHealth(r.id);
        results.push({ dvr_id: r.id, name: r.name, ok: true, health: h.health });
      } catch (e) {
        results.push({ dvr_id: r.id, name: r.name, ok: false, error: (e && e.message) || 'تعذر الفحص' });
      }
    }
    return { ok: true, results, dvrs: listDvrs().dvrs };
  }

  // Phase 3: Remote Playback Recording Search on DVR HDD
  async function searchRecordings({ dvrId, channel = 1, startTime, endTime }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const st = String(startTime || '').trim();
    const et = String(endTime || '').trim();
    if (!st || !et) throw new Error('يرجى تحديد وقت البداية والنهاية للبحث');

    const createResp = await executeDvrCgi(dvr, '/cgi-bin/mediaFileFind.cgi?action=factory.create', { timeoutMs: 7000 });
    if (createResp.statusCode !== 200) {
      throw new Error(`جهاز الـ DVR لا يدعم البحث عن بُعد أو كلمة السر غير صحيحة (HTTP ${createResp.statusCode})`);
    }
    const createKv = parseDahuaKvLines(createResp.body.toString('utf8'));
    const objId = createKv.result || createResp.body.toString('utf8').trim();
    if (!objId) throw new Error('تعذر فتح جلسة البحث في هارد الـ DVR');

    const items = [];
    try {
      // Dahua mediaFileFind uses 1-based channel in newer NVR4.0 and 0-based in some older XVR firmwares — try ch first, then ch-1 if empty
      for (const condCh of [ch, ch - 1]) {
        if (condCh < 0) continue;
        const findUrl =
          `/cgi-bin/mediaFileFind.cgi?action=findFile&object=${encodeURIComponent(objId)}` +
          `&condition.Channel=${condCh}` +
          `&condition.StartTime=${encodeURIComponent(st)}` +
          `&condition.EndTime=${encodeURIComponent(et)}`;
        const fResp = await executeDvrCgi(dvr, findUrl, { timeoutMs: 8000 });
        const fTxt = fResp.body.toString('utf8').trim();
        if (fResp.statusCode === 200 && /ok/i.test(fTxt)) {
          const nextResp = await executeDvrCgi(
            dvr,
            `/cgi-bin/mediaFileFind.cgi?action=findNextFile&object=${encodeURIComponent(objId)}&count=40`,
            { timeoutMs: 9000 }
          );
          const kv = parseDahuaKvLines(nextResp.body.toString('utf8'));
          const foundCount = parseInt(kv.found || '0', 10) || 0;
          for (let i = 0; i < foundCount; i++) {
            const pfx = `items[${i}]`;
            if (kv[`${pfx}.StartTime`] || kv[`${pfx}.FilePath`]) {
              items.push({
                channel: ch,
                start_time: kv[`${pfx}.StartTime`] || st,
                end_time: kv[`${pfx}.EndTime`] || et,
                size_bytes: Number(kv[`${pfx}.Length`] || 0) || 0,
                file_path: kv[`${pfx}.FilePath`] || '',
                type: kv[`${pfx}.Type`] || 'dav',
              });
            }
          }
          if (items.length > 0) break;
        }
      }
    } finally {
      executeDvrCgi(dvr, `/cgi-bin/mediaFileFind.cgi?action=close&object=${encodeURIComponent(objId)}`, { timeoutMs: 3500 }).catch(() => {});
      executeDvrCgi(dvr, `/cgi-bin/mediaFileFind.cgi?action=factory.destroy&object=${encodeURIComponent(objId)}`, { timeoutMs: 3500 }).catch(() => {});
    }

    return { ok: true, items };
  }

  // Phase 3: Download short recorded incident clip (Sub-Stream first for fast, zero-lag transfer)
  async function downloadRecordingClip({ dvrId, channel = 1, startTime, endTime }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const st = String(startTime || '').trim();
    const et = String(endTime || '').trim();
    if (!st || !et) throw new Error('وقت المقطع مفقود');

    for (const sub of [1, 0]) {
      const loadPath =
        `/cgi-bin/loadfile.cgi?action=startLoad&channel=${ch}` +
        `&startTime=${encodeURIComponent(st)}` +
        `&endTime=${encodeURIComponent(et)}` +
        `&subtype=${sub}`;
      const resp = await executeDvrCgi(dvr, loadPath, { timeoutMs: 28_000, maxBytes: 8 * 1024 * 1024 });
      if (resp.statusCode === 200 && resp.body && resp.body.length > 1024) {
        const safeTime = st.replace(/[^0-9]/g, '').slice(0, 14);
        // Check if MP4 ('ftyp') or Dahua DAV ('DHAV')
        const isMp4 = resp.body.slice(4, 8).toString('ascii') === 'ftyp';
        const ext = isMp4 ? 'mp4' : 'dav';
        const mime = isMp4 ? 'video/mp4' : 'application/octet-stream';
        return {
          buf: resp.body,
          mime,
          fileName: `Dahua_${dvr.name.replace(/[^\w\u0600-\u06FF-]+/g, '_')}_CH${ch}_${safeTime}.${ext}`,
        };
      }
    }
    throw new Error('لم يُعثر على تسجيل فيديو في هذه الفترة الزمنية على هارد الـ DVR');
  }

  // Phase 5: PTZ Directional & Optical Zoom Control
  async function ptzMove({ dvrId, channel = 1, code, speed = 4, durationMs = 350 }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const allowedCodes = ['Up', 'Down', 'Left', 'Right', 'ZoomTele', 'ZoomWide', 'FocusNear', 'FocusFar'];
    const cleanCode = allowedCodes.find((c) => c.toLowerCase() === String(code || '').toLowerCase());
    if (!cleanCode) throw new Error('أمر PTZ غير معروف');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const spd = Math.max(1, Math.min(8, Number(speed || 4) || 4));
    const startPath = `/cgi-bin/ptz.cgi?action=start&channel=${ch}&code=${cleanCode}&arg1=0&arg2=${spd}&arg3=0`;
    const stopPath = `/cgi-bin/ptz.cgi?action=stop&channel=${ch}&code=${cleanCode}&arg1=0&arg2=${spd}&arg3=0`;
    await executeDvrCgi(dvr, startPath, { timeoutMs: 4500 });
    setTimeout(() => {
      executeDvrCgi(dvr, stopPath, { timeoutMs: 4500 }).catch(() => {});
    }, Math.max(180, Math.min(1500, Number(durationMs || 350))));
    return { ok: true };
  }

  // ----- Phase 6: Live Camera Audio (AAC 16kHz / G.711A / G.711Mu / PCM, 0% CPU when muted) -----

  async function detectAudioChannels(dvrId) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const resp = await executeDvrCgi(dvr, '/cgi-bin/configManager.cgi?action=getConfig&name=Encode', {
      timeoutMs: 8500,
      maxBytes: 524288,
    });
    if (resp.statusCode === 401) throw new Error('بيانات دخول الـ DVR غير صحيحة (401)');
    if (resp.statusCode !== 200) throw new Error(`تعذر قراءة إعدادات الصوت من الـ DVR (HTTP ${resp.statusCode})`);
    const txt = resp.body.toString('utf8');
    const foundSet = new Set();
    for (const ln of txt.split(/\r?\n/)) {
      const m = ln.match(/table\.Encode\[(\d+)\]\.(?:MainFormat|ExtraFormat)\[\d+\]\.AudioEnable=(true|1)\b/i);
      if (m) {
        const ch = parseInt(m[1], 10) + 1;
        if (ch >= 1 && ch <= 64) foundSet.add(ch);
      }
    }
    const sorted = Array.from(foundSet).sort((a, b) => a - b);
    db.prepare('UPDATE cctv_dvrs SET audio_channels=? WHERE id=?').run(JSON.stringify(sorted), dvr.id);
    return {
      ok: true,
      dvr_id: dvr.id,
      audio_channels: sorted,
      dvrs: listDvrs().dvrs,
    };
  }

  function getOrCreateAudioStream(streamKey) {
    let st = audioStreams.get(streamKey);
    if (!st) {
      st = {
        seq: 0,
        adtsCarry: Buffer.alloc(0),
        chunks: [],
        error: '',
        errorAt: 0,
        fallbackInflight: false,
      };
      audioStreams.set(streamKey, st);
      if (audioStreams.size > 48) {
        const oldest = audioStreams.keys().next().value;
        audioStreams.delete(oldest);
      }
    }
    return st;
  }

  function stripDhavAudioPayloads(buf) {
    if (!buf || buf.length < 32) return buf;
    // Check ASCII "DHAV" (0x44 0x48 0x41 0x56)
    if (buf[0] !== 0x44 || buf[1] !== 0x48 || buf[2] !== 0x41 || buf[3] !== 0x56) {
      return buf;
    }
    const parts = [];
    let off = 0;
    while (off + 32 <= buf.length) {
      if (buf[off] !== 0x44 || buf[off + 1] !== 0x48 || buf[off + 2] !== 0x41 || buf[off + 3] !== 0x56) {
        off += 1;
        continue;
      }
      const pktLen = buf.readUInt32LE(off + 8);
      const hdrLen = buf.readUInt8(off + 12) || 24;
      if (pktLen < hdrLen + 8 || pktLen > 65536 || off + pktLen > buf.length) {
        break;
      }
      const frameType = buf[off + 4];
      if (frameType === 0xf0) {
        parts.push(buf.subarray(off + hdrLen, off + pktLen - 8));
      }
      off += pktLen;
    }
    return parts.length ? Buffer.concat(parts) : buf;
  }

  function extractCompleteAdtsFrames(buf) {
    const frames = [];
    let pos = 0;
    let sampleRate = 16000;
    let lastValidEnd = 0;
    while (pos + 7 <= buf.length) {
      if (buf[pos] === 0xff && (buf[pos + 1] & 0xf0) === 0xf0 && (buf[pos + 1] & 0x06) === 0x00) {
        const frameLen = ((buf[pos + 3] & 0x03) << 11) | (buf[pos + 4] << 3) | ((buf[pos + 5] & 0xe0) >> 5);
        const sfIdx = (buf[pos + 2] >> 2) & 0x0f;
        if (frameLen >= 7 && frameLen <= 2048 && sfIdx < ADTS_SAMPLE_RATES.length) {
          if (pos + frameLen > buf.length) {
            break;
          }
          // Verify next byte (if available) is also an ADTS syncword so random 0xFFFx bytes never false-trigger
          if (pos + frameLen + 2 <= buf.length) {
            if (buf[pos + frameLen] !== 0xff || (buf[pos + frameLen + 1] & 0xf0) !== 0xf0) {
              pos += 1;
              continue;
            }
          }
          sampleRate = ADTS_SAMPLE_RATES[sfIdx] || 16000;
          frames.push(buf.subarray(pos, pos + frameLen));
          pos += frameLen;
          lastValidEnd = pos;
          continue;
        }
      }
      pos += 1;
    }
    const remainder = pos < buf.length ? Buffer.from(buf.subarray(lastValidEnd > 0 ? pos : Math.max(0, buf.length - 2048))) : Buffer.alloc(0);
    return {
      framesBuf: frames.length ? Buffer.concat(frames) : null,
      frameCount: frames.length,
      sampleRate,
      remainder,
    };
  }

  function ingestRawAudioBytes(dvrId, channel, contentType, rawBuf) {
    if (!rawBuf || !rawBuf.length) return;
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const streamKey = `${dvrId}:${ch}`;
    const st = getOrCreateAudioStream(streamKey);
    st.error = '';

    const inner = stripDhavAudioPayloads(rawBuf);
    if (!inner || !inner.length) return;

    const ctLower = String(contentType || '').toLowerCase();
    const looksAdts =
      ctLower.includes('aac') ||
      (inner.length >= 7 && inner[0] === 0xff && (inner[1] & 0xf0) === 0xf0 && (inner[1] & 0x06) === 0x00);

    if (looksAdts) {
      const combined = st.adtsCarry.length ? Buffer.concat([st.adtsCarry, inner]) : inner;
      const capped = combined.length > 65536 ? combined.subarray(combined.length - 65536) : combined;
      const parsed = extractCompleteAdtsFrames(capped);
      st.adtsCarry = parsed.remainder;
      if (parsed.framesBuf && parsed.frameCount > 0) {
        st.seq += 1;
        st.chunks.push({
          seq: st.seq,
          at: Date.now(),
          format: 'aac',
          sample_rate: parsed.sampleRate,
          frame_count: parsed.frameCount,
          data_b64: parsed.framesBuf.toString('base64'),
        });
        if (st.chunks.length > 28) st.chunks.splice(0, st.chunks.length - 28);
      }
      return;
    }

    // Fallback for G.711Mu / G.711A / 16-bit PCM
    let pcmBuf;
    if (ctLower.includes('pcm') || ctLower.includes('l16')) {
      pcmBuf = inner;
    } else {
      const table = (ctLower.includes('ulaw') || ctLower.includes('mulaw') || ctLower === 'audio/basic')
        ? ULAW_TO_PCM16
        : ALAW_TO_PCM16;
      pcmBuf = Buffer.allocUnsafe(inner.length * 2);
      for (let i = 0; i < inner.length; i++) {
        pcmBuf.writeInt16LE(table[inner[i]], i * 2);
      }
    }
    st.seq += 1;
    st.chunks.push({
      seq: st.seq,
      at: Date.now(),
      format: 'pcm16',
      sample_rate: 8000,
      frame_count: 0,
      data_b64: pcmBuf.toString('base64'),
    });
    if (st.chunks.length > 28) st.chunks.splice(0, st.chunks.length - 28);
  }

  function ingestBridgeAudioChunk({ deviceId, dvrId, channel, contentType, dataB64, error }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr || dvr.bridge_device_id !== deviceId) return false;
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const lease = audioLeases.get(dvr.id);
    const isActive = Boolean(lease && lease.channel === ch && lease.until > Date.now());
    const st = getOrCreateAudioStream(`${dvr.id}:${ch}`);
    if (error) {
      st.error = String(error).slice(0, 220);
      st.errorAt = Date.now();
      return false;
    }
    if (!isActive) return false;
    if (dataB64) {
      const raw = Buffer.from(String(dataB64), 'base64');
      ingestRawAudioBytes(dvr.id, ch, contentType, raw);
    }
    return true;
  }

  async function ensureDirectAudioStream(dvr, channel) {
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const streamKey = `${dvr.id}:${ch}`;
    if (directAudioReqs.has(streamKey)) return;

    const pq = `/cgi-bin/audio.cgi?action=getAudio&httptype=singlepart&channel=${ch}`;
    const cacheKey = `${dvr.host}:${dvr.http_port}:${dvr.username}`;
    let authHdr = '';
    const cached = digestCache.get(cacheKey);
    if (!cached || !cached.challenge) {
      try {
        const probe = await rawHttpGet({ host: dvr.host, port: dvr.http_port, pathWithQuery: pq, timeoutMs: 2500 });
        const rawWww = probe.headers && probe.headers['www-authenticate'];
        const wwwStr = Array.isArray(rawWww) ? rawWww.join(', ') : String(rawWww || '');
        const chObj = parseDigestHeader(wwwStr);
        if (chObj) digestCache.set(cacheKey, { challenge: chObj, nc: 1 });
      } catch (_) {}
    }
    const curDigest = digestCache.get(cacheKey);
    if (curDigest && curDigest.challenge) {
      curDigest.nc = (curDigest.nc || 1) + 1;
      authHdr = buildDigestAuthorization({
        method: 'GET',
        uri: pq,
        username: dvr.username,
        password: dvr.password,
        challenge: curDigest.challenge,
        ncNum: curDigest.nc,
      });
    } else {
      authHdr = 'Basic ' + Buffer.from(`${dvr.username}:${dvr.password}`, 'utf8').toString('base64');
    }

    const st = getOrCreateAudioStream(streamKey);
    const req = http.request(
      {
        hostname: dvr.host,
        port: Number(dvr.http_port || 80),
        path: pq,
        method: 'GET',
        headers: {
          Authorization: authHdr,
          Accept: '*/*',
          'User-Agent': 'IT-ELKHAWGA-CCTV/1.1',
        },
      },
      (res) => {
        if (res.statusCode !== 200) {
          st.error = res.statusCode === 401
            ? 'بيانات دخول الـ DVR غير صحيحة (401)'
            : `هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت مغلق في الـ DVR (HTTP ${res.statusCode})`;
          st.errorAt = Date.now();
          res.resume();
          directAudioReqs.delete(streamKey);
          return;
        }
        const ct = String((res.headers && res.headers['content-type']) || 'Audio/AAC');
        let gotAny = false;
        res.on('data', (chunk) => {
          gotAny = true;
          const lease = audioLeases.get(dvr.id);
          if (!lease || lease.channel !== ch || lease.until <= Date.now()) {
            try { req.destroy(); } catch (_) {}
            directAudioReqs.delete(streamKey);
            return;
          }
          ingestRawAudioBytes(dvr.id, ch, ct, chunk);
        });
        res.on('end', () => {
          if (!gotAny) {
            st.error = 'هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت غير مفعّل لها في الـ DVR';
            st.errorAt = Date.now();
          }
          directAudioReqs.delete(streamKey);
        });
      }
    );
    directAudioReqs.set(streamKey, req);
    req.on('error', (err) => {
      if (!st.chunks.length) {
        st.error = 'هذه الكاميرا غير مزوّدة بمايكروفون أو تعذر فتح الصوت: ' + (err.message || '');
        st.errorAt = Date.now();
      }
      directAudioReqs.delete(streamKey);
    });
    req.end();
  }

  async function pollAudio({ dvrId, channel = 1, sinceSeq = 0 }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));

    // If audio_channels was already scanned on this DVR and this channel is NOT enabled, fail fast with a helpful message!
    if (typeof dvr.audio_channels === 'string' && dvr.audio_channels.trim().startsWith('[')) {
      try {
        const knownAudio = JSON.parse(dvr.audio_channels) || [];
        if (Array.isArray(knownAudio) && !knownAudio.includes(ch)) {
          const hint = knownAudio.length
            ? ` (الكاميرات المزوّدة بصوت في ${dvr.name}: ${knownAudio.join('، ')})`
            : ' (لا توجد كاميرات مفعّل لها الصوت حالياً في إعدادات هذا الـ DVR)';
          return {
            ok: false,
            no_mic: true,
            audio_channels: knownAudio,
            error: `🔇 الكاميرا رقم ${ch} غير مزوّدة بمايكروفون${hint}`,
          };
        }
      } catch (_) {}
    }

    const streamKey = `${dvr.id}:${ch}`;
    const st = getOrCreateAudioStream(streamKey);
    const prevLease = audioLeases.get(dvr.id);
    if (!prevLease || prevLease.channel !== ch) {
      // Fresh unmute or switched camera: clear old error & carry
      st.error = '';
      st.adtsCarry = Buffer.alloc(0);
      if (prevLease && prevLease.channel !== ch) {
        const oldDirect = directAudioReqs.get(`${dvr.id}:${prevLease.channel}`);
        if (oldDirect) {
          try { oldDirect.destroy(); } catch (_) {}
          directAudioReqs.delete(`${dvr.id}:${prevLease.channel}`);
        }
      }
    }

    audioLeases.set(dvr.id, {
      dvrId: dvr.id,
      bridgeDeviceId: dvr.connection_mode === 'bridge' ? String(dvr.bridge_device_id || '') : '',
      channel: ch,
      until: Date.now() + 7500,
    });

    if (dvr.connection_mode === 'bridge') {
      const dev = db.prepare('SELECT last_seen, label, hostname, app_version FROM devices WHERE device_id=?').get(dvr.bridge_device_id);
      const devLabel = (dev && (dev.label || dev.hostname)) || dvr.bridge_device_id;
      if (!dev || !dev.last_seen || Date.now() - Number(dev.last_seen) > 60_000) {
        throw new Error(`كمبيوتر الفرع (${devLabel}) غير متصل حالياً`);
      }
      // Seamless fallback if branch PC is still on v1.1.0 before silent upgrade to v1.1.1
      if (!isVersionAtLeast(dev.app_version, 1, 1, 1) && isVersionAtLeast(dev.app_version, 1, 1, 0) && !st.fallbackInflight) {
        st.fallbackInflight = true;
        executeDvrCgi(dvr, `/cgi-bin/audio.cgi?action=getAudio&httptype=singlepart&channel=${ch}`, {
          maxBytes: 4096,
          timeoutMs: 6500,
        })
          .then((r) => {
            if (r.statusCode === 200 && r.body && r.body.length > 0) {
              ingestRawAudioBytes(dvr.id, ch, r.contentType, r.body);
            } else {
              st.error = `هذه الكاميرا غير مزوّدة بمايكروفون (HTTP ${r.statusCode})`;
            }
          })
          .catch((e) => {
            st.error = String((e && e.message) || '').includes('Unexpected EOF')
              ? 'هذه الكاميرا غير مزوّدة بمايكروفون أو الصوت غير مفعّل لها في الـ DVR'
              : ((e && e.message) || 'تعذر جلب الصوت');
          })
          .finally(() => {
            st.fallbackInflight = false;
          });
      }
    } else {
      ensureDirectAudioStream(dvr, ch).catch(() => {});
    }

    if (st.error && (!st.chunks.length || Date.now() - st.errorAt < 5000)) {
      audioLeases.delete(dvr.id);
      return { ok: false, error: st.error };
    }

    const reqSeq = Number(sinceSeq || 0);
    const nowMs = Date.now();
    const freshChunks = st.chunks.filter((c) => nowMs - c.at < 8000);
    const outChunks = reqSeq > 0
      ? freshChunks.filter((c) => c.seq > reqSeq)
      : freshChunks.slice(-2);

    return {
      ok: true,
      seq: st.seq,
      chunks: outChunks,
    };
  }

  function stopAudio({ dvrId = '' } = {}) {
    if (dvrId) {
      const lease = audioLeases.get(dvrId);
      audioLeases.delete(dvrId);
      if (lease) {
        const req = directAudioReqs.get(`${dvrId}:${lease.channel}`);
        if (req) {
          try { req.destroy(); } catch (_) {}
          directAudioReqs.delete(`${dvrId}:${lease.channel}`);
        }
      }
    } else {
      audioLeases.clear();
      for (const req of directAudioReqs.values()) {
        try { req.destroy(); } catch (_) {}
      }
      directAudioReqs.clear();
    }
    return { ok: true };
  }

  async function handleAction({ action, payload = {}, actor = '', role = 'super' }) {
    switch (String(action || '')) {
      case 'pull_names':
        return pullChannelNames(payload.dvr_id);
      case 'detect_audio':
        return detectAudioChannels(payload.dvr_id);
      case 'poll_audio':
        return pollAudio({
          dvrId: payload.dvr_id,
          channel: payload.channel,
          sinceSeq: payload.since_seq,
        });
      case 'stop_audio':
        return stopAudio({ dvrId: payload.dvr_id });
      case 'save_channel_meta':
        return saveChannelMeta({
          dvrId: payload.dvr_id,
          channel: payload.channel,
          title: payload.title,
          hidden: payload.hidden,
        });
      case 'save_favorites':
        return { ok: true, settings: setSettings({ favorites: payload.favorites || [] }) };
      case 'save_settings':
        if (String(role).toLowerCase() !== 'super' && payload.super_only !== undefined) {
          delete payload.super_only;
        }
        return { ok: true, settings: setSettings(payload) };
      case 'check_health':
        return checkDvrHealth(payload.dvr_id);
      case 'check_all_health':
        return checkAllDvrsHealth();
      case 'search_recordings':
        return searchRecordings({
          dvrId: payload.dvr_id,
          channel: payload.channel,
          startTime: payload.start_time,
          endTime: payload.end_time,
        });
      case 'ptz':
        return ptzMove({
          dvrId: payload.dvr_id,
          channel: payload.channel,
          code: payload.code,
          speed: payload.speed,
        });
      default:
        throw new Error('إجراء كاميرات غير معروف');
    }
  }

  return {
    getSettings,
    setSettings,
    listDvrs,
    getRawDvr,
    saveDvr,
    deleteDvr,
    testDvrConnection,
    getActiveTaskForDevice,
    ingestBridgeFrame,
    ingestBridgeAudioChunk,
    getFrame,
    scanLocalLanForDahua,
    scanBranchForDahua,
    popPendingScanForDevice,
    ingestBranchScanResult,
    popPendingCgiForDevice,
    ingestBranchCgiResult,
    detectAudioChannels,
    checkDvrHealth,
    checkAllDvrsHealth,
    downloadRecordingClip,
    handleAction,
  };
}
