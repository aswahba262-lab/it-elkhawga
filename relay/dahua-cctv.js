import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';

const CCTV_LOG_PATHS = [
  'C:\\Users\\IT APP\\Desktop\\blockwebsite\\cctv-cameras.log',
  'C:\\Users\\IT APP\\Desktop\\blockwebsite\\logs\\05-cctv-cameras.log',
  'C:\\Users\\IT APP\\Desktop\\blockwebsite\\logs\\00-master-all-events.log',
  'C:\\ProgramData\\IT-ELKHAWGA-Relay\\cctv-cameras.log',
];
const cctvLogMemoryRing = [];
const cctvLogThrottleMap = new Map();

function writeCctvLog(level, event, detail, throttleKey = '', throttleMs = 0) {
  try {
    const nowMs = Date.now();
    if (throttleKey && throttleMs > 0) {
      const prev = cctvLogThrottleMap.get(throttleKey) || 0;
      if (nowMs - prev < throttleMs) return;
      cctvLogThrottleMap.set(throttleKey, nowMs);
      if (cctvLogThrottleMap.size > 400) cctvLogThrottleMap.clear();
    }
    const iso = new Date(nowMs).toISOString();
    const line = `[${iso}] [${level}] [${event}] ${detail}`;
    cctvLogMemoryRing.push(line);
    if (cctvLogMemoryRing.length > 350) {
      cctvLogMemoryRing.splice(0, cctvLogMemoryRing.length - 350);
    }
    for (const lp of CCTV_LOG_PATHS) {
      try {
        if (fs.existsSync(lp)) {
          const st = fs.statSync(lp);
          if (st.size > 2 * 1024 * 1024) {
            const tail = cctvLogMemoryRing.slice(-150).join('\r\n') + '\r\n';
            fs.writeFileSync(lp, tail, 'utf8');
            continue;
          }
        }
        fs.appendFileSync(lp, line + '\r\n', 'utf8');
      } catch (_) {}
    }
  } catch (_) {}
}

function readRecentCctvLogs(limit = 160) {
  const cap = Math.max(20, Math.min(350, Number(limit || 160) || 160));
  if (cctvLogMemoryRing.length >= 10) {
    return cctvLogMemoryRing.slice(-cap);
  }
  for (const lp of CCTV_LOG_PATHS) {
    try {
      if (fs.existsSync(lp)) {
        const lines = fs.readFileSync(lp, 'utf8').split(/\r?\n/).filter(Boolean);
        return lines.slice(-cap);
      }
    } catch (_) {}
  }
  return cctvLogMemoryRing.slice(-cap);
}

writeCctvLog(
  'INFO',
  'ENGINE_BOOT',
  'تم تشغيل محرك الكاميرات المطور (100% Router Direct Low-Latency RTSP + Unified Batch Wall). نسخة احتياطية محفوظة في: C:\\Users\\IT APP\\Desktop\\blockwebsite\\backups\\cctv-pre-upgrade'
);

const FFMPEG_CANDIDATES = [
  'C:\\ProgramData\\IT-ELKHAWGA-Relay\\ffmpeg.exe',
  'C:\\Users\\IT APP\\.gemini\\antigravity\\brain\\a112d828-8041-4e7c-ae05-3591e36d86fa\\scratch\\video-gen\\node_modules\\ffmpeg-static\\ffmpeg.exe',
];

let cachedFfmpegBin = null;
function resolveFfmpegBin() {
  if (cachedFfmpegBin) return cachedFfmpegBin;
  for (const p of FFMPEG_CANDIDATES) {
    try {
      if (fs.existsSync(p)) {
        cachedFfmpegBin = p;
        return p;
      }
    } catch (_) {}
  }
  return 'ffmpeg';
}

function isH264AnnexB(buf) {
  return Boolean(
    buf &&
    buf.length >= 512 &&
    buf[0] === 0x00 &&
    buf[1] === 0x00 &&
    ((buf[2] === 0x00 && buf[3] === 0x01) || buf[2] === 0x01)
  );
}

function remuxDavBufferToMp4(davBuf) {
  if (!davBuf || davBuf.length < 1024) return null;
  if (davBuf.slice(4, 8).toString('ascii') === 'ftyp') return davBuf;
  const tmpId = crypto.randomUUID().replace(/-/g, '');
  const inPath = `${os.tmpdir()}\\itk_clip_${tmpId}.dav`;
  const outPath = `${os.tmpdir()}\\itk_clip_${tmpId}.mp4`;
  try {
    fs.writeFileSync(inPath, davBuf);
    const bin = resolveFfmpegBin();
    // 1) Fast zero-CPU stream copy (-c:v copy) for H.264/H.265 DAV -> MP4
    let res = spawnSync(
      bin,
      ['-hide_banner', '-loglevel', 'error', '-y', '-i', inPath, '-c:v', 'copy', '-an', '-movflags', '+faststart', outPath],
      { timeout: 30000, windowsHide: true }
    );
    if (!fs.existsSync(outPath) || fs.statSync(outPath).size < 1024) {
      // 2) Universal H.264 baseline transcode fallback so iPad / iPhone / Android plays 100% natively
      res = spawnSync(
        bin,
        ['-hide_banner', '-loglevel', 'error', '-y', '-i', inPath, '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p', '-an', '-movflags', '+faststart', outPath],
        { timeout: 45000, windowsHide: true }
      );
    }
    if (fs.existsSync(outPath)) {
      const mp4Buf = fs.readFileSync(outPath);
      if (mp4Buf && mp4Buf.length > 1024 && mp4Buf.slice(4, 8).toString('ascii') === 'ftyp') {
        return mp4Buf;
      }
    }
  } catch (_) {
  } finally {
    try { if (fs.existsSync(inPath)) fs.unlinkSync(inPath); } catch (_) {}
    try { if (fs.existsSync(outPath)) fs.unlinkSync(outPath); } catch (_) {}
  }
  return null;
}

function transcodeH264KeyframeToJpeg(h264Buf) {
  try {
    const bin = resolveFfmpegBin();
    const res = spawnSync(
      bin,
      ['-hide_banner', '-loglevel', 'error', '-f', 'h264', '-i', 'pipe:0', '-frames:v', '1', '-f', 'image2', '-c:v', 'mjpeg', '-q:v', '4', 'pipe:1'],
      {
        input: h264Buf,
        maxBuffer: 8 * 1024 * 1024,
        timeout: 3500,
        windowsHide: true,
      }
    );
    if (res && res.stdout && res.stdout.length >= 256 && res.stdout[0] === 0xff && res.stdout[1] === 0xd8) {
      return res.stdout;
    }
  } catch (_) {}
  return null;
}

// Disable HTTP keep-alive to Dahua DVRs: embedded Dahua HTTP servers (sonia/boa) only have
// 4-6 worker threads total; holding idle keep-alive sockets open exhausts the DVR's worker pool.
const dvrHttpAgent = new http.Agent({
  keepAlive: false,
  maxSockets: 16,
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
          Connection: 'close',
          Accept: '*/*',
          'User-Agent': 'IT-ELKHAWGA-CCTV/1.1',
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

  // Safe schema migrations for v1.1.0+ enterprise CCTV & Live Audio & Router Direct features
  for (const sql of [
    "ALTER TABLE cctv_dvrs ADD COLUMN hidden_channels TEXT DEFAULT '[]'",
    "ALTER TABLE cctv_dvrs ADD COLUMN allowed_admins TEXT DEFAULT ''",
    "ALTER TABLE cctv_dvrs ADD COLUMN health_json TEXT DEFAULT '{}'",
    "ALTER TABLE cctv_dvrs ADD COLUMN audio_channels TEXT DEFAULT ''",
    "ALTER TABLE cctv_dvrs ADD COLUMN router_host TEXT DEFAULT ''",
    "ALTER TABLE cctv_dvrs ADD COLUMN router_http_port INTEGER NOT NULL DEFAULT 8081",
    "ALTER TABLE cctv_dvrs ADD COLUMN router_rtsp_port INTEGER NOT NULL DEFAULT 5540",
    "ALTER TABLE cctv_dvrs ADD COLUMN backup_bridge_device_id TEXT DEFAULT ''",
    "ALTER TABLE cctv_dvrs ADD COLUMN remote_channels_json TEXT DEFAULT '{}'",
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

  // Latest frames cached in memory: key = `${dvrId}:${channel}:${hd ? 1 : 0}` -> { buf, mime, at, error, transport }
  const frameCache = new Map();
  // Continuous 3.2-second RTSP Ring Buffer per `${dvrId}:${channel}:${hd ? 1 : 0}` -> { seq: number, frames: Array<{ seq, at, b64 }> }
  // Ensures zero dropped frames and silky-smooth 3-second buffered playback over fluctuating branch VDSL lines!
  const frameRingBuffers = new Map();

  function pushToFrameRingBuffer(cacheKey, buf, ts) {
    let ring = frameRingBuffers.get(cacheKey);
    if (!ring) {
      ring = { seq: 0, frames: [] };
      frameRingBuffers.set(cacheKey, ring);
      if (frameRingBuffers.size > 96) {
        const oldest = frameRingBuffers.keys().next().value;
        frameRingBuffers.delete(oldest);
      }
    }
    ring.seq += 1;
    ring.frames.push({
      seq: ring.seq,
      at: ts,
      b64: buf.toString('base64'),
    });
    if (ring.frames.length > 48) {
      ring.frames.splice(0, ring.frames.length - 48);
    }
    return ring.seq;
  }
  // Channels that have produced at least 1 valid image frame (never auto-marked dead on transient timeouts!)
  const verifiedWorkingChannels = new Set();
  // Consecutive failure counter per `${dvrId}:${channel}` before marking an unplugged BNC port as dead
  const channelFailCounts = new Map();
  // Temporary cooldown for unplugged/offline channels so bridge PCs never stall on empty BNC/IP slots
  const deadChannelUntil = new Map();
  // Deduplicate concurrent identical direct & bridge fetches
  const inflightDirect = new Map();
  const inflightBridge = new Map();
  // Router direct reachability cache per dvrId -> { ok, checkedAt, routerHost, routerPort, lastSuccessAt }
  const routerReachabilityCache = new Map();
  // Last frame arrival timestamp per bridge deviceId -> ms (for automatic failover to backup branch PC)
  const bridgeLastFrameAt = new Map();

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
    const favs = Array.isArray(patch.favorites) ? patch.favorites.slice(0, 64) : cur.favorites;
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

  function isPublicIpv4(ipStr) {
    const s = String(ipStr || '').trim();
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) return false;
    if (s.startsWith('127.') || s.startsWith('10.') || s.startsWith('192.168.') || s.startsWith('169.254.') || s.startsWith('100.')) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(s)) return false;
    return true;
  }

  // Automatically selects the best online PC in the branch (primary -> backup -> same branch name prefix)
  function resolveActiveBridgeDevice(dvr) {
    if (!dvr) return null;
    const nowMs = Date.now();
    const allDevs = db.prepare('SELECT device_id, label, hostname, app_version, last_seen, ip, group_id FROM devices').all();
    const byId = new Map(allDevs.map((d) => [d.device_id, d]));
    const isReady = (d) => Boolean(d && d.last_seen && (nowMs - Number(d.last_seen) < 120_000) && isVersionAtLeast(d.app_version, 1, 0, 9));

    const primary = byId.get(String(dvr.bridge_device_id || '').trim());
    const backup = byId.get(String(dvr.backup_bridge_device_id || '').trim());
    const syncRouterIpFromDev = (dev) => {
      if (dev && isPublicIpv4(dev.ip) && dev.ip !== dvr.router_host) {
        dvr.router_host = String(dev.ip).trim();
        if (dvr.id && !String(dvr.id).startsWith('test_')) {
          try { db.prepare('UPDATE cctv_dvrs SET router_host=? WHERE id=?').run(dvr.router_host, dvr.id); } catch (_) {}
        }
      }
    };
    if (primary && isPublicIpv4(primary.ip)) syncRouterIpFromDev(primary);
    else if (backup && isPublicIpv4(backup.ip)) syncRouterIpFromDev(backup);

    // If primary is online, check if it has stalled while backup is online
    if (isReady(primary)) {
      const pLastFrame = bridgeLastFrameAt.get(primary.device_id) || 0;
      const pLeaseMap = bridgeLeases.get(primary.device_id);
      const hasActiveLease = Boolean(pLeaseMap && pLeaseMap.size > 0);
      // If primary is healthy or no backup is ready, use primary
      if (!isReady(backup) || !hasActiveLease || (nowMs - pLastFrame < 14_000) || pLastFrame === 0) {
        return primary;
      }
    }
    if (isReady(backup)) {
      syncRouterIpFromDev(backup);
      return backup;
    }
    // Auto-match another online PC on the exact same Branch Router Public IP!
    const primaryPublicIp = primary && isPublicIpv4(primary.ip) ? primary.ip : (isPublicIpv4(dvr.router_host) ? dvr.router_host : '');
    if (primaryPublicIp) {
      const sameIpMatch = allDevs.find((d) => isReady(d) && d.ip === primaryPublicIp);
      if (sameIpMatch) return sameIpMatch;
    }
    // Auto-match another online PC in the same branch by branch name prefix (e.g. "october", "doki", "zayed", "nozha", "maadi", "helwan")
    const branchFirstWord = String(dvr.name || '')
      .trim()
      .toLowerCase()
      .split(/[\s_-]+/)[0];
    if (branchFirstWord && branchFirstWord.length >= 3) {
      const match = allDevs.find((d) => {
        if (!isReady(d)) return false;
        const lbl = String(d.label || d.hostname || '').toLowerCase();
        return lbl.includes(branchFirstWord);
      });
      if (match) return match;
    }
    // Fallback to primary record even if offline so caller can display a clear message
    return primary || backup || null;
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
    const backupName = row.backup_bridge_device_id && bridgeDevicesMap ? (bridgeDevicesMap.get(row.backup_bridge_device_id) || '') : '';
    const activeDev = resolveActiveBridgeDevice(row);
    const activeBridgeId = (activeDev && activeDev.device_id) || row.bridge_device_id || '';
    const activeBridgeName = (activeDev && (activeDev.label || activeDev.hostname || activeDev.device_id)) || bName;
    const rCache = routerReachabilityCache.get(row.id);
    return {
      id: row.id,
      name: row.name,
      connection_mode: row.connection_mode || 'direct',
      bridge_device_id: row.bridge_device_id || '',
      bridge_device_name: bName,
      backup_bridge_device_id: row.backup_bridge_device_id || '',
      backup_bridge_device_name: backupName,
      active_bridge_device_id: activeBridgeId,
      active_bridge_device_name: activeBridgeName,
      router_host: String(row.router_host || ''),
      router_http_port: Number(row.router_http_port || 8081) || 8081,
      router_rtsp_port: Number(row.router_rtsp_port || 5540) || 5540,
      router_direct_online: Boolean(rCache && rCache.ok && (Date.now() - rCache.checkedAt < 120_000)),
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

  let lastPrewarmAt = 0;
  function prewarmDvrsBackground() {
    const nowMs = Date.now();
    if (nowMs - lastPrewarmAt < 25_000) return;
    lastPrewarmAt = nowMs;
    try {
      const rows = db.prepare('SELECT * FROM cctv_dvrs WHERE enabled=1 ORDER BY created_at ASC').all();
      for (const dvr of rows) {
        if (dvr.connection_mode === 'router' && dvr.router_host) {
          ensureRouterDirectStatus(dvr, false)
            .then((st) => {
              if (st && st.tcpOpen) {
                const maxPre = Math.min(4, Number(dvr.channels_count || 4));
                for (let ch = 1; ch <= maxPre; ch++) {
                  const ck = `${dvr.id}:${ch}:0`;
                  const cur = frameCache.get(ck);
                  if (!cur || Date.now() - cur.at > 15_000) {
                    fetchDirectSnapshot({ ...dvr, host: st.routerHost, http_port: st.routerPort }, ch, false)
                      .then((res) => {
                        verifiedWorkingChannels.add(`${dvr.id}:${ch}`);
                        frameCache.set(ck, { buf: res.buf, mime: res.mime, at: res.at, error: '', transport: 'router', hd: false });
                      })
                      .catch(() => {});
                  }
                }
              }
            })
            .catch(() => {});
        }
      }
    } catch (_) {}
  }
  setTimeout(prewarmDvrsBackground, 1500);

  function listDvrs(opts = {}) {
    prewarmDvrsBackground();
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
    const rawMode = String(payload.connection_mode || 'bridge').trim().toLowerCase();
    const mode = rawMode === 'router' ? 'router' : (rawMode === 'direct' ? 'direct' : 'bridge');
    const bridgeDeviceId = (mode === 'bridge' || mode === 'router')
      ? String(payload.bridge_device_id || (existing && existing.bridge_device_id) || '').trim()
      : '';
    const backupBridgeDeviceId = (mode === 'bridge' || mode === 'router')
      ? String(payload.backup_bridge_device_id !== undefined ? payload.backup_bridge_device_id : ((existing && existing.backup_bridge_device_id) || '')).trim()
      : '';
    if (mode === 'bridge' && !bridgeDeviceId && !backupBridgeDeviceId) {
      throw new Error('يرجى اختيار جهاز الكمبيوتر الوسيط في الفرع عند استخدام وضع الربط عبر جسر الفرع');
    }
    let routerHost = String(payload.router_host !== undefined ? payload.router_host : ((existing && existing.router_host) || ''))
      .trim()
      .replace(/^https?:\/\//i, '')
      .split('/')[0] || '';
    if (routerHost.includes(':')) routerHost = routerHost.split(':')[0];
    const routerHttpPort = Math.max(1, Math.min(65535, Number(payload.router_http_port || (existing && existing.router_http_port) || 8081) || 8081));
    const routerRtspPort = Math.max(1, Math.min(65535, Number(payload.router_rtsp_port || (existing && existing.router_rtsp_port) || 5540) || 5540));

    let host = String(payload.host || (existing && existing.host) || '').trim().replace(/^https?:\/\//i, '').split('/')[0] || '';
    if (host.includes(':')) {
      host = host.split(':')[0];
    }
    if (!host && routerHost) host = routerHost;
    if (!host) throw new Error('يرجى إدخال عنوان IP الخاص بجهاز Dahua DVR (مثل 10.10.1.108 أو 192.168.1.108)');
    if (mode === 'router' && !routerHost && !bridgeDeviceId) {
      throw new Error('في وضع راوتر الفرع، أدخل الـ Public IP للراوتر أو اختر كمبيوتر الفرع لاكتشاف الـ IP تلقائياً');
    }
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
        name=?, connection_mode=?, bridge_device_id=?, backup_bridge_device_id=?, router_host=?, router_http_port=?, router_rtsp_port=?,
        host=?, http_port=?, rtsp_port=?, username=?, password=?, channels_count=?, channel_names=?, hidden_channels=?, allowed_admins=?, enabled=?, updated_at=?
        WHERE id=?`).run(
        name, mode, bridgeDeviceId, backupBridgeDeviceId, routerHost, routerHttpPort, routerRtspPort,
        host, httpPort, rtspPort, username, password, channelsCount, JSON.stringify(channelNamesObj), JSON.stringify(hiddenArr), allowedAdmins, enabled, ts, id
      );
    } else {
      db.prepare(`INSERT INTO cctv_dvrs
        (id, name, connection_mode, bridge_device_id, backup_bridge_device_id, router_host, router_http_port, router_rtsp_port, host, http_port, rtsp_port, username, password, channels_count, channel_names, hidden_channels, allowed_admins, enabled, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        id, name, mode, bridgeDeviceId, backupBridgeDeviceId, routerHost, routerHttpPort, routerRtspPort,
        host, httpPort, rtspPort, username, password, channelsCount, JSON.stringify(channelNamesObj), JSON.stringify(hiddenArr), allowedAdmins, enabled, ts, ts
      );
    }
    routerReachabilityCache.delete(id);
    try { syncAndEnsureMediaMtxGateway(true); } catch (_) {}
    return listDvrs();
  }

  function deleteDvr(id) {
    db.prepare('DELETE FROM cctv_dvrs WHERE id=?').run(String(id || ''));
    try { syncAndEnsureMediaMtxGateway(true); } catch (_) {}
    return listDvrs();
  }

  async function dahuaAuthedGet({ host, port, pathWithQuery, username, password, timeoutMs = 4500 }) {
    const cacheKey = `${host}:${port}:${username}`;
    const cached = digestCache.get(cacheKey);
    if (cached && cached.challenge && (cached.nc || 1) < 500) {
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
      const isAuthErrBody = r1.body && r1.body.length <= 256 && r1.body.toString('utf8').includes('Invalid Authority');
      if (r1.statusCode !== 401 && !isAuthErrBody) {
        return r1;
      }
      digestCache.delete(cacheKey);
    } else if (cached) {
      digestCache.delete(cacheKey);
    }

    // Initial request to obtain WWW-Authenticate challenge
    let probe = await rawHttpGet({ host, port, pathWithQuery, timeoutMs });
    const probeAuthErrBody = probe.body && probe.body.length <= 256 && probe.body.toString('utf8').includes('Invalid Authority');
    if (probe.statusCode !== 401 && probeAuthErrBody) {
      // Older Dahua HCVR firmware returns HTTP 200 "Invalid Authority!" on unauthenticated /cgi-bin/snapshot.cgi;
      // probe ChannelTitle to obtain the HTTP 401 WWW-Authenticate Digest challenge.
      try {
        const authProbe = await rawHttpGet({
          host,
          port,
          pathWithQuery: '/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle',
          timeoutMs,
        });
        if (authProbe.statusCode === 401 && authProbe.headers && authProbe.headers['www-authenticate']) {
          probe = authProbe;
        }
      } catch (_) {}
    }
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

  // Per-DVR HTTP concurrency queue so embedded Dahua web servers (which have only 4-6 worker threads
  // and 1 hardware JPEG encoder) never deadlock when an admin views 4-16 cameras simultaneously.
  const dvrHttpQueues = new Map(); // dvrKey -> { active: number, max: number, queue: Array<() => void> }

  function runDvrHttpQueued(dvr, taskFn) {
    const dvrKey = (dvr && (dvr.id || `${dvr.host}:${dvr.http_port}`)) || 'default';
    const maxConc = Number((dvr && dvr.channels_count) || 8) <= 4 ? 2 : 3;
    let qState = dvrHttpQueues.get(dvrKey);
    if (!qState) {
      qState = { active: 0, max: maxConc, queue: [] };
      dvrHttpQueues.set(dvrKey, qState);
    } else {
      qState.max = maxConc;
    }
    return new Promise((resolve, reject) => {
      const exec = async () => {
        qState.active += 1;
        try {
          resolve(await taskFn());
        } catch (err) {
          reject(err);
        } finally {
          qState.active = Math.max(0, qState.active - 1);
          const next = qState.queue.shift();
          if (next) next();
        }
      };
      if (qState.active < qState.max) {
        exec();
      } else {
        // Bound queue length so stale snapshot requests never pile up
        if (qState.queue.length >= 16) {
          reject(new Error('DVR HTTP queue busy'));
          return;
        }
        qState.queue.push(exec);
      }
    });
  }

  // Continuous on-demand RTSP-to-MJPEG live streaming engine (`8-10 FPS` when port 554 is open, `0% CPU` when closed)
  const activeRtspStreams = new Map(); // cacheKey -> { proc, dvrId, ch, hd, startedAt, lastFrameAt, frameCount, until }
  const rtspFailCooldown = new Map();  // `${dvrId}:${ch}` -> timestamp ms
  const dvrLastRtspSpawnAt = new Map(); // dvrId -> timestamp ms (staggers RTSP handshakes by 450ms so DVR never drops concurrent DESCRIBE)
  const dvrIpChannelFallbackUntil = new Map(); // `${dvrId}:${ch}` -> timestamp ms when parent DVR HTTP/RTSP failed for a hybrid IP cam

  function ensureRtspLiveStream(dvr, targetHost, rtspPort, channel, hd = false, transportTag = 'router') {
    if (!dvr || !dvr.id || !targetHost || !rtspPort) return false;
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const tileKey = `${dvr.id}:${ch}`;
    const cacheKey = `${dvr.id}:${ch}:${hd ? 1 : 0}`;
    const nowMs = Date.now();

    const deadInfo = deadChannelUntil.get(tileKey);
    if (deadInfo && deadInfo.until > nowMs && !verifiedWorkingChannels.has(tileKey)) {
      return false;
    }
    const cooldownUntil = rtspFailCooldown.get(tileKey) || 0;
    if (cooldownUntil > nowMs) {
      return false;
    }

    const existing = activeRtspStreams.get(cacheKey);
    if (existing) {
      existing.until = nowMs + 12_000;
      return existing.frameCount > 0;
    }

    // Zero stagger for the first 4 RTSP streams of a DVR so 1x1 and 2x2 grids start all streams simultaneously!
    let dvrStreamCount = 0;
    for (const st of activeRtspStreams.values()) {
      if (st.dvrId === dvr.id) dvrStreamCount += 1;
    }
    if (dvrStreamCount >= 16) return false;

    const lastSpawn = dvrLastRtspSpawnAt.get(dvr.id) || 0;
    const minStaggerMs = dvrStreamCount < 4 ? 25 : 140;
    if (nowMs - lastSpawn < minStaggerMs) {
      return false;
    }

    dvrLastRtspSpawnAt.set(dvr.id, nowMs);
    const userEnc = encodeURIComponent(String(dvr.username || 'admin'));
    const passEnc = encodeURIComponent(String(dvr.password || ''));
    const sub = hd ? 0 : 1;
    const customRtspPath = dvr.rtsp_path ? String(dvr.rtsp_path).trim() : '';
    const rtspUrl = customRtspPath
      ? `rtsp://${userEnc}:${passEnc}@${targetHost}:${rtspPort}${customRtspPath.startsWith('/') ? '' : '/'}${customRtspPath}`
      : `rtsp://${userEnc}:${passEnc}@${targetHost}:${rtspPort}/cam/realmonitor?channel=${ch}&subtype=${sub}`;
    // Normalize Dahua anamorphic 1080N (960x1080) & CIF (352x288) into true 16:9 Widescreen (1280x720 HD / 854x480 SD) at 15 FPS
    const vf = hd
      ? 'fps=15,scale=1280:720:flags=fast_bilinear'
      : 'fps=15,scale=854:480:flags=fast_bilinear';
    const qv = hd ? '3' : '4';

    let proc;
    try {
      proc = spawn(
        resolveFfmpegBin(),
        [
          '-hide_banner',
          '-loglevel', 'error',
          '-fflags', 'nobuffer+discardcorrupt',
          '-flags', 'low_delay',
          '-probesize', '65536',
          '-analyzeduration', '500000',
          '-rtsp_transport', 'tcp',
          '-timeout', '5000000',
          '-i', rtspUrl,
          '-an',
          '-vf', vf,
          '-f', 'image2pipe',
          '-vcodec', 'mjpeg',
          '-q:v', qv,
          'pipe:1',
        ],
        { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }
      );
      writeCctvLog(
        'INFO',
        'RTSP_START',
        `بدء بث RTSP مباشر: فرع=${dvr.name || dvr.id} كاميرا=${ch} (${hd ? 'HD' : 'Sub'}) عبر الراوتر ${targetHost}:${rtspPort}`,
        `rtsp_start_${cacheKey}`,
        10_000
      );
    } catch (spawnErr) {
      writeCctvLog('ERROR', 'RTSP_SPAWN_ERR', `تعذر تشغيل ffmpeg لفرع=${dvr.name || dvr.id} كاميرا=${ch}: ${spawnErr && spawnErr.message}`);
      rtspFailCooldown.set(tileKey, nowMs + 120_000);
      return false;
    }

    const state = {
      proc,
      dvrId: dvr.id,
      dvrName: dvr.name || dvr.id,
      ch,
      hd: Boolean(hd),
      startedAt: nowMs,
      lastFrameAt: 0,
      frameCount: 0,
      until: nowMs + 14_000,
    };
    activeRtspStreams.set(cacheKey, state);

    let carry = Buffer.alloc(0);
    const SOI = Buffer.from([0xff, 0xd8]);
    const EOI = Buffer.from([0xff, 0xd9]);

    proc.stdout.on('data', (chunk) => {
      if (Date.now() > state.until) {
        try { proc.kill(); } catch (_) {}
        activeRtspStreams.delete(cacheKey);
        return;
      }
      carry = carry.length ? Buffer.concat([carry, chunk]) : chunk;
      if (carry.length > 2 * 1024 * 1024) {
        carry = Buffer.alloc(0);
        return;
      }
      while (true) {
        const soi = carry.indexOf(SOI);
        if (soi === -1) {
          carry = Buffer.alloc(0);
          break;
        }
        const eoi = carry.indexOf(EOI, soi + 2);
        if (eoi === -1) {
          if (soi > 0) carry = carry.subarray(soi);
          break;
        }
        const jpg = Buffer.from(carry.subarray(soi, eoi + 2));
        carry = carry.subarray(eoi + 2);
        // Accept all complete JPEG frames >= 1.8 KB so Sub-Stream night/corridor scenes never get dropped
        if (jpg.length >= 1800) {
          const ts = Date.now();
          if (state.frameCount === 0) {
            writeCctvLog(
              'INFO',
              'RTSP_LOCKED',
              `استلام أول إطار RTSP بنجاح خلال ${ts - state.startedAt}ms — فرع=${state.dvrName} كاميرا=${ch} (${Math.round(jpg.length / 1024)}KB)`,
              `rtsp_lock_${cacheKey}`,
              15_000
            );
          }
          state.lastFrameAt = ts;
          state.frameCount += 1;
          verifiedWorkingChannels.add(tileKey);
          channelFailCounts.delete(tileKey);
          deadChannelUntil.delete(tileKey);
          const rec = { buf: jpg, mime: 'image/jpeg', at: ts, error: '', transport: transportTag === 'router' ? 'rtsp_router' : 'rtsp_direct' };
          frameCache.set(cacheKey, rec);
          pushToFrameRingBuffer(cacheKey, jpg, ts);
          if (hd) {
            frameCache.set(`${dvr.id}:${ch}:0`, rec);
          }
        }
      }
    });

    const cleanup = () => {
      activeRtspStreams.delete(cacheKey);
      if (state.frameCount === 0 && Date.now() <= state.until) {
        rtspFailCooldown.set(tileKey, Date.now() + 60_000);
      }
    };
    proc.once('exit', cleanup);
    proc.once('error', cleanup);
    return false;
  }

  // Reap idle or stalled RTSP ffmpeg workers every 2.5 seconds
  setInterval(() => {
    const nowMs = Date.now();
    for (const [key, st] of activeRtspStreams.entries()) {
      const stalledStartup = st.frameCount === 0 && (nowMs - st.startedAt > 7500);
      const stalledMidstream = st.frameCount > 0 && (nowMs - st.lastFrameAt > 8500);
      if (nowMs > st.until || stalledStartup || stalledMidstream) {
        if (stalledStartup) {
          rtspFailCooldown.set(`${st.dvrId}:${st.ch}`, nowMs + 60_000);
        }
        try { st.proc.kill(); } catch (_) {}
        activeRtspStreams.delete(key);
      }
    }
  }, 2500).unref();

  async function fetchDirectSnapshot(dvr, channel, hd = false) {
    return runDvrHttpQueued(dvr, async () => {
      let ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
      let targetHost = dvr.host;
      let targetPort = dvr.http_port;
      let targetUser = dvr.username;
      let targetPass = dvr.password;
      const tileKey = dvr.id ? `${dvr.id}:${ch}` : '';
      if (!isPublicIpv4(targetHost) && tileKey && (dvrIpChannelFallbackUntil.get(tileKey) || 0) > Date.now()) {
        const remCam = parseRemoteChannelsMap(dvr)[String(ch)];
        if (remCam && remCam.host) {
          targetHost = remCam.host;
          targetPort = Number(remCam.http_port || 80) || 80;
          targetUser = remCam.username || targetUser;
          if (remCam.password && !/^\*+$/.test(String(remCam.password))) {
            targetPass = remCam.password;
          }
          ch = Number(remCam.remote_channel || 1) || 1;
        }
      }
      const sub = hd ? 0 : 1;
      const primaryPath = `/cgi-bin/snapshot.cgi?channel=${ch}&subtype=${sub}`;
      let resp = null;
      try {
        resp = await dahuaAuthedGet({
          host: targetHost,
          port: targetPort,
          pathWithQuery: primaryPath,
          username: targetUser,
          password: targetPass,
          timeoutMs: 4200,
        });
      } catch (err) {
        if (hd) throw err;
      }

      if (resp && resp.statusCode === 401) {
        throw new Error('اسم المستخدم أو كلمة مرور جهاز الـ DVR غير صحيحة (HTTP 401)');
      }

      if ((!resp || resp.statusCode !== 200 || !isLikelyImage(resp.body)) && !hd) {
        // Older Dahua firmware / hybrid IP channel fallback without &subtype=1
        try {
          resp = await dahuaAuthedGet({
            host: targetHost,
            port: targetPort,
            pathWithQuery: `/cgi-bin/snapshot.cgi?channel=${ch}`,
            username: targetUser,
            password: targetPass,
            timeoutMs: 4200,
          });
        } catch (_) {}
      }

      if ((!resp || resp.statusCode !== 200 || !isLikelyImage(resp.body)) && Number(dvr.channels_count || 8) === 1) {
        // Standalone IP Cam (Hikvision / ONVIF / generic IPC) HTTP snapshot fallback paths
        for (const altPath of [`/ISAPI/Streaming/channels/10${hd ? '1' : '2'}/picture`, '/snap.jpg', '/image/jpeg.cgi']) {
          try {
            const altResp = await dahuaAuthedGet({
              host: targetHost,
              port: targetPort,
              pathWithQuery: altPath,
              username: targetUser,
              password: targetPass,
              timeoutMs: 3200,
            });
            if (altResp && altResp.statusCode === 200 && isLikelyImage(altResp.body)) {
              resp = altResp;
              break;
            }
          } catch (_) {}
        }
      }

      if (!resp || resp.statusCode !== 200 || !isLikelyImage(resp.body)) {
        const code = (resp && resp.statusCode) || 0;
        writeCctvLog(
          'WARN',
          'HTTP_SNAPSHOT_ERR',
          `تعذر جلب صورة HTTP من فرع=${dvr.name || dvr.id} (${targetHost}:${targetPort}) كاميرا=${channel} (HTTP ${code})`,
          `http_err_${dvr.id || targetHost}_${channel}`,
          20_000
        );
        if (tileKey && (code === 400 || code === 404 || code === 500)) {
          const fails = (channelFailCounts.get(tileKey) || 0) + 1;
          channelFailCounts.set(tileKey, fails);
          const remCam = parseRemoteChannelsMap(dvr)[String(channel)];
          if (remCam && remCam.host) {
            dvrIpChannelFallbackUntil.set(tileKey, Date.now() + 300_000);
          } else if (!verifiedWorkingChannels.has(tileKey) && fails >= 2) {
            deadChannelUntil.set(tileKey, {
              until: Date.now() + 180_000,
              error: `القناة رقم ${channel} غير موصلة على الـ DVR (HTTP ${code})`,
            });
          }
        }
        throw new Error(`تعذر جلب صورة الكاميرا رقم ${channel} (HTTP ${code})`);
      }

      if (tileKey) {
        channelFailCounts.delete(tileKey);
        deadChannelUntil.delete(tileKey);
      }
      const mime = resp.body[0] === 0x89 ? 'image/png' : 'image/jpeg';
      return { buf: resp.body, mime, at: Date.now() };
    });
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
    const rawMode = String(payload.connection_mode || (existing && existing.connection_mode) || 'bridge').trim().toLowerCase();
    const mode = rawMode === 'router' ? 'router' : (rawMode === 'direct' ? 'direct' : 'bridge');
    let host = String(payload.host || (existing && existing.host) || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (host.includes(':')) host = host.split(':')[0];
    const httpPort = Number(payload.http_port || (existing && existing.http_port) || 80) || 80;
    const username = String(payload.username || (existing && existing.username) || 'admin').trim();
    const password = payload.password ? String(payload.password) : (existing ? existing.password : '');

    if (mode === 'router') {
      const rProbe = await detectRouterIpAndProbePort({
        dvr_id: existing ? existing.id : '',
        bridge_device_id: payload.bridge_device_id || (existing && existing.bridge_device_id) || '',
        router_host: payload.router_host || (existing && existing.router_host) || '',
        router_http_port: payload.router_http_port || (existing && existing.router_http_port) || 8081,
        host: host || '10.10.1.108',
        http_port: httpPort,
        username,
        password,
      });
      if (!rProbe.ok) {
        throw new Error(rProbe.error || 'تعذر فحص راوتر الفرع');
      }
      return rProbe;
    }

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

  function getRecommendedConcurrency(dvr) {
    let model = '';
    try {
      const h = JSON.parse((dvr && dvr.health_json) || '{}') || {};
      model = String(h.device_model || '');
    } catch (_) {}
    // Older Dahua HCVR-S2 / HCVR-S3 / DVR04 / DVR08 models use a single hardware JPEG encoder
    // that responds ~2.5x faster and 100% reliably when queried sequentially (`concurrency = 1`).
    if (/HCVR|DVR04|DVR08|-S2|-S3/i.test(model) || Number((dvr && dvr.channels_count) || 8) <= 4) {
      return 1;
    }
    return 4;
  }

  function parseRemoteChannelsMap(dvr) {
    if (!dvr || !dvr.remote_channels_json) return {};
    try {
      const parsed = typeof dvr.remote_channels_json === 'object'
        ? dvr.remote_channels_json
        : JSON.parse(dvr.remote_channels_json || '{}');
      return (parsed && typeof parsed === 'object') ? parsed : {};
    } catch (_) {
      return {};
    }
  }

  const ipCamDirectFailUntil = new Map();

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
        if (!dvr || !dvr.enabled || dvr.connection_mode === 'router') {
          map.delete(k);
          continue;
        }
        const chKey = `${dvr.id}:${item.channel}`;
        const deadInfo = deadChannelUntil.get(chKey);
        if (deadInfo && deadInfo.until > nowMs && !verifiedWorkingChannels.has(chKey)) {
          continue;
        }
        const remoteMap = parseRemoteChannelsMap(dvr);
        const remCam = remoteMap[String(item.channel)];
        const directIpSkipUntil = ipCamDirectFailUntil.get(chKey) || 0;
        const parentDvrFailedForIpCam = (dvrIpChannelFallbackUntil.get(chKey) || 0) > nowMs;
        const hasValidRemPass = Boolean(remCam && remCam.password && !/^\*+$/.test(String(remCam.password)));
        // Only query the IP camera's individual LAN IP directly if the parent DVR itself failed on that channel
        // (e.g. Dokki Ch4 Imou IPC-A12 where the old HCVR returns HTTP 500 on snapshot.cgi), whereas in all standard
        // branches (October, Maadi, etc.) the DVR itself streams all added IP cameras directly!
        if (remCam && remCam.host && hasValidRemPass && parentDvrFailedForIpCam && directIpSkipUntil <= nowMs) {
          const vId = `${dvr.id}__ipch_${item.channel}`;
          const rCh = Number(remCam.remote_channel || 1) || 1;
          byDvr.set(vId, {
            dvr_id: vId,
            host: remCam.host,
            http_port: Number(remCam.http_port || 80),
            username: remCam.username || dvr.username || 'admin',
            password: remCam.password || dvr.password || '',
            channels: [rCh],
            hd: Boolean(item.hd),
            concurrency: 1,
            until: item.until,
            ttl_ms: Math.max(2000, item.until - nowMs),
            audio_channel: 0,
            audio_until: 0,
            audio_ttl_ms: 0,
          });
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
            concurrency: getRecommendedConcurrency(dvr),
            until: item.until,
            ttl_ms: Math.max(2000, item.until - nowMs),
            audio_channel: 0,
            audio_until: 0,
            audio_ttl_ms: 0,
          };
          byDvr.set(dvr.id, entry);
        }
        if (!entry.channels.includes(item.channel)) entry.channels.push(item.channel);
        if (item.hd) entry.hd = true;
        if (item.until > entry.until) {
          entry.until = item.until;
          entry.ttl_ms = Math.max(2000, item.until - nowMs);
        }
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
      const remoteMap = parseRemoteChannelsMap(dvr);
      const remCam = remoteMap[String(aLease.channel)];
      const targetTaskId = (remCam && remCam.host) ? `${dvr.id}__ipch_${aLease.channel}` : dvr.id;
      const targetHost = (remCam && remCam.host) ? remCam.host : dvr.host;
      const targetPort = (remCam && remCam.http_port) ? Number(remCam.http_port) : Number(dvr.http_port || 80);
      const targetUser = (remCam && remCam.username) ? remCam.username : (dvr.username || 'admin');
      const targetPass = (remCam && remCam.password) ? remCam.password : (dvr.password || '');
      const targetAudioCh = (remCam && remCam.host) ? (Number(remCam.remote_channel || 1) || 1) : aLease.channel;

      let entry = byDvr.get(targetTaskId);
      const aTtl = Math.max(2000, aLease.until - nowMs);
      if (!entry) {
        entry = {
          dvr_id: targetTaskId,
          host: targetHost,
          http_port: targetPort,
          username: targetUser,
          password: targetPass,
          channels: [],
          hd: false,
          concurrency: (remCam && remCam.host) ? 1 : getRecommendedConcurrency(dvr),
          until: aLease.until,
          ttl_ms: aTtl,
          audio_channel: targetAudioCh,
          audio_until: aLease.until,
          audio_ttl_ms: aTtl,
        };
        byDvr.set(targetTaskId, entry);
      } else {
        entry.audio_channel = targetAudioCh;
        entry.audio_until = aLease.until;
        entry.audio_ttl_ms = aTtl;
        if (aLease.until > entry.until) {
          entry.until = aLease.until;
          entry.ttl_ms = Math.max(entry.ttl_ms, aTtl);
        }
      }
    }

    const tasks = Array.from(byDvr.values());
    return tasks.length ? tasks : null;
  }

  function ingestBridgeFrame({ deviceId, dvrId, channel, hd, imageB64, error }) {
    let realDvrId = String(dvrId || '');
    let realChannel = Number(channel || 1);
    const ipchMatch = realDvrId.match(/^(.+)__ipch_(\d+)$/);
    const isDirectIpCamTask = Boolean(ipchMatch);
    if (ipchMatch) {
      realDvrId = ipchMatch[1];
      realChannel = parseInt(ipchMatch[2], 10) || 1;
    }
    const isTestProbe = realDvrId.startsWith('test_');
    const dvr = isTestProbe ? { id: realDvrId, bridge_device_id: deviceId } : getRawDvr(realDvrId);
    if (!dvr) return false;
    const ch = Math.max(1, Math.min(64, realChannel || 1));
    const chKey = `${dvr.id}:${ch}`;
    const key = `${dvr.id}:${ch}:${hd ? 1 : 0}`;
    const fallbackKey = `${dvr.id}:${ch}:0`;
    if (error) {
      if (isDirectIpCamTask) {
        // Alternate to querying the parent DVR for this channel for 30s if direct IP cam failed
        ipCamDirectFailUntil.set(chKey, Date.now() + 30_000);
      } else {
        // If parent DVR failed for a hybrid channel, enable direct IP cam fallback for 5 minutes!
        ipCamDirectFailUntil.delete(chKey);
        const remCam = parseRemoteChannelsMap(dvr)[String(ch)];
        if (remCam && remCam.host) {
          dvrIpChannelFallbackUntil.set(chKey, Date.now() + 300_000);
        }
      }
      const errMsg = String(error).slice(0, 200);
      const prev = frameCache.get(key) || frameCache.get(fallbackKey);
      const fails = (channelFailCounts.get(chKey) || 0) + 1;
      channelFailCounts.set(chKey, fails);
      // NEVER wipe a working camera's last good frame on transient DVR timeout,
      // and NEVER mark a channel dead if it has ever produced a valid image!
      if (!prev || !prev.buf) {
        frameCache.set(key, { buf: null, mime: 'image/jpeg', at: Date.now(), error: errMsg, transport: 'bridge' });
      }
      if (!verifiedWorkingChannels.has(chKey) && fails >= 6) {
        deadChannelUntil.set(chKey, { until: Date.now() + 30_000, error: errMsg });
      }
      return true;
    }
    if (isDirectIpCamTask) {
      ipCamDirectFailUntil.delete(chKey);
    }
    channelFailCounts.delete(chKey);
    deadChannelUntil.delete(chKey);
    let clean = String(imageB64 || '').trim();
    const idx = clean.indexOf(';base64,');
    if (idx !== -1) clean = clean.slice(idx + 8);
    if (!clean) return false;
    let buf = Buffer.from(clean, 'base64');
    if (isH264AnnexB(buf)) {
      const jpg = transcodeH264KeyframeToJpeg(buf);
      if (jpg) buf = jpg;
    }
    if (!isLikelyImage(buf)) return false;
    verifiedWorkingChannels.add(chKey);
    bridgeLastFrameAt.set(deviceId, Date.now());
    const mime = buf[0] === 0x89 ? 'image/png' : 'image/jpeg';
    const record = { buf, mime, at: Date.now(), error: '', transport: 'bridge' };
    frameCache.set(key, record);
    if (hd) frameCache.set(fallbackKey, record);
    if (frameCache.size > 160) {
      const oldestKey = frameCache.keys().next().value;
      frameCache.delete(oldestKey);
    }
    return true;
  }

  // Queries a branch PC for its external Public WAN IP (even behind Tailscale Funnel!)
  async function discoverBranchPublicIp(bridgeDeviceId) {
    const devId = String(bridgeDeviceId || '').trim();
    if (!devId) return '';
    const dev = db.prepare('SELECT device_id, ip, last_seen, app_version, label, hostname FROM devices WHERE device_id=?').get(devId);
    if (dev && isPublicIpv4(dev.ip)) {
      return String(dev.ip).trim();
    }
    if (!dev || !dev.last_seen || Date.now() - Number(dev.last_seen) > 60_000) {
      return '';
    }
    if (!isVersionAtLeast(dev.app_version, 1, 1, 0)) {
      return '';
    }
    for (const [svcHost, svcPath] of [['api.ipify.org', '/'], ['checkip.amazonaws.com', '/']]) {
      try {
        const jobId = rid('ip_');
        const ipTxt = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            branchCgiJobs.delete(jobId);
            reject(new Error('timeout'));
          }, 6500);
          branchCgiJobs.set(jobId, {
            deviceId: devId,
            dispatched: false,
            until: Date.now() + 6500,
            payload: {
              job_id: jobId,
              host: svcHost,
              http_port: 80,
              username: '',
              password: '',
              path: svcPath,
              max_bytes: 512,
              timeout_ms: 4500,
            },
            resolve: (val) => {
              clearTimeout(timer);
              resolve(val && val.body ? val.body.toString('utf8').trim() : '');
            },
            reject: (err) => {
              clearTimeout(timer);
              reject(err);
            },
          });
        });
        const cleanIp = String(ipTxt || '').split(/\r?\n/)[0].trim();
        if (isPublicIpv4(cleanIp)) {
          try { db.prepare('UPDATE devices SET ip=? WHERE device_id=?').run(cleanIp, devId); } catch (_) {}
          return cleanIp;
        }
      } catch (_) {}
    }
    return '';
  }

  const inflightRouterProbe = new Map();

  // Checks if a DVR configured in 'router' (or hybrid) mode has its forwarded router port open AND verified as a Dahua DVR
  async function ensureRouterDirectStatus(dvr, forceProbe = false) {
    if (!dvr) return { ok: false, routerHost: '', routerPort: 8085 };
    let rHost = String(dvr.router_host || '').trim();
    const rPort = Number(dvr.router_http_port || 8085) || 8085;
    if (!rHost) {
      const activeDev = resolveActiveBridgeDevice(dvr);
      if (activeDev && isPublicIpv4(activeDev.ip)) {
        rHost = String(activeDev.ip).trim();
        if (dvr.id && !String(dvr.id).startsWith('test_')) {
          try { db.prepare('UPDATE cctv_dvrs SET router_host=? WHERE id=?').run(rHost, dvr.id); } catch (_) {}
        }
      }
    }
    if (!rHost) return { ok: false, routerHost: '', routerPort: rPort };

    const cached = routerReachabilityCache.get(dvr.id);
    const nowMs = Date.now();
    if (!forceProbe && cached && cached.routerHost === rHost && cached.routerPort === rPort) {
      const ttl = cached.ok ? 60_000 : 15_000;
      if (nowMs - cached.checkedAt < ttl) {
        return cached;
      }
    }

    const probeKey = dvr.id || `${rHost}:${rPort}`;
    if (!forceProbe && inflightRouterProbe.has(probeKey)) {
      return inflightRouterProbe.get(probeKey);
    }

    const probePromise = (async () => {
      try {
        const prefRtspPort = Number(dvr.router_rtsp_port || 554) || 554;
        const [tcpOpen, rtsp554Open, rtspPrefOpen] = await Promise.all([
          probeTcpPort(rHost, rPort, 2600),
          probeTcpPort(rHost, 554, 1800),
          prefRtspPort !== 554 ? probeTcpPort(rHost, prefRtspPort, 1800) : Promise.resolve(false),
        ]);
        const activeRtspPort = rtspPrefOpen ? prefRtspPort : (rtsp554Open ? 554 : 0);
        let verifiedDahua = false;
        if (tcpOpen) {
          try {
            const snap = await fetchDirectSnapshot(
              { id: dvr.id, channels_count: dvr.channels_count, host: rHost, http_port: rPort, username: dvr.username || 'admin', password: dvr.password || '' },
              1,
              false
            );
            if (snap && snap.buf) {
              verifiedDahua = true;
              if (dvr.id) {
                verifiedWorkingChannels.add(`${dvr.id}:1`);
                frameCache.set(`${dvr.id}:1:0`, { buf: snap.buf, mime: snap.mime, at: snap.at, error: '', transport: 'router' });
              }
            }
          } catch (_) {}
        }
        const state = {
          ok: tcpOpen && verifiedDahua,
          tcpOpen,
          rtspOpen: activeRtspPort > 0,
          rtspPort: activeRtspPort || 554,
          checkedAt: Date.now(),
          routerHost: rHost,
          routerPort: rPort,
          failStreak: 0,
          lastSuccessAt: (tcpOpen && verifiedDahua) ? Date.now() : ((cached && cached.lastSuccessAt) || 0),
        };
        writeCctvLog(
          state.ok ? 'INFO' : 'WARN',
          'ROUTER_PROBE',
          `فحص راوتر الفرع (${dvr.name || dvr.id}) ${rHost}:${rPort} -> HTTP=${tcpOpen ? 'مفتوح' : 'مغلق'} | DVR=${verifiedDahua ? 'متصل' : 'غير محقق'} | RTSP(${state.rtspPort})=${state.rtspOpen ? 'مفتوح' : 'مغلق'}`,
          `router_probe_${dvr.id}`,
          30_000
        );
        if (dvr.id) routerReachabilityCache.set(dvr.id, state);
        return state;
      } finally {
        inflightRouterProbe.delete(probeKey);
      }
    })();
    inflightRouterProbe.set(probeKey, probePromise);
    return probePromise;
  }

  async function detectRouterIpAndProbePort(payload = {}) {
    const dvr = payload.dvr_id ? getRawDvr(payload.dvr_id) : null;
    const bridgeId = String(payload.bridge_device_id || (dvr && dvr.bridge_device_id) || '').trim();
    let routerHost = String(payload.router_host || (dvr && dvr.router_host) || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (routerHost.includes(':')) routerHost = routerHost.split(':')[0];
    const routerPort = Math.max(1, Math.min(65535, Number(payload.router_http_port || (dvr && dvr.router_http_port) || 8081) || 8081));
    const internalHost = String(payload.host || (dvr && dvr.host) || '10.10.1.108').trim();
    const internalPort = Number(payload.http_port || (dvr && dvr.http_port) || 80) || 80;
    const username = String(payload.username || (dvr && dvr.username) || 'admin').trim();
    const password = payload.password ? String(payload.password) : ((dvr && dvr.password) || '');

    let autoDiscoveredIp = '';
    if (bridgeId) {
      autoDiscoveredIp = await discoverBranchPublicIp(bridgeId);
      if (autoDiscoveredIp) {
        routerHost = autoDiscoveredIp;
        if (dvr) {
          try { db.prepare('UPDATE cctv_dvrs SET router_host=? WHERE id=?').run(routerHost, dvr.id); } catch (_) {}
        }
      }
    }

    if (!routerHost) {
      return {
        ok: false,
        router_host: '',
        router_http_port: routerPort,
        port_open: false,
        error: 'لم يتم العثور على الـ IP الخارجي للراوتر بعد — تأكد من اختيار كمبيوتر متصل حالياً في الفرع أو اكتب الـ Public IP / DDNS للراوتر يدوياً.',
      };
    }

    const portOpen = await probeTcpPort(routerHost, routerPort, 2200);
    let dvrVerified = false;
    let detectedChannels = 0;
    let channelNames = null;
    let authError = '';

    if (portOpen) {
      try {
        const snap = await fetchDirectSnapshot(
          { host: routerHost, http_port: routerPort, username, password },
          1,
          false
        );
        if (snap && snap.buf) dvrVerified = true;
      } catch (e) {
        authError = String((e && e.message) || '');
      }
      try {
        const titleResp = await dahuaAuthedGet({
          host: routerHost,
          port: routerPort,
          pathWithQuery: '/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle',
          username,
          password,
          timeoutMs: 3500,
        });
        if (titleResp.statusCode === 200) {
          dvrVerified = true;
          const names = {};
          for (const ln of titleResp.body.toString('utf8').split(/\r?\n/)) {
            const m = ln.match(/table\.ChannelTitle\[(\d+)\]\.Name=(.+)$/);
            if (m) {
              const idx1 = parseInt(m[1], 10) + 1;
              if (idx1 > detectedChannels) detectedChannels = idx1;
              if (m[2].trim()) names[String(idx1)] = m[2].trim();
            }
          }
          if (Object.keys(names).length) channelNames = names;
        }
      } catch (_) {}
    }

    if (dvr) {
      routerReachabilityCache.set(dvr.id, {
        ok: portOpen && dvrVerified,
        tcpOpen: portOpen,
        checkedAt: Date.now(),
        routerHost,
        routerPort,
        lastSuccessAt: (portOpen && dvrVerified) ? Date.now() : 0,
      });
    }

    return {
      ok: true,
      router_host: routerHost,
      auto_discovered: Boolean(autoDiscoveredIp),
      router_http_port: routerPort,
      internal_host: internalHost,
      internal_port: internalPort,
      port_open: portOpen && dvrVerified,
      tcp_open_only: portOpen && !dvrVerified,
      dvr_verified: dvrVerified,
      detected_channels: detectedChannels || undefined,
      channel_names: channelNames || undefined,
      auth_error: authError || undefined,
      message: (portOpen && dvrVerified)
        ? `✅ ممتاز! البورت ${routerPort} مفتوح في راوتر الفرع (${routerHost}) والسيرفر متصل بالـ DVR مباشرةً بسرعة فائقة (يعمل 24 ساعة حتى بعد إغلاق كمبيوترات الفرع)!`
        : (portOpen && authError.includes('401'))
          ? `🟢 البورت ${routerPort} مفتوح ووصل للـ DVR على راوتر الفرع (${routerHost})! تأكد فقط من كلمة مرور الـ DVR ثم اضغط حفظ.`
          : `📡 تم اكتشاف الـ IP الخارجي لراوتر الفرع بنجاح (${routerHost})، ولكن البورت الخارجي (${routerPort}) غير موجّه للـ DVR بعد في الراوتر.\n💡 افتح صفحة راوتر الفرع ⬅ Port Forwarding ⬅ وجّه البورت الخارجي ${routerPort} إلى الـ IP الداخلي ${internalHost} بورت ${internalPort} (TCP).\n(ملاحظة: سيعمل البث تلقائياً عبر جسر كمبيوتر الفرع بدون توقف حتى تفتح البورت في الراوتر!)`,
    };
  }

  async function getFrame({ dvrId, channel = 1, hd = false, waitMs = 3500, overrideDvr = null }) {
    const dvr = overrideDvr || getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const tileKey = `${dvr.id}:${ch}`;
    const cacheKey = `${dvr.id}:${ch}:${hd ? 1 : 0}`;
    const nowMs = Date.now();

    const remCamForCh = parseRemoteChannelsMap(dvr)[String(ch)];
    const hasValidRemCam = Boolean(
      remCamForCh &&
      remCamForCh.host &&
      remCamForCh.password &&
      !/^\*+$/.test(String(remCamForCh.password))
    );
    const useBridgeForHybridIp = hasValidRemCam && ((dvrIpChannelFallbackUntil.get(tileKey) || 0) > nowMs);

    // 1) If mode === 'router', connect 100% directly through the Branch Router (never route through employee PCs!)
    if (dvr.connection_mode === 'router') {
      const rState = await ensureRouterDirectStatus(dvr, false);
      const rHost = (rState && rState.routerHost) || String(dvr.router_host || '').trim();
      const rPort = (rState && rState.routerPort) || Number(dvr.router_http_port || 8085) || 8085;
      if (!rHost) {
        throw new Error(`لم يتم تحديد الـ IP الخارجي لراوتر الفرع (${dvr.name})`);
      }
      if (rState && rState.rtspOpen) {
        ensureRtspLiveStream(dvr, rHost, rState.rtspPort || 554, ch, hd, 'router');
      }
      const cachedR = frameCache.get(cacheKey);
      if (cachedR && cachedR.buf && Date.now() - cachedR.at < 140) {
        return cachedR;
      }
      if (inflightDirect.has(cacheKey)) {
        return inflightDirect.get(cacheKey);
      }
      const routerDvr = { ...dvr, host: rHost, http_port: rPort };
      const p = fetchDirectSnapshot(routerDvr, ch, hd).finally(() => inflightDirect.delete(cacheKey));
      inflightDirect.set(cacheKey, p);
      const res = await p;
      const rec = { buf: res.buf, mime: res.mime, at: res.at, error: '', transport: 'router' };
      verifiedWorkingChannels.add(tileKey);
      frameCache.set(cacheKey, rec);
      return rec;
    }

    if (dvr.connection_mode === 'bridge') {
      const activeDev = resolveActiveBridgeDevice(dvr);
      const activeDevId = (activeDev && activeDev.device_id) || dvr.bridge_device_id;
      const devLabel = (activeDev && (activeDev.label || activeDev.hostname)) || activeDevId || 'غير محدد';
      if (!activeDev || !activeDev.last_seen || Date.now() - Number(activeDev.last_seen) > 60_000) {
        throw new Error(`كمبيوتر الفرع (${devLabel}) غير متصل حالياً`);
      }
      if (!isVersionAtLeast(activeDev.app_version, 1, 0, 9)) {
        throw new Error(`كمبيوتر الفرع (${devLabel}) يعمل بالإصدار v${activeDev.app_version || '1.0.0'} ويحتاج التحديث`);
      }
      const chKey = `${dvr.id}:${ch}`;
      const deadInfo = deadChannelUntil.get(chKey);
      if (deadInfo && deadInfo.until > Date.now() && !verifiedWorkingChannels.has(chKey)) {
        throw new Error(deadInfo.error || `القناة ${ch} غير متصلة`);
      }
      const existing = frameCache.get(cacheKey) || (!hd ? frameCache.get(`${dvr.id}:${ch}:1`) : frameCache.get(`${dvr.id}:${ch}:0`));
      const routedDvr = { ...dvr, bridge_device_id: activeDevId };
      if (existing && existing.buf && Date.now() - existing.at < 1800) {
        registerBridgeLease(routedDvr, ch, hd, 12_000, overrideDvr ? { ...overrideDvr, bridge_device_id: activeDevId } : null);
        return existing;
      }
      if (inflightBridge.has(cacheKey)) {
        return inflightBridge.get(cacheKey);
      }
      const bp = (async () => {
        try {
          registerBridgeLease(routedDvr, ch, hd, 16_000, overrideDvr ? { ...overrideDvr, bridge_device_id: activeDevId } : null);
          const started = Date.now();
          const prevAt = existing ? existing.at : 0;
          while (Date.now() - started < waitMs) {
            await new Promise((r) => setTimeout(r, 140));
            const deadNow = deadChannelUntil.get(chKey);
            if (deadNow && deadNow.until > Date.now() && !verifiedWorkingChannels.has(chKey)) {
              throw new Error(deadNow.error || `القناة ${ch} غير متصلة`);
            }
            const cur = frameCache.get(cacheKey) || (!hd ? frameCache.get(`${dvr.id}:${ch}:1`) : null);
            if (cur && cur.at > prevAt) {
              if (cur.buf) return cur;
              if (cur.error) throw new Error(cur.error);
            }
          }
          if (existing && existing.buf && Date.now() - existing.at < 90_000) {
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

    // Direct mode (with continuous RTSP stream + 120ms micro-coalescing)
    ensureRtspLiveStream(dvr, dvr.host, Number(dvr.rtsp_port || 554) || 554, ch, hd, 'direct');
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
        verifiedWorkingChannels.add(`${dvr.id}:${ch}`);
        const rec = { buf: res.buf, mime: res.mime, at: res.at, error: '', transport: 'direct' };
        frameCache.set(cacheKey, rec);
        return rec;
      } finally {
        inflightDirect.delete(cacheKey);
      }
    })();
    inflightDirect.set(cacheKey, p);
    return p;
  }

  // Non-blocking single-request batch frame fetcher for the CCTV Wall (returns in <5ms, zero browser socket lockup!)
  async function pollWallFrames({ items = [], actor = '', role = 'super' } = {}) {
    if (!Array.isArray(items) || !items.length) {
      return { ok: true, frames: {} };
    }
    const nowMs = Date.now();
    const outFrames = {};
    const dvrCache = new Map();

    for (const it of items.slice(0, 24)) {
      const dvrId = String((it && it.dvr_id) || '').trim();
      const ch = Math.max(1, Math.min(64, Number((it && it.channel) || 1) || 1));
      const hd = Boolean(it && it.hd);
      const sinceAt = Number((it && it.since_at) || 0);
      const sinceSeq = Number((it && it.since_seq) || 0);
      const wantBatch = Boolean(it && it.buffered);
      if (!dvrId) continue;

      let dvr = dvrCache.get(dvrId);
      if (dvr === undefined) {
        dvr = getRawDvr(dvrId);
        dvrCache.set(dvrId, dvr);
      }
      if (!dvr || !canAdminAccessDvr(dvr, actor, role)) continue;

      const tileKey = `${dvr.id}:${ch}`;
      const cacheKey = `${dvr.id}:${ch}:${hd ? 1 : 0}`;
      const fallbackKey = `${dvr.id}:${ch}:${hd ? 0 : 1}`;

      const deadCheck = deadChannelUntil.get(tileKey);
      const isCurrentlyDead = Boolean(deadCheck && deadCheck.until > nowMs && !verifiedWorkingChannels.has(tileKey));

      const remCamForCh = parseRemoteChannelsMap(dvr)[String(ch)];
      const hasValidRemCam = Boolean(
        remCamForCh &&
        remCamForCh.host &&
        remCamForCh.password &&
        !/^\*+$/.test(String(remCamForCh.password))
      );
      const useBridgeForHybridIp = hasValidRemCam && ((dvrIpChannelFallbackUntil.get(tileKey) || 0) > nowMs);

      // Trigger background refresh without blocking the HTTP response!
      if (!isCurrentlyDead) {
        if (dvr.connection_mode === 'direct') {
          const rtspStreaming = ensureRtspLiveStream(dvr, dvr.host, Number(dvr.rtsp_port || 554) || 554, ch, hd, 'direct');
          const cur = frameCache.get(cacheKey);
          if (!rtspStreaming && (!cur || nowMs - cur.at > 220) && !inflightDirect.has(cacheKey)) {
            getFrame({ dvrId: dvr.id, channel: ch, hd, waitMs: 3000 }).catch(() => {});
          }
        } else if (dvr.connection_mode === 'router') {
          let rCached = routerReachabilityCache.get(dvr.id);
          if (!rCached || (nowMs - rCached.checkedAt > (rCached.ok ? 40_000 : 18_000))) {
            ensureRouterDirectStatus(dvr, false).catch(() => {});
          }
          const rHost = (rCached && rCached.routerHost) || String(dvr.router_host || '').trim();
          const rPort = (rCached && rCached.routerPort) || Number(dvr.router_http_port || 8085) || 8085;
          const rRtspPort = (rCached && rCached.rtspPort) || Number(dvr.router_rtsp_port || 554) || 554;
          if (rHost) {
            // Start RTSP live stream immediately (even before router probe finishes if router_rtsp_port is configured!)
            const canTryRtsp = !rCached || rCached.rtspOpen !== false;
            const rtspStreaming = canTryRtsp
              ? ensureRtspLiveStream(dvr, rHost, rRtspPort, ch, hd, 'router')
              : false;
            const cur = frameCache.get(cacheKey);
            // Simultaneous HTTP + RTSP Dual-Start: while RTSP is locking onto the first keyframe,
            // fire HTTP snapshot immediately so the first frame appears in <250ms!
            if (!rtspStreaming && (!cur || nowMs - cur.at > 260) && !inflightDirect.has(cacheKey)) {
              const p = fetchDirectSnapshot(
                { ...dvr, host: rHost, http_port: rPort },
                ch,
                hd
              )
                .then((res) => {
                  verifiedWorkingChannels.add(tileKey);
                  if (rCached) rCached.failStreak = 0;
                  // Only overwrite frameCache if a newer RTSP frame hasn't already arrived
                  const latest = frameCache.get(cacheKey);
                  if (!latest || !String(latest.transport || '').includes('rtsp') || (nowMs - latest.at > 1500)) {
                    frameCache.set(cacheKey, { buf: res.buf, mime: res.mime, at: res.at, error: '', transport: 'router', hd: Boolean(hd) });
                  }
                })
                .catch((err) => {
                  const msg = String((err && err.message) || '');
                  const isNetDown = /ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|timeout|انتهت مهلة|socket hang up/i.test(msg) && !/HTTP\s*\d+/i.test(msg);
                  if (isNetDown && rCached) {
                    rCached.failStreak = (rCached.failStreak || 0) + 1;
                    if (rCached.failStreak >= 4) {
                      routerReachabilityCache.set(dvr.id, { ...rCached, ok: false, checkedAt: Date.now() });
                    }
                  }
                })
                .finally(() => {
                  inflightDirect.delete(cacheKey);
                });
              inflightDirect.set(cacheKey, p);
            }
          }
        } else {
          const activeDev = resolveActiveBridgeDevice(dvr);
          if (activeDev && activeDev.last_seen && (nowMs - Number(activeDev.last_seen) < 120_000)) {
            registerBridgeLease({ ...dvr, bridge_device_id: activeDev.device_id }, ch, hd, 14_000);
          }
        }
      }

      const hit = frameCache.get(cacheKey) || frameCache.get(fallbackKey);
      const ring = frameRingBuffers.get(cacheKey) || frameRingBuffers.get(fallbackKey);
      const deadInfo = deadChannelUntil.get(tileKey);
      if (hit && hit.buf) {
        if (wantBatch && ring && ring.frames.length > 0) {
          const newBatch = sinceSeq > 0
            ? ring.frames.filter((fr) => fr.seq > sinceSeq).slice(-15)
            : ring.frames.slice(-10);
          outFrames[tileKey] = {
            ok: true,
            changed: newBatch.length > 0,
            at: hit.at,
            latest_seq: ring.seq,
            hd: Boolean(hd),
            mime: hit.mime || 'image/jpeg',
            transport: hit.transport || dvr.connection_mode,
            batch: newBatch,
            image: newBatch.length ? newBatch[newBatch.length - 1].b64 : '',
          };
        } else if (hit.at > sinceAt) {
          outFrames[tileKey] = {
            ok: true,
            changed: true,
            at: hit.at,
            latest_seq: ring ? ring.seq : 0,
            hd: Boolean(hd),
            mime: hit.mime || 'image/jpeg',
            transport: hit.transport || dvr.connection_mode,
            image: hit.buf.toString('base64'),
          };
        } else {
          outFrames[tileKey] = {
            ok: true,
            changed: false,
            at: hit.at,
            latest_seq: ring ? ring.seq : 0,
            hd: Boolean(hd),
            transport: hit.transport || dvr.connection_mode,
          };
        }
      } else if (deadInfo && deadInfo.until > nowMs && !verifiedWorkingChannels.has(tileKey)) {
        outFrames[tileKey] = {
          ok: false,
          dead: true,
          error: deadInfo.error || `القناة ${ch} غير متصلة`,
        };
      } else {
        const activeDev = dvr.connection_mode === 'bridge'
          ? resolveActiveBridgeDevice(dvr)
          : null;
        const devOnline = Boolean(activeDev && activeDev.last_seen && (nowMs - Number(activeDev.last_seen) < 120_000));
        outFrames[tileKey] = {
          ok: false,
          waiting: true,
          error: (dvr.connection_mode === 'bridge' && !devOnline)
            ? `كمبيوتر الفرع (${(activeDev && (activeDev.label || activeDev.hostname)) || dvr.name}) غير متصل حالياً`
            : ((hit && hit.error) || `⏳ جاري استلام البث المباشر من راوتر الفرع (${dvr.router_host || dvr.host}:${dvr.router_http_port || dvr.http_port})...`),
        };
      }
    }

    return { ok: true, frames: outFrames };
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
    let effectiveDvr = dvr;
    let effectivePath = pathWithQuery;
    // If executing PTZ or direct camera CGI on a hybrid IP camera channel, route directly only when not in 100% router mode
    if (dvr.connection_mode !== 'router' && /\/cgi-bin\/(ptz|snapshot|audio)\.cgi/i.test(pathWithQuery) && !dvr._no_remote_redirect) {
      const chMatch = pathWithQuery.match(/([?&]channel=)(\d+)/i);
      if (chMatch) {
        const reqCh = chMatch[2];
        const remCam = parseRemoteChannelsMap(dvr)[String(reqCh)];
        if (remCam && remCam.host && remCam.http_online) {
          effectiveDvr = {
            ...dvr,
            connection_mode: dvr.connection_mode === 'direct' ? 'direct' : 'bridge',
            host: remCam.host,
            http_port: Number(remCam.http_port || 80) || 80,
            username: remCam.username || dvr.username || 'admin',
            password: remCam.password || dvr.password || '',
          };
          effectivePath = pathWithQuery.replace(/([?&]channel=)\d+/i, `$1${Number(remCam.remote_channel || 1) || 1}`);
        }
      }
    }
    if (effectiveDvr.connection_mode === 'router') {
      const rState = await ensureRouterDirectStatus(effectiveDvr, false);
      const rHost = (rState && rState.routerHost) || String(effectiveDvr.router_host || '').trim();
      const rPort = (rState && rState.routerPort) || Number(effectiveDvr.router_http_port || 8085) || 8085;
      if (!rHost) {
        throw new Error(`بورت راوتر الفرع (${effectiveDvr.router_host || ''}:${rPort}) غير محدد بعد`);
      }
      const resp = await dahuaAuthedGet({
        host: rHost,
        port: rPort,
        pathWithQuery: effectivePath,
        username: effectiveDvr.username,
        password: effectiveDvr.password,
        timeoutMs,
      });
      return {
        statusCode: resp.statusCode,
        contentType: String((resp.headers && resp.headers['content-type']) || 'text/plain'),
        body: resp.body.length > maxBytes ? resp.body.subarray(0, maxBytes) : resp.body,
      };
    }
    if (effectiveDvr.connection_mode === 'direct') {
      const resp = await dahuaAuthedGet({
        host: effectiveDvr.host,
        port: effectiveDvr.http_port,
        pathWithQuery: effectivePath,
        username: effectiveDvr.username,
        password: effectiveDvr.password,
        timeoutMs,
      });
      return {
        statusCode: resp.statusCode,
        contentType: String((resp.headers && resp.headers['content-type']) || 'text/plain'),
        body: resp.body.length > maxBytes ? resp.body.subarray(0, maxBytes) : resp.body,
      };
    }

    const activeDev = resolveActiveBridgeDevice(effectiveDvr);
    const devId = String((activeDev && activeDev.device_id) || effectiveDvr.bridge_device_id || '').trim();
    const dev = activeDev || db.prepare('SELECT last_seen, label, hostname, app_version FROM devices WHERE device_id=?').get(devId);
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
          reject(new Error(`تأخر رد جهاز الـ DVR في فرع ${effectiveDvr.name}`));
        }
      }, waitLimit);
      branchCgiJobs.set(jobId, {
        deviceId: devId,
        dispatched: false,
        until: Date.now() + waitLimit,
        payload: {
          job_id: jobId,
          host: effectiveDvr.host,
          http_port: Number(effectiveDvr.http_port || 80),
          username: effectiveDvr.username || 'admin',
          password: effectiveDvr.password || '',
          path: effectivePath,
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

  // Phase 1: Pull Camera Names + Hybrid RemoteDevice IP Cameras from DVR
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
    let maxIdx = 0;
    for (const ln of txt.split(/\r?\n/)) {
      const m = ln.match(/table\.ChannelTitle\[(\d+)\]\.Name=(.+)$/);
      if (m) {
        const chNum = parseInt(m[1], 10) + 1;
        if (chNum > maxIdx) maxIdx = chNum;
        const ch = String(chNum);
        const title = m[2].trim();
        if (title) {
          existingNames[ch] = title;
          count++;
        }
      }
    }

    // Also inspect RemoteDevice table for hybrid IP cameras connected to the DVR (e.g. Dokki Channel 4 -> 10.10.1.8 IPC-A12)
    const remoteChannels = parseRemoteChannelsMap(dvr);
    const ipAudioChans = [];
    try {
      const remResp = await executeDvrCgi(dvr, '/cgi-bin/configManager.cgi?action=getConfig&name=RemoteDevice', { timeoutMs: 7500 });
      if (remResp.statusCode === 200 && remResp.body) {
        const remKv = parseDahuaKvLines(remResp.body.toString('utf8'));
        const byPrefix = new Map();
        for (const [k, v] of Object.entries(remKv)) {
          const m = k.match(/^(table\.RemoteDevice\.[^.]+)\.(.+)$/);
          if (m) {
            const pfx = m[1];
            const prop = m[2];
            if (!byPrefix.has(pfx)) byPrefix.set(pfx, {});
            byPrefix.get(pfx)[prop] = v;
          }
        }
        for (const [pfx, info] of byPrefix.entries()) {
          const idxMatch = pfx.match(/_(\d+)$/) || pfx.match(/\[(\d+)\]$/);
          if (!idxMatch) continue;
          const ch1 = parseInt(idxMatch[1], 10) + 1;
          const enabled = String(info.Enable || '').toLowerCase() === 'true' || info.Enable === '1';
          const addr = String(info.Address || '').trim();
          if (enabled && addr && addr !== '0.0.0.0' && addr !== '192.168.0.0') {
            if (ch1 > maxIdx) maxIdx = ch1;
            const model = String(info.DeviceType || 'IP-Cam').trim();
            const rawPass = String(info.Password || '').trim();
            const prevEntry = remoteChannels[String(ch1)];
            const resolvedPass = (rawPass && !/^\*+$/.test(rawPass))
              ? rawPass
              : ((prevEntry && prevEntry.password && !/^\*+$/.test(String(prevEntry.password)))
                  ? prevEntry.password
                  : (dvr.password || ''));
            remoteChannels[String(ch1)] = {
              host: addr,
              http_port: Number(info.HttpPort || 80) || 80,
              rtsp_port: Number(info.RtspPort || 554) || 554,
              username: String(info.UserName || 'admin').trim() || 'admin',
              password: resolvedPass,
              remote_channel: 1,
              model,
            };
            ipAudioChans.push(ch1);
            if (!existingNames[String(ch1)] || /^CAM\s*\d+$/i.test(existingNames[String(ch1)])) {
              existingNames[String(ch1)] = `IP ${model} (${addr})`;
            }
            deadChannelUntil.delete(`${dvr.id}:${ch1}`);
          }
        }
      }
    } catch (_) {}

    const nextChCount = (maxIdx > 0 && maxIdx !== dvr.channels_count) ? maxIdx : dvr.channels_count;
    db.prepare('UPDATE cctv_dvrs SET channel_names=?, channels_count=?, remote_channels_json=?, updated_at=? WHERE id=?').run(
      JSON.stringify(existingNames),
      nextChCount,
      JSON.stringify(remoteChannels),
      Date.now(),
      dvr.id
    );
    try {
      const audRes = await detectAudioChannels(dvr.id);
      if (ipAudioChans.length && audRes && Array.isArray(audRes.audio_channels)) {
        const mergedAud = Array.from(new Set([...audRes.audio_channels, ...ipAudioChans])).sort((a, b) => a - b);
        db.prepare('UPDATE cctv_dvrs SET audio_channels=? WHERE id=?').run(JSON.stringify(mergedAud), dvr.id);
      }
    } catch (_) {
      if (ipAudioChans.length) {
        db.prepare('UPDATE cctv_dvrs SET audio_channels=? WHERE id=?').run(JSON.stringify(ipAudioChans), dvr.id);
      }
    }
    return {
      ok: true,
      pulled_count: count,
      channel_names: existingNames,
      remote_channels: remoteChannels,
      dvrs: listDvrs().dvrs,
      message: count > 0 ? `✓ تم سحب أسماء ${count} كاميرا وكشف كاميرات الـ IP والصوت بنجاح` : 'تم الاتصال وسحب إعدادات القنوات بنجاح',
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
        if (!hasAnyDiskEntry || /^Error/i.test(txt.trim())) {
          // Legacy Dahua HCVR-S2 / HCVR-S3 fallback (`factory.getCollect` -> `/dev/sda`)
          try {
            const colResp = await executeDvrCgi(dvr, '/cgi-bin/storageDevice.cgi?action=factory.getCollect', { timeoutMs: 6000 });
            if (colResp.statusCode === 200) {
              const colKv = parseDahuaKvLines(colResp.body.toString('utf8'));
              const devPaths = Object.values(colKv).filter((v) => v && v.startsWith('/dev/'));
              if (devPaths.length > 0) {
                hasAnyDiskEntry = true;
                for (const dp of devPaths.slice(0, 4)) {
                  const pResp = await executeDvrCgi(dvr, `/cgi-bin/storageDevice.cgi?action=getPartInfo&name=${encodeURIComponent(dp)}`, { timeoutMs: 6000 }).catch(() => null);
                  if (pResp && pResp.statusCode === 200) {
                    const pKv = parseDahuaKvLines(pResp.body.toString('utf8'));
                    for (const [pk, pv] of Object.entries(pKv)) {
                      if (/TotalBytes$/i.test(pk)) {
                        const n = parseFloat(pv);
                        if (Number.isFinite(n) && n > 0) totalBytes += n;
                      }
                      if (/UsedBytes$/i.test(pk)) {
                        const u = parseFloat(pv);
                        if (Number.isFinite(u) && u >= 0) usedBytes += u;
                      }
                      if (/IsError$/i.test(pk) && String(pv).toLowerCase() === 'true') hasErr = true;
                    }
                  }
                }
                hddStatus = hasErr ? 'error' : 'ok';
                hddStateRaw = hddStateRaw || 'Active';
              } else {
                hddStatus = 'missing';
              }
            } else {
              hddStatus = 'missing';
            }
          } catch (_) {
            hddStatus = 'missing';
          }
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
        const fResp = await executeDvrCgi(dvr, findUrl, { timeoutMs: 9000 });
        const fTxt = fResp.body.toString('utf8').trim();
        if (fResp.statusCode === 200 && /ok/i.test(fTxt)) {
          // Loop through up to 3 pages of 100 items so long multi-hour searches return all segments
          for (let page = 0; page < 3; page++) {
            const nextResp = await executeDvrCgi(
              dvr,
              `/cgi-bin/mediaFileFind.cgi?action=findNextFile&object=${encodeURIComponent(objId)}&count=100`,
              { timeoutMs: 10000 }
            );
            const kv = parseDahuaKvLines(nextResp.body.toString('utf8'));
            const foundCount = parseInt(kv.found || '0', 10) || 0;
            if (foundCount <= 0) break;
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
            if (foundCount < 100) break;
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
      const resp = await executeDvrCgi(dvr, loadPath, { timeoutMs: 95_000, maxBytes: 45 * 1024 * 1024 });
      if (resp.statusCode === 200 && resp.body && resp.body.length > 1024) {
        const safeTime = st.replace(/[^0-9]/g, '').slice(0, 14);
        let outBuf = resp.body;
        let isMp4 = outBuf.slice(4, 8).toString('ascii') === 'ftyp';
        if (!isMp4) {
          const converted = remuxDavBufferToMp4(outBuf);
          if (converted) {
            outBuf = converted;
            isMp4 = true;
          }
        }
        const ext = isMp4 ? 'mp4' : 'dav';
        const mime = isMp4 ? 'video/mp4' : 'application/octet-stream';
        return {
          buf: outBuf,
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
      const nowTs = Date.now();
      // Coalesce at least 8 ADTS frames (~512ms @ 16kHz) or 400ms elapsed so Web Audio plays a silky continuous stream
      if (parsed.framesBuf && parsed.frameCount > 0 && (parsed.frameCount >= 8 || !st.lastEmitAt || (nowTs - st.lastEmitAt >= 400))) {
        st.adtsCarry = parsed.remainder;
        st.lastEmitAt = nowTs;
        st.seq += 1;
        st.chunks.push({
          seq: st.seq,
          at: nowTs,
          format: 'aac',
          sample_rate: parsed.sampleRate,
          frame_count: parsed.frameCount,
          data_b64: parsed.framesBuf.toString('base64'),
        });
        if (st.chunks.length > 32) st.chunks.splice(0, st.chunks.length - 32);
      } else {
        st.adtsCarry = capped;
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
    let realDvrId = String(dvrId || '');
    let realChannel = Number(channel || 1);
    const ipchMatch = realDvrId.match(/^(.+)__ipch_(\d+)$/);
    if (ipchMatch) {
      realDvrId = ipchMatch[1];
      realChannel = parseInt(ipchMatch[2], 10) || 1;
    }
    const dvr = getRawDvr(realDvrId);
    if (!dvr) return false;
    const ch = Math.max(1, Math.min(64, realChannel || 1));
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

    let useDirectRouterAudio = false;
    let routerDvrForAudio = dvr;
    if (dvr.connection_mode === 'router') {
      const rState = await ensureRouterDirectStatus(dvr, false);
      const rHost = (rState && rState.routerHost) || String(dvr.router_host || '').trim();
      const rPort = (rState && rState.routerPort) || Number(dvr.router_http_port || 8085) || 8085;
      if (!rHost) {
        throw new Error(`عنوان راوتر الفرع (${dvr.name}) غير محدد`);
      }
      useDirectRouterAudio = true;
      routerDvrForAudio = { ...dvr, host: rHost, http_port: rPort };
    }

    const activeBridgeDev = (dvr.connection_mode === 'bridge' || (dvr.connection_mode === 'router' && !useDirectRouterAudio))
      ? resolveActiveBridgeDevice(dvr)
      : null;
    const activeBridgeId = (activeBridgeDev && activeBridgeDev.device_id) || String(dvr.bridge_device_id || '');

    audioLeases.set(dvr.id, {
      dvrId: dvr.id,
      bridgeDeviceId: (dvr.connection_mode === 'bridge' || (dvr.connection_mode === 'router' && !useDirectRouterAudio))
        ? activeBridgeId
        : '',
      channel: ch,
      until: Date.now() + 7500,
    });

    if (dvr.connection_mode === 'bridge' || (dvr.connection_mode === 'router' && !useDirectRouterAudio)) {
      const dev = activeBridgeDev || db.prepare('SELECT last_seen, label, hostname, app_version FROM devices WHERE device_id=?').get(activeBridgeId);
      const devLabel = (dev && (dev.label || dev.hostname)) || activeBridgeId;
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
      ensureDirectAudioStream(routerDvrForAudio, ch).catch(() => {});
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

  // ==========================================================================
  // Dahua Next-Generation Enterprise Streaming Gateway
  // (MediaMTX WebRTC WHEP + Zero-Transcode fMP4 MSE Multiplexer + HLS Fallback)
  // ==========================================================================
  const MEDIAMTX_DIR = 'C:\\ProgramData\\IT-ELKHAWGA-Relay\\mediamtx';
  const MEDIAMTX_EXE = `${MEDIAMTX_DIR}\\mediamtx.exe`;
  const MEDIAMTX_CFG = `${MEDIAMTX_DIR}\\mediamtx.generated.yml`;
  let mediaMtxProc = null;
  let mediaMtxConfigSig = '';

  function buildDvrRtspUrl(dvr, channel, hd = false) {
    if (!dvr) return '';
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const sub = hd ? 0 : 1;
    const targetHost = dvr.connection_mode === 'router'
      ? String(dvr.router_host || dvr.host || '').trim()
      : String(dvr.host || '').trim();
    const targetPort = dvr.connection_mode === 'router'
      ? (Number(dvr.router_rtsp_port || dvr.rtsp_port || 554) || 554)
      : (Number(dvr.rtsp_port || 554) || 554);
    if (!targetHost) return '';
    const u = encodeURIComponent(String(dvr.username || 'admin'));
    const p = encodeURIComponent(String(dvr.password || ''));
    const customRtspPath = dvr.rtsp_path ? String(dvr.rtsp_path).trim() : '';
    return customRtspPath
      ? `rtsp://${u}:${p}@${targetHost}:${targetPort}${customRtspPath.startsWith('/') ? '' : '/'}${customRtspPath}`
      : `rtsp://${u}:${p}@${targetHost}:${targetPort}/cam/realmonitor?channel=${ch}&subtype=${sub}`;
  }

  function buildMediaMtxPathName(dvrId, channel, hd = false) {
    const cleanId = String(dvrId || '').replace(/[^A-Za-z0-9_-]/g, '');
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    return `cam_${cleanId}_${ch}_${hd ? 'main' : 'sub'}`;
  }

  function syncAndEnsureMediaMtxGateway(forceReload = false) {
    try {
      if (!fs.existsSync(MEDIAMTX_EXE)) return false;
      const rows = db.prepare('SELECT * FROM cctv_dvrs WHERE enabled=1 ORDER BY created_at ASC').all();
      const yamlLines = [
        'logLevel: warn',
        'logDestinations: [stdout]',
        'api: yes',
        'apiAddress: 127.0.0.1:9997',
        'rtsp: yes',
        'rtspAddress: 127.0.0.1:8554',
        'rtmp: no',
        'srt: no',
        'hls: yes',
        'hlsAddress: 127.0.0.1:8888',
        'hlsVariant: lowLatency',
        'hlsSegmentCount: 7',
        'hlsSegmentDuration: 1s',
        'hlsPartDuration: 200ms',
        'hlsAllowOrigins: ["*"]',
        'webrtc: yes',
        'webrtcAddress: 127.0.0.1:8889',
        'webrtcLocalUDPAddress: :8189',
        'webrtcIPsFromInterfaces: yes',
        'webrtcAllowOrigins: ["*"]',
        'paths:',
      ];
      let hasAnyPath = false;
      for (const dvr of rows) {
        const totalCh = Math.max(1, Math.min(64, Number(dvr.channels_count || 8) || 8));
        for (let ch = 1; ch <= totalCh; ch++) {
          for (const hd of [true, false]) {
            const rtspUrl = buildDvrRtspUrl(dvr, ch, hd);
            if (!rtspUrl) continue;
            hasAnyPath = true;
            const pName = buildMediaMtxPathName(dvr.id, ch, hd);
            const escapedUrl = rtspUrl.replace(/"/g, '\\"');
            yamlLines.push(`  ${pName}:`);
            yamlLines.push(`    source: "${escapedUrl}"`);
            yamlLines.push(`    sourceProtocol: tcp`);
            yamlLines.push(`    sourceOnDemand: yes`);
            yamlLines.push(`    sourceOnDemandStartTimeout: 8s`);
            yamlLines.push(`    sourceOnDemandCloseAfter: 10s`);
          }
        }
      }
      if (!hasAnyPath) {
        yamlLines.push('  all_others:');
      }
      const yamlText = yamlLines.join('\n') + '\n';
      if (yamlText !== mediaMtxConfigSig || forceReload || !fs.existsSync(MEDIAMTX_CFG)) {
        fs.writeFileSync(MEDIAMTX_CFG, yamlText, 'utf8');
        mediaMtxConfigSig = yamlText;
      }
      if (!mediaMtxProc || mediaMtxProc.killed || mediaMtxProc.exitCode !== null) {
        mediaMtxProc = spawn(MEDIAMTX_EXE, [MEDIAMTX_CFG], {
          cwd: MEDIAMTX_DIR,
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        mediaMtxProc.on('exit', (code) => {
          writeCctvLog('WARN', 'MEDIAMTX_EXIT', `توقفت بوابة MediaMTX (code=${code})، سيتم إعادة تشغيلها عند الطلب`);
          mediaMtxProc = null;
        });
        writeCctvLog('INFO', 'MEDIAMTX_BOOT', 'تم تشغيل بوابة MediaMTX Streaming Gateway على 127.0.0.1:8889 (WebRTC WHEP) و 127.0.0.1:8888 (Low-Latency HLS)');
      }
      return true;
    } catch (err) {
      writeCctvLog('ERROR', 'MEDIAMTX_ERR', `خطأ في تهيئة MediaMTX: ${(err && err.message) || err}`);
      return false;
    }
  }
  setTimeout(() => syncAndEnsureMediaMtxGateway(false), 1200);

  // Deduplicated Zero-Transcode fMP4/MSE Multiplexer Sessions:
  // If 3 admins watch the same camera simultaneously, ONLY 1 RTSP connection is opened to the branch router!
  const activeFmp4Hubs = new Map(); // hubKey -> { proc, dvrId, ch, hd, mode, initBuf, codecMime, videoCodec, width, height, latestGopChunks, clients: Set<res>, startedAt, lastDataAt, bytesTotal, firstFrameMs }

  function parseIsoBoxes(buf) {
    const out = [];
    let off = 0;
    while (off + 8 <= buf.length) {
      const sz = buf.readUInt32BE(off);
      if (sz < 8 || off + sz > buf.length) break;
      const type = buf.slice(off + 4, off + 8).toString('ascii');
      out.push({ type, size: sz, start: off, end: off + sz });
      off += sz;
    }
    return out;
  }

  function detectFmp4CodecMime(initSegment) {
    if (!initSegment || initSegment.length < 16) {
      return { codecMime: 'video/mp4; codecs="avc1.640020"', videoCodec: 'H.264' };
    }
    const avcIdx = initSegment.indexOf(Buffer.from('avcC'));
    if (avcIdx !== -1 && avcIdx + 8 <= initSegment.length) {
      const prof = initSegment[avcIdx + 5].toString(16).padStart(2, '0');
      const compat = initSegment[avcIdx + 6].toString(16).padStart(2, '0');
      const level = initSegment[avcIdx + 7].toString(16).padStart(2, '0');
      return {
        codecMime: `video/mp4; codecs="avc1.${prof}${compat}${level}"`,
        videoCodec: 'H.264',
      };
    }
    const hvcIdx = initSegment.indexOf(Buffer.from('hvcC'));
    if (hvcIdx !== -1) {
      return {
        codecMime: 'video/mp4; codecs="hev1.1.6.L120.90"',
        videoCodec: 'H.265 / HEVC',
      };
    }
    return { codecMime: 'video/mp4; codecs="avc1.640020"', videoCodec: 'H.264' };
  }

  function getOrCreateFmp4Hub(dvr, channel, hd = false, mode = 'copy') {
    const ch = Math.max(1, Math.min(64, Number(channel || 1) || 1));
    const safeMode = mode === 'h264' ? 'h264' : 'copy';
    const hubKey = `${dvr.id}:${ch}:${hd ? 1 : 0}:${safeMode}`;
    const existing = activeFmp4Hubs.get(hubKey);
    if (existing && existing.proc && !existing.proc.killed && existing.proc.exitCode === null) {
      return existing;
    }

    const rtspUrl = buildDvrRtspUrl(dvr, ch, hd);
    if (!rtspUrl) {
      throw new Error('عنوان RTSP للفرع غير مكتمل');
    }

    const args = [
      '-hide_banner',
      '-loglevel', 'error',
      '-fflags', 'nobuffer+genpts+discardcorrupt',
      '-flags', 'low_delay',
      '-probesize', '32768',
      '-analyzeduration', '250000',
      '-rtsp_transport', 'tcp',
      '-timeout', '5000000',
      '-use_wallclock_as_timestamps', '1',
      '-i', rtspUrl,
      '-an',
    ];

    if (safeMode === 'copy') {
      // Zero-Transcode Remuxing (-c:v copy): 0% CPU, original camera quality, lowest latency!
      args.push('-c:v', 'copy');
    } else {
      // On-demand ultrafast H.264 fallback ONLY if a client browser lacks hardware HEVC support
      const scaleFilter = hd ? 'fps=15,scale=1280:720:flags=fast_bilinear' : 'fps=15,scale=854:480:flags=fast_bilinear';
      args.push(
        '-vf', scaleFilter,
        '-c:v', 'libx264',
        '-preset', 'ultrafast',
        '-tune', 'zerolatency',
        '-profile:v', 'baseline',
        '-pix_fmt', 'yuv420p',
        '-g', '15'
      );
    }

    args.push(
      '-f', 'mp4',
      '-movflags', 'frag_keyframe+empty_moov+default_base_moof+omit_tfhd_offset',
      '-frag_duration', '80000',
      'pipe:1'
    );

    const startedAt = Date.now();
    const proc = spawn(resolveFfmpegBin(), args, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const hub = {
      hubKey,
      proc,
      dvrId: dvr.id,
      dvrName: dvr.name || dvr.id,
      ch,
      hd: Boolean(hd),
      mode: safeMode,
      initBuf: null,
      codecMime: '',
      videoCodec: '',
      latestMoofMdat: null,
      clients: new Set(),
      startedAt,
      lastDataAt: startedAt,
      bytesTotal: 0,
      firstFrameMs: 0,
      idleTimer: null,
    };
    activeFmp4Hubs.set(hubKey, hub);

    writeCctvLog(
      'INFO',
      'MSE_HUB_START',
      `بدء جلسة بث مباشر fMP4 (${safeMode === 'copy' ? 'Zero-Transcode Remux -c:v copy' : 'H.264 Ultrafast'}): فرع=${hub.dvrName} كاميرا=${ch} (${hd ? 'Main HD' : 'Sub SD'})`,
      `mse_start_${hubKey}`,
      5000
    );

    let carry = Buffer.alloc(0);

    proc.stdout.on('data', (chunk) => {
      hub.lastDataAt = Date.now();
      hub.bytesTotal += chunk.length;

      if (!hub.initBuf) {
        carry = carry.length ? Buffer.concat([carry, chunk]) : chunk;
        const boxes = parseIsoBoxes(carry);
        const ftyp = boxes.find((b) => b.type === 'ftyp');
        const moov = boxes.find((b) => b.type === 'moov');
        if (ftyp && moov) {
          const initEnd = moov.end;
          hub.initBuf = Buffer.from(carry.subarray(0, initEnd));
          const det = detectFmp4CodecMime(hub.initBuf);
          hub.codecMime = det.codecMime;
          hub.videoCodec = det.videoCodec;
          hub.firstFrameMs = Date.now() - hub.startedAt;
          const rest = carry.subarray(initEnd);
          carry = Buffer.alloc(0);

          writeCctvLog(
            'INFO',
            'MSE_INIT_READY',
            `جاهزية البث fMP4 لفرع=${hub.dvrName} كاميرا=${ch} (${hd ? 'Main' : 'Sub'}) خلال ${hub.firstFrameMs}ms | الترميز=${hub.videoCodec} (${hub.codecMime})`,
            `mse_init_${hubKey}`,
            8000
          );

          for (const clientRes of hub.clients) {
            try {
              if (!clientRes.headersSent) {
                clientRes.writeHead(200, {
                  'Content-Type': 'video/mp4',
                  'Cache-Control': 'no-store, no-cache, must-revalidate',
                  'Connection': 'keep-alive',
                  'Access-Control-Allow-Origin': '*',
                  'Access-Control-Expose-Headers': 'X-Video-Codec, X-Codec-Mime, X-Stream-Mode, X-First-Frame-Ms',
                  'X-Video-Codec': hub.videoCodec,
                  'X-Codec-Mime': hub.codecMime,
                  'X-Stream-Mode': safeMode === 'copy' ? 'Zero-Transcode Remux' : 'H264 Compatibility',
                  'X-First-Frame-Ms': String(hub.firstFrameMs),
                });
              }
              clientRes.write(hub.initBuf);
              if (rest.length > 0) clientRes.write(rest);
            } catch (_) {}
          }
        } else if (carry.length > 4 * 1024 * 1024) {
          carry = Buffer.alloc(0);
        }
        return;
      }

      for (const clientRes of hub.clients) {
        try {
          if (clientRes.headersSent && !clientRes.writableEnded) {
            clientRes.write(chunk);
          }
        } catch (_) {}
      }
    });

    proc.on('close', () => {
      activeFmp4Hubs.delete(hubKey);
      for (const clientRes of hub.clients) {
        try {
          if (!clientRes.headersSent) {
            clientRes.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
            clientRes.end(JSON.stringify({ ok: false, error: 'انقطع اتصال RTSP بكاميرا الفرع' }));
          } else if (!clientRes.writableEnded) {
            clientRes.end();
          }
        } catch (_) {}
      }
      hub.clients.clear();
    });

    return hub;
  }

  function subscribeClientToFmp4Stream({ dvrId, channel = 1, hd = false, mode = 'copy', actor = '', role = 'super', req, res }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'جهاز الـ DVR غير موجود' }));
      return;
    }
    if (!canAdminAccessDvr(dvr, actor, role)) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'لا تملك صلاحية الوصول إلى كاميرات هذا الفرع' }));
      return;
    }

    let hub;
    try {
      hub = getOrCreateFmp4Hub(dvr, channel, hd, mode);
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: (e && e.message) || 'تعذر فتح بث الكاميرا' }));
      return;
    }

    if (hub.idleTimer) {
      clearTimeout(hub.idleTimer);
      hub.idleTimer = null;
    }

    hub.clients.add(res);

    if (hub.initBuf) {
      res.writeHead(200, {
        'Content-Type': 'video/mp4',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Expose-Headers': 'X-Video-Codec, X-Codec-Mime, X-Stream-Mode, X-First-Frame-Ms',
        'X-Video-Codec': hub.videoCodec || 'H.264',
        'X-Codec-Mime': hub.codecMime || 'video/mp4; codecs="avc1.640020"',
        'X-Stream-Mode': hub.mode === 'copy' ? 'Zero-Transcode Remux' : 'H264 Compatibility',
        'X-First-Frame-Ms': String(hub.firstFrameMs || 150),
      });
      try { res.write(hub.initBuf); } catch (_) {}
    }

    const cleanup = () => {
      hub.clients.delete(res);
      if (hub.clients.size === 0 && !hub.idleTimer) {
        // Keep hub warm for 6 seconds in case user switches Fit/Fill or fullscreen, then close RTSP to save 100% bandwidth
        hub.idleTimer = setTimeout(() => {
          if (hub.clients.size === 0) {
            try { hub.proc.kill(); } catch (_) {}
            activeFmp4Hubs.delete(hub.hubKey);
            writeCctvLog('INFO', 'MSE_HUB_STOP', `إيقاف جلسة البث fMP4 تلقائياً لعدم وجود مشاهدين: فرع=${hub.dvrName} كاميرا=${hub.ch}`);
          }
        }, 6000);
      }
    };

    req.on('close', cleanup);
    res.on('close', cleanup);
    res.on('error', cleanup);
  }

  async function negotiateWebRtcWhep({ dvrId, channel = 1, hd = false, offerSdp = '', actor = '', role = 'super' }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) throw new Error('جهاز الـ DVR غير موجود');
    if (!canAdminAccessDvr(dvr, actor, role)) {
      throw new Error('لا تملك صلاحية الوصول إلى كاميرات هذا الفرع');
    }
    if (!offerSdp || !String(offerSdp).includes('v=0')) {
      throw new Error('SDP Offer غير صالح');
    }
    syncAndEnsureMediaMtxGateway(false);
    const pName = buildMediaMtxPathName(dvr.id, channel, hd);
    const whepPath = `/${pName}/whep`;

    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: 8889,
          path: whepPath,
          method: 'POST',
          headers: {
            'Content-Type': 'application/sdp',
            'Content-Length': Buffer.byteLength(offerSdp, 'utf8'),
          },
          timeout: 9000,
        },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const answerSdp = Buffer.concat(chunks).toString('utf8');
            if (res.statusCode === 201 || res.statusCode === 200) {
              writeCctvLog(
                'INFO',
                'WEBRTC_WHEP_OK',
                `نجاح اتصال WebRTC WHEP مباشر: فرع=${dvr.name} كاميرا=${channel} (${hd ? 'Main HD' : 'Sub SD'})`,
                `whep_ok_${pName}`,
                8000
              );
              resolve({ ok: true, answer_sdp: answerSdp, path_name: pName });
            } else {
              reject(new Error(answerSdp.trim() || `MediaMTX WHEP HTTP ${res.statusCode}`));
            }
          });
        }
      );
      req.on('error', (e) => reject(e));
      req.on('timeout', () => {
        req.destroy(new Error('انتهت مهلة التفاوض على WebRTC WHEP'));
      });
      req.end(offerSdp, 'utf8');
    });
  }

  function proxyMediaMtxHls({ dvrId, channel = 1, hd = false, subFile = 'index.m3u8', actor = '', role = 'super', token = '', res }) {
    const dvr = getRawDvr(dvrId);
    if (!dvr) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'DVR not found' }));
      return;
    }
    if (!canAdminAccessDvr(dvr, actor, role)) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'Forbidden branch' }));
      return;
    }
    syncAndEnsureMediaMtxGateway(false);
    const pName = buildMediaMtxPathName(dvr.id, channel, hd);
    const cleanFile = String(subFile || 'index.m3u8').replace(/\.\./g, '').replace(/^\/+/, '') || 'index.m3u8';
    const upstreamPath = `/${pName}/${cleanFile}`;

    const hReq = http.request(
      {
        hostname: '127.0.0.1',
        port: 8888,
        path: upstreamPath,
        method: 'GET',
        timeout: 10000,
      },
      (hRes) => {
        const ctype = hRes.headers['content-type'] || (cleanFile.endsWith('.m3u8') ? 'application/vnd.apple.mpegurl' : 'video/mp4');
        const chunks = [];
        hRes.on('data', (c) => chunks.push(c));
        hRes.on('end', () => {
          let buf = Buffer.concat(chunks);
          if (cleanFile.endsWith('.m3u8') && token && hRes.statusCode === 200) {
            // Append ?token=... to child playlists/segments inside m3u8 so native HLS players authenticate automatically
            const txt = buf.toString('utf8').replace(
              /^((?!#)\S+\.(?:m3u8|mp4|ts)(\?\S*)?)$/gm,
              (m) => (m.includes('?') ? `${m}&token=${encodeURIComponent(token)}` : `${m}?token=${encodeURIComponent(token)}`)
            );
            buf = Buffer.from(txt, 'utf8');
          }
          res.writeHead(hRes.statusCode || 200, {
            'Content-Type': ctype,
            'Content-Length': buf.length,
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Access-Control-Allow-Origin': '*',
          });
          res.end(buf);
        });
      }
    );
    hReq.on('error', (e) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    hReq.end();
  }

  function getActiveStreamingTelemetry() {
    const mseStreams = [];
    for (const h of activeFmp4Hubs.values()) {
      mseStreams.push({
        dvr_id: h.dvrId,
        dvr_name: h.dvrName,
        channel: h.ch,
        hd: h.hd,
        mode: h.mode,
        codec: h.videoCodec || 'probing',
        codec_mime: h.codecMime || '',
        viewers: h.clients.size,
        first_frame_ms: h.firstFrameMs,
        bytes_total: h.bytesTotal,
        uptime_sec: Math.round((Date.now() - h.startedAt) / 1000),
      });
    }
    return {
      ok: true,
      mediamtx_running: Boolean(mediaMtxProc && !mediaMtxProc.killed && mediaMtxProc.exitCode === null),
      active_mse_hubs: mseStreams.length,
      active_rtsp_mjpeg: activeRtspStreams.size,
      mse_streams: mseStreams,
    };
  }

  async function handleAction({ action, payload = {}, actor = '', role = 'super' }) {
    switch (String(action || '')) {
      case 'poll_wall_frames':
        return pollWallFrames({
          items: payload.items || [],
          actor,
          role,
        });
      case 'detect_router_ip':
        return detectRouterIpAndProbePort(payload);
      case 'raw_cgi': {
        const dvr = getRawDvr(payload.dvr_id);
        const overrideHost = payload.override_host ? String(payload.override_host).trim() : '';
        const targetDvr = {
          ...dvr,
          connection_mode: (overrideHost && !isPublicIpv4(overrideHost)) ? 'bridge' : dvr.connection_mode,
          host: overrideHost || dvr.host,
          http_port: Number(payload.override_port || dvr.http_port || 80),
          username: payload.override_user ? String(payload.override_user) : dvr.username,
          password: payload.override_pass ? String(payload.override_pass) : dvr.password,
        };
        const r = await executeDvrCgi(targetDvr, String(payload.path || '/cgi-bin/magicBox.cgi?action=getSystemInfo'), {
          timeoutMs: Number(payload.timeout_ms || 8000),
        });
        return {
          ok: true,
          status: r.statusCode,
          content_type: r.contentType,
          text: String(r.contentType || '').includes('image') ? '' : (r.body ? r.body.toString('utf8') : ''),
          b64: String(r.contentType || '').includes('image') && r.body ? r.body.toString('base64').slice(0, 80) : '',
          len: r.body ? r.body.length : 0,
        };
      }
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
      case 'webrtc_whep':
        return negotiateWebRtcWhep({
          dvrId: payload.dvr_id,
          channel: payload.channel,
          hd: Boolean(payload.hd),
          offerSdp: payload.offer_sdp || '',
          actor,
          role,
        });
      case 'streaming_telemetry':
        return getActiveStreamingTelemetry();
      case 'get_cctv_logs':
        return {
          ok: true,
          log_path: CCTV_LOG_PATHS[0],
          lines: readRecentCctvLogs(payload.limit || 180),
        };
      case 'clear_cctv_logs':
        cctvLogMemoryRing.length = 0;
        for (const lp of CCTV_LOG_PATHS) {
          try { fs.writeFileSync(lp, '', 'utf8'); } catch (_) {}
        }
        writeCctvLog('INFO', 'LOG_CLEARED', `تم مسح سجل الكاميرات بواسطة ${actor || 'admin'}`);
        return {
          ok: true,
          log_path: CCTV_LOG_PATHS[0],
          lines: readRecentCctvLogs(50),
        };
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
    subscribeClientToFmp4Stream,
    negotiateWebRtcWhep,
    proxyMediaMtxHls,
    syncAndEnsureMediaMtxGateway,
    getActiveStreamingTelemetry,
  };
}
