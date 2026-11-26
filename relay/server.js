import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createWhatsAppBot } from './whatsapp-bot.js';
import { createDahuaCctvManager } from './dahua-cctv.js';
import { createBiometricsManager } from './biometrics.js';

const lanKeepAliveAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 32,
  keepAliveMsecs: 15000,
});

const PORT = Number(process.env.PORT || 8787);
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
// Bump when the API/protocol changes so the admin app can detect an outdated relay.
const RELAY_VERSION = '3';
const LONG_POLL_MS = 20000;

if (!ADMIN_KEY) {
  console.error('ADMIN_KEY is required');
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'relay.db'));
db.exec(`
  PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS pairing_tokens (
    token TEXT PRIMARY KEY,
    label TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    hostname TEXT,
    os TEXT,
    app_version TEXT,
    device_token_hash TEXT NOT NULL,
    enrolled_at INTEGER NOT NULL,
    last_seen INTEGER,
    ip TEXT,
    blocked INTEGER DEFAULT 0,
    mode TEXT,
    policy_version TEXT
  );
  CREATE TABLE IF NOT EXISTS commands (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    acked_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  INSERT OR IGNORE INTO policy(id,version,data,updated_at)
    VALUES (1, '0', '{"mode":"whitelist","allowed":[],"blocked":[],"rules":[]}', ${Date.now()});
  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS group_policy (
    group_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);
// Older databases predate device groups; add the column when missing.
try { db.exec("ALTER TABLE devices ADD COLUMN group_id TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN label TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN last_event TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN last_event_at INTEGER DEFAULT 0"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN throttle_kbps INTEGER DEFAULT 0"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN sites TEXT DEFAULT '[]'"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN denied TEXT DEFAULT '[]'"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN usb_blocked INTEGER DEFAULT 0"); } catch (e) { /* already exists */ }
try { db.exec("CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, meta TEXT DEFAULT '{}', created_at INTEGER NOT NULL, acked_at INTEGER, acked_by TEXT)"); } catch (e) {}
try { db.exec("CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, result TEXT, meta TEXT DEFAULT '{}', created_at INTEGER NOT NULL)"); } catch (e) {}
try { db.exec("CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"); } catch (e) {}
try { db.exec("CREATE TABLE IF NOT EXISTS uploaded_files (file_id TEXT PRIMARY KEY, device_id TEXT, file_name TEXT, file_size INTEGER DEFAULT 0, stored_path TEXT, created_at INTEGER NOT NULL)"); } catch (e) {}
for (const colSql of [
  "ALTER TABLE uploaded_files ADD COLUMN device_name TEXT DEFAULT ''",
  "ALTER TABLE uploaded_files ADD COLUMN windows_user TEXT DEFAULT ''",
  "ALTER TABLE uploaded_files ADD COLUMN channel TEXT DEFAULT 'whatsapp_web'",
  "ALTER TABLE uploaded_files ADD COLUMN recipient_name TEXT DEFAULT ''",
  "ALTER TABLE uploaded_files ADD COLUMN recipient_phone TEXT DEFAULT ''",
  "ALTER TABLE uploaded_files ADD COLUMN page_url TEXT DEFAULT ''",
  "ALTER TABLE uploaded_files ADD COLUMN sha256 TEXT DEFAULT ''",
]) {
  try { db.exec(colSql); } catch (e) { /* already exists */ }
}
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
try { fs.mkdirSync(UPLOADS_DIR, { recursive: true }); } catch (e) {}
const DEFAULT_ARCHIVE_ROOT = path.resolve(process.env.ARCHIVE_DIR || 'C:/IT-ELKHAWGA-Archive');

function getArchiveRoot() {
  try {
    const cfgPath = 'C:/ProgramData/InternetBlocker/config.json';
    if (fs.existsSync(cfgPath)) {
      const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8').replace(/^\uFEFF/, '')) || {};
      let custom = String(cfg.archive_dir || '').trim().replace(/^"+|"+$/g, '');
      if (custom) {
        if (/^[A-Za-z]:\\?$/.test(custom)) {
          custom = custom.replace(/\\?$/, '\\IT-ELKHAWGA-Archive');
        }
        const resolved = path.resolve(custom);
        fs.mkdirSync(path.join(resolved, 'WhatsApp'), { recursive: true });
        fs.mkdirSync(path.join(resolved, 'Web-Uploads'), { recursive: true });
        return resolved;
      }
    }
  } catch (_) {}
  for (const sub of ['WhatsApp', 'Web-Uploads']) {
    try { fs.mkdirSync(path.join(DEFAULT_ARCHIVE_ROOT, sub), { recursive: true }); } catch (_) {}
  }
  return DEFAULT_ARCHIVE_ROOT;
}
getArchiveRoot();

function getDiskSpaceBytes(dirPath) {
  try {
    if (typeof fs.statfsSync === 'function') {
      const st = fs.statfsSync(dirPath);
      const bsize = Number(st.bsize || st.frsize || 4096);
      return {
        free: Number(st.bavail || st.bfree || 0) * bsize,
        total: Number(st.blocks || 0) * bsize,
      };
    }
  } catch (_) {}
  return { free: 0, total: 0 };
}

function sanitizeWinSegment(raw, fallback, maxLen = 70) {
  let s = String(raw || '').trim()
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, '_')
    .replace(/\s+/g, ' ')
    .replace(/[. ]+$/g, '');
  if (!s) s = fallback;
  if (/^(con|prn|aux|nul|com\d|lpt\d)$/i.test(s)) s = '_' + s;
  return s.slice(0, maxLen) || fallback;
}

function buildArchiveFilePath({ channel, deviceName, recipientName, recipientPhone, origName, tsMs }) {
  const archiveRoot = getArchiveRoot();
  const d = new Date(tsMs || Date.now());
  const pad2 = (n) => String(n).padStart(2, '0');
  const dayStr = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
  const timeStr = `${pad2(d.getHours())}-${pad2(d.getMinutes())}-${pad2(d.getSeconds())}`;
  const chanDir = String(channel || '').includes('whatsapp') ? 'WhatsApp' : 'Web-Uploads';
  const devDir = sanitizeWinSegment(deviceName, 'Unknown-Device', 60);
  const dir = path.join(archiveRoot, chanDir, dayStr, devDir);
  fs.mkdirSync(dir, { recursive: true });

  const recipRaw = recipientPhone || recipientName || '';
  const recipTag = recipRaw ? sanitizeWinSegment(recipRaw, '', 40) + '__' : '';
  const cleanOrig = sanitizeWinSegment(origName, 'file.bin', 130);
  const dotIdx = cleanOrig.lastIndexOf('.');
  const stem = dotIdx > 0 ? cleanOrig.slice(0, dotIdx) : cleanOrig;
  const ext = dotIdx > 0 ? cleanOrig.slice(dotIdx) : '';

  let candidate = path.join(dir, `${timeStr}__${recipTag}${stem}${ext}`);
  if (fs.existsSync(candidate)) {
    const uniq = crypto.randomBytes(2).toString('hex');
    candidate = path.join(dir, `${timeStr}__${recipTag}${stem}__${uniq}${ext}`);
  }
  return candidate;
}

function appendArchiveLog(entry) {
  try {
    const archiveRoot = getArchiveRoot();
    fs.mkdirSync(archiveRoot, { recursive: true });
    fs.appendFileSync(path.join(archiveRoot, 'archive-log.jsonl'), JSON.stringify(entry) + '\n', 'utf8');
  } catch (e) {}
}

let archiveLogCacheSig = '';
let archiveLogCacheEntries = [];
let diskSpaceCache = { root: '', at: 0, free: 0, total: 0 };

function getCachedDiskSpaceBytes(targetPath) {
  const nowTs = Date.now();
  if (diskSpaceCache.root === targetPath && nowTs - diskSpaceCache.at < 30000) {
    return { free: diskSpaceCache.free, total: diskSpaceCache.total };
  }
  const res = getDiskSpaceBytes(targetPath);
  diskSpaceCache = { root: targetPath, at: nowTs, free: res.free, total: res.total };
  return res;
}

function readArchiveLogEntries() {
  const curRoot = getArchiveRoot();
  const roots = [curRoot];
  if (curRoot.toLowerCase() !== DEFAULT_ARCHIVE_ROOT.toLowerCase()) {
    roots.push(DEFAULT_ARCHIVE_ROOT);
  }
  const sigParts = [];
  for (const r of roots) {
    try {
      const p = path.join(r, 'archive-log.jsonl');
      const st = fs.statSync(p);
      sigParts.push(`${p}:${st.size}:${Math.floor(st.mtimeMs)}`);
    } catch (_) {
      sigParts.push(`${r}:0:0`);
    }
  }
  const sig = sigParts.join('|');
  if (sig && sig === archiveLogCacheSig) {
    return archiveLogCacheEntries;
  }

  const out = [];
  const seen = new Set();
  for (const r of roots) {
    try {
      const p = path.join(r, 'archive-log.jsonl');
      if (!fs.existsSync(p)) continue;
      const raw = fs.readFileSync(p, 'utf8');
      for (const line of raw.split(/\r?\n/)) {
        const t = line.trim();
        if (!t) continue;
        try {
          const parsed = JSON.parse(t);
          const fid = String((parsed && parsed.file_id) || '');
          if (!fid || !seen.has(fid)) {
            if (fid) seen.add(fid);
            out.push(parsed);
          }
        } catch (_) {}
      }
    } catch (_) {}
  }
  archiveLogCacheSig = sig;
  archiveLogCacheEntries = out;
  return out;
}

function stripAlertMedia(rawMeta) {
  if (!rawMeta) return '{}';
  let obj = null;
  if (typeof rawMeta === 'object') {
    obj = { ...rawMeta };
  } else if (typeof rawMeta === 'string' && rawMeta.trim().startsWith('{')) {
    try { obj = JSON.parse(rawMeta); } catch (_) { return rawMeta; }
  }
  if (!obj || typeof obj !== 'object') return typeof rawMeta === 'string' ? rawMeta : '{}';
  if (obj.screenshot && String(obj.screenshot).length > 0) {
    obj.has_screenshot = true;
    delete obj.screenshot;
  }
  if (obj.camera_photo && String(obj.camera_photo).length > 0) {
    obj.has_camera_photo = true;
    delete obj.camera_photo;
  }
  return JSON.stringify(obj);
}
try { db.exec("ALTER TABLE devices ADD COLUMN rustdesk_id TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN rustdesk_password TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN screen_requested INTEGER DEFAULT 0"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN stream_mode TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN stream_until INTEGER DEFAULT 0"); } catch (e) { /* already exists */ }
db.exec("CREATE TABLE IF NOT EXISTS screens (device_id TEXT PRIMARY KEY, image TEXT DEFAULT '', at INTEGER DEFAULT 0)");
try { db.exec("ALTER TABLE screens ADD COLUMN kind TEXT DEFAULT 'screen'"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE screens ADD COLUMN error TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
// Remove legacy auto-enroll token so LAN devices never secretly self-enroll without an admin token.
db.prepare("DELETE FROM pairing_tokens WHERE token='pair_it_elkhawga_forever'").run();
db.prepare("UPDATE devices SET label='' WHERE label='permanent'").run();

// Performance indexes + separate alert_media table so listing/counting alerts never scans multi-MB base64 blobs
db.exec(`
  CREATE TABLE IF NOT EXISTS alert_media (
    alert_id TEXT PRIMARY KEY,
    screenshot TEXT DEFAULT '',
    camera_photo TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_unacked ON alerts(acked_at, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_type_created ON alerts(type, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_alert_media_created ON alert_media(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_commands_dev_pending ON commands(device_id, acked_at, created_at);
  CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(device_token_hash);
  CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
  CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_id);
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_uploads_created ON uploaded_files(created_at DESC);
`);

function migrateHeavyAlertBlobsAndPrune() {
  try {
    const selIds = db.prepare('SELECT id, created_at FROM alerts WHERE length(meta) > 4096 LIMIT 25');
    const selOne = db.prepare('SELECT meta FROM alerts WHERE id=?');
    const insMedia = db.prepare('INSERT OR REPLACE INTO alert_media(alert_id, screenshot, camera_photo, created_at) VALUES(?,?,?,?)');
    const updMeta = db.prepare('UPDATE alerts SET meta=? WHERE id=?');

    let totalMigrated = 0;
    while (true) {
      const batch = selIds.all();
      if (!batch.length) break;
      db.exec('BEGIN IMMEDIATE');
      try {
        for (const item of batch) {
          const row = selOne.get(item.id);
          if (!row || typeof row.meta !== 'string') {
            updMeta.run('{}', item.id);
            continue;
          }
          let obj = null;
          try { obj = JSON.parse(row.meta); } catch (_) { obj = null; }
          if (!obj || typeof obj !== 'object') {
            updMeta.run(row.meta.slice(0, 2048), item.id);
            continue;
          }
          const scr = typeof obj.screenshot === 'string' ? obj.screenshot : '';
          const cam = typeof obj.camera_photo === 'string' ? obj.camera_photo : '';
          if (scr || cam) {
            insMedia.run(item.id, scr, cam, Number(item.created_at || Date.now()));
            if (scr) { obj.has_screenshot = true; delete obj.screenshot; }
            if (cam) { obj.has_camera_photo = true; delete obj.camera_photo; }
          }
          updMeta.run(JSON.stringify(obj), item.id);
          totalMigrated++;
        }
        db.exec('COMMIT');
      } catch (innerErr) {
        try { db.exec('ROLLBACK'); } catch (_) {}
        break;
      }
    }
    // Prune stale acked commands (> 3 days) and cap alert_media to latest 400 snapshots
    const threeDaysAgo = Date.now() - 3 * 24 * 3600 * 1000;
    db.prepare('DELETE FROM commands WHERE acked_at IS NOT NULL AND created_at < ?').run(threeDaysAgo);
    db.prepare(`DELETE FROM alert_media WHERE alert_id NOT IN (
      SELECT alert_id FROM alert_media ORDER BY created_at DESC LIMIT 400
    )`).run();
    db.prepare(`DELETE FROM audit_log WHERE id NOT IN (
      SELECT id FROM audit_log ORDER BY created_at DESC LIMIT 4000
    )`).run();
    try { db.exec('PRAGMA optimize; PRAGMA wal_checkpoint(PASSIVE);'); } catch (_) {}
    if (totalMigrated > 0) {
      console.log(`Migrated ${totalMigrated} heavy alert media blobs out of alerts table for instant queries.`);
    }
  } catch (e) {
    console.warn('Alert DB optimization warning:', e && e.message);
  }
}
migrateHeavyAlertBlobsAndPrune();
setInterval(migrateHeavyAlertBlobsAndPrune, 30 * 60 * 1000);

function compactDatabaseIfNeeded() {
  try {
    const fc = db.prepare('PRAGMA freelist_count').get();
    const pc = db.prepare('PRAGMA page_count').get();
    const freePages = Number((fc && fc.freelist_count) || 0);
    const totalPages = Number((pc && pc.page_count) || 0);
    if (freePages > 5000 && totalPages > 0 && (freePages / totalPages) > 0.05) {
      console.log(`Compacting relay.db (${freePages}/${totalPages} free pages)...`);
      const t0 = Date.now();
      db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);');
      console.log(`relay.db compacted successfully in ${Date.now() - t0}ms.`);
    }
  } catch (e) {
    console.warn('relay.db VACUUM warning:', e && e.message);
  }
}
compactDatabaseIfNeeded();

const cctv = createDahuaCctvManager({ db });
const waBot = createWhatsAppBot({ db, dataDir: DATA_DIR, getArchiveRoot, cctv });
const biometrics = createBiometricsManager({
  db,
  onDeviceStatusChange: (ev) => {
    waBot.onBiometricStatusEvent(ev).catch(() => {});
  },
});
waBot.setBiometricsManager(biometrics);

function storeAlertWithSeparatedMedia({ id, deviceId, type, severity, message, rawMeta, createdAt, ignoreExisting }) {
  let obj = {};
  if (rawMeta && typeof rawMeta === 'object') {
    obj = { ...rawMeta };
  } else if (typeof rawMeta === 'string' && rawMeta.trim().startsWith('{')) {
    try { obj = JSON.parse(rawMeta); } catch (_) { obj = {}; }
  }
  const scr = typeof obj.screenshot === 'string' ? obj.screenshot : '';
  const cam = typeof obj.camera_photo === 'string' ? obj.camera_photo : '';
  if (scr) { obj.has_screenshot = true; delete obj.screenshot; }
  if (cam) { obj.has_camera_photo = true; delete obj.camera_photo; }
  const ts = Number(createdAt) > 0 ? Number(createdAt) : Date.now();
  const sql = ignoreExisting
    ? 'INSERT OR IGNORE INTO alerts(id,device_id,type,severity,message,meta,created_at) VALUES(?,?,?,?,?,?,?)'
    : 'INSERT INTO alerts(id,device_id,type,severity,message,meta,created_at) VALUES(?,?,?,?,?,?,?)';
  const info = db.prepare(sql).run(id, deviceId, type, severity, message, JSON.stringify(obj), ts);
  const insertedNew = !ignoreExisting || info.changes > 0;
  if ((scr || cam) && insertedNew) {
    db.prepare('INSERT OR REPLACE INTO alert_media(alert_id, screenshot, camera_photo, created_at) VALUES(?,?,?,?)')
      .run(id, scr, cam, ts);
  }
  if (insertedNew) {
    waBot.onAlert({
      id,
      deviceId,
      type,
      severity,
      message,
      metaObj: obj,
      screenshotB64: scr,
    }).catch(() => {});
  }
  return obj;
}

function now() { return Date.now(); }
function rid(prefix='') { return prefix + crypto.randomUUID().replace(/-/g,''); }
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function hashAdminPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.pbkdf2Sync(Buffer.from(String(pw), 'utf8'), salt, 100000, 32, 'sha256');
  return `pbkdf2$100000$${salt.toString('hex')}$${dk.toString('hex')}`;
}

function verifyPasswordHash(supplied, stored) {
  const s = String(stored || '').trim();
  if (!s) return true;
  if (s.startsWith('pbkdf2$')) {
    const parts = s.split('$');
    if (parts.length !== 4) return false;
    const iters = parseInt(parts[1], 10);
    if (!iters || iters < 10000 || iters > 1000000) return false;
    try {
      const salt = Buffer.from(parts[2], 'hex');
      const expected = Buffer.from(parts[3], 'hex');
      const actual = crypto.pbkdf2Sync(Buffer.from(String(supplied), 'utf8'), salt, iters, expected.length, 'sha256');
      return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    } catch (_) {
      return false;
    }
  }
  const cand = Buffer.from(sha256(String(supplied)), 'utf8');
  const exp = Buffer.from(s, 'utf8');
  return cand.length === exp.length && crypto.timingSafeEqual(cand, exp);
}

function readLocalHostConfig() {
  try {
    const p = 'C:/ProgramData/InternetBlocker/config.json';
    if (!fs.existsSync(p)) return {};
    const raw = fs.readFileSync(p, 'utf8').replace(/^\uFEFF/, '');
    return JSON.parse(raw) || {};
  } catch (_) {
    return {};
  }
}

function verifyAdminJwtToken(rawTok) {
  const tok = String(rawTok || '').trim();
  if (!tok) return null;
  const parts = tok.split('.');
  if (parts.length !== 3) return null;
  const cfg = readLocalHostConfig();
  const secret = (process.env.AGY_JWT_SECRET && process.env.AGY_JWT_SECRET.trim())
    ? process.env.AGY_JWT_SECRET.trim()
    : (cfg.api_token && String(cfg.api_token).trim())
      ? `ibp-jwt-${String(cfg.api_token).trim()}`
      : 'it-elkhawga-default-jwt-secret-key';
  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`${parts[0]}.${parts[1]}`)
    .digest('base64url');
  const sigA = Buffer.from(parts[2], 'utf8');
  const sigB = Buffer.from(expectedSig, 'utf8');
  if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload || !payload.sub || (payload.exp && payload.exp <= nowSec)) return null;
    return { claims: payload, dlpSuperOnly: Boolean(cfg.dlp_super_only) };
  } catch (_) {
    return null;
  }
}

const loginRateBuckets = new Map();
function checkRelayLoginLockout(key) {
  const b = loginRateBuckets.get(key);
  if (!b) return 0;
  const t = now();
  if (b.lockedUntil > t) return Math.ceil((b.lockedUntil - t) / 1000);
  if (t - b.firstFail > 600_000) loginRateBuckets.delete(key);
  return 0;
}
function recordRelayLoginAttempt(key, username, ip, ok) {
  if (ok) {
    loginRateBuckets.delete(key);
    return false;
  }
  const t = now();
  let b = loginRateBuckets.get(key);
  if (!b || (t - b.firstFail > 600_000)) {
    b = { fails: 0, firstFail: t, lockedUntil: 0 };
    loginRateBuckets.set(key, b);
  }
  b.fails += 1;
  if (b.fails >= 5) {
    b.lockedUntil = t + 600_000;
    try {
      const msg = `تحذير أمني: حظر مؤقت بعد 5 محاولات دخول فاشلة لحساب المدير (${username}) من العنوان ${ip || 'بعيد'}`;
      db.prepare('INSERT INTO alerts(id,device_id,type,severity,message,meta,created_at) VALUES(?,?,?,?,?,?,?)')
        .run(rid('alt_'), 'admin_portal', 'auth_fail', 'high', msg, JSON.stringify({ ip, username }), t);
    } catch (_) {}
    return true;
  }
  return false;
}

function json(res, status, body) {
  if (status === 204) {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': CORS_ORIGIN,
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    });
    return res.end();
  }
  const raw = Buffer.from(JSON.stringify(body), 'utf8');
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Vary': 'Accept-Encoding',
    'Access-Control-Allow-Origin': CORS_ORIGIN,
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  };
  if (res.__acceptGzip && raw.length >= 1024) {
    const gz = zlib.gzipSync(raw, { level: zlib.constants.Z_BEST_SPEED });
    headers['Content-Encoding'] = 'gzip';
    headers['Content-Length'] = gz.length;
    res.writeHead(status, headers);
    return res.end(gz);
  }
  headers['Content-Length'] = raw.length;
  res.writeHead(status, headers);
  res.end(raw);
}
async function readBody(req, limit=6*1024*1024) {
  let n = 0; const chunks = [];
  for await (const c of req) { n += c.length; if (n > limit) throw new Error('body too large'); chunks.push(c); }
  const s = Buffer.concat(chunks).toString('utf8');
  return s ? JSON.parse(s) : {};
}
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
}
function clientIpFromReq(req) {
  const xff = String(req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '').split(',')[0].trim();
  const raw = xff || String((req.socket && req.socket.remoteAddress) || '').trim();
  return raw.replace(/^::ffff:/i, '');
}
function requireAdmin(req, res) {
  if (!ADMIN_KEY || bearer(req) !== ADMIN_KEY) { json(res, 401, {ok:false,error:'unauthorized'}); return false; }
  return true;
}
function getDeviceByToken(token) {
  if (!token) return null;
  const h = sha256(token);
  const row = db.prepare('SELECT * FROM devices WHERE device_token_hash=?').get(h);
  if (row) {
    try { db.prepare('UPDATE devices SET last_seen=? WHERE device_id=?').run(now(), row.device_id); } catch (_) {}
  }
  return row || null;
}
function pendingCommand(deviceId) {
  return db.prepare('SELECT id,type FROM commands WHERE device_id=? AND acked_at IS NULL AND created_at <= ? ORDER BY created_at ASC LIMIT 1').get(deviceId, now()) || null;
}

// ============================================================================
// Unified Project Subsystem Logger (C:\Users\IT APP\Desktop\blockwebsite\logs)
// ============================================================================
const PROJECT_LOGS_DIR = 'C:\\Users\\IT APP\\Desktop\\blockwebsite\\logs';
const LOG_FILES = {
  master: path.join(PROJECT_LOGS_DIR, '00-master-all-events.log'),
  devices: path.join(PROJECT_LOGS_DIR, '01-devices-and-commands.log'),
  updates: path.join(PROJECT_LOGS_DIR, '02-auto-updates.log'),
  policies: path.join(PROJECT_LOGS_DIR, '03-policies-and-groups.log'),
  dlp: path.join(PROJECT_LOGS_DIR, '04-dlp-uploads-and-alerts.log'),
  cctv: path.join(PROJECT_LOGS_DIR, '05-cctv-cameras.log'),
  errors: path.join(PROJECT_LOGS_DIR, '06-errors-and-diagnostics.log'),
  audit: path.join(PROJECT_LOGS_DIR, '07-admin-audit-trail.log'),
  localAgent: path.join(PROJECT_LOGS_DIR, '08-local-server-and-agent.log'),
  biometrics: path.join(PROJECT_LOGS_DIR, '09-biometrics-attendance.log'),
};
const logThrottleCache = new Map();

function ensureProjectLogsDir() {
  try {
    if (!fs.existsSync(PROJECT_LOGS_DIR)) {
      fs.mkdirSync(PROJECT_LOGS_DIR, { recursive: true });
    }
  } catch (_) {}
}

function appendSafeLogFile(filePath, line) {
  try {
    if (fs.existsSync(filePath)) {
      const st = fs.statSync(filePath);
      if (st.size > 5 * 1024 * 1024) {
        const content = fs.readFileSync(filePath, 'utf8');
        const tailLines = content.split(/\r?\n/).slice(-1200).join('\r\n') + '\r\n';
        fs.writeFileSync(filePath, tailLines, 'utf8');
      }
    }
    fs.appendFileSync(filePath, line + '\r\n', 'utf8');
  } catch (_) {}
}

function writeProjectLog(category, level, event, detail, throttleKey = '', throttleMs = 0) {
  try {
    const nowMs = Date.now();
    if (throttleKey && throttleMs > 0) {
      const prev = logThrottleCache.get(throttleKey) || 0;
      if (nowMs - prev < throttleMs) return;
      logThrottleCache.set(throttleKey, nowMs);
      if (logThrottleCache.size > 600) logThrottleCache.clear();
    }
    ensureProjectLogsDir();
    const iso = new Date(nowMs).toISOString();
    const catTag = String(category || 'SYSTEM').toUpperCase();
    const line = `[${iso}] [${level}] [${catTag}] [${event}] ${detail}`;
    appendSafeLogFile(LOG_FILES.master, line);
    const targetFile = LOG_FILES[category];
    if (targetFile && targetFile !== LOG_FILES.master) {
      appendSafeLogFile(targetFile, line);
    }
    if (level === 'ERROR' || level === 'WARN') {
      appendSafeLogFile(LOG_FILES.errors, line);
    }
  } catch (_) {}
}

function exportInitialHistoricalLogsSnapshot() {
  try {
    ensureProjectLogsDir();
    const bootMarker = `[${new Date().toISOString()}] [INFO] [SYSTEM] [RELAY_BOOT] بدء تشغيل السيرفر السحابي الموحد (Relay v${RELAY_VERSION}) وتفعيل منظومة التسجيل الشامل في: ${PROJECT_LOGS_DIR}`;
    appendSafeLogFile(LOG_FILES.master, bootMarker);

    // 1. Snapshot of all enrolled devices
    const devs = db.prepare('SELECT device_id,label,hostname,ip,app_version,blocked,admin_open,usb_blocked,group_id,last_seen,last_event,rustdesk_id FROM devices ORDER BY last_seen DESC').all();
    for (const d of devs) {
      const seenIso = d.last_seen ? new Date(d.last_seen).toISOString() : 'never';
      const stateStr = Number(d.admin_open) === 1 ? 'OPEN_BY_ADMIN' : (d.blocked ? 'BLOCKED' : 'UNBLOCKED');
      writeProjectLog(
        'devices',
        'INFO',
        'DEVICE_SNAPSHOT',
        `جهاز مسجل: "${d.label || d.hostname}" | Host=${d.hostname} | ID=${d.device_id} | IP=${d.ip} | Ver=v${d.app_version} | الحالة=${stateStr} | USB=${d.usb_blocked ? 'LOCKED' : 'OPEN'} | Group=${d.group_id || 'بدون مجموعة'} | RustDesk=${d.rustdesk_id || '-'} | آخر ظهور=${seenIso}`
      );
    }

    // 2. Snapshot of groups & policies
    const grps = groupList();
    const globalPol = getPolicy() || {};
    writeProjectLog(
      'policies',
      'INFO',
      'GLOBAL_POLICY_SNAPSHOT',
      `السياسة العامة (بدون مجموعة): الوضع=${globalPol.mode || 'whitelist'} | المواقع المسموحة=(${(globalPol.allowed || []).join(', ')}) | المواقع المحظورة=(${(globalPol.blocked || []).join(', ')})`
    );
    for (const g of grps) {
      writeProjectLog(
        'policies',
        'INFO',
        'GROUP_POLICY_SNAPSHOT',
        `مجموعة "${g.name}" (${g.id}): الأجهزة=${g.devices} | الوضع=${g.mode} | المتصفح النظيف=${g.ephemeral_browser ? 'مفعل' : 'معطل'} | قفل الفلاشات=${g.usb_block ? 'مفعل' : 'معطل'} | المواقع المسموحة=(${(g.allowed || []).join(', ')})`
      );
    }

    // 3. Snapshot of recent DLP uploaded files
    const upRows = db.prepare('SELECT file_id,device_name,windows_user,channel,file_name,file_size,recipient_name,recipient_phone,stored_path,created_at FROM uploaded_files ORDER BY created_at DESC LIMIT 60').all();
    for (const u of upRows.reverse()) {
      const dt = u.created_at ? new Date(u.created_at).toISOString() : '';
      writeProjectLog(
        'dlp',
        'INFO',
        'DLP_ARCHIVE_RECORD',
        `[${dt}] ملف مؤرشف: "${u.file_name}" (${Math.round((u.file_size || 0) / 1024)} KB) | الجهاز=${u.device_name} | المستخدم=${u.windows_user || '-'} | القناة=${u.channel} | المستلم=${u.recipient_name || '-'} (${u.recipient_phone || '-'}) | المسار=${u.stored_path}`
      );
    }

    // 4. Snapshot of recent security alerts
    const altRows = db.prepare('SELECT id,device_id,type,severity,message,created_at FROM alerts ORDER BY created_at DESC LIMIT 60').all();
    for (const a of altRows.reverse()) {
      const dt = a.created_at ? new Date(a.created_at).toISOString() : '';
      writeProjectLog(
        'dlp',
        a.severity === 'critical' || a.severity === 'high' ? 'WARN' : 'INFO',
        `ALERT_${String(a.type || 'TAMPER').toUpperCase()}`,
        `[${dt}] تنبيه أمني (${a.severity}): الجهاز=${a.device_id} | الرسالة=${a.message}`
      );
    }

    // 5. Snapshot of recent audit log entries
    const audRows = db.prepare('SELECT actor,action,target,result,meta,created_at FROM audit_log ORDER BY created_at DESC LIMIT 80').all();
    for (const ar of audRows.reverse()) {
      const dt = ar.created_at ? new Date(ar.created_at).toISOString() : '';
      writeProjectLog(
        'audit',
        'INFO',
        `AUDIT_${String(ar.action || 'ACTION').toUpperCase()}`,
        `[${dt}] الفاعل=${ar.actor} | الإجراء=${ar.action} | الهدف=${ar.target || '-'} | النتيجة=${ar.result} | تفاصيل=${ar.meta || '{}'}`
      );
    }

    // 6. Sync existing CCTV log & Local Rust activity.log
    try {
      const cctvSrc = 'C:\\Users\\IT APP\\Desktop\\blockwebsite\\cctv-cameras.log';
      if (fs.existsSync(cctvSrc) && !fs.existsSync(LOG_FILES.cctv)) {
        fs.copyFileSync(cctvSrc, LOG_FILES.cctv);
      }
    } catch (_) {}
    try {
      const rustLogSrc = 'C:\\ProgramData\\InternetBlocker\\activity.log';
      if (fs.existsSync(rustLogSrc)) {
        fs.copyFileSync(rustLogSrc, LOG_FILES.localAgent);
      } else {
        appendSafeLogFile(LOG_FILES.localAgent, `[${new Date().toISOString()}] [INFO] [LOCAL_AGENT] سجل السيرفر المحلي والعميل (C:\\ProgramData\\InternetBlocker\\activity.log) جاهز للتسجيل.`);
      }
    } catch (_) {}

    appendSafeLogFile(LOG_FILES.updates, `[${new Date().toISOString()}] [INFO] [UPDATES] سجل التحديثات التلقائية للأجهزة (Auto-Update v1.2.6) جاهز للتسجيل.`);
    appendSafeLogFile(LOG_FILES.errors, `[${new Date().toISOString()}] [INFO] [DIAGNOSTICS] سجل الأخطاء والتشخيص الفني جاهز — لا توجد أخطاء حرجة حالياً.`);
  } catch (e) {
    console.error('Log snapshot error:', e);
  }
}

function audit(actor, action, target, result, meta) {
  try {
    db.prepare('INSERT INTO audit_log(id,actor,action,target,result,meta,created_at) VALUES(?,?,?,?,?,?,?)')
      .run(rid('aud_'), actor, action, target || null, result || 'ok', JSON.stringify(meta || {}), now());
    const actStr = String(action || '');
    const metaJson = JSON.stringify(meta || {});
    let cat = 'audit';
    if (actStr.includes('group') || actStr.includes('policy')) cat = 'policies';
    else if (['block', 'unblock', 'usb_block', 'usb_unblock', 'restart', 'shutdown', 'device_rename', 'device_delete', 'enroll'].includes(actStr)) cat = 'devices';
    else if (actStr.includes('cctv')) cat = 'cctv';
    writeProjectLog(
      cat,
      result && result !== 'ok' ? 'WARN' : 'INFO',
      `AUDIT_${actStr.toUpperCase()}`,
      `الفاعل=${actor} | الإجراء=${actStr} | الهدف=${target || '-'} | النتيجة=${result || 'ok'} | تفاصيل=${metaJson}`
    );
    if (cat !== 'audit') {
      appendSafeLogFile(
        LOG_FILES.audit,
        `[${new Date().toISOString()}] [INFO] [AUDIT] [AUDIT_${actStr.toUpperCase()}] الفاعل=${actor} | الإجراء=${actStr} | الهدف=${target || '-'} | النتيجة=${result || 'ok'} | تفاصيل=${metaJson}`
      );
    }
  } catch (e) { /* ignore */ }
}

function cleanPolicyHost(raw) {
  let s = String(raw || '').trim().toLowerCase();
  if (s.startsWith('https://')) s = s.slice(8);
  else if (s.startsWith('http://')) s = s.slice(7);
  const slashIdx = s.search(/[/?#]/);
  if (slashIdx >= 0) s = s.slice(0, slashIdx);
  const colonIdx = s.indexOf(':');
  if (colonIdx >= 0) s = s.slice(0, colonIdx);
  s = s.replace(/^\.+|\.+$/g, '');
  if (!s || s.length > 253 || !/^[a-z0-9.-]+$/.test(s) || s.includes('..')) return '';
  return s;
}

function normalizePolicyDomains(list, isAllowed) {
  const arr = Array.isArray(list) ? list : [];
  const seen = new Set();
  const out = [];
  const pushHost = (h) => {
    const c = cleanPolicyHost(h);
    if (c && !seen.has(c)) {
      seen.add(c);
      out.push(c);
    }
  };
  for (const item of arr) {
    pushHost(item);
  }
  if (isAllowed) {
    const hasWa = out.some(d => d.includes('whatsapp'));
    if (hasWa) {
      pushHost('whatsapp.com');
      pushHost('web.whatsapp.com');
      pushHost('whatsapp.net');
      pushHost('web.whatsapp.net');
    }
    const hasErp = out.some(d => d.includes('elkhawaga.uk') || d === '26.32.24.229' || d === '192.168.10.102');
    if (hasErp) {
      pushHost('elkhawaga.uk');
      pushHost('26.32.24.229');
      pushHost('192.168.10.102');
      pushHost('10.10.1.1');
    }
  }
  return out;
}

const ALL_OPEN_TLDS = [
  'com','net','org','eg','uk','io','co','ai','me','tv','edu','gov','info','biz','app','dev',
  'cloud','live','online','site','store','tech','de','fr','sa','ae','us','ca','ru','cn','in',
  'jp','br','it','es','nl','se','ch','au','nz','za','tr','gr','pl','cz','at','be','dk','fi',
  'no','pt','ie','qa','kw','bh','om','jo','lb','ma','tn','dz','sd','iq','sy','ye','ly','ps',
  'youtube.com','facebook.com','m.facebook.com','twitter.com','x.com','instagram.com',
  'tiktok.com','reddit.com','netflix.com','twitch.tv','snapchat.com','pinterest.com','linkedin.com',
  'google.com','microsoft.com','live.com','office.com','bing.com','msn.com','cloudflare.com','googleapis.com','gstatic.com'
];
try { db.exec('ALTER TABLE devices ADD COLUMN admin_open INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
try {
  db.exec("UPDATE devices SET admin_open=1, blocked=0 WHERE device_id IN (SELECT device_id FROM commands WHERE type='unblock' AND acked_at IS NULL)");
} catch (_) {}

function buildEffectiveDevicePolicy(dev) {
  const basePol = (dev && dev.group_id && getGroupPolicy(dev.group_id)) || getPolicy();
  if (!basePol) return null;
  if (dev && Number(dev.admin_open) === 1) {
    const mergedAllowed = Array.from(new Set([...(basePol.allowed || []), ...ALL_OPEN_TLDS]));
    return {
      ...basePol,
      version: String(basePol.version || 'v1') + '__OPEN',
      mode: 'blacklist',
      blocked: [],
      allowed: mergedAllowed,
    };
  }
  return basePol;
}

function getPolicy() {
  const row = db.prepare('SELECT version,data FROM policy WHERE id=1').get();
  if (!row) return null;
  const parsed = JSON.parse(row.data);
  parsed.allowed = normalizePolicyDomains(parsed.allowed, true);
  parsed.blocked = normalizePolicyDomains(parsed.blocked, false);
  return { version: row.version, ...parsed };
}
function getGroupPolicy(groupId) {
  if (!groupId) return null;
  const row = db.prepare('SELECT version,data FROM group_policy WHERE group_id=?').get(groupId);
  if (!row) return null;
  const gData = JSON.parse(row.data);
  const globalPol = getPolicy() || {};
  gData.allowed = normalizePolicyDomains(gData.allowed, true);
  gData.blocked = normalizePolicyDomains(gData.blocked, false);
  return {
    ...globalPol,
    ...gData,
    usb_block: Boolean(gData.usb_block || globalPol.usb_block),
    version: row.version,
  };
}
function groupList() {
  const rows = db.prepare('SELECT id,name,created_at FROM groups ORDER BY created_at ASC').all();
  return rows.map(g => {
    const rawRow = db.prepare('SELECT version,data FROM group_policy WHERE group_id=?').get(g.id);
    const pol = rawRow ? { version: rawRow.version, ...(JSON.parse(rawRow.data)) } : { version: '', mode: 'whitelist', allowed: [], blocked: [] };
    const count = db.prepare('SELECT COUNT(*) AS n FROM devices WHERE group_id=?').get(g.id).n;
    return { id: g.id, name: g.name, created_at: g.created_at, devices: count,
      version: pol.version, mode: pol.mode, allowed: pol.allowed || [], blocked: pol.blocked || [],
      ephemeral_browser: !!pol.ephemeral_browser, usb_block: !!pol.usb_block };
  });
}

const server = http.createServer(async (req, res) => {
  try {
    res.__acceptGzip = /\bgzip\b/i.test(String(req.headers['accept-encoding'] || '')) && req.method !== 'HEAD';
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (req.method === 'OPTIONS') return json(res, 204, {});
    // Health
    const findNewestSetupInstaller = (productPrefix) => {
      const searchDirs = [
        path.join(process.cwd(), '..', 'final-release'),
        path.join(process.cwd(), 'final-release'),
        'C:/Users/IT APP/Desktop/blockwebsite/final-release',
        'C:/Users/IT APP/Desktop/tools',
      ];
      const parseSemver = (v) => String(v || '0.0.0').split('.').map((n) => parseInt(n, 10) || 0);
      const cmpSemver = (a, b) => {
        const pa = parseSemver(a), pb = parseSemver(b);
        for (let i = 0; i < 3; i++) {
          if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
        }
        return 0;
      };
      let best = null;
      const seenPaths = new Set();
      for (const dir of searchDirs) {
        try {
          if (!fs.existsSync(dir)) continue;
          for (const fname of fs.readdirSync(dir)) {
            if (!fname.startsWith(productPrefix) || !fname.endsWith('_x64-setup.exe')) continue;
            const full = path.resolve(dir, fname);
            if (seenPaths.has(full.toLowerCase())) continue;
            seenPaths.add(full.toLowerCase());
            const st = fs.statSync(full);
            if (!st.isFile() || st.size <= 500000) continue;
            const verMatch = fname.slice(productPrefix.length).match(/^([0-9]+\.[0-9]+\.[0-9]+)_x64-setup\.exe$/i);
            const ver = verMatch ? verMatch[1] : '1.0.0';
            if (
              !best ||
              Math.floor(st.mtimeMs) > Math.floor(best.stat.mtimeMs) + 2000 ||
              (Math.abs(Math.floor(st.mtimeMs) - Math.floor(best.stat.mtimeMs)) <= 2000 && cmpSemver(ver, best.version) > 0)
            ) {
              best = { path: full, stat: st, version: ver };
            }
          }
        } catch (_) {}
      }
      return best;
    };

    if (req.method === 'GET' && url.pathname === '/healthz') return json(res, 200, {ok:true, version: RELAY_VERSION, ts: now()});
    if (req.method === 'GET' && url.pathname === '/api/v1/version') {
      const ci = findNewestSetupInstaller('IT ELKHAWGA Client_');
      return json(res, 200, { ok: true, version: RELAY_VERSION, latest_client_version: (ci && ci.version) || '1.1.2' });
    }
    if (req.method === 'GET' && (url.pathname === '/api/v1/client-setup.exe' || url.pathname === '/api/client-setup.exe')) {
      const foundInfo = findNewestSetupInstaller('IT ELKHAWGA Client_');
      if (!foundInfo) return json(res, 404, { error: 'client installer not found on relay' });
      const { path: found, stat, version: ver } = foundInfo;
      const dlIp = clientIpFromReq(req);
      console.log(`[UPDATE-DL] GET ${url.pathname} ip=${dlIp} file=${path.basename(found)} ver=${ver} size=${stat.size}`);
      writeProjectLog('updates', 'INFO', 'UPDATE_DOWNLOAD_START', `بدء تحميل التحديث التلقائي: الملف=${path.basename(found)} (v${ver}) | الحجم=${Math.round(stat.size / 1024)} KB | IP=${dlIp}`);
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': stat.size,
        'Content-Disposition': 'attachment; filename="it-elkhawga-client-setup.exe"',
        'Access-Control-Allow-Origin': CORS_ORIGIN,
      });
      const st = fs.createReadStream(found);
      st.on('end', () => {
        console.log(`[UPDATE-DL-DONE] ip=${dlIp} size=${stat.size}`);
        writeProjectLog('updates', 'INFO', 'UPDATE_DOWNLOAD_DONE', `اكتمل تحميل ملف التحديث بنجاح (v${ver}) | IP=${dlIp} | الحجم=${Math.round(stat.size / 1024)} KB`);
      });
      st.on('error', (e) => {
        console.log(`[UPDATE-DL-ERR] ip=${dlIp} err=${e.message}`);
        writeProjectLog('updates', 'ERROR', 'UPDATE_DOWNLOAD_ERROR', `خطأ أثناء تحميل ملف التحديث (v${ver}) | IP=${dlIp} | السبب=${e.message}`);
      });
      st.pipe(res);
      return;
    }

    // Authenticated Admin self-update metadata & NSIS installer download
    if (req.method === 'GET' && (url.pathname === '/api/v1/admin/update-info' || url.pathname === '/api/v1/admin/admin-setup.exe')) {
      if (!requireAdmin(req, res)) return;
      const foundAdminInfo = findNewestSetupInstaller('IT ELKHAWGA Admin_');
      if (!foundAdminInfo) return json(res, 404, { ok: false, error: 'admin installer not found on relay' });
      const { path: foundAdmin, stat: st, version: adminVer } = foundAdminInfo;
      if (url.pathname === '/api/v1/admin/update-info') {
        const cacheKey = `${foundAdmin}|${st.size}|${Math.floor(st.mtimeMs)}`;
        if (!globalThis.__adminSetupHashCache || globalThis.__adminSetupHashCache.key !== cacheKey) {
          const digest = crypto.createHash('sha256').update(fs.readFileSync(foundAdmin)).digest('hex');
          globalThis.__adminSetupHashCache = { key: cacheKey, sha256: digest };
        }
        return json(res, 200, {
          ok: true,
          available: true,
          size: st.size,
          mtime_ms: Math.floor(st.mtimeMs),
          sha256: globalThis.__adminSetupHashCache.sha256,
          version: adminVer || '1.1.4',
        });
      }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': st.size,
        'Content-Disposition': 'attachment; filename="it-elkhawga-admin-setup.exe"',
        'Access-Control-Allow-Origin': CORS_ORIGIN,
      });
      fs.createReadStream(foundAdmin).pipe(res);
      return;
    }

    // Download archived uploaded file copy (DLP evidence) — strictly authenticated (ADMIN_KEY or Admin JWT)
    const uploadDlMatch = url.pathname.match(/^\/api(?:\/v1)?\/uploads\/([^/]+)$/);
    if (req.method === 'GET' && uploadDlMatch) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && hdrTok === ADMIN_KEY);
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'يرجى تسجيل الدخول بحساب المدير لتحميل الملفات المؤرشفة' });
      }
      if (jwtVerified && jwtVerified.dlpSuperOnly && String(jwtVerified.claims.role || '').toLowerCase() !== 'super') {
        return json(res, 403, { ok: false, error: 'تم حصر تحميل ملفات الأرشيف الحساسة بحساب السوبر أدمن فقط' });
      }
      const fid = decodeURIComponent(uploadDlMatch[1]).replace(/[^A-Za-z0-9_-]/g, '');
      if (!fid) return json(res, 400, { ok: false, error: 'invalid file_id' });
      const dispKind = url.searchParams.get('inline') === '1' ? 'inline' : 'attachment';
      const etagVal = `"${fid}"`;
      const inm = String(req.headers['if-none-match'] || '');
      if (inm && inm.includes(etagVal)) {
        const h304 = {
          'ETag': etagVal,
          'Access-Control-Allow-Origin': CORS_ORIGIN,
        };
        if (dispKind === 'inline') {
          h304['Cache-Control'] = 'private, max-age=604800, immutable';
        }
        res.writeHead(304, h304);
        return res.end();
      }
      const row = db.prepare('SELECT file_name, stored_path FROM uploaded_files WHERE file_id=?').get(fid);
      let filePath = row && row.stored_path && fs.existsSync(row.stored_path) ? row.stored_path : '';
      let fileName = (row && row.file_name) || '';
      if (!filePath) {
        const logList = readArchiveLogEntries();
        for (let i = logList.length - 1; i >= 0; i--) {
          const entry = logList[i];
          if (entry && entry.file_id === fid && entry.stored_path && fs.existsSync(entry.stored_path)) {
            filePath = entry.stored_path;
            if (!fileName) fileName = entry.file_name || '';
            break;
          }
        }
      }
      if (!filePath) {
        for (const dir of [UPLOADS_DIR, 'C:/ProgramData/InternetBlocker/uploaded-files']) {
          try {
            if (!fs.existsSync(dir)) continue;
            const hit = fs.readdirSync(dir).find((f) => f.startsWith(fid + '__'));
            if (hit) {
              filePath = path.join(dir, hit);
              if (!fileName) fileName = hit.slice(fid.length + 2);
              break;
            }
          } catch (_) {}
        }
      }
      if (!filePath || !fs.existsSync(filePath)) return json(res, 404, { ok: false, error: 'file not found' });
      const stat = fs.statSync(filePath);
      const asciiName = (fileName || 'file.bin').replace(/["\r\n\\/]/g, '_').replace(/[^\x20-\x7E]/g, '_') || 'file.bin';
      const utf8Name = encodeURIComponent(fileName || 'file.bin');
      const lowerExt = asciiName.toLowerCase();
      const mime = (lowerExt.endsWith('.jpg') || lowerExt.endsWith('.jpeg')) ? 'image/jpeg'
        : lowerExt.endsWith('.png') ? 'image/png'
        : lowerExt.endsWith('.webp') ? 'image/webp'
        : lowerExt.endsWith('.gif') ? 'image/gif'
        : lowerExt.endsWith('.pdf') ? 'application/pdf'
        : 'application/octet-stream';
      const dlHeaders = {
        'Content-Type': mime,
        'Content-Length': stat.size,
        'Content-Disposition': `${dispKind}; filename="${asciiName}"; filename*=UTF-8''${utf8Name}`,
        'ETag': etagVal,
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Access-Control-Allow-Origin': CORS_ORIGIN,
        'Access-Control-Expose-Headers': 'Content-Disposition, Content-Length, ETag',
      };
      if (dispKind === 'inline') {
        dlHeaders['Cache-Control'] = 'private, max-age=604800, immutable';
      }
      res.writeHead(200, dlHeaders);
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    // Proxy authenticated ERP backup file downloads (/api/erp-backups/download/:name or /api/v1/erp-backups/download/:name -> 127.0.0.1:8787)
    if (req.method === 'GET' && (url.pathname.startsWith('/api/v1/erp-backups/download/') || url.pathname.startsWith('/api/erp-backups/download/'))) {
      const authCtx = checkUploadDownloadAuth(req, url);
      if (!authCtx.ok) {
        return json(res, authCtx.code || 401, { ok: false, error: authCtx.error || 'unauthorized' });
      }
      const cfg = readLocalHostConfig();
      const apiToken = String(cfg.api_token || '').trim();
      const lanPort = Number(cfg.server_port || 8787) || 8787;
      const dlReq = http.request(
        {
          hostname: '127.0.0.1',
          port: lanPort,
          path: url.pathname,
          method: 'GET',
          headers: { authorization: `Bearer ${apiToken}` },
          agent: lanKeepAliveAgent,
          timeout: 120000,
        },
        (dlRes) => {
          res.writeHead(dlRes.statusCode || 200, {
            'Content-Type': dlRes.headers['content-type'] || 'application/octet-stream',
            'Content-Disposition': dlRes.headers['content-disposition'] || 'attachment',
            'X-Content-Type-Options': 'nosniff',
            'Access-Control-Allow-Origin': CORS_ORIGIN,
          });
          dlRes.pipe(res);
        }
      );
      dlReq.on('error', () => {
        if (!res.headersSent) json(res, 502, { ok: false, error: 'تعذر تحميل ملف النسخة من السيرفر الرئيسي' });
      });
      dlReq.end();
      return;
    }

    // Proxy LAN Admin Server endpoints (/api/v1/admin/lan-proxy/* -> http://127.0.0.1:8787/api/admin/*)
    // so remote IT Engineers outside the company can see and manage company LAN devices & server backups!
    if (url.pathname.startsWith('/api/v1/admin/lan-proxy/')) {
      if (!requireAdmin(req, res)) return;
      const cfg = readLocalHostConfig();
      const apiToken = String(cfg.api_token || '').trim();
      const lanPort = Number(cfg.server_port || 8787) || 8787;
      if (!apiToken) {
        return json(res, 503, { ok: false, error: 'local LAN server token not initialized' });
      }
      const subPath = url.pathname.slice('/api/v1/admin/lan-proxy/'.length);
      const targetPath = '/api/admin/' + subPath + (url.search || '');
      const fwdHeaders = {
        host: `127.0.0.1:${lanPort}`,
        authorization: `Bearer ${apiToken}`,
      };
      if (req.headers['content-type']) fwdHeaders['content-type'] = req.headers['content-type'];
      if (req.headers['content-length']) fwdHeaders['content-length'] = req.headers['content-length'];
      const proxyReq = http.request(
        {
          hostname: '127.0.0.1',
          port: lanPort,
          path: targetPath,
          method: req.method,
          headers: fwdHeaders,
          agent: lanKeepAliveAgent,
          timeout: 15000,
        },
        (proxyRes) => {
          let chunks = [];
          proxyRes.on('data', (c) => chunks.push(c));
          proxyRes.on('end', () => {
            const rawBuf = Buffer.concat(chunks);
            const outHeaders = {
              'Content-Type': proxyRes.headers['content-type'] || 'application/json; charset=utf-8',
              'X-Content-Type-Options': 'nosniff',
              'Vary': 'Accept-Encoding',
              'Access-Control-Allow-Origin': CORS_ORIGIN,
            };
            if (res.__acceptGzip && rawBuf.length >= 1024 && !proxyRes.headers['content-encoding']) {
              const gz = zlib.gzipSync(rawBuf, { level: zlib.constants.Z_BEST_SPEED });
              outHeaders['Content-Encoding'] = 'gzip';
              outHeaders['Content-Length'] = gz.length;
              res.writeHead(proxyRes.statusCode || 200, outHeaders);
              return res.end(gz);
            }
            outHeaders['Content-Length'] = rawBuf.length;
            res.writeHead(proxyRes.statusCode || 200, outHeaders);
            res.end(rawBuf);
          });
        }
      );
      proxyReq.on('error', () => {
        if (!res.headersSent) json(res, 502, { ok: false, error: 'تعذر الاتصال بالسيرفر المحلي 8787' });
      });
      req.pipe(proxyReq);
      return;
    }

    // Admin: create pairing token
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/pairing-tokens') {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const token = rid('pair_');
      const mins = Number(body.expires_minutes||0);
      const exp = mins > 0 ? now() + Math.max(5, mins) * 60_000 : 0;  // 0 = never expires
      db.prepare('INSERT INTO pairing_tokens(token,label,created_at,expires_at) VALUES(?,?,?,?)')
        .run(token, body.label||'', now(), exp);
      audit('admin', 'pairing_token', token.slice(0, 12), 'ok', {label: body.label || ''});
      return json(res, 200, {ok:true, token, expires_at: exp});
    }
    // Shared admin accounts across all admin installs.
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/users') {
      if (!requireAdmin(req,res)) return;
      const rows = db.prepare('SELECT username, role, password_hash FROM admin_users ORDER BY username ASC').all();
      return json(res, 200, {
        ok: true,
        users: rows.map(r => ({
          username: r.username,
          role: r.role,
          password_hash: r.password_hash || '',
        })),
      });
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/users') {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '').trim();
      const rawHash = String(body.password_hash || '').trim();
      const role = String(body.role || 'admin').trim() || 'admin';
      if (!username) return json(res, 400, { ok: false, error: 'username required' });
      const key = rawHash || (password ? hashAdminPassword(password) : '');
      const nowTs = now();
      db.prepare(`INSERT INTO admin_users(username,password_hash,role,created_at,updated_at)
        VALUES(?,?,?,?,?)
        ON CONFLICT(username) DO UPDATE SET
          password_hash=CASE WHEN excluded.password_hash!='' THEN excluded.password_hash ELSE admin_users.password_hash END,
          role=excluded.role,
          updated_at=excluded.updated_at`)
        .run(username, key, role, nowTs, nowTs);
      audit(String(body.actor_username || 'admin'), 'admin_user_upsert', username, 'ok', { role });
      return json(res, 200, { ok: true });
    }
    const adminUserMatch = url.pathname.match(/^\/api\/v1\/admin\/users\/([^/]+)$/);
    if (adminUserMatch && req.method === 'DELETE') {
      if (!requireAdmin(req,res)) return;
      const username = decodeURIComponent(adminUserMatch[1]).replace(/%20/g, ' ');
      const removed = db.prepare('DELETE FROM admin_users WHERE lower(username)=lower(?)').run(username).changes;
      audit('admin', 'admin_user_delete', username, removed ? 'ok' : 'not_found', {});
      return json(res, 200, { ok: true, deleted: !!removed });
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/login') {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const clientIp = String(body.client_ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      if (!username) return json(res, 401, { ok: false, error: 'missing username' });
      const rateKey = `${clientIp}|${username.toLowerCase()}`;
      const waitSec = checkRelayLoginLockout(rateKey);
      if (waitSec > 0) {
        return json(res, 429, { ok: false, error: `تم حظر المحاولات مؤقتاً لحماية الحساب. حاول بعد ${Math.max(1, Math.ceil(waitSec / 60))} دقيقة` });
      }
      const row = db.prepare('SELECT username, role, password_hash FROM admin_users WHERE lower(username)=lower(?)').get(username);
      if (!row) {
        recordRelayLoginAttempt(rateKey, username, clientIp, false);
        return json(res, 401, { ok: false, error: 'invalid credentials' });
      }
      const ok = verifyPasswordHash(password, row.password_hash);
      if (!ok) {
        recordRelayLoginAttempt(rateKey, username, clientIp, false);
        return json(res, 401, { ok: false, error: 'invalid credentials' });
      }
      recordRelayLoginAttempt(rateKey, username, clientIp, true);
      if (password && row.password_hash && !String(row.password_hash).startsWith('pbkdf2$')) {
        try {
          db.prepare('UPDATE admin_users SET password_hash=?, updated_at=? WHERE lower(username)=lower(?)')
            .run(hashAdminPassword(password), now(), username);
        } catch (_) {}
      }
      return json(res, 200, { ok: true, success: true, username: row.username, role: row.role, is_super_admin: row.role === 'super' });
    }

    // ----- Dashboard KPIs -----
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/rustdesk-oss') {
      if (!requireAdmin(req, res)) return;
      const rdDir = 'C:/ProgramData/IT-ELKHAWGA-RustDeskServer';
      const hbbsExists = fs.existsSync(path.join(rdDir, 'hbbs.exe')) && fs.existsSync(path.join(rdDir, 'hbbr.exe'));
      const pubFile = path.join(rdDir, 'id_ed25519.pub');
      let publicKey = '';
      try { if (fs.existsSync(pubFile)) publicKey = fs.readFileSync(pubFile, 'utf8').trim(); } catch (_) {}
      let lanIp = '';
      try {
        const nets = os.networkInterfaces();
        const allv4 = [];
        for (const list of Object.values(nets)) {
          for (const net of (list || [])) {
            if ((net.family === 'IPv4' || net.family === 4) && !net.internal && !String(net.address).startsWith('169.254.')) {
              allv4.push(String(net.address));
            }
          }
        }
        lanIp = allv4.find((ip) => /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip))
          || allv4.find((ip) => !ip.startsWith('100.'))
          || allv4[0]
          || '';
      } catch (_) {}
      const pol = getPolicy() || {};
      return json(res, 200, {
        ok: true,
        installed: hbbsExists,
        lan_ip: lanIp,
        lan_host: lanIp ? `${lanIp}:21116` : '',
        public_key: publicKey,
        active_server: pol.rustdesk_server || '',
        active_key: pol.rustdesk_key || '',
      });
    }
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/stats') {
      if (!requireAdmin(req,res)) return;
      const totalUsers = db.prepare('SELECT COUNT(*) AS n FROM devices').get().n;
      const onlineUsers = db.prepare('SELECT COUNT(*) AS n FROM devices WHERE last_seen > ?')
        .get(now() - 120_000).n;
      const commands = db.prepare('SELECT COUNT(*) AS n FROM commands').get().n;
      const pending = db.prepare('SELECT COUNT(*) AS n FROM commands WHERE acked_at IS NULL').get().n;
      const engagement = totalUsers ? Math.round((onlineUsers / totalUsers) * 1000) / 10 : 0;
      return json(res, 200, {
        ok: true,
        stats: {
          users: { value: totalUsers, growth: 12.5 },
          profit: { value: 128450, growth: 8.2 },     // mock placeholder
          orders: { value: pending, growth: -3.1 },   // active (unacked) commands
          engagement: { value: engagement, growth: 4.4 }
        }
      });
    }

    // ----- Dahua CCTV Live Center -----
    // 1. Zero-Transcode fMP4 over MSE live stream (/api/cctv/mse)
    if (req.method === 'GET' && (url.pathname === '/api/cctv/mse' || url.pathname === '/api/v1/cctv/mse')) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && hdrTok === ADMIN_KEY);
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'unauthorized' });
      }
      const cctvCfg = cctv.getSettings();
      const actor = jwtVerified && jwtVerified.claims ? String(jwtVerified.claims.sub || '') : 'admin';
      const role = jwtVerified && jwtVerified.claims ? String(jwtVerified.claims.role || 'super').toLowerCase() : 'super';
      if (cctvCfg.super_only && role !== 'super') {
        return json(res, 403, { ok: false, error: 'تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط' });
      }
      const dvrId = String(url.searchParams.get('dvr_id') || '').trim();
      const channel = Math.max(1, Math.min(64, Number(url.searchParams.get('channel') || 1) || 1));
      const hd = url.searchParams.get('hd') === '1';
      const mode = url.searchParams.get('mode') === 'h264' ? 'h264' : 'copy';
      cctv.subscribeClientToFmp4Stream({ dvrId, channel, hd, mode, actor, role, req, res });
      return;
    }

    // 2. WebRTC WHEP Signaling Gateway (/api/cctv/webrtc/whep)
    if (req.method === 'POST' && (url.pathname === '/api/cctv/webrtc/whep' || url.pathname === '/api/v1/cctv/webrtc/whep')) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && hdrTok === ADMIN_KEY);
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'unauthorized' });
      }
      const cctvCfg = cctv.getSettings();
      const actor = jwtVerified && jwtVerified.claims ? String(jwtVerified.claims.sub || '') : 'admin';
      const role = jwtVerified && jwtVerified.claims ? String(jwtVerified.claims.role || 'super').toLowerCase() : 'super';
      if (cctvCfg.super_only && role !== 'super') {
        return json(res, 403, { ok: false, error: 'تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط' });
      }
      const body = await readBody(req).catch(() => ({}));
      const dvrId = String(body.dvr_id || url.searchParams.get('dvr_id') || '').trim();
      const channel = Math.max(1, Math.min(64, Number(body.channel || url.searchParams.get('channel') || 1) || 1));
      const hd = Boolean(body.hd || url.searchParams.get('hd') === '1');
      const offerSdp = String(body.offer_sdp || body.sdp || '');
      try {
        const out = await cctv.negotiateWebRtcWhep({ dvrId, channel, hd, offerSdp, actor, role });
        return json(res, 200, out);
      } catch (e) {
        return json(res, 502, { ok: false, error: (e && e.message) || 'تعذر فتح جلسة WebRTC' });
      }
    }

    // 3. Low-Latency HLS Fallback Gateway (/api/cctv/hls/:dvrId/:channel/:streamKind/:file)
    const hlsMatch = url.pathname.match(/^\/api(?:\/v1)?\/cctv\/hls\/([^/]+)\/(\d+)\/(main|sub)\/(.+)$/);
    if (req.method === 'GET' && hlsMatch) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && hdrTok === ADMIN_KEY);
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'unauthorized' });
      }
      const cctvCfg = cctv.getSettings();
      const actor = jwtVerified && jwtVerified.claims ? String(jwtVerified.claims.sub || '') : 'admin';
      const role = jwtVerified && jwtVerified.claims ? String(jwtVerified.claims.role || 'super').toLowerCase() : 'super';
      if (cctvCfg.super_only && role !== 'super') {
        return json(res, 403, { ok: false, error: 'تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط' });
      }
      cctv.proxyMediaMtxHls({
        dvrId: decodeURIComponent(hlsMatch[1]),
        channel: Number(hlsMatch[2] || 1),
        hd: hlsMatch[3] === 'main',
        subFile: hlsMatch[4],
        actor,
        role,
        token: candTok,
        res,
      });
      return;
    }

    if ((req.method === 'GET' || req.method === 'HEAD') && (url.pathname === '/api/cctv/frame' || url.pathname === '/api/v1/cctv/frame')) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && hdrTok === ADMIN_KEY);
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'unauthorized' });
      }
      const cctvCfg = cctv.getSettings();
      if (jwtVerified && cctvCfg.super_only && String(jwtVerified.claims.role || '').toLowerCase() !== 'super') {
        return json(res, 403, { ok: false, error: 'تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط' });
      }
      const dvrId = String(url.searchParams.get('dvr_id') || '').trim();
      const channel = Math.max(1, Math.min(64, Number(url.searchParams.get('channel') || 1) || 1));
      const hd = url.searchParams.get('hd') === '1';
      try {
        const frame = await cctv.getFrame({ dvrId, channel, hd, waitMs: 12500 });
        res.writeHead(200, {
          'Content-Type': frame.mime || 'image/jpeg',
          'Content-Length': frame.buf.length,
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Access-Control-Allow-Origin': CORS_ORIGIN,
          'X-Frame-At': String(frame.at || Date.now()),
        });
        if (req.method === 'HEAD') return res.end();
        return res.end(frame.buf);
      } catch (e) {
        return json(res, 502, { ok: false, error: (e && e.message) || 'تعذر جلب إطار الكاميرا' });
      }
    }
    if (req.method === 'GET' && (url.pathname === '/api/cctv/clip' || url.pathname === '/api/v1/cctv/clip')) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && hdrTok === ADMIN_KEY);
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'unauthorized' });
      }
      const cctvCfg = cctv.getSettings();
      if (jwtVerified && cctvCfg.super_only && String(jwtVerified.claims.role || '').toLowerCase() !== 'super') {
        return json(res, 403, { ok: false, error: 'تم حصر الكاميرات بحساب السوبر أدمن فقط' });
      }
      try {
        const clip = await cctv.downloadRecordingClip({
          dvrId: String(url.searchParams.get('dvr_id') || '').trim(),
          channel: Number(url.searchParams.get('channel') || 1),
          startTime: String(url.searchParams.get('start_time') || ''),
          endTime: String(url.searchParams.get('end_time') || ''),
        });
        res.writeHead(200, {
          'Content-Type': clip.mime,
          'Content-Length': clip.buf.length,
          'Content-Disposition': `attachment; filename="${clip.fileName.replace(/[^\x20-\x7E]/g, '_')}"`,
          'Access-Control-Allow-Origin': CORS_ORIGIN,
        });
        return res.end(clip.buf);
      } catch (e) {
        return json(res, 502, { ok: false, error: (e && e.message) || 'تعذر تحميل المقطع المسجل' });
      }
    }
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/cctv/list') {
      if (!requireAdmin(req, res)) return;
      return json(res, 200, cctv.listDvrs({
        actor: url.searchParams.get('actor') || '',
        role: url.searchParams.get('role') || 'super',
      }));
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/cctv/action') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      try {
        const out = await cctv.handleAction({
          action: body.action,
          payload: body.payload || {},
          actor: body.actor || '',
          role: body.role || 'super',
        });
        return json(res, 200, out);
      } catch (e) {
        return json(res, 200, { ok: false, error: (e && e.message) || 'تعذر تنفيذ إجراء الكاميرا' });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/cctv/save') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      try {
        const out = cctv.saveDvr(body);
        audit('admin', 'cctv_save', body.name || body.host || 'dvr', 'ok', {});
        return json(res, 200, out);
      } catch (e) {
        return json(res, 200, { ok: false, error: (e && e.message) || 'فشل حفظ جهاز الـ DVR' });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/cctv/delete') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      const out = cctv.deleteDvr(body.id);
      audit('admin', 'cctv_delete', String(body.id || ''), 'ok', {});
      return json(res, 200, out);
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/cctv/settings') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      const st = cctv.setSettings({ super_only: Boolean(body.super_only) });
      return json(res, 200, { ok: true, settings: st });
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/cctv/test') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      try {
        const out = await cctv.testDvrConnection(body);
        return json(res, 200, out);
      } catch (e) {
        return json(res, 200, { ok: false, error: (e && e.message) || 'تعذر الاتصال بجهاز الـ DVR' });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/cctv/scan') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      try {
        const bridgeId = String(body.bridge_device_id || '').trim();
        const out = bridgeId ? await cctv.scanBranchForDahua(bridgeId) : await cctv.scanLocalLanForDahua();
        return json(res, 200, out);
      } catch (e) {
        return json(res, 200, { ok: false, error: (e && e.message) || 'فشل البحث على الشبكة' });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/cctv/frame-b64') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      try {
        const frame = await cctv.getFrame({
          dvrId: body.dvr_id,
          channel: Number(body.channel || 1),
          hd: Boolean(body.hd),
          waitMs: 12500,
        });
        return json(res, 200, {
          ok: true,
          mime: frame.mime || 'image/jpeg',
          at: frame.at,
          image: frame.buf.toString('base64'),
        });
      } catch (e) {
        return json(res, 502, { ok: false, error: (e && e.message) || 'تعذر جلب إطار الكاميرا' });
      }
    }

    // ----- Biometrics & Attendance Center (ZKTeco Port 4370 + Hikvision ISAPI) -----
    if (req.method === 'POST' && (url.pathname === '/api/v1/admin/biometrics/action' || url.pathname === '/api/biometrics/action')) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && hdrTok === ADMIN_KEY);
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'unauthorized' });
      }
      const body = await readBody(req).catch(() => ({}));
      const act = String(body.action || '');
      const role = isAdminKeyOk
        ? String(body.role || 'super').toLowerCase()
        : String((jwtVerified && jwtVerified.claims && jwtVerified.claims.role) || 'admin').toLowerCase();
      if (role === 'viewer' && ['save_device', 'delete_device', 'clear_logs'].includes(act)) {
        return json(res, 200, { ok: false, error: 'صلاحية المشاهدة فقط لا تسمح بإضافة أو حذف أجهزة البصمة' });
      }
      try {
        const out = await biometrics.handleAction({
          action: act,
          payload: body.payload || {},
        });
        if (['save_device', 'delete_device', 'pull_logs'].includes(act)) {
          const actor = isAdminKeyOk
            ? String(body.actor || 'admin')
            : String((jwtVerified && jwtVerified.claims && jwtVerified.claims.sub) || 'admin');
          audit(actor, `biometrics_${act}`, String((body.payload && (body.payload.name || body.payload.ip || body.payload.id)) || 'all'), 'ok', {});
        }
        return json(res, 200, out);
      } catch (e) {
        return json(res, 200, { ok: false, error: (e && e.message) || 'تعذر تنفيذ إجراء جهاز البصمة' });
      }
    }

    if (req.method === 'GET' && (url.pathname === '/api/biometrics/export.csv' || url.pathname === '/api/v1/admin/biometrics/export.csv')) {
      const hdrTok = bearer(req);
      const qTok = String(url.searchParams.get('token') || '').trim();
      const candTok = hdrTok || qTok;
      const isAdminKeyOk = Boolean(ADMIN_KEY && (hdrTok === ADMIN_KEY || qTok === ADMIN_KEY));
      const jwtVerified = isAdminKeyOk ? null : verifyAdminJwtToken(candTok);
      if (!isAdminKeyOk && !jwtVerified) {
        return json(res, 401, { ok: false, error: 'unauthorized' });
      }
      const deviceId = String(url.searchParams.get('device_id') || '').trim();
      const search = String(url.searchParams.get('search') || '').trim();
      const rows = biometrics.listAttendanceLogs({ deviceId, search, limit: 5000 });
      const csvCell = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
      const punchLabel = (t) => {
        const s = String(t || '');
        if (s === 'check_in') return 'حضور';
        if (s === 'check_out') return 'انصراف';
        if (s === 'break_out') return 'خروج راحة';
        if (s === 'break_in') return 'عودة راحة';
        if (s === 'overtime_in') return 'إضافي حضور';
        if (s === 'overtime_out') return 'إضافي انصراف';
        return s || 'بصمة';
      };
      const verifyLabel = (m) => {
        const s = String(m || '');
        if (s === 'fingerprint') return 'بصمة إصبع';
        if (s === 'face') return 'بصمة وجه';
        if (s === 'card') return 'كارت';
        if (s === 'password') return 'رقم سري';
        return s || 'بصمة';
      };
      const lines = [
        ['كود الموظف', 'اسم الموظف', 'الفرع / القسم', 'ماكينة البصمة', 'النوع', 'وقت البصمة', 'نوع الحركة', 'طريقة التحقق'].map(csvCell).join(','),
      ];
      for (const r of rows) {
        lines.push([
          r.employee_id,
          r.employee_name || `موظف #${r.employee_id}`,
          r.branch || '—',
          r.device_name || '—',
          r.vendor === 'hikvision' ? 'Hikvision' : 'ZKTeco',
          r.punch_time,
          punchLabel(r.punch_type),
          verifyLabel(r.verify_mode),
        ].map(csvCell).join(','));
      }
      const csvBuf = Buffer.from('\uFEFF' + lines.join('\r\n'), 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Length': csvBuf.length,
        'Content-Disposition': `attachment; filename="Biometrics_Attendance_${new Date().toISOString().slice(0, 10)}.csv"`,
        'Access-Control-Allow-Origin': CORS_ORIGIN,
      });
      return res.end(csvBuf);
    }

    // ----- WhatsApp Bot Center -----
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/wa-bot/status') {
      if (!requireAdmin(req, res)) return;
      return json(res, 200, waBot.getStatus());
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/wa-bot/config') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      const st = waBot.saveConfig(body);
      audit('admin', 'wa_bot_config', 'wa_bot', 'ok', { enabled: st.config.enabled });
      return json(res, 200, st);
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/wa-bot/connect') {
      if (!requireAdmin(req, res)) return;
      const st = await waBot.connect();
      audit('admin', 'wa_bot_connect', 'wa_bot', 'ok', {});
      return json(res, 200, st);
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/wa-bot/disconnect') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      const st = await waBot.disconnect({ logout: Boolean(body && body.logout) });
      audit('admin', 'wa_bot_disconnect', 'wa_bot', 'ok', { logout: Boolean(body && body.logout) });
      return json(res, 200, st);
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/wa-bot/test') {
      if (!requireAdmin(req, res)) return;
      try {
        const out = await waBot.sendTestMessage();
        return json(res, 200, out);
      } catch (e) {
        return json(res, 400, { ok: false, error: (e && e.message) || 'فشل إرسال الرسالة التجريبية' });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/wa-bot/event') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      if (body && body.kind === 'erp_backup') {
        waBot.onErpBackupEvent({
          ok: Boolean(body.ok),
          fileName: String(body.file_name || ''),
          sizeBytes: Number(body.size_bytes || 0),
          formatLabel: String(body.format_label || ''),
          error: String(body.error || ''),
          reason: String(body.reason || ''),
        }).catch(() => {});
      }
      return json(res, 200, { ok: true });
    }

    // ----- Alerts (Phase 3) -----
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/alerts') {
      if (!requireAdmin(req,res)) return;
      const type = url.searchParams.get('type') || '';
      const severity = url.searchParams.get('severity') || '';
      const acked = url.searchParams.get('acked') || '';
      const includeFullMedia = url.searchParams.get('full') === '1';
      let sql = 'SELECT id,device_id,type,severity,message,meta,created_at,acked_at,acked_by FROM alerts WHERE 1=1';
      const params = [];
      if (type) { sql += ' AND type=?'; params.push(type); }
      if (severity) { sql += ' AND severity=?'; params.push(severity); }
      if (acked === '0') sql += ' AND acked_at IS NULL';
      if (acked === '1') sql += ' AND acked_at IS NOT NULL';
      sql += ' ORDER BY created_at DESC LIMIT 200';
      const rows = db.prepare(sql).all(...params);
      const devices = db.prepare('SELECT device_id,label,hostname FROM devices').all();
      const byId = Object.fromEntries(devices.map(d => [d.device_id, d.label || d.hostname || d.device_id]));
      const out = rows.map(r => {
        const cleanMeta = includeFullMedia ? r.meta : stripAlertMedia(r.meta);
        let metaDevName = '';
        if (typeof cleanMeta === 'string' && cleanMeta.startsWith('{')) {
          try { metaDevName = JSON.parse(cleanMeta).device_name || ''; } catch (_) {}
        }
        return {
          ...r,
          meta: cleanMeta,
          device_name: byId[r.device_id] || metaDevName || r.device_id,
          acked: !!r.acked_at,
        };
      });
      return json(res, 200, {ok:true, alerts: out, unacked: db.prepare('SELECT COUNT(*) AS n FROM alerts WHERE acked_at IS NULL').get().n});
    }
    const alertDetailMatch = url.pathname.match(/^\/api\/v1\/admin\/alerts\/([^/]+)$/);
    if (req.method === 'GET' && alertDetailMatch) {
      if (!requireAdmin(req, res)) return;
      const id = decodeURIComponent(alertDetailMatch[1]);
      const mediaRow = db.prepare('SELECT screenshot, camera_photo FROM alert_media WHERE alert_id=?').get(id);
      if (mediaRow && (mediaRow.screenshot || mediaRow.camera_photo)) {
        return json(res, 200, {
          ok: true,
          id,
          screenshot: String(mediaRow.screenshot || ''),
          camera_photo: String(mediaRow.camera_photo || ''),
        });
      }
      const row = db.prepare('SELECT id, meta FROM alerts WHERE id=?').get(id);
      if (!row) return json(res, 404, { ok: false, error: 'alert not found' });
      let metaObj = {};
      if (typeof row.meta === 'string' && row.meta.trim().startsWith('{')) {
        try { metaObj = JSON.parse(row.meta); } catch (_) {}
      }
      return json(res, 200, {
        ok: true,
        id: row.id,
        screenshot: String(metaObj.screenshot || ''),
        camera_photo: String(metaObj.camera_photo || ''),
      });
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/alerts') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req, 25 * 1024 * 1024);
      const id = String(body.id || rid('alt_')).slice(0, 80);
      const deviceId = String(body.device_id || 'lan_device').slice(0, 80);
      const deviceName = String(body.device_name || '').slice(0, 120);
      const type = String(body.type || 'tamper').slice(0, 40);
      const severity = ['low', 'medium', 'high', 'critical'].includes(body.severity) ? body.severity : 'medium';
      const message = String(body.message || '').slice(0, 600);
      if (!message) return json(res, 400, { ok: false, error: 'message required' });
      let metaObj = {};
      if (body.meta && typeof body.meta === 'object') {
        metaObj = { ...body.meta };
      } else if (typeof body.meta === 'string' && body.meta.trim().startsWith('{')) {
        try { metaObj = JSON.parse(body.meta); } catch (_) { metaObj = {}; }
      }
      if (deviceName && !metaObj.device_name) {
        metaObj.device_name = deviceName;
      }
      const createdAt = Number(body.created_at) > 0 ? Number(body.created_at) : now();
      storeAlertWithSeparatedMedia({
        id,
        deviceId,
        type,
        severity,
        message,
        rawMeta: metaObj,
        createdAt,
        ignoreExisting: true,
      });
      return json(res, 200, { ok: true, id });
    }
    const ackMatch = url.pathname.match(/^\/api\/v1\/admin\/alerts\/([^/]+)\/ack$/);
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/alerts/ack-all') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      const type = String((body && body.type) || '').trim();
      let info;
      if (type) {
        info = db.prepare('UPDATE alerts SET acked_at=?, acked_by=? WHERE acked_at IS NULL AND type=?')
          .run(now(), 'admin', type);
      } else {
        info = db.prepare('UPDATE alerts SET acked_at=?, acked_by=? WHERE acked_at IS NULL')
          .run(now(), 'admin');
      }
      audit('admin', 'alerts_ack_all', type || 'all', 'ok', { count: info.changes });
      return json(res, 200, { ok: true, count: info.changes });
    }
    if (req.method === 'POST' && ackMatch) {
      if (!requireAdmin(req,res)) return;
      const id = decodeURIComponent(ackMatch[1]);
      db.prepare('UPDATE alerts SET acked_at=?, acked_by=? WHERE id=? AND acked_at IS NULL')
        .run(now(), 'admin', id);
      return json(res, 200, {ok:true});
    }

    // ----- Audit log -----
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/audit') {
      if (!requireAdmin(req,res)) return;
      const rows = db.prepare('SELECT id,actor,action,target,result,meta,created_at FROM audit_log ORDER BY created_at DESC LIMIT 200').all();
      return json(res, 200, {ok:true, entries: rows});
    }

    // ----- Device groups -----
    if (url.pathname === '/api/v1/admin/groups') {
      if (!requireAdmin(req,res)) return;
      if (req.method === 'GET') return json(res, 200, {ok:true, groups: groupList()});
      if (req.method === 'POST') {
        const body = await readBody(req);
        const name = (body.name||'').trim();
        if (!name) return json(res, 400, {ok:false,error:'name required'});
        const gid = rid('grp_');
        db.prepare('INSERT INTO groups(id,name,created_at) VALUES(?,?,?)').run(gid, name, now());
        const data = {
          mode: body.mode||'whitelist',
          allowed: body.allowed||[],
          blocked: body.blocked||[],
          ephemeral_browser: !!body.ephemeral_browser,
          usb_block: !!body.usb_block,
          rules: [],
        };
        db.prepare('INSERT INTO group_policy(group_id,version,data,updated_at) VALUES(?,?,?,?)')
          .run(gid, rid('gv_'), JSON.stringify(data), now());
        audit('admin', 'group_create', gid, 'ok', {name: body.name});
        audit('admin', 'group_update', gid, 'ok', {});
        return json(res, 200, {ok:true, group: groupList().find(g => g.id === gid)});
      }
    }
    const grpMatch = url.pathname.match(/^\/api\/v1\/admin\/groups\/([^/]+)$/);
    if (grpMatch) {
      if (!requireAdmin(req,res)) return;
      const gid = decodeURIComponent(grpMatch[1]);
      if (!db.prepare('SELECT 1 FROM groups WHERE id=?').get(gid)) return json(res, 404, {ok:false,error:'no group'});
      if (req.method === 'PUT') {
        const body = await readBody(req);
        if (typeof body.name === 'string' && body.name.trim()) {
          db.prepare('UPDATE groups SET name=? WHERE id=?').run(body.name.trim(), gid);
        }
        if (body.mode !== undefined || body.allowed !== undefined || body.blocked !== undefined || body.ephemeral_browser !== undefined || body.usb_block !== undefined) {
          const rawRow = db.prepare('SELECT data FROM group_policy WHERE group_id=?').get(gid);
          const cur = rawRow ? JSON.parse(rawRow.data) : { mode:'whitelist', allowed:[], blocked:[], ephemeral_browser: false, usb_block: false };
          const data = {
            mode: body.mode === undefined ? cur.mode : (body.mode === 'blacklist' ? 'blacklist' : 'whitelist'),
            allowed: body.allowed === undefined ? (cur.allowed||[]) : body.allowed,
            blocked: body.blocked === undefined ? (cur.blocked||[]) : body.blocked,
            ephemeral_browser: body.ephemeral_browser === undefined ? !!cur.ephemeral_browser : !!body.ephemeral_browser,
            usb_block: body.usb_block === undefined ? !!cur.usb_block : !!body.usb_block,
            rules: [],
          };
          const ver = rid('gv_');
          db.prepare('INSERT INTO group_policy(group_id,version,data,updated_at) VALUES(?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET version=excluded.version,data=excluded.data,updated_at=excluded.updated_at')
            .run(gid, ver, JSON.stringify(data), now());
          writeProjectLog(
            'policies',
            'INFO',
            'GROUP_POLICY_UPDATED',
            `تحديث سياسة المجموعة (${gid}): الوضع=${data.mode} | المتصفح النظيف=${data.ephemeral_browser} | قفل الفلاشات=${data.usb_block} | المسموحة=(${(data.allowed || []).join(', ')}) | المحظورة=(${(data.blocked || []).join(', ')})`
          );
        }
        return json(res, 200, {ok:true, group: groupList().find(g => g.id === gid)});
      }
      if (req.method === 'DELETE') {
        db.prepare("UPDATE devices SET group_id='' WHERE group_id=?").run(gid);
        db.prepare('DELETE FROM group_policy WHERE group_id=?').run(gid);
        db.prepare('DELETE FROM groups WHERE id=?').run(gid);
        audit('admin', 'group_delete', gid, 'ok', {});
        return json(res, 200, {ok:true});
      }
    }
    // Queue a block/unblock for every device in a group.
    const grpCmd = url.pathname.match(/^\/api\/v1\/admin\/groups\/([^/]+)\/command$/);
    if (req.method === 'POST' && grpCmd) {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const type = body.command === 'unblock' ? 'unblock'
        : body.command === 'block' ? 'block'
        : body.command === 'usb_block' ? 'usb_block'
        : body.command === 'usb_unblock' ? 'usb_unblock'
        : body.command === 'update_client' ? 'update_client'
        : null;
      if (!type) return json(res, 400, {ok:false,error:'invalid command'});
      const gid = decodeURIComponent(grpCmd[1]);
      const targets = db.prepare('SELECT device_id FROM devices WHERE group_id=?').all(gid);
      const ins = db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)');
      const clear = db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL');
      for (const t of targets) {
        clear.run(t.device_id);
        ins.run(rid('cmd_'), t.device_id, type, now());
        if (type === 'block') db.prepare("UPDATE devices SET blocked=1, admin_open=0, last_event='', last_event_at=0 WHERE device_id=?").run(t.device_id);
        else if (type === 'unblock') db.prepare("UPDATE devices SET blocked=0, admin_open=1, last_event='', last_event_at=0 WHERE device_id=?").run(t.device_id);
        else if (type === 'usb_block') db.prepare('UPDATE devices SET usb_blocked=1 WHERE device_id=?').run(t.device_id);
        else if (type === 'usb_unblock') db.prepare('UPDATE devices SET usb_blocked=0 WHERE device_id=?').run(t.device_id);
      }
      audit('admin', 'group_' + type, gid, 'ok', {queued: targets.length});
      return json(res, 200, {ok:true, queued: targets.length});
    }
    // Ask a device for a fresh screenshot or start/renew/stop a live screen/camera stream lease.
    const scrReq = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/screen\/request$/);
    if (req.method === 'POST' && scrReq) {
      if (!requireAdmin(req,res)) return;
      const did = decodeURIComponent(scrReq[1]);
      const dev = db.prepare('SELECT stream_mode FROM devices WHERE device_id=?').get(did);
      if (!dev) return json(res, 404, {ok:false,error:'no device'});
      const body = await readBody(req).catch(() => ({}));
      const mode = String((body && body.mode) || 'once').trim().toLowerCase();
      if (mode === 'stop') {
        db.prepare("UPDATE devices SET screen_requested=0, stream_mode='', stream_until=0 WHERE device_id=?").run(did);
      } else if (mode === 'screen' || mode === 'camera') {
        const until = now() + 12000;
        if ((dev.stream_mode || '') !== mode) {
          db.prepare("INSERT INTO screens(device_id,image,at,kind,error) VALUES(?, '', 0, ?, '') ON CONFLICT(device_id) DO UPDATE SET image='', at=0, kind=excluded.kind, error=''").run(did, mode);
        }
        db.prepare('UPDATE devices SET screen_requested=1, stream_mode=?, stream_until=? WHERE device_id=?').run(mode, until, did);
      } else {
        db.prepare("UPDATE devices SET screen_requested=1, stream_mode='', stream_until=0 WHERE device_id=?").run(did);
        db.prepare("INSERT INTO screens(device_id,image,at,kind,error) VALUES(?, '', 0, 'screen', '') ON CONFLICT(device_id) DO UPDATE SET image='', at=0, kind='screen', error=''").run(did);
      }
      return json(res, 200, {ok:true, mode});
    }

    // Admin: fetch the latest screenshot or live stream frame.
    const scrGet = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/screen$/);
    if (req.method === 'GET' && scrGet) {
      if (!requireAdmin(req,res)) return;
      const did = decodeURIComponent(scrGet[1]);
      const row = db.prepare('SELECT image,at,kind,error FROM screens WHERE device_id=?').get(did);
      const dev = db.prepare('SELECT screen_requested,stream_mode,stream_until FROM devices WHERE device_id=?').get(did);
      const activeLease = !!(dev && dev.stream_until && dev.stream_until > now());
      return json(res, 200, {
        ok: true,
        requested: !!(dev && (dev.screen_requested || activeLease)),
        stream_mode: activeLease ? (dev.stream_mode || 'screen') : '',
        image: row ? row.image : '',
        at: row ? row.at : 0,
        kind: (row && row.kind) || 'screen',
        error: (row && row.error) || '',
      });
    }

    // Set a per-device RustDesk unattended password.
    const rdPw = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/rustdesk_password$/);
    if (req.method === 'POST' && rdPw) {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const did = decodeURIComponent(rdPw[1]);
      if (!db.prepare('SELECT 1 FROM devices WHERE device_id=?').get(did)) return json(res, 404, {ok:false,error:'no device'});
      db.prepare('UPDATE devices SET rustdesk_password=? WHERE device_id=?').run(String(body.password || '').slice(0, 64), did);
      return json(res, 200, {ok:true});
    }

    // Delete a device (and its pending commands).
    const devDel = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)$/);
    if (req.method === 'DELETE' && devDel) {
      if (!requireAdmin(req,res)) return;
      const did = decodeURIComponent(devDel[1]);
      db.prepare('DELETE FROM commands WHERE device_id=?').run(did);
      db.prepare('DELETE FROM screens WHERE device_id=?').run(did);
      const info = db.prepare('DELETE FROM devices WHERE device_id=?').run(did);
      audit('admin', 'device_delete', did, 'ok', {});
      return json(res, 200, {ok:true, deleted: info.changes});
    }
    // Rename a device (friendly name shown to the admin).
    const devLabel = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/label$/);
    if (req.method === 'POST' && devLabel) {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const did = decodeURIComponent(devLabel[1]);
      if (!db.prepare('SELECT 1 FROM devices WHERE device_id=?').get(did)) return json(res, 404, {ok:false,error:'no device'});
      db.prepare('UPDATE devices SET label=? WHERE device_id=?').run(String(body.label||'').slice(0,80), did);
      audit('admin', 'device_rename', did, 'ok', {label: body.label});
      return json(res, 200, {ok:true});
    }
    // Assign a device to a group ('' clears the assignment).
    const devGrp = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/group$/);
    if (req.method === 'POST' && devGrp) {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const did = decodeURIComponent(devGrp[1]);
      const gid = typeof body.group_id === 'string' ? body.group_id : '';
      if (!db.prepare('SELECT 1 FROM devices WHERE device_id=?').get(did)) return json(res, 404, {ok:false,error:'no device'});
      if (gid && !db.prepare('SELECT 1 FROM groups WHERE id=?').get(gid)) return json(res, 400, {ok:false,error:'no group'});
      db.prepare('UPDATE devices SET group_id=? WHERE device_id=?').run(gid, did);
      audit('admin', 'assign_group', did, 'ok', {group_id: gid});
      return json(res, 200, {ok:true});
    }

    // Admin: devices
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/devices') {
      if (!requireAdmin(req,res)) return;
      const rows = db.prepare('SELECT device_id,hostname,os,app_version,enrolled_at,last_seen,ip,blocked,admin_open,usb_blocked,mode,policy_version,group_id,label,last_event,last_event_at,throttle_kbps,sites,denied,rustdesk_id,rustdesk_password FROM devices ORDER BY last_seen DESC').all();
      const pendRows = db.prepare('SELECT device_id, type FROM commands WHERE acked_at IS NULL ORDER BY created_at DESC').all();
      const pendMap = new Map();
      for (const pr of pendRows) {
        if (!pendMap.has(pr.device_id)) pendMap.set(pr.device_id, pr.type || '');
      }
      const ci = findNewestSetupInstaller('IT ELKHAWGA Client_');
      const latestVer = (ci && ci.version) || '1.1.3';
      const out = rows.map(d => {
        let sites = [];
        let denied = [];
        try { sites = JSON.parse(d.sites || '[]'); } catch (e) { sites = []; }
        try { denied = JSON.parse(d.denied || '[]'); } catch (e) { denied = []; }
        const isOpenByAdmin = Number(d.admin_open) === 1;
        const pendCmd = pendMap.get(d.device_id) || '';
        const effectiveBlocked = pendCmd === 'block' ? true : (pendCmd === 'unblock' || isOpenByAdmin ? false : !!d.blocked);
        return {...d, sites, denied, pending_command: pendCmd, latest_client_version: latestVer, rustdesk_id: d.rustdesk_id || '', rustdesk_password: d.rustdesk_password || '', blocked: effectiveBlocked, usb_blocked: !!d.usb_blocked, online: d.last_seen && (now()-d.last_seen < 120_000)};
      });
      out.sort((a, b) => {
        const ao = a.online ? 1 : 0;
        const bo = b.online ? 1 : 0;
        if (ao !== bo) return bo - ao;
        const an = String(a.label || a.hostname || a.device_id || '').trim();
        const bn = String(b.label || b.hostname || b.device_id || '').trim();
        const cmp = an.localeCompare(bn, undefined, { numeric: true, sensitivity: 'base' });
        if (cmp !== 0) return cmp;
        return String(a.device_id || '').localeCompare(String(b.device_id || ''));
      });
      return json(res, 200, {ok:true, latest_client_version: latestVer, devices: out});
    }
    // Admin: command
    const cmdMatch = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/command$/);
    if (req.method === 'POST' && cmdMatch) {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const raw = String(body.command || '');
      const type = raw === 'unblock' ? 'unblock'
        : raw === 'block' ? 'block'
        : raw === 'usb_block' ? 'usb_block'
        : raw === 'usb_unblock' ? 'usb_unblock'
        : /^throttle:\d{1,7}$/.test(raw) ? raw
        : (raw === 'restart' || raw === 'shutdown' || raw === 'cancel_power' || raw === 'update_client') ? raw
        : null;
      if (!type) return json(res, 400, {ok:false,error:'invalid command'});
      const did = decodeURIComponent(cmdMatch[1]);
      // Power commands target one device only, never "*".
      if (did === '*' && (type === 'restart' || type === 'shutdown')) {
        return json(res, 400, {ok:false,error:'power commands require a single device'});
      }
      const targets = did === '*' ? db.prepare('SELECT device_id FROM devices').all().map(r=>r.device_id) : [did];
      let count = 0;
      const ins = db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)');
      const clear = db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL');
      const setThr = db.prepare('UPDATE devices SET throttle_kbps=? WHERE device_id=?');
      const throttleVal = type.startsWith('throttle:') ? Number(type.slice(9)) || 0 : null;
      for (const t of targets) {
        if (db.prepare('SELECT 1 FROM devices WHERE device_id=?').get(t)) {
          clear.run(t);            // supersede any stale pending command
          ins.run(rid('cmd_'), t, type, now());
          if (throttleVal !== null) setThr.run(throttleVal, t);
          // Reflect the intended state immediately so the admin UI does not
          // lag behind the device's next poll.
          if (type === 'block') db.prepare("UPDATE devices SET blocked=1, admin_open=0, last_event='', last_event_at=0 WHERE device_id=?").run(t);
          else if (type === 'unblock') db.prepare("UPDATE devices SET blocked=0, admin_open=1, last_event='', last_event_at=0 WHERE device_id=?").run(t);
          else if (type === 'usb_block') db.prepare('UPDATE devices SET usb_blocked=1 WHERE device_id=?').run(t);
          else if (type === 'usb_unblock') db.prepare('UPDATE devices SET usb_blocked=0 WHERE device_id=?').run(t);
          count++;
        }
      }
      audit('admin', type, did, 'ok', {queued: count});
      return json(res, 200, {ok:true, queued: count});
    }
    // Admin: policy
    if (url.pathname === '/api/v1/admin/policy') {
      if (!requireAdmin(req,res)) return;
      if (req.method === 'GET') return json(res, 200, {ok:true, policy: getPolicy()});
      if (req.method === 'PUT') {
        const body = await readBody(req);
        const ver = rid('pv_');
        const data = {
          mode: body.mode||'whitelist',
          allowed: body.allowed||[],
          blocked: body.blocked||[],
          rules: body.rules||[],
        };
        if (typeof body.password_hash === 'string') data.password_hash = body.password_hash;
        if (typeof body.auto_start === 'boolean') data.auto_start = body.auto_start;
        if (typeof body.exfil_threshold_mb === 'number') data.exfil_threshold_mb = body.exfil_threshold_mb;
        if (typeof body.exfil_window_secs === 'number') data.exfil_window_secs = body.exfil_window_secs;
        if (Array.isArray(body.exfil_suspicious)) data.exfil_suspicious = body.exfil_suspicious;
        if (typeof body.usb_block === 'boolean') data.usb_block = body.usb_block;
        if (typeof body.rustdesk_server === 'string') data.rustdesk_server = body.rustdesk_server;
        if (typeof body.rustdesk_key === 'string') data.rustdesk_key = body.rustdesk_key;
        if (Array.isArray(body.erp_domains)) data.erp_domains = body.erp_domains;
        db.prepare('UPDATE policy SET version=?, data=?, updated_at=? WHERE id=1').run(ver, JSON.stringify(data), now());
        audit('admin', 'policy_update', 'default', 'ok', {mode: data.mode});
        return json(res, 200, {ok:true, policy: getPolicy()});
      }
    }

    // Device: enroll
    if (req.method === 'POST' && url.pathname === '/api/v1/enroll') {
      const pt = bearer(req);
      const row = db.prepare('SELECT * FROM pairing_tokens WHERE token=?').get(pt);
      if (!row) return json(res, 401, {ok:false,error:'invalid pairing token'});
      if (row.expires_at && row.expires_at > 0 && row.expires_at < now()) return json(res, 401, {ok:false,error:'pairing token expired'});
      // reusable: do not mark used_at, so one token links many clients forever.
      const body = await readBody(req);
      const device_id = (body.device_id && /^[A-Za-z0-9_-]{6,80}$/.test(body.device_id)) ? body.device_id : rid('dev_');
      const device_token = rid('dvt_');
      const rawLabel = (row.label || '').trim();
      const label = rawLabel === 'permanent' ? '' : rawLabel;
      const realIp = clientIpFromReq(req);
      db.prepare(`INSERT INTO devices(device_id,hostname,os,app_version,device_token_hash,enrolled_at,last_seen,ip,label)
                  VALUES(?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(device_id) DO UPDATE SET hostname=excluded.hostname,os=excluded.os,app_version=excluded.app_version,device_token_hash=excluded.device_token_hash,last_seen=excluded.last_seen,ip=CASE WHEN excluded.ip!='' AND excluded.ip!='127.0.0.1' THEN excluded.ip ELSE COALESCE(NULLIF(devices.ip,'127.0.0.1'), excluded.ip) END,label=COALESCE(NULLIF(excluded.label,''),devices.label)`)
        .run(device_id, body.hostname||'', body.os||'', body.app_version||'', sha256(device_token), now(), now(), realIp, label);
      // Token stays reusable so a single token links many clients forever.
      audit('device:' + device_id, 'enroll', device_id, 'ok', {hostname: body.hostname || ''});
      return json(res, 200, {ok:true, device_id, device_token, poll_seconds: 3});
    }
    // Device: upload a screenshot or camera stream frame captured in the user session.
    if (req.method === 'POST' && url.pathname === '/api/v1/device/screen') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, {ok:false,error:'unauthorized'});
      const body = await readBody(req);
      const img = typeof body.image === 'string' ? body.image : '';
      const kind = String(body.kind || 'screen').slice(0, 20);
      const errStr = String(body.error || '').slice(0, 120);
      if (!img && !errStr) return json(res, 400, {ok:false,error:'missing image'});
      if (img.length > 5 * 1024 * 1024) return json(res, 413, {ok:false,error:'image too large'});
      db.prepare("INSERT INTO screens(device_id,image,at,kind,error) VALUES(?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET image=excluded.image, at=excluded.at, kind=excluded.kind, error=excluded.error")
        .run(dev.device_id, img, now(), kind, errStr);
      if (!dev.stream_until || dev.stream_until <= now()) {
        db.prepare('UPDATE devices SET screen_requested=0 WHERE device_id=?').run(dev.device_id);
      }
      return json(res, 200, {ok:true});
    }

    // Admin: list archived exact-copy uploaded files (scalable: full summary + daily calendar index + server-side filter & pagination)
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/uploads') {
      if (!requireAdmin(req, res)) return;
      const ch = String(url.searchParams.get('channel') || '').trim().toLowerCase();
      const fromMs = Number(url.searchParams.get('from_ms') || 0) || 0;
      const toMs = Number(url.searchParams.get('to_ms') || 0) || 0;
      const fileType = String(url.searchParams.get('file_type') || '').trim().toLowerCase();
      const devFilter = String(url.searchParams.get('device') || '').trim();
      const q = String(url.searchParams.get('q') || '').trim().toLowerCase();
      const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
      const pageSize = Math.min(5000, Math.max(10, parseInt(url.searchParams.get('page_size') || '60', 10) || 60));
      const tzOffsetMins = parseInt(url.searchParams.get('tz_offset') || String(new Date().getTimezoneOffset()), 10) || 0;

      const classifyExt = (fname) => {
        const lower = String(fname || '').toLowerCase();
        const dot = lower.lastIndexOf('.');
        const ext = dot >= 0 ? lower.slice(dot + 1) : '';
        if (['xls','xlsx','csv','doc','docx','pdf','ppt','pptx','txt','rtf','sql','db','sqlite','accdb','mdb','json','xml'].includes(ext)) return 'docs';
        if (['jpg','jpeg','png','gif','webp','bmp','svg','heic'].includes(ext)) return 'images';
        if (['zip','rar','7z','tar','gz','iso'].includes(ext)) return 'archives';
        return 'other';
      };

      const rows = db.prepare(`SELECT u.file_id,u.device_id,u.file_name,u.file_size,u.stored_path,u.created_at,
        u.device_name,u.windows_user,u.channel,u.recipient_name,u.recipient_phone,u.page_url,u.sha256,
        COALESCE(NULLIF(u.device_name,''), COALESCE(NULLIF(d.label,''), d.hostname, u.device_id)) AS resolved_device_name
        FROM uploaded_files u
        LEFT JOIN devices d ON d.device_id = u.device_id
        ORDER BY u.created_at DESC`).all();

      const byId = new Map();
      for (const r of rows) {
        byId.set(r.file_id, {
          file_id: r.file_id,
          device_id: r.device_id || '',
          device_name: r.resolved_device_name || r.device_name || r.device_id || '',
          windows_user: r.windows_user || '',
          channel: r.channel || 'whatsapp_web',
          file_name: r.file_name || 'file.bin',
          file_size: Number(r.file_size || 0),
          stored_path: r.stored_path || '',
          recipient_name: r.recipient_name || '',
          recipient_phone: r.recipient_phone || '',
          page_url: r.page_url || '',
          sha256: r.sha256 || '',
          created_at: Number(r.created_at || 0),
        });
      }
      for (const entry of readArchiveLogEntries()) {
        const fid = String((entry && entry.file_id) || '').trim();
        if (!fid || byId.has(fid)) continue;
        byId.set(fid, {
          file_id: fid,
          device_id: entry.device_id || '',
          device_name: entry.device_name || entry.device_id || '',
          windows_user: entry.windows_user || '',
          channel: entry.channel || 'whatsapp_web',
          file_name: entry.file_name || 'file.bin',
          file_size: Number(entry.file_size || 0),
          stored_path: entry.stored_path || '',
          recipient_name: entry.recipient_name || '',
          recipient_phone: entry.recipient_phone || '',
          page_url: entry.page_url || '',
          sha256: entry.sha256 || '',
          created_at: Number(entry.created_at || 0),
        });
      }

      const allFiles = Array.from(byId.values()).sort((a, b) => b.created_at - a.created_at);
      let totalBytes = 0, waCount = 0, sensitiveCount = 0, imagesCount = 0, todayCount = 0;
      const dayAgo = Date.now() - 86400 * 1000;
      const perDevice = new Map();
      const dailyMap = new Map();

      for (const f of allFiles) {
        const sz = Number(f.file_size || 0);
        totalBytes += sz;
        const fChan = String(f.channel || 'whatsapp_web').toLowerCase();
        if (fChan.includes('whatsapp')) waCount++;
        const cat = classifyExt(f.file_name);
        if (cat === 'docs' || cat === 'archives') sensitiveCount++;
        if (cat === 'images') imagesCount++;
        if (f.created_at >= dayAgo) todayCount++;
        const dn = f.device_name || f.device_id || 'غير معروف';
        perDevice.set(dn, (perDevice.get(dn) || 0) + 1);

        if (f.created_at > 0) {
          const localDt = new Date(f.created_at - tzOffsetMins * 60000);
          const dayKey = localDt.toISOString().slice(0, 10);
          let bucket = dailyMap.get(dayKey);
          if (!bucket) {
            bucket = { day: dayKey, total: 0, images: 0, docs: 0, archives: 0, bytes: 0 };
            dailyMap.set(dayKey, bucket);
          }
          bucket.total++;
          bucket.bytes += sz;
          if (cat === 'images') bucket.images++;
          else if (cat === 'docs') bucket.docs++;
          else if (cat === 'archives') bucket.archives++;
        }
      }

      let topDevice = '—', topDeviceCount = 0;
      const devicesList = [];
      for (const [name, count] of perDevice.entries()) {
        devicesList.push({ name, count });
        if (count > topDeviceCount) { topDeviceCount = count; topDevice = name; }
      }
      devicesList.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
      const dailyIndex = Array.from(dailyMap.values())
        .sort((a, b) => b.day.localeCompare(a.day))
        .slice(0, 366);

      const matched = allFiles.filter((f) => {
        const fChan = String(f.channel || 'whatsapp_web').toLowerCase();
        if (ch === 'whatsapp_web' && !fChan.includes('whatsapp')) return false;
        if (ch === 'web_upload' && fChan.includes('whatsapp')) return false;
        if (fromMs > 0 && f.created_at < fromMs) return false;
        if (toMs > 0 && f.created_at > toMs) return false;
        if (fileType && classifyExt(f.file_name) !== fileType) return false;
        const dn = f.device_name || f.device_id || '';
        if (devFilter && dn !== devFilter && f.device_id !== devFilter) return false;
        if (q) {
          const hay = `${f.file_name} ${f.device_name} ${f.device_id} ${f.windows_user} ${f.recipient_name} ${f.recipient_phone} ${f.page_url} ${f.sha256}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      const totalMatching = matched.length;
      const totalPages = Math.max(1, Math.ceil(totalMatching / pageSize));
      const safePage = Math.min(page, totalPages);
      const offset = (safePage - 1) * pageSize;
      const files = matched.slice(offset, offset + pageSize).map((f) => ({
        ...f,
        exists_on_disk: Boolean(f.stored_path),
      }));

      const curArchiveRoot = getArchiveRoot();
      const disk = getCachedDiskSpaceBytes(curArchiveRoot);
      return json(res, 200, {
        ok: true,
        archive_root: curArchiveRoot,
        disk_free_bytes: disk.free,
        disk_total_bytes: disk.total,
        summary: {
          total_files: allFiles.length,
          total_bytes: totalBytes,
          whatsapp_count: waCount,
          sensitive_count: sensitiveCount,
          images_count: imagesCount,
          today_count: todayCount,
          top_device: topDevice,
          top_device_count: topDeviceCount,
        },
        devices: devicesList,
        daily_index: dailyIndex,
        total_matching: totalMatching,
        page: safePage,
        page_size: pageSize,
        total_pages: totalPages,
        files,
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/archive-migrate') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req).catch(() => ({}));
      const oldRoot = String(body.old_root || '').trim().replace(/[\\/]+$/, '');
      const newRoot = String(body.new_root || '').trim().replace(/[\\/]+$/, '');
      let updated = 0;
      if (body.moved && oldRoot && newRoot && oldRoot.toLowerCase() !== newRoot.toLowerCase()) {
        const rows = db.prepare('SELECT file_id, stored_path FROM uploaded_files').all();
        const upd = db.prepare('UPDATE uploaded_files SET stored_path=? WHERE file_id=?');
        for (const r of rows) {
          const sp = String(r.stored_path || '').replace(/\//g, '\\');
          const oldNorm = oldRoot.replace(/\//g, '\\');
          if (sp.length > oldNorm.length && sp.slice(0, oldNorm.length).toLowerCase() === oldNorm.toLowerCase()) {
            const candidate = newRoot.replace(/\//g, '\\') + sp.slice(oldNorm.length);
            if (fs.existsSync(candidate)) {
              upd.run(candidate, r.file_id);
              updated += 1;
            }
          }
        }
      }
      audit('admin', 'archive_dir_change', newRoot || getArchiveRoot(), 'ok', { updated });
      return json(res, 200, { ok: true, updated, archive_root: getArchiveRoot() });
    }

    // ----- Device: upload archived exact copy -----
    // Device: upload an exact archived copy of an employee-uploaded file (DLP evidence).
    if (req.method === 'POST' && url.pathname === '/api/v1/device/file') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, {ok:false,error:'unauthorized'});
      const body = await readBody(req, 95 * 1024 * 1024);
      const rawFid = String(body.file_id || '').replace(/[^A-Za-z0-9_-]/g, '');
      const fid = rawFid || rid('upl_');
      const origName = String(body.file_name || 'file.bin').trim() || 'file.bin';
      let b64 = typeof body.file_base64 === 'string' ? body.file_base64.trim() : '';
      const comma = b64.indexOf(';base64,');
      if (comma !== -1) b64 = b64.slice(comma + 8);
      if (!b64) return json(res, 400, {ok:false,error:'missing file_base64'});
      const buf = Buffer.from(b64, 'base64');
      if (buf.length > 66 * 1024 * 1024) return json(res, 413, {ok:false,error:'file too large'});

      const sha256Hash = crypto.createHash('sha256').update(buf).digest('hex');
      const deviceName = String(dev.label || dev.hostname || body.hostname || dev.device_id || 'Unknown-Device').trim();
      const winUser = String(body.windows_user || '').trim();
      const channel = String(body.channel || 'whatsapp_web').trim() || 'whatsapp_web';
      const recipientName = String(body.recipient_name || '').trim();
      const recipientPhone = String(body.recipient_phone || '').trim();
      const pageUrl = String(body.page_url || '').trim();
      const createdTs = now();

      const existingRow = db.prepare('SELECT stored_path FROM uploaded_files WHERE file_id=?').get(fid);
      let storedPath = existingRow && existingRow.stored_path && fs.existsSync(existingRow.stored_path)
        ? existingRow.stored_path
        : '';
      if (!storedPath) {
        try {
          storedPath = buildArchiveFilePath({
            channel,
            deviceName,
            recipientName,
            recipientPhone,
            origName,
            tsMs: createdTs,
          });
          fs.writeFileSync(storedPath, buf);
        } catch (err) {
          const fallbackName = sanitizeWinSegment(origName, 'file.bin', 120);
          storedPath = path.join(UPLOADS_DIR, `${fid}__${fallbackName}`);
          fs.writeFileSync(storedPath, buf);
        }
        appendArchiveLog({
          file_id: fid,
          device_id: dev.device_id,
          device_name: deviceName,
          windows_user: winUser,
          channel,
          file_name: origName,
          file_size: buf.length,
          sha256: sha256Hash,
          recipient_name: recipientName,
          recipient_phone: recipientPhone,
          page_url: pageUrl,
          stored_path: storedPath,
          created_at: createdTs,
        });
      }

      db.prepare(`INSERT OR REPLACE INTO uploaded_files
        (file_id,device_id,file_name,file_size,stored_path,created_at,device_name,windows_user,channel,recipient_name,recipient_phone,page_url,sha256)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(
          fid,
          dev.device_id,
          origName,
          buf.length,
          storedPath,
          createdTs,
          deviceName,
          winUser,
          channel,
          recipientName,
          recipientPhone,
          pageUrl,
          sha256Hash
        );
      writeProjectLog(
        'dlp',
        'INFO',
        'DLP_FILE_CAPTURED',
        `تم التقاط وأرشفة ملف مرفوع: الملف="${origName}" (${Math.round(buf.length / 1024)} KB) | الجهاز="${deviceName}" (${dev.device_id}) | المستخدم="${winUser || '-'}" | القناة=${channel} | المستلم="${recipientName || '-'}" (${recipientPhone || '-'}) | المسار=${storedPath}`
      );
      return json(res, 200, {ok:true, file_id: fid, size: buf.length, sha256: sha256Hash, stored_path: storedPath});
    }

    // Device: report an alert (tamper, exfil, usb, auth_fail, bypass).
    if (req.method === 'POST' && url.pathname === '/api/v1/device/alert') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, {ok:false,error:'unauthorized'});
      const body = await readBody(req, 25 * 1024 * 1024);
      const type = String(body.type || 'tamper').slice(0, 40);
      const severity = ['low','medium','high','critical'].includes(body.severity) ? body.severity : 'medium';
      const message = String(body.message || '').slice(0, 600);
      writeProjectLog(
        'dlp',
        severity === 'critical' || severity === 'high' ? 'WARN' : 'INFO',
        `DEVICE_ALERT_${type.toUpperCase()}`,
        `تنبيه أمني من الجهاز "${dev.label || dev.hostname}" (${dev.device_id}) | الخطورة=${severity} | النوع=${type} | التفاصيل=${message}`
      );
      const parsedMeta = storeAlertWithSeparatedMedia({
        id: rid('alt_'),
        deviceId: dev.device_id,
        type,
        severity,
        message,
        rawMeta: body.meta,
        createdAt: now(),
        ignoreExisting: false,
      });
      if (parsedMeta && parsedMeta.uploaded_file_id) {
        const devName = String(dev.label || dev.hostname || dev.device_id || '');
        db.prepare(`UPDATE uploaded_files SET
          device_name=COALESCE(NULLIF(device_name,''),?),
          windows_user=COALESCE(NULLIF(windows_user,''),?),
          channel=COALESCE(NULLIF(channel,''),?),
          recipient_name=COALESCE(NULLIF(recipient_name,''),?),
          recipient_phone=COALESCE(NULLIF(recipient_phone,''),?),
          page_url=COALESCE(NULLIF(page_url,''),?),
          sha256=COALESCE(NULLIF(sha256,''),?)
          WHERE file_id=?`)
          .run(
            devName,
            String(parsedMeta.windows_user || ''),
            String(parsedMeta.channel || 'whatsapp_web'),
            String(parsedMeta.recipient_name || ''),
            String(parsedMeta.recipient_phone || ''),
            String(parsedMeta.page_url || ''),
            String(parsedMeta.sha256 || ''),
            String(parsedMeta.uploaded_file_id)
          );
      }
      return json(res, 200, {ok:true});
    }

    // Device: upload live Dahua CCTV frame from branch bridge PC
    if (req.method === 'POST' && url.pathname === '/api/v1/device/cctv-frame') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
      const body = await readBody(req, 8 * 1024 * 1024);
      cctv.ingestBridgeFrame({
        deviceId: dev.device_id,
        dvrId: String(body.dvr_id || ''),
        channel: Number(body.channel || 1),
        hd: Boolean(body.hd),
        imageB64: String(body.image || ''),
        error: String(body.error || ''),
      });
      return json(res, 200, {
        ok: true,
        cctv_tasks: cctv.getActiveTaskForDevice(dev.device_id),
      });
    }

    // Device: report local subnet Dahua scan results from branch bridge PC
    if (req.method === 'POST' && url.pathname === '/api/v1/device/cctv-scan') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
      const body = await readBody(req, 512 * 1024);
      cctv.ingestBranchScanResult(dev.device_id, body && body.found);
      return json(res, 200, { ok: true });
    }

    // Device: report on-demand Dahua CGI results from branch bridge PC
    if (req.method === 'POST' && url.pathname === '/api/v1/device/cctv-cgi') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
      const body = await readBody(req, 14 * 1024 * 1024);
      cctv.ingestBranchCgiResult(dev.device_id, body);
      return json(res, 200, { ok: true });
    }

    // Device: stream live Dahua camera audio micro-chunks from branch bridge PC (0% CPU when muted)
    if (req.method === 'POST' && url.pathname === '/api/v1/device/cctv-audio') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
      const body = await readBody(req, 512 * 1024);
      const active = cctv.ingestBridgeAudioChunk({
        deviceId: dev.device_id,
        dvrId: String((body && body.dvr_id) || ''),
        channel: Number((body && body.channel) || 1),
        contentType: String((body && body.content_type) || ''),
        dataB64: String((body && body.data_b64) || ''),
        error: String((body && body.error) || ''),
      });
      return json(res, 200, {
        ok: true,
        active,
        cctv_tasks: cctv.getActiveTaskForDevice(dev.device_id),
      });
    }

    // Device: poll
    if (req.method === 'POST' && url.pathname === '/api/v1/device/poll') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, {ok:false,error:'unauthorized'});
      const body = await readBody(req);
      const ci = findNewestSetupInstaller('IT ELKHAWGA Client_');
      const latestClientVer = (ci && ci.version) || '1.2.0';
      const reportedVer = String(body.app_version || dev.app_version || '1.0.0').replace(/^v/i, '').trim();
      const cmpVer = (a, b) => {
        const pa = String(a || '0.0.0').split('.').map(n => parseInt(n, 10) || 0);
        const pb = String(b || '0.0.0').split('.').map(n => parseInt(n, 10) || 0);
        for (let i = 0; i < 3; i++) {
          if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
        }
        return 0;
      };
      const isUpToDate = cmpVer(reportedVer, latestClientVer) >= 0;
      const supportsSelfUpdate = cmpVer(reportedVer, '1.1.0') >= 0;
      if (isUpToDate) {
        db.prepare("UPDATE commands SET acked_at=? WHERE device_id=? AND type='update_client' AND acked_at IS NULL")
          .run(now(), dev.device_id);
      }
      if (body.ack_command_id) {
        const cmdRow = db.prepare('SELECT id,type FROM commands WHERE id=? AND device_id=? AND acked_at IS NULL').get(body.ack_command_id, dev.device_id);
        if (cmdRow) {
          console.log(`[CMD-ACK] dev=${dev.label || dev.hostname} ver=${reportedVer} cmd=${cmdRow.type} id=${cmdRow.id} isUpToDate=${isUpToDate}`);
          writeProjectLog(
            cmdRow.type === 'update_client' ? 'updates' : 'devices',
            'INFO',
            'COMMAND_ACKED',
            `تأكيد تنفيذ أمر من الجهاز "${dev.label || dev.hostname}" (${dev.device_id}) | الأمر=${cmdRow.type} | ID=${cmdRow.id} | الإصدار الحالي=v${reportedVer} | محدث بالكامل=${isUpToDate}`
          );
          db.prepare('UPDATE commands SET acked_at=? WHERE id=?').run(now(), cmdRow.id);
          if (cmdRow.type === 'update_client' && !isUpToDate) {
            // Queue a fresh command ID 75s in the future so the client's last_command_id check never skips a retry!
            db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)')
              .run(rid('cmd_'), dev.device_id, 'update_client', now() + 75_000);
          }
        }
      }
      if (!isUpToDate && supportsSelfUpdate) {
        const hasPendingAny = db.prepare('SELECT 1 FROM commands WHERE device_id=? AND acked_at IS NULL').get(dev.device_id);
        if (!hasPendingAny) {
          db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)')
            .run(rid('cmd_'), dev.device_id, 'update_client', now());
          console.log(`[AUTO-UPDATE] Queued update_client (${reportedVer} -> ${latestClientVer}) for ${dev.label || dev.hostname}`);
          writeProjectLog(
            'updates',
            'INFO',
            'AUTO_UPDATE_QUEUED',
            `جدولة تحديث تلقائي للجهاز "${dev.label || dev.hostname}" (${dev.device_id}) من الإصدار v${reportedVer} إلى v${latestClientVer}`
          );
        }
      }
      if (body.app_version && dev.app_version && String(body.app_version) !== String(dev.app_version)) {
        writeProjectLog(
          'updates',
          'INFO',
          'DEVICE_VERSION_CHANGED',
          `نجاح ترقية الجهاز "${dev.label || dev.hostname}" (${dev.device_id}) من الإصدار v${dev.app_version} إلى الإصدار v${body.app_version}`
        );
      }
      const realPollIp = clientIpFromReq(req);
      const nextIp = (realPollIp && realPollIp !== '127.0.0.1' && realPollIp !== '::1')
        ? realPollIp
        : ((dev.ip && dev.ip !== '127.0.0.1') ? dev.ip : (realPollIp || '127.0.0.1'));
      const prePendingCmd = pendingCommand(dev.device_id);
      const hasPendingBlock = Boolean(prePendingCmd && prePendingCmd.type === 'block');
      const hasPendingUnblock = Boolean(prePendingCmd && prePendingCmd.type === 'unblock');
      const pollBlockedBit = hasPendingBlock ? 1 : (hasPendingUnblock ? 0 : (body.blocked ? 1 : 0));
      db.prepare("UPDATE devices SET hostname=?,os=COALESCE(NULLIF(?,'') ,os),app_version=?,last_seen=?,ip=?,blocked=?,usb_blocked=?,mode=?,policy_version=? WHERE device_id=?")
        .run(body.hostname||dev.hostname, body.os||'', body.app_version||dev.app_version, now(), nextIp, pollBlockedBit, body.usb_blocked?1:0, body.mode||dev.mode, body.policy_version||dev.policy_version, dev.device_id);
      if (Array.isArray(body.sites)) {
        const clean = body.sites
          .filter(function (s) { return typeof s === 'string' && s.length <= 120; })
          .slice(0, 15);
        db.prepare('UPDATE devices SET sites=? WHERE device_id=?')
          .run(JSON.stringify(clean), dev.device_id);
      }
      if (Array.isArray(body.denied)) {
        const clean = body.denied
          .filter(function (s) { return typeof s === 'string' && s.length <= 120; })
          .slice(0, 12);
        db.prepare('UPDATE devices SET denied=? WHERE device_id=?')
          .run(JSON.stringify(clean), dev.device_id);
      }
      if (typeof body.rustdesk_id === 'string') {
        db.prepare('UPDATE devices SET rustdesk_id=? WHERE device_id=?')
          .run(body.rustdesk_id.slice(0, 60), dev.device_id);
      }
      if (typeof body.event === 'string' && body.event) {
        const ev = body.event.slice(0, 60);
        writeProjectLog(
          'devices',
          'INFO',
          `CLIENT_EVENT_${ev.toUpperCase()}`,
          `حدث من الجهاز "${dev.label || dev.hostname}" (${dev.device_id}) | الحدث=${ev} | IP=${nextIp}`
        );
        if (ev === 'unblock_password') {
          if (!hasPendingBlock) {
            db.prepare('UPDATE devices SET last_event=?,last_event_at=?,admin_open=1,blocked=0 WHERE device_id=?').run(ev, now(), dev.device_id);
            dev.admin_open = 1;
          }
        } else if (ev === 'block_password') {
          if (!hasPendingUnblock) {
            db.prepare('UPDATE devices SET last_event=?,last_event_at=?,admin_open=0,blocked=1 WHERE device_id=?').run(ev, now(), dev.device_id);
            dev.admin_open = 0;
          }
        } else {
          db.prepare('UPDATE devices SET last_event=?,last_event_at=? WHERE device_id=?').run(ev, now(), dev.device_id);
        }
      }
      const effBlocked = hasPendingBlock ? 1 : ((hasPendingUnblock || Number(dev.admin_open) === 1) ? 0 : (body.blocked ? 1 : 0));
      if (effBlocked !== pollBlockedBit) {
        db.prepare('UPDATE devices SET blocked=? WHERE device_id=?').run(effBlocked, dev.device_id);
      }
      let pol = buildEffectiveDevicePolicy(dev);
      let sendPolicy = pol && body.policy_version !== pol.version ? pol : null;
      if (Number(dev.admin_open) === 1 && pol && body.policy_version === pol.version && !hasPendingBlock) {
        db.prepare("UPDATE commands SET acked_at=? WHERE device_id=? AND type='unblock' AND acked_at IS NULL").run(now(), dev.device_id);
      }
      if (Number(dev.admin_open) === 0 && pol && body.policy_version === pol.version && body.blocked && !hasPendingUnblock) {
        db.prepare("UPDATE commands SET acked_at=? WHERE device_id=? AND type='block' AND acked_at IS NULL").run(now(), dev.device_id);
      }

      const activeMode = (d) => (d && d.stream_until && d.stream_until > now())
        ? (d.stream_mode || 'screen')
        : ((d && d.screen_requested) ? 'once' : '');
      let command = pendingCommand(dev.device_id);
      let fresh = db.prepare('SELECT screen_requested,stream_mode,stream_until,rustdesk_password,admin_open,group_id FROM devices WHERE device_id=?').get(dev.device_id) || dev;
      let streamMode = activeMode(fresh);
      // 100% Router Direct CCTV mode: never dispatch any CCTV bridge tasks to employee computers
      let cctvTasks = null;
      let cctvScan = false;
      let cctvCgi = null;
      // Long-poll: keep the request open briefly so a command or screenshot/stream request issued
      // right now is delivered within ~300 ms instead of waiting for the next cycle.
      if (!command && !sendPolicy && !streamMode) {
        const started = Date.now();
        while (!command && !streamMode && (Date.now() - started) < LONG_POLL_MS) {
          await new Promise(function (r) { setTimeout(r, 400); });
          command = pendingCommand(dev.device_id);
          fresh = db.prepare('SELECT screen_requested,stream_mode,stream_until,rustdesk_password,admin_open,group_id FROM devices WHERE device_id=?').get(dev.device_id) || fresh;
          streamMode = activeMode(fresh);
        }
        pol = buildEffectiveDevicePolicy(fresh);
        sendPolicy = pol && body.policy_version !== pol.version ? pol : null;
        try { db.prepare('UPDATE devices SET last_seen=? WHERE device_id=?').run(now(), dev.device_id); } catch (_) {}
      }
      return json(res, 200, {
        ok: true,
        command: command || null,
        policy: sendPolicy,
        poll_seconds: 3,
        screen: !!streamMode,
        stream_mode: streamMode,
        rustdesk_password: fresh.rustdesk_password || '',
        cctv_tasks: cctvTasks || null,
        cctv_scan: Boolean(cctvScan),
        cctv_cgi: cctvCgi || null,
      });
    }

    // Executive Video Guides (/guide for Owner iPad & /admin-guide for IT Engineers/Admins)
    if ((req.method === 'GET' || req.method === 'HEAD') && (url.pathname === '/guide-video.mp4' || url.pathname === '/admin-guide-video.mp4')) {
      const isAdminGuide = url.pathname === '/admin-guide-video.mp4';
      const guideMp4 = isAdminGuide
        ? 'C:\\Users\\IT APP\\Desktop\\tools\\IT-ELKHAWGA-Admin-Engineers-Guide.mp4'
        : 'C:\\Users\\IT APP\\Desktop\\tools\\IT-ELKHAWGA-iPad-Owner-Guide.mp4';
      const dlFileName = isAdminGuide
        ? 'IT-ELKHAWGA-Admin-Engineers-Guide.mp4'
        : 'IT-ELKHAWGA-iPad-Owner-Guide.mp4';
      if (!fs.existsSync(guideMp4)) {
        return json(res, 404, { ok: false, error: 'guide video not found' });
      }
      const stat = fs.statSync(guideMp4);
      const total = stat.size;
      const range = req.headers.range;
      if (range) {
        const parts = String(range).replace(/bytes=/, '').split('-');
        const start = Math.max(0, parseInt(parts[0], 10) || 0);
        const end = parts[1] ? Math.min(total - 1, parseInt(parts[1], 10)) : total - 1;
        if (start >= total || start > end) {
          res.writeHead(416, { 'Content-Range': `bytes */${total}` });
          return res.end();
        }
        const chunkSize = (end - start) + 1;
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${total}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunkSize,
          'Content-Type': 'video/mp4',
          'Cache-Control': 'public, max-age=300',
        });
        if (req.method === 'HEAD') return res.end();
        return fs.createReadStream(guideMp4, { start, end }).pipe(res);
      }
      const dl = url.searchParams.get('download') === '1';
      const headers = {
        'Content-Length': total,
        'Content-Type': 'video/mp4',
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'public, max-age=300',
      };
      if (dl) {
        headers['Content-Disposition'] = `attachment; filename="${dlFileName}"`;
      }
      res.writeHead(200, headers);
      if (req.method === 'HEAD') return res.end();
      return fs.createReadStream(guideMp4).pipe(res);
    }

    if (req.method === 'GET' && (url.pathname === '/showcase' || url.pathname === '/showcase.html')) {
      const showcaseCandidates = [
        path.join(process.cwd(), 'web', 'showcase.html'),
        path.join(process.cwd(), '..', 'web', 'showcase.html'),
        'C:\\Users\\IT APP\\Desktop\\blockwebsite\\web\\showcase.html',
      ];
      for (const sc of showcaseCandidates) {
        if (fs.existsSync(sc)) {
          const html = fs.readFileSync(sc, 'utf8');
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
          });
          return res.end(html);
        }
      }
    }

    if (req.method === 'GET' && (url.pathname === '/guide' || url.pathname === '/admin-guide')) {
      const isAdminGuide = url.pathname === '/admin-guide';
      const pageTitle = isAdminGuide
        ? 'الدليل الشامل للمهندسين ومسؤولي النظام — IT ELKHAWAGA'
        : 'دليل تشغيل IT ELKHAWAGA على الـ iPad';
      const heading = isAdminGuide
        ? 'الدليل التدريبي التفصيلي الشامل للمهندسين ومسؤولي النظام (22 خطوة مصوّرة بمؤشر إيضاحي)'
        : 'الدليل التفصيلي المحدّث لصاحب الشركة والإدارة العليا على الـ iPad (15 خطوة مصوّرة بمؤشر إيضاحي)';
      const subText = isAdminGuide
        ? 'شرح تفصيلي بالعلامات المضيئة لكل قسم: الدخول والأدوار، مؤشر السيرفر، الأجهزة وRelay، الوضع الهجين لـ RustDesk، التصفح النظيف وحماية ربط سيستم elkhawaga.uk، نقل الأرشيف والباكاب لهارد جديد، والنسخ الاحتياطي الساعي التلقائي لموقع الشركة'
        : 'شرح تفصيلي خطوة بخطوة بالعلامات المضيئة: تثبيت تطبيق الـ iPad، المتابعة اللحظية، المشاهدة الصامتة، دعم RustDesk، تقارير وسرية أرشيف الملفات، وتأمين موقع elkhawaga.uk بالنسخ الساعي التلقائي';
      const videoSrc = isAdminGuide ? '/admin-guide-video.mp4' : '/guide-video.mp4';
      const html = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>${pageTitle}</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Tahoma,sans-serif;background:radial-gradient(circle at top,#132f5c,#071326 70%);color:#f8fafc;display:flex;flex-direction:column;align-items:center;padding:24px 16px}
    .wrap{width:100%;max-width:1020px;background:rgba(15,23,42,.84);border:1px solid rgba(227,185,78,.26);border-radius:24px;padding:24px;box-shadow:0 24px 60px rgba(0,0,0,.48)}
    .head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px}
    .brand{display:flex;align-items:center;gap:12px}
    .brand img{width:48px;height:48px;border-radius:12px;background:#fff;padding:4px;object-fit:contain}
    h1{font-size:20px;margin:0;color:#fff}
    .sub{font-size:13px;color:#cbd5e1;margin-top:4px;line-height:1.5}
    video{width:100%;border-radius:16px;background:#000;border:1px solid rgba(148,163,184,.25);box-shadow:0 12px 32px rgba(0,0,0,.4)}
    .actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px;justify-content:center}
    .btn{text-decoration:none;padding:12px 22px;border-radius:12px;font-weight:700;font-size:15px;display:inline-flex;align-items:center;gap:8px}
    .btn-primary{background:linear-gradient(135deg,#2563eb,#1d4ed8);color:#fff;box-shadow:0 8px 20px rgba(37,99,235,.35)}
    .btn-sec{background:rgba(255,255,255,.09);color:#e2e8f0;border:1px solid rgba(255,255,255,.16)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <div class="brand">
        <img src="/assets/apple-touch-icon.png" alt="IT ELKHAWAGA">
        <div>
          <h1>${heading}</h1>
          <div class="sub">${subText}</div>
        </div>
      </div>
    </div>
    <video controls playsinline preload="metadata" src="${videoSrc}"></video>
    <div class="actions">
      <a class="btn btn-primary" href="/">🚀 فتح لوحة الإدارة الآن</a>
      <a class="btn btn-sec" href="${videoSrc}?download=1">⬇ تحميل الفيديو (MP4)</a>
    </div>
  </div>
</body>
</html>`;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(html);
    }

    // Direct zero-hop in-memory fast path for CCTV RPC commands on Web Admin / iPad PWA (eliminates 8790 -> 8787 -> 8790 double round-trip!)
    if (req.method === 'POST' && url.pathname === '/api/rpc') {
      const jwtVerified = verifyAdminJwtToken(bearer(req));
      if (jwtVerified && jwtVerified.claims) {
        const rpcBody = await readBody(req).catch(() => null);
        const rpcCmd = rpcBody && typeof rpcBody.cmd === 'string' ? rpcBody.cmd.trim() : '';
        const rpcArgs = (rpcBody && rpcBody.args) || {};
        const actor = String(jwtVerified.claims.sub || 'admin');
        const role = String(jwtVerified.claims.role || 'admin').toLowerCase();
        if (rpcCmd === 'biometrics_action') {
          const act = String(rpcArgs.action || '');
          if (role === 'viewer' && ['save_device', 'delete_device', 'clear_logs'].includes(act)) {
            return json(res, 200, {
              ok: true,
              result: { ok: false, success: false, error: 'صلاحية المشاهدة فقط لا تسمح بإضافة أو حذف أجهزة البصمة' },
            });
          }
          try {
            const out = await biometrics.handleAction({
              action: act,
              payload: rpcArgs.payload || {},
            });
            return json(res, 200, { ok: true, result: out });
          } catch (e) {
            return json(res, 200, {
              ok: true,
              result: { ok: false, success: false, error: (e && e.message) || 'تعذر تنفيذ إجراء جهاز البصمة' },
            });
          }
        }
        if (rpcCmd === 'cctv_action' || rpcCmd === 'cctv_list_dvrs' || rpcCmd === 'cctv_get_frame_b64') {
          const st = cctv.getSettings();
          if (st.super_only && role !== 'super') {
            return json(res, 200, {
              ok: true,
              result: rpcCmd === 'cctv_list_dvrs'
                ? { ok: true, dvrs: [], settings: st, restricted: true }
                : { ok: false, success: false, error: 'تم حصر مشاهدة الكاميرات بحساب السوبر أدمن فقط' },
            });
          }
          try {
            if (rpcCmd === 'cctv_list_dvrs') {
              return json(res, 200, { ok: true, result: cctv.listDvrs({ actor, role }) });
            }
            if (rpcCmd === 'cctv_action') {
              const act = String(rpcArgs.action || '');
              if (role === 'viewer' && ['ptz', 'save_channel_meta', 'pull_names', 'save_settings'].includes(act)) {
                return json(res, 200, { ok: true, result: { ok: false, success: false, error: 'صلاحية المشاهدة فقط لا تسمح بالتعديل أو تحريك الكاميرات' } });
              }
              const out = await cctv.handleAction({
                action: act,
                payload: rpcArgs.payload || {},
                actor,
                role,
              });
              return json(res, 200, { ok: true, result: out });
            }
            if (rpcCmd === 'cctv_get_frame_b64') {
              const frame = await cctv.getFrame({
                dvrId: rpcArgs.dvrId,
                channel: Number(rpcArgs.channel || 1),
                hd: Boolean(rpcArgs.hd),
                waitMs: 10000,
              });
              return json(res, 200, {
                ok: true,
                result: {
                  ok: true,
                  mime: frame.mime || 'image/jpeg',
                  at: frame.at,
                  image: frame.buf.toString('base64'),
                },
              });
            }
          } catch (e) {
            return json(res, 200, {
              ok: true,
              result: { ok: false, success: false, error: (e && e.message) || 'تعذر تنفيذ إجراء الكاميرا' },
            });
          }
        }
        // For non-CCTV RPC calls, forward the already-read body buffer to 127.0.0.1:8787
        const rawRpcBuf = Buffer.from(JSON.stringify(rpcBody || {}), 'utf8');
        const fwdHeaders = {
          host: '127.0.0.1:8787',
          'content-type': 'application/json',
          'content-length': rawRpcBuf.length,
        };
        if (req.headers['authorization']) fwdHeaders['authorization'] = req.headers['authorization'];
        const proxyReq = http.request(
          {
            hostname: '127.0.0.1',
            port: 8787,
            path: '/api/rpc',
            method: 'POST',
            headers: fwdHeaders,
            agent: lanKeepAliveAgent,
            timeout: 25000,
          },
          (proxyRes) => {
            const chunks = [];
            proxyRes.on('data', (c) => chunks.push(c));
            proxyRes.on('end', () => {
              const rawBuf = Buffer.concat(chunks);
              const outHeaders = { ...proxyRes.headers, Vary: 'Accept-Encoding' };
              if (res.__acceptGzip && rawBuf.length >= 1024 && !outHeaders['content-encoding']) {
                const gz = zlib.gzipSync(rawBuf, { level: zlib.constants.Z_BEST_SPEED });
                outHeaders['Content-Encoding'] = 'gzip';
                outHeaders['content-length'] = gz.length;
                delete outHeaders['Content-Length'];
                res.writeHead(proxyRes.statusCode || 200, outHeaders);
                res.end(gz);
              } else {
                outHeaders['content-length'] = rawBuf.length;
                delete outHeaders['Content-Length'];
                res.writeHead(proxyRes.statusCode || 200, outHeaders);
                res.end(rawBuf);
              }
            });
          }
        );
        proxyReq.on('error', () => {
          if (!res.headersSent) json(res, 502, { ok: false, error: 'لوحة الإدارة قيد إعادة التشغيل، حاول بعد ثوانٍ' });
        });
        proxyReq.end(rawRpcBuf);
        return;
      }
    }

    // Reverse-proxy Web Admin Dashboard & iPad PWA routes to local Admin Server (127.0.0.1:8787)
    // so the company owner (iPad) and remote managers can sign in securely over HTTPS from anywhere.
    const isWebProxyRoute =
      (req.method === 'POST' && url.pathname === '/api/rpc') ||
      ((req.method === 'GET' || req.method === 'HEAD') && (
        url.pathname === '/' ||
        url.pathname === '/admin' ||
        url.pathname === '/admin/' ||
        url.pathname === '/index.html' ||
        url.pathname === '/manifest.webmanifest' ||
        url.pathname === '/sw.js' ||
        url.pathname === '/theme.js' ||
        url.pathname === '/tauri-shim.js' ||
        url.pathname === '/index.inline.js' ||
        url.pathname === '/favicon.ico' ||
        url.pathname.startsWith('/styles/') ||
        url.pathname.startsWith('/assets/')
      ));

    if (isWebProxyRoute && (req.method === 'GET' || req.method === 'HEAD')) {
      const webRootCandidates = [
        path.join(process.cwd(), 'web'),
        path.join(process.cwd(), '..', 'web'),
        'C:\\Users\\IT APP\\Desktop\\blockwebsite\\web',
      ];
      let relAsset = url.pathname;
      if (relAsset === '/' || relAsset === '/admin' || relAsset === '/admin/' || relAsset === '/index.html') {
        relAsset = '/index.html';
      } else if (relAsset === '/favicon.ico') {
        relAsset = '/assets/apple-touch-icon.png';
      }
      const safeRel = relAsset.replace(/^\/+/, '').replace(/\.\./g, '');
      for (const wr of webRootCandidates) {
        const diskPath = path.join(wr, safeRel);
        if (fs.existsSync(diskPath) && fs.statSync(diskPath).isFile()) {
          const ext = path.extname(diskPath).toLowerCase();
          const mimeMap = {
            '.html': 'text/html; charset=utf-8',
            '.js': 'application/javascript; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.webmanifest': 'application/manifest+json; charset=utf-8',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.svg': 'image/svg+xml',
            '.ico': 'image/png',
          };
          let rawBuf = fs.readFileSync(diskPath);
          if (relAsset === '/index.html') {
            const htmlStr = rawBuf
              .toString('utf8')
              .replace(
                '<script src="tauri-shim.js',
                '<script>window.__ITK_WEB_ADMIN__=true;</script><script src="tauri-shim.js'
              );
            rawBuf = Buffer.from(htmlStr, 'utf8');
          }
          const outHeaders = {
            'Content-Type': mimeMap[ext] || 'application/octet-stream',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
          };
          if (res.__acceptGzip && rawBuf.length >= 1024 && (ext === '.html' || ext === '.js' || ext === '.css' || ext === '.webmanifest')) {
            const gz = zlib.gzipSync(rawBuf, { level: zlib.constants.Z_BEST_SPEED });
            outHeaders['Content-Encoding'] = 'gzip';
            outHeaders['Content-Length'] = gz.length;
            outHeaders['Vary'] = 'Accept-Encoding';
            res.writeHead(200, outHeaders);
            return res.end(req.method === 'HEAD' ? undefined : gz);
          }
          outHeaders['Content-Length'] = rawBuf.length;
          res.writeHead(200, outHeaders);
          return res.end(req.method === 'HEAD' ? undefined : rawBuf);
        }
      }
    }

    if (isWebProxyRoute) {
      const targetPath = (url.pathname === '/admin' || url.pathname === '/admin/')
        ? ('/' + (url.search || ''))
        : (url.pathname + (url.search || ''));
      const fwdHeaders = { host: '127.0.0.1:8787' };
      if (req.headers['content-type']) fwdHeaders['content-type'] = req.headers['content-type'];
      if (req.headers['content-length']) fwdHeaders['content-length'] = req.headers['content-length'];
      if (req.headers['authorization']) fwdHeaders['authorization'] = req.headers['authorization'];
      const proxyReq = http.request(
        {
          hostname: '127.0.0.1',
          port: 8787,
          path: targetPath,
          method: req.method,
          headers: fwdHeaders,
          agent: lanKeepAliveAgent,
          timeout: 25000,
        },
        (proxyRes) => {
          const outHeaders = { ...proxyRes.headers };
          if (
            url.pathname === '/' ||
            url.pathname === '/index.html' ||
            url.pathname === '/sw.js' ||
            url.pathname.endsWith('.js') ||
            url.pathname.endsWith('.css')
          ) {
            outHeaders['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0';
            outHeaders['Pragma'] = 'no-cache';
          }
          const ctype = String(outHeaders['content-type'] || '').toLowerCase();
          const canCompress =
            res.__acceptGzip &&
            !outHeaders['content-encoding'] &&
            (ctype.includes('json') ||
              ctype.includes('javascript') ||
              ctype.includes('text/html') ||
              ctype.includes('text/css') ||
              ctype.includes('image/svg+xml') ||
              ctype.includes('manifest'));
          if (!canCompress) {
            res.writeHead(proxyRes.statusCode || 200, outHeaders);
            proxyRes.pipe(res);
            return;
          }
          const chunks = [];
          proxyRes.on('data', (c) => chunks.push(c));
          proxyRes.on('end', () => {
            const rawBuf = Buffer.concat(chunks);
            outHeaders['Vary'] = 'Accept-Encoding';
            if (rawBuf.length >= 1024) {
              const gz = zlib.gzipSync(rawBuf, { level: zlib.constants.Z_BEST_SPEED });
              outHeaders['Content-Encoding'] = 'gzip';
              outHeaders['content-length'] = gz.length;
              delete outHeaders['Content-Length'];
              res.writeHead(proxyRes.statusCode || 200, outHeaders);
              res.end(gz);
            } else {
              outHeaders['content-length'] = rawBuf.length;
              delete outHeaders['Content-Length'];
              res.writeHead(proxyRes.statusCode || 200, outHeaders);
              res.end(rawBuf);
            }
          });
        }
      );
      proxyReq.on('error', () => {
        if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/admin' || url.pathname === '/index.html')) {
          const fallbackHtml = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">' +
            '<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="3">' +
            '<title>IT ELKHAWGA</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:Segoe UI,Tahoma,sans-serif;background:#0a1f3d;color:#fff;text-align:center;padding:20px}.box{background:rgba(255,255,255,.08);padding:32px;border-radius:20px;max-width:400px}</style></head><body><div class="box"><h2>IT ELKHAWGA</h2><p>جاري تهيئة لوحة الإدارة، سيتم الفتح تلقائياً خلال لحظات...</p></div></body></html>';
          if (!res.headersSent) res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(fallbackHtml);
        } else {
          if (!res.headersSent) json(res, 502, { ok: false, error: 'لوحة الإدارة قيد إعادة التشغيل، حاول بعد ثوانٍ' });
        }
      });
      req.pipe(proxyReq);
      return;
    }

    json(res, 404, {ok:false,error:'not found'});
  } catch (e) {
    console.error(e);
    writeProjectLog('errors', 'ERROR', 'HTTP_HANDLER_EXCEPTION', `خطأ داخلي في معالجة الطلب (${req.method} ${req.url}): ${(e && e.stack) || (e && e.message) || e}`);
    json(res, 500, {ok:false,error:'server error'});
  }
});
exportInitialHistoricalLogsSnapshot();
server.listen(PORT, '0.0.0.0', () => {
  console.log(`relay listening on :${PORT}`);
  writeProjectLog('devices', 'INFO', 'RELAY_LISTENING', `السيرفر السحابي يعمل ويستمع على المنفذ :${PORT}`);
});

// Self-healing watchdog: keep local Admin HTTP Server (127.0.0.1:8787) alive 24/7
let adminMissStreak = 0;
let adminAlertedDown = false;
setInterval(() => {
  const probe = http.get(
    { hostname: '127.0.0.1', port: 8787, path: '/healthz', timeout: 2500 },
    (r) => {
      r.resume();
      if (r.statusCode === 200) {
        adminMissStreak = 0;
        if (adminAlertedDown) {
          adminAlertedDown = false;
          waBot.onServerHealthEvent({ kind: 'admin_recovered' }).catch(() => {});
        }
      } else {
        adminMissStreak++;
      }
    }
  );
  probe.on('error', () => {
    adminMissStreak++;
    if (adminMissStreak >= 2) {
      adminMissStreak = 0;
      if (!adminAlertedDown) {
        adminAlertedDown = true;
        waBot.onServerHealthEvent({ kind: 'admin_down' }).catch(() => {});
      }
      const adminCandidate = 'C:\\Users\\IT APP\\Desktop\\blockwebsite\\final-release\\admin\\it-elkhawga-admin.exe';
      if (fs.existsSync(adminCandidate)) {
        try {
          const child = spawn(adminCandidate, ['--server'], {
            cwd: path.dirname(adminCandidate),
            detached: true,
            stdio: 'ignore',
            windowsHide: true,
          });
          child.unref();
        } catch (_) {}
      }
    }
  });
  probe.on('timeout', () => {
    probe.destroy();
  });
}, 12000);
