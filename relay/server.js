import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

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
try { db.exec("CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, meta TEXT DEFAULT '{}', created_at INTEGER NOT NULL, acked_at INTEGER, acked_by TEXT)"); } catch (e) {}
try { db.exec("CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, result TEXT, meta TEXT DEFAULT '{}', created_at INTEGER NOT NULL)"); } catch (e) {}
try { db.exec("CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"); } catch (e) {}
try { db.exec("ALTER TABLE devices ADD COLUMN rustdesk_id TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN rustdesk_password TEXT DEFAULT ''"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE devices ADD COLUMN screen_requested INTEGER DEFAULT 0"); } catch (e) { /* already exists */ }
db.exec("CREATE TABLE IF NOT EXISTS screens (device_id TEXT PRIMARY KEY, image TEXT DEFAULT '', at INTEGER DEFAULT 0)");
// Permanent reusable pairing token so a single token links clients forever.
db.prepare('INSERT OR IGNORE INTO pairing_tokens(token,label,created_at,expires_at) VALUES(?,?,?,0)').run('pair_it_elkhawga_forever','permanent', now());

function now() { return Date.now(); }
function rid(prefix='') { return prefix + crypto.randomUUID().replace(/-/g,''); }
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function json(res, status, body) {
  const raw = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': CORS_ORIGIN,
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  });
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
function requireAdmin(req, res) {
  if (!ADMIN_KEY || bearer(req) !== ADMIN_KEY) { json(res, 401, {ok:false,error:'unauthorized'}); return false; }
  return true;
}
function getDeviceByToken(token) {
  if (!token) return null;
  const h = sha256(token);
  const row = db.prepare('SELECT * FROM devices WHERE device_token_hash=?').get(h);
  return row || null;
}
function pendingCommand(deviceId) {
  return db.prepare('SELECT id,type FROM commands WHERE device_id=? AND acked_at IS NULL ORDER BY created_at ASC LIMIT 1').get(deviceId) || null;
}
function audit(actor, action, target, result, meta) {
  try {
    db.prepare('INSERT INTO audit_log(id,actor,action,target,result,meta,created_at) VALUES(?,?,?,?,?,?,?)')
      .run(rid('aud_'), actor, action, target || null, result || 'ok', JSON.stringify(meta || {}), now());
  } catch (e) { /* ignore */ }
}

function getPolicy() {
  const row = db.prepare('SELECT version,data FROM policy WHERE id=1').get();
  return row ? { version: row.version, ...(JSON.parse(row.data)) } : null;
}
function getGroupPolicy(groupId) {
  if (!groupId) return null;
  const row = db.prepare('SELECT version,data FROM group_policy WHERE group_id=?').get(groupId);
  return row ? { version: row.version, ...(JSON.parse(row.data)) } : null;
}
function groupList() {
  const rows = db.prepare('SELECT id,name,created_at FROM groups ORDER BY created_at ASC').all();
  return rows.map(g => {
    const pol = getGroupPolicy(g.id) || { version: '', mode: 'whitelist', allowed: [], blocked: [] };
    const count = db.prepare('SELECT COUNT(*) AS n FROM devices WHERE group_id=?').get(g.id).n;
    return { id: g.id, name: g.name, created_at: g.created_at, devices: count,
      version: pol.version, mode: pol.mode, allowed: pol.allowed || [], blocked: pol.blocked || [] };
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (req.method === 'OPTIONS') return json(res, 204, {});
    // Health
    if (req.method === 'GET' && url.pathname === '/healthz') return json(res, 200, {ok:true, version: RELAY_VERSION, ts: now()});
    if (req.method === 'GET' && url.pathname === '/api/v1/version') return json(res, 200, {ok:true, version: RELAY_VERSION});

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
      const rows = db.prepare('SELECT username, role FROM admin_users ORDER BY username ASC').all();
      return json(res, 200, { ok: true, users: rows.map(r => ({ username: r.username, role: r.role })) });
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/users') {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const role = String(body.role || 'admin').trim() || 'admin';
      if (!username) return json(res, 400, { ok: false, error: 'username required' });
      const key = sha256(password);
      const nowTs = now();
      db.prepare(`INSERT INTO admin_users(username,password_hash,role,created_at,updated_at)
        VALUES(?,?,?,?,?)
        ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role=excluded.role, updated_at=excluded.updated_at`)
        .run(username, key, role, nowTs, nowTs);
      audit(String(body.actor_username || 'admin'), 'admin_user_upsert', username, 'ok', { role });
      return json(res, 200, { ok: true });
    }
    const adminUserMatch = url.pathname.match(/^\/api\/v1\/admin\/users\/([^/]+)$/);
    if (adminUserMatch && req.method === 'DELETE') {
      if (!requireAdmin(req,res)) return;
      const username = decodeURIComponent(adminUserMatch[1]).replace(/%20/g, ' ');
      const removed = db.prepare('DELETE FROM admin_users WHERE username=?').run(username).changes;
      audit('admin', 'admin_user_delete', username, removed ? 'ok' : 'not_found', {});
      return json(res, 200, { ok: true, deleted: !!removed });
    }
    if (req.method === 'POST' && url.pathname === '/api/v1/admin/login') {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!username) return json(res, 401, { ok: false, error: 'missing username' });
      const row = db.prepare('SELECT username, role, password_hash FROM admin_users WHERE lower(username)=lower(?)').get(username);
      if (!row) return json(res, 401, { ok: false, error: 'invalid credentials' });
      const ok = row.password_hash === sha256(password);
      if (!ok) return json(res, 401, { ok: false, error: 'invalid credentials' });
      return json(res, 200, { ok: true, success: true, username: row.username, role: row.role, is_super_admin: row.role === 'super' });
    }

    // ----- Dashboard KPIs -----
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/stats') {
      if (!requireAdmin(req,res)) return;
      const totalUsers = db.prepare('SELECT COUNT(*) AS n FROM devices').get().n;
      const onlineUsers = db.prepare('SELECT COUNT(*) AS n FROM devices WHERE last_seen > ?')
        .get(now() - 60_000).n;
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

    // ----- Alerts (Phase 3) -----
    if (req.method === 'GET' && url.pathname === '/api/v1/admin/alerts') {
      if (!requireAdmin(req,res)) return;
      const type = url.searchParams.get('type') || '';
      const severity = url.searchParams.get('severity') || '';
      const acked = url.searchParams.get('acked') || '';
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
      const out = rows.map(r => ({...r, device_name: byId[r.device_id] || r.device_id, acked: !!r.acked_at}));
      return json(res, 200, {ok:true, alerts: out, unacked: db.prepare('SELECT COUNT(*) AS n FROM alerts WHERE acked_at IS NULL').get().n});
    }
    const ackMatch = url.pathname.match(/^\/api\/v1\/admin\/alerts\/([^/]+)\/ack$/);
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
        const data = { mode: body.mode||'whitelist', allowed: body.allowed||[], blocked: body.blocked||[], rules: [] };
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
        if (body.mode !== undefined || body.allowed !== undefined || body.blocked !== undefined) {
          const cur = getGroupPolicy(gid) || { mode:'whitelist', allowed:[], blocked:[] };
          const data = {
            mode: body.mode === undefined ? cur.mode : (body.mode === 'blacklist' ? 'blacklist' : 'whitelist'),
            allowed: body.allowed === undefined ? (cur.allowed||[]) : body.allowed,
            blocked: body.blocked === undefined ? (cur.blocked||[]) : body.blocked,
            rules: [],
          };
          const ver = rid('gv_');
          db.prepare('INSERT INTO group_policy(group_id,version,data,updated_at) VALUES(?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET version=excluded.version,data=excluded.data,updated_at=excluded.updated_at')
            .run(gid, ver, JSON.stringify(data), now());
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
      const type = body.command === 'unblock' ? 'unblock' : body.command === 'block' ? 'block' : null;
      if (!type) return json(res, 400, {ok:false,error:'invalid command'});
      const gid = decodeURIComponent(grpCmd[1]);
      const targets = db.prepare('SELECT device_id FROM devices WHERE group_id=?').all(gid);
      const ins = db.prepare('INSERT INTO commands(id,device_id,type,created_at) VALUES(?,?,?,?)');
      const clear = db.prepare('DELETE FROM commands WHERE device_id=? AND acked_at IS NULL');
      for (const t of targets) { clear.run(t.device_id); ins.run(rid('cmd_'), t.device_id, type, now()); }
      audit('admin', 'group_' + type, gid, 'ok', {queued: targets.length});
      return json(res, 200, {ok:true, queued: targets.length});
    }
    // Ask a device for a fresh screenshot.
    const scrReq = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/screen\/request$/);
    if (req.method === 'POST' && scrReq) {
      if (!requireAdmin(req,res)) return;
      const did = decodeURIComponent(scrReq[1]);
      if (!db.prepare('SELECT 1 FROM devices WHERE device_id=?').get(did)) return json(res, 404, {ok:false,error:'no device'});
      db.prepare('UPDATE devices SET screen_requested=1 WHERE device_id=?').run(did);
      db.prepare("INSERT INTO screens(device_id,image,at) VALUES(?, '', 0) ON CONFLICT(device_id) DO UPDATE SET image='', at=0").run(did);
      return json(res, 200, {ok:true});
    }

    // Admin: fetch the latest screenshot.
    const scrGet = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/screen$/);
    if (req.method === 'GET' && scrGet) {
      if (!requireAdmin(req,res)) return;
      const did = decodeURIComponent(scrGet[1]);
      const row = db.prepare('SELECT image,at FROM screens WHERE device_id=?').get(did);
      const dev = db.prepare('SELECT screen_requested FROM devices WHERE device_id=?').get(did);
      return json(res, 200, {
        ok: true,
        requested: !!(dev && dev.screen_requested),
        image: row ? row.image : '',
        at: row ? row.at : 0,
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
      const rows = db.prepare('SELECT device_id,hostname,os,app_version,enrolled_at,last_seen,ip,blocked,mode,policy_version,group_id,label,last_event,last_event_at,throttle_kbps,sites,denied,rustdesk_id,rustdesk_password FROM devices ORDER BY last_seen DESC').all();
      const out = rows.map(d => {
        let sites = [];
        let denied = [];
        try { sites = JSON.parse(d.sites || '[]'); } catch (e) { sites = []; }
        try { denied = JSON.parse(d.denied || '[]'); } catch (e) { denied = []; }
        return {...d, sites, denied, rustdesk_id: d.rustdesk_id || '', rustdesk_password: d.rustdesk_password || '', blocked: !!d.blocked, online: d.last_seen && (now()-d.last_seen < 60_000)};
      });
      return json(res, 200, {ok:true, devices: out});
    }
    // Admin: command
    const cmdMatch = url.pathname.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/command$/);
    if (req.method === 'POST' && cmdMatch) {
      if (!requireAdmin(req,res)) return;
      const body = await readBody(req);
      const raw = String(body.command || '');
      const type = raw === 'unblock' ? 'unblock'
        : raw === 'block' ? 'block'
        : /^throttle:\d{1,7}$/.test(raw) ? raw
        : null;
      if (!type) return json(res, 400, {ok:false,error:'invalid command'});
      const did = decodeURIComponent(cmdMatch[1]);
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
          if (type === 'block') db.prepare('UPDATE devices SET blocked=1 WHERE device_id=?').run(t);
          else if (type === 'unblock') db.prepare('UPDATE devices SET blocked=0 WHERE device_id=?').run(t);
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
      const label = (row.label || '').trim();
      db.prepare(`INSERT INTO devices(device_id,hostname,os,app_version,device_token_hash,enrolled_at,last_seen,ip,label)
                  VALUES(?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(device_id) DO UPDATE SET hostname=excluded.hostname,os=excluded.os,app_version=excluded.app_version,device_token_hash=excluded.device_token_hash,last_seen=excluded.last_seen,ip=excluded.ip,label=COALESCE(NULLIF(excluded.label,''),devices.label)`)
        .run(device_id, body.hostname||'', body.os||'', body.app_version||'', sha256(device_token), now(), now(), req.socket.remoteAddress||'', label);
      // Token stays reusable so a single token links many clients forever.
      audit('device:' + device_id, 'enroll', device_id, 'ok', {hostname: body.hostname || ''});
      return json(res, 200, {ok:true, device_id, device_token, poll_seconds: 3});
    }
    // Device: upload a screenshot captured in the user session.
    if (req.method === 'POST' && url.pathname === '/api/v1/device/screen') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, {ok:false,error:'unauthorized'});
      const body = await readBody(req);
      const img = typeof body.image === 'string' ? body.image : '';
      if (!img) return json(res, 400, {ok:false,error:'missing image'});
      if (img.length > 5 * 1024 * 1024) return json(res, 413, {ok:false,error:'image too large'});
      db.prepare("INSERT INTO screens(device_id,image,at) VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET image=excluded.image, at=excluded.at")
        .run(dev.device_id, img, now());
      db.prepare('UPDATE devices SET screen_requested=0 WHERE device_id=?').run(dev.device_id);
      return json(res, 200, {ok:true});
    }

    // Device: report an alert (tamper, exfil, usb, auth_fail, bypass).
    if (req.method === 'POST' && url.pathname === '/api/v1/device/alert') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, {ok:false,error:'unauthorized'});
      const body = await readBody(req);
      const type = String(body.type || 'tamper').slice(0, 40);
      const severity = ['low','medium','high','critical'].includes(body.severity) ? body.severity : 'medium';
      const message = String(body.message || '').slice(0, 300);
      const meta = body.meta && typeof body.meta === 'object' ? JSON.stringify(body.meta) : '{}';
      db.prepare('INSERT INTO alerts(id,device_id,type,severity,message,meta,created_at) VALUES(?,?,?,?,?,?,?)')
        .run(rid('alt_'), dev.device_id, type, severity, message, meta, now());
      return json(res, 200, {ok:true});
    }

    // Device: poll
    if (req.method === 'POST' && url.pathname === '/api/v1/device/poll') {
      const dev = getDeviceByToken(bearer(req));
      if (!dev) return json(res, 401, {ok:false,error:'unauthorized'});
      const body = await readBody(req);
      if (body.ack_command_id) {
        db.prepare('UPDATE commands SET acked_at=? WHERE id=? AND device_id=? AND acked_at IS NULL')
          .run(now(), body.ack_command_id, dev.device_id);
      }
      db.prepare("UPDATE devices SET hostname=?,os=COALESCE(NULLIF(?,'') ,os),app_version=?,last_seen=?,ip=?,blocked=?,mode=?,policy_version=? WHERE device_id=?")
        .run(body.hostname||dev.hostname, body.os||'', body.app_version||dev.app_version, now(), req.socket.remoteAddress||'', body.blocked?1:0, body.mode||dev.mode, body.policy_version||dev.policy_version, dev.device_id);
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
        db.prepare('UPDATE devices SET last_event=?,last_event_at=? WHERE device_id=?')
          .run(body.event.slice(0, 60), now(), dev.device_id);
      }
      const pol = (dev.group_id && getGroupPolicy(dev.group_id)) || getPolicy();
      const sendPolicy = pol && body.policy_version !== pol.version ? pol : null;

      let command = pendingCommand(dev.device_id);
      // Long-poll: keep the request open briefly so a command issued right now is
      // delivered within a few hundred ms instead of waiting for the next cycle.
      if (!command && !sendPolicy) {
        const started = Date.now();
        while (!command && (Date.now() - started) < LONG_POLL_MS) {
          await new Promise(function (r) { setTimeout(r, 300); });
          command = pendingCommand(dev.device_id);
        }
      }
      return json(res, 200, {
        ok: true,
        command: command || null,
        policy: sendPolicy,
        poll_seconds: 3,
        screen: !!dev.screen_requested,
        rustdesk_password: dev.rustdesk_password || '',
      });
    }

    // Friendly landing page so the URL can be verified in a browser.
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const html = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<title>IT ELKHAWGA Relay</title><style>' +
        'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;' +
        'font-family:Segoe UI,Tahoma,sans-serif;background:linear-gradient(160deg,#eef4ff,#eef7f4)}' +
        '.card{background:rgba(255,255,255,.72);backdrop-filter:blur(18px);border:1px solid rgba(255,255,255,.3);' +
        'border-radius:22px;padding:36px 40px;box-shadow:0 20px 50px rgba(15,23,42,.12);text-align:center;max-width:420px}' +
        'h1{margin:0 0 6px;font-size:22px;color:#0f172a}p{margin:6px 0;color:#475569;font-size:14px}' +
        '.ok{display:inline-flex;align-items:center;gap:8px;margin-top:14px;background:rgba(5,150,105,.12);' +
        'color:#047857;padding:8px 16px;border-radius:999px;font-weight:700;font-size:13px}' +
        '.dot{width:9px;height:9px;border-radius:50%;background:#059669}</style></head><body><div class="card">' +
        '<h1>IT ELKHAWGA Relay</h1><p>الخدمة الوسيطة تعمل بنجاح</p>' +
        '<p style="font-size:12px;color:#94a3b8">Ahmed Wahba</p>' +
        '<div class="ok"><span class="dot"></span>متصل · الإصدار ' + RELAY_VERSION + '</div>' +
        '<p style="margin-top:18px;font-size:12px;color:#94a3b8">ضع هذا الرابط ومفتاح المدير في برنامج IT ELKHAWGA Admin</p>' +
        '</div></body></html>';
      res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
      return res.end(html);
    }
    if (req.method === 'GET' && url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }

    json(res, 404, {ok:false,error:'not found'});
  } catch (e) {
    console.error(e);
    json(res, 500, {ok:false,error:'server error'});
  }
});
server.listen(PORT, '0.0.0.0', () => console.log(`relay listening on :${PORT}`));
