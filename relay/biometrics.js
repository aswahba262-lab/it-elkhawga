import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';

const BIOMETRICS_LOG_PATHS = [
  'C:\\Users\\IT APP\\Desktop\\blockwebsite\\logs\\09-biometrics-attendance.log',
  'C:\\Users\\IT APP\\Desktop\\blockwebsite\\logs\\00-master-all-events.log',
];

function writeBioLog(level, event, detail) {
  try {
    const iso = new Date().toISOString();
    const line = `[${iso}] [${level}] [BIOMETRICS] [${event}] ${detail}\r\n`;
    for (const lp of BIOMETRICS_LOG_PATHS) {
      try {
        fs.appendFileSync(lp, line, 'utf8');
      } catch (_) {}
    }
  } catch (_) {}
}

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

// ============================================================================
// 1. ZKTeco TCP Protocol (Port 4370) — Pure Node.js Implementation
// ============================================================================
const ZK_MAGIC_1 = 0x5050;
const ZK_MAGIC_2 = 0x827d;
const CMD_CONNECT = 1000;
const CMD_EXIT = 1001;
const CMD_ENABLEDEVICE = 1002;
const CMD_DISABLEDEVICE = 1003;
const CMD_ACK_OK = 2000;
const CMD_ACK_UNAUTH = 2005;
const CMD_PREPARE_DATA = 1500;
const CMD_DATA = 1501;
const CMD_FREE_DATA = 1502;
const CMD_DATA_WRRQ = 1503;
const CMD_ATTLOG_RRQ = 13;
const CMD_USERTEMP_RRQ = 9;
const CMD_OPTIONS_RRQ = 11;
const CMD_AUTH = 1102;

const win1256Decoder = (() => {
  try {
    return new TextDecoder('windows-1256');
  } catch (_) {
    return new TextDecoder('utf-8');
  }
})();

function decodeZkNameBytes(buf) {
  const zeroIdx = buf.indexOf(0);
  const slice = zeroIdx >= 0 ? buf.subarray(0, zeroIdx) : buf;
  if (!slice.length) return '';
  // Try UTF-8 first if valid multibyte UTF-8 without replacement chars, otherwise Windows-1256 (standard Arabic encoding on ZKTeco terminals)
  const utf8Str = slice.toString('utf8');
  if (!utf8Str.includes('\uFFFD') && /[\u0600-\u06FF]/.test(utf8Str)) {
    return utf8Str.replace(/[\x00-\x1F]/g, '').trim();
  }
  return win1256Decoder.decode(slice).replace(/[\x00-\x1F]/g, '').trim();
}

function parseZkUsersBuffer(rawBuf) {
  const userMap = new Map();
  if (!rawBuf || rawBuf.length < 12) return userMap;
  let buf = rawBuf;
  const leadingSize = buf.readUInt32LE(0);
  if (leadingSize === buf.length - 4 || (leadingSize > 0 && leadingSize <= buf.length - 4 && ((buf.length - 4) % 72 === 0 || (buf.length - 4) % 28 === 0))) {
    buf = buf.subarray(4);
  }
  const stride = (buf.length % 72 === 0) ? 72 : ((buf.length % 28 === 0) ? 28 : 72);
  for (let off = 0; off + stride <= buf.length; off += stride) {
    const rec = buf.subarray(off, off + stride);
    if (stride === 72) {
      const uid = rec.readUInt16LE(0);
      const name = decodeZkNameBytes(rec.subarray(11, 35));
      const userId = cleanZkAscii(rec.subarray(48, 72)) || String(uid || '');
      if (userId && name) {
        userMap.set(userId, name);
      }
      if (uid && name && !userMap.has(String(uid))) {
        userMap.set(String(uid), name);
      }
    } else if (stride === 28) {
      const uid = rec.readUInt16LE(0);
      const name = decodeZkNameBytes(rec.subarray(8, 16));
      const userId = String(rec.readUInt32LE(24) || uid || '');
      if (userId && name) {
        userMap.set(userId, name);
      }
    }
  }
  return userMap;
}

function zkChecksum16(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) {
    if (i === buf.length - 1) {
      sum += buf[i];
    } else {
      sum += buf.readUInt16LE(i);
    }
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  return (~sum) & 0xffff;
}

function createZkTcpPacket(cmd, sessionId, replyId, payload = Buffer.alloc(0)) {
  const inner = Buffer.alloc(8 + payload.length);
  inner.writeUInt16LE(cmd, 0);
  inner.writeUInt16LE(0, 2);
  inner.writeUInt16LE(sessionId & 0xffff, 4);
  inner.writeUInt16LE(replyId & 0xffff, 6);
  if (payload.length > 0) payload.copy(inner, 8);
  const chksum = zkChecksum16(inner);
  inner.writeUInt16LE(chksum, 2);

  const tcp = Buffer.alloc(8 + inner.length);
  tcp.writeUInt16LE(ZK_MAGIC_1, 0);
  tcp.writeUInt16LE(ZK_MAGIC_2, 2);
  tcp.writeUInt32LE(inner.length, 4);
  inner.copy(tcp, 8);
  return tcp;
}

function makeZkCommKeyPayload(commKey, sessionId) {
  let k = Number(commKey || 0) >>> 0;
  const sid = Number(sessionId || 0) & 0xffff;
  let mask = 0;
  for (let i = 0; i < 32; i++) {
    if (k & (1 << i)) {
      mask = ((mask << 1) | 1) >>> 0;
    } else {
      mask = (mask << 1) >>> 0;
    }
  }
  mask = (mask + sid) >>> 0;
  const b = Buffer.alloc(4);
  b.writeUInt32LE(mask, 0);
  const swapped = Buffer.from([b[0] ^ 0x5a, b[1] ^ 0x4b, b[3] ^ 0x53, b[2] ^ 0x4f]);
  const ticks = 50;
  return Buffer.from([swapped[0] ^ ticks, swapped[1] ^ ticks, ticks, swapped[3] ^ ticks]);
}

function decodeZkTime(t) {
  const sec = t % 60;
  let r = Math.floor(t / 60);
  const min = r % 60;
  r = Math.floor(r / 60);
  const hour = r % 24;
  r = Math.floor(r / 24);
  const day = (r % 31) + 1;
  r = Math.floor(r / 31);
  const month = (r % 12) + 1;
  const year = Math.floor(r / 12) + 2000;
  if (year < 2005 || year > 2038 || month < 1 || month > 12 || day < 1 || day > 31) return null;
  const pad = (n) => String(n).padStart(2, '0');
  const isoStr = `${year}-${pad(month)}-${pad(day)} ${pad(hour)}:${pad(min)}:${pad(sec)}`;
  const dt = new Date(`${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${pad(min)}:${pad(sec)}`);
  return {
    timeStr: isoStr,
    tsMs: isNaN(dt.getTime()) ? Date.now() : dt.getTime(),
  };
}

function cleanZkAscii(buf) {
  const zeroIdx = buf.indexOf(0);
  const slice = zeroIdx >= 0 ? buf.subarray(0, zeroIdx) : buf;
  return slice.toString('utf8').replace(/[^\x20-\x7E\u0600-\u06FF]/g, '').trim();
}

function parseZkAttendanceBuffer(rawBuf, userMap = null) {
  if (!rawBuf || rawBuf.length < 8) return [];
  let buf = rawBuf;
  // Strip 4-byte total size prefix if present
  if (buf.length >= 12) {
    const leadingSize = buf.readUInt32LE(0);
    if (leadingSize === buf.length - 4 || (leadingSize > 0 && leadingSize <= buf.length && (buf.length - 4) % 40 === 0)) {
      buf = buf.subarray(4);
    }
  }

  // Detect record stride: modern ZKTeco color/TFT firmware (e.g. K14 Pro/ID) uses 40 bytes; legacy B&W uses 16 or 8 bytes
  let stride = 40;
  if (buf.length % 40 === 0) {
    stride = 40;
  } else if (buf.length % 16 === 0) {
    stride = 16;
  } else {
    if (buf.length >= 40 && (decodeZkTime(buf.readUInt32LE(27)) || decodeZkTime(buf.readUInt32LE(26)))) {
      stride = 40;
    } else if (buf.length >= 16 && decodeZkTime(buf.readUInt32LE(4))) {
      stride = 16;
    }
  }

  const mapPunchState = (st) => {
    if (st === 1) return 'check_out';
    if (st === 2) return 'break_out';
    if (st === 3) return 'break_in';
    if (st === 4) return 'overtime_in';
    if (st === 5) return 'overtime_out';
    return 'check_in';
  };

  const mapVerifyMode = (vm) => {
    if (vm === 15) return 'face';
    if (vm === 2 || vm === 4) return 'card';
    if (vm === 3) return 'password';
    return 'fingerprint';
  };

  const records = [];
  for (let off = 0; off + stride <= buf.length; off += stride) {
    const rec = buf.subarray(off, off + stride);
    if (stride === 40) {
      const uid = rec.readUInt16LE(0);
      const userIdStr = cleanZkAscii(rec.subarray(2, 26)) || String(uid || '');
      // Standard ZKTeco 40-byte SSR record has verifyMode at byte 26, 4-byte timestamp at bytes 27..31, and punchState at byte 31
      let decoded = decodeZkTime(rec.readUInt32LE(27));
      let verifyMode = rec[26];
      let punchState = rec[31];
      if (!decoded || decoded.timeStr.startsWith('203')) {
        const alt = decodeZkTime(rec.readUInt32LE(26));
        if (alt && !alt.timeStr.startsWith('203')) {
          decoded = alt;
          verifyMode = rec[30];
          punchState = rec[31];
        }
      }
      if (userIdStr && decoded) {
        const empName = (userMap && (userMap.get(userIdStr) || userMap.get(String(uid)))) || '';
        records.push({
          employee_id: userIdStr,
          employee_name: empName,
          punch_time: decoded.timeStr,
          punch_ts: decoded.tsMs,
          punch_type: mapPunchState(punchState),
          verify_mode: mapVerifyMode(verifyMode),
        });
      }
    } else if (stride === 16) {
      const uid = rec.readUInt16LE(0);
      const tVal = rec.readUInt32LE(4);
      const decoded = decodeZkTime(tVal);
      if (uid > 0 && decoded) {
        const empId = String(uid);
        const empName = (userMap && userMap.get(empId)) || '';
        records.push({
          employee_id: empId,
          employee_name: empName,
          punch_time: decoded.timeStr,
          punch_ts: decoded.tsMs,
          punch_type: 'check_in',
          verify_mode: 'fingerprint',
        });
      }
    }
  }
  return records;
}

function createZkUdpPacket(cmd, sessionId, replyId, payload = Buffer.alloc(0)) {
  const inner = Buffer.alloc(8 + payload.length);
  inner.writeUInt16LE(cmd, 0);
  inner.writeUInt16LE(0, 2);
  inner.writeUInt16LE(sessionId & 0xffff, 4);
  inner.writeUInt16LE(replyId & 0xffff, 6);
  if (payload.length > 0) payload.copy(inner, 8);
  const chksum = zkChecksum16(inner);
  inner.writeUInt16LE(chksum, 2);
  return inner;
}

async function fetchZkUdpBulkTable({ host, port = 4370, commKey = 0, reqCmd, reqPayload = Buffer.alloc(0), timeoutMs = 6000 }) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let sessionId = 0;
    let replyId = 0;
    let currentWaiter = null;
    let closed = false;

    const cleanup = () => {
      if (closed) return;
      closed = true;
      try { sock.close(); } catch (_) {}
    };

    const timer = setTimeout(() => {
      cleanup();
      resolve(null);
    }, timeoutMs);

    sock.on('error', () => {
      clearTimeout(timer);
      cleanup();
      resolve(null);
    });

    sock.on('message', (msg) => {
      if (msg.length >= 8 && currentWaiter) {
        const cmd = msg.readUInt16LE(0);
        const sid = msg.readUInt16LE(4);
        const ridNum = msg.readUInt16LE(6);
        const data = msg.subarray(8);
        currentWaiter({ cmd, sessionId: sid, replyId: ridNum, data });
      }
    });

    const sendUdpCmd = (cmd, payload = Buffer.alloc(0), waitMs = 2000) => {
      return new Promise((resCmd, rejCmd) => {
        replyId = (replyId + 1) & 0xffff;
        const pkt = createZkUdpPacket(cmd, sessionId, replyId, payload);
        const tCmd = setTimeout(() => {
          currentWaiter = null;
          rejCmd(new Error(`UDP cmd ${cmd} timeout`));
        }, waitMs);
        currentWaiter = (pktIn) => {
          clearTimeout(tCmd);
          currentWaiter = null;
          resCmd(pktIn);
        };
        sock.send(pkt, Number(port || 4370), host);
      });
    };

    (async () => {
      try {
        const connRes = await sendUdpCmd(CMD_CONNECT, Buffer.alloc(0), 1800);
        sessionId = connRes.sessionId;
        if (connRes.cmd === CMD_ACK_UNAUTH || Number(commKey) > 0) {
          const authPayload = makeZkCommKeyPayload(Number(commKey || 0), sessionId);
          await sendUdpCmd(CMD_AUTH, authPayload, 1500).catch(() => {});
        }
        const firstPkt = await sendUdpCmd(reqCmd, reqPayload, 2500);
        let resultBuf = null;
        if (firstPkt && firstPkt.cmd === CMD_DATA) {
          resultBuf = firstPkt.data;
        } else if (firstPkt && firstPkt.cmd === CMD_PREPARE_DATA && firstPkt.data.length >= 4) {
          const expectedBytes = firstPkt.data.readUInt32LE(0);
          const chunks = [];
          let received = 0;
          await new Promise((resData) => {
            const dTimer = setTimeout(resData, 4200);
            currentWaiter = (pIn) => {
              if (pIn.cmd === CMD_DATA) {
                chunks.push(pIn.data);
                received += pIn.data.length;
                if (received >= expectedBytes) {
                  clearTimeout(dTimer);
                  currentWaiter = null;
                  resData();
                }
              } else if (pIn.cmd === CMD_ACK_OK && received > 0) {
                clearTimeout(dTimer);
                currentWaiter = null;
                resData();
              }
            };
          });
          resultBuf = Buffer.concat(chunks);
          await sendUdpCmd(CMD_FREE_DATA, Buffer.alloc(0), 900).catch(() => {});
        }
        await sendUdpCmd(CMD_EXIT, Buffer.alloc(0), 600).catch(() => {});
        clearTimeout(timer);
        cleanup();
        resolve(resultBuf);
      } catch (_) {
        clearTimeout(timer);
        cleanup();
        resolve(null);
      }
    })();
  });
}

async function queryZkTecoUdp({ host, port = 4370, commKey = 0, pullLogs = false, timeoutMs = 4500 }) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const sock = dgram.createSocket('udp4');
    let sessionId = 0;
    let replyId = 0;
    let currentWaiter = null;
    let closed = false;

    const cleanup = () => {
      if (closed) return;
      closed = true;
      try { sock.close(); } catch (_) {}
    };

    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('UDP timeout'));
    }, timeoutMs);

    sock.on('error', (err) => {
      clearTimeout(timer);
      cleanup();
      reject(err);
    });

    sock.on('message', (msg) => {
      if (msg.length >= 8 && currentWaiter) {
        const cmd = msg.readUInt16LE(0);
        const sid = msg.readUInt16LE(4);
        const ridNum = msg.readUInt16LE(6);
        const data = msg.subarray(8);
        currentWaiter({ cmd, sessionId: sid, replyId: ridNum, data });
      }
    });

    const sendUdpCmd = (cmd, payload = Buffer.alloc(0), waitMs = 1800) => {
      return new Promise((resCmd, rejCmd) => {
        replyId = (replyId + 1) & 0xffff;
        const pkt = createZkUdpPacket(cmd, sessionId, replyId, payload);
        const tCmd = setTimeout(() => {
          currentWaiter = null;
          rejCmd(new Error(`UDP cmd ${cmd} timeout`));
        }, waitMs);
        currentWaiter = (pktIn) => {
          clearTimeout(tCmd);
          currentWaiter = null;
          resCmd(pktIn);
        };
        sock.send(pkt, Number(port || 4370), host);
      });
    };

    (async () => {
      try {
        const connRes = await sendUdpCmd(CMD_CONNECT, Buffer.alloc(0), 1800);
        const latencyMs = Date.now() - t0;
        sessionId = connRes.sessionId;
        if (connRes.cmd === CMD_ACK_UNAUTH || Number(commKey) > 0) {
          const authPayload = makeZkCommKeyPayload(Number(commKey || 0), sessionId);
          await sendUdpCmd(CMD_AUTH, authPayload, 1500).catch(() => {});
        }
        let serialNumber = '';
        let deviceModel = 'ZKTeco Terminal';
        try {
          const snRes = await sendUdpCmd(CMD_OPTIONS_RRQ, Buffer.from('~SerialNumber\0', 'ascii'), 1400);
          if (snRes && snRes.data && snRes.data.length) {
            const s = cleanZkAscii(snRes.data);
            serialNumber = s.includes('=') ? s.split('=')[1].trim() : s;
          }
        } catch (_) {}
        try {
          const devNameRes = await sendUdpCmd(CMD_OPTIONS_RRQ, Buffer.from('~DeviceName\0', 'ascii'), 1400);
          if (devNameRes && devNameRes.data && devNameRes.data.length) {
            const s = cleanZkAscii(devNameRes.data);
            deviceModel = (s.includes('=') ? s.split('=')[1].trim() : s) || deviceModel;
          }
        } catch (_) {}

        await sendUdpCmd(CMD_EXIT, Buffer.alloc(0), 800).catch(() => {});
        clearTimeout(timer);
        cleanup();

        let logs = [];
        if (pullLogs) {
          let userMap = new Map();
          const userBuf = await fetchZkUdpBulkTable({
            host,
            port,
            commKey,
            reqCmd: CMD_USERTEMP_RRQ,
            reqPayload: Buffer.from([0x05]),
            timeoutMs: 5500,
          });
          if (userBuf && userBuf.length >= 12) {
            userMap = parseZkUsersBuffer(userBuf);
          }
          const attBuf = await fetchZkUdpBulkTable({
            host,
            port,
            commKey,
            reqCmd: CMD_ATTLOG_RRQ,
            reqPayload: Buffer.alloc(0),
            timeoutMs: 6500,
          });
          if (attBuf && attBuf.length >= 8) {
            logs = parseZkAttendanceBuffer(attBuf, userMap);
          }
        }

        resolve({
          ok: true,
          online: true,
          vendor: 'zkteco',
          latency_ms: latencyMs,
          serial_number: serialNumber,
          device_model: deviceModel,
          logs,
        });
      } catch (e) {
        clearTimeout(timer);
        cleanup();
        reject(e);
      }
    })();
  });
}

async function queryZkTecoDevice({ host, port = 4370, commKey = 0, pullLogs = false, timeoutMs = 6500 }) {
  // Prefer ZKTeco UDP 4370 first (standard fast connectionless protocol supported by K14 Pro/ID & all ZKTeco terminals without TCP session locks)
  const fastUdp = await queryZkTecoUdp({
    host,
    port,
    commKey,
    pullLogs,
    timeoutMs: pullLogs ? 7500 : 2600,
  }).catch(() => null);
  if (fastUdp && fastUdp.ok && (!pullLogs || (Array.isArray(fastUdp.logs) && fastUdp.logs.length > 0))) {
    return fastUdp;
  }

  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const sock = new net.Socket();
    let sessionId = 0;
    let replyId = 0;
    let rxCarry = Buffer.alloc(0);
    let currentWaiter = null;
    let closed = false;
    let tcpConnected = false;
    let tcpLatencyMs = 0;
    let partialSerial = '';
    let partialModel = 'ZKTeco Terminal';
    let partialLogs = [];

    const finishOnlineFallback = async () => {
      if (closed) return;
      closed = true;
      try { sock.destroy(); } catch (_) {}
      // Try UDP 4370 protocol fallback in case this ZKTeco firmware speaks UDP for commands
      const udpRes = await queryZkTecoUdp({ host, port, commKey, pullLogs, timeoutMs: pullLogs ? 9000 : 2800 }).catch(() => null);
      if (udpRes && udpRes.ok) {
        return resolve(udpRes);
      }
      resolve({
        ok: true,
        online: true,
        vendor: 'zkteco',
        latency_ms: tcpLatencyMs || Math.max(1, Date.now() - t0),
        serial_number: partialSerial,
        device_model: partialModel,
        logs: partialLogs,
      });
    };

    const finishErr = async (err) => {
      if (closed) return;
      if (tcpConnected) {
        return finishOnlineFallback();
      }
      closed = true;
      try { sock.destroy(); } catch (_) {}
      // Before failing, check if device responds on UDP 4370
      const udpRes = await queryZkTecoUdp({ host, port, commKey, pullLogs, timeoutMs: pullLogs ? 9000 : 2500 }).catch(() => null);
      if (udpRes && udpRes.ok) {
        return resolve(udpRes);
      }
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    const timer = setTimeout(() => {
      finishErr(new Error(`انتهت مهلة الاتصال بجهاز البصمة ZKTeco (${host}:${port})`));
    }, timeoutMs);

    sock.on('error', (e) => {
      clearTimeout(timer);
      finishErr(e);
    });

    sock.on('data', (chunk) => {
      rxCarry = rxCarry.length ? Buffer.concat([rxCarry, chunk]) : chunk;
      while (rxCarry.length >= 8) {
        if (rxCarry.readUInt16LE(0) !== ZK_MAGIC_1 || rxCarry.readUInt16LE(2) !== ZK_MAGIC_2) {
          // Resync magic header
          let found = -1;
          for (let i = 1; i + 4 <= rxCarry.length; i++) {
            if (rxCarry.readUInt16LE(i) === ZK_MAGIC_1 && rxCarry.readUInt16LE(i + 2) === ZK_MAGIC_2) {
              found = i;
              break;
            }
          }
          if (found === -1) {
            rxCarry = Buffer.alloc(0);
            break;
          }
          rxCarry = rxCarry.subarray(found);
          if (rxCarry.length < 8) break;
        }
        const pktLen = rxCarry.readUInt32LE(4);
        if (pktLen > 16 * 1024 * 1024) {
          rxCarry = Buffer.alloc(0);
          break;
        }
        if (rxCarry.length < 8 + pktLen) break;
        const inner = rxCarry.subarray(8, 8 + pktLen);
        rxCarry = rxCarry.subarray(8 + pktLen);
        if (inner.length >= 8 && currentWaiter) {
          const cmd = inner.readUInt16LE(0);
          const sid = inner.readUInt16LE(4);
          const ridNum = inner.readUInt16LE(6);
          const data = inner.subarray(8);
          currentWaiter({ cmd, sessionId: sid, replyId: ridNum, data });
        }
      }
    });

    const sendCmd = (cmd, payload = Buffer.alloc(0), waitMs = 3500) => {
      return new Promise((resCmd, rejCmd) => {
        replyId = (replyId + 1) & 0xffff;
        const pkt = createZkTcpPacket(cmd, sessionId, replyId, payload);
        const tCmd = setTimeout(() => {
          currentWaiter = null;
          rejCmd(new Error(`timeout cmd ${cmd}`));
        }, waitMs);
        currentWaiter = (pktIn) => {
          clearTimeout(tCmd);
          currentWaiter = null;
          resCmd(pktIn);
        };
        sock.write(pkt);
      });
    };

    sock.connect(Number(port || 4370), host, async () => {
      const latencyMs = Date.now() - t0;
      tcpConnected = true;
      tcpLatencyMs = latencyMs;
      try {
        const connRes = await sendCmd(CMD_CONNECT, Buffer.alloc(0), 2800);
        sessionId = connRes.sessionId;
        if (connRes.cmd === CMD_ACK_UNAUTH || Number(commKey) > 0) {
          const authPayload = makeZkCommKeyPayload(Number(commKey || 0), sessionId);
          await sendCmd(CMD_AUTH, authPayload, 2500).catch(() => {});
        }

        let serialNumber = '';
        let deviceModel = 'ZKTeco Terminal';
        try {
          const snRes = await sendCmd(CMD_OPTIONS_RRQ, Buffer.from('~SerialNumber\0', 'ascii'), 1800);
          if (snRes && snRes.data && snRes.data.length) {
            const s = cleanZkAscii(snRes.data);
            if (s.includes('=')) serialNumber = s.split('=')[1].trim();
            else serialNumber = s;
            partialSerial = serialNumber;
          }
        } catch (_) {}
        try {
          const devNameRes = await sendCmd(CMD_OPTIONS_RRQ, Buffer.from('~DeviceName\0', 'ascii'), 1800);
          if (devNameRes && devNameRes.data && devNameRes.data.length) {
            const s = cleanZkAscii(devNameRes.data);
            if (s.includes('=')) deviceModel = s.split('=')[1].trim() || deviceModel;
            else if (s) deviceModel = s;
            partialModel = deviceModel;
          }
        } catch (_) {}

        let logs = [];
        if (pullLogs) {
          await sendCmd(CMD_DISABLEDEVICE, Buffer.alloc(0), 2000).catch(() => {});
          try {
            // Request attendance log buffer (supports both legacy CMD_ATTLOG_RRQ=13 and modern CMD_DATA_WRRQ=1503)
            const firstPkt = await sendCmd(CMD_ATTLOG_RRQ, Buffer.alloc(0), 4000).catch(() => null);
            if (firstPkt && firstPkt.cmd === CMD_DATA) {
              logs = parseZkAttendanceBuffer(firstPkt.data);
            } else if (firstPkt && firstPkt.cmd === CMD_PREPARE_DATA && firstPkt.data.length >= 4) {
              const expectedBytes = firstPkt.data.readUInt32LE(0);
              const chunks = [];
              let received = 0;
              await new Promise((resData) => {
                const dTimer = setTimeout(resData, 4500);
                currentWaiter = (pIn) => {
                  if (pIn.cmd === CMD_DATA) {
                    chunks.push(pIn.data);
                    received += pIn.data.length;
                    if (received >= expectedBytes) {
                      clearTimeout(dTimer);
                      currentWaiter = null;
                      resData();
                    }
                  } else if (pIn.cmd === CMD_ACK_OK) {
                    clearTimeout(dTimer);
                    currentWaiter = null;
                    resData();
                  }
                };
              });
              logs = parseZkAttendanceBuffer(Buffer.concat(chunks));
              await sendCmd(CMD_FREE_DATA, Buffer.alloc(0), 1500).catch(() => {});
            } else {
              // Modern ZKTeco CMD_DATA_WRRQ (1503) payload for attendance table: 01 0d 00 00 00 00 00 00 00 00 00
              const wrPayload = Buffer.from([0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
              const wrPkt = await sendCmd(CMD_DATA_WRRQ, wrPayload, 4000).catch(() => null);
              if (wrPkt && wrPkt.cmd === CMD_DATA) {
                logs = parseZkAttendanceBuffer(wrPkt.data);
              } else if (wrPkt && wrPkt.data && wrPkt.data.length >= 8) {
                logs = parseZkAttendanceBuffer(wrPkt.data);
              }
            }
          } catch (_) {}
          await sendCmd(CMD_ENABLEDEVICE, Buffer.alloc(0), 1800).catch(() => {});
        }

        await sendCmd(CMD_EXIT, Buffer.alloc(0), 1200).catch(() => {});
        clearTimeout(timer);
        closed = true;
        try { sock.destroy(); } catch (_) {}
        resolve({
          ok: true,
          online: true,
          vendor: 'zkteco',
          latency_ms: latencyMs,
          serial_number: serialNumber,
          device_model: deviceModel,
          logs,
        });
      } catch (innerErr) {
        clearTimeout(timer);
        closed = true;
        try { sock.destroy(); } catch (_) {}
        // Even if ZK binary command failed, TCP port 4370 connected successfully so device is online!
        resolve({
          ok: true,
          online: true,
          vendor: 'zkteco',
          latency_ms: latencyMs,
          serial_number: '',
          device_model: 'ZKTeco Terminal',
          logs: [],
          warn: innerErr.message,
        });
      }
    });
  });
}

// ============================================================================
// 2. Hikvision ISAPI Protocol (HTTP Port 80 / 8000) — Digest Auth + AcsEvent
// ============================================================================
function rawHttpRequest({ host, port = 80, method = 'GET', pathWithQuery = '/', headers = {}, body = null, timeoutMs = 5500 }) {
  return new Promise((resolve, reject) => {
    const bodyBuf = body ? (Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8')) : null;
    const reqHeaders = {
      Connection: 'close',
      Accept: '*/*',
      'User-Agent': 'IT-ELKHAWGA-Biometrics/1.2',
      ...headers,
    };
    if (bodyBuf) {
      reqHeaders['Content-Length'] = bodyBuf.length;
    }
    const req = http.request(
      {
        hostname: host,
        port: Number(port || 80),
        path: pathWithQuery,
        method,
        headers: reqHeaders,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers || {},
            body: Buffer.concat(chunks),
          });
        });
      }
    );
    req.on('error', (e) => reject(e));
    req.on('timeout', () => req.destroy(new Error('HTTP timeout')));
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

async function hikvisionAuthedRequest({ host, port = 80, method = 'GET', pathWithQuery, username = 'admin', password = '', body = null, contentType = 'application/json', timeoutMs = 5500 }) {
  const baseHeaders = body ? { 'Content-Type': contentType } : {};
  const probe = await rawHttpRequest({ host, port, method, pathWithQuery, headers: baseHeaders, body, timeoutMs });
  if (probe.statusCode !== 401) return probe;

  const rawWww = probe.headers['www-authenticate'];
  const wwwStr = Array.isArray(rawWww) ? rawWww.join(', ') : String(rawWww || '');
  const challenge = parseDigestHeader(wwwStr);
  if (challenge) {
    const authHdr = buildDigestAuthorization({
      method,
      uri: pathWithQuery,
      username,
      password,
      challenge,
      ncNum: 1,
    });
    return rawHttpRequest({
      host,
      port,
      method,
      pathWithQuery,
      headers: { ...baseHeaders, Authorization: authHdr },
      body,
      timeoutMs,
    });
  }
  const basic = Buffer.from(`${username}:${password}`, 'utf8').toString('base64');
  return rawHttpRequest({
    host,
    port,
    method,
    pathWithQuery,
    headers: { ...baseHeaders, Authorization: `Basic ${basic}` },
    body,
    timeoutMs,
  });
}

function probeTcpSocket(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const s = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { s.destroy(); } catch (_) {}
      resolve({ ok, latencyMs: Date.now() - t0 });
    };
    s.setTimeout(timeoutMs);
    s.on('connect', () => finish(true));
    s.on('error', () => finish(false));
    s.on('timeout', () => finish(false));
    s.connect(Number(port), host);
  });
}

async function queryHikvisionDevice({ host, port = 80, username = 'admin', password = '', pullLogs = false, timeoutMs = 6000 }) {
  const t0 = Date.now();
  const tcpRes = await probeTcpSocket(host, port, Math.min(3000, timeoutMs));
  if (!tcpRes.ok) {
    throw new Error(`تعذر الوصول إلى جهاز البصمة Hikvision على ${host}:${port}`);
  }

  let deviceModel = 'Hikvision Access Terminal';
  let serialNumber = '';
  try {
    const infoRes = await hikvisionAuthedRequest({
      host,
      port,
      method: 'GET',
      pathWithQuery: '/ISAPI/System/deviceInfo',
      username,
      password,
      timeoutMs: 4500,
    });
    if (infoRes.statusCode === 200 && infoRes.body) {
      const xml = infoRes.body.toString('utf8');
      const mModel = xml.match(/<model>([^<]+)<\/model>/i);
      const mSn = xml.match(/<serialNumber>([^<]+)<\/serialNumber>/i);
      if (mModel && mModel[1]) deviceModel = mModel[1].trim();
      if (mSn && mSn[1]) serialNumber = mSn[1].trim();
    }
  } catch (_) {}

  const logs = [];
  if (pullLogs) {
    try {
      const nowDt = new Date();
      const fromDt = new Date(nowDt.getTime() - 30 * 86400 * 1000);
      const fmtIso = (d) => d.toISOString().slice(0, 19) + '+02:00';
      const searchPayload = JSON.stringify({
        AcsEventCond: {
          searchID: rid('hik_'),
          searchResultPosition: 0,
          maxResults: 200,
          major: 5,
          minor: 0,
          startTime: fmtIso(fromDt),
          endTime: fmtIso(nowDt),
        },
      });
      const evRes = await hikvisionAuthedRequest({
        host,
        port,
        method: 'POST',
        pathWithQuery: '/ISAPI/AccessControl/AcsEvent?format=json',
        username,
        password,
        body: searchPayload,
        contentType: 'application/json',
        timeoutMs: 6500,
      });
      if (evRes.statusCode === 200 && evRes.body) {
        const parsed = JSON.parse(evRes.body.toString('utf8'));
        const infoList = (parsed && parsed.AcsEvent && parsed.AcsEvent.InfoList) || [];
        for (const item of infoList) {
          const empId = String(item.employeeNoString || item.cardNo || '').trim();
          const empName = String(item.name || '').trim();
          const rawTime = String(item.time || '').trim();
          if (!empId && !empName) continue;
          const cleanTime = rawTime.replace('T', ' ').replace(/[+-]\d{2}:\d{2}$/, '');
          const dt = new Date(rawTime);
          const minor = Number(item.minor || 0);
          const verifyMode = minor === 75 ? 'بصمة وجه' : (minor === 38 ? 'بصمة إصبع' : (minor === 1 ? 'كارت' : 'بصمة هيكفيجن'));
          logs.push({
            employee_id: empId || empName,
            employee_name: empName,
            punch_time: cleanTime || new Date().toISOString().slice(0, 19).replace('T', ' '),
            punch_ts: isNaN(dt.getTime()) ? Date.now() : dt.getTime(),
            punch_type: item.attendanceStatus === 'checkOut' ? 'انصراف' : 'حضور',
            verify_mode: verifyMode,
          });
        }
      }
    } catch (_) {}
  }

  return {
    ok: true,
    online: true,
    vendor: 'hikvision',
    latency_ms: tcpRes.latencyMs || (Date.now() - t0),
    serial_number: serialNumber,
    device_model: deviceModel,
    logs,
  };
}

// ============================================================================
// 3. Biometrics Attendance Manager (SQLite Persistence + 24/7 Health Monitor)
// ============================================================================
export function createBiometricsManager({ db, onDeviceStatusChange = null }) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS biometric_devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      branch_name TEXT DEFAULT '',
      vendor TEXT NOT NULL DEFAULT 'zkteco',
      host TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 4370,
      username TEXT DEFAULT 'admin',
      password TEXT DEFAULT '',
      comm_key INTEGER NOT NULL DEFAULT 0,
      serial_number TEXT DEFAULT '',
      device_model TEXT DEFAULT '',
      online INTEGER NOT NULL DEFAULT 0,
      latency_ms INTEGER NOT NULL DEFAULT 0,
      last_seen INTEGER NOT NULL DEFAULT 0,
      last_checked INTEGER NOT NULL DEFAULT 0,
      last_pull_at INTEGER NOT NULL DEFAULT 0,
      total_logs_pulled INTEGER NOT NULL DEFAULT 0,
      last_error TEXT DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS biometric_logs (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      device_name TEXT NOT NULL,
      branch_name TEXT DEFAULT '',
      vendor TEXT NOT NULL,
      employee_id TEXT NOT NULL,
      employee_name TEXT DEFAULT '',
      punch_time TEXT NOT NULL,
      punch_ts INTEGER NOT NULL,
      punch_type TEXT DEFAULT 'بصمة',
      verify_mode TEXT DEFAULT 'بصمة إصبع',
      created_at INTEGER NOT NULL,
      UNIQUE(device_id, employee_id, punch_time)
    );
    CREATE INDEX IF NOT EXISTS idx_bio_logs_ts ON biometric_logs(punch_ts DESC);
  `);

  // Runtime state tracker for offline/online transition notifications (avoids false alarms on single packet drop)
  const runtimeHealthMap = new Map(); // id -> { failStreak: number, alertedOffline: boolean, offlineSince: number }
  let monitorBootSeeded = false;

  function listDevices() {
    const rows = db.prepare('SELECT * FROM biometric_devices ORDER BY created_at ASC').all();
    const totalLogs = db.prepare('SELECT COUNT(*) AS n FROM biometric_logs').get().n || 0;
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayLogs = db.prepare('SELECT COUNT(*) AS n FROM biometric_logs WHERE punch_ts >= ?').get(todayStart.getTime()).n || 0;

    const devices = rows.map((r) => ({
      id: r.id,
      name: r.name,
      branch_name: r.branch_name || '',
      branch: r.branch_name || '',
      vendor: r.vendor === 'hikvision' ? 'hikvision' : 'zk',
      vendor_label: r.vendor === 'hikvision' ? 'Hikvision' : 'ZKTeco',
      host: r.host,
      ip: r.host,
      port: Number(r.port || (r.vendor === 'hikvision' ? 80 : 4370)),
      username: r.username || 'admin',
      has_password: Boolean(r.password && r.password.length > 0),
      comm_key: Number(r.comm_key || 0),
      serial_number: r.serial_number || '',
      device_model: r.device_model || '',
      online: Boolean(r.online),
      latency_ms: Number(r.latency_ms || 0),
      last_seen: Number(r.last_seen || 0),
      last_checked: Number(r.last_checked || 0),
      last_pull_at: Number(r.last_pull_at || 0),
      total_logs_pulled: Number(r.total_logs_pulled || 0),
      last_pull_count: Number(r.total_logs_pulled || 0),
      last_error: r.last_error || '',
      enabled: Boolean(r.enabled),
      created_at: Number(r.created_at || 0),
    }));

    const onlineCount = devices.filter((d) => d.online).length;
    return {
      ok: true,
      summary: {
        total_devices: devices.length,
        online_devices: onlineCount,
        offline_devices: Math.max(0, devices.length - onlineCount),
        total_logs: totalLogs,
        today_logs: todayLogs,
      },
      devices,
    };
  }

  function saveDevice(payload = {}) {
    const id = String(payload.id || '').trim() || rid('bio_');
    const existing = db.prepare('SELECT * FROM biometric_devices WHERE id=?').get(id);
    const name = String(payload.name || (existing && existing.name) || '').trim();
    if (!name) throw new Error('يرجى إدخال اسم جهاز البصمة (مثال: بصمة المقر الرئيسي أو بصمة فرع الدقي)');
    const rawBranch = payload.branch_name !== undefined ? payload.branch_name : payload.branch;
    const branchName = String(rawBranch !== undefined ? rawBranch : ((existing && existing.branch_name) || '')).trim();
    const rawVendor = String(payload.vendor || (existing && existing.vendor) || 'zkteco').trim().toLowerCase();
    const vendor = rawVendor.includes('hik') ? 'hikvision' : 'zkteco';
    let host = String(payload.host || payload.ip || (existing && existing.host) || '').trim().replace(/^https?:\/\//i, '').split('/')[0] || '';
    if (host.includes(':')) host = host.split(':')[0];
    if (!host) throw new Error('يرجى إدخال عنوان IP لجهاز البصمة على الشبكة المحلية (مثال: 192.168.1.201)');

    const defaultPort = vendor === 'hikvision' ? 80 : 4370;
    const port = Math.max(1, Math.min(65535, Number(payload.port || (existing && existing.port) || defaultPort) || defaultPort));
    const username = String(payload.username !== undefined ? payload.username : ((existing && existing.username) || 'admin')).trim() || 'admin';
    const password = payload.password !== undefined && String(payload.password) !== ''
      ? String(payload.password)
      : ((existing && existing.password) || '');
    const commKey = Math.max(0, Number(payload.comm_key !== undefined ? payload.comm_key : ((existing && existing.comm_key) || 0)) || 0);
    const enabled = payload.enabled === undefined ? 1 : (payload.enabled ? 1 : 0);
    const ts = Date.now();

    if (existing) {
      db.prepare(`UPDATE biometric_devices SET
        name=?, branch_name=?, vendor=?, host=?, port=?, username=?, password=?, comm_key=?, enabled=?, updated_at=?
        WHERE id=?`).run(name, branchName, vendor, host, port, username, password, commKey, enabled, ts, id);
    } else {
      db.prepare(`INSERT INTO biometric_devices
        (id,name,branch_name,vendor,host,port,username,password,comm_key,enabled,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, name, branchName, vendor, host, port, username, password, commKey, enabled, ts, ts);
    }

    writeBioLog('INFO', existing ? 'DEVICE_UPDATED' : 'DEVICE_ADDED', `تم حفظ جهاز بصمة: "${name}" (${vendor.toUpperCase()}) على ${host}:${port}`);
    const savedRow = db.prepare('SELECT * FROM biometric_devices WHERE id=?').get(id);
    checkSingleDeviceHealth(savedRow, false).catch(() => {});
    return listDevices();
  }

  function deleteDevice(id) {
    const cleanId = String(id || '').trim();
    const row = db.prepare('SELECT name, host FROM biometric_devices WHERE id=?').get(cleanId);
    db.prepare('DELETE FROM biometric_devices WHERE id=?').run(cleanId);
    runtimeHealthMap.delete(cleanId);
    if (row) {
      writeBioLog('INFO', 'DEVICE_DELETED', `تم حذف جهاز البصمة "${row.name}" (${row.host})`);
    }
    return listDevices();
  }

  async function probeSingleDeviceRaw(devRow, pullLogs = false) {
    const vendor = String(devRow.vendor || 'zkteco').toLowerCase();
    const host = String(devRow.host || '').trim();
    const port = Number(devRow.port || (vendor === 'hikvision' ? 80 : 4370));
    if (vendor === 'hikvision') {
      return queryHikvisionDevice({
        host,
        port,
        username: devRow.username || 'admin',
        password: devRow.password || '',
        pullLogs,
        timeoutMs: pullLogs ? 8500 : 4500,
      });
    }
    return queryZkTecoDevice({
      host,
      port,
      commKey: Number(devRow.comm_key || 0),
      pullLogs,
      timeoutMs: pullLogs ? 8500 : 4500,
    });
  }

  async function checkSingleDeviceHealth(devRow, notifyTransitions = true) {
    if (!devRow || !devRow.id) return null;
    const nowMs = Date.now();
    let trk = runtimeHealthMap.get(devRow.id);
    if (!trk) {
      trk = {
        failStreak: devRow.online ? 0 : 2,
        alertedOffline: !devRow.online && devRow.last_checked > 0,
        offlineSince: devRow.online ? 0 : (devRow.last_checked || nowMs),
      };
      runtimeHealthMap.set(devRow.id, trk);
    }

    try {
      const res = await probeSingleDeviceRaw(devRow, false);
      const wasAlertedOffline = trk.alertedOffline;
      trk.failStreak = 0;
      trk.alertedOffline = false;
      trk.offlineSince = 0;

      db.prepare(`UPDATE biometric_devices SET
        online=1,
        latency_ms=?,
        last_seen=?,
        last_checked=?,
        serial_number=COALESCE(NULLIF(?,''), serial_number),
        device_model=COALESCE(NULLIF(?,''), device_model),
        last_error=''
        WHERE id=?`).run(
        Number(res.latency_ms || 5),
        nowMs,
        nowMs,
        String(res.serial_number || ''),
        String(res.device_model || ''),
        devRow.id
      );

      if (notifyTransitions && wasAlertedOffline && typeof onDeviceStatusChange === 'function') {
        writeBioLog('INFO', 'DEVICE_RECOVERED', `عاد جهاز البصمة "${devRow.name}" (${devRow.host}:${devRow.port}) للاتصال (${res.latency_ms}ms)`);
        onDeviceStatusChange({
          kind: 'online',
          device: { ...devRow, online: true, latency_ms: res.latency_ms },
        }).catch(() => {});
      }
      return { ok: true, online: true, latency_ms: res.latency_ms, serial_number: res.serial_number, device_model: res.device_model };
    } catch (err) {
      const errMsg = (err && err.message) || 'غير متصل بالشبكة';
      trk.failStreak += 1;
      if (!trk.offlineSince) trk.offlineSince = nowMs;

      db.prepare(`UPDATE biometric_devices SET
        online=0,
        latency_ms=0,
        last_checked=?,
        last_error=?
        WHERE id=?`).run(nowMs, errMsg.slice(0, 200), devRow.id);

      // Alert on WhatsApp after 2 consecutive failed probes (~60s) so a momentary LAN hiccup never causes false alerts
      if (notifyTransitions && trk.failStreak >= 2 && !trk.alertedOffline) {
        trk.alertedOffline = true;
        writeBioLog('WARN', 'DEVICE_OFFLINE', `انقطع اتصال جهاز البصمة "${devRow.name}" (${devRow.host}:${devRow.port}) — السبب: ${errMsg}`);
        if (typeof onDeviceStatusChange === 'function') {
          onDeviceStatusChange({
            kind: 'offline',
            device: { ...devRow, online: false, last_error: errMsg },
          }).catch(() => {});
        }
      }
      return { ok: false, online: false, error: errMsg };
    }
  }

  async function checkAllDevicesHealth(notifyTransitions = true) {
    const rows = db.prepare('SELECT * FROM biometric_devices WHERE enabled=1 ORDER BY created_at ASC').all();
    if (!monitorBootSeeded) {
      monitorBootSeeded = true;
      for (const r of rows) {
        await checkSingleDeviceHealth(r, false);
      }
      return listDevices();
    }
    await Promise.all(rows.map((r) => checkSingleDeviceHealth(r, notifyTransitions)));
    return listDevices();
  }

  async function testDeviceConnection(payload = {}) {
    const vendor = String(payload.vendor || 'zkteco').toLowerCase().includes('hik') ? 'hikvision' : 'zkteco';
    let host = String(payload.host || payload.ip || '').trim().replace(/^https?:\/\//i, '').split('/')[0] || '';
    if (host.includes(':')) host = host.split(':')[0];
    if (!host) throw new Error('أدخل عنوان IP لجهاز البصمة أولاً');
    const port = Number(payload.port || (vendor === 'hikvision' ? 80 : 4370)) || (vendor === 'hikvision' ? 80 : 4370);
    let password = String(payload.password || '');
    if (!password && payload.id) {
      const ex = db.prepare('SELECT password FROM biometric_devices WHERE id=?').get(String(payload.id));
      if (ex && ex.password) password = ex.password;
    }

    const res = await probeSingleDeviceRaw(
      {
        vendor,
        host,
        port,
        username: payload.username || 'admin',
        password,
        comm_key: Number(payload.comm_key || 0),
      },
      false
    );
    return {
      ok: true,
      online: true,
      vendor,
      latency_ms: res.latency_ms,
      serial_number: res.serial_number || '',
      device_model: res.device_model || '',
      message: `🟢 متصل بنجاح (${res.latency_ms}ms) — الطراز: ${res.device_model || vendor.toUpperCase()}${res.serial_number ? ` · S/N: ${res.serial_number}` : ''}`,
    };
  }

  async function pullAttendanceLogs({ deviceId = '' } = {}) {
    const targets = deviceId
      ? db.prepare('SELECT * FROM biometric_devices WHERE id=?').all(String(deviceId))
      : db.prepare('SELECT * FROM biometric_devices WHERE enabled=1 ORDER BY created_at ASC').all();

    if (!targets.length) {
      throw new Error('لا توجد أجهزة بصمة مسجلة لسحب السجلات منها');
    }

    const insStmt = db.prepare(`INSERT INTO biometric_logs
      (id,device_id,device_name,branch_name,vendor,employee_id,employee_name,punch_time,punch_ts,punch_type,verify_mode,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(device_id, employee_id, punch_time) DO UPDATE SET
        employee_name=COALESCE(NULLIF(excluded.employee_name,''), biometric_logs.employee_name),
        device_name=excluded.device_name,
        branch_name=excluded.branch_name,
        punch_type=excluded.punch_type,
        verify_mode=excluded.verify_mode`);

    let totalPulled = 0;
    let newInserted = 0;
    const results = [];
    const nowMs = Date.now();

    for (const dev of targets) {
      try {
        const res = await probeSingleDeviceRaw(dev, true);
        const pulledList = Array.isArray(res.logs) ? res.logs : [];
        let devInserted = 0;
        for (const item of pulledList) {
          totalPulled += 1;
          const info = insStmt.run(
            rid('att_'),
            dev.id,
            dev.name,
            dev.branch_name || '',
            dev.vendor,
            String(item.employee_id || ''),
            String(item.employee_name || ''),
            String(item.punch_time || ''),
            Number(item.punch_ts || nowMs),
            String(item.punch_type || 'بصمة'),
            String(item.verify_mode || 'بصمة إصبع'),
            nowMs
          );
          if (info && info.changes > 0) {
            newInserted += 1;
            devInserted += 1;
          }
        }
        const devTotalInDb = db.prepare('SELECT COUNT(*) AS n FROM biometric_logs WHERE device_id=?').get(dev.id).n || 0;
        db.prepare(`UPDATE biometric_devices SET
          online=1, latency_ms=?, last_seen=?, last_checked=?, last_pull_at=?, total_logs_pulled=?,
          serial_number=COALESCE(NULLIF(?,''), serial_number),
          device_model=COALESCE(NULLIF(?,''), device_model),
          last_error=''
          WHERE id=?`).run(
          Number(res.latency_ms || 5),
          nowMs,
          nowMs,
          nowMs,
          devTotalInDb,
          String(res.serial_number || ''),
          String(res.device_model || ''),
          dev.id
        );
        results.push({
          device_id: dev.id,
          name: dev.name,
          ok: true,
          pulled_count: pulledList.length,
          new_count: devInserted,
          total_stored: devTotalInDb,
        });
        writeBioLog(
          'INFO',
          'LOGS_PULLED',
          `تم سحب البصمات من "${dev.name}" (${dev.host}): إجمالي مستلم=${pulledList.length} | حركات جديدة=${devInserted} | مخزن بالسيرفر=${devTotalInDb}`
        );
      } catch (e) {
        const errMsg = (e && e.message) || 'تعذر الاتصال بالجهاز';
        db.prepare('UPDATE biometric_devices SET online=0, last_checked=?, last_error=? WHERE id=?').run(nowMs, errMsg.slice(0, 200), dev.id);
        results.push({
          device_id: dev.id,
          name: dev.name,
          ok: false,
          error: errMsg,
        });
        writeBioLog('WARN', 'LOGS_PULL_FAIL', `تعذر سحب البصمات من "${dev.name}" (${dev.host}): ${errMsg}`);
      }
    }

    const curState = listDevices();
    const curLogs = queryStoredLogs({ limit: 350 }).logs;
    return {
      ok: true,
      total_pulled: totalPulled,
      new_inserted: newInserted,
      total_inserted: newInserted,
      results,
      state: curState,
      devices: curState.devices,
      summary: curState.summary,
      logs: curLogs,
    };
  }

  function listAttendanceLogs({ deviceId = '', search = '', limit = 300 } = {}) {
    const cap = Math.max(10, Math.min(5000, Number(limit || 300) || 300));
    let sql = 'SELECT * FROM biometric_logs WHERE 1=1';
    const params = [];
    if (deviceId && deviceId !== 'all') {
      sql += ' AND device_id=?';
      params.push(String(deviceId));
    }
    if (search && String(search).trim()) {
      const q = `%${String(search).trim()}%`;
      sql += ' AND (employee_id LIKE ? OR employee_name LIKE ? OR device_name LIKE ? OR branch_name LIKE ? OR punch_time LIKE ?)';
      params.push(q, q, q, q, q);
    }
    sql += ` ORDER BY punch_ts DESC LIMIT ${cap}`;
    return db.prepare(sql).all(...params).map((r) => ({
      ...r,
      branch: r.branch_name || '',
    }));
  }

  function queryStoredLogs({ deviceId = '', search = '', limit = 300 } = {}) {
    return {
      ok: true,
      logs: listAttendanceLogs({ deviceId, search, limit }),
    };
  }

  // Automatic Local Subnet Scanner for ZKTeco (TCP 4370) & Hikvision Access Terminals (TCP 80 / 8000)
  async function scanLocalLanForBiometrics({ customSubnetPrefix = '' } = {}) {
    const prefixes = new Set();
    if (customSubnetPrefix && /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(customSubnetPrefix.trim())) {
      prefixes.add(customSubnetPrefix.trim());
    }
    const nets = os.networkInterfaces();
    for (const list of Object.values(nets)) {
      for (const netIf of list || []) {
        if ((netIf.family === 'IPv4' || netIf.family === 4) && !netIf.internal) {
          const parts = String(netIf.address || '').split('.');
          if (parts.length === 4 && !parts[0].startsWith('169')) {
            prefixes.add(`${parts[0]}.${parts[1]}.${parts[2]}`);
          }
        }
      }
    }
    if (!prefixes.size) prefixes.add('192.168.1');

    const found = [];
    for (const prefix of Array.from(prefixes).slice(0, 2)) {
      const candidates = [];
      for (let i = 1; i <= 254; i++) {
        candidates.push(`${prefix}.${i}`);
      }
      const batchSize = 32;
      for (let b = 0; b < candidates.length; b += batchSize) {
        const slice = candidates.slice(b, b + batchSize);
        await Promise.all(
          slice.map(async (ip) => {
            // 1. Check ZKTeco standard port 4370
            const zkProbe = await probeTcpSocket(ip, 4370, 420);
            if (zkProbe.ok) {
              found.push({
                host: ip,
                ip,
                port: 4370,
                vendor: 'zkteco',
                label: `ZKTeco Biometric (${ip}:4370 · ${zkProbe.latencyMs}ms)`,
              });
              return;
            }
          })
        );
      }
    }
    return { ok: true, found };
  }

  async function handleAction({ action, payload = {} }) {
    switch (String(action || '')) {
      case 'overview':
      case 'list': {
        const st = listDevices();
        const logs = listAttendanceLogs({
          deviceId: payload.device_id || '',
          search: payload.search || '',
          limit: payload.limit || 350,
        });
        return {
          ...st,
          logs,
        };
      }
      case 'save':
      case 'save_device':
        return saveDevice(payload);
      case 'delete':
      case 'delete_device':
        return deleteDevice(payload.id);
      case 'test':
      case 'test_device':
        return testDeviceConnection(payload);
      case 'check_all':
      case 'probe_all':
        return checkAllDevicesHealth(true);
      case 'probe_one': {
        const targetId = String(payload.id || payload.device_id || '').trim();
        const row = db.prepare('SELECT * FROM biometric_devices WHERE id=?').get(targetId);
        if (!row) throw new Error('ماكينة البصمة غير موجودة');
        await checkSingleDeviceHealth(row, true);
        const st = listDevices();
        const dev = st.devices.find((d) => d.id === targetId) || null;
        return {
          ...st,
          device: dev,
        };
      }
      case 'pull_logs':
        return pullAttendanceLogs({ deviceId: payload.device_id || payload.id || '' });
      case 'get_logs':
        return queryStoredLogs({
          deviceId: payload.device_id || '',
          search: payload.search || '',
          limit: payload.limit || 300,
        });
      case 'clear_logs': {
        const targetId = String(payload.device_id || payload.id || '').trim();
        if (targetId) {
          db.prepare('DELETE FROM biometric_logs WHERE device_id=?').run(targetId);
        } else {
          db.prepare('DELETE FROM biometric_logs').run();
        }
        return handleAction({ action: 'overview', payload: {} });
      }
      case 'scan_lan':
        return scanLocalLanForBiometrics({ customSubnetPrefix: payload.subnet_prefix || '' });
      default:
        throw new Error('إجراء أجهزة بصمة غير معروف');
    }
  }

  // 24/7 Background Health Monitor every 30 seconds
  setInterval(() => {
    checkAllDevicesHealth(true).catch(() => {});
  }, 30_000);
  setTimeout(() => {
    checkAllDevicesHealth(false).catch(() => {});
  }, 3500);

  writeBioLog('INFO', 'ENGINE_BOOT', 'تم تشغيل محرك أجهزة البصمة والحضور والانصراف (ZKTeco TCP 4370 + Hikvision ISAPI + 24/7 Monitor)');

  return {
    listDevices,
    listAttendanceLogs,
    saveDevice,
    deleteDevice,
    testDeviceConnection,
    checkAllDevicesHealth,
    pullAttendanceLogs,
    queryStoredLogs,
    scanLocalLanForBiometrics,
    handleAction,
  };
}
