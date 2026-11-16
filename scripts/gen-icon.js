// Generates assets/icon.png (1024x1024): violet-to-blue rounded square with a white shield and check mark.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const N = 1024;
const SS = 3;
const px = Buffer.alloc(N * N * 4);

const lerp = (a, b, t) => a + (b - a) * t;
const c1 = [124, 108, 246];
const c2 = [79, 142, 247];

function inRoundedSquare(x, y) {
  const r = 230, m = 40;
  const cx = Math.min(Math.max(x, m + r), N - m - r);
  const cy = Math.min(Math.max(y, m + r), N - m - r);
  return x >= m && x <= N - m && y >= m && y <= N - m && (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}

const shield = [[512, 190], [790, 290], [790, 530], [512, 850], [234, 530], [234, 290]];
function inPolygon(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function distToSegment(x, y, [ax, ay], [bx, by]) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - (ax + t * dx), y - (ay + t * dy));
}

const check = [[392, 520], [476, 606], [650, 420]];
function onCheck(x, y) {
  return distToSegment(x, y, check[0], check[1]) <= 34 || distToSegment(x, y, check[1], check[2]) <= 34;
}

for (let y = 0; y < N; y++) {
  for (let x = 0; x < N; x++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let sy = 0; sy < SS; sy++) {
      for (let sx = 0; sx < SS; sx++) {
        const fx = x + (sx + 0.5) / SS, fy = y + (sy + 0.5) / SS;
        if (!inRoundedSquare(fx, fy)) continue;
        const t = (fx + fy) / (2 * N);
        let col = [lerp(c1[0], c2[0], t), lerp(c1[1], c2[1], t), lerp(c1[2], c2[2], t)];
        if (inPolygon(fx, fy, shield)) col = onCheck(fx, fy) ? col : [255, 255, 255];
        r += col[0]; g += col[1]; b += col[2]; a += 255;
      }
    }
    const n = SS * SS, i = (y * N + x) * 4;
    const cov = a / 255;
    px[i] = cov ? r / cov : 0;
    px[i + 1] = cov ? g / cov : 0;
    px[i + 2] = cov ? b / cov : 0;
    px[i + 3] = Math.round(a / n);
  }
}

const raw = Buffer.alloc((N * 4 + 1) * N);
for (let y = 0; y < N; y++) {
  raw[y * (N * 4 + 1)] = 0;
  px.copy(raw, y * (N * 4 + 1) + 1, y * N * 4, (y + 1) * N * 4);
}

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(body) >>> 0);
  return Buffer.concat([len, body, crc]);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(N, 0); ihdr.writeUInt32BE(N, 4); ihdr[8] = 8; ihdr[9] = 6;
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

const out = path.join(__dirname, '..', 'assets', 'icon.png');
fs.writeFileSync(out, png);
console.log('wrote', out, png.length, 'bytes');
