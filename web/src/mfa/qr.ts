// Minimal QR code encoder (ISO/IEC 18004): byte mode, error correction
// level M, versions 1–10 (up to 213 bytes) — enough for an otpauth:// URI.
// Produces a square boolean matrix (true = dark). No dependencies.

const EC_M_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
const BLOCKS_M = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
const MAX_VERSION = 10;
/** EC level M format bits are 00. */
const EC_M_BITS = 0;

export type QrMatrix = { size: number; version: number; mask: number; modules: boolean[][] };

/** Raw data modules (codewords × 8 plus remainder bits) of a version. */
function rawDataModules(ver: number): number {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}

function totalCodewords(ver: number): number {
  return Math.floor(rawDataModules(ver) / 8);
}

export function dataCodewords(ver: number): number {
  return totalCodewords(ver) - EC_M_PER_BLOCK[ver] * BLOCKS_M[ver];
}

export function alignmentPositions(ver: number): number[] {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2;
  const size = ver * 4 + 17;
  const step = Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2;
  const out = [6];
  for (let pos = size - 7; out.length < n; pos -= step) out.splice(1, 0, pos);
  return out;
}

// ---------- Reed–Solomon over GF(256), polynomial 0x11D ----------

function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

export function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

export function rsRemainder(data: readonly number[], divisor: readonly number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ (result.shift() as number);
    result.push(0);
    divisor.forEach((coef, i) => { result[i] ^= gfMul(coef, factor); });
  }
  return result;
}

// ---------- Bit stream ----------

function pushBits(bits: number[], val: number, len: number): void {
  for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
}

export function utf8Bytes(s: string): number[] {
  return Array.from(new TextEncoder().encode(s));
}

/** Data codewords (mode, count, payload, terminator, padding) for `bytes` at `ver`. */
export function encodeData(bytes: readonly number[], ver: number): number[] {
  const capBits = dataCodewords(ver) * 8;
  const bits: number[] = [];
  pushBits(bits, 0x4, 4); // byte mode
  pushBits(bits, bytes.length, ver <= 9 ? 8 : 16);
  bytes.forEach((b) => pushBits(bits, b, 8));
  if (bits.length > capBits) throw new Error("data too long for version");
  pushBits(bits, 0, Math.min(4, capBits - bits.length));
  pushBits(bits, 0, (8 - (bits.length % 8)) % 8);
  const out: number[] = [];
  for (let i = 0; i < bits.length; i += 8) out.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  for (let pad = 0xec; out.length < capBits / 8; pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}

/** Split into blocks, add EC to each, interleave. */
export function addEcAndInterleave(data: readonly number[], ver: number): number[] {
  const numBlocks = BLOCKS_M[ver];
  const ecLen = EC_M_PER_BLOCK[ver];
  const raw = totalCodewords(ver);
  const numShort = numBlocks - (raw % numBlocks);
  const shortLen = Math.floor(raw / numBlocks);
  const div = rsDivisor(ecLen);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - ecLen + (i < numShort ? 0 : 1));
    k += dat.length;
    const ec = rsRemainder(dat, div);
    if (i < numShort) dat.push(0); // placeholder so all blocks align; skipped below
    blocks.push([...dat, ...ec]);
  }
  const out: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((blk, j) => {
      if (i !== shortLen - ecLen || j >= numShort) out.push(blk[i]);
    });
  }
  return out;
}

// ---------- Matrix ----------

class Grid {
  readonly version: number;
  readonly size: number;
  readonly mod: boolean[][];
  readonly fn: boolean[][];
  constructor(version: number) {
    this.version = version;
    this.size = version * 4 + 17;
    this.mod = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.fn = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }
  set(x: number, y: number, dark: boolean): void {
    this.mod[y][x] = dark;
    this.fn[y][x] = true;
  }
}

function finder(g: Grid, cx: number, cy: number): void {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx;
      const y = cy + dy;
      if (x < 0 || y < 0 || x >= g.size || y >= g.size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      g.set(x, y, d !== 2 && d !== 4);
    }
  }
}

function alignment(g: Grid, cx: number, cy: number): void {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) g.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
}

export function formatBits(mask: number): number {
  const data = (EC_M_BITS << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

export function versionBits(ver: number): number {
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (ver << 12) | rem;
}

function drawFormat(g: Grid, mask: number): void {
  const bits = formatBits(mask);
  const bit = (i: number) => ((bits >>> i) & 1) !== 0;
  for (let i = 0; i <= 5; i++) g.set(8, i, bit(i));
  g.set(8, 7, bit(6));
  g.set(8, 8, bit(7));
  g.set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) g.set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) g.set(g.size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) g.set(8, g.size - 15 + i, bit(i));
  g.set(8, g.size - 8, true); // dark module
}

function drawFunctionPatterns(g: Grid): void {
  for (let i = 0; i < g.size; i++) {
    g.set(6, i, i % 2 === 0);
    g.set(i, 6, i % 2 === 0);
  }
  finder(g, 3, 3);
  finder(g, g.size - 4, 3);
  finder(g, 3, g.size - 4);
  const pos = alignmentPositions(g.version);
  const n = pos.length;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
      alignment(g, pos[i], pos[j]);
    }
  }
  drawFormat(g, 0); // reserve; redrawn with the chosen mask
  if (g.version >= 7) {
    const bits = versionBits(g.version);
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0;
      const a = g.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      g.set(a, b, dark);
      g.set(b, a, dark);
    }
  }
}

/** Zig-zag placement: column pairs right to left (skipping column 6), alternating up/down. */
export function placementOrder(size: number, isFunction: (x: number, y: number) => boolean): [number, number][] {
  const order: [number, number][] = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isFunction(x, y)) order.push([x, y]);
      }
    }
  }
  return order;
}

export function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

function penalty(m: boolean[][]): number {
  const size = m.length;
  let score = 0;
  const line = (get: (i: number) => boolean) => {
    let s = 0;
    let run = 1;
    for (let i = 1; i <= size; i++) {
      if (i < size && get(i) === get(i - 1)) run++;
      else {
        if (run >= 5) s += 3 + (run - 5);
        run = 1;
      }
    }
    // Finder-like 1:1:3:1:1 with 4 light modules on either side.
    for (let i = 0; i + 6 < size; i++) {
      if (get(i) && !get(i + 1) && get(i + 2) && get(i + 3) && get(i + 4) && !get(i + 5) && get(i + 6)) {
        let before = true;
        let after = true;
        for (let k = 1; k <= 4; k++) {
          if (i - k >= 0 && get(i - k)) before = false;
          if (i + 6 + k < size && get(i + 6 + k)) after = false;
        }
        if (before || after) s += 40;
      }
    }
    return s;
  };
  for (let y = 0; y < size; y++) score += line((i) => m[y][i]);
  for (let x = 0; x < size; x++) score += line((i) => m[i][x]);
  for (let y = 0; y + 1 < size; y++) {
    for (let x = 0; x + 1 < size; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) score += 3;
    }
  }
  const dark = m.reduce((a, row) => a + row.filter(Boolean).length, 0);
  const total = size * size;
  score += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return score;
}

/** Smallest version (1–10, level M) that fits. */
export function chooseVersion(byteLen: number): number {
  for (let v = 1; v <= MAX_VERSION; v++) {
    const header = 4 + (v <= 9 ? 8 : 16);
    if (header + byteLen * 8 <= dataCodewords(v) * 8) return v;
  }
  throw new Error(`Text too long for a version ${MAX_VERSION} QR code (${byteLen} bytes)`);
}

export function encodeQr(text: string, forceMask?: number): QrMatrix {
  const bytes = utf8Bytes(text);
  const version = chooseVersion(bytes.length);
  const codewords = addEcAndInterleave(encodeData(bytes, version), version);
  const base = new Grid(version);
  drawFunctionPatterns(base);
  const order = placementOrder(base.size, (x, y) => base.fn[y][x]);
  const data = base.mod.map((r) => [...r]);
  order.forEach(([x, y], i) => {
    const byte = codewords[i >>> 3];
    data[y][x] = byte !== undefined && ((byte >>> (7 - (i & 7))) & 1) === 1;
  });
  let best: QrMatrix | null = null;
  let bestScore = Infinity;
  const masks = forceMask === undefined ? [0, 1, 2, 3, 4, 5, 6, 7] : [forceMask];
  for (const mask of masks) {
    const g = new Grid(version);
    drawFunctionPatterns(g);
    for (let y = 0; y < g.size; y++) {
      for (let x = 0; x < g.size; x++) {
        if (!g.fn[y][x]) g.mod[y][x] = data[y][x] !== maskBit(mask, x, y);
      }
    }
    drawFormat(g, mask);
    const s = penalty(g.mod);
    if (s < bestScore) {
      bestScore = s;
      best = { size: g.size, version, mask, modules: g.mod };
    }
  }
  return best as QrMatrix;
}
