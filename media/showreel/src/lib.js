// Shared math, easing, randomness, and drawing helpers for the showreel.
// Every frame is a pure function of time, so nothing here keeps mutable global state.

export const W = 1920;
export const H = 1080;
export const FPS = 60;
export const BPM = 128;
export const BEAT = 60 / BPM; // 0.46875 s
export const BAR = BEAT * 4; // 1.875 s
export const EIGHTH = BEAT / 2;
export const SIXTEENTH = BEAT / 4;
export const DURATION = BAR * 8; // 15.0 s
export const TAU = Math.PI * 2;

export const C = {
  bg: '#04060c',
  ink: '#e8eef8',
  soft: '#a9b5c9',
  dim: '#7c8aa3',
  dimmer: '#4f5d75',
  hair: 'rgba(148,163,184,0.16)',
  blue: '#3b82f6',
  blueL: '#60a5fa',
  blueXL: '#93c5fd',
  cyan: '#22d3ee',
  navy: '#0b1733',
  slate800: '#1e293b',
  panel: 'rgba(11,18,33,0.94)',
  panelHi: 'rgba(17,27,48,0.96)',
  crit: '#ef4444',
  high: '#f97316',
  med: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
  ok: '#34d399',
  okD: '#10b981',
  amber: '#f59e0b',
  violet: '#818cf8',
};

export const F = {
  hero: 'Unbounded',
  sans: 'Geist',
  mono: 'Geist Mono',
  serif: 'Instrument Serif',
};

export const clamp = (x, a = 0, b = 1) => (x < a ? a : x > b ? b : x);
export const lerp = (a, b, t) => a + (b - a) * t;
export const prog = (t, a, b) => clamp((t - a) / (b - a));
export const smooth = (t) => t * t * (3 - 2 * t);

export const ease = {
  lin: (t) => t,
  inQuad: (t) => t * t,
  outQuad: (t) => 1 - (1 - t) * (1 - t),
  inOutQuad: (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2),
  inCubic: (t) => t * t * t,
  outCubic: (t) => 1 - Math.pow(1 - t, 3),
  inOutCubic: (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2),
  inQuart: (t) => t * t * t * t,
  outQuart: (t) => 1 - Math.pow(1 - t, 4),
  inOutQuart: (t) => (t < 0.5 ? 8 * t ** 4 : 1 - Math.pow(-2 * t + 2, 4) / 2),
  inQuint: (t) => t ** 5,
  outQuint: (t) => 1 - Math.pow(1 - t, 5),
  inOutQuint: (t) => (t < 0.5 ? 16 * t ** 5 : 1 - Math.pow(-2 * t + 2, 5) / 2),
  inExpo: (t) => (t <= 0 ? 0 : Math.pow(2, 10 * t - 10)),
  outExpo: (t) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t)),
  inOutExpo: (t) =>
    t <= 0 ? 0 : t >= 1 ? 1 : t < 0.5 ? Math.pow(2, 20 * t - 10) / 2 : (2 - Math.pow(2, -20 * t + 10)) / 2,
  outBack: (t, s = 1.70158) => 1 + (s + 1) * Math.pow(t - 1, 3) + s * Math.pow(t - 1, 2),
  inBack: (t, s = 1.70158) => (s + 1) * t * t * t - s * t * t,
  outCirc: (t) => Math.sqrt(1 - Math.pow(t - 1, 2)),
  inCirc: (t) => 1 - Math.sqrt(1 - t * t),
};

// Progress through [a, b] passed through an easing curve.
export const ep = (t, a, b, fn = ease.outExpo) => fn(prog(t, a, b));

// Damped spring step response; x is seconds since the trigger. Overshoots, settles at 1.
export function spring(x, freq = 3.2, damp = 0.42) {
  if (x <= 0) return 0;
  const w = TAU * freq;
  const wd = w * Math.sqrt(1 - damp * damp);
  return 1 - Math.exp(-damp * w * x) * (Math.cos(wd * x) + ((damp * w) / wd) * Math.sin(wd * x));
}

// Exponential decay envelope that starts at 1 on the trigger.
export const decay = (x, rate = 8) => (x < 0 ? 0 : Math.exp(-x * rate));

// Deterministic integer hash -> [0, 1).
export function hash(a, b = 0, c = 0) {
  let h = Math.imul(a | 0, 0x27d4eb2d) ^ Math.imul(b | 0, 0x165667b1) ^ Math.imul(c | 0, 0x1b873593);
  h = Math.imul(h ^ (h >>> 15), 0x85ebca6b);
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35);
  h ^= h >>> 16;
  return (h >>> 0) / 4294967296;
}

export function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function setFont(ctx, family, weight, size, { italic = false, tracking = 0 } = {}) {
  ctx.font = `${italic ? 'italic ' : ''}${weight} ${size}px "${family}"`;
  ctx.letterSpacing = `${tracking}px`;
}

// x offsets of each character (kerning preserved by measuring prefixes).
export function layoutChars(ctx, str) {
  const xs = [];
  for (let i = 0; i < str.length; i++) xs.push(ctx.measureText(str.slice(0, i)).width);
  return { xs, width: ctx.measureText(str).width };
}

const alignOffset = (align, width) => (align === 'center' ? -width / 2 : align === 'right' ? -width : 0);

// Per-character kinetic text. o.t is local time since the animation starts.
export function kinetic(ctx, str, x, y, o) {
  const {
    t,
    stagger = 0.035,
    dur = 0.6,
    fn = ease.outExpo,
    mode = 'rise',
    dist = 1,
    align = 'left',
    color = C.ink,
    mask = true,
    order = 'ltr',
    size = 100,
    out = null, // { t, stagger, dur, fn, mode }
  } = o;
  const { xs, width } = layoutChars(ctx, str);
  const ox = x + alignOffset(align, width);
  const letterSpacing = ctx.letterSpacing;
  ctx.save();
  if (mask) {
    ctx.beginPath();
    ctx.rect(ox - size * 0.5, y - size * 1.05, width + size, size * 1.35);
    ctx.clip();
  }
  ctx.letterSpacing = '0px';
  ctx.fillStyle = color;
  const n = str.length;
  for (let i = 0; i < n; i++) {
    const ch = str[i];
    if (ch === ' ') continue;
    const k = order === 'rtl' ? n - 1 - i : order === 'center' ? Math.abs(i - (n - 1) / 2) : i;
    const p = fn(prog(t - k * stagger, 0, dur));
    let q = 1;
    if (out) {
      const ko = out.order === 'rtl' ? n - 1 - i : i;
      q = 1 - (out.fn || ease.inExpo)(prog(out.t - ko * (out.stagger ?? 0.02), 0, out.dur ?? 0.3));
    }
    if (p <= 0 || q <= 0) continue;
    const cx = ox + xs[i];
    ctx.save();
    let dy = 0;
    let dx = 0;
    let sc = 1;
    let alpha = 1;
    if (mode === 'rise') dy = (1 - p) * size * 1.1 * dist;
    else if (mode === 'drop') dy = -(1 - p) * size * 1.1 * dist;
    else if (mode === 'slideR') dx = (1 - p) * size * 3 * dist;
    else if (mode === 'scale') {
      sc = lerp(2.2, 1, p);
      alpha = clamp(p * 2);
    } else if (mode === 'fade') alpha = p;
    if (out) {
      const om = out.mode || 'rise';
      if (om === 'rise') dy -= (1 - q) * size * 1.1;
      else if (om === 'drop') dy += (1 - q) * size * 1.1;
      else if (om === 'slideL') dx -= (1 - q) * size * 3;
      else alpha *= q;
    }
    ctx.globalAlpha *= alpha;
    if (sc !== 1) {
      const cw = ctx.measureText(ch).width;
      ctx.translate(cx + dx + cw / 2, y + dy - size * 0.36);
      ctx.scale(sc, sc);
      ctx.fillText(ch, -cw / 2, size * 0.36);
    } else {
      ctx.fillText(ch, cx + dx, y + dy);
    }
    ctx.restore();
  }
  ctx.restore();
  ctx.letterSpacing = letterSpacing;
  return width;
}

const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/#%&*+<>=_:';

// Decode effect: characters resolve left to right; unresolved ones flicker through glyphs.
export function scramble(str, p, fi, seed = 1) {
  if (p >= 1) return str;
  let out = '';
  const n = str.length;
  for (let i = 0; i < n; i++) {
    const ch = str[i];
    const th = (i / Math.max(1, n)) * 0.75 + hash(seed, i) * 0.25;
    if (ch === ' ') out += ' ';
    else if (p >= th) out += ch;
    else if (p >= th - 0.35) out += GLYPHS[Math.floor(hash(seed, i, Math.floor(fi / 2)) * GLYPHS.length)];
    else out += ' ';
  }
  return out;
}

// Outer-only text outline, cached as a bitmap. Variable fonts carry overlapping contours, so
// strokeText would also draw the overlaps inside each glyph; stroking at 2x width and then
// punching the fill back out leaves just the outside edge.
const OUTLINES = new Map();
export function outlineBitmap(text, family, weight, size, lw, color, tracking = 0) {
  const key = `${text}|${family}|${weight}|${size.toFixed(2)}|${lw}|${color}|${tracking.toFixed(2)}`;
  let e = OUTLINES.get(key);
  if (e) return e;
  const c = document.createElement('canvas');
  const x = c.getContext('2d');
  setFont(x, family, weight, size, { tracking });
  const mt = x.measureText(text);
  const pad = Math.ceil(lw * 2 + 6);
  const left = Math.ceil(mt.actualBoundingBoxLeft) + pad;
  const asc = Math.ceil(mt.actualBoundingBoxAscent) + pad;
  c.width = Math.ceil(mt.actualBoundingBoxLeft + mt.actualBoundingBoxRight) + pad * 2;
  c.height = Math.ceil(mt.actualBoundingBoxAscent + mt.actualBoundingBoxDescent) + pad * 2;
  setFont(x, family, weight, size, { tracking });
  x.lineJoin = 'round';
  x.strokeStyle = color;
  x.lineWidth = lw * 2;
  x.strokeText(text, left, asc);
  x.globalCompositeOperation = 'destination-out';
  x.fillText(text, left, asc);
  e = { canvas: c, ox: left, oy: asc };
  OUTLINES.set(key, e);
  return e;
}

export function drawOutline(ctx, text, x, y, { family, weight = 800, size, lw = 2, color, tracking = 0, align = 'left' }) {
  const b = outlineBitmap(text, family, weight, size, lw, color, tracking);
  let dx = 0;
  if (align !== 'left') {
    setFont(ctx, family, weight, size, { tracking });
    dx = alignOffset(align, ctx.measureText(text).width);
  }
  ctx.drawImage(b.canvas, x + dx - b.ox, y - b.oy);
}

export function typed(str, p) {
  return str.slice(0, Math.round(clamp(p) * str.length));
}

export function drawText(ctx, str, x, y, { color = C.ink, align = 'left', alpha = 1 } = {}) {
  if (alpha <= 0 || !str) return 0;
  const w = ctx.measureText(str).width;
  ctx.save();
  ctx.globalAlpha *= alpha;
  ctx.fillStyle = color;
  ctx.fillText(str, x + alignOffset(align, w), y);
  ctx.restore();
  return w;
}

export function rrect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.roundRect(x, y, w, h, r);
}

export function line(ctx, x1, y1, x2, y2) {
  ctx.beginPath();
  ctx.moveTo(x1, y1);
  ctx.lineTo(x2, y2);
  ctx.stroke();
}

// Partial straight line from (x1,y1) toward (x2,y2).
export function lineTo(ctx, x1, y1, x2, y2, p) {
  if (p <= 0) return;
  line(ctx, x1, y1, lerp(x1, x2, p), lerp(y1, y2, p));
}

export function circle(ctx, x, y, r) {
  ctx.beginPath();
  ctx.arc(x, y, Math.max(0, r), 0, TAU);
}

// The ShakerScan compass needle (from ui/public/favicon.svg), unit = 1/16 of tip-to-tip length.
// Top chevron: (0,-8) (-4,0) (0,-2) (4,0). Bottom: (0,-2) (-4,0) (0,8) (4,0).
export function needlePaths(ctx, s) {
  const top = new Path2D();
  top.moveTo(0, -8 * s);
  top.lineTo(-4 * s, 0);
  top.lineTo(0, -2 * s);
  top.lineTo(4 * s, 0);
  top.closePath();
  const bottom = new Path2D();
  bottom.moveTo(0, -2 * s);
  bottom.lineTo(-4 * s, 0);
  bottom.lineTo(0, 8 * s);
  bottom.lineTo(4 * s, 0);
  bottom.closePath();
  return { top, bottom };
}

export function drawNeedle(ctx, s, { top = C.blue, bottom = C.blueL, alpha = 1 } = {}) {
  const p = needlePaths(ctx, s);
  ctx.save();
  ctx.globalAlpha *= alpha;
  ctx.fillStyle = top;
  ctx.fill(p.top);
  ctx.fillStyle = bottom;
  ctx.fill(p.bottom);
  ctx.restore();
}

export function rhombus(ctx, cx, cy, a, b, rot = 0) {
  const c = Math.cos(rot);
  const s = Math.sin(rot);
  const pts = [
    [0, -b],
    [a, 0],
    [0, b],
    [-a, 0],
  ];
  ctx.beginPath();
  pts.forEach(([x, y], i) => {
    const px = cx + x * c - y * s;
    const py = cy + x * s + y * c;
    if (i === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  });
  ctx.closePath();
}

export function fmtInt(n) {
  return Math.round(n).toLocaleString('en-US');
}

export function pad(n, w = 2) {
  return String(Math.floor(n)).padStart(w, '0');
}
