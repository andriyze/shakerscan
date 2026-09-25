// 08 LOGO: the needle halves slam into the ring (which arrived as the "O" of OPEN), shockwave,
// sparks, wordmark and the three verbs on eighth notes.
import {
  W, H, C, F, TAU, BEAT, EIGHTH,
  clamp, lerp, prog, ep, ease, setFont, drawText, circle, spring, decay, hash, drawNeedle, layoutChars,
} from '../lib.js';
import { ambient, baseFill, dotGrid } from '../common.js';

export const MARK_R = 100;
export const MARK_S = MARK_R / 14; // favicon units -> px
export const RING_W = 2 * MARK_S; // favicon stroke width is 2 units
const WORD = 'ShakerScan';
const WSIZE = 126;

let MARK = null;
export const markScreen = () => MARK || [W / 2, H / 2];

export function logoLayout(ctx) {
  setFont(ctx, F.sans, 700, WSIZE, { tracking: -3.5 });
  const ww = ctx.measureText(WORD).width;
  const gap = 56;
  const total = MARK_R * 2 + gap + ww;
  const x0 = (W - total) / 2;
  const my = 486;
  MARK = [x0 + MARK_R, my];
  return { mx: x0 + MARK_R, my, wx: x0 + MARK_R * 2 + gap, wy: my + WSIZE * 0.355, ww, total, x0 };
}

export function drawRing(c, x, y, rx, ry, lw, color = C.blue, fill = null) {
  if (fill) {
    c.fillStyle = fill;
    c.beginPath();
    c.ellipse(x, y, Math.max(0, rx), Math.max(0, ry), 0, 0, TAU);
    c.fill();
  }
  c.strokeStyle = color;
  c.lineWidth = lw;
  c.beginPath();
  c.ellipse(x, y, Math.max(0, rx - lw / 2), Math.max(0, ry - lw / 2), 0, 0, TAU);
  c.stroke();
}

const SPARKS = Array.from({ length: 150 }, (_, i) => ({
  a: hash(i, 1) * TAU,
  v: 500 + hash(i, 2) ** 1.6 * 2300,
  len: 10 + hash(i, 3) * 36,
  life: 0.5 + hash(i, 4) * 1.1,
  w: 1 + hash(i, 5) * 2,
  hue: hash(i, 6),
}));

function sparks(L, u, mx, my) {
  if (u < 0) return;
  const drag = 3.2;
  SPARKS.forEach((s) => {
    const life = clamp(1 - u / s.life);
    if (life <= 0) return;
    const d = (s.v / drag) * (1 - Math.exp(-drag * u));
    const vNow = s.v * Math.exp(-drag * u);
    const dx = Math.cos(s.a);
    const dy = Math.sin(s.a);
    const x = mx + dx * (MARK_R + d);
    const y = my + dy * (MARK_R + d);
    const tail = s.len + vNow * 0.012;
    L.both((c, glow) => {
      c.save();
      c.globalAlpha = life * (glow ? 0.8 : 1);
      c.strokeStyle = glow ? C.blue : s.hue > 0.6 ? '#ffffff' : C.blueXL;
      c.lineWidth = glow ? s.w * 3 : s.w;
      c.lineCap = 'round';
      c.beginPath();
      c.moveTo(x, y);
      c.lineTo(x - dx * tail, y - dy * tail);
      c.stroke();
      c.restore();
    });
  });
}

function dust(L, u) {
  const m = L.m;
  m.save();
  for (let i = 0; i < 90; i++) {
    const x = (hash(i, 11) * W + u * (10 + hash(i, 12) * 30)) % W;
    const y = (hash(i, 13) * H - u * (6 + hash(i, 14) * 20) + H) % H;
    m.globalAlpha = 0.15 + 0.35 * hash(i, 15) * ep(u, 0.1, 0.8);
    m.fillStyle = C.blueXL;
    m.fillRect(x, y, 1.6, 1.6);
  }
  m.restore();
}

// Background and the arriving ring are shared with the end of the montage (u < 0).
export function scene8(L, u, fi) {
  const { m, g } = L;
  const lay = logoLayout(m);
  const { mx, my } = lay;
  baseFill(L);
  const push = 1 + 0.035 * ep(u, 0, 1.9, ease.outCubic);
  L.save();
  L.zoom(push, W / 2, H / 2);
  ambient(L, mx + 200, my + 40, 1100, ep(u, -0.05, 0.3));
  dotGrid(L, u, { alpha: 0.6 * ep(u, 0, 0.5) });
  dust(L, u);

  // shockwave
  const sw = prog(u, 0, 0.75);
  if (sw > 0 && sw < 1) {
    L.both((c, glow) => {
      c.save();
      c.globalAlpha = (1 - sw) * (glow ? 1 : 0.7);
      c.strokeStyle = glow ? C.blue : C.blueXL;
      c.lineWidth = (glow ? 16 : 4) * (1 - sw) + 0.5;
      circle(c, mx, my, MARK_R + ease.outCubic(sw) * 1500);
      c.stroke();
      c.restore();
    });
  }
  sparks(L, u, mx, my);

  // mark
  const punch = u >= 0 ? 1 + 0.16 * (1 - spring(u, 2.4, 0.3)) : 1;
  L.save();
  L.translate(mx, my);
  L.scale(punch, punch);
  const fillA = ep(u, 0, 0.12);
  drawRing(m, 0, 0, MARK_R, MARK_R, RING_W, C.blue, `rgba(30,41,59,${fillA})`);
  g.save();
  g.globalAlpha = 0.6 + 0.4 * decay(u, 3);
  drawRing(g, 0, 0, MARK_R, MARK_R, RING_W * 1.6, C.blue);
  g.restore();
  // needle halves converge from above/below and lock at u = 0
  const k = u < 0 ? ease.inCubic(prog(u, -0.2, 0)) : 1;
  const off = (1 - k) * 620;
  if (k > 0) {
    const { top, bottom } = needlePathsCached();
    m.save();
    m.translate(0, -off);
    m.fillStyle = C.blue;
    m.fill(top);
    m.restore();
    m.save();
    m.translate(0, off);
    m.fillStyle = C.blueL;
    m.fill(bottom);
    m.restore();
    g.save();
    g.globalAlpha = 0.5 + 0.5 * decay(u, 4);
    g.translate(0, -off);
    g.fillStyle = C.blue;
    g.fill(top);
    g.translate(0, off * 2);
    g.fillStyle = C.blueL;
    g.fill(bottom);
    g.restore();
  }
  L.restore();

  // wordmark
  if (u > 0) {
    setFont(m, F.sans, 700, WSIZE, { tracking: -3.5 });
    const { xs } = layoutChars(m, WORD);
    m.save();
    m.beginPath();
    m.rect(lay.wx - 20, lay.wy - WSIZE, lay.ww + 60, WSIZE * 1.3);
    m.clip();
    m.letterSpacing = '0px';
    for (let i = 0; i < WORD.length; i++) {
      const p = ep(u, 0.05 + i * 0.028, 0.6 + i * 0.028, ease.outExpo);
      if (p <= 0) continue;
      m.fillStyle = '#ffffff';
      m.fillText(WORD[i], lay.wx + xs[i], lay.wy + (1 - p) * WSIZE * 1.05);
    }
    m.restore();
  }

  // verbs on eighth notes
  const words = [
    ['Scan.', BEAT, F.sans, 500, 46, C.ink, false],
    ['Hunt.', BEAT + EIGHTH, F.sans, 500, 46, C.ink, false],
    ['Prove.', BEAT * 2, F.serif, 400, 58, C.blueXL, true],
  ];
  let widths = 0;
  const gaps = 22;
  words.forEach(([w, , fam, wt, sz, , it]) => {
    setFont(m, fam, wt, sz, { italic: it, tracking: fam === F.sans ? -1 : 0 });
    widths += m.measureText(w).width;
  });
  let tx = W / 2 - (widths + gaps * 2) / 2;
  const ty = my + MARK_R + 128;
  words.forEach(([w, t, fam, wt, sz, col, it]) => {
    setFont(m, fam, wt, sz, { italic: it, tracking: fam === F.sans ? -1 : 0 });
    const ww = m.measureText(w).width;
    const p = ep(u, t - 0.02, t + 0.3, ease.outExpo);
    if (p > 0) {
      m.save();
      m.globalAlpha = clamp(p * 1.5);
      m.translate(tx + ww / 2, ty);
      const s = lerp(1.35, 1, p);
      m.scale(s, s);
      drawText(m, w, -ww / 2, 0, { color: col });
      m.restore();
      if (it) {
        g.save();
        g.globalAlpha = 0.25 * p;
        setFont(g, fam, wt, sz, { italic: it });
        g.fillStyle = C.blueL;
        g.fillText(w, tx, ty);
        g.restore();
      }
    }
    tx += ww + gaps;
  });

  // footer line
  const fa = ep(u, 1.05, 1.4);
  if (fa > 0) {
    setFont(m, F.mono, 500, 17, { tracking: 2.5 });
    const line = 'OPEN SOURCE  ·  AGPL-3.0  ·  GITHUB.COM/ANDRIYZE/SHAKERSCAN';
    m.save();
    m.globalAlpha = fa;
    m.translate(0, (1 - fa) * 12);
    drawText(m, line, W / 2, ty + 74, { color: C.dim, align: 'center' });
    m.restore();
  }
  L.restore();
}

let cachedNeedle = null;
function needlePathsCached() {
  if (!cachedNeedle) {
    const s = MARK_S;
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
    cachedNeedle = { top, bottom };
  }
  return cachedNeedle;
}
