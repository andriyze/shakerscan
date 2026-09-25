// 07 ONE PLATFORM: eighth-note word slams, then a text-mask recap of every shot through the
// letters of OPEN SOURCE; the O becomes the logo ring.
import {
  W, H, C, F, TAU, BEAT, EIGHTH, SIXTEENTH,
  clamp, lerp, prog, ep, ease, setFont, drawText, layoutChars, decay, hash, drawOutline,
} from '../lib.js';
import { Layers } from '../layers.js';
import { baseFill } from '../common.js';
import { scene1 } from './s1_map.js';
import { scene2 } from './s2_scan.js';
import { scene3 } from './s3_hunt.js';
import { scene4 } from './s4_prove.js';
import { scene5 } from './s5_grade.js';
import { logoLayout, MARK_R, RING_W, drawRing } from './s8_logo.js';

export const PART_B = BEAT * 2; // text-mask montage starts
export const PART_C = PART_B + SIXTEENTH * 6; // O -> ring morph starts
const END = BEAT * 4;

const WORDS = [
  { w: 'WEB', bg: '#04060c', fg: C.ink, echo: 'rgba(232,238,248,0.2)' },
  { w: 'APIs', bg: C.blue, fg: '#030817', echo: 'rgba(3,8,23,0.28)' },
  { w: 'AI', bg: '#e8eef8', fg: C.blue, echo: 'rgba(59,130,246,0.3)' },
  { w: 'DEVICES', bg: '#04060c', fg: C.blueL, echo: 'rgba(96,165,250,0.22)' },
];

function heroSize(m, word, maxW, base) {
  setFont(m, F.hero, 800, base, { tracking: -base * 0.02 });
  const w = m.measureText(word).width;
  return w > maxW ? base * (maxW / w) : base;
}

function slams(L, u, fi) {
  const m = L.m;
  const k = clamp(Math.floor(u / EIGHTH), 0, 3);
  const v = u - k * EIGHTH;
  const wd = WORDS[k];
  m.fillStyle = wd.bg;
  m.fillRect(0, 0, W, H);
  const size = heroSize(m, wd.w, 1540, 420);
  setFont(m, F.hero, 800, size, { tracking: -size * 0.02 });
  const tw = m.measureText(wd.w).width;
  const p = ep(v, 0, 0.17, ease.outExpo);
  const s = lerp(1.45, 1, p);
  const rot = (k % 2 ? 1 : -1) * 0.05 * (1 - p);
  const base = H / 2 + size * 0.36;
  m.save();
  m.translate(W / 2, H / 2);
  m.rotate(rot);
  m.scale(s, s);
  m.translate(-W / 2, -H / 2);
  const drift = (k % 2 ? -1 : 1) * v * 520;
  for (let j = -2; j <= 2; j++) {
    if (j === 0) continue;
    drawOutline(m, wd.w, W / 2 - tw / 2, base + j * size * 0.9 + drift, {
      family: F.hero, size, lw: 2.5, color: wd.echo, tracking: -size * 0.02,
    });
  }
  m.fillStyle = wd.fg;
  m.fillText(wd.w, W / 2 - tw / 2, base);
  m.restore();
  if (k === 0 || k === 3) {
    const g = L.g;
    g.save();
    g.globalAlpha = 0.18;
    setFont(g, F.hero, 800, size, { tracking: -size * 0.02 });
    g.fillStyle = C.blue;
    g.fillText(wd.w, W / 2 - tw / 2, base);
    g.restore();
  }
  // index + caption
  setFont(m, F.mono, 600, 16, { tracking: 4 });
  const dark = wd.bg === '#04060c';
  const cap = dark ? C.soft : 'rgba(3,8,23,0.75)';
  drawText(m, `0${k + 1} / 04`, 120, H / 2 - size * 0.62, { color: cap });
  drawText(m, 'ONE FINDINGS STORE · ONE EXPOSURE GRAPH', W - 120, H / 2 + size * 0.62 + 16, { color: cap, align: 'right' });
}

// Offscreen layers used to render recap shots that are then masked by the letters.
let OFF = null;
function off() {
  if (!OFF) {
    const mk = (w, h) => {
      const c = document.createElement('canvas');
      c.width = w;
      c.height = h;
      return c.getContext('2d');
    };
    OFF = { L: new Layers(mk(W, H), mk(W / 2, H / 2), 0.5), mask: mk(W, H), maskG: mk(W / 2, H / 2), oGeom: null };
  }
  return OFF;
}

function lettersLayout(m) {
  const size = heroSize(m, 'SOURCE', 1480, 330);
  setFont(m, F.hero, 800, size, { tracking: -size * 0.02 });
  const l1 = layoutChars(m, 'OPEN');
  const l2 = layoutChars(m, 'SOURCE');
  const capH = m.measureText('O').actualBoundingBoxAscent;
  const gap = size * 0.2;
  const top = H / 2 - (capH * 2 + gap) / 2 - 10;
  return {
    size,
    lines: [
      { text: 'OPEN', x: W / 2 - l1.width / 2, y: top + capH, xs: l1.xs },
      { text: 'SOURCE', x: W / 2 - l2.width / 2, y: top + capH * 2 + gap, xs: l2.xs },
    ],
  };
}

// Measure the rendered O (centre, radii, stroke) once so the ring swap is seamless.
function oGeometry(lay) {
  const O = off();
  if (O.oGeom && O.oGeom.size === lay.size) return O.oGeom;
  const c = O.mask;
  c.setTransform(1, 0, 0, 1, 0, 0);
  c.clearRect(0, 0, W, H);
  setFont(c, F.hero, 800, lay.size, { tracking: 0 });
  c.letterSpacing = '0px';
  c.fillStyle = '#fff';
  const ln = lay.lines[0];
  c.fillText('O', ln.x, ln.y);
  const mt = c.measureText('O');
  const x0 = Math.floor(ln.x - mt.actualBoundingBoxLeft);
  const x1 = Math.ceil(ln.x + mt.actualBoundingBoxRight);
  const y0 = Math.floor(ln.y - mt.actualBoundingBoxAscent);
  const y1 = Math.ceil(ln.y + mt.actualBoundingBoxDescent);
  const midY = Math.round((y0 + y1) / 2);
  const row = c.getImageData(x0, midY, x1 - x0, 1).data;
  let first = -1;
  let end = -1;
  for (let i = 0; i < x1 - x0; i++) {
    const on = row[i * 4 + 3] > 127;
    if (on && first < 0) first = i;
    if (!on && first >= 0) {
      end = i;
      break;
    }
  }
  const th = end > first ? end - first : lay.size * 0.18;
  O.oGeom = { size: lay.size, cx: (x0 + x1) / 2, cy: (y0 + y1) / 2, rx: (x1 - x0) / 2, ry: (y1 - y0) / 2, th };
  return O.oGeom;
}

function drawLetters(c, lay, { skipO = false, scale = 1, fill = '#fff', stroke = null, lw = 2 } = {}) {
  setFont(c, F.hero, 800, lay.size, { tracking: 0 });
  c.letterSpacing = '0px';
  c.save();
  c.translate(W / 2, H / 2);
  c.scale(scale, scale);
  c.translate(-W / 2, -H / 2);
  lay.lines.forEach((ln, li) => {
    for (let i = 0; i < ln.text.length; i++) {
      if (skipO && li === 0 && i === 0) continue;
      if (fill) {
        c.fillStyle = fill;
        c.fillText(ln.text[i], ln.x + ln.xs[i], ln.y);
      }
      if (stroke) {
        c.strokeStyle = stroke;
        c.lineWidth = lw;
        c.strokeText(ln.text[i], ln.x + ln.xs[i], ln.y);
      }
    }
  });
  c.restore();
}

function outlineWords(c, lay, scale, color, lw) {
  c.save();
  c.translate(W / 2, H / 2);
  c.scale(scale, scale);
  c.translate(-W / 2, -H / 2);
  for (const ln of lay.lines) {
    drawOutline(c, ln.text, ln.x, ln.y, { family: F.hero, size: lay.size, lw, color, tracking: -lay.size * 0.02 });
  }
  c.restore();
}

const CUTS = [
  { draw: (L2, fi) => scene1(L2, 1.25, fi), z: 1.35, px: 1335, py: 548 },
  { draw: (L2, fi) => scene2(L2, 1.5, fi), z: 1.5, px: 1500, py: 470 },
  { draw: (L2, fi) => scene3(L2, 1.3, fi), z: 1.4, px: 1410, py: 468 },
  { draw: (L2, fi) => scene4(L2, 1.3, fi), z: 1.5, px: 1381, py: 700 },
  { draw: (L2, fi) => scene5(L2, 1.3, fi), z: 1.45, px: 1174, py: 498 },
  { solid: C.blue },
];

function maskMontage(L, u, fi) {
  const { m, g } = L;
  const v = u - PART_B;
  const k = clamp(Math.floor(v / SIXTEENTH), 0, CUTS.length - 1);
  const cv = v - k * SIXTEENTH;
  const lay = lettersLayout(m);
  const grow = lerp(1, 1.06, prog(v, 0, PART_C - PART_B));
  m.fillStyle = '#04060c';
  m.fillRect(0, 0, W, H);
  const cut = CUTS[k];
  const O = off();
  const L2 = O.L;
  L2.reset();
  if (cut.solid) {
    L2.m.fillStyle = cut.solid;
    L2.m.fillRect(0, 0, W, H);
  } else {
    const z = cut.z * lerp(1, 1.1, cv / SIXTEENTH);
    L2.save();
    L2.translate(W / 2, H / 2);
    L2.scale(z, z);
    L2.translate(-cut.px, -cut.py);
    cut.draw(L2, fi);
    L2.restore();
    // cool duotone wash keeps the recap on-brand
    L2.m.save();
    L2.m.setTransform(1, 0, 0, 1, 0, 0);
    L2.m.globalCompositeOperation = 'color';
    L2.m.fillStyle = k % 2 ? 'rgba(59,130,246,0.55)' : 'rgba(96,165,250,0.35)';
    L2.m.fillRect(0, 0, W, H);
    L2.m.restore();
  }
  // mask main + glow by the letters
  const mk = O.mask;
  mk.setTransform(1, 0, 0, 1, 0, 0);
  mk.clearRect(0, 0, W, H);
  drawLetters(mk, lay, { scale: grow });
  const mg = O.maskG;
  mg.setTransform(1, 0, 0, 1, 0, 0);
  mg.clearRect(0, 0, W / 2, H / 2);
  mg.setTransform(0.5, 0, 0, 0.5, 0, 0);
  drawLetters(mg, lay, { scale: grow });
  for (const [c, mask] of [
    [L2.m, mk],
    [L2.g, mg],
  ]) {
    c.save();
    c.setTransform(1, 0, 0, 1, 0, 0);
    c.globalCompositeOperation = 'destination-in';
    c.drawImage(mask.canvas, 0, 0);
    c.restore();
  }
  m.save();
  m.setTransform(1, 0, 0, 1, 0, 0);
  m.drawImage(L2.m.canvas, 0, 0);
  m.restore();
  g.save();
  g.setTransform(1, 0, 0, 1, 0, 0);
  g.drawImage(L2.g.canvas, 0, 0);
  g.restore();
  outlineWords(m, lay, grow, 'rgba(232,238,248,0.6)', 2);
  outlineWords(g, lay, grow, C.blue, 5);
  // cut counter
  setFont(m, F.mono, 600, 15, { tracking: 4 });
  drawText(m, `RECAP ${String(k + 1).padStart(2, '0')}/06`, 120, 150, { color: C.soft });
}

function morph(L, u, fi) {
  const { m, g } = L;
  const p = prog(u, PART_C, END);
  const lay = lettersLayout(m);
  const grow = 1.06;
  const geo = oGeometry(lay);
  const logo = logoLayout(m);
  m.fillStyle = '#04060c';
  m.fillRect(0, 0, W, H);
  // letters scatter outward from the O
  const e = ease.inCubic(p);
  setFont(m, F.hero, 800, lay.size, { tracking: 0 });
  m.letterSpacing = '0px';
  lay.lines.forEach((ln, li) => {
    for (let i = 0; i < ln.text.length; i++) {
      if (li === 0 && i === 0) continue;
      const cw = m.measureText(ln.text[i]).width;
      const lx = W / 2 + (ln.x + ln.xs[i] + cw / 2 - W / 2) * grow;
      const ly = H / 2 + (ln.y - lay.size * 0.36 - H / 2) * grow;
      const dx = lx - geo.cx;
      const dy = ly - geo.cy;
      const d = Math.hypot(dx, dy) || 1;
      const s = grow * lerp(1, 1.7, e);
      m.save();
      m.globalAlpha = 1 - ease.inQuad(p);
      m.translate(lx + (dx / d) * 1100 * e, ly + (dy / d) * 700 * e);
      m.scale(s, s);
      m.fillStyle = C.blue;
      m.fillText(ln.text[i], -cw / 2, lay.size * 0.36);
      m.restore();
    }
  });
  // the O becomes the ring
  const q = ease.inOutCubic(p);
  const gx = W / 2 + (geo.cx - W / 2) * grow;
  const gy = H / 2 + (geo.cy - H / 2) * grow;
  const x = lerp(gx, logo.mx, q);
  const y = lerp(gy, logo.my, q);
  const rx = lerp(geo.rx * grow, MARK_R, q);
  const ry = lerp(geo.ry * grow, MARK_R, q);
  const th = lerp(geo.th * grow, RING_W, q);
  L.both((c, glow) => {
    c.save();
    if (glow) c.globalAlpha = 0.5 + 0.5 * q;
    drawRing(c, x, y, rx, ry, glow ? th * 1.6 : th, C.blue);
    c.restore();
  });
}

export function scene7(L, u, fi) {
  if (u < PART_B) slams(L, u, fi);
  else if (u < PART_C) maskMontage(L, u, fi);
  else morph(L, u, fi);
}
