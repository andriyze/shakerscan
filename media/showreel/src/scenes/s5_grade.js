// 05 GRADE: the finding card flips into the scan report. Observed risk (A-F) and assurance are
// separate axes and are never blended.
import {
  W, H, C, F, TAU, BEAT, EIGHTH, SIXTEENTH,
  clamp, lerp, prog, ep, ease, setFont, drawText, rrect, circle, spring, decay, hash,
} from '../lib.js';
import { column, dotGrid, ambient, baseFill, ghostWord, COL, pushIn } from '../common.js';
import { CARD } from './s4_prove.js';

export const REPORT = { x: 960, y: 206, w: 842, h: 650 };
const LAND = BEAT * 2; // grade lands on beat 2
const SCORE = 84;
const GRADES = ['F', 'D', 'C', 'B', 'A'];
const BANDS = ['none', 'weak', 'limited', 'adequate', 'strong'];
const SEVS = [
  ['critical', C.crit, 1],
  ['high', C.high, 3],
  ['medium', C.med, 5],
  ['low', C.low, 8],
  ['info', C.info, 12],
];

export function reportRect(u) {
  const p = ep(u, -0.12, 0.42, ease.outExpo);
  return {
    x: lerp(CARD.x, REPORT.x, p),
    y: lerp(CARD.y, REPORT.y, p),
    w: lerp(CARD.w, REPORT.w, p),
    h: lerp(CARD.h, REPORT.h, p),
  };
}

function gauge(L, u, fi, cx, cy) {
  const { m, g } = L;
  const r = 138;
  const a0 = Math.PI * 0.75;
  const sweep = Math.PI * 1.5;
  const v = SCORE * ep(u, 0.12, LAND, ease.outCubic);
  // ticks
  for (let i = 0; i <= 50; i++) {
    const a = a0 + (i / 50) * sweep;
    const major = i % 10 === 0;
    const lit = i / 50 <= v / 100;
    m.strokeStyle = lit ? (major ? '#bfdbfe' : 'rgba(147,197,253,0.7)') : 'rgba(148,163,184,0.2)';
    m.lineWidth = major ? 2 : 1;
    const r0 = r + 22;
    const r1 = r + (major ? 34 : 29);
    m.beginPath();
    m.moveTo(cx + Math.cos(a) * r0, cy + Math.sin(a) * r0);
    m.lineTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
    m.stroke();
  }
  m.lineCap = 'round';
  m.strokeStyle = 'rgba(148,163,184,0.16)';
  m.lineWidth = 16;
  m.beginPath();
  m.arc(cx, cy, r, a0, a0 + sweep);
  m.stroke();
  const end = a0 + (sweep * v) / 100;
  if (v > 0.5) {
    const grad = m.createConicGradient(a0 - 0.2, cx, cy);
    grad.addColorStop(0, C.blue);
    grad.addColorStop(0.75, C.blueXL);
    grad.addColorStop(1, C.blue);
    m.strokeStyle = grad;
    m.beginPath();
    m.arc(cx, cy, r, a0, end);
    m.stroke();
    g.save();
    g.lineCap = 'round';
    g.strokeStyle = C.blue;
    g.lineWidth = 22;
    g.globalAlpha = 0.7;
    g.beginPath();
    g.arc(cx, cy, r, a0, end);
    g.stroke();
    g.restore();
    // head
    m.fillStyle = '#ffffff';
    circle(m, cx + Math.cos(end) * r, cy + Math.sin(end) * r, 5);
    m.fill();
  }
  m.lineCap = 'butt';
  // slot reel: decelerates through ~20 letters and lands on B exactly on the beat
  const landed = u >= LAND;
  const P_LAND = 23; // 23 % 5 -> 'B'
  const pos = landed ? P_LAND : P_LAND - 22 * Math.pow(1 - prog(u, 0.12, LAND), 2);
  const idx = Math.floor(pos);
  const frac = pos - idx;
  const punch = landed ? 1 + 0.26 * decay(u - LAND, 9) : 1;
  const SP = 150;
  setFont(m, F.hero, 800, 124, { tracking: 0 });
  m.save();
  m.translate(cx, cy + 6);
  m.scale(punch, punch);
  m.beginPath();
  m.rect(-110, -112, 220, 162);
  m.clip();
  for (let j = -1; j <= 1; j++) {
    const letter = GRADES[(((idx + j) % 5) + 5) % 5];
    const y = 42 + (frac - j) * SP;
    const edge = clamp(1 - Math.abs(y - 42) / SP);
    drawText(m, letter, 0, y, { color: landed ? '#ffffff' : C.ink, align: 'center', alpha: 0.35 + 0.65 * edge });
  }
  m.restore();
  if (landed) {
    g.save();
    g.globalAlpha = 0.35 * decay(u - LAND, 3) + 0.12;
    setFont(g, F.hero, 800, 124, { tracking: 0 });
    g.translate(cx, cy + 6);
    g.scale(punch, punch);
    drawText(g, 'B', 0, 42, { color: C.blueL, align: 'center' });
    g.restore();
  }
  setFont(m, F.mono, 500, 17, { tracking: 1 });
  drawText(m, `${Math.round(v)} / 100`, cx, cy + 98, { color: C.soft, align: 'center' });
}

function assurance(L, u, x, y) {
  const { m, g } = L;
  setFont(m, F.mono, 500, 12.5, { tracking: 2.5 });
  drawText(m, 'ASSURANCE', x, y, { color: C.dim });
  const n = 4; // lands on "adequate"
  const segW = 60;
  const gap = 6;
  const sy = y + 28;
  BANDS.forEach((b, i) => {
    const t = BEAT + i * SIXTEENTH;
    const on = i < n && u >= t;
    const pop = on ? ep(u, t, t + 0.18, (q) => ease.outBack(q, 2)) : 0;
    const sx = x + i * (segW + gap);
    m.fillStyle = 'rgba(148,163,184,0.14)';
    rrect(m, sx, sy, segW, 14, 4);
    m.fill();
    if (on) {
      m.save();
      m.translate(sx + segW / 2, sy + 7);
      m.scale(1, pop);
      m.fillStyle = i === n - 1 ? C.blueXL : C.blueL;
      rrect(m, -segW / 2, -7, segW, 14, 4);
      m.fill();
      m.restore();
      g.save();
      g.globalAlpha = 0.5;
      g.fillStyle = C.blue;
      g.fillRect(sx, sy, segW, 14);
      g.restore();
    }
    setFont(m, F.mono, 400, 11.5, { tracking: 0.5 });
    drawText(m, b, sx + segW / 2, sy + 34, { color: on ? C.soft : C.dimmer, align: 'center' });
  });
  const la = ep(u, LAND, LAND + 0.3);
  setFont(m, F.sans, 700, 40, { tracking: -1 });
  const aw = drawText(m, 'Adequate', x, y + 116, { color: C.ink, alpha: la });
  setFont(m, F.mono, 500, 16, { tracking: 1 });
  drawText(m, `${Math.round(71 * ep(u, BEAT, LAND + 0.2, ease.outCubic))} / 100`, x + aw + 16, y + 114, { color: C.soft, alpha: la });
  const checks = [
    ['authenticated coverage', true],
    ['two principals compared', true],
    ['14 proof attempts', true],
    ['browser crawl partial', false],
  ];
  setFont(m, F.sans, 400, 18, { tracking: 0 });
  checks.forEach(([t, ok], i) => {
    const ct = LAND + 0.05 + i * SIXTEENTH * 0.8;
    const a = ep(u, ct, ct + 0.25);
    if (a <= 0) return;
    const cy = y + 162 + i * 32;
    m.save();
    m.globalAlpha = a;
    m.translate((1 - a) * 20, 0);
    if (ok) {
      m.strokeStyle = C.ok;
      m.lineWidth = 2;
      m.lineCap = 'round';
      m.beginPath();
      m.moveTo(x, cy - 5);
      m.lineTo(x + 4.5, cy);
      m.lineTo(x + 12, cy - 10);
      m.stroke();
    } else {
      m.fillStyle = C.amber;
      m.fillRect(x, cy - 6, 12, 2.5);
    }
    drawText(m, t, x + 24, cy, { color: ok ? '#cbd5e1' : C.amber });
    m.restore();
  });
}

function severityBar(L, u, x, y, w) {
  const { m, g } = L;
  setFont(m, F.mono, 500, 12.5, { tracking: 2.5 });
  drawText(m, 'FINDINGS BY SEVERITY', x, y, { color: C.dim });
  const total = SEVS.reduce((s, [, , n]) => s + n, 0);
  let cx = x;
  const by = y + 20;
  SEVS.forEach(([name, col, n], i) => {
    const t = BEAT + EIGHTH + i * SIXTEENTH * 0.7;
    const p = ep(u, t, t + 0.35, ease.outExpo);
    const sw = ((w - 4 * 4) * n) / total;
    if (p > 0) {
      m.fillStyle = col;
      rrect(m, cx, by, Math.max(0.1, sw * p), 16, 4);
      m.fill();
      if (i < 2) {
        g.save();
        g.globalAlpha = 0.5;
        g.fillStyle = col;
        g.fillRect(cx, by, sw * p, 16);
        g.restore();
      }
    }
    // legend
    const la = ep(u, t + 0.1, t + 0.4);
    setFont(m, F.mono, 400, 13.5, { tracking: 0.5 });
    m.save();
    m.globalAlpha = la;
    m.fillStyle = col;
    circle(m, x + i * 152 + 5, by + 44, 4.5);
    m.fill();
    drawText(m, `${name} ${Math.round(n * la)}`, x + i * 152 + 16, by + 49, { color: C.soft });
    m.restore();
    cx += sw + 4;
  });
}

export function drawReport(L, u, fi, rect) {
  const { m } = L;
  const { x, y, w, h } = rect;
  m.save();
  m.shadowColor = 'rgba(0,0,0,0.5)';
  m.shadowBlur = 60;
  m.shadowOffsetY = 24;
  m.fillStyle = C.panelHi;
  rrect(m, x, y, w, h, 18);
  m.fill();
  m.restore();
  m.save();
  m.strokeStyle = 'rgba(96,165,250,0.3)';
  m.lineWidth = 1.5;
  rrect(m, x, y, w, h, 18);
  m.stroke();
  const ca = ep(u, -0.3, -0.12);
  if (ca > 0) {
    m.beginPath();
    m.rect(x, y, w, h);
    m.clip();
    m.globalAlpha = ca;
    setFont(m, F.sans, 600, 24, { tracking: -0.3 });
    const tw = drawText(m, 'Scan report', x + 36, y + 52, { color: C.ink });
    setFont(m, F.mono, 400, 16, { tracking: 0 });
    drawText(m, '·  app.acme.test', x + 36 + tw + 12, y + 51, { color: C.dim });
    setFont(m, F.mono, 500, 12.5, { tracking: 1 });
    const pill = 'risk_and_assurance/v8';
    const pw = m.measureText(pill).width + 24;
    m.fillStyle = 'rgba(148,163,184,0.1)';
    rrect(m, x + w - 36 - pw, y + 32, pw, 28, 7);
    m.fill();
    drawText(m, pill, x + w - 36 - pw + 12, y + 51, { color: C.dim });
    m.fillStyle = 'rgba(148,163,184,0.12)';
    m.fillRect(x + 36, y + 82, w - 72, 1);
    setFont(m, F.mono, 500, 12.5, { tracking: 2.5 });
    drawText(m, 'OBSERVED RISK', x + 36, y + 122, { color: C.dim });
    gauge(L, u, fi, x + 214, y + 292);
    // divider between axes
    m.fillStyle = 'rgba(148,163,184,0.12)';
    m.fillRect(x + 432, y + 108, 1, 360);
    setFont(m, F.serif, 400, 25, { italic: true, tracking: 0 });
    drawText(m, 'never blended', x + 432, y + 494, { color: C.blueXL, align: 'center', alpha: ep(u, LAND + 0.2, LAND + 0.5) });
    assurance(L, u, x + 478, y + 122);
    severityBar(L, u, x + 36, y + 552, w - 72);
  }
  m.restore();
}

export function scene5(L, u, fi, { bg = true, flip = Math.PI, exit = null } = {}) {
  if (bg) {
    baseFill(L);
    ambient(L, 1381, 530, 1000);
    dotGrid(L, u);
  }
  L.save();
  pushIn(L, u);
  if (flip >= Math.PI) ghostWord(L, 'GRADE', -60, H + 140, 700, 0.06 * ep(u, 0.1, 0.5));
  if (flip > Math.PI / 2) {
    const r = reportRect(u);
    const cx = r.x + r.w / 2;
    const cy = r.y + r.h / 2;
    L.save();
    L.translate(cx, cy);
    L.scale(Math.max(0.001, -Math.cos(flip)), 1);
    L.translate(-cx, -cy);
    drawReport(L, u, fi, r);
    if (flip < Math.PI) {
      L.m.fillStyle = `rgba(0,0,0,${0.55 * Math.sin(flip)})`;
      rrect(L.m, r.x, r.y, r.w, r.h, 18);
      L.m.fill();
    }
    L.restore();
  }
  column(L, u, fi, {
    label: '05 — RISK × ASSURANCE',
    labelIn: 0.05,
    hero: 'GRADE',
    heroIn: 0.02,
    heroMode: 'scale',
    heroOrder: 'center',
    heroStagger: 0.04,
    heroDur: 0.45,
    heroMask: false,
    desc: ['Risk graded A–F, assurance scored apart.', 'A shallow scan never reads as clean.'],
    descIn: 0.22,
    exit,
  });
  L.restore();
}
