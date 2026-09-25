// 04 PROVE: an AI-proposed candidate becomes a verified finding only through deterministic,
// two-principal replay evidence.
import {
  W, H, C, F, TAU, BEAT, EIGHTH, SIXTEENTH,
  clamp, lerp, prog, ep, ease, setFont, drawText, rrect, circle, spring, decay, typed, scramble,
} from '../lib.js';
import { column, dotGrid, ambient, baseFill, ghostWord, COL, pushIn } from '../common.js';

export const CARD = { x: 960, y: 172, w: 842, h: 252 };
const PANEL_Y = 470;
const PANEL_H = 300;
const PANELS = [
  { x: 960, who: 'A', name: 'Principal A', role: 'owner', col: C.blueL, t: 0.02 },
  { x: 1402, who: 'B', name: 'Principal B', role: 'different user', col: C.high, t: 0.1 },
];
const PW = 400;
const VERIFY_AT = BEAT * 2;
const JSON_LINES = ['{', '  "id": 1042,', '  "owner": "alice@acme.test",', '  "total": "$84.10"', '}'];
const MATCH = [1, 2];

function chip(m, g, u, x, y) {
  // right-aligned status chip; returns nothing
  let label;
  let fg;
  let bgc;
  let border;
  let dashed = false;
  if (u < BEAT) {
    label = 'AI CANDIDATE';
    fg = C.amber;
    bgc = 'rgba(245,158,11,0.1)';
    border = 'rgba(245,158,11,0.7)';
    dashed = true;
  } else if (u < VERIFY_AT) {
    label = 'VERIFYING';
    fg = C.blueXL;
    bgc = 'rgba(59,130,246,0.14)';
    border = 'rgba(96,165,250,0.7)';
  } else {
    label = 'VERIFIED';
    fg = '#bbf7d0';
    bgc = 'rgba(16,185,129,0.28)';
    border = 'rgba(52,211,153,0.95)';
  }
  const stateT = u < BEAT ? 0 : u < VERIFY_AT ? BEAT : VERIFY_AT;
  const pop = stateT > 0 ? 1 + 0.35 * decay(u - stateT, 9) * (stateT === VERIFY_AT ? 1.6 : 0.6) : 1;
  setFont(m, F.mono, 700, 15, { tracking: 2.2 });
  const tw = m.measureText(label).width;
  const w = tw + 58;
  const h = 36;
  m.save();
  m.translate(x - w / 2, y);
  m.scale(pop, pop);
  m.translate(-w / 2, -h / 2);
  m.fillStyle = bgc;
  rrect(m, 0, 0, w, h, 18);
  m.fill();
  if (dashed) m.setLineDash([5, 4]);
  m.strokeStyle = border;
  m.lineWidth = 1.5;
  m.stroke();
  m.setLineDash([]);
  // icon
  const ix = 22;
  const iy = h / 2;
  if (u < BEAT) {
    m.fillStyle = C.amber;
    m.beginPath();
    for (let k = 0; k < 8; k++) {
      const a = (k / 8) * TAU;
      const r = k % 2 ? 2.2 : 7;
      m.lineTo(ix + Math.cos(a) * r, iy + Math.sin(a) * r);
    }
    m.closePath();
    m.fill();
  } else if (u < VERIFY_AT) {
    m.strokeStyle = C.blueXL;
    m.lineWidth = 2.2;
    m.beginPath();
    m.arc(ix, iy, 6.5, u * 14, u * 14 + 4.2);
    m.stroke();
  } else {
    m.strokeStyle = '#6ee7b7';
    m.lineWidth = 2.6;
    m.lineCap = 'round';
    m.beginPath();
    m.moveTo(ix - 6, iy + 0.5);
    m.lineTo(ix - 1.5, iy + 5);
    m.lineTo(ix + 7, iy - 5);
    m.stroke();
  }
  drawText(m, label, 40, iy + 5.5, { color: fg });
  m.restore();
  if (u >= VERIFY_AT) {
    g.save();
    g.globalAlpha = 0.45 + 0.55 * decay(u - VERIFY_AT, 5);
    g.fillStyle = C.okD;
    rrect(g, x - w, y - h / 2, w, h, 18);
    g.fill();
    g.restore();
  }
}

export function drawFindingCard(L, u, fi, rect = CARD) {
  const { m, g } = L;
  const { x, y, w, h } = rect;
  m.save();
  m.shadowColor = 'rgba(0,0,0,0.5)';
  m.shadowBlur = 50;
  m.shadowOffsetY = 20;
  m.fillStyle = C.panelHi;
  rrect(m, x, y, w, h, 16);
  m.fill();
  m.restore();
  m.save();
  const verified = u >= VERIFY_AT;
  m.strokeStyle = verified ? 'rgba(52,211,153,0.45)' : 'rgba(148,163,184,0.2)';
  m.lineWidth = 1.5;
  rrect(m, x, y, w, h, 16);
  m.stroke();
  // severity rail
  m.fillStyle = C.high;
  m.beginPath();
  m.roundRect(x, y, 6, h, [16, 0, 0, 16]);
  m.fill();
  g.save();
  g.fillStyle = C.high;
  g.globalAlpha = 0.6;
  g.fillRect(x, y + 10, 6, h - 20);
  g.restore();
  // badges
  let bx = x + 36;
  const by = y + 34;
  setFont(m, F.mono, 700, 13.5, { tracking: 1.8 });
  [
    ['HIGH', C.high, 'rgba(249,115,22,0.18)'],
    ['BOLA', C.soft, 'rgba(148,163,184,0.12)'],
    ['CWE-639', C.soft, 'rgba(148,163,184,0.12)'],
  ].forEach(([t, fg, bgc]) => {
    const tw = m.measureText(t).width + 24;
    m.fillStyle = bgc;
    rrect(m, bx, by - 14, tw, 28, 7);
    m.fill();
    drawText(m, t, bx + 12, by + 5, { color: fg });
    bx += tw + 10;
  });
  chip(m, g, u, x + w - 30, by);
  setFont(m, F.sans, 600, 37, { tracking: -0.8 });
  drawText(m, 'Broken object-level authorization', x + 36, y + 110, { color: C.ink });
  setFont(m, F.mono, 400, 19, { tracking: 0 });
  const ew = drawText(m, 'GET /api/v2/orders/{id}', x + 36, y + 150, { color: C.soft });
  drawText(m, '·  app.acme.test', x + 36 + ew + 14, y + 150, { color: C.dimmer });
  m.fillStyle = 'rgba(148,163,184,0.12)';
  m.fillRect(x + 36, y + 180, w - 72, 1);
  setFont(m, F.mono, 500, 13.5, { tracking: 1.6 });
  const evA = ep(u, VERIFY_AT + 0.05, VERIFY_AT + 0.35);
  const ev = [
    ['EVIDENCE', verified ? 'sha256:7c41…e09b' : 'pending'],
    ['PRINCIPALS', '2 distinct'],
    ['PROOF', verified ? 'deterministic replay' : '—'],
  ];
  let ex = x + 36;
  ev.forEach(([k, v]) => {
    const kw = drawText(m, k, ex, y + 220, { color: C.dimmer });
    const val = verified ? scramble(v, evA, fi, k.length) : v;
    const vw = drawText(m, val, ex + kw + 12, y + 220, { color: verified ? '#a7f3d0' : C.dim });
    ex += kw + vw + 44;
  });
  m.restore();
}

function panels(L, u, fi, exit) {
  const { m, g } = L;
  const hl = ep(u, BEAT + EIGHTH, BEAT + EIGHTH + 0.3, ease.inOutCubic);
  PANELS.forEach((p, idx) => {
    const a = ep(u, p.t - 0.15, p.t + 0.3);
    if (a <= 0) return;
    const ex = exit ? ep(u, exit + idx * 0.03, exit + idx * 0.03 + 0.28, ease.inBack) : 0;
    m.save();
    m.globalAlpha = a * (1 - ex);
    m.translate(0, (1 - a) * 60 + ex * 260);
    const x = p.x;
    const y = PANEL_Y;
    m.fillStyle = C.panel;
    rrect(m, x, y, PW, PANEL_H, 14);
    m.fill();
    m.strokeStyle = 'rgba(148,163,184,0.18)';
    m.lineWidth = 1;
    m.stroke();
    // header
    m.fillStyle = p.col + '33';
    circle(m, x + 34, y + 36, 17);
    m.fill();
    m.strokeStyle = p.col;
    m.lineWidth = 1.5;
    m.stroke();
    setFont(m, F.sans, 700, 16, { tracking: 0 });
    drawText(m, p.who, x + 34, y + 42, { color: p.col, align: 'center' });
    setFont(m, F.sans, 600, 20, { tracking: -0.2 });
    const nw = drawText(m, p.name, x + 62, y + 43, { color: C.ink });
    setFont(m, F.mono, 400, 14, { tracking: 0.5 });
    drawText(m, p.role, x + 62 + nw + 10, y + 43, { color: C.dim });
    m.fillStyle = 'rgba(148,163,184,0.12)';
    m.fillRect(x, y + 70, PW, 1);
    // request
    setFont(m, F.mono, 700, 13, { tracking: 1 });
    m.fillStyle = 'rgba(96,165,250,0.16)';
    rrect(m, x + 20, y + 88, 50, 24, 6);
    m.fill();
    drawText(m, 'GET', x + 45, y + 105, { color: C.blueL, align: 'center' });
    setFont(m, F.mono, 400, 16.5, { tracking: 0 });
    drawText(m, typed('/api/v2/orders/1042', prog(u, p.t + 0.02, p.t + 0.24)), x + 82, y + 106, { color: C.ink });
    // response
    const ra = ep(u, p.t + 0.3, p.t + 0.45);
    if (ra > 0) {
      m.save();
      m.globalAlpha *= ra;
      setFont(m, F.mono, 700, 15.5, { tracking: 0.5 });
      const sw = drawText(m, '200 OK', x + 20, y + 146, { color: '#4ade80' });
      setFont(m, F.mono, 400, 14.5, { tracking: 0 });
      drawText(m, '· application/json · 1.2 kB', x + 20 + sw + 10, y + 146, { color: C.dimmer });
      m.restore();
    }
    // json body
    setFont(m, F.mono, 400, 16, { tracking: 0 });
    JSON_LINES.forEach((ln, li) => {
      const la = ep(u, p.t + 0.34 + li * 0.03, p.t + 0.5 + li * 0.03);
      if (la <= 0) return;
      const ly = y + 184 + li * 25;
      if (MATCH.includes(li) && hl > 0) {
        m.save();
        m.fillStyle = 'rgba(249,115,22,0.18)';
        m.fillRect(x + 14, ly - 18, (PW - 28) * hl, 24);
        m.fillStyle = C.high;
        m.fillRect(x + 14, ly - 18, 3, 24 * clamp(hl * 3));
        m.restore();
      }
      m.save();
      m.globalAlpha *= la;
      const [k, v] = ln.includes(':') ? [ln.slice(0, ln.indexOf(':') + 1), ln.slice(ln.indexOf(':') + 1)] : [ln, ''];
      const kw = drawText(m, k, x + 26, ly, { color: C.soft });
      drawText(m, v, x + 26 + kw, ly, { color: MATCH.includes(li) && hl > 0.5 ? '#fdba74' : '#cbd5e1' });
      m.restore();
    });
    m.restore();
  });
  // equality badges between the panels
  MATCH.forEach((li, k) => {
    const t0 = BEAT + EIGHTH + 0.12 + k * 0.06;
    const pa = ep(u, t0, t0 + 0.25, (t) => ease.outBack(t, 2.4));
    if (pa <= 0) return;
    const ex = exit ? ep(u, exit, exit + 0.2) : 0;
    const cx = 1381;
    const cy = PANEL_Y + 184 + li * 25 - 6;
    m.save();
    m.globalAlpha = 1 - ex;
    m.translate(cx, cy);
    m.scale(pa, pa);
    m.fillStyle = C.high;
    circle(m, 0, 0, 13);
    m.fill();
    m.fillStyle = '#0b1220';
    m.fillRect(-6, -4.5, 12, 2.6);
    m.fillRect(-6, 1.9, 12, 2.6);
    m.restore();
    g.save();
    g.globalAlpha = 0.7 * (1 - ex);
    g.fillStyle = C.high;
    circle(g, cx, cy, 16 * pa);
    g.fill();
    g.restore();
  });
  // caption over the panels
  setFont(m, F.mono, 500, 12.5, { tracking: 2.5 });
  const ca = ep(u, 0.1, 0.4) * (exit ? 1 - ep(u, exit, exit + 0.15) : 1);
  drawText(m, 'DIFFERENTIAL REPLAY  ·  SAME OBJECT, TWO PRINCIPALS', 960, PANEL_Y - 16, { color: C.dim, alpha: ca });
}

function stamp(L, u, exit) {
  const { m, g } = L;
  const t0 = VERIFY_AT - 0.1;
  const p = prog(u, t0, VERIFY_AT);
  if (p <= 0) return;
  const s = lerp(2.6, 1, ease.inQuad(p));
  const settle = u > VERIFY_AT ? 1 + 0.06 * Math.sin((u - VERIFY_AT) * 40) * decay(u - VERIFY_AT, 12) : 1;
  const ex = exit ? ep(u, exit + 0.05, exit + 0.3, ease.inBack) : 0;
  const cx = 1381;
  const cy = PANEL_Y + PANEL_H + 6;
  m.save();
  m.globalAlpha = clamp(p * 1.6) * (1 - ex);
  m.translate(cx, cy + ex * 300);
  m.rotate(-0.12);
  m.scale(s * settle, s * settle);
  setFont(m, F.hero, 800, 54, { tracking: 2 });
  const word = 'VERIFIED';
  const tw = m.measureText(word).width;
  const bw = tw + 70;
  const bh = 118;
  m.fillStyle = 'rgba(4,20,16,0.9)';
  rrect(m, -bw / 2, -bh / 2, bw, bh, 14);
  m.fill();
  m.strokeStyle = C.ok;
  m.lineWidth = 4;
  rrect(m, -bw / 2, -bh / 2, bw, bh, 14);
  m.stroke();
  m.lineWidth = 1.5;
  rrect(m, -bw / 2 + 8, -bh / 2 + 8, bw - 16, bh - 16, 9);
  m.stroke();
  drawText(m, word, 0, 12, { color: '#6ee7b7', align: 'center' });
  setFont(m, F.mono, 600, 13.5, { tracking: 4 });
  drawText(m, 'DETERMINISTIC PROOF', 0, 40, { color: '#6ee7b7', align: 'center' });
  m.restore();
  g.save();
  g.globalAlpha = clamp(p * 1.6) * (1 - ex) * (0.55 + 0.45 * decay(u - VERIFY_AT, 4));
  g.translate(cx, cy + ex * 300);
  g.rotate(-0.12);
  g.scale(s * settle, s * settle);
  g.strokeStyle = C.okD;
  g.lineWidth = 10;
  rrect(g, -bw / 2, -bh / 2, bw, bh, 14);
  g.stroke();
  g.restore();
  // shockwave at impact
  const sw = prog(u, VERIFY_AT, VERIFY_AT + 0.45);
  if (sw > 0 && sw < 1) {
    L.both((c, glow) => {
      c.save();
      c.globalAlpha = (1 - sw) * (glow ? 0.9 : 0.6);
      c.strokeStyle = glow ? C.okD : C.ok;
      c.lineWidth = (glow ? 10 : 3) * (1 - sw);
      c.beginPath();
      c.ellipse(cx, cy, 40 + ease.outCubic(sw) * 420, 20 + ease.outCubic(sw) * 210, -0.12, 0, TAU);
      c.stroke();
      c.restore();
    });
  }
}

function stateRail(L, u, exit) {
  const m = L.m;
  const x = COL.x;
  const y = COL.extra + 20;
  const steps = [
    ['candidate', C.amber, 0],
    ['verifying', C.blueL, BEAT],
    ['verified', C.ok, VERIFY_AT],
  ];
  const a = ep(u, 0.3, 0.6) * (exit ? 1 - ep(u, exit, exit + 0.2) : 1);
  if (a <= 0) return;
  m.save();
  m.globalAlpha = a;
  m.fillStyle = 'rgba(148,163,184,0.2)';
  m.fillRect(x + 8, y - 1, 440, 2);
  const fillTo = clamp((u - 0.0) / VERIFY_AT);
  m.fillStyle = C.blueL;
  m.fillRect(x + 8, y - 1, 440 * ease.inOutCubic(fillTo), 2);
  setFont(m, F.mono, 500, 15, { tracking: 1 });
  steps.forEach(([label, col, t], i) => {
    const sx = x + 8 + i * 220;
    const on = u >= t;
    const pop = on ? 1 + 0.5 * decay(u - t, 10) : 1;
    m.fillStyle = on ? col : C.bg;
    m.strokeStyle = on ? col : 'rgba(148,163,184,0.5)';
    m.lineWidth = 2;
    circle(m, sx, y, 7 * pop);
    m.fill();
    m.stroke();
    drawText(m, label, sx, y + 34, { color: on ? col : C.dimmer, align: i === 0 ? 'left' : 'center' });
  });
  m.restore();
}

export function scene4(L, u, fi, { bg = true, flip = 0, exit = null } = {}) {
  if (bg) {
    baseFill(L);
    ambient(L, 1381, 470, 1000);
    dotGrid(L, u);
  }
  L.save();
  pushIn(L, u);
  ghostWord(L, 'PROVE', -60, H + 140, 700, 0.06);
  panels(L, u, fi, exit);
  // finding card, optionally mid-flip (0 .. PI/2)
  if (flip < Math.PI / 2) {
    const a = ep(u, -0.25, 0.15);
    const cx = CARD.x + CARD.w / 2;
    const cy = CARD.y + CARD.h / 2;
    L.save();
    L.alpha(a);
    L.translate(cx, cy + (1 - a) * -40);
    L.scale(Math.max(0.001, Math.cos(flip)), 1);
    L.translate(-cx, -cy);
    drawFindingCard(L, u, fi);
    if (flip > 0) {
      L.m.fillStyle = `rgba(0,0,0,${0.55 * Math.sin(flip)})`;
      rrect(L.m, CARD.x, CARD.y, CARD.w, CARD.h, 16);
      L.m.fill();
    }
    L.restore();
  }
  stamp(L, u, exit);
  column(L, u, fi, {
    label: '04 — DETERMINISTIC PROOF',
    labelIn: 0.0,
    hero: 'PROVE',
    heroIn: -0.02,
    heroMode: 'drop',
    heroStagger: 0.045,
    heroDur: 0.5,
    heroFn: (t) => ease.outBack(t, 1.4),
    heroMask: false,
    desc: ['AI proposes candidates. Only deterministic', 'proof marks a finding verified.'],
    descIn: 0.2,
    exit,
  });
  stateRail(L, u, exit);
  L.restore();
}
