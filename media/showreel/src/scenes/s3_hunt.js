// 03 HUNT: the ShakerScan compass. An external coding agent plans; the needle swings on the beat to
// each server-advertised capability it invokes while typed budgets reserve and settle.
import {
  W, H, C, F, TAU, BEAT, EIGHTH,
  clamp, lerp, prog, ep, ease, setFont, drawText, rrect, circle, spring, decay, typed, scramble,
  drawNeedle,
} from '../lib.js';
import { column, dotGrid, ambient, baseFill, ghostWord, COL, pushIn } from '../common.js';

export const CC = { x: 1360, y: 478 };
export const NEEDLE_S = 11; // logo units -> px (disc radius = 14 units)
const R_DISC = 14 * NEEDLE_S;
const R_NODE = 318;
const deg = (d) => (d * Math.PI) / 180;

const NODES = [
  { name: 'tls.inspect', a: -140 },
  { name: 'web.crawl', a: -105 },
  { name: 'http.request', a: -70, at: BEAT },
  { name: 'browser.navigate', a: -35, at: BEAT + EIGHTH },
  { name: 'javascript.analyze', a: 0, at: BEAT * 2 },
  { name: 'authz.differential', a: 35, at: BEAT * 2 + EIGHTH },
  { name: 'candidate.verify', a: 70, at: BEAT * 3 },
  { name: 'service.nse_check', a: 105 },
  { name: 'dns.inspect', a: 140 },
];
const SEQ = NODES.filter((n) => n.at != null);
export const LAST_ANGLE = deg(SEQ[SEQ.length - 1].a);

const nodePos = (a, r = R_NODE) => [CC.x + Math.sin(deg(a)) * r, CC.y - Math.cos(deg(a)) * r];

export function needleAngle(u) {
  const first = deg(SEQ[0].a);
  if (u < SEQ[0].at) {
    const p = ease.outCubic(prog(u, -0.25, SEQ[0].at));
    return first - (1 - p) * TAU * 3.25;
  }
  let i = 0;
  for (let k = 1; k < SEQ.length; k++) if (u >= SEQ[k].at) i = k;
  if (i === 0) {
    const x = u - SEQ[0].at;
    return first + 0.14 * Math.exp(-7 * x) * Math.sin(x * 34);
  }
  const s = spring(u - SEQ[i].at, 3.4, 0.36);
  return lerp(deg(SEQ[i - 1].a), deg(SEQ[i].a), s);
}

function compass(L, u) {
  const { m, g } = L;
  const appear = ep(u, -0.25, 0.3, ease.outCubic);
  const ang = needleAngle(u);
  m.save();
  m.globalAlpha = appear;
  // tick ring
  const rot = -u * 0.25;
  for (let i = 0; i < 72; i++) {
    const a = rot + (i / 72) * TAU;
    const major = i % 6 === 0;
    const r0 = 232;
    const r1 = major ? 214 : 224;
    m.strokeStyle = major ? 'rgba(191,219,254,0.7)' : 'rgba(147,197,253,0.3)';
    m.lineWidth = major ? 2 : 1;
    m.beginPath();
    m.moveTo(CC.x + Math.sin(a) * r0, CC.y - Math.cos(a) * r0);
    m.lineTo(CC.x + Math.sin(a) * r1, CC.y - Math.cos(a) * r1);
    m.stroke();
    if (major) {
      setFont(m, F.mono, 500, 11, { tracking: 1 });
      m.save();
      m.translate(CC.x + Math.sin(a) * 252, CC.y - Math.cos(a) * 252);
      m.rotate(a);
      drawText(m, String(i * 5).padStart(3, '0'), 0, 4, { color: C.dimmer, align: 'center' });
      m.restore();
    }
  }
  m.strokeStyle = 'rgba(147,197,253,0.4)';
  m.lineWidth = 1.2;
  circle(m, CC.x, CC.y, 232);
  m.stroke();
  // dashed inner ring
  m.save();
  m.setLineDash([2, 10]);
  m.lineDashOffset = u * 40;
  m.strokeStyle = 'rgba(147,197,253,0.45)';
  circle(m, CC.x, CC.y, 190);
  m.stroke();
  m.restore();
  // lock arc on the outer ring follows the needle
  L.both((c, glow) => {
    c.save();
    c.globalAlpha = appear;
    c.strokeStyle = glow ? C.blue : C.blueXL;
    c.lineWidth = glow ? 8 : 3;
    c.beginPath();
    c.arc(CC.x, CC.y, 232, ang - Math.PI / 2 - 0.13, ang - Math.PI / 2 + 0.13);
    c.stroke();
    c.restore();
  });
  // logo disc
  m.fillStyle = 'rgba(30,41,59,0.92)';
  circle(m, CC.x, CC.y, R_DISC);
  m.fill();
  m.strokeStyle = C.blue;
  m.lineWidth = 3;
  m.stroke();
  g.save();
  g.globalAlpha = appear * 0.55;
  g.strokeStyle = C.blue;
  g.lineWidth = 7;
  circle(g, CC.x, CC.y, R_DISC);
  g.stroke();
  g.restore();
  // needle
  L.save();
  L.translate(CC.x, CC.y);
  L.rotate(ang);
  drawNeedle(m, NEEDLE_S);
  g.save();
  g.globalAlpha = appear * 0.8;
  drawNeedle(g, NEEDLE_S);
  g.restore();
  L.restore();
  m.fillStyle = '#e2e8f0';
  circle(m, CC.x, CC.y, 5);
  m.fill();
  m.restore();
}

function nodes(L, u, fi) {
  const { m, g } = L;
  NODES.forEach((n, i) => {
    const a0 = -0.2 + i * 0.03;
    const ap = ep(u, a0, a0 + 0.45);
    if (ap <= 0) return;
    const [x, y] = nodePos(n.a);
    const invoked = n.at != null && u >= n.at;
    const pulse = invoked ? decay(u - n.at, 6) : 0;
    // spoke: drawn from disc edge to node when invoked
    if (n.at != null) {
      const sp = ep(u, n.at - 0.02, n.at + 0.14, ease.outCubic);
      if (sp > 0) {
        const [sx, sy] = nodePos(n.a, R_DISC + 8);
        const ex = lerp(sx, x, sp);
        const ey = lerp(sy, y, sp);
        L.both((c, glow) => {
          c.save();
          c.strokeStyle = glow ? C.blue : C.blueL;
          c.globalAlpha = glow ? 0.5 + pulse * 0.5 : 0.55 + pulse * 0.45;
          c.lineWidth = glow ? 4 : 1.5;
          c.beginPath();
          c.moveTo(sx, sy);
          c.lineTo(ex, ey);
          c.stroke();
          c.restore();
        });
        // travelling packet
        const tp = prog(u, n.at, n.at + 0.2);
        if (tp > 0 && tp < 1) {
          const px = lerp(sx, x, ease.outCubic(tp));
          const py = lerp(sy, y, ease.outCubic(tp));
          L.both((c, glow) => {
            c.fillStyle = glow ? C.blueL : '#ffffff';
            circle(c, px, py, glow ? 9 : 4);
            c.fill();
          });
        }
      }
    } else {
      m.save();
      m.strokeStyle = 'rgba(148,163,184,0.12)';
      m.setLineDash([2, 6]);
      m.globalAlpha = ap;
      const [sx, sy] = nodePos(n.a, R_DISC + 40);
      m.beginPath();
      m.moveTo(sx, sy);
      m.lineTo(x, y);
      m.stroke();
      m.restore();
    }
    // node
    m.save();
    m.globalAlpha = ap;
    if (pulse > 0.01) {
      m.strokeStyle = C.blueXL;
      m.globalAlpha = ap * pulse;
      m.lineWidth = 1.5;
      circle(m, x, y, 8 + (1 - pulse) * 30);
      m.stroke();
      m.globalAlpha = ap;
    }
    m.fillStyle = invoked ? '#ffffff' : C.bg;
    m.strokeStyle = invoked ? C.blueXL : 'rgba(148,163,184,0.55)';
    m.lineWidth = 1.5;
    circle(m, x, y, invoked ? 6 : 5);
    m.fill();
    m.stroke();
    if (invoked) {
      g.save();
      g.fillStyle = C.blueL;
      g.globalAlpha = 0.6 + 0.4 * pulse;
      circle(g, x, y, 12);
      g.fill();
      g.restore();
    }
    // label chip, placed radially outward
    setFont(m, F.mono, 500, 15, { tracking: 0.2 });
    const tw = m.measureText(n.name).width;
    const sx = Math.sin(deg(n.a));
    const side = sx > 0.2 ? 1 : sx < -0.2 ? -1 : 0;
    const lx = side === 1 ? x + 18 : side === -1 ? x - 18 - tw - 20 : x - (tw + 20) / 2;
    const ly = side === 0 ? (Math.cos(deg(n.a)) > 0 ? y - 38 : y + 16) : y - 14;
    m.fillStyle = invoked ? 'rgba(30,58,138,0.55)' : 'rgba(8,14,28,0.8)';
    rrect(m, lx, ly, tw + 20, 28, 6);
    m.fill();
    m.strokeStyle = invoked ? 'rgba(147,197,253,0.6)' : 'rgba(148,163,184,0.16)';
    m.lineWidth = 1;
    m.stroke();
    const txt = n.at != null && u < n.at + 0.2 && u >= n.at ? scramble(n.name, prog(u, n.at, n.at + 0.2), fi, 70 + i) : n.name;
    drawText(m, txt, lx + 10, ly + 19, { color: invoked ? '#ffffff' : C.dim });
    m.restore();
  });
}

const TERM = [
  { t: 0.42, text: '› hunt started · app.acme.test · scope bound', color: C.soft },
  { t: BEAT + 0.02, text: '› http.request        GET /api/v2/orders/1042  200', color: C.ink },
  { t: BEAT + EIGHTH + 0.02, text: '› browser.navigate    /account  ok', color: C.ink },
  { t: BEAT * 2 + 0.02, text: '› javascript.analyze  app.js → 14 routes', color: C.ink },
  { t: BEAT * 2 + EIGHTH + 0.02, text: '› authz.differential  principal A ⇄ B', color: C.ink },
  { t: BEAT * 3 + 0.02, text: '⚑ candidate recorded — needs deterministic proof', color: C.amber },
];

function terminal(L, u, fi) {
  const m = L.m;
  const x = COL.x;
  const y = COL.extra - 30;
  const w = 760;
  const h = 262;
  const a = ep(u, 0.02, 0.35);
  if (a <= 0) return;
  m.save();
  m.globalAlpha = a;
  m.translate(0, (1 - a) * 24);
  m.fillStyle = 'rgba(7,11,22,0.92)';
  rrect(m, x, y, w, h, 14);
  m.fill();
  m.strokeStyle = 'rgba(148,163,184,0.2)';
  m.lineWidth = 1;
  m.stroke();
  ['#475569', '#475569', '#475569'].forEach((c, i) => {
    m.fillStyle = c;
    circle(m, x + 22 + i * 17, y + 20, 5);
    m.fill();
  });
  setFont(m, F.mono, 500, 12.5, { tracking: 2 });
  drawText(m, 'AGENT SESSION', x + w - 20, y + 25, { color: C.dimmer, align: 'right' });
  m.fillStyle = 'rgba(148,163,184,0.12)';
  m.fillRect(x, y + 40, w, 1);
  setFont(m, F.mono, 400, 17.5, { tracking: -0.1 });
  const cmd = '$ shakerscan agent claude';
  const cp = prog(u, 0.05, 0.36);
  const shown = typed(cmd, cp);
  const lx = x + 22;
  let ly = y + 72;
  const cw = drawText(m, shown, lx, ly, { color: '#ffffff' });
  let lastX = lx + cw;
  let lastY = ly;
  TERM.forEach((ln) => {
    ly += 30;
    const p = prog(u, ln.t, ln.t + 0.12);
    if (p <= 0) return;
    const txt = scramble(ln.text, p, fi, ln.t * 100);
    const tw = drawText(m, txt, lx, ly, { color: ln.color });
    lastX = lx + tw;
    lastY = ly;
  });
  // blinking block cursor
  if (Math.floor(u * 4) % 2 === 0 || cp < 1) {
    m.fillStyle = C.blueL;
    m.fillRect(lastX + 6, lastY - 16, 10, 20);
  }
  m.restore();
}

function budgets(L, u) {
  const m = L.m;
  const x = 1066;
  const y0 = 862;
  const bw = 440;
  const rowsDef = [
    { k: 'requests', max: 120, base: 23, steps: [1, 8, 3, 4, 0], fmt: (v) => `${Math.round(v)} / 120` },
    { k: 'capability calls', max: 40, base: 4, steps: [1, 1, 1, 1, 1], fmt: (v) => `${Math.round(v)} / 40` },
    { k: 'wall time', max: 900, base: 112, steps: [5, 6, 5, 6, 4], fmt: (v) => `${Math.floor(v / 60)}:${String(Math.floor(v % 60)).padStart(2, '0')} / 15:00` },
  ];
  const a = ep(u, 0.2, 0.55);
  if (a <= 0) return;
  m.save();
  m.globalAlpha = a;
  setFont(m, F.mono, 500, 12.5, { tracking: 2.5 });
  drawText(m, 'BUDGET  ·  RESERVED → SETTLED', x, y0 - 26, { color: C.dim });
  rowsDef.forEach((r, i) => {
    const y = y0 + i * 32;
    let settled = r.base;
    let reserved = r.base;
    SEQ.forEach((s, k) => {
      if (u >= s.at) {
        const st = ep(u, s.at + 0.1, s.at + 0.34, ease.outCubic);
        reserved += r.steps[k] * 1.6;
        settled += r.steps[k] * st;
        reserved -= r.steps[k] * 0.6 * st;
      }
    });
    setFont(m, F.mono, 400, 14, { tracking: 0.5 });
    drawText(m, r.k, x, y + 5, { color: C.soft });
    const bx = x + 176;
    m.fillStyle = 'rgba(148,163,184,0.14)';
    m.fillRect(bx, y - 3, bw, 6);
    m.fillStyle = 'rgba(96,165,250,0.35)';
    m.fillRect(bx, y - 3, (bw * reserved) / r.max, 6);
    m.fillStyle = C.blueL;
    m.fillRect(bx, y - 3, (bw * settled) / r.max, 6);
    drawText(m, r.fmt(settled), x + 176 + bw + 18, y + 5, { color: C.ink });
  });
  m.restore();
}

export function scene3(L, u, fi, { bg = true } = {}) {
  if (bg) {
    baseFill(L);
    ambient(L, CC.x, CC.y, 1000);
    dotGrid(L, u);
  }
  L.save();
  pushIn(L, u);
  ghostWord(L, 'HUNT', -60, H + 140, 760, 0.06);
  compass(L, u);
  nodes(L, u, fi);
  budgets(L, u);
  column(L, u, fi, {
    label: '03 — AGENT-DRIVEN HUNT',
    labelIn: 0.0,
    hero: 'HUNT',
    heroIn: -0.04,
    heroMode: 'slideR',
    heroStagger: 0.04,
    heroDur: 0.55,
    heroMask: false,
    desc: ['Claude Code, Codex or OpenCode plans.', 'ShakerScan enforces scope, budget and proof.'],
    descIn: 0.18,
  });
  terminal(L, u, fi);
  L.restore();
}
