// 01 MAP: laser ignition, aperture reveal, a rotating point-cloud attack surface whose targets are
// discovered on the beat, then a zoom-through into app.acme.test.
import {
  W, H, C, F, TAU, BEAT, SIXTEENTH,
  clamp, lerp, prog, ep, ease, setFont, drawText, scramble, circle, fmtInt, decay,
} from '../lib.js';
import { column, dotGrid, ambient, baseFill, COL } from '../common.js';

const N = 1500;
const PTS = [];
for (let i = 0; i < N; i++) {
  const y = 1 - ((i + 0.5) / N) * 2;
  const r = Math.sqrt(1 - y * y);
  const th = i * Math.PI * (3 - Math.sqrt(5));
  PTS.push([Math.cos(th) * r, y, Math.sin(th) * r]);
}

export const S1 = { cx: 1335, cy: 548, R: 352 };
const yaw = (u) => 0.55 + u * 0.36;
const PITCH = -0.34;

function rot(p, a, b) {
  const ca = Math.cos(a);
  const sa = Math.sin(a);
  const x1 = p[0] * ca + p[2] * sa;
  const z1 = -p[0] * sa + p[2] * ca;
  const cb = Math.cos(b);
  const sb = Math.sin(b);
  return [x1, p[1] * cb - z1 * sb, p[1] * sb + z1 * cb];
}

function project(p, R, cx, cy) {
  const f = 3.4;
  const s = f / (f - p[2]);
  return [cx + p[0] * R * s, cy + p[1] * R * s, s];
}

const LABELS = ['app.acme.test', 'api.acme.test/v2', '10.0.4.12:8443', 'chat.acme.test', 'models.acme.test', 'cam-07.iot.acme'];

// Pick well-separated, front-facing targets deterministically (screen positions at u = 1.1).
const TARGETS = (() => {
  const cand = [];
  PTS.forEach((p, i) => {
    const q = rot(p, yaw(1.1), PITCH);
    if (q[2] > 0.38 && Math.abs(q[1]) < 0.8) cand.push({ i, x: q[0], y: q[1] });
  });
  // start closest to the front-centre (this is the zoom-through node)
  cand.sort((a, b) => a.x * a.x + (a.y + 0.08) ** 2 - (b.x * b.x + (b.y + 0.08) ** 2));
  const picked = [cand[0]];
  while (picked.length < 12) {
    let best = null;
    let bestD = -1;
    for (const c of cand) {
      let d = Infinity;
      for (const p of picked) d = Math.min(d, (c.x - p.x) ** 2 + (c.y - p.y) ** 2);
      if (d > bestD) {
        bestD = d;
        best = c;
      }
    }
    picked.push(best);
  }
  return picked.map((c) => c.i);
})();

// Each target links to its two nearest neighbours, so the mesh hugs the visible hemisphere.
const ARCS = (() => {
  const seen = new Set();
  const out = [];
  TARGETS.forEach((ia, a) => {
    const P = PTS[ia];
    const near = TARGETS.map((ib, b) => ({ b, d: (PTS[ib][0] - P[0]) ** 2 + (PTS[ib][1] - P[1]) ** 2 + (PTS[ib][2] - P[2]) ** 2 }))
      .filter((x) => x.b !== a)
      .sort((x, y) => x.d - y.d)
      .slice(0, 2);
    for (const { b } of near) {
      const key = a < b ? `${a}-${b}` : `${b}-${a}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push([Math.min(a, b), Math.max(a, b)]);
      }
    }
  });
  return out;
})();

const discoverAt = (k) => BEAT * 1 + 0.02 + k * SIXTEENTH * 0.5;

function slerpArc(a, b, s) {
  const dot = clamp(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], -1, 1);
  const om = Math.acos(dot);
  const so = Math.sin(om) || 1e-6;
  const w1 = Math.sin((1 - s) * om) / so;
  const w2 = Math.sin(s * om) / so;
  const lift = 1 + 0.22 * Math.sin(Math.PI * s);
  return [(a[0] * w1 + b[0] * w2) * lift, (a[1] * w1 + b[1] * w2) * lift, (a[2] * w1 + b[2] * w2) * lift];
}

export function targetScreen(u, k = 0) {
  const { cx, cy, R } = S1;
  const sc = sphereScale(u);
  return project(rot(PTS[TARGETS[k]], yaw(u), PITCH), R * sc, cx, cy);
}

function sphereScale(u) {
  return lerp(0.55, 1, ep(u, 0.12, 1.0, ease.outExpo));
}

function drawSphere(L, u, fi, zoomed) {
  const { m, g } = L;
  const { cx, cy, R } = S1;
  const sc = sphereScale(u);
  const Rr = R * sc;
  const a = yaw(u);
  const appear = ep(u, 0.14, 0.7, ease.outCubic);

  // radar sweep
  m.save();
  m.beginPath();
  m.arc(cx, cy, Rr * 1.2, 0, TAU);
  m.clip();
  const sweepA = -Math.PI / 2 + u * TAU * 0.9;
  const cg = m.createConicGradient(sweepA, cx, cy);
  cg.addColorStop(0, 'rgba(96,165,250,0)');
  cg.addColorStop(0.78, 'rgba(96,165,250,0)');
  cg.addColorStop(0.995, `rgba(96,165,250,${0.2 * appear})`);
  cg.addColorStop(1, 'rgba(96,165,250,0)');
  m.fillStyle = cg;
  m.fillRect(cx - Rr * 1.3, cy - Rr * 1.3, Rr * 2.6, Rr * 2.6);
  m.restore();

  // orbit ring
  m.save();
  m.globalAlpha = 0.5 * appear;
  m.strokeStyle = C.blueL;
  m.lineWidth = 1;
  m.setLineDash([3, 9]);
  m.lineDashOffset = -u * 60;
  m.beginPath();
  m.ellipse(cx, cy, Rr * 1.34, Rr * 0.34, -0.22, 0, TAU);
  m.stroke();
  m.restore();

  // wire rings (equator + meridians)
  const rings = [];
  for (let k = 0; k < 4; k++) rings.push(k);
  m.save();
  m.lineWidth = 1;
  for (const k of rings) {
    let prev = null;
    for (let j = 0; j <= 72; j++) {
      const th = (j / 72) * TAU;
      let p;
      if (k === 0) p = [Math.cos(th), 0, Math.sin(th)];
      else {
        const ph = (k / 3) * Math.PI;
        p = [Math.cos(th) * Math.cos(ph), Math.sin(th), Math.cos(th) * Math.sin(ph)];
      }
      const q = rot(p, a, PITCH);
      const s = project(q, Rr, cx, cy);
      if (prev) {
        m.globalAlpha = (q[2] > 0 ? 0.3 : 0.08) * appear;
        m.strokeStyle = C.blueL;
        m.beginPath();
        m.moveTo(prev[0], prev[1]);
        m.lineTo(s[0], s[1]);
        m.stroke();
      }
      prev = s;
    }
  }
  m.restore();

  // points
  m.save();
  m.fillStyle = C.blueL;
  for (let i = 0; i < N; i++) {
    const q = rot(PTS[i], a, PITCH);
    const s = project(q, Rr, cx, cy);
    const depth = (q[2] + 1) / 2;
    // reveal points in a sweep from the top as the aperture opens
    const rv = clamp((appear * 1.4 - (1 - (PTS[i][1] + 1) / 2) * 0.4));
    const al = (0.1 + 0.9 * depth * depth) * rv;
    if (al < 0.02) continue;
    const sz = 1.1 + 2.1 * depth;
    m.globalAlpha = al;
    if (zoomed) {
      m.beginPath();
      m.arc(s[0], s[1], sz * 0.6, 0, TAU);
      m.fill();
    } else m.fillRect(s[0] - sz / 2, s[1] - sz / 2, sz, sz);
  }
  m.restore();

  // arcs between discovered targets
  for (const [ia, ib] of ARCS) {
    const t0 = Math.max(discoverAt(ia), discoverAt(ib)) + 0.05;
    const p = ep(u, t0, t0 + 0.45, ease.inOutCubic);
    if (p <= 0) continue;
    const A = PTS[TARGETS[ia]];
    const B = PTS[TARGETS[ib]];
    const steps = 28;
    const upto = Math.max(1, Math.round(steps * p));
    const mid = rot(slerpArc(A, B, 0.5), a, PITCH);
    const depthA = clamp(mid[2] * 2.5 + 0.35);
    if (depthA <= 0.02) continue;
    L.both((c, glow) => {
      c.save();
      c.strokeStyle = glow ? C.blue : C.blueL;
      c.globalAlpha = (glow ? 0.9 : 0.75) * depthA;
      c.lineWidth = glow ? 3 : 1.4;
      c.beginPath();
      for (let j = 0; j <= upto; j++) {
        const q = rot(slerpArc(A, B, (j / upto) * p), a, PITCH);
        const s = project(q, Rr, cx, cy);
        if (j === 0) c.moveTo(s[0], s[1]);
        else c.lineTo(s[0], s[1]);
      }
      c.stroke();
      c.restore();
    });
  }

  // targets
  TARGETS.forEach((idx, k) => {
    const q = rot(PTS[idx], a, PITCH);
    if (q[2] < -0.1) return;
    const s = project(q, Rr, cx, cy);
    const td = discoverAt(k);
    const p = ep(u, td, td + 0.3, ease.outBack);
    if (p <= 0) return;
    const pulse = prog(u, td, td + 0.55);
    const vis = clamp((q[2] + 0.1) * 3);
    m.save();
    m.globalAlpha = vis;
    if (pulse < 1) {
      m.strokeStyle = C.blueXL;
      m.globalAlpha = vis * (1 - pulse);
      m.lineWidth = 1.5;
      circle(m, s[0], s[1], 6 + pulse * 34);
      m.stroke();
    }
    m.globalAlpha = vis;
    m.strokeStyle = C.blueXL;
    m.lineWidth = 1.5;
    circle(m, s[0], s[1], 9 * p);
    m.stroke();
    m.fillStyle = '#ffffff';
    circle(m, s[0], s[1], 3.4 * p);
    m.fill();
    m.restore();
    g.save();
    g.globalAlpha = vis;
    g.fillStyle = C.blueL;
    circle(g, s[0], s[1], 10 * p);
    g.fill();
    g.restore();
  });

  // labels on the first targets
  setFont(m, F.mono, 500, 15, { tracking: 0.5 });
  LABELS.forEach((label, k) => {
    const q = rot(PTS[TARGETS[k]], a, PITCH);
    if (q[2] < 0.05) return;
    const s = project(q, Rr, cx, cy);
    const td = discoverAt(k) + 0.08;
    const p = prog(u, td, td + 0.4);
    if (p <= 0) return;
    const right = s[0] > cx - 60;
    const lx = s[0] + (right ? 26 : -26);
    const ly = s[1] - 22;
    const vis = clamp((q[2] - 0.05) * 4);
    m.save();
    m.globalAlpha = vis;
    m.strokeStyle = 'rgba(147,197,253,0.6)';
    m.lineWidth = 1;
    const lp = ep(u, td, td + 0.2);
    m.beginPath();
    m.moveTo(s[0] + (right ? 8 : -8), s[1] - 6);
    m.lineTo(lerp(s[0], lx, lp), lerp(s[1], ly + 6, lp));
    m.stroke();
    const txt = scramble(label, p, 0, 40 + k);
    const tw = m.measureText(label).width;
    const bx = right ? lx + 4 : lx - tw - 18;
    m.fillStyle = 'rgba(8,14,28,0.82)';
    m.beginPath();
    m.roundRect(bx - 6, ly - 13, (tw + 22) * ep(u, td, td + 0.25), 26, 5);
    m.fill();
    m.fillStyle = k === 0 ? '#ffffff' : C.blueXL;
    m.fillText(txt, bx + 5, ly + 5);
    m.restore();
  });
}

function stats(L, u) {
  const m = L.m;
  const items = [
    ['TARGETS', 12],
    ['ROUTES', 214],
    ['SERVICES', 38],
  ];
  items.forEach(([k, v], i) => {
    const t0 = 0.78 + i * 0.06;
    const a = ep(u, t0, t0 + 0.4);
    if (a <= 0) return;
    const x = COL.x + i * 190;
    const y = COL.extra + 30;
    m.save();
    m.globalAlpha = a;
    m.fillStyle = 'rgba(148,163,184,0.25)';
    m.fillRect(x, y - 44, 1, 70);
    setFont(m, F.mono, 500, 13, { tracking: 2.5 });
    drawText(m, k, x + 16, y - 26, { color: C.dim });
    setFont(m, F.sans, 600, 40, { tracking: -1 });
    const n = v * ep(u, t0, t0 + 0.75, ease.outCubic);
    drawText(m, fmtInt(n), x + 14, y + 20, { color: C.ink });
    m.restore();
  });
}

export function scene1(L, u, fi, zoomed = false) {
  const { m, g } = L;
  baseFill(L);
  const laser = ep(u, 0.02, 0.26, ease.outExpo);
  const open = ep(u, 0.13, 0.6, ease.inOutCubic);
  const cy = H / 2;
  const half = open * (H / 2 + 20);

  // everything inside the aperture
  L.save();
  L.clip((c) => c.rect(-W, cy - half, W * 3, half * 2));
  ambient(L, S1.cx, S1.cy, 1000, open);
  dotGrid(L, u, { alpha: open });
  drawSphere(L, u, fi, zoomed);
  column(L, u, fi, {
    label: '01 — ATTACK SURFACE',
    labelIn: 0.3,
    hero: 'MAP',
    heroIn: BEAT - 0.03,
    heroStagger: 0.07,
    heroDur: 0.7,
    desc: ['Every target, route and origin, mapped', 'and kept under continuous coverage.'],
    descIn: 0.62,
  });
  stats(L, u);
  L.restore();

  // laser line and aperture edges
  if (half < H / 2 + 10) {
    const w = W * laser;
    const edgeA = 1 - open * 0.85;
    L.both((c, glow) => {
      c.save();
      c.fillStyle = glow ? C.blueL : '#ffffff';
      const th = glow ? 7 : 2;
      c.globalAlpha = edgeA * (glow ? 1 : 0.95);
      c.fillRect(W / 2 - w / 2, cy - half - th / 2, w, th);
      if (half > 1) c.fillRect(W / 2 - w / 2, cy + half - th / 2, w, th);
      c.restore();
    });
    // ignition flare at the centre
    const fl = decay(u - 0.02, 7);
    g.save();
    g.globalAlpha = fl;
    g.fillStyle = '#bcd8ff';
    g.beginPath();
    g.ellipse(W / 2, cy, 520 * laser + 40, 22, 0, 0, TAU);
    g.fill();
    g.restore();
  }
}
