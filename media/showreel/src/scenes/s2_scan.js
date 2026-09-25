// 02 SCAN: the target app's window arrives out of the zoom-through; a deterministic scan beam tests
// one endpoint per 16th note and pops severity-coded results.
import {
  W, H, C, F, TAU, BEAT, SIXTEENTH,
  clamp, lerp, prog, ep, ease, setFont, drawText, rrect, circle, spring, decay, typed,
} from '../lib.js';
import { column, dotGrid, ambient, baseFill, ghostWord, COL, pushIn } from '../common.js';

export const WIN = { x: 960, y: 232, w: 842, h: 604 };
const BAR_H = 56;
const ROW0 = WIN.y + BAR_H + 54;
const ROW_H = 64;
const SEV = {
  crit: [C.crit, 'CRITICAL'],
  high: [C.high, 'HIGH'],
  med: [C.med, 'MEDIUM'],
  ok: [C.ok, 'CLEAN'],
};
const ROWS = [
  ['GET', '/api/search?q=', 'SQLi', 'crit'],
  ['POST', '/api/login  json:{"user":…}', 'Auth', 'ok'],
  ['GET', '/api/v2/orders/{id}', 'BOLA', 'high'],
  ['PUT', '/api/users/{id}', 'Mass assignment', 'med'],
  ['GET', '/search#q=', 'DOM XSS', 'high'],
  ['GET', '/api/token', 'JWT alg:none', 'crit'],
  ['GET', '/assets/app.js', 'Templates', 'ok'],
];
const METHOD = { GET: C.blueL, POST: C.ok, PUT: C.amber };
const hitAt = (i) => BEAT + i * SIXTEENTH;
const rowY = (i) => ROW0 + i * ROW_H;
const beamY = (u) => rowY(0) + ((u - hitAt(0)) / SIXTEENTH) * ROW_H;

function windowChrome(L, u, fi) {
  const { m, g } = L;
  const { x, y, w, h } = WIN;
  // body
  m.save();
  m.shadowColor = 'rgba(0,0,0,0.55)';
  m.shadowBlur = 60;
  m.shadowOffsetY = 24;
  m.fillStyle = C.panel;
  rrect(m, x, y, w, h, 18);
  m.fill();
  m.restore();
  m.save();
  m.strokeStyle = 'rgba(96,165,250,0.34)';
  m.lineWidth = 1.5;
  rrect(m, x, y, w, h, 18);
  m.stroke();
  // title bar
  m.fillStyle = 'rgba(255,255,255,0.025)';
  m.beginPath();
  m.roundRect(x, y, w, BAR_H, [18, 18, 0, 0]);
  m.fill();
  m.fillStyle = 'rgba(148,163,184,0.16)';
  m.fillRect(x, y + BAR_H, w, 1);
  ['#334155', '#334155', '#334155'].forEach((c, i) => {
    m.fillStyle = c;
    circle(m, x + 28 + i * 20, y + BAR_H / 2, 6);
    m.fill();
  });
  // url pill
  const ux = x + 104;
  m.fillStyle = 'rgba(15,23,42,0.9)';
  rrect(m, ux, y + 13, 420, 30, 15);
  m.fill();
  m.strokeStyle = 'rgba(148,163,184,0.14)';
  m.stroke();
  // padlock
  m.strokeStyle = C.dim;
  m.lineWidth = 1.5;
  m.beginPath();
  m.arc(ux + 22, y + 25, 4, Math.PI, 0);
  m.stroke();
  m.fillStyle = C.dim;
  m.fillRect(ux + 16.5, y + 25, 11, 8);
  setFont(m, F.mono, 400, 15, { tracking: 0 });
  const url = 'https://app.acme.test';
  drawText(m, typed(url, prog(u, 0.12, 0.42)), ux + 38, y + 33, { color: C.soft });
  // status
  const done = u > hitAt(6) + 0.2;
  setFont(m, F.mono, 500, 13, { tracking: 2 });
  const st = done ? 'SCAN COMPLETE' : 'SCAN RUNNING';
  const sc = done ? C.ok : C.blueL;
  const sw = drawText(m, st, x + w - 26, y + 33, { color: sc, align: 'right' });
  const pulse = done ? 1 : 0.55 + 0.45 * Math.sin(u * TAU * 2.1);
  m.fillStyle = sc;
  m.globalAlpha = pulse;
  circle(m, x + w - 26 - sw - 14, y + 28, 4.5);
  m.fill();
  m.globalAlpha = 1;
  g.save();
  g.globalAlpha = pulse * 0.8;
  g.fillStyle = sc;
  circle(g, x + w - 26 - sw - 14, y + 28, 8);
  g.fill();
  g.restore();
  // progress hairline under title bar
  const pr = clamp((u - hitAt(0) + SIXTEENTH) / (SIXTEENTH * 7));
  m.fillStyle = C.blueL;
  m.fillRect(x, y + BAR_H, w * pr, 2);
  // column headers
  setFont(m, F.mono, 500, 12, { tracking: 2.5 });
  drawText(m, 'METHOD', x + 30, ROW0 - 36, { color: C.dimmer, alpha: ep(u, 0.2, 0.5) });
  drawText(m, 'ENDPOINT', x + 118, ROW0 - 36, { color: C.dimmer, alpha: ep(u, 0.22, 0.52) });
  drawText(m, 'RESULT', x + w - 30, ROW0 - 36, { color: C.dimmer, align: 'right', alpha: ep(u, 0.24, 0.54) });
  m.restore();
}

function rows(L, u, fi) {
  const { m, g } = L;
  const { x, w } = WIN;
  ROWS.forEach(([meth, path, fam, sev], i) => {
    const a = ep(u, 0.16 + i * 0.035, 0.55 + i * 0.035);
    if (a <= 0) return;
    const cy = rowY(i);
    const hit = hitAt(i);
    const flash = u >= hit ? decay(u - hit, 7) : 0;
    m.save();
    m.globalAlpha = a;
    m.translate((1 - a) * -40, 0);
    // row background
    m.fillStyle = i % 2 ? 'rgba(255,255,255,0.018)' : 'rgba(255,255,255,0.0)';
    m.fillRect(x + 12, cy - ROW_H / 2 + 4, w - 24, ROW_H - 8);
    if (flash > 0.01) {
      m.fillStyle = `rgba(147,197,253,${0.16 * flash})`;
      m.fillRect(x + 12, cy - ROW_H / 2 + 4, w - 24, ROW_H - 8);
    }
    // method pill
    const mc = METHOD[meth];
    m.fillStyle = mc + '22';
    rrect(m, x + 28, cy - 14, 66, 28, 7);
    m.fill();
    setFont(m, F.mono, 700, 14, { tracking: 1 });
    drawText(m, meth, x + 61, cy + 5, { color: mc, align: 'center' });
    // path, with the body-spec part dimmed
    setFont(m, F.mono, 400, 19, { tracking: -0.2 });
    const [p0, p1] = path.split('  ');
    const pw = drawText(m, p0, x + 118, cy + 7, { color: C.ink });
    if (p1) drawText(m, p1, x + 118 + pw + 18, cy + 7, { color: C.dim });
    // result chip
    if (u >= hit) {
      const [col, word] = SEV[sev];
      const pp = ep(u, hit, hit + 0.32, (t) => ease.outBack(t, 2.2));
      setFont(m, F.mono, 600, 14, { tracking: 1.2 });
      const label = sev === 'ok' ? `✓ ${fam.toUpperCase()} · ${word}` : `${fam.toUpperCase()} · ${word}`;
      const tw = m.measureText(label).width;
      const cw = tw + 44;
      const cx = x + w - 28 - cw;
      m.save();
      m.translate(cx + cw, cy);
      m.scale(pp, pp);
      m.translate(-(cx + cw), -cy);
      m.fillStyle = sev === 'ok' ? 'rgba(52,211,153,0.08)' : col + '26';
      rrect(m, cx, cy - 16, cw, 32, 16);
      m.fill();
      m.strokeStyle = col + (sev === 'ok' ? '55' : '99');
      m.lineWidth = 1.2;
      m.stroke();
      if (sev !== 'ok') {
        m.fillStyle = col;
        circle(m, cx + 18, cy, 4.5);
        m.fill();
      }
      drawText(m, label, cx + (sev === 'ok' ? 16 : 30), cy + 5, { color: sev === 'ok' ? '#86efac' : col });
      m.restore();
      if (sev !== 'ok') {
        g.save();
        g.globalAlpha = 0.35 + 0.65 * flash;
        g.fillStyle = col;
        circle(g, cx + 18, cy, 9);
        g.fill();
        g.globalAlpha = 0.5 * flash;
        rrect(g, cx, cy - 16, cw, 32, 16);
        g.fill();
        g.restore();
      }
    }
    m.restore();
  });
}

function beam(L, u) {
  const { m, g } = L;
  const vis = ep(u, hitAt(0) - 0.12, hitAt(0) - 0.02) * (1 - ep(u, hitAt(6) + 0.08, hitAt(6) + 0.25));
  if (vis <= 0) return;
  const { x, w } = WIN;
  const by = beamY(u);
  const top = ROW0 - ROW_H / 2;
  m.save();
  m.beginPath();
  m.rect(x + 1, top - 6, w - 2, ROW_H * 7 + 12);
  m.clip();
  // scanned tint and trail
  m.globalAlpha = vis;
  m.fillStyle = 'rgba(59,130,246,0.045)';
  m.fillRect(x, top, w, Math.max(0, by - top));
  const tr = m.createLinearGradient(0, by - 110, 0, by);
  tr.addColorStop(0, 'rgba(96,165,250,0)');
  tr.addColorStop(1, 'rgba(96,165,250,0.2)');
  m.fillStyle = tr;
  m.fillRect(x, by - 110, w, 110);
  m.fillStyle = '#ffffff';
  m.fillRect(x, by - 1, w, 2);
  m.restore();
  g.save();
  g.globalAlpha = vis;
  g.fillStyle = C.blueL;
  g.fillRect(x, by - 4, w, 8);
  g.globalAlpha = vis * 0.6;
  g.fillStyle = C.blue;
  g.fillRect(x, by - 40, w, 40);
  g.restore();
  // edge sparks
  for (const ex of [x, x + w]) {
    m.save();
    m.globalAlpha = vis;
    m.fillStyle = '#ffffff';
    circle(m, ex, by, 3.5);
    m.fill();
    m.restore();
  }
}

function footer(L, u) {
  const m = L.m;
  const { x, y, w, h } = WIN;
  const fy = y + h - 44;
  m.save();
  m.fillStyle = 'rgba(148,163,184,0.12)';
  m.fillRect(x, fy, w, 1);
  m.beginPath();
  m.rect(x + 20, fy, w - 330, 44);
  m.clip();
  setFont(m, F.mono, 400, 13.5, { tracking: 1.5 });
  const fams = 'recon · templates · xss · sqli · bola · jwt · auth · mass_assignment · nosqli · headers · exposure · ';
  const fw = m.measureText(fams).width;
  const off = -((u * 140) % fw);
  m.globalAlpha = ep(u, 0.3, 0.7);
  drawText(m, fams + fams, x + 20 + off, fy + 27, { color: C.dimmer });
  m.restore();
  m.save();
  setFont(m, F.mono, 500, 13.5, { tracking: 1.5 });
  const found = ROWS.filter((r, i) => r[3] !== 'ok' && u >= hitAt(i)).length;
  const tested = ROWS.filter((r, i) => u >= hitAt(i)).length;
  drawText(m, `${tested}/7 TESTED  ·  ${found} FINDINGS`, x + w - 26, fy + 27, { color: C.soft, align: 'right', alpha: ep(u, 0.3, 0.7) });
  m.restore();
}

function profiles(L, u) {
  const m = L.m;
  const x0 = COL.x;
  const y0 = COL.extra + 6;
  const segs = ['fast', 'balanced', 'thorough'];
  const sw = 172;
  const a = ep(u, 0.55, 0.95);
  if (a <= 0) return;
  m.save();
  m.globalAlpha = a;
  m.translate(0, (1 - a) * 16);
  setFont(m, F.mono, 500, 12.5, { tracking: 2.5 });
  drawText(m, 'BUDGET PROFILE', x0, y0 - 18, { color: C.dim });
  m.fillStyle = 'rgba(15,23,42,0.85)';
  rrect(m, x0, y0, sw * 3 + 8, 54, 27);
  m.fill();
  m.strokeStyle = 'rgba(148,163,184,0.18)';
  m.lineWidth = 1;
  m.stroke();
  // highlight slides balanced -> thorough on beat 2
  const pos = 1 + spring(u - BEAT * 2, 2.6, 0.5);
  const hx = x0 + 4 + pos * sw;
  m.fillStyle = C.blue;
  rrect(m, hx, y0 + 4, sw, 46, 23);
  m.fill();
  L.g.save();
  L.g.globalAlpha = a * 0.7;
  L.g.fillStyle = C.blue;
  rrect(L.g, hx, y0 + 4, sw, 46, 23);
  L.g.fill();
  L.g.restore();
  setFont(m, F.sans, 500, 21, { tracking: -0.2 });
  segs.forEach((s, i) => {
    const on = clamp(1 - Math.abs(pos - i));
    drawText(m, s, x0 + 4 + i * sw + sw / 2, y0 + 34, { color: on > 0.5 ? '#ffffff' : C.soft, align: 'center' });
  });
  m.restore();
}

// Camera arrives out of the zoom-through: scale 0.36 -> 1 around the screen centre.
export function scene2(L, u, fi, { bg = true } = {}) {
  if (bg) {
    baseFill(L);
    ambient(L, WIN.x + WIN.w / 2, H / 2, 1000);
  }
  const arrive = ep(u, 0, 0.62, ease.outExpo);
  const s = lerp(0.36, 1, arrive);
  L.save();
  pushIn(L, u);
  L.save();
  L.zoom(s, W / 2, H / 2, lerp(0.12, 0, arrive));
  dotGrid(L, u, { x0: -W, y0: -H, x1: W * 2, y1: H * 2 });
  ghostWord(L, 'SCAN', -40, H + 150, 760, 0.06);
  windowChrome(L, u, fi);
  rows(L, u, fi);
  beam(L, u);
  footer(L, u);
  L.restore();
  column(L, u, fi, {
    label: '02 — DETERMINISTIC DAST',
    labelIn: 0.08,
    hero: 'SCAN',
    heroIn: 0.1,
    heroStagger: 0.05,
    desc: ['One reproducible Scan. Profiles set', 'hard budget ceilings, never authority.'],
    descIn: 0.32,
  });
  profiles(L, u);
  L.restore();
}
