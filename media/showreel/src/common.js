import {
  W, H, C, F, FPS, BAR, TAU,
  clamp, lerp, prog, ep, ease, setFont, drawText, kinetic, scramble, hash, pad, drawOutline,
} from './lib.js';

// Left text column shared by the verb shots, so the eye always knows where to read.
export const COL = { x: 110, label: 318, hero: 520, desc: 592, lh: 41, extra: 700, maxHero: 790 };

export const SHOTS = [
  '01 — MAP',
  '02 — SCAN',
  '03 — HUNT',
  '04 — PROVE',
  '05 — GRADE',
  '06 — BEYOND WEB',
  '07 — ONE PLATFORM',
  '08 — SHAKERSCAN',
];

// Slow camera push through a shot; lives inside each scene so transitions inherit it.
export const PUSH = 0.025;
export function pushIn(L, u) {
  L.zoom(1 + PUSH * clamp(u / BAR, 0, 1.25), W / 2, H / 2);
}

export function baseFill(L, color = C.bg) {
  L.m.fillStyle = color;
  L.m.fillRect(-W, -H, W * 3, H * 3);
}

export function ambient(L, x = W * 0.68, y = H * 0.5, r = 1050, a = 1) {
  const m = L.m;
  const g = m.createRadialGradient(x, y, 0, x, y, r);
  g.addColorStop(0, `rgba(26,56,128,${0.42 * a})`);
  g.addColorStop(0.45, `rgba(12,28,70,${0.2 * a})`);
  g.addColorStop(1, 'rgba(4,6,12,0)');
  m.fillStyle = g;
  m.fillRect(x - r, y - r, r * 2, r * 2);
}

// Dot grid in the current transform. ox/oy scroll it, reach extends it for camera moves.
export function dotGrid(L, t, { alpha = 1, sp = 48, ox = 0, oy = 0, x0 = -120, y0 = -120, x1 = W + 120, y1 = H + 120 } = {}) {
  const m = L.m;
  const dx = ((ox + t * 7) % sp + sp) % sp;
  const dy = ((oy + t * 3) % sp + sp) % sp;
  m.save();
  m.globalAlpha *= alpha;
  m.fillStyle = 'rgba(120,160,230,0.13)';
  for (let y = y0 - sp + dy; y < y1; y += sp) {
    for (let x = x0 - sp + dx; x < x1; x += sp) m.fillRect(x, y, 2, 2);
  }
  m.restore();
}

// Huge outlined word used as parallax depth behind a shot.
export function ghostWord(L, word, x, y, size, alpha = 0.07) {
  if (alpha <= 0.001) return;
  const m = L.m;
  m.save();
  m.globalAlpha *= alpha;
  drawOutline(m, word, x, y, { family: F.hero, size, lw: 2, color: C.blueL, tracking: -size * 0.02 });
  m.restore();
}

export function fitSize(ctx, word, family, weight, size, maxW, tracking = 0) {
  setFont(ctx, family, weight, size, { tracking });
  const w = ctx.measureText(word).width;
  return w > maxW ? size * (maxW / w) : size;
}

// Eyebrow label + hero verb + description lines, each with its own entrance.
export function column(L, u, fi, s) {
  const m = L.m;
  const x = COL.x;
  const exitA = s.exit != null ? 1 - ep(u, s.exit, s.exit + 0.22, ease.inCubic) : 1;
  m.save();
  // eyebrow
  if (s.label) {
    const p = prog(u, s.labelIn ?? 0.05, (s.labelIn ?? 0.05) + 0.45);
    if (p > 0) {
      setFont(m, F.mono, 500, 17, { tracking: 3.5 });
      const bar = ep(u, s.labelIn ?? 0.05, (s.labelIn ?? 0.05) + 0.4);
      m.fillStyle = C.blueL;
      m.globalAlpha = exitA;
      m.fillRect(x, COL.label - 12, 26 * bar, 2);
      drawText(m, scramble(s.label, p, fi, s.seed ?? 7), x + 40, COL.label, { color: C.blueL, alpha: exitA });
    }
  }
  // hero
  if (s.hero) {
    const size = fitSize(m, s.hero, F.hero, 800, s.heroSize ?? 214, COL.maxHero, -4);
    setFont(m, F.hero, 800, size, { tracking: -4 });
    m.globalAlpha = 1;
    kinetic(m, s.hero, x - 6, COL.hero, {
      t: u - (s.heroIn ?? 0),
      size,
      mode: s.heroMode ?? 'rise',
      stagger: s.heroStagger ?? 0.045,
      dur: s.heroDur ?? 0.62,
      fn: s.heroFn ?? ease.outExpo,
      color: C.ink,
      mask: (s.heroMask ?? true) || (s.exit != null && u >= s.exit),
      order: s.heroOrder ?? 'ltr',
      out: s.exit != null ? { t: u - s.exit, dur: 0.26, stagger: 0.02, mode: s.heroOut ?? 'rise', fn: ease.inExpo } : null,
    });
  }
  // description
  if (s.desc) {
    setFont(m, F.sans, 400, 29, { tracking: -0.2 });
    s.desc.forEach((ln, i) => {
      const a = ep(u, (s.descIn ?? 0.35) + i * 0.07, (s.descIn ?? 0.35) + i * 0.07 + 0.5);
      if (a <= 0) return;
      m.save();
      m.globalAlpha = a * exitA;
      m.translate(0, (1 - a) * 18);
      m.fillStyle = i === 0 ? '#c9d3e3' : C.soft;
      m.fillText(ln, x, COL.desc + i * COL.lh);
      m.restore();
    });
  }
  m.restore();
}

function corner(m, x, y, sx, sy, len, p) {
  m.beginPath();
  m.moveTo(x + sx * len * p, y);
  m.lineTo(x, y);
  m.lineTo(x, y + sy * len * p);
  m.stroke();
}

// Persistent showreel HUD: corner marks, slate, shot counter, timecode, progress rail.
export function hud(L, tF, fi, { dark = false } = {}) {
  const m = L.m;
  const INK = dark ? '#0b1428' : C.ink;
  const DIM = dark ? 'rgba(11,20,40,0.7)' : C.dim;
  const inA = ep(tF, 0.22, 0.9, ease.outCubic);
  const outA = 1 - ep(tF, BAR * 7 - 0.05, BAR * 7 + 0.1, ease.inQuad);
  const a = inA * outA;
  if (a <= 0.001) return;
  m.save();
  m.globalAlpha = a;
  m.strokeStyle = dark ? 'rgba(11,20,40,0.5)' : 'rgba(170,190,220,0.55)';
  m.lineWidth = 1.5;
  const d = 44;
  const len = 26;
  corner(m, d, d, 1, 1, len, inA);
  corner(m, W - d, d, -1, 1, len, inA);
  corner(m, d, H - d, 1, -1, len, inA);
  corner(m, W - d, H - d, -1, -1, len, inA);

  setFont(m, F.mono, 700, 14, { tracking: 3 });
  const slate = 'SHAKERSCAN';
  const p1 = prog(tF, 0.3, 0.8);
  const w1 = drawText(m, scramble(slate, p1, fi, 11), 84, 84, { color: INK });
  setFont(m, F.mono, 400, 14, { tracking: 3 });
  drawText(m, scramble('/  CAPABILITIES REEL 2026', prog(tF, 0.45, 1.0), fi, 12), 84 + w1 + 14, 84, { color: DIM });

  // shot counter rolls to the next label on every bar
  const shot = clamp(Math.floor(tF / BAR), 0, 7);
  const local = tF - shot * BAR;
  const roll = shot > 0 ? ep(local, 0, 0.3, ease.outExpo) : 1;
  setFont(m, F.mono, 500, 14, { tracking: 3 });
  m.save();
  m.beginPath();
  m.rect(W - 520, 64, 440, 28);
  m.clip();
  drawText(m, SHOTS[shot], W - 84, 84 + (1 - roll) * 24, { color: INK, align: 'right' });
  if (shot > 0 && roll < 1) drawText(m, SHOTS[shot - 1], W - 84, 84 - roll * 24, { color: INK, align: 'right', alpha: 1 - roll });
  m.restore();

  // timecode
  setFont(m, F.mono, 400, 14, { tracking: 2.5 });
  const tc = `${pad(0)}:${pad(0)}:${pad(Math.floor(tF))}:${pad(fi % FPS)}`;
  drawText(m, 'TC ' + tc, 84, H - 76, { color: DIM });
  drawText(m, '128 BPM  ·  1920×1080  ·  60P', W - 84, H - 76, { color: DIM, align: 'right' });

  // progress rail with bar ticks
  const x0 = 84;
  const x1 = W - 84;
  const y = H - 104;
  m.fillStyle = dark ? 'rgba(11,20,40,0.25)' : 'rgba(148,163,184,0.18)';
  m.fillRect(x0, y, (x1 - x0) * inA, 1);
  for (let i = 0; i <= 8; i++) {
    const x = lerp(x0, x1, i / 8);
    m.fillStyle = dark ? 'rgba(11,20,40,0.6)' : i <= shot ? 'rgba(147,197,253,0.9)' : 'rgba(148,163,184,0.35)';
    m.fillRect(Math.round(x) - 0.5, y - 4, 1, 9);
  }
  const px = lerp(x0, x1, clamp(tF / (BAR * 8)));
  m.fillStyle = dark ? C.blue : C.blueL;
  m.fillRect(x0, y - 1, (px - x0) * inA, 3);
  L.g.save();
  L.g.globalAlpha = a;
  L.g.fillStyle = C.blue;
  L.g.fillRect(px - 60, y - 2, 60, 5);
  L.g.restore();
  m.fillStyle = dark ? '#0b1428' : '#ffffff';
  m.fillRect(px - 1, y - 5, 2, 11);
  m.restore();
}
