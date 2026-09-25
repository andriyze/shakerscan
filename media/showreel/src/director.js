// Edit decision list: which shot is on screen, how shots hand over, and the lens/post track.
import {
  W, H, C, BAR, BEAT, EIGHTH, SIXTEENTH, DURATION, TAU,
  clamp, lerp, prog, ep, ease, decay, hash, rhombus,
} from './lib.js';
import { hud, baseFill, ambient, dotGrid, PUSH } from './common.js';
import { scene1, targetScreen } from './scenes/s1_map.js';
import { scene2, WIN } from './scenes/s2_scan.js';
import { scene3, CC, NEEDLE_S, LAST_ANGLE } from './scenes/s3_hunt.js';
import { scene4 } from './scenes/s4_prove.js';
import { scene5 } from './scenes/s5_grade.js';
import { scene6 } from './scenes/s6_beyond.js';
import { scene7, PART_B, PART_C } from './scenes/s7_montage.js';
import { scene8, markScreen } from './scenes/s8_logo.js';

export const T = {
  map: 0,
  scan: BAR,
  hunt: BAR * 2,
  prove: BAR * 3,
  grade: BAR * 4,
  beyond: BAR * 5,
  montage: BAR * 6,
  logo: BAR * 7,
  end: DURATION,
};

const ZOOM = [T.scan - 0.44, T.scan];
const WHIP = [T.hunt - 0.24, T.hunt + 0.22];
const WIPE = [T.prove - 0.27, T.prove + 0.1];
const EXIT4 = 1.5; // scene-4 elements leave (local time)
const FLIP = [T.grade - 0.3, T.grade + 0.12];
const PUSH_END = T.beyond + BEAT * 2 + 0.07;
const COLLAPSE = [T.montage - 0.26, T.montage];

function zoomThrough(L, t, fi) {
  const zp = prog(t, ZOOM[0], ZOOM[1]);
  if (zp <= 0) {
    scene1(L, t, fi);
    return;
  }
  const [px, py] = targetScreen(t, 0);
  const z = Math.exp(Math.log(110) * ease.inCubic(zp));
  const c = ease.inOutCubic(zp);
  L.save();
  L.translate(lerp(px, W / 2, c), lerp(py, H / 2, c));
  L.rotate(0.22 * ease.inCubic(zp));
  L.scale(z, z);
  L.translate(-px, -py);
  scene1(L, t, fi, z > 1.6);
  L.restore();
}

// One continuous camera move: SCAN sits at x = 0, HUNT one screen and a bit to the right.
function whip(L, t, fi) {
  const off = W * 1.15;
  const pan = off * ease.inOutQuart(prog(t, WHIP[0], WHIP[1]));
  baseFill(L);
  L.save();
  L.translate(-pan, 0);
  ambient(L, WIN.x + WIN.w / 2, H / 2, 1000);
  ambient(L, off + CC.x, CC.y, 1000);
  dotGrid(L, t, { x0: -200, x1: off + W + 200 });
  scene2(L, t - T.scan, fi, { bg: false });
  L.translate(off, 0);
  scene3(L, t - T.hunt, fi, { bg: false });
  L.restore();
}

// The HUNT needle (a rhombus) grows and turns into a window onto PROVE.
function diamondWipe(L, t, fi) {
  scene3(L, t - T.hunt, fi);
  const p = prog(t, WIPE[0], WIPE[1]);
  const e = ease.inOutCubic(p);
  // follow the needle exactly, including HUNT's slow camera push
  const s3 = 1 + PUSH * clamp((t - T.hunt) / BAR, 0, 1.25);
  const cx = W / 2 + (CC.x - W / 2) * s3;
  const cy = H / 2 + (CC.y - H / 2) * s3;
  const a0 = 4 * NEEDLE_S * s3;
  const a = a0 * Math.pow(2000 / a0, e);
  const rot = LAST_ANGLE + e * Math.PI * 0.5;
  L.save();
  L.clip((c) => rhombus(c, cx, cy, a, a * 2, rot));
  scene4(L, t - T.prove, fi, { exit: EXIT4 });
  L.restore();
  L.both((c, glow) => {
    c.save();
    c.strokeStyle = glow ? C.blue : '#dbeafe';
    c.lineWidth = glow ? 10 : 2.5;
    c.globalAlpha = 1 - ep(p, 0.75, 1);
    rhombus(c, cx, cy, a, a * 2, rot);
    c.stroke();
    c.restore();
  });
}

function flip(L, t, fi) {
  const th = Math.PI * ease.inOutCubic(prog(t, FLIP[0], FLIP[1]));
  scene4(L, t - T.prove, fi, { flip: th, exit: EXIT4 });
  if (th > Math.PI / 2) scene5(L, t - T.grade, fi, { bg: false, flip: th });
}

// Each GRADE column is pushed out by its BEYOND panel as that panel lands on the beat.
function push(L, t, fi) {
  scene6(L, t - T.beyond, fi);
  for (let i = 0; i < 3; i++) {
    const v = t - T.beyond - i * BEAT;
    const inP = ep(v, -0.22, 0.06, ease.outExpo);
    if (inP >= 1) continue;
    const dir = i % 2 === 0 ? -1 : 1;
    const off = -dir * inP * H;
    // the clip travels with the strip so the incoming panel is visible right behind it
    L.save();
    L.clip((c) => c.rect((i * W) / 3, off, W / 3, H));
    L.translate(0, off);
    scene5(L, t - T.grade, fi);
    L.restore();
  }
}

export function direct(L, t, env) {
  const { fi, tFrame } = env;
  if (t < T.scan) zoomThrough(L, t, fi);
  else if (t < WHIP[0]) scene2(L, t - T.scan, fi);
  else if (t < WHIP[1]) whip(L, t, fi);
  else if (t < WIPE[0]) scene3(L, t - T.hunt, fi);
  else if (t < WIPE[1]) diamondWipe(L, t, fi);
  else if (t < FLIP[0]) scene4(L, t - T.prove, fi, { exit: EXIT4 });
  else if (t < FLIP[1]) flip(L, t, fi);
  else if (t < T.beyond - 0.22) scene5(L, t - T.grade, fi);
  else if (t < PUSH_END) push(L, t, fi);
  else if (t < T.montage) scene6(L, t - T.beyond, fi, { exitP: prog(t, COLLAPSE[0], COLLAPSE[1]) });
  else if (t < T.logo) scene7(L, t - T.montage, fi);
  else scene8(L, t - T.logo, fi);
  // the HUD flips to dark ink on the one white slam (AI)
  const slam = tFrame - T.montage;
  hud(L, tFrame, fi, { dark: slam >= EIGHTH * 2 && slam < EIGHTH * 3 });
}

// Motion-blur sample count per output frame: more where the camera moves fast.
export function shutterSamples(t) {
  // first match wins, so the short, fastest stretches come first
  const windows = [
    [T.scan - 0.12, T.scan + 0.03, 32],
    [T.hunt - 0.1, T.hunt + 0.08, 36],
    [T.prove - 0.12, T.prove + 0.1, 24],
    [ZOOM[0] + 0.18, T.scan + 0.28, 18],
    [0.12, 0.62, 8],
    [WHIP[0] + 0.06, WHIP[1] - 0.04, 18],
    [WIPE[0], WIPE[1], 10],
    [T.prove + BEAT * 2 - 0.12, T.prove + BEAT * 2 + 0.05, 8],
    [FLIP[0], FLIP[1], 10],
    [T.grade + 0.12, T.grade + BEAT * 2 + 0.05, 10], // slot reel
    [T.beyond - 0.24, T.beyond + BEAT * 2 + 0.08, 8],
    [COLLAPSE[0], T.montage + 0.1, 10],
    [T.montage + PART_C - 0.02, T.logo + 0.35, 14],
  ];
  for (const [a, b, k] of windows) if (t >= a && t <= b) return k;
  return 5;
}

// Accent hits: [time, flash, flash decay, chromatic kick, shake px, colour]
const BLUE = [0.55, 0.72, 1.0];
const WHITE = [1, 1, 1];
const GREEN = [0.45, 1.0, 0.75];
const ICE = [0.82, 0.9, 1.0];
const HITS = [
  [0.03, 0.16, 12, 0.003, 0, BLUE],
  [T.scan, 0.5, 9, 0.006, 7, BLUE],
  [T.hunt, 0.08, 10, 0.004, 3, BLUE],
  [T.prove, 0.16, 9, 0.004, 3, BLUE],
  [T.prove + BEAT * 2, 0.12, 8, 0.004, 6, GREEN],
  [T.grade, 0.08, 10, 0.002, 0, BLUE],
  [T.grade + BEAT * 2, 0.1, 9, 0.003, 3, BLUE],
  [T.beyond, 0.12, 9, 0.003, 3, BLUE],
  [T.beyond + BEAT, 0.08, 10, 0.003, 2, BLUE],
  [T.beyond + BEAT * 2, 0.08, 10, 0.003, 2, BLUE],
  [T.montage, 0.4, 10, 0.007, 6, WHITE],
  [T.montage + EIGHTH, 0.2, 12, 0.005, 5, WHITE],
  [T.montage + EIGHTH * 2, 0.2, 12, 0.005, 5, WHITE],
  [T.montage + EIGHTH * 3, 0.2, 12, 0.005, 5, WHITE],
  [T.montage + PART_B, 0.3, 11, 0.006, 6, BLUE],
  [T.logo, 1.0, 15, 0.01, 14, ICE],
  [T.logo + BEAT, 0.05, 12, 0.002, 0, BLUE],
  [T.logo + BEAT + EIGHTH, 0.05, 12, 0.002, 0, BLUE],
  [T.logo + BEAT * 2, 0.08, 10, 0.003, 1, BLUE],
];
for (let k = 1; k < 6; k++) HITS.push([T.montage + PART_B + k * SIXTEENTH, 0.12, 14, 0.004, 3, BLUE]);

export function postParams(t, fi) {
  let flash = 0;
  let ca = 0.0009;
  let shake = 0;
  const col = [0, 0, 0];
  for (const [ht, f, d, k, s, c] of HITS) {
    const x = t - ht;
    if (x < 0 || x > 2) continue;
    const e = Math.exp(-x * d);
    flash += f * e;
    col[0] += c[0] * f * e;
    col[1] += c[1] * f * e;
    col[2] += c[2] * f * e;
    ca += k * Math.exp(-x * d * 1.8);
    shake += s * Math.exp(-x * 12);
  }
  const flashCol = flash > 0 ? col.map((v) => v / flash) : BLUE;
  // beat pump through the groove (bars 2-6)
  let exposure = 1;
  if (t >= T.scan && t < T.montage) {
    const x = (t - T.scan) % BEAT;
    exposure += 0.035 * Math.exp(-x * 12);
  }
  // glitch: collapse into the montage and the recap cuts
  let glitch = 0;
  glitch += 0.9 * ep(t, COLLAPSE[0] + 0.08, COLLAPSE[1], ease.inQuad) * (t < T.montage ? 1 : 0);
  if (t >= T.montage + PART_B && t < T.montage + PART_C) {
    const x = (t - T.montage - PART_B) % SIXTEENTH;
    glitch += 0.35 * Math.exp(-x * 40);
  }
  // lens breathing on the big hits
  const distort = 0.18 * decay(t - T.logo, 6) + 0.12 * ep(t, ZOOM[0] + 0.2, ZOOM[1], ease.inCubic) * (t < T.scan ? 1 : 0) + 0.1 * decay(t - T.scan, 8);
  const sx = (hash(fi, 1) - 0.5) * 2 * shake;
  const sy = (hash(fi, 2) - 0.5) * 2 * shake;
  // bright full-frame slams must not bloom the whole picture
  const bright = t >= T.montage && t < T.montage + PART_B;
  // the logo hit bursts from the mark rather than washing the frame
  const logoHit = t >= T.logo - 0.01 && t < T.logo + 1.5;
  const mp = markScreen();
  return {
    glowGain: 1.0,
    mainBloom: bright ? 0.0 : 0.08,
    threshold: 0.82,
    bloom: 0.2,
    ca: ca + (bright ? 0.001 : 0),
    flash: clamp(flash, 0, 1),
    flashCol,
    flashPos: logoHit ? [mp[0] / W, 1 - mp[1] / H, 1] : [0.5, 0.5, 0],
    grain: 0.028,
    vignette: bright ? 0.25 : 0.55,
    glitch: clamp(glitch, 0, 1),
    distort,
    exposure,
    fade: 1 - ep(t, DURATION - 0.18, DURATION, ease.inQuad),
    shake: [sx / W, sy / H],
  };
}
