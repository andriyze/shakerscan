import { W, H, FPS, DURATION } from './lib.js';
import { Post } from './post.js';
import { Layers } from './layers.js';
import { direct, postParams, shutterSamples } from './director.js';

const GS = 0.5; // glow layer scale
const mainCanvas = document.createElement('canvas');
mainCanvas.width = W;
mainCanvas.height = H;
const glowCanvas = document.createElement('canvas');
glowCanvas.width = W * GS;
glowCanvas.height = H * GS;
const m = mainCanvas.getContext('2d', { alpha: false });
const g = glowCanvas.getContext('2d', { alpha: false });
const out = document.getElementById('out');
out.width = W;
out.height = H;
const post = new Post(out, W, H, W * GS, H * GS);
const L = new Layers(m, g, GS);

const FONTS = [
  '800 100px "Unbounded"',
  '900 100px "Unbounded"',
  '400 100px "Geist"',
  '500 100px "Geist"',
  '600 100px "Geist"',
  '700 100px "Geist"',
  '400 100px "Geist Mono"',
  '500 100px "Geist Mono"',
  '700 100px "Geist Mono"',
  'italic 400 100px "Instrument Serif"',
];

window.__init = async () => {
  await Promise.all(FONTS.map((f) => document.fonts.load(f)));
  await document.fonts.ready;
  return { fps: FPS, frames: Math.round(DURATION * FPS), width: W, height: H };
};

// Render output frame `fi`. Sub-frames sample a 180-degree shutter centred on the frame time.
window.__renderFrame = (fi, opts = {}) => {
  const tFrame = fi / FPS;
  const k = opts.samples ?? shutterSamples(tFrame);
  const shutter = (opts.shutter ?? 0.5) / FPS;
  post.begin();
  for (let s = 0; s < k; s++) {
    const t = k === 1 ? tFrame : tFrame + ((s + 0.5) / k - 0.5) * shutter;
    L.reset();
    direct(L, t, { fi, tFrame });
    post.accumulate(mainCanvas, glowCanvas, 1 / k);
  }
  post.finish(postParams(tFrame, fi), fi);
  return k;
};

// Raw RGBA of the finished frame (rows bottom-up, as GL returns them).
const pixels = new Uint8Array(W * H * 4);
window.__grab = () => {
  const gl = post.gl;
  gl.bindFramebuffer(gl.FRAMEBUFFER, null);
  gl.readPixels(0, 0, W, H, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
  return pixels;
};
