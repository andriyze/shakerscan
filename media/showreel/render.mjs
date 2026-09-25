#!/usr/bin/env node
// Deterministic renderer: drives index.html frame by frame in headless Chromium, reads back the
// finished WebGL frame, and streams raw pixels over localhost straight into one ffmpeg encode.
// Frames never depend on wall-clock time, so any frame can be re-rendered identically.
//
//   node render.mjs                                  full render -> out/shakerscan-showreel.mp4
//   node render.mjs --stills 0,300,840 --dir stills  PNG stills of individual frames
//   node render.mjs --from 0 --to 120 --preview      partial, quick render
//
// Environment: FFMPEG (default "ffmpeg"), CHROMIUM (optional executable path).
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const v = args[i + 1];
  return v === undefined || v.startsWith('--') ? true : v;
};

const FFMPEG = process.env.FFMPEG || 'ffmpeg';
const W = 1920;
const H = 1080;
const FRAME_BYTES = W * H * 4;
const stills = opt('stills', null);
const outDir = path.resolve(opt('dir', path.join(ROOT, 'out')));
const outFile = path.resolve(opt('out', path.join(ROOT, 'out', 'shakerscan-showreel.mp4')));
const audio = path.resolve(opt('audio', path.join(ROOT, 'out', 'soundtrack.wav')));
const samplesOverride = opt('samples', null);
const preview = Boolean(opt('preview', false));
const workers = Number(opt('workers', 2));

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.woff2': 'font/woff2', '.json': 'application/json' };
let onFrame = null; // (index, Buffer) => Promise, resolves once the frame has been consumed

function serve() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'POST' && url.pathname === '/frame') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', async () => {
        const buf = Buffer.concat(chunks);
        if (!onFrame || buf.length !== FRAME_BYTES) {
          res.writeHead(400);
          res.end();
          return;
        }
        await onFrame(Number(url.searchParams.get('i')), buf);
        res.writeHead(204);
        res.end();
      });
      return;
    }
    const rel = decodeURIComponent(url.pathname).replace(/^\/+/, '') || 'index.html';
    const file = path.resolve(ROOT, rel);
    if (!file.startsWith(ROOT)) {
      res.writeHead(403);
      res.end();
      return;
    }
    fs.readFile(file, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
      res.end(data);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// One browser per worker: each gets its own GPU process, so SwiftShader work runs in parallel.
async function openWorker(port) {
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM || undefined,
    // CPU raster for 2D canvas is ~12x faster than emulated-GPU raster; WebGL stays on SwiftShader.
    args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist', '--disable-accelerated-2d-canvas'],
  });
  const page = await browser.newPage({ viewport: { width: W, height: H }, deviceScaleFactor: 1 });
  page.on('pageerror', (e) => console.error('[page error]', e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('[console]', m.text());
  });
  await page.goto(`http://127.0.0.1:${port}/index.html`);
  await page.waitForFunction(() => typeof window.__init === 'function');
  const info = await page.evaluate(() => window.__init());
  const render = (fi, samples) =>
    page.evaluate(
      async ([f, s]) => {
        window.__renderFrame(f, s ? { samples: s } : {});
        // A Blob body takes Chromium's fast data-pipe path: ~30 ms for 8 MB versus ~420 ms for a
        // bare Uint8Array body.
        const r = await fetch(`/frame?i=${f}`, { method: 'POST', body: new Blob([window.__grab()]) });
        if (!r.ok) throw new Error(`frame upload failed: ${r.status}`);
      },
      [fi, samples],
    );
  return { browser, info, render };
}

function ffmpeg(argv) {
  const ff = spawn(FFMPEG, ['-y', '-loglevel', 'error', ...argv], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise((resolve, reject) =>
    ff.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`ffmpeg exited ${code}`)))),
  );
  const write = (buf) => new Promise((resolve) => (ff.stdin.write(buf) ? resolve() : ff.stdin.once('drain', resolve)));
  return { ff, done, write };
}

const RAW_IN = (fps) => ['-f', 'rawvideo', '-pix_fmt', 'rgba', '-s', `${W}x${H}`, '-framerate', String(fps), '-i', '-'];

async function main() {
  const server = await serve();
  const port = server.address().port;
  const samples = samplesOverride ? Number(samplesOverride) : preview ? 2 : null;
  const opened = [];
  try {
    if (stills) {
      fs.mkdirSync(outDir, { recursive: true });
      const wk = await openWorker(port);
      opened.push(wk);
      for (const f of String(stills).split(',').map(Number)) {
        const t0 = Date.now();
        const file = path.join(outDir, `frame_${String(f).padStart(4, '0')}.png`);
        const enc = ffmpeg([...RAW_IN(wk.info.fps), '-vf', 'vflip', '-frames:v', '1', file]);
        onFrame = (_, buf) => enc.write(buf);
        await wk.render(f, samples);
        enc.ff.stdin.end();
        await enc.done;
        console.log(`${file}  (${Date.now() - t0} ms)`);
      }
      return;
    }

    for (let i = 0; i < workers; i++) opened.push(await openWorker(port));
    const { fps, frames } = opened[0].info;
    const from = Number(opt('from', 0));
    const to = Math.min(Number(opt('to', frames)), frames);
    const total = to - from;
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    const withAudio = fs.existsSync(audio);
    const enc = ffmpeg([
      ...RAW_IN(fps),
      ...(withAudio ? ['-ss', String(from / fps), '-t', String(total / fps), '-i', audio] : []),
      '-map', '0:v', ...(withAudio ? ['-map', '1:a', '-c:a', 'aac', '-b:a', '256k'] : []),
      '-vf', 'vflip,scale=out_color_matrix=bt709:out_range=tv,format=yuv420p',
      '-c:v', 'libx264', '-preset', preview ? 'veryfast' : 'slow', '-crf', preview ? '22' : String(opt('crf', 19)),
      '-tune', 'film', '-x264-params', 'aq-mode=3',
      '-colorspace', 'bt709', '-color_primaries', 'bt709', '-color_trc', 'bt709', '-color_range', 'tv',
      '-movflags', '+faststart', '-r', String(fps),
      outFile,
    ]);
    // Workers render interleaved frames; a small reorder buffer feeds the encoder in order and
    // holds back any worker that runs ahead.
    let next = from;
    const waiting = new Map();
    const pump = async () => {
      while (waiting.has(next)) {
        const { buf, resolve } = waiting.get(next);
        waiting.delete(next);
        await enc.write(buf);
        next++;
        resolve();
      }
    };
    let pumping = Promise.resolve();
    onFrame = (i, buf) =>
      new Promise((resolve) => {
        waiting.set(i, { buf, resolve });
        pumping = pumping.then(pump);
      });
    const started = Date.now();
    let rendered = 0;
    await Promise.all(
      opened.map(async (wk, w) => {
        for (let f = from + w; f < to; f += opened.length) {
          await wk.render(f, samples);
          rendered++;
          if (rendered % 30 === 0) {
            const el = (Date.now() - started) / 1000;
            console.log(`  ${rendered}/${total} frames  ${(el / rendered).toFixed(2)} s/frame  eta ${Math.round((el / rendered) * (total - rendered))} s`);
          }
        }
      }),
    );
    await pumping;
    enc.ff.stdin.end();
    await enc.done;
    console.log(`wrote ${outFile}  (${total} frames in ${Math.round((Date.now() - started) / 1000)} s${withAudio ? ', with audio' : ''})`);
  } finally {
    await Promise.all(opened.map((wk) => wk.browser.close()));
    server.close();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
