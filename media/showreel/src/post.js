// WebGL2 post pipeline: linear-light motion-blur accumulation, dual-filter bloom driven by a
// dedicated glow layer, then a lens pass (chromatic aberration, glitch, grain, vignette, flash).

const VS = `#version 300 es
out vec2 vUv;
void main() {
  vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
  vUv = p;
  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;

const HEAD = `#version 300 es
precision highp float;
in vec2 vUv;
out vec4 o;
`;

const FS_ACC = `${HEAD}
uniform sampler2D uSrc;
uniform float uW;
void main() {
  // canvases are uploaded top-down (no UNPACK_FLIP_Y copy), so flip here
  vec3 c = texture(uSrc, vec2(vUv.x, 1.0 - vUv.y)).rgb;
  o = vec4(pow(c, vec3(2.2)) * uW, uW);
}`;

const FS_PRE = `${HEAD}
uniform sampler2D uGlow;
uniform sampler2D uMain;
uniform float uGlowGain;
uniform float uMainGain;
uniform float uThresh;
void main() {
  vec3 g = texture(uGlow, vUv).rgb * uGlowGain;
  vec3 m = texture(uMain, vUv).rgb;
  float l = max(max(m.r, m.g), m.b);
  vec3 b = m * smoothstep(uThresh, uThresh + 0.35, l) * uMainGain;
  o = vec4(g + b, 1.0);
}`;

const FS_DOWN = `${HEAD}
uniform sampler2D uSrc;
uniform vec2 uTexel;
void main() {
  vec2 h = uTexel;
  vec3 s = texture(uSrc, vUv).rgb * 4.0;
  s += texture(uSrc, vUv - h).rgb;
  s += texture(uSrc, vUv + h).rgb;
  s += texture(uSrc, vUv + vec2(h.x, -h.y)).rgb;
  s += texture(uSrc, vUv - vec2(h.x, -h.y)).rgb;
  o = vec4(s / 8.0, 1.0);
}`;

const FS_UP = `${HEAD}
uniform sampler2D uSrc;
uniform sampler2D uBase;
uniform vec2 uTexel;
uniform float uBaseW;
void main() {
  vec2 h = uTexel;
  vec3 s = texture(uSrc, vUv + vec2(-h.x * 2.0, 0.0)).rgb;
  s += texture(uSrc, vUv + vec2(-h.x, h.y)).rgb * 2.0;
  s += texture(uSrc, vUv + vec2(0.0, h.y * 2.0)).rgb;
  s += texture(uSrc, vUv + vec2(h.x, h.y)).rgb * 2.0;
  s += texture(uSrc, vUv + vec2(h.x * 2.0, 0.0)).rgb;
  s += texture(uSrc, vUv + vec2(h.x, -h.y)).rgb * 2.0;
  s += texture(uSrc, vUv + vec2(0.0, -h.y * 2.0)).rgb;
  s += texture(uSrc, vUv + vec2(-h.x, -h.y)).rgb * 2.0;
  o = vec4(s / 12.0 + texture(uBase, vUv).rgb * uBaseW, 1.0);
}`;

const FS_FINAL = `${HEAD}
uniform sampler2D uMain;
uniform sampler2D uBloom;
uniform vec2 uRes;
uniform float uFrame;
uniform float uCA;
uniform float uBloomAmt;
uniform float uFlash;
uniform vec3 uFlashCol;
uniform vec3 uFlashPos; // uv of the burst centre, z = how focused (0 = uniform)
uniform float uGrain;
uniform float uVig;
uniform float uGlitch;
uniform float uDistort;
uniform float uExposure;
uniform float uFade;
uniform vec2 uShake;

float h11(float p) { p = fract(p * 0.1031); p *= p + 33.33; p *= p + p; return fract(p); }
float h21(vec2 p) { vec3 p3 = fract(vec3(p.xyx) * 0.1031); p3 += dot(p3, p3.yzx + 33.33); return fract((p3.x + p3.y) * p3.z); }

vec3 shoulder(vec3 c) {
  const float k = 0.82;
  vec3 over = max(c - k, 0.0);
  return min(c, vec3(k)) + (1.0 - k) * (1.0 - exp(-over / (1.0 - k)));
}

void main() {
  vec2 uv = vUv;
  float gl = uGlitch;
  if (gl > 0.001) {
    float band = floor(uv.y * 28.0);
    float r = h11(band * 13.17 + uFrame * 7.31);
    if (r < gl * 0.55) uv.x += (h11(band * 3.31 + uFrame * 1.93) - 0.5) * 0.16 * gl;
    float blk = floor(uv.y * 7.0) + floor(uv.x * 5.0) * 7.0;
    if (h11(blk * 5.1 + uFrame * 3.7) < gl * 0.18) uv += (vec2(h11(blk + uFrame), h11(blk * 2.0 + uFrame)) - 0.5) * 0.05 * gl;
  }
  vec2 cc = uv - 0.5;
  cc.x *= uRes.x / uRes.y;
  float r2 = dot(cc, cc);
  uv = (uv - 0.5) * (1.0 + uDistort * r2) / (1.0 + uDistort * 0.25) + 0.5 + uShake;

  vec2 dir = uv - 0.5;
  float ca = uCA * (0.35 + 1.65 * length(dir)) + gl * 0.006;
  vec3 col;
  col.r = texture(uMain, uv + dir * ca).r;
  col.g = texture(uMain, uv).g;
  col.b = texture(uMain, uv - dir * ca).b;
  vec3 bl;
  bl.r = texture(uBloom, uv + dir * ca * 1.5).r;
  bl.g = texture(uBloom, uv).g;
  bl.b = texture(uBloom, uv - dir * ca * 1.5).b;
  col += bl * uBloomAmt;
  col *= uExposure;
  col = shoulder(col);

  vec2 vv = (vUv - 0.5) * vec2(1.0, 1.1);
  float vig = smoothstep(0.92, 0.2, length(vv) * 1.25);
  col *= mix(1.0, vig, uVig);

  col = pow(max(col, 0.0), vec3(1.0 / 2.2));
  // flash is a screen blend in display space so small values stay subtle; focused flashes
  // burst from a point instead of lifting the whole frame
  float fd = length((vUv - uFlashPos.xy) * vec2(uRes.x / uRes.y, 1.0));
  float fmask = mix(1.0, 0.18 + 0.82 * exp(-fd * fd * 5.0), uFlashPos.z);
  col = 1.0 - (1.0 - col) * (1.0 - clamp(uFlashCol * uFlash * fmask, 0.0, 1.0));
  float n = h21(gl_FragCoord.xy + fract(uFrame * 0.6180339) * vec2(113.1, 71.7))
          + h21(gl_FragCoord.xy * 1.37 + fract(uFrame * 0.3117) * vec2(51.3, 97.1)) - 1.0;
  float lum = dot(col, vec3(0.2126, 0.7152, 0.0722));
  col += n * uGrain * (0.45 + 0.55 * (1.0 - abs(lum * 2.0 - 1.0)));
  col *= uFade;
  o = vec4(col, 1.0);
}`;

function compile(gl, type, src) {
  const s = gl.createShader(type);
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s) + '\n' + src);
  return s;
}

function program(gl, fs) {
  const p = gl.createProgram();
  gl.attachShader(p, compile(gl, gl.VERTEX_SHADER, VS));
  gl.attachShader(p, compile(gl, gl.FRAGMENT_SHADER, fs));
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p));
  const uniforms = {};
  const n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
  for (let i = 0; i < n; i++) {
    const info = gl.getActiveUniform(p, i);
    uniforms[info.name] = gl.getUniformLocation(p, info.name);
  }
  return { p, u: uniforms };
}

function texture(gl, w, h, internal, format, type) {
  const t = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, t);
  gl.texImage2D(gl.TEXTURE_2D, 0, internal, w, h, 0, format, type, null);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  return t;
}

function target(gl, w, h) {
  const tex = texture(gl, w, h, gl.RGBA16F, gl.RGBA, gl.HALF_FLOAT);
  const fb = gl.createFramebuffer();
  gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
  gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
  if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) throw new Error('incomplete framebuffer');
  return { tex, fb, w, h };
}

export class Post {
  constructor(canvas, w, h, gw, gh) {
    const gl = canvas.getContext('webgl2', {
      antialias: false,
      alpha: false,
      premultipliedAlpha: false,
      preserveDrawingBuffer: true,
    });
    if (!gl) throw new Error('WebGL2 unavailable');
    if (!gl.getExtension('EXT_color_buffer_float')) throw new Error('float render targets unavailable');
    this.gl = gl;
    this.w = w;
    this.h = h;
    this.progAcc = program(gl, FS_ACC);
    this.progPre = program(gl, FS_PRE);
    this.progDown = program(gl, FS_DOWN);
    this.progUp = program(gl, FS_UP);
    this.progFinal = program(gl, FS_FINAL);
    this.srcMain = texture(gl, w, h, gl.RGBA8, gl.RGBA, gl.UNSIGNED_BYTE);
    this.srcGlow = texture(gl, gw, gh, gl.RGBA8, gl.RGBA, gl.UNSIGNED_BYTE);
    this.accMain = target(gl, w, h);
    this.accGlow = target(gl, gw, gh);
    this.down = [];
    let lw = gw;
    let lh = gh;
    for (let i = 0; i < 6; i++) {
      this.down.push(target(gl, lw, lh));
      lw = Math.max(1, Math.round(lw / 2));
      lh = Math.max(1, Math.round(lh / 2));
    }
    this.up = this.down.map((d) => target(gl, d.w, d.h));
    this.vao = gl.createVertexArray();
    // Both canvases are opaque, so premultiplied upload is exact and skips a per-pixel conversion.
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
    gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, true);
  }

  begin() {
    const gl = this.gl;
    for (const t of [this.accMain, this.accGlow]) {
      gl.bindFramebuffer(gl.FRAMEBUFFER, t.fb);
      gl.viewport(0, 0, t.w, t.h);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
    }
  }

  // Upload one sub-frame and add it into the accumulation buffers with the given weight.
  accumulate(mainCanvas, glowCanvas, weight) {
    const gl = this.gl;
    gl.bindVertexArray(this.vao);
    gl.bindTexture(gl.TEXTURE_2D, this.srcMain);
    gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, gl.RGBA, gl.UNSIGNED_BYTE, mainCanvas);
    gl.bindTexture(gl.TEXTURE_2D, this.srcGlow);
    gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, gl.RGBA, gl.UNSIGNED_BYTE, glowCanvas);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE);
    gl.useProgram(this.progAcc.p);
    gl.uniform1i(this.progAcc.u.uSrc, 0);
    gl.uniform1f(this.progAcc.u.uW, weight);
    gl.activeTexture(gl.TEXTURE0);
    for (const [src, dst] of [
      [this.srcMain, this.accMain],
      [this.srcGlow, this.accGlow],
    ]) {
      gl.bindFramebuffer(gl.FRAMEBUFFER, dst.fb);
      gl.viewport(0, 0, dst.w, dst.h);
      gl.bindTexture(gl.TEXTURE_2D, src);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }
    gl.disable(gl.BLEND);
  }

  pass(prog, dst, bind) {
    const gl = this.gl;
    gl.useProgram(prog.p);
    gl.bindFramebuffer(gl.FRAMEBUFFER, dst ? dst.fb : null);
    gl.viewport(0, 0, dst ? dst.w : this.w, dst ? dst.h : this.h);
    bind(prog.u);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }

  bindTex(unit, tex) {
    const gl = this.gl;
    gl.activeTexture(gl.TEXTURE0 + unit);
    gl.bindTexture(gl.TEXTURE_2D, tex);
  }

  finish(p, frame) {
    const gl = this.gl;
    gl.bindVertexArray(this.vao);
    this.pass(this.progPre, this.down[0], (u) => {
      this.bindTex(0, this.accGlow.tex);
      this.bindTex(1, this.accMain.tex);
      gl.uniform1i(u.uGlow, 0);
      gl.uniform1i(u.uMain, 1);
      gl.uniform1f(u.uGlowGain, p.glowGain);
      gl.uniform1f(u.uMainGain, p.mainBloom);
      gl.uniform1f(u.uThresh, p.threshold);
    });
    for (let i = 1; i < this.down.length; i++) {
      const src = this.down[i - 1];
      this.pass(this.progDown, this.down[i], (u) => {
        this.bindTex(0, src.tex);
        gl.uniform1i(u.uSrc, 0);
        gl.uniform2f(u.uTexel, 1 / src.w, 1 / src.h);
      });
    }
    let prev = this.down[this.down.length - 1];
    for (let i = this.down.length - 2; i >= 0; i--) {
      const base = this.down[i];
      const src = prev;
      this.pass(this.progUp, this.up[i], (u) => {
        this.bindTex(0, src.tex);
        this.bindTex(1, base.tex);
        gl.uniform1i(u.uSrc, 0);
        gl.uniform1i(u.uBase, 1);
        gl.uniform2f(u.uTexel, 1 / src.w, 1 / src.h);
        gl.uniform1f(u.uBaseW, 1.0);
      });
      prev = this.up[i];
    }
    const bloom = prev;
    this.pass(this.progFinal, null, (u) => {
      this.bindTex(0, this.accMain.tex);
      this.bindTex(1, bloom.tex);
      gl.uniform1i(u.uMain, 0);
      gl.uniform1i(u.uBloom, 1);
      gl.uniform2f(u.uRes, this.w, this.h);
      gl.uniform1f(u.uFrame, frame);
      gl.uniform1f(u.uCA, p.ca);
      gl.uniform1f(u.uBloomAmt, p.bloom);
      gl.uniform1f(u.uFlash, p.flash);
      gl.uniform3f(u.uFlashCol, p.flashCol[0], p.flashCol[1], p.flashCol[2]);
      gl.uniform3f(u.uFlashPos, p.flashPos[0], p.flashPos[1], p.flashPos[2]);
      gl.uniform1f(u.uGrain, p.grain);
      gl.uniform1f(u.uVig, p.vignette);
      gl.uniform1f(u.uGlitch, p.glitch);
      gl.uniform1f(u.uDistort, p.distort);
      gl.uniform1f(u.uExposure, p.exposure);
      gl.uniform1f(u.uFade, p.fade);
      gl.uniform2f(u.uShake, p.shake[0], p.shake[1]);
    });
    gl.finish();
  }
}
