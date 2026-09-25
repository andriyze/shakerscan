// Two synchronized 2D contexts: `m` is the picture, `g` is the emission layer that only feeds bloom.
// Transform and clip calls go to both so glow always registers with the picture.
export class Layers {
  constructor(m, g, gs) {
    this.m = m;
    this.g = g;
    this.gs = gs;
  }

  reset() {
    for (const c of [this.m, this.g]) {
      c.setTransform(1, 0, 0, 1, 0, 0);
      c.globalAlpha = 1;
      c.globalCompositeOperation = 'source-over';
      c.filter = 'none';
      c.letterSpacing = '0px';
      c.lineDash = [];
      c.setLineDash([]);
      c.lineCap = 'butt';
      c.lineJoin = 'miter';
    }
    this.g.fillStyle = '#000';
    this.g.fillRect(0, 0, this.g.canvas.width, this.g.canvas.height);
    this.g.setTransform(this.gs, 0, 0, this.gs, 0, 0);
  }

  save() {
    this.m.save();
    this.g.save();
  }

  restore() {
    this.m.restore();
    this.g.restore();
  }

  translate(x, y) {
    this.m.translate(x, y);
    this.g.translate(x, y);
  }

  scale(x, y = x) {
    this.m.scale(x, y);
    this.g.scale(x, y);
  }

  rotate(a) {
    this.m.rotate(a);
    this.g.rotate(a);
  }

  transform(a, b, c, d, e, f) {
    this.m.transform(a, b, c, d, e, f);
    this.g.transform(a, b, c, d, e, f);
  }

  // Scale around a pivot point.
  zoom(s, px, py, rot = 0) {
    this.translate(px, py);
    if (rot) this.rotate(rot);
    this.scale(s, s);
    this.translate(-px, -py);
  }

  alpha(a) {
    this.m.globalAlpha *= a;
    this.g.globalAlpha *= a;
  }

  clip(pathFn) {
    for (const c of [this.m, this.g]) {
      c.beginPath();
      pathFn(c);
      c.clip();
    }
  }

  both(fn) {
    fn(this.m, false);
    fn(this.g, true);
  }
}
