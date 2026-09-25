#!/usr/bin/env python3
"""Synthesize the showreel soundtrack, locked to the picture's cue sheet.

128 BPM, 8 bars = 15.0 s, A minor (Am - F - C - G - Am, build over F-G, resolve to A major on
the logo). Every hit, tick and whoosh below is derived from the same timing functions the
animation uses, so sound and picture stay frame-accurate.

    python3 audio/soundtrack.py [out/soundtrack.wav]
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from scipy import signal
from scipy.io import wavfile

SR = 48_000
BPM = 128
BEAT = 60 / BPM
BAR = BEAT * 4
EIGHTH = BEAT / 2
SIXTEENTH = BEAT / 4
DUR = BAR * 8
N = int(round(DUR * SR))
RNG = np.random.default_rng(20260925)

T_MAP, T_SCAN, T_HUNT, T_PROVE = 0.0, BAR, BAR * 2, BAR * 3
T_GRADE, T_BEYOND, T_MONTAGE, T_LOGO = BAR * 4, BAR * 5, BAR * 6, BAR * 7

# ----------------------------------------------------------------------------- buses

dry = np.zeros((2, N))
music = np.zeros((2, N))  # sidechained by the kick
verb = np.zeros((2, N))  # reverb send


def midi(n: float) -> float:
    return 440.0 * 2 ** ((n - 69) / 12)


def tvec(dur: float) -> np.ndarray:
    return np.arange(int(dur * SR)) / SR


def place(bus: np.ndarray, sig: np.ndarray, t0: float, gain: float = 1.0, pan: float = 0.0, send: float = 0.0) -> None:
    """Mix a mono or stereo signal into a bus at time t0 with constant-power panning."""
    i0 = int(round(t0 * SR))
    if sig.ndim == 1:
        a = (pan + 1) * np.pi / 4
        sig = np.vstack([sig * np.cos(a), sig * np.sin(a)])
    if i0 < 0:
        sig = sig[:, -i0:]
        i0 = 0
    n = min(sig.shape[1], N - i0)
    if n <= 0:
        return
    bus[:, i0:i0 + n] += sig[:, :n] * gain
    if send:
        verb[:, i0:i0 + n] += sig[:, :n] * gain * send


def noise(n: int) -> np.ndarray:
    return RNG.uniform(-1, 1, n)


def sos(kind: str, f, order: int = 2):
    nyq = SR / 2
    if isinstance(f, (list, tuple)):
        wn = [min(x / nyq, 0.99) for x in f]
    else:
        wn = min(f / nyq, 0.99)
    return signal.butter(order, wn, btype=kind, output='sos')


def filt(x: np.ndarray, kind: str, f, order: int = 2) -> np.ndarray:
    return signal.sosfilt(sos(kind, f, order), x)


def sweep(x: np.ndarray, kind: str, f0: float, f1: float, curve: str = 'exp', q_bw: float = 0.7) -> np.ndarray:
    """Time-varying filter processed in blocks; cutoff moves from f0 to f1."""
    out = np.zeros_like(x)
    block = 256
    nb = int(np.ceil(len(x) / block))
    zi = None
    for b in range(nb):
        p = b / max(1, nb - 1)
        f = f0 * (f1 / f0) ** p if curve == 'exp' else f0 + (f1 - f0) * p
        if kind == 'band':
            s = sos('band', [f * (1 - q_bw / 2), f * (1 + q_bw / 2)])
        else:
            s = sos(kind, f)
        if zi is None:
            zi = np.zeros((s.shape[0], 2))
        seg = x[b * block:(b + 1) * block]
        y, zi = signal.sosfilt(s, seg, zi=zi)
        out[b * block:b * block + len(seg)] = y
    return out


def saw(freq, dur: float) -> np.ndarray:
    """Band-limited sawtooth (polyBLEP); freq may be a scalar or per-sample array."""
    n = int(dur * SR)
    f = np.broadcast_to(np.asarray(freq, dtype=float), (n,)) if np.ndim(freq) == 0 else np.asarray(freq)[:n]
    dt = f / SR
    ph = np.cumsum(dt) % 1.0
    y = 2 * ph - 1
    m1 = ph < dt
    t1 = ph[m1] / dt[m1]
    y[m1] -= t1 + t1 - t1 * t1 - 1
    m2 = ph > 1 - dt
    t2 = (ph[m2] - 1) / dt[m2]
    y[m2] -= t2 * t2 + t2 + t2 + 1
    return y


def sine(freq, dur: float, phase: float = 0.0) -> np.ndarray:
    n = int(dur * SR)
    f = np.broadcast_to(np.asarray(freq, dtype=float), (n,)) if np.ndim(freq) == 0 else np.asarray(freq)[:n]
    return np.sin(2 * np.pi * np.cumsum(f) / SR + phase)


def env_exp(dur: float, rate: float, attack: float = 0.002) -> np.ndarray:
    t = tvec(dur)
    a = np.clip(t / max(attack, 1e-6), 0, 1)
    return a * np.exp(-t * rate)


def env_adsr(dur: float, a: float, d: float, s: float, r: float) -> np.ndarray:
    t = tvec(dur)
    e = np.where(t < a, t / a, np.where(t < a + d, 1 - (1 - s) * (t - a) / d, s))
    rel = np.clip((dur - t) / r, 0, 1)
    return e * rel


# ----------------------------------------------------------------------------- instruments


def kick(punch: float = 1.0, dur: float = 0.5) -> np.ndarray:
    t = tvec(dur)
    f = 44 + 130 * np.exp(-t * 32) * punch
    body = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t * 6.5)
    click = filt(noise(len(t)), 'high', 1800) * np.exp(-t * 260) * 0.45
    return np.tanh(1.6 * (body + click))


def sub_boom(dur: float = 2.2, f0: float = 95, f1: float = 30) -> np.ndarray:
    t = tvec(dur)
    f = f1 + (f0 - f1) * np.exp(-t * 5)
    x = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t * 2.2)
    return np.tanh(1.8 * x)


def clap(dur: float = 0.35) -> np.ndarray:
    n = int(dur * SR)
    t = np.arange(n) / SR
    e = np.zeros(n)
    for k, off in enumerate((0.0, 0.009, 0.018)):
        m = t >= off
        e[m] += np.exp(-(t[m] - off) * (140 if k < 2 else 20)) * (0.8 if k < 2 else 1.0)
    x = filt(noise(n), 'band', [900, 3200]) * e
    return x * 1.6


def hat(open_: bool = False) -> np.ndarray:
    dur = 0.28 if open_ else 0.06
    t = tvec(dur)
    x = filt(noise(len(t)), 'high', 7200, 4)
    return x * np.exp(-t * (11 if open_ else 70))


def crash(dur: float = 2.2) -> np.ndarray:
    t = tvec(dur)
    x = filt(noise(len(t)), 'high', 3500, 2)
    x += 0.5 * filt(noise(len(t)), 'band', [5000, 9000])
    return x * (np.exp(-t * 2.1) * 0.8 + np.exp(-t * 18) * 0.6)


def blip(freq: float, dur: float = 0.12, rate: float = 38, kind: str = 'sine', fm: float = 0.0) -> np.ndarray:
    t = tvec(dur)
    if fm:
        mod = np.sin(2 * np.pi * freq * 2.01 * t) * fm * np.exp(-t * 30)
        x = np.sin(2 * np.pi * freq * t + mod)
    elif kind == 'tri':
        x = signal.sawtooth(2 * np.pi * freq * t, 0.5)
    else:
        x = np.sin(2 * np.pi * freq * t)
    return x * env_exp(dur, rate, 0.001)


def click(bright: float = 4000, dur: float = 0.012) -> np.ndarray:
    t = tvec(dur)
    return filt(noise(len(t)), 'band', [bright * 0.6, bright * 1.4]) * np.exp(-t * 600)


def whoosh(dur: float, f0: float, f1: float, peak: float = 0.5) -> np.ndarray:
    n = int(dur * SR)
    t = np.arange(n) / SR
    x = noise(n)
    half = int(n * peak)
    up = sweep(x[:half], 'band', f0, f1, q_bw=0.9)
    down = sweep(x[half:], 'band', f1, f0 * 1.5, q_bw=0.9)
    y = np.concatenate([up, down])
    p = t / dur
    bell = np.where(p < peak, (p / peak) ** 2.2, np.exp(-(p - peak) / (1 - peak) * 4))
    return y * bell


def riser(dur: float, f0: float = 300, f1: float = 9000) -> np.ndarray:
    n = int(dur * SR)
    t = np.arange(n) / SR
    x = sweep(noise(n), 'band', f0, f1, q_bw=0.6)
    tone = saw(110 * 2 ** (3 * (t / dur) ** 1.6), dur) * 0.25
    tone = sweep(tone, 'low', 400, 6000)
    return (x + tone) * (t / dur) ** 2.4


def reverse_swell(dur: float = 0.9) -> np.ndarray:
    tail = crash(dur) + 0.6 * sweep(noise(int(dur * SR)), 'low', 9000, 800) * np.exp(-tvec(dur) * 3)
    return tail[::-1] * 0.9


def pluck(freq: float, dur: float = 0.22, cutoff: float = 3200) -> np.ndarray:
    x = saw(freq, dur) + 0.5 * saw(freq * 1.005, dur)
    x = sweep(x, 'low', cutoff, 300)
    return x * env_exp(dur, 16, 0.002)


def supersaw(freq: float, dur: float, voices: int = 5, spread: float = 0.012) -> np.ndarray:
    out = np.zeros((2, int(dur * SR)))
    for v in range(voices):
        d = (v - (voices - 1) / 2) / ((voices - 1) / 2)
        x = saw(freq * (1 + d * spread), dur)
        pan = d * 0.8
        a = (pan + 1) * np.pi / 4
        out[0] += x * np.cos(a)
        out[1] += x * np.sin(a)
    return out / voices


def bell(freq: float, dur: float = 1.6) -> np.ndarray:
    t = tvec(dur)
    x = np.sin(2 * np.pi * freq * t) * np.exp(-t * 2.6)
    x += 0.4 * np.sin(2 * np.pi * freq * 2.76 * t) * np.exp(-t * 5)
    x += 0.2 * np.sin(2 * np.pi * freq * 5.4 * t) * np.exp(-t * 9)
    return x * np.clip(t / 0.002, 0, 1)


def clank() -> np.ndarray:
    dur = 0.6
    t = tvec(dur)
    x = np.zeros(len(t))
    for f, r, a in ((317, 7, 0.6), (873, 11, 0.45), (1447, 16, 0.3), (2310, 24, 0.2)):
        x += a * np.sin(2 * np.pi * f * t) * np.exp(-t * r)
    x += filt(noise(len(t)), 'band', [1500, 6000]) * np.exp(-t * 90) * 0.8
    return x


def glitch_burst(dur: float, seed: int) -> np.ndarray:
    r = np.random.default_rng(seed)
    n = int(dur * SR)
    out = np.zeros(n)
    step = int(SIXTEENTH / 2 * SR)
    for i in range(0, n, step):
        seg = min(step, n - i)
        f = r.choice([220, 330, 440, 660, 880, 1320])
        tt = np.arange(seg) / SR
        sq = np.sign(np.sin(2 * np.pi * f * tt)) * 0.4
        nz = r.uniform(-1, 1, seg) * 0.5
        s = sq if r.random() < 0.5 else nz
        crush = np.round(s * 6) / 6
        out[i:i + seg] = crush * np.exp(-tt * 30)
    return out


def tape_stop(dur: float = 0.26, f0: float = 220) -> np.ndarray:
    t = tvec(dur)
    f = f0 * (1 - t / dur) ** 2 + 20
    x = saw(f, dur) * 0.5 + np.sin(2 * np.pi * np.cumsum(f / 2) / SR) * 0.6
    return filt(x, 'low', 1800) * (1 - t / dur)


# ----------------------------------------------------------------------------- arrangement

CHORDS = {
    'Am': (45, [57, 60, 64, 67]),
    'F': (41, [53, 57, 60, 64]),
    'C': (48, [55, 60, 64, 67]),
    'G': (43, [55, 59, 62, 67]),
    'A': (45, [57, 61, 64, 69, 71]),
}
PROG = ['Am', 'F', 'C', 'G', 'Am']  # bars 2-6

kick_times: list[float] = []


def add_kick(t: float, gain: float = 1.0, punch: float = 1.0) -> None:
    place(dry, kick(punch), t, gain)
    kick_times.append(t)


def groove() -> None:
    for b, name in enumerate(PROG):
        t0 = T_SCAN + b * BAR
        root, notes = CHORDS[name]
        for k in range(4):
            tb = t0 + k * BEAT
            add_kick(tb, 0.95)
            # rolling bass on the three 16ths after each kick
            for s in (1, 2, 3):
                ts = tb + s * SIXTEENTH
                f = midi(root - 12 if s != 2 else root)
                x = saw(f, SIXTEENTH * 0.95) * 0.6 + np.sin(2 * np.pi * midi(root - 12) * tvec(SIXTEENTH * 0.95)) * 0.8
                x = filt(x, 'low', 900) * env_exp(SIXTEENTH * 0.95, 9, 0.003)
                place(music, x, ts, 0.34)
            # hats
            place(dry, hat(False), tb + EIGHTH, 0.16, pan=0.25)
            place(dry, hat(True), tb + EIGHTH, 0.05, pan=0.25)
            for s in (1, 3):
                place(dry, hat(False), tb + s * SIXTEENTH, 0.06 + 0.03 * RNG.random(), pan=-0.3)
            if k in (1, 3):
                place(dry, clap(), tb, 0.36, send=0.25)
        # pad
        pad = np.zeros((2, int(BAR * SR) + 2000))
        for n in notes:
            pad[:, :int(BAR * SR)] += supersaw(midi(n), BAR)
        pad = np.vstack([sweep(pad[0], 'low', 900, 2600), sweep(pad[1], 'low', 900, 2600)])
        e = env_adsr(BAR + 2000 / SR, 0.08, 0.3, 0.8, 0.2)
        place(music, pad * e, t0, 0.2, send=0.3)
        # arp from bar 3 on
        if b >= 1:
            seq = notes + [n + 12 for n in notes]
            for s in range(16):
                idx = [0, 1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 2, 3, 4, 7][s] % len(seq)
                place(music, pluck(midi(seq[idx] + 12), 0.2, 2400 + 1600 * (s % 4 == 0)), t0 + s * SIXTEENTH, 0.07, pan=0.35 * np.sin(s), send=0.25)


def intro() -> None:
    # ignition zap + sub thump
    t = tvec(0.35)
    zap = np.sin(2 * np.pi * np.cumsum(300 + 3800 * np.exp(-t * 18)) / SR) * np.exp(-t * 9)
    place(dry, zap, 0.03, 0.3, send=0.35)
    place(dry, sub_boom(1.2, 110, 36), 0.03, 0.55)
    place(dry, crash(1.6), 0.03, 0.1, send=0.6)
    # dark drone
    d = BAR - 0.03
    drone = np.zeros((2, int(d * SR)))
    for n in (45, 52, 57, 60):
        drone += supersaw(midi(n), d, 5, 0.008)
    drone = np.vstack([sweep(drone[0], 'low', 250, 1800), sweep(drone[1], 'low', 250, 1800)])
    drone *= np.linspace(0, 1, drone.shape[1]) ** 0.8
    place(music, drone, 0.03, 0.2, send=0.4)
    # MAP lands on beat 1
    add_kick(BEAT, 0.8, 0.9)
    place(dry, clap(), BEAT, 0.12, send=0.5)
    # 16th ticks, rising
    for s in range(4, 16):
        place(dry, hat(False), s * SIXTEENTH, 0.04 + 0.1 * s / 16, pan=0.3 * (-1) ** s)
    # target discoveries: pentatonic sparkle
    penta = [81, 84, 86, 88, 91, 93]
    for k in range(12):
        td = BEAT + 0.02 + k * SIXTEENTH * 0.5
        place(dry, blip(midi(penta[(k * 2) % 6] + (12 if k > 7 else 0)), 0.18, 24, fm=1.5), td, 0.06, pan=RNG.uniform(-0.7, 0.7), send=0.5)
    # zoom-through riser into the drop
    r = riser(0.95, 250, 9000)
    place(dry, r, T_SCAN - 0.95, 0.34, send=0.3)
    place(dry, reverse_swell(0.5), T_SCAN - 0.5, 0.42)


def scan_sfx() -> None:
    place(dry, crash(2.4), T_SCAN, 0.22, send=0.4)
    place(dry, sub_boom(1.4, 100, 34), T_SCAN, 0.6)
    # typing the URL
    for i in range(21):
        place(dry, click(3500 + 800 * RNG.random()), T_SCAN + 0.12 + i * (0.3 / 21), 0.12, pan=0.2)
    # beam hits, ascending
    notes = [69, 72, 74, 76, 79, 81, 84]
    sev = ['crit', 'ok', 'high', 'med', 'high', 'crit', 'ok']
    for i, n in enumerate(notes):
        ti = T_SCAN + BEAT + i * SIXTEENTH
        place(dry, blip(midi(n + 12), 0.14, 26, fm=0.8), ti, 0.11, pan=-0.4 + i * 0.13, send=0.3)
        if sev[i] != 'ok':
            place(dry, blip(midi(n), 0.08, 40, kind='tri'), ti, 0.06)
    # profile switch
    place(dry, click(2200, 0.02), T_SCAN + BEAT * 2, 0.35)
    place(dry, blip(midi(88), 0.1, 30), T_SCAN + BEAT * 2, 0.07)
    # whip pan
    place(dry, whoosh(0.6, 400, 5000, 0.62), T_HUNT - 0.36, 0.5, send=0.2)


def hunt_sfx() -> None:
    # needle spin ratchet: one click per 20 degrees of the real needle rotation
    lock = BEAT
    us = np.linspace(-0.25, lock, 4000)
    p = np.clip((us + 0.25) / (lock + 0.25), 0, 1)
    ang = -(1 - (1 - (1 - p) ** 3)) * 2 * np.pi * 3.25
    steps = np.floor(ang / np.deg2rad(20))
    for i in np.nonzero(np.diff(steps))[0]:
        place(dry, click(5200, 0.008), T_HUNT + us[i], 0.16, pan=0.3)
    place(dry, clank(), T_HUNT + lock, 0.18, send=0.3)
    # typing the agent command
    for i in range(25):
        place(dry, click(3000 + 900 * RNG.random()), T_HUNT + 0.05 + i * (0.31 / 25), 0.1, pan=-0.35)
    # capability invocations: FM packets rising
    for k, n in enumerate([76, 79, 81, 84, 88]):
        tk = T_HUNT + BEAT + k * EIGHTH
        place(dry, blip(midi(n + 12), 0.16, 22, fm=2.5), tk, 0.09, pan=-0.5 + k * 0.25, send=0.35)
    # needle-to-window wipe
    place(dry, whoosh(0.5, 300, 7000, 0.7), T_PROVE - 0.36, 0.34, send=0.3)
    place(dry, reverse_swell(0.35), T_PROVE - 0.35, 0.2)


def prove_sfx() -> None:
    place(dry, crash(1.8), T_PROVE, 0.12, send=0.4)
    # verifying warble
    t = tvec(BEAT)
    war = np.sin(2 * np.pi * (660 + 40 * np.sin(2 * np.pi * 14 * t)) * t) * np.exp(-t * 3) * (1 - np.exp(-t * 60))
    place(dry, war, T_PROVE + BEAT, 0.05, send=0.3)
    # VERIFIED stamp
    tv = T_PROVE + BEAT * 2
    place(dry, sub_boom(0.9, 120, 40), tv, 0.5)
    place(dry, clank(), tv, 0.32, send=0.35)
    for k, n in enumerate((81, 85, 88, 93)):
        place(dry, bell(midi(n), 1.6), tv + 0.03 + k * 0.035, 0.09, pan=-0.3 + k * 0.2, send=0.6)
    # card flip
    place(dry, whoosh(0.4, 600, 6000, 0.5), T_GRADE - 0.28, 0.3, pan=0.2)


def grade_sfx() -> None:
    # slot reel: tick every time a letter passes the window
    land = BEAT * 2
    us = np.linspace(0.12, land, 4000)
    pos = 23 - 22 * (1 - (us - 0.12) / (land - 0.12)) ** 2
    for i in np.nonzero(np.diff(np.floor(pos)))[0]:
        place(dry, click(2600, 0.01), T_GRADE + us[i], 0.2, pan=-0.1)
    place(dry, bell(midi(88), 1.2), T_GRADE + land, 0.1, send=0.5)
    place(dry, bell(midi(93), 1.2), T_GRADE + land + 0.02, 0.07, send=0.5)
    # assurance segments fill on 16ths
    for i, n in enumerate((76, 79, 81, 83)):
        place(dry, blip(midi(n + 12), 0.09, 40), T_GRADE + BEAT + i * SIXTEENTH, 0.06, pan=0.4)


def beyond_sfx() -> None:
    for i in range(3):
        tl = T_BEYOND + i * BEAT
        place(dry, whoosh(0.34, 200, 3000, 0.75), tl - 0.26, 0.28, pan=(-0.6, 0, 0.6)[i])
        place(dry, sub_boom(0.5, 90, 40), tl, 0.25)
    # prompt injection alert (AI Gate)
    ta = T_BEYOND + 0.68
    place(dry, blip(midi(84), 0.09, 30, kind='tri'), ta, 0.08, pan=-0.6)
    place(dry, blip(midi(79), 0.12, 24, kind='tri'), ta + 0.07, 0.08, pan=-0.6)
    # model intake denied
    tb = T_BEYOND + BEAT + 0.2 + 5 * SIXTEENTH * 0.9 + 0.08
    t = tvec(0.25)
    buzz = signal.square(2 * np.pi * 98 * t) * np.exp(-t * 10)
    place(dry, filt(buzz, 'low', 1200), tb, 0.12)
    # device port sweep sonar
    for k, v in enumerate((0.18, 0.27, 0.39, 0.46, 0.55)):
        place(dry, blip(midi(91 - k * 2), 0.2, 16), T_BEYOND + BEAT * 2 + v, 0.05, pan=0.6, send=0.5)
    # glitch collapse into the montage
    g = glitch_burst(0.24, 7)
    place(dry, g, T_MONTAGE - 0.26, 0.18, pan=0.0)
    place(dry, tape_stop(0.26), T_MONTAGE - 0.26, 0.3)


def montage_sfx() -> None:
    # four eighth-note slams
    for k in range(4):
        tk = T_MONTAGE + k * EIGHTH
        add_kick(tk, 1.0, 1.2)
        place(dry, clap(), tk, 0.34, send=0.3)
        place(dry, crash(0.9), tk, 0.13 + 0.03 * k, send=0.3)
        place(dry, sub_boom(0.4, 80 + 10 * k, 40), tk, 0.3)
    # montage: 16th snare build + riser
    t_b = T_MONTAGE + BEAT * 2
    for k in range(6):
        tk = t_b + k * SIXTEENTH
        place(dry, clap(), tk, 0.18 + 0.04 * k, send=0.3)
        place(dry, kick(1.3, 0.25), tk, 0.35 + 0.05 * k)
        place(dry, blip(midi(69 + k * 2), 0.1, 30, kind='tri'), tk, 0.06)
    # 32nd-note roll in the last beat
    for k in range(6):
        place(dry, clap(), t_b + 6 * SIXTEENTH + k * SIXTEENTH / 2, 0.1 + 0.03 * k)
    # held F -> G chords under the build
    for i, name in enumerate(('F', 'G')):
        root, notes = CHORDS[name]
        d = BAR / 2
        pad = np.zeros((2, int(d * SR)))
        for n in notes:
            pad += supersaw(midi(n), d)
        pad = np.vstack([sweep(pad[0], 'low', 1200, 5000), sweep(pad[1], 'low', 1200, 5000)])
        place(music, pad * env_adsr(d, 0.02, 0.1, 0.9, 0.05), T_MONTAGE + i * d, 0.2, send=0.3)
    place(dry, riser(BEAT * 2, 400, 10000), T_LOGO - BEAT * 2, 0.26, send=0.3)
    place(dry, reverse_swell(0.62), T_LOGO - 0.62, 0.5)


def logo_sfx() -> None:
    tl = T_LOGO
    place(dry, sub_boom(2.6, 110, 28), tl, 0.95)
    place(dry, kick(1.4, 0.6), tl, 0.9)
    place(dry, crash(2.8), tl, 0.34, send=0.8)
    place(dry, clank(), tl, 0.22, send=0.6)
    root, notes = CHORDS['A']
    d = DUR - tl
    pad = np.zeros((2, int(d * SR)))
    for n in notes + [n + 12 for n in notes[:3]]:
        pad += supersaw(midi(n), d, 7, 0.01)
    pad = np.vstack([sweep(pad[0], 'low', 5000, 1400), sweep(pad[1], 'low', 5000, 1400)])
    pad *= env_adsr(d, 0.01, 0.6, 0.55, 0.9)
    place(dry, pad, tl, 0.2, send=0.6)
    bass = saw(midi(root - 12), d) * 0.5 + sine(midi(root - 24), d)
    place(dry, filt(bass, 'low', 600) * env_exp(d, 1.4, 0.005), tl, 0.35)
    for k, n in enumerate((81, 88, 93)):
        place(dry, bell(midi(n), 2.2), tl + 0.02 + k * 0.04, 0.11, pan=-0.3 + 0.3 * k, send=0.7)
    # Scan. Hunt. Prove. on eighths
    for k, (n, g) in enumerate(((76, 0.1), (81, 0.1), (85, 0.16))):
        tk = tl + BEAT + k * EIGHTH
        place(dry, pluck(midi(n), 0.5, 5200), tk, g, pan=(-0.3, 0, 0.3)[k], send=0.5)
        place(dry, bell(midi(n + 12), 1.4), tk, g * 0.6, send=0.6)
        place(dry, hat(False), tk, 0.08)
    place(dry, sub_boom(0.8, 70, 40), tl + BEAT * 2, 0.2)


# ----------------------------------------------------------------------------- render


def reverb_ir(dur: float = 2.6) -> np.ndarray:
    t = tvec(dur)
    irs = []
    for ch in range(2):
        n = RNG.standard_normal(len(t))
        n = filt(n, 'low', 7000) * np.exp(-t * 2.4)
        n[: int(0.012 * SR)] *= np.linspace(0, 1, int(0.012 * SR))
        irs.append(n / np.sqrt(np.sum(n ** 2)))
    return np.vstack(irs)


def sidechain_env() -> np.ndarray:
    t = np.arange(N) / SR
    g = np.ones(N)
    for tk in kick_times:
        m = t >= tk
        x = t[m] - tk
        g[m] = np.minimum(g[m], 1 - 0.72 * np.exp(-x / 0.11) * (x < 0.4))
    return g


def main(out: Path) -> None:
    intro()
    groove()
    scan_sfx()
    hunt_sfx()
    prove_sfx()
    grade_sfx()
    beyond_sfx()
    montage_sfx()
    logo_sfx()
    sc = sidechain_env()
    mix = dry + music * sc
    ir = reverb_ir()
    wet = np.vstack([signal.fftconvolve(verb[c], ir[c])[:N] for c in range(2)])
    mix += wet * 0.55
    # gentle master: low-cut, soft clip, fade tail, normalise to -1.5 dBFS (AAC true-peak headroom)
    mix = np.vstack([filt(mix[c], 'high', 28) for c in range(2)])
    mix = np.tanh(mix * 1.15) / np.tanh(1.15)
    fade = np.ones(N)
    nf = int(0.35 * SR)
    fade[-nf:] = np.linspace(1, 0, nf) ** 1.5
    mix *= fade
    peak = np.max(np.abs(mix))
    mix *= 10 ** (-1.5 / 20) / peak
    out.parent.mkdir(parents=True, exist_ok=True)
    wavfile.write(out, SR, mix.T.astype(np.float32))
    rms = np.sqrt(np.mean(mix ** 2))
    print(f'wrote {out}  {DUR:.3f}s  peak -1.5 dBFS  rms {20 * np.log10(rms):.1f} dBFS')


if __name__ == '__main__':
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'out' / 'soundtrack.wav')
