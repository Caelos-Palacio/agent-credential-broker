#!/usr/bin/env python3
# ---- suite kit (identical in every repo): 800x450, 15 fps, pure render(t) -> image ----
import os, sys, shutil, subprocess, tempfile
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

W, H, FPS, S = 800, 450, 15, 2          # S = supersampling factor
BG, TEXT, MUTED = '#0d1117', '#e6edf3', '#8b949e'
ACCENT, OK, ERROR, WARN = '#58a6ff', '#3fb950', '#f85149', '#d29922'
FONT_DIRS = [Path.home() / '.local/share/fonts/JetBrainsMonoNerd']
FALLBACK = ['/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf']
FONT_FILES = {False: 'JetBrainsMonoNerdFont-Regular.ttf', True: 'JetBrainsMonoNerdFont-Bold.ttf'}


def rgb(h, a=1.0):
    h = h.lstrip('#')
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), round(255 * max(0, min(1, a))))


def clamp(x): return max(0.0, min(1.0, x))
def seg(t, a, b): return clamp((t - a) / (b - a))
def ease(x): x = clamp(x); return 4 * x ** 3 if x < .5 else 1 - (-2 * x + 2) ** 3 / 2   # cubic in-out
def lerp(a, b, k): return a + (b - a) * k
def typed(s, t, t0, cps=55): return s[:max(0, int((t - t0) * cps))]


_fonts = {}
def font(size, bold=False):
    key = (size, bold)
    if key not in _fonts:
        cands = [d / FONT_FILES[bold] for d in FONT_DIRS] + [Path(p) for p in FALLBACK]
        path = next(p for p in cands if p.exists())
        _fonts[key] = ImageFont.truetype(str(path), round(size * S))
    return _fonts[key]


class Cv:
    def __init__(self):
        self.img = Image.new('RGB', (W * S, H * S), BG)
        self.d = ImageDraw.Draw(self.img, 'RGBA')

    def text(self, x, y, s, size=13, color=TEXT, a=1.0, bold=False, anchor='la'):
        if a > .01 and s:
            self.d.text((x * S, y * S), s, font=font(size, bold), fill=rgb(color, a), anchor=anchor)

    def width(self, s, size=13, bold=False): return font(size, bold).getlength(s) / S

    def box(self, x0, y0, x1, y1, outline=MUTED, a=1.0, fill=None, fa=1.0, r=6, w=1):
        self.d.rounded_rectangle([x0 * S, y0 * S, x1 * S, y1 * S], radius=r * S,
                                 outline=rgb(outline, a), width=round(w * S),
                                 fill=rgb(fill, fa) if fill else None)

    def line(self, x0, y0, x1, y1, color=MUTED, a=1.0, w=1, dash=0):
        if not dash:
            self.d.line([x0 * S, y0 * S, x1 * S, y1 * S], fill=rgb(color, a), width=round(w * S))
            return
        n = int(max(abs(x1 - x0), abs(y1 - y0)) // dash)
        for i in range(0, n, 2):
            p, q = i / n, min(1, (i + 1) / n)
            self.d.line([lerp(x0, x1, p) * S, lerp(y0, y1, p) * S, lerp(x0, x1, q) * S, lerp(y0, y1, q) * S],
                        fill=rgb(color, a), width=round(w * S))

    def arrow(self, x0, y0, x1, y1, color=MUTED, a=1.0):
        self.line(x0, y0, x1, y1, color, a)
        s = 1 if x1 > x0 else -1
        self.d.polygon([(x1 * S, y1 * S), ((x1 - 7 * s) * S, (y1 - 4) * S), ((x1 - 7 * s) * S, (y1 + 4) * S)], fill=rgb(color, a))

    def dot(self, x, y, color=ACCENT, a=1.0, r=4.5):
        self.d.ellipse([(x - r) * S, (y - r) * S, (x + r) * S, (y + r) * S], fill=rgb(color, a))
        self.d.ellipse([(x - r * 2) * S, (y - r * 2) * S, (x + r * 2) * S, (y + r * 2) * S], fill=rgb(color, a * .16))


def envelope(t, T, fade=.5):
    """Loop envelope: blank at t=0 and t=T, so the GIF loops seamlessly."""
    return ease(seg(t, 0, fade)) * (1 - ease(seg(t, T - fade, T)))


def finish(cv, t, T):
    blank = Image.new('RGB', cv.img.size, BG)
    img = Image.blend(blank, cv.img, envelope(t, T))
    return img.resize((W, H), Image.LANCZOS)


def build(render, T, out, frame=None):
    if frame is not None:
        render(frame).save(out); return
    n = round(T * FPS)
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(n):
            render(i / FPS).save(f'{tmp}/f{i:04d}.png')
        pal = f'{tmp}/pal.png'
        subprocess.run(['ffmpeg', '-v', 'error', '-y', '-framerate', str(FPS), '-i', f'{tmp}/f%04d.png',
                        '-vf', 'palettegen=max_colors=128:stats_mode=full', pal], check=True)
        subprocess.run(['ffmpeg', '-v', 'error', '-y', '-framerate', str(FPS), '-i', f'{tmp}/f%04d.png', '-i', pal,
                        '-lavfi', 'paletteuse=dither=none', '-loop', '0', str(out)], check=True)
    print(f'{out}: {n} frames, {T}s, {Path(out).stat().st_size / 1e6:.2f} MB')


def cli(render, T, default_out):
    a = sys.argv[1:]
    if a[:1] == ['--frame']:          # python demo.py --frame 5.5 out.png
        build(render, T, a[2], float(a[1]))
    else:
        build(render, T, a[0] if a else default_out)
# ---- end kit ----

# ---- scene: agent -> broker -> API; every terminal line is REAL output (capture.json) ----
HERE = Path(__file__).resolve().parent
import json
CAP = json.loads((HERE / 'capture.json').read_text())
T = 10.0
STEPS = CAP['steps']


def clip(s, n):                      # truncation is always shown with an ellipsis
    return s if len(s) <= n else s[:n - 1] + '…'

def mid(s, a, b): return s if len(s) <= a + b + 3 else s[:a] + ' … ' + s[-b:]

IN = [s['in'] for s in STEPS]
OUT = [clip(STEPS[0]['out'], 88), clip(STEPS[1]['out'], 88), STEPS[2]['out']]
AUDIT = mid(CAP['audit'][0], 56, 28)
KEY = CAP['fakeKey']
AG, BR, AP = (40, 180), (330, 470), (620, 760)       # node x-ranges
YN = (80, 150)                                       # node y-range
LANE_REQ, LANE_RES = 105, 127
PH = [(0.5, 2.6), (2.6, 4.6), (4.6, 8.0), (8.0, 9.4)]
CAPTIONS = [
    (0.6, 4.6, 'The agent asks for a named action. It never supplies a URL or a header.'),
    (4.6, 8.0, 'The key leaves only toward the API. What comes back is projected to {"id"}.'),
    (8.0, 9.4, 'Audit export: metadata only. No key, no payload.'),
]


def node(cv, rng, title, sub, active, sub_color=MUTED):
    a = lerp(.45, 1, active)
    cv.box(rng[0], YN[0], rng[1], YN[1], outline=ACCENT if active > .5 else MUTED, a=a, r=8)
    cv.text((rng[0] + rng[1]) / 2, YN[0] + 20, title, 13, TEXT, a, bold=True, anchor='ma')
    cv.text((rng[0] + rng[1]) / 2, YN[0] + 44, sub, 12, sub_color, a, anchor='ma')


def travel(cv, x0, x1, y, t, a, b, color=ACCENT):
    k = seg(t, a, b)
    if 0 < k < 1: cv.dot(lerp(x0, x1, ease(k)), y, color)


def render(t):
    cv = Cv()
    cv.text(40, 24, 'agent-credential-broker', 14, TEXT, bold=True)
    cv.text(760, 26, 'fake key · stub provider · real CLI output', 12, MUTED, anchor='ra')
    # --- diagram
    act = lambda a, b: ease(seg(t, a, a + .3)) * (1 - ease(seg(t, b - .3, b)))
    ag = max(act(.5, 2.6), act(2.6, 4.6), act(4.6, 5.4), act(7.4, 8.0))
    br = max(act(.9, 2.6), act(3.0, 4.6), act(5.0, 7.6), act(8.0, 9.4))
    ap = act(5.9, 7.0)
    cv.line(255, 62, 255, 168, MUTED, .7, dash=5)
    cv.text(255, 168, 'trust boundary', 12, MUTED, .8, anchor='ma')
    cv.arrow(AG[1] + 6, LANE_REQ, BR[0] - 6, LANE_REQ, MUTED, .5)
    cv.arrow(BR[1] + 6, LANE_REQ, AP[0] - 6, LANE_REQ, MUTED, .5)
    cv.arrow(BR[0] - 6, LANE_RES, AG[1] + 6, LANE_RES, MUTED, .35)
    cv.arrow(AP[0] - 6, LANE_RES, BR[1] + 6, LANE_RES, MUTED, .35)
    node(cv, AG, 'AGENT', 'holds no key', ag)
    node(cv, BR, 'BROKER', clip(KEY, 12), br, WARN)
    node(cv, AP, 'API', 'api.example.com', ap)
    # packets
    for a, b in ((0.9, 1.4), (3.0, 3.5), (5.0, 5.5)):
        travel(cv, AG[1] + 6, BR[0] - 6, LANE_REQ, t, a, b)
    for a, b in ((1.6, 2.1), (3.7, 4.2)):
        travel(cv, BR[0] - 6, AG[1] + 6, LANE_RES, t, a, b, OK)
    travel(cv, BR[1] + 6, AP[0] - 6, LANE_REQ, t, 5.8, 6.4, WARN)      # key-bearing request: broker -> API only
    travel(cv, AP[0] - 6, BR[1] + 6, LANE_RES, t, 6.6, 7.1, MUTED)     # raw provider body
    travel(cv, BR[0] - 6, AG[1] + 6, LANE_RES, t, 7.4, 7.9, OK)        # projected result
    # projection note under broker<->API: {id, api_key_echo} -> api_key_echo struck
    k = ease(seg(t, 7.0, 7.35)) * (1 - ease(seg(t, 7.8, 8.0)))
    if k > .01:
        parts = [('{"id", ', TEXT), ('"api_key_echo"', ERROR), ('}', TEXT)]
        total = sum(cv.width(p, 12) for p, _ in parts); x = 545 - total / 2
        for p, c in parts:
            cv.text(x, 140, p, 12, c, k)
            if c == ERROR: cv.line(x, 147, x + cv.width(p, 12), 147, ERROR, k)
            x += cv.width(p, 12)
        cv.text(545, 160, 'dropped by the broker', 12, MUTED, k, anchor='ma')
    # --- terminal
    cv.box(40, 196, 760, 394, MUTED, .5, r=6)
    cv.text(54, 205, 'agent · broker.sock', 12, MUTED, .9)
    cv.line(54, 350, 746, 350, MUTED, .3)
    y = 228
    rows = [(.6, 'in', IN[0], 1.55), (1.6, 'out', OUT[0], 2.0),
            (2.7, 'in', IN[1], 3.5), (3.7, 'out', OUT[1], 4.1),
            (4.7, 'in', IN[2], 5.3), (7.5, 'out', OUT[2], 7.9)]
    for t0, kind, s, ready in rows:
        if t < t0: y += 20; continue
        if kind == 'in':
            cv.text(54, y, '>', 13, ACCENT)
            cv.text(72, y, clip(typed(s, t, t0, 70), 88), 13, TEXT)
        else:
            key_line = s is OUT[2]
            cv.text(72, y, s, 13, OK if key_line else MUTED, ease(seg(t, t0, t0 + .25)), bold=key_line)
        y += 20
    ta = ease(seg(t, 8.0, 8.3))
    cv.text(54, 356, 'custodian $ agent-credential-broker audit-export --directory DIR', 12, MUTED, ta)
    cv.text(54, 374, typed(AUDIT, t, 8.3, 140), 12, TEXT, ta)
    # --- caption
    for a, b, s in CAPTIONS:
        k = ease(seg(t, a, a + .3)) * (1 - ease(seg(t, b - .3, b)))
        cv.text(40, 414, s, 14, TEXT, k)
    return finish(cv, t, T)


if __name__ == '__main__':
    cli(render, T, HERE / 'demo.gif')
