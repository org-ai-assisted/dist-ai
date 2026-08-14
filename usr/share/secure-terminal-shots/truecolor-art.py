#!/usr/bin/python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Display-only truecolor terminal-art demo (a sunset beach + green hills).
## SAFE TO cat: emits ONLY SGR colour (ESC[38;2;r;g;bm / ESC[48;2;r;g;bm),
## the half-block glyph, newlines, and a trailing reset. No cursor movement,
## no screen clear, no alt-screen, no title/OSC -- nothing that repositions or
## persists. Every line ends with ESC[0m so a scrollback stays clean.
##
## Technique: the upper-half-block 'U+2580' shows TWO stacked pixels per cell --
## foreground = top pixel, background = bottom pixel -- doubling vertical
## resolution for smooth gradients.

import math
import sys

WIDTH = 80          # columns
ROWS = 22           # text rows -> 2*ROWS pixels tall
HEIGHT = ROWS * 2

UPPER_HALF = '\u2580'   # the upper-half-block glyph; ASCII-escaped source per R-001


def lerp(a, b, t):
    return a + (b - a) * t


def mix(c1, c2, t):
    return tuple(round(lerp(c1[i], c2[i], t)) for i in range(3))


def clamp(v):
    return max(0, min(255, round(v)))


def pixel(x, y):
    """RGB for pixel (x,y). y=0 top."""
    nx = x / (WIDTH - 1)
    ny = y / (HEIGHT - 1)

    horizon = 0.52          # sea/sky boundary
    beach_top = 0.86        # sand starts

    # --- sun ---
    sun_x, sun_y = 0.30, horizon - 0.04
    sun_r = 0.11
    dx = (nx - sun_x) * (WIDTH / HEIGHT)   # correct aspect
    dy = ny - sun_y
    sun_d = math.hypot(dx, dy)

    if ny < horizon:
        # SKY: deep indigo (top) -> warm orange near the horizon
        t = ny / horizon
        top = (34, 40, 92)
        midtop = (120, 78, 140)
        low = (250, 156, 92)
        if t < 0.55:
            col = mix(top, midtop, t / 0.55)
        else:
            col = mix(midtop, low, (t - 0.55) / 0.45)
        # the sun disc + glow
        if sun_d < sun_r:
            col = (255, 240, 200)
        elif sun_d < sun_r + 0.10:
            g = (sun_d - sun_r) / 0.10
            col = mix((255, 214, 150), col, g)
        return col

    if ny < beach_top:
        # SEA: horizon glow -> deeper teal, with a vertical sun-reflection shimmer
        t = (ny - horizon) / (beach_top - horizon)
        near = (232, 150, 110)     # reflected sunset at the waterline
        far = (18, 74, 96)
        col = mix(near, far, t)
        # vertical sun-reflection column: horizontal shimmer bands directly
        # below the sun, widening and fading with depth.
        wobble = 0.012 * math.sin(ny * 34 + 0.7)
        refl = abs(nx - sun_x - wobble) < (0.035 + 0.06 * t)
        band = math.sin(ny * 90) > 0.1
        if refl and band:
            col = mix(col, (255, 228, 172), 0.5 * (1 - t) ** 1.3)
        return col

    # BEACH: wet sand near the sea -> dry warm sand at the bottom
    t = (ny - beach_top) / (1 - beach_top)
    wet = (150, 120, 92)
    dry = (214, 190, 150)
    return mix(wet, dry, t)


def hill_ridge(nx):
    """Rolling-hills ridge line (ny of the crest) across the far shore."""
    # several offset humps so the crest rolls instead of sitting flat
    r = 0.455
    r -= 0.050 * math.sin(nx * 5.3 + 1.1)
    r -= 0.030 * math.sin(nx * 11.0 + 0.3)
    r -= 0.045 * math.exp(-((nx - 0.82) * 4.5) ** 2)   # one taller hill
    return r


def apply_hills(x, y, col):
    nx = x / (WIDTH - 1)
    ny = y / (HEIGHT - 1)
    horizon = 0.52
    ridge = hill_ridge(nx)
    # hills sit on the far shore (right side), crest above the waterline
    if nx > 0.52 and ridge < ny < horizon:
        shade = (ny - ridge) / max(0.001, (horizon - ridge))
        crest = (86, 150, 84)     # sun-lit crest
        deep = (22, 66, 40)       # shadowed base
        base = mix(crest, deep, shade ** 0.7)
        # rim light along the very top edge
        if shade < 0.12:
            base = mix(base, (196, 210, 150), 0.5 * (1 - shade / 0.12))
        return base
    return col


def render():
    out = []
    for row in range(ROWS):
        line = []
        for x in range(WIDTH):
            ytop = row * 2
            ybot = row * 2 + 1
            ct = apply_hills(x, ytop, pixel(x, ytop))
            cb = apply_hills(x, ybot, pixel(x, ybot))
            line.append(
                '\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm%s'
                % (clamp(ct[0]), clamp(ct[1]), clamp(ct[2]),
                   clamp(cb[0]), clamp(cb[1]), clamp(cb[2]), UPPER_HALF)
            )
        line.append('\x1b[0m')
        out.append(''.join(line))
    return '\n'.join(out) + '\n'


if __name__ == '__main__':
    sys.stdout.write(render())
