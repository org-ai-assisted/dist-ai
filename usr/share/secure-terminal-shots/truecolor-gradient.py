#!/usr/bin/python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Display-only 24-bit colour board: a curated 2D slice of the truecolour gamut.
## SAFE TO cat: emits ONLY SGR colour (ESC[38;2;r;g;bm / ESC[48;2;r;g;bm), the upper-half-block
## glyph, newlines, and a trailing reset. No cursor movement, no clear, no alt-screen, no OSC --
## nothing that repositions or persists; every line ends with ESC[0m so the scrollback stays clean.
##
## RGB is a 3D volume (16.7M colours), so a 2D image can only ever show a slice of it -- not
## every colour. This board picks the most legible slice: hue across X, lightness top-to-bottom
## (white -> pure hue -> black) at full saturation, with a thin greyscale ramp along the bottom.
## The point next to a 256-colour terminal: the ramps are dead smooth here and visibly banded
## there. The upper-half-block 'U+2580' packs two stacked pixels per cell (fg = top, bg = bottom),
## doubling vertical resolution for smooth gradients.

import argparse
import sys

WIDTH = 80          # columns (default; --cols overrides)
ROWS = 22           # text rows -> 2*ROWS pixels tall (default; --rows overrides)
HEIGHT = ROWS * 2

UPPER_HALF = '\u2580'   # the upper-half-block glyph; ASCII-escaped source per R-001

## Bottom greyscale ramp height, in PIXELS (2 per text row). A thin band is enough to read the
## smoothness; the rest of the canvas is the hue x lightness field.
RAMP_PX = 4


def clamp(v):
    return max(0, min(255, round(v)))


def lerp(a, b, t):
    return a + (b - a) * t


def hsl_to_rgb(h, s, light):
    """h, s, light in [0, 1]. Returns an (r, g, b) int triple in [0, 255]."""
    if s == 0:
        v = clamp(light * 255)
        return (v, v, v)
    q = light * (1 + s) if light < 0.5 else light + s - light * s
    p = 2 * light - q

    def hue(t):
        if t < 0:
            t += 1
        if t > 1:
            t -= 1
        if t < 1 / 6:
            return p + (q - p) * 6 * t
        if t < 1 / 2:
            return q
        if t < 2 / 3:
            return p + (q - p) * (2 / 3 - t) * 6
        return p

    return (clamp(hue(h + 1 / 3) * 255), clamp(hue(h) * 255), clamp(hue(h - 1 / 3) * 255))


def pixel(x, y):
    """RGB for pixel (x, y). y = 0 top."""
    nx = x / (WIDTH - 1)

    ramp_top = HEIGHT - RAMP_PX
    if y >= ramp_top:
        # bottom band: a pure greyscale ramp 0 -> 255 across the width.
        v = clamp(nx * 255)
        return (v, v, v)

    # main field: hue across X, lightness white (top) -> pure hue (middle) -> black (bottom).
    ny = y / (ramp_top - 1) if ramp_top > 1 else 0.0
    light = lerp(0.92, 0.08, ny)
    return hsl_to_rgb(nx, 1.0, light)


def render():
    out = []
    for row in range(ROWS):
        line = []
        for x in range(WIDTH):
            ct = pixel(x, row * 2)
            cb = pixel(x, row * 2 + 1)
            line.append(
                '\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm%s'
                % (ct[0], ct[1], ct[2], cb[0], cb[1], cb[2], UPPER_HALF)
            )
        line.append('\x1b[0m')
        out.append(''.join(line))
    return '\n'.join(out) + '\n'


def main(argv=None):
    global WIDTH, ROWS, HEIGHT
    parser = argparse.ArgumentParser(
        description='Display-only 24-bit colour board (SGR truecolour + half-block only).')
    parser.add_argument('--cols', type=int, default=WIDTH,
                        help='width in character columns (default: %(default)s)')
    parser.add_argument('--rows', type=int, default=ROWS,
                        help='text rows, each 2 pixels tall (default: %(default)s)')
    args = parser.parse_args(argv)
    # pixel() normalises by (WIDTH-1), and the bottom RAMP_PX pixels are the greyscale ramp, so
    # the hue x lightness field needs at least one pixel row above it (2*rows > RAMP_PX). Below
    # that the whole canvas is the ramp -- an all-grey board, not the field the comment describes.
    min_rows = RAMP_PX // 2 + 1
    if args.cols < 2 or args.rows < min_rows:
        parser.error('--cols must be >= 2 and --rows >= %d (one row above the %d-pixel ramp)'
                     % (min_rows, RAMP_PX))
    WIDTH = args.cols
    ROWS = args.rows
    HEIGHT = ROWS * 2
    sys.stdout.write(render())


if __name__ == '__main__':
    main()
