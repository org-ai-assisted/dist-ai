#!/usr/bin/python3 -Bsu

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
## resolution. Supersampling averages several scene samples into each pixel so
## curved edges and narrow details stay smooth at terminal resolution.

import argparse
import math
import sys

WIDTH = 80          # columns (default; --cols overrides)
ROWS = 22           # text rows -> 2*ROWS pixels tall (default; --rows overrides)
HEIGHT = ROWS * 2
SUPERSAMPLE = 4

UPPER_HALF = '\u2580'   # the upper-half-block glyph; ASCII-escaped source per R-001


def lerp(a, b, t):
    return a + (b - a) * t


def mix(c1, c2, t):
    return tuple(lerp(c1[i], c2[i], t) for i in range(3))


def smoothstep(edge0, edge1, value):
    t = max(0.0, min(1.0, (value - edge0) / (edge1 - edge0)))
    return t * t * (3.0 - 2.0 * t)


def clamp(v):
    return max(0, min(255, round(v)))


def scene_color(nx, ny):
    """Return the continuous RGB scene colour at normalized coordinates."""
    horizon = 0.52          # sea/sky boundary
    beach_top = 0.86        # sand starts
    edge_x = 0.5 / WIDTH
    edge_y = 0.5 / HEIGHT

    # SKY: deep indigo (top) -> warm orange near the horizon.
    top = (34.0, 40.0, 92.0)
    midtop = (120.0, 78.0, 140.0)
    low = (250.0, 156.0, 92.0)
    sky_t = ny / horizon
    sky = mix(top, midtop, smoothstep(0.0, 0.55, sky_t))
    sky = mix(sky, low, smoothstep(0.55, 1.0, sky_t))

    # Smooth radial masks keep both the bright disc and its glow continuous.
    sun_x, sun_y = 0.30, horizon - 0.04
    sun_r = 0.11
    dx = (nx - sun_x) * (WIDTH / HEIGHT)   # correct aspect
    dy = ny - sun_y
    sun_d = math.hypot(dx, dy)
    radial_epsilon = edge_y
    glow = 1.0 - smoothstep(sun_r - radial_epsilon,
                            sun_r + 0.10, sun_d)
    disc = 1.0 - smoothstep(sun_r - radial_epsilon,
                            sun_r + radial_epsilon, sun_d)
    sky = mix(sky, (255.0, 214.0, 150.0), glow)
    sky = mix(sky, (255.0, 240.0, 200.0), disc)

    # SEA: horizon glow -> deeper teal, with a vertical reflection shimmer.
    sea_t = smoothstep(horizon, beach_top, ny)
    sea = mix((232.0, 150.0, 110.0), (18.0, 74.0, 96.0), sea_t)
    wobble = 0.012 * math.sin(ny * 34.0 + 0.7)
    reflection_width = 0.035 + 0.06 * sea_t
    reflection_distance = abs(nx - sun_x - wobble)
    reflection = 1.0 - smoothstep(reflection_width - edge_x,
                                  reflection_width + edge_x,
                                  reflection_distance)
    shimmer = smoothstep(-0.15, 0.35, math.sin(ny * 90.0))
    reflection_strength = (0.5 * (1.0 - sea_t) ** 1.3
                           * reflection * shimmer)
    sea = mix(sea, (255.0, 228.0, 172.0), reflection_strength)

    # BEACH: wet sand near the sea -> dry warm sand at the bottom.
    beach_t = smoothstep(beach_top, 1.0, ny)
    beach = mix((150.0, 120.0, 92.0), (214.0, 190.0, 150.0), beach_t)

    # Smooth surface transitions prevent the horizon and shoreline aliasing.
    col = mix(sky, sea,
              smoothstep(horizon - edge_y, horizon + edge_y, ny))
    col = mix(col, beach,
              smoothstep(beach_top - edge_y, beach_top + edge_y, ny))

    ridge = hill_ridge(nx)
    hill_left = smoothstep(0.52 - edge_x, 0.52 + edge_x, nx)
    hill_top = smoothstep(ridge - edge_y, ridge + edge_y, ny)
    hill_bottom = 1.0 - smoothstep(horizon - edge_y,
                                   horizon + edge_y, ny)
    hill_mask = hill_left * hill_top * hill_bottom

    # floor the denominator: hill_ridge can land on horizon, and shade is clamped
    # to [0, 1] regardless, so this only removes a divide-by-zero at that edge.
    shade = max(0.0, min(1.0, (ny - ridge) / max(1e-6, horizon - ridge)))
    hill = mix((86.0, 150.0, 84.0), (22.0, 66.0, 40.0), shade ** 0.7)
    rim = 0.5 * (1.0 - smoothstep(0.0, 0.12, shade))
    hill = mix(hill, (196.0, 210.0, 150.0), rim)
    return mix(col, hill, hill_mask)


def hill_ridge(nx):
    """Rolling-hills ridge line (ny of the crest) across the far shore."""
    # several offset humps so the crest rolls instead of sitting flat
    r = 0.455
    r -= 0.050 * math.sin(nx * 5.3 + 1.1)
    r -= 0.030 * math.sin(nx * 11.0 + 0.3)
    r -= 0.045 * math.exp(-((nx - 0.82) * 4.5) ** 2)   # one taller hill
    return r


def sample_pixel(x, y, supersample):
    """Average a sample grid across one normalized scene pixel."""
    total = [0.0, 0.0, 0.0]
    for sy in range(supersample):
        ny = (y + (sy + 0.5) / supersample) / HEIGHT
        for sx in range(supersample):
            nx = (x + (sx + 0.5) / supersample) / WIDTH
            col = scene_color(nx, ny)
            for channel in range(3):
                total[channel] += col[channel]
    sample_count = supersample * supersample
    return tuple(value / sample_count for value in total)


def render(supersample=SUPERSAMPLE):
    out = []
    for row in range(ROWS):
        line = []
        for x in range(WIDTH):
            ytop = row * 2
            ybot = row * 2 + 1
            ct = sample_pixel(x, ytop, supersample)
            cb = sample_pixel(x, ybot, supersample)
            line.append(
                '\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm%s'
                % (clamp(ct[0]), clamp(ct[1]), clamp(ct[2]),
                   clamp(cb[0]), clamp(cb[1]), clamp(cb[2]), UPPER_HALF)
            )
        line.append('\x1b[0m')
        out.append(''.join(line))
    return '\n'.join(out) + '\n'


def main(argv=None):
    global WIDTH, ROWS, HEIGHT
    parser = argparse.ArgumentParser(
        description='Display-only truecolor sunset terminal-art (SGR + half-block only).')
    parser.add_argument('--cols', type=int, default=WIDTH,
                        help='width in character columns (default: %(default)s)')
    parser.add_argument('--rows', type=int, default=ROWS,
                        help='text rows, each 2 pixels tall (default: %(default)s)')
    parser.add_argument('--supersample', type=int, default=SUPERSAMPLE,
                        help='samples per axis for each pixel (default: %(default)s)')
    args = parser.parse_args(argv)
    if args.cols < 2 or args.rows < 2:
        parser.error('--cols and --rows must each be >= 2')
    if args.supersample < 1:
        parser.error('--supersample must be >= 1')
    WIDTH = args.cols
    ROWS = args.rows
    HEIGHT = ROWS * 2
    sys.stdout.write(render(args.supersample))


if __name__ == '__main__':
    main()
