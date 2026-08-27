#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Compose the homepage before/after slider pair from the two hero-compare shots.

The site's CSS resize slider overlays the two images, so they must be the SAME size and
their terminal TEXT must sit at the same coordinates -- otherwise dragging the divider
jogs the text. secure-terminal carries more top chrome (a toolbar + tab strip) and a
bottom notice than a plain terminal, so its text starts lower. This:

  1. finds each image's text top -- the first white terminal row (below the title bar)
     that carries dark text;
  2. keeps the TITLE BARS aligned at y=0, and inserts a white band ABOVE the text of the
     shallower-chrome terminal so both text tops line up (padding with terminal
     background, so the band reads as ordinary empty terminal space);
  3. unifies the WIDTH to the narrower window (both windows are pinned to one width at
     capture, so this only trims a few px of border off the wider one; a larger gap fails
     loud -- the pin regressed) and pads the height to the taller shot, so both land on one
     shared canvas and the two windows overlay exactly.

    hero-slider-compose.py <secure.png> <traditional.png> <out-secure.png> <out-traditional.png>
"""

import os
import sys

from PIL import Image

WHITE = (255, 255, 255)


def shot_scale():
    """SHOT_SCALE from the environment (default 1), validated like the shell side: a
    non-integer or < 1 value falls back to 1 rather than distorting the tolerance."""
    try:
        s = int(os.environ.get('SHOT_SCALE', '1'))
    except (TypeError, ValueError):
        return 1
    return s if s >= 1 else 1


# Never strip a shot below this height: a real black band is a thin bottom strip, so a
# trim that would consume almost the whole image means the shot is degenerate (a blank /
# all-black grab that capture_settled should have discarded upstream). Stopping at a floor
# keeps the result taller than text_top()'s default (28) so the later crop stays valid --
# an all-black image would otherwise strip to ~0 and crash pad_above_text with lower<upper.
MIN_KEEP = 40


def strip_bottom_black(im, thresh=16, frac=0.98):
    """Trim trailing near-uniform-BLACK rows off the bottom of a window shot.

    The taller shot (secure-terminal) carries a band of the captured compositor / window
    frame -- pure black -- below its status bar; the shorter shot has none. Left in, that
    band shows as a black strip on one side of the slider (the other side is white
    compose-padding). Trimming it lets both shots end on their real content, so the shared
    canvas pads BOTH with the same white below the window. A row counts as background only
    when nearly every pixel is near-black, so a content row (status pills, text) is never
    cut; and it never strips below MIN_KEEP, so a degenerate all-black grab cannot strip to
    nothing and crash the crop below."""
    g = im.convert('L')
    w, h = g.size
    px = g.load()
    y = h
    while y > MIN_KEEP and sum(1 for x in range(w) if px[x, y - 1] < thresh) >= w * frac:
        y -= 1
    return im if y == h else im.crop((0, 0, w, y))


def text_top(im):
    """First row (below the title bar) that is a white terminal row carrying dark text."""
    g = im.convert('L')
    w, h = g.size
    px = g.load()
    strip = min(200, w)
    for y in range(28, h):
        white = sum(1 for x in range(w) if px[x, y] >= 250)
        if white <= w * 0.6:
            continue
        if any(px[x, y] < 90 for x in range(2, strip)):
            return y
    return 28


def pad_above_text(im, top, amount):
    """Insert `amount` px of white between row `top` and the rest, so the text below
    `top` shifts down while the chrome above it (incl. the title bar) stays put."""
    if amount <= 0:
        return im
    w, h = im.size
    out = Image.new('RGB', (w, h + amount), WHITE)
    out.paste(im.crop((0, 0, w, top)), (0, 0))
    out.paste(im.crop((0, top, w, h)), (0, top + amount))
    return out


def extent(im, w, h):
    out = Image.new('RGB', (w, h), WHITE)
    out.paste(im, (0, 0))
    return out


# Both hero windows are pinned to ONE width at CAPTURE time (comparison-capture.sh
# HERO_WIN_W_BASE), so each shot -- cropped to its own window -- should already be the same
# width bar a few px of VTE cell-snap on the traditional side. A gap wider than a few cells
# means that pin BROKE (a narrower window would leave a dead-space band on one side of the
# slider). Fail loud rather than paper over it with white padding. The tolerance is scaled by
# SHOT_SCALE (the capture pipeline scales every geometry by it) so it keeps meaning ~3 Hack
# cells at any scale: a FIXED px tolerance would accept multi-cell cropping at SHOT_SCALE=1
# and could reject a legitimate one-cell snap at a high scale.
MAX_WIDTH_GAP_BASE = 20   # 1x px, ~3 Hack cells; multiplied by SHOT_SCALE at use


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 4:
        sys.stderr.write('usage: hero-slider-compose.py <secure.png> <traditional.png>'
                         ' <out-secure.png> <out-traditional.png>\n')
        return 2
    sec_p, trad_p, out_sec, out_trad = argv
    sec = strip_bottom_black(Image.open(sec_p).convert('RGB'))
    trad = strip_bottom_black(Image.open(trad_p).convert('RGB'))

    # The two windows must be the SAME horizontal length or the slider exposes a dead-space
    # band when dragged. They are pinned equal at capture; refuse a composition where they are
    # not (the capture-time pin regressed) instead of hiding it behind padding.
    gap = abs(sec.width - trad.width)
    max_gap = MAX_WIDTH_GAP_BASE * shot_scale()
    if gap > max_gap:
        sys.stderr.write(
            'hero-slider-compose: hero window widths differ by %d px (secure %d, traditional'
            ' %d) -- exceeds the %d px cell-snap tolerance; the capture-time width pin'
            ' (HERO_WIN_W_BASE) regressed. Not composing a mismatched slider pair.\n'
            % (gap, sec.width, trad.width, max_gap))
        return 1

    tt_sec = text_top(sec)
    tt_trad = text_top(trad)
    target = max(tt_sec, tt_trad)
    sec = pad_above_text(sec, tt_sec, target - tt_sec)
    trad = pad_above_text(trad, tt_trad, target - tt_trad)

    # Unify the width to the NARROWER window and crop both to it, so both windows end at the
    # same x and overlay exactly -- trimming only the few px of window border the wider one
    # carries past the shared width (the gap is <= MAX_WIDTH_GAP, guarded above, so no content
    # is cut). Height still pads to the taller shot (compose aligned the text tops; the extra
    # is empty terminal rows).
    w = min(sec.width, trad.width)
    h = max(sec.height, trad.height)
    extent(sec.crop((0, 0, w, sec.height)), w, h).save(out_sec)
    extent(trad.crop((0, 0, w, trad.height)), w, h).save(out_trad)
    print('hero-slider-compose: %dx%d (text top aligned at y=%d, width gap %d px)'
          % (w, h, target, gap))
    return 0


if __name__ == '__main__':
    sys.exit(main())
