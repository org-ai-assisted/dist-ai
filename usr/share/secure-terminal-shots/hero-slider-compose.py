#!/usr/bin/python3
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
  3. pads both to one shared canvas (max width x max height, white, top-left).

    hero-slider-compose.py <secure.png> <traditional.png> <out-secure.png> <out-traditional.png>
"""

import sys

from PIL import Image

WHITE = (255, 255, 255)


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


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 4:
        sys.stderr.write('usage: hero-slider-compose.py <secure.png> <traditional.png>'
                         ' <out-secure.png> <out-traditional.png>\n')
        return 2
    sec_p, trad_p, out_sec, out_trad = argv
    sec = Image.open(sec_p).convert('RGB')
    trad = Image.open(trad_p).convert('RGB')

    tt_sec = text_top(sec)
    tt_trad = text_top(trad)
    target = max(tt_sec, tt_trad)
    sec = pad_above_text(sec, tt_sec, target - tt_sec)
    trad = pad_above_text(trad, tt_trad, target - tt_trad)

    w = max(sec.width, trad.width)
    h = max(sec.height, trad.height)
    extent(sec, w, h).save(out_sec)
    extent(trad, w, h).save(out_trad)
    print('hero-slider-compose: %dx%d (text top aligned at y=%d)' % (w, h, target))
    return 0


if __name__ == '__main__':
    sys.exit(main())
