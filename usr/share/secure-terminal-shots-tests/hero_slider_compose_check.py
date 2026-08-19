#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Drive the REAL hero-slider-compose.py against a synthetic hero pair and report a verdict.

The homepage before/after slider overlays the secure-terminal and gnome-terminal hero shots,
so the two windows must be the SAME horizontal length. hero-slider-compose.py is the final
guarantor: it unifies the pair to the narrower window's width (a few px of cell-snap is
expected) and FAILS LOUD when the widths differ by more than one shared cell (the capture-time
width pin regressed) instead of padding the gap with white.

    hero_slider_compose_check.py <compose.py> <match|mismatch>

  match     synthetic 1402- and 1396-wide windows (6 px cell-snap): compose must succeed,
            emit two EQUAL-sized outputs, and unify the width to the narrower (1396).
  mismatch  synthetic 1402- and 1277-wide windows (the pre-fix 123 px gap): compose must
            REJECT it (non-zero) -- this is the regression canary. The pre-change compose
            padded to the max width and returned 0, so this case fails on the old tree.

Prints 'OK <mode>' on success, 'FAIL: <reason>' otherwise; exits 0/1 to match.
"""

import subprocess
import sys
import tempfile

from PIL import Image

WHITE = (255, 255, 255)
BLUE = (120, 150, 210)
DARK = (20, 20, 20)


def make_window(path, w, h):
    """A minimal decorated-window shot: a title bar band plus one row of dark text, on a
    white terminal background -- enough for text_top() to find a text row and for the width
    logic to act on."""
    im = Image.new('RGB', (w, h), WHITE)
    px = im.load()
    for y in range(26):                 # title bar
        for x in range(w):
            px[x, y] = BLUE
    for x in range(2, min(200, w)):     # a dark text row below the chrome
        px[x, 40] = DARK
    im.save(path)


def run_compose(compose, work, sec_wh, trad_wh):
    sec = '%s/sec.png' % work
    trad = '%s/trad.png' % work
    out_sec = '%s/out-sec.png' % work
    out_trad = '%s/out-trad.png' % work
    make_window(sec, *sec_wh)
    make_window(trad, *trad_wh)
    proc = subprocess.run(
        ['python3', compose, sec, trad, out_sec, out_trad],
        capture_output=True, text=True)
    return proc, out_sec, out_trad


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        sys.stderr.write('usage: hero_slider_compose_check.py <compose.py> <match|mismatch>\n')
        return 2
    compose, mode = argv

    with tempfile.TemporaryDirectory() as work:
        if mode == 'match':
            proc, out_sec, out_trad = run_compose(compose, work, (1402, 700), (1396, 680))
            if proc.returncode != 0:
                print('FAIL: match pair rejected (rc=%d): %s'
                      % (proc.returncode, proc.stderr.strip()))
                return 1
            a = Image.open(out_sec).size
            b = Image.open(out_trad).size
            if a != b:
                print('FAIL: outputs differ in size: %r vs %r' % (a, b))
                return 1
            if a[0] != 1396:
                print('FAIL: width not unified to the narrower window (got %d, want 1396)'
                      % a[0])
                return 1
            print('OK match')
            return 0

        if mode == 'mismatch':
            proc, _, _ = run_compose(compose, work, (1402, 700), (1277, 680))
            if proc.returncode == 0:
                print('FAIL: 125 px width gap accepted (rc=0) -- the pin regression is not caught')
                return 1
            print('OK mismatch')
            return 0

    sys.stderr.write("hero_slider_compose_check: unknown mode '%s'\n" % mode)
    return 2


if __name__ == '__main__':
    sys.exit(main())
