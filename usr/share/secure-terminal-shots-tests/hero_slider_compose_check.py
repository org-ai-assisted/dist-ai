#!/usr/bin/python3 -Bsu
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
  mismatch  synthetic 1402- and 1277-wide windows (a 125 px gap): compose must
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


def make_window(path, w, h, bottom_black=0):
    """A minimal decorated-window shot: a title bar band plus one row of dark text, on a
    white terminal background -- enough for text_top() to find a text row and for the width
    logic to act on. `bottom_black` paints that many pure-black rows at the very bottom, to
    stand in for the captured compositor/frame band below the taller (secure) window."""
    im = Image.new('RGB', (w, h), WHITE)
    px = im.load()
    for y in range(26):                 # title bar
        for x in range(w):
            px[x, y] = BLUE
    for x in range(2, min(200, w)):     # a dark text row below the chrome
        px[x, 40] = DARK
    for y in range(h - bottom_black, h):  # captured desktop/frame band
        for x in range(w):
            px[x, y] = (0, 0, 0)
    im.save(path)


def bottom_black_rows(path, thresh=16):
    im = Image.open(path).convert('L')
    w, h = im.size
    px = im.load()
    n = 0
    for y in range(h - 1, -1, -1):
        if sum(1 for x in range(w) if px[x, y] < thresh) >= w * 0.9:
            n += 1
        else:
            break
    return n


def run_compose(compose, work, sec_wh, trad_wh, sec_black=0):
    sec = '%s/sec.png' % work
    trad = '%s/trad.png' % work
    out_sec = '%s/out-sec.png' % work
    out_trad = '%s/out-trad.png' % work
    make_window(sec, *sec_wh, bottom_black=sec_black)
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

        if mode == 'degenerate':
            # A degenerate all-near-black secure shot (a blank grab that slipped past the
            # capture blank-check) must NOT crash compose: strip_bottom_black must floor at
            # MIN_KEEP so the later crop stays valid, not strip to ~0 and raise ValueError.
            proc, _, _ = run_compose(compose, work, (1402, 700), (1396, 680), sec_black=700)
            if proc.returncode != 0:
                print('FAIL: all-black secure shot crashed compose (rc=%d): %s'
                      % (proc.returncode, proc.stderr.strip()[:160]))
                return 1
            print('OK degenerate')
            return 0

        if mode == 'blackband':
            # secure carries a 19px captured black band below its window; compose must trim
            # it so NEITHER composed output ends in a black strip (both share white padding).
            proc, out_sec, out_trad = run_compose(
                compose, work, (1402, 720), (1396, 680), sec_black=19)
            if proc.returncode != 0:
                print('FAIL: black-band pair rejected (rc=%d): %s'
                      % (proc.returncode, proc.stderr.strip()))
                return 1
            bs, bt = bottom_black_rows(out_sec), bottom_black_rows(out_trad)
            if bs or bt:
                print('FAIL: composed output still ends in black (secure %d rows, traditional'
                      ' %d rows)' % (bs, bt))
                return 1
            print('OK blackband')
            return 0

    sys.stderr.write("hero_slider_compose_check: unknown mode '%s'\n" % mode)
    return 2


if __name__ == '__main__':
    sys.exit(main())
