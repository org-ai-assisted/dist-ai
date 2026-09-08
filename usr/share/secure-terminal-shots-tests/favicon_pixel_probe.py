#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Shell-invocation guard: under bash/sh the shebang is ignored and the `import`
## lines below would run as shell commands (`import` is ImageMagick -> XGrabServer,
## which freezes X). Re-exec under python3; inert as a string literal in python3.
"exec" "python3" "-Bsu" "$0" "$@"

## Pixel probes for favicon_rendered_e2e_test.sh (kept out of the shell as a real file per the
## dist-ai style rule against stdin-heredoc python):
##   black <png>              -> prints the fraction of pure-#000000 pixels (a black margin shows here)
##   green <png> R G B TOL    -> prints the count of pixels within TOL (per channel) of (R,G,B)
##                               (the favicon's signature green-check badge)

import sys

from PIL import Image


def main():
    if len(sys.argv) < 3:
        sys.stderr.write('usage: favicon_pixel_probe.py black|green <png> [R G B TOL]\n')
        return 2
    mode = sys.argv[1]
    pixels = list(Image.open(sys.argv[2]).convert('RGB').getdata())
    total = max(1, len(pixels))
    if mode == 'black':
        black = sum(1 for r, g, b in pixels if r == 0 and g == 0 and b == 0)
        print('%.4f' % (black / total))
        return 0
    if mode == 'green':
        gr, gg, gb, tol = (int(x) for x in sys.argv[3:7])
        n = sum(1 for r, g, b in pixels
                if abs(r - gr) <= tol and abs(g - gg) <= tol and abs(b - gb) <= tol)
        print(n)
        return 0
    sys.stderr.write("unknown mode %r (want black|green)\n" % mode)
    return 2


if __name__ == '__main__':
    sys.exit(main())
