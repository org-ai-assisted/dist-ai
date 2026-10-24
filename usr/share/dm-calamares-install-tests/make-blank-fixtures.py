#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Fixture generator for blank_floor_nonblank_test.sh: write a 1-colour pure-black PNG
## (degenerate) and a 2-colour PNG (one white pixel on black -- sparse but non-uniform, the
## legitimate console/prompt case). Uses PIL, the same library image-blank-check reads with, so
## the test adds no dependency beyond the gate it exercises.
##   make-blank-fixtures.py BLACK_PNG CONTENT_PNG

import sys

from PIL import Image


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: make-blank-fixtures.py BLACK_PNG CONTENT_PNG\n")
        return 2
    black, content = argv[1], argv[2]
    Image.new("RGB", (64, 48), (0, 0, 0)).save(black)
    im = Image.new("RGB", (64, 48), (0, 0, 0))
    im.putpixel((1, 1), (255, 255, 255))
    im.save(content)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
