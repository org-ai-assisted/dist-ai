#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Fixture for image_redact_tokens_test.sh: render OCR-friendly white-on-black text containing a
## kernel-style timestamp and a LUKS-UUID token between plain marker words, so the test can OCR
## the redacted result and assert the tokens are gone while the markers remain.
##   make-redact-fixture.py OUTFILE

import sys

from PIL import Image, ImageDraw, ImageFont

FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
)


def load_font(size):
    for path in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    raise SystemExit("make-redact-fixture: no usable TrueType font found")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: make-redact-fixture.py OUTFILE\n")
        return 2
    out = argv[1]
    image = Image.new("RGB", (960, 260), (0, 0, 0))
    draw = ImageDraw.Draw(image)
    font = load_font(30)
    draw.text((6, 8), "ALPHA 12.345678 BRAVO", fill=(255, 255, 255), font=font)
    draw.text((6, 64), "CHARLIE luks-abcd1234ef56aa DELTA",
              fill=(255, 255, 255), font=font)
    ## Upper-case LUKS token: proves the redactor is case-INSENSITIVE (a lower-case 'luks-'
    ## pattern must still mask this), matching how OCR returns unstable case on real frames.
    draw.text((6, 120), "GOLF LUKS-DEADBEEF01 HOTEL",
              fill=(255, 255, 255), font=font)
    ## A UUID with a NON-hex glyph (S) mid-string, as OCR garbles real UUIDs: a 'luks-'
    ## prefix pattern must still mask it (a hex-strict pattern would miss it after the S).
    draw.text((6, 176), "INDIA luks-6df5S68a5-9f5f JULIET",
              fill=(255, 255, 255), font=font)
    image.save(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
