#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Analyze a hero-board payload and print ONE verdict line the test compares against.

Asserts the homepage hero board carries exactly the four documented display-deception
primitives and nothing more dangerous:
  - homoglyph  U+0430 inside "example.com" (bytes d0 b0), rendering a clean domain
  - bidi       U+202E right-to-left override (e2 80 ae) closed by U+202C (e2 80 ac)
  - OSC 0      a title-set escape  ESC ] 0 ;  ... BEL
  - OSC 52     a clipboard-write   ESC ] 52 ; c ; <b64> BEL

CAT-SAFE means every ESC in the stream opens one of those two OSC escapes and is
closed by BEL -- there is NO CSI (ESC [), NO alt-screen (?1049h), NO clear, NO charset
shift (ESC (), i.e. nothing that moves the cursor, repaints or persists beyond `reset`.

Prints 'OK cat-safe' when every check holds, else the FIRST failing token -- so a
regression (a mangled escape, a dropped primitive, an unsafe sequence sneaking in)
turns the verdict non-'OK cat-safe' and fails the test.

    hero_board_check.py <payload-file>
"""

import sys


def analyze(data):
    checks = [
        ('homoglyph-url', b'https://ex\xd0\xb0mple.com'),   # U+0430 in example.com
        ('bidi-rlo', b'\xe2\x80\xae'),                       # U+202E
        ('bidi-pdf', b'\xe2\x80\xac'),                       # U+202C (override closed)
        ('osc0-title', b'\x1b]0;'),                          # OSC 0 title-set
        ('osc52-clip', b'\x1b]52;c;'),                       # OSC 52 clipboard write
    ]
    for name, needle in checks:
        if needle not in data:
            return 'MISSING:' + name

    # CAT-SAFE: every ESC must open ']0;' or ']52;' and be closed by BEL before the
    # next ESC. Anything else (CSI, charset shift, alt-screen, clear) is unsafe.
    i = 0
    n = len(data)
    while True:
        e = data.find(0x1b, i)
        if e == -1:
            break
        tail = data[e + 1:]
        if tail.startswith(b']0;'):
            pass
        elif tail.startswith(b']52;'):
            pass
        else:
            return 'UNSAFE:non-osc-escape@%d' % e
        bel = data.find(0x07, e)
        if bel == -1:
            return 'UNSAFE:unterminated-osc@%d' % e
        # No stray ESC may hide between the OSC opener and its BEL.
        if data.find(0x1b, e + 1, bel) != -1:
            return 'UNSAFE:nested-escape@%d' % e
        i = bel + 1

    return 'OK cat-safe'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write('usage: hero_board_check.py <payload-file>\n')
        return 2
    with open(argv[0], 'rb') as fh:
        print(analyze(fh.read()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
