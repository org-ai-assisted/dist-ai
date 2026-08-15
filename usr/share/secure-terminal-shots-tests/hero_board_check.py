#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Analyze a hero-board payload and print ONE verdict line the test compares against.

Asserts the homepage hero board carries EXACTLY the four documented display-deception
primitives and nothing more dangerous:
  - homoglyph  U+0430 inside "example.com", rendering a clean domain
  - bidi       U+202E right-to-left override, closed by U+202C
  - OSC 0      exactly one title-set escape   ESC ] 0 ;  ... BEL
  - OSC 52     exactly one clipboard-write     ESC ] 52 ; c ; <b64> BEL

CAT-SAFE (validated on the DECODED code points, so a UTF-8-encoded C1 control cannot
slip past a byte scan): every ESC opens one of those two OSC escapes and is closed by
BEL with no nested ESC; and OUTSIDE those two escapes there is no C0 control except the
newline, no DEL, and no C1 control (U+0080-U+009F) -- nothing that moves the cursor,
repaints or persists beyond `reset`. The OSC 52 clipboard body must itself be INERT:
ASCII, comment-style, carrying no shell-execution metacharacter or homoglyph, so a
regression cannot re-plant a runnable command in the clipboard.

Prints 'OK cat-safe' when every check holds, else the FIRST failing token -- so a
regression (a dropped/duplicated primitive, an unsafe control byte, or an executable
clipboard body) turns the verdict non-'OK cat-safe' and fails the test.

    hero_board_check.py <payload-file>
"""

import base64
import sys

OSC0_OPEN = '\x1b]0;'
OSC52_OPEN = '\x1b]52;c;'


def analyze(data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        return 'UNSAFE:invalid-utf8@%d' % exc.start

    # 1. presence of the four documented primitives.
    for name, needle in (
        ('homoglyph-url', 'https://ex\u0430mple.com'),  # U+0430 in example.com
        ('bidi-rlo', '\u202e'),                         # right-to-left override
        ('bidi-pdf', '\u202c'),                         # override closed
        ('osc0-title', OSC0_OPEN),                       # OSC 0 title-set
        ('osc52-clip', OSC52_OPEN),                      # OSC 52 clipboard write
    ):
        if needle not in text:
            return 'MISSING:' + name

    # 2. walk every ESC: it must open exactly one of the two OSC escapes and close with
    #    BEL, with no nested ESC. Record the spans and require exactly one of each.
    osc0 = osc52 = 0
    clip_b64 = None
    spans = []
    i = 0
    while True:
        e = text.find('\x1b', i)
        if e == -1:
            break
        tail = text[e:]
        if tail.startswith(OSC0_OPEN):
            osc0 += 1
        elif tail.startswith(OSC52_OPEN):
            osc52 += 1
        else:
            return 'UNSAFE:non-osc-escape@%d' % e
        bel = text.find('\x07', e)
        if bel == -1:
            return 'UNSAFE:unterminated-osc@%d' % e
        if text.find('\x1b', e + 1, bel) != -1:
            return 'UNSAFE:nested-escape@%d' % e
        if tail.startswith(OSC52_OPEN):
            clip_b64 = text[e + len(OSC52_OPEN):bel]
        spans.append((e, bel))
        i = bel + 1
    if osc0 != 1:
        return 'UNSAFE:osc0-count=%d' % osc0
    if osc52 != 1:
        return 'UNSAFE:osc52-count=%d' % osc52

    # 3. every code point OUTSIDE an OSC span must be printable or a newline -- no C0
    #    control (except \n), no DEL, no C1 control (U+0080-U+009F).
    def in_span(pos):
        return any(a <= pos <= b for a, b in spans)
    for pos, ch in enumerate(text):
        if in_span(pos):
            continue
        o = ord(ch)
        if o == 0x0a:
            continue
        if o < 0x20 or o == 0x7f or 0x80 <= o <= 0x9f:
            return 'UNSAFE:control@%d' % pos

    # 4. the OSC 52 clipboard body must be INERT: ASCII, comment-style, and free of shell
    #    metacharacters or the homoglyph -- else a regression re-plants an executable command.
    try:
        clip = base64.b64decode(clip_b64, validate=True).decode('ascii')
    except Exception:
        return 'UNSAFE:clipboard-not-ascii'
    if not clip.startswith('#'):
        return 'UNSAFE:clipboard-not-comment'
    for bad in ('|', '`', '$', '&', ';', '\u0430', 'curl'):
        if bad in clip:
            return 'UNSAFE:clipboard-exec:' + repr(bad)

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
