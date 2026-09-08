#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Write a fully transparent Xcursor theme so a headless wlroots compositor (labwc)
## draws an INVISIBLE pointer. On the headless + pixman path wlroots software-composites
## its cursor straight into the output buffer, so grim captures it even with the overlay
## cursor disabled -- and a stray pointer on the black field defeats the trim-to-window
## crop. A blank cursor removes it at the source.
##
##   wl-blank-cursor.py <icons-dir> [theme-name]
##
## Creates <icons-dir>/<theme>/cursors/<name> for the common pointer shapes, each a 1x1
## transparent Xcursor. Point the compositor at it with XCURSOR_PATH=<icons-dir>
## XCURSOR_THEME=<theme>. Prints the theme name.

import os
import struct
import sys

## Xcursor on-disk format (see libXcursor): magic, header, one table-of-contents entry
## per chunk, then the image chunks. One 1x1 fully transparent ARGB image is enough.
_MAGIC = b'Xcur'
_HEADER_SIZE = 16
_VERSION = 0x00010000
_IMAGE_TYPE = 0xfffd0002
_IMAGE_HEADER_SIZE = 36
_NOMINAL_SIZE = 1

## Shapes a terminal/GUI capture may request; all alias the same invisible glyph so no
## requested cursor name falls back to a visible theme default.
_CURSOR_NAMES = (
    'left_ptr', 'default', 'xterm', 'text', 'ptr', 'arrow',
    'top_left_arrow', 'hand1', 'hand2', 'pointer', 'watch', 'wait',
)


def _blank_cursor_bytes():
    out = _MAGIC + struct.pack('<III', _HEADER_SIZE, _VERSION, 1)
    ## table of contents: one image chunk, at the offset right after header + toc.
    image_offset = _HEADER_SIZE + 1 * 12
    out += struct.pack('<III', _IMAGE_TYPE, _NOMINAL_SIZE, image_offset)
    ## chunk header: size, type, subtype (nominal size), version.
    out += struct.pack('<IIII', _IMAGE_HEADER_SIZE, _IMAGE_TYPE, _NOMINAL_SIZE, 1)
    ## width, height, xhot, yhot, delay, then one transparent ARGB pixel.
    out += struct.pack('<IIII', 1, 1, 0, 0)
    out += struct.pack('<I', 0)
    out += struct.pack('<I', 0x00000000)
    return out


def main(argv):
    if len(argv) < 2:
        print('wl-blank-cursor.py: usage: wl-blank-cursor.py <icons-dir> [theme-name]',
              file=sys.stderr)
        return 2
    icons_dir = argv[1]
    theme = argv[2] if len(argv) > 2 else 'blank'
    cursors_dir = os.path.join(icons_dir, theme, 'cursors')
    os.makedirs(cursors_dir, exist_ok=True)
    payload = _blank_cursor_bytes()
    ## An index.theme lets libXcursor recognise the directory as a real theme.
    with open(os.path.join(icons_dir, theme, 'index.theme'), 'w', encoding='utf-8') as handle:
        handle.write('[Icon Theme]\nName=%s\n' % theme)
    for name in _CURSOR_NAMES:
        with open(os.path.join(cursors_dir, name), 'wb') as handle:
            handle.write(payload)
    print(theme)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
