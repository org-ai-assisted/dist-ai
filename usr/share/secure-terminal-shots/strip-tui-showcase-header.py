#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Strip the human-facing "read me first" safety preamble from a tui-showcase SHOT payload,
## in place. The board proper begins at the first ESC (0x1b) -- the OSC title / alt-screen
## switch; everything before it is the leading '#'-comment header. The corpus file keeps the
## header for raw downloads; only the shot copy is stripped. HARD-FAIL if no ESC anchor is
## found (a corpus format change), never silently ship the header.
##
## The board's EMBEDDED prompt line is deliberately KEPT here: a traditional emulator hides
## the real typed command on the primary screen (it renders the board on the alt screen), so
## the embedded prompt is what shows 'cat tui-showcase.payload' at the top of THOSE shots.
## secure-terminal renders inline and shows the real prompt, so the embedded copy is stripped
## for its capture only -- separately, by strip-tui-showcase-prompt.py, between the two loops.

import sys

if len(sys.argv) != 2:
    sys.stderr.write("usage: strip-tui-showcase-header.py PAYLOAD\n")
    sys.exit(2)

path = sys.argv[1]
with open(path, "rb") as handle:
    data = handle.read()
esc = data.find(b"\x1b")
if esc < 0:
    sys.stderr.write("strip-tui-showcase-header: no ESC anchor found in %s\n" % path)
    sys.exit(1)
if esc:
    with open(path, "wb") as handle:
        handle.write(data[esc:])
