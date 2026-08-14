#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Strip the human-facing "read me first" safety preamble from a tui-showcase SHOT payload,
## in place. The board proper begins at the first ESC (0x1b) -- the OSC title / alt-screen
## switch; everything before it is the leading '#'-comment header. The corpus file keeps the
## header for raw downloads; only the shot copy is stripped. The kept region still starts with
## the 'user@host:~$ cat tui-showcase.payload' echo (it sits AFTER the escapes). HARD-FAIL if
## no ESC anchor is found (a corpus format change), never silently ship the header.

import sys

if len(sys.argv) != 2:
    sys.stderr.write("usage: strip-tui-showcase-header.py PAYLOAD\n")
    sys.exit(2)

path = sys.argv[1]
data = open(path, "rb").read()
esc = data.find(b"\x1b")
if esc < 0:
    sys.stderr.write("strip-tui-showcase-header: no ESC anchor found in %s\n" % path)
    sys.exit(1)
if esc:
    open(path, "wb").write(data[esc:])
