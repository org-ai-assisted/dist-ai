#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Remove the board's EMBEDDED fake prompt line 'user@host:~$ cat tui-showcase.payload' from a
## tui-showcase SHOT payload, in place. Applied ONLY between the emulator loop and the
## secure-terminal loop of comparison-capture.sh, so:
##   - traditional emulators (captured first) KEEP it -- their alt-screen hides the real typed
##     command, so the embedded line is what shows 'cat tui-showcase.payload' at the top;
##   - secure-terminal (captured after) renders inline and shows the REAL prompt, so the
##     embedded copy would be a DUPLICATE at the top -- stripped here.
## Best-effort: absent is already the desired state for the secure-terminal pass, so no fail.

import sys

if len(sys.argv) != 2:
    sys.stderr.write("usage: strip-tui-showcase-prompt.py PAYLOAD\n")
    sys.exit(2)

path = sys.argv[1]
with open(path, "rb") as handle:
    data = handle.read()
embedded_prompt = b"user@host:~$ cat tui-showcase.payload\n"
at = data.find(embedded_prompt)
if at >= 0:
    data = data[:at] + data[at + len(embedded_prompt):]
    with open(path, "wb") as handle:
        handle.write(data)
