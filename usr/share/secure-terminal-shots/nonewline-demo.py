#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Generate the no-trailing-newline demo board (terminal-safe-corpus
demos/nonewline-safe-to-cat.txt), a display-only ASCII file whose LAST line is emitted
WITHOUT a final newline.

That missing newline IS the demonstration: `cat`ting this file leaves the shell prompt on
the last output line, and secure-terminal flags it with the left-gutter no-trailing-newline
mark. The secure-terminal.github.io screenshots reproduce from exactly this file
(`cat demos/nonewline-safe-to-cat.txt`).

Single source of truth for the committed bytes: the corpus drift gate byte-compares this
output against the committed copy, so the file cannot drift by hand.
"""

import sys

# One entry per line; joined with '\n' and with NO trailing newline appended, so the file
# ends mid-line -- the exact condition the demo shows. Plain ASCII (no escapes), safe to cat
# anywhere.
LINES = (
    'secure-terminal -- no-trailing-newline demo (display-only, safe to cat)',
    'A file whose last line has no final newline leaves the shell prompt on that',
    'line; secure-terminal flags it in the left gutter -> this line has no newline',
)


def board():
    """The demo bytes: the lines joined by newlines, with NO trailing newline."""
    return '\n'.join(LINES)


if __name__ == '__main__':
    sys.stdout.write(board())
