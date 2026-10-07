#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""A fake Claude Code TUI: looks like the real thing, does nothing real.

Purpose: a deterministic child to drive the "last TUI row clipped" / "Ctrl+End does
nothing" regression. Claude Code draws a full-screen frame in the PRIMARY buffer (a
bottom-anchored footer -- divider, input box, status line -- over scrollback above), NOT
the alternate screen. This fixture reproduces that exact shape with no AI, no network, no
state.

Faithful-repro contract:
  - It fills EXACTLY `rows` lines and NEVER scrolls (positions every line with CUP, writes
    no bare LF at the bottom, autowrap off). So the document stays at <= grid rows ->
    SecureTerminal._grid_fixed_canvas() is True -> the view is TOP-PINNED with the vertical
    scrollbar off, and any winsize-vs-viewport row overcount clips the BOTTOM row. That is
    the bug under test.
  - The STATUS line sits on the very LAST row, so "is the bottom row visible" is directly
    observable.
  - On Ctrl+End (ESC[1;5F -- exactly what Claude Code's "jump to bottom" binding expects,
    and what SecureTerminal encodes for Ctrl+End), it overwrites the last row with the
    sentinel BOTTOMMARK. A test asserts BOTTOMMARK renders on the last, un-clipped row --
    proving BOTH that the key was delivered and that the bottom row is on-screen.

Two uses:
  - Automated: launched as the widget's child command by test_tui_jump_to_bottom.py.
  - Manual repro: run it inside a real secure-terminal tab (e.g. a command tab), watch the
    status line, press Ctrl+End. `--alt` additionally exercises the alternate-screen
    fixed-canvas path.
"""

import fcntl
import os
import signal
import struct
import sys
import termios
import tty

STATUS = 'FAKECLAUDE model | ctx 92% | 0 agents'   # initial last-row text (bottom-visible probe)
BOTTOMMARK = 'BOTTOMMARK'                           # written on the last row on Ctrl+End
_ALT = '--alt' in sys.argv[1:]

_bottom_text = STATUS


def _winsize():
    """(rows, cols) of the controlling pty, read from stdout."""
    try:
        packed = fcntl.ioctl(1, termios.TIOCGWINSZ, b'\0' * 8)
        rows, cols, _xp, _yp = struct.unpack('HHHH', packed)
    except OSError:
        rows, cols = 0, 0
    return max(3, rows or 24), max(2, cols or 80)


def _w(text):
    os.write(1, text.encode('ascii', 'replace'))


def _row(r, text, cols):
    """Place `text` at row r (1-based), col 1: clear the line, then a width-clamped write
    (clamped so it can never wrap to the next row and scroll the fixed canvas)."""
    _w('\x1b[%d;1H\x1b[2K' % r)
    _w(text[:max(0, cols - 1)])


def draw():
    rows, cols = _winsize()
    _w('\x1b[H\x1b[2J')                       # home + clear; no scroll
    for r in range(1, rows - 2):              # scrollback-like filler above the footer
        _row(r, 'scrollback line %03d -- the quick brown fox' % r, cols)
    _row(rows - 2, '-' * (cols - 1), cols)    # divider
    _row(rows - 1, '> type a message',  cols)  # input box
    _row(rows, _bottom_text, cols)            # STATUS / BOTTOMMARK -- the very last row
    _w('\x1b[%d;3H' % (rows - 1))             # park the cursor in the input box
    try:
        sys.stdout.flush()
    except (OSError, ValueError):
        pass  # best-effort flush: a closed pty / broken pipe is ignorable here


def _on_winch(_signum, _frame):
    draw()


def main():
    # Raw mode like a real TUI: noncanonical + no echo, so os.read(0) returns the control
    # bytes (ESC[1;5F) immediately instead of a canonical line discipline buffering them
    # until a newline that a key sequence never carries.
    try:
        _old_tc = termios.tcgetattr(0)
        tty.setraw(0)
    except (termios.error, OSError, ValueError):
        _old_tc = None
    if _ALT:
        _w('\x1b[?1049h')                     # alternate screen (optional second repro path)
    _w('\x1b[?7l')                            # autowrap OFF: a full-width line cannot scroll
    try:
        signal.signal(signal.SIGWINCH, _on_winch)
    except (OSError, ValueError, AttributeError):
        pass  # best-effort SIGWINCH handler: its absence just means no resize redraw
    draw()
    global _bottom_text
    buf = b''
    try:
        while True:
            try:
                chunk = os.read(0, 4096)      # PEP 475: auto-retries across SIGWINCH
            except OSError:
                break
            if not chunk:
                break                         # EOF: parent closed the pty
            buf += chunk
            if b'\x1b[1;5F' in buf:           # Ctrl+End -> "jump to bottom"
                _bottom_text = BOTTOMMARK
                draw()
                buf = b''
            buf = buf[-16:]                   # only need the tail to match the CSI
    finally:
        if _ALT:
            _w('\x1b[?1049l')
        if _old_tc is not None:
            try:
                termios.tcsetattr(0, termios.TCSADRAIN, _old_tc)
            except (termios.error, OSError, ValueError):
                pass  # best-effort terminal-mode restore during teardown


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass  # clean exit on Ctrl+C
