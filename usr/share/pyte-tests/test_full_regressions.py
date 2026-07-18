"""Regression tests for defects found by the fuzz/audit pass.

Each test asserts the *correct* (no-crash) behaviour a robust VT emulator
should exhibit. They are marked ``xfail(strict=True)`` because the bug is
still present on upstream master: the suite stays green, and the day upstream
fixes a defect the corresponding test turns into an ``XPASS`` (a strict-xfail
failure), prompting removal of the marker.

Full analysis and proposed patches live in ``BUGS/`` at the repo root. All four
defects were confirmed on BOTH Debian ``python3-pyte`` 0.8.0-3 and upstream
master 0.8.3.dev, and every one escapes ``Stream.feed()`` (so it crashes the
hosting application, not just an internal handler).
"""
import pytest

import pyte
from pyte import modes as mo


def feed(data, columns=10, lines=5):
    screen = pyte.Screen(columns, lines)
    pyte.Stream(screen).feed(data)
    return screen


# --------------------------------------------------------------------------
# Bug C -- erase_in_line / erase_in_display crash on an unhandled ``how``.
# ``interval`` is never assigned for out-of-range values, raising
# UnboundLocalError.  Expected: unknown ``how`` is a silent no-op.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="BUG-C: erase_in_line UnboundLocalError")
def test_erase_in_line_unknown_how_is_noop():
    screen = pyte.Screen(5, 1)
    screen.draw("abcde")
    screen.erase_in_line(3)                 # no standard meaning
    assert "".join(screen.buffer[0][x].data for x in range(5)) == "abcde"


@pytest.mark.xfail(strict=True, reason="BUG-C: erase_in_display UnboundLocalError")
def test_erase_in_display_unknown_how_is_noop():
    screen = pyte.Screen(3, 2)
    screen.erase_in_display(4)              # no standard meaning
    assert screen.display == ["   ", "   "]


@pytest.mark.xfail(strict=True, reason="BUG-C via stream: ESC[3K")
def test_stream_el_how3_no_crash():
    feed("\x1b[3K")


@pytest.mark.xfail(strict=True, reason="BUG-C via stream: ESC[4J")
def test_stream_ed_how4_no_crash():
    feed("\x1b[4J")


# --------------------------------------------------------------------------
# Bug D -- cursor_to_line (VPA) and report_device_status (DSR) crash when
# DECOM is set but no scrolling margins exist. cursor_position() guards the
# same situation; these two do not.  Expected: no crash.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="BUG-D: VPA under DECOM w/o margins")
def test_vpa_under_decom_without_margins():
    feed("\x1b[?6h\x1b[5d")


@pytest.mark.xfail(strict=True, reason="BUG-D: DSR under DECOM w/o margins")
def test_dsr_under_decom_without_margins():
    feed("\x1b[?6h\x1b[6n")


@pytest.mark.xfail(strict=True, reason="BUG-D: direct cursor_to_line")
def test_cursor_to_line_decom_no_margins_direct():
    screen = pyte.Screen(10, 5)
    screen.set_mode(mo.DECOM)          # DECOM on, margins still None
    screen.cursor_to_line(3)


# --------------------------------------------------------------------------
# Bug A -- a CSI handler crashes with TypeError when the sequence carries
# more numeric parameters than the handler accepts (parser forwards *params).
# Expected: extra parameters ignored, no crash.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="BUG-A: extra CSI params -> TypeError")
def test_extra_params_cursor_up():
    feed("\x1b[1;2A")                  # cursor_up(1, 2)


@pytest.mark.xfail(strict=True, reason="BUG-A: extra CSI params -> TypeError")
def test_extra_params_cursor_position():
    feed("\x1b[1;2;3H")                # cursor_position(1, 2, 3)


@pytest.mark.xfail(strict=True, reason="BUG-A: extra CSI params -> TypeError")
def test_extra_params_insert_characters():
    feed("\x1b[0;0@")                  # insert_characters(0, 0)


# --------------------------------------------------------------------------
# Bug B -- a private ("?") CSI whose final byte maps to a handler without a
# ``private`` keyword crashes with TypeError. Expected: sequence ignored or
# handled, no crash.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="BUG-B: private flag -> unexpected kwarg")
def test_private_flag_cursor_up():
    feed("\x1b[?0A")                   # cursor_up(0, private=True)


@pytest.mark.xfail(strict=True, reason="BUG-B: private flag -> unexpected kwarg")
def test_private_flag_insert_characters():
    feed("\x1b[?0@")                   # insert_characters(0, private=True)


# --------------------------------------------------------------------------
# Bug E -- resize() to fewer lines can leave the cursor below the new bottom
# line, because restore_cursor()'s ensure_vbounds() runs while self.lines
# still holds the OLD value. A subsequent draw() then lands on an off-screen
# buffer row that never appears in display() -- silent data loss.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="BUG-E: resize leaves cursor.y out of bounds")
def test_resize_shrink_keeps_cursor_in_bounds():
    screen = pyte.Screen(1, 10)
    screen.cursor_position(9, 1)       # y = 8
    screen.resize(lines=1, columns=1)
    assert 0 <= screen.cursor.y < screen.lines


@pytest.mark.xfail(strict=True, reason="BUG-E: resize leaves cursor.x out of bounds")
def test_resize_column_shrink_keeps_cursor_x_in_bounds():
    screen = pyte.Screen(10, 1)
    screen.cursor_to_column(9)         # x = 8
    screen.resize(lines=1, columns=2)
    assert 0 <= screen.cursor.x <= screen.columns


@pytest.mark.xfail(strict=True, reason="BUG-E: draw after shrink lost off-screen")
def test_draw_after_shrink_is_visible():
    screen = pyte.Screen(1, 10)
    screen.cursor_position(9, 1)
    screen.resize(lines=1, columns=1)
    screen.draw("X")
    assert "X" in "".join(screen.display)
