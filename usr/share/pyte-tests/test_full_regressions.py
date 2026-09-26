#!/usr/bin/python3 -Bsu

"""Regression tests for the defects found by the fuzz/audit pass.

Each test asserts the correct (no-crash) behaviour a robust VT emulator should
exhibit. Whether a defect must be FIXED or must still REPRODUCE is taken from
the declaration the tree under test ships (``pyte_audit_fixes``), so one suite
stays honest against the org-ai-assisted/pyte fork, upstream master and a
distribution package alike:

  * declared fixed -- a plain test, so a regression turns it red;
  * not declared -- ``xfail(strict=True)``, so fixing the defect without
    declaring the fix turns the XPASS red, prompting the declaration.

Full analysis and proposed patches live in the org-ai-assisted/pyte-audit
repository. Every defect below escapes ``Stream.feed()``, so it crashes the
hosting application rather than just an internal handler.
"""
import pytest

import pyte
from pyte import modes as mo

import pyte_audit_fixes

DECLARED_FIXES = pyte_audit_fixes.declared_fixes(pyte)


def audited(bug_id, detail):
    """Mark a defect test per the tree's declaration (see the module docstring)."""
    return pytest.mark.xfail(
        bug_id not in DECLARED_FIXES,
        strict=True,
        reason=f"BUG-{bug_id}: {detail}",
    )


# --------------------------------------------------------------------------
# The declaration mechanism itself. A typo'd id would otherwise read as "this
# defect is simply not fixed here", which is the one failure mode the strict
# markers cannot distinguish on their own.
# --------------------------------------------------------------------------

def test_declared_fixes_are_known_finding_ids():
    unknown = DECLARED_FIXES - pyte_audit_fixes.KNOWN_BUG_IDS
    assert not unknown, \
        f"unknown ids in {pyte_audit_fixes.MANIFEST_NAME}: {sorted(unknown)}"


def test_manifest_parsing_drops_comments_blanks_and_case():
    text = '## header\n\n  c  \nD # why\n'
    assert pyte_audit_fixes.parse_manifest(text) == frozenset({'C', 'D'})


def feed(data, columns=10, lines=5):
    screen = pyte.Screen(columns, lines)
    pyte.Stream(screen).feed(data)
    return screen


# --------------------------------------------------------------------------
# Bug C -- erase_in_line / erase_in_display crash on an unhandled ``how``.
# ``interval`` is never assigned for out-of-range values, raising
# UnboundLocalError.  Expected: unknown ``how`` is a silent no-op.
# --------------------------------------------------------------------------

@audited('C', 'erase_in_line UnboundLocalError')
def test_erase_in_line_unknown_how_is_noop():
    screen = pyte.Screen(5, 1)
    screen.draw('abcde')
    screen.erase_in_line(3)                 # no standard meaning
    assert ''.join(screen.buffer[0][x].data for x in range(5)) == 'abcde'


@audited('C', 'erase_in_display UnboundLocalError')
def test_erase_in_display_unknown_how_is_noop():
    screen = pyte.Screen(3, 2)
    screen.erase_in_display(4)              # no standard meaning
    assert screen.display == ['   ', '   ']


@audited('C', 'via stream, ESC[3K')
def test_stream_el_how3_no_crash():
    feed('\x1b[3K')


@audited('C', 'via stream, ESC[4J')
def test_stream_ed_how4_no_crash():
    feed('\x1b[4J')


# --------------------------------------------------------------------------
# Bug D -- cursor_to_line (VPA) and report_device_status (DSR) crash when
# DECOM is set but no scrolling margins exist. cursor_position() guards the
# same situation; these two do not.  Expected: no crash.
# --------------------------------------------------------------------------

@audited('D', 'VPA under DECOM w/o margins')
def test_vpa_under_decom_without_margins():
    feed('\x1b[?6h\x1b[5d')


@audited('D', 'DSR under DECOM w/o margins')
def test_dsr_under_decom_without_margins():
    feed('\x1b[?6h\x1b[6n')


@audited('D', 'direct cursor_to_line')
def test_cursor_to_line_decom_no_margins_direct():
    screen = pyte.Screen(10, 5)
    screen.set_mode(mo.DECOM)          # DECOM on, margins still None
    screen.cursor_to_line(3)


# --------------------------------------------------------------------------
# Bug A -- a CSI handler crashes with TypeError when the sequence carries
# more numeric parameters than the handler accepts (parser forwards *params).
# Expected: extra parameters ignored, no crash.
# --------------------------------------------------------------------------

@audited('A', 'extra CSI params -> TypeError')
def test_extra_params_cursor_up():
    feed('\x1b[1;2A')                  # cursor_up(1, 2)


@audited('A', 'extra CSI params -> TypeError')
def test_extra_params_cursor_position():
    feed('\x1b[1;2;3H')                # cursor_position(1, 2, 3)


@audited('A', 'extra CSI params -> TypeError')
def test_extra_params_insert_characters():
    feed('\x1b[0;0@')                  # insert_characters(0, 0)


# --------------------------------------------------------------------------
# Bug B -- a private ("?") CSI whose final byte maps to a handler without a
# ``private`` keyword crashes with TypeError. Expected: sequence ignored or
# handled, no crash.
# --------------------------------------------------------------------------

@audited('B', 'private flag -> unexpected kwarg')
def test_private_flag_cursor_up():
    feed('\x1b[?0A')                   # cursor_up(0, private=True)


@audited('B', 'private flag -> unexpected kwarg')
def test_private_flag_insert_characters():
    feed('\x1b[?0@')                   # insert_characters(0, private=True)


# --------------------------------------------------------------------------
# Bug E -- resize() to fewer lines can leave the cursor below the new bottom
# line, because restore_cursor()'s ensure_vbounds() runs while self.lines
# still holds the OLD value. A subsequent draw() then lands on an off-screen
# buffer row that never appears in display() -- silent data loss.
# --------------------------------------------------------------------------

@audited('E', 'resize leaves cursor.y out of bounds')
def test_resize_shrink_keeps_cursor_in_bounds():
    screen = pyte.Screen(1, 10)
    screen.cursor_position(9, 1)       # y = 8
    screen.resize(lines=1, columns=1)
    assert 0 <= screen.cursor.y < screen.lines


@audited('E', 'resize leaves cursor.x out of bounds')
def test_resize_column_shrink_keeps_cursor_x_in_bounds():
    screen = pyte.Screen(10, 1)
    screen.cursor_to_column(9)         # x = 8
    screen.resize(lines=1, columns=2)
    assert 0 <= screen.cursor.x <= screen.columns


@audited('E', 'draw after shrink lost off-screen')
def test_draw_after_shrink_is_visible():
    screen = pyte.Screen(1, 10)
    screen.cursor_position(9, 1)
    screen.resize(lines=1, columns=1)
    screen.draw('X')
    assert 'X' in ''.join(screen.display)


# --------------------------------------------------------------------------
# Bug H -- a bare LF after a width-filling line does not clear the DECAWM
# deferred-wrap ("last column") flag, so the cursor advances twice and a blank
# row is inserted (X lands two rows down at column 0). xterm clears the flag on
# a line feed and keeps the column, so X lands at the last column of the next
# row. Declared fixed in the fork -> plain test.
# --------------------------------------------------------------------------

@audited('H', 'bare LF after full-width line clears the last-column flag')
def test_linefeed_after_full_width_line_no_blank_row():
    assert feed('abc\nX', columns=3, lines=3).display == ['abc', '  X', '   ']


# --------------------------------------------------------------------------
# Bug I -- SU (CSI S) / SD (CSI T) are unimplemented, so a scroll-region scroll
# is a silent no-op. Expected (ECMA-48/xterm): SD moves the region down with a
# blank row at the top; SU moves it up with a blank row at the bottom.
# --------------------------------------------------------------------------

@audited('I', 'SD (CSI T) scrolls the region down')
def test_sd_scrolls_region_down():
    screen = feed('AAAAA\r\nBBBBB\r\nCCCCC\r\nDDDDD\x1b[T', columns=5, lines=4)
    assert screen.display == ['     ', 'AAAAA', 'BBBBB', 'CCCCC']


@audited('I', 'SU (CSI S) scrolls the region up')
def test_su_scrolls_region_up():
    screen = feed('AAAAA\r\nBBBBB\r\nCCCCC\r\nDDDDD\x1b[S', columns=5, lines=4)
    assert screen.display == ['BBBBB', 'CCCCC', 'DDDDD', '     ']


# --------------------------------------------------------------------------
# Bug J -- resize() smaller keeps the WRONG half when a scrolling region with
# top > 0 is active. resize() drops the top rows via delete_lines() from cursor
# (0, 0), but (0, 0) is outside the active margins so delete_lines() is a no-op:
# the earliest rows survive instead of the latest, silently contradicting the
# documented "clipped at the top" contract. Not declared -> xfail(strict).
# --------------------------------------------------------------------------

@audited('J', 'resize keeps latest rows even with an active scroll region')
def test_resize_shrink_with_margins_keeps_latest_rows():
    screen = pyte.Screen(80, 24)
    stream = pyte.Stream(screen)
    for i in range(24):
        stream.feed('row%02d\r\n' % i)
    stream.feed('\x1b[5;20r')               # DECSTBM active, top > 0
    screen.resize(lines=10)
    assert screen.display[0].startswith('row15')   # latest rows kept, per docstring


# --------------------------------------------------------------------------
# Bug K -- resize() to fewer columns does not prune self.tabstops, so tab()
# honours a stale stop past the new width and parks the cursor at/after
# self.columns. The next draw() writes an off-screen cell that display() never
# renders -- the character is silently lost. Not declared -> xfail(strict).
# --------------------------------------------------------------------------

@audited('K', 'resize prunes tabstops so tab stays on-screen')
def test_resize_column_shrink_prunes_tabstops():
    screen = pyte.Screen(80, 24)
    screen.resize(lines=24, columns=20)
    screen.cursor_position(1, 19)           # x = 18
    screen.tab()
    assert screen.cursor.x < screen.columns


# --------------------------------------------------------------------------
# Bug L -- erasing/deleting the head of a paired wide (width-2) character
# leaves the orphan stub (data == "") with no head before it. render() gives an
# empty-data cell zero width, so the joined row is shorter than self.columns --
# a display row no longer represents exactly self.columns on-screen cells.
# Not declared -> xfail(strict).
# --------------------------------------------------------------------------

@audited('L', 'erasing a wide-char head keeps the row full width')
def test_erase_wide_char_head_keeps_row_width():
    screen = feed('a\u30b3b\x1b[1;2H\x1b[X', columns=5, lines=2)   # \u30b3 = width-2 CJK
    assert len(screen.display[0]) == screen.columns


@audited('L', 'deleting a wide-char head keeps the row full width')
def test_delete_wide_char_head_keeps_row_width():
    screen = pyte.Screen(5, 2)
    screen.draw('a')
    screen.draw('\u30b3')                   # width-2 CJK char
    screen.draw('b')
    screen.cursor_position(1, 2)            # at the wide char's head
    screen.delete_characters(1)
    assert len(screen.display[0]) == screen.columns
