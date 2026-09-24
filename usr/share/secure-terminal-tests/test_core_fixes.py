#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for the ai-review-confirmed pre-existing core bugs (terminal.py):
Save-Transcript integrity (alt-leave snapshot), colors=false in TUI, TUI scrollback
repaint on a theme toggle, the CLI Alt/Meta prefix, the zero-width mid-row-gap cursor
advance, the PROMPT_START split carry, and the OSC-52 modal notifier guard."""

from test_widget_common import *   # noqa: F401,F403  (shared harness)

from PyQt6.QtGui import QKeyEvent
from PyQt6.QtCore import QEvent
from secure_terminal.terminal import (_alt_partial_tail, _alt_scan_partial_tail, PROMPT_START,
                                       _SafeHistoryScreen, _Utf8CharsetByteStream,
                                       sound_file_allowed)

_PS = PROMPT_START.encode('ascii')      # b'\x1b[?2004h'


# --- #6: _alt_partial_tail carries a split PROMPT_START -------------------------------
ok(_alt_partial_tail(b'done\x1b[?200') == len(b'\x1b[?200'),
   'a PROMPT_START split across a read boundary is held back for the next read')
ok(_alt_partial_tail(b'text' + _PS) == 0,
   'a COMPLETE PROMPT_START at the tail is not held back (fed now)')
ok(_alt_partial_tail(b'ordinary text') == 0, 'a non-marker tail is not held back')
# offload #8: the byte carry now reunites a COMBINED (ESC[?47;1049h) and numeric-equivalent
# (ESC[?01049h) alt marker split across a read boundary too, so the byte-feed path agrees with
# the text scan (which already resolves those forms). Held while incomplete, released once whole.
ok(_alt_partial_tail(b'x\x1b[?47;1049') == len(b'\x1b[?47;1049'),
   '#8: a split COMBINED alt marker (ESC[?47;1049...) is held back for the next read')
ok(_alt_partial_tail(b'x\x1b[?01049') == len(b'\x1b[?01049'),
   '#8: a split numeric-equivalent alt marker (ESC[?01049...) is held back')
ok(_alt_partial_tail(b'x\x1b[?47;1049h') == 0,
   '#8: a COMPLETE combined alt marker is NOT held back (fed now for its snapshot)')
# the str twin carries the SAME incomplete-CSI forms, so the CLI text scan and the byte feed
# cannot disagree on a split combined/numeric marker.
eq(_alt_scan_partial_tail('x\x1b[?47;1049'), len('\x1b[?47;1049'),
   '#8: the str carry twin holds a split combined alt marker like the byte carry')
eq(_alt_scan_partial_tail('plain text'), 0, '#8: the str twin does not hold a non-marker tail')


# --- #3: a zero-width char at a mid-row gap does NOT advance the cursor ---------------
_scr = _SafeHistoryScreen(20, 5)
_st = _Utf8CharsetByteStream(_scr)
_st.feed(b'\x1b[1;6H')                      # CUP to row 0, col 5 (x-1=4 never drawn)
eq((_scr.cursor.x, _scr.cursor.y), (5, 0), 'cursor at the mid-row gap')
_st.feed(chr(0x0301).encode('utf-8'))       # a lone COMBINING ACUTE ACCENT (zero width)
eq(_scr.cursor.x, 5, 'a zero-width char at a mid-row gap leaves the cursor put (no shift)')
# the true origin (0,0) still steps past its placeholder
_scr2 = _SafeHistoryScreen(20, 5)
_st2 = _Utf8CharsetByteStream(_scr2)
_st2.feed(chr(0x0301).encode('utf-8'))
eq(_scr2.cursor.x, 1, 'a lone zero-width char at the (0,0) origin still occupies + steps')


# --- #1: colors=false renders the grid monochrome (default fg), stripping program SGR -
_t1 = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
feed_output(_t1, b'\x1b[31mRED\x1b[0m')      # a red 'R' at (0,0)
_t1._render_tui()
APP.processEvents()
_red = _t1._screen.buffer[0][0]
# colors_allowed() is env-driven (NO_COLOR / TERM); pin _effective_colors to the toggle so
# the test controls it. A plain (non-marking) cell always takes the non-marking path, so
# disp is irrelevant.
_t1._effective_colors = lambda: _t1._colors
_t1._colors = True                           # colors ON for the sanity half
_default = _t1._grid_cell_format(_red._replace(fg='default'), None)
ok(_t1._grid_cell_format(_red, None).foreground().color().name()
   != _default.foreground().color().name(),
   'sanity: colors ON -- a red grid cell differs from a default cell')
_t1.apply_colors(False)
APP.processEvents()
eq(_t1._grid_cell_format(_red, None).foreground().color().name(),
   _default.foreground().color().name(),
   'colors=false renders a red TUI cell in the DEFAULT foreground (monochrome)')
_t1.apply_colors(True)
_t1.close()


# --- #2: the alt-leave exit snapshot holds ONLY the final frame, not primary scrollback -
_t2 = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
# primary scrollback exceeding one screen, with a distinctive marker
feed_output(_t2, b''.join(b'PRIMARY-SCROLL-%03d\r\n' % i
                         for i in range(_t2._screen.lines * 2)))
_t2._render_tui()
APP.processEvents()
# a full-screen program: enter alt, draw a distinctive final frame, leave
feed_output(_t2, b'\x1b[?1049h\x1b[2J\x1b[HALT-FINAL-FRAME\x1b[?1049l')
APP.processEvents()
_sb = _t2.scrollback_text()
_marker = '----- full-screen application (final screen) -----'
ok(_marker in _sb, '#2: an exit snapshot was recorded')
_snap = _sb.split(_marker, 1)[1]
ok('ALT-FINAL-FRAME' in _snap,
   '#2: the exit snapshot holds the alt program final frame')
ok('PRIMARY-SCROLL-000' not in _snap and 'PRIMARY-SCROLL-001' not in _snap,
   '#2: the exit snapshot does NOT inflate with the primary scrollback')
_t2.close()


# --- #5: CLI-mode Alt+key sends an ESC (Meta) prefix, and is not mirrored literally ----
_t5 = SecureTerminal(command='/bin/cat')       # line/CLI mode
APP.processEvents()
_writes = []
_orig_write = _t5._write
_t5._write = lambda b: _writes.append(b)
_altf = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_F, Qt.KeyboardModifier.AltModifier, 'f')
_t5.keyPressEvent(_altf)
ok(b'\x1bf' in _writes, 'Alt+f sends ESC f (readline M-f backward/forward-word)')
ok('f' not in _t5._line_buffer, 'a Meta binding is NOT mirrored into the line buffer')
_writes.clear()
_altbs = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Backspace,
                   Qt.KeyboardModifier.AltModifier, '')
_t5.keyPressEvent(_altbs)
ok(b'\x1b\x7f' in _writes, 'Alt+Backspace sends ESC DEL (readline M-DEL kill-word)')
# a PLAIN key still sends the bare byte and mirrors
_writes.clear()
_t5._line_buffer = ''
_plainf = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_F, Qt.KeyboardModifier.NoModifier, 'f')
_t5.keyPressEvent(_plainf)
ok(_writes == [b'f'] and _t5._line_buffer == 'f',
   'a plain key sends the bare byte and mirrors into the line buffer')
_t5._write = _orig_write
_t5.close()


# --- #8: the OSC-52 consent emit disables the pty notifier for its duration -----------
_t8 = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
_t8.apply_osc('osc_clipboard_read', True)
_seen = {}
_t8.clipboard_read_requested.connect(
    lambda: _seen.__setitem__('enabled_during', _t8._notifier.isEnabled()))
_enabled_before = _t8._notifier.isEnabled()
_t8._osc_clipboard_read()                   # _clipboard_read is None -> asks -> emits
ok(_seen.get('enabled_during') is False,
   '#8: the pty notifier is DISABLED while the consent modal (emit) runs')
ok(_t8._notifier.isEnabled() == _enabled_before,
   '#8: the notifier is restored to its prior state after the emit')
_t8.close()

# --- #7: theme/markings toggles rebuild the WHOLE grid view so already-promoted scrollback
# repaints (not just the live grid). A plain row's colour is palette-driven (not a per-cell
# format), so assert the fix's mechanism: the toggle resets + rebuilds the grid view. On the
# old code apply_theme only re-armed the render timer and apply_markings only reconciled the
# live tail, so _reset_grid_view was NOT called and scrollback kept the old theme/tints.
def _rebuilds_on(term, action):
    feed_output(term, b''.join(b'ROW-%03d\r\n' % i for i in range(term._screen.lines * 3)))
    term._render_tui()
    APP.processEvents()
    _hits = []
    _orig = term._reset_grid_view

    def _spy():
        _hits.append(1)
        _orig()
    term._reset_grid_view = _spy
    action()
    APP.processEvents()
    term._reset_grid_view = _orig
    return bool(_hits)


_t7 = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
ok(_rebuilds_on(_t7, lambda: _t7.apply_theme('light' if _t7._theme == 'dark' else 'dark')),
   '#7: a theme toggle in TUI rebuilds the grid view (promoted scrollback repaints)')
ok(_rebuilds_on(_t7, lambda: _t7.apply_markings(not _t7.markings_enabled())),
   '#7: a markings toggle in TUI rebuilds the grid view (promoted scrollback repaints)')
_t7.close()

# --- offload #5: colors=false strips PROGRAM colour on the show-mode structural / markings-off
# ELSE branch of _grid_cell_format too (not only the plain main path in #1 above), while
# PRESERVING the risk-class tint for unicode/control cells (gated by markings, not colours). ----
_c5 = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
_c5._effective_colors = lambda: _c5._colors      # pin off the env-driven colors_allowed()
_c5.apply_mode('show')                           # show mode -> a structural glyph shown as itself
# a coloured BOX-DRAWING glyph (U+2500) is STRUCTURAL: the else-branch renders it in the
# program's OWN SGR, so colours-off must strip that program colour like the main path.
feed_output(_c5, ('\x1b[31m' + chr(0x2500) + '\x1b[0m').encode('utf-8'))
_c5._render_tui()
APP.processEvents()
_box = _c5._screen.buffer[0][0]
_box_default = _c5._grid_cell_format(
    _box._replace(fg='default'), None).foreground().color().name()
_c5.apply_colors(True)
ok(_c5._grid_cell_format(_box, None).foreground().color().name() != _box_default,
   'sanity: colors ON -- a coloured structural glyph keeps its program colour (else branch)')
_c5.apply_colors(False)
eq(_c5._grid_cell_format(_box, None).foreground().color().name(), _box_default,
   '#5: colors=false strips PROGRAM colour on the structural show-mode else branch too')
# a RISK-class cell (a confusable) keeps its marking tint even with colours OFF (markings ON):
# risk colouring is independent of the colours setting.
_c5.apply_markings(True)
feed_output(_c5, ('\x1b[32m' + chr(0x0430) + '\x1b[0m').encode('utf-8'))   # Cyrillic a (confusable)
_c5._render_tui()
APP.processEvents()
_risk = next((_c5._screen.buffer[0][_col] for _col in range(_c5._screen.columns)
              if _c5._screen.buffer[0][_col].data == chr(0x0430)), None)
ok(_risk is not None, 'sanity: the confusable risk-class cell is on the grid')
ok(_c5._grid_cell_format(_risk, None).foreground().color().name() != _box_default,
   '#5: a unicode/control risk-class cell keeps its marking tint even with colours OFF')
_c5.apply_colors(True)
_c5.close()


# --- offload #7: sound_file_allowed returns None (system-beep fallback) on a NUL-containing path
# instead of crashing -- os.path.realpath's lstat raises ValueError, not OSError, on an embedded
# NUL. Distinct from the settled F5 validate-then-use symlink race; this is a plain crash guard. -
ok(sound_file_allowed('/tmp/a\x00b') is None,
   '#7: a NUL-containing bell_sound path returns None (system beep), never raises ValueError')
ok(sound_file_allowed('') is None, "#7: an empty path is still disallowed (no change)")


# --- offload #8 integration: a COMBINED alt-enter marker SPLIT across two CLI reads is reunited
# by the str carry (_alt_scan_carry), so _alt_screen flips -- the same result the byte feed now
# gives, so the byte and text paths agree. On the old fixed 7-char window the combined form was
# lost (its ESC fell outside the window). ------------------------------------------------------
_a8 = SecureTerminal(command='/bin/cat')          # CLI/line mode
APP.processEvents()
feed_output(_a8, b'before\x1b[?47;1049')          # read 1 ends mid combined marker
ok(_a8._alt_scan_carry.endswith('\x1b[?47;1049'),
   '#8: a split combined alt marker is carried across the CLI read boundary')
feed_output(_a8, b'h')                             # read 2 completes it
ok(_a8._alt_screen, '#8: the reunited combined alt-enter marker flips _alt_screen (paths agree)')
_a8.close()


# --- Cl2: the deferred grace-SIGKILL timer is cancelled on tab teardown ---------------
# _terminate_pgrp SIGTERMs the foreground group, then SIGKILLs a survivor after a grace
# period. A bare QTimer.singleShot survived a tab close and, ~2s later, fired its lambda
# against the deleteLater'd widget -> RuntimeError -> WHOLE-APP abort. The timer is now
# parented to the widget AND stopped in shutdown(), so a close during the grace cancels it.
_cl2 = spawn_live(command=['/bin/sh', '-c', 'trap "" TERM; exec sleep 60'])
_cl2._SURVIVOR_GRACE_MS = 5000                     # keep it pending for the assertions
_cl2_signalled, _cl2_errno = _cl2._terminate_pgrp(os.getpgid(_cl2._pid))
ok(_cl2_signalled and _cl2._survivor_timer is not None and _cl2._survivor_timer.isActive(),
   'Cl2: _terminate_pgrp arms the parented grace-SIGKILL timer')
_cl2.shutdown()
ok(not _cl2._survivor_timer.isActive(),
   'Cl2: shutdown() cancels the pending grace-SIGKILL timer (no fire on a closed tab)')


# --- Cl3: Enter clears the line-pending mirror ONLY when the CR is delivered ----------
# A dropped CR (a wedged/slow child -> short _write) must leave _line_pending() True, so a
# later CLI<->TUI re-export is not typed onto -- and does not submit -- the unsent line.
_cl3 = spawn_live(command='/bin/cat')
_cl3._line_buffer = 'secret command'
_cl3._line_dirty = True
_cl3._write = lambda data: 0                       # wedged child: nothing accepted
key(_cl3, Qt.Key.Key_Return)
ok(_cl3._line_buffer == 'secret command' and _cl3._line_pending(),
   'Cl3: a dropped Enter CR keeps the line pending (mirror NOT cleared)')
_cl3._write = lambda data: len(data)              # child now accepts the write
key(_cl3, Qt.Key.Key_Return)
ok(_cl3._line_buffer == '' and not _cl3._line_dirty,
   'Cl3: a fully-delivered Enter CR clears the line-pending mirror')
_cl3.close()


# --- Cl5: OSC-52 read-consent prompts are flood-bounded -------------------------------
# Each un-granted read query opens a BLOCKING modal consent dialog; a flood would freeze
# the UI behind thousands of them and pressure the user toward "Always". Past the per-window
# cap the excess is auto-denied (no prompt, no reply -> no exfiltration) and advised once.
_cl5 = spawn_live(command='/bin/cat')
_cl5._osc['osc_clipboard_read'] = True            # feature on for this tab
_cl5_prompts = []
_cl5.clipboard_read_requested.connect(lambda: _cl5_prompts.append(1))
for _ in range(20):
    _cl5._clipboard_read = None                    # each "once" decision resets to None
    _cl5._osc_clipboard_read()
ok(len(_cl5_prompts) <= 5 and _cl5._clip_read_flood_advised,
   'Cl5: a read-query flood is bounded to a few prompts, then auto-denied + advised once')
_cl5.close()

finish('core-fixes')
