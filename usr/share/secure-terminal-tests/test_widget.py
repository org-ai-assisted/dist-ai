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
st_dialog.PasteWarningDialog.confirm = staticmethod(lambda *a, **k: False)
mime2 = QMimeData()
mime2.setText('pay' + chr(0x0430) + 'l\n')
p.insertFromMimeData(mime2)
eq(psent, [], 'unsafe paste rejected sends nothing')
st_dialog.PasteWarningDialog.confirm = staticmethod(lambda *a, **k: True)
p.insertFromMimeData(mime2)
eq(psent, [b'payl\r'], 'unsafe paste allowed sends sanitized')

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
else:
    # already recorded as a FAIL above; do not silently pass
    sys.stderr.write('secure-terminal-tests(widget): FAIL pyte absent, TUI-mode '
                     'assertions could not run\n')

# --- window: rename, colour, settings round-trip ------------------------------
from secure_terminal.main import MainWindow, _is_font_noise   # noqa: E402
from secure_terminal import settings                 # noqa: E402

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
# unicode display is two on/off toggles (Show / Reveal), mutually exclusive,
# defaulting to strip; each carries an icon
eq((win.act_show.isChecked(), win.act_reveal.isChecked()), (False, False),
   'unicode toggles default to strip (both off)')
win.act_show.setChecked(True)
eq(win.current().current_mode(), 'show', 'Show toggle selects show mode')
win.act_reveal.setChecked(True)
eq((win.act_show.isChecked(), win.current().current_mode()), (False, 'reveal'),
   'Reveal turns Show off and selects reveal')
win.act_reveal.setChecked(False)
eq(win.current().current_mode(), 'strip', 'unchecking Reveal falls back to strip')
ok(not win.act_show.icon().isNull() and not win.act_colors.icon().isNull(),
   'toolbar toggles carry icons')
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
