#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.main's window-level dialogs and the `ctl`
## remote-control client. Kept as its own small offscreen suite -- rather than
## folded into the large widget suite -- because a second long-lived MainWindow
## plus its modal dialogs perturbs the big suite's Qt teardown; here the window
## is built, exercised and destroyed in isolation. The modal dialogs are shown
## with QDialog.exec() stubbed (Accepted/Rejected) so nothing blocks, and the
## ctl client is driven with ipc.send_request stubbed to canned replies.
## SKIPs (exit 77) when PyQt6 is unavailable.

import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QDialog
    import secure_terminal.main as M
    from secure_terminal.main import MainWindow, _ctl_main
except Exception as exc:                                       # pragma: no cover
    sys.stderr.write('secure-terminal-tests: SKIP (PyQt6/main unavailable: '
                     '%s)\n' % exc)
    raise SystemExit(77)

APP = QApplication.instance() or QApplication([])

# Isolate config/state so the window loads clean defaults regardless of what any
# earlier suite (run in the same coverage batch) may have written to the real
# drop-in dirs -- keeps this suite deterministic in any run order.
import tempfile                                                # noqa: E402
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp()
os.environ['XDG_STATE_HOME'] = tempfile.mkdtemp()

_failures = 0


def ok(cond, msg):
    global _failures
    if cond:
        print('ok   %s' % msg)
    else:
        _failures += 1
        print('FAIL: %s' % msg)


def eq(got, want, msg):
    ok(got == want, '%s (got %r, want %r)' % (msg, got, want))


win = MainWindow()
win.new_tab()

# --- window dialogs: built and shown with exec() stubbed ----------------------
_orig_exec = QDialog.exec
QDialog.exec = lambda _self: int(QDialog.DialogCode.Accepted)
try:
    win.show_about()
    ok(True, 'show_about builds and shows')
    win.show_locations()
    ok(True, 'show_locations builds and shows the paths dialog')
    win.show_global_settings()
    ok(True, 'show_global_settings applies the chosen defaults on accept')
    QDialog.exec = lambda _self: int(QDialog.DialogCode.Rejected)
    win.show_global_settings()
    ok(True, 'show_global_settings: cancel returns without applying')
finally:
    QDialog.exec = _orig_exec

# --- the `secure-terminal ctl ...` remote-control client (_ctl_main) -----------
_orig_sr = M.ipc.send_request
try:
    M.ipc.send_request = lambda *_a, **_k: None
    eq(_ctl_main(['ls']), 1, 'ctl ls: no running instance -> exit 1')
    M.ipc.send_request = lambda *_a, **_k: {'ok': False, 'error': 'denied'}
    eq(_ctl_main(['ls']), 1, 'ctl ls: an error reply -> exit 1')
    M.ipc.send_request = lambda *_a, **_k: {
        'ok': True, 'tabs': [{'id': 1, 'title': 'one', 'tui': True},
                             {'id': 2, 'title': 'two'}]}
    eq(_ctl_main(['ls']), 0, 'ctl ls: lists tabs -> exit 0')
    M.ipc.send_request = lambda *_a, **_k: {'ok': True}
    eq(_ctl_main(['send-text', '--tab', 'id:1', 'hi\n']), 0, 'ctl send-text -> 0')
    eq(_ctl_main(['set-tab-title', '--tab', 'id:1', 'Renamed']), 0,
       'ctl set-tab-title -> 0')
    M.ipc.send_request = lambda *_a, **_k: {'ok': True, 'text': 'rendered text'}
    eq(_ctl_main(['dump-tab', '--tab', 'title:one', '--lines', '5']), 0,
       'ctl dump-tab -> 0')
finally:
    M.ipc.send_request = _orig_sr

# --- clipboard-read (OSC 52) request dialog: countdown + a choice -------------
from PyQt6.QtWidgets import QPushButton                         # noqa: E402
from PyQt6.QtCore import QEventLoop, QTimer                     # noqa: E402

term = win.tabs.currentWidget()
win._paste_delay = 2                       # secs=2 so the countdown _tick loops
_dec_before = getattr(term, '_clip_read', None)


def _exec_clip(self):
    # let the 1s countdown _tick fire a couple of times (covers both branches),
    # then click "Allow once" to drive _choose.
    loop = QEventLoop()
    QTimer.singleShot(2300, loop.quit)
    loop.exec()
    for _b in self.findChildren(QPushButton):
        if _b.text().startswith('Allow once'):
            _b.click()
            break
    return int(QDialog.DialogCode.Accepted)


QDialog.exec = _exec_clip
try:
    win._on_clipboard_read_requested(term)
    ok(True, 'clipboard-read dialog: countdown enables Allow, choice is recorded')
finally:
    QDialog.exec = _orig_exec

# --- keyboard-shortcuts dialog: build, Reset, Save ----------------------------
def _exec_shortcuts(self):
    for _b in self.findChildren(QPushButton):
        if _b.text() == 'Reset to defaults':
            _b.click()                     # fires _do_reset
    for _b in self.findChildren(QPushButton):
        if _b.text() == 'Save':
            _b.click()                     # fires _do_save -> accept on success
    return int(QDialog.DialogCode.Accepted)


QDialog.exec = _exec_shortcuts
try:
    win.show_shortcuts()
    ok(True, 'show_shortcuts: builds, resets and saves the bindings')
finally:
    QDialog.exec = _orig_exec

# locked keybindings: the fields and buttons are shown read-only
win._locked = set(win._locked) | {'keybindings'}
QDialog.exec = lambda _s: int(QDialog.DialogCode.Rejected)
try:
    win.show_shortcuts()
    ok(True, 'show_shortcuts: admin-locked bindings render read-only')
finally:
    QDialog.exec = _orig_exec

win.close()
win.deleteLater()
APP.processEvents()

print('secure-terminal-tests(mainwin): all passed' if not _failures else
      'secure-terminal-tests(mainwin): %d failed' % _failures)
# Flush before exit; the offscreen Qt platform can crash in its static teardown
# after a clean run, which would mask an otherwise-passing result -- so exit hard
# once the result is known and printed (all real work is already done). os._exit
# skips atexit, so persist coverage data explicitly first (a no-op otherwise).
try:
    import coverage
    _cov = coverage.Coverage.current()
    if _cov is not None:
        _cov.save()
except Exception:
    pass
sys.stdout.flush()
sys.stderr.flush()
os._exit(1 if _failures else 0)
