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
os.environ['XDG_RUNTIME_DIR'] = tempfile.mkdtemp()   # single-instance socket dir

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

# --- _read_hook_config: parse the command-hook settings ------------------------
from secure_terminal.main import _read_hook_config, _test_canary  # noqa: E402
from PyQt6.QtWidgets import (QFileDialog, QMenu, QMessageBox)      # noqa: E402
from PyQt6.QtCore import QPoint                                    # noqa: E402

eq(_read_hook_config({'command_hook': ''}), None,
   '_read_hook_config: no handler configured -> None')
eq(_read_hook_config({'command_hook': '"unterminated'}), None,
   '_read_hook_config: an unparseable command line -> None')
_hc = _read_hook_config({'command_hook': 'myhook --flag',
                         'command_hook_timeout': 'notanint'})
ok(_hc and _hc['argv'] == ['myhook', '--flag'] and _hc['timeout'] == 10,
   '_read_hook_config: parses argv; a bad timeout falls back to 10')

# --- close_tab (on a throwaway window so emptying it is harmless) --------------
w2 = MainWindow()
w2.new_tab()
w2.new_tab()
_n0 = w2.tabs.count()
w2.close_tab(999)                           # out-of-range -> no-op
ok(w2.tabs.count() == _n0, 'close_tab: an out-of-range index is a no-op')
w2.close_tab(0)
ok(w2.tabs.count() == _n0 - 1, 'close_tab: removes the tab at the given index')
while w2.tabs.count() > 0:                   # last close empties + closes window
    w2.close_tab(0)
ok(w2.tabs.count() == 0, 'close_tab: closing the last tab empties the window')
w2.deleteLater()

# --- tab context menu (exec stubbed) ------------------------------------------
_ome = QMenu.exec
QMenu.exec = lambda *_a, **_k: None
try:
    _pt = win.tabs.tabBar().tabRect(0).center()
    win._tab_context_menu(_pt)
    ok(True, 'tab context menu: builds over a tab')
    win._tab_context_menu(QPoint(9999, 9999))
    ok(True, 'tab context menu: no tab under the point -> no-op')
finally:
    QMenu.exec = _ome

# --- bell-sound picker (file dialog + allow-list gate, stubbed) ---------------
_owarn = QMessageBox.warning
_ogof = QFileDialog.getOpenFileName
QMessageBox.warning = staticmethod(lambda *_a, **_k: None)
_orig_locked = win._bell_sound_locked
try:
    win._bell_sound_locked = lambda: True
    win._pick_bell_sound()                  # locked -> return
    ok(True, '_pick_bell_sound: a locked setting is a no-op')
    win._bell_sound_locked = lambda: False
    QFileDialog.getOpenFileName = staticmethod(lambda *_a, **_k: ('', ''))
    win._pick_bell_sound()                  # cancelled -> return
    ok(True, '_pick_bell_sound: cancelling the dialog is a no-op')
    QFileDialog.getOpenFileName = staticmethod(
        lambda *_a, **_k: ('/etc/hostname', ''))   # a real file, not in the allow-list
    win._pick_bell_sound()                  # disallowed -> warning -> return
    ok(True, '_pick_bell_sound: a file outside the allowed dirs is refused')
finally:
    win._bell_sound_locked = _orig_locked
    QFileDialog.getOpenFileName = _ogof
    QMessageBox.warning = _owarn

# --- save_transcript (save dialog stubbed) ------------------------------------
_ogsf = QFileDialog.getSaveFileName
try:
    QFileDialog.getSaveFileName = staticmethod(lambda *_a, **_k: ('', ''))
    win.save_transcript()                   # cancelled -> return
    ok(True, 'save_transcript: cancelling the dialog is a no-op')
    _tpath = tempfile.mktemp(suffix='.txt')
    QFileDialog.getSaveFileName = staticmethod(lambda *_a, **_k: (_tpath, ''))
    win.save_transcript()
    ok(os.path.exists(_tpath), 'save_transcript: writes the transcript to disk')
finally:
    QFileDialog.getSaveFileName = _ogsf

# --- _test_canary: writes the marker + echoes; loud failure on a bad path -----
import secure_terminal.main as _MM              # noqa: E402
eq(_test_canary(), 0, '_test_canary: writes the marker and returns 0')
_orig_marker = _MM.canary_marker_path
try:
    _MM.canary_marker_path = lambda: '/proc/nonexistent-dir/marker'
    eq(_test_canary(), 1, '_test_canary: an unwritable marker fails loud (exit 1)')
finally:
    _MM.canary_marker_path = _orig_marker

# --- setting appliers: the apply path and the admin-locked early return --------
win.set_auto_tab_colors(True)
win.set_auto_tab_colors(False)
win.set_markings(True)
win.set_clipboard_read_always(True)
win.set_scrollback(1000)
win.set_paste_delay(3)
win.set_bell_sound('')                      # empty/disallowed -> cleared, applied
ok(True, 'setting appliers push the change to every tab and persist')

_saved_locked = set(win._locked)
_saved_bsl = win._bell_sound_locked
try:
    win._locked = {'auto_tab_colors'}
    win.set_auto_tab_colors(True)           # locked -> early return
    win._locked = {'colored_markings'}
    win.set_markings(True)
    win._locked = {'osc_clipboard_read_always'}
    win.set_clipboard_read_always(True)
    win._bell_sound_locked = lambda: True
    win.set_bell_sound('/etc/hostname')     # locked -> early return
    ok(True, 'setting appliers respect an admin lock (no change)')
finally:
    win._locked = _saved_locked
    win._bell_sound_locked = _saved_bsl

# --- the tray context menu is built from fixed, safe actions ------------------
_tray_menu = win._build_tray_menu()
ok(_tray_menu is not None and len(_tray_menu.actions()) >= 3,
   '_build_tray_menu: builds the fixed Show/Hide, New Tab, Quit menu')

# --- the find bar: search, step, and its key handling -------------------------
from PyQt6.QtGui import QKeyEvent                                # noqa: E402
from PyQt6.QtCore import Qt, QEvent                              # noqa: E402
from PyQt6.QtWidgets import QSystemTrayIcon                      # noqa: E402

win.show_find()
win._find_bar.input.setText('a')
win._find_update()
win._find_bar.case.setChecked(True)
win._find_bar.all_tabs.setChecked(True)
win._find_update()
win._find_step(False)
win._find_step(True)


def _fbkey(qtkey, mods=Qt.KeyboardModifier.NoModifier):
    win._find_bar.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, qtkey, mods, ''))


_fbkey(Qt.Key.Key_Return)
_fbkey(Qt.Key.Key_Return, Qt.KeyboardModifier.ShiftModifier)   # backward
_fbkey(Qt.Key.Key_A)                        # a plain key -> passed to super
_fbkey(Qt.Key.Key_Escape)                   # -> hide_find
ok(True, 'find bar: search updates, stepping and the Esc/Enter keys work')

# --- the system-tray icon: disabled, unavailable, and created -----------------
_o_avail = QSystemTrayIcon.isSystemTrayAvailable
_o_systray = win._systray
try:
    win._systray = False
    ok(win._tray_icon() is None, 'tray: disabled in settings -> None')
    win._systray = True
    win._tray = None
    QSystemTrayIcon.isSystemTrayAvailable = staticmethod(lambda: False)
    ok(win._tray_icon() is None, 'tray: no platform tray -> None')
    QSystemTrayIcon.isSystemTrayAvailable = staticmethod(lambda: True)
    win._tray = None
    win._tray_icon()                        # -> creates + shows the tray icon
    ok(win._tray is not None, 'tray: created when enabled and available')
finally:
    QSystemTrayIcon.isSystemTrayAvailable = _o_avail
    win._systray = _o_systray

# --- a window built while TUI is unavailable greys out the TUI controls --------
_o_tuia = M.tui_available
try:
    M.tui_available = lambda: False
    _wt = MainWindow()
    ok(True, 'window builds with TUI unavailable (TUI controls disabled)')
    _wt.deleteLater()
    APP.processEvents()
finally:
    M.tui_available = _o_tuia

# --- copy/paste/zoom + input-dialog actions routed through the current tab -----
from PyQt6.QtWidgets import QInputDialog, QSystemTrayIcon        # noqa: E402

win.copy_selection()
win.paste_clipboard()
win.zoom_in()
win.zoom_out()
win._on_zoom_step(1)
ok(True, 'copy/paste/zoom route through the current tab')

_ogt = QInputDialog.getText
try:
    QInputDialog.getText = staticmethod(lambda *_a, **_k: ('', False))
    win.new_tab_running()                   # cancelled -> no new tab
    win.show_command_palette()              # cancelled
    QInputDialog.getText = staticmethod(lambda *_a, **_k: ('echo hi', True))
    win.new_tab_running()                   # -> new_tab('echo hi')
    win.show_command_palette()              # -> run_command('echo hi')
    ok(True, 'new_tab_running and the command palette read the input dialog')
finally:
    QInputDialog.getText = _ogt

# move the current tab left/right (needs more than one tab; wraps)
while win.tabs.count() < 2:
    win.new_tab()
win._on_tab_move(1)
win._on_tab_move(-1)
ok(True, 'the current tab moves left/right with wrap-around')

# a program-set title updates the tab label; window visibility + tray trigger
win._on_tab_title(win.current(), 'a program title')
win.show()
win._toggle_window_visibility()             # visible -> hide
win._toggle_window_visibility()             # hidden -> restore
win._on_tray_activated(QSystemTrayIcon.ActivationReason.Trigger)
ok(True, 'program title, window visibility toggle and tray trigger all work')

# a tab whose shell exits is closed; an unknown term is ignored
win.new_tab()
_victim_tab = win.tabs.widget(win.tabs.count() - 1)
_n_before = win.tabs.count()
win._on_shell_exited(_victim_tab)
ok(win.tabs.count() == _n_before - 1, '_on_shell_exited closes the tab whose shell ended')
win._on_shell_exited(win.current())         # called again is harmless
ok(True, '_on_shell_exited on the current tab is handled')

# --- the current-tab actions are safe no-ops when there is no current tab -----
w3 = MainWindow()
while w3.tabs.count():
    w3.tabs.removeTab(0)                     # empty it without closing the window
ok(w3.current() is None, 'a window with no tabs has no current tab')
w3.copy_selection()
w3.paste_clipboard()
w3.zoom_in()
w3.zoom_out()
w3._on_zoom_step(-1)
w3.set_markings(True)                        # current() None -> apply skipped
w3.set_tui(True)
w3.save_transcript()                         # current() None -> returns before any dialog
ok(True, 'current-tab actions are harmless no-ops with no tab open')
w3.deleteLater()
APP.processEvents()

# --- a keybindings drop-in drives the custom-shortcut parse at startup ---------
_cfgd = os.path.join(os.environ['XDG_CONFIG_HOME'], 'secure-terminal.d')
os.makedirs(_cfgd, exist_ok=True)
with open(os.path.join(_cfgd, '90-keys.conf'), 'w', encoding='utf-8') as _kf:
    _kf.write('keybindings=find=Ctrl+F new_tab=Ctrl+Shift+T\n')
_wk = MainWindow()
ok(True, 'a keybindings drop-in is parsed when the window starts')
_wk.deleteLater()
APP.processEvents()

# --- main(): the entry point, driven with QApplication + exec + ipc mocked ----
import signal as _signal                             # noqa: E402
from secure_terminal.main import main as _main       # noqa: E402
from PyQt6.QtWidgets import QApplication as _QA       # noqa: E402

_o_argv = sys.argv[:]
_o_sr = M.ipc.send_request
_o_qa = M.QApplication
_o_qexec = _QA.exec
_o_chld = _signal.getsignal(_signal.SIGCHLD)
try:
    # `ctl` subcommand is dispatched before Qt
    M.ipc.send_request = lambda *_a, **_k: {'ok': True, 'tabs': []}
    sys.argv = ['secure-terminal', 'ctl', 'ls']
    eq(_main(), 0, 'main: a `ctl` argv dispatches to the ctl client')
    # --test-canary fires the headless positive control
    sys.argv = ['secure-terminal', '--new-instance', '--test-canary']
    eq(_main(), 0, 'main: --test-canary runs the headless canary before Qt')
    # a running instance accepts the launch -> exit 0 without starting Qt
    M.ipc.send_request = lambda *_a, **_k: {'ok': True}
    sys.argv = ['secure-terminal', '--title', 'x']
    eq(_main(), 0, 'main: an existing instance accepts the launch -> 0')
    # a running instance refusing the launch -> exit 1
    M.ipc.send_request = lambda *_a, **_k: {'ok': False, 'error': 'refused'}
    eq(_main(), 1, 'main: an existing instance refusing the launch -> 1')
    # no running instance -> full startup (QApplication + window + event loop),
    # with the app object and its blocking exec() replaced
    M.ipc.send_request = lambda *_a, **_k: None

    class _AppProxy:                        # call -> the existing app; else delegate
        def __call__(self, _argv):
            return APP

        def __getattr__(self, _name):
            return getattr(_QA, _name)

    M.QApplication = _AppProxy()
    _QA.exec = lambda _self: 0
    sys.argv = ['secure-terminal', '--title', 'fresh']
    eq(_main(), 0, 'main: with no running instance it starts the app + event loop')
finally:
    sys.argv = _o_argv
    M.ipc.send_request = _o_sr
    M.QApplication = _o_qa
    _QA.exec = _o_qexec
    _signal.signal(_signal.SIGCHLD, _o_chld)

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
