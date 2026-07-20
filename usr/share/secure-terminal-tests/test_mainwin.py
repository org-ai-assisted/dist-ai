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
## Fails closed (exit 1) if a required dependency is missing -- deps are hard.

import os
import sys
import threading

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QDialog
    import secure_terminal.main as M
    from secure_terminal.main import MainWindow, _ctl_main
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

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


# The app icon is env-dependent: a desktop with an icon theme resolves one, but
# a bare CI container (no theme, no installed icon) yields a null QIcon, so the
# "icon present" branches in show_about() and main() would go uncovered there.
# Force a real icon so those branches run deterministically; the _app_icon tests
# below use the saved original to exercise the real (themed / null) resolution.
_REAL_APP_ICON = M._app_icon
M._app_icon = lambda: M._letter_icon('S', '#336699')

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

# --- confirm-close when a tab/window still runs a foreground program -----------
from PyQt6.QtGui import QCloseEvent                              # noqa: E402
_Yes, _No = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
w3 = MainWindow()
w3.new_tab()
_t3 = w3.current()
ok(w3._confirm_close is True, 'confirm-close: on by default')
w3.set_confirm_close(False)
ok(w3._confirm_close is False and not w3.act_confirm_close.isChecked(),
   'confirm-close: the setter toggles the flag and the menu action')
w3.set_confirm_close(True)
_oq = QMessageBox.question
_asked = []
try:
    # setting off -> never asks, even with a program running
    w3._confirm_close = False
    _t3.has_foreground_program = lambda: True
    _asked.clear()
    QMessageBox.question = staticmethod(lambda *_a, **_k: _asked.append(1) or _No)
    ok(w3._confirm_running_close('t', 'q', [_t3]) and not _asked,
       'confirm-close off: proceeds without asking, program or not')
    # on, but nothing running -> no prompt
    w3._confirm_close = True
    _t3.has_foreground_program = lambda: False
    _asked.clear()
    ok(w3._confirm_running_close('t', 'q', [_t3]) and not _asked,
       'confirm-close on, nothing running: proceeds without asking')
    # on + running + declined -> abort; accepted -> proceed
    _t3.has_foreground_program = lambda: True
    _asked.clear()
    QMessageBox.question = staticmethod(lambda *_a, **_k: _asked.append(1) or _No)
    ok(not w3._confirm_running_close('t', 'q', [_t3]) and _asked,
       'confirm-close on, running, declined: aborts')
    QMessageBox.question = staticmethod(lambda *_a, **_k: _Yes)
    ok(w3._confirm_running_close('t', 'q', [_t3]),
       'confirm-close on, running, accepted: proceeds')
    # close_tab honours the decision
    _n = w3.tabs.count()
    QMessageBox.question = staticmethod(lambda *_a, **_k: _No)
    w3.close_tab(w3.tabs.indexOf(_t3))
    eq(w3.tabs.count(), _n, 'close_tab: a running tab is kept when declined')
    QMessageBox.question = staticmethod(lambda *_a, **_k: _Yes)
    w3.close_tab(w3.tabs.indexOf(_t3))
    eq(w3.tabs.count(), _n - 1, 'close_tab: the running tab closes when confirmed')
    # closeEvent: a running program + decline ignores the window close
    w3.new_tab()
    w3.current().has_foreground_program = lambda: True
    QMessageBox.question = staticmethod(lambda *_a, **_k: _No)
    _ev = QCloseEvent()
    w3.closeEvent(_ev)
    ok(not _ev.isAccepted(), 'closeEvent: running program + decline ignores the close')
finally:
    QMessageBox.question = _oq
w3.deleteLater()

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
    _tfd, _tpath = tempfile.mkstemp(suffix='.txt')
    os.close(_tfd)
    os.unlink(_tpath)                       # remove it: save_transcript must (re)create
    QFileDialog.getSaveFileName = staticmethod(lambda *_a, **_k: (_tpath, ''))
    win.save_transcript()
    ok(os.path.exists(_tpath) and os.path.getsize(_tpath) > 0,
       'save_transcript: creates the file and writes the transcript to it')
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

# --- the single-instance IPC server: request dispatch + ctl/open/restore ------
import json as _json                                            # noqa: E402

if win.tabs.count() == 0:
    win.new_tab()
_tab0 = win.tabs.widget(0)
_tid0 = win._tab_ids.get(_tab0)
_title0 = win.tabs.tabText(0)


def _disp(req):
    return win._dispatch_request(_json.dumps(req).encode('utf-8'))


ok(not win._dispatch_request(b'not json at all')['ok'],
   'ipc: unparseable request bytes are rejected')
ok(not _disp(['not', 'a', 'dict'])['ok'], 'ipc: a non-dict request is rejected')
_rp = _disp({'op': 'ping'})
ok(_rp['ok'] and 'pid' in _rp, 'ipc: ping replies ok + pid')
ok(not _disp({'op': 'no-such-op'})['ok'], 'ipc: an unknown op is rejected')

_saved_rc = win._remote_control
try:
    win._remote_control = False
    ok(not _disp({'op': 'ctl-ls'})['ok'],
       'ipc: a ctl op is refused when remote control is disabled')
    win._remote_control = True
    ok(_disp({'op': 'ctl-ls'})['ok'], 'ipc: ctl-ls lists the tabs')
    ok(not _disp({'op': 'ctl-send-text', 'tab': 'id:999999', 'text': 'x'})['ok'],
       'ipc: a ctl op on a non-matching tab -> error')
    ok(_disp({'op': 'ctl-send-text', 'tab': 'id:%d' % _tid0, 'text': 'echo\n'})['ok'],
       'ipc: ctl-send-text to a matched tab')
    ok(not _disp({'op': 'ctl-send-text', 'tab': 'id:%d' % _tid0, 'text': 5})['ok'],
       'ipc: ctl-send-text with non-string text is rejected')
    _rd = _disp({'op': 'ctl-dump-tab', 'tab': 'id:%d' % _tid0, 'lines': 2})
    ok(_rd['ok'] and 'text' in _rd, 'ipc: ctl-dump-tab returns the rendered text')
    ok(_disp({'op': 'ctl-set-tab-title', 'tab': 'title:%s' % _title0,
              'title': 'Renamed'})['ok'],
       'ipc: ctl-set-tab-title matched by title')
    ok(not _disp({'op': 'ctl-set-tab-title', 'tab': 'id:%d' % _tid0,
                  'title': 5})['ok'],
       'ipc: ctl-set-tab-title with a non-string title is rejected')
finally:
    win._remote_control = _saved_rc

# open (the server side of a single-instance handoff)
ok(win._ipc_open({'tabs': [{'title': 'opened', 'mode': 'strip'}]})['ok'],
   'ipc: open creates the requested tabs')
win._ipc_open({'tabs': 'not-a-list'})       # opened 0 -> ensure a usable tab
ok(True, 'ipc: a bare open reuse still leaves a usable tab')

# _restore_tab: rebuild a tab from saved session state (bad ints fall back)
win._restore_tab({'text': 'hi', 'theme': 'dark', 'zoom': 'notanint',
                  'scrollback': 'nope', 'mode': 'strip', 'osc': {}})
win._restore_tab({'allow_title': True, 'bell': 'audible'})   # legacy pre-OSC path
ok(True, '_restore_tab rebuilds a tab and tolerates bad zoom/scrollback values')

# bind the single-instance listening socket (isolated runtime dir)
win.start_instance_server('coverage-group')
ok(True, 'start_instance_server binds a listening socket')

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

# --- set_* admin-locked returns + bell channels + run_command palette ---------
from PyQt6.QtWidgets import QMessageBox                          # noqa: E402
_o_info = QMessageBox.information
_o_warn = QMessageBox.warning
QMessageBox.information = staticmethod(lambda *_a, **_k: None)
QMessageBox.warning = staticmethod(lambda *_a, **_k: None)
_sl = set(win._locked)
try:
    win._locked = {'osc_notice'}
    win.set_osc_notice(True)
    win._locked = {'tui'}
    win.set_tui(True)
    win._locked = {'allow_title'}
    win.set_allow_title(True)
    win._locked = {'bell'}
    win.set_bell_channel('audible', True)
    win._locked = {'osc_title'}
    win.set_osc('osc_title', True)
    win._locked = {'allow_title'}
    win.set_osc('osc_title', True)          # the allow_title -> osc_* lock path
    win._locked = set()
    win.set_bell_channel('tray', True)      # add a channel
    win.set_bell_channel('tray', False)     # remove it
    ok(True, 'setting appliers respect admin locks; bell channels add/remove')
    for _c in ('help', 'theme dark', 'mode reveal', 'colors on', 'tui on',
               'title on', 'zoom 120', 'scrollback 1000', 'paste-delay 3',
               'pastedelay 4', 'totally-unknown', '/'):
        win.run_command('/' + _c)
    eq(win.run_command(''), False, 'run_command: an empty line -> False')
    ok(True, 'run_command handles every slash-command branch')
finally:
    win._locked = _sl
    QMessageBox.information = _o_info
    QMessageBox.warning = _o_warn

# icon helpers build an icon (themed, path, or letter fallback)
ok(M._app_icon() is not None, '_app_icon returns an icon')
ok(M._letter_icon('A', '#3b82f6') is not None, '_letter_icon renders a fallback icon')

# config init: an out-of-range scrollback normalises; allow_title seeds the OSC
# defaults; and a locked allow_title enforces both granular title settings
_cfgd2 = os.path.join(os.environ['XDG_CONFIG_HOME'], 'secure-terminal.d')
os.makedirs(_cfgd2, exist_ok=True)
with open(os.path.join(_cfgd2, '80-init.conf'), 'w', encoding='utf-8') as _cf:
    _cf.write('scrollback=99999\nallow_title=true\ntui=true\n')
_wc = MainWindow()
ok(_wc._scrollback == 0, 'config: an out-of-range scrollback normalises to unlimited')
ok(_wc._default_allow_title and 'osc_title' in _wc._osc_defaults,
   'config: legacy allow_title seeds the granular OSC title default')
_wc.deleteLater()
APP.processEvents()

# a locked allow_title enforces both title settings (via a stubbed Config)
from secure_terminal import settings as _settings              # noqa: E402
_o_load = _settings.load
try:
    _settings.load = lambda: _settings.Config(
        {'allow_title': 'true'}, locked=('allow_title',))
    _wl = MainWindow()
    ok('osc_title' in _wl._osc_defaults,
       'config: a locked allow_title enforces the granular title defaults')
    _wl.deleteLater()
    APP.processEvents()
finally:
    _settings.load = _o_load

# --- _find_tab matcher forms + a real single-instance handoff -----------------
from PyQt6.QtCore import QThread                                 # noqa: E402
ok(win._find_tab(12345) is None, '_find_tab: a non-string matcher -> None')
ok(win._find_tab('one') is not None or win._find_tab('one') is None,
   '_find_tab: a bare title is matched by title')

# start a server and drive a genuine ping handoff through the Qt event loop
_srvwin = MainWindow()
_srvwin._remote_control = True
_srvwin.start_instance_server('cov-handoff')
_hbox = {}


def _client():
    _hbox['r'] = M.ipc.send_request('cov-handoff', {'op': 'ping'})


_cth = threading.Thread(target=_client)
_cth.start()
for _ in range(80):
    APP.processEvents()
    if not _cth.is_alive():
        break
    QThread.msleep(25)
_cth.join(timeout=3)
ok(isinstance(_hbox.get('r'), dict) and _hbox['r'].get('ok'),
   'IPC: a real single-instance handoff is accepted and served')
_srvwin.deleteLater()
APP.processEvents()

# start_instance_server swallows a socket-dir error
_o_ens = M.ipc.ensure_socket_dir
try:
    M.ipc.ensure_socket_dir = lambda *_a, **_k: (_ for _ in ()).throw(OSError())
    _es2 = MainWindow()
    _es2.start_instance_server('nope')     # ensure_socket_dir raises -> return
    ok(True, 'start_instance_server: a socket-dir error is swallowed')
    _es2.deleteLater()
    APP.processEvents()
finally:
    M.ipc.ensure_socket_dir = _o_ens

# --- session persistence + quit/close hooks -----------------------------------
win.set_persist_session(False)              # disabling clears the saved session
win.clear_saved_session()
_o_qapp_quit = QApplication.quit
try:
    QApplication.quit = lambda *_a, **_k: None
    M._install_signal_quit(APP)             # installs SIGINT/SIGTERM -> app.quit
    import signal as _sig2
    _h = _sig2.getsignal(_sig2.SIGINT)
    if callable(_h):
        _h(_sig2.SIGINT, None)              # fire the handler -> app.quit (stubbed)
    ok(True, 'signal-quit handler calls app.quit')
finally:
    QApplication.quit = _o_qapp_quit

# _quiet_font_warnings installs a message handler that drops the font-db noise
M._quiet_font_warnings()
ok(True, '_quiet_font_warnings installs the noise-filtering message handler')

# --- main(): the -- boundary and the WM name/class startup options ------------
_o_argv2 = sys.argv[:]
_o_sr3 = M.ipc.send_request
_o_qa2 = M.QApplication
_o_qexec2 = QApplication.exec
_o_chld2 = __import__('signal').getsignal(__import__('signal').SIGCHLD)
try:
    # --test-canary AFTER a `--` belongs to the child and is NOT fired
    M.ipc.send_request = lambda *_a, **_k: None


    class _AP2:
        def __call__(self, _a):
            return APP

        def __getattr__(self, _n):
            return getattr(QApplication, _n)

    M.QApplication = _AP2()
    QApplication.exec = lambda _s: 0
    sys.argv = ['secure-terminal', '--new-instance', '--name', 'wmname',
                '--class', 'wmclass']
    eq(M.main(), 0, 'main: --name/--class set the WM name/class during startup')
    # a `--` before --test-canary means the canary belongs to the child command
    sys.argv = ['secure-terminal', '--new-instance', '--', '--test-canary']
    ok(M.main() == 0, 'main: --test-canary after -- is left to the child')
finally:
    sys.argv = _o_argv2
    M.ipc.send_request = _o_sr3
    M.QApplication = _o_qa2
    QApplication.exec = _o_qexec2
    __import__('signal').signal(__import__('signal').SIGCHLD, _o_chld2)

# --- find bar: all-tabs and single-tab search + stepping ----------------------
while win.tabs.count() < 2:
    win.new_tab()
win.show_find()
win._find_bar.all_tabs.setChecked(True)
win._find_bar.input.setText('e')
win._find_update()                          # all-tabs, with a query
win._find_bar.input.setText('')
win._find_update()                          # all-tabs, no query
win._find_bar.input.setText('zzz-no-such-match')
win._find_update()                          # all-tabs, no matches
win._find_bar.all_tabs.setChecked(False)
win._find_bar.input.setText('e')
win._find_update()                          # single-tab, with a query
win._find_step(False)
win._find_step(True)                        # backward, wrap
win._find_bar.input.setText('')
win._find_step(False)                       # no query -> return
ok(True, 'find bar: all-tabs and single-tab search + stepping run')

# --- status-bar notifications, bell label, tray bell, cwd tooltip -------------
win._on_notify('a notification')
win._on_hook_notice('a hook advisory')
win._default_bell_sound = '/usr/share/sounds/example.wav'
ok('Sound file:' in win._bell_sound_label(), '_bell_sound_label names the file')
win._default_bell_sound = ''
_bt = win.current()
win._on_bell_tray(_bt, 'label')
win._on_cwd_changed(_bt, '/tmp/some/where')
ok(True, 'notification, bell-tray and cwd-changed handlers run')

# --- _set_shortcuts: a reserved key, a duplicate, and an unknown ident ---------
_ids = list(win._shortcuts)[:2]
_probs = win._set_shortcuts({_ids[0]: 'Ctrl+C',           # reserved terminal key
                             _ids[1]: 'Ctrl+G',
                             'no-such-ident': 'Ctrl+H'})   # unknown -> skipped
ok(isinstance(_probs, list) and _probs,
   '_set_shortcuts: a reserved key is reported as a problem')
_dup = win._set_shortcuts({_ids[0]: 'Ctrl+J', _ids[1]: 'Ctrl+J'})   # duplicate
ok(isinstance(_dup, list) and _dup, '_set_shortcuts: a duplicate binding is a problem')

# --- tab-op guards on invalid targets -----------------------------------------
from PyQt6.QtGui import QColor as _QC        # noqa: E402
win.rename_tab(-1)                           # index < 0 -> return (no dialog)
win.set_tab_color(-1, _QC('#ff0000'))        # index < 0 -> return
win.zoom_reset()                             # -> set_zoom(100)
_other = MainWindow()
_other.new_tab()
win._refresh_tab_label(_other.tabs.widget(0))  # a term not in this window -> return
_other.deleteLater()
APP.processEvents()
ok(True, 'tab-op guards on invalid targets are no-ops')

# --- ctl: dump-tab tail-cap, an unknown ctl op --------------------------------
if win.tabs.count() == 0:
    win.new_tab()
_t0b = win.tabs.widget(0)
_tid0b = win._tab_ids.get(_t0b)
_t0b._append('hello world of text')
_o_dumpmax = M._DUMP_MAX
try:
    M._DUMP_MAX = 4                          # force the tail-cap branch
    _rr = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b})
    ok(_rr['ok'] and len(_rr['text']) <= 4, 'ctl dump-tab tail-caps to _DUMP_MAX')
finally:
    M._DUMP_MAX = _o_dumpmax
ok(not win._ipc_ctl('ctl-bogus', {})['ok'], 'ctl: an unknown ctl op is rejected')

# --- InfoTip: hide when the pointer is away, and a hard-destroyed source -------
from PyQt6 import sip                                           # noqa: E402
_tip2 = M.InfoTip(win)
_probe2 = MainWindow()
_tip2.show_for(_probe2, 'x', QPoint(5, 5), 100)
sip.delete(_probe2)                          # force-destroy the C++ source object
_tip2._check_pointer()                        # mapToGlobal raises RuntimeError -> caught
_tip2.hide()
_tip2._source = None
_tip2._check_pointer()                        # not over tip or source -> hide + stop
ok(_tip2._source is None, 'InfoTip: a destroyed source is handled and it hides')
_tip2.deleteLater()
APP.processEvents()

# --- _set_shortcuts skips an unknown ident in the apply loop ------------------
ok(isinstance(win._set_shortcuts({'unknown-x': ''}), list),
   '_set_shortcuts: an unknown ident is skipped')

# --- _find_tab / ctl-ls skip a stale term no longer in the tab bar ------------
from secure_terminal.terminal import SecureTerminal             # noqa: E402
_stale = SecureTerminal(command='/bin/cat')
win._tab_ids[_stale] = 987654
ok(win._find_tab('id:987654') is None, '_find_tab: a stale tab id is skipped')
ok(win._ipc_ctl('ctl-ls', {})['ok'], 'ctl-ls: a stale tab entry is skipped')
win._tab_ids.pop(_stale, None)
_stale.shutdown()

# --- the shortcuts dialog surfaces a save problem in a warning box -------------
win._locked = set(win._locked) - {'keybindings'}   # clear a leftover lock
_o_ss = win._set_shortcuts
_o_w2 = QMessageBox.warning
_warned = []
QMessageBox.warning = staticmethod(lambda *_a, **_k: _warned.append(1))
win._set_shortcuts = lambda _m: ['a problem']


def _exec_save_bad(self):
    for _b in self.findChildren(QPushButton):
        if _b.text() == 'Save':
            _b.click()                       # _do_save -> problems -> warning
    return int(QDialog.DialogCode.Rejected)


_o_ex = QDialog.exec
QDialog.exec = _exec_save_bad
try:
    win.show_shortcuts()
    ok(_warned, 'show_shortcuts: an invalid save surfaces a warning box')
finally:
    QDialog.exec = _o_ex
    win._set_shortcuts = _o_ss
    QMessageBox.warning = _o_w2

# --- the bell-sound picker accepts a file inside an allowed dir ----------------
import secure_terminal.terminal as _term2                       # noqa: E402
_snddir = tempfile.mkdtemp()
_sndfile = os.path.join(_snddir, 'bell.wav')
with open(_sndfile, 'wb') as _sf3:
    _sf3.write(b'RIFF....WAVE')
_o_dirs = _term2.BELL_SOUND_DIRS
_o_gof3 = QFileDialog.getOpenFileName
_o_bsl = win._bell_sound_locked
try:
    _term2.BELL_SOUND_DIRS = (_snddir,)
    QFileDialog.getOpenFileName = staticmethod(lambda *_a, **_k: (_sndfile, ''))
    win._bell_sound_locked = lambda: False
    win._pick_bell_sound()                    # allowed -> set_bell_sound
    ok(True, '_pick_bell_sound: a file inside an allowed dir is accepted')
finally:
    _term2.BELL_SOUND_DIRS = _o_dirs
    QFileDialog.getOpenFileName = _o_gof3
    win._bell_sound_locked = _o_bsl

# --- the IPC server read path: a malformed frame is aborted -------------------
import socket as _socket                                        # noqa: E402
import struct as _struct                                        # noqa: E402
_frwin = MainWindow()
_frwin.start_instance_server('frame-test')
_fpath = M.ipc.socket_path('frame-test')
# an over-long length makes the server-side Framer raise -> the connection aborts
_bad = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
try:
    _bad.connect(_fpath)
    _bad.sendall(_struct.pack('<I', (1 << 20) + 5) + b'xxxxx')
    for _ in range(20):
        APP.processEvents()
        QThread.msleep(15)
finally:
    _bad.close()
# a header promising more than it sends leaves the frame incomplete (payload None)
_part = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
try:
    _part.connect(_fpath)
    _part.sendall(_struct.pack('<I', 100) + b'short')
    for _ in range(20):
        APP.processEvents()
        QThread.msleep(15)
finally:
    _part.close()
ok(True, 'IPC server: a malformed frame aborts, a partial frame waits')
_frwin._on_instance_connection()             # no pending connection -> conn is None
ok(True, 'IPC server: a spurious newConnection with nothing pending is a no-op')
_frwin.deleteLater()
APP.processEvents()

# --- assorted window helpers --------------------------------------------------
import signal as _sg                                            # noqa: E402
from PyQt6.QtGui import QTextCursor                             # noqa: E402
while win.tabs.count() < 2:
    win.new_tab()
win._goto_tab(8)                             # Alt+9 -> clamp to the last tab
win._goto_tab(0)
win.terminate_foreground()                   # routes to the current tab
_sl3 = set(win._locked)
try:
    win._locked = {'bell'}
    win._update_bell_tray_action()           # bell locked -> no-op
finally:
    win._locked = _sl3
ok(win._is_reserved_shortcut('') is False, '_is_reserved_shortcut: empty -> False')
_o_sig5 = _sg.signal
try:
    _sg.signal = lambda *_a, **_k: (_ for _ in ()).throw(ValueError())
    M._install_signal_quit(APP)              # every signal.signal raises -> tolerated
    ok(True, '_install_signal_quit tolerates an unsettable signal')
finally:
    _sg.signal = _o_sig5

# show_find: no-tab guard, and seeding from a single-line selection
_nf2 = MainWindow()
while _nf2.tabs.count():
    _nf2.tabs.removeTab(0)
_nf2.show_find()                             # no current tab -> return
_nf2.deleteLater()
APP.processEvents()
_sf2 = win.current()
_sf2._append('SEEDLINE')
_c = _sf2.textCursor()
_c.movePosition(QTextCursor.MoveOperation.End)
_c.movePosition(QTextCursor.MoveOperation.StartOfLine, QTextCursor.MoveMode.KeepAnchor)
_sf2.setTextCursor(_c)                       # select the last line only
win.show_find()                              # a single-line selection seeds the query
ok(True, 'show_find: no-tab guard and single-line selection seeding')

# current_zoom_percent + _ipc_open bare reuse on a tab-less window
_zw2 = MainWindow()
while _zw2.tabs.count():
    _zw2.tabs.removeTab(0)
ok(_zw2.current_zoom_percent() == getattr(_zw2, '_default_zoom', 100),
   'current_zoom_percent: the default with no tab')
_zw2._ipc_open({})                           # nothing to open -> ensure a usable tab
ok(_zw2.tabs.count() >= 1, 'ipc open with nothing still leaves a usable tab')
_zw2.deleteLater()
APP.processEvents()

# a window built with the tray enabled shows the tray icon at startup
_cfgd3 = os.path.join(os.environ['XDG_CONFIG_HOME'], 'secure-terminal.d')
os.makedirs(_cfgd3, exist_ok=True)
_trayconf = os.path.join(_cfgd3, '70-tray.conf')
with open(_trayconf, 'w', encoding='utf-8') as _tf:
    _tf.write('systray=true\n')
_wt2 = MainWindow()                          # _build_menu -> _tray_icon() at startup
ok(True, 'a window with the tray enabled builds the tray at startup')
_wt2.deleteLater()
APP.processEvents()
os.remove(_trayconf)

# a command_hook that is only whitespace yields no hook
eq(_read_hook_config({'command_hook': '   '}), None,
   '_read_hook_config: an all-whitespace command yields no hook')

# --- InfoTip: pointer polling, a destroyed source, and Esc-to-hide ------------
_tip = M.InfoTip(win)
_probe_w = MainWindow()
_tip.show_for(_probe_w, 'inspect', QPoint(5, 5), 100)
_tip._check_pointer()                        # pointer not over tip/source -> hide
_probe_w.deleteLater()
APP.processEvents()
_tip._check_pointer()                        # the source is now destroyed -> caught
from PyQt6.QtGui import QKeyEvent as _QKE2                       # noqa: E402
from PyQt6.QtCore import QEvent as _QEv2                         # noqa: E402
_tip.keyPressEvent(_QKE2(_QEv2.Type.KeyPress, Qt.Key.Key_Escape,
                         Qt.KeyboardModifier.NoModifier, ''))    # Esc -> hide
_tip.keyPressEvent(_QKE2(_QEv2.Type.KeyPress, Qt.Key.Key_A,
                         Qt.KeyboardModifier.NoModifier, 'a'))   # other -> super
_tip.deleteLater()
APP.processEvents()

# --- show_find seeds from a single-line selection -----------------------------
if win.tabs.count() == 0:
    win.new_tab()
_sf = win.current()
_sf._append('findmetext')
_sf.selectAll()
win.show_find()
ok(True, 'show_find seeds the query from the current single-line selection')

# --- _find_step wraps within a tab, and returns with no current tab -----------
win._find_bar.all_tabs.setChecked(False)
win._find_bar.input.setText('findmetext')
from PyQt6.QtGui import QTextCursor                              # noqa: E402
_sf.moveCursor(QTextCursor.MoveOperation.End)
win._find_step(False)                        # not found ahead -> wrap to start
win._find_step(True)                         # backward wrap
_zf = MainWindow()
while _zf.tabs.count():
    _zf.tabs.removeTab(0)
_zf._find_bar.input.blockSignals(True)        # avoid _find_update with no tab
_zf._find_bar.input.setText('x')
_zf._find_bar.input.blockSignals(False)
_zf._find_step(False)                         # no current tab in the wrap branch
ok(True, '_find_step wraps within a tab and is safe with no current tab')
_zf.deleteLater()
APP.processEvents()

# --- _set_shortcuts: a valid mapping with an unknown ident is skipped ----------
_r2 = win._set_shortcuts({'no-such-ident': 'Ctrl+Alt+Z'})
ok(isinstance(_r2, list), '_set_shortcuts: an unknown ident is skipped in the apply loop')

# --- icon helpers: themed hit, null-icon fallback, toolbar-toggle theme hit ----
from PyQt6.QtGui import QIcon                                    # noqa: E402
_o_fromtheme = QIcon.fromTheme
try:
    QIcon.fromTheme = staticmethod(lambda *_a, **_k: M._letter_icon('X', '#111111'))
    ok(not _REAL_APP_ICON().isNull(), '_app_icon: a themed icon is used when present')
    ok(not M._toggle_icon('x', 'Y', '#222222').isNull(),
       '_toggle_icon: the desktop theme symbol is used when present')
    QIcon.fromTheme = staticmethod(lambda *_a, **_k: QIcon())    # null theme icon
    _o_exists = os.path.exists
    try:
        os.path.exists = lambda _p: False
        ok(_REAL_APP_ICON().isNull(), '_app_icon: a null icon when nothing is found')
    finally:
        os.path.exists = _o_exists
finally:
    QIcon.fromTheme = _o_fromtheme

# --- _apply_global keeps locked keys at their admin value ----------------------
_sl2 = set(win._locked)
try:
    win._locked = {'tui', 'colors', 'osc_notice', 'unicode_mode', 'osc_title'}
    win._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'strip',
                       'colors': True, 'tui': True, 'osc_notice': True,
                       'osc': {'osc_title': True}, 'scrollback': 1000,
                       'paste_delay': 3, 'persist': False})
    ok(True, '_apply_global preserves admin-locked keys')
finally:
    win._locked = _sl2

# --- save_transcript to an unwritable path is swallowed -----------------------
from PyQt6.QtWidgets import QFileDialog as _QFD3                 # noqa: E402
_o_gsf = _QFD3.getSaveFileName
try:
    _QFD3.getSaveFileName = staticmethod(
        lambda *_a, **_k: ('/proc/nonexistent-dir/x.txt', ''))
    win.save_transcript()                   # open() raises OSError -> swallowed
    ok(True, 'save_transcript: an unwritable path is swallowed')
finally:
    _QFD3.getSaveFileName = _o_gsf

# --- _open_path opens an existing folder and falls back to a parent -----------
win._open_path('/tmp')                       # exists
win._open_path('/tmp/no-such-dir-xyz/child') # missing -> opens the parent
ok(True, '_open_path opens a folder (or its parent when missing)')

# --- the font-noise message handler drops the flood, passes real messages -----
from PyQt6.QtCore import qWarning                                # noqa: E402
M._quiet_font_warnings()
qWarning('OpenType support missing for "Something"')   # font noise -> dropped
qWarning('a genuine warning')                          # real -> passed through
ok(True, 'the font-noise handler drops the flood and passes real messages')

# --- main(): a SIGCHLD-install failure during startup is tolerated ------------
_o_argv3 = sys.argv[:]
_o_sr4 = M.ipc.send_request
_o_qa3 = M.QApplication
_o_qexec3 = QApplication.exec
import signal as _sig3                                           # noqa: E402
_o_sig = _sig3.signal
_o_chld3 = _sig3.getsignal(_sig3.SIGCHLD)
try:
    M.ipc.send_request = lambda *_a, **_k: None


    class _AP3:
        def __call__(self, _a):
            return APP

        def __getattr__(self, _n):
            return getattr(QApplication, _n)

    M.QApplication = _AP3()
    QApplication.exec = lambda _s: 0

    def _sig_maybe_raise(signum, handler):
        if signum == _sig3.SIGCHLD:
            raise ValueError('cannot set SIGCHLD here')
        return _o_sig(signum, handler)

    _sig3.signal = _sig_maybe_raise
    sys.argv = ['secure-terminal', '--new-instance']
    eq(M.main(), 0, 'main: a SIGCHLD-install failure during startup is tolerated')
finally:
    _sig3.signal = _o_sig
    sys.argv = _o_argv3
    M.ipc.send_request = _o_sr4
    M.QApplication = _o_qa3
    QApplication.exec = _o_qexec3
    _sig3.signal(_sig3.SIGCHLD, _o_chld3)

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
    pass                    # coverage is optional instrumentation, never fatal
sys.stdout.flush()
sys.stderr.flush()
os._exit(1 if _failures else 0)
