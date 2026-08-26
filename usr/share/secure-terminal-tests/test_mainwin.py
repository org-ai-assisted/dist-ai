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
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
# Pin the font DPI to 72 BEFORE any QApplication so font metrics are deterministic
# by default. The responsive-toolbar tier assertions below are calibrated to the
# real compositor's ~9pt metrics; bare offscreen defaults to a different DPI (a
# larger 12pt), which widens the toolbar tiers and breaks the 'labeled'-default
# calibration. The secure-terminal-tests / -coverage runners export this before
# python starts (the authoritative safe path); this setdefault is the fallback
# for a direct `python3 test_mainwin.py` run, and honours an explicit override
# (e.g. a real-compositor run) either way.
os.environ.setdefault('QT_FONT_DPI', '72')

try:
    from PyQt6.QtWidgets import QApplication, QDialog
    import secure_terminal.main as M
    from secure_terminal.main import MainWindow, _ctl_main
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

APP = QApplication.instance() or QApplication([])

# _require_default_font (main) aborts startup with exit 1 when the default font
# (Hack / fonts-hack, a hard dependency) is absent, so Qt cannot silently
# substitute a fallback that reintroduces confusable glyphs / ligatures. fonts-hack
# need not be installed in the test environment, so every full-startup test pins
# the check present via this fake QFontDatabase; the dedicated _require_default_font
# test drives both branches AND the real families() API (to catch an API break).
_REAL_QFONTDB = M.QFontDatabase


class _FontDBPresent:
    @staticmethod
    def families():
        return [M.DEFAULT_FONT_FAMILY, 'DejaVu Sans Mono']

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


def pump(ms=10):
    """Process pending Qt events, then briefly yield so a just-forked child can
    reach its chdir/exec before the next poll, without busy-spinning. Used by the
    cwd-restore poll below; reachable only when the child is not ready on the
    first try, so it must always be defined (not left to a startup-timing race)."""
    APP.processEvents()
    time.sleep(ms / 1000.0)
    APP.processEvents()


# The app icon is env-dependent: a desktop with an icon theme resolves one, but
# a bare CI container (no theme, no installed icon) yields a null QIcon, so the
# "icon present" branches in show_about() and main() would go uncovered there.
# Force a real icon so those branches run deterministically; the _app_icon tests
# below use the saved original to exercise the real (themed / null) resolution.
_REAL_APP_ICON = M._app_icon
M._app_icon = lambda: M._letter_icon('S', '#336699')

win = MainWindow()
win.new_tab()

# The shipped default theme is LIGHT (white bg): a window with no theme configured
# comes up light, and its tabs render on the light base.
eq(win._default_theme, 'light',
   'default theme is light when nothing is configured')
ok(win.current().current_theme() == 'light',
   'a tab of a freshly-defaulted window is light')
# escape_limit defaults to 4096 when nothing is configured (the freeze bound is on)
eq(win._escape_limit, 4096,
   'default escape_limit is 4096 when nothing is configured')
eq(win.current().current_escape_limit(), 4096,
   'a freshly-defaulted tab carries the 4096 escape-limit bound')

# --- window dialogs: built and shown with exec() stubbed ----------------------
from PyQt6.QtWidgets import QFormLayout as _QFL                 # noqa: E402


def _dlg_field(dlg, label_text):
    # the field widget on the form row whose label contains label_text (labels
    # carry an "(i)" HTML marker, so match by substring, not equality).
    for _form in dlg.findChildren(_QFL):
        for _r in range(_form.rowCount()):
            _l = _form.itemAt(_r, _QFL.ItemRole.LabelRole)
            _f = _form.itemAt(_r, _QFL.ItemRole.FieldRole)
            if _l and _f and _l.widget() is not None \
               and label_text in _l.widget().text():
                return _f.widget()
    return None


_orig_exec = QDialog.exec
_dialogs = []
QDialog.exec = lambda _self: (_dialogs.append(_self),
                              int(QDialog.DialogCode.Accepted))[1]
try:
    win.show_about()
    ok(True, 'show_about builds and shows')
    win.show_locations()
    ok(True, 'show_locations builds and shows the paths dialog')
    win.show_global_settings()
    ok(True, 'show_global_settings applies the chosen defaults on accept')
    # the paste-delay combo must SHOW the current value, even when it is not one of
    # the presets (config allows any 0-60); a blank selection was confusing.
    from PyQt6.QtWidgets import QComboBox as _QCbD              # noqa: E402
    win._paste_delay = 7
    _dialogs.clear()
    win.show_global_settings()
    _pd = [c for c in _dialogs[-1].findChildren(_QCbD) if c.findData(7) >= 0]
    ok(bool(_pd) and _pd[0].currentData() == 7 and _pd[0].currentText() == '7 seconds',
       'settings: a non-preset paste delay (7s) shows in the combo, not a blank')
    # likewise the escape-limit combo SHOWS a non-preset config value (any 0+ is
    # valid), not a blank selection.
    win._escape_limit = 12345
    _dialogs.clear()
    win.show_global_settings()
    _el = _dlg_field(_dialogs[-1], 'Suppressed-output notice')
    ok(_el is not None and _el.currentData() == 12345
       and _el.currentText() == 'After 12345 characters',
       'settings: a non-preset escape limit (12345) shows in the combo, not a blank')
    win._escape_limit = 4096
    # #79: every settings input has a tooltip; every tipped label shows the "(i)"
    # indicator so it is visible a (copyable) tooltip is available.
    from PyQt6.QtWidgets import (QCheckBox as _QCbx79, QSpinBox as _QSpn79,  # noqa: E402
                                 QLabel as _QLbl79)
    _sd79 = _dialogs[-1]
    _fields79 = _sd79.findChildren((_QCbD, _QCbx79, _QSpn79))
    ok(len(_fields79) >= 10 and all(f.toolTip() for f in _fields79),
       '#79: every settings input field has a tooltip')
    _lbls79 = [l for l in _sd79.findChildren(_QLbl79) if l.toolTip()]
    ok(len(_lbls79) >= 9 and all('(i)' in l.text() for l in _lbls79),
       '#79: every tipped settings label shows the (i) indicator')
    win._paste_delay = 3
    _dialogs.clear()
    # every dialog's descriptive text must be selectable so it can be copied
    from PyQt6.QtWidgets import QLabel as _QLabelD           # noqa: E402
    from PyQt6.QtCore import Qt as _QtD                      # noqa: E402
    _seld = _QtD.TextInteractionFlag.TextSelectableByMouse
    for _dlg in _dialogs:
        _dlabels = _dlg.findChildren(_QLabelD)
        ok(bool(_dlabels) and all(l.textInteractionFlags() & _seld
                                  for l in _dlabels),
           'dialog "%s" labels are all selectable/copyable' % _dlg.windowTitle())
    QDialog.exec = lambda _self: int(QDialog.DialogCode.Rejected)
    win.show_global_settings()
    ok(True, 'show_global_settings: cancel returns without applying')
    # #125: the settings dialog Ctrl+wheel live-zooms the chrome (UI) scale.
    from secure_terminal.main import _ZoomDialog as _ZD           # noqa: E402
    from PyQt6.QtGui import QWheelEvent as _QWE                   # noqa: E402
    from PyQt6.QtCore import QPointF as _QPF, QPoint as _QP       # noqa: E402
    _us0 = win._ui_scale
    QDialog.exec = lambda _self: (_dialogs.append(_self),
                                  int(QDialog.DialogCode.Accepted))[1]
    _dialogs.clear()
    win.show_global_settings()
    _zdlg = [d for d in _dialogs if isinstance(d, _ZD)][-1]
    _zdlg.on_zoom(1)                          # covers _live_zoom (step + live re-scale)
    ok(win._ui_scale >= _us0,
       'Ctrl+wheel up on the settings dialog raises the menu scale live')
    _zoomed = []
    _zdlg.on_zoom = lambda direction: _zoomed.append(direction)

    def _wheel(mod, dy):
        return _QWE(_QPF(1, 1), _QPF(1, 1), _QP(0, 0), _QP(0, dy),
                    _QtD.MouseButton.NoButton, mod,
                    _QtD.ScrollPhase.NoScrollPhase, False)
    _zdlg.wheelEvent(_wheel(_QtD.KeyboardModifier.ControlModifier, 120))
    _zdlg.wheelEvent(_wheel(_QtD.KeyboardModifier.NoModifier, 120))
    eq(_zoomed, [1],
       'Ctrl+wheel steps the zoom; a plain wheel scrolls without zooming')
    win._ui_scale = _us0
    # a locked ui_scale refuses the live Ctrl+wheel scale (else a locked chrome
    # size is changeable for the session, though _persist drops it from disk).
    _sl_uiz = set(win._locked)
    win._locked = {'ui_scale'}
    _us_lk = win._ui_scale
    _dialogs.clear()
    win.show_global_settings()
    _zlk = [d for d in _dialogs if isinstance(d, _ZD)][-1]
    _zlk.on_zoom(1)
    eq(win._ui_scale, _us_lk,
       'a locked ui_scale ignores the settings-dialog Ctrl+wheel live zoom')
    # a locked key disables its Global Settings control, so it cannot be edited
    # into a value _apply_global then silently discards. Every control asserted
    # here was ungated before the table-driven disable loop.
    win._locked = {'theme', 'scrollback', 'persist_session', 'unicode_mode',
                   M.OSC_FEATURES[0][0]}
    _dialogs.clear()
    win.show_global_settings()
    _gs = _dialogs[-1]
    # collect first so a not-found field fails the ok() gracefully rather than
    # raising AttributeError on None.isEnabled() (e.g. if a label is renamed).
    _locked_ctls = [_dlg_field(_gs, _lbl) for _lbl in
                    ('Theme', 'Scrollback', 'Restore session on start',
                     'Unicode', 'OSC ' + M.OSC_FEATURES[0][1])]
    ok(all(_c is not None and not _c.isEnabled() for _c in _locked_ctls),
       'a locked global-settings key disables its dialog control')
    win._locked = _sl_uiz
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
    # COR-7 client half: --lines 0 must be FORWARDED (0 is falsy, the base guard dropped it).
    _sent0 = {}
    def _cap_req(*_a, **_k):
        for _x in _a:
            if isinstance(_x, dict) and 'op' in _x:
                _sent0.clear()
                _sent0.update(_x)
        return {'ok': True, 'text': ''}
    M.ipc.send_request = _cap_req
    eq(_ctl_main(['dump-tab', '--tab', 'title:one', '--lines', '0']), 0,
       'ctl dump-tab --lines 0 -> 0')
    ok(_sent0.get('lines') == 0,
       'COR-7: the client forwards --lines 0 (not dropped as a falsy value)')
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
# a NON-POSITIVE timeout must be rejected: subprocess.run(timeout<=0) raises
# TimeoutExpired instantly, and with on_error=allow that fails OPEN (auto-approves
# every command while the UI shows the hook enabled). reviewdrain15.
eq(_read_hook_config({'command_hook': 'h', 'command_hook_timeout': '-1'})['timeout'],
   10, '_read_hook_config: a negative timeout is rejected (would fail OPEN)')
eq(_read_hook_config({'command_hook': 'h', 'command_hook_timeout': '0'})['timeout'],
   10, '_read_hook_config: a zero timeout is rejected (would fail OPEN)')
# an ABSURDLY large timeout (2**63) parses as a Python int but overflows subprocess's
# C PyTime_t with an uncaught OverflowError -- clamp it away. codex ai-review.
eq(_read_hook_config({'command_hook': 'h',
                      'command_hook_timeout': str(2 ** 63)})['timeout'],
   10, '_read_hook_config: an overflow-large timeout is rejected (would crash eval)')
# Locking command_hook must AUTO-LOCK its security-steering companions
# (command_hook_timeout / on_error / transcript), or a home config could set
# command_hook_timeout=-1 (fail-open) to defeat an admin-locked hook. reviewdrain15.
from secure_terminal import settings as _st_hook               # noqa: E402
_hooksys = tempfile.mkdtemp(prefix='st-hooklock-')
with open(os.path.join(_hooksys, '10-hook.conf'), 'w', encoding='utf-8') as _hf:
    _hf.write('command_hook=/usr/bin/judge\nlock=command_hook\n')
_orig_hooksys = _st_hook._system_dirs
_st_hook._system_dirs = lambda: [_hooksys]
try:
    _hcfg = _st_hook.load()
    for _ck in ('command_hook_timeout', 'command_hook_on_error',
                'command_hook_transcript'):
        ok(_ck in _hcfg.locked,
           'locking command_hook auto-locks its companion %s' % _ck)
    _st_hook._system_dirs = lambda: [tempfile.mkdtemp(prefix='st-nohooklock-')]
    ok('command_hook_timeout' not in _st_hook.load().locked,
       'without a command_hook lock, the companions stay user-settable')
finally:
    _st_hook._system_dirs = _orig_hooksys
# on_error default: an ADMIN-LOCKED (enforced) hook fails CLOSED by default, so
# locking the hook + auto-locking on_error can never DOWNGRADE it to fail-open (a
# user's block was discarded and defaulted to allow -- codex ai-review). An unlocked
# hook keeps the historical fail-open default; an explicit value always wins.
eq(_read_hook_config(_st_hook.Config({'command_hook': 'h'},
                                     locked=('command_hook',)))['on_error'],
   'block', '_read_hook_config: a LOCKED hook fails closed by default (no downgrade)')
eq(_read_hook_config(_st_hook.Config({'command_hook': 'h'}))['on_error'],
   'allow', '_read_hook_config: an unlocked hook keeps the fail-open default')
eq(_read_hook_config(_st_hook.Config({'command_hook': 'h', 'command_hook_on_error':
                                      'allow'}, locked=('command_hook',)))['on_error'],
   'allow', '_read_hook_config: an explicit admin on_error=allow still wins when locked')

# A modal must never be reachable in this user-less harness: QMessageBox.question
# BLOCKS in the event loop with nobody to answer, and the suite hangs forever
# (observed: 1h25m in poll, single-threaded, right here). close_tab asks it via
# _confirm_running_close whenever a tab reports a foreground program, which a
# freshly spawned shell can do transiently -- so the auto-answer must be armed
# before the first close_tab call in this module runs.
from PyQt6.QtWidgets import QMessageBox as _QMB_early           # noqa: E402

_QMB_early.question = staticmethod(
    lambda *_a, **_k: _QMB_early.StandardButton.Yes)

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

# F2: closing a tab that holds a paste/copy review hides the bar first, so its
# buttons cannot dispatch onto the destroyed terminal (RuntimeError).
_fw = MainWindow()
_fw.new_tab()
_ft = _fw.current()
_fw._review_bar.show_review(_ft, 'risky text', 0, 'paste')
ok(_fw._review_bar.reviewed_term() is _ft, 'F2: the review bar tracks the reviewed tab')
_fw.close_tab(_fw.tabs.indexOf(_ft))
ok(_fw._review_bar.reviewed_term() is None,
   'F2: closing the reviewed tab hides its review bar (no dangling terminal)')
_fw.deleteLater()

# --- confirm-close when a tab/window still runs a foreground program -----------
from PyQt6.QtGui import QCloseEvent                              # noqa: E402
_Yes, _No = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
# Default every confirm-on-close dialog to "Yes" (quit) so incidental window
# closes in this user-less harness never block on the modal. A `-- PROGRAM` tab
# now counts as a running program, so closing any window that holds one pops the
# confirm dialog; a window closed OUTSIDE an explicit confirm-close test below
# would otherwise hang. The explicit tests set their own mock and restore to THIS
# default (captured as _oq), not the real modal, so the guarantee survives them.
QMessageBox.question = staticmethod(lambda *_a, **_k: _Yes)
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
    # _force_close (a signal-driven / programmatic quit) accepts the close even
    # with a program running, WITHOUT opening the modal: the confirmation needs a
    # user, and a modal run during XCB teardown segfaults. The mock would decline
    # if asked, so an accepted close proves the prompt was skipped. This checks the
    # guard decision only -- tab shutdown is stubbed so the real SIGHUP/SIGCHLD
    # teardown (exercised in the aboutToQuit test) does not fire mid-suite and feed
    # the known offscreen ipc-reaper race.
    w3._persist_session = False              # clear, don't write a bogus session
    for _i in range(w3.tabs.count()):
        w3.tabs.widget(_i).has_foreground_program = lambda: True
        w3.tabs.widget(_i).shutdown = lambda: None
    w3._force_close = True
    _asked.clear()
    QMessageBox.question = staticmethod(lambda *_a, **_k: _asked.append(1) or _No)
    _ev_fc = QCloseEvent()
    _ev_fc.ignore()                          # start REJECTED so only an explicit accept passes
    w3.closeEvent(_ev_fc)
    ok(_ev_fc.isAccepted() and not _asked,
       'closeEvent: _force_close accepts the close without prompting')
    w3._force_close = False
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

# --- open_transcript: writes the transcript under the XDG state dir + opens it -----------
# (NOT /tmp: the shipped AppArmor profile allows ~/.local/state/secure-terminal/** but not
# /tmp; a fixed reused file so history does not accumulate.)
from PyQt6.QtGui import QDesktopServices as _QDS         # noqa: E402
import secure_terminal.session as _sess                  # noqa: E402
_oou = _QDS.openUrl
_osd = _sess._state_dir
_opened = []
_state_tmp = tempfile.mkdtemp(prefix='st-transcript-state-')
try:
    _QDS.openUrl = staticmethod(lambda url: _opened.append(url.toLocalFile()) or True)
    _sess._state_dir = lambda: _state_tmp
    _ocur = win.current
    win.current = lambda: None                  # no active tab -> no-op
    win.open_transcript()
    ok(_opened == [], 'open_transcript: no active tab is a no-op')
    win.current = _ocur
    win.open_transcript()
    ok(len(_opened) == 1 and os.path.dirname(_opened[0]) == _state_tmp
       and os.path.basename(_opened[0]) == 'transcript.txt'
       and os.path.getsize(_opened[0]) > 0,
       'open_transcript: writes transcript.txt under the state dir and opens it')
    win.open_transcript()                        # a second open REUSES the one file (no leak)
    ok(len(_opened) == 2 and _opened[0] == _opened[1],
       'open_transcript: reuses one file rather than leaking a new temp each time')
finally:
    _QDS.openUrl = _oou
    _sess._state_dir = _osd

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

# line editing: the live per-tab setter pushes into the current tab, flips the menu
# action and updates the default used for new tabs.
win.set_line_edits(False)
eq(win.current().line_edits_enabled(), False,
   'set_line_edits(False) reaches the current tab')
ok(not win.act_line_edits.isChecked(), 'set_line_edits syncs the menu action')
eq(win._default_line_edits, False, 'set_line_edits updates the new-tab default')
win.set_line_edits(True)
eq(win.current().line_edits_enabled(), True, 'set_line_edits(True) restores it')

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
    win._locked = {'copy_warn'}
    win.set_copy_warn('always')             # locked -> early return
    win._locked = {'line_edits'}
    win.set_line_edits(False)               # locked -> early return
    eq(win._default_line_edits, True,
       'a locked line_edits cannot be turned off by the user')
    ok(True, 'setting appliers respect an admin lock (no change)')
    # a locked paste_warn / copy_warn is greyed out in the menu, not silently
    # clickable-but-ignored.
    win._locked = {'copy_warn', 'paste_warn'}
    win._apply_locks()
    ok(all(not a.isEnabled() for a in win._copy_warn_actions.values())
       and all(not a.isEnabled() for a in win._paste_warn_actions.values()),
       'a locked paste_warn / copy_warn greys out its menu actions')
    # a locked zoom greys its View-menu actions too (its setter already refuses,
    # so an enabled-but-no-op click would only mislead), matching the zoom_box.
    win._locked = {'zoom'}
    win._apply_locks()
    ok(not win.act_zin.isEnabled() and not win.act_zout.isEnabled()
       and not win.act_zreset.isEnabled(),
       'a locked zoom greys out its View-menu Zoom In/Out/Reset actions')
    # a locked font_family greys the View > Font action: its setter (set_font_family)
    # refuses a locked change, so an enabled trigger would open the picker and then
    # silently discard the pick -- a UI that lies. Same class as the greyed zoom
    # triggers. Fails on the pre-fix _apply_locks (act_font was never gated).
    win._locked = {'font_family'}
    win._apply_locks()
    ok(not win.act_font.isEnabled(),
       'a locked font_family greys out the View > Font action')
    # a locked osc_notice_off greys the per-TYPE notice toggles: set_osc_notice_type
    # refuses a locked change, so an enabled tick would never apply -- a UI that lies.
    # Fails on the pre-fix _apply_locks (the per-type actions were never gated).
    win._locked = {'osc_notice_off'}
    win._apply_locks()
    ok(win._osc_notice_actions
       and all(not a.isEnabled() for a in win._osc_notice_actions.values()),
       'a locked osc_notice_off greys out the per-type OSC-notice toggles')
finally:
    win._locked = _saved_locked
    win._bell_sound_locked = _saved_bsl
    for _a in (list(win._copy_warn_actions.values())
               + list(win._paste_warn_actions.values())
               + list(win._osc_notice_actions.values())
               + [win.act_zin, win.act_zout, win.act_zreset, win.act_font]):
        _a.setEnabled(True)             # undo the lock disable for later tests

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

# pwd-as-tab-title (#90): with no explicit name and no program title, the tab
# label is the working-directory basename (kept live by the fg poll), not a static
# "shell". A set name or program title still wins; an unreadable cwd -> "shell".
_pw = win.current()
_pw_cwd = _pw.cwd_basename
_pw.cwd_basename = lambda: 'myproj'
win._user_titles.pop(_pw, None)
win._prog_titles.pop(_pw, None)
win._refresh_tab_label(_pw)
eq(win.tabs.tabText(win.tabs.indexOf(_pw)), 'myproj',
   '#90: no explicit title -> the tab shows the pwd basename')
win._user_titles[_pw] = 'Named'
win._refresh_tab_label(_pw)
eq(win.tabs.tabText(win.tabs.indexOf(_pw)), 'Named',
   '#90: an explicit tab name overrides the pwd basename')
win._user_titles.pop(_pw, None)
_pw.cwd_basename = lambda: None
win._refresh_tab_label(_pw)
eq(win.tabs.tabText(win.tabs.indexOf(_pw)), 'shell',
   '#90: an unreadable cwd falls back to "shell"')
_pw.cwd_basename = _pw_cwd
# the tab tooltip escapes an untrusted program title: setTabToolTip renders rich text
# (unlike setTabText), so an OSC-set title with markup must be shown literally -- the same
# class as the command-hook PlainText gate. Pre-fix the raw '<b>' reached the tooltip.
win._user_titles.pop(_pw, None)
win._prog_titles[_pw] = '<b>owned</b>'
win._refresh_tab_label(_pw)
_tip = win.tabs.tabToolTip(win.tabs.indexOf(_pw))
ok('<b>' not in _tip and '&lt;b&gt;owned&lt;/b&gt;' in _tip,
   'tab tooltip escapes an untrusted program title (no raw markup)')
win._prog_titles.pop(_pw, None)
win._refresh_tab_label(_pw)

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
    # SEC-3: a user/IPC-set title bypasses the program-title sanitizer, so the write site
    # must strip bidi/homoglyph -- else an RLO override spoofs the tab label, the bell
    # notification and the OSC-52 consent dialog, which all read _user_titles.
    ok(_disp({'op': 'ctl-set-tab-title', 'tab': 'id:%d' % _tid0,
              'title': 'a\u202eb'})['ok'], 'ipc: ctl-set-tab-title with a bidi title accepted')
    ok('\u202e' not in win._user_titles.get(_tab0, ''),
       'SEC-3: a ctl-set-tab-title bidi/RLO override is sanitized out at the write site')
    ok(not _disp({'op': 'ctl-set-tab-title', 'tab': 'id:%d' % _tid0,
                  'title': 5})['ok'],
       'ipc: ctl-set-tab-title with a non-string title is rejected')
finally:
    win._remote_control = _saved_rc

# open (the server side of a --reuse handoff)
ok(win._ipc_open({'tabs': [{'title': 'opened', 'mode': 'box'}]})['ok'],
   'ipc: open creates the requested tabs')
# --reuse always asks for a new tab, so a bare reuse (no specs) opens a fresh
# default tab -- it never leaves the running instance unchanged (the old
# behaviour, which only added a tab when the window had none, was the bug: a
# bare relaunch did nothing). Assert the tab count actually grew.
_before_bare = win.tabs.count()
win._ipc_open({'tabs': 'not-a-list'})       # opened 0 -> a new default tab
ok(win.tabs.count() == _before_bare + 1,
   'ipc: a bare reuse opens a NEW default tab (count grows by one)')

# open: cap the tab count per frame. ~58k tiny specs fit in the 1 MiB IPC frame and
# would exhaust fds/memory, so a frame past the cap is refused whole. The gate is on
# the list LENGTH, so the spec contents are irrelevant (None keeps the check cheap).
_before_cap = win.tabs.count()
_rcap = win._ipc_open({'tabs': [None] * (_MM._MAX_OPEN_TABS + 1)})
ok(not _rcap['ok'] and 'too many' in _rcap['error'],
   'ipc: an over-cap open frame is refused, not opened')
ok(win.tabs.count() == _before_cap,
   'ipc: a refused over-cap frame opens no tabs')

# open --if-absent: idempotent open that dedups by COMMAND (what open-all relies
# on). _normalize_command: a -e STRING and its shell-split argv are equal; None (a
# plain shell tab) is never a dedup key.
_nc = MainWindow._normalize_command
ok(_nc('echo a b') == ('echo', 'a', 'b') == _nc(['echo', 'a', 'b']),
   'if_absent: a -e string and its argv normalize equal')
ok(_nc(None) is None and _nc('') == (),
   'if_absent: None (a shell) is never a dedup key')
ok(_nc('"unbalanced') == ('"unbalanced',),
   'if_absent: a command that will not shell-split falls back to the raw string')
# a command LIST with an unhashable element must not crash the dedup: elements are
# str()-coerced so the key is always hashable (an IPC payload can carry such a list).
ok(_nc(['echo', ['nested']]) == ('echo', "['nested']"),
   'if_absent: list command elements are str()-coerced to a hashable key')
try:
    _ru = win._ipc_open({'tabs': [{'command': ['echo', ['nested']]}], 'if_absent': True})
    ok(_ru['opened'] == 1,
       'if_absent: an unhashable command element does not crash _ipc_open')
except TypeError:
    ok(False, 'if_absent: an unhashable command element crashed _ipc_open (TypeError)')
# seed a live tab's command; an if_absent open of the SAME command is skipped and
# adds no tab (nor a bare default tab) -- fully idempotent.
_tab0.launch_command = _nc('seeded-if-absent-canary --flag')
_before_if = win.tabs.count()
_rs = win._ipc_open({'tabs': [{'command': 'seeded-if-absent-canary --flag'}],
                     'if_absent': True})
ok(_rs['opened'] == 0 and _rs['skipped'] == 1,
   'if_absent: a command already running in a tab is skipped')
ok(win.tabs.count() == _before_if,
   'if_absent: a fully-skipped open adds no tab (idempotent, no default tab)')
# the argv form of the seeded string command matches too
_ra = win._ipc_open({'tabs': [{'command': ['seeded-if-absent-canary', '--flag']}],
                     'if_absent': True})
ok(_ra['skipped'] == 1, 'if_absent: matches the argv form against the seeded string')
# a stale _tab_ids entry no longer in the bar is ignored by _live_commands (it does
# not crash the scan nor mask the real match).
from PyQt6.QtWidgets import QWidget                             # noqa: E402
_orphan = QWidget()
win._tab_ids[_orphan] = 999999
try:
    _ro = win._ipc_open({'tabs': [{'command': 'seeded-if-absent-canary --flag'}],
                         'if_absent': True})
    ok(_ro['skipped'] == 1,
       'if_absent: a _tab_ids entry not in the bar is skipped by _live_commands')
finally:
    del win._tab_ids[_orphan]
# a non-dict tab spec is skipped; a valid spec in the same batch still opens.
_before_nd = win.tabs.count()
win._ipc_open({'tabs': [42, {'title': 'nd'}]})
ok(win.tabs.count() == _before_nd + 1,
   'ipc: a non-dict tab spec is skipped, the valid one still opens')
# two specs sharing a NEW command in one batch: the first opens (dedup set grows),
# the duplicate second is skipped -- intra-batch idempotency.
_rb = win._ipc_open({'tabs': [{'command': ['cat']}, {'command': 'cat'}],
                     'if_absent': True})
ok(_rb['opened'] == 1 and _rb['skipped'] == 1,
   'if_absent: a command repeated within one batch opens once, skips the rest')
# without if_absent the same command opens a duplicate (default behaviour intact)
_before_dup = win.tabs.count()
win._ipc_open({'tabs': [{'command': 'seeded-if-absent-canary --flag'}]})
ok(win.tabs.count() == _before_dup + 1,
   'if_absent off: a duplicate command still opens (unchanged default)')

# _restore_tab: rebuild a tab from saved session state (bad ints fall back)
win._restore_tab({'text': 'hi', 'theme': 'dark', 'zoom': 'notanint',
                  'scrollback': 'nope', 'mode': 'box', 'osc': {},
                  'font_family': 123, 'font_size': 'invalid'})
_bad_tab = win.current()
win._restore_tab({'allow_title': True, 'bell': 'audible'})   # legacy pre-OSC path
ok(True, '_restore_tab rebuilds a tab and tolerates bad zoom/scrollback values')
# a TAMPERED boolean flag (a JSON string/number, not a real bool) must NOT coerce
# truthy via bool() and fail OPEN -- it falls back to the default (#5). "false" is a
# non-empty string (bool("false") is True), the classic fail-open value.
win._restore_tab({'tui': 'false'})
ok(win.current().tui_active() is False,
   'a non-bool saved flag falls back to the default, not bool()-coerced True (#5)')
# a corrupt/hand-edited session with a non-str font_family or non-int font_size must
# fall back to the default, not crash the restore (.strip() / int() on a bad type).
eq(_bad_tab.current_font_family(), win._default_font_family,
   '_restore_tab falls back to the default font family on a non-string saved value')
eq(_bad_tab.current_font_size(), win._default_font_size,
   '_restore_tab falls back to the default font size on a non-int saved value')
# an unhashable saved theme (a JSON array/object) must not crash the membership test
# (THEMES is a dict); it falls back to the default theme.
win._restore_tab({'text': '', 'theme': [], 'osc': {}})
eq(win.current().current_theme(), win._default_theme,
   '_restore_tab falls back to the default theme on an unhashable saved value')

# a restored tab spawns its shell in the SAVED cwd (bug: pwd was not restored)
_rcwd = tempfile.mkdtemp(prefix='st-restore-cwd-')
win._restore_tab({'text': '', 'cwd': _rcwd, 'osc': {}})
_rterm = win.current()
_rok = False
for _ in range(60):
    try:
        if os.path.realpath(os.readlink('/proc/%d/cwd' % _rterm._pid)) \
                == os.path.realpath(_rcwd):
            _rok = True
            break
    except OSError:
        ## /proc/<pid>/cwd is not readable until the forked child has chdir'd
        ## and exec'd; poll on, the loop's own tries budget is the timeout.
        pass
    pump(10)
ok(_rok, '_restore_tab spawns the restored tab in its saved cwd')
# a vanished saved cwd still restores (falls back, no crash)
win._restore_tab({'text': '', 'cwd': '/no/such/dir/for/restore', 'osc': {}})
ok(win.current()._pid is not None,
   '_restore_tab with a vanished saved cwd still spawns a shell')

# session restore honours admin locks: a session saved BEFORE a lock was applied
# must not reopen bypassing it. _restore_tab applied the saved per-tab settings
# (mode/tui/colors/line_edits/markings/zoom/theme/scrollback/font) without the
# _locked check it applies to OSC/bell, so a pre-lock session could reload an
# admin-locked terminal in the wrong state. Locked -> the admin DEFAULT wins over
# the saved value; unlocked -> the saved value is still restored. (ai-review)
_rl_saved = set(win._locked)
try:
    _rl_other_mode = next(_m for _m in _MM.DISPLAY_MODES if _m != win._default_mode)
    _rl_info = {
        'text': '', 'osc': {},
        'mode': _rl_other_mode,
        'tui': not win._default_tui,
        'colors': not win._default_colors,
        'line_edits': not win._default_line_edits,
        'markings': not win._default_markings,
        'theme': 'light' if win._default_theme == 'dark' else 'dark',
        'zoom': win._default_zoom + 40,
        'scrollback': win._scrollback + 500,
        'font_family': win._default_font_family,
        'font_size': win._default_font_size + 3,
    }
    win._locked = {'unicode_mode', 'tui', 'colors', 'line_edits',
                   'colored_markings', 'theme', 'zoom', 'scrollback',
                   'font_family', 'font_size'}
    win._restore_tab(_rl_info, activate=True)
    _rt = win.current()
    eq(_rt.current_mode(), win._default_mode, 'restore honours a locked unicode_mode')
    eq(_rt.current_tui(), win._default_tui, 'restore honours a locked tui')
    eq(_rt.colors_enabled(), win._default_colors, 'restore honours a locked colors')
    eq(_rt.line_edits_enabled(), win._default_line_edits,
       'restore honours a locked line_edits')
    eq(_rt.markings_enabled(), win._default_markings,
       'restore honours a locked colored_markings')
    eq(_rt.current_theme(), win._default_theme, 'restore honours a locked theme')
    eq(_rt.current_zoom(), win._default_zoom, 'restore honours a locked zoom')
    eq(_rt.current_scrollback(), win._scrollback, 'restore honours a locked scrollback')
    eq(_rt.current_font_size(), win._default_font_size,
       'restore honours a locked font_size')
    # nothing locked: the saved values are restored, not clobbered by the default
    win._locked = set()
    win._restore_tab(_rl_info, activate=True)
    _ru = win.current()
    eq(_ru.current_mode(), _rl_other_mode, 'restore keeps a saved mode when unlocked')
    eq(_ru.current_scrollback(), win._scrollback + 500,
       'restore keeps a saved scrollback when unlocked')
    eq(_ru.current_zoom(), win._default_zoom + 40,
       'restore keeps a saved zoom when unlocked')
finally:
    win._locked = _rl_saved

# session restore honours a locked allow_title in the LEGACY branch too: a session
# saved before the granular OSC controls carries a bare 'allow_title' bool and NO
# 'osc' key, so _restore_tab takes its legacy branch. That branch applied the saved
# value UNCONDITIONALLY, ignoring the lock the granular branch honours -> a pre-lock
# legacy session could re-enable an admin-locked title/notify capability on restart.
# Locked -> the admin default wins over the saved bool; unlocked -> the saved value
# is restored. Fails on the pre-fix legacy branch (which applied the saved True). (ai-review)
_al_saved_locked = set(win._locked)
_al_saved_default = win._default_allow_title
_al_saved_osc = dict(win._osc_defaults)
try:
    # 1. allow_title locked -> title + notify both forced to the admin default
    win._default_allow_title = False
    win._osc_defaults['osc_title'] = False
    win._osc_defaults['osc_notify'] = False
    win._locked = {'allow_title'}
    win._restore_tab({'text': '', 'allow_title': True}, activate=True)   # legacy, no 'osc'
    ok(not win.current().allow_title_enabled(),
       'legacy restore honours a locked allow_title (admin default wins over the saved bool)')
    # 2. nothing locked -> the saved legacy value is restored
    win._locked = set()
    win._restore_tab({'text': '', 'allow_title': True}, activate=True)   # legacy, no 'osc'
    ok(win.current().allow_title_enabled(),
       'legacy restore keeps the saved allow_title when unlocked')
    # 3. a GRANULAR lock on osc_title alone (allow_title NOT locked) must win in the
    # legacy branch too: osc_title holds the admin default, osc_notify keeps the saved
    # bool. Fails on a fix that only checked 'allow_title' in _locked.
    win._osc_defaults['osc_title'] = False
    win._locked = {'osc_title'}
    win._restore_tab({'text': '', 'allow_title': True}, activate=True)   # legacy, no 'osc'
    _rt = win.current()
    ok(not _rt.osc_enabled('osc_title'),
       'legacy restore honours a granular osc_title lock (default wins over the legacy bool)')
    ok(_rt.osc_enabled('osc_notify'),
       'legacy restore keeps the saved value for the unlocked osc_notify')
finally:
    win._locked = _al_saved_locked
    win._default_allow_title = _al_saved_default
    win._osc_defaults = _al_saved_osc

# a NEW tab opens in the ACTIVE tab's current working directory (like konsole), not the
# app's launch dir. Restore a tab into a known cwd, wait for its shell to land there, then
# open a new tab and confirm it spawned in that same dir (bug: new tabs used the launch dir).
_ncwd = tempfile.mkdtemp(prefix='st-newtab-cwd-')
win._restore_tab({'text': '', 'cwd': _ncwd, 'osc': {}})
_nactive = win.current()
for _ in range(60):
    if (_nactive.shell_cwd()
            and os.path.realpath(_nactive.shell_cwd()) == os.path.realpath(_ncwd)):
        break
    pump(10)
win.new_tab()
_nnew = win.current()
_ncwd_ok = False
for _ in range(60):
    try:
        if os.path.realpath(os.readlink('/proc/%d/cwd' % _nnew._pid)) \
                == os.path.realpath(_ncwd):
            _ncwd_ok = True
            break
    except OSError:
        ## /proc/<pid>/cwd unreadable until the forked child has chdir'd + exec'd.
        pass
    pump(10)
ok(_ncwd_ok, 'a new tab opens in the ACTIVE tab current working directory')

# set_tui refuses + reverts the toggle when a program is running (the shell's
# terminfo cannot be re-exported under a running program) -- #63.
_stt = win.current()
_stt_fg = _stt.has_foreground_program
_stt.has_foreground_program = lambda: True
_stt_before = win.act_tui.isChecked()
win.set_tui(not _stt_before)
ok(win.act_tui.isChecked() == _stt.current_tui(),
   'set_tui reverts the toggle to the actual mode when a program is running')
_stt.has_foreground_program = _stt_fg

# P2 (ai-review): a refused switch must NOT clobber the global default. The revert
# setChecked would re-enter set_tui(actual) and persist it as _default_tui; blocked
# signals stop that. Set the default DIFFERENT from the tab's mode to catch it.
_stt._tui = False                              # this tab is CLI
_saved_def = win._default_tui
win._default_tui = True                        # global default differs from the tab
win.act_tui.blockSignals(True)
win.act_tui.setChecked(True)                   # as if the user toggled TUI on
win.act_tui.blockSignals(False)
_stt.has_foreground_program = lambda: True      # a program blocks the switch
win.set_tui(True)                              # refused -> revert must not re-enter
eq(win._default_tui, True,
   'set_tui: a refused switch does not clobber the global TUI default (P2)')
ok(not win.act_tui.isChecked(), 'the refused toggle reverted to the tab mode (CLI)')
_stt.has_foreground_program = _stt_fg
win._default_tui = _saved_def

# bind the single-instance listening socket (isolated runtime dir)
win.start_instance_server('coverage-group')
ok(True, 'start_instance_server binds a listening socket')

# --- main(): the entry point, driven with QApplication + exec + ipc mocked ----
import signal as _signal                             # noqa: E402
from secure_terminal.main import main as _main       # noqa: E402
from PyQt6.QtWidgets import QApplication as _QA       # noqa: E402

import io as _io                                       # noqa: E402
import contextlib as _ctx                              # noqa: E402

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
    # --reuse: hand off to the running primary -> exit 0 without starting Qt.
    # (Reuse is the ONLY path that hands off now; a bare launch always builds its
    # own window -- see the new-window test below and the no-handoff regression.)
    M.ipc.send_request = lambda *_a, **_k: {'ok': True}
    sys.argv = ['secure-terminal', '--reuse', '--title', 'x']
    eq(_main(), 0, 'main: --reuse hands off to an existing instance -> 0')
    # the primary refusing the handoff -> exit 1
    M.ipc.send_request = lambda *_a, **_k: {'ok': False, 'error': 'refused'}
    eq(_main(), 1, 'main: --reuse to an instance that refuses -> 1')
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

    # Pin the default-font check present (see _FontDBPresent) so the startup tests
    # here do not depend on fonts-hack being installed.
    M.QFontDatabase = _FontDBPresent
    sys.argv = ['secure-terminal', '--title', 'fresh']
    eq(_main(), 0, 'main: with no running instance it starts the app + event loop')

    # REGRESSION (the core bug): a bare launch (no --reuse) must NEVER hand off to
    # a running instance -- it builds its OWN window. Record every request main()
    # sends and assert no 'open' handoff is issued without --reuse, but IS issued
    # with it. send_request returns a reply so that a mistaken handoff would
    # short-circuit before Qt -- making a regression observable as a wrong result
    # rather than a hang.
    _seen_ops = []

    def _rec(_group, req, *_a, **_k):
        _seen_ops.append(req.get('op'))
        return {'ok': True} if req.get('op') == 'open' else None

    M.ipc.send_request = _rec
    _seen_ops.clear()
    sys.argv = ['secure-terminal', '--title', 'bare']
    eq(_main(), 0, 'main: a bare launch builds its own window')
    ok('open' not in _seen_ops,
       'main: a bare launch sends NO open handoff (new independent window)')
    _seen_ops.clear()
    sys.argv = ['secure-terminal', '--reuse', '--title', 'joined']
    eq(_main(), 0, 'main: --reuse issues the open handoff and exits')
    ok('open' in _seen_ops,
       'main: --reuse DOES send an open handoff to the primary')
    M.ipc.send_request = lambda *_a, **_k: None

    # _require_default_font: the Hack font (fonts-hack) is a hard dependency. Qt
    # would SILENTLY substitute a fallback that may reintroduce the confusable
    # glyphs / ligatures Hack is chosen to avoid, so a missing default font fails
    # loud like a missing Python dependency (preflight.require) -- main() aborts
    # with exit 1 before building a window. Drive both branches via the module's
    # QFontDatabase alias (present is pinned above for the other startup tests).
    class _FontDBAbsent:
        @staticmethod
        def families():
            return ['DejaVu Sans Mono', 'monospace']

    ok(M._require_default_font() is True,
       'font: _require_default_font True when the default family is installed')
    M.QFontDatabase = _FontDBAbsent
    _err = _io.StringIO()
    with _ctx.redirect_stderr(_err):
        ok(M._require_default_font() is False,
           'font: _require_default_font False when the default family is missing')
    ok('fonts-hack' in _err.getvalue(),
       'font: the missing-font message names the fonts-hack package')
    # Drive the REAL QFontDatabase.families() path so an API break (as hasFamily
    # was removed in Qt6) is caught here, without assuming Hack is installed.
    M.QFontDatabase = _REAL_QFONTDB
    with _ctx.redirect_stderr(_io.StringIO()):
        ok(isinstance(M._require_default_font(), bool),
           'font: _require_default_font uses a live QFontDatabase API (returns bool)')
    M.QFontDatabase = _FontDBPresent    # restore present for the shot test below
    # NOTE: the exit-1 wiring (main() -> `return 1`) is asserted in the block below,
    # AFTER the threaded single-instance handoff test -- an extra main() call BEFORE
    # that delicate block destabilizes it into an intermittent segfault.

    # SECURE_TERMINAL_SHOT=1 (#51 deterministic screenshot mode): main() stops the
    # app-wide caret blink so no captured frame depends on the caret phase. Drive the
    # full startup with the env set and confirm _shot_mode() takes the shot branch
    # (setCursorFlashTime(0)); with the env unset it is a no-op (covered above).
    ok(M._shot_mode() is False, 'shot: _shot_mode() is False when the env is unset')
    os.environ['SECURE_TERMINAL_SHOT'] = '1'
    _o_flash = APP.cursorFlashTime()
    try:
        ok(M._shot_mode() is True, 'shot: SECURE_TERMINAL_SHOT=1 -> _shot_mode() True')
        sys.argv = ['secure-terminal', '--title', 'shot']
        eq(_main(), 0, 'shot: main() starts with SECURE_TERMINAL_SHOT=1')
        eq(APP.cursorFlashTime(), 0, 'shot: main() stops the caret blink (flash time 0)')
    finally:
        del os.environ['SECURE_TERMINAL_SHOT']
        APP.setCursorFlashTime(_o_flash)

    # --clipboard-watch: the tray-only clipboard sanitizer, dispatched early in
    # main() (opening no terminal window). With no system tray (offscreen) its
    # run() returns 1; this covers the dispatch branch and _clipboard_watch_main.
    # Placed AFTER the delicate threaded-handoff + shot tests so it cannot perturb
    # them (see the note above).
    _o_qlwc = APP.quitOnLastWindowClosed()
    sys.argv = ['secure-terminal', '--clipboard-watch']
    eq(_main(), 1, 'main: --clipboard-watch runs the tray sanitizer (no tray -> 1)')
    APP.setQuitOnLastWindowClosed(_o_qlwc)
    # its own font-missing abort (like the normal path, it fails loud before Qt work)
    M.QFontDatabase = _FontDBAbsent
    with _ctx.redirect_stderr(_io.StringIO()):
        eq(_main(), 1,
           'main: --clipboard-watch aborts (exit 1) when the default font is missing')
    M.QFontDatabase = _FontDBPresent
finally:
    sys.argv = _o_argv
    M.ipc.send_request = _o_sr
    M.QApplication = _o_qa
    _QA.exec = _o_qexec
    M.QFontDatabase = _REAL_QFONTDB
    _signal.signal(_signal.SIGCHLD, _o_chld)

# --- launch parsing: the instance dispositions are mutually exclusive ----------
# --reuse (join the primary) and --new-instance (standalone, never the primary)
# directly contradict; --window is the explicit default. The parser must reject
# any two together (argparse SystemExit) and parse each alone.
_pla = M._parse_launch_args
ok(_pla(['--reuse']).reuse is True and _pla(['--reuse']).new_instance is False,
   'parse: --reuse alone -> reuse')
ok(_pla(['--window']).reuse is False and _pla(['--window']).new_instance is False,
   'parse: --window alone -> new independent window (the default)')
ok(_pla(['--new-instance']).new_instance is True and _pla(['--new-instance']).reuse is False,
   'parse: --new-instance alone -> standalone')
for _combo in (['--reuse', '--new-instance'], ['--window', '--new-instance'],
               ['--reuse', '--window']):
    _rej = False
    try:
        _pla(_combo)
    except SystemExit:
        _rej = True
    ok(_rej, 'parse: %s is rejected (mutually exclusive dispositions)' % ' '.join(_combo))

# --if-absent (idempotent reuse) parses and flows into the open request.
ok(_pla(['--if-absent']).if_absent is True, 'parse: --if-absent -> if_absent')
ok(_pla([]).if_absent is False, 'parse: if_absent defaults off')
_lreq = M._launch_to_request(_pla(['--if-absent', '--title', 't', '--', 'cmd']))
ok(_lreq['op'] == 'open' and _lreq.get('if_absent') is True,
   'launch->request: if_absent flows into the open request')
ok(M._launch_to_request(_pla([])).get('if_absent') is False,
   'launch->request: if_absent defaults off in the request')

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
    win._locked = {'tui_autobox_notice'}
    win.set_tui_autobox_notice(False)       # admin-locked -> refused
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
               'escape-limit 65536', 'pastedelay 4', 'totally-unknown', '/'):
        win.run_command('/' + _c)
    eq(win.run_command(''), False, 'run_command: an empty line -> False')
    ok(True, 'run_command handles every slash-command branch')

    # CLASH: the palette's help text vs what the palette actually dispatches.
    # Driving every branch (above) proves only that nothing raises -- it cannot
    # notice a command the help omits, which is how `/mode detail` went
    # undocumented while being the DEFAULT mode everywhere else.
    import ast as _ast
    import inspect as _inspect
    import re as _re

    from secure_terminal import sanitize as _san

    _help_cmds = set(_re.findall(r'/([a-z][a-z-]*)', MainWindow._COMMAND_HELP))
    # The dispatched names: every string literal compared against `cmd` in
    # run_command, derived from the source so a new branch cannot hide.
    _src = _inspect.getsource(MainWindow.run_command)
    _tree = _ast.parse(_src.lstrip())
    _dispatched = set()
    for _node in _ast.walk(_tree):
        if not isinstance(_node, _ast.Compare):
            continue
        if not (isinstance(_node.left, _ast.Name) and _node.left.id == 'cmd'):
            continue
        for _cmp in _node.comparators:
            if isinstance(_cmp, _ast.Constant) and isinstance(_cmp.value, str):
                _dispatched.add(_cmp.value)
            elif isinstance(_cmp, (_ast.Tuple, _ast.List, _ast.Set)):
                for _elt in _cmp.elts:
                    if isinstance(_elt, _ast.Constant) and isinstance(_elt.value, str):
                        _dispatched.add(_elt.value)
    ok(len(_dispatched) >= 8,
       'the run_command dispatch list was extracted (%d names)' % len(_dispatched))
    # An undocumented alias is the finding; `help` is documented and dispatched.
    eq(sorted(_dispatched - _help_cmds), [],
       'every dispatched slash command appears in the palette help')
    eq(sorted(_help_cmds - _dispatched), [],
       'every command in the palette help is actually dispatched')

    # ...and the /mode alternatives must be the real mode list, not a subset.
    _mode_line = [ln for ln in MainWindow._COMMAND_HELP.split('\n')
                  if ln.strip().startswith('/mode')]
    eq(len(_mode_line), 1, 'the palette help documents /mode exactly once')
    eq(sorted(_mode_line[0].split(None, 1)[1].split('|')), sorted(_san.DISPLAY_MODES),
       'the /mode alternatives in the help equal sanitize.DISPLAY_MODES')
finally:
    win._locked = _sl
    QMessageBox.information = _o_info
    QMessageBox.warning = _o_warn

# --- clipboard-sanitizer controls (menu / setters / systray coupling) ----------
from secure_terminal import clipboard_watch as _cw                # noqa: E402
from PyQt6.QtCore import QMimeData, QProcess                       # noqa: E402
from PyQt6.QtWidgets import QMenu                                  # noqa: E402

_cw_saved = (_cw.is_running, _cw.stop_running, _cw.push_warn_any,
             _cw.set_autostart, _cw.autostart_enabled)
_o_startdet = QProcess.startDetached
_o_avail_c = QSystemTrayIcon.isSystemTrayAvailable
_o_systray_c = win._systray
_o_warnany_c = win._clip_warn_any
## Save the process clipboard (every MIME format) and restore it in finally:
## the test overwrites it, and a bare clear() would discard a developer's real
## clipboard on a live (non-offscreen) desktop session.
_o_clip_c = QMimeData()
_src_clip_c = APP.clipboard().mimeData()   # None under the offscreen platform
if _src_clip_c is not None:
    for _clip_fmt_c in _src_clip_c.formats():
        _o_clip_c.setData(_clip_fmt_c, _src_clip_c.data(_clip_fmt_c))
_calls = {}
try:
    _cw.is_running = lambda: _calls.get('running', False)
    _cw.stop_running = lambda: _calls.__setitem__('stopped', True)
    _cw.push_warn_any = lambda v: _calls.__setitem__('pushed', v)
    _cw.set_autostart = lambda v: _calls.__setitem__('autostart', v)
    _cw.autostart_enabled = lambda: _calls.get('autostart_state', True)
    QProcess.startDetached = staticmethod(
        lambda *a, **k: _calls.__setitem__('launched', True))

    _calls.clear(); _calls['running'] = False
    win.set_clip_run(True)
    ok('launched' in _calls, 'clip: set_clip_run(True) launches the daemon when absent')
    _calls.clear(); _calls['running'] = True
    win.set_clip_run(True)
    ok('launched' not in _calls, 'clip: set_clip_run(True) idempotent when already running')
    _calls.clear()
    win.set_clip_run(False)
    ok(_calls.get('stopped'), 'clip: set_clip_run(False) stops the daemon')

    win.set_clip_warn_any(True)
    ok(win._clip_warn_any is True, 'clip: set_clip_warn_any records the setting')
    eq(_calls.get('pushed'), True, 'clip: set_clip_warn_any live-updates the daemon')
    win.set_clip_warn_any(False)

    ## Finding-2 regression: the clipboard-watch tray persists clip_warn_any via a
    ## single-key write; a later terminal _persist (a bulk write for some OTHER
    ## setting) must PRESERVE it, not clobber it with the terminal's stale value.
    from secure_terminal import settings as _st_clip   # noqa: PLC0415
    # isolate the privileged dirs to an EMPTY temp dir: a real admin lock= on
    # clip_warn_any (a supported /etc config) would otherwise pin the value and
    # false-fail this no-clobber check.
    _clip_sysd = tempfile.mkdtemp(prefix='st-clipsys-')
    _clip_orig_sysd = _st_clip._system_dirs
    _st_clip._system_dirs = lambda: [_clip_sysd]
    try:
        _st_clip.set_user_key('clip_warn_any', 'true')  # the tray toggles it ON on disk
        win._clip_warn_any = False                       # the terminal's stale in-memory value
        win._persist()                                   # a bulk write for another setting
        ok(_st_clip.load().get('clip_warn_any') == 'true',
           'terminal _persist preserves the tray-set clip_warn_any (no clobber)')
    finally:
        _st_clip._system_dirs = _clip_orig_sysd

    # Fix-3: Global-settings Apply must NOT write clip_warn_any when the user did
    # not toggle it here -- the daemon may have changed it on disk since the dialog
    # opened, so a theme-only Apply must leave the daemon value and not push a stale
    # checkbox to a running daemon.
    _clip_sysd3 = tempfile.mkdtemp(prefix='st-clipsys3-')
    _clip_orig_sysd3 = _st_clip._system_dirs
    _st_clip._system_dirs = lambda: [_clip_sysd3]
    try:
        win._clip_warn_any = False                       # dialog opened with it OFF
        _st_clip.set_user_key('clip_warn_any', 'true')   # daemon turns it ON afterwards
        _calls.clear()
        win._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'box',
                           'colors': True, 'line_edits': True, 'scrollback': 1000,
                           'paste_delay': 3, 'escape_limit': 4096, 'persist': False,
                           'clip_warn_any': False})       # unchanged from win._clip_warn_any
        eq(_st_clip.load().get('clip_warn_any'), 'true',
           'apply: a clip_warn_any unchanged in the dialog is not clobbered')
        ok('pushed' not in _calls,
           'apply: no daemon push when clip_warn_any was not toggled')
        # ...but a value the user DID toggle here is written to DISK and pushed.
        _st_clip.set_user_key('clip_warn_any', 'false')  # reset disk so the write shows
        win._clip_warn_any = False
        _calls.clear()
        win._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'box',
                           'colors': True, 'line_edits': True, 'scrollback': 1000,
                           'paste_delay': 3, 'escape_limit': 4096, 'persist': False,
                           'clip_warn_any': True})        # toggled ON in the dialog
        ok(win._clip_warn_any is True and _calls.get('pushed') is True
           and _st_clip.load().get('clip_warn_any') == 'true',
           'apply: a clip_warn_any toggled in the dialog is written to disk and pushed')
    finally:
        _st_clip._system_dirs = _clip_orig_sysd3

    # _persist must DROP a key locked at STARTUP (win._locked) even when it is not
    # currently locked in the system config -- i.e. it passes its startup snapshot
    # to update_user. Isolate the privileged dirs to an empty dir so load() locks
    # nothing; only win._locked should cause the drop.
    _pl_sysd = tempfile.mkdtemp(prefix='st-plsys-')
    _pl_usrd = tempfile.mkdtemp(prefix='st-plusr-')
    _pl_o_sys, _pl_o_usr = _st_clip._system_dirs, _st_clip._user_config_dir
    _pl_o_locked, _pl_o_theme = set(win._locked), win._default_theme
    _st_clip._system_dirs = lambda: [_pl_sysd]
    _st_clip._user_config_dir = lambda: _pl_usrd
    try:
        win._locked = frozenset({'theme'})              # theme locked at launch
        win._default_theme = 'dark'
        win._persist()
        _pw = {}
        _st_clip._parse_into(_st_clip.user_config_file(), _pw)
        ok('theme' not in _pw and 'zoom' in _pw,
           '_persist drops a startup-locked key (theme) but writes the rest')
    finally:
        win._locked, win._default_theme = _pl_o_locked, _pl_o_theme
        _st_clip._system_dirs, _st_clip._user_config_dir = _pl_o_sys, _pl_o_usr

    QSystemTrayIcon.isSystemTrayAvailable = staticmethod(lambda: True)
    win._systray = True
    ok(win._clip_controls_enabled(), 'clip: controls enabled when systray on + available')
    win._systray = False
    ok(not win._clip_controls_enabled(), 'clip: controls disabled when systray off')
    QSystemTrayIcon.isSystemTrayAvailable = staticmethod(lambda: False)
    win._systray = True
    ok(not win._clip_controls_enabled(), 'clip: controls disabled when no tray available')

    # set_clip_autostart is gated on the controls; off always applies
    win._systray = False
    _calls.pop('autostart', None)
    win.set_clip_autostart(True)
    ok('autostart' not in _calls, 'clip: set_clip_autostart(True) refused with no tray')
    QSystemTrayIcon.isSystemTrayAvailable = staticmethod(lambda: True)
    win._systray = True
    win.set_clip_autostart(True)
    eq(_calls.get('autostart'), True, 'clip: autostart on when controls enabled')
    win.set_clip_autostart(False)
    eq(_calls.get('autostart'), False, 'clip: autostart off always applies')

    # populate both tooltip branches + the context-menu injection
    win._systray = False
    _m = QMenu()
    win._populate_clipboard_menu(_m)
    ok(len(_m.actions()) >= 4, 'clip: menu populated (disabled-controls branch)')
    win._systray = True
    _m2 = QMenu()
    win._populate_clipboard_menu(_m2)
    ok(len(_m2.actions()) >= 4, 'clip: menu populated (enabled-controls branch)')
    _ctxmenu = QMenu()
    win.add_terminal_context_actions(_ctxmenu)
    ok(any(a.text() == 'System tray icon' for a in _ctxmenu.actions()),
       'clip: context menu gains the system-tray toggle')

    # systray coupling: turning the tray OFF clears clipboard autostart only when on
    QSystemTrayIcon.isSystemTrayAvailable = _o_avail_c
    win._systray = False
    _calls.clear(); _calls['autostart_state'] = True
    win.set_systray(False)
    eq(_calls.get('autostart'), False,
       'clip: disabling systray clears clipboard autostart')
    _calls.clear(); _calls['autostart_state'] = False
    win.set_systray(False)
    ok('autostart' not in _calls,
       'clip: disabling systray leaves an already-off autostart alone')

    # Review-now builds an in-process reviewer for the current clipboard
    APP.clipboard().setText('deceptive \u202e text')
    win._clip_review_now()
    ok(win._clip_reviewer is not None, 'clip: Review-now builds an in-process reviewer')
    win._clip_reviewer._popup.hide()
finally:
    (_cw.is_running, _cw.stop_running, _cw.push_warn_any,
     _cw.set_autostart, _cw.autostart_enabled) = _cw_saved
    QProcess.startDetached = _o_startdet
    QSystemTrayIcon.isSystemTrayAvailable = _o_avail_c
    win._systray = _o_systray_c
    win._clip_warn_any = _o_warnany_c
    win._clip_reviewer = None
    APP.clipboard().setMimeData(_o_clip_c)

# a tab terminal's right-click menu gains the app toggles through its MainWindow
from PyQt6.QtCore import QPoint                                    # noqa: E402
_rcmenu = win.current()._reviewed_context_menu(QPoint(0, 0))
ok(any(a.text() == 'System tray icon' for a in _rcmenu.actions()),
   'context menu: a tab terminal gains the app toggles via its window')

# icon helpers build an icon (themed, path, or letter fallback)
ok(M._app_icon() is not None, '_app_icon returns an icon')
ok(M._letter_icon('A', '#3b82f6') is not None, '_letter_icon renders a fallback icon')

# config init: an out-of-range scrollback normalises; allow_title seeds the OSC
# defaults; and a locked allow_title enforces both granular title settings
_cfgd2 = os.path.join(os.environ['XDG_CONFIG_HOME'], 'secure-terminal.d')
os.makedirs(_cfgd2, exist_ok=True)
with open(os.path.join(_cfgd2, '80-init.conf'), 'w', encoding='utf-8') as _cf:
    _cf.write('scrollback=99999\nallow_title=true\ntui=true\nescape_limit=65536\n')
_wc = MainWindow()
ok(_wc._scrollback == 0, 'config: an out-of-range scrollback normalises to unlimited')
ok(_wc._escape_limit == 65536, 'config: a valid escape_limit is read from the config')
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
ok(win._find_tab(win.tabs.tabText(0)) is not None,
   '_find_tab: an existing bare title is matched by title')
ok(win._find_tab('no-such-tab-title') is None,
   '_find_tab: an absent title matches nothing')
# a bare title containing a colon (e.g. 'host:port') is matched WHOLE, not split at
# the first ':' into a bogus kind -- regression: partition(':') mis-parsed it so
# 'prod:server' matched nothing. An explicit 'id:'/'title:' prefix still works.
_ft_saved = win.tabs.tabText(0)
win.tabs.setTabText(0, 'prod:server')
ok(win._find_tab('prod:server') is not None,
   '_find_tab: a bare title containing a colon is matched whole')
ok(win._find_tab('title:prod:server') is not None,
   '_find_tab: an explicit title: prefix matches a colon-bearing title')
ok(win._find_tab('id:prod:server') is None,
   '_find_tab: an id: prefix on a non-numeric value matches nothing')
win.tabs.setTabText(0, _ft_saved)

# _on_escape_suppressed: a long unterminated escape sequence surfaces a one-time,
# per-tab "output suppressed" advisory (it never lifts the suppression).
_esc_term = win.current()
win._esc_notified.discard(_esc_term)
win._advisories.pop(_esc_term, None)
win._on_escape_suppressed(_esc_term)
eq(win._advisories.get(_esc_term, (None,))[0], 'escape',
   '_on_escape_suppressed raises the suppression advisory')
win._advisories.pop(_esc_term, None)
win._on_escape_suppressed(_esc_term)         # already notified for this tab -> no re-raise
ok(_esc_term not in win._advisories,
   '_on_escape_suppressed does not re-raise for a tab already notified')
# the freeze notice WINS over the OSC notice (grok ai-review): an over-cap
# unterminated OSC fires escape_suppressed then osc_used('osc_other') in one read,
# and _on_osc_used must not clobber the more-actionable freeze banner.
win._esc_notified.discard(_esc_term)
win._advisories.pop(_esc_term, None)
win._osc_notified = {p for p in win._osc_notified if p[0] is not _esc_term}
win._on_escape_suppressed(_esc_term)         # freeze notice up
win._on_osc_used(_esc_term, 'osc_other')     # must NOT clobber it
eq(win._advisories.get(_esc_term, (None,))[0], 'escape',
   'the freeze notice wins: _on_osc_used does not clobber an active escape advisory')
ok((_esc_term, 'osc_other') not in win._osc_notified,
   'the skipped OSC notice stays un-marked so a later real OSC use can still notice')
win._advisories.pop(_esc_term, None)
win._esc_notified.discard(_esc_term)

# --- reviewdrain15 batch-2 security findings (admin-lock bypass + session DoS) ----
_b2_lock = set(win._locked)
# #3: the legacy "Allow title" control must refuse a GRANULAR osc_title/osc_notify
# lock, not only an allow_title lock -- else it bypasses the granular lock.
win._default_allow_title = False
win._locked = {'osc_title'}
win.set_allow_title(True)
ok(win._default_allow_title is False,
   '#3: set_allow_title refuses a granular osc_title lock (no legacy-control bypass)')
win._locked = {'osc_notify'}
win.set_allow_title(True)
ok(win._default_allow_title is False,
   '#3: set_allow_title refuses a granular osc_notify lock too')
# #6: set_clip_warn_any must honour a clip_warn_any lock (every sibling setter does).
win._clip_warn_any = False
win._locked = {'clip_warn_any'}
win.set_clip_warn_any(True)
ok(win._clip_warn_any is False,
   '#6: set_clip_warn_any refuses an admin clip_warn_any lock')
win._locked = _b2_lock
# #4: a crafted session with a NON-STRING tab name must not crash restore (insertTab
# needs a str). The placeholder path used a bare truth test.
_before_ct = win.tabs.count()
win._add_placeholder_tab({'name': ['not', 'a', 'string'], 'cwd': '/tmp'}, _before_ct)
ok(win.tabs.count() == _before_ct + 1,
   '#4: a non-string saved tab name falls back to a label, no restore crash')
win.tabs.removeTab(win.tabs.count() - 1)
# #5: a non-ASCII / non-str saved window geometry must not crash startup.
_o_persist = win._persist_session
win._persist_session = True                  # else _restore_window_geometry no-ops
_o_loadwin = M.session.load_window
try:
    M.session.load_window = lambda: 'not base64 ' + chr(0x20ac) + chr(0x4e2d)  # non-ASCII blob
    win._restore_window_geometry()
    ok(True, '#5: a non-ASCII saved geometry is tolerated, not a startup crash')
    M.session.load_window = lambda: ['not', 'a', 'string']      # non-str blob
    win._restore_window_geometry()
    ok(True, '#5: a non-string saved geometry is tolerated too')
finally:
    M.session.load_window = _o_loadwin
    win._persist_session = _o_persist

# NOTE: the client is a background THREAD. Two alternatives were measured and
# are WORSE, so do not 'simplify' this back to either: a subprocess client
# segfaults often even without coverage (the window installs a SIGCHLD handler
# to reap its pty children, so an unrelated child races it), and a same-thread
# non-blocking socket driven by processEvents() segfaults inside on_ready.
# This shape is clean WITHOUT coverage. UNDER coverage the C tracer's per-thread
# sys.settrace races this handoff and segfaults, so the coverage gate selects the
# sys.monitoring core (COVERAGE_CORE=sysmon); see secure-terminal-tests-coverage.
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

# REGRESSION (socket must not be STOLEN from a live primary): with multiple
# independent instances, a second instance that finds a live listener on the group
# socket must stay server-less rather than rebind. A mistaken always-bind
# (removeServer + listen regardless) would steal the live socket, creating a
# _server even when a primary is already up. This drives the REAL sockets (no
# mock): a connect probe (ipc.socket_is_live) sees a bound peer even before its
# event loop can reply, so a concurrent second launch cannot steal it. These
# assertions catch a regression to that always-bind behaviour.
_primary = MainWindow()
_primary.start_instance_server('steal-group')
ok(getattr(_primary, '_server', None) is not None,
   'start_instance_server: a free group -> the first instance claims it (binds)')
ok(M.ipc.socket_is_live('steal-group'),
   'ipc.socket_is_live: a bound listener answers a raw connect')
ok(not M.ipc.socket_is_live('no-such-live-group'),
   'ipc.socket_is_live: an absent socket -> not live (connect refused)')
_second = MainWindow()
_second.start_instance_server('steal-group')     # a live peer owns it
ok(getattr(_second, '_server', None) is None,
   'start_instance_server: a live peer -> the second instance stays server-less')
ok(M.ipc.socket_is_live('steal-group'),
   'start_instance_server: the first instance still owns the socket (not stolen)')
_second.deleteLater()
_primary.deleteLater()
APP.processEvents()
# a genuinely STALE socket file (no listener) is reclaimed, not treated as live
_stale_grp = 'stale-group'
_stale_path = M.ipc.socket_path(_stale_grp)
os.makedirs(os.path.dirname(_stale_path), exist_ok=True)
with open(_stale_path, 'w', encoding='utf-8') as _sf3:
    _sf3.write('')                               # a plain file: exists, nobody listening
ok(not M.ipc.socket_is_live(_stale_grp),
   'ipc.socket_is_live: a stale socket file is not live')
_reclaim = MainWindow()
_reclaim.start_instance_server(_stale_grp)       # clears the stale file, binds
ok(getattr(_reclaim, '_server', None) is not None,
   'start_instance_server: a stale socket is cleared and reclaimed')
_reclaim.deleteLater()
APP.processEvents()

# --- session persistence + quit/close hooks -----------------------------------
win.set_persist_session(False)              # disabling clears the saved session
win.clear_saved_session()
_o_qapp_quit = QApplication.quit
try:
    _quit_calls = []
    QApplication.quit = lambda *_a, **_k: _quit_calls.append(1)
    win._force_close = False                 # handler must flip this before quit
    M._install_signal_quit(APP)             # installs SIGINT/SIGTERM handlers
    import signal as _sig2
    _h = _sig2.getsignal(_sig2.SIGINT)
    if callable(_h):
        _h(_sig2.SIGINT, None)              # fire the handler
    # The quit is QUEUED (QTimer.singleShot), not synchronous: it must NOT have
    # fired yet -- that is exactly what lets a signal arriving before exec() still
    # be honored. The event loop then delivers it.
    ok(not _quit_calls, 'signal-quit handler does not call app.quit synchronously')
    APP.processEvents()
    ok(_quit_calls, 'signal-quit handler queues app.quit (honored once the loop runs)')
    ok(win._force_close is True,
       'signal-quit handler force-closes windows so teardown skips the modal')
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
    M.QFontDatabase = _FontDBPresent    # startup is font-independent here
    QApplication.exec = lambda _s: 0
    sys.argv = ['secure-terminal', '--new-instance', '--name', 'wmname',
                '--class', 'wmclass']
    eq(M.main(), 0, 'main: --name/--class set the WM name/class during startup')
    # a `--` before --test-canary means the canary belongs to the child command
    sys.argv = ['secure-terminal', '--new-instance', '--', '--test-canary']
    ok(M.main() == 0, 'main: --test-canary after -- is left to the child')
    # the missing-default-font wiring: main() -> `if not _require_default_font():
    # return 1`. Asserted here (after the threaded handoff test) on purpose -- see
    # the note in the font block above.
    M.QFontDatabase = _FontDBAbsent
    sys.argv = ['secure-terminal', '--new-instance', '--title', 'nofont']
    with _ctx.redirect_stderr(_io.StringIO()):
        eq(M.main(), 1, 'font: main() exits 1 when the default font is missing')
    M.QFontDatabase = _FontDBPresent
finally:
    sys.argv = _o_argv2
    M.ipc.send_request = _o_sr3
    M.QApplication = _o_qa2
    M.QFontDatabase = _REAL_QFONTDB
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
win._on_cwd_changed(_bt, '/tmp/some/where')  # nosec B108 -- literal path string arg to a handler under test; nothing is created
ok(True, 'notification, bell-tray and cwd-changed handlers run')
# SEC-2: the OSC-7 cwd tooltip must be html-escaped (setTabToolTip renders rich text), or
# a cwd path could inject markup -- the sibling _refresh_tab_label already escapes.
win._on_cwd_changed(_bt, '/<img src=x>')  # nosec B108 -- literal handler arg, nothing created
_cwdtip = win.tabs.tabToolTip(win.tabs.indexOf(_bt))
ok('<img' not in _cwdtip and '&lt;img' in _cwdtip,
   'SEC-2: an OSC-7 cwd path is html-escaped in the tab tooltip (no raw markup)')

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
# COR-7: --lines 0 must dump ZERO lines, not the whole tab. The server's `lines > 0` guard
# defaulted 0 to a full dump, and text.split('\n')[-0:] is the WHOLE list (negative-zero).
_rl0 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': 0})
ok(_rl0['ok'] and _rl0['text'] == '',
   'COR-7: ctl-dump-tab lines=0 dumps zero lines, not the full tab')
_rl1 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': 1})
ok(_rl1['ok'] and 'hello world of text' in _rl1['text'],
   'COR-7: ctl-dump-tab lines=1 still dumps the last line')
_o_dumpmax = M._DUMP_MAX
try:
    M._DUMP_MAX = 4                          # force the tail-cap branch
    _rr = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b})
    ok(_rr['ok'] and len(_rr['text']) <= 4, 'ctl dump-tab tail-caps to _DUMP_MAX')
finally:
    M._DUMP_MAX = _o_dumpmax
# F4: dump-tab bounds the ENCODED frame, not the character count -- non-ASCII expands
# ~6x under json.dumps(ensure_ascii), so a char cap alone could overflow the IPC frame
# and the client would drop it. Force a tiny frame cap + non-ASCII content past it.
import secure_terminal.ipc as _ipc4              # noqa: E402
import json as _json4                            # noqa: E402
_o_maxreq = _ipc4._MAX_REQUEST
try:
    _ipc4._MAX_REQUEST = 200
    _t0b._append('\u2603' * 200)             # snowmen: ~6 encoded bytes each
    _r4 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b})
    ok(_r4['ok'], 'F4: dump-tab succeeds even when the raw text overflows the frame')
    ok(len(_json4.dumps(_r4).encode('utf-8')) <= _ipc4._MAX_REQUEST,
       'F4: the dump-tab reply is bounded by the ENCODED frame, not the char count')
finally:
    _ipc4._MAX_REQUEST = _o_maxreq
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
# regression: a long tip at a high zoom must NOT be clipped (the wrapped last line
# used to vanish), and the tip must not be maximizable full-screen (max size capped
# to content, so a WM maximize is a no-op and the pointer poll can still hide it)
_longtip = ('The monospace font family used for the terminal grid. The default Hack '
            'avoids confusable glyphs and has no ligatures. Applies to every tab.')
_tip2.show_for(win, _longtip, QPoint(5, 5), 300)
ok(_tip2.height() >= _tip2.heightForWidth(_tip2.width()),
   'InfoTip: a long tip at high zoom fits its wrapped text (not clipped)')
ok(_tip2.maximumSize() == _tip2.size(),
   'InfoTip: max size is capped to content, so a WM maximize is a no-op')
_tip_running = _tip2._poll.isActive()
_tip2.close()
ok(_tip_running and not _tip2._poll.isActive(),
   'InfoTip: closeEvent stops the pointer poll')
_tip2.deleteLater()
APP.processEvents()

# --- #95: a settings (i) marker is a CLICK target that pops the copyable InfoTip
from PyQt6.QtCore import Qt as _Qt95, QEvent as _QEvent95, QPointF as _QPointF95  # noqa: E402
from PyQt6.QtGui import QMouseEvent as _QMouseEvent95            # noqa: E402
_il = M._InfoLabel('Theme <span>(i)</span>', 'the theme risk explanation', win)
ok(_il.cursor().shape() == _Qt95.CursorShape.PointingHandCursor,
   '#95: an info (i) marker uses a clickable pointing-hand cursor')
_il.mousePressEvent(_QMouseEvent95(
    _QEvent95.Type.MouseButtonPress, _QPointF95(1.0, 1.0),
    _Qt95.MouseButton.LeftButton, _Qt95.MouseButton.LeftButton,
    _Qt95.KeyboardModifier.NoModifier))
_iltip = win._tip_filter._tip
ok(_iltip.isVisible() and 'theme risk explanation' in _iltip.text(),
   '#95: clicking an (i) marker shows the copyable InfoTip with the row help')
_iltip.hide()
_iltip._poll.stop()

# --- #132: a second click on the SAME (i) marker toggles the tip closed --------
def _click95(label):
    label.mousePressEvent(_QMouseEvent95(
        _QEvent95.Type.MouseButtonPress, _QPointF95(1.0, 1.0),
        _Qt95.MouseButton.LeftButton, _Qt95.MouseButton.LeftButton,
        _Qt95.KeyboardModifier.NoModifier))
_click95(_il)
ok(_iltip.isVisible(), '#132: first click re-opens the InfoTip')
_click95(_il)
ok(not _iltip.isVisible(),
   '#132: a second click on the same marker hides it (toggle)')
_iltip._poll.stop()

# --- #130: the View > Paste delay check-mark follows the current delay ---------
win.set_paste_delay(5)                            # a preset -> that entry checks
ok(win._paste_delay_actions[5].isChecked()
   and not win._paste_delay_actions[0].isChecked(),
   '#130: setting a preset paste delay checks that menu entry')
win.set_paste_delay(7)                            # not a preset -> none checked
ok(not any(a.isChecked() for a in win._paste_delay_actions.values()),
   '#130: a custom paste delay leaves every menu entry unchecked')
win.set_paste_delay(3)                            # restore the default preset

# --- #128: menu hints are left to Qt's native tooltip (stacks above the popup);
# a non-menu widget still gets the copyable tool-window InfoTip -----------------
from PyQt6.QtWidgets import QMenu as _QMenu128                  # noqa: E402
from PyQt6.QtGui import QHelpEvent as _QHelpEvent128            # noqa: E402
_menu128 = _QMenu128(win)
_menu128.addAction('X').setToolTip('menu hint')
_he128 = _QHelpEvent128(_QEvent95.Type.ToolTip, QPoint(1, 1), QPoint(1, 1))
win._tip_filter._tip.hide()
win._tip_filter.eventFilter(_menu128, _he128)     # QMenu -> left to Qt
ok(not win._tip_filter._tip.isVisible(),
   '#128: a menu ToolTip is left to Qt, not shown as the tool-window InfoTip')
_wtip128 = M.QLabel('x', win)
_wtip128.setToolTip('row help 128')
ok(win._tip_filter.eventFilter(_wtip128, _he128)
   and win._tip_filter._tip.isVisible(),
   '#128: a non-menu widget still shows the copyable InfoTip')
win._tip_filter._tip.hide()
win._tip_filter._tip._poll.stop()

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
# #7: a shortcut rebound to a MODIFIED cursor/Home/End key (forwarded as ESC[1;p<final>)
# or to Ctrl+<punctuation> (a C0 control byte) must be reserved -- else it shadows the key
# for a TUI program. These all read False on the pre-fix code (bare nav + Ctrl+letter only).
for _rk in ('Ctrl+End', 'Shift+Home', 'Alt+Left',
            'Ctrl+[', 'Ctrl+]', 'Ctrl+\\', 'Ctrl+Space'):
    ok(win._is_reserved_shortcut(_rk),
       '_is_reserved_shortcut: %s is reserved (forwarded to the program)' % _rk)
# keyPressEvent routes every Ctrl+Shift combo to the window shortcuts, never the child, so
# Ctrl+Shift+<nav> and Ctrl+Shift+<letter> both stay available to rebind (not reserved).
for _ak in ('Ctrl+Shift+T', 'Ctrl+Shift+End'):
    ok(not win._is_reserved_shortcut(_ak),
       '_is_reserved_shortcut: %s stays available (routed to a window shortcut)' % _ak)
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
    # the theme lacks the symbol -> _toggle_icon draws the letter-chip fallback
    ok(not M._toggle_icon('x', 'Y', '#222222').isNull(),
       '_toggle_icon: draws the letter-chip fallback when the theme lacks the symbol')
    _o_exists = os.path.exists
    try:
        os.path.exists = lambda _p: True            # a shipped icon path is present
        ok(_REAL_APP_ICON() is not None,
           '_app_icon: loads the shipped SVG by path when no theme icon exists')
        os.path.exists = lambda _p: False
        ok(_REAL_APP_ICON().isNull(), '_app_icon: a null icon when nothing is found')
    finally:
        os.path.exists = _o_exists
finally:
    QIcon.fromTheme = _o_fromtheme

# --- _apply_global keeps locked keys at their admin value ----------------------
_sl2 = set(win._locked)
try:
    win._locked = {'tui', 'colors', 'osc_notice', 'unicode_mode', 'osc_title',
                   'font_family'}
    win._default_font_family = 'Hack'
    win._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'box',
                       'font_family': 'Attacker Font', 'font_size': 20,
                       'colors': True, 'line_edits': True, 'tui': True, 'osc_notice': True,
                       'tui_autobox_notice': True,
                       'osc': {'osc_title': True}, 'scrollback': 1000,
                       'paste_delay': 3, 'escape_limit': 4096, 'persist': False})
    ok(win._default_font_family == 'Hack',
       '_apply_global preserves admin-locked keys (incl. a locked font_family)')
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
# Stub openUrl: offscreen QPA does not spawn, but a direct run under a real desktop
# platform would pop an external file-manager window -- capture the path instead.
_op_opened = []
_op_oou = _QDS.openUrl
try:
    _QDS.openUrl = staticmethod(lambda url: _op_opened.append(url.toLocalFile()) or True)
    win._open_path('/tmp')                       # exists  # nosec B108 -- known-existing dir to exercise _open_path
    win._open_path('/tmp/no-such-dir-xyz/child') # missing -> parent  # nosec B108 -- missing path exercises the parent-fallback branch
finally:
    _QDS.openUrl = _op_oou
ok(len(_op_opened) == 2 and _op_opened[0] == '/tmp',
   '_open_path opens the folder, and a missing path falls back to a parent')

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
    M.QFontDatabase = _FontDBPresent    # startup is font-independent here
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
    M.QFontDatabase = _REAL_QFONTDB
    QApplication.exec = _o_qexec3
    _sig3.signal(_sig3.SIGCHLD, _o_chld3)

# F5: the module-level SIGCHLD handler delegates to SecureTerminal.reap_pty_children --
# reaping only our own pty children, never a subprocess child -- so it replaces the
# returncode-defanging SIGCHLD=SIG_IGN. It ignores its (signum, frame) args.
M._reap_pty_children(_sig3.SIGCHLD, None)
ok(True, '_reap_pty_children handler runs without error')

# --- set_font_family / choose_font: the per-tab font picker -------------------
from PyQt6.QtGui import QFont as _QFont                          # noqa: E402
from PyQt6.QtWidgets import QFontDialog as _QFontDialog          # noqa: E402
if win.tabs.count() == 0:
    win.new_tab()
win.set_font_family('DejaVu Sans Mono')         # normal path: apply + persist
eq(win._default_font_family, 'DejaVu Sans Mono',
   'set_font_family sets the tab family and the new-tab default')
win.set_font_family('')                          # empty -> falls back to the default
ok(win._default_font_family, 'set_font_family: an empty family falls back to the default')
_sfl = set(win._locked)
try:
    win._locked = {'font_family'}
    _before = win._default_font_family
    win.set_font_family('Ignored')               # admin-locked -> early return
    eq(win._default_font_family, _before,
       'set_font_family: an admin-locked family is not changed')
finally:
    win._locked = _sfl

# font_size from config: a valid value is honoured; a bad one falls back to the base
import secure_terminal.settings as _setmod_fs                     # noqa: E402
from secure_terminal.settings import Config as _Cfg_fs            # noqa: E402
from secure_terminal.terminal import BASE_POINT_SIZE as _BPS_fs   # noqa: E402
_o_load_fs = _setmod_fs.load
_base_cfg_fs = _o_load_fs()


def _cfg_with(**over):
    return _Cfg_fs({**dict(_base_cfg_fs), **over}, _base_cfg_fs.locked,
                   _base_cfg_fs.violations)


try:
    _setmod_fs.load = lambda: _cfg_with(font_size='16', ui_scale='150',
                                        font_family='DejaVu Sans Mono')
    _wfs = MainWindow()
    eq(_wfs._default_font_size, 16, 'font_size read from config (valid int)')
    eq(_wfs._default_font_family, 'DejaVu Sans Mono', 'font_family read from config')
    eq(_wfs._ui_scale, 150, 'ui_scale (menu size) read from config (valid int)')
    _setmod_fs.load = lambda: _cfg_with(font_size='not-a-number')
    _wfs2 = MainWindow()
    eq(_wfs2._default_font_size, _BPS_fs,
       'an invalid font_size falls back to the base point size')
finally:
    _setmod_fs.load = _o_load_fs

# the global-settings dialog now carries the paste/copy REVIEW level; _apply_global
# stores it and applies it to every open tab.
_pw_save, _cw_save = win._paste_warn, win._copy_warn
try:
    win._apply_global({'theme': 'dark', 'zoom': 100,
                       'font_family': win._default_font_family,
                       'font_size': win._default_font_size, 'mode': 'box',
                       'colors': True, 'line_edits': True, 'tui': False,
                       'osc': {}, 'osc_notice': True, 'tui_autobox_notice': True,
                       'scrollback': 0, 'paste_delay': 3, 'escape_limit': 4096,
                       'paste_warn': 'always', 'copy_warn': 'never', 'persist': False})
    eq((win._paste_warn, win._copy_warn), ('always', 'never'),
       '_apply_global stores the paste/copy review levels')
    ok(all(t.current_paste_warn() == 'always' and t.current_copy_warn() == 'never'
           for t in win._real_terms()),
       '_apply_global applies the paste/copy review levels to every open tab')
finally:
    win._paste_warn, win._copy_warn = _pw_save, _cw_save

# UI (menu) scale: _select_labels enlarges a dialog's font for readability; the base
# point size is captured once so a re-scaled fresh dialog never compounds, and a
# scale of 100 is a no-op.
from secure_terminal.main import _select_labels as _sel_scale     # noqa: E402
from PyQt6.QtWidgets import QDialog as _QDlgScale                  # noqa: E402
_probe_dlg = _QDlgScale()
_probe_before = _probe_dlg.font().pointSizeF()
_sel_scale(_probe_dlg, 150)
ok(_probe_dlg.font().pointSizeF() > _probe_before or _probe_before <= 0,
   '_select_labels(scale=150) enlarges the dialog font (menu zoom)')
_probe_dlg2 = _QDlgScale()
_pb2 = _probe_dlg2.font().pointSizeF()
_sel_scale(_probe_dlg2, 100)
eq(_probe_dlg2.font().pointSizeF(), _pb2,
   '_select_labels(scale=100) leaves the dialog font unchanged')
_us_save = win._ui_scale
try:
    win._apply_global({'theme': 'dark', 'zoom': 100,
                       'font_family': win._default_font_family,
                       'font_size': win._default_font_size, 'ui_scale': 175,
                       'mode': 'box', 'colors': True, 'line_edits': True, 'tui': False, 'osc': {},
                       'osc_notice': True, 'tui_autobox_notice': True,
                       'scrollback': 0, 'paste_delay': 3, 'escape_limit': 4096,
                       'persist': False})
    eq(win._ui_scale, 175, '_apply_global stores the menu (UI) scale')
finally:
    win._ui_scale = _us_save

_o_getfont = _QFontDialog.getFont
try:
    _QFontDialog.getFont = staticmethod(
        lambda *_a, **_k: (_QFont('DejaVu Sans Mono'), True))
    win.choose_font()                            # accepted -> set_font_family
    ok(True, 'choose_font: an accepted pick applies the family')
    _QFontDialog.getFont = staticmethod(lambda *_a, **_k: (_QFont('X'), False))
    win.choose_font()                            # cancelled -> no change
    ok(True, 'choose_font: a cancelled pick is a no-op')
finally:
    _QFontDialog.getFont = _o_getfont

# choose_font with no current tab returns before the dialog
_nf3 = MainWindow()
while _nf3.tabs.count():
    _nf3.tabs.removeTab(0)
_nf3.choose_font()                               # no tab -> return
ok(True, 'choose_font: no current tab -> returns before the dialog')
_nf3.deleteLater()
APP.processEvents()

# choose_font: a Qt build without the MonospacedFonts option falls back to no
# options (the defensive AttributeError branch)
_o_qfd = M.QFontDialog
try:
    class _FakeFDO:
        def __getattr__(self, _n):
            raise AttributeError(_n)             # .MonospacedFonts -> AttributeError

        def __call__(self, _n):
            return 0

    class _FakeFontDialog:
        FontDialogOption = _FakeFDO()

        @staticmethod
        def getFont(*_a, **_k):
            return (_QFont('DejaVu Sans Mono'), True)

    M.QFontDialog = _FakeFontDialog
    win.choose_font()                            # MonospacedFonts missing -> fallback opts
    ok(True, 'choose_font: a missing MonospacedFonts option falls back to no options')
finally:
    M.QFontDialog = _o_qfd

# --- set_paste_warn / set_copy_warn: valid modes applied to every tab ----------
win.set_paste_warn('always')
eq(win._paste_warn, 'always', 'set_paste_warn applies the chosen mode')
win.set_copy_warn('always')
eq(win._copy_warn, 'always', 'set_copy_warn applies the chosen mode')
win.set_paste_warn('bogus')                      # invalid -> ignored
eq(win._paste_warn, 'always', 'set_paste_warn: an invalid mode is ignored')
win.set_copy_warn('unicode')
win.set_paste_warn('unicode')
ok(True, 'set_paste_warn / set_copy_warn push the mode to every tab and persist')

# --- review risk lamp (#116): reflects the config and goes red on unreviewed risk
from PyQt6.QtWidgets import QDialog as _QDlgSec                    # noqa: E402
_pw0, _cw0, _ur0 = win._paste_warn, win._copy_warn, win._unreviewed_risk
try:
    win.set_paste_warn('unicode')
    win.set_copy_warn('unicode')
    win._unreviewed_risk = False
    eq(win._review_level()[0], '#1f8a54',
       'review lamp is green when both directions are reviewed')
    win.set_paste_warn('never')
    eq(win._review_level()[0], '#e5a50a',
       "review lamp is yellow when a direction's review is off")
    win._on_unreviewed_risk()
    ok(win._unreviewed_risk and win._review_level()[0] == '#e5484d',
       'unreviewed risk lights the review lamp red')
    win._on_unreviewed_risk()                    # already red -> stays red, no error
    _osec = _QDlgSec.exec
    _QDlgSec.exec = lambda _self: int(_QDlgSec.DialogCode.Accepted)
    try:
        win._show_security_details()             # acknowledging clears the red
    finally:
        _QDlgSec.exec = _osec
    ok(not win._unreviewed_risk,
       'opening the security details acknowledges and clears the red review lamp')
finally:
    win.set_paste_warn(_pw0)
    win.set_copy_warn(_cw0)
    win._unreviewed_risk = _ur0

# --- the paste/copy review bar: _show_review / _hide_paste_review --------------
from secure_terminal.terminal import SecureTerminal as _ST2      # noqa: E402
if win.tabs.count() == 0:
    win.new_tab()
_rvterm = win.current()
win._show_review(_rvterm, 'risky text', 0, 'paste')   # current tab -> bar shown
win._hide_paste_review(_rvterm)                        # current tab -> refocus
ok(True, '_show_review / _hide_paste_review drive the review bar for the active tab')
# a request from a NON-current tab is ignored (its text stays held)
_bgterm = _ST2(command='/bin/cat')
win._show_review(_bgterm, 'held', 0, 'copy')           # not current -> return
win._hide_paste_review(_bgterm)                        # not current -> no refocus
ok(True, '_show_review / _hide_paste_review ignore a background tab')
_bgterm.shutdown()

# --- app.aboutToQuit teardown: shuts every window's tabs, tolerating a raise ---
# main() connected _shutdown_all_tabs to app.aboutToQuit during the full-startup
# runs above; fire it with a tab whose shutdown() raises to drive the
# best-effort guard (the except that must never block quit).
_teardown_win = MainWindow()
_teardown_win.new_tab()


def _raise_shutdown():
    raise RuntimeError('shutdown blew up')


_teardown_win.tabs.widget(0).shutdown = _raise_shutdown
APP.aboutToQuit.emit()
ok(True, 'aboutToQuit teardown shuts down every tab and tolerates a failing shutdown')
_teardown_win.deleteLater()
APP.processEvents()

# global settings persist across restart (#68): _apply_global writes the defaults
# to the config so a fresh window reads them back.
import secure_terminal.settings as _ps                         # noqa: E402
_pcfg_prev = os.environ.get('XDG_CONFIG_HOME')
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp(prefix='st-persist-')
try:
    _pw = MainWindow()
    ok(_pw._tui_autobox_notice,
       'tui_autobox_notice loads default-on from a fresh (absent) config')
    _pw._apply_global({'theme': 'light', 'zoom': 175, 'mode': 'reveal', 'colors': True, 'line_edits': True,
                       'tui': False, 'osc': {}, 'osc_notice': False,
                       'tui_autobox_notice': False,
                       'scrollback': 7000, 'paste_delay': 5, 'escape_limit': 65536,
                       'persist': True})
    ok(not _pw._tui_autobox_notice and not _pw.act_tui_autobox_notice.isChecked(),
       '_apply_global stores tui_autobox_notice and mirrors it on the menu action')
    _pc = _ps.load()
    eq(_pc.get('theme'), 'light', 'settings persist: theme written to config')
    eq(_pc.get('zoom'), '175', 'settings persist: zoom written to config')
    eq(_pc.get('unicode_mode'), 'reveal', 'settings persist: unicode mode written')
    eq(_pc.get('scrollback'), '7000', 'settings persist: scrollback written')
    eq(_pc.get('paste_delay'), '5', 'settings persist: paste delay written')
    eq(_pc.get('escape_limit'), '65536', 'settings persist: escape limit written')
    eq(_pc.get('tui_autobox_notice'), 'false',
       'settings persist: tui_autobox_notice written to config')
    _pw.close()
    _pw.deleteLater()
finally:
    if _pcfg_prev is None:
        os.environ.pop('XDG_CONFIG_HOME', None)
    else:
        os.environ['XDG_CONFIG_HOME'] = _pcfg_prev

# deferred session restore (#59): the first tab is restored synchronously so the
# window opens with content; the rest render after the window is up (a big session
# no longer blocks the first paint), and closeEvent finishes any pending restore so
# no tab is dropped from the save.
import secure_terminal.session as _ds                         # noqa: E402
from PyQt6.QtCore import QEventLoop as _QEL59                  # noqa: E402
from PyQt6.QtGui import QCloseEvent as _QCE59                  # noqa: E402
_st_prev = os.environ.get('XDG_STATE_HOME')
_cfg_prev = os.environ.get('XDG_CONFIG_HOME')
os.environ['XDG_STATE_HOME'] = tempfile.mkdtemp(prefix='st-defer-')
# a fresh, empty config so persist_session defaults to True (a prior test may have
# written persist_session=false), otherwise the restore path is skipped entirely.
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp(prefix='st-defer-cfg-')
try:
    _ds.save([{'name': 'd0', 'text': 'zero\n', 'osc': {}},
              {'name': 'd1', 'text': 'one\n', 'osc': {}},
              {'name': 'd2', 'text': 'two\n', 'osc': {}}])
    from PyQt6.QtWidgets import QWidget as _QWidget99            # noqa: E402
    _dw = MainWindow()
    # #99: the WHOLE tab bar is drawn up front (all three entries at once), but only
    # the active tab has real content synchronously; the rest are placeholders that
    # swap in their real shell lazily -- so the bar never grows one tab at a time.
    eq(_dw.tabs.count(), 3,
       '#99: the whole tab bar is drawn up front (all entries present at once)')
    eq(len(_dw._real_terms()), 1,
       '#99: only the active tab has real content synchronously')
    eq(len(_dw._deferred_restore), 2,
       '#99: the remaining tabs are placeholders queued for a lazy swap')
    # #80: background tabs must not steal focus or switch the view -- a deferred
    # restore that switched to each tab flashed the view through all of them.
    _switches80 = []
    _dw.tabs.currentChanged.connect(lambda i: _switches80.append(i))
    for _ in range(40):
        _l = _QEL59()
        QTimer.singleShot(20, _l.quit)
        _l.exec()
        if not _dw._deferred_restore:
            break
    eq(_dw.tabs.count(), 3, 'deferred restore: all tabs restored after the window is up')
    eq(len(_dw._real_terms()), 3, '#99: every placeholder is swapped for a real tab')
    eq(_dw.tabs.currentIndex(), 0,
       '#80: the view stays on the first tab through the background restore')
    eq(_switches80, [],
       '#80: swapping in background tabs raises no tab-switch (no flashing)')
    ok(not _dw._deferred_restore, 'deferred restore: the queue drains')
    _dw._restore_next_deferred()      # a no-op once the queue is empty (early return)
    eq(_dw.tabs.count(), 3, 'deferred restore: a spurious drain call is a no-op')
    _dw._swap_placeholder(_QWidget99())   # #99: swap of an unknown placeholder -> no-op
    eq(_dw.tabs.count(), 3, '#99: swapping an unknown placeholder is a safe no-op')
    _dw.close()
    _dw.deleteLater()

    # #88/#92: the previously-focused tab is the one SHOWN immediately (never tab 0
    # first), and the others fill in AROUND it at their saved positions -- the active
    # widget stays visible throughout, so nothing flashes. Restore tab 2 as active.
    _ds.save([{'name': 'a0', 'text': 'a\n', 'osc': {}},
              {'name': 'a1', 'text': 'b\n', 'osc': {}},
              {'name': 'a2', 'text': 'c\n', 'osc': {}}], active=2)
    _aw = MainWindow()
    _active_w = _aw.current()                     # shown FIRST, before any deferred
    eq(_aw._user_titles.get(_active_w, ''), 'a2',
       '#92: the saved active tab is shown first, not tab 0')
    _shown = set()
    _aw.tabs.currentChanged.connect(lambda _i: _shown.add(_aw.current()))
    for _ in range(40):
        _l = _QEL59()
        QTimer.singleShot(20, _l.quit)
        _l.exec()
        if _aw.tabs.count() >= 3 and not _aw._deferred_restore:
            break
    eq([_aw._user_titles.get(_aw.tabs.widget(_i), '') for _i in range(3)],
       ['a0', 'a1', 'a2'], '#92: the restored tabs keep their saved order')
    eq(_aw.current(), _active_w, '#92: the active tab is still current after restore')
    ok(_shown <= {_active_w},
       '#92: only the active tab is ever shown -- no first-tab flash')
    _aw.close()
    _aw.deleteLater()
    # a saved active index that no longer fits the restored tabs is ignored (the
    # default first tab stays current). Craft it directly: save() drops an
    # out-of-range index, so write an inconsistent session to hit the guard.
    _ds._write_atomic(_ds.session_path(),
                      '{"tabs": [{"name": "b0", "osc": {}}], "active": 5}')
    _bw = MainWindow()
    eq(_bw.tabs.currentIndex(), 0, '#88: an active index past the restored tabs falls back to tab 0')
    _bw.deleteLater()
    # closeEvent must finish a still-pending restore so no tab is dropped from save
    _ds.save([{'name': 'e0', 'text': 'a\n', 'osc': {}},
              {'name': 'e1', 'text': 'b\n', 'osc': {}},
              {'name': 'e2', 'text': 'c\n', 'osc': {}}])
    _cw = MainWindow()
    eq(len(_cw._deferred_restore), 2, 'deferred restore: two tabs pending before close')
    _cw.closeEvent(_QCE59())
    ok(not _cw._deferred_restore and _cw.tabs.count() == 3,
       'closeEvent finishes the deferred restore before saving (no tab dropped)')
    _cw.deleteLater()

    # #99 (ai-review): a placeholder is labelled like its real tab (saved name, else
    # the saved cwd basename, else "shell") and is safe to select and to close before
    # its shell swaps in -- neither must call a SecureTerminal method on the QWidget.
    _ds.save([{'name': 'i0', 'text': 'x\n', 'osc': {}},          # active, restored real
              {'name': 'named', 'text': 'y\n', 'osc': {}},       # placeholder: user name
              {'name': '', 'cwd': '/usr/share', 'text': 'z\n', 'osc': {}},  # cwd basename
              {'name': '', 'text': 'w\n', 'osc': {}}], active=0)          # -> 'shell'
    _iw = MainWindow()
    eq(_iw.tabs.count(), 4, '#99: the full bar is drawn up front')
    eq(len(_iw._deferred_restore), 3, '#99: three placeholders pending')
    eq(_iw.tabs.tabText(1), 'named', '#99: a placeholder shows the saved name')
    eq(_iw.tabs.tabText(2), 'share',
       '#99: an unnamed placeholder shows its saved cwd basename')
    eq(_iw.tabs.tabText(3), 'shell',
       '#99: an unnamed placeholder with no saved cwd shows shell')
    ok(_iw.tabs.isTabEnabled(0) and not _iw.tabs.isTabEnabled(1)
       and not _iw.tabs.isTabEnabled(2) and not _iw.tabs.isTabEnabled(3),
       '#99 (F1): the active tab is enabled, placeholders are disabled (unselectable)')
    # a bulk "apply to all tabs" must skip placeholders, not call a setter on a QWidget
    _iw._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'box', 'colors': True, 'line_edits': True,
                       'tui': False, 'osc_notice': True, 'tui_autobox_notice': True, 'osc': {},
                       'scrollback': 1000, 'paste_delay': 0, 'escape_limit': 4096,
                       'persist': True})
    ok(_iw.current().current_theme() == 'dark',
       '#99 (F1): apply-to-all updates real tabs and skips placeholders (no crash)')
    # an all-tabs find hop must skip placeholders too (query absent from the real tab
    # forces the hop loop over the placeholder tabs)
    _iw._find_bar.input.setText('zqxjnomatch')
    _iw._find_bar.all_tabs.setChecked(True)
    _iw._find_step(False)
    ok(True, '#99 (F1): an all-tabs find skips placeholders without crashing')
    _iw.tabs.setCurrentIndex(2)                  # select a placeholder
    _iw._update_terminate_enabled()              # the 400ms poll path on a placeholder
    ok(not _iw.act_terminate.isEnabled(),
       '#99: selecting a placeholder disables Terminate and does not crash')
    _ph_close = _iw.tabs.widget(3)
    _iw.close_tab(3)                             # close a placeholder
    ok(_ph_close not in _iw._deferred_restore and _ph_close not in _iw._pending_restore
       and _iw.tabs.count() == 3,
       '#99: closing a placeholder drops it cleanly (no confirm, no shutdown)')
    _iw.close()
    _iw.deleteLater()

    # #99 (F7): closing the LAST tab when it is a placeholder must close the window --
    # the placeholder branch has to run the count==0 -> self.close() step too.
    _ds.save([{'name': 'l0', 'text': 'a\n', 'osc': {}},
              {'name': 'l1', 'text': 'b\n', 'osc': {}}], active=0)
    _lw = MainWindow()
    eq(_lw.tabs.count(), 2, '#99 (F7): a real active tab plus one placeholder')
    _lw.close_tab(0)                             # close the real active tab
    eq(_lw.tabs.count(), 1, '#99 (F7): one placeholder remains')
    _lw.close_tab(0)                             # close the last remaining placeholder
    ok(_lw.tabs.count() == 0,
       '#99 (F7): closing the last placeholder empties the window')
    _lw.deleteLater()

    # window geometry (size + maximized) persists across restart -- #77
    from PyQt6.QtWidgets import QApplication as _QApp77          # noqa: E402
    _ds.clear()
    _gw = MainWindow()
    _gw.resize(724, 468)
    _QApp77.processEvents()
    _ds.save(_gw._session_tabs(), _gw._window_state())
    ok(_ds.load_window() is not None, '#77: window geometry is saved with the session')
    _gw.deleteLater()
    _gw2 = MainWindow()                       # __init__ restores the saved geometry
    _QApp77.processEvents()
    ok(abs(_gw2.size().width() - 724) <= 8 and abs(_gw2.size().height() - 468) <= 8,
       '#77: a fresh window reopens at the saved size')
    _gw2.showMaximized()
    _QApp77.processEvents()
    _ds.save(_gw2._session_tabs(), _gw2._window_state())
    _gw2.deleteLater()
    _gw3 = MainWindow()
    _gw3.show()
    _QApp77.processEvents()
    ok(_gw3.isMaximized(), '#77: a maximized window reopens maximized')
    _gw3.deleteLater()
    # persist_session off -> geometry restore is skipped (covers the guard)
    _gw3b = MainWindow()
    _gw3b._persist_session = False
    _gw3b._restore_window_geometry()
    ok(True, '#77: geometry restore is a no-op when persistence is off')
    _gw3b.deleteLater()

    # #78: a restored tab renders its scrollback ONCE in the saved mode -- no
    # re-render churn (which flickered the mode detail->show->box and jumped the
    # scrollbar). Spy on _rerender across the restore.
    from secure_terminal.terminal import SecureTerminal as _ST78    # noqa: E402
    _rr_orig = _ST78._rerender
    _rr = {'n': 0}
    def _rr_spy(self):                                              # noqa: E306
        _rr['n'] += 1
        return _rr_orig(self)
    _ST78._rerender = _rr_spy
    try:
        _mw78 = MainWindow()
        _rr['n'] = 0
        _mw78._restore_tab({'text': 'cafe box\n', 'mode': 'box', 'colors': True, 'line_edits': True,
                            'markings': False, 'osc': {}})
        _t78 = _mw78.current()
        eq(_t78.current_mode(), 'box', '#78: restored tab keeps its saved mode')
        ok(_t78.colors_enabled() and not _t78.markings_enabled(),
           '#78: restored tab keeps its saved colours/markings')
        eq(_rr['n'], 0,
           '#78: restore does not re-render (scrollback drawn once in final mode)')
        _mw78.deleteLater()
    finally:
        _ST78._rerender = _rr_orig
finally:
    for _var, _prev in (('XDG_STATE_HOME', _st_prev), ('XDG_CONFIG_HOME', _cfg_prev)):
        if _prev is None:
            os.environ.pop(_var, None)
        else:
            os.environ[_var] = _prev

# --- CLASH: shortcuts -- registry completeness, collisions, forwarded keys -----
# Ground truth is the LIVE QAction set, not win._shortcuts: taking the registry as
# truth is exactly what hid Alt+1..9, which were bound with a bare setShortcut and
# so were absent from the Shortcuts dialog AND from the duplicate check.
from PyQt6.QtCore import Qt as _Qt_sc                        # noqa: E402
from PyQt6.QtGui import QAction as _QAction_sc               # noqa: E402
from PyQt6.QtGui import QKeySequence as _QKS                 # noqa: E402

# Only actions reachable from the menubar: findChildren() also returns actions a
# rebuilt menu left behind as orphaned children, which are not user-reachable and
# would report as unregistered without meaning anything.
_menu_acts = []
for _m in win.menuBar().findChildren(QMenu):
    _menu_acts.extend(_m.actions())
_acts_with_keys = [a for a in dict.fromkeys(_menu_acts)
                   if not a.shortcut().isEmpty()]
ok(len(_acts_with_keys) >= 20,
   'actions carrying a shortcut were enumerated (%d)' % len(_acts_with_keys))

# Every shortcut-carrying action must be in the registry, or it is unlistable and
# uncheckable. Compared by QAction identity, so a label change cannot mask it.
_registered = {entry[0] for entry in win._shortcuts.values()}
_unregistered = sorted(a.text().replace('&', '') for a in _acts_with_keys
                       if a not in _registered)
eq(_unregistered, [],
   'every action with a shortcut is registered (listable and collision-checked)')

# No two registered actions may hold the same key.
_by_seq = {}
for _ident, _entry in win._shortcuts.items():
    _norm = _entry[0].shortcut().toString()
    if _norm:
        _by_seq.setdefault(_norm, []).append(_ident)
eq(sorted(k for k, v in _by_seq.items() if len(v) > 1), [],
   'no key combination is assigned to two actions')

# No default may shadow a BARE key the terminal forwards to the running program:
# QAction processing fires first, so the key never reaches the program. This is
# what put fullscreen on F11 and shortcuts_help on F1 while _build_tui_keys mapped
# F11 -> ESC[23~ and F1 -> ESC OP, so vim and htop never received either.
# Scoped to the forwarding tables deliberately: a bare Ctrl+<letter> default
# (quit = Ctrl+Q) is a SEPARATE, deliberate decision -- _set_shortcuts documents
# that a built-in default is allowed to stand and only a user REBIND is refused.
from secure_terminal.main import _forwarded_keys as _fwd_keys      # noqa: E402

_shadowing = []
for _i, _e in win._shortcuts.items():
    if not _e[1]:
        continue
    _qks = _QKS(_e[1])
    if _qks.isEmpty():
        continue
    _combo = _qks[0]
    if (_combo.keyboardModifiers() == _Qt_sc.KeyboardModifier.NoModifier
            and _combo.key() in _fwd_keys()):
        _shadowing.append('%s=%s' % (_i, _e[1]))
eq(sorted(_shadowing), [],
   'no shortcut default shadows a bare key the terminal forwards')

# ...and the reserved set must really come from the forwarding tables, not a
# hand-written list: every bare forwarded key must be reported reserved.
from secure_terminal.terminal import _build_tui_keys as _btk    # noqa: E402

_not_reserved = []
for _qtkey in _btk():
    if _qtkey in (_Qt_sc.Key.Key_Return, _Qt_sc.Key.Key_Enter,
                  _Qt_sc.Key.Key_Tab, _Qt_sc.Key.Key_Escape,
                  _Qt_sc.Key.Key_Backspace):
        continue          # Qt does not express these as a bare window shortcut
    if not win._is_reserved_shortcut(_QKS(_qtkey)):
        _not_reserved.append(int(_qtkey))
eq(_not_reserved, [],
   'every bare key the terminal forwards is treated as reserved')

# The collision check must consider the LIVE registry, not only the submitted
# mapping: a one-key change that lands on another action's key is a collision.
_sc_prev = dict(win._keybindings)
try:
    _copy_seq = win._shortcuts['copy'][0].shortcut().toString()
    _problems = win._set_shortcuts({'find': _copy_seq})
    ok(bool(_problems),
       'assigning one action the key another already holds is reported')
finally:
    win._keybindings = _sc_prev

# --- CLASH: lock= must hold on EVERY dialog-settable key ----------------------
# An administrator `lock=<key>` is a security control, and it was enforced per
# key by hand: _apply_global had a six-entry lock list while assigning fourteen
# attributes, so a locked paste_warn/copy_warn (and others) was overridable from
# the global Settings dialog even though the View-menu setter correctly refused.
# Drive the table instead of a hand-written list, so a new key cannot escape.
_gk = MainWindow._GLOBAL_KEYS
ok(len(_gk) >= 14, 'the dialog-settable key table was found (%d keys)' % len(_gk))

# Every key in the table must actually be persisted -- otherwise it is not a
# setting and the lock question is meaningless.
import ast as _ast_lk                                      # noqa: E402
import inspect as _in_lk                                   # noqa: E402

_persist_src = _in_lk.getsource(MainWindow._persist)
_persist_keys = set()
for _n in _ast_lk.walk(_ast_lk.parse(_persist_src.lstrip())):
    if isinstance(_n, _ast_lk.Dict):
        for _k in _n.keys:
            if isinstance(_k, _ast_lk.Constant) and isinstance(_k.value, str):
                _persist_keys.add(_k.value)
ok(len(_persist_keys) >= 20,
   'the _persist() key set was extracted (%d keys)' % len(_persist_keys))
eq(sorted({_k for _k, _f, _a in _gk} - _persist_keys), [],
   'every dialog-settable key is actually persisted')

# The load-bearing assertion: lock a key, hand _apply_global a DIFFERENT value,
# and require the attribute not to move. Derived from the table, so this covers
# a newly added key automatically.
_lk_prev = win._locked
_lk_bad = []
try:
    for _key, _field, _attr in _gk:
        _before = getattr(win, _attr)
        # A value guaranteed to differ from the current one, per type.
        if isinstance(_before, bool):
            _other = not _before
        elif isinstance(_before, int):
            _other = int(_before) + 7
        elif _key == 'unicode_mode':
            _other = 'reveal' if _before != 'reveal' else 'box'
        elif _key in ('paste_warn', 'copy_warn'):
            _other = 'always' if _before != 'always' else 'never'
        elif _key == 'theme':
            _other = 'light' if _before != 'light' else 'dark'
        else:
            _other = str(_before) + 'X'
        win._locked = {_key}
        _opts = {'theme': win._default_theme, 'zoom': win._default_zoom,
                 'mode': win._default_mode, 'colors': win._default_colors,
                 'line_edits': win._default_line_edits, 'tui': win._default_tui,
                 'scrollback': win._scrollback, 'paste_delay': win._paste_delay,
                 'escape_limit': win._escape_limit,
                 'persist': win._persist_session, 'systray': win._systray,
                 'auto_tab_colors': win._auto_tab_colors}
        _opts[_field] = _other
        win._apply_global(dict(_opts))
        _after = getattr(win, _attr)
        if _after != _before:
            _lk_bad.append((_key, _before, _other, _after))
finally:
    win._locked = _lk_prev
eq(_lk_bad, [],
   'a locked key is not overridable through the global settings dialog')

# --- every lock guard actually returns early ----------------------------------
# The guards added with the _GLOBAL_KEYS work refuse a locked change in the
# SETTER, which _apply_global never reaches -- so drive each setter directly with
# its key locked and require the value not to move.
_lk2_prev = win._locked
_setter_bad = []
try:
    for _key, _call, _read in (
            ('zoom', lambda: win.set_zoom(win._default_zoom + 13),
             lambda: win._default_zoom),
            ('theme', lambda: win.set_theme(
                'light' if win._default_theme != 'light' else 'dark'),
             lambda: win._default_theme),
            ('scrollback', lambda: win.set_scrollback(win._scrollback + 500),
             lambda: win._scrollback),
            ('paste_delay', lambda: win.set_paste_delay(win._paste_delay + 3),
             lambda: win._paste_delay),
            ('escape_limit', lambda: win.set_escape_limit(win._escape_limit + 512),
             lambda: win._escape_limit),
            ('persist_session', lambda: win.set_persist_session(
                not win._persist_session),
             lambda: win._persist_session),
            ('confirm_close', lambda: win.set_confirm_close(
                not win._confirm_close),
             lambda: win._confirm_close)):
        win._locked = {_key}
        _before = _read()
        _call()
        if _read() != _before:
            _setter_bad.append(_key)
    # osc_notice_off is a set, so compare a copy
    win._locked = {'osc_notice_off'}
    _before_off = set(win._osc_notice_off)
    win.set_osc_notice_type('osc_title', False)
    if set(win._osc_notice_off) != _before_off:
        _setter_bad.append('osc_notice_off')
finally:
    win._locked = _lk2_prev
eq(_setter_bad, [], 'every lock-guarded setter refuses a locked change')

# _apply_locks must disable the zoom SPIN BOX, which is not a QAction and so is
# gated separately from the action list.
_lk3_prev = win._locked
try:
    win._locked = {'zoom'}
    win._apply_locks()
    ok(not win.zoom_box.isEnabled(),
       'a locked zoom disables the zoom spin box')
finally:
    win._locked = _lk3_prev
    win.zoom_box.setEnabled(True)

# Ctrl+PageUp / Ctrl+PageDown are consumed by the widget for tab switching, so a
# window shortcut there would never fire and must be reported reserved.
# Built from the Qt.Key ENUM, not a hand-typed name: Qt spells these "PgUp" /
# "PgDown", and QKeySequence('Ctrl+PageUp') silently parses to Key_unknown -- a
# test written that way passes or fails for the wrong reason.
_pgup = _QKS(_Qt_sc.KeyboardModifier.ControlModifier | _Qt_sc.Key.Key_PageUp)
_pgdn = _QKS(_Qt_sc.KeyboardModifier.ControlModifier | _Qt_sc.Key.Key_PageDown)
_pgup_shift = _QKS(_Qt_sc.KeyboardModifier.ControlModifier
                   | _Qt_sc.KeyboardModifier.ShiftModifier
                   | _Qt_sc.Key.Key_PageUp)
ok(win._is_reserved_shortcut(_pgup) and win._is_reserved_shortcut(_pgdn)
   and win._is_reserved_shortcut(_pgup_shift),
   'the tab-switch keys are reserved for the widget')

# --- CLASH: menu accelerators ------------------------------------------------
# The '&' in an action's text is a MNEMONIC marker, so two items in one menu
# marking the same letter make one of them unreachable by keyboard, and a literal
# ampersand must be written '&&' or Qt eats it (the item then reads "Folders
# Files..."). Both are silent: the menu still opens and every action still works.
# Derive from the live menubar rather than a list of expected labels.
import re as _re_mn                                       # noqa: E402

_mn_dupes = []
_mn_literal = []
for _menu in win.menuBar().findChildren(QMenu):
    _seen_keys = {}
    for _act in _menu.actions():
        _text = _act.text()
        if not _text:
            continue                                      # separator
        # A bare '&' that is neither '&&' nor a mnemonic marker on an alphanumeric
        # is a swallowed literal ampersand.
        for _m in _re_mn.finditer(r'&+', _text):
            _run = _m.group(0)
            if len(_run) % 2 == 0:
                continue                                  # '&&' pairs are literals
            _after = _text[_m.end():_m.end() + 1]
            if not _after.isalnum():
                _mn_literal.append((_menu.title(), _text))
        for _letter in _re_mn.findall(r'(?<!&)&(\w)', _text):
            _key = _letter.lower()
            if _key in _seen_keys:
                _mn_dupes.append((_menu.title(), _key,
                                  _seen_keys[_key], _text))
            else:
                _seen_keys[_key] = _text
ok(len(list(win.menuBar().findChildren(QMenu))) >= 4,
   'the menubar was enumerated (%d menus)'
   % len(list(win.menuBar().findChildren(QMenu))))
eq(_mn_literal, [],
   'no menu item swallows a literal ampersand (write it as "&&")')
eq(_mn_dupes, [], 'no two items in one menu claim the same mnemonic letter')

# --- responsive toolbar: no ">>" overflow at narrow widths -------------------
# At the old fixed 820px default (and any window narrower than the full-label
# layout) Qt folded the trailing chips + zoom behind a ">>" chevron, unreachable
# without the overflow menu. The toolbar now steps through three display tiers so
# every control stays on the bar with labels as informative as the width allows:
#   full    -- text-beside-icon action buttons + chip captions
#   labeled -- icon-only action buttons + chip captions (the app's 860 default)
#   icons   -- icon-only action buttons, chip captions hidden (narrowest)
# Driven WITHOUT show(): an offscreen second MainWindow shown under the coverage
# tracer perturbs Qt teardown (see the module header). resizeEvent + an explicit
# layout activation exercises the same relayout path deterministically. isHidden()
# (the explicit hide flag), not isVisible() (false while the window is unshown),
# is what tells captions apart here.
from PyQt6.QtCore import Qt as _QtTB, QSize as _QSzTB             # noqa: E402
from PyQt6.QtGui import QResizeEvent as _QRETB                    # noqa: E402
_tw = MainWindow()
_tb = _tw._toolbar
_caps = _tw._compact_hide
ok(len(_caps) == 3, 'toolbar: the three chip captions are hideable')
# tiers are ordered richest-first and every one has a measured width.
_tier_names = [t[0] for t in _tw._toolbar_tiers]
eq(_tier_names, ['full', 'labeled', 'icons'], 'toolbar: three tiers, richest first')
ok(all(w > 0 for _n, w in _tw._toolbar_tiers), 'toolbar: every tier has a width')
_need = dict(_tw._toolbar_tiers)
ok(_need['full'] > _need['labeled'] > _need['icons'],
   'toolbar: richer tiers need more width')

# a resizeEvent dispatched while the toolbar does not yet exist (early in
# construction) must be a safe no-op, not an AttributeError.
_saved_tb = _tw._toolbar
_tw._toolbar = None
_tw.resizeEvent(_QRETB(_QSzTB(800, 520), _QSzTB(800, 520)))
ok(_tw._toolbar is None, 'toolbar: a resize before the toolbar exists is a no-op')
_tw._toolbar = _saved_tb


def _tb_resize(width):
    _tw.resize(width, 520)
    _tw.resizeEvent(_QRETB(_QSzTB(width, 520), _QSzTB(width, 520)))
    _tb.layout().activate()          # recompute sizeHint for the new mode, unshown
    _tb.updateGeometry()
    APP.processEvents()


# wide window: full text-beside-icon labels, captions shown, whole bar fits.
_tb_resize(1500)
eq(_tw._toolbar_tier, 'full', 'toolbar: a wide window shows the full labels')
eq(_tb.toolButtonStyle(), _QtTB.ToolButtonStyle.ToolButtonTextBesideIcon,
   'toolbar: a wide window uses text-beside-icon buttons')
ok(not any(c.isHidden() for c in _caps),
   'toolbar: a wide window shows the chip captions')
ok(_tb.sizeHint().width() <= _tw.width(),
   'toolbar: the full toolbar fits a wide window without the >> overflow')

# the app's default width: the "labeled" middle tier -- icon-only action buttons
# but the chip captions still shown (the clean, self-documenting narrow view).
_tb_resize(M.TOOLBAR_DEFAULT_WIDTH)
eq(_tw._toolbar_tier, 'labeled', 'toolbar: the default width uses the labeled tier')
eq(_tb.toolButtonStyle(), _QtTB.ToolButtonStyle.ToolButtonIconOnly,
   'toolbar: the labeled tier uses icon-only buttons')
ok(not any(c.isHidden() for c in _caps),
   'toolbar: the labeled tier keeps the chip captions')
ok(_tb.sizeHint().width() <= _tw.width(),
   'toolbar: the labeled tier fits the default width without the >> overflow')

# narrower still: the leanest "icons" tier -- captions hidden so the bar fits.
_tb_resize(_need['labeled'] - 1)
eq(_tw._toolbar_tier, 'icons', 'toolbar: a narrow window drops to the icons tier')
eq(_tb.toolButtonStyle(), _QtTB.ToolButtonStyle.ToolButtonIconOnly,
   'toolbar: the icons tier uses icon-only buttons')
ok(all(c.isHidden() for c in _caps), 'toolbar: the icons tier hides the chip captions')
ok(_tb.sizeHint().width() <= _tw.width(),
   'toolbar: the icons tier fits a narrow window without the >> overflow')
# icon-only is only safe if every button actually has an icon (the fallbacks
# guarantee one even with no desktop icon theme, as in this offscreen run).
ok(all(not a.icon().isNull() for a in
       (_tw.act_new, _tw.act_copy, _tw.act_paste, _tw.act_terminate)),
   'toolbar: every icon-only button has a non-null icon')

# widening again restores the full labels (covers the icons -> full path, which
# steps up through more than one tier in a single relayout).
_tb_resize(1500)
eq(_tw._toolbar_tier, 'full', 'toolbar: re-widening restores the full labels')

# hysteresis: a width just inside a tier's slack band, reached from a leaner tier,
# does NOT step up yet (so the switch cannot oscillate at the boundary).
_tb_resize(_need['labeled'] - 1)               # settle in the icons tier
eq(_tw._toolbar_tier, 'icons', 'toolbar: hysteresis setup lands in icons')
_tb_resize(_need['labeled'] + M.TOOLBAR_COMPACT_SLACK - 1)
eq(_tw._toolbar_tier, 'icons',
   'toolbar: a step up inside the slack band is held off (hysteresis)')
_tb_resize(_need['labeled'] + M.TOOLBAR_COMPACT_SLACK)
eq(_tw._toolbar_tier, 'labeled',
   'toolbar: past the slack band it steps up to the labeled tier')

# The tier thresholds must cover the WORST case -- the TUI indicator (the yellow
# dot, shown only while TUI is active) visible -- so an active-TUI tab near a
# boundary does not overflow: the dot widens the layout, and a threshold cached
# without it would keep a richer tier a few px too long.
_dot_prev = _tw.tui_dot_action.isVisible()
_tw.tui_dot_action.setVisible(True)
_tb.layout().activate()
APP.processEvents()
ok(_tw._toolbar_full_width >= _tb.sizeHint().width(),
   'toolbar: the tier threshold covers the TUI-indicator width')
_tw.tui_dot_action.setVisible(_dot_prev)
_tb.layout().activate()
APP.processEvents()

_tw.deleteLater()
APP.processEvents()

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
