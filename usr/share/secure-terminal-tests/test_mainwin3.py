#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## set_* admin-locked returns + bell channels + run_command, clipboard-sanitizer controls, _find_tab matcher + server dispatch, the cross-tab OSC risk lamp, the batch-2 security findings, _handoff / adopt / lock degradation, session persistence + quit/close handlers.
##
## One of the MainWindow / ctl suites split out of the former single 5300-line
## test_mainwin.py. Shared setup, the global dialog/modal stubs, the font-DB
## stubs, the helpers and the pass/fail counters all live in
## test_mainwin_common; see it for the split rationale (fresh window + fresh
## monkeypatch baselines per suite eliminate cross-suite ordering deps). This
## suite builds its OWN MainWindow and reports via finish().

from test_mainwin_common import *          # noqa: F401,F403

win = MainWindow()
win.new_tab()

# Imported once in a section that now lives in an earlier suite.
from PyQt6.QtWidgets import QSystemTrayIcon      # noqa: E402
from PyQt6.QtCore import QObject as _QObject, pyqtSignal as _pyqtSignal  # noqa: E402
import json as _json                             # noqa: E402
import shutil                                     # noqa: E402

# --- set_* admin-locked returns + bell channels + run_command palette ---------
from PyQt6.QtWidgets import QMessageBox                          # noqa: E402
_o_info = QMessageBox.information
_o_warn = QMessageBox.warning
QMessageBox.information = staticmethod(lambda *_a, **_k: None)
QMessageBox.warning = staticmethod(lambda *_a, **_k: None)
_sl = set(win._locked)
try:
    # Each admin-locked setter must REFUSE: set the OPPOSITE of the current value while
    # locked, read the resulting state back, and assert it did NOT change. (canary: drop
    # the `_locked` check from any of these setters and the value flips -> its read-back
    # below fails; without the read-back the calls only proved they do not raise.)
    win._locked = {'osc_notice'}
    win.set_osc_notice(False)                # locked (default on) -> refused, stays on
    _lk_osc_notice = win._osc_notice is True
    win._locked = {'tui_autobox_notice'}
    win.set_tui_autobox_notice(False)        # locked (default on) -> refused, stays on
    _lk_autobox = win._tui_autobox_notice is True
    win._locked = {'tui'}
    win.set_tui(True)                        # locked (default CLI) -> refused, stays CLI
    _lk_tui = win.current().current_tui() is False
    win._locked = {'allow_title'}
    win.set_allow_title(True)                # locked (default off) -> refused, stays off
    _lk_allow_title = win.current().allow_title_enabled() is False
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
    ok(not _lk_bell and not _lk_osc and not _lk_osc_alias and _add_tray and _rm_tray
       and _lk_osc_notice and _lk_autobox and _lk_tui and _lk_allow_title,
       'admin locks refuse osc_notice / tui_autobox_notice / tui / allow_title / bell / '
       'osc_title / allow_title->osc_title; unlocked bell channels add+remove (read-back)')
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
    # default to '' so a missing/renamed /mode line records a clean FAIL below rather
    # than an IndexError that aborts the rest of the suite and drops its coverage.
    _mode_alts = _mode_line[0].split(None, 1)[1].split('|') if _mode_line else []
    eq(sorted(_mode_alts), sorted(_san.DISPLAY_MODES),
       'the /mode alternatives in the help equal sanitize.DISPLAY_MODES')
finally:
    win._locked = _sl
    QMessageBox.information = _o_info
    QMessageBox.warning = _o_warn

# --- clipboard-sanitizer controls (menu / setters / systray coupling) ----------
from secure_terminal import clipboard_watch as _cw                # noqa: E402
from PyQt6.QtCore import QMimeData                                 # noqa: E402
from PyQt6.QtWidgets import QMenu                                  # noqa: E402

_cw_saved = (_cw.set_autostart, _cw.autostart_enabled)
_o_avail_c = QSystemTrayIcon.isSystemTrayAvailable
_o_systray_c = win._systray
_o_warnany_c = win._clip_warn_any
_o_primary_c = win._is_primary
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
    _cw.set_autostart = lambda v: _calls.__setitem__('autostart', v)
    _cw.autostart_enabled = lambda: _calls.get('autostart_state', True)

    _calls.clear()
    win.set_clip_run(True)
    ok(win._clip_bg_watcher is not None,
       'clip: set_clip_run(True) starts the IN-PROCESS watcher (no daemon spawn -> no 2nd icon)')
    _first_bg = win._clip_bg_watcher
    win.set_clip_run(True)
    ok(win._clip_bg_watcher is _first_bg,
       'clip: set_clip_run(True) is idempotent (keeps the single in-process watcher)')
    win.set_clip_run(False)
    ok(win._clip_bg_watcher is None,
       'clip: set_clip_run(False) stops the in-process watcher')
    _calls.clear()

    # close-to-tray: with the tray on AND the in-process sanitizer running, a window
    # CLOSE hides to tray (keeps the process + sanitizer alive) instead of quitting.
    from PyQt6.QtGui import QCloseEvent                              # noqa: E402
    QSystemTrayIcon.isSystemTrayAvailable = staticmethod(lambda: True)
    win._systray = True
    win._apply_primary(True)            # the single tray icon exists only on the primary
    win._tray_icon()                    # the single tray icon must exist for close-to-tray
    win.set_clip_run(True)              # start the in-process watcher
    win._really_quit = False
    win.show()
    _ce = QCloseEvent()
    win.closeEvent(_ce)
    ok(not _ce.isAccepted() and win.isHidden(),
       'close-to-tray: a window close hides to tray + keeps the sanitizer (not a quit)')
    win.show()
    # while the in-process watcher runs: the menu shows Run-in-background ticked, and
    # Warn-on-any live-updates the IN-PROCESS watcher.
    _cmenu = QMenu()
    win._populate_clipboard_menu(_cmenu)
    _run_a = [a for a in _cmenu.actions() if a.text() == 'Run in the background'][0]
    ok(_run_a.isChecked(),
       'clip menu: Run-in-background ticked while the in-process watcher runs')
    win.set_clip_warn_any(True)
    ok(win._clip_bg_watcher._any_mode is True,
       'set_clip_warn_any live-updates the in-process watcher')
    win.set_clip_warn_any(False)

    # --tray hidden-to-tray setup forces the tray on (this session), creates the single
    # icon, and arms the in-process sanitizer -- without showing the window.
    win.set_clip_run(False)
    win._tray = None
    win._systray = False
    win.act_systray.setChecked(False)
    # A --tray launch forces the tray on for THIS session but must NOT persist it (a
    # launch mode, not a settings change): the display-only setChecked(True) must not
    # re-enter set_systray -> _persist, which would write systray=true and leave the tray
    # on for later NORMAL launches. (canary: without blockSignals the toggled signal fires
    # set_systray -> _persist.) None of the other _enter_tray_mode calls persist.
    _etm_persists = []
    _etm_o_persist = win._persist
    win._persist = lambda *a, **k: _etm_persists.append(1)
    try:
        win._enter_tray_mode()
    finally:
        win._persist = _etm_o_persist
    ok(win._systray and win._tray is not None,
       '_enter_tray_mode: forces the tray on and creates the single icon')
    ok(win._clip_bg_watcher is not None,
       '_enter_tray_mode: arms the in-process clipboard sanitizer')
    ok(_etm_persists == [],
       '_enter_tray_mode: does NOT persist (launch mode) -- no set_systray re-entry')
    win.set_clip_run(False)
    ok(win._tray is not None, '_enter_tray_mode armed the single tray icon')
    win._tray.hide()
    win._tray = None
    _calls.clear()

    win.set_clip_warn_any(True)
    ok(win._clip_warn_any is True, 'clip: set_clip_warn_any records the setting')
    win.set_clip_warn_any(False)

    ## Finding-2 regression: clip_warn_any is written with a single-key update; a later
    ## terminal _persist (a bulk write for some OTHER setting) must PRESERVE a value
    ## another instance wrote on disk, not clobber it with this terminal's stale value.
    from secure_terminal import settings as _st_clip   # noqa: PLC0415
    # isolate the privileged dirs to an EMPTY temp dir: a real admin lock= on
    # clip_warn_any (a supported /etc config) would otherwise pin the value and
    # false-fail this no-clobber check.
    _clip_sysd = tempfile.mkdtemp(prefix='st-clipsys-')
    _clip_orig_sysd = _st_clip._system_dirs
    _st_clip._system_dirs = lambda: [_clip_sysd]
    try:
        _st_clip.set_user_key('clip_warn_any', 'true')  # another instance sets it ON on disk
        win._clip_warn_any = False                       # this terminal's stale in-memory value
        win._persist()                                   # a bulk write for another setting
        ok(_st_clip.load().get('clip_warn_any') == 'true',
           'terminal _persist preserves an externally-set clip_warn_any (no clobber)')
    finally:
        _st_clip._system_dirs = _clip_orig_sysd
        shutil.rmtree(_clip_sysd, ignore_errors=True)

    # Fix-3: Global-settings Apply must NOT write clip_warn_any when the user did not
    # toggle it here -- another instance may have changed it on disk since the dialog
    # opened, so a theme-only Apply must leave that value untouched.
    _clip_sysd3 = tempfile.mkdtemp(prefix='st-clipsys3-')
    _clip_orig_sysd3 = _st_clip._system_dirs
    _st_clip._system_dirs = lambda: [_clip_sysd3]
    try:
        win._clip_warn_any = False                       # dialog opened with it OFF
        _st_clip.set_user_key('clip_warn_any', 'true')   # another instance turns it ON afterwards
        win._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'box',
                           'colors': True, 'line_edits': True, 'scrollback': 1000,
                           'paste_delay': 3, 'escape_limit': 4096, 'persist': False,
                           'clip_warn_any': False})       # unchanged from win._clip_warn_any
        eq(_st_clip.load().get('clip_warn_any'), 'true',
           'apply: a clip_warn_any unchanged in the dialog is not clobbered')
        # ...but a value the user DID toggle here is written to DISK.
        _st_clip.set_user_key('clip_warn_any', 'false')  # reset disk so the write shows
        win._clip_warn_any = False
        win._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'box',
                           'colors': True, 'line_edits': True, 'scrollback': 1000,
                           'paste_delay': 3, 'escape_limit': 4096, 'persist': False,
                           'clip_warn_any': True})        # toggled ON in the dialog
        ok(win._clip_warn_any is True
           and _st_clip.load().get('clip_warn_any') == 'true',
           'apply: a clip_warn_any toggled in the dialog is written to disk')
    finally:
        _st_clip._system_dirs = _clip_orig_sysd3
        shutil.rmtree(_clip_sysd3, ignore_errors=True)

    # _persist must DROP a key locked at STARTUP (win._locked) even when it is not
    # currently locked in the system config -- i.e. it passes its startup snapshot
    # to update_user. Isolate the privileged dirs to an empty dir so load() locks
    # nothing; only win._locked should cause the drop.
    _pl_sysd = tempfile.mkdtemp(prefix='st-plsys-')
    _pl_usrd = tempfile.mkdtemp(prefix='st-plusr-')
    _pl_o_sys, _pl_o_usr = _st_clip._system_dirs, _st_clip._user_config_dir
    _pl_o_locked, _pl_o_theme = set(win._locked), win._default_theme
    _pl_o_zoom = win._default_zoom
    _st_clip._system_dirs = lambda: [_pl_sysd]
    _st_clip._user_config_dir = lambda: _pl_usrd
    try:
        win._locked = frozenset({'theme'})              # theme locked at launch
        win._default_theme = 'dark'
        win._default_zoom = 175          # a NON-default key so "writes the rest" has one to check
        win._persist()
        _pw: dict[str, str] = {}
        _st_clip._parse_into(_st_clip.user_config_file(), _pw)
        ok('theme' not in _pw and 'zoom' in _pw,
           '_persist drops a startup-locked key (theme) but writes the rest')
    finally:
        win._locked, win._default_theme = _pl_o_locked, _pl_o_theme
        win._default_zoom = _pl_o_zoom
        _st_clip._system_dirs, _st_clip._user_config_dir = _pl_o_sys, _pl_o_usr
        shutil.rmtree(_pl_sysd, ignore_errors=True)
        shutil.rmtree(_pl_usrd, ignore_errors=True)

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
    (_cw.set_autostart, _cw.autostart_enabled) = _cw_saved
    QSystemTrayIcon.isSystemTrayAvailable = _o_avail_c
    win._systray = _o_systray_c
    win._clip_warn_any = _o_warnany_c
    win._apply_primary(_o_primary_c)
    win._clip_reviewer = None
    if win._clip_bg_watcher is not None:      # stop any in-process watcher this block left
        win._clip_bg_watcher.stop()
        win._clip_bg_watcher = None
    win._really_quit = False
    if win._tray is not None:                 # drop the tray the close-to-tray test created
        win._tray.hide()
        win._tray = None
    win.show()                                # undo the close-to-tray hide()
    APP.clipboard().setMimeData(_o_clip_c)

# tray Quit (close-to-tray TEARDOWN): an explicit Quit sets _really_quit so the SAME
# close tears down instead of hiding, even with the background sanitizer running. A
# throwaway window (closing destroys it), so it never disturbs the shared `win`.
_qsta_o3 = QSystemTrayIcon.isSystemTrayAvailable
QSystemTrayIcon.isSystemTrayAvailable = staticmethod(lambda: True)
_qw = MainWindow()
_qw.new_tab()
_qw._systray = True
_qw._tray_icon()
_qw.set_clip_run(True)                  # bg watcher running -> close-to-tray would else hide
_qw._force_close = True                 # no running-program confirm on teardown
_qw._quit_from_tray()                   # sets _really_quit + close() -> closeEvent tears down
ok(_qw._really_quit and _qw._clip_bg_watcher is None,
   'tray Quit tears down (really_quit set + sanitizer stopped), NOT hide-to-tray')
QSystemTrayIcon.isSystemTrayAvailable = _qsta_o3

# ClipboardWatcher.stop() is idempotent: a second stop (its clipboard signal already
# disconnected) hits the disconnect-failure branch harmlessly.
_idem_w = _cw.ClipboardWatcher(APP, theme='dark', watch=True)
_idem_w.stop()
_idem_w.stop()
ok(True, 'ClipboardWatcher.stop() is idempotent (a double stop does not raise)')

# a tab terminal's right-click menu gains the app toggles through its MainWindow
from PyQt6.QtCore import QPoint                                    # noqa: E402
_rcmenu = win.current()._reviewed_context_menu(QPoint(0, 0))
ok(any(a.text() == 'System tray icon' for a in _rcmenu.actions()),
   'context menu: a tab terminal gains the app toggles via its window')

# icon helpers build a NON-NULL icon (themed, path, or letter fallback). A QIcon is
# never None even on failure -- it returns a null icon -- so assert not .isNull().
ok(not M._app_icon().isNull(), '_app_icon returns a non-null icon')
ok(not M._letter_icon('A', '#3b82f6').isNull(), '_letter_icon renders a fallback icon')

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
## The drop-in is consumed; remove it so its tui=true/scrollback etc. do not leak
## into the ~dozen later MainWindow() instances built in this file.
os.remove(os.path.join(_cfgd2, '80-init.conf'))

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

# --- _find_tab matcher forms + the single-instance server dispatch ------------
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
win._on_osc_used(_esc_term, 'osc_other', -1)     # must NOT clobber it
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

# The advisory banner is a top OVERLAY, not a layout item: showing it must NOT resize
# the terminal grid. As a layout sibling it shrank the grid, SIGWINCHing the child --
# which re-prompts the shell and reflows a full-screen program (the broken-TUI-shot
# regression). It reserves a winsize-neutral top INSET instead, so content renders
# below the banner. Canary: against the old (layout) code _rows shrinks here.
_ov = MainWindow()
_ov.resize(900, 640)
_ov.show()
pump(50)
_ov.set_tui(True)
# settle the offscreen layout fully before sampling the baseline grid, so a
# mid-settle read cannot masquerade as a banner-induced change.
for _ in range(6):
    pump(50)
_ovt = _ov.current()
_ov_rows0, _ov_cols0 = _ovt._rows, _ovt._cols
_ov._osc_notified = {p for p in _ov._osc_notified if p[0] is not _ovt}
_ov._advisories.pop(_ovt, None)
_ov._on_osc_used(_ovt, 'osc_hyperlink', 8)      # raise an OSC advisory (a type NOT muted by default)
pump(50)
ok(wait_for(lambda: _ov._banner.isVisible()),
   'advisory overlay: the banner is shown for the current tab')
eq(_ovt._rows, _ov_rows0,
   'advisory overlay: showing the banner does NOT change the grid rows (no SIGWINCH)')
eq(_ovt._cols, _ov_cols0,
   'advisory overlay: showing the banner does NOT change the grid cols')
ok(_ovt._chrome_top_inset > 0,
   'advisory overlay: the terminal reserves a top inset so content sits below the banner')
_ov_inset0 = _ovt._chrome_top_inset
_ov._position_banner()                        # idempotent re-place (same width/font)
eq(_ovt._chrome_top_inset, _ov_inset0,
   'advisory overlay: re-placing the banner at the same size is a no-op inset')
_ov._dismiss_advisory()                       # the X button: hide + release the inset
pump(50)
ok(wait_for(lambda: not _ov._banner.isVisible()),
   'advisory overlay: dismiss hides the banner')
eq(_ovt._chrome_top_inset, 0,
   'advisory overlay: dismissing releases the top inset')
eq(_ovt._rows, _ov_rows0,
   'advisory overlay: hiding the banner also leaves the grid rows unchanged')
_ov.close()

# Smoke test: closing the LAST tab while the banner is up must not crash. The
# invariant is that current() is live whenever the banner shows, but the close/
# resize/_refresh ordering is subtle, so _position_banner keeps a None-guard as a
# belt-and-suspenders against a real-GUI timing this offscreen harness cannot force.
_ov2 = MainWindow()
_ov2.resize(900, 640)
_ov2.show()
pump(50)
_ov2._on_osc_used(_ov2.current(), 'osc_hyperlink', 8)   # a type NOT muted by default
pump(20)
ok(wait_for(lambda: _ov2._banner.isVisible()),
   'advisory overlay: banner shown before the last-tab close')
_ov2.close_tab(0)                             # empties the window with the banner still visible
pump(20)
ok(True, 'advisory overlay: closing the last tab with the banner up does not crash')
_ov2.close()

# --- OSC risk lamp is cross-tab -------------------------------------------------
# OSC side-effects (clipboard/title/notify) are SYSTEM-global and a BACKGROUND tab
# keeps honoring them, so the lamp reflects risk across ALL tabs, not just the
# current one -- a live OSC tab in the background keeps the lamp non-green even while
# a CLI tab is in front (otherwise the "no live risk" state would be a lie).
_xw = MainWindow()
_xw.resize(800, 500)
_xw.show()
pump(30)
_xw.set_osc('osc_clipboard', True)            # arm high-risk on tab 0 (+ new-tab default)
_xw.new_tab(tui=False)                         # tab 1 (CLI), created while tab 0 is also CLI
pump(20)
_xfront = _xw.current()
_xbg = next(t for t in _xw._real_terms() if t is not _xfront)
_xw.tabs.setCurrentWidget(_xbg)               # bring tab 0 to front to flip it to TUI
# setCurrentWidget is async: set_tui acts on current(), so the switch MUST land first
# or set_tui misfires on the old tab under load (the root of the parallel-coverage flake).
wait_for(lambda: _xw.current() is _xbg)
_xw.set_tui(True)                             # tab 0: live in TUI
_xw.tabs.setCurrentWidget(_xfront)            # tab 1 (CLI) back in front
wait_for(lambda: _xw.current() is _xfront)
ok(wait_for(lambda: not _xfront.tui_active() and _xbg.tui_active()),
   'cross-tab OSC: front tab is CLI, background tab is in TUI')
ok(wait_for(lambda: _xw._osc_level()[0] == '#e5484d'),
   'cross-tab OSC: a background TUI tab with clipboard live keeps the lamp red on a CLI front tab')
_xw.tabs.setCurrentWidget(_xbg)               # drop the live (background) tab out of TUI
wait_for(lambda: _xw.current() is _xbg)       # switch must land before set_tui acts on current()
_xw.set_tui(False)
ok(wait_for(lambda: _xw._osc_level()[0] == '#1f8a54'),
   'cross-tab OSC: lamp returns to green once no tab is in TUI')
# NOT closed: destroying a window that held a background-TUI tab segfaults Qt's
# offscreen teardown mid-suite; the suite's os._exit(0) skips that teardown, as it
# does for the other long-lived windows here.

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

# Exercise the single-instance server path (_on_instance_connection + on_ready +
# _dispatch_request + the reply framing/teardown) DETERMINISTICALLY, via a recording fake
# QLocalSocket. Servicing a REAL accepted socket in-process from this long-lived suite
# intermittently SIGSEGVs inside Qt's QLocalSocket readyRead DISPATCH (the server accepts
# the connection, but the crash is in Qt C++ before the Python slot body runs) -- a
# Qt-level race, platform-independent (offscreen AND wayland alike) and reproducible only
# under the suite's accumulated state, NOT a fault in our code. A fake socket drives the
# same server slots with no Qt socket dispatch, so the coverage is deterministic. The real
# end-to-end socket handoff between separate processes is covered by test_instances.
# _FakeConn / _FakeServer (the recording QLocalSocket + server stand-ins) live in
# test_mainwin_common -- they are shared with the IPC read-path tests in a later
# split suite -- and arrive via `from test_mainwin_common import *`.


def _unframe(buf):
    length = int.from_bytes(buf[:4], 'little')
    return _json.loads(buf[4:4 + length].decode('utf-8'))


_hsrv = MainWindow()
_hc = _FakeConn()
_hsrv._server = _FakeServer(_hc)
_hsrv._on_instance_connection()
_hc.feed(M.ipc.frame(_json.dumps({'op': 'ping'}).encode('utf-8')))
_hrep = _unframe(_hc.written) if _hc.written else None
ok(isinstance(_hrep, dict) and _hrep.get('ok') and _hrep.get('pid') == os.getpid(),
   'IPC: a framed single-instance ping is dispatched and answered')
ok(_hc.disconnected_from_server, 'IPC: the server disconnects the socket after replying')
# a trailing readyRead after the reply is a guarded no-op (no second dispatch, no UAF)
_hw = len(_hc.written)
_hc.feed(b'trailing')
ok(len(_hc.written) == _hw, 'IPC: a trailing readyRead after finish is ignored')
# a disconnected delivered after finish is idempotent (the `finished` latch)
_hc.disconnected.emit()
ok(True, 'IPC: a post-reply disconnected is idempotent')
# a partial (sub-header) frame buffers, no reply yet
_hc2 = _FakeConn()
_hsrv._server = _FakeServer(_hc2)
_hsrv._on_instance_connection()
_hc2.feed(b'\x02\x00')
ok(_hc2.written == b'' and not _hc2.disconnected_from_server,
   'IPC: a partial frame is buffered, not answered')
# an over-long frame is rejected (abort), never dispatched
_hc3 = _FakeConn()
_hsrv._server = _FakeServer(_hc3)
_hsrv._on_instance_connection()
_hc3.feed((0xFFFFFFFF).to_bytes(4, 'little'))
ok(_hc3.aborted, 'IPC: an over-long frame aborts the connection')
# a bare connect (no framed request) is reaped via disconnected
_hc4 = _FakeConn()
_hsrv._server = _FakeServer(_hc4)
_hsrv._on_instance_connection()
_hc4.disconnected.emit()
ok(_hc4.disconnected_from_server, 'IPC: a bare connect is reaped on disconnect')
# a spurious newConnection with nothing pending is a no-op (nextPendingConnection None)
_hsrv._server = _FakeServer(None)
_hsrv._on_instance_connection()
ok(True, 'IPC: newConnection with no pending connection is a no-op')
_hsrv.deleteLater()
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

# REGRESSION (socket must not be STOLEN from a live primary): a second instance that
# finds a live listener on the group socket must stay server-less rather than rebind. A
# mistaken always-bind (removeServer + listen regardless) would steal the live socket. The
# gate is start_instance_server -> _bind_instance_server -> the REAL ipc.socket_is_live
# raw-connect probe. A bare QLocalServer stands in for the primary's bound socket, so the
# claim/steal DECISION runs against a REAL live socket WITHOUT this suite servicing an
# accepted connection in-process -- servicing a real accepted QLocalSocket amid the suite's
# accumulated state segfaults in Qt's readyRead dispatch (QAbstractSocketPrivate::
# canReadNotification), platform-independently. The full accept/serve/reply path is covered
# end-to-end by the subprocess test_instances; the server slot itself by the fake handoff above.
from PyQt6.QtNetwork import QLocalServer as _QLocalServer   # noqa: E402
M.ipc.ensure_socket_dir()
_QLocalServer.removeServer(M.ipc.socket_path('steal-group'))
_bare_primary = _QLocalServer()
_bare_primary.setSocketOptions(_QLocalServer.SocketOption.UserAccessOption)
ok(_bare_primary.listen(M.ipc.socket_path('steal-group')),
   'a bound listener stands in for a live primary')
ok(M.ipc.socket_is_live('steal-group'),
   'ipc.socket_is_live: a bound listener answers a raw connect')
ok(not M.ipc.socket_is_live('no-such-live-group'),
   'ipc.socket_is_live: an absent socket -> not live (connect refused)')
_second = MainWindow()
_second.start_instance_server('steal-group')     # a live peer owns it
ok(getattr(_second, '_server', None) is None,
   'start_instance_server: a live peer -> the second instance stays server-less')
ok(M.ipc.socket_is_live('steal-group'),
   'start_instance_server: the live peer still owns the socket (not stolen)')
_second.deleteLater()
_bare_primary.close()
APP.processEvents()
# a genuinely STALE socket file (no listener) is reclaimed AND the now-free group is
# claimed (start_instance_server's claim path: bind + adopt; no client connects, so the
# adopted server never services an accepted socket here).
_stale_grp = 'stale-group'
_stale_path = M.ipc.socket_path(_stale_grp)
os.makedirs(os.path.dirname(_stale_path), exist_ok=True)
with open(_stale_path, 'w', encoding='utf-8') as _sf3:
    _sf3.write('')                               # a plain file: exists, nobody listening
ok(not M.ipc.socket_is_live(_stale_grp),
   'ipc.socket_is_live: a stale socket file is not live')
_reclaim = MainWindow()
ok(_reclaim.start_instance_server(_stale_grp) == 'claimed',
   'start_instance_server: a stale socket is cleared and the free group is claimed')
ok(getattr(_reclaim, '_server', None) is not None,
   'start_instance_server: the reclaimed group has a live server')
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

# adopt_instance_server drains a connection that queued before the handler wired. Driven
# with a fake QLocalServer + fake conn so the drain loop + the wired slot run with no live
# socket dispatch (see the handoff note above); the fake conn is served a real framed ping
# to prove the drained connection was wired to _on_instance_connection.
class _FakePendingServer(_QObject):
    """Stand-in QLocalServer with exactly one pre-queued connection to drain."""

    newConnection = _pyqtSignal()

    def __init__(self, conn):
        super().__init__()
        self._pending = [conn]

    def hasPendingConnections(self):
        return bool(self._pending)

    def nextPendingConnection(self):
        return self._pending.pop(0) if self._pending else None


_ad_conn = _FakeConn()
_ad_srv = _FakePendingServer(_ad_conn)
_ad_win = MainWindow()
_ad_win.adopt_instance_server(_ad_srv, 'adopt-drain')
ok(_ad_win._server is _ad_srv and not _ad_srv.hasPendingConnections(),
   'adopt_instance_server: adopts the server and drains the pre-queued connection')
_ad_conn.feed(M.ipc.frame(_json.dumps({'op': 'ping'}).encode('utf-8')))
ok(_ad_conn.written != b'' and _unframe(_ad_conn.written).get('ok'),
   'adopt_instance_server: the drained connection was wired and is served')
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
# claude (ai-review): a SYMLINK planted at the predictable lock path must not be followed.
# O_NOFOLLOW turns it into an ELOOP that the SAME self-heal (unlink+retry) clears -- the
# symlink is replaced by a real regular file and its target is never opened through the
# link. (O_NOFOLLOW is not bypassed by root, so this holds under CI's root too.) canary:
# without O_NOFOLLOW os.open follows the symlink and the lock path stays a symlink.
_lsym_victim = os.path.join(os.path.dirname(_lp), 'lock-victim')
with open(_lsym_victim, 'w', encoding='utf-8') as _lvh:
    _lvh.write('KEEP-ME')
os.symlink(_lsym_victim, _lp)
_lsfd = M._acquire_group_lock(_lg)
ok(_lsfd is not None and not os.path.islink(_lp) and os.path.isfile(_lp),
   '_acquire_group_lock: a symlink at the lock path is self-healed (O_NOFOLLOW), not followed')
with open(_lsym_victim, encoding='utf-8') as _lvh:
    ok(_lvh.read() == 'KEEP-ME',
       '_acquire_group_lock: the symlink target is untouched (never opened through the link)')
if _lsfd is not None:
    os.close(_lsfd)
if os.path.exists(_lp) and not os.path.isdir(_lp):
    os.remove(_lp)
os.remove(_lsym_victim)
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
_o_sig_close = M._signal_close_windows
try:
    _sig_close_calls = []
    M._signal_close_windows = lambda _app: _sig_close_calls.append(_app)
    win._force_close = False                 # crash-safe path must NOT force-close
    import signal as _sig2
    # Save the REAL SIGINT/SIGTERM/SIGHUP dispositions so the finally can restore
    # them: _install_signal_quit replaces them PROCESS-WIDE, and without a restore a
    # signal delivered to this process later (e.g. a CI process-group signal) would
    # run secure_terminal's handler instead of the original.
    _o_sig_handlers = {_s: _sig2.getsignal(_s)
                       for _s in (_sig2.SIGINT, _sig2.SIGTERM, _sig2.SIGHUP)}
    M._install_signal_quit(APP)             # installs SIGINT/SIGTERM/SIGHUP handlers
    _h = _sig2.getsignal(_sig2.SIGINT)
    if callable(_h):
        _h(_sig2.SIGINT, None)              # fire the handler
    # The close is QUEUED (QTimer.singleShot), not synchronous: it must NOT have
    # run yet -- that is exactly what lets a signal arriving before exec() still be
    # honored, and what keeps the confirm modal off the teardown path. CANARY: the
    # old handler force-closed here (set _force_close, queued app.quit) so a stray
    # SIGTERM/SIGHUP killed a running program with no confirmation.
    ok(not _sig_close_calls, 'signal handler defers the close (does not run it synchronously)')
    ok(win._force_close is False,
       'signal handler no longer force-closes -- the crash-safe confirm path runs instead')
    APP.processEvents()
    ok(_sig_close_calls == [APP],
       'signal handler queues the live-loop window close (honored once the loop runs)')
    # A second signal while a close is already pending does NOT stack another (the
    # mocked close never clears app._signal_close_pending, mimicking a prompt still up).
    _sig_close_calls.clear()
    if callable(_h):
        _h(_sig2.SIGINT, None)
    APP.processEvents()
    ok(not _sig_close_calls, 'a second signal while a close is pending is ignored (no stacked prompt)')
finally:
    M._signal_close_windows = _o_sig_close
    APP._signal_close_pending = False        # do not leave the global handler wedged
    for _s, _oh in _o_sig_handlers.items():
        _sig2.signal(_s, _oh)                # restore the real SIGINT/SIGTERM/SIGHUP handlers

# _signal_close_windows: a terminate signal is ATOMIC across every window -- confirm
# ONCE, and a veto keeps EVERY window (never close an idle one while another's prompt
# is unanswered). On confirm, force every window closed. A fake app drives it so the
# sweep does not tear down sibling test windows.
class _SigFakeApp:
    def __init__(self, windows):
        self._windows = windows
        self._signal_close_pending = True    # set by the real handler before deferring
        self.quit_calls = 0
    def topLevelWidgets(self):
        return self._windows
    def quit(self):
        self.quit_calls += 1

def _mk_sig_window(running, shut_sink):
    _w = MainWindow()
    _w.set_persist_session(False)
    _w.clear_saved_session()
    _w._confirm_close = True                  # arm the confirm-on-close prompt
    _has = (lambda: True) if running else (lambda: False)
    for _i in range(_w.tabs.count()):
        _w.tabs.widget(_i).has_foreground_program = _has
        _w.tabs.widget(_i).shutdown = lambda: shut_sink.append(True)
    return _w

# grok's case: window A is an idle shell, window B runs a program. A veto must keep
# BOTH -- the old per-window loop closed idle A before B's prompt was answered No, so
# the terminate applied only partly. (canary: fails on a per-window close.)
_shut_a: list[bool] = []
_shut_b: list[bool] = []
_win_a = _mk_sig_window(False, _shut_a)
_win_b = _mk_sig_window(True, _shut_b)
_sig_asked: list[int] = []


def _sig_veto_q(*_a, **_k):
    _sig_asked.append(1)
    return _No


## Save the harness default (test_mainwin_common installs an always-Yes question
## so no modal blocks the headless run) and restore it after this block -- else
## the always-No / always-Yes stubs below leak to any later confirm dialog.
_o_sig_q = QMessageBox.question
QMessageBox.question = staticmethod(_sig_veto_q)
_fa = _SigFakeApp([_win_a, _win_b])
M._signal_close_windows(_fa)
ok(_sig_asked and not _shut_a and not _shut_b and not _win_a._force_close
   and not _win_b._force_close and _fa.quit_calls == 0,
   'signal terminate is atomic: a veto keeps EVERY window, even an idle one (no partial close)')
ok(_fa._signal_close_pending is False, 'the signal-terminate guard re-arms after a veto')
# confirm -> every window is force-closed and shut down
QMessageBox.question = staticmethod(lambda *_a, **_k: _Yes)
M._signal_close_windows(_fa)
ok(_shut_a and _shut_b and _win_a._force_close and _win_b._force_close,
   'a confirmed terminate force-closes and shuts down every window')
# nothing running -> no prompt, closes anyway
_shut_c: list[bool] = []
_win_c = _mk_sig_window(False, _shut_c)
_asked_c: list[int] = []


def _sig_noask_q(*_a, **_k):
    _asked_c.append(1)
    return _No


QMessageBox.question = staticmethod(_sig_noask_q)
M._signal_close_windows(_SigFakeApp([_win_c]))
ok(not _asked_c and _shut_c and _win_c._force_close,
   'a terminate with no running program closes without asking')
# no windows -> quit
_fa_empty = _SigFakeApp([])
M._signal_close_windows(_fa_empty)
ok(_fa_empty.quit_calls == 1 and _fa_empty._signal_close_pending is False,
   'a signal with no windows left honors the terminate by quitting')
for _w in (_win_a, _win_b, _win_c):
    _w.deleteLater()
APP.processEvents()
QMessageBox.question = _o_sig_q          # restore the shared always-Yes default

# _quiet_font_warnings installs a message handler that drops the font-db noise
M._quiet_font_warnings()
ok(True, '_quiet_font_warnings installs the noise-filtering message handler')


finish('mainwin3')
