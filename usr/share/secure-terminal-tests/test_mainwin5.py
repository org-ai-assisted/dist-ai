#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## app.aboutToQuit teardown, the CLASH shortcut/lock/accelerator audits, the responsive toolbar, container theming + render sweep, SEC-10, the per-tab cgroup, OSC-notice defaults + toggles, tab-bar elide, Copy Transcript File Path, and the Part B config-persistence (non-default overrides only).
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

# Imported once in sections that now live in earlier suites.
from PyQt6.QtWidgets import QMenu                 # noqa: E402
from PyQt6.QtCore import QTimer                   # noqa: E402
from PyQt6.QtGui import QCloseEvent               # noqa: E402

# global settings persist across restart (#68): _apply_global writes the CHANGED
# (non-default) settings to the config so a fresh window reads them back. A value
# left at its default is omitted (the default applies on reload) -- so this asserts
# NON-default values, which are the ones persistence must carry.
import secure_terminal.settings as _ps                         # noqa: E402
_pcfg_prev = os.environ.get('XDG_CONFIG_HOME')
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp(prefix='st-persist-')
try:
    _pw = MainWindow()
    ok(_pw._tui_autobox_notice,
       'tui_autobox_notice loads default-on from a fresh (absent) config')
    _pw._apply_global({'theme': 'dark', 'zoom': 175, 'mode': 'reveal', 'colors': True, 'line_edits': True,
                       'tui': False, 'osc': {}, 'osc_notice': False,
                       'tui_autobox_notice': False,
                       'scrollback': 7000, 'paste_delay': 5, 'escape_limit': 65536,
                       'persist': True})
    ok(not _pw._tui_autobox_notice and not _pw.act_tui_autobox_notice.isChecked(),
       '_apply_global stores tui_autobox_notice and mirrors it on the menu action')
    _pc = _ps.load()
    eq(_pc.get('theme'), 'dark', 'settings persist: a non-default theme is written to config')
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
        _other: object
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

# claude (#9): an ABSENT granular OSC key must fall back to the feature's DEFAULT, not a
# forced False. With the default ON (set_allow_title True seeds osc_title/osc_notify on) and
# a saved osc dict that OMITS osc_title, the restored tab must inherit the enabled default.
# The old osc_state.get(key, False) handed _saved_bool a real bool for an absent key, pinning
# it OFF even where the default was ON (a session saved before the feature key existed).
_p9w = MainWindow(); _p9w._locked = set()
_p9w.set_allow_title(True)                       # seeds osc_title/osc_notify defaults ON
_p9w._restore_tab({'osc': {'osc_clipboard': 'false'}})   # dict present, osc_title ABSENT
ok(_p9w.current().osc_enabled('osc_title'),
   'claude #9: an absent OSC key restores to the enabled default, not a forced False')
_p9w.close(); _p9w.deleteLater(); APP.processEvents()

# claude (ai-review): _restore_tab must seed the global 'always allow clipboard READ (no
# prompt)' default, exactly as _apply_osc_defaults does for a NEW tab. The old restore
# path applied the per-key OSC capabilities but never called set_clipboard_read_always, so
# every tab restored from a saved session silently reverted to per-request prompting --
# dropping the user's persisted 'no prompt' choice. (canary: old code left the term at its
# constructor default False.)
_craw = MainWindow(); _craw._locked = set()
_craw._osc_clipboard_read_always = True           # persisted 'always allow read, no prompt'
_craw._restore_tab({'osc': {'osc_clipboard_read': 'true'}})
ok(_craw.current()._clipboard_read_always is True,
   'claude: a restored tab inherits the global always-allow-clipboard-read default')
_craw.close(); _craw.deleteLater(); APP.processEvents()

# grok: _on_tab_step must SKIP a disabled restore placeholder and keep walking
# (wrapping) to the next real tab, not dead-end on it -- a single `if enabled` did.
# Indices are computed from count() (a fresh MainWindow already owns one live tab).
# Clear any session an earlier section in this suite persisted to the state dir, so
# this window opens with only its fresh live tab (the original relied on the
# clear_saved_session calls that now live in a different split suite).
_ds.clear()
_stw = MainWindow()
_stw.new_tab()                            # a SECOND live tab (idx 1): the start index must
                                          # DIFFER from the wrap target (live 0), else a no-op
                                          # _on_tab_step would also "pass" (start == expected end)
_stw._add_placeholder_tab({'name': 'ph', 'cwd': '/tmp'}, _stw.tabs.count())  # nosec B108 (inert cwd string) -- placeholder LAST
_stw_phi = _stw.tabs.count() - 1
_stw.tabs.setCurrentIndex(_stw_phi - 1)   # the last LIVE tab (idx 1), just before the placeholder
_stw._on_tab_step(1)                      # PageDown: -> ph (skip) -> wrap -> live 0
ok(_stw.tabs.currentIndex() == 0,
   'grok: tab-step from the last live tab skips a disabled placeholder and wraps to live 0')
_stw.tabs.removeTab(_stw_phi)             # drop the orphan before close (closeEvent covered below)
_stw.close(); _stw.deleteLater(); APP.processEvents()

# claude: closeEvent + _session_tabs iterate REAL terminals only -- a restore
# placeholder that survives the deferred-restore drain (an unknown placeholder is a
# safe swap no-op) must never reach has_foreground_program/shutdown/toPlainText, which a
# bare QWidget lacks. Pre-fix those bulk-over-all-tabs loops abort the process on it.
# Direct closeEvent(QCloseEvent()) so a pre-fix AttributeError is a catchable failure
# here, not the uncatchable Qt-dispatch abort that .close() would raise.
_ds.clear()                                                    # no stray session to restore
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

# --- per-tab cgroup: with a delegated base, each new tab gets its own limited
# cgroup (main.py _alloc_cgroup -> resource_isolation.create_tab). A fake base dir
# stands in for the delegated hierarchy; this covers the window-side plumbing, the
# module's own paths are unit-tested in test_modules and the live containment in the
# sandbox cgroup suite.
import tempfile as _tf_mcg                                                       # noqa: E402
import shutil as _sh_mcg                                                         # noqa: E402
from secure_terminal.resource_isolation import PIDS_MAX as _PIDS_MAX             # noqa: E402
_cgbase = _tf_mcg.mkdtemp(prefix='st-cgm-')
_wcg = MainWindow(cg_base=_cgbase)          # ctor auto-opens the first tab
_seq0 = _wcg._cg_seq
_wcg.new_tab()
eq(_wcg._cg_seq, _seq0 + 1, 'cgroup: each new tab advances the per-tab name counter')
# name carries the pid so concurrent instances / a crashed instance's leftover never collide
_tabN = os.path.join(_cgbase, 'tab-%d-%d' % (os.getpid(), _seq0))
ok(os.path.exists(os.path.join(_tabN, 'pids.max')),
   'cgroup: new_tab creates a per-tab cgroup when a base is delegated')
with open(os.path.join(_tabN, 'pids.max'), encoding='ascii') as _mh:
    ok(_mh.read().strip() == str(_PIDS_MAX),
       'cgroup: the per-tab cgroup carries the pids.max ceiling')

# ai-review #1: an admin lock on clip_run / clip_autostart must make the setters no-ops
# AND grey the tray controls (mirrors clip_warn_any's enforcement). Canary: unguarded,
# both setters run and both controls stay enabled despite the lock.
from PyQt6.QtWidgets import QMenu as _QMenu_lk, QSystemTrayIcon as _QSTI_lk   # noqa: E402
import secure_terminal.clipboard_watch as _cw_lk                              # noqa: E402
_lkw = MainWindow()
_lkw._locked = set(_lkw._locked) | {'clip_run', 'clip_autostart'}
_lkw._systray = True
_o_avail_lk = _QSTI_lk.isSystemTrayAvailable
_QSTI_lk.isSystemTrayAvailable = staticmethod(lambda: True)   # tray present: lock is the only gate
_lk_probe = []
_o_sa = _cw_lk.set_autostart
_cw_lk.set_autostart = lambda _v: _lk_probe.append('auto')
try:
    _lkw.set_clip_run(True)          # locked -> must return before creating a watcher
    _lkw.set_clip_run(False)
    _lkw.set_clip_autostart(True)    # locked -> must return before set_autostart
    ok(not _lk_probe and _lkw._clip_bg_watcher is None,
       'ai-review #1: set_clip_run / set_clip_autostart are no-ops when admin-locked')
    _lkm = _QMenu_lk()
    _lkw._populate_clipboard_menu(_lkm)
    _lk_by = {a.text(): a for a in _lkm.actions()}
    ok(not _lk_by['Run in the background'].isEnabled(),
       'ai-review #1: Run-in-background greyed when clip_run admin-locked')
    ok(not _lk_by['Start on login'].isEnabled(),
       'ai-review #1: Start-on-login greyed when clip_autostart admin-locked')
finally:
    _cw_lk.set_autostart = _o_sa
    _QSTI_lk.isSystemTrayAvailable = _o_avail_lk
_lkw.close()
_wcg.close()
APP.processEvents()
# --- OSC-notice defaults -------------------------------------------------------
# The title/palette OSC notices fire on routine output, so they are muted by
# DEFAULT (OSC_NOTICE_DEFAULT_OFF) when the key is ABSENT. A present value (even
# empty) is the user's own choice. These canary-fail on the pre-change code
# (which seeded _osc_notice_off empty regardless of the key's presence).
import tempfile as _tf_nm                                        # noqa: E402


def _win_with_conf(entries):
    """Build a MainWindow whose ONLY user config is `entries` (a KEY->value dict,
    or None for no user file) in an isolated XDG dir. Returns (win, cfg_dir)."""
    _d = _tf_nm.mkdtemp()
    _confdir = os.path.join(_d, 'secure-terminal.d')
    os.makedirs(_confdir)
    if entries is not None:
        with open(os.path.join(_confdir, '20_auto-generated.conf'), 'w',
                  encoding='utf-8') as _fh:
            for _k, _v in entries.items():
                _fh.write('%s=%s\n' % (_k, _v))
    _o = os.environ.get('XDG_CONFIG_HOME')
    os.environ['XDG_CONFIG_HOME'] = _d
    try:
        _w = MainWindow()
    finally:
        if _o is None:
            os.environ.pop('XDG_CONFIG_HOME', None)   # was unset: pop, do not pin to the temp dir
        else:
            os.environ['XDG_CONFIG_HOME'] = _o
    return _w, _d


# (a) key ABSENT (fresh / default config): the noisy types are muted by default.
_wa, _ = _win_with_conf(None)
eq(_wa._osc_notice_off, {'osc_title', 'osc_colors'},
   'an absent osc_notice_off mutes the title + palette notices by default')
_wa.close()

# (b) key PRESENT (here empty): honoured verbatim as the user's own choice -- the
# default is NOT injected, so an explicit empty means notify about every type.
_wb, _ = _win_with_conf({'osc_notice_off': ''})
eq(_wb._osc_notice_off, set(),
   'a present (empty) osc_notice_off is honoured as-is (no default injected)')
_wb.close()

# (c) a present non-empty osc_notice_off is parsed to exactly its listed types.
_wc, _ = _win_with_conf({'osc_notice_off': 'osc_cwd,osc_hyperlink'})
eq(_wc._osc_notice_off, {'osc_cwd', 'osc_hyperlink'},
   'a present osc_notice_off is parsed to its listed types')
_wc.close()

# --- Global settings: per-type OSC-notice toggles ------------------------------
# The dialog exposes one notify toggle per OSC type (ticked == notify), mirroring
# the View > Notify on OSC use submenu. The notice rows carry "(OSC <codes>)" in
# their label, which the OSC-feature rows do not -- match on that to target them.
win._osc_notice_off = {'osc_title'}
QDialog.exec = _accept_exec
_dialogs.clear()
win.show_global_settings()
_gsn = _dialogs[-1]
_nt = _dlg_field(_gsn, 'Window / tab title  (OSC 0, 2)')
_nh = _dlg_field(_gsn, 'Hyperlinks  (OSC 8)')
ok(_nt is not None and not _nt.isChecked(),
   'per-type notice: a muted type (osc_title) shows unticked in Global settings')
ok(_nh is not None and _nh.isChecked(),
   'per-type notice: an un-muted type (osc_hyperlink) shows ticked')
ok(_dlg_field(_gsn, 'All OSC notices') is not None,
   'Global settings shows the master "All OSC notices" toggle')

# an admin-locked osc_notice_off greys every per-type notice checkbox in the
# dialog (an editable-but-ignored control misleads worse than a greyed one).
_sl_nd = set(win._locked)
try:
    win._locked = {'osc_notice_off'}
    _dialogs.clear()
    win.show_global_settings()
    _gsl = _dialogs[-1]
    _ntl = _dlg_field(_gsl, 'Window / tab title  (OSC 0, 2)')
    ok(_ntl is not None and not _ntl.isEnabled(),
       'a locked osc_notice_off greys the per-type notice checkboxes in Global settings')
finally:
    win._locked = _sl_nd

# _apply_global with osc_notice_types updates _osc_notice_off AND syncs the
# View-menu actions (ticked == notify; an unticked type is muted).
win._locked = set()
win._osc_notice_off = set()
_types = {_k: (_k != 'osc_colors') for _k, *_ in M.OSC_FEATURES}   # mute only palette
win._apply_global({'theme': 'light', 'zoom': 100, 'mode': 'box',
                   'font_family': 'Hack', 'font_size': 11,
                   'colors': True, 'line_edits': True, 'tui': False,
                   'osc_notice': True, 'osc_notice_types': _types,
                   'tui_autobox_notice': True, 'osc': {},
                   'scrollback': 1000, 'paste_delay': 3, 'escape_limit': 4096,
                   'persist': False})
eq(win._osc_notice_off, {'osc_colors'},
   '_apply_global mutes exactly the unticked per-type notice (palette)')
ok(not win._osc_notice_actions['osc_colors'].isChecked()
   and win._osc_notice_actions['osc_title'].isChecked(),
   '_apply_global syncs the View-menu per-type notice actions to the dialog')

# Ctrl+wheel anywhere in the Global settings dialog live-zooms, even over the scroll-area
# viewport (or a spinbox) that would otherwise consume the wheel -- the regression where the
# QScrollArea wrapper swallowed Ctrl+wheel so the dialog stopped zooming. Deliver the wheel
# to a CHILD (the viewport), which is what exposes the bug; a wheel sent to the dialog
# directly would zoom even with the bug live.
from PyQt6.QtWidgets import QScrollArea as _QSA_gz             # noqa: E402
from PyQt6.QtGui import QWheelEvent as _QWE_gz                 # noqa: E402
from PyQt6.QtCore import QPoint as _QP_gz, QPointF as _QPF_gz  # noqa: E402
_gz_ui_orig = win._ui_scale
win._locked = set()
win._ui_scale = 100                        # a mid value on the 75..300 / step-25 grid
_dialogs.clear()
win.show_global_settings()
_gsz = _dialogs[-1]
ok(isinstance(_gsz, M._ZoomDialog) and _gsz.on_zoom is not None,
   'Global settings is a _ZoomDialog with its Ctrl+wheel zoom wired')
_gsz.show()                                # a real showEvent installs the wheel event filter
_gsz.resize(320, 240)                      # force the tall content to overflow -> scrollable
APP.processEvents()
_gsz_sa = _gsz.findChild(_QSA_gz)
ok(_gsz_sa is not None, 'the Global settings body is a scroll area')
_gsz_vp = _gsz_sa.viewport()
_gsz_sa.verticalScrollBar().setValue(_gsz_sa.verticalScrollBar().maximum() // 2)


def _gz_ctrl_wheel(target, dy):
    ev = _QWE_gz(_QPF_gz(5, 5), _QPF_gz(5, 5), _QP_gz(0, 0), _QP_gz(0, dy),
                 _Qt_sc.MouseButton.NoButton, _Qt_sc.KeyboardModifier.ControlModifier,
                 _Qt_sc.ScrollPhase.NoScrollPhase, False)
    APP.sendEvent(target, ev)


_gz_before = win._ui_scale
_gz_ctrl_wheel(_gsz_vp, 120)               # Ctrl+wheel UP over the scroll-area viewport
eq(win._ui_scale, _gz_before + M.UI_SCALE_STEP,
   'Ctrl+wheel over the scroll-area viewport zooms the Global settings dialog (was swallowed)')
_gsz.close()
win._ui_scale = _gz_ui_orig

# --- tab bar elides in the MIDDLE (keeps the trailing session number) ----------
# ElideRight on many same-prefixed tabs (claude-rc-session: dev46x/dev47x) drops
# the identifying number -> every tab reads the same prefix; ElideMiddle keeps it.
from PyQt6.QtCore import Qt as _QtTB                              # noqa: E402
eq(win.tabs.tabBar().elideMode(), _QtTB.TextElideMode.ElideMiddle,
   'the tab bar elides in the middle so the session number survives')

# --- Copy Transcript File Path: env-independent, one-click copy ----------------
# Writes the scrollback to the app's default state-dir transcript file and shows
# that path (no SECURE_TERMINAL_TRANSCRIPT_FILE required); the Copy button copies it.
from PyQt6.QtWidgets import QLineEdit as _QLE11, QPushButton as _QPB11   # noqa: E402
_dialogs.clear()
win.copy_transcript_path()
_tpdlg = _dialogs[-1]
_tpfields = [w for w in _tpdlg.findChildren(_QLE11) if w.isReadOnly()]
ok(bool(_tpfields) and _tpfields[0].text().endswith('transcript.txt')
   and os.path.exists(_tpfields[0].text()),
   'Copy Transcript File Path names a real default state-dir file (no env var needed)')
_tppath = _tpfields[0].text()
_tpcopy = [b for b in _tpdlg.findChildren(_QPB11) if 'Copy' in b.text()]
ok(bool(_tpcopy), 'the transcript-path dialog has a Copy button')
APP.clipboard().setText('')
_tpcopy[0].click()
eq(APP.clipboard().text(), _tppath,
   'the Copy button puts the transcript path on the clipboard')

# --- Part B: the generated config stores ONLY non-default overrides -----------
# A fresh-config window persists NO keys (every value == its default -> omitted),
# which doubles as the drift guard for _PERSIST_DEFAULTS: a value here that diverges
# from the constructor's actual default would be written and fail this.
import tempfile as _tf_pb                                          # noqa: E402
_pbdir = _tf_pb.mkdtemp()
_o_pb = os.environ.get('XDG_CONFIG_HOME')
os.environ['XDG_CONFIG_HOME'] = _pbdir
try:
    def _pb_lines():
        _p = M.settings.user_config_file()
        return ([_l.strip() for _l in open(_p)
                 if _l.strip() and not _l.startswith('#')] if os.path.exists(_p) else [])
    _pbw = MainWindow()
    _pbw._persist()
    ok(_pb_lines() == [],
       'Part B: a fresh-config window persists NO keys (defaults omitted; _PERSIST_DEFAULTS drift guard)')
    _pbw._default_zoom = 200            # one real override
    _pbw._persist()
    ok(_pb_lines() == ['zoom=200'], 'Part B: only a non-default override is written')
    _pbw._default_zoom = int(M._PERSIST_DEFAULTS['zoom'])   # back to default
    _pbw._persist()
    ok(_pb_lines() == [], 'Part B: a key reset to its default is pruned from the file')
    _pbw.close()
finally:
    if _o_pb is None:
        os.environ.pop('XDG_CONFIG_HOME', None)   # was unset: pop, do not pin to the temp dir
    else:
        os.environ['XDG_CONFIG_HOME'] = _o_pb

_sh_mcg.rmtree(_cgbase, ignore_errors=True)


finish('mainwin5')
