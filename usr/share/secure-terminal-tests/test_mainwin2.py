#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Setting appliers, tray menu, find bar, tray icon, copy/paste/zoom + input-dialog actions routed through the current tab, keybindings drop-in parse, the single-instance IPC server dispatch, main() entry point, launch parsing.
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
import secure_terminal.main as _MM              # noqa: E402

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
    ok(_disp({'op': 'ctl-send-text', 'tab': 'id:%d' % _tid0, 'text': 'echo',
              'submit': True})['ok'],
       'ipc: ctl-send-text with submit=true runs the line')
    ok(not _disp({'op': 'ctl-send-text', 'tab': 'id:%d' % _tid0, 'text': 'x',
                  'submit': 'yes'})['ok'],
       'ipc: ctl-send-text with a non-boolean submit is rejected')
    ok(not _disp({'op': 'ctl-send-text', 'tab': 'id:%d' % _tid0, 'text': 5})['ok'],
       'ipc: ctl-send-text with non-string text is rejected')
    _rd = _disp({'op': 'ctl-dump-tab', 'tab': 'id:%d' % _tid0, 'lines': 2})
    ok(_rd['ok'] and 'text' in _rd, 'ipc: ctl-dump-tab returns the rendered text')
    # ctl-dump-state: the deterministic full state dump (text default + json).
    _rs = _disp({'op': 'ctl-dump-state', 'tab': 'id:%d' % _tid0})
    ok(_rs['ok'] and _rs.get('text', '').startswith('# secure-terminal state dump'),
       'ipc: ctl-dump-state returns a headed state dump (text default)')
    _rj = _disp({'op': 'ctl-dump-state', 'tab': 'id:%d' % _tid0, 'format': 'json'})
    ok(_rj['ok'] and _json.loads(_rj['text']).get('version') == 2,
       'ipc: ctl-dump-state format=json returns a parseable dump')
    ok(not _disp({'op': 'ctl-dump-state', 'tab': 'id:%d' % _tid0,
                  'format': 'yaml'})['ok'],
       'ipc: ctl-dump-state rejects an unknown format')
    ok(not _disp({'op': 'ctl-dump-state', 'tab': 'id:999999'})['ok'],
       'ipc: ctl-dump-state on a non-matching tab -> error')
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
# (OSC-map fail-closed restore is tested in test_mainwin5, after the ctl-dump-tab
# COR-7 assertions, so its probe tab cannot perturb their fixture.)
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
    # _FontDBAbsent (families() without the default) comes from test_mainwin_common.
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


finish('mainwin2')
