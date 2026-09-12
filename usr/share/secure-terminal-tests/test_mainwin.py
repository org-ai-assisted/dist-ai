#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## MainWindow dialogs + tooltips, main.py behavioural fixes, tab focus, _InfoLabel, new-tab cwd, the ctl remote-control client, the clipboard-read and keyboard-shortcuts dialogs, close_tab / confirm-close, tab context menu, bell picker, save/open transcript, rename, IPC-open, _test_canary.
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

# --- OSC-feature tooltips name their risk class -------------------------------
# Regression: _RISK_TAG mapped 'low' to '' so the sole low-risk feature
# (Working-directory report / osc_cwd) showed no [risk] tag while medium/high did.
ok(set(M._RISK_TAG) >= {f[4] for f in M.OSC_FEATURES},
   'every OSC_FEATURES risk level has a _RISK_TAG entry')
ok(all(M._RISK_TAG[_r].strip() for _r in M._RISK_TAG),
   'no _RISK_TAG entry is blank (a blank drops the risk label from a tooltip)')
_cwd_act = win._osc_actions.get('osc_cwd')
ok(_cwd_act is not None and 'risk: low' in _cwd_act.toolTip(),
   'osc_cwd (Working-directory report) tooltip names its low risk')

# --- native menu QToolTip is styled readable, both themes ---------------------
# Regression: menu action hints use Qt's native QToolTip, which was unstyled and
# inherited a dark-on-dark platform palette. It must carry contrasting fg/bg.
#
# The stylesheet ALONE is not enough: under the Fusion style + a platform theme
# (qt5ct) Qt paints the tooltip from its PALETTE (ToolTipBase/ToolTipText), which a
# QToolTip{} stylesheet rule does NOT override -- so the fix must ALSO pin the palette.
# The palette assertions below are the canary: they FAIL on the stylesheet-only code
# that read green while the real desktop stayed dark-on-dark.
from PyQt6.QtWidgets import QToolTip as _QTT                       # noqa: E402
from PyQt6.QtGui import QPalette as _QPal, QColor as _QCol         # noqa: E402
_TT_BASE = _QPal.ColorRole.ToolTipBase
_TT_TEXT = _QPal.ColorRole.ToolTipText
# Qt paints a QTipLabel from the INACTIVE color group (a tooltip is never an active
# window), so the pin that the desktop actually shows lives there -- assert that group,
# not the default (Active) group, else the check can read green while qt5ct paints dark.
_TT_INACT = _QPal.ColorGroup.Inactive
win.set_theme('dark')
_ss_dark = APP.styleSheet()
_d_bg, _d_fg, _d_bd = M._TIP_COLORS['dark']
ok('QToolTip' in _ss_dark, 'app installs a QToolTip stylesheet')
ok(_d_bg in _ss_dark and _d_fg in _ss_dark, 'dark QToolTip uses the dark card fg/bg')
ok(_d_bg != _d_fg, 'QToolTip fg and bg differ (readable, not dark-on-dark)')
ok(_QTT.palette().color(_TT_INACT, _TT_BASE) == _QCol(_d_bg),
   'dark QToolTip INACTIVE-group base is pinned to the card bg (the group Qt paints)')
ok(_QTT.palette().color(_TT_INACT, _TT_TEXT) == _QCol(_d_fg),
   'dark QToolTip INACTIVE-group text is pinned to the card fg (not the dark platform text)')
win.set_theme('light')                       # restore the default for later tests
_ss_light = APP.styleSheet()
_l_bg, _l_fg, _l_bd = M._TIP_COLORS['light']
ok(_l_bg in _ss_light and _l_fg in _ss_light, 'light QToolTip uses the light card fg/bg')
ok(_QTT.palette().color(_TT_INACT, _TT_BASE) == _QCol(_l_bg),
   'light QToolTip INACTIVE-group base is pinned to the card bg')
ok(_QTT.palette().color(_TT_INACT, _TT_TEXT) == _QCol(_l_fg),
   'light QToolTip INACTIVE-group text is pinned to the card fg')
# Regression (the reported light-theme dark-on-dark tooltips): the base app palette is
# captured from the DESKTOP theme, which may be DARK; a native (non-Fusion) light style
# can paint QToolTip from the APP palette, so the light path must RE-PIN the tooltip roles
# rather than restore the dark base verbatim (QToolTip.setPalette + the QToolTip{} QSS are
# not honoured by every platform style). Simulate a dark-desktop base and confirm light
# re-pins the APP-palette tooltip roles. FAILS on the old code that restored the base as-is.
_saved_base = win._base_app_palette
_dark_base = _QPal(win._base_app_palette)
_dark_base.setColor(_TT_INACT, _TT_BASE, _QCol('#0f1216'))    # dark desktop tooltip bg
_dark_base.setColor(_TT_INACT, _TT_TEXT, _QCol('#0f1216'))    # dark-on-dark (the reported bug)
win._base_app_palette = _dark_base
win.set_theme('dark')                        # bounce so the light path re-runs
win.set_theme('light')
ok(APP.palette().color(_TT_INACT, _TT_BASE) == _QCol(_l_bg),
   'light re-pins the APP-palette tooltip base even when the desktop base is dark')
ok(APP.palette().color(_TT_INACT, _TT_TEXT) == _QCol(_l_fg),
   'light re-pins the APP-palette tooltip text (no dark-on-dark leak from the desktop)')
win._base_app_palette = _saved_base
win.set_theme('light')                       # restore the clean default for later tests

# --- window dialogs: built and shown with exec() stubbed ----------------------
try:
    win.show_about()
    ok(True, 'show_about builds and shows')
    # About must be a _ZoomDialog so Ctrl+wheel zooms it (regression: it was a plain
    # QDialog and its title was a fixed 16px, so nothing scaled).
    from secure_terminal.main import _ZoomDialog as _ZD_about     # noqa: E402
    _about_dlg = _dialogs[-1]
    ok(isinstance(_about_dlg, _ZD_about), 'About is a _ZoomDialog (Ctrl+wheel zoomable)')
    ok(_about_dlg.on_zoom is not None, 'About wires a Ctrl+wheel zoom handler')
    _a_titles = [_l for _l in _about_dlg.findChildren(M.QLabel)
                 if _l.text().startswith('secure-terminal ')]
    ok(bool(_a_titles), 'About shows a version heading')
    _a_pt0 = _a_titles[0].font().pointSizeF()
    _about_dlg.on_zoom(1)                     # Ctrl+wheel up
    ok(_a_titles[0].font().pointSizeF() > _a_pt0,
       'zooming the About dialog enlarges its heading')
    # The body lives in a scroll area so a zoomed (or maximized-parent) About SCROLLS
    # instead of overflowing/overlapping the fixed frame (the reported bug). The old
    # plain-QVBoxLayout About had no scroll area, so this fails pre-fix.
    _a_scroll = _about_dlg.findChild(M.QScrollArea)
    ok(_a_scroll is not None and _a_scroll.widgetResizable(),
       'About hosts its content in a resizable scroll area (no zoom overflow/overlap)')
    # Zooming hard must keep the dialog on-screen (fit-to-screen resize) and keep the
    # content hosted by the scroll area (it scrolls, never clips).
    _avail_h = M.QApplication.primaryScreen().availableGeometry().height()
    for _ in range(8):
        _about_dlg.on_zoom(1)
    ok(_about_dlg.height() <= _avail_h and _a_scroll.widget() is not None,
       'a heavily-zoomed About stays within the screen and keeps its content scrollable')
    # _fit_about's no-screen guard: with no primary screen it cannot read
    # availableGeometry, so the fit is skipped -- a zoom must still not crash. (The
    # dialog is maxed out above, so zoom DOWN to force a real rescale -> _fit_about.)
    _o_ps_about = M.QApplication.primaryScreen
    M.QApplication.primaryScreen = staticmethod(lambda: None)
    try:
        _about_dlg.on_zoom(-1)               # a scale change -> _apply_about_scale -> _fit_about
        ok(True, 'About zoom tolerates a missing primary screen (fit is skipped, no crash)')
    finally:
        M.QApplication.primaryScreen = _o_ps_about
    win.show_locations()
    ok(True, 'show_locations builds and shows the paths dialog')
    # Folders & Files must expose the transcripts directory (regression: no entry).
    from secure_terminal import session as _SESS_loc            # noqa: E402
    from PyQt6.QtWidgets import QLineEdit as _QLE_loc, QLabel as _QLbl_loc  # noqa: E402
    _loc_dlg = _dialogs[-1]
    _loc_labels = [_l.text() for _l in _loc_dlg.findChildren(_QLbl_loc)]
    ok('Transcripts' in _loc_labels, 'Folders & Files lists a Transcripts entry')
    _loc_fields = [_f.text() for _f in _loc_dlg.findChildren(_QLE_loc)]
    ok(_SESS_loc._state_dir() in _loc_fields,
       'the Transcripts row shows the transcript state directory')
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

    # --- Reset to defaults restores shipped defaults (drift-guarded) ----------
    # Source of truth = a window loaded from a CLEAN (empty) config, so this fails if
    # the Reset defaults ever drift from the constructor's fallbacks.
    import tempfile as _tf_rd                                 # noqa: E402
    from PyQt6.QtWidgets import QPushButton as _QPB           # noqa: E402
    _clean_cfg = _tf_rd.mkdtemp()
    _o_cfg = os.environ.get('XDG_CONFIG_HOME')
    os.environ['XDG_CONFIG_HOME'] = _clean_cfg
    try:
        _dw = MainWindow()
    finally:
        os.environ['XDG_CONFIG_HOME'] = _o_cfg if _o_cfg is not None else _clean_cfg
    _def_theme, _def_zoom, _def_ui = _dw._default_theme, _dw._default_zoom, _dw._ui_scale
    _def_fs, _def_sb, _def_mode = _dw._default_font_size, _dw._scrollback, _dw._default_mode
    _def_col, _def_tui = _dw._default_colors, _dw._default_tui
    _def_mk, _def_cra = _dw._default_markings, _dw._osc_clipboard_read_always
    _def_pd, _def_esc, _def_pw = _dw._paste_delay, _dw._escape_limit, _dw._paste_warn
    _def_sys, _def_persist = _dw._systray, _dw._persist_session
    # perturb every field we assert, so Reset has something to revert
    _dw._default_theme, _dw._default_zoom, _dw._default_tui = 'dark', 150, True
    _dw._paste_delay, _dw._systray, _dw._persist_session = 5, True, False
    _dw._default_mode, _dw._default_colors = 'box', False
    _dw._default_markings, _dw._osc_clipboard_read_always = False, True
    _dialogs.clear()
    _dw.show_global_settings()
    _gs = _dialogs[-1]
    _rb = [b for b in _gs.findChildren(_QPB) if b.text() == 'Reset to defaults']
    ok(bool(_rb), 'Global settings has a Reset to defaults button')
    # perturb the per-type OSC-notice toggles so Reset has something to revert (rd#1:
    # _reset_defaults missed them, so Reset+Apply persisted a wrong mute set)
    _nt_reset = _dlg_field(_gs, 'Window / tab title  (OSC 0, 2)')
    _nh_reset = _dlg_field(_gs, 'Hyperlinks  (OSC 8)')
    _nt_reset.setChecked(True)       # un-mute title (non-default)
    _nh_reset.setChecked(False)      # mute hyperlink (non-default)
    _rb[0].click()
    ok(not _nt_reset.isChecked() and _nh_reset.isChecked(),
       'reset: per-type OSC-notice toggles revert to default (title muted, hyperlink notified)')
    eq(_dlg_field(_gs, 'Theme').currentData(), _def_theme, 'reset: theme -> default')
    eq(_dlg_field(_gs, 'Zoom').value(), _def_zoom, 'reset: zoom -> default')
    eq(_dlg_field(_gs, 'Menu size').value(), _def_ui, 'reset: menu size -> default')
    eq(_dlg_field(_gs, 'Font size').value(), _def_fs, 'reset: font size -> default')
    eq(_dlg_field(_gs, 'Scrollback').currentData(), _def_sb, 'reset: scrollback -> default')
    eq(_dlg_field(_gs, 'Unicode').currentData(), _def_mode, 'reset: unicode -> default')
    ok(_dlg_field(_gs, 'Colours').isChecked() == _def_col, 'reset: colours -> default')
    ok(_dlg_field(_gs, 'Colored markings').isChecked() == _def_mk,
       'reset: colored markings -> default')
    ok(_dlg_field(_gs, 'Always allow clipboard read').isChecked() == _def_cra,
       'reset: clipboard-read-always -> default')
    ok(_dlg_field(_gs, 'TUI mode').isChecked() == _def_tui, 'reset: tui -> default')
    eq(_dlg_field(_gs, 'Paste delay').currentData(), _def_pd, 'reset: paste delay -> default')
    ok(_dlg_field(_gs, 'System tray').isChecked() == _def_sys, 'reset: systray -> default')
    ok(_dlg_field(_gs, 'Restore session').isChecked() == _def_persist,
       'reset: restore-session -> default')
    _dw.close()

    # --- Global settings opens sized to its content (no default scrollbar) -----
    _dialogs.clear()
    win.show_global_settings()
    _gs2 = _dialogs[-1]
    from PyQt6.QtWidgets import QScrollArea as _QSA           # noqa: E402
    _sa = _gs2.findChildren(_QSA)
    ok(bool(_sa), 'settings dialog uses a scroll area')
    # the dialog is tall enough that the scroll content is not clipped by default:
    # its height covers the content's natural height (capped only by the screen).
    _sc = _sa[0]
    _fits = _gs2.height() >= min(_sc.widget().sizeHint().height(),
                                 int(APP.primaryScreen().availableGeometry().height()
                                     * 0.9))
    ok(_fits, 'settings dialog opens tall enough to show content (no default scroll)')

    win._paste_delay = 3
    # every dialog's descriptive text must be selectable so it can be copied.
    # (asserts the settings dialog opened just above, still in _dialogs -- do NOT
    # clear _dialogs here or this loop runs over an empty list and never checks.)
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
    # clip_autostart is tray-gated AND lock-gated: with the tray available it must
    # STILL disable when locked (it was missing from the disable loop, so a locked
    # setting looked editable and set_clip_autostart silently dropped the change).
    _ca_lock = set(win._locked)
    _ca_cce = win._clip_controls_enabled
    try:      # stubs the SHARED win -> restore in finally so a raise cannot leak them
        win._clip_controls_enabled = lambda: True     # simulate tray on + available
        win._locked = set()
        _dialogs.clear()
        win.show_global_settings()
        _ca_on = _dlg_field(_dialogs[-1], 'Start sanitizer on login')
        ok(_ca_on is not None and _ca_on.isEnabled(),
           'clip_autostart is editable when unlocked and the tray is available')
        win._locked = {'clip_autostart'}
        _dialogs.clear()
        win.show_global_settings()
        _ca_off = _dlg_field(_dialogs[-1], 'Start sanitizer on login')
        ok(_ca_off is not None and not _ca_off.isEnabled(),
           'a locked clip_autostart disables its Global Settings control (not editable-but-ignored)')
    finally:
        win._clip_controls_enabled = _ca_cce
        win._locked = _ca_lock
    # #24: a Ctrl+wheel live-zoom during Global settings must be DISCARDED on Cancel, like
    # every other field. _live_zoom mutates self._ui_scale and _persist()s it LIVE, so a
    # bare cancel-returns-without-applying left the wheeled scale applied AND on disk.
    win._locked = set()                       # ui_scale unlocked so the wheel step lands
    win._ui_scale = 100                       # sub-max so on_zoom(1) MUST raise it
    _persisted24 = []
    _orig_persist24 = win._persist
    try:      # stubs the SHARED win._persist + QDialog.exec -> restore in finally
        win._persist = lambda: _persisted24.append(win._ui_scale)

        def _cancel_after_zoom(_self):
            _dialogs.append(_self)
            if getattr(_self, 'on_zoom', None) is not None:
                _self.on_zoom(1)              # a Ctrl+wheel step WHILE the dialog is open
            return int(QDialog.DialogCode.Rejected)
        QDialog.exec = _cancel_after_zoom
        win.show_global_settings()
    finally:
        QDialog.exec = _accept_exec
        win._persist = _orig_persist24
    eq(win._ui_scale, 100,
       '#24: a Ctrl+wheel live-zoom is reverted when Global settings is cancelled')
    ok(_persisted24 and _persisted24[-1] == 100,
       '#24: the reverted ui_scale is re-persisted on cancel (no cancelled zoom left on disk)')
    win._locked = _sl_uiz
finally:
    QDialog.exec = _orig_exec

# --- reviewdrain #9/#10/#11/#13: main.py behavioural fixes --------------------
# #10: the Line-editing toggle applies to EVERY tab, not just current() -- a background
# tab kept the old policy silently (unlike set_paste_warn / set_copy_warn).
_lew = MainWindow()
_lew.new_tab()
_lew.new_tab()                                  # two real tabs
_lew.set_line_edits(False)
ok(all(not t.line_edits_enabled() for t in _lew._real_terms()),
   '#10: set_line_edits(False) applies to every tab, not just the current one')
_lew.set_line_edits(True)
ok(all(t.line_edits_enabled() for t in _lew._real_terms()),
   '#10: set_line_edits(True) re-applies to every tab')
_lew.deleteLater()
APP.processEvents()                             # reap the tabs' shells (free ptys/fds)

# #9: _ipc_open must count only tabs it ACTUALLY opened. An explicit empty command opens
# NO tab, so opened=0 and the bare-reuse fallback (a fresh tab) still fires.
_ipw = MainWindow()
_ipw.new_tab()
_ip_before = _ipw.tabs.count()
_ip_reply = _ipw._ipc_open({'tabs': [{'command': []}]})
eq(_ip_reply.get('opened'), 0,
   '#9: _ipc_open reports opened=0 when a spec (empty command) opens no tab')
ok(_ipw.tabs.count() > _ip_before,
   '#9: an all-declined open batch still falls back to a fresh tab (contract kept)')
_ipw.deleteLater()
APP.processEvents()

# #13: a non-preset scrollback (any int via /scrollback N) must show a fallback combo item
# in Global Settings, so OK does not read currentData()=None and corrupt the config
# (scrollback=None -> int('None') crashes the next launch, resetting to Unlimited).
_sbw = MainWindow()
_sbw.new_tab()
_sbw._scrollback = 5000                          # not one of SCROLLBACK_CHOICES
_dialogs.clear()
QDialog.exec = _accept_exec
try:
    _sbw.show_global_settings()
    eq(_dlg_field(_dialogs[-1], 'Scrollback').currentData(), 5000,
       '#13: a non-preset scrollback shows a real fallback combo item (not a blank)')
    eq(_sbw._scrollback, 5000,
       '#13: the non-preset scrollback survives Global Settings OK (not overwritten with None)')
finally:
    QDialog.exec = _orig_exec
_sbw.deleteLater()
APP.processEvents()

# #11: a config keybinding override that COLLIDES with another action's default must not
# leave BOTH on the same chord (Qt renders an ambiguous chord dead for both) -- the
# override loses, protecting the built-in default (here the Terminate panic key).
_kb_dir = tempfile.mkdtemp()
os.makedirs(os.path.join(_kb_dir, 'secure-terminal.d'))
with open(os.path.join(_kb_dir, 'secure-terminal.d', '50_kb.conf'), 'w', encoding='utf-8') as _kh:
    _kh.write('keybindings=copy=Ctrl+Shift+K\n')  # collides with terminate's default
_kb_o_cfg = os.environ.get('XDG_CONFIG_HOME')
os.environ['XDG_CONFIG_HOME'] = _kb_dir
try:
    _kbw = MainWindow()
    eq(_kbw.act_terminate.shortcut().toString(), 'Ctrl+Shift+K',
       '#11: the Terminate panic key keeps Ctrl+Shift+K despite a colliding config override')
    ok(_kbw.act_copy.shortcut().toString() != 'Ctrl+Shift+K',
       '#11: the colliding copy override does not double-bind Ctrl+Shift+K (reverts to default)')
    _kbw.deleteLater()
finally:
    os.environ['XDG_CONFIG_HOME'] = _kb_o_cfg if _kb_o_cfg is not None else _kb_dir
APP.processEvents()

# #11 (the other collision direction): an EARLY-bound override colliding with a LATER
# action's DEFAULT -- the later default stands and the earlier override is reverted (new_tab
# binds before terminate, so terminate's Ctrl+Shift+K default reverts the new_tab override).
with open(os.path.join(_kb_dir, 'secure-terminal.d', '50_kb.conf'), 'w', encoding='utf-8') as _kh:
    _kh.write('keybindings=new_tab=Ctrl+Shift+K\n')
_kb_o_cfg2 = os.environ.get('XDG_CONFIG_HOME')
os.environ['XDG_CONFIG_HOME'] = _kb_dir
try:
    _kbw2 = MainWindow()
    eq(_kbw2.act_terminate.shortcut().toString(), 'Ctrl+Shift+K',
       '#11: a later built-in default stands; the earlier colliding override is reverted')
    ok(_kbw2.act_new.shortcut().toString() != 'Ctrl+Shift+K',
       '#11: the earlier new_tab override reverts off the collided chord')
    _kbw2.deleteLater()
finally:
    os.environ['XDG_CONFIG_HOME'] = _kb_o_cfg2 if _kb_o_cfg2 is not None else _kb_dir
APP.processEvents()

# coverage: the tab-chrome helpers are safe no-ops in a degenerate state (defensive guards).
_tt_orig = QApplication.instance
QApplication.instance = staticmethod(lambda: None)
try:
    win._apply_tooltip_style('dark')                    # no QApplication instance -> no-op
    ok(True, '_apply_tooltip_style is a no-op with no QApplication instance')
finally:
    QApplication.instance = _tt_orig
_fc_orig = win.current
win.current = lambda: M.QWidget()                       # a placeholder, not a SecureTerminal
try:
    win._focus_current_terminal()                       # current() not a real terminal -> no-op
    ok(True, '_focus_current_terminal is a no-op when current() is not a terminal')
finally:
    win.current = _fc_orig

# --- switching tabs focuses the terminal (no second click needed) -------------
# Regression: _sync_chrome_to_tab did not focus the newly-current terminal, so a
# QTabWidget switch left focus on the tab bar -- the tab was visible but typing
# needed an extra click.
_fw = MainWindow()
_fw.new_tab()
_fw.new_tab()                             # two real tabs
_fw_first = _fw.tabs.widget(0)
# Offscreen Qt never reports a real focus widget (no active window), so spy the call:
# _sync_chrome_to_tab must invoke the newly-current terminal's setFocus() on a switch.
_fw_focused = []
_fw_first.setFocus = lambda *_a, **_k: _fw_focused.append(True)
_fw.tabs.setCurrentIndex(1)
_fw.tabs.setCurrentIndex(0)               # switch back to the first tab -> _sync_chrome_to_tab
ok(_fw_focused, 'switching tabs gives the terminal keyboard focus (setFocus called)')

# Window ACTIVATION (alt-tab back, a fresh open-all launch, a raise) must ALSO focus the
# current terminal, but ONLY when focus is loose -- Qt leaves it on no child (or the tab
# bar), so the window looks active yet typing needs an extra click. If a real input child
# already holds focus (the paste/copy review editor, the zoom box, the find bar) activation
# must NOT steal it, or the next Enter/Esc drops the pending review.
# Canary: fails on a MainWindow without the changeEvent focus grab / the predicate.
from PyQt6.QtCore import QEvent as _QEv                        # noqa: E402
from PyQt6.QtWidgets import QLineEdit as _QLE                  # noqa: E402
# The loose-vs-held decision is a pure predicate -- assert it directly (deterministic
# offscreen, where real focus tracking needs a shown top-level).
ok(_fw._activation_should_claim_focus(None),
   'activation claims focus when nothing holds it (the extra-click case)')
ok(_fw._activation_should_claim_focus(_fw.tabs.tabBar()),
   'activation claims focus off the tab bar (arrow keys would step tabs, not type)')
ok(not _fw._activation_should_claim_focus(_QLE()),
   'activation does NOT steal focus from an input editor (review bar / zoom box)')
# changeEvent, given loose focus, actually drives the grab. focusWidget() is GLOBAL Qt
# state -- a prior test that left an input widget focused makes it non-None, so the
# predicate would decline and this flakes. Force the loose-focus case the test means.
_o_focus_widget = QApplication.focusWidget
QApplication.focusWidget = staticmethod(lambda: None)     # loose focus: nothing holds it
try:
    _fw_act = []
    _fw_cur = _fw.current()
    _fw_cur.setFocus = lambda *_a, **_k: _fw_act.append(True)
    _fw.isActiveWindow = lambda: True     # offscreen has no real active window; force it
    _fw.changeEvent(_QEv(_QEv.Type.ActivationChange))
    ok(_fw_act, 'window activation with loose focus focuses the current terminal')
    # Loose focus but the find bar is open -> the helper's own guard keeps focus in the
    # field. Offscreen never shows the top-level, so a child's isVisible() stays False; stub it.
    _fw._find_bar.isVisible = lambda: True
    _fw_act.clear()
    _fw.changeEvent(_QEv(_QEv.Type.ActivationChange))
    ok(not _fw_act, 'window activation leaves focus in an open find bar')
finally:
    QApplication.focusWidget = _o_focus_widget
_fw.close()

# --- _InfoLabel: the (i) marker is a link; label text stays selectable ---------
# Regression: clicking anywhere on the settings label popped the tip over the text
# being selected. Now only the (i) anchor opens it; the text selects for copy.
from PyQt6.QtCore import Qt as _QtIL                          # noqa: E402
_il = M._InfoLabel('Notify on OSC use <span style="color:#5b9bd5">(i)</span>',
                   'the explanation', win)
ok('href="tip"' in _il.text(), '_InfoLabel renders the (i) marker as a link')
ok(bool(_il.textInteractionFlags() & _QtIL.TextInteractionFlag.LinksAccessibleByMouse),
   '_InfoLabel keeps the (i) link clickable')
ok(bool(_il.textInteractionFlags() & _QtIL.TextInteractionFlag.TextSelectableByMouse),
   '_InfoLabel text stays selectable for copy')
_il_shown = []
_o_sit = win.show_info_tip
win.show_info_tip = lambda _w, _t: _il_shown.append(_t)
try:
    _il.linkActivated.emit('tip')            # clicking the (i) link
finally:
    win.show_info_tip = _o_sit
eq(_il_shown, ['the explanation'], 'clicking the (i) link opens the InfoTip')

# --- a new tab inherits the ACTIVE tab's working directory (konsole-like) ------
# Guards the wiring new_tab -> active.shell_cwd() -> the new tab's cwd, so a new tab
# opens where the current one is, not in secure-terminal's launch dir.
import tempfile as _tf_ct                                     # noqa: E402
_ct_dir = _tf_ct.mkdtemp()
_cw = MainWindow()
_cw.new_tab()
_cw.current().shell_cwd = lambda: _ct_dir      # stub the active tab's reported cwd
_cw.new_tab()
eq(_cw.current()._cwd, _ct_dir,
   'a new tab inherits the active tab shell_cwd, not the launch dir')
_cw.close()

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
    eq(_ctl_main(['send-text', '--tab', 'id:1', '--submit', 'echo hi']), 0,
       'ctl send-text --submit -> 0 (forwards submit=true)')
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
    # dump-state: forwards tab + format, prints the reply to stdout by default and
    # writes it to --file otherwise (the client-side arg-build + reply-print path).
    _sents: dict[str, object] = {}
    def _cap_reqs(*_a, **_k):
        for _x in _a:
            if isinstance(_x, dict) and 'op' in _x:
                _sents.clear()
                _sents.update(_x)
        return {'ok': True, 'text': '# secure-terminal state dump v2\nmode: tui\n'}
    M.ipc.send_request = _cap_reqs
    eq(_ctl_main(['dump-state', '--tab', 'id:1']), 0, 'ctl dump-state -> 0')
    ok(_sents.get('op') == 'ctl-dump-state' and _sents.get('tab') == 'id:1'
       and _sents.get('format') == 'text',
       'ctl: the client builds ctl-dump-state (tab + default format=text forwarded)')
    eq(_ctl_main(['dump-state', '--tab', 'id:1', '--format', 'json']), 0,
       'ctl dump-state --format json -> 0')
    ok(_sents.get('format') == 'json',
       'ctl: dump-state --format json is forwarded')
    # --file writes the reply atomically instead of stdout.
    _sd_dir = tempfile.mkdtemp(prefix='st-dumpstate-')
    _sd_path = os.path.join(_sd_dir, 'state.dump')
    eq(_ctl_main(['dump-state', '--tab', 'id:1', '--file', _sd_path]), 0,
       'ctl dump-state --file -> 0')
    with open(_sd_path, encoding='utf-8') as _sdh:
        ok(_sdh.read() == '# secure-terminal state dump v2\nmode: tui\n',
           'ctl: dump-state --file writes the reply to the path (atomic tmp+rename)')
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

# Launch banner: a tab LAUNCHED with a command (show_command via new_tab / a launch
# spec) records it as a scrollback banner, so the original command a bare prompt
# never echoes is visible; a plain login-shell tab (no command) shows none. The
# banner is seeded in the ctor before the child forks, so it is present at once.
_bw = MainWindow()
_bw.new_tab(command=['/bin/sh', '-c', 'exit 0'])
_bw_cmd = _bw.tabs.widget(_bw.tabs.count() - 1)
ok("[secure-terminal] running: /bin/sh -c 'exit 0'" in _bw_cmd.transcript_text(),
   'a command-launched tab records the launch command as a scrollback banner')
_deadline = time.time() + 5                          # drain to restart-as-shell -> clean close
while time.time() < _deadline and _bw_cmd._command is not None:
    pump(30)
_bw.new_tab()                                        # a plain login-shell tab
_bw_shell = _bw.tabs.widget(_bw.tabs.count() - 1)
ok('[secure-terminal] running:' not in _bw_shell.transcript_text(),
   'a bare login-shell tab shows no launch banner')
while _bw.tabs.count() > 0:
    _bw.close_tab(0)
_bw.deleteLater()

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
# _Yes / _No (the QMessageBox button codes) come from test_mainwin_common.
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
    # a symlink planted at the chosen save path must NOT be followed (O_NOFOLLOW):
    # the save fails+warns rather than overwriting the link target, matching every
    # sibling transcript writer. (canary: pre-fix _save_capture used open(path,'w')
    # and silently clobbered the target through the symlink.) The open fails with
    # ELOOP before getter(term) runs, so the current tab's content is irrelevant --
    # do not add a tab here (that would pollute win.current() for later tests).
    _lk_dir = tempfile.mkdtemp(prefix='st-savesym-')
    _lk_victim = os.path.join(_lk_dir, 'victim.txt')
    with open(_lk_victim, 'w', encoding='utf-8') as _vh:
        _vh.write('ORIGINAL')
    _lk_link = os.path.join(_lk_dir, 'save-here.txt')
    os.symlink(_lk_victim, _lk_link)
    _owarn = QMessageBox.warning
    _lk_warned = []
    QMessageBox.warning = staticmethod(lambda *_a, **_k: _lk_warned.append(True))
    try:
        QFileDialog.getSaveFileName = staticmethod(lambda *_a, **_k: (_lk_link, ''))
        win.save_transcript()
    finally:
        QMessageBox.warning = _owarn
    with open(_lk_victim, encoding='utf-8') as _vr:
        ok(_vr.read() == 'ORIGINAL' and bool(_lk_warned),
           'save_transcript: a symlinked target is refused (O_NOFOLLOW), link target intact')
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
_ocur = win.current           # restored in the finally: this stubs the SHARED win
try:
    def _spy_open_url(url):
        _opened.append(url.toLocalFile())
        return True
    _QDS.openUrl = staticmethod(_spy_open_url)
    _sess._state_dir = lambda: _state_tmp
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
    # Save/Open Current Screen: the live-frame counterparts (#12), delegating to the same
    # helpers with transcript_text as the getter, writing screen.txt (not transcript.txt).
    _opened.clear()
    win.open_current_screen()
    ok(len(_opened) == 1 and os.path.basename(_opened[0]) == 'screen.txt'
       and os.path.getsize(_opened[0]) > 0,
       'open_current_screen: writes screen.txt under the state dir and opens it')
    _cs_path = os.path.join(tempfile.mkdtemp(), 'screen-save.txt')
    _ogsf2 = QFileDialog.getSaveFileName
    QFileDialog.getSaveFileName = staticmethod(lambda *_a, **_k: (_cs_path, ''))
    try:
        win.save_current_screen()
        ok(os.path.exists(_cs_path) and os.path.getsize(_cs_path) > 0,
           'save_current_screen: writes the current-screen capture to the chosen file')
    finally:
        QFileDialog.getSaveFileName = _ogsf2
    # ai-review #3: session state is SENSITIVE history -- the dir must be 0o700 (enforced
    # even on a pre-existing wider dir) and the files 0o600, never world-readable.
    import stat as _stat3
    os.chmod(_state_tmp, 0o755)  # nosec B103 -- intentional wide pre-existing dir; the test asserts the app tightens it to 0o700
    win.open_transcript()                        # ensure_state_dir must chmod it back to 0o700
    ok(_stat3.S_IMODE(os.stat(_state_tmp).st_mode) == 0o700,
       'ai-review#3: ensure_state_dir enforces 0o700 on the sensitive state dir')
    ok(_stat3.S_IMODE(os.stat(os.path.join(_state_tmp, 'transcript.txt')).st_mode) == 0o600,
       'ai-review#3: the transcript file is owner-only (0o600), not world-readable')
    os.chmod(_state_tmp, 0o755)  # nosec B103 -- intentional wide dir; the test asserts session.save tightens it to 0o700
    _sess.save([{'text': 'scrollback', 'command': None}], window=None, active=0)
    ok(_stat3.S_IMODE(os.stat(_state_tmp).st_mode) == 0o700,
       'ai-review#3: session.save enforces 0o700 on the state dir')
    ok(_stat3.S_IMODE(os.stat(_sess.session_path()).st_mode) == 0o600
       and _stat3.S_IMODE(os.stat(_sess._log_path(0)).st_mode) == 0o600,
       'ai-review#3: session.json and the per-tab log are owner-only (0o600)')
    # a chmod failure in ensure_state_dir is best-effort: swallowed, never raised (the dir
    # already exists so _makedirs_private returns before its own chmod; only this one fires).
    def _chmod_boom(*_a, **_k):
        raise OSError('chmod denied')
    _ochmod3 = _sess.os.chmod
    _sess.os.chmod = _chmod_boom
    try:
        _sess.ensure_state_dir()                 # must NOT raise
        ok(True, 'ai-review#3: ensure_state_dir swallows a chmod OSError (best-effort)')
    finally:
        _sess.os.chmod = _ochmod3
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
    win.current = _ocur       # backstop: a raise mid-try must not leak the None stub

# --- ai-review #2: rename_tab on a session-restore placeholder (a bare QWidget, not a
# SecureTerminal) must be a safe no-op, not an AttributeError (term.cwd_basename()) that
# escapes the Qt slot and aborts the whole window.
_ph2 = M.QWidget()
win.tabs.addTab(_ph2, 'placeholder')
_phi2 = win.tabs.indexOf(_ph2)
win.rename_tab(_phi2)                               # returns via the isinstance guard -- no crash
ok(win.tabs.indexOf(_ph2) == _phi2 and win.tabs.tabText(_phi2) == 'placeholder',
   'ai-review#2: rename_tab on a non-terminal placeholder is a safe no-op')
win.tabs.removeTab(_phi2)
_ph2.deleteLater()

# --- ai-review #4: an IPC "open" spec with an EXPLICIT empty command opens NO tab (fail
# closed like the CLI's -e "" / -- ""), never a silent login-shell fallback via the socket.
_n4 = win.tabs.count()
win._open_launch_tab({'command': ''})
win._open_launch_tab({'command': []})
win._open_launch_tab({'command': ['']})
win._open_launch_tab({'command': ['   ']})
eq(win.tabs.count(), _n4,
   'ai-review#4: an explicit-empty IPC command opens no tab (no login-shell fallback)')

# --- _test_canary: writes the marker + echoes; loud failure on a bad path -----
import secure_terminal.main as _MM              # noqa: E402
eq(_test_canary(), 0, '_test_canary: writes the marker and returns 0')
_orig_marker = _MM.canary_marker_path
try:
    _MM.canary_marker_path = lambda: '/proc/nonexistent-dir/marker'
    eq(_test_canary(), 1, '_test_canary: an unwritable marker fails loud (exit 1)')
finally:
    _MM.canary_marker_path = _orig_marker


finish('mainwin')
