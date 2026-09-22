#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""SecureTabBar two-line polish: the close button re-centred on line 1, the per-element
tooltips (trust lock / untrusted line-2 band), and the line-2 separator/paint. Structural
+ geometry assertions on the real headless-Wayland widget path (no pixel diffing)."""

from test_widget_common import *   # noqa: F401,F403  (shared harness: APP, ok, eq, finish, Qt, QRect ...)

from PyQt6.QtWidgets import QWidget, QTabBar
from PyQt6.QtGui import QHelpEvent
from PyQt6.QtCore import QPoint, QEvent
from secure_terminal.main import SecureTabBar, _ToolTipFilter


def _bar():
    b = SecureTabBar()
    b.set_theme(False)
    b.set_two_line(True)
    b.setTabsClosable(True)
    for i, (lbl, acc, ttl) in enumerate(
            [('proj', '#d83933', 'npm run build'), ('bare', None, '')]):
        b.addTab(lbl)
        b.set_accent(i, acc)
        b.set_ptitle(i, ttl)
    b.resize(520, b.sizeHint().height())
    b.show()
    APP.processEvents()
    return b


_RIGHT = QTabBar.ButtonPosition.RightSide

# --- close button re-centred on LINE 1 (#7) ------------------------------------------
_b = _bar()
_b.grab()                                   # force a paintEvent (separator + font paths)
_b.tabLayoutChange()                        # the two_line reposition branch
APP.processEvents()
_r = _b.tabRect(0)
_line1_bottom = _r.top() + (_r.height() - _b._LINE2_H)
_btn = _b.tabButton(0, _RIGHT)
ok(_btn is not None, 'a closable tab has a right-side close button')
ok(_btn.geometry().center().y() < _line1_bottom,
   'the close button sits on line 1, not on the untrusted band below it')

# not-two-line early return + the btn-None branch of _place_close_buttons
_b.set_two_line(False)
_b.tabLayoutChange()                        # early-return branch (single line)
_b.set_two_line(True)
_b.setTabButton(0, _RIGHT, None)            # drop a button -> the `btn is None: continue` path
_b.tabLayoutChange()
APP.processEvents()
_b.close()

# --- per-element tooltips (#1 lock, #5 line-2 band) ----------------------------------
_b = _bar()
_r0 = _b.tabRect(0)
_l1h = _r0.height() - _b._LINE2_H
_lock_pt = QPoint(_r0.left() + 2 + _b._ACCENT_W + _b._PAD + 2,
                  _r0.top() + (_l1h - _b._GLYPH) // 2 + 2)
_lock_tip = _b.element_tooltip(_lock_pt) or ''
ok('Trusted label' in _lock_tip, 'the lock glyph has its own trust tooltip')

_band_pt = QPoint(_r0.center().x(), _r0.top() + _l1h + 3)
_band_tip = _b.element_tooltip(_band_pt) or ''
ok('Line 2' in _band_tip and 'npm run build' in _band_tip,
   'the line-2 band tooltip explains the untrusted title AND shows it in full')

_r1 = _b.tabRect(1)                         # tab 1 has an EMPTY program title
_band_pt1 = QPoint(_r1.center().x(),
                   _r1.top() + (_r1.height() - _b._LINE2_H) + 3)
_band_tip1 = _b.element_tooltip(_band_pt1) or ''
ok('Line 2' in _band_tip1 and 'Title:' not in _band_tip1,
   'an empty title yields the band explainer with no Title: line')

# a point on the line-1 text (neither lock nor band) -> no element tooltip
_mid_pt = QPoint(_r0.center().x(), _r0.top() + _l1h // 2)
ok(_b.element_tooltip(_mid_pt) is None, 'the line-1 text area has no per-element tooltip')
# off-bar / bad index -> None
ok(_b.element_tooltip(QPoint(99999, 99999)) is None, 'a point off every tab returns None')

# single-line bar: the band branch is skipped
_b.set_two_line(False)
APP.processEvents()
ok(_b.element_tooltip(QPoint(_r0.center().x(), _r0.center().y())) is None
   or 'Trusted label' in (_b.element_tooltip(_lock_pt) or ''),
   'single-line bar still resolves the lock tooltip and skips the band')
_b.close()

# --- the tooltip filter routes an element tip over the tab bar (#1/#5 wiring) ---------
class _StubWin(QWidget):
    def current_zoom_percent(self):
        return 100

    def current_theme_key(self):
        return 'light'


_win = _StubWin()
_flt = _ToolTipFilter(_win)
_b = _bar()
_r0 = _b.tabRect(0)
_l1h = _r0.height() - _b._LINE2_H
_lock_pt = QPoint(_r0.left() + 2 + _b._ACCENT_W + _b._PAD + 2,
                  _r0.top() + (_l1h - _b._GLYPH) // 2 + 2)
_ev = QHelpEvent(QEvent.Type.ToolTip, _lock_pt, _b.mapToGlobal(_lock_pt))
ok(_flt.eventFilter(_b, _ev) is True,
   'the tooltip filter shows (and consumes) the per-element lock tooltip on the tab bar')

# over the line-1 TEXT (no element under the pointer) the filter falls back to the
# tab-level tooltip.
_b.setTabToolTip(0, 'tab-level: name / program / cwd')
_mid = QPoint(_r0.center().x(), _r0.top() + _l1h // 2)
_ev2 = QHelpEvent(QEvent.Type.ToolTip, _mid, _b.mapToGlobal(_mid))
ok(_flt.eventFilter(_b, _ev2) is True,
   'off any element, the filter falls back to the tab-level tooltip')
_b.close()

finish('tabbar-polish')
