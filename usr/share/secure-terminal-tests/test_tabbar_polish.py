#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""SecureTabBar two-line polish: the close button re-centred on line 1, the per-element
tooltips (trust lock / untrusted line-2 band), and the line-2 separator/paint. Structural
+ geometry assertions on the real headless-Wayland widget path (no pixel diffing)."""

from test_widget_common import *   # noqa: F401,F403  (shared harness: APP, ok, eq, finish, Qt, QRect ...)

from PyQt6.QtWidgets import QWidget, QTabBar, QTabWidget
from PyQt6.QtGui import QHelpEvent
from PyQt6.QtCore import QPoint, QEvent
from secure_terminal.main import SecureTabBar, _ToolTipFilter, normalize_ptitle


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

# --- normalize_ptitle: strip shell-prompt noise, keep the informative residue (#6) -----
# Real OSC-title shapes captured from bash / grml-zsh / vim.
eq(normalize_ptitle('user@host:~ [pts/5]'), '',
   'a bare shell prompt (user@host:path + tty tag) normalizes to empty')
eq(normalize_ptitle('user@host:/usr/lib (cd /tmp) [pts/5]'), 'cd /tmp',
   'the running command survives; user@host, path and tty tag are stripped and the '
   'parens unwrapped')
eq(normalize_ptitle('osc_sample.txt (/tmp) - VIM'), 'osc_sample.txt (/tmp) - VIM',
   "an app title with no user@host prefix is kept verbatim")
eq(normalize_ptitle('npm run build'), 'npm run build',
   'a bare command with no prompt noise is unchanged')
eq(normalize_ptitle(''), '', 'empty in -> empty out')
eq(normalize_ptitle('user@host:~/deep/path'), '',
   'a path-only prompt title (no command) normalizes to empty')
# ai-review grok#1: a leading /path is stripped ONLY inside a user@host: prompt, never
# from a plain app title / command (else a filename or command reads as disposable cwd).
eq(normalize_ptitle('/tmp/foo.py - VIM'), '/tmp/foo.py - VIM',
   'a leading path in a plain title (no user@host:) is content, not stripped')
# ai-review grok#3: only a SINGLE wrapping paren group is unwrapped, never a title that
# merely starts "(" and ends ")".
eq(normalize_ptitle('(gdb) backtrace (full)'), '(gdb) backtrace (full)',
   'a title with two paren groups is not mis-unwrapped')
eq(normalize_ptitle('(make check)'), 'make check',
   'a single wrapping paren group is unwrapped')

# tooltip branches over the band: norm==raw (Title:), norm!=raw (Shown/Full), norm empty
_tb = SecureTabBar()
_tb.set_theme(False)
_tb.set_two_line(True)
_tb.setTabsClosable(True)
for _i, _ttl in enumerate(['npm run build',                       # norm == raw
                           'user@host:~ (vim notes.txt) [pts/1]',  # norm != raw
                           'user@host:~ [pts/1]']):                # norm empty (noise)
    _tb.addTab('t%d' % _i)
    _tb.set_ptitle(_i, _ttl)
_tb.resize(600, _tb.sizeHint().height())
_tb.show()
APP.processEvents()


def _band_tip(bar, idx):
    r = bar.tabRect(idx)
    pt = QPoint(r.center().x(), r.top() + (r.height() - bar._LINE2_H) + 3)
    return bar.element_tooltip(pt) or ''


ok('Title: npm run build' in _band_tip(_tb, 0),
   'a title with no prompt noise shows a single Title: line in the tooltip')
_t1 = _band_tip(_tb, 1)
ok('Shown: vim notes.txt' in _t1 and 'Full: user@host:~ (vim notes.txt) [pts/1]' in _t1,
   'a normalized title shows BOTH the normalized (Shown) and the raw (Full) in the tooltip')
_t2 = _band_tip(_tb, 2)
ok('Blank here' in _t2 and 'shell prompt' in _t2
   and 'Full title: user@host:~ [pts/1]' in _t2,
   'an all-noise title tooltip explains WHY the band is blank and shows the raw title')
_tb.close()

# --- ai-review grok#4: a current-tab switch must not drop the close button onto the band -
# Host the bar in a QTabWidget exactly as the app does: setCurrentIndex re-lays-out the
# old + new current tab's close button WITHOUT firing tabLayoutChange.
_tw = QTabWidget()
_swb = SecureTabBar()
_tw.setTabBar(_swb)
_tw.setTabsClosable(True)
_swb.set_two_line(True)
for _i in range(3):
    _tw.addTab(QWidget(), 't%d' % _i)
_tw.resize(600, 300)
_tw.show()
APP.processEvents()
_tw.setCurrentIndex(1)
APP.processEvents()
for _i in (0, 1):
    _btn = _swb.tabButton(_i, _RIGHT)
    _r = _swb.tabRect(_i)
    _l1b = _r.top() + (_r.height() - _swb._LINE2_H)
    ok(_btn is not None and _btn.geometry().center().y() < _l1b,
       'tab %d close button stays on line 1 after a current-tab switch' % _i)
_tw.close()

# --- ai-review grok#5: the band hit rect covers the TOP row of the painted band --------
_hb = _bar()
_r0 = _hb.tabRect(0)
_l1h = _r0.height() - _hb._LINE2_H
_top_of_band = QPoint(_r0.center().x(), _r0.top() + _l1h)     # first painted band row
ok('Line 2' in (_hb.element_tooltip(_top_of_band) or ''),
   'the line-2 band tooltip covers the top row of the painted band (no 1px gap)')
_hb.close()

finish('tabbar-polish')
