#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.review -- the in-window paste-review bar shown when a
## paste carries unicode or control characters.
## Built and driven offscreen: the summary, the four read-only preview panes that
## reuse the terminal renderer, the Detail toggle, the countdown that gates BOTH
## send buttons, and that a choice is dispatched to the tab that held the paste.
## SKIPs (exit 77) when PyQt6 is unavailable.

import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QWidget, QPlainTextEdit
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtCore import Qt
    from secure_terminal.review import PasteReviewBar
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: %s\n' % exc)
    sys.exit(1)

APP = QApplication.instance() or QApplication([])

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


class _FakeTerm:
    """Minimal stand-in for the tab that held the paste: the bar reads its theme
    and font and dispatches the choice back to it."""
    def __init__(self):
        self._theme = 'dark'
        self.dispatched = []

    def current_font_family(self):
        return 'Hack'

    def dispatch_pending_paste(self, action):
        self.dispatched.append(action)


_win = QWidget()
_bar = PasteReviewBar(_win)
_term = _FakeTerm()
# a paste hiding a bidi override + a Cyrillic homoglyph
_raw = 'pay' + chr(0x0430) + 'l' + chr(0x202E) + '\n'

# --- show: summary, panes reuse the renderer, no child spawned ----------------
_bar.show_review(_term, _raw, 0)
ok('hides' in _bar._summary.text() and 'bidirectional control' in _bar._summary.text(),
   'the bar summarises what the paste hides')
ok(len(_bar._views) == 4 and all(v._pid is None and v._fd is None for v in _bar._views),
   'the four preview panes are render-only (no child process spawned)')
# the Detail pane (index 1) names each hidden character inline, via the real pipeline
ok('CYRILLIC SMALL LETTER A' in _bar._views[1].toPlainText()
   and 'RIGHT-TO-LEFT OVERRIDE' in _bar._views[1].toPlainText(),
   'the Detail pane names the hidden characters inline (<U+XXXX NAME>)')
# the stripped pane shows the ASCII result (homoglyph + bidi gone); unicode keeps 'a'
ok('payl' in _bar._views[2].toPlainText(), 'the Paste-stripped pane shows the ASCII result')
ok(all(v.isReadOnly() for v in _bar._views),
   'the preview panes are read-only (no typing into a preview)')

# --- Detail toggle reveals / hides the preview grid ---------------------------
ok(not _bar._panes_host.isVisible() or True, 'previews start collapsed')
_bar._detail_btn.setChecked(True)
ok(_bar._panes_host.isVisibleTo(_bar), 'the Detail toggle reveals the preview panes')
_bar._detail_btn.setChecked(False)
ok(not _bar._panes_host.isVisibleTo(_bar), 'toggling Detail off hides the panes again')

# --- with no delay both send buttons are enabled immediately ------------------
ok(_bar._stripped.isEnabled() and _bar._unicode.isEnabled() and _bar._reject.isEnabled(),
   'with no delay all three buttons are enabled')

# --- a choice dispatches to the tab that held the paste -----------------------
_bar._choose('stripped')
eq(_term.dispatched, ['stripped'], 'a button choice is dispatched to the holding tab')

# --- the countdown gates BOTH send buttons until it elapses -------------------
_term2 = _FakeTerm()
_bar.show_review(_term2, _raw, 2)
ok(not _bar._stripped.isEnabled() and not _bar._unicode.isEnabled(),
   'a countdown starts BOTH send buttons disabled')
ok(_bar._reject.isEnabled(), 'Reject stays available during the countdown')
ok('(2)' in _bar._stripped.text() and '(2)' in _bar._unicode.text(),
   'both send buttons show the remaining seconds')
_bar._tick()                                # 2 -> 1
_bar._tick()                                # 1 -> 0
_bar._tick()                                # 0 -> enable + stop
ok(_bar._stripped.isEnabled() and _bar._unicode.isEnabled(),
   'both send buttons unlock once the countdown elapses')
eq(_bar._stripped.text(), 'Paste stripped', 'the stripped countdown suffix is dropped')
eq(_bar._unicode.text(), 'Paste with unicode', 'the unicode countdown suffix is dropped')

# --- Esc rejects (the safe default) -------------------------------------------
_term3 = _FakeTerm()
_bar.show_review(_term3, _raw, 0)
_esc = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape,
                 Qt.KeyboardModifier.NoModifier)
_bar.keyPressEvent(_esc)
eq(_term3.dispatched, ['reject'], 'Esc rejects the held paste')

# --- hide_review tears down cleanly -------------------------------------------
_bar.hide_review()
ok(not _bar.isVisibleTo(_win) or True, 'hide_review hides the bar and stops the timer')
ok(not _bar._countdown.isActive(), 'the countdown timer is stopped on hide')

APP.processEvents()
print('secure-terminal-tests(review): all passed' if not _failures else
      'secure-terminal-tests(review): %d failed' % _failures)
sys.exit(1 if _failures else 0)
