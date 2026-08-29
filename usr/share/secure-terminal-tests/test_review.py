#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.review -- the in-window review bar shown when text
## crossing the terminal boundary (a paste IN, or a copy OUT) carries unicode or
## control characters. Built and driven offscreen: the summary, the SINGLE mirror
## pane that reuses the terminal renderer and follows the reviewed tab's display
## mode live, the countdown that gates BOTH send buttons, that a choice is
## dispatched to the tab that held the text, and that the copy direction relabels
## the buttons + dispatches to the copy path. SKIPs (exit 77) when PyQt6 is
## unavailable.

import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QWidget
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtCore import Qt
    from secure_terminal.review import ReviewBar
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
    """Minimal stand-in for the tab that held the paste: the bar reads its theme,
    font and display MODE (the mirror renders the held text the way the tab would)
    and dispatches the choice back to it."""
    def __init__(self):
        self._theme = 'dark'
        self._mode = 'detail'         # the mirror renders in the tab's current mode
        self._markings = True
        self.dispatched = []

    def current_font_family(self):
        return 'Hack'

    def current_mode(self):
        return self._mode

    def dispatch_pending_paste(self, action):
        self.dispatched.append(('paste', action))

    def dispatch_pending_copy(self, action):
        self.dispatched.append(('copy', action))


_win = QWidget()
_bar = ReviewBar(_win)
_term = _FakeTerm()
# a paste hiding a bidi override + a Cyrillic homoglyph
_raw = 'pay' + chr(0x0430) + 'l' + chr(0x202E) + '\n'

# --- show: summary, mirror reuses the renderer, no child spawned --------------
_bar.show_review(_term, _raw, 0)
ok('hides' in _bar._summary.text() and 'bidirectional control' in _bar._summary.text(),
   'the bar summarises what the paste hides')
ok(_bar._mirror._pid is None and _bar._mirror._fd is None,
   'the mirror pane is render-only (no child process spawned)')
ok(_bar._mirror.isVisibleTo(_bar),
   'the mirror pane is shown with the bar (no Detail toggle to expand)')
# the tab is in 'detail' mode, so the mirror names each hidden character inline,
# via the real pipeline -- proving the pane renders in the TAB's mode
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText()
   and 'RIGHT-TO-LEFT OVERRIDE' in _bar._mirror.toPlainText(),
   'the mirror names the hidden characters inline (the tab\'s detail mode)')
ok(_bar._mirror.isReadOnly(),
   'the mirror pane is read-only (no typing into a review)')

# --- the mirror follows the tab's display mode LIVE ---------------------------
# Flipping the tab's mode (the normal shortcut -> set_mode -> rerender_mirror) must
# re-render the SAME pane, not a preview-only branch. In 'show' mode the homoglyph
# is displayed as-is, so its inline <U+XXXX NAME> (a detail-mode artefact) is gone.
_term_m = _FakeTerm()
_bar.show_review(_term_m, _raw, 0)
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText(),
   'the mirror starts in the tab\'s detail mode (names the homoglyph)')
_term_m._mode = 'show'
_bar.rerender_mirror()
ok('CYRILLIC SMALL LETTER A' not in _bar._mirror.toPlainText(),
   'flipping the tab to show mode live re-renders the mirror (inline names gone)')
# with no review open, rerender_mirror is a harmless no-op (window calls it always)
_bar._choose('reject')
_before = _bar._mirror.toPlainText()
_bar.rerender_mirror()
eq(_bar._mirror.toPlainText(), _before,
   'rerender_mirror is a no-op once the review is resolved (no _term)')

# --- with no delay both send buttons are enabled immediately ------------------
_bar.show_review(_FakeTerm(), _raw, 0)
ok(_bar._stripped.isEnabled() and _bar._unicode.isEnabled() and _bar._reject.isEnabled(),
   'with no delay all three buttons are enabled')

# --- a choice dispatches to the tab that held the paste, exactly once ----------
_term_c1 = _FakeTerm()
_bar.show_review(_term_c1, _raw, 0)
_bar._choose('stripped')
eq(_term_c1.dispatched, [('paste', 'stripped')],
   'a button choice is dispatched to the holding tab')
# single-shot: a second choose (a double-click, or Esc right after) is a no-op, so
# the same held paste is never dispatched twice
_bar._choose('unicode')
eq(_term_c1.dispatched, [('paste', 'stripped')],
   'a second choice after dispatch is a no-op (single-shot: dispatched exactly once)')

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
_bar._choose('reject')

# --- Esc rejects (the safe default) -------------------------------------------
_term3 = _FakeTerm()
_bar.show_review(_term3, _raw, 0)
_esc = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape,
                 Qt.KeyboardModifier.NoModifier)
_bar.keyPressEvent(_esc)
eq(_term3.dispatched, [('paste', 'reject')], 'Esc rejects the held paste')

# --- any OTHER key falls through and chooses nothing --------------------------
# The countdown exists so a stray keystroke cannot fire a paste; Esc is the only
# key the bar itself acts on. Every other key must reach the base handler without
# dispatching, or Enter/Space would send the very paste the review is holding.
_term_key = _FakeTerm()
_bar.show_review(_term_key, _raw, 0)
for _key in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space,
             Qt.Key.Key_Y, Qt.Key.Key_Tab):
    _bar.keyPressEvent(QKeyEvent(QKeyEvent.Type.KeyPress, _key,
                                 Qt.KeyboardModifier.NoModifier))
eq(_term_key.dispatched, [],
   'a non-Esc key dispatches nothing (no stray-keystroke paste)')
_bar._choose('reject')

# --- copy direction: relabelled buttons + dispatch to the copy path -----------
_term_c = _FakeTerm()
_bar.show_review(_term_c, _raw, 0, 'copy')
eq(_bar._reject.text(), "Don't copy", 'copy review: Reject becomes "Don\'t copy"')
ok(_bar._stripped.text() == 'Copy stripped' and _bar._unicode.text() == 'Copy with unicode',
   'copy review: the action buttons are relabelled for copy')
ok('copy' in _bar._summary.text().lower() and 'clipboard' in _bar._summary.text().lower(),
   'copy review: the summary is phrased for the clipboard direction')
_bar._choose('stripped')
eq(_term_c.dispatched, [('copy', 'stripped')],
   'copy review dispatches to the tab\'s copy path, not the paste path')

# --- a clean (always-mode) review does not claim hidden characters ------------
# In "always" mode a plain-ASCII paste/copy is reviewed too; classify_paste finds
# nothing, so the summary must NOT assert hidden characters that are not there.
_term_clean = _FakeTerm()
_bar.show_review(_term_clean, 'plain ascii command\n', 0, 'paste')
ok('hide' not in _bar._summary.text().lower()
   and 'hidden' not in _bar._summary.text().lower(),
   'a clean paste review does not claim hidden characters')
ok('shell' in _bar._summary.text().lower(), 'the clean-paste summary points at the shell')
ok('plain ascii command' in _bar._mirror.toPlainText(),
   'the mirror shows the held text even for a clean review')
_bar.show_review(_term_clean, 'plain ascii\n', 0, 'copy')
ok('hidden' not in _bar._summary.text().lower()
   and 'clipboard' in _bar._summary.text().lower(),
   'a clean copy review does not claim hidden characters, and names the clipboard')
_bar._choose('reject')

# --- send-button colours clear the contrast guard on BOTH themes --------------
# The two send buttons are coloured from the app's canonical SAFE_FG/RISK_FG, not
# a one-off tint tuned for one theme. Pin that (a) the widgets use those constants
# and (b) each colour stays readable against both the light and the dark theme
# background -- a regression guard for the old fg-only #0a5c37/#b1170f, which fell
# under the >=30 luminance gap on a dark desktop palette.
from secure_terminal.review import SAFE_FG as _SAFE_FG, RISK_FG as _RISK_FG  # noqa: E402
from secure_terminal.terminal import THEMES as _THEMES, _rgb as _rgb         # noqa: E402
from secure_terminal.sanitize import too_close as _too_close                 # noqa: E402
from PyQt6.QtGui import QColor as _QColor                                     # noqa: E402

ok(_SAFE_FG in _bar._stripped.styleSheet(),
   'the stripped send button uses the canonical SAFE_FG colour')
ok(_RISK_FG in _bar._unicode.styleSheet(),
   'the with-unicode send button uses the canonical RISK_FG colour')
for _theme in ('dark', 'light'):
    _bg = _rgb(_QColor(_THEMES[_theme][0]))
    for _name, _hex in (('SAFE_FG', _SAFE_FG), ('RISK_FG', _RISK_FG)):
        ok(not _too_close(_rgb(_QColor(_hex)), _bg),
           '%s send-button colour reads on the %s theme background' % (_name, _theme))

# --- hide_review tears down cleanly -------------------------------------------
_bar.show_review(_FakeTerm(), _raw, 0)
_bar.hide_review()
ok(not _bar.isVisibleTo(_win), 'hide_review hides the bar')
ok(not _bar._countdown.isActive(), 'the countdown timer is stopped on hide')
ok(_bar.reviewed_term() is None, 'hide_review clears the reviewed tab')

APP.processEvents()
print('secure-terminal-tests(review): all passed' if not _failures else
      'secure-terminal-tests(review): %d failed' % _failures)
sys.exit(1 if _failures else 0)
