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
## the buttons + dispatches to the copy path. PyQt6 is REQUIRED: it fails loud
## (exit 1), never a silent skip, when the dependency is unavailable.

import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QWidget
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtCore import Qt, QEvent
    from secure_terminal.review import ReviewBar
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: %s\n' % exc)
    sys.exit(1)

import secure_terminal.review as _rev                                          # noqa: E402

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
        self.last_text = None         # the text a dispatch delivered (edited buffer)

    def current_font_family(self):
        return 'Hack'

    def current_mode(self):
        return self._mode

    def current_zoom(self):
        return 100

    def _bracketed_paste_active(self):
        # the delivered-form preview drops the trailing auto-submit CR when the
        # target is NOT bracketed (a bare shell prompt) -- the common case.
        return False

    def dispatch_pending_paste(self, action, text=None):
        self.dispatched.append(('paste', action))
        self.last_text = text

    def dispatch_pending_copy(self, action, edited=None):
        self.dispatched.append(('copy', action))
        self.last_text = edited


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

# The mirror bounds its RENDER (render_preview), not the source length, so it cannot
# hang the pane; delivery still sends the WHOLE text -- so the summary must warn that
# the preview is truncated, in this unspoofable label. A unicode paste whose SOURCE
# is well under the cap still overflows because detail badges expand it ~32x, and the
# notice must fire on that. (canary: a source-length notice would stay silent here --
# 200k source chars < the 1M cap -- and a no-cap build had no notice at all.)
_bar.show_review(_term, chr(0x0430) * (_bar._mirror._RAW_MAX // 5), 0)
ok('truncated' in _bar._summary.text()
   and 'FULL paste' in _bar._summary.text(),
   'an over-render unicode paste warns the preview is truncated + full paste delivers')
_bar.show_review(_term, _raw, 0)                 # small paste: no truncation notice
ok('truncated' not in _bar._summary.text(),
   'a small paste carries no truncation notice')

# _delivered (hover/focus of a delivery button) must not materialize an unbounded
# paste: sanitizing a 50MB clipboard here -- BEFORE the render cap -- froze the UI
# (~8.6s / ~0.5GB). It sanitizes only a bounded source prefix. (canary: the uncapped
# version returned the full sanitized raw, ~3x the cap.)
_bar.show_review(_term, 'a' * (_bar._mirror._RAW_MAX * 3), 0)
ok(len(_bar._delivered('stripped')) <= _bar._mirror._RAW_MAX,
   '_delivered sanitizes only a bounded source prefix (no full-paste materialization)')
_bar._choose('reject')

# When _delivered TRUNCATES the paste, an embedded newline that lands exactly at the
# cap must NOT be stripped as a "trailing submit": the truncated preview would then
# deceptively show a safe prompt-wait while real delivery auto-runs the lines before
# it (agy/coderabbit). A truncated delivery preview keeps that boundary newline.
# (canary: the unconditional submit-strip removed it, hiding the auto-run.)
_capn = _bar._mirror._RAW_MAX
_bar.show_review(_term, 'A' * (_capn - 1) + '\nB', 0)     # newline at index _capn-1
ok(_bar._delivered('stripped').endswith('\n'),
   'a truncated delivery preview keeps a boundary newline (no false submit-strip)')
_bar._choose('reject')

# classify_paste must be capped too -- it is the one uncapped materialization in
# show_review, and on a 50-100MB clipboard it froze the Qt thread for tens of seconds
# BEFORE the Reject button appeared (claude). A hidden char BEYOND the cap is not
# counted (the truncation notice then discloses the count is partial). (canary: the
# uncapped classify counted the beyond-cap bidi override, so 'bidirectional' appeared.)
_capc = _bar._mirror._RAW_MAX
_bar.show_review(_term, 'a' * _capc + chr(0x202E), 0)    # RTL override past the cap
ok('bidirectional' not in _bar._summary.text()
   and 'scanned for hidden' in _bar._summary.text(),
   'classify_paste is capped: a beyond-cap hidden char is uncounted; the notice says '
   'the count is partial (scanned only the first N chars), not a silent "0 hidden"')
_bar._choose('reject')

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

# --- delivered-form-on-focus: the mirror shows what a button SENDS -------------
# codex HIGH: the mirror must not hide the DELIVERED (de-obfuscated) form behind a
# label. Focusing/hovering a delivery button re-renders the mirror to that button's
# exact sent text, so a homoglyph 'ram' revealed as 'rm' cannot cross unseen.
_term_d = _FakeTerm()
_rawd = 'r' + chr(0x0430) + 'm /etc\n'      # Cyrillic a: reads as 'ram', strips to 'rm'
_bar.show_review(_term_d, _rawd, 0)
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText(),
   'the mirror starts on the RAW held text (the homoglyph is named in detail mode)')
# hover the ASCII delivery button -> its DELIVERED, de-obfuscated form
_bar.eventFilter(_bar._stripped, QEvent(QEvent.Type.Enter))
_dtext = _bar._mirror.toPlainText()
ok('rm /etc' in _dtext and 'CYRILLIC SMALL LETTER A' not in _dtext,
   'hovering Paste (ASCII) shows the DELIVERED, de-obfuscated form (ram -> rm)')
# re-entering the SAME button is a no-op (already previewing it)
_bar.eventFilter(_bar._stripped, QEvent(QEvent.Type.Enter))
ok('rm /etc' in _bar._mirror.toPlainText(),
   're-entering the same delivery button is a no-op (preview unchanged)')
# un-hover with nothing else focused/hovered -> back to the raw held text
_bar.eventFilter(_bar._stripped, QEvent(QEvent.Type.Leave))
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText(),
   'un-hovering the delivery button returns the mirror to the raw held text')
# hovering Paste (unicode) keeps the homoglyph (named), unlike Paste (ASCII)
_bar.eventFilter(_bar._unicode, QEvent(QEvent.Type.Enter))
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText(),
   'hovering Paste (unicode) keeps the homoglyph (named), unlike Paste (ASCII)')
_bar.eventFilter(_bar._unicode, QEvent(QEvent.Type.Leave))
_bar._choose('reject')

# --- REGRESSION (agy): the mirror is derived FOCUS-FIRST ----------------------
# Keyboard Enter/Space commits the FOCUSED delivery button, so the mirror must show
# THAT button's outcome even while the mouse hovers the sibling -- else the mirror
# would show the hovered (stripped) form while Enter dispatches the focused (unicode)
# payload, an unseen dispatch. The old code set the preview to whatever was hovered.
_term_g = _FakeTerm()
_bar.show_review(_term_g, _rawd, 0)
_bar.eventFilter(_bar._unicode, QEvent(QEvent.Type.FocusIn))    # Tab to Paste (unicode)
_bar.eventFilter(_bar._stripped, QEvent(QEvent.Type.Enter))     # mouse hovers Paste (ASCII)
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText(),
   'focus-first: hovering the sibling keeps the mirror on the FOCUSED (unicode) '
   'outcome, not the hovered (stripped) one Enter would not send')
# un-hovering the sibling still shows the focused button, never stale
_bar.eventFilter(_bar._stripped, QEvent(QEvent.Type.Leave))
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText(),
   'un-hovering the sibling reverts to the focused button, not a stale preview')
# focus-out with nothing hovered -> raw
_bar.eventFilter(_bar._unicode, QEvent(QEvent.Type.FocusOut))
ok('CYRILLIC SMALL LETTER A' in _bar._mirror.toPlainText(),
   'focusing out with nothing hovered returns the mirror to the raw text')
_bar._choose('reject')

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

# --- the countdown gates the delivery CLICK, but the buttons stay ENABLED ------
# A disabled Qt button cannot take keyboard focus (and does not reliably receive
# hover), so disabling the send buttons during the countdown would kill the
# delivered-form preview -- the very thing the countdown window is for. So the
# buttons stay ENABLED (focus/hover -> preview) and the CLICK is gated instead.
_term2 = _FakeTerm()
_bar.show_review(_term2, _raw, 2)
ok(_bar._stripped.isEnabled() and _bar._unicode.isEnabled(),
   'the send buttons stay ENABLED during the countdown (so focus/hover can preview)')
ok(_bar._gated, 'but the anti-fat-finger gate is up')
ok(_bar._reject.isEnabled(), 'Reject stays available during the countdown')
ok('(2)' in _bar._stripped.text() and '(2)' in _bar._unicode.text(),
   'both send buttons show the remaining seconds')
# a DELIVERY choice while gated is a no-op -- nothing dispatched, still reviewing
_bar._choose('stripped')
eq(_term2.dispatched, [], 'a delivery choice during the countdown is a gated no-op')
ok(_bar._term is _term2, 'the bar keeps reviewing (the gated click did not resolve it)')
_bar._tick()                                # 2 -> 1
_bar._tick()                                # 1 -> 0
_bar._tick()                                # 0 -> drop the gate + stop
ok(not _bar._gated, 'the gate drops once the countdown elapses')
eq(_bar._stripped.text(), 'Paste (ASCII)', 'the ASCII countdown suffix is dropped')
eq(_bar._unicode.text(), 'Paste (unicode)', 'the unicode countdown suffix is dropped')
# now a delivery choice ACTS
_bar._choose('stripped')
eq(_term2.dispatched, [('paste', 'stripped')],
   'after the countdown a delivery choice dispatches')
ok(_bar._term is None, 'and _choose resolves + hides the bar')

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
ok(_bar._stripped.text() == 'Copy (ASCII)' and _bar._unicode.text() == 'Copy (unicode)',
   'copy review: the action buttons are relabelled for copy')
ok('copy' in _bar._summary.text().lower() and 'clipboard' in _bar._summary.text().lower(),
   'copy review: the summary is phrased for the clipboard direction')
_bar._choose('stripped')
eq(_term_c.dispatched, [('copy', 'stripped')],
   'copy review dispatches to the tab\'s copy path, not the paste path')

# --- a clean (always-mode) review shows a positive ASCII-only all-clear -------
# In "always" mode a plain-ASCII paste/copy is reviewed too; nothing is hidden, so
# the bar states a positive green all-clear rather than claiming classes that are
# not there. (A TRUNCATED clean scan cannot promise this -- it keeps the cautious
# summary + notice, covered by the truncation checks above.)
_term_clean = _FakeTerm()
_bar.show_review(_term_clean, 'plain ascii command\n', 0, 'paste')
eq(_bar._summary.text(), _rev._CLEAN_MSG,
   'a clean paste review shows the ASCII-only all-clear, not a hidden-char claim')
ok('hides' not in _bar._summary.text().lower(),
   'the all-clear does not claim the paste hides anything')
ok(_rev.SAFE_FG in _bar._dot.styleSheet(),
   'the risk dot turns safe-green for a clean paste review')
ok('plain ascii command' in _bar._mirror.toPlainText(),
   'the mirror shows the held text even for a clean review')
_bar.show_review(_term_clean, 'plain ascii\n', 0, 'copy')
eq(_bar._summary.text(), _rev._CLEAN_MSG,
   'a clean copy review shows the same ASCII-only all-clear')
_bar._choose('reject')

# --- colour: ONLY Reject is green; the delivery buttons are uncoloured --------
# Only Reject (the one unconditionally-safe choice) is tinted, with the canonical
# SAFE_FG. The two delivery buttons carry NO colour on purpose -- neither is safe in
# general (stripping de-obfuscates, keeping preserves deception), so a green would
# mislead; the mirror shows the truth. The contrast guard still applies to SAFE_FG
# (Reject) and RISK_FG (the risk dot), readable on both themes.
from secure_terminal.review import SAFE_FG as _SAFE_FG, RISK_FG as _RISK_FG  # noqa: E402
from secure_terminal.terminal import THEMES as _THEMES, _rgb as _rgb         # noqa: E402
from secure_terminal.sanitize import too_close as _too_close                 # noqa: E402
from PyQt6.QtGui import QColor as _QColor                                     # noqa: E402

ok(_SAFE_FG in _bar._reject.styleSheet(),
   'only Reject is tinted, with the canonical SAFE_FG (safe-green)')
ok(_SAFE_FG not in _bar._stripped.styleSheet()
   and _RISK_FG not in _bar._stripped.styleSheet(),
   'Paste (ASCII) is UNCOLOURED (stripping is not unconditionally safe)')
ok(_SAFE_FG not in _bar._unicode.styleSheet()
   and _RISK_FG not in _bar._unicode.styleSheet(),
   'Paste (unicode) is UNCOLOURED (keeping unicode is not unconditionally safe)')
for _theme in ('dark', 'light'):
    _bg = _rgb(_QColor(_THEMES[_theme][0]))
    for _name, _hex in (('SAFE_FG', _SAFE_FG), ('RISK_FG', _RISK_FG)):
        ok(not _too_close(_rgb(_QColor(_hex)), _bg),
           '%s reads on the %s theme background' % (_name, _theme))

# --- hide_review tears down cleanly -------------------------------------------
_bar.show_review(_FakeTerm(), _raw, 0)
_bar.hide_review()
ok(not _bar.isVisibleTo(_win), 'hide_review hides the bar')
ok(not _bar._countdown.isActive(), 'the countdown timer is stopped on hide')
ok(_bar.reviewed_term() is None, 'hide_review clears the reviewed tab')

# --- the breakdown: Structure section + per-class hidden-character table ------
# _raw hides a bidi override + a Cyrillic homoglyph and ends in a submit newline.
_bar.show_review(_term, _raw, 0)
_d = _bar._detail.text()
ok('Structure' in _d and 'Hidden characters' in _d,
   'the breakdown shows a Structure section and a hidden-character table')
ok('Look-alike' in _d and 'Bidirectional control' in _d,
   'the table names the finer classes (homoglyph, bidi) the summary folds')
ok('Box-drawing' in _d and 'Combining' in _d,
   'the table lists every class incl. those absent (what is NOT present is explicit)')
ok('If accepted' in _d and 'press Enter to run' in _d,
   'a paste shows the never-auto-run guarantee row (waits for Enter, non-bracketed)')
# selectable so the user can copy the text to ask about it
ok(_bar._summary.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse,
   'the summary text is selectable')
ok(_bar._detail.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse,
   'the breakdown text is selectable')

# box-drawing is its OWN low-risk row, not folded into "other non-ASCII"
_bar.show_review(_term, 'a' + chr(0x2500) + chr(0x2502) + 'b', 0)
ok('Box-drawing / blocks' in _bar._detail.text(),
   'box-drawing glyphs get their own table row')

# bracketed target: the guarantee row states the program buffers it as text
_bt = _FakeTerm()
_bt._bracketed_paste_active = lambda: True  # type: ignore[method-assign]
_bar.show_review(_bt, _raw, 0)
ok('your program receives it as text' in _bar._detail.text(),
   'a bracketed-paste target shows the program-receives-it-as-text guarantee')

# an ASCII-only paste (held here because it is multi-line) reads as a positive
# all-clear: green dot, the clean summary, and no hidden-character rows
_bar.show_review(_term, 'ls\necho hi\n', 0)
eq(_bar._summary.text(), _rev._CLEAN_MSG, 'an ASCII-only paste gets the clean all-clear')
ok(_rev.SAFE_FG in _bar._dot.styleSheet(),
   'the risk dot turns safe-green for an ASCII-only paste')
ok('(none)' in _bar._detail.text() and 'multi-line' in _bar._detail.text(),
   'the clean breakdown shows no hidden chars but still flags the multi-line structure')

# #20: the truncation notice names the real DIRECTION (copy, not paste)
_bar.show_review(_term, chr(0x0430) * (_bar._mirror._RAW_MAX // 5), 0, 'copy')
ok('the FULL copy' in _bar._summary.text() and 'FULL paste' not in _bar._summary.text(),
   'a truncated COPY review names the copy action, not "paste" (#20)')
_bar.show_review(_term, _raw, 0)                 # restore paste state

# --- editable held text: edits drive the summary/table AND what delivers -------
_et = _FakeTerm()
_bar.show_review(_et, _raw, 0)                    # _raw hides a bidi + a homoglyph
ok('hides' in _bar._summary.text(), 'the held unicode is flagged before any edit')
_bar._edit.setPlainText('echo hello')            # edit down to plain ASCII
eq(_bar._summary.text(), _rev._CLEAN_MSG,
   'editing the held text to ASCII re-runs the classifier and clears the summary')
ok('(none)' in _bar._detail.text(),
   'the breakdown updates from the edited buffer (no hidden chars)')
_bar._choose('unicode')
eq(_et.last_text, 'echo hello',
   'a delivery choice sends the EDITED buffer, not the originally held text')
_et2 = _FakeTerm()
_bar.show_review(_et2, 'plain', 0)
_bar._edit.setPlainText('a' + chr(0x202E) + 'b')  # edit a hidden char IN
ok('Bidirectional control' in _bar._detail.text() and 'hides' in _bar._summary.text(),
   'editing a hidden char into the buffer re-flags it in the summary + table')
_bar._choose('reject')

# a truncated review marks the Structure counts as a scanned prefix, not a definite
# total (a 2M-char paste must not read a flat "1,000,000 characters")
_bar.show_review(_term, chr(0x0430) * (_bar._mirror._RAW_MAX // 5), 0)
ok('scanned prefix' in _bar._detail.text(),
   'a truncated review marks the Length as a scanned prefix, not a definite count')
_bar._choose('reject')

# CANARY: the table depends on classify_paste_detail, not a hardcoded layout
_saved_detail = _rev.classify_paste_detail
_rev.classify_paste_detail = lambda raw: {
    'counts': dict.fromkeys(
        ('bidi', 'control', 'invisible', 'confusable', 'combining',
         'nonascii', 'structural'), 0),
    'lines': 1, 'multiline': False, 'ends_with_submit': False,
    'chars': 0, 'bytes': 0}
try:
    _cw2 = QWidget()
    _cb2 = ReviewBar(_cw2)
    _cb2.show_review(_FakeTerm(), _raw, 0)
    ok('Look-alike' not in _cb2._detail.text() or '(none)' in _cb2._detail.text(),
       'CANARY: the breakdown table depends on classify_paste_detail (has teeth)')
finally:
    _rev.classify_paste_detail = _saved_detail

# --- CANARY: the hidden-character summary has teeth ---------------------------
# A classifier that finds nothing must make "the bar summarises what the paste
# hides" FALSE -- proof the summary checks are not tautologies (0 failures !=
# 0 coverage), mirroring the per-class self-test in test_invariants.py. review.py
# resolves classify_paste at show_review time, so monkeypatching the module symbol
# drives the same path the checks above do; restore it after.
import secure_terminal.review as _review_mod                                   # noqa: E402
_saved_classify = _review_mod.classify_paste
_review_mod.classify_paste = lambda raw: []      # broken: detects no hidden classes
try:
    _cwin = QWidget()
    _cbar = ReviewBar(_cwin)
    _cbar.show_review(_FakeTerm(), _raw, 0)
    ok('bidirectional control' not in _cbar._summary.text(),
       'CANARY: the hidden-character summary depends on classify_paste (has teeth)')
finally:
    _review_mod.classify_paste = _saved_classify

APP.processEvents()
print('secure-terminal-tests(review): all passed' if not _failures else
      'secure-terminal-tests(review): %d failed' % _failures)
sys.exit(1 if _failures else 0)
