#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared harness for the offscreen widget/window tests, split across test_widget.py
and test_widget2.py so the two halves run as separate processes (the coverage gate
runs them concurrently; combine unions the result). Each half does
`from test_widget_common import *`, runs its sections, then calls finish(<label>).

The pass/fail counters live HERE: ok()/eq() (imported into each half) mutate this
module's PASS/FAIL, and finish() reads them -- so a half's tally is correct even
though `from ... import *` binds its own PASS/FAIL names to the import-time value.

Needs PyQt6 (offscreen) and python3-pyte, declared dependencies of the test, so a
missing one is a hard FAILURE, not a skip -- a security-relevant test must never be
silently disabled.
"""

import os
import sys
import signal
import tempfile

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp(prefix='st-widget-cfg-')
# Isolate session state too, or a real leftover session on the box would be
# restored and make the window's initial mode/tabs nondeterministic.
os.environ['XDG_STATE_HOME'] = tempfile.mkdtemp(prefix='st-widget-state-')
try:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
except (OSError, ValueError, AttributeError):
    pass                    # not the main thread / unsupported: reaping is optional

try:
    from PyQt6.QtWidgets import QApplication, QInputDialog
    from PyQt6.QtGui import QKeyEvent, QColor, QTextCursor
    from PyQt6.QtCore import QEvent, Qt, QTimer, QEventLoop, QMimeData, QPoint
    from secure_terminal.terminal import SecureTerminal, tui_available
except Exception as exc:  # pylint: disable=broad-except
    # Fail closed: a missing test dependency (PyQt6, pyte, the module) must not
    # be silently skipped.
    sys.stderr.write('secure-terminal-tests(widget): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

APP = QApplication.instance() or QApplication([])
PASS = 0
FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        sys.stderr.write('FAIL: ' + msg + '\n')


def eq(got, want, msg):
    ok(got == want, '%s -> %r, want %r' % (msg, got, want))


def pump(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def key(term, qtkey, text='', mods=Qt.KeyboardModifier.NoModifier):
    term.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, qtkey, mods, text))


def spy_writes(term):
    sent: list[bytes] = []
    term._write = sent.append          # pylint: disable=protected-access
    return sent


def feed_output(term, raw):
    """Drive the real _on_readable with `raw` bytes via a pipe, as if the child had
    printed them, so the full output path (pyte feed + _handle_osc + line render)
    runs -- not a shortcut that skips the OSC read handlers."""
    r, w = os.pipe()
    old = term._fd                         # pylint: disable=protected-access
    term._fd = r
    w_open = True
    try:
        os.write(w, raw)
        os.close(w)
        w_open = False
        term._on_readable()                # pylint: disable=protected-access
    finally:
        term._fd = old
        os.close(r)
        if w_open:
            os.close(w)
    # CLI line-mode paints are debounced to ~60fps by a single-shot timer; in the
    # live app the paint fires from the event loop shortly after the read. These
    # synchronous tests feed then inspect at once, so flush the pending paint here
    # (the same flush teardown and every transcript/copy getter perform) so the
    # document reflects the just-fed bytes without pumping a real 16ms wait.
    term._flush_paint()


# MARKING_COLORS is theme-keyed {fg, bg} per risk class (dark gets a background
# BAND on the dangerous classes; light and honest-foreign stay fg-only). These
# read the fg / bg for a widget's CURRENT theme.
def mark_fg(term, cls):
    return term.MARKING_COLORS[term._theme][cls]['fg']    # noqa: protected-access


def mark_bg(term, cls):
    return term.MARKING_COLORS[term._theme][cls]['bg']    # noqa: protected-access


# A `-- PROGRAM` launch tab now correctly counts as a running program, so closing
# its window pops the confirm-on-close dialog -- which would block the user-less
# harness. Auto-answer "Yes" (quit anyway) so window closes never hang here;
# test_mainwin owns the explicit confirm-close behaviour tests.
from PyQt6.QtWidgets import QMessageBox        # noqa: E402
QMessageBox.question = staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes)


def fmt_of_char(term, ch):
    """The QTextCharFormat of the first cell rendering `ch` in `term`'s document.
    Shared by both halves (a colour cell is asserted in each)."""
    doc = term.toPlainText()
    idx = doc.index(ch)
    cur = term.textCursor()
    cur.setPosition(idx)
    cur.setPosition(idx + 1, QTextCursor.MoveMode.KeepAnchor)
    return cur.charFormat()


def glyph_pt(term, idx):
    """Viewport point at the visual center of the grid/line cell whose glyph sits
    AT document position idx. The native caret is hidden (cursorRect width 0), so
    center() of a single caret rect lands on the cell boundary; take the midpoint to
    idx+1, as the astral-glyph hover check already does. Shared by both halves."""
    a = QTextCursor(term.document())
    a.setPosition(idx)
    b = QTextCursor(term.document())
    b.setPosition(idx + 1)
    ra, rb = term.cursorRect(a), term.cursorRect(b)
    x = (ra.x() + rb.x()) // 2 if rb.x() > ra.x() else ra.x() + 3
    return QPoint(x, ra.center().y())


def finish(label):
    """Report this half's tally and exit. The offscreen Qt platform can crash in its
    static teardown after a clean run (destroying the many widgets/pyte screens/timers
    these suites build), which would turn a fully-passing run into a non-zero exit. All
    tests have run and the result is known, so persist coverage and exit hard, bypassing
    that teardown."""
    sys.stdout.write('secure-terminal-tests(%s): %d passed, %d failed\n'
                     % (label, PASS, FAIL))
    try:
        import coverage as _coverage
        _covw = _coverage.Coverage.current()
        if _covw is not None:
            _covw.save()
    except Exception:
        pass                    # coverage is optional instrumentation, never fatal
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0 if FAIL == 0 else 1)
