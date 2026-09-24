#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Startup winsize / first-prompt race regression suite (bug #9).

The shell must draw its FIRST prompt at the FINAL terminal width, so there is never a
corrective SIGWINCH that makes zsh reprint and leave a stray padded first line. The
idiomatic design (st / VTE / xterm / kitty): the PTY winsize is established BEFORE the
child renders anything. secure-terminal does this by DEFERRING the shell spawn until the
widget has real geometry and SIZING the PTY before the child exec's (a go-pipe barrier
holds the child pre-exec until the parent has set TIOCSWINSZ).

Canaries (each FAILS on the pre-fix eager-fork-at-ctor code):
  - child-size invariant: a child that reports `stty size` sees the widget's REAL grid,
    not the fork-time default -- the direct, deterministic repro of the root cause.
  - deferred spawn: constructing without geometry does NOT fork a child yet.
  - spawn triggers: both showEvent and resizeEvent spawn a pending child, exactly once.
  - initial_grid: the test-only eager path forks at exactly the requested grid, proving
    the size-before-exec barrier.
"""

import os
import re
import sys
import signal
import tempfile

from st_qt_platform import require_wayland
require_wayland('secure-terminal-tests(startup-winsize)')
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp(prefix='st-winsize-cfg-')
os.environ['XDG_STATE_HOME'] = tempfile.mkdtemp(prefix='st-winsize-state-')
try:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
except (OSError, ValueError, AttributeError):
    pass

try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import QEventLoop, QTimer
    from secure_terminal.terminal import SecureTerminal
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(startup-winsize): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

APP = QApplication.instance() or QApplication([])
PASS = 0
FAIL = 0
_LIVE = []


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        sys.stderr.write('FAIL: ' + msg + '\n')


def pump(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_for(predicate, timeout_ms=4000, step_ms=20):
    import time as _time
    deadline = _time.monotonic() + timeout_ms / 1000.0
    while not predicate():
        if _time.monotonic() >= deadline:
            return predicate()
        pump(step_ms)
    return True


def _stty_term(**kw):
    ## A child that prints its winsize (stty size -> "ROWS COLS") once, then holds the pty
    ## open so the master fd stays readable. Read back what size the child was BORN at.
    kw.setdefault('command', ['/bin/sh', '-c', 'stty size; exec sleep 60'])
    term = SecureTerminal(**kw)
    _LIVE.append(term)
    return term


def _reported_size(term):
    m = re.search(r'(\d+)\s+(\d+)', term.toPlainText())
    return (int(m.group(1)), int(m.group(2))) if m else None


def test_child_born_at_widget_grid():
    ## THE repro: born at ctor (pre-fix) the child runs stty at the fork-time default and
    ## reports a size that does NOT match the widget's real grid; born after geometry
    ## (post-fix) it reports exactly the widget grid.
    term = _stty_term()
    term.resize(1000, 600)
    term.show()
    wait_for(lambda: term._cols > 0 and _reported_size(term) is not None)
    reported = _reported_size(term)
    grid = (term._rows, term._cols)
    ok(reported == grid and term._cols > 0,
       'child stty size %r must equal the widget grid %r' % (reported, grid))


def test_deferred_no_child_before_geometry():
    ## Constructing without geometry (and without the test-only initial_grid) must NOT
    ## fork a child yet -- the spawn is deferred to the first real sizing.
    term = _stty_term()
    ok(term._pid is None,
       'no child before geometry: _pid=%r must be None (deferred spawn)' % (term._pid,))


def test_spawn_fires_on_show_and_resize():
    ## Both geometry handlers spawn a pending child, and only once. Drive them directly so
    ## the show-path (a tab shown without a size change -- a background tab switch) and the
    ## resize-path are BOTH exercised deterministically, independent of Qt event ordering.
    from PyQt6.QtGui import QShowEvent, QResizeEvent
    from PyQt6.QtCore import QSize
    t_show = _stty_term()
    ok(t_show._pid is None, 'no child before showEvent (deferred)')
    t_show.showEvent(QShowEvent())
    ok(t_show._pid is not None, 'showEvent spawns the deferred child')
    t_resize = _stty_term()
    ok(t_resize._pid is None, 'no child before resizeEvent (deferred)')
    t_resize.resizeEvent(QResizeEvent(QSize(400, 200), QSize(0, 0)))
    ok(t_resize._pid is not None, 'resizeEvent spawns the deferred child')
    pid = t_resize._pid
    t_resize.showEvent(QShowEvent())               # a second trigger must not re-spawn
    ok(t_resize._pid == pid and not t_resize._spawn_pending,
       'a second geometry event on an already-spawned tab is a no-op')


def test_initial_grid_eager_size_before_exec():
    ## The test-only eager path forks at exactly the requested grid; the child sees it via
    ## its first stty size -> proves the winsize is set BEFORE the child exec's. initial_grid
    ## is (cols, rows) -- matching _grid_size()/_set_winsize(cols, rows); stty size prints
    ## "rows cols", so (cols=100, rows=30) -> "30 100".
    try:
        term = _stty_term(initial_grid=(100, 30))
    except TypeError as exc:
        ok(False, 'initial_grid kwarg missing: %s' % exc)
        return
    ok(term._pid is not None, 'initial_grid must spawn eagerly (a live child)')
    wait_for(lambda: _reported_size(term) is not None)
    ok(_reported_size(term) == (30, 100),
       'child born at initial_grid (cols=100, rows=30) must report "30 100", got %r'
       % (_reported_size(term),))


def test_deferred_tui_spawns_at_geometry():
    ## TUI also sizes the PTY before releasing the child (not just CLI), closing the raceful
    ## 0x0 window a post-exec _make_screen would leave. A deferred TUI term shown at real
    ## geometry spawns its child and seeds the pyte screen at the widget grid; the child sees
    ## that same size. (The exact race window is timing-bound, so this asserts the settled
    ## consistency -- child size == pyte-screen grid -- rather than the transient.)
    term = _stty_term(tui=True)
    ok(term._pid is None, 'deferred tui term: no child before geometry')
    term.resize(900, 500)
    term.show()
    wait_for(lambda: term._pid is not None and term._screen is not None
             and _reported_size(term) is not None)
    dims = (term._screen.columns, term._screen.lines) if term._screen else None
    ok(term._pid is not None and dims is not None
       and _reported_size(term) == (dims[1], dims[0]),
       'deferred tui child born at the pyte-screen grid: child=%r screen=%r'
       % (_reported_size(term), dims))


for _t in (test_child_born_at_widget_grid,
           test_deferred_no_child_before_geometry,
           test_spawn_fires_on_show_and_resize,
           test_initial_grid_eager_size_before_exec,
           test_deferred_tui_spawns_at_geometry):
    try:
        _t()
    except Exception as exc:  # pylint: disable=broad-except
        ok(False, '%s raised %r' % (_t.__name__, exc))

try:
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
except (OSError, ValueError, AttributeError):
    pass
for _term in _LIVE:
    try:
        _term.shutdown()
    except Exception:
        pass

sys.stdout.write('secure-terminal-tests(startup-winsize): %d passed, %d failed\n'
                 % (PASS, FAIL))
try:
    # Persist coverage before os._exit (which skips coverage's atexit save), so the
    # deferred-spawn lines this suite alone exercises are counted under the gate.
    import coverage as _coverage
    _covw = _coverage.Coverage.current()
    if _covw is not None:
        _covw.save()
except Exception:
    pass                        # coverage is optional instrumentation, never fatal
sys.stdout.flush()
sys.stderr.flush()
os._exit(0 if FAIL == 0 else 1)
