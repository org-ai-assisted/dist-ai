#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared harness for the headless-Wayland MainWindow / `ctl` tests, split across
test_mainwin.py .. test_mainwin5.py so each cohesive suite runs as its own
process (the coverage gate runs them concurrently; combine UNIONS the result,
so the split covers secure_terminal.main identically to the old single file).
Each suite does `from test_mainwin_common import *`, builds its OWN
`win = MainWindow(); win.new_tab()`, runs its sections, then calls
finish(<label>).

Tests for secure_terminal.main's window-level dialogs and the `ctl`
remote-control client. Runs under a REAL headless Wayland compositor (labwc, via
require_wayland below) -- NEVER the offscreen QPA platform, whose
focus/active-window/tray behaviour differs. A second long-lived MainWindow plus
its modal dialogs perturbs Qt teardown, so each suite builds, exercises and
destroys its windows in isolation. Modal dialogs are shown with QDialog.exec()
stubbed (Accepted/Rejected) so nothing blocks, and the ctl client is driven with
ipc.send_request stubbed to canned replies. Fails closed (exit 1) if a required
dependency is missing -- deps are hard.

The pass/fail counters live HERE: ok()/eq() (imported into each suite) mutate
this module's PASS/FAIL, and finish() reads them -- so a suite's tally is correct
even though `from ... import *` binds its own PASS/FAIL names to the import-time
value.

Each suite gets a FRESH `win` and the identical monkeypatch baselines (below),
so a mutation one section leaves on `win` or on a global stub cannot leak into a
section that lands in a different suite: cross-suite ordering dependencies are
eliminated by the fresh process. A section that relied on a prior section's
un-restored state surfaces as a FAILURE (not a silent coverage dip).
"""

import os
import sys
import time
import signal
import atexit
import tempfile

from st_qt_platform import require_wayland
require_wayland('secure-terminal-tests(mainwin)')
# Pin the font DPI to 72 BEFORE any QApplication so font metrics are deterministic
# by default. The responsive-toolbar tier assertions are calibrated to the real
# compositor's ~9pt metrics; bare offscreen defaults to a different DPI (a larger
# 12pt), which widens the toolbar tiers. The runners export this before python
# starts (the authoritative safe path); this setdefault is the fallback for a
# direct `python3 test_mainwinN.py` run, and honours an explicit override either way.
os.environ.setdefault('QT_FONT_DPI', '72')

try:
    from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox
    import secure_terminal.main as M
    from secure_terminal.main import MainWindow, _ctl_main
    from secure_terminal.terminal import SecureTerminal as _ST_reap
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

APP = QApplication.instance() or QApplication([])

# Isolate config/state AFTER the QApplication above: Qt connects to the Wayland
# compositor during QApplication() using the compositor's XDG_RUNTIME_DIR, so the
# single-instance-socket redirect below must not run first, or Qt cannot find the
# wayland socket and aborts. Config/state redirect keeps every window loading
# clean defaults regardless of what a concurrent suite wrote to the drop-in dirs.
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp()
os.environ['XDG_STATE_HOME'] = tempfile.mkdtemp()
os.environ['XDG_RUNTIME_DIR'] = tempfile.mkdtemp()   # single-instance socket dir

# _require_default_font (main) aborts startup with exit 1 when the default font
# (Hack / fonts-hack, a hard dependency) is absent, so Qt cannot silently
# substitute a fallback that reintroduces confusable glyphs / ligatures. fonts-hack
# need not be installed in the test environment, so every full-startup test pins
# the check present via this fake QFontDatabase; the dedicated _require_default_font
# test drives both branches AND the real families() API (to catch an API break).
_REAL_QFONTDB = M.QFontDatabase


class _FontDBPresent:
    @staticmethod
    def families():
        return [M.DEFAULT_FONT_FAMILY, 'DejaVu Sans Mono']


class _FontDBAbsent:
    @staticmethod
    def families():
        return ['DejaVu Sans Mono', 'monospace']


# The app icon is env-dependent: a desktop with an icon theme resolves one, but
# a bare CI container (no theme, no installed icon) yields a null QIcon, so the
# "icon present" branches in show_about() and main() would go uncovered there.
# Force a real icon so those branches run deterministically; the _app_icon tests
# use the saved original to exercise the real (themed / null) resolution.
_REAL_APP_ICON = M._app_icon
M._app_icon = lambda: M._letter_icon('S', '#336699')

# --- default-safe pty teardown backstop --------------------------------------
# The app installs a SIGCHLD handler (main._reap_pty_children) that reaps ONLY our
# pty shells (SecureTerminal._LIVE_PTY_PIDS), never a subprocess child, so a closed
# tab's hung-up shell never lingers defunct. These tests drive MainWindow WITHOUT going
# through main(), so that handler is absent by default and every closed window's shell
# leaks a zombie. Install the REAL handler here (not SIG_IGN, which would defang a
# subprocess returncode) so the test environment matches production; the main() startup
# tests save/restore SIGCHLD around their own calls, so this ambient value is
# transparent to them. Belt-and-suspenders: an atexit sweep force-closes any window a
# test tore down with deleteLater() (or left open) so its shell is hung up and reaped
# instead of escaping the test process. It runs ONLY on the uncaught-exception path
# (interpreter shutdown); the normal path exits via finish()'s os._exit, where the
# live SIGCHLD reaper and the OS closing every fd hang up the pty children -- closing
# widgets there would re-enter the Qt teardown crash os._exit dodges. Default-safe by
# design: no per-test teardown call to remember.
signal.signal(signal.SIGCHLD, M._reap_pty_children)


def _pty_teardown_sweep():
    for _w in list(APP.topLevelWidgets()):
        if isinstance(_w, MainWindow):
            _w._force_close = True
            try:
                _w.close()          # -> closeEvent -> tab.shutdown() -> SIGHUP the shell
            except RuntimeError:
                pass                # C++ object already deleted (deleteLater processed)
    APP.processEvents()
    for _ in range(25):             # SIGHUP is async: reap as the hung-up shells die
        if not _ST_reap._LIVE_PTY_PIDS:
            break
        _ST_reap.reap_pty_children()
        time.sleep(0.02)


atexit.register(_pty_teardown_sweep)

# A modal must never be reachable in this user-less harness: QMessageBox.question
# BLOCKS in the event loop with nobody to answer, and the suite hangs forever
# (observed: 1h25m in poll, single-threaded). close_tab asks it via
# _confirm_running_close whenever a tab reports a foreground program, which a
# freshly spawned shell can do transiently -- so the auto-answer "Yes" (quit) is
# armed HERE at import, before any suite builds a window; the explicit confirm-close
# tests set their own mock and restore to THIS default.
QMessageBox.question = staticmethod(
    lambda *_a, **_k: QMessageBox.StandardButton.Yes)

# Shared button-code shorthands (used by the confirm-close and signal-terminate tests
# across more than one split suite).
_Yes = QMessageBox.StandardButton.Yes
_No = QMessageBox.StandardButton.No

# --- window dialogs are shown with exec() stubbed -----------------------------
# QDialog.exec() BLOCKS in the event loop; stub it to accept (and record the
# dialog) so nothing hangs. This is the DEFAULT baseline; sections that need the
# real exec or another disposition set QDialog.exec themselves and restore to
# _orig_exec / _accept_exec.
_orig_exec = QDialog.exec
_dialogs = []


def _accept_exec(_self):
    _dialogs.append(_self)
    return int(QDialog.DialogCode.Accepted)


QDialog.exec = _accept_exec


def _dlg_field(dlg, label_text):
    # the field widget on the form row whose label contains label_text (labels
    # carry an "(i)" HTML marker, so match by substring, not equality).
    from PyQt6.QtWidgets import QFormLayout as _QFL
    for _form in dlg.findChildren(_QFL):
        for _r in range(_form.rowCount()):
            _l = _form.itemAt(_r, _QFL.ItemRole.LabelRole)
            _f = _form.itemAt(_r, _QFL.ItemRole.FieldRole)
            if _l and _f and _l.widget() is not None \
               and label_text in _l.widget().text():
                return _f.widget()
    return None


# --- shared IPC-server test scaffolding --------------------------------------
# Recording stand-ins for the accepted QLocalSocket + its server, used by the
# single-instance IPC read-path tests in more than one split suite, so they live
# here rather than being copied.
from PyQt6.QtCore import QObject as _QObject, pyqtSignal as _pyqtSignal


class _FakeConn(_QObject):
    """Recording stand-in for the accepted QLocalSocket: drives the REAL server slots
    (on_ready / _finish) through real Qt signals, without a live socket dispatch."""

    readyRead = _pyqtSignal()
    disconnected = _pyqtSignal()

    def __init__(self):
        super().__init__()
        self._inbuf = b''
        self.written = b''
        self.aborted = False
        self.disconnected_from_server = False

    def feed(self, data):
        self._inbuf += data
        self.readyRead.emit()

    def readAll(self):
        data, self._inbuf = self._inbuf, b''
        return data

    def write(self, data):
        self.written += bytes(data)
        return len(data)

    def flush(self):
        return True

    def disconnectFromServer(self):
        self.disconnected_from_server = True

    def abort(self):
        self.aborted = True


class _FakeServer:
    """nextPendingConnection() hands the conn once, then None (a spurious re-fire)."""

    def __init__(self, conn):
        self._conn = conn
        self._handed = False

    def nextPendingConnection(self):
        if self._handed:
            return None
        self._handed = True
        return self._conn


PASS = 0
FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
        print('ok   %s' % msg)
    else:
        FAIL += 1
        print('FAIL: %s' % msg)


def eq(got, want, msg):
    ok(got == want, '%s (got %r, want %r)' % (msg, got, want))


def pump(ms=10):
    """Process pending Qt events, then briefly yield so a just-forked child can
    reach its chdir/exec before the next poll, without busy-spinning."""
    APP.processEvents()
    time.sleep(ms / 1000.0)
    APP.processEvents()


def wait_for(predicate, timeout_ms=2000, interval_ms=20):
    """Pump the Qt event loop until PREDICATE() is true or TIMEOUT_MS elapses;
    return its final value. Use it for an assertion that reads state produced by a
    QUEUED signal/slot (an OSC risk-lamp recolour, a tab TUI flip, a banner
    show/hide) instead of a single-shot check after a fixed pump(): under heavy
    parallel-coverage load the event that lands the state can be starved past a
    fixed delay, false-reding the gate nondeterministically. A genuinely-wrong
    state still fails -- it just fails after the timeout, never early on a
    not-yet-delivered event."""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while True:
        APP.processEvents()
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return bool(predicate())
        time.sleep(interval_ms / 1000.0)
        APP.processEvents()


def finish(label):
    """Report this suite's tally and exit. Qt can crash in its static teardown
    after a clean run (destroying the many widgets/pyte screens/timers a suite
    builds), which would turn a fully-passing run into a non-zero exit. All tests
    have run and the result is known, so persist coverage and exit hard, bypassing
    that teardown. Do NOT close/destroy windows here: that would re-enter the Qt
    static-teardown crash os._exit exists to dodge -- the live SIGCHLD reaper plus
    the OS closing every fd on process exit hang up and reap the pty children.
    os._exit skips atexit, so save coverage explicitly first."""
    print('secure-terminal-tests(%s): all passed' % label if not FAIL else
          'secure-terminal-tests(%s): %d failed' % (label, FAIL))
    try:
        import coverage
        _cov = coverage.Coverage.current()
        if _cov is not None:
            _cov.save()
    except Exception:
        pass                    # coverage is optional instrumentation, never fatal
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(1 if FAIL else 0)


# Explicit re-export surface. This module is a harness HUB: each suite does
# `from test_mainwin_common import *`, so every name below IS consumed -- naming
# them in __all__ makes that intent machine-visible and keeps `import *` behaviour
# byte-identical to the implicit all-public-names default.
__all__ = [
    'os', 'sys', 'time', 'signal', 'tempfile',
    'QApplication', 'QDialog', 'QMessageBox',
    'M', 'MainWindow', '_ctl_main', 'APP',
    '_REAL_QFONTDB', '_FontDBPresent', '_FontDBAbsent', '_REAL_APP_ICON',
    '_orig_exec', '_accept_exec', '_dialogs', '_dlg_field',
    '_FakeConn', '_FakeServer', '_Yes', '_No',
    'PASS', 'FAIL', 'ok', 'eq', 'pump', 'wait_for', 'finish',
]
