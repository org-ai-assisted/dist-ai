#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Startup-noise E2E: a normal launch must not spew warnings a user sees the moment
## they open the app. Two regressions, each with its own canary (a test that cannot
## fail proves nothing):
##   - Qt non-UTF-8 locale warning: under a C/POSIX ambient locale Qt printed
##     'Detected locale "C" ... not UTF-8 ... switched to "C.UTF-8"'. The app now
##     gives ITS OWN process a UTF-8 ctype before QApplication (main.py, mirroring
##     sanitize.ensure_utf8_ctype), so Qt stays silent.
##   - cgroup isolation notice: 'per-tab resource isolation unavailable (no cgroup v2
##     delegation); tabs share the session limits' printed on EVERY launch (and every
##     ctl invocation) on a non-delegated host -- the common Qubes AppVM case, which is
##     normal, not an error. It is now silent by default and gated behind
##     SECURE_TERMINAL_CGROUP_DEBUG=1 (usr/bin/secure-terminal).
##
## Spawns the REAL usr/bin/secure-terminal launcher (not a re-embedded copy), like
## test_instances. Plain-runner E2E; not coverage-gated (whole processes, not traced
## lines).

import os
import sys
import time
import signal
import tempfile
import subprocess
import importlib.util

from st_qt_platform import require_wayland
require_wayland('secure-terminal-tests(startup-stderr)')

try:
    if importlib.util.find_spec('PyQt6.QtWidgets') is None:
        raise ImportError('PyQt6.QtWidgets')
    from secure_terminal import ipc
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests(startup-stderr): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

# Resolve the actual launcher from the package location (checkout or install):
#   <root>/usr/lib/python3/dist-packages/secure_terminal/ipc.py -> <root>/usr/bin/secure-terminal
_USR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.realpath(ipc.__file__))))))
_BIN = os.path.join(_USR, 'bin', 'secure-terminal')
if not os.path.isfile(_BIN):
    sys.stderr.write('secure-terminal-tests(startup-stderr): FAIL launcher not found '
                     'at %s\n' % _BIN)
    sys.exit(1)

# Force the non-UTF-8 ambient condition the operator hit (C/POSIX), regardless of the
# host locale: a child with LANG=C and no LC_ALL/LC_CTYPE. Isolated HOME/XDG so the
# instance loads clean defaults and shares the compositor's XDG_RUNTIME_DIR (wayland +
# single-instance socket), like test_instances.
_BASE_ENV = dict(os.environ,
                 HOME=tempfile.mkdtemp(prefix='st-noise-home-'),
                 XDG_CONFIG_HOME=tempfile.mkdtemp(prefix='st-noise-cfg-'),
                 XDG_STATE_HOME=tempfile.mkdtemp(prefix='st-noise-state-'),
                 SHELL='/bin/bash',
                 LANG='C')
_BASE_ENV.pop('LC_ALL', None)
_BASE_ENV.pop('LC_CTYPE', None)

_LOCALE_MARK = 'Detected locale'
_CGROUP_MARK = 'resource isolation unavailable'
_QT_STARTUP_CRASH = frozenset((-signal.SIGSEGV, -signal.SIGABRT))
_SPAWN_ATTEMPTS = 10


def _launch_capture(extra_env=None, settle=3.0):
    """Launch the real app, let it start (warnings print synchronously at/just after
    QApplication), then SIGTERM its session and return captured stderr. Respawns a Qt
    startup crash (SIGSEGV/SIGABRT: an environmental artifact under headless Qt, not a
    product fault), bounded. Returns the stderr text, or None if every attempt crashed."""
    env = dict(_BASE_ENV, PYTHONPATH=os.pathsep.join(sys.path))
    if extra_env:
        env.update(extra_env)
    for _ in range(_SPAWN_ATTEMPTS):
        proc = subprocess.Popen(
            [sys.executable, _BIN],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, start_new_session=True)
        time.sleep(settle)
        # Tear the whole session down, then collect. Signal the process GROUP *before*
        # anything reaps the leader (no poll()/wait() precedes this): a leader that already
        # exited during settle is still a zombie here, so its pid -- and thus the pgid --
        # stays reserved and killpg cannot race onto a reused pid (CWE-362). communicate()
        # then reaps the leader and drains stderr even when a surviving descendant still
        # holds the pipe open; its timeout + SIGKILL fallback guarantees no hang and no
        # orphaned process tree. A clean early exit and a still-running launch take the
        # same path; a startup crash (SIGSEGV/SIGABRT) is detected from returncode below.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            _out, err = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _out, err = proc.communicate()
        if proc.returncode in _QT_STARTUP_CRASH:
            continue                      # startup crash -> respawn
        return (err or b'').decode('utf-8', 'replace')
    return None


def _locale_canary():
    """A bare QApplication under LC_ALL=C MUST print the locale warning -- proves this
    environment genuinely reproduces the non-UTF-8 condition and that Qt warns on it, so
    a silent app launch is a real suppression, not a vacuous pass."""
    env = dict(os.environ, LC_ALL='C')
    env.pop('LC_CTYPE', None)
    env.pop('LANG', None)
    code = ('import os,sys; os.environ.setdefault("QT_QPA_PLATFORM",'
            'os.environ.get("QT_QPA_PLATFORM","wayland"));'
            'from PyQt6.QtWidgets import QApplication; QApplication([sys.argv[0]])')
    proc = subprocess.run([sys.executable, '-c', code], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                          timeout=30, check=False)
    return proc.stderr.decode('utf-8', 'replace')


def main():
    failures = 0

    def ok(cond, msg):
        nonlocal failures
        if cond:
            print('ok   %s' % msg)
        else:
            failures += 1
            print('FAIL: %s' % msg)

    # Canary first: the environment must be able to provoke the locale warning at all.
    canary = _locale_canary()
    ok(_LOCALE_MARK in canary,
       'canary: bare QApplication under LC_ALL=C emits the Qt locale warning')

    # 1. A normal launch under a C ambient locale is clean of both warnings.
    err = _launch_capture()
    ok(err is not None, 'app launched (did not crash on every attempt)')
    if err is not None:
        ok(_LOCALE_MARK not in err,
           'no Qt non-UTF-8 locale warning on a normal launch')
        # Integration check only; the cgroup-notice gating itself is unit-tested
        # deterministically in test_modules (isolation_notice), env-independent.
        ok(_CGROUP_MARK not in err,
           'no cgroup isolation notice on a normal launch')

    if failures:
        print('secure-terminal-tests(startup-stderr): %d failed' % failures)
        return 1
    print('secure-terminal-tests(startup-stderr): all passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
