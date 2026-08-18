#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Multi-process E2E for the independent-instance model: every launch opens its
## OWN window+process, reuse is opt-in via --reuse, and a second instance must
## NOT steal a live primary's socket. In-process unit tests (test_mainwin) cover
## the decision logic, but coexistence can only be shown with REAL processes: two
## windows sharing one main-thread event loop cannot answer each other's blocking
## ping, so this suite spawns real offscreen secure-terminal processes and drives
## the actual sockets. Each child runs in its OWN session (start_new_session) and
## is reaped by process-group in a finally, so a crash mid-suite leaks nothing and
## the reaper can never reach another session's processes.
##
## Not part of the coverage gate (it exercises whole processes, not traced lines);
## wired into secure-terminal-tests only, like test_unicode_gallery.

import os
import sys
import time
import signal
import tempfile
import subprocess

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    import PyQt6.QtWidgets  # noqa: F401  -- children need it; fail closed if absent
    from secure_terminal import ipc
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests(instances): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

_failures = 0


def ok(cond, msg):
    global _failures
    if cond:
        print('ok   %s' % msg)
    else:
        _failures += 1
        print('FAIL: %s' % msg)


# Isolate every XDG surface so the spawned instances load clean defaults and share
# ONE socket dir with this parent (which pings via ipc.send_request, reading
# XDG_RUNTIME_DIR from its own environ -- it must match the children's).
_RUN = tempfile.mkdtemp(prefix='st-inst-run-')
os.environ['XDG_RUNTIME_DIR'] = _RUN
_ENV = dict(os.environ,
            QT_QPA_PLATFORM='offscreen',
            XDG_RUNTIME_DIR=_RUN,
            HOME=tempfile.mkdtemp(prefix='st-inst-home-'),
            XDG_CONFIG_HOME=tempfile.mkdtemp(prefix='st-inst-cfg-'),
            XDG_STATE_HOME=tempfile.mkdtemp(prefix='st-inst-state-'),
            SHELL='/bin/bash')

# Drive the ACTUAL usr/bin/secure-terminal launcher (not a re-embedded copy),
# derived from the package location so it resolves in a checkout or an install:
#   <root>/usr/lib/python3/dist-packages/secure_terminal/ipc.py
#   <root>/usr/bin/secure-terminal
# The launcher self-adds its sibling package to sys.path, so it runs from a
# checkout with no PYTHONPATH; we pass one anyway to pin the tree under test.
_USR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.realpath(ipc.__file__))))))
_BIN = os.path.join(_USR, 'bin', 'secure-terminal')
if not os.path.isfile(_BIN):
    sys.stderr.write('secure-terminal-tests(instances): FAIL launcher not found '
                     'at %s\n' % _BIN)
    sys.exit(1)

_GROUP = 'e2e'
_kids = []


def _spawn(*args):
    proc = subprocess.Popen(
        [sys.executable, _BIN, *args],
        env=dict(_ENV, PYTHONPATH=os.pathsep.join(sys.path)),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)
    _kids.append(proc)
    return proc


def _alive(proc):
    return proc.poll() is None


def _ping(group=_GROUP, timeout=1.0):
    return ipc.send_request(group, {'op': 'ping'}, timeout=timeout)


def _wait_primary(group=_GROUP, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        reply = _ping(group)
        if reply is not None:
            return reply
        time.sleep(0.2)
    return None


try:
    # A: the first launch of a group becomes its PRIMARY (owns the group socket).
    _a = _spawn('--instance-group', _GROUP)
    _ra = _wait_primary()
    ok(_ra is not None, 'A: the first launch becomes the group primary (answers ping)')
    ok(_ra is not None and _ra.get('pid') == _a.pid, 'A: the primary pid is A')

    # B: a BARE second launch is a NEW INDEPENDENT process, never a handoff -- the
    # core bug fix (a bare relaunch used to do nothing). Both stay alive, and the
    # primary is STILL A: B did not steal the live socket.
    _b = _spawn('--instance-group', _GROUP)
    time.sleep(5)
    ok(_alive(_a) and _alive(_b),
       'B: a bare second launch coexists as its own process (2 live instances)')
    _rb = _ping()
    ok(_rb is not None and _rb.get('pid') == _a.pid,
       'B: the primary is STILL A -- a bare launch does not steal the socket')

    # C: --new-instance is a standalone process that also coexists and never
    # becomes the primary.
    _c = _spawn('--new-instance', '--instance-group', _GROUP)
    time.sleep(4)
    _rc = _ping()
    ok(_alive(_c) and _rc is not None and _rc.get('pid') == _a.pid,
       'C: --new-instance coexists and never becomes the primary')

    # D: --reuse hands the launch to the primary A and EXITS 0 -- no lingering
    # process. A keeps serving.
    _d = _spawn('--reuse', '--instance-group', _GROUP)
    _drc = None
    try:
        _drc = _d.wait(timeout=15)
        # cleanly reaped and childless (it exits before forking a shell): drop it
        # from the reap list so the finally never killpg's its now-freed PID.
        _kids.remove(_d)
    except subprocess.TimeoutExpired:
        pass
    ok(_drc == 0, 'D: --reuse hands off to the primary and exits 0')
    ok(_alive(_a), 'D: the primary A is still alive after serving the --reuse handoff')

    # E: a different --instance-group is fully independent -- its own primary, and
    # the default group is untouched.
    _e = _spawn('--instance-group', 'other')
    _re = _wait_primary('other')
    ok(_re is not None and _re.get('pid') == _e.pid,
       'E: --instance-group other owns its own socket (an independent primary)')
    # capture the reply ONCE: a second _ping() could time out to None and .get()
    # would raise, crashing the suite instead of reporting a clean failure.
    _rdefault = _ping()
    ok(_rdefault is not None and _rdefault.get('pid') == _a.pid,
       'E: the default-group primary is untouched by the other group')
finally:
    # Reap by process-group (each child is its own session), TERM then KILL, so a
    # crash mid-suite leaves no orphan and the reaper never reaches another
    # session's processes. Signal UNCONDITIONALLY, not only while the leader is
    # alive: a leader that exited (a handed-off --reuse client) or crashed can
    # still leave live group members, and a poll()-guarded reap would orphan them.
    # A group that is already gone raises ProcessLookupError, which is swallowed.
    for _sig in (signal.SIGTERM, signal.SIGKILL):
        for _p in _kids:
            try:
                os.killpg(_p.pid, _sig)
            except (ProcessLookupError, PermissionError):
                pass
        if _sig is signal.SIGTERM:
            time.sleep(1.5)

if _failures:
    print('secure-terminal-tests(instances): %d failed' % _failures)
    sys.exit(1)
print('secure-terminal-tests(instances): all passed')
