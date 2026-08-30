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
import importlib.util

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    # The spawned instances need PyQt6; probe (not import) so a missing dependency
    # fails this suite LOUD here instead of surfacing as a child that never binds.
    if importlib.util.find_spec('PyQt6.QtWidgets') is None:
        raise ImportError('PyQt6.QtWidgets')
    from secure_terminal import ipc
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests(instances): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)


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

# Qt's offscreen QPA platform can SIGSEGV/SIGABRT during QApplication startup under
# concurrent process launches -- an environmental artifact (empty stderr, the process
# dies before it binds or hands off), NOT a product fault. Every single-launch scenario
# RESPAWNS a launch that dies this way (see _primary/_coexisting/_handoff below), so a
# flake never reads as a product failure; a launch that exits for ANY OTHER reason, or a
# genuine coexistence/handoff failure, is reported. A whole-suite retry backstops the one
# race scenario (F) in the rare case its whole burst crashes. All bounded, so a persistent
# crash still fails loud.
_QT_STARTUP_CRASH = frozenset((-signal.SIGSEGV, -signal.SIGABRT))
_SPAWN_ATTEMPTS = 6


def _run_suite(tag):
    """One full E2E pass. Returns (failures, saw_qt_startup_crash). Group names carry
    `tag` so a retry never collides with a prior attempt's still-draining socket."""
    failures = 0
    kids = []

    def ok(cond, msg):
        nonlocal failures
        if cond:
            print('ok   %s' % msg)
        else:
            failures += 1
            print('FAIL: %s' % msg)

    def spawn(*args):
        proc = subprocess.Popen(
            [sys.executable, _BIN, *args],
            env=dict(_ENV, PYTHONPATH=os.pathsep.join(sys.path)),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        kids.append(proc)
        return proc

    def alive(proc):
        return proc.poll() is None

    def crashed(proc):
        return proc.poll() is not None and proc.returncode in _QT_STARTUP_CRASH

    def ping(group, timeout=1.0):
        return ipc.send_request(group, {'op': 'ping'}, timeout=timeout)

    def wait_primary(group, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            reply = ping(group)
            if reply is not None:
                return reply
            time.sleep(0.2)
        return None

    def spawn_primary(group, *args):
        """Spawn and wait until it owns the group socket, respawning ONLY a launch that
        dies of the Qt-startup crash. Returns (proc, reply) -- reply is None if it ran
        but never became primary (a real failure)."""
        proc = None
        for _ in range(_SPAWN_ATTEMPTS):
            proc = spawn(*args)
            reply = wait_primary(group)
            if reply is not None:
                return proc, reply
            if crashed(proc):
                continue
            return proc, None
        return proc, None

    def spawn_coexisting(*args, settle=2.5):
        """Spawn a launch that must STAY alive (a bare / --new-instance instance),
        respawning ONLY a Qt-startup crash. Returns the live proc (or the last dead one,
        for the assertion to report a non-crash exit)."""
        proc = None
        for _ in range(_SPAWN_ATTEMPTS):
            proc = spawn(*args)
            end = time.time() + settle
            while time.time() < end and alive(proc):
                time.sleep(0.1)
            if alive(proc) or not crashed(proc):
                return proc
        return proc

    def spawn_handoff(group, *args, timeout=15):
        """Spawn a --reuse client that hands off and exits 0, respawning ONLY a Qt-startup
        crash. Returns the exit code (0 on a clean handoff)."""
        proc = None
        for _ in range(_SPAWN_ATTEMPTS):
            proc = spawn(*args)
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return None  # a stuck --reuse -> the assertion fails loud
            if rc in _QT_STARTUP_CRASH:
                continue     # crashed in startup -> respawn
            if rc == 0:
                # clean, childless exit: drop from the reap list so the finally never
                # killpg's its now-freed PID.
                kids.remove(proc)
            return rc
        return proc.returncode if proc is not None else None

    grp = 'e2e-' + tag
    other = 'other-' + tag
    race = 'race-' + tag
    reelect = 'reelect-' + tag
    saw_crash = False
    try:
        # A: the first launch of a group becomes its PRIMARY (owns the group socket).
        _a, _ra = spawn_primary(grp, '--instance-group', grp)
        ok(_ra is not None, 'A: the first launch becomes the group primary (answers ping)')
        ok(_ra is not None and _ra.get('pid') == _a.pid, 'A: the primary pid is A')

        # B: a BARE second launch is a NEW INDEPENDENT process, never a handoff -- the
        # invariant this suite guards. Both stay alive, and the primary is STILL A: B
        # did not steal the live socket.
        _b = spawn_coexisting('--instance-group', grp)
        ok(alive(_a) and alive(_b),
           'B: a bare second launch coexists as its own process (2 live instances)')
        _rb = ping(grp)
        ok(_rb is not None and _rb.get('pid') == _a.pid,
           'B: the primary is STILL A -- a bare launch does not steal the socket')

        # C: --new-instance is a standalone process that also coexists and never
        # becomes the primary.
        _c = spawn_coexisting('--new-instance', '--instance-group', grp)
        _rc = ping(grp)
        ok(alive(_c) and _rc is not None and _rc.get('pid') == _a.pid,
           'C: --new-instance coexists and never becomes the primary')

        # D: --reuse hands the launch to the primary A and EXITS 0 -- no lingering
        # process. A keeps serving.
        _drc = spawn_handoff(grp, '--reuse', '--instance-group', grp)
        ok(_drc == 0, 'D: --reuse hands off to the primary and exits 0')
        ok(alive(_a), 'D: the primary A is still alive after serving the --reuse handoff')

        # E: a different --instance-group is fully independent -- its own primary, and
        # the default group is untouched.
        _e, _re = spawn_primary(other, '--instance-group', other)
        ok(_re is not None and _re.get('pid') == _e.pid,
           'E: --instance-group other owns its own socket (an independent primary)')
        # capture the reply ONCE: a second ping() could time out to None and .get()
        # would raise, crashing the suite instead of reporting a clean failure.
        _rdefault = ping(grp)
        ok(_rdefault is not None and _rdefault.get('pid') == _a.pid,
           'E: the default-group primary is untouched by the other group')

        # F: a BURST of concurrent --reuse into a fresh group converges on exactly ONE
        # primary; every loser hands its request off and exits 0, never opening a
        # redundant window. The old always-bind/removeServer claim let racers steal or
        # miss the socket -- leaving several coexisting windows (or zero listeners), the
        # reported "opens a new window instead of a tab" bug. On the old code the losers
        # do NOT hand off: they open their own server-less windows and stay alive, so
        # more than one racer survives and this fails. (A racer killed by the Qt-startup
        # crash flake never handed off: excluded below; if the WHOLE burst crashes the
        # whole-suite retry re-runs it.)
        _racers = [spawn('--reuse', '--instance-group', race) for _ in range(5)]
        ok(wait_primary(race) is not None,
           'F: a burst of --reuse into a fresh group yields a reachable primary')
        _fend = time.time() + 25
        while time.time() < _fend and sum(alive(p) for p in _racers) > 1:
            time.sleep(0.3)
        _fa = [p for p in _racers if alive(p)]
        ok(len(_fa) == 1,
           'F: exactly one racer becomes the primary (the rest hand off)')
        ok(all(p.returncode == 0 for p in _racers
               if not alive(p) and p.returncode not in _QT_STARTUP_CRASH),
           'F: every handed-off racer exits 0')
        ok(ping(race) is not None, 'F: the surviving primary answers ping')

        # G: a primary that DIES is replaced by the next --reuse, not left as an orphaned
        # socket that every later launch falls through. Guards the reclaim path (a stale
        # file cleared and re-bound) end to end.
        _g1, _rg1 = spawn_primary(reelect, '--reuse', '--instance-group', reelect)
        ok(_rg1 is not None, 'G: the first --reuse establishes a primary')
        os.killpg(_g1.pid, signal.SIGKILL)          # the primary's window/session dies
        _g1.wait(timeout=10)
        _g2, _rg2 = spawn_primary(reelect, '--reuse', '--instance-group', reelect)
        ok(_rg2 is not None and _rg2.get('pid') == _g2.pid,
           'G: after the primary dies, a new --reuse becomes a reachable primary')
    finally:
        # Note a Qt-startup crash BEFORE the reap rewrites returncodes to -SIGTERM/-SIGKILL.
        # A child SIGKILL'd on purpose (G's _g1) exits -SIGKILL, which is not in the set.
        saw_crash = any(p.poll() is not None and p.returncode in _QT_STARTUP_CRASH
                        for p in kids)
        # Reap by process-group (each child is its own session), TERM then KILL, so a
        # crash mid-suite leaves no orphan and the reaper never reaches another
        # session's processes. Signal UNCONDITIONALLY, not only while the leader is
        # alive: a leader that exited (a handed-off --reuse client) or crashed can
        # still leave live group members, and a poll()-guarded reap would orphan them.
        # A group that is already gone raises ProcessLookupError, which is swallowed.
        for _sig in (signal.SIGTERM, signal.SIGKILL):
            for _p in kids:
                try:
                    os.killpg(_p.pid, _sig)
                except (ProcessLookupError, PermissionError):
                    pass  # group already reaped, or not ours: nothing left to kill
            if _sig is signal.SIGTERM:
                time.sleep(1.5)
    return failures, saw_crash


# Per-launch respawn (above) handles the common flake; this whole-suite retry backstops
# the race scenario (F) when its entire burst crashes. Fresh group names each attempt; a
# failure with NO Qt-startup crash is a real bug, reported at once and never retried.
_MAX_ATTEMPTS = 3
_failures = 0
for _attempt in range(_MAX_ATTEMPTS):
    _failures, _saw_crash = _run_suite('%d-%d' % (os.getpid(), _attempt))
    if _failures == 0:
        print('secure-terminal-tests(instances): all passed')
        sys.exit(0)
    if not _saw_crash:
        break  # a real failure (no Qt-startup crash) -> report now, never masked by a retry
    print('secure-terminal-tests(instances): attempt %d/%d hit the Qt-offscreen '
          'startup-crash flake (%d failed); retrying on fresh groups'
          % (_attempt + 1, _MAX_ATTEMPTS, _failures), file=sys.stderr)

print('secure-terminal-tests(instances): %d failed' % _failures)
sys.exit(1)
