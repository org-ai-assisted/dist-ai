#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for image-test-gc's fail-closed VM cleanup.

Guards the reviewdrain/CodeRabbit finding: a `VBoxManage list vms` failure inside a
process substitution did NOT propagate (errexit/pipefail could not see it), so the
script wiped the VM folder and printed "done" while registrations survived; the
unregister failure was also swallowed. The fix rc-checks the list via an assignment
(not <(...)) and makes unregister strict. These tests drive the REAL image-test-gc
with PATH stubs (sudo dropped to a passthrough, VBoxManage/getent/id/safe-rm faked)
and assert it aborts BEFORE the folder wipe when list or unregister fails.
"""

import os
import stat
import subprocess
from pathlib import Path

import pytest

GC = Path(__file__).resolve().parents[2] / 'bin' / 'image-test-gc'


def _write_exec(path, body):
    path.write_text('#!/bin/bash\n' + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def env(tmp_path):
    """A stub PATH + env so the real image-test-gc runs unprivileged.

    sudo -> drop the leading '-u <user>' and exec the rest (so VBoxManage etc.
    resolve to the stubs below); id -> user exists; getent -> a home under tmp;
    safe-rm -> record its args to a marker so a test can assert it did/did not run.
    """
    binp = tmp_path / 'bin'
    binp.mkdir()
    home = tmp_path / 'ephhome'
    home.mkdir()
    marker = tmp_path / 'safe-rm.calls'
    _write_exec(binp / 'sudo', 'shift 2\nexec "$@"\n')
    _write_exec(binp / 'id', 'exit 0\n')
    _write_exec(binp / 'getent',
                'printf "%s:x:9999:9999::%s:/bin/bash\\n" "eph-test" "%s"\n'
                % ('%s', '%s', home))
    ## getent needs to echo the home path; build it plainly to avoid quoting games.
    _write_exec(binp / 'getent',
                'echo "eph-test:x:9999:9999::' + str(home) + ':/bin/bash"\n')
    _write_exec(binp / 'safe-rm', 'echo "$@" >> "' + str(marker) + '"\n')
    environ = dict(os.environ)
    environ['PATH'] = str(binp) + os.pathsep + environ['PATH']
    return {'bin': binp, 'home': home, 'marker': marker, 'environ': environ}


def _run(env, user='eph-test'):
    return subprocess.run(
        [str(GC), user], env=env['environ'],
        capture_output=True, text=True, timeout=60)


def test_list_failure_aborts_before_wipe(env):
    ## VBoxManage `list vms` fails -> the script must abort non-zero and NEVER reach
    ## the folder wipe or print "done" (the exact silent-pass the fix closes).
    _write_exec(env['bin'] / 'VBoxManage',
                'case "$1" in list) exit 1 ;; *) exit 0 ;; esac\n')
    res = _run(env)
    assert res.returncode != 0, res.stdout + res.stderr
    assert not env['marker'].exists(), 'safe-rm ran despite the list failure'
    assert 'done' not in res.stdout


def test_unregister_failure_aborts(env):
    ## list returns a VM but unregister fails -> strict: script aborts non-zero.
    _write_exec(env['bin'] / 'VBoxManage',
                'case "$1" in\n'
                '  list) echo \'"vm1" {00000000-0000-0000-0000-000000000001}\' ;;\n'
                '  unregistervm) exit 1 ;;\n'
                '  *) exit 0 ;;\n'
                'esac\n')
    res = _run(env)
    assert res.returncode != 0, res.stdout + res.stderr


def test_happy_path_wipes_and_reports_done(env):
    ## canary: list ok + unregister ok -> exits 0, wipes the folder, prints "done".
    ## (If this passed while the failure cases above also "passed", the stubs would
    ## be inert -- so this proves the harness actually exercises the script.)
    _write_exec(env['bin'] / 'VBoxManage',
                'case "$1" in\n'
                '  list) echo \'"vm1" {00000000-0000-0000-0000-000000000001}\' ;;\n'
                '  *) exit 0 ;;\n'
                'esac\n')
    res = _run(env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert 'done' in res.stdout
    assert env['marker'].exists(), 'safe-rm was not invoked on the happy path'


def test_eph_leak_accepted(env):
    ## The leak namespace (eph-leak-) must be wipeable like any eph-* account --
    ## canary against a future narrowing of the eph-* allow-arm to eph-run- only,
    ## which would silently strand leak-account VBox state.
    _write_exec(env['bin'] / 'VBoxManage',
                'case "$1" in\n'
                '  list) echo \'"vm1" {00000000-0000-0000-0000-000000000001}\' ;;\n'
                '  *) exit 0 ;;\n'
                'esac\n')
    res = _run(env, 'eph-leak-whonix-18-2-3-5')
    assert res.returncode == 0, res.stdout + res.stderr
    assert 'done' in res.stdout
    assert env['marker'].exists(), 'safe-rm was not invoked for an eph-leak- account'


def test_persist_refused(env):
    ## persist-* is the golden fleet: refused BEFORE any VBox call or folder wipe.
    _write_exec(env['bin'] / 'VBoxManage', 'exit 0\n')
    res = _run(env, 'persist-stable-whonix')
    assert res.returncode != 0, res.stdout + res.stderr
    assert not env['marker'].exists(), 'safe-rm ran on a persist- account'


def test_unknown_prefix_refused(env):
    ## default-deny: a name in neither the install nor the leak namespace is refused.
    _write_exec(env['bin'] / 'VBoxManage', 'exit 0\n')
    res = _run(env, 'random-user')
    assert res.returncode != 0, res.stdout + res.stderr
    assert not env['marker'].exists(), 'safe-rm ran on an unknown-prefix account'
