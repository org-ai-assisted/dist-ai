#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Tests for privleap's PAM shim, the component that actually performs the
privilege change.

privleapd hands the shim a calling account, a target account, a target group,
a umask and a command, and the shim runs that command as the target after
taking PAM through an account check and a session open. Everything it refuses
BEFORE reaching that point is a boundary worth pinning: a shim that accepted
a target account that does not exist, or a malformed umask, would be running
a root command on the strength of an argument it never validated.

Each rejection exits 255, and that exit code is the whole contract with
privleapd, so it is what these tests assert.

The rejection paths need no root and no PAM: they are reached before the shim
touches either. The paths past PAM are exercised by the e2e lanes, which run
the shim through a real daemon.
"""

import argparse
import os
import subprocess  # nosec B404 -- running the shim IS the test
import sys
from typing import Any, Callable

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import Results, current_username  # noqa: E402


## The shim's entire contract with privleapd for a refusal.
REFUSED: int = 255

## Names that cannot resolve on any sane system.
NO_SUCH_USER: str = 'privleap-no-such-account'
NO_SUCH_GROUP: str = 'privleap-no-such-group'


def shim_path() -> str:
    """
    Locate the shim under test.

    Refuses to fall back to the installed copy when PRIVLEAP_REPO is set:
    testing a different shim than the one asked for and reporting a pass is
    worse than not running.
    """

    repo: str | None = os.environ.get('PRIVLEAP_REPO')
    if repo:
        candidate: str = os.path.join(repo, 'usr/libexec/privleap/shim.py')
        if not os.path.isfile(candidate):
            ## Not a skip: the launcher lets an earlier suite's pass carry a
            ## 77, so a named-but-missing shim would report green having
            ## tested nothing.
            print(
                f"FAIL: PRIVLEAP_REPO='{repo}' has no "
                'usr/libexec/privleap/shim.py. Refusing to skip: a named '
                'target that cannot be found is a failure, not an absence.'
            )
            raise SystemExit(1)
        return candidate
    installed: str = '/usr/libexec/privleap/shim.py'
    if not os.path.isfile(installed):
        print('SKIP: no privleap shim found.')
        raise SystemExit(77)
    return installed


## Whatever the shim last wrote to stderr, so an unexpected exit code can be
## explained rather than merely reported. A missing PAM module makes the shim
## die at import with code 1, which as a bare number looks like a refusal that
## used the wrong code.
LAST_STDERR: list[str] = ['']


def run_shim(shim: str, args: list[str], timeout_s: float = 20.0) -> int:
    """
    Run the shim with the given arguments and return its exit code, recording
    its stderr for the failure message.

    A shim that neither exits nor runs anything is a finding in its own
    right, so a timeout is reported as a distinct code rather than hanging
    the suite.
    """

    try:
        completed: Any = subprocess.run(  # nosec B603 -- fixed argv, no shell
            [sys.executable, shim] + args,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        LAST_STDERR[0] = 'timed out'
        return -1
    LAST_STDERR[0] = completed.stderr.decode('utf-8', errors='replace').strip()
    return int(completed.returncode)


def why(code: int) -> str:
    """A failure label that names the cause instead of just the exit code."""

    if code == REFUSED:
        return ''
    tail: str = LAST_STDERR[0].splitlines()[-1] if LAST_STDERR[0] else ''
    return f" (exit {code}: {tail or 'no stderr'})"


def test_missing_arguments_are_refused(results: Results, shim: str) -> None:
    """
    The shim needs a calling account, a target account, a target group and a
    umask before it may do anything. Too few means privleapd called it wrongly,
    and guessing at the missing ones would mean escalating on made-up input.
    """

    print('== too few arguments are refused ==')
    user: str = current_username()
    for count, args in enumerate(
        [
            [],
            [user],
            [user, 'root'],
            [user, 'root', 'root'],
        ]
    ):
        code: int = run_shim(shim, args)
        results.expect_eq(
            f"{count} argument(s) is refused{why(code)}", code, REFUSED
        )


def test_unresolvable_target_is_refused(
    results: Results, shim: str
) -> None:
    """
    The target account and group are what the command will run as. A shim
    that ran the command anyway when they do not resolve would be choosing
    the identity itself.
    """

    print('== an unresolvable target account or group is refused ==')
    user: str = current_username()
    cases: list[tuple[str, list[str]]] = [
        (
            'a target account that does not exist',
            [user, NO_SUCH_USER, 'root', '0', '/bin/true'],
        ),
        (
            'a target group that does not exist',
            [user, 'root', NO_SUCH_GROUP, '0', '/bin/true'],
        ),
        (
            'neither target resolving',
            [user, NO_SUCH_USER, NO_SUCH_GROUP, '0', '/bin/true'],
        ),
        (
            'an empty target account',
            [user, '', 'root', '0', '/bin/true'],
        ),
    ]
    for label, args in cases:
        code: int = run_shim(shim, args)
        results.expect_eq(f"{label} is refused{why(code)}", code, REFUSED)


def test_malformed_umask_is_refused(results: Results, shim: str) -> None:
    """
    The umask decides the permissions of everything the command creates. A
    shim that fell back to some default when handed a malformed one would
    silently create files under permissions nobody chose.
    """

    print('== a malformed umask is refused ==')
    user: str = current_username()
    for label, umask in (
        ('a non-numeric umask', 'not-a-number'),
        ('an empty umask', ''),
        ('a umask with trailing text', '63abc'),
        ('a floating point umask', '63.5'),
    ):
        code: int = run_shim(shim, [user, 'root', 'root', umask, '/bin/true'])
        results.expect_eq(f"{label} is refused{why(code)}", code, REFUSED)


def test_refusal_runs_nothing(results: Results, shim: str) -> None:
    """
    A refusal must happen BEFORE the command runs. Exiting 255 after having
    already run it would be the worst of both: the caller sees a failure and
    the command ran as the target anyway.
    """

    print('== a refused invocation never runs the command ==')
    user: str = current_username()
    sentinel: str = os.path.join(
        os.environ.get('TMPDIR', '/tmp'), 'privleap-shim-test-sentinel'
    )
    for label, args in (
        (
            'an unresolvable target',
            [user, NO_SUCH_USER, 'root', '0', '/bin/touch', sentinel],
        ),
        (
            'a malformed umask',
            [user, 'root', 'root', 'nonsense', '/bin/touch', sentinel],
        ),
    ):
        if os.path.exists(sentinel):
            os.unlink(sentinel)
        code = run_shim(shim, args)
        results.expect_eq(f"{label} is refused{why(code)}", code, REFUSED)
        results.check(
            f"{label}: the command did not run",
            not os.path.exists(sentinel),
        )
    if os.path.exists(sentinel):
        os.unlink(sentinel)


def run_test(
    results: Results, test: Callable[..., None], *args: Any
) -> None:
    """Run one test, turning an unexpected exception into a failure."""

    try:
        test(results, *args)
    except (Exception, SystemExit) as exc:  # pylint: disable=broad-exception-caught
        results.check(
            f"{test.__name__} raised {type(exc).__name__}: {exc}", False
        )


def main() -> int:
    """Entry point."""

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='privleap PAM shim tests'
    )
    parser.add_argument(
        '--seed', type=int, default=1, help='accepted for interface parity'
    )
    parser.parse_args()

    shim: str = shim_path()
    print(f"shim under test: {shim}")
    results: Results = Results()

    run_test(results, test_missing_arguments_are_refused, shim)
    run_test(results, test_unresolvable_target_is_refused, shim)
    run_test(results, test_malformed_umask_is_refused, shim)
    run_test(results, test_refusal_runs_nothing, shim)

    print('')
    return results.report('shim test')


if __name__ == '__main__':
    sys.exit(main())
