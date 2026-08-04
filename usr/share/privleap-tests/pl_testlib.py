#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Shared helpers for the privleap in-process test harnesses.

The harnesses import the REAL privleap library and daemon code and drive
the genuine, security-critical code paths an unprivileged local user can
reach over their comm socket:

  * the server-side wire-protocol parser (privleap.PrivleapSession.get_msg
    and the framing / tokenizer it calls), and
  * the authorization engine (privleapd.authorize_user /
    auth_signal_request / is_user_allowed).

The target privleap is resolved in this order:
  1. PRIVLEAP_REPO (a derivative-maker checkout root) if set,
  2. the installed package under /usr/lib/python3/dist-packages, else
  3. the in-tree derivative-maker checkout at its default path.
"""

import importlib
import os
import pwd
import sys
from types import ModuleType
from typing import Any, NoReturn


DEFAULT_REPO: str = '/home/user/derivative-maker/packages/kicksecure/privleap'
INSTALLED_PARENT: str = '/usr/lib/python3/dist-packages'


def _dist_packages_dir() -> str | None:
    """
    Return the directory to put on sys.path so that ``import privleap.privleap``
    resolves the target privleap, or None if no target can be found.
    """

    repo: str | None = os.environ.get('PRIVLEAP_REPO')
    if repo:
        candidate: str = os.path.join(repo, 'usr/lib/python3/dist-packages')
        if os.path.isfile(
            os.path.join(candidate, 'privleap', 'privleap.py')
        ):
            return candidate
        ## PRIVLEAP_REPO was set but points at no privleap tree. Do not
        ## silently fall back to the installed package (that would test the
        ## wrong code); skip with a clear message instead.
        return None
    if os.path.isfile(
        os.path.join(INSTALLED_PARENT, 'privleap', 'privleap.py')
    ):
        return INSTALLED_PARENT
    candidate: str = os.path.join(DEFAULT_REPO, 'usr/lib/python3/dist-packages')
    if os.path.isfile(os.path.join(candidate, 'privleap', 'privleap.py')):
        return candidate
    return None


def _skip_not_found(what: str) -> NoReturn:
    """
    End the run because the target privleap could not be found.

    A skip (77) ONLY when nothing was asked for: privleap is simply not
    installed and no checkout was named. When PRIVLEAP_REPO WAS set and does
    not contain a privleap tree, that is a broken target, and it exits 1 --
    the launcher treats 77 as a skip and lets an earlier suite's pass carry
    the run, so skipping there would report a green run that never tested
    anything.
    """

    repo: str | None = os.environ.get('PRIVLEAP_REPO')
    if repo:
        print(
            f"FAIL: PRIVLEAP_REPO='{repo}' contains no privleap tree "
            '(expected usr/lib/python3/dist-packages/privleap/privleap.py). '
            'Refusing to skip: a named target that cannot be found is a '
            'failure, not an absence.'
        )
        raise SystemExit(1)
    print(f"SKIP: {what} not found.")
    print('      set PRIVLEAP_REPO to a derivative-maker checkout root.')
    raise SystemExit(77)


def import_privleap() -> ModuleType:
    """
    Import and return the privleap.privleap library module, or skip (exit 77)
    if it cannot be found.
    """

    parent: str | None = _dist_packages_dir()
    if parent is None:
        _skip_not_found('privleap library')
    if parent not in sys.path:
        sys.path.insert(0, parent)
    return importlib.import_module('privleap.privleap')


def import_privleapd() -> ModuleType:
    """
    Import and return the privleap.privleapd daemon module (which pulls in the
    library too), or skip (exit 77) if the privleap package is not present.

    A skip means "privleap is not installed / not on the path" -- NOT "the code
    under test is broken". So only a genuinely missing privleap package maps to
    a skip; a syntax error or a broken transitive import inside privleapd.py
    must surface as a real failure rather than being masked as skipped.
    """

    parent: str | None = _dist_packages_dir()
    if parent is None:
        _skip_not_found('privleap daemon')
    if parent not in sys.path:
        sys.path.insert(0, parent)
    try:
        return importlib.import_module('privleap.privleapd')
    except ModuleNotFoundError as exc:
        if exc.name not in ('privleap', 'privleap.privleapd'):
            raise
        _skip_not_found('privleap daemon')


def import_privleap_module(module_name: str) -> ModuleType:
    """
    Import and return any module of the target privleap package by its bare
    name (for example "leapctl" or "leaprun"), or skip (exit 77) if the
    privleap package is not present.

    As with import_privleapd(), only a genuinely missing privleap package maps
    to a skip. A broken module must surface as a real failure.
    """

    parent: str | None = _dist_packages_dir()
    if parent is None:
        _skip_not_found(f"privleap {module_name}")
    if parent not in sys.path:
        sys.path.insert(0, parent)
    try:
        return importlib.import_module(f"privleap.{module_name}")
    except ModuleNotFoundError as exc:
        if exc.name not in ('privleap', f"privleap.{module_name}"):
            raise
        _skip_not_found(f"privleap {module_name}")


def current_username() -> str:
    """
    Return the name of the user the test is acting as. Under sudo this is the
    invoking user (SUDO_USER), so the live-daemon harness treats requests as
    coming from a normal account rather than root.
    """

    sudo_user: str | None = os.environ.get('SUDO_USER')
    if sudo_user:
        try:
            pwd.getpwnam(sudo_user)
            return sudo_user
        except KeyError:
            pass
    return pwd.getpwuid(os.getuid()).pw_name


class Results:
    """
    Minimal pass/fail accumulator with a stable, greppable line format.
    """

    def __init__(self) -> None:
        self.passed: int = 0
        self.failed: int = 0

    def check(self, label: str, condition: bool) -> bool:
        """
        Record a boolean assertion. Returns the condition for convenience.
        """

        if condition:
            self.passed += 1
        else:
            self.failed += 1
            print(f"  FAIL: {label}")
        return condition

    def expect_eq(self, label: str, got: Any, expected: Any) -> bool:
        """
        Record an equality assertion, printing both values on mismatch.
        """

        if got == expected:
            self.passed += 1
            return True
        self.failed += 1
        print(f"  FAIL: {label}: expected {expected!r}, got {got!r}")
        return False

    def report(self, title: str) -> int:
        """
        Print a summary line and return a process exit code (0 pass, 1 fail).
        """

        total: int = self.passed + self.failed
        print(f"{title}: {self.passed}/{total} checks passed")
        if self.failed:
            print(f"RESULT: FAIL ({self.failed} failed)")
            return 1
        if total == 0:
            ## A suite that recorded nothing has proved nothing. Reporting
            ## PASS for it is how a suite that silently stopped running keeps
            ## looking green.
            print('RESULT: FAIL (no checks ran)')
            return 1
        print('RESULT: PASS')
        return 0
