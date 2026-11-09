#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: a systemcheck W^X unit that filters SystemCallFilter=~memfd_create
AND spawns a memfd-using GUI helper as a DIRECT child must deny memfd_create via
a soft errno (SystemCallErrorNumber=EPERM), never the default SIGSYS kill.

Why: ~memfd_create is a defense-in-depth denylist (it blocks the anonymous-memfd
W^X exec-bypass). With NO SystemCallErrorNumber= the denied call SIGSYS-KILLS the
caller. Both GTK (yad) and Qt/xcb (PyQt, kdialog) allocate their shared-memory
buffer via memfd_create, so a GUI child inheriting the filter is killed outright
-- and in updatecheck that kill was silently masked as success. EPERM blocks the
bypass identically (no memfd is created) while letting the toolkit fall back and
render. The kill adds no security over EPERM here, so for these GUI-spawning
units it is simply the wrong failure mode.

The check models systemd's effective-policy semantics (memfd_denial): the
[Service] section only, SystemCallFilter= empty-reset, a per-syscall ':' action
that overrides the global SystemCallErrorNumber, and errno validity -- a lint
fooled by any of those would report a confident wrong pass. (The parser mirrors
privleap-tests/service_hardening_test.py; a cross-suite shared module is not on
either suite's import path, so the two are kept in step by hand.)

Scope (units whose process tree includes a DIRECT memfd-using GUI child):
  * updatecheck.service -- forks one-time-popup.py (PyQt5) directly.
  * systemcheck.service -- the --progressbarx path forks yad (GTK3) directly
                           (msgcollector -> msgprogressbar -> yad).
canary.service is intentionally EXCLUDED: it is a bash+curl system daemon with
no GUI child, where the aggressive SIGSYS kill on an anomalous memfd_create is a
deliberate, sound choice -- so this lint does not require a soft errno there.

Resolves units via SYSTEMCHECK_REPO (dist-ai/CLAUDE.md).
"""

import errno
import os
import unittest

from systemcheck_testlib import read, systemcheck_dir

## systemd accepts an errno name or a number 1..4095; anything else (empty,
## 'kill', 0, out of range, junk) is NOT a soft-fail errno.
_ERRNO_MIN, _ERRNO_MAX = 1, 4095
## Retryable errnos are a BAD soft-deny: the caller re-issues the blocked syscall in
## a tight loop instead of giving up, so memfd_create never settles. Reject them by
## name (the form units use); a real soft deny is a terminal errno like EPERM.
_RETRYABLE_ERRNOS = {
    'EINTR', 'EAGAIN', 'EWOULDBLOCK',
    'ERESTART', 'ERESTARTSYS', 'ERESTARTNOINTR', 'ERESTARTNOHAND',
}
## A real errno name. systemd IGNORES an unknown name (e.g. EBOGUS) and keeps the
## default KILL action, so an invalid name is NOT a soft deny.
_VALID_ERRNO_NAMES = frozenset(errno.errorcode.values())

## user-scope units that spawn a memfd-using GUI helper as a direct child.
GUI_UNITS = ('updatecheck.service', 'systemcheck.service')


def _usr_dir() -> str:
    ## systemcheck_dir() -> <repo>/usr/libexec/systemcheck; climb to <repo>/usr.
    return os.path.dirname(os.path.dirname(systemcheck_dir()))


def _service_lines(text: str) -> list:
    """Logical directive lines inside [Service], '\\'-continuations joined.
    Directives outside [Service] are inert, so the lint ignores them too."""
    out: list = []
    buf: str = ''
    in_service: bool = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            ## systemd section names are CASE-SENSITIVE: directives under a
            ## '[service]' header are ignored, so a case-insensitive match would
            ## credit hardening systemd never applies.
            in_service = stripped == '[Service]'
            continue
        ## systemd ignores lines starting with '#' OR ';' (comments).
        if not in_service or stripped.startswith('#') or stripped.startswith(';'):
            continue
        if stripped.endswith('\\'):
            buf += stripped[:-1] + ' '
        else:
            out.append((buf + stripped).strip())
            buf = ''
    if buf:
        out.append(buf.strip())
    return out


def _service_values(lines: list, key: str) -> list:
    ## Split on the FIRST '=' and strip both sides: systemd ignores whitespace
    ## around '=' ("Key = value"), so a prefix-only match would miss a spaced
    ## assignment and silently under-read the effective filter.
    out: list = []
    for line in lines:
        name, sep, value = line.partition('=')
        if sep and name.strip() == key:
            out.append(value.strip())
    return out


def _errno_is_soft(value: str) -> bool:
    val = value.strip()
    if not val or val.lower() == 'kill':
        return False
    if val.upper() in _RETRYABLE_ERRNOS:
        return False
    if val.isdigit():
        return _ERRNO_MIN <= int(val) <= _ERRNO_MAX
    ## an errno NAME must be a REAL errno: systemd ignores an unknown name and keeps
    ## the KILL action, so a bogus name (EBOGUS) is not a soft deny.
    return val in _VALID_ERRNO_NAMES


def memfd_denial(text: str) -> str:
    """'none' | 'soft' | 'kill' for memfd_create under [Service], honoring
    SystemCallFilter= empty-reset, a per-syscall ':' action (overrides the global
    errno), and the global SystemCallErrorNumber. A '~' token denies memfd_create;
    a later positive assignment of it re-allows it (last wins). A full allowlist
    omitting memfd_create is out of scope -- these units use the '~' denylist form."""
    lines = _service_lines(text)
    effective: list = []
    for value in _service_values(lines, 'SystemCallFilter'):
        if value == '':
            effective = []
        else:
            effective.append(value)
    denied = False
    per_syscall = None
    for value in effective:
        negate = value.startswith('~')
        for token in (value[1:] if negate else value).split():
            if token.split(':', 1)[0] != 'memfd_create':
                continue
            if negate:
                ## '~' denylist: memfd_create is denied; ':' sets its per-syscall action.
                denied = True
                per_syscall = token.split(':', 1)[1] if ':' in token else None
            else:
                ## a later POSITIVE assignment re-allows the syscall (systemd removes
                ## it from the denylist), so it is no longer denied.
                denied = False
                per_syscall = None
    if not denied:
        return 'none'
    if per_syscall is not None:
        return 'soft' if _errno_is_soft(per_syscall) else 'kill'
    errnos = _service_values(lines, 'SystemCallErrorNumber')
    if errnos and _errno_is_soft(errnos[-1]):
        return 'soft'
    return 'kill'


class WxSeccompErrnoTest(unittest.TestCase):
    def _unit_text(self, unit: str) -> str:
        ## systemcheck_dir() is FATAL without SYSTEMCHECK_REPO, so this always runs
        ## against the checkout, which ships these units. A missing REQUIRED unit is
        ## a broken subject -> read() raises (FAIL), never a vacuous skip.
        path = os.path.join(_usr_dir(), 'lib', 'systemd', 'user', unit)
        return read(path)

    def test_gui_units_deny_memfd_soft_not_sigsys(self) -> None:
        for unit in GUI_UNITS:
            with self.subTest(unit=unit):
                text = self._unit_text(unit)
                self.assertEqual(
                    memfd_denial(text), 'soft',
                    f"{unit}: memfd_create must be denied via a soft errno "
                    '(SystemCallErrorNumber=EPERM), not the default SIGSYS kill '
                    '-- otherwise the inherited GUI child (yad/PyQt) is killed. '
                    "memfd_denial reported it as not 'soft' (see effective "
                    'filter / per-syscall action / errno).')


class WxParserFidelityTest(unittest.TestCase):
    """Guards the directive parser the lint trusts -- whitespace-around-'=', a
    retryable errno, empty-reset, and an exact syscall match -- against a silent
    regression that would weaken the memfd verdict."""

    def test_service_values_tolerates_whitespace_around_eq(self) -> None:
        self.assertEqual(
            _service_values(['SystemCallFilter = ~memfd_create'],
                            'SystemCallFilter'),
            ['~memfd_create'])

    def test_errno_is_soft_rejects_eintr(self) -> None:
        self.assertFalse(_errno_is_soft('EINTR'))

    def test_memfd_denial_eintr_is_kill_not_soft(self) -> None:
        unit = ('[Service]\n'
                'SystemCallFilter=~memfd_create\n'
                'SystemCallErrorNumber=EINTR\n')
        self.assertEqual(memfd_denial(unit), 'kill')

    def test_memfd_denial_honors_whitespace_filter(self) -> None:
        unit = '[Service]\nSystemCallFilter = ~memfd_create:EPERM\n'
        self.assertEqual(memfd_denial(unit), 'soft')

    def test_memfd_denial_empty_reset_clears_earlier_filter(self) -> None:
        unit = ('[Service]\n'
                'SystemCallFilter=~memfd_create:EPERM\n'
                'SystemCallFilter=\n')
        self.assertEqual(memfd_denial(unit), 'none')

    def test_memfd_denial_requires_exact_syscall_name(self) -> None:
        unit = '[Service]\nSystemCallFilter=~memfd_create_secret:EPERM\n'
        self.assertEqual(memfd_denial(unit), 'none')

    def test_wrong_case_service_header_is_ignored(self) -> None:
        unit = '[service]\nSystemCallFilter=~memfd_create:EPERM\n'
        self.assertEqual(memfd_denial(unit), 'none')

    def test_semicolon_comment_is_skipped(self) -> None:
        unit = '[Service]\n; a comment line\nSystemCallFilter=~memfd_create:EPERM\n'
        self.assertEqual(memfd_denial(unit), 'soft')

    def test_positive_assignment_reallows_syscall(self) -> None:
        unit = ('[Service]\n'
                'SystemCallFilter=~memfd_create:EPERM\n'
                'SystemCallFilter=memfd_create\n')
        self.assertEqual(memfd_denial(unit), 'none')

    def test_errno_is_soft_rejects_bogus_name(self) -> None:
        self.assertFalse(_errno_is_soft('EBOGUS'))

    def test_errno_is_soft_accepts_a_real_errno(self) -> None:
        self.assertTrue(_errno_is_soft('EPERM'))

    def test_missing_required_unit_fails_not_skips(self) -> None:
        ## A missing REQUIRED unit must be an error, never a vacuous skip.
        probe = WxSeccompErrnoTest('test_gui_units_deny_memfd_soft_not_sigsys')
        try:
            probe._unit_text('definitely-not-a-real-unit.service')  # pylint: disable=protected-access
        except unittest.SkipTest:
            self.fail('a missing REQUIRED unit raised SkipTest (vacuous skip)')
        except FileNotFoundError:
            ## correct: a missing REQUIRED unit surfaces as an error, not a skip.
            pass


if __name__ == '__main__':
    unittest.main()
