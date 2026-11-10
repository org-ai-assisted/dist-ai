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
fooled by any of those would report a confident wrong pass. That model is the
SINGLE source dist_ai_seccomp, imported identically by
privleap-tests/service_hardening_test.py (no hand-synced copy to drift).

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
import sys
import unittest

from systemcheck_testlib import read, systemcheck_dir

## The seccomp policy model (memfd_denial / errno_is_soft / the directive parser) is a
## SINGLE source shared with privleap-tests, shipped in dist-ai's dist-packages tree.
## Insert it relative to this file (the dm_test_results idiom) so both suites import the
## same code -- no hand-synced copy to drift.
_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from dist_ai_seccomp import (  # noqa: E402
    errno_is_soft, memfd_denial, service_lines, service_values)

## user-scope units that spawn a memfd-using GUI helper as a direct child.
GUI_UNITS = ('updatecheck.service', 'systemcheck.service')


def _usr_dir() -> str:
    ## systemcheck_dir() -> <repo>/usr/libexec/systemcheck; climb to <repo>/usr.
    return os.path.dirname(os.path.dirname(systemcheck_dir()))


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
            service_values(['SystemCallFilter = ~memfd_create'],
                           'SystemCallFilter'),
            ['~memfd_create'])

    def test_errno_is_soft_rejects_eintr(self) -> None:
        self.assertFalse(errno_is_soft('EINTR'))

    def test_errno_is_soft_rejects_retryable_by_number(self) -> None:
        ## systemd accepts SystemCallErrorNumber= as a name OR a number, so a retryable
        ## errno in numeric form (EAGAIN=11, EINTR=4) is the SAME spinning bad soft-deny
        ## as the name -- it must not slip through just because the name check cannot see
        ## the number. memfd_create stays denied, but via the default kill, not a 'soft'.
        self.assertFalse(errno_is_soft(str(errno.EAGAIN)))
        self.assertFalse(errno_is_soft(str(errno.EINTR)))
        unit = ('[Service]\n'
                'SystemCallFilter=~memfd_create\n'
                f'SystemCallErrorNumber={errno.EAGAIN}\n')
        self.assertEqual(memfd_denial(unit), 'kill')

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
        self.assertFalse(errno_is_soft('EBOGUS'))

    def test_errno_is_soft_accepts_a_real_errno(self) -> None:
        self.assertTrue(errno_is_soft('EPERM'))

    def test_errno_is_soft_accepts_digit_in_name_errno(self) -> None:
        ## A REAL errno whose name carries a digit (E2BIG, EL2HLT) is accepted by
        ## systemd -- the denied call returns that errno, it does not SIGSYS. .isdigit()
        ## is False (it has letters), so it must be validated by name, never
        ## mis-classified as a kill (which would false-RED a genuinely soft unit).
        self.assertTrue(errno_is_soft('E2BIG'))
        self.assertTrue(errno_is_soft('EL2HLT'))

    def test_errno_is_soft_accepts_numeric_errno_in_range(self) -> None:
        self.assertTrue(errno_is_soft('13'))

    def test_errno_is_soft_accepts_name_aliases(self) -> None:
        ## errno.errorcode keeps only one name per number, dropping the alias of each pair
        ## (EOPNOTSUPP/ENOTSUP, EDEADLOCK/EDEADLK) which systemd accepts -- the valid-name set must
        ## be built from every errno.E* constant, else a unit using the dropped alias is wrongly
        ## reported 'kill' (a false lint failure). WHICH alias errorcode drops is platform-dependent.
        self.assertTrue(errno_is_soft('EOPNOTSUPP'))
        self.assertTrue(errno_is_soft('EDEADLOCK'))

    def test_service_header_after_continuation_stays_in_prior_value(self) -> None:
        ## systemd JOINS a trailing-'\' line to the next BEFORE testing the section
        ## header, so 'Description=x \' + '[Service]' keeps '[Service]' part of the
        ## [Unit] Description VALUE -- the unit never enters [Service], and a directive
        ## below is NOT applied. Testing the header per physical line (pre-join) would
        ## credit a [Service] section systemd never opened: a false pass.
        unit = ('[Unit]\n'
                'Description=continued \\\n'
                '[Service]\n'
                'MemoryDenyWriteExecute=yes\n')
        self.assertEqual(
            service_values(service_lines(unit), 'MemoryDenyWriteExecute'), [])

    def test_filter_after_continued_header_is_not_denied(self) -> None:
        ## Same continuation swallow for the memfd verdict: the SystemCallFilter is
        ## really in [Unit] (ignored), so memfd_create is NOT denied.
        unit = ('[Unit]\n'
                'Description=continued \\\n'
                '[Service]\n'
                'SystemCallFilter=~memfd_create:EPERM\n')
        self.assertEqual(memfd_denial(unit), 'none')

    def test_nbsp_before_key_is_an_unknown_directive(self) -> None:
        ## systemd strips ASCII whitespace only; a U+00A0 (NBSP) before the key leaves
        ## '\xa0SystemCallFilter' an UNKNOWN directive systemd ignores. str.strip()
        ## would drop the NBSP and read it as a real filter -- crediting a denial
        ## systemd never applies (a false pass).
        unit = '[Service]\n\xa0SystemCallFilter=~memfd_create:EPERM\n'
        self.assertEqual(memfd_denial(unit), 'none')
        self.assertEqual(
            service_values(['\xa0SystemCallFilter=x'], 'SystemCallFilter'), [])

    def test_nbsp_inside_filter_value_is_not_a_token_split(self) -> None:
        ## systemd splits filter tokens on ASCII whitespace only, so
        ## 'memfd_create\xa0foo' is ONE token != memfd_create -- not a denial.
        ## str.split() would split on the NBSP, see a 'memfd_create' token, and
        ## report a denial systemd never makes.
        unit = '[Service]\nSystemCallFilter=~memfd_create\xa0foo\n'
        self.assertEqual(memfd_denial(unit), 'none')

    def test_formfeed_does_not_start_a_new_directive(self) -> None:
        ## systemd splits physical lines on '\n' only; a form-feed (U+000C) stays in
        ## the value, so what follows is part of the first SystemCallFilter value, not
        ## its own directive. str.splitlines() would split on it and read a second,
        ## denying filter that systemd never sees.
        unit = ('[Service]\n'
                'SystemCallFilter=x\x0cSystemCallFilter=~memfd_create:EPERM\n')
        self.assertEqual(memfd_denial(unit), 'none')

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
