#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for check_mount_options -- systemcheck's presenter over
security-misc's `remount-secure --check` mount-options audit.

check_mount_options runs `remount-secure --check 3` and translates its verdict
into a systemcheck result: exit 0 -> green info (verbose-gated); a deviation
exit -> an orange "Not hardened" warning listing the DEVIATION lines; a failed
run (no deviation lines) -> an orange "Indeterminate" warning. All set EXIT_CODE.

remount-secure is stubbed as the branch sink; its own set-based audit logic is
covered in the security-misc-tests suite (test_remount_secure_check_audit.py).
The stub ASSERTS it was invoked with `--check`: a regression that dropped it and
called `remount-secure 3` would, as root, enter mutating remount mode -- so the
stub must make that fail the test, not pass silently.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)

## Guards that --check is actually passed; otherwise emits an error and a
## sentinel exit so the caller's assertions (info / DEVIATION) cannot be met.
_REQUIRE_CHECK = (
    "remount-secure() {\n"
    "   case \" $* \" in\n"
    "      *\" --check \"*)\n"
    "         true\n"
    "         ;;\n"
    "      *)\n"
    "         printf '%s\\n' \"STUB-ERROR: --check not passed, got: $*\" >&2\n"
    "         return 2\n"
    "         ;;\n"
    "   esac\n"
)

CLEAN_STUB = _REQUIRE_CHECK + (
    "   printf '%s\\n' \"OK: '/boot' has intended mount options\"\n"
    "   return 0\n"
    "}"
)

DEVIATION_STUB = _REQUIRE_CHECK + (
    "   printf '%s\\n' \"DEVIATION: '/boot' missing 'noexec' (have: 'rw,nosuid,nodev')\"\n"
    "   return 1\n"
    "}"
)

## Nonzero exit with NO DEVIATION line: the audit could not run (e.g. an older
## remount-secure that rejects --check), still receiving --check.
INDETERMINATE_STUB = _REQUIRE_CHECK + (
    "   printf '%s\\n' \"ERROR: --check unsupported\" >&2\n"
    "   return 1\n"
    "}"
)


class CheckMountOptionsScenarios(ScenarioTestBase):
    FILE = 'check_mount_options.bsh'

    def test_hardened_emits_info_when_verbose(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=1', stubs=CLEAN_STUB)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    def test_hardened_is_silent_when_not_verbose(self) -> None:
        ## The green result is verbose-gated: a hardened system stays quiet.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=CLEAN_STUB)
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')

    def test_deviation_warns_and_fails(self) -> None:
        ## A deviation must warn regardless of verbosity, set EXIT_CODE, and
        ## surface the deviating mountpoint.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=DEVIATION_STUB)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')
        self.assertIn('/boot', r.joined())
        self.assertIn('Not hardened', r.joined())

    def test_failed_audit_reports_indeterminate(self) -> None:
        ## A nonzero exit with no DEVIATION lines is a failed audit, reported
        ## honestly as Indeterminate rather than a false "Not hardened".
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=INDETERMINATE_STUB)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')
        self.assertIn('Indeterminate', r.joined())
        self.assertNotIn('Not hardened', r.joined())


if __name__ == '__main__':
    unittest.main()
