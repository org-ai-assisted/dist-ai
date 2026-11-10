#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for check_mount_options -- systemcheck's presenter over
security-misc's `remount-secure --check` mount-options audit.

check_mount_options runs `remount-secure --check 3` and translates its verdict
into a systemcheck result: exit 0 -> green info (verbose-gated); nonzero -> an
orange "Not hardened" warning that lists the DEVIATION lines and sets EXIT_CODE.

remount-secure is stubbed as the branch sink (clean vs deviation); its own
set-based audit logic is covered in the security-misc-tests suite
(test_remount_secure_check_audit.py), not re-tested here.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)

CLEAN_STUB = (
    "remount-secure() {\n"
    "   printf '%s\\n' \"OK: '/boot' has intended mount options\"\n"
    "   return 0\n"
    "}"
)

DEVIATION_STUB = (
    "remount-secure() {\n"
    "   printf '%s\\n' \"DEVIATION: '/boot' missing 'noexec' (have: 'rw,nosuid,nodev')\"\n"
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
        ## A nonzero audit must warn regardless of verbosity and set EXIT_CODE,
        ## surfacing the deviating mountpoint to the operator.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=DEVIATION_STUB)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')
        self.assertIn('/boot', r.joined())
        self.assertIn('Not hardened', r.joined())


if __name__ == '__main__':
    unittest.main()
