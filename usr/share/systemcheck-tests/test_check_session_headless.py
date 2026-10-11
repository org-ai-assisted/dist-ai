#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for the user-manager-unreachable auto-skip.

Running systemcheck with NO reachable per-user systemd manager (serial console / VBox
guestcontrol / `su - user` without a user bus) made the user systemd-units check and the
user system-ready check WARN as artifacts. systemcheck_session_detection now probes user-bus
CONNECTIVITY and those two checks report N/A only then -- with a HARD GUARD: a reachable but
degraded user manager stays "present", so a real failure (failed user unit on a tty / ssh /
graphical login) is NEVER masked. The opt-out (systemcheck_headless_autoskip) is applied at
the check sites, which run after source_config, so a config override is honored.

Drives the REAL functions via run_check_scenario (preparation.bsh, which defines the detector
+ emit helpers, is always sourced). No bwrap needed.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)

## Emit the detector's verdict so a scenario can assert on it.
_DETECT = ('systemcheck_session_detection; '
           'emit_message info "DETECT:${systemcheck_user_manager_present}"')
## `systemctl --user show --property=Version` is the connectivity probe: rc 0 = reachable.
_SYSTEMCTL_UNREACHABLE = 'systemctl() { return 1; }'
_SYSTEMCTL_REACHABLE = 'systemctl() { return 0; }'


class TestSessionDetection(ScenarioTestBase):
    FILE = 'check_services.bsh'

    def test_unreachable_user_manager_detected(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), _DETECT, stubs=_SYSTEMCTL_UNREACHABLE)
        self.assertCleanRun(r)
        self.assertIn('DETECT:false', r.joined())

    def test_reachable_user_manager_is_present(self) -> None:
        ## A reachable manager -> present, EVEN degraded (connectivity, not health).
        r = run_check_scenario(
            self.check(self.FILE), _DETECT, stubs=_SYSTEMCTL_REACHABLE)
        self.assertCleanRun(r)
        self.assertIn('DETECT:true', r.joined())


class TestCheckServicesHeadless(ScenarioTestBase):
    FILE = 'check_services.bsh'

    def test_user_units_na_when_unreachable(self) -> None:
        ## No reachable user manager: the user-units check reports N/A (info), does not fail.
        r = run_check_scenario(
            self.check(self.FILE), 'check_services_do',
            env_setup='check_type=user\nsystemcheck_user_manager_present=false\nverbose=1')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')
        self.assertIn('not applicable', r.joined())

    def test_user_units_failure_not_masked_when_reachable(self) -> None:
        ## HARD GUARD: the user manager IS reachable, so a failed user unit still fails.
        r = run_check_scenario(
            self.check(self.FILE), 'check_services_do',
            env_setup='check_type=user\nsystemcheck_user_manager_present=true\n'
                      'machine_command_machine=fail_stub\nmachine_command_pretty=fail_stub\n'
                      'machine_command_desc=desc',
            stubs='fail_stub() { printf "%s\\n" "foo.service loaded failed failed"; }\n'
                  'sanitize-string() { printf "%s" "$3"; }\n'
                  'br_add() { printf "%s" "$1"; }')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')

    def test_optout_runs_the_check_even_when_unreachable(self) -> None:
        ## systemcheck_headless_autoskip=false forces the check to run (never auto-skip),
        ## read at the gate so a config-file override takes effect.
        r = run_check_scenario(
            self.check(self.FILE), 'check_services_do',
            env_setup='check_type=user\nsystemcheck_user_manager_present=false\n'
                      'systemcheck_headless_autoskip=false\n'
                      'machine_command_machine=fail_stub\nmachine_command_pretty=fail_stub\n'
                      'machine_command_desc=desc',
            stubs='fail_stub() { printf "%s\\n" "foo.service loaded failed failed"; }\n'
                  'sanitize-string() { printf "%s" "$3"; }\n'
                  'br_add() { printf "%s" "$1"; }')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')


class TestCheckSystemReadyHeadless(ScenarioTestBase):
    FILE = 'check_system_ready.bsh'

    def test_user_ready_na_when_unreachable(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_system_ready_user',
            env_setup='systemcheck_user_manager_present=false\nverbose=1')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')
        self.assertIn('not applicable', r.joined())

    def test_user_ready_failure_not_masked_when_reachable(self) -> None:
        ## HARD GUARD: with the user manager reachable it proceeds into the real check
        ## (stubbed to fail here), so a genuine failure still reddens -- not short-circuited.
        r = run_check_scenario(
            self.check(self.FILE), 'check_system_ready_user',
            env_setup='systemcheck_user_manager_present=true',
            stubs='leaprun_cmd_describe() { printf "desc"; }\n'
                  'check_system_ready_shared() { EXIT_CODE=1; emit_message warning "<p>stub Failed</p>"; }')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
