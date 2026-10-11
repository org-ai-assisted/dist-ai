#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for the headless session-dependent auto-skip.

Running systemcheck with NO graphical/logind session (serial console / VBox
guestcontrol / `su - user`) made the user systemd-manager check and the user
system-ready check WARN as artifacts. systemcheck_session_detection now detects a
genuinely headless context and those two checks report N/A there -- with a HARD
GUARD: when a graphical session IS present, a real failure is NEVER masked.

Drives the REAL functions via run_check_scenario (preparation.bsh, which defines
the detector + emit helpers, is always sourced). No bwrap needed.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)

## Emit the detector's verdict so a scenario can assert on it.
_DETECT = ('systemcheck_session_detection; '
           'emit_message info "DETECT:${systemcheck_graphical_session_present}"')
## A headless environment: no graphical env vars, and graphical-session.target inactive.
_HEADLESS_ENV = ('unset XDG_SESSION_TYPE DISPLAY WAYLAND_DISPLAY XDG_CURRENT_DESKTOP\n'
                 'unset systemcheck_headless_autoskip')
_NO_GRAPHICAL_TARGET = 'systemctl() { return 1; }'


class TestSessionDetection(ScenarioTestBase):
    FILE = 'check_services.bsh'

    def test_headless_detected_when_no_session(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), _DETECT,
            env_setup=_HEADLESS_ENV, stubs=_NO_GRAPHICAL_TARGET)
        self.assertCleanRun(r)
        self.assertIn('DETECT:false', r.joined())

    def test_graphical_session_type_is_present(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), _DETECT, env_setup='XDG_SESSION_TYPE=wayland')
        self.assertCleanRun(r)
        self.assertIn('DETECT:true', r.joined())

    def test_display_set_is_present(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), _DETECT,
            env_setup='unset XDG_SESSION_TYPE WAYLAND_DISPLAY XDG_CURRENT_DESKTOP\n'
                      'DISPLAY=:0',
            stubs=_NO_GRAPHICAL_TARGET)
        self.assertCleanRun(r)
        self.assertIn('DETECT:true', r.joined())

    def test_optout_forces_present_even_when_headless(self) -> None:
        ## systemcheck_headless_autoskip=false must never soften (always run the checks).
        r = run_check_scenario(
            self.check(self.FILE), _DETECT,
            env_setup='systemcheck_headless_autoskip=false\n'
                      'unset XDG_SESSION_TYPE DISPLAY WAYLAND_DISPLAY XDG_CURRENT_DESKTOP',
            stubs=_NO_GRAPHICAL_TARGET)
        self.assertCleanRun(r)
        self.assertIn('DETECT:true', r.joined())


class TestCheckServicesHeadless(ScenarioTestBase):
    FILE = 'check_services.bsh'

    def test_user_units_na_when_headless(self) -> None:
        ## Headless: the user-units check reports N/A (info), does not fail.
        r = run_check_scenario(
            self.check(self.FILE), 'check_services_do',
            env_setup='check_type=user\nsystemcheck_graphical_session_present=false\nverbose=1')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')
        self.assertIn('not applicable', r.joined())

    def test_user_units_failure_not_masked_when_session_present(self) -> None:
        ## HARD GUARD: a graphical session IS present, a failed user unit still fails.
        r = run_check_scenario(
            self.check(self.FILE), 'check_services_do',
            env_setup='check_type=user\nsystemcheck_graphical_session_present=true\n'
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

    def test_user_ready_na_when_headless(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_system_ready_user',
            env_setup='systemcheck_graphical_session_present=false\nverbose=1')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')
        self.assertIn('not applicable', r.joined())

    def test_user_ready_failure_not_masked_when_session_present(self) -> None:
        ## HARD GUARD: with a session present it proceeds into the real check (stubbed to
        ## fail here), so a genuine failure still reddens -- not short-circuited to N/A.
        r = run_check_scenario(
            self.check(self.FILE), 'check_system_ready_user',
            env_setup='systemcheck_graphical_session_present=true',
            stubs='leaprun_cmd_describe() { printf "desc"; }\n'
                  'check_system_ready_shared() { EXIT_CODE=1; emit_message warning "<p>stub Failed</p>"; }')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
