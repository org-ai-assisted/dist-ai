#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for the user-sysmaint-split boot-role mismatch detection.

A SYSMAINT Session requested at boot (kernel 'boot-role=sysmaint', captured as
booted_in_sysmaint_session=true) that lands on an unprivileged account instead
of 'sysmaint' is a grave, easy-to-miss state: root / sudo silently will not
work though the user believes they are in a maintenance session.
check_user_sysmaint_split_boot_mismatch raises a grave (error) popup, and it is
registered in systemcheck_autostart_functions so it also surfaces at login.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)


class TestSysmaintBootMismatchScenarios(ScenarioTestBase):
    FILE = 'check_user_sysmaint_split.bsh'

    def test_requested_sysmaint_but_standard_user_is_grave(self) -> None:
        ## SYSMAINT requested at boot, landed as standard 'user' -> grave popup.
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mismatch',
            env_setup='booted_in_sysmaint_session=true\nwho_ami=user')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('error'))
        ## Grave error reaches BOTH channels: the GUI popup (passivepopupqueuex,
        ## recorded with channel '-') and the CLI (messagecli, channel 'cli').
        self.assertTrue(any(c == 'cli' and s == 'error' for c, s, _m in r.records))
        self.assertTrue(any(c == '-' and s == 'error' for c, s, _m in r.records))
        self.assertIn('sysmaint', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_sysmaint_session_lands_as_sysmaint_is_quiet(self) -> None:
        ## SYSMAINT requested AND logged in as 'sysmaint' -> nothing to warn.
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mismatch',
            env_setup='booted_in_sysmaint_session=true\nwho_ami=sysmaint')
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])

    def test_user_session_is_quiet(self) -> None:
        ## Plain USER Session (no SYSMAINT requested) -> nothing to warn.
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mismatch',
            env_setup='booted_in_sysmaint_session=false\nwho_ami=user')
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])

    def test_autostart_registration(self) -> None:
        ## Grave checks surface in autostart mode only when registered in
        ## systemcheck_autostart_functions (see preparation.bsh gating).
        r = run_check_scenario(
            self.check(self.FILE),
            'printf "LIST\\t%s\\n" "${systemcheck_autostart_functions}"',
            env_setup='systemcheck_autostart_functions="${systemcheck_autostart_functions:-}"')
        self.assertIn('check_user_sysmaint_split_boot_mismatch', r.stdout)


class TestSysmaintBootModeLineScenarios(ScenarioTestBase):
    FILE = 'check_user_sysmaint_split.bsh'

    def test_boot_mode_line_honest_on_mismatch(self) -> None:
        ## The info result line must not claim "SYSMAINT Session" when the
        ## session actually landed on an unprivileged account.
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mode',
            env_setup='booted_in_sysmaint_session=true\nwho_ami=user')
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertIn('standard user', r.joined())
        self.assertIn('user', r.joined())

    def test_boot_mode_line_sysmaint_session(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mode',
            env_setup='booted_in_sysmaint_session=true\nwho_ami=sysmaint')
        self.assertCleanRun(r)
        self.assertIn('SYSMAINT Session', r.joined())
        self.assertNotIn('standard user', r.joined())

    def test_boot_mode_line_user_session(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mode',
            env_setup='booted_in_sysmaint_session=false\nwho_ami=user')
        self.assertCleanRun(r)
        self.assertIn('USER Session', r.joined())


if __name__ == '__main__':
    unittest.main()
