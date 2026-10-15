#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for the user-sysmaint-split boot-role mismatch detection.

A grave, easy-to-miss state is when the account the session landed on does not
match the session type requested at boot (kernel 'boot-role=sysmaint', captured
as booted_in_sysmaint_session):
  - SYSMAINT requested, landed unprivileged: root / sudo silently fail though
    the user believes they are in a maintenance session.
  - USER requested, landed on 'sysmaint': the user believes they are in a
    locked-down session but actually holds sudo-capable privileges.
check_user_sysmaint_split_boot_mismatch raises a grave (error) popup for either
direction, and is registered in systemcheck_autostart_functions so it also
surfaces at login. The factual session line (check_user_sysmaint_split_boot_mode)
reports the account actually in use and does NOT duplicate the warning at info.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)


class TestSysmaintBootMismatchScenarios(ScenarioTestBase):
    FILE = 'check_user_sysmaint_split.bsh'

    def _assert_grave(self, r) -> None:
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('error'))
        ## Grave error reaches BOTH channels: the GUI popup (passivepopupqueuex,
        ## recorded with channel '-') and the CLI (messagecli, channel 'cli').
        self.assertTrue(any(c == 'cli' and s == 'error' for c, s, _m in r.records))
        self.assertTrue(any(c == '-' and s == 'error' for c, s, _m in r.records))
        self.assertEqual(r.exit_code, '0')

    def _run(self, env_setup: str):
        return run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mismatch',
            env_setup=env_setup)

    def test_sysmaint_requested_but_standard_user_is_grave(self) -> None:
        r = self._run('booted_in_sysmaint_session=true\nwho_ami=user')
        self._assert_grave(r)
        self.assertIn('SYSMAINT Session', r.joined())
        self.assertIn('sysmaint', r.joined())

    def test_user_requested_but_sysmaint_account_is_grave(self) -> None:
        r = self._run('booted_in_sysmaint_session=false\nwho_ami=sysmaint')
        self._assert_grave(r)
        self.assertIn('USER Session', r.joined())
        self.assertIn('sysmaint', r.joined())

    def test_sysmaint_session_aligned_is_quiet(self) -> None:
        r = self._run('booted_in_sysmaint_session=true\nwho_ami=sysmaint')
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])

    def test_user_session_aligned_is_quiet(self) -> None:
        r = self._run('booted_in_sysmaint_session=false\nwho_ami=user')
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

    def _line(self, env_setup: str):
        return run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split_boot_mode',
            env_setup=env_setup)

    def test_line_is_factual_by_account_sysmaint(self) -> None:
        ## Reports the account actually in use; never editorializes the mismatch
        ## (that is the grave popup's job, not an info line).
        for booted in ('true', 'false'):
            r = self._line(f'booted_in_sysmaint_session={booted}\nwho_ami=sysmaint')
            self.assertCleanRun(r)
            self.assertTrue(r.has_severity('info'))
            self.assertIn('SYSMAINT Session', r.joined())
            self.assertNotIn('USER Session', r.joined())

    def test_line_is_factual_by_account_user(self) -> None:
        for booted in ('true', 'false'):
            r = self._line(f'booted_in_sysmaint_session={booted}\nwho_ami=user')
            self.assertCleanRun(r)
            self.assertTrue(r.has_severity('info'))
            self.assertIn('USER Session', r.joined())
            self.assertNotIn('SYSMAINT Session', r.joined())

    def test_line_not_error_severity(self) -> None:
        ## The result line is info only -- the mismatch is reported once, as the
        ## grave popup, never duplicated here at a second severity.
        r = self._line('booted_in_sysmaint_session=true\nwho_ami=user')
        self.assertFalse(r.has_severity('error'))


if __name__ == '__main__':
    unittest.main()
