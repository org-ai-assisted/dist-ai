#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Functional tests for the pure bash helpers in preparation.bsh, run by sourcing
the real fragment.
"""

import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    fragment_sources,
    run_sourced,
)


class TestLeaprunCmdDescribe(SystemcheckTestBase):
    def test_privileged_form(self) -> None:
        out = run_sourced(
            fragment_sources(),
            'leaprun_cmd_describe "systemctl --wait is-system-running" '
            '"system-ready-check"',
        )
        self.assertIn('leaprun system-ready-check', out)
        self.assertIn('as root via privleap', out)
        self.assertIn('systemctl --wait is-system-running', out)

    def test_unprivileged_form(self) -> None:
        out = run_sourced(
            fragment_sources(),
            'leaprun_cmd_describe "systemctl --user --wait is-system-running"',
        )
        self.assertIn('systemctl --user --wait is-system-running', out)
        self.assertNotIn('leaprun', out)
        self.assertNotIn('privleap', out)


class TestRemediationInstructions(SystemcheckTestBase):
    def test_sysmaint_session(self) -> None:
        ## Working sysmaint session: requested at boot AND landed on 'sysmaint'.
        out = run_sourced(
            fragment_sources(),
            'remediation_instructions "dpkg --configure -a"',
            setup='booted_in_sysmaint_session=true\n'
                  'who_ami=sysmaint\n'
                  'user_sysmaint_split_installed=false',
        )
        self.assertIn('Open Terminal', out)
        self.assertIn('System Maintenance Panel', out)
        ## sysmaint is a sudo-capable session, so sudo is still shown.
        self.assertIn('sudo dpkg --configure -a', out)

    def test_sysmaint_requested_but_landed_as_user(self) -> None:
        ## Mismatch: SYSMAINT requested at boot but logged in unprivileged.
        ## No panel / sudo is available here, so the fix must be the reboot
        ## advice, NOT "Open Terminal in the System Maintenance Panel".
        out = run_sourced(
            fragment_sources(),
            'remediation_instructions "dpkg --configure -a"',
            setup='booted_in_sysmaint_session=true\n'
                  'who_ami=user\n'
                  'user_sysmaint_split_installed=true',
        )
        self.assertIn('reboot into', out)
        self.assertIn('SYSMAINT Session', out)
        self.assertIn('sudo dpkg --configure -a', out)

    def test_sysmaint_account_without_boot_role_not_panel_guidance(self) -> None:
        ## sysmaint ACCOUNT reached without a 'boot-role=sysmaint' boot (console
        ## su, manual default-user): sudo works but the System Maintenance Panel
        ## session does not exist, so the guidance must NOT be the immediate
        ## "click Open Terminal in the panel, then run" branch. Gating on the
        ## account alone (not the session) regresses this.
        out = run_sourced(
            fragment_sources(),
            'remediation_instructions "dpkg --configure -a"',
            setup='booted_in_sysmaint_session=false\n'
                  'who_ami=sysmaint\n'
                  'user_sysmaint_split_installed=true',
        )
        self.assertIn('reboot into', out)

    def test_user_sysmaint_split(self) -> None:
        out = run_sourced(
            fragment_sources(),
            'remediation_instructions "dpkg --configure -a"',
            setup='booted_in_sysmaint_session=false\n'
                  'user_sysmaint_split_installed=true',
        )
        self.assertIn('SYSMAINT Session', out)
        self.assertIn('System Maintenance Panel', out)
        self.assertIn('sudo dpkg --configure -a', out)

    def test_plain_uses_sudo(self) -> None:
        out = run_sourced(
            fragment_sources(),
            'remediation_instructions "dpkg --configure -a"',
            setup='booted_in_sysmaint_session=false\n'
                  'user_sysmaint_split_installed=false\n'
                  'start_menu_instructions_system_first_part="Start Menu / System"',
        )
        self.assertIn('sudo dpkg --configure -a', out)


if __name__ == '__main__':
    unittest.main()
