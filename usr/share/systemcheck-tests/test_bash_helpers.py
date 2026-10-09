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
        out = run_sourced(
            fragment_sources(),
            'remediation_instructions "dpkg --configure -a"',
            setup='booted_in_sysmaint_session=true\n'
                  'user_sysmaint_split_installed=false',
        )
        self.assertIn('Open Terminal', out)
        self.assertIn('System Maintenance Panel', out)
        ## sysmaint is a sudo-capable session, so sudo is still shown.
        self.assertIn('sudo dpkg --configure -a', out)

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
