#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Functional tests for the pure bash helpers in preparation.bsh, extracted and
run in isolation (the fragment cannot be sourced wholesale -- it sources
sibling files by absolute path).
"""

import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    extract_bash_function,
    run_bash_function,
)


class TestLeaprunCmdDescribe(SystemcheckTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.func = extract_bash_function(cls.preparation, "leaprun_cmd_describe")

    def test_privileged_form(self) -> None:
        out = run_bash_function(
            self.func,
            'leaprun_cmd_describe "systemctl --wait is-system-running" '
            '"system-ready-check"',
        )
        self.assertIn("leaprun system-ready-check", out)
        self.assertIn("as root via privleap, not sudo", out)
        self.assertIn("systemctl --wait is-system-running", out)

    def test_unprivileged_form(self) -> None:
        out = run_bash_function(
            self.func, 'leaprun_cmd_describe "systemctl --user --wait is-system-running"'
        )
        self.assertIn("systemctl --user --wait is-system-running", out)
        self.assertNotIn("leaprun", out)
        self.assertNotIn("privleap", out)


class TestRemediationInstructions(SystemcheckTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.func = extract_bash_function(cls.preparation, "remediation_instructions")

    def test_sysmaint_session(self) -> None:
        out = run_bash_function(
            self.func,
            'remediation_instructions "dpkg --configure -a"',
            env_setup='booted_in_sysmaint_session=true\n'
                      'user_sysmaint_split_installed=false',
        )
        self.assertIn("Open Terminal", out)
        self.assertIn("System Maintenance Panel", out)
        ## sysmaint is a sudo-capable session, so sudo is still shown.
        self.assertIn("sudo dpkg --configure -a", out)

    def test_user_sysmaint_split(self) -> None:
        out = run_bash_function(
            self.func,
            'remediation_instructions "dpkg --configure -a"',
            env_setup='booted_in_sysmaint_session=false\n'
                      'user_sysmaint_split_installed=true',
        )
        self.assertIn("SYSMAINT Session", out)
        self.assertIn("System Maintenance Panel", out)
        self.assertIn("sudo dpkg --configure -a", out)

    def test_plain_uses_sudo(self) -> None:
        out = run_bash_function(
            self.func,
            'remediation_instructions "dpkg --configure -a"',
            env_setup='booted_in_sysmaint_session=false\n'
                      'user_sysmaint_split_installed=false\n'
                      'start_menu_instructions_system_first_part="Start Menu / System"',
        )
        self.assertIn("sudo dpkg --configure -a", out)


if __name__ == "__main__":
    unittest.main()
