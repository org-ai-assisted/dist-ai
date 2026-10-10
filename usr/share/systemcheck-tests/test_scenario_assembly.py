#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for systemcheck_testlib's scenario script assembly.

run_check_scenario_isolated materializes 'place' fixtures through a shell
prefix (mkdir + 'printf | base64 -d > file' + chmod). A failed fixture write
must abort the scenario before the SOURCED marker, so the scenario fails loud;
otherwise a check that does not inspect that fixture passes against the wrong
filesystem state. Runs the assembled script with plain bash (no bwrap), so this
stays in the strict parent suite.
"""

import subprocess
import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    _assemble_scenario_script,
    _parse_scenario_output,
)


class TestScenarioPrefixFailsLoud(ScenarioTestBase):
    FILE = 'check_environment_variables.bsh'

    def run_with_prefix(self, prefix: str):
        script = _assemble_scenario_script(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=workstation\nWHONIX=1', stubs='',
            prefix=prefix)
        return subprocess.run(['bash', '-c', script], capture_output=True,
                              text=True, timeout=30)

    def test_good_prefix_reaches_sourced(self) -> None:
        proc = self.run_with_prefix('true')
        result = _parse_scenario_output(proc)
        self.assertIsNotNone(result.exit_code)

    def test_failed_command_aborts_before_sourced(self) -> None:
        proc = self.run_with_prefix('mkdir -- /proc/no-such-dir/x')
        self.assertNotIn('SOURCED', proc.stdout.splitlines())
        with self.assertRaises(AssertionError):
            _parse_scenario_output(proc)

    def test_failed_decode_pipeline_aborts_before_sourced(self) -> None:
        ## Invalid base64 fails base64 -d, the LAST pipeline stage; the redirect
        ## target is a scratch file, so only the decode failure can stop it.
        proc = self.run_with_prefix(
            'printf %s "!!not-base64!!" | base64 -d > /dev/null')
        self.assertNotIn('SOURCED', proc.stdout.splitlines())

    def test_failed_first_pipeline_stage_aborts_before_sourced(self) -> None:
        ## Only pipefail catches a failure in a NON-last stage.
        proc = self.run_with_prefix('false | base64 -d > /dev/null')
        self.assertNotIn('SOURCED', proc.stdout.splitlines())


if __name__ == '__main__':
    unittest.main()
