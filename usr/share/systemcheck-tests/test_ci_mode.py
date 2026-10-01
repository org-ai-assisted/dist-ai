#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for systemcheck's --ci mode: a CI/automated-test run tolerates WARNING-class
findings (e.g. pending package updates on a fresh install) but must still fail on a
real ERROR, a script crash, or a signal. The decision lives in the pure helper
systemcheck_apply_ci_exit (cleanup.bsh); error-severity is tracked by emit_message
(preparation.bsh).
"""

import os
import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    extract_bash_function,
    run_bash_function,
)


class TestApplyCiExit(SystemcheckTestBase):
    func: str

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cleanup = os.path.join(cls.dir, 'cleanup.bsh')
        cls.func = extract_bash_function(cleanup, 'systemcheck_apply_ci_exit')

    def _apply(self, raw: str, ci: str, saw_err: str, script_err: str) -> str:
        return run_bash_function(
            self.func,
            f'systemcheck_apply_ci_exit "{raw}" "{ci}" "{saw_err}" "{script_err}"')

    def test_ci_warning_only_passes(self) -> None:
        ## the whole point: --ci + a warning-only run (EXIT_CODE 1, no error) -> 0.
        self.assertEqual(self._apply('1', 'true', 'false', ''), '0')

    def test_ci_error_still_fails(self) -> None:
        ## an error-severity message was emitted -> stays non-zero even under --ci.
        self.assertEqual(self._apply('1', 'true', 'true', ''), '1')

    def test_without_ci_unchanged(self) -> None:
        ## default (no --ci): warnings keep exiting non-zero, behaviour unchanged.
        self.assertEqual(self._apply('1', 'false', 'false', ''), '1')

    def test_ci_script_error_not_masked(self) -> None:
        ## a trapped script error (error_handler set exit_code) is never masked.
        self.assertEqual(self._apply('1', 'true', 'false', '5'), '1')

    def test_ci_sigterm_not_masked(self) -> None:
        self.assertEqual(self._apply('143', 'true', 'false', ''), '143')

    def test_ci_sigint_not_masked(self) -> None:
        self.assertEqual(self._apply('130', 'true', 'false', ''), '130')

    def test_ci_already_zero(self) -> None:
        self.assertEqual(self._apply('0', 'true', 'false', ''), '0')


class TestEmitMessageTracksError(SystemcheckTestBase):
    func: str

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.func = extract_bash_function(cls.preparation, 'emit_message')

    def _emit(self, severity: str) -> str:
        ## stub the two output channels ($output_x/$output_cli -> no-op true), run
        ## emit_message, then report the tracked flag.
        env = (
            'systemcheck_saw_error="false"\n'
            'output_x=true\n'
            'output_cli=true\n'
            'output_opts=()\n'
        )
        return run_bash_function(
            self.func,
            f'emit_message {severity} "<p>msg</p>"; printf "%s" "$systemcheck_saw_error"',
            env_setup=env)

    def test_error_sets_flag(self) -> None:
        self.assertEqual(self._emit('error'), 'true')

    def test_warning_leaves_flag(self) -> None:
        self.assertEqual(self._emit('warning'), 'false')

    def test_info_leaves_flag(self) -> None:
        self.assertEqual(self._emit('info'), 'false')


if __name__ == '__main__':
    unittest.main()
