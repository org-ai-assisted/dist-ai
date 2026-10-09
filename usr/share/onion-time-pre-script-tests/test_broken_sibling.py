#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
onion-time-pre-script EXECUTED with a broken sibling library.

sdwdate reads exit 2 as 'busy, wait'. A sibling .bsh that fails to source must
therefore exit through the script's own exit_handler with the error code 1,
never leak a raw bash status. That only holds if strict mode and the traps are
in place BEFORE the sibling sources run, which sourcing-for-tests must not
disturb.

The real subject is executed with HELPER_SCRIPTS_PATH pointing at a scratch
tree whose siblings are symlinks to the real files, except the one sibling
under test, which is replaced by a broken stand-in.
"""

import os
import subprocess
import tempfile
import unittest

from onion_time_pre_script_testlib import PreScriptTestBase

LIBEXEC = os.path.join('usr', 'libexec', 'helper-scripts')


class TestBrokenSibling(PreScriptTestBase):
    """A sibling that fails to source exits 1 via exit_handler."""

    def run_with_broken(self, name: str, content: 'str | None',
                        argv0: 'list[str]', **extra_env: str
                        ) -> 'subprocess.CompletedProcess':
        real_dir = os.path.join(self.root or '/', LIBEXEC)
        with tempfile.TemporaryDirectory() as tmp:
            fake_dir = os.path.join(tmp, LIBEXEC)
            os.makedirs(fake_dir)
            for entry in os.listdir(real_dir):
                if entry == name:
                    continue
                os.symlink(os.path.join(real_dir, entry),
                           os.path.join(fake_dir, entry))
            if content is not None:
                with open(os.path.join(fake_dir, name), 'w',
                          encoding='utf-8') as handle:
                    handle.write(content)
            env = dict(os.environ, HELPER_SCRIPTS_PATH=tmp, **extra_env)
            return subprocess.run(
                argv0 + [self.path],
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=60,
            )

    def assert_error_exit(self, result: 'subprocess.CompletedProcess') -> None:
        detail = 'stdout:\n%s\nstderr:\n%s' % (result.stdout, result.stderr)
        self.assertEqual(result.returncode, 1, detail)
        self.assertIn("exit_code '1'", result.stdout, detail)

    def test_missing_sibling_executed(self) -> None:
        self.assert_error_exit(
            self.run_with_broken('tor_enabled_check', None, []))

    def test_missing_sibling_via_bash(self) -> None:
        ## 'bash <script>' ignores shebang options; the guard must not rely on them.
        self.assert_error_exit(
            self.run_with_broken('tor_enabled_check', None, ['bash']))

    def test_failing_sibling_executed(self) -> None:
        self.assert_error_exit(
            self.run_with_broken('strings.bsh', 'false\n', []))

    def test_sibling_status_2_is_not_busy(self) -> None:
        ## A raw 2 would read as 'busy, wait' to sdwdate.
        self.assert_error_exit(
            self.run_with_broken('tor_enabled_check', 'return 2\n', []))

    def test_sibling_command_failure_status_2_is_not_busy(self) -> None:
        self.assert_error_exit(
            self.run_with_broken('tor_enabled_check', '[ 1 -eq abc ]\n', []))

    def test_unknown_command_in_sibling_is_error(self) -> None:
        ## 127 is outside the 0/1/2 contract.
        self.assert_error_exit(
            self.run_with_broken(
                'tor_enabled_check',
                'onion-time-pre-script-test-no-such-command\n', []))

    def test_inherited_exit_code_does_not_mask_failure(self) -> None:
        self.assert_error_exit(
            self.run_with_broken('tor_enabled_check', None, [], exit_code='0'))


if __name__ == '__main__':
    unittest.main()
