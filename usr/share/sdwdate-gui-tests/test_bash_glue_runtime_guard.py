#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit test for the shared runtime guard in the sdwdate-gui bash glue.

Each of the four sdwdate-gui glue scripts opens by sourcing check_runtime.bsh
(for was_executed) and, if was_executed is not defined afterwards, prints a
clear error and exits 1 instead of letting a later 'was_executed: command not
found' cascade hide the real cause. This pins that fail-closed contract for all
of them, both when the source itself fails and when it succeeds but defines
nothing.
"""

# pylint: disable=invalid-name

import tempfile
import unittest
from pathlib import Path

from bash_harness_common import locate_script, run_sourced

SCRIPTS = (
    'sdwdate-gui-qubes-connect-setup',
    'sdwdate-gui-qubes-proxy',
    'sdwdate-gui-qubes-proxy-helper',
    'sdwdate-gui-enabled-check',
)


class TestRuntimeGuard(unittest.TestCase):
    """An unsourceable check_runtime.bsh is a clean exit 1, not a cascade."""

    def test_unsourceable_check_runtime_fails_closed(self) -> None:
        """Each script errors and exits 1 when check_runtime.bsh is missing."""
        body = """
        source "${SDWDATE_GUI_SCRIPT}"
        """
        for name in SCRIPTS:
            with self.subTest(script=name):
                result = run_sourced(
                    locate_script(name),
                    body,
                    {'HELPER_SCRIPTS_PATH': '/nonexistent'},
                )
                self.assertEqual(
                    result.returncode,
                    1,
                    f'{name} did not exit 1 on an unsourceable '
                    f'check_runtime.bsh (stderr: {result.stderr})',
                )
                self.assertIn(
                    'cannot source check_runtime.bsh',
                    result.stderr,
                    f'{name} did not print the check_runtime.bsh guard error',
                )

    def test_sourceable_but_undefined_was_executed_fails_closed(self) -> None:
        """A check_runtime.bsh that sources OK but defines nothing exits 1."""
        body = """
        source "${SDWDATE_GUI_SCRIPT}"
        """
        for name in SCRIPTS:
            with self.subTest(script=name):
                with tempfile.TemporaryDirectory() as tmp_str:
                    hs_dir = (
                        Path(tmp_str) / 'usr' / 'libexec' / 'helper-scripts'
                    )
                    hs_dir.mkdir(parents=True)
                    (hs_dir / 'check_runtime.bsh').write_text(
                        '', encoding='utf-8'
                    )
                    result = run_sourced(
                        locate_script(name),
                        body,
                        {'HELPER_SCRIPTS_PATH': str(tmp_str)},
                    )
                    self.assertEqual(
                        result.returncode,
                        1,
                        f'{name} did not exit 1 when was_executed stayed '
                        f'undefined (stderr: {result.stderr})',
                    )
                    self.assertIn(
                        'cannot source check_runtime.bsh',
                        result.stderr,
                        f'{name} did not print the guard error on an empty '
                        f'check_runtime.bsh',
                    )


if __name__ == '__main__':
    unittest.main()
