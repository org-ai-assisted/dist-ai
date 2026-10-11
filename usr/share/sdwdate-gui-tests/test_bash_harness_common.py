#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for the bash-test harness itself (bash_harness_common).

locate_script must distinguish an ABSENT subject (the sdwdate_gui package not
importable -> a legitimate SkipTest) from a BROKEN one (the package importable
but a required libexec script missing -> a loud failure, never a silent skip).
A SkipTest in the broken case reads as success and would let the python tests
pass the suite green while the bash tests silently vanished.
"""

# pylint: disable=invalid-name

import unittest

## No top-level importability probe here: locate_script() imports sdwdate_gui
## and skips (via subject_guard) when it is absent, so every test is already
## guarded. A bare `import sdwdate_gui` probe would be a redundant unused import
## (CodeQL py/unused-import) with no added coverage.
from bash_harness_common import locate_script


class TestLocateScript(unittest.TestCase):
    """locate_script fails loud on a missing script when the module is present."""

    def test_real_script_resolves(self) -> None:
        """A shipped script resolves to an existing file."""
        script = locate_script('sdwdate-gui-qubes-proxy-helper')
        self.assertTrue(script.is_file())

    def test_missing_script_raises_not_skips(self) -> None:
        """
        A bogus script name (module importable, script absent) must raise a
        hard error, NOT unittest.SkipTest -- the broken-install case must fail
        loud. Catch SkipTest explicitly and self.fail, so the old behaviour
        FAILS this test rather than skipping it (a skip would read as success).
        """
        ## SkipTest is checked first: it is also an Exception, so an outer
        ## RuntimeError clause would never see it, but self.fail raising
        ## AssertionError inside the except is what records the FAILURE.
        try:
            locate_script('sdwdate-gui-this-script-does-not-exist')
        except unittest.SkipTest:
            self.fail('locate_script skipped on a missing script (silent-green)')
        except RuntimeError:
            return
        self.fail('locate_script did not raise on a missing script')


if __name__ == '__main__':
    unittest.main()
