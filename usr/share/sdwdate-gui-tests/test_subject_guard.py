#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for subject_guard.skip_if_subject_absent.

The suites catch ModuleNotFoundError at import and skip when the subject is
absent. The trap it closes: skipping on ANY missing module (not just
sdwdate_gui) lets a broken install -- sdwdate_gui present but a dependency or
submodule missing -- read GREEN. The guard must skip ONLY when the sdwdate_gui
package itself is absent, and fail loud otherwise.
"""

# pylint: disable=invalid-name

import unittest

from subject_guard import skip_if_subject_absent


class TestSkipIfSubjectAbsent(unittest.TestCase):
    """Skip only when sdwdate_gui itself is absent; else re-raise (fail loud)."""

    def test_absent_package_skips(self) -> None:
        """exc.name == 'sdwdate_gui' -> SkipTest (the subject is not installed)."""
        exc = ModuleNotFoundError("No module named 'sdwdate_gui'", name='sdwdate_gui')
        with self.assertRaises(unittest.SkipTest):
            skip_if_subject_absent(exc)

    def _assert_reraises(self, exc: ModuleNotFoundError) -> None:
        """
        skip_if_subject_absent must re-raise `exc`, NOT turn it into a SkipTest.
        Catch SkipTest explicitly and self.fail -- a regression (unconditional
        SkipTest) would otherwise SKIP this test (reads green), not fail it.
        """
        try:
            skip_if_subject_absent(exc)
        except unittest.SkipTest:
            self.fail(
                f"{exc.name!r} (a broken install) was turned into a SkipTest; "
                'it must fail loud'
            )
        except ModuleNotFoundError as caught:
            self.assertIs(caught, exc)
            return
        self.fail('skip_if_subject_absent did not raise')

    def test_missing_dependency_reraises(self) -> None:
        """A missing dependency (exc.name != 'sdwdate_gui') must fail loud."""
        self._assert_reraises(
            ModuleNotFoundError("No module named 'pyinotify'", name='pyinotify')
        )

    def test_missing_submodule_reraises(self) -> None:
        """A missing sdwdate_gui SUBMODULE is also a broken install -> fail loud."""
        self._assert_reraises(
            ModuleNotFoundError(
                "No module named 'sdwdate_gui.nope'", name='sdwdate_gui.nope'
            )
        )


if __name__ == '__main__':
    unittest.main()
