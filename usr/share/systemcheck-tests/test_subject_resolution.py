#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
systemcheck_dir() subject resolution.

Pins that an UNSET SYSTEMCHECK_REPO is FATAL (exit 1), NOT a silent fallback to
the installed /usr/libexec/systemcheck. That stale installed copy lags an `ai`
checkout and fails cryptically on helpers it predates (the version-skew trap that
produced the spurious test_bash_modules_load_tolerance failures). CI always wires
SYSTEMCHECK_REPO via --component-root, so a wired run is unaffected.
"""

import os
import unittest

from systemcheck_testlib import systemcheck_dir


class TestSubjectResolution(unittest.TestCase):
    def _restore_repo(self, value):
        if value is None:
            os.environ.pop('SYSTEMCHECK_REPO', None)
        else:
            os.environ['SYSTEMCHECK_REPO'] = value

    def test_unset_systemcheck_repo_is_fatal(self):
        """Unset -> FATAL exit 1, never a silent stale-installed run."""
        self.addCleanup(self._restore_repo, os.environ.get('SYSTEMCHECK_REPO'))
        os.environ.pop('SYSTEMCHECK_REPO', None)
        with self.assertRaises(SystemExit) as caught:
            systemcheck_dir()
        self.assertEqual(caught.exception.code, 1)

    def test_set_systemcheck_repo_resolves(self):
        """A wired checkout (how the suite always runs) resolves to a real dir."""
        self.assertTrue(os.path.isdir(systemcheck_dir()))


if __name__ == '__main__':
    unittest.main()
