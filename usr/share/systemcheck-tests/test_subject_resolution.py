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

from systemcheck_testlib import systemcheck_dir, _msgcollector_libexec


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


class TestMsgcollectorResolution(unittest.TestCase):
    """An EXPLICIT MSGCOLLECTOR_REPO that lacks its libexec dir must FAIL loudly,
    not silently fall back to the host msgcollector (the version-skew false-green
    the bwrap orchestrator suite exists to avoid)."""

    def test_explicit_missing_msgcollector_repo_raises(self):
        saved = os.environ.get('MSGCOLLECTOR_REPO')
        self.addCleanup(
            lambda: os.environ.__setitem__('MSGCOLLECTOR_REPO', saved)
            if saved is not None else os.environ.pop('MSGCOLLECTOR_REPO', None))
        os.environ['MSGCOLLECTOR_REPO'] = '/nonexistent-msgcollector-checkout'
        with self.assertRaises(AssertionError):
            _msgcollector_libexec()


if __name__ == '__main__':
    unittest.main()
