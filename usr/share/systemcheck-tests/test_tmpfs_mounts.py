#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for systemcheck_testlib.tmpfs_mounts, the bwrap --tmpfs target
selection behind run_check_scenario_isolated's hide_dirs / place.

bwrap cannot create a mount point under a read-only host dir, so a placed
file whose parent is absent must be reached through its nearest EXISTING
ancestor. A real temp tree stands in for the host filesystem; no bwrap needed,
so this runs in the strict parent suite.
"""

import os
import tempfile
import unittest

from systemcheck_testlib import tmpfs_mounts


class TestTmpfsMounts(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        os.makedirs(self.p('usr/share/qubes'))
        os.makedirs(self.p('run'))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def p(self, rel: str) -> str:
        return os.path.join(self.root, rel)

    def test_existing_parent_is_the_target(self) -> None:
        self.assertEqual(
            tmpfs_mounts([], [self.p('usr/share/qubes/marker-vm')]),
            [self.p('usr/share/qubes')])

    def test_absent_parent_uses_nearest_existing_ancestor(self) -> None:
        ## The regression: the absent parent itself was the tmpfs target, which
        ## bwrap cannot create under a read-only ancestor.
        self.assertEqual(
            tmpfs_mounts([], [self.p('usr/share/anon-gw-base-files/gateway')]),
            [self.p('usr/share')])
        self.assertEqual(
            tmpfs_mounts([], [self.p('run/qubes/this-is-templatevm')]),
            [self.p('run')])

    def test_absent_hide_dir_needs_no_mount(self) -> None:
        self.assertEqual(tmpfs_mounts([self.p('run/qubes')], []), [])

    def test_target_under_another_target_is_dropped(self) -> None:
        ## /usr/share/qubes sits inside the /usr/share tmpfs the absent gateway
        ## dir forces, so mounting it too would be redundant.
        self.assertEqual(
            tmpfs_mounts([self.p('usr/share/qubes')],
                         [self.p('usr/share/anon-gw-base-files/gateway')]),
            [self.p('usr/share')])

    def test_relative_path_is_refused(self) -> None:
        ## dirname('') == '' never reaches an existing dir: refuse, do not hang.
        with self.assertRaises(ValueError):
            tmpfs_mounts([], ['relative-name'])
        with self.assertRaises(ValueError):
            tmpfs_mounts(['relative-dir'], [])

    def test_sibling_prefix_is_not_nesting(self) -> None:
        os.makedirs(self.p('usr/share/qubes-extra'))
        self.assertEqual(
            tmpfs_mounts([self.p('usr/share/qubes'),
                          self.p('usr/share/qubes-extra')], []),
            [self.p('usr/share/qubes'), self.p('usr/share/qubes-extra')])


if __name__ == '__main__':
    unittest.main()
