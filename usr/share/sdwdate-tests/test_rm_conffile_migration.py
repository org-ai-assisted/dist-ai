#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: the upgrade-migration in debian/sdwdate.maintscript must stay
consistent with the package tree.

Each rm_conffile removes a renamed/merged conffile on upgrade. If the package
ALSO still shipped a file at that same path, dpkg would delete the freshly
installed file (or the rename would resurrect the old one) -- a classic
rm_conffile-vs-ship conflict. So every rm_conffile path must be ABSENT from the
tree, and the files that REPLACED them (the renamed daemon profile, the moved
privleap conf) must be present.

Text/path scan over the package tree (resolved via SDWDATE_REPO), matching
test_apparmor_confinement.py; no dpkg needed.
"""

import os
import re
import unittest

## rm_conffile paths that must NOT be shipped (resurrected) by the package.
EXPECTED_RM_CONFFILES = {
    '/etc/sdwdate.d/30_default',
    '/etc/sdwdate.d/30_sdwdate_default',
    '/etc/sdwdate.d/31_anon_dist_con_check_plugin',
    '/etc/sdwdate.d/31_anon_dist_stream_isolation_plugin',
    '/etc/apparmor.d/abstractions/sdwdate',
    '/etc/apparmor.d/usr.lib.sdwdate.url_to_unixtime',
    '/etc/apparmor.d/usr.bin.sdwdate',
    '/etc/privleap/conf.d/sdwdate.conf',
}

## Files that replaced the removed ones and MUST ship.
EXPECTED_REPLACEMENTS = (
    'etc/apparmor.d/usr.libexec.sdwdate.sdwdate',
    'usr/lib/privleap/conf.d/sdwdate.conf',
)

_RM_CONFFILE_RE = re.compile(r'^\s*rm_conffile\s+(\S+)\s*$')


def _repo_root() -> str:
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    return repo if repo else '/'


class RmConffileMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = _repo_root()
        cls.maintscript = os.path.join(
            cls.root, 'debian', 'sdwdate.maintscript')
        if not os.path.exists(cls.maintscript):
            ## style-ok: allow-skip: packaging source absent (not a --component run)
            raise unittest.SkipTest(
                '%s not found -- set SDWDATE_REPO to the package tree'
                % cls.maintscript)
        with open(cls.maintscript, encoding='utf-8') as handle:
            cls.rm_conffiles = {
                match.group(1)
                for match in (_RM_CONFFILE_RE.match(line)
                              for line in handle)
                if match}

    def test_maintscript_lists_the_expected_migrations(self) -> None:
        ## Guard against a migration entry silently dropped: the maintscript's
        ## rm_conffile set must match what this test enforces.
        self.assertEqual(
            self.rm_conffiles, EXPECTED_RM_CONFFILES,
            'debian/sdwdate.maintscript rm_conffile set drifted from the '
            'migration this test pins')

    def test_no_rm_conffile_is_resurrected_in_the_tree(self) -> None:
        for conffile in sorted(self.rm_conffiles):
            tree_path = os.path.join(self.root, conffile.lstrip('/'))
            self.assertFalse(
                os.path.exists(tree_path),
                'rm_conffile %s is ALSO shipped at %s -- dpkg would delete the '
                'installed file on upgrade (rm_conffile vs ship conflict)'
                % (conffile, tree_path))

    def test_replacement_files_ship(self) -> None:
        for relative in EXPECTED_REPLACEMENTS:
            tree_path = os.path.join(self.root, relative)
            self.assertTrue(
                os.path.exists(tree_path),
                '%s must ship (it replaced a removed conffile)' % tree_path)


if __name__ == '__main__':
    unittest.main()
