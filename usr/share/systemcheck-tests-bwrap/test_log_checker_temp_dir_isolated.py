#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for log-checker prep_temp_dir TOCTOU: 'mkdir --mode' sets the
mode only on CREATE, so an already-existing (pre-created) temp dir keeps its own
mode/owner. The dir must therefore be validated (non-symlink, owned by us, 0700)
and refused otherwise, or the full journal could be written into an
attacker-shaped world-readable dir.

prep_temp_dir hardcodes /var/cache/systemcheck-log-checker, which exists on
every host, so each case needs a bubblewrap tmpfs over /var/cache. The other
log-checker hardening cases: test_log_checker_config_hardening.py.
"""

import unittest

from systemcheck_testlib import LogCheckerHardeningBase


class TestLogCheckerTempDirTocToU(LogCheckerHardeningBase):
    """prep_temp_dir must fail closed when the fixed temp dir already exists with
    unsafe type/owner/permissions (mkdir --mode does not re-apply to it)."""

    def test_clean_dir_created_and_accepted(self) -> None:
        proc = self._run_prep_temp_dir()
        self.assertIn('PREP_OK', proc.stdout,
                      'a freshly-created 0700 dir must be accepted')
        self.assertNotIn('PREP_FAIL', proc.stdout)

    def test_pre_created_world_writable_dir_refused(self) -> None:
        setup = ('mkdir --parents --mode=777 -- '
                 '/var/cache/systemcheck-log-checker\n')
        proc = self._run_prep_temp_dir(setup)
        self.assertIn('PREP_FAIL', proc.stdout,
                      'a pre-created mode-0777 temp dir must be refused, not written into')

    def test_symlink_temp_dir_refused(self) -> None:
        ## A symlink in place of the dir (mkdir -p is a no-op on it) must be
        ## refused so the journal is not written through it to another location.
        setup = ('ln --symbolic -- /tmp /var/cache/systemcheck-log-checker\n')
        proc = self._run_prep_temp_dir(setup)
        self.assertIn('PREP_FAIL', proc.stdout,
                      'a symlinked temp dir must be refused')



if __name__ == '__main__':
    unittest.main()
