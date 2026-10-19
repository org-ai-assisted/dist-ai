#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for dconf access in the usr.bin.systemcheck AppArmor profile.

THE BUG: systemcheck launches yad (progress dialogs) confined under its own
profile. yad (GTK) reads the user's GSettings (font, text-scaling, high-contrast)
via dconf and creates a runtime cache-invalidation flag file under
'$XDG_RUNTIME_DIR/dconf/'. The profile once carried

  deny /run/user/*/dconf/** rwk,

and granted NO dconf read. That BOTH logged a spurious

  dconf-CRITICAL **: unable to create file '/run/user/<uid>/dconf/user':
  Permission denied.  dconf will not work properly.

AND silently dropped the user's interface settings (the persistent
'~/.config/dconf/user' read was denied too), so the dialog fell back to
schema defaults.

The fix includes <abstractions/dconf> (system-db read + persistent user-db read
+ runtime shm rw) and allows creating the runtime dconf dir, so the dialog honors
the user's settings with no critical. This asserts that grant stays in place and
that no 'deny' rule re-covers the dconf path (AppArmor applies a matching deny
BEFORE any allow, so a covering deny would silently re-break it).
"""

import os
import re
import unittest

import systemcheck_testlib


class ApparmorDconfGrantTest(systemcheck_testlib.SystemcheckTestBase):
    """usr.bin.systemcheck must let its confined yad read dconf settings."""

    def _profile_path(self) -> str:
        ## setUpClass resolved cls.dir (and SKIPs if the systemcheck sources are
        ## absent), so a checkout exists here when SYSTEMCHECK_REPO is set.
        repo = os.environ.get('SYSTEMCHECK_REPO', '').strip()
        if repo:
            return os.path.join(
                repo, 'etc', 'apparmor.d', 'usr.bin.systemcheck')
        return '/etc/apparmor.d/usr.bin.systemcheck'

    def _lines(self) -> list[str]:
        profile = self._profile_path()
        self.assertTrue(
            os.path.isfile(profile),
            f"systemcheck AppArmor profile missing: {profile!r}")
        with open(profile, encoding='utf-8') as handle:
            return handle.read().splitlines()

    def test_dconf_abstraction_included(self) -> None:
        """The dconf abstraction grants the system-db read, the persistent
        user-db read, and the runtime shm rw -- i.e. the dialog honors the
        user's settings instead of defaulting."""
        lines = self._lines()
        self.assertTrue(
            any(re.match(r'^\s*include\s+<abstractions/dconf>\s*$', ln)
                for ln in lines),
            f"{self._profile_path()}: no 'include <abstractions/dconf>' -- a "
            "confined yad cannot read the user's GSettings, so progress dialogs "
            "fall back to schema defaults (lost font/scale/high-contrast) and "
            "dconf logs a spurious dconf-CRITICAL")

    def test_runtime_dconf_dir_creatable(self) -> None:
        """The runtime dconf dir may not pre-exist (e.g. for sysmaint, which has
        no full login session), so dconf must be able to create it; otherwise
        the critical is merely moved from the file to the directory."""
        lines = self._lines()
        self.assertTrue(
            any(re.match(r'^\s*owner\s+/run/user/\*/dconf/\s+[a-z]*w[a-z]*\s*,\s*$',
                         ln)
                for ln in lines),
            f"{self._profile_path()}: no writable 'owner /run/user/*/dconf/' "
            "rule -- if the runtime dconf dir is absent, dconf cannot create it "
            "and still logs a dconf-CRITICAL")

    def test_no_deny_covers_dconf(self) -> None:
        """A matching deny is applied before the allow, so any 'deny' rule naming
        a dconf path would silently override the grant above. The realistic
        regression is re-adding 'deny /run/user/*/dconf/** rwk,'."""
        lines = self._lines()
        offenders = [
            ln for ln in lines
            if re.match(r'^\s*(?:audit\s+)?deny\s', ln) and 'dconf' in ln]
        self.assertFalse(
            offenders,
            f"{self._profile_path()}: a 'deny' rule names a dconf path "
            f"{offenders!r} -- AppArmor applies it before the allow, re-breaking "
            "the dconf grant")


if __name__ == '__main__':
    unittest.main()
