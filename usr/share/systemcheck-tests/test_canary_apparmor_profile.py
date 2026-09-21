#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for the systemcheck warrant-canary AppArmor profile.

THE BUG: 'canary-download' EXECUTES /usr/libexec/helper-scripts/settings_echo
(to read GATEWAY_IP on the Whonix Gateway). The profile once carried an explicit
'/usr/libexec/helper-scripts/settings_echo rix,' rule, but a refactor collapsed
the per-file helper-scripts rules into a single read-only glob
'/usr/libexec/helper-scripts/** r,'. That glob matches settings_echo but grants
only 'r', so the exec was denied:

  apparmor="DENIED" operation="exec" ... name=".../settings_echo"
  comm="canary-download" requested_mask="x"

and the hourly canary download failed. (The same rule had regressed the same way
once before.)

This asserts the profile carries a PLAIN allow rule that grants exec (a mode
containing 'x') on settings_echo -- i.e. a bare 'path mode,' line, not one hidden
behind a read-only glob, an 'owner' qualifier (canary-download runs as the
non-root 'canary' user, so an owner-restricted rule would deny it), or a 'deny'.
So a future glob-collapse that drops the exec bit fails here, not in the field.
Adversarial rules crafted to defeat this check are out of scope (the profile is
maintained by us, not attacker-supplied).
"""

import os
import re
import unittest

import systemcheck_testlib

SETTINGS_ECHO = '/usr/libexec/helper-scripts/settings_echo'

## A bare allow rule granting exec on settings_echo: optional leading whitespace,
## the exact path, whitespace, a permission mode containing 'x', a trailing comma.
## A leading qualifier ('owner'/'deny'/'audit') or a glob '**' would not begin
## with the path, so this deliberately does NOT match those.
_ALLOW_EXEC_RE = re.compile(
    r'^\s*' + re.escape(SETTINGS_ECHO) + r'\s+[a-zA-Z]*x[a-zA-Z]*,\s*$')


class CanaryApparmorProfileTest(systemcheck_testlib.SystemcheckTestBase):
    """The canary profile must let canary-download exec settings_echo."""

    def _profile_path(self) -> str:
        ## setUpClass already resolved cls.dir (and SKIPs the suite if the
        ## systemcheck sources are absent), so the sources exist here.
        repo = os.environ.get('SYSTEMCHECK_REPO', '').strip()
        if repo:
            return os.path.join(
                repo, 'etc', 'apparmor.d', 'usr.libexec.systemcheck.canary')
        return '/etc/apparmor.d/usr.libexec.systemcheck.canary'

    def test_settings_echo_is_executable(self) -> None:
        profile = self._profile_path()
        self.assertTrue(
            os.path.isfile(profile),
            f"canary AppArmor profile missing: {profile!r}")

        with open(profile, encoding='utf-8') as handle:
            granted = any(_ALLOW_EXEC_RE.match(line) for line in handle)

        self.assertTrue(
            granted,
            f"{profile}: no plain rule grants exec (x) on {SETTINGS_ECHO} -- "
            "canary-download's exec of settings_echo will be denied "
            "(a read-only '/usr/libexec/helper-scripts/** r,' glob is NOT "
            "enough; restore the explicit 'settings_echo rix,' rule)")


if __name__ == '__main__':
    unittest.main()
