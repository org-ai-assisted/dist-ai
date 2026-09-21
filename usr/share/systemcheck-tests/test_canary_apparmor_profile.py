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
once before.) This test asserts the profile GRANTS EXEC on settings_echo, so a
future glob-collapse that drops the exec bit fails here instead of in the field.
"""

import os
import re
import unittest

import systemcheck_testlib

## The helper-script that canary-download must be able to execute.
SETTINGS_ECHO = '/usr/libexec/helper-scripts/settings_echo'


def _expand_braces(pattern: str) -> list[str]:
    """Expand AppArmor '{a,b}' alternations (as used by '/{,usr/}bin/...')."""
    match = re.search(r'\{([^{}]*)\}', pattern)
    if not match:
        return [pattern]
    pre, post = pattern[:match.start()], pattern[match.end():]
    out = []
    for alt in match.group(1).split(','):
        out.extend(_expand_braces(pre + alt + post))
    return out


def _glob_to_regex(glob: str) -> str:
    """AppArmor path glob -> anchored regex. '**' crosses '/', '*' and '?' do not."""
    out = ['^']
    i = 0
    while i < len(glob):
        char = glob[i]
        if char == '*':
            if glob[i + 1:i + 2] == '*':
                out.append('.*')
                i += 2
                continue
            out.append('[^/]*')
            i += 1
            continue
        if char == '?':
            out.append('[^/]')
            i += 1
            continue
        out.append(re.escape(char))
        i += 1
    out.append('$')
    return ''.join(out)


def _path_matches(path_glob: str, target: str) -> bool:
    return any(re.match(_glob_to_regex(expanded), target)
               for expanded in _expand_braces(path_glob))


## One file-access rule: optional 'owner'/'audit' qualifiers, an optional 'deny',
## a path, a permission mode, a trailing comma.
_RULE_RE = re.compile(
    r'^(?:owner\s+)?(?:audit\s+)?(deny\s+)?(\S+)\s+([a-zA-Z]+),\s*$')


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

        allow_exec = False
        deny_exec = False
        with open(profile, encoding='utf-8') as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith(('#', 'include ', 'include<')):
                    continue
                match = _RULE_RE.match(line)
                if not match:
                    continue
                is_deny, path_glob, mode = match.groups()
                if 'x' not in mode:
                    continue
                if not _path_matches(path_glob, SETTINGS_ECHO):
                    continue
                if is_deny:
                    deny_exec = True
                else:
                    allow_exec = True

        self.assertFalse(
            deny_exec,
            f"{profile}: an explicit rule DENIES exec on {SETTINGS_ECHO}")
        self.assertTrue(
            allow_exec,
            f"{profile}: no rule grants exec (x) on {SETTINGS_ECHO} -- "
            "canary-download's exec of settings_echo will be denied "
            "(a read-only '/usr/libexec/helper-scripts/** r,' glob is NOT "
            "enough; restore the explicit 'settings_echo rix,' rule)")


if __name__ == '__main__':
    unittest.main()
