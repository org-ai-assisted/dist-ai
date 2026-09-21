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

This asserts the profile carries a PLAIN allow rule that grants exec on
settings_echo AND that no matching 'deny ... x' rule overrides it -- AppArmor
evaluates a matching deny BEFORE any allow, so a covering deny would silently
break the exec while a naive allow-only check still passed. An adversarially
CRAFTED rule (a character class like 'settings_[e]cho', a quoted path with
embedded spaces) is out of scope -- the profile is maintained by us, not
attacker-supplied; the realistic regressions are a glob-collapse dropping the
exec bit or a broad deny added for hardening.
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

## A deny rule (AppArmor modifier order is 'audit deny owner'), capturing the
## path (optionally quoted, no embedded space) and the permission mode.
_DENY_RE = re.compile(
    r'^\s*(?:audit\s+)?deny\s+(?:owner\s+)?"?([^"\s]+)"?\s+([a-zA-Z]+)\s*,')


def _expand_braces(pattern: str) -> list[str]:
    """Expand AppArmor '{a,b}' alternations (e.g. '/{,usr/}bin/...')."""
    match = re.search(r'\{([^{}]*)\}', pattern)
    if not match:
        return [pattern]
    pre, post = pattern[:match.start()], pattern[match.end():]
    out = []
    for alt in match.group(1).split(','):
        out.extend(_expand_braces(pre + alt + post))
    return out


def _glob_to_regex(glob: str) -> str:
    """AppArmor path glob -> anchored regex. '**' crosses '/', '*' and '?' do
    not. A character class is treated literally (adversarial crafting is out of
    scope), so this never OVER-matches a real path."""
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
    out.append(r'\Z')
    return ''.join(out)


def _path_covers(path_glob: str, target: str) -> bool:
    return any(re.match(_glob_to_regex(expanded), target)
               for expanded in _expand_braces(path_glob))


def _deny_exec_covers(lines) -> bool:
    """True if any 'deny ... x' rule's path covers settings_echo (a deny that
    AppArmor would apply before the allow, denying the exec)."""
    for line in lines:
        match = _DENY_RE.match(line)
        if not match:
            continue
        path_glob, mode = match.groups()
        if 'x' in mode and _path_covers(path_glob, SETTINGS_ECHO):
            return True
    return False


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
            lines = handle.read().splitlines()

        self.assertTrue(
            any(_ALLOW_EXEC_RE.match(line) for line in lines),
            f"{profile}: no plain rule grants exec (x) on {SETTINGS_ECHO} -- "
            "canary-download's exec of settings_echo will be denied "
            "(a read-only '/usr/libexec/helper-scripts/** r,' glob is NOT "
            "enough; restore the explicit 'settings_echo rix,' rule)")

        self.assertFalse(
            _deny_exec_covers(lines),
            f"{profile}: a 'deny ... x' rule matches {SETTINGS_ECHO} -- "
            "AppArmor applies a matching deny BEFORE the allow, so the exec "
            "grant is overridden and canary-download's exec is denied")

    def test_network_is_the_socket_not_apache2_common(self) -> None:
        """canary-download reaches the network only through the local Tor SOCKS
        proxy, needing a TCP socket. That must be granted directly, NOT by
        pulling in abstractions/apache2-common (which also grants ptrace and
        signal (receive) peer=unconfined -- unrelated to a Tor fetcher)."""
        profile = self._profile_path()
        with open(profile, encoding='utf-8') as handle:
            lines = handle.read().splitlines()

        self.assertFalse(
            any(re.match(r'^\s*include\s+<abstractions/apache2-common>', ln)
                for ln in lines),
            f"{profile}: includes abstractions/apache2-common, which grants "
            "broad ptrace/signal(receive) peer=unconfined to a Tor-only "
            "fetcher; grant 'network inet stream,' directly instead")
        self.assertTrue(
            any(re.match(r'^\s*network\s+inet\s+stream\s*,\s*$', ln)
                for ln in lines),
            f"{profile}: no 'network inet stream,' rule -- canary-download "
            "cannot open the TCP socket to the Tor SOCKS proxy")


if __name__ == '__main__':
    unittest.main()
