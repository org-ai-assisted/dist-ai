#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for the sdwdate AppArmor confinement (three profiles).

Background -- the bug these guard against:

  * The daemon profile used to attach the UNUSED interactive wrapper
    /usr/bin/sdwdate, while sdwdate.service runs /usr/libexec/sdwdate/sdwdate
    directly -- so the profile never confined the running daemon. Re-pointing it
    to the real entrypoint then exposed that it lacked the privleap-client rules
    the daemon needs (leaprun exec + /run/privleapd/{pid,comm}); without them
    leaprun exec is DENIED and sdwdate's tor/anondate preparation fails.

  * The service sets NoNewPrivileges=true, under which a discrete AppArmor Px
    transition is DENIED by no_new_privs. The privileged helpers (sclockadj,
    url_to_unixtime) must therefore transition via additive profile STACKING
    ('Cx -> &profile'), never a bare 'Px'.

Text-scan (not apparmor_parser) so it runs with no apparmor package and no
kernel AppArmor, matching systemcheck-tests/test_canary_apparmor_profile.py.
Syntax/compile is covered at package build time by dh_apparmor.
"""

import os
import re
import unittest

APPARMOR_SUBDIR = os.path.join('etc', 'apparmor.d')

DAEMON_PROFILE = 'usr.libexec.sdwdate.sdwdate'
SCLOCKADJ_PROFILE = 'usr.libexec.sdwdate.sclockadj'
URL_TO_UNIXTIME_PROFILE = 'usr.bin.url_to_unixtime'

DAEMON_PATH = '/usr/libexec/sdwdate/sdwdate'
SCLOCKADJ_PATH = '/usr/libexec/sdwdate/sclockadj'
URL_TO_UNIXTIME_PATH = '/usr/bin/url_to_unixtime'
WRAPPER_PATH = '/usr/bin/sdwdate'


def _apparmor_dir() -> str:
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    base = repo if repo else '/'
    return os.path.join(base, APPARMOR_SUBDIR)


def _read(profile_name: str):
    path = os.path.join(_apparmor_dir(), profile_name)
    with open(path, encoding='utf-8') as handle:
        return path, handle.read().splitlines()


## An exec-transition rule: a path, an exec mode (contains 'x'), optionally an
## arrow to a target profile. Captures (path, mode, target-with-optional-&).
_EXEC_RE = re.compile(
    r'^\s*"?([^"\s]+)"?\s+([a-zA-Z]*x[a-zA-Z]*)\s*'
    r'(?:->\s*(\S+?))?\s*,\s*$')


def _exec_rules(lines):
    for line in lines:
        ## Skip only a block-opening line ('<path> flags=(...) {'); a rule with a
        ## brace-glob path ('/{,usr/}bin/leaprun rix,') must NOT be skipped.
        if line.rstrip().endswith('{'):
            continue
        match = _EXEC_RE.match(line)
        if match:
            yield match.groups()


class SdwdateApparmorBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        directory = _apparmor_dir()
        daemon = os.path.join(directory, DAEMON_PROFILE)
        if not os.path.exists(daemon):
            ## style-ok: allow-skip: sdwdate sources absent (not a --component run)
            raise unittest.SkipTest(
                'sdwdate AppArmor profiles not found under %s -- install '
                'sdwdate or set SDWDATE_REPO' % directory)


class DaemonProfileTest(SdwdateApparmorBase):
    def setUp(self) -> None:
        self.path, self.lines = _read(DAEMON_PROFILE)

    def test_confines_the_real_daemon_not_the_wrapper(self) -> None:
        """The profile must attach the real entrypoint the service runs, not the
        unused /usr/bin/sdwdate wrapper (the original unconfined-daemon bug)."""
        header = [ln for ln in self.lines if ln.strip().endswith('{')]
        self.assertTrue(
            any(DAEMON_PATH in ln for ln in header),
            '%s: no profile head attaches %s' % (self.path, DAEMON_PATH))
        self.assertFalse(
            any(re.match(r'\s*' + re.escape(WRAPPER_PATH) + r'\s+flags', ln)
                for ln in header),
            '%s: still attaches the unused wrapper %s; the daemon runs %s'
            % (self.path, WRAPPER_PATH, DAEMON_PATH))

    def test_privleap_client_rules_present(self) -> None:
        """The daemon drives privileged time ops through privleap; without these
        leaprun exec is denied and tor/anondate preparation fails."""
        text = '\n'.join(self.lines)
        self.assertTrue(
            any('leaprun' in m[0] and 'x' in m[1] for m in _exec_rules(self.lines)),
            '%s: no exec rule for leaprun -- the daemon cannot run privleap '
            'actions (leaprun exec would be DENIED)' % self.path)
        for probe in ('/run/privleapd/pid', '/run/privleapd/comm'):
            self.assertRegex(
                text, re.escape(probe) + r'\s+r\s*,',
                '%s: missing read rule for %s (privleap client)'
                % (self.path, probe))

    def test_helpers_use_nnp_safe_stacking_not_discrete_px(self) -> None:
        """Under NoNewPrivileges a discrete Px is denied; the helper transitions
        must stack additively ('Cx -> &profile')."""
        for helper in (SCLOCKADJ_PATH, URL_TO_UNIXTIME_PATH):
            rules = [m for m in _exec_rules(self.lines) if m[0] == helper]
            self.assertTrue(
                rules, '%s: no exec transition for %s' % (self.path, helper))
            for _path, _mode, target in rules:
                self.assertIsNotNone(
                    target,
                    '%s: %s has no transition target; it must stack to its own '
                    'profile' % (self.path, helper))
                self.assertTrue(
                    target.startswith('&'),
                    '%s: %s transition target %r is not stacked (missing "&"); '
                    'a discrete Px is denied under NoNewPrivileges'
                    % (self.path, helper, target))


class SclockadjProfileTest(SdwdateApparmorBase):
    def setUp(self) -> None:
        self.path, self.lines = _read(SCLOCKADJ_PROFILE)

    def test_attaches_sclockadj(self) -> None:
        self.assertTrue(
            any(SCLOCKADJ_PATH in ln and ln.strip().endswith('{')
                for ln in self.lines),
            '%s: does not attach %s' % (self.path, SCLOCKADJ_PATH))

    def test_has_cap_sys_time(self) -> None:
        """sclockadj is the privileged clock setter; it needs CAP_SYS_TIME."""
        self.assertTrue(
            any(re.match(r'\s*capability\s+sys_time\s*,', ln)
                for ln in self.lines),
            '%s: no "capability sys_time," -- sclockadj cannot set the clock'
            % self.path)

    def test_is_minimal_no_network_no_python(self) -> None:
        """Stacking strips the daemon's broad powers; the sclockadj profile must
        stay minimal (it only reads/sets CLOCK_REALTIME)."""
        text = '\n'.join(self.lines)
        self.assertNotRegex(
            text, r'^\s*network\b',
            '%s: grants network to the clock setter' % self.path)
        self.assertNotIn(
            'abstractions/python', text,
            '%s: pulls in python for the clock setter' % self.path)


class UrlToUnixtimeProfileTest(SdwdateApparmorBase):
    def test_profile_attaches_url_to_unixtime(self) -> None:
        path, lines = _read(URL_TO_UNIXTIME_PROFILE)
        self.assertTrue(
            any(URL_TO_UNIXTIME_PATH in ln and ln.strip().endswith('{')
                for ln in lines),
            '%s: does not attach %s' % (path, URL_TO_UNIXTIME_PATH))


_FLAGS_RE = re.compile(r'flags\s*=\s*\(([^)]*)\)')


class ShipsEnforceNotComplainTest(SdwdateApparmorBase):
    """None of the three profiles may ship in complain mode.

    A profile carrying 'complain' in its flags loads PERMISSIVE: AppArmor only
    LOGS, never denies. For the stacked privileged helpers this is silent
    under-confinement -- the narrow sclockadj/url_to_unixtime profile adds no
    real restriction, so the helper is bounded only by the broad parent, i.e.
    effectively not confined to its own set at all. It is also a false-green
    trap: a 'zero denials' e2e on a complain build proves nothing, because
    complain never denies. (url_to_unixtime historically shipped complain
    upstream; it was re-pointed to enforce once its enforce ruleset was proven
    complete by a real time fetch with zero denials.) Enforce is mandatory.
    """

    def test_no_profile_declares_complain(self) -> None:
        for profile in (DAEMON_PROFILE, SCLOCKADJ_PROFILE,
                        URL_TO_UNIXTIME_PROFILE):
            path, lines = _read(profile)
            for line in lines:
                for flags in _FLAGS_RE.findall(line):
                    tokens = [t.strip() for t in flags.split(',')]
                    self.assertNotIn(
                        'complain', tokens,
                        '%s: ships in COMPLAIN mode (flags=(%s)) -- complain is '
                        'permissive, so the stacked helper is not actually '
                        'confined to its set. Must be enforce.' % (path, flags))


if __name__ == '__main__':
    unittest.main()
