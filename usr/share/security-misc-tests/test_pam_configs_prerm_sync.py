#!/usr/bin/python3 -Bsu

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression guard: the prerm 'pam-auth-update --package --remove' list must name
exactly the pam-config profiles shipped in usr/share/pam-configs/.

security-misc's prerm removes each PAM policy by hand (its own comment: "This
list of policies must be kept in sync with the contents of usr/share/pam-configs").
A new profile added without a prerm entry leaves a stale PAM policy enabled after
package removal (fail-open); a dropped profile leaves a dead removal name. Nothing
else guards this, so assert the two sets are identical.

The subject is a security-misc SOURCE checkout (the test compares source files:
the pam-configs directory against debian/security-misc-shared.prerm), resolved by
SECURITY_MISC_REPO (wired by dist-ai-tests-all; set in CI). Absent that variable
the source tree is not present and the test skips (allow-skip). When the variable
IS set, a missing path is drift in the resolved subject and FAILS, never skips.
"""

import os
import unittest

PAM_CONFIGS_REL = 'usr/share/pam-configs'
PRERM_REL = 'debian/security-misc-shared.prerm'
REMOVE_MARKER = 'pam-auth-update --package --remove'


def _security_misc_repo():
    return os.environ.get('SECURITY_MISC_REPO', '').strip()


def _shipped_profiles(pam_configs_dir):
    """Every pam-config profile shipped: each regular file's basename with the
    '#<package>' install tag stripped. pam-auth-update treats every file in this
    directory as a profile, so the test does too -- no name-convention filter, so
    a profile that does NOT follow the '-security-misc' convention still has to
    appear in the prerm removal list (it would otherwise be a silent fail-open)."""
    names = set()
    for entry in os.listdir(pam_configs_dir):
        if not os.path.isfile(os.path.join(pam_configs_dir, entry)):
            continue
        names.add(entry.split('#', 1)[0])
    return names


def _prerm_remove_list(prerm_path):
    """Profile operands passed to EVERY prerm 'pam-auth-update --package --remove'
    call. For each marker occurrence, collect the operands on its own line
    remainder and on the backslash-continued lines that follow. Full-line shell
    comments are ignored (so a comment that merely mentions the marker does not
    start a bogus empty collection), surrounding shell quotes are stripped, and
    option words (leading '-') are skipped, leaving only profile names. This is a
    deliberately small scan, not a shell parser."""
    names = set()
    collecting = False
    with open(prerm_path, encoding='utf-8') as handle:
        for raw in handle:
            line = raw.rstrip('\n')
            if not collecting:
                if line.lstrip().startswith('#'):
                    continue
                marker = line.find(REMOVE_MARKER)
                if marker == -1:
                    continue
                collecting = True
                line = line[marker + len(REMOVE_MARKER):]
            has_continuation = line.rstrip().endswith('\\')
            for token in line.rstrip().rstrip('\\').split():
                token = token.strip('\'"')
                if token and not token.startswith('-'):
                    names.add(token)
            if not has_continuation:
                ## command ended; a later --remove command is collected too
                collecting = False
    return names


class PrermPamConfigsSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = _security_misc_repo()
        if not repo:
            ## style-ok: allow-skip: subject is a security-misc SOURCE checkout,
            ## wired via SECURITY_MISC_REPO (CI); absent it there is nothing to compare
            raise unittest.SkipTest('SECURITY_MISC_REPO unset')
        cls.pam_configs_dir = os.path.join(repo, PAM_CONFIGS_REL)
        cls.prerm_path = os.path.join(repo, PRERM_REL)

    def test_prerm_remove_list_matches_pam_configs(self):
        ## repo IS resolved here: a missing path is drift in the subject (a renamed
        ## or removed prerm / pam-configs dir), NOT a reason to skip -- skipping
        ## would mask exactly the breakage this guard exists to catch.
        self.assertTrue(
            os.path.isdir(self.pam_configs_dir),
            '%s missing in resolved checkout %s' % (PAM_CONFIGS_REL, self.pam_configs_dir))
        self.assertTrue(
            os.path.isfile(self.prerm_path),
            '%s missing in resolved checkout %s' % (PRERM_REL, self.prerm_path))
        shipped = _shipped_profiles(self.pam_configs_dir)
        listed = _prerm_remove_list(self.prerm_path)
        self.assertTrue(shipped, 'no pam-config profiles found to compare')
        self.assertTrue(listed, 'no prerm removal operands found to compare')
        only_shipped = sorted(shipped - listed)
        only_prerm = sorted(listed - shipped)
        self.assertEqual(
            shipped, listed,
            "prerm '--remove' list is out of sync with %s\n"
            '  shipped but not in prerm: %s\n'
            '  in prerm but not shipped: %s'
            % (PAM_CONFIGS_REL, only_shipped, only_prerm))


if __name__ == '__main__':
    unittest.main()
