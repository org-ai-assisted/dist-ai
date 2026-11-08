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

The security-misc checkout is resolved by SECURITY_MISC_REPO (wired by
dist-ai-tests-all); absent it the subject is not present and the test skips.
"""

import os
import unittest

PAM_CONFIGS_REL = 'usr/share/pam-configs'
PRERM_REL = 'debian/security-misc-shared.prerm'
REMOVE_MARKER = 'pam-auth-update --package --remove'
PROFILE_SUFFIX = '-security-misc'


def _security_misc_repo():
    return os.environ.get('SECURITY_MISC_REPO', '').strip()


def _shipped_profiles(pam_configs_dir):
    """Installed profile names: the basename with the '#<package>' install tag
    stripped (the tag is not part of the installed name)."""
    names = set()
    for entry in os.listdir(pam_configs_dir):
        if not os.path.isfile(os.path.join(pam_configs_dir, entry)):
            continue
        names.add(entry.split('#', 1)[0])
    return names


def _prerm_remove_list(prerm_path):
    """Names passed to the prerm '--package --remove' call: tokens ending in
    '-security-misc' on the backslash-continued lines after the marker."""
    names = set()
    collecting = False
    with open(prerm_path, encoding='utf-8') as handle:
        for raw in handle:
            line = raw.rstrip('\n')
            if not collecting:
                if REMOVE_MARKER in line:
                    collecting = True
                continue
            has_continuation = line.rstrip().endswith('\\')
            for token in line.rstrip().rstrip('\\').split():
                if token.endswith(PROFILE_SUFFIX):
                    names.add(token)
            if not has_continuation:
                break
    return names


class PrermPamConfigsSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = _security_misc_repo()
        if not repo:
            ## style-ok: allow-skip: subject resolved via SECURITY_MISC_REPO
            raise unittest.SkipTest('SECURITY_MISC_REPO unset')
        cls.pam_configs_dir = os.path.join(repo, PAM_CONFIGS_REL)
        cls.prerm_path = os.path.join(repo, PRERM_REL)
        if not os.path.isdir(cls.pam_configs_dir):
            ## style-ok: allow-skip: pam-configs dir absent in this checkout
            raise unittest.SkipTest('%s not found' % PAM_CONFIGS_REL)
        if not os.path.isfile(cls.prerm_path):
            ## style-ok: allow-skip: prerm absent in this checkout
            raise unittest.SkipTest('%s not found' % PRERM_REL)

    def test_prerm_remove_list_matches_pam_configs(self):
        shipped = _shipped_profiles(self.pam_configs_dir)
        listed = _prerm_remove_list(self.prerm_path)
        self.assertTrue(shipped, 'no pam-config profiles found to compare')
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
