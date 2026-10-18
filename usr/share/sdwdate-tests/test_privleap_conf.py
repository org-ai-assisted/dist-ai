#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: the privleap authorization matrix in
usr/lib/privleap/conf.d/sdwdate.conf must grant exactly the intended
privileges -- a widened AuthorizedUsers/Groups or a wrong TargetUser is a
privilege-escalation surface that no runtime test on a hardened build would
flag.

Pinned facts:
  * sdwdate-libexec runs the daemon as TargetUser=sdwdate, NOT root.
  * sdwdate-sync-hwclock is authorized to the sdwdate service user only (no
    sudo/privleap group, no interactive `user`).
  * No action authorizes a user or group outside the intended set.
  * Every sdwdate-OWNED Command binary exists in the tree.

Text-scan over the package tree (resolved via SDWDATE_REPO), matching
test_apparmor_confinement.py; commented (#...) directives are ignored.
"""

import os
import re
import unittest
from typing import Any

## The full intended matrix. Equality catches an added/removed/retyped field.
EXPECTED_ACTIONS = {
    'sdwdate-clock-jump': {
        'Command': '/usr/sbin/sdwdate-clock-jump',
        'AuthorizedGroups': 'sudo,privleap',
        'AuthorizedUsers': 'user',
    },
    'sdwdate-libexec': {
        'Command': '/usr/libexec/sdwdate/sdwdate',
        'TargetUser': 'sdwdate',
        'AuthorizedGroups': 'sudo,privleap',
        'AuthorizedUsers': 'user',
    },
    'start-sdwdate': {
        'Command': '/bin/systemctl --no-pager --no-block start sdwdate',
        'AuthorizedGroups': 'sudo,privleap',
        'AuthorizedUsers': 'user',
    },
    'restart-sdwdate': {
        'Command': '/bin/systemctl --no-pager --no-block restart sdwdate',
        'AuthorizedGroups': 'sudo,privleap',
        'AuthorizedUsers': 'user',
    },
    'stop-sdwdate': {
        'Command': '/bin/systemctl --no-pager --no-block stop sdwdate',
        'AuthorizedGroups': 'sudo,privleap',
        'AuthorizedUsers': 'user',
    },
    'sdwdate-log-viewer': {
        'Command': '/usr/bin/sdwdate-log-viewer',
        'AuthorizedGroups': 'sudo,privleap',
        'AuthorizedUsers': 'user',
    },
    'sdwdate-sync-hwclock': {
        'Command': ('if [ ! -f /usr/share/qubes/marker-vm ]; then '
                    '/usr/sbin/hwclock --verbose --systohc; fi'),
        'AuthorizedUsers': 'sdwdate',
    },
    'sdwdate-clock-jump-do-once-file-create': {
        'Command': '/usr/bin/touch -- /run/sdwdate/clock_jump_do_once',
        'AuthorizedGroups': 'sudo,privleap',
        'AuthorizedUsers': 'user',
        'TargetUser': 'sdwdate',
    },
}

## Command binaries the sdwdate package itself ships (vs system tools like
## systemctl/hwclock/touch). Each must exist in the tree. sclockadj is built
## from source so it is not listed here.
OWNED_COMMAND_FILES = (
    '/usr/sbin/sdwdate-clock-jump',
    '/usr/libexec/sdwdate/sdwdate',
    '/usr/bin/sdwdate-log-viewer',
)

ALLOWED_USERS = {'user', 'sdwdate'}
ALLOWED_GROUPS = {'sudo', 'privleap'}

_SECTION_RE = re.compile(r'^\[(.+)\]\s*$')
_KV_RE = re.compile(r'^([A-Za-z]\w*)=(.*)$')


def _repo_root() -> str:
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    return repo if repo else '/'


def _parse(path):
    sections: dict = {}
    current = None
    with open(path, encoding='utf-8') as handle:
        for raw in handle:
            stripped = raw.rstrip('\n').strip()
            if not stripped or stripped.startswith('#'):
                continue
            section = _SECTION_RE.match(stripped)
            if section:
                current = section.group(1)
                sections[current] = {}
                continue
            ## Match the STRIPPED line, as privleap does (it strips then splits on
            ## '='): a leading-whitespace directive like ' TargetGroup=root' is a
            ## real directive to privleap, so the matrix check must see it too.
            kv = _KV_RE.match(stripped)
            if kv and current is not None:
                sections[current][kv.group(1)] = kv.group(2)
    return sections


class PrivleapConfTest(unittest.TestCase):
    conf: Any
    root: Any
    sections: Any
    actions: Any

    @classmethod
    def setUpClass(cls) -> None:
        root = _repo_root()
        cls.conf = os.path.join(
            root, 'usr', 'lib', 'privleap', 'conf.d', 'sdwdate.conf')
        cls.root = root
        if not os.path.exists(cls.conf):
            ## style-ok: allow-skip: privleap conf absent (not a --component run)
            raise unittest.SkipTest(
                '%s not found -- set SDWDATE_REPO or install sdwdate' % cls.conf)
        cls.sections = _parse(cls.conf)
        cls.actions = {
            name[len('action:'):]: fields
            for name, fields in cls.sections.items()
            if name.startswith('action:')}

    def test_authorization_matrix_matches(self) -> None:
        self.assertEqual(
            self.actions, EXPECTED_ACTIONS,
            'privleap action matrix drifted from the intended authorization')

    def test_libexec_targets_sdwdate_not_root(self) -> None:
        self.assertEqual(
            self.actions['sdwdate-libexec'].get('TargetUser'), 'sdwdate',
            'sdwdate-libexec must run as the sdwdate service user, not root')

    def test_sync_hwclock_authorized_to_sdwdate_only(self) -> None:
        action = self.actions['sdwdate-sync-hwclock']
        self.assertEqual(action.get('AuthorizedUsers'), 'sdwdate')
        self.assertNotIn(
            'AuthorizedGroups', action,
            'sdwdate-sync-hwclock must not authorize any group')

    def test_no_action_authorizes_an_unexpected_user_or_group(self) -> None:
        for name, fields in self.actions.items():
            users = [u for u in fields.get('AuthorizedUsers', '').split(',')
                     if u]
            groups = [g for g in fields.get('AuthorizedGroups', '').split(',')
                      if g]
            for user in users:
                self.assertIn(
                    user, ALLOWED_USERS,
                    'action %s authorizes unexpected user %r' % (name, user))
            for group in groups:
                self.assertIn(
                    group, ALLOWED_GROUPS,
                    'action %s authorizes unexpected group %r' % (name, group))

    def test_owned_command_binaries_exist(self) -> None:
        for command in OWNED_COMMAND_FILES:
            tree_path = os.path.join(self.root, command.lstrip('/'))
            self.assertTrue(
                os.path.exists(tree_path),
                'privleap Command %s does not exist in the tree (%s)'
                % (command, tree_path))

    def test_persistent_user_is_sdwdate(self) -> None:
        self.assertEqual(
            self.sections.get('persistent-users', {}).get('User'), 'sdwdate')


if __name__ == '__main__':
    unittest.main()
