#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression guard: the postinst must not make the shared status-files dir
group- or world-writable.

/var/cache/setup-dist/status-files holds the system-wide "setup done" markers.
They are written by root via privleap (setup-dist-done, repository-dist), so
the directory must stay root-owned and not writable by group or other. A
world/group-writable dir would let any local user plant a .done/.skip and
silently skip the wizard. This test fails if the postinst reintroduces a
group/other write grant on that directory.
"""

import os
import re
import unittest

STATUS_FILES_DIR = '/var/cache/setup-dist/status-files'


def _symbolic_mode_grants_group_or_other_write(mode):
    """True if a symbolic chmod mode adds write for group, other, or all.

    A bounded chmod-mode reader (clause = [ugoa]*[-+=]perms), not a shell
    parser: an empty scope means 'a' (group+other included), and only the '+'
    and '=' operators grant.
    """
    for clause in mode.split(','):
        match = re.fullmatch(r'([ugoa]*)([-+=])([rwxXst]*)', clause)
        if match is None:
            ## Unrecognized clause: flag rather than wave it through.
            return True
        scope, operator, perms = match.groups()
        if operator == '-':
            continue
        if 'w' not in perms:
            continue
        if scope == '' or 'a' in scope or 'g' in scope or 'o' in scope:
            return True
    return False


def _octal_mode_grants_group_or_other_write(mode):
    """True if an octal mode has the write bit set for group or other."""
    digits = mode[-3:]
    group_digit = int(digits[-2])
    other_digit = int(digits[-1])
    return bool(group_digit & 0o2) or bool(other_digit & 0o2)


def _mode_grants_group_or_other_write(mode):
    if re.fullmatch(r'0?[0-7]{3,4}', mode):
        return _octal_mode_grants_group_or_other_write(mode)
    return _symbolic_mode_grants_group_or_other_write(mode)


def _modes_on_line(tokens):
    """Explicit permission modes set by a chmod/install/mkdir command.

    Returns the mode operands only -- flags, the target path, and a mkdir/
    install with no -m/--mode (default umask mode, not an explicit grant) yield
    nothing.
    """
    command = tokens[0].split('/')[-1]
    modes = []
    if command == 'chmod':
        for token in tokens[1:]:
            if token.startswith('-'):
                ## A chmod option (-R, -v, ...); a grant never needs a dash.
                continue
            ## The first non-flag operand is the mode; the rest are paths.
            modes.append(token)
            break
    elif command in ('install', 'mkdir'):
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token.startswith('--mode='):
                modes.append(token[len('--mode='):])
            elif token in ('-m', '--mode') and index + 1 < len(tokens):
                modes.append(tokens[index + 1])
                index += 1
            index += 1
    return modes


def _find_postinst():
    """Locate the shipped setup-wizard-dist.postinst, or None."""
    repo = os.environ.get('SETUP_WIZARD_DIST_REPO', '').strip()
    candidates = []
    if repo:
        candidates.append(
            os.path.join(repo, 'debian', 'setup-wizard-dist.postinst')
        )
    ## Installed maintainer script, for a run on a target system.
    candidates.append('/var/lib/dpkg/info/setup-wizard-dist.postinst')
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


class PostinstPermsTestCase(unittest.TestCase):
    def setUp(self):
        self.postinst = _find_postinst()
        if self.postinst is None:
            self.skipTest(
                'setup-wizard-dist.postinst not found; set '
                'SETUP_WIZARD_DIST_REPO to a checkout or install the package'
            )

    def test_status_files_dir_not_group_or_world_writable(self):
        with open(self.postinst, encoding='ascii') as handle:
            lines = handle.read().splitlines()
        offenders = []
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if STATUS_FILES_DIR not in line:
                continue
            tokens = line.split()
            if not tokens:
                continue
            for mode in _modes_on_line(tokens):
                if _mode_grants_group_or_other_write(mode):
                    offenders.append(f'{number}: {stripped}')
                    break
        self.assertEqual(
            offenders,
            [],
            f'{self.postinst} grants group/other write to {STATUS_FILES_DIR}:\n'
            + '\n'.join(offenders),
        )


class ModeHelperTestCase(unittest.TestCase):
    """Guard the mode reader itself (canary for the guard)."""

    def test_symbolic_group_other_write_flagged(self):
        for mode in ('g+w', 'o+w', 'a+w', '+w', 'go+w', 'ug+w', 'a=rw'):
            self.assertTrue(_mode_grants_group_or_other_write(mode), mode)

    def test_user_only_or_no_write_not_flagged(self):
        for mode in ('u+w', 'u+x', 'g-w', 'o-w', 'g+r', 'a+x'):
            self.assertFalse(_mode_grants_group_or_other_write(mode), mode)

    def test_octal_modes(self):
        for mode in ('0775', '0757', '0777', '0070', '0666'):
            self.assertTrue(_mode_grants_group_or_other_write(mode), mode)
        for mode in ('0755', '0700', '0750', '0705', '0644', '0555'):
            self.assertFalse(_mode_grants_group_or_other_write(mode), mode)

    def test_modes_on_line_extraction(self):
        cases = [
            (['chmod', 'o+w', '"/d"'], ['o+w']),
            (['chmod', '-R', 'g+w', '/d'], ['g+w']),
            (['mkdir', '--parents', '--mode=0755', '--', '"/d"'], ['0755']),
            (['mkdir', '--parents', '"/d"'], []),
            (['install', '-d', '-m', '0750', '/d'], ['0750']),
            (['install', '-d', '--mode=0700', '/d'], ['0700']),
        ]
        for tokens, expected in cases:
            self.assertEqual(_modes_on_line(tokens), expected, tokens)


if __name__ == '__main__':
    unittest.main()
