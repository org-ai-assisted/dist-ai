#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: sdwdate.service's SystemCallFilter must stay an ALLOWLIST (no
leading '~') listing the syscalls the daemon genuinely needs.

If a '~' crept in, the directive would flip to a DENYLIST and permit everything
not named -- silently removing the sandbox. If a required syscall were dropped,
the daemon would be SIGSYS-killed at runtime (e.g. clock_settime is how it sets
the clock; splice/mincore show up in the Python/Tor path). This static parse
catches both at CI time, no root.

systemd ACCUMULATES multiple SystemCallFilter= assignments and an EMPTY one
RESETS the filter, so a sneaked `SystemCallFilter=` + `SystemCallFilter=~read`
pair would reset the allowlist to a permissive denylist; parsing only the first
directive would miss it. So every SystemCallFilter= directive is collected (with
'\\' continuation) and the effective set is computed with reset semantics.

Scans usr/lib/systemd/system/sdwdate.service (resolved via SDWDATE_REPO).
"""

import os
import unittest
from typing import Any

## A conservative core that must always be present; not the whole set, so adding
## a syscall does not need a test edit, but dropping one of these fails.
REQUIRED_SYSCALLS = {
    'read', 'write', 'openat', 'close', 'socket', 'connect', 'sendto',
    'recvfrom', 'clone', 'execve', 'clock_settime', 'splice', 'mincore',
    'getrandom', 'rt_sigaction',
}


def _service_path() -> str:
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    base = repo if repo else '/'
    return os.path.join(
        base, 'usr', 'lib', 'systemd', 'system', 'sdwdate.service')


def _parse_syscall_filters(lines):
    """Return every SystemCallFilter= directive VALUE in order, each with its
    '\\'-continuations joined (systemd accumulates multiple assignments)."""
    directives = []
    collecting = False
    parts: list = []
    for raw in lines:
        line = raw.rstrip('\n')
        if collecting:
            continued = line.endswith('\\')
            parts.append(line[:-1] if continued else line)
            if not continued:
                directives.append(' '.join(parts))
                parts = []
                collecting = False
            continue
        if line.startswith('SystemCallFilter='):
            body = line[len('SystemCallFilter='):]
            continued = body.endswith('\\')
            parts = [body[:-1] if continued else body]
            if continued:
                collecting = True
            else:
                directives.append(' '.join(parts))
                parts = []
    if parts:
        directives.append(' '.join(parts))
    return directives


def _effective_allow(directives):
    """The effective allowed-syscall set after systemd reset semantics: an empty
    value clears it; a '~' (denylist) value clears it (the allowlist assertion
    fails separately); otherwise the tokens accumulate."""
    effective: set = set()
    for directive in directives:
        value = directive.strip()
        if value == '' or value.startswith('~'):
            effective = set()
        else:
            effective |= set(value.split())
    return effective


class SeccompFilterTest(unittest.TestCase):
    path: Any
    directives: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.path = _service_path()
        if not os.path.exists(cls.path):
            ## style-ok: allow-skip: systemd unit absent (not a --component run)
            raise unittest.SkipTest(
                '%s not found -- set SDWDATE_REPO or install sdwdate' % cls.path)
        with open(cls.path, encoding='utf-8') as handle:
            cls.directives = _parse_syscall_filters(handle.readlines())

    def test_directive_present(self) -> None:
        self.assertTrue(
            self.directives, '%s has no SystemCallFilter=' % self.path)

    def test_is_an_allowlist_not_a_denylist(self) -> None:
        for directive in self.directives:
            self.assertFalse(
                directive.strip().startswith('~'),
                'a SystemCallFilter directive is a DENYLIST (%r) -- that permits '
                'every unnamed syscall and removes the sandbox' % directive)

    def test_required_syscalls_present(self) -> None:
        missing = REQUIRED_SYSCALLS - _effective_allow(self.directives)
        self.assertEqual(
            missing, set(),
            'SystemCallFilter is missing required syscalls %s -- the daemon '
            'would be SIGSYS-killed on that call' % sorted(missing))


if __name__ == '__main__':
    unittest.main()
